//! Space credential cache: read/mint the cached 2h space credential.
//!
//! On miss (or near-expiry within the configured skew) the AppView runs
//! delegation -> attestation -> `getSpaceCredential`, verifies the returned
//! credential, and caches it in `space_credential_cache`.

use atproto_client::client::DPoPAuth;
use atproto_space::types::SpaceUri;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::db::DbPool;
use crate::error::{AppError, AppResult};
use crate::space::attestation::mint_client_attestation;
use crate::space::delegation::obtain_delegation_token;
use crate::state::WebContext;
use crate::xrpc;

/// Look up a cached, unexpired credential for `(space, member_did)`.
///
/// Returns the credential only when it remains valid past `now + skew_secs`,
/// so callers always get a credential with at least `skew_secs` of headroom.
pub async fn get_cached_credential(
    pool: &DbPool,
    space: &SpaceUri,
    member_did: &str,
    skew_secs: u64,
) -> AppResult<Option<String>> {
    let space_str = space.to_string();
    let threshold = (Utc::now() + Duration::seconds(skew_secs as i64)).to_rfc3339();
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT credential FROM space_credential_cache \
         WHERE space = ? AND member_did = ? AND expires_at > ? \
         LIMIT 1",
    )
    .bind(&space_str)
    .bind(member_did)
    .bind(&threshold)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(c,)| c))
}

/// Store a freshly minted credential in the cache.
pub async fn store_credential(
    pool: &DbPool,
    space: &SpaceUri,
    member_did: &str,
    credential: &str,
    expires_at: DateTime<Utc>,
) -> AppResult<()> {
    let space_str = space.to_string();
    let expires = expires_at.to_rfc3339();
    sqlx::query(
        "INSERT INTO space_credential_cache (space, member_did, credential, expires_at) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(space, member_did) DO UPDATE SET \
           credential = excluded.credential, expires_at = excluded.expires_at",
    )
    .bind(&space_str)
    .bind(member_did)
    .bind(credential)
    .bind(&expires)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get a valid space credential, minting (and caching) one if necessary.
///
/// On a cache hit (with `space_cred_skew_secs` of headroom) the cached value is
/// returned. Otherwise it runs the three-token flow: `getDelegationToken` on
/// the member's PDS (`host`, member OAuth+DPoP), mints a fresh client
/// attestation, exchanges both at `getSpaceCredential` on the authority host,
/// caches the result with the configured skew, and returns it.
pub async fn ensure_credential(
    ctx: &WebContext,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
    member_did: &str,
) -> AppResult<String> {
    let skew = ctx.config.space_cred_skew_secs;
    if let Some(cred) = get_cached_credential(&ctx.pool, space, member_did, skew).await? {
        return Ok(cred);
    }

    // Step A — delegation token from the member's own PDS (OAuth+DPoP).
    let delegation_token = obtain_delegation_token(&ctx.http_client, auth, host, space).await?;

    // Step B — client attestation (local), signed by the AppView OAuth key.
    let signing_key = ctx
        .config
        .oauth_signing_key()
        .ok_or_else(|| AppError::Space("no OAuth signing key configured".to_string()))?;
    let client_id = ctx.config.oauth_client_id();
    let attestation = mint_client_attestation(signing_key, &client_id, &space.space_did)?;

    // Step C — exchange on the authority host (Bearer delegation token + body).
    let authority_host = authority_host(ctx, space).await?;
    let credential = xrpc::get_space_credential(
        &ctx.http_client,
        &authority_host,
        space,
        &delegation_token,
        Some(&attestation),
    )
    .await?;

    // Cache with the configured early-expiry skew: expires_at = exp - skew.
    let exp = credential_exp(&credential).unwrap_or_else(|| {
        // Conservative fallback: assume a 2h credential from now.
        (Utc::now() + Duration::seconds(7200)).timestamp()
    });
    let expires_at = DateTime::<Utc>::from_timestamp(exp, 0)
        .unwrap_or_else(|| Utc::now() + Duration::seconds(7200))
        - Duration::seconds(skew as i64);
    store_credential(&ctx.pool, space, member_did, &credential, expires_at).await?;

    Ok(credential)
}

/// Resolve the space authority host (`#atproto_space_host`) for credential
/// exchange and authority-host reads.
async fn authority_host(ctx: &WebContext, space: &SpaceUri) -> AppResult<String> {
    let owner_did = ctx
        .config
        .space_owner_did
        .clone()
        .unwrap_or_else(|| space.space_did.clone());
    let document = ctx
        .identity_resolver
        .resolve(&owner_did)
        .await
        .map_err(|e| AppError::Space(format!("resolve space owner {owner_did}: {e}")))?;
    document
        .service_endpoint("atproto_space_host")
        .or_else(|| document.service_endpoint("atproto_pds"))
        .map(|s| s.trim_end_matches('/').to_string())
        .ok_or_else(|| AppError::Space(format!("owner {owner_did} has no #atproto_space_host")))
}

/// Decode the `exp` (seconds since epoch) claim from a compact JWS credential
/// without verifying the signature (used only to schedule cache expiry).
fn credential_exp(credential: &str) -> Option<i64> {
    let mut parts = credential.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload_bytes = BASE64_URL_NO_PAD.decode(payload_b64).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp").and_then(Value::as_i64)
}
