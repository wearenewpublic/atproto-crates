//! HTTP-layer auth helpers for `com.atproto.space.*`.
//!
//! Three token shapes flow through Spaces endpoints:
//! 1. **OAuth bearer** — same DPoP-bound HS256 token used for the public
//!    realm. Verified by [`crate::oauth::token::verify_oauth_jwt`]. Used for
//!    own-PDS reads and writes.
//! 2. **MemberGrant JWT** (`typ=space_member_grant`) — passed to
//!    `getSpaceCredential`. Signed by the member's atproto signing key.
//! 3. **SpaceCredential JWT** (`typ=space_credential`) — passed to
//!    `getRecord`/`listRecords`/`getRepoState`/etc. by remote consumers.
//!    Signed by the space owner's atproto signing key.
//!
//! the design (§15.7), MemberGrant verification at the owner's PDS
//! requires resolving the member's DID document to obtain their signing
//! key. The **same-PDS** case (the member is also a locally-managed
//! account on this PDS) looks up the signing key directly via the
//! `AccountManager` + `KeyStore`. Cross-PDS resolution through
//! `atproto-identity` is wired — the resolver picks the path automatically based on
//! whether the DID is locally managed.

use crate::account::AccountManager;
use crate::http::errors::XrpcError;
use crate::security::JtiReplayGuard;
use atproto_identity::key::{KeyData, to_public};
use atproto_space::credential::{
    LXM_GET_SPACE_CREDENTIAL, MemberGrant, TYP_MEMBER_GRANT, TYP_SPACE_CREDENTIAL,
    verify_member_grant,
};
use atproto_space::types::SpaceUri;
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// JWT typ discriminator inspection.
#[derive(Debug, Deserialize)]
struct JwtTypHeader {
    typ: String,
}

/// Identify which kind of token this is by parsing the JWT header `typ`.
/// Returns the literal `typ` value or `None` if the token is malformed /
/// missing a `typ` claim.
pub fn classify_token_typ(token: &str) -> Option<String> {
    let header_b64 = token.split('.').next()?;
    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .ok()?;
    let header: JwtTypHeader = serde_json::from_slice(&header_bytes).ok()?;
    Some(header.typ)
}

/// Recognised Spaces token shapes.
#[derive(Debug, PartialEq, Eq)]
pub enum SpaceTokenKind {
    /// `space_member_grant`.
    MemberGrant,
    /// `space_credential`.
    SpaceCredential,
    /// Anything else (likely an OAuth access token).
    Other(String),
}

/// Convenience over [`classify_token_typ`].
#[must_use]
pub fn classify(token: &str) -> Option<SpaceTokenKind> {
    let typ = classify_token_typ(token)?;
    Some(match typ.as_str() {
        TYP_MEMBER_GRANT => SpaceTokenKind::MemberGrant,
        TYP_SPACE_CREDENTIAL => SpaceTokenKind::SpaceCredential,
        _ => SpaceTokenKind::Other(typ),
    })
}

/// Resolve a locally-managed account's signing key in private form.
pub async fn local_signing_key(accounts: &AccountManager, did: &str) -> Result<KeyData, XrpcError> {
    let key_ref: Option<(String,)> =
        sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
            .bind(did)
            .fetch_optional(accounts.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("lookup signing_key_ref: {e}"),
                )
            })?;
    let key_ref = key_ref
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {did}"),
            )
        })?
        .0;
    accounts.key_store().get(&key_ref).await.map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })
}

/// Resolve a locally-managed account's *public* signing key (used for
/// verifying MemberGrants issued by that account).
pub async fn local_public_key(accounts: &AccountManager, did: &str) -> Result<KeyData, XrpcError> {
    let private = local_signing_key(accounts, did).await?;
    to_public(&private).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive public key: {e}"),
        )
    })
}

/// Verify a MemberGrant against a same-PDS member's signing key, with replay
/// protection.
///
/// MemberGrants don't carry an explicit `jti` claim — instead we synthesize
/// one from `(iss, iat, lxm, space, clientId)` so the replay guard rejects
/// duplicate exchanges of the same grant. TTL is the grant's remaining
/// lifetime (`exp - now`).
///
/// Returns the decoded payload on success. Used by `getSpaceCredential`.
///
/// # Errors
///
/// - 400 `InvalidToken` if the grant is unparseable / expired / claim mismatch.
/// - 401 `AuthenticationRequired` if the issuer (member) is not known on this PDS.
/// - 409 `Replay` if the same grant has already been exchanged within its TTL.
pub async fn verify_local_member_grant(
    accounts: &Arc<AccountManager>,
    jti_guard: &JtiReplayGuard,
    grant_jwt: &str,
    expected_owner_did: &str,
    expected_space: &SpaceUri,
    expected_client_id: &str,
) -> Result<MemberGrant, XrpcError> {
    // Peek the issuer claim without verifying signature, so we know which
    // member's key to fetch. We re-verify with the proper key below.
    let payload_b64 = grant_jwt.split('.').nth(1).ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "MemberGrant: missing payload",
        )
    })?;
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "MemberGrant: payload not base64url",
            )
        })?;
    let unverified: MemberGrant = serde_json::from_slice(&payload_bytes).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "MemberGrant: payload not JSON",
        )
    })?;

    if unverified.lxm != LXM_GET_SPACE_CREDENTIAL {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("MemberGrant lxm mismatch: {}", unverified.lxm),
        ));
    }

    let member_pub = local_public_key(accounts, &unverified.iss).await?;
    let payload = verify_member_grant(
        grant_jwt,
        expected_owner_did,
        expected_space,
        expected_client_id,
        &member_pub,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!("MemberGrant verification: {e}"),
        )
    })?;

    // Replay protection. Synthesize a JTI from the structural identity of the
    // grant; record with TTL = remaining lifetime so the guard self-cleans.
    let synthetic_jti = synthesize_member_grant_jti(&payload);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = Duration::from_secs(payload.exp.saturating_sub(now));
    jti_guard
        .check_and_insert(&synthetic_jti, ttl)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::CONFLICT,
                "Replay",
                format!("MemberGrant replay rejected: {e}"),
            )
        })?;

    Ok(payload)
}

/// Verify a MemberGrant issued by a member on a *remote* PDS by resolving
/// their DID document for the atproto signing key.
///
/// The flow mirrors [`verify_local_member_grant`] but the public-key
/// lookup goes through `atproto-identity` instead of the local
/// `AccountManager`:
///
/// 1. Peek the JWT payload to learn the issuer DID + claim shape.
/// 2. Resolve the issuer's DID document via the configured PLC directory
///    (for `did:plc`) or `.well-known/did.json` (for `did:web`).
/// 3. Find the verification method whose id ends in `#atproto`; decode the
///    multibase public key into a `KeyData`.
/// 4. Re-verify the JWT against that key, plus the same JTI replay guard
///    used on the local path.
///
/// `plc_directory_hostname` is the configured PLC directory (e.g.
/// `plc.directory`); pass `None` to use the upstream default.
///
/// # Errors
///
/// - 400 `InvalidToken` — grant unparseable / wrong `lxm` / claim mismatch.
/// - 401 `AuthenticationRequired` — DID document doesn't resolve, or
///   doesn't carry an `#atproto` verification method.
/// - 403 `InvalidToken` — signature verification failed.
/// - 409 `Replay` — the same grant has already been exchanged.
pub async fn verify_remote_member_grant(
    http: &reqwest::Client,
    jti_guard: &JtiReplayGuard,
    grant_jwt: &str,
    expected_owner_did: &str,
    expected_space: &SpaceUri,
    expected_client_id: &str,
    plc_directory_hostname: Option<&str>,
) -> Result<MemberGrant, XrpcError> {
    let payload_b64 = grant_jwt.split('.').nth(1).ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "MemberGrant: missing payload",
        )
    })?;
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "MemberGrant: payload not base64url",
            )
        })?;
    let unverified: MemberGrant = serde_json::from_slice(&payload_bytes).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "MemberGrant: payload not JSON",
        )
    })?;

    if unverified.lxm != LXM_GET_SPACE_CREDENTIAL {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("MemberGrant lxm mismatch: {}", unverified.lxm),
        ));
    }

    let member_pub = remote_atproto_signing_key(http, &unverified.iss, plc_directory_hostname)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                format!("resolve member DID document for {}: {e}", unverified.iss),
            )
        })?;
    let payload = verify_member_grant(
        grant_jwt,
        expected_owner_did,
        expected_space,
        expected_client_id,
        &member_pub,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!("MemberGrant verification: {e}"),
        )
    })?;

    let synthetic_jti = synthesize_member_grant_jti(&payload);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = Duration::from_secs(payload.exp.saturating_sub(now));
    jti_guard
        .check_and_insert(&synthetic_jti, ttl)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::CONFLICT,
                "Replay",
                format!("MemberGrant replay rejected: {e}"),
            )
        })?;

    Ok(payload)
}

/// Resolve a remote DID's atproto signing key (the `#atproto` verification
/// method's `publicKeyMultibase`). Returns `KeyData` ready for
/// `verify_member_grant` etc.
async fn remote_atproto_signing_key(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<KeyData> {
    use atproto_identity::key::identify_key;
    use atproto_identity::model::VerificationMethod;
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    let document = if did.starts_with("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
        plc_query(http, host, did).await?
    } else if did.starts_with("did:web:") {
        web_query(http, did).await?
    } else {
        anyhow::bail!("unsupported DID method for remote member-grant verification: {did}");
    };
    let mut atproto_pub: Option<String> = None;
    for method in &document.verification_method {
        if let VerificationMethod::Multikey {
            id,
            public_key_multibase,
            ..
        } = method
        {
            // Match either `#atproto` (relative) or
            // `did:plc:xxx#atproto` (absolute). Spec allows either form.
            if id.ends_with("#atproto") {
                atproto_pub = Some(public_key_multibase.clone());
                break;
            }
        }
    }
    let mb = atproto_pub.ok_or_else(|| {
        anyhow::anyhow!("DID document has no #atproto Multikey verification method")
    })?;
    // `identify_key` accepts either a bare multibase value or a `did:key:`
    // wrapper. Normalize so the call site is robust to either form.
    let did_key = if mb.starts_with("did:key:") {
        mb
    } else {
        format!("did:key:{}", mb)
    };
    Ok(identify_key(&did_key)?)
}

/// Build a deterministic JTI for a MemberGrant payload. We hash the load-bearing
/// claims so two grants with the same `(iss, iat, lxm, space, clientId)`
/// collide (replay) but distinct issuances do not.
fn synthesize_member_grant_jti(grant: &MemberGrant) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mg:");
    hasher.update(grant.iss.as_bytes());
    hasher.update(b"|");
    hasher.update(grant.iat.to_be_bytes());
    hasher.update(b"|");
    hasher.update(grant.lxm.as_bytes());
    hasher.update(b"|");
    hasher.update(grant.space.as_bytes());
    hasher.update(b"|");
    hasher.update(grant.client_id.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use atproto_identity::key::KeyType;
    use atproto_space::credential::{MEMBER_GRANT_TTL_SECS, create_member_grant};
    use atproto_space::types::{SpaceKey, SpaceType};
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn fresh_manager(dir: &std::path::Path) -> Arc<AccountManager> {
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        for did in ["did:plc:owner", "did:plc:alice"] {
            manager
                .create_account(CreateAccountParams {
                    did,
                    handle: &format!("{}.example", did.trim_start_matches("did:plc:")),
                    email: None,
                    password: "pw",
                    pds_managed_rotation: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        manager
    }

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn classify_token_kinds() {
        // synthetic header-only jwt-shaped strings
        let mg_header = general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256","typ":"space_member_grant"}"#);
        let sc_header =
            general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"space_credential"}"#);
        let jwt_a = format!("{}.payload.sig", mg_header);
        let jwt_b = format!("{}.payload.sig", sc_header);
        assert_eq!(classify(&jwt_a), Some(SpaceTokenKind::MemberGrant));
        assert_eq!(classify(&jwt_b), Some(SpaceTokenKind::SpaceCredential));
    }

    fn fresh_jti_guard() -> JtiReplayGuard {
        JtiReplayGuard::new(1024)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_member_grant_round_trip() {
        let tmp = TempDir::new().unwrap();
        let manager = fresh_manager(tmp.path()).await;
        let alice_priv = local_signing_key(&manager, "did:plc:alice").await.unwrap();

        let space = test_space();
        let grant = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "https://app.example/client-metadata.json",
            &alice_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();

        let guard = fresh_jti_guard();
        let payload = verify_local_member_grant(
            &manager,
            &guard,
            &grant,
            "did:plc:owner",
            &space,
            "https://app.example/client-metadata.json",
        )
        .await
        .unwrap();
        assert_eq!(payload.iss, "did:plc:alice");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn member_grant_replay_rejected() {
        let tmp = TempDir::new().unwrap();
        let manager = fresh_manager(tmp.path()).await;
        let alice_priv = local_signing_key(&manager, "did:plc:alice").await.unwrap();

        let space = test_space();
        let grant = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "client",
            &alice_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();

        let guard = fresh_jti_guard();

        // First exchange: succeeds.
        verify_local_member_grant(&manager, &guard, &grant, "did:plc:owner", &space, "client")
            .await
            .unwrap();

        // Second exchange of the same grant: rejected as a replay.
        let result =
            verify_local_member_grant(&manager, &guard, &grant, "did:plc:owner", &space, "client")
                .await;
        assert!(result.is_err(), "second exchange should be rejected");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn member_grant_unknown_issuer_rejected() {
        let tmp = TempDir::new().unwrap();
        let manager = fresh_manager(tmp.path()).await;
        let alice_priv = local_signing_key(&manager, "did:plc:alice").await.unwrap();

        let space = test_space();
        // Issue with a *different* iss claim — verify lookup of the unknown
        // issuer fails. We hand-craft the payload to bypass create_member_grant.
        let header = general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"ES256K","typ":"space_member_grant"}"#);
        let bad_payload = serde_json::to_vec(&serde_json::json!({
            "iss": "did:plc:nobody",
            "aud": "did:plc:owner",
            "space": space.to_string(),
            "clientId": "client",
            "lxm": "com.atproto.space.getSpaceCredential",
            "iat": 1_700_000_000,
            "exp": 9_999_999_999u64,
        }))
        .unwrap();
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&bad_payload);
        let signing_input = format!("{}.{}", header, payload_b64);
        let sig = atproto_identity::key::sign(&alice_priv, signing_input.as_bytes()).unwrap();
        let token = format!(
            "{}.{}",
            signing_input,
            general_purpose::URL_SAFE_NO_PAD.encode(&sig)
        );

        let guard = fresh_jti_guard();
        let result =
            verify_local_member_grant(&manager, &guard, &token, "did:plc:owner", &space, "client")
                .await;
        assert!(result.is_err());
    }
}
