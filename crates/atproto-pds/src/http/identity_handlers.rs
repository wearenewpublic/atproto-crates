//! XRPC handlers for `com.atproto.identity.*`.
//!
//! this surface ships:
//!
//! - `resolveHandle` — handle → DID resolution. Tries the local accounts
//!   directory first; falls back to HTTP `.well-known/atproto-did` for
//!   non-local handles. (DNS-resolution is a future enhancement that
//!   needs a DnsResolver threaded through `HttpState`.)
//! - `updateHandle` — auth-required. Builds a PLC update operation
//!   changing `alsoKnownAs`, signs it with the caller's rotation key, and
//!   submits it to PLC. On success, updates `account.handle` to match.
//! - `requestPlcOperationSignature` — issues a service-auth token scoped
//!   to `lxm=com.atproto.identity.signPlcOperation`. Same machinery as
//!   `getServiceAuth` with the lexicon method locked.

use crate::http::auth::{request_htm_htu, require_authn_sub};
use crate::http::errors::XrpcError;
use crate::http::space_auth::local_signing_key;
use crate::http::state::HttpState;
use atproto_identity::key::{jws_alg, sign as identity_sign};
use atproto_identity::resolve::{resolve_handle as identity_resolve_handle, resolve_handle_http};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
//  resolveHandle
// ---------------------------------------------------------------------------

/// Query params for `resolveHandle`.
#[derive(Debug, Deserialize)]
pub struct ResolveHandleQuery {
    /// Handle to resolve (e.g. `alice.example`).
    pub handle: String,
}

/// Output of `resolveHandle`.
#[derive(Debug, Serialize)]
pub struct ResolveHandleResponse {
    /// Resolved DID.
    pub did: String,
}

/// `GET /xrpc/com.atproto.identity.resolveHandle`.
///
/// Resolution order:
///
/// 1. Check the local accounts directory — fastest, covers PDS-hosted handles.
/// 2. If a [`DnsResolver`](atproto_identity::traits::DnsResolver) is wired
///    via `HttpState::dns_resolver`, run the spec-compliant dual lookup
///    (`atproto_identity::resolve::resolve_handle` — DNS TXT + HTTPS
///    `.well-known/atproto-did`, with conflict detection).
/// 3. Otherwise, fall back to HTTP-only via `resolve_handle_http`.
pub async fn resolve_handle(
    State(state): State<HttpState>,
    Query(q): Query<ResolveHandleQuery>,
) -> Result<Json<ResolveHandleResponse>, XrpcError> {
    let directory = state.reader.accounts();
    if let Some(row) = directory
        .lookup_handle(&q.handle)
        .await
        .map_err(XrpcError::from)?
    {
        return Ok(Json(ResolveHandleResponse { did: row.did }));
    }

    // Non-local handle — fall through to network resolution.
    let client = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;

    let did = if let Some(dns_resolver) = state.dns_resolver.as_ref() {
        // DNS + HTTP dual resolution with conflict detection.
        identity_resolve_handle(&client, dns_resolver.as_ref(), &q.handle)
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::NOT_FOUND,
                    "HandleNotFound",
                    format!("could not resolve {handle}: {e}", handle = q.handle),
                )
            })?
    } else {
        // HTTP-only fallback (no DNS resolver wired).
        resolve_handle_http(&client, &q.handle).await.map_err(|e| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "HandleNotFound",
                format!("could not resolve {handle}: {e}", handle = q.handle),
            )
        })?
    };
    Ok(Json(ResolveHandleResponse { did }))
}

// ---------------------------------------------------------------------------
//  updateHandle
// ---------------------------------------------------------------------------

/// Inputs for `updateHandle`.
#[derive(Debug, Deserialize)]
pub struct UpdateHandleInput {
    /// New handle to switch to.
    pub handle: String,
}

/// `POST /xrpc/com.atproto.identity.updateHandle`. Auth-required.
///
/// Two-step PLC update:
///
/// 1. Fetch the current PLC audit log to learn the latest operation CID
///    (the `prev` of the next op).
/// 2. Build a fresh `UnsignedOperation` with `alsoKnownAs = [at://<new>]`,
///    `prev = <latest cid>`, and the existing rotation/verification keys
///    and service endpoints.
/// 3. Sign with the PDS-managed rotation key.
/// 4. Submit to PLC.
/// 5. UPDATE `account.handle` locally on success.
///
/// All five steps run inside a single handler; failure at any step returns
/// the appropriate XRPC error with the underlying `PlcError`-derived
/// message preserved.
pub async fn update_handle(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateHandleInput>,
) -> Result<StatusCode, XrpcError> {
    let (htm, htu) = request_htm_htu(&parts);
    let did = require_authn_sub(&parts, &state, &htm, &htu).await?;
    do_update_handle(&state, &did, &input.handle).await?;
    Ok(StatusCode::OK)
}

/// Core PLC + local update for a handle change.
///
/// Used by both the user-facing `updateHandle` (auth = the account's own
/// session) and the admin-side `admin.updateAccountHandle` (auth = admin
/// Basic-auth). The flow is identical: fetch current PLC state → build an
/// updated `Operation::new_update` with `alsoKnownAs = [at://<new>]` →
/// sign with the PDS-managed rotation key → submit to PLC → UPDATE the
/// local `account.handle`.
pub async fn do_update_handle(
    state: &HttpState,
    did: &str,
    new_handle: &str,
) -> Result<(), XrpcError> {
    use atproto_identity::plc::{Operation, fetch_audit_log};

    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;
    let plc = state.plc_service.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PlcUnavailable",
            "PDS_DID_PLC_URL is not configured",
        )
    })?;

    // §5.4 — `lookup_rotation_key_ref` dispatches per backend
    // and collapses "row missing" + "rotation_key_ref NULL" into a
    // single `None` so the precondition error stays uniform.
    let rotation_ref = manager
        .lookup_rotation_key_ref(did)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("lookup rotation_key_ref: {e}"),
            )
        })?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::PRECONDITION_FAILED,
                "NoRotationKey",
                "this account has no PDS-managed rotation key",
            )
        })?;
    let rotation_priv = manager
        .key_store()
        .get(&rotation_ref)
        .await
        .map_err(XrpcError::from)?;

    // Fetch the current PLC state to learn the latest op (we need its CID
    // as `prev` and we want to preserve the existing rotation keys, signing
    // keys, and service endpoints — only `alsoKnownAs` changes).
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;
    let log = fetch_audit_log(&http, plc.directory_hostname(), did)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::BAD_GATEWAY,
                "PlcUnavailable",
                format!("fetch audit log: {e}"),
            )
        })?;
    let last = log.into_iter().rfind(|e| !e.nullified).ok_or_else(|| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "PLC audit log empty for this DID",
        )
    })?;

    let new_uri = if new_handle.starts_with("at://") {
        new_handle.to_string()
    } else {
        format!("at://{new_handle}")
    };
    let unsigned = match last.operation {
        Operation::PlcOperation {
            rotation_keys,
            verification_methods,
            services,
            ..
        } => Operation::new_update(
            rotation_keys,
            verification_methods,
            vec![new_uri],
            services,
            last.cid,
        ),
        Operation::PlcTombstone { .. } | Operation::LegacyCreate { .. } => {
            return Err(XrpcError::new(
                StatusCode::PRECONDITION_FAILED,
                "InvalidPlcState",
                "current PLC operation is a legacy-create or tombstone — cannot update handle",
            ));
        }
    };
    let signed = unsigned.sign(&rotation_priv).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign PLC op: {e}"),
        )
    })?;
    plc.submit_operation(did, &signed)
        .await
        .map_err(XrpcError::from)?;

    // §5.4 — `set_handle` dispatches per backend.
    manager.set_handle(did, new_handle).await.map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("update local handle: {e}"),
        )
    })?;
    tracing::info!(did = %did, handle = %new_handle, "handle updated via PLC");
    Ok(())
}

// ---------------------------------------------------------------------------
//  requestPlcOperationSignature
// ---------------------------------------------------------------------------

/// Output of `requestPlcOperationSignature`.
#[derive(Debug, Serialize)]
pub struct PlcOperationSignatureResponse {
    /// Service-auth JWT good for `lxm=com.atproto.identity.signPlcOperation`.
    pub token: String,
}

/// `POST /xrpc/com.atproto.identity.requestPlcOperationSignature`.
/// Auth-required.
///
/// Issues a short-lived service-auth token scoped to the PLC-signing
/// lexicon. Same machinery as `getServiceAuth` but with `lxm` locked so a
/// caller can't reuse the token for unrelated XRPCs.
pub async fn request_plc_operation_signature(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<PlcOperationSignatureResponse>, XrpcError> {
    let (htm, htu) = request_htm_htu(&parts);
    let did = require_authn_sub(&parts, &state, &htm, &htu).await?;

    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;
    let signing_key = local_signing_key(manager, &did).await?;

    let now = now_secs();
    let exp = now + 60;
    let claims = serde_json::json!({
        "iss": did,
        "aud": did, // PLC self-signing — caller is the audience.
        "lxm": "com.atproto.identity.signPlcOperation",
        "iat": now,
        "exp": exp,
        "jti": random_jti(),
    });
    let header = serde_json::json!({
        "alg": jws_alg(&signing_key),
        "typ": crate::http::service_auth_handlers::TYP_SERVICE_AUTH,
    });
    let header_b64 = B64URL.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = B64URL.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = identity_sign(&signing_key, signing_input.as_bytes()).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign service-auth jwt: {e}"),
        )
    })?;
    let token = format!("{signing_input}.{}", B64URL.encode(&sig));
    Ok(Json(PlcOperationSignatureResponse { token }))
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    B64URL.encode(bytes)
}

// ---------------------------------------------------------------------------
//  getRecommendedDidCredentials
// ---------------------------------------------------------------------------

/// Service endpoint shape returned in `services.<name>`.
#[derive(Debug, Serialize)]
pub struct RecommendedServiceEndpoint {
    /// Service type, e.g. `"AtprotoPersonalDataServer"`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URL.
    pub endpoint: String,
}

/// Output of `getRecommendedDidCredentials`. Mirrors the PLC `Operation`
/// shape: rotation keys (public did:key), verification methods (atproto
/// signing key as did:key), `alsoKnownAs` array, and `services` map.
#[derive(Debug, Serialize)]
pub struct RecommendedDidCredentials {
    /// Rotation keys (public form, `did:key:...`). Empty when the caller's
    /// account doesn't use PDS-managed rotation.
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Vec<String>,
    /// Verification methods (`{"atproto": "did:key:..."}`).
    #[serde(rename = "verificationMethods")]
    pub verification_methods: std::collections::BTreeMap<String, String>,
    /// `alsoKnownAs` list (typically `["at://<handle>"]`).
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    /// Service endpoints keyed by name.
    pub services: std::collections::BTreeMap<String, RecommendedServiceEndpoint>,
}

/// `GET /xrpc/com.atproto.identity.getRecommendedDidCredentials`. Auth-required.
///
/// Returns the credentials shape this PDS would publish for the caller's
/// account. Used by the migration flow: a new PDS calls this on the old
/// PDS to learn which keys + services the user is currently registered
/// with, then constructs an updated PLC operation that swaps in the new
/// PDS's keys + endpoint.
///
/// Builds the response from local state — no PLC round-trip:
///
/// - `rotationKeys`: public form of `account.rotation_key_ref` (empty if
///   the account doesn't use PDS-managed rotation).
/// - `verificationMethods`: `{atproto: did:key:<account.signing_key_ref pub>}`.
/// - `alsoKnownAs`: `["at://<account.handle>"]`.
/// - `services`: `{atproto_pds: {type: "AtprotoPersonalDataServer",
///   endpoint: <PlcService.service_endpoint>}}`. Falls back to
///   `https://<service_did host>` when no PlcService is configured.
pub async fn get_recommended_did_credentials(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<RecommendedDidCredentials>, XrpcError> {
    use atproto_identity::key::to_public;

    let (htm, htu) = request_htm_htu(&parts);
    let did = require_authn_sub(&parts, &state, &htm, &htu).await?;

    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;

    // §5.4 — combined credentials lookup dispatches
    // backend and folds the three columns into one round-trip.
    let (handle, signing_key_ref, rotation_key_ref) = manager
        .lookup_did_credentials(&did)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("account lookup: {e}"),
            )
        })?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {did}"),
            )
        })?;

    // Derive the public signing key (atproto Multikey).
    let signing_priv = manager
        .key_store()
        .get(&signing_key_ref)
        .await
        .map_err(XrpcError::from)?;
    let signing_pub = to_public(&signing_priv).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive signing pub: {e}"),
        )
    })?;
    let signing_did_key = signing_pub.to_string();

    // Rotation key (only when the account uses PDS-managed rotation).
    let mut rotation_keys: Vec<String> = Vec::new();
    if let Some(rk_ref) = rotation_key_ref {
        let rotation_priv = manager
            .key_store()
            .get(&rk_ref)
            .await
            .map_err(XrpcError::from)?;
        let rotation_pub = to_public(&rotation_priv).map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("derive rotation pub: {e}"),
            )
        })?;
        rotation_keys.push(rotation_pub.to_string());
    }

    // Verification methods + alsoKnownAs.
    let mut verification_methods = std::collections::BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_did_key);
    let handle_uri = if handle.starts_with("at://") {
        handle.clone()
    } else {
        format!("at://{handle}")
    };

    // Service endpoint: prefer the PlcService config; fall back to deriving
    // from `state.service_did` (works for did:web hosts).
    let endpoint = match state.plc_service.as_ref() {
        Some(plc) => plc.service_endpoint().to_string(),
        None => derive_service_endpoint(&state.service_did),
    };
    let mut services = std::collections::BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        RecommendedServiceEndpoint {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint,
        },
    );

    Ok(Json(RecommendedDidCredentials {
        rotation_keys,
        verification_methods,
        also_known_as: vec![handle_uri],
        services,
    }))
}

fn derive_service_endpoint(service_did: &str) -> String {
    let host = service_did
        .strip_prefix("did:web:")
        .unwrap_or("localhost")
        .to_string();
    let scheme = if host.starts_with("localhost") || host.starts_with("127.") {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{host}")
}

// ---------------------------------------------------------------------------
//  refreshIdentity
// ---------------------------------------------------------------------------

/// Inputs for `refreshIdentity`.
#[derive(Debug, Deserialize)]
pub struct RefreshIdentityInput {
    /// DID whose identity to refresh.
    pub did: String,
}

/// Output of `refreshIdentity` — reports what the PDS observed during the
/// re-fetch.
#[derive(Debug, Serialize)]
pub struct RefreshIdentityResponse {
    /// DID refreshed.
    pub did: String,
    /// Most-recent handle observed in the PLC document. Echoed for
    /// idempotency checks; matches `account.handle` after the refresh
    /// when the PLC document carries an `alsoKnownAs` entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// `true` when the local `account.handle` was updated as a side
    /// effect of the refresh.
    #[serde(rename = "handleUpdated")]
    pub handle_updated: bool,
    /// `true` when an `#identity` outbox event was emitted to wake
    /// downstream `subscribeRepos` consumers.
    #[serde(rename = "identityEventEmitted")]
    pub identity_event_emitted: bool,
}

/// `POST /xrpc/com.atproto.identity.refreshIdentity`. Auth-required.
///
/// Re-fetches the named account's PLC document via
/// `atproto_identity::plc::query`, updates `account.handle` if the
/// document's first `alsoKnownAs` entry differs, and emits an
/// `#identity` event onto the firehose stream so `subscribeRepos`
/// consumers re-resolve. The PDS doesn't currently maintain a long-lived
/// in-process PLC cache, so the refresh is a no-op for cache state — but
/// the outbox event ensures fan-out, and the local-handle reconciliation
/// catches handle rotations performed out-of-band on PLC.
///
/// Caller authorization: any authenticated session can refresh ANY DID's
/// identity (the operation is read-only on PLC + emits a public `#identity`
/// event; no privilege escalation possible). For tighter restriction
/// operators can wrap this in a per-account rate limit.
pub async fn refresh_identity(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<RefreshIdentityInput>,
) -> Result<Json<RefreshIdentityResponse>, XrpcError> {
    use atproto_identity::plc;

    let (htm, htu) = request_htm_htu(&parts);
    let _caller = require_authn_sub(&parts, &state, &htm, &htu).await?;

    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;

    // Build an HTTP client up-front; reused for query + audit-log lookups.
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;

    // Fetch the current PLC document. For did:plc we query the directory;
    // for did:web we'd need a different path — only PLC is supported here.
    let observed_handle = if input.did.starts_with("did:plc:") {
        let plc_host = state
            .plc_service
            .as_ref()
            .map(|p| p.directory_hostname())
            .unwrap_or("plc.directory");
        match plc::query(&http, plc_host, &input.did).await {
            Ok(doc) => doc
                .also_known_as
                .iter()
                .find_map(|aka| aka.strip_prefix("at://"))
                .map(str::to_string),
            Err(e) => {
                tracing::warn!(did = %input.did, error = ?e, "refreshIdentity: PLC query failed");
                None
            }
        }
    } else {
        // did:web / did:webvh refresh is documented as a future
        // enhancement; the route still emits the #identity event so
        // tailing consumers re-resolve on their own path.
        tracing::debug!(did = %input.did, "refreshIdentity: non-PLC DID; skipping document re-fetch");
        None
    };

    // §5.4 — both the read + the write dispatch per backend.
    let mut handle_updated = false;
    if let Some(ref new_handle) = observed_handle {
        let current_handle = manager.lookup_handle(&input.did).await.map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("account handle lookup: {e}"),
            )
        })?;
        if let Some(current_handle) = current_handle
            && &current_handle != new_handle
        {
            manager
                .set_handle(&input.did, new_handle)
                .await
                .map_err(|e| {
                    XrpcError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        format!("update local handle: {e}"),
                    )
                })?;
            tracing::info!(
                did = %input.did,
                old = %current_handle,
                new = %new_handle,
                "refreshIdentity: local handle reconciled with PLC alsoKnownAs"
            );
            handle_updated = true;
        }
    }

    // Emit an `#identity` event onto the firehose stream. Best-effort:
    // failures log and we still return Ok with `identityEventEmitted=false`.
    let event_emitted = match emit_identity_event(
        &manager.sequencer(),
        &input.did,
        observed_handle.as_deref(),
    )
    .await
    {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(did = %input.did, error = ?e, "refreshIdentity: emit #identity failed");
            false
        }
    };

    Ok(Json(RefreshIdentityResponse {
        did: input.did,
        handle: observed_handle,
        handle_updated,
        identity_event_emitted: event_emitted,
    }))
}

/// Append an `#identity` event to the firehose stream so tailing
/// `subscribeRepos` consumers re-resolve the document.
async fn emit_identity_event(
    sequencer: &crate::sequencer::Sequencer,
    did: &str,
    handle: Option<&str>,
) -> crate::errors::PdsResult<()> {
    let bytes = crate::sequencer::payload::encode(&crate::sequencer::payload::IdentityBody {
        did: did.to_string(),
        handle: handle.map(str::to_string),
    })?;
    sequencer
        .append(did, crate::sequencer::EventType::Identity.as_str(), bytes)
        .await?;
    Ok(())
}
