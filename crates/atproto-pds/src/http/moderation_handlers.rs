//! `com.atproto.moderation.createReport`.
//!
//! The PDS doesn't run a moderation service itself — moderation lives
//! upstream (the AppView / labeler service for the network the user
//! belongs to). This handler forwards a user-issued report:
//!
//! 1. Authenticate the caller via the standard session/OAuth path.
//! 2. (Optional) Verify the report subject DID is hosted by this PDS —
//!    fail closed when the subject is a remote DID we can't vouch for.
//!    the design note, this is configurable; the default behavior is
//!    permissive (any subject DID is accepted) since the moderation
//!    service is the final authority on whether the subject is in scope.
//! 3. Mint a service-auth JWT (`aud=PDS_REPORT_SERVICE_DID`,
//!    `lxm=com.atproto.moderation.createReport`, 60s TTL) signed with the
//!    caller's atproto signing key.
//! 4. POST the user's payload to
//!    `<PDS_REPORT_SERVICE_URL>/xrpc/com.atproto.moderation.createReport`
//!    with `Authorization: Bearer <jwt>` and `Content-Type: application/json`.
//! 5. Forward the upstream response code + body verbatim.
//!
//! Returns `503 ModerationServiceUnavailable` when
//! `PDS_REPORT_SERVICE_DID` / `PDS_REPORT_SERVICE_URL` are unset (the
//! operator hasn't wired forwarding yet).

use crate::http::auth::request_htm_htu;
use crate::http::errors::XrpcError;
use crate::http::space_auth::local_signing_key;
use crate::http::state::HttpState;
use atproto_identity::key::{jws_alg, sign as identity_sign};
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngExt;
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `POST /xrpc/com.atproto.moderation.createReport`. Auth-required.
///
/// Forwards the JSON request body verbatim to the configured moderation
/// service with a fresh service-auth bearer. Forwarding failures bubble
/// up as `502 BadGateway`.
pub async fn create_report(
    State(state): State<HttpState>,
    parts: Parts,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, XrpcError> {
    use axum::response::IntoResponse;

    let (htm, htu) = request_htm_htu(&parts, state.trusted_proxy_hops);
    let subject = crate::http::auth::require_authn(&parts, &state, &htm, &htu).await?;
    let caller = subject.sub().to_string();
    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;

    let report_did = state.report_service_did.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ModerationServiceUnavailable",
            "PDS_REPORT_SERVICE_DID is not configured",
        )
    })?;
    let report_url = state.report_service_url.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ModerationServiceUnavailable",
            "PDS_REPORT_SERVICE_URL is not configured",
        )
    })?;

    // This is a proxied call: it mints a service-auth JWT under the caller's
    // own key and forwards to the moderation service, exactly as
    // `proxy_handlers` does -- and that path asserts the `rpc:` scope while
    // this one did not. `transition:generic` satisfies it, matching the
    // specification's "API endpoints and service proxying for most Lexicon
    // endpoints", so this refuses only a token that was never granted the
    // call.
    if subject.is_oauth() {
        subject
            .scopes()
            .assert_rpc("com.atproto.moderation.createReport", report_did)
            .map_err(|missing| {
                XrpcError::new(
                    StatusCode::FORBIDDEN,
                    "InsufficientScope",
                    format!("this token does not grant {}", missing.scope),
                )
            })?;
    }

    // Mint a service-auth JWT signed by the caller's atproto signing key.
    let signing_key = local_signing_key(manager, &caller).await?;
    let token = mint_service_auth(&caller, report_did, &signing_key)?;

    // Forward.
    let endpoint = format!(
        "{base}/xrpc/com.atproto.moderation.createReport",
        base = report_url.trim_end_matches('/')
    );
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;
    let response = http
        .post(&endpoint)
        .bearer_auth(&token)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = ?e, endpoint = %endpoint, "createReport forward failed");
            XrpcError::new(
                StatusCode::BAD_GATEWAY,
                "ModerationServiceUnavailable",
                format!("forward to moderation service failed: {e}"),
            )
        })?;

    let status = response.status();
    let body_bytes = response.bytes().await.map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_GATEWAY,
            "ModerationServiceUnavailable",
            format!("read upstream body: {e}"),
        )
    })?;
    tracing::info!(
        caller = %caller,
        upstream_status = status.as_u16(),
        "createReport forwarded to moderation service"
    );

    let mut response = (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
        body_bytes.to_vec(),
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    Ok(response)
}

/// Service-auth JWT header (matches `service_auth_handlers::JwtHeader`).
#[derive(Serialize)]
struct ServiceAuthHeader {
    alg: String,
    typ: &'static str,
}

/// Service-auth JWT claims (matches `service_auth_handlers::ServiceAuthClaims`).
#[derive(Serialize)]
struct ServiceAuthClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    lxm: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

/// Mint a 60-second service-auth token signed by `signing_key`,
/// scoped to the moderation NSID.
fn mint_service_auth(
    caller_did: &str,
    aud_did: &str,
    signing_key: &atproto_identity::key::KeyData,
) -> Result<String, XrpcError> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let exp = iat + 60;
    let jti = {
        let mut bytes = [0u8; 16];
        rand::rng().fill(&mut bytes);
        B64URL.encode(bytes)
    };
    let header = ServiceAuthHeader {
        alg: jws_alg(signing_key).to_string(),
        typ: crate::http::service_auth_handlers::TYP_SERVICE_AUTH,
    };
    let payload = ServiceAuthClaims {
        iss: caller_did,
        aud: aud_did,
        lxm: "com.atproto.moderation.createReport",
        iat,
        exp,
        jti,
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })?;
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(&header_bytes),
        B64URL.encode(&payload_bytes)
    );
    let sig = identity_sign(signing_key, signing_input.as_bytes()).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign: {e}"),
        )
    })?;
    Ok(format!("{}.{}", signing_input, B64URL.encode(&sig)))
}
