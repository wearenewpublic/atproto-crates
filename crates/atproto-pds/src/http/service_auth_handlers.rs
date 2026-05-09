//! `com.atproto.server.getServiceAuth` — short-lived JWT for inter-service
//! calls.
//!
//! mints a JWT signed with
//! the calling account's atproto signing key with claims:
//! - `iss` = caller's DID
//! - `aud` = audience service DID (`did:web:appview.example` etc.)
//! - `lxm` = NSID of the lexicon method this token is good for (optional)
//! - `iat`, `exp` — short TTL (default 60s, max 600s)
//! - `jti` — random nonce for replay protection on the receiving side
//!
//! (PLC genesis), the same machinery doubles as the
//! `lxm=com.atproto.server.createAccount` migration token used to gate a
//! repo handoff between PDSes.

use crate::http::errors::XrpcError;
use crate::http::space_auth::local_signing_key;
use crate::http::state::HttpState;
use atproto_identity::key::{jws_alg, sign as identity_sign};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use base64::{Engine as _, engine::general_purpose};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default service-auth TTL (60s, ).
pub const DEFAULT_SERVICE_AUTH_TTL_SECS: u64 = 60;
/// Maximum service-auth TTL the PDS will mint (10 min).
pub const MAX_SERVICE_AUTH_TTL_SECS: u64 = 600;

/// `typ` header value for service-auth JWTs.
pub const TYP_SERVICE_AUTH: &str = "at+jwt";

/// Query params for `getServiceAuth`.
#[derive(Debug, Deserialize)]
pub struct GetServiceAuthQuery {
    /// Audience — DID of the receiving service.
    pub aud: String,
    /// Lifespan in seconds (clamped to [1, 600]). Default 60.
    pub exp: Option<u64>,
    /// Optional NSID of the lexicon method to scope this token to.
    pub lxm: Option<String>,
}

/// Output of `getServiceAuth`.
#[derive(Debug, Serialize)]
pub struct ServiceAuthResponse {
    /// The compact-form JWT.
    pub token: String,
}

/// Service-auth JWT header.
#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: Option<String>,
}

/// Service-auth JWT payload.
#[derive(Debug, Serialize)]
struct ServiceAuthClaims {
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lxm: Option<String>,
    iat: u64,
    exp: u64,
    jti: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn b64url(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    b64url(&bytes)
}

/// `GET /xrpc/com.atproto.server.getServiceAuth`. Auth-required.
pub async fn get_service_auth(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetServiceAuthQuery>,
) -> Result<Json<ServiceAuthResponse>, XrpcError> {
    // Caller must hold a session access JWT or an OAuth token. OAuth
    // tokens with a `cnf.jkt` thumbprint require a fresh DPoP proof
    // (RFC 9449) — the unified helper enforces that automatically.
    let (htm, htu) = crate::http::auth::request_htm_htu(&parts);
    let claims = crate::http::auth::require_authn(&parts, &state, &htm, &htu).await?;

    if !q.aud.starts_with("did:") {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "aud must be a DID",
        ));
    }
    if let Some(lxm) = q.lxm.as_deref()
        && !is_nsid(lxm)
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("invalid lxm NSID: {lxm}"),
        ));
    }

    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;
    let claims_sub = claims.sub().to_string();
    let signing_key = local_signing_key(manager, &claims_sub).await?;

    let ttl = q
        .exp
        .unwrap_or(DEFAULT_SERVICE_AUTH_TTL_SECS)
        .clamp(1, MAX_SERVICE_AUTH_TTL_SECS);
    let iat = now_secs();
    let exp = iat + ttl;

    let header = JwtHeader {
        alg: jws_alg(&signing_key).to_string(),
        typ: TYP_SERVICE_AUTH.to_string(),
        kid: None,
    };
    let payload = ServiceAuthClaims {
        iss: claims_sub.clone(),
        aud: q.aud,
        lxm: q.lxm,
        iat,
        exp,
        jti: random_jti(),
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
    let signing_input = format!("{}.{}", b64url(&header_bytes), b64url(&payload_bytes));
    let sig = identity_sign(&signing_key, signing_input.as_bytes()).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign: {e}"),
        )
    })?;
    let token = format!("{}.{}", signing_input, b64url(&sig));
    Ok(Json(ServiceAuthResponse { token }))
}

/// Permissive NSID validation (3+ dot-segments, alphanumeric+hyphen).
fn is_nsid(s: &str) -> bool {
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() < 3 {
        return false;
    }
    segs.iter().all(|seg| {
        !seg.is_empty()
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !seg.starts_with('-')
            && !seg.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsid_validation_basic() {
        assert!(is_nsid("com.atproto.repo.createRecord"));
        assert!(is_nsid("app.bsky.feed.post"));
        assert!(!is_nsid("two.parts"));
        assert!(!is_nsid("with space.x.y"));
        assert!(!is_nsid("trailing.dot."));
    }
}
