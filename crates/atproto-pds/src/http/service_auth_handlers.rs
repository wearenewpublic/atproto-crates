//! `com.atproto.server.getServiceAuth` — short-lived JWT for inter-service
//! calls.
//!
//! mints a JWT signed with
//! the calling account's atproto signing key with claims:
//! - `iss` = caller's DID
//! - `aud` = audience service DID (`did:web:appview.example` etc.)
//! - `lxm` = NSID of the lexicon method this token is good for (optional)
//! - `iat`, `exp` — `exp` is an absolute epoch-seconds instant, defaulting to
//!   60s out; at most an hour when `lxm` scopes the token, at most a minute
//!   when it does not
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

/// `typ` header value for service-auth JWTs.
///
/// `"JWT"`, not `"at+jwt"`. `@atproto/xrpc-server` throws `BadJwtType` for
/// any other value, so a token typed `at+jwt` is refused by the Bluesky
/// AppView, by Ozone, and by every service built on that library — before
/// the signature is even checked.
pub const TYP_SERVICE_AUTH: &str = "JWT";

/// Longest life a service-auth token may be given, when `lxm` scopes it.
pub const MAX_SERVICE_AUTH_LIFETIME_SECS: u64 = 3600;

/// Longest life a *method-less* service-auth token may be given.
///
/// A token with no `lxm` satisfies every method the receiving service scopes
/// by one, so it is a general-purpose credential for its whole lifetime. It is
/// permitted, because the reference permits it, but only for a minute.
pub const MAX_METHODLESS_SERVICE_AUTH_LIFETIME_SECS: u64 = 60;

/// Methods that must never be reachable through a service-auth token.
///
/// These manage the account itself — its handle, its identity, its app
/// passwords, its email, its very existence — and are required to be called
/// directly by the account holder. Minting a credential that authorises one of
/// them to a third party hands over the account.
pub const PROTECTED_METHODS: &[&str] = &[
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
];

/// Methods a service-auth token may reach only from a privileged session.
///
/// `createAccount` is the account-migration credential: a token bearing it
/// lets the holder create an account elsewhere in the issuer's name. The
/// `chat.bsky.*` namespace carries direct-message access.
pub const PRIVILEGED_METHODS: &[&str] = &[
    "com.atproto.server.createAccount",
    "chat.bsky.actor.deleteAccount",
    "chat.bsky.actor.exportAccountData",
    "chat.bsky.convo.acceptConvo",
    "chat.bsky.convo.addReaction",
    "chat.bsky.convo.deleteMessageForSelf",
    "chat.bsky.convo.getConvo",
    "chat.bsky.convo.getConvoAvailability",
    "chat.bsky.convo.getConvoForMembers",
    "chat.bsky.convo.getLog",
    "chat.bsky.convo.getMessages",
    "chat.bsky.convo.leaveConvo",
    "chat.bsky.convo.listConvos",
    "chat.bsky.convo.muteConvo",
    "chat.bsky.convo.removeReaction",
    "chat.bsky.convo.sendMessage",
    "chat.bsky.convo.sendMessageBatch",
    "chat.bsky.convo.unmuteConvo",
    "chat.bsky.convo.updateAllRead",
    "chat.bsky.convo.updateRead",
];

/// The one method a taken-down account may still mint a token for, so that
/// migrating away from a hostile or mistaken takedown stays possible.
pub const TAKENDOWN_ALLOWED_LXM: &str = "com.atproto.server.createAccount";

/// Query params for `getServiceAuth`.
#[derive(Debug, Deserialize)]
pub struct GetServiceAuthQuery {
    /// Audience — DID of the receiving service.
    pub aud: String,
    /// Absolute expiry as epoch seconds. Defaults to 60 seconds from now.
    ///
    /// Not a lifespan: a caller naming `exp=120` is asking for a token that
    /// expired in 1970, and gets `BadExpiration`.
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

    // A service-auth token authorises another service to act for this account.
    // Which method it authorises decides whether it may be minted at all.
    let lxm = q.lxm.as_deref();

    if let Some(lxm) = lxm
        && PROTECTED_METHODS.contains(&lxm)
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("cannot request a service auth token for the protected method: {lxm}"),
        ));
    }
    if let Some(lxm) = lxm
        && PRIVILEGED_METHODS.contains(&lxm)
        && !claims.privileged()
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("insufficient access to request a service auth token for the method: {lxm}"),
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

    // A taken-down account keeps exactly one capability: migrating away. Any
    // other token would let a moderated account keep acting through a peer.
    if manager
        .account_state(&claims_sub)
        .await
        .map_err(XrpcError::from)?
        == Some(crate::account::AccountState::Takendown)
        && lxm != Some(TAKENDOWN_ALLOWED_LXM)
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "Bad token scope",
        ));
    }

    let signing_key = local_signing_key(manager, &claims_sub).await?;

    // `exp` is an absolute epoch-seconds instant, not a lifetime. Reading it
    // as a TTL meant a client asking for 30 seconds received 600, and a client
    // naming a real timestamp received a token lasting until the clamp.
    let iat = now_secs();
    let exp = match q.exp {
        None => iat + DEFAULT_SERVICE_AUTH_TTL_SECS,
        Some(requested) => {
            let lifetime = requested.checked_sub(iat).ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "BadExpiration",
                    "expiration is in the past",
                )
            })?;
            let ceiling = if lxm.is_some() {
                MAX_SERVICE_AUTH_LIFETIME_SECS
            } else {
                MAX_METHODLESS_SERVICE_AUTH_LIFETIME_SECS
            };
            if lifetime > ceiling {
                return Err(XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "BadExpiration",
                    format!(
                        "cannot request a token expiring more than {ceiling} seconds in the future{}",
                        if lxm.is_some() { "" } else { " without an lxm" }
                    ),
                ));
            }
            requested
        }
    };

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
