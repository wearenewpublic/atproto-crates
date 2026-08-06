//! Token endpoint — `POST /oauth/token`.
//!
//! Supports `grant_type=authorization_code` (with PKCE verification)
//! and `grant_type=refresh_token` (with single-use rotation). Issues
//! HMAC-signed access + refresh JWTs; the access token carries a `cnf.jkt`
//! claim binding it to a DPoP key (per RFC 9449).

use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::oauth::dpop::verify_token_endpoint_dpop;
use crate::oauth::extract::JsonOrForm;
use crate::oauth::state::RefreshHandle;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// `typ` for OAuth access tokens.
pub const TYP_ACCESS: &str = "at-oauth-access";

/// `typ` for OAuth refresh tokens.
pub const TYP_REFRESH: &str = "at-oauth-refresh";

/// Inputs for `POST /oauth/token`.
#[derive(Debug, Deserialize)]
pub struct TokenInput {
    /// Grant type — `authorization_code` or `refresh_token`.
    pub grant_type: String,
    /// `client_id` (required).
    pub client_id: String,
    /// Authorization code (for `authorization_code` grant).
    pub code: Option<String>,
    /// Refresh token (for `refresh_token` grant).
    pub refresh_token: Option<String>,
    /// Redirect URI used at PAR (for `authorization_code` grant).
    pub redirect_uri: Option<String>,
    /// PKCE verifier (for `authorization_code` grant).
    pub code_verifier: Option<String>,
    /// RFC 7523 assertion type, for a confidential client.
    pub client_assertion_type: Option<String>,
    /// The signed assertion itself, for a confidential client.
    pub client_assertion: Option<String>,
}

// Note: there is deliberately no `dpop_jkt` field. The DPoP binding is taken
// from the signed proof in the `DPoP` header, never from a request parameter —
// a parameter is an assertion anyone can make, a proof is a demonstration.

/// Spec-shaped response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Access JWT.
    pub access_token: String,
    /// Token type — `DPoP` if DPoP-bound, otherwise `Bearer`.
    pub token_type: String,
    /// Seconds until access expiry.
    pub expires_in: u64,
    /// Refresh JWT (single-use rotation).
    pub refresh_token: String,
    /// Granted scope.
    pub scope: String,
    /// Subject DID.
    pub sub: String,
}

/// JWT claims for OAuth access/refresh tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Subject DID.
    pub sub: String,
    /// Issuer (PDS service DID).
    pub iss: String,
    /// Audience (PDS service DID).
    pub aud: String,
    /// Client ID (for binding).
    pub client_id: String,
    /// Granted scope (space-separated).
    pub scope: String,
    /// DPoP confirmation — `cnf.jkt = <key thumbprint>`.
    pub cnf: Option<DpopConfirmation>,
    /// Issued-at (epoch seconds).
    pub iat: u64,
    /// Expiration (epoch seconds).
    pub exp: u64,
    /// JWT ID (for refresh-rotation tracking).
    pub jti: String,
    /// The account's session epoch when this grant was minted.
    ///
    /// An OAuth access token is a stateless JWT, so without this there is
    /// nothing to consult to end one early -- deleting the refresh row stops
    /// the grant being renewed but leaves the access token usable for the rest
    /// of its life. "Log out everywhere" advances the account's epoch, and the
    /// auth layer refuses any token minted under an older one.
    ///
    /// `#[serde(default)]` so grants issued before this claim existed decode
    /// as epoch 0, which is what a never-revoked account carries.
    #[serde(default)]
    pub ses: i64,
}

/// `cnf` claim for DPoP-bound access tokens (RFC 9449).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopConfirmation {
    /// JWK thumbprint.
    pub jkt: String,
}

/// Handler for `POST /oauth/token`.
///
/// Rate-limited per `client_id` via the shared sliding-window limiter
/// — guards against credential-stuffing through brute-force PKCE /
/// refresh attempts.
pub async fn token_handler(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonOrForm(input): JsonOrForm<TokenInput>,
) -> Result<Json<TokenResponse>, XrpcError> {
    state
        .rate_limiter
        .try_acquire(&format!("oauth-token:{}", input.client_id))
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimited",
                format!("oauth/token rate-limit hit: {e}"),
            )
        })?;

    // Every grant must demonstrate possession of the DPoP key. The proof is
    // the only client authentication a public AT Protocol OAuth client has:
    // without it, a stolen authorization code or refresh token is redeemable
    // by whoever holds it, which is exactly what DPoP exists to prevent. The
    // server also advertises `require_dpop_bound_access_tokens: true`, so
    // accepting an unproven request contradicts its own metadata.
    let proof_jkt =
        verify_token_endpoint_dpop(&headers, &token_endpoint_url(&state), &state.jti_guard).await?;

    match input.grant_type.as_str() {
        "authorization_code" => handle_code(state, input, proof_jkt).await,
        "refresh_token" => handle_refresh(state, input, proof_jkt).await,
        other => Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("grant_type {other} not supported"),
        )),
    }
}

/// The canonical `htu` a token-endpoint DPoP proof must be bound to.
fn token_endpoint_url(state: &HttpState) -> String {
    format!(
        "https://{}/oauth/token",
        state.service_did.replace("did:web:", "")
    )
}

async fn handle_code(
    state: HttpState,
    input: TokenInput,
    proof_jkt: String,
) -> Result<Json<TokenResponse>, XrpcError> {
    let code = input.code.as_deref().ok_or_else(|| {
        XrpcError::new(StatusCode::BAD_REQUEST, "invalid_request", "code required")
    })?;
    let auth = state
        .oauth
        .take_code(code)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "code unknown or expired",
            )
        })?;

    if auth.request.client_id != input.client_id {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id mismatch",
        ));
    }
    if input.redirect_uri.as_deref() != Some(auth.request.redirect_uri.as_str()) {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        ));
    }
    let verifier = input.code_verifier.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier required (PKCE)",
        )
    })?;
    if !verify_pkce(&auth.request.code_challenge, verifier) {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        ));
    }

    // DPoP binding comes from the proof, and from nothing else.
    //
    // `input.dpop_jkt` is deliberately ignored. Letting the request body name
    // the thumbprint meant an attacker redeeming a stolen code could bind the
    // issued token to their own key, so the resulting token was DPoP-bound —
    // to the wrong party. When the authorization request pinned a thumbprint,
    // the proof must match it; a mismatch means the code is being redeemed by
    // a different key than the one that asked for it.
    if let Some(pinned) = auth.request.dpop_jkt.as_deref()
        && pinned != proof_jkt
    {
        tracing::warn!(
            client_id = %auth.request.client_id,
            "token exchange rejected: DPoP proof key differs from the key pinned at authorization"
        );
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "DPoP proof key does not match the key bound at authorization",
        ));
    }

    // Authenticate the client the way its own metadata says it does, before
    // anything is issued. A confidential client that presents no assertion is
    // refused here rather than downgraded to a public one -- the declaration is
    // what makes a stolen authorization code useless without the key.
    let metadata = crate::oauth::client_metadata::resolve_client_metadata(
        &auth.request.client_id,
        &crate::user_agent(),
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            client_id = %auth.request.client_id,
            error = ?e,
            "could not resolve client metadata at token exchange"
        );
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "this client's metadata could not be retrieved",
        )
    })?;
    // Both spellings an assertion may name: the issuer identifier and the
    // token endpoint itself. Implementations differ on which they mint, and
    // rejecting the other would refuse a correctly-signed assertion.
    let issuer = format!("https://{}", state.service_did.replace("did:web:", ""));
    crate::oauth::client_auth::set_expected_audience(vec![
        issuer.clone(),
        token_endpoint_url(&state),
    ]);
    crate::oauth::client_auth::authenticate(
        &metadata,
        &auth.request.client_id,
        input.client_assertion_type.as_deref(),
        input.client_assertion.as_deref(),
        &state.jti_guard,
    )
    .await?;

    // Expand any `include:` here and nowhere else. The result is what both
    // tokens carry, so refresh below reuses it rather than re-resolving: the
    // permission-set record lives in the *client's* repository, and a client
    // that could re-expand on every refresh could widen a grant the account
    // holder approved once and never sees again.
    let granted =
        crate::oauth::permission_set::expand(state.lexicon_resolver.as_ref(), &auth.request.scope)
            .await;

    issue_pair(
        &state,
        &auth.did,
        &auth.request.client_id,
        &granted,
        &proof_jkt,
    )
    .await
    .map(Json)
}

async fn handle_refresh(
    state: HttpState,
    input: TokenInput,
    proof_jkt: String,
) -> Result<Json<TokenResponse>, XrpcError> {
    let raw = input.refresh_token.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token required",
        )
    })?;
    let claims = verify_oauth_jwt(raw, TYP_REFRESH, &state.jwt_secret)
        .map_err(|e| XrpcError::new(StatusCode::BAD_REQUEST, "invalid_grant", e.to_string()))?;
    if claims.client_id != input.client_id {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "client_id mismatch",
        ));
    }

    // Rotate.
    let old_jti = claims.jti.clone();
    let new_jti = random_jti();
    let handle = state
        .oauth
        .rotate_refresh(&old_jti, new_jti)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token already consumed or revoked",
            )
        })?;

    // A refresh token carries the thumbprint it was bound to. Presenting it
    // requires proving possession of that same key — otherwise a leaked
    // refresh token is bearer-usable despite carrying `cnf`, and rotation
    // hands the attacker a fresh pair indefinitely.
    if handle.dpop_jkt != proof_jkt {
        tracing::warn!(
            client_id = %handle.client_id,
            "refresh rejected: DPoP proof key differs from the key the refresh token is bound to"
        );
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "DPoP proof key does not match the key this refresh token is bound to",
        ));
    }

    // Same rule as the app-password refresh path: a token minted before a
    // takedown must not keep producing access tokens after it.
    if let Some(account) = state
        .reader
        .accounts()
        .lookup_did(&handle.did)
        .await
        .map_err(XrpcError::from)?
        && !account.state.allows_writes()
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            format!("account {} is {}", account.did, account.state),
        ));
    }

    issue_pair(
        &state,
        &handle.did,
        &handle.client_id,
        &handle.scope,
        &handle.dpop_jkt,
    )
    .await
    .map(Json)
}

/// Mint an access/refresh pair bound to `dpop_jkt`.
///
/// The thumbprint is not optional. Every grant proves possession at the token
/// endpoint before reaching here, so an unbound token is not something this
/// server can issue — and when the parameter was an `Option`, an absent value
/// was stored as an empty string, came back as `cnf.jkt = ""`, and matched no
/// proof for the life of the session (F-OAUTH-04). Taking `&str` means that
/// failure cannot be expressed rather than merely not happening.
async fn issue_pair(
    state: &HttpState,
    did: &str,
    client_id: &str,
    scope: &str,
    dpop_jkt: &str,
) -> Result<TokenResponse, XrpcError> {
    let now = chrono::Utc::now().timestamp() as u64;
    let access_jti = random_jti();
    let refresh_jti = random_jti();
    let cnf = Some(DpopConfirmation {
        jkt: dpop_jkt.to_string(),
    });

    // §10.4 — TTLs come from runtime config; default to module constants
    // (15 min / 30d) when the operator hasn't overridden via env.
    let access_ttl = state.oauth_access_ttl_secs;
    let refresh_ttl = state.oauth_refresh_ttl_secs;

    // Stamped so "log out everywhere" can end this grant. Read here rather
    // than carried from the code or refresh token: a grant minted after the
    // epoch advanced must carry the new value, not the one in force when the
    // authorization began.
    let epoch = crate::account::portal::session_epoch(&state.reader.accounts().account_pool(), did)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                e.to_string(),
            )
        })?;

    let access_claims = OAuthClaims {
        sub: did.to_string(),
        iss: format!("did:web:{}", host_from_service_did(&state.service_did)),
        aud: state.service_did.clone(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        cnf: cnf.clone(),
        iat: now,
        exp: now + access_ttl,
        jti: access_jti,
        ses: epoch,
    };
    let refresh_claims = OAuthClaims {
        sub: did.to_string(),
        iss: access_claims.iss.clone(),
        aud: state.service_did.clone(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        cnf: cnf.clone(),
        iat: now,
        exp: now + refresh_ttl,
        jti: refresh_jti.clone(),
        ses: epoch,
    };

    let access_jwt = mint_oauth_jwt(TYP_ACCESS, &access_claims, &state.jwt_secret)
        .map_err(|e| XrpcError::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", e))?;
    let refresh_jwt = mint_oauth_jwt(TYP_REFRESH, &refresh_claims, &state.jwt_secret)
        .map_err(|e| XrpcError::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", e))?;

    state
        .oauth
        .register_refresh(
            refresh_jti.clone(),
            RefreshHandle {
                did: did.to_string(),
                client_id: client_id.to_string(),
                dpop_jkt: dpop_jkt.to_string(),
                scope: scope.to_string(),
                issued_at: Utc::now(),
            },
        )
        .await
        .map_err(XrpcError::from)?;

    Ok(TokenResponse {
        access_token: access_jwt,
        // Always DPoP: there is no path here that does not carry a thumbprint.
        token_type: "DPoP".to_string(),
        expires_in: access_ttl,
        refresh_token: refresh_jwt,
        scope: scope.to_string(),
        sub: did.to_string(),
    })
}

fn host_from_service_did(service_did: &str) -> String {
    service_did
        .strip_prefix("did:web:")
        .unwrap_or(service_did)
        .to_string()
}

fn verify_pkce(code_challenge: &str, code_verifier: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = B64URL.encode(digest);
    computed == code_challenge
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Test-only re-export so adjacent crates (e.g. the revoke endpoint tests)
/// can mint OAuth JWTs without duplicating the JWS code.
#[cfg(test)]
pub(crate) fn mint_oauth_jwt_for_test(typ: &str, claims: &OAuthClaims, secret: &[u8]) -> String {
    mint_oauth_jwt(typ, claims, secret).expect("mint test jwt")
}

fn mint_oauth_jwt(typ: &str, claims: &OAuthClaims, secret: &[u8]) -> Result<String, String> {
    let header = JwtHeader {
        alg: "HS256".to_string(),
        typ: typ.to_string(),
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    let payload_bytes = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(&header_bytes),
        B64URL.encode(&payload_bytes)
    );
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    Ok(format!(
        "{}.{}",
        signing_input,
        B64URL.encode(mac.finalize().into_bytes())
    ))
}

/// Verify an OAuth JWT and return its claims. `expected_typ` is one of
/// [`TYP_ACCESS`] or [`TYP_REFRESH`].
pub fn verify_oauth_jwt(
    token: &str,
    expected_typ: &str,
    secret: &[u8],
) -> Result<OAuthClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed JWT".to_string());
    }
    let header_bytes = B64URL.decode(parts[0]).map_err(|e| e.to_string())?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    if header.alg != "HS256" {
        return Err(format!("unsupported alg {}", header.alg));
    }
    if header.typ != expected_typ {
        return Err(format!("expected typ {expected_typ}, got {}", header.typ));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    let sig = B64URL.decode(parts[2]).map_err(|e| e.to_string())?;
    mac.verify_slice(&sig)
        .map_err(|_| "signature invalid".to_string())?;
    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| e.to_string())?;
    let claims: OAuthClaims = serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;
    let now = Utc::now().timestamp() as u64;
    if claims.exp <= now {
        return Err("token expired".to_string());
    }
    Ok(claims)
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_round_trip() {
        let verifier = "verifier-12345-67890-abcdef-ghijkl-mnopqr-stuvwx-yzabcd";
        let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        assert!(verify_pkce(&challenge, verifier));
        assert!(!verify_pkce(&challenge, "wrong-verifier"));
    }

    #[test]
    fn oauth_jwt_round_trip() {
        let secret = b"secret-bytes-32!";
        let claims = OAuthClaims {
            sub: "did:plc:alice".to_string(),
            iss: "did:web:test".to_string(),
            aud: "did:web:test".to_string(),
            client_id: "client".to_string(),
            scope: "atproto".to_string(),
            cnf: Some(DpopConfirmation {
                jkt: "thumb".to_string(),
            }),
            iat: chrono::Utc::now().timestamp() as u64,
            exp: (chrono::Utc::now().timestamp() + 600) as u64,
            jti: "jti1".to_string(),
            ses: 0,
        };
        let jwt = mint_oauth_jwt(TYP_ACCESS, &claims, secret).unwrap();
        let parsed = verify_oauth_jwt(&jwt, TYP_ACCESS, secret).unwrap();
        assert_eq!(parsed.sub, "did:plc:alice");
        assert_eq!(parsed.cnf.unwrap().jkt, "thumb");
    }

    #[test]
    fn typ_mismatch_rejected() {
        let secret = b"secret-bytes-32!";
        let claims = OAuthClaims {
            sub: "did:plc:alice".to_string(),
            iss: "did:web:t".to_string(),
            aud: "did:web:t".to_string(),
            client_id: "c".to_string(),
            scope: "atproto".to_string(),
            cnf: None,
            iat: chrono::Utc::now().timestamp() as u64,
            exp: (chrono::Utc::now().timestamp() + 600) as u64,
            jti: "jti1".to_string(),
            ses: 0,
        };
        let access = mint_oauth_jwt(TYP_ACCESS, &claims, secret).unwrap();
        assert!(verify_oauth_jwt(&access, TYP_REFRESH, secret).is_err());
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_from_service_did("did:web:pds.example.com"),
            "pds.example.com"
        );
    }
}
