//! OAuth callback: exchange the authorization code for DPoP-bound tokens and
//! set the encrypted session + readable identity cookies.

use atproto_identity::key::identify_key;
use atproto_oauth::resources::pds_resources;
use atproto_oauth::workflow::{OAuthClient, OAuthRequest, oauth_complete};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::WebError;
use crate::oauth::session::{
    IdentityCookie, SessionCookie, build_identity_cookie_header, build_session_cookie_header,
    encode_identity_cookie, encode_session_cookie,
};
use crate::state::WebContext;

/// OAuth request state persisted (as JSON) in the `oauth_request` table between
/// `login` (PAR) and `callback` (code exchange). Single-use, keyed by `state`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedOAuthRequest {
    /// The CSRF state value (primary key).
    pub state: String,
    /// The authorization server issuer.
    pub issuer: String,
    /// The OAuth nonce.
    pub nonce: String,
    /// The PKCE code verifier.
    pub pkce_verifier: String,
    /// The per-session DPoP private key (`did:key:...`).
    pub dpop_private_key: String,
    /// The original login hint (handle/DID/URL) the user supplied.
    pub login_hint: String,
    /// The DID resolved at PAR time, when the login hint resolved to one.
    ///
    /// Pinning it here means the callback binds the token response to the
    /// account the flow actually began for, rather than to whatever the login
    /// hint happens to resolve to at callback time. `None` for a bare PDS URL
    /// login, where no DID is known until the token exchange.
    #[serde(default)]
    pub subject: Option<String>,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
}

/// Query parameters for `GET /callback`.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The opaque state value echoed back.
    pub state: String,
    /// The issuer (RFC 9207), if present.
    pub iss: Option<String>,
    /// The authorization code.
    pub code: Option<String>,
    /// An error code, if the authorization failed.
    pub error: Option<String>,
}

/// `GET /callback` — complete the OAuth flow and set session cookies.
pub async fn callback(
    State(ctx): State<WebContext>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, WebError> {
    if let Some(error) = query.error {
        return Err(WebError::BadRequest(format!(
            "authorization failed: {error}"
        )));
    }

    let code = query
        .code
        .ok_or_else(|| WebError::BadRequest("missing authorization code".to_string()))?;

    // Load + single-use-delete the persisted request keyed by `state`.
    let persisted = take_oauth_request(&ctx, &query.state)
        .await?
        .ok_or_else(|| WebError::BadRequest("unknown or expired oauth state".to_string()))?;

    if persisted.expires_at < Utc::now() {
        return Err(WebError::BadRequest("oauth state expired".to_string()));
    }

    // RFC 9207: the returned `iss` must match the authorization server.
    if let Some(iss) = &query.iss
        && iss != &persisted.issuer
    {
        return Err(WebError::BadRequest("issuer mismatch".to_string()));
    }

    // Resolve the identity (handle/DID/URL) -> DID document -> PDS endpoint.
    let document = ctx
        .identity_resolver
        .resolve(persisted.login_hint.trim_start_matches("at://"))
        .await
        .map_err(|e| WebError::BadRequest(format!("identity resolution failed: {e}")))?;
    let pds_endpoint = document
        .pds_endpoints()
        .first()
        .map(|s| s.to_string())
        .ok_or_else(|| WebError::BadRequest("no PDS endpoint".to_string()))?;

    // Re-discover the authorization server for the token exchange.
    let (_protected_resource, authorization_server) =
        pds_resources(&ctx.http_client, &pds_endpoint)
            .await
            .map_err(|e| WebError::Internal(anyhow::anyhow!("resource discovery failed: {e}")))?;

    if authorization_server.issuer != persisted.issuer {
        return Err(WebError::BadRequest(
            "authorization server issuer changed".to_string(),
        ));
    }

    // If a DID was pinned at PAR time, the login hint must still resolve to it.
    // A change means the handle was re-pointed mid-flow.
    if let Some(pinned) = &persisted.subject
        && pinned != &document.id
    {
        return Err(WebError::BadRequest(
            "identity changed during the authorization flow".to_string(),
        ));
    }

    // Rebuild the DPoP key + OAuth client + request used during PAR.
    let dpop_key = identify_key(&persisted.dpop_private_key)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("invalid stored DPoP key: {e}")))?;

    let signing_key =
        ctx.config.oauth_signing_key().cloned().ok_or_else(|| {
            WebError::Internal(anyhow::anyhow!("no OAuth signing key configured"))
        })?;

    let oauth_client = OAuthClient {
        redirect_uri: ctx.config.oauth_redirect_uri(),
        client_id: ctx.config.oauth_client_id(),
        private_signing_key_data: signing_key,
    };

    let signing_public_key = ctx
        .config
        .oauth_signing_key()
        .and_then(|k| atproto_identity::key::to_public(k).ok())
        .map(|k| k.to_string())
        .unwrap_or_default();

    let oauth_request = OAuthRequest {
        oauth_state: persisted.state.clone(),
        subject: document.id.clone(),
        issuer: persisted.issuer.clone(),
        authorization_server: authorization_server.issuer.clone(),
        nonce: persisted.nonce.clone(),
        pkce_verifier: persisted.pkce_verifier.clone(),
        signing_public_key,
        dpop_private_key: persisted.dpop_private_key.clone(),
        created_at: persisted.created_at,
        expires_at: persisted.expires_at,
    };

    // Exchange the code for DPoP-bound access + refresh tokens.
    let token_response = oauth_complete(
        &ctx.http_client,
        &oauth_client,
        &dpop_key,
        &code,
        &document.id,
        &oauth_request,
        &authorization_server,
    )
    .await
    .map_err(|e| WebError::Internal(anyhow::anyhow!("token exchange failed: {e}")))?;

    // `oauth_complete` bound the token response's `sub` claim to `document.id`,
    // so the resolved DID is authoritative. Never fall back to a token-supplied
    // subject: that is how a hostile authorization server mints a session as
    // someone else.
    let did = document.id.clone();

    let expires_at = Utc::now() + Duration::seconds(i64::from(token_response.expires_in));

    let session = SessionCookie {
        did: did.clone(),
        access_token: token_response.access_token.clone(),
        refresh_token: token_response.refresh_token.clone(),
        expires_at,
        dpop_private_key: persisted.dpop_private_key.clone(),
    };

    let identity = IdentityCookie {
        did: did.clone(),
        handle: document.handles().map(|h| h.to_string()),
        pds_url: Some(pds_endpoint),
    };

    // Build both Set-Cookie headers.
    let cookie_secret = ctx
        .config
        .cookie_secret
        .as_ref()
        .ok_or_else(|| WebError::Internal(anyhow::anyhow!("no cookie secret configured")))?;

    let session_value = encode_session_cookie(cookie_secret, &session)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("session encode failed: {e}")))?;
    let identity_value = encode_identity_cookie(&identity)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("identity encode failed: {e}")))?;

    let domain = &ctx.config.http_external_base;
    let max_age = Duration::days(30).num_seconds();

    let mut headers = HeaderMap::new();
    if let Ok(h) = build_session_cookie_header(domain, &session_value, max_age) {
        headers.append(header::SET_COOKIE, h);
    }
    if let Ok(h) = build_identity_cookie_header(domain, &identity_value, max_age) {
        headers.append(header::SET_COOKIE, h);
    }

    Ok((headers, Redirect::to("/")).into_response())
}

/// Atomically read + delete (single-use) an OAuth request by `state`.
async fn take_oauth_request(
    ctx: &WebContext,
    state: &str,
) -> Result<Option<PersistedOAuthRequest>, WebError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT data FROM oauth_request WHERE state = ?")
        .bind(state)
        .fetch_optional(&ctx.pool)
        .await?;

    // Delete regardless so the state cannot be replayed.
    sqlx::query("DELETE FROM oauth_request WHERE state = ?")
        .bind(state)
        .execute(&ctx.pool)
        .await?;

    match row {
        Some((data,)) => {
            let parsed: PersistedOAuthRequest = serde_json::from_str(&data)?;
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}
