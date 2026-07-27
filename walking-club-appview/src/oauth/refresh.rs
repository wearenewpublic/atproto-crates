//! Stateless OAuth session refresh.
//!
//! If the session access token is near expiry, re-mint it via `oauth_refresh`
//! and re-set the session cookie. `try_refresh_session` is also called by
//! `feed`/`compose` handlers before any PDS write.

use atproto_identity::key::identify_key;
use atproto_oauth::workflow::{OAuthClient, oauth_refresh};
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};

use crate::error::WebError;
use crate::oauth::session::{
    SessionCookie, build_session_cookie_header, encode_session_cookie, get_session_from_headers,
};
use crate::state::WebContext;

/// `POST /auth/refresh` — refresh the session cookie if needed.
pub async fn refresh(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let session = get_session_from_headers(&ctx.config, &headers).ok_or(WebError::Unauthorized)?;

    let (_session, set_cookie) = try_refresh_session(&ctx, session).await?;

    match set_cookie {
        Some(value) => {
            let mut out = HeaderMap::new();
            if let Ok(header_value) = http_cookie_value(&value) {
                out.append(header::SET_COOKIE, header_value);
            }
            Ok((out, axum::http::StatusCode::NO_CONTENT).into_response())
        }
        None => Ok(axum::http::StatusCode::NO_CONTENT.into_response()),
    }
}

/// Convert a cookie string into a header value.
fn http_cookie_value(value: &str) -> Result<axum::http::HeaderValue, WebError> {
    axum::http::HeaderValue::from_str(value)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("invalid cookie value: {e}")))
}

/// Refresh a session in place if it is near expiry, returning the (possibly
/// updated) session and an optional `Set-Cookie` header value.
///
/// Resolves the DID document for `session.did`, rebuilds the DPoP key, and calls
/// `atproto_oauth::workflow::oauth_refresh`. On success the session cookie is
/// re-encoded and returned for the caller to set.
pub async fn try_refresh_session(
    ctx: &WebContext,
    session: SessionCookie,
) -> Result<(SessionCookie, Option<String>), WebError> {
    if !session.expires_within(Duration::minutes(5)) {
        return Ok((session, None));
    }

    let refresh_token = match &session.refresh_token {
        Some(token) => token.clone(),
        None => return Ok((session, None)),
    };

    let signing_key =
        ctx.config.oauth_signing_key().cloned().ok_or_else(|| {
            WebError::Internal(anyhow::anyhow!("no OAuth signing key configured"))
        })?;

    let dpop_key = identify_key(&session.dpop_private_key)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("invalid stored DPoP key: {e}")))?;

    let document = ctx
        .identity_resolver
        .resolve(&session.did)
        .await
        .map_err(|e| WebError::Internal(anyhow::anyhow!("identity resolution failed: {e}")))?;

    let oauth_client = OAuthClient {
        redirect_uri: ctx.config.oauth_redirect_uri(),
        client_id: ctx.config.oauth_client_id(),
        private_signing_key_data: signing_key,
    };

    let token_response = oauth_refresh(
        &ctx.http_client,
        &oauth_client,
        &dpop_key,
        &refresh_token,
        &document,
    )
    .await
    .map_err(|e| WebError::Internal(anyhow::anyhow!("token refresh failed: {e}")))?;

    let expires_at = Utc::now() + Duration::seconds(i64::from(token_response.expires_in));

    let new_session = SessionCookie {
        did: session.did.clone(),
        access_token: token_response.access_token.clone(),
        refresh_token: token_response
            .refresh_token
            .clone()
            .or(session.refresh_token.clone()),
        expires_at,
        dpop_private_key: session.dpop_private_key.clone(),
    };

    let cookie_secret = ctx
        .config
        .cookie_secret
        .as_ref()
        .ok_or_else(|| WebError::Internal(anyhow::anyhow!("no cookie secret configured")))?;

    let encoded = encode_session_cookie(cookie_secret, &new_session)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("session encode failed: {e}")))?;

    let max_age = Duration::days(30).num_seconds();
    let set_cookie = build_session_cookie_header(&ctx.config.http_external_base, &encoded, max_age)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("cookie build failed: {e}")))?
        .to_str()
        .map_err(|e| WebError::Internal(anyhow::anyhow!("cookie to_str failed: {e}")))?
        .to_string();

    Ok((new_session, Some(set_cookie)))
}
