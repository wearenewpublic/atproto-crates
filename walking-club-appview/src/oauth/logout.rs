//! OAuth logout: clear both the session and identity cookies.

use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};

use crate::error::WebError;
use crate::oauth::session::{IDENTITY_COOKIE_NAME, SESSION_COOKIE_NAME, build_clear_cookie_header};
use crate::state::WebContext;

/// `POST /auth/logout` — clear both cookies and redirect home.
pub async fn logout(State(ctx): State<WebContext>) -> Result<Response, WebError> {
    let domain = &ctx.config.http_external_base;
    let mut headers = HeaderMap::new();
    // http_only flags must match how each cookie was originally set.
    if let Ok(clear_session) = build_clear_cookie_header(SESSION_COOKIE_NAME, domain, true) {
        headers.append(header::SET_COOKIE, clear_session);
    }
    if let Ok(clear_identity) = build_clear_cookie_header(IDENTITY_COOKIE_NAME, domain, false) {
        headers.append(header::SET_COOKIE, clear_identity);
    }
    Ok((headers, Redirect::to("/")).into_response())
}
