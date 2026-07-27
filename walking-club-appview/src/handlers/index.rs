//! Landing page handler.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use serde_json::json;

use crate::error::WebError;
use crate::oauth::session::get_session_from_headers;
use crate::state::WebContext;

/// `GET /` — landing page with login entry point.
///
/// Shows the login form to anonymous visitors and a short "you are signed in"
/// summary (with links to the feed and compose) when a valid session cookie is
/// present.
pub async fn index(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let session = get_session_from_headers(&ctx.config, &headers);
    let body = ctx.render_template(
        "index.html",
        &json!({
            "title": "Walking Club",
            "space_uri": ctx.config.space_uri.as_ref().map(|s| s.to_string()),
            "logged_in": session.is_some(),
            "did": session.as_ref().map(|s| s.did.clone()),
        }),
    )?;
    Ok(Html(body).into_response())
}
