//! `GET /.well-known/atproto-did` — the AppView's atproto DID.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::state::WebContext;

/// `GET /.well-known/atproto-did` — plain-text did:web identifier.
///
/// The owner fetches this during notify-recipient resolution (plan §3.2, §3.6).
pub async fn atproto_did(State(ctx): State<WebContext>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        ctx.config.appview_did(),
    )
        .into_response()
}
