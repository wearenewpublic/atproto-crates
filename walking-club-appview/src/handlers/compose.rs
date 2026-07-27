//! Compose handlers — the compose page and the event/post create endpoints.
//!
//! The compose page is server-rendered; the two create endpoints write the
//! member's own permissioned record into the space on the member's own PDS,
//! authorized by their OAuth+DPoP access token (writes are author-attributed —
//! the space credential is never used for writes). See plan §3.4.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::error::WebError;
use crate::oauth::session::{SessionCookie, get_authenticated_session};
use crate::space::writer;
use crate::state::WebContext;
use crate::xrpc::dpop_auth_from_session;

/// Event collection NSID.
const EVENT_COLLECTION: &str = "community.lexicon.calendar.event";
/// Post collection NSID.
const POST_COLLECTION: &str = "app.bsky.feed.post";

/// `GET /compose` — the compose form (members only).
pub async fn compose(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let session = get_authenticated_session(&ctx.config, &headers)?;
    let body = ctx.render_template(
        "compose.html",
        &json!({ "title": "Compose", "did": session.did }),
    )?;
    Ok(Html(body).into_response())
}

/// Request body for creating an event.
#[derive(Debug, Deserialize)]
pub struct EventForm {
    /// Event name.
    pub name: String,
    /// Start time (RFC3339).
    pub starts_at: String,
    /// End time (RFC3339), optional.
    pub ends_at: Option<String>,
}

/// `POST /api/compose/event` — create a calendar event in the space.
pub async fn create_event(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
    Json(form): Json<EventForm>,
) -> Result<Response, WebError> {
    let session = get_authenticated_session(&ctx.config, &headers)?;
    let (auth, host, space) = prepare_write(&ctx, &session).await?;

    let record = json!({
        "$type": EVENT_COLLECTION,
        "name": form.name,
        "startsAt": normalize_datetime(&form.starts_at),
        "endsAt": form.ends_at.as_deref().map(normalize_datetime),
        "createdAt": now_iso(),
    });

    let result = writer::create_event(&ctx.http_client, &auth, &host, &space, &session.did, record)
        .await
        .map_err(|e| WebError::Internal(anyhow::anyhow!("{e}")))?;

    Ok(Json(result).into_response())
}

/// Request body for creating a post.
#[derive(Debug, Deserialize)]
pub struct PostForm {
    /// Post text.
    pub text: String,
}

/// `POST /api/compose/post` — create a feed post in the space.
pub async fn create_post(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
    Json(form): Json<PostForm>,
) -> Result<Response, WebError> {
    let session = get_authenticated_session(&ctx.config, &headers)?;
    let (auth, host, space) = prepare_write(&ctx, &session).await?;

    let record = json!({
        "$type": POST_COLLECTION,
        "text": form.text,
        "createdAt": now_iso(),
    });

    let result = writer::create_post(&ctx.http_client, &auth, &host, &space, &session.did, record)
        .await
        .map_err(|e| WebError::Internal(anyhow::anyhow!("{e}")))?;

    Ok(Json(result).into_response())
}

/// Resolve the prerequisites shared by both write paths: the member's DPoP auth
/// rebuilt from the session, their own PDS host, and the configured space URI.
async fn prepare_write(
    ctx: &WebContext,
    session: &SessionCookie,
) -> Result<
    (
        atproto_client::client::DPoPAuth,
        String,
        atproto_space::types::SpaceUri,
    ),
    WebError,
> {
    let space = ctx
        .config
        .space_uri
        .clone()
        .ok_or_else(|| WebError::BadRequest("no space configured".into()))?;

    let doc = ctx
        .identity_resolver
        .resolve(&session.did)
        .await
        .map_err(|e| WebError::Internal(anyhow::anyhow!("resolve member did: {e}")))?;
    let host = doc
        .pds_endpoints()
        .first()
        .map(|s| s.to_string())
        .ok_or_else(|| WebError::BadRequest("member has no PDS endpoint".into()))?;

    let auth =
        dpop_auth_from_session(session).map_err(|e| WebError::Internal(anyhow::anyhow!("{e}")))?;

    Ok((auth, host, space))
}

/// Current time as an ISO-8601 / RFC3339 UTC string.
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Best-effort normalization of an HTML `datetime-local` value (no zone) to
/// RFC3339. Values that already parse as RFC3339 are returned unchanged.
fn normalize_datetime(value: &str) -> String {
    if chrono::DateTime::parse_from_rfc3339(value).is_ok() {
        return value.to_string();
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M") {
        return naive
            .and_utc()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }
    value.to_string()
}
