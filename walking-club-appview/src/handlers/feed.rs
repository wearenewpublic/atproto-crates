//! Feed handlers — full page + the poll-able HTML fragment.
//!
//! Both handlers read the server-side projection tables (`events`, `posts`)
//! for the configured space and render minijinja templates. The full page wraps
//! the fragment in `feed.html`; `/feed/fragment` returns the bare fragment for
//! the inline-JS `setInterval` live poll (no JSON API, no build step). The feed
//! is members-only: a valid session cookie is required.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde_json::{Value, json};

use crate::error::WebError;
use crate::oauth::session::get_session_from_headers;
use crate::state::WebContext;

/// Maximum number of events / posts rendered per load.
const FEED_LIMIT: i64 = 100;

/// `GET /feed` — the full feed page (events + posts).
pub async fn feed(State(ctx): State<WebContext>, headers: HeaderMap) -> Result<Response, WebError> {
    // Members-only: require a session, otherwise bounce to the landing page.
    if get_session_from_headers(&ctx.config, &headers).is_none() {
        return Ok(Redirect::to("/").into_response());
    }

    let (events, posts) = load_feed(&ctx).await?;
    let body = ctx.render_template(
        "feed.html",
        &json!({ "title": "Feed", "events": events, "posts": posts }),
    )?;
    Ok(Html(body).into_response())
}

/// `GET /feed/fragment` — the HTML fragment polled by the feed page.
pub async fn feed_fragment(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    if get_session_from_headers(&ctx.config, &headers).is_none() {
        return Err(WebError::Unauthorized);
    }

    let (events, posts) = load_feed(&ctx).await?;
    let body = ctx.render_template(
        "feed_fragment.html",
        &json!({ "events": events, "posts": posts }),
    )?;
    Ok(Html(body).into_response())
}

/// Load the projected events + posts for the configured space, newest first.
///
/// Returns `(events, posts)` as JSON arrays ready for template rendering. When
/// no space is configured both lists are empty.
async fn load_feed(ctx: &WebContext) -> Result<(Vec<Value>, Vec<Value>), WebError> {
    let Some(space) = ctx.config.space_uri.as_ref().map(|s| s.to_string()) else {
        return Ok((Vec::new(), Vec::new()));
    };

    let event_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT writer_did, rkey, name, starts_at, ends_at \
         FROM events WHERE space = ?1 \
         ORDER BY COALESCE(starts_at, indexed_at) DESC LIMIT ?2",
    )
    .bind(&space)
    .bind(FEED_LIMIT)
    .fetch_all(&ctx.pool)
    .await?;

    let events = event_rows
        .into_iter()
        .map(|(writer_did, rkey, name, starts_at, ends_at)| {
            json!({
                "writer_did": writer_did,
                "rkey": rkey,
                "name": name,
                "starts_at": starts_at,
                "ends_at": ends_at,
            })
        })
        .collect::<Vec<_>>();

    let post_rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT writer_did, rkey, text_body, created_at \
         FROM posts WHERE space = ?1 \
         ORDER BY COALESCE(created_at, indexed_at) DESC LIMIT ?2",
    )
    .bind(&space)
    .bind(FEED_LIMIT)
    .fetch_all(&ctx.pool)
    .await?;

    let posts = post_rows
        .into_iter()
        .map(|(writer_did, rkey, text_body, created_at)| {
            json!({
                "writer_did": writer_did,
                "rkey": rkey,
                "text_body": text_body,
                "created_at": created_at,
            })
        })
        .collect::<Vec<_>>();

    Ok((events, posts))
}
