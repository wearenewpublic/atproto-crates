//! Admin handlers — writer-set view + force-resync (basic-auth gated).
//!
//! Gated by HTTP Basic auth against `ADMIN_PASSWORD` (username ignored). Renders
//! the current writer set (from the `writers` projection table) for the
//! configured space so an operator can inspect cursors and trigger a resync.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::error::WebError;
use crate::state::WebContext;

/// `GET /admin` — admin dashboard (writer set + resync entry point).
pub async fn admin_index(
    State(ctx): State<WebContext>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    if !check_basic_auth(&ctx, &headers) {
        return Ok((
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"walking-club-admin\"",
            )],
            "Unauthorized",
        )
            .into_response());
    }

    let space = ctx.config.space_uri.as_ref().map(|s| s.to_string());

    let writers = match &space {
        Some(space) => {
            let rows = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ),
            >(
                "SELECT writer_did, rev, pds_host, cursor, last_commit_hash, verified_at \
                 FROM writers WHERE space = ?1 ORDER BY writer_did",
            )
            .bind(space)
            .fetch_all(&ctx.pool)
            .await?;
            rows.into_iter()
                .map(
                    |(writer_did, rev, pds_host, cursor, last_commit_hash, verified_at)| {
                        json!({
                            "writer_did": writer_did,
                            "rev": rev,
                            "pds_host": pds_host,
                            "cursor": cursor,
                            "last_commit_hash": last_commit_hash,
                            "verified_at": verified_at,
                        })
                    },
                )
                .collect::<Vec<_>>()
        }
        None => Vec::new(),
    };

    let body = ctx.render_template(
        "admin/index.html",
        &json!({ "title": "Admin", "space": space, "writers": writers }),
    )?;
    Ok(Html(body).into_response())
}

/// Verify the `Authorization: Basic` header against `ADMIN_PASSWORD`.
///
/// Returns `false` when no admin password is configured (admin disabled), the
/// header is missing/malformed, or the password does not match. The username
/// component is ignored; the password is compared in constant time.
fn check_basic_auth(ctx: &WebContext, headers: &HeaderMap) -> bool {
    let Some(expected) = ctx.config.admin_password.as_ref() else {
        return false;
    };
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(b64) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = BASE64_STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(creds) = String::from_utf8(decoded) else {
        return false;
    };
    let password = creds.split_once(':').map(|(_, p)| p).unwrap_or("");
    password.as_bytes().ct_eq(expected.as_bytes()).into()
}
