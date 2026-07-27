//! Inbound `com.atproto.space.notifyWrite` handler.
//!
//! The owner PDS POSTs a contentless notify authenticated with AT-Proto service
//! auth. After verifying `aud`/`lxm`/signature, the AppView enqueues a
//! `NotifyJob` so the notify worker re-pulls the affected repo.

use atproto_xrpcs::authorization::Authorization;
use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::error::WebError;
use crate::state::WebContext;

/// The lexicon method this endpoint authorizes against.
const NOTIFY_WRITE_LXM: &str = "com.atproto.space.notifyWrite";

/// Body of `com.atproto.space.notifyWrite`.
#[derive(Debug, Deserialize)]
pub struct NotifyWritePayload {
    /// The space the write occurred in.
    pub space: String,
    /// The repo (author DID) that was written.
    pub repo: String,
    /// The new commit rev.
    pub rev: String,
}

/// `POST /xrpc/com.atproto.space.notifyWrite` — accept an inbound notify.
///
/// Verifies AT-Proto service auth (`aud == appview_did`, `lxm == notifyWrite`,
/// signature valid), guards against `jti` replay, enqueues a `NotifyJob`, and
/// returns `200` immediately so a slow re-pull never times out the notifier.
pub async fn notify_write(
    State(ctx): State<WebContext>,
    auth: Option<Authorization>,
    Json(payload): Json<NotifyWritePayload>,
) -> Result<Response, WebError> {
    ctx.metrics.notify_total.inc();

    let auth = auth.ok_or(WebError::Unauthorized)?;
    check_service_auth(&ctx, &auth)?;

    // Replay guard: a fresh `jti` must not have been seen before. Tokens without
    // a `jti` are rejected so an attacker cannot bypass the guard entirely.
    let jti = auth
        .1
        .jose
        .json_web_token_id
        .as_deref()
        .ok_or(WebError::Unauthorized)?;
    if !claim_jti(&ctx, jti).await? {
        // Already processed; treat as a successful no-op (idempotent).
        return Ok(Json(json!({})).into_response());
    }

    let job = crate::space::notify::NotifyJob {
        space: payload.space,
        repo: payload.repo,
        rev: payload.rev,
    };
    if let Err(err) = ctx.notify_tx.try_send(job) {
        tracing::warn!(error = ?err, "notify queue full or closed; dropping job");
    }

    Ok(Json(json!({})).into_response())
}

/// Assert the verified service-auth claims target this AppView.
///
/// Requires the JWT to validate against the issuer's DID keys (the `Authorization`
/// extractor's validation flag), `aud` to equal this AppView's `did:web` DID, and
/// `lxm` to equal `com.atproto.space.notifyWrite`.
pub fn check_service_auth(ctx: &WebContext, auth: &Authorization) -> Result<(), WebError> {
    // `auth.3` is the extractor's signature-validation flag.
    if !auth.3 {
        return Err(WebError::Unauthorized);
    }

    let expected_aud = ctx.config.appview_did();
    let aud = auth
        .1
        .jose
        .audience
        .as_deref()
        .ok_or(WebError::Unauthorized)?;
    if aud != expected_aud {
        tracing::warn!(aud = %aud, expected = %expected_aud, "notify aud mismatch");
        return Err(WebError::Unauthorized);
    }

    // `lxm` (lexicon method) is a private claim.
    let lxm = auth
        .1
        .private
        .get("lxm")
        .and_then(|v| v.as_str())
        .ok_or(WebError::Unauthorized)?;
    if lxm != NOTIFY_WRITE_LXM {
        tracing::warn!(lxm = %lxm, "notify lxm mismatch");
        return Err(WebError::Unauthorized);
    }

    Ok(())
}

/// Atomically record a `jti` as seen. Returns `true` if it was newly inserted
/// (i.e. not a replay), `false` if it was already present.
async fn claim_jti(ctx: &WebContext, jti: &str) -> Result<bool, WebError> {
    let now = chrono::Utc::now().to_rfc3339();
    let result = sqlx::query("INSERT OR IGNORE INTO notify_jti (jti, seen_at) VALUES (?, ?)")
        .bind(jti)
        .bind(now)
        .execute(&ctx.pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
