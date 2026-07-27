//! Notify worker: `registerNotify` keepalive + inbound notify -> reader.
//!
//! A background task re-registers the AppView's notify endpoint before its TTL,
//! and consumes `NotifyJob`s (enqueued by the inbound notifyWrite handler) to
//! debounce and re-pull the affected repo.

use std::collections::HashMap;
use std::time::Duration;

use atproto_space::types::SpaceUri;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::error::{AppError, AppResult};
use crate::space::reader;
use crate::state::WebContext;

/// A job enqueued when an inbound `notifyWrite` is received.
#[derive(Debug, Clone)]
pub struct NotifyJob {
    /// The space the write occurred in.
    pub space: String,
    /// The repo (author DID) that was written.
    pub repo: String,
    /// The new commit rev.
    pub rev: String,
}

/// Background worker: drains `NotifyJob`s and re-pulls affected repos
/// (debounced), and periodically re-registers the notify endpoint.
///
/// Two concerns share the loop:
/// 1. **Keepalive** — re-`registerNotify` every `NOTIFY_REREGISTER_SECS` (and
///    once at startup) so the owner keeps fanning out to us.
/// 2. **Re-pull** — collect inbound jobs over a short debounce window, dedup by
///    repo, then call `reader::sync_repo` once per affected writer.
pub async fn run_notify_worker(
    ctx: WebContext,
    mut rx: mpsc::Receiver<NotifyJob>,
    cancel: CancellationToken,
) {
    let space = ctx.config.space_uri.clone();
    let debounce = Duration::from_millis(ctx.config.read_debounce_ms.max(1));
    let reregister = Duration::from_secs(ctx.config.notify_reregister_secs.max(1));

    // Initial registration (best effort).
    if let Some(space) = space.as_ref()
        && let Err(err) = register_notify_endpoint(&ctx, space).await
    {
        tracing::warn!(error = ?err, "initial registerNotify failed; relying on debounce/manual resync");
    }

    let keepalive = tokio::time::sleep(reregister);
    tokio::pin!(keepalive);

    // Pending re-pull jobs, deduplicated by repo (keep the latest rev).
    let mut pending: HashMap<String, NotifyJob> = HashMap::new();
    // The debounce deadline; `None` when no jobs are pending.
    let mut flush_at: Option<Instant> = None;

    loop {
        let flush_sleep = async {
            match flush_at {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                // Park forever until a job arrives and arms the deadline.
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = &mut keepalive => {
                if let Some(space) = space.as_ref()
                    && let Err(err) = register_notify_endpoint(&ctx, space).await
                {
                    tracing::warn!(error = ?err, "registerNotify keepalive failed");
                }
                keepalive.as_mut().reset(Instant::now() + reregister);
            }

            maybe_job = rx.recv() => {
                match maybe_job {
                    Some(job) => {
                        pending.insert(job.repo.clone(), job);
                        flush_at.get_or_insert_with(|| Instant::now() + debounce);
                    }
                    // Channel closed: drain remaining work and stop.
                    None => {
                        flush_pending(&ctx, &mut pending).await;
                        break;
                    }
                }
            }

            _ = flush_sleep => {
                flush_pending(&ctx, &mut pending).await;
                flush_at = None;
            }
        }
    }
}

/// Re-pull every pending repo once, clearing the queue.
async fn flush_pending(ctx: &WebContext, pending: &mut HashMap<String, NotifyJob>) {
    for (_repo, job) in pending.drain() {
        let space = match SpaceUri::parse(&job.space) {
            Ok(space) => space,
            Err(err) => {
                tracing::warn!(error = ?err, space = %job.space, "notify job had an invalid space uri");
                continue;
            }
        };
        let span = tracing::info_span!("notify_sync_repo", repo = %job.repo, rev = %job.rev);
        if let Err(err) = reader::sync_repo(ctx, &space, &job.repo)
            .instrument(span)
            .await
        {
            tracing::error!(error = ?err, repo = %job.repo, "notify-triggered sync_repo failed");
        }
    }
}

/// Register (or re-register) the AppView's notify endpoint for `space`.
///
/// POSTs `com.atproto.space.registerNotify` on the authority host (the space
/// owner's `#atproto_space_host`) with `Authorization: Bearer <space credential>`
/// and `endpoint` set to the **bare base origin** (the notifier appends
/// `/xrpc/com.atproto.space.notifyWrite`). `repo` is omitted for a whole-space
/// subscription.
///
/// The space credential is read from the cache (populated by the read path when
/// a member is active). When no credential is cached this returns an error and
/// the caller falls back to the §3.5 debounce / manual resync.
pub async fn register_notify_endpoint(ctx: &WebContext, space: &SpaceUri) -> AppResult<()> {
    let owner_did = ctx
        .config
        .space_owner_did
        .clone()
        .ok_or_else(|| AppError::Space("SPACE_OWNER_DID is not configured".to_string()))?;

    // Resolve the authority host (the owner's space-host endpoint).
    let doc = ctx
        .identity_resolver
        .resolve(&owner_did)
        .await
        .map_err(AppError::Other)?;
    let host = doc
        .service_endpoint("atproto_space_host")
        .or_else(|| doc.pds_endpoints().first().copied())
        .ok_or_else(|| {
            AppError::Space(format!(
                "owner {owner_did} exposes no atproto_space_host endpoint"
            ))
        })?
        .trim_end_matches('/')
        .to_string();

    // A cached space credential is required (Bearer auth on the authority host).
    let credential = crate::space::credential::get_cached_credential(
        &ctx.pool,
        space,
        &owner_did,
        ctx.config.space_cred_skew_secs,
    )
    .await?
    .ok_or_else(|| {
        AppError::Space(
            "no cached space credential available for registerNotify; awaiting a member read"
                .to_string(),
        )
    })?;

    let url = format!("{host}/xrpc/com.atproto.space.registerNotify");
    // The endpoint is the bare base origin ONLY; the notifier appends the path.
    let endpoint = ctx.config.external_base_url();
    let body = json!({
        "space": space.to_string(),
        "endpoint": endpoint,
    });

    let response = ctx
        .http_client
        .post(&url)
        .bearer_auth(&credential)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Space(format!("registerNotify request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(AppError::Space(format!(
            "registerNotify returned {status}: {text}"
        )));
    }

    tracing::info!(host = %host, endpoint = %endpoint, "registered notify endpoint");
    Ok(())
}
