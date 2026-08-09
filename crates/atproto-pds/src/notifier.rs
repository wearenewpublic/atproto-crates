//! Spaces notifier — `notifyWrite` outbound delivery.
//!
//! Spaces writes don't fan out via the public firehose; instead the owner's
//! PDS POSTs the contentless `notifyWrite` payload to each consumer service
//! that holds a current `SpaceCredential`. The set of recipient services lives
//! in the per-actor `space_credential_recipient` table; delivery attempts
//! (with retry + exponential backoff) live in the shared `notify_attempt` DLQ.
//!
//! This module ships:
//!
//! - [`enqueue_notification`] — append a delivery attempt to the DLQ.
//! - [`Notifier`] — background worker that drains due rows, POSTs them, and
//!   retries on failure with exponential backoff.
//!
//! Configuration knobs (see `PDS_SPACE_NOTIFY_*` env vars):
//!
//! - `max_attempts` — give-up threshold (default 8 → ~1.5h with backoff).
//! - `initial_backoff_ms` — first retry delay (default 1000ms).
//! - `timeout` — per-delivery HTTP timeout (default 10s), applied by
//!   [`build_client`]. Deliveries run serially in a background task that no
//!   request timeout covers, so this is what stops one unresponsive recipient
//!   from stalling every other space's notifications.

use crate::errors::{PdsError, PdsResult};
use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Default initial retry backoff (1s).
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 1000;
/// Default max retry attempts (8 → cumulative ~1.5h with exponential backoff).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;
/// Default per-delivery HTTP timeout (10s).
///
/// The value matters more here than the number does. `reqwest` applies no
/// timeout unless asked, and [`Notifier::tick`] delivers its batch serially in
/// a background task -- the one outbound path on the server that no request
/// timeout covers. A recipient that accepts the connection and then never
/// answers therefore stops the notifier permanently, and every other space's
/// notifications queue behind it. Ten seconds is generous for a `notifyWrite`
/// POST that carries no content; a recipient slower than that is failing, and
/// the backoff is the right place to absorb it.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Build the notifier's HTTP client.
///
/// One constructor so the timeout cannot be configured in one call site and
/// forgotten in the other -- which is exactly how the untimed client survived:
/// [`Notifier::default`] and the binary's worker each built their own.
#[must_use]
pub fn build_client(timeout: std::time::Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(timeout)
        // A separate, shorter bound on connection setup. The total timeout
        // above already covers it, but a recipient whose DNS or TCP hangs is
        // unreachable rather than slow, and there is nothing to wait for.
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        // `build()` fails only on TLS backend initialisation. A client with no
        // timeout is the very thing this exists to prevent, so fall back to
        // one that at least keeps the bound.
        .unwrap_or_else(|e| {
            tracing::warn!(error = ?e, "notifier HTTP client build failed; using defaults");
            reqwest::Client::new()
        })
}

/// State enum for `notify_attempt.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttemptState {
    /// Not yet attempted, or scheduled for retry.
    Pending,
    /// Successfully delivered.
    Delivered,
    /// Permanent failure (max attempts reached).
    Failed,
}

impl AttemptState {
    /// String form for SQL persistence + log lines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptState::Pending => "pending",
            AttemptState::Delivered => "delivered",
            AttemptState::Failed => "failed",
        }
    }
}

/// Append a notify-attempt row.
///
/// `payload` is the request body the consumer will see (JSON for the
/// contentless notifyWrite); `nsid` selects the worker's POST URL;
/// `content_type` is the request `Content-Type`; `auth_token`, when present,
/// is delivered as a `Bearer` service-auth header.
pub async fn enqueue_notification(
    pool: &SqlitePool,
    target_service_did: &str,
    target_endpoint: &str,
    payload: Vec<u8>,
    nsid: &str,
    content_type: &str,
    auth_token: Option<&str>,
) -> PdsResult<String> {
    let id = format!("n-{}-{}", Utc::now().timestamp_millis(), random_suffix(8));
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO notify_attempt
         (id, target_service_did, target_endpoint, payload_cbor, nsid,
          content_type, auth_token, attempt_count, next_attempt_at, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'pending')",
    )
    .bind(&id)
    .bind(target_service_did)
    .bind(target_endpoint)
    .bind(&payload)
    .bind(nsid)
    .bind(content_type)
    .bind(auth_token)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("enqueue_notification: {e}"),
    })?;
    Ok(id)
}

/// One row from `notify_attempt` ready to be acted on.
#[derive(Debug, Clone)]
pub struct DueAttempt {
    /// Row primary key.
    pub id: String,
    /// DID of the receiving service.
    pub target_service_did: String,
    /// HTTPS endpoint base of the receiving service.
    pub target_endpoint: String,
    /// Request body bytes (DAG-CBOR or JSON depending on `content_type`).
    pub payload_cbor: Vec<u8>,
    /// XRPC NSID — appended to the endpoint to compose the POST URL.
    pub nsid: String,
    /// Request `Content-Type` header.
    pub content_type: String,
    /// Optional `Bearer` service-auth token.
    pub auth_token: Option<String>,
    /// How many times we've already tried this row.
    pub attempt_count: u32,
}

/// Raw row shape returned by the `due_now` query (id, service_did, endpoint,
/// payload, nsid, content_type, auth_token, attempt_count).
type DueRow = (
    String,
    String,
    String,
    Vec<u8>,
    String,
    String,
    Option<String>,
    i64,
);

/// Read all `pending` rows whose `next_attempt_at <= now`. Caller is
/// responsible for marking each row as delivered/failed/retry after the POST.
pub async fn due_now(pool: &SqlitePool, limit: u32) -> PdsResult<Vec<DueAttempt>> {
    let now = Utc::now().to_rfc3339();
    let limit = limit.clamp(1, 1000);
    let rows: Vec<DueRow> = sqlx::query_as(
        "SELECT id, target_service_did, target_endpoint, payload_cbor, nsid,
                    content_type, auth_token, attempt_count
             FROM notify_attempt
             WHERE state = 'pending' AND next_attempt_at <= ?
             ORDER BY next_attempt_at ASC
             LIMIT ?",
    )
    .bind(&now)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("due_now: {e}"),
    })?;
    Ok(rows
        .into_iter()
        .map(
            |(id, did, endpoint, payload, nsid, content_type, auth_token, attempts)| DueAttempt {
                id,
                target_service_did: did,
                target_endpoint: endpoint,
                payload_cbor: payload,
                nsid,
                content_type,
                auth_token,
                attempt_count: attempts as u32,
            },
        )
        .collect())
}

/// Mark a row as `delivered` (terminal success).
pub async fn mark_delivered(pool: &SqlitePool, id: &str) -> PdsResult<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE notify_attempt
         SET state = 'delivered', last_attempt_at = ?, attempt_count = attempt_count + 1
         WHERE id = ?",
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("mark_delivered: {e}"),
    })?;
    Ok(())
}

/// Schedule a retry with exponential backoff, OR mark as `failed` if
/// `max_attempts` has been reached.
pub async fn record_failure(
    pool: &SqlitePool,
    id: &str,
    error: &str,
    initial_backoff_ms: u64,
    max_attempts: u32,
) -> PdsResult<AttemptState> {
    let now = Utc::now();
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT attempt_count FROM notify_attempt WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("record_failure select: {e}"),
            })?;
    let next_count = row.map(|(c,)| c as u32 + 1).unwrap_or(1);

    if next_count >= max_attempts {
        sqlx::query(
            "UPDATE notify_attempt
             SET state = 'failed', last_attempt_at = ?, last_error = ?,
                 attempt_count = ?
             WHERE id = ?",
        )
        .bind(now.to_rfc3339())
        .bind(error)
        .bind(next_count as i64)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("record_failure mark failed: {e}"),
        })?;
        return Ok(AttemptState::Failed);
    }

    let backoff_ms = initial_backoff_ms.saturating_mul(2u64.saturating_pow(next_count));
    let next_at: DateTime<Utc> = now + chrono::Duration::milliseconds(backoff_ms as i64);
    sqlx::query(
        "UPDATE notify_attempt
         SET state = 'pending', last_attempt_at = ?, last_error = ?,
             attempt_count = ?, next_attempt_at = ?
         WHERE id = ?",
    )
    .bind(now.to_rfc3339())
    .bind(error)
    .bind(next_count as i64)
    .bind(next_at.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("record_failure schedule retry: {e}"),
    })?;
    Ok(AttemptState::Pending)
}

/// Delivery worker.
///
/// Holds a reqwest client + the configured backoff + max-attempts knobs.
/// Call [`Notifier::tick`] from a periodic task; each tick drains up to
/// `batch_size` due rows.
#[derive(Clone)]
pub struct Notifier {
    /// HTTP client for outbound POSTs.
    pub client: reqwest::Client,
    /// First-retry backoff in milliseconds.
    pub initial_backoff_ms: u64,
    /// Max retry attempts before giving up.
    pub max_attempts: u32,
    /// How many due rows to drain per tick.
    pub batch_size: u32,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            client: build_client(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            batch_size: 50,
        }
    }
}

impl Notifier {
    /// Drain one batch of due notifications. Returns the count delivered.
    pub async fn tick(&self, pool: &SqlitePool) -> PdsResult<u32> {
        let due = due_now(pool, self.batch_size).await?;
        let mut delivered = 0u32;
        for attempt in due {
            let endpoint = format!("{}/xrpc/{}", attempt.target_endpoint, attempt.nsid);
            let mut req = self
                .client
                .post(&endpoint)
                .header(reqwest::header::CONTENT_TYPE, attempt.content_type.clone())
                .body(attempt.payload_cbor.clone());
            if let Some(token) = attempt.auth_token.as_deref() {
                req = req.bearer_auth(token);
            }
            let result = req.send().await;
            match result {
                Ok(resp) if resp.status().is_success() => {
                    mark_delivered(pool, &attempt.id).await?;
                    delivered += 1;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let _ = record_failure(
                        pool,
                        &attempt.id,
                        &format!("HTTP {status}"),
                        self.initial_backoff_ms,
                        self.max_attempts,
                    )
                    .await?;
                }
                Err(e) => {
                    let _ = record_failure(
                        pool,
                        &attempt.id,
                        &format!("transport: {e}"),
                        self.initial_backoff_ms,
                        self.max_attempts,
                    )
                    .await?;
                }
            }
        }
        Ok(delivered)
    }
}

fn random_suffix(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let mut buf = [0u8; 1];
        rng.fill(&mut buf);
        out.push(ALPHABET[(buf[0] as usize) % ALPHABET.len()] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    async fn fresh_pool() -> SqlitePool {
        let dir = AccountDirectory::open_memory().await.unwrap();
        dir.pool().clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unresponsive_recipient_does_not_stall_the_notifier() {
        // A recipient that completes the TCP handshake and then says nothing.
        // This is the case `reqwest` waits on forever when no timeout is set,
        // and the reason it matters here is that `tick` delivers serially in a
        // background task: one of these used to stop the notifier for good.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let black_hole = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                // Hold the connection open and never write a response.
                held.push(socket);
            }
        });

        let pool = fresh_pool().await;
        enqueue_notification(
            &pool,
            "did:web:black-hole.example",
            &format!("http://{addr}"),
            b"payload-bytes".to_vec(),
            "com.atproto.space.notifyWrite",
            "application/json",
            None,
        )
        .await
        .unwrap();

        let notifier = Notifier {
            client: build_client(std::time::Duration::from_millis(300)),
            ..Notifier::default()
        };

        // An outer timeout so a regression fails the test instead of hanging
        // the suite -- "waits forever" is the failure mode under test.
        let delivered =
            tokio::time::timeout(std::time::Duration::from_secs(5), notifier.tick(&pool))
                .await
                .expect("tick must return; without a timeout it waits on this recipient forever")
                .unwrap();

        assert_eq!(delivered, 0, "nothing was delivered");

        // The row is a failure to retry, not one silently dropped, and the
        // backoff has taken it out of the due set for now.
        let due = due_now(&pool, 100).await.unwrap();
        assert!(
            due.is_empty(),
            "the failed delivery should be backed off, not immediately due again"
        );

        black_hole.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enqueue_then_due_round_trip() {
        let pool = fresh_pool().await;
        let id = enqueue_notification(
            &pool,
            "did:web:appview.example",
            "https://appview.example",
            b"payload-bytes".to_vec(),
            "com.atproto.space.notifyWrite",
            "application/json",
            None,
        )
        .await
        .unwrap();
        let due = due_now(&pool, 100).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].nsid, "com.atproto.space.notifyWrite");
        assert_eq!(due[0].attempt_count, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delivered_rows_are_filtered_out() {
        let pool = fresh_pool().await;
        let id = enqueue_notification(
            &pool,
            "did:web:x",
            "https://x.example",
            b"data".to_vec(),
            "com.atproto.space.notifyWrite",
            "application/json",
            None,
        )
        .await
        .unwrap();
        mark_delivered(&pool, &id).await.unwrap();
        let due = due_now(&pool, 100).await.unwrap();
        assert_eq!(due.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_failure_reschedules_with_backoff() {
        let pool = fresh_pool().await;
        let id = enqueue_notification(
            &pool,
            "did:web:x",
            "https://x.example",
            b"data".to_vec(),
            "com.atproto.space.notifyWrite",
            "application/json",
            None,
        )
        .await
        .unwrap();
        let state = record_failure(&pool, &id, "HTTP 503", 100, 8)
            .await
            .unwrap();
        assert_eq!(state, AttemptState::Pending);
        // Row still pending but next_attempt_at is now in the future, so
        // due_now should not return it immediately.
        let due = due_now(&pool, 100).await.unwrap();
        assert_eq!(due.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_failure_caps_at_max_attempts() {
        let pool = fresh_pool().await;
        let id = enqueue_notification(
            &pool,
            "did:web:x",
            "https://x.example",
            b"data".to_vec(),
            "com.atproto.space.notifyWrite",
            "application/json",
            None,
        )
        .await
        .unwrap();
        // After 2 failures with max=2 the row goes to `failed`.
        record_failure(&pool, &id, "fail-1", 10, 2).await.unwrap();
        let final_state = record_failure(&pool, &id, "fail-2", 10, 2).await.unwrap();
        assert_eq!(final_state, AttemptState::Failed);
    }
}
