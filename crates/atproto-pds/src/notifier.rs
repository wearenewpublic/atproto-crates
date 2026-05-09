//! Spaces notifier — `notifyWrite` / `notifyMembership` outbound delivery.
//!
//!  Spaces
//! writes don't fan out via the public firehose; instead the owner's PDS
//! POSTs the signed `notifyWrite` (records) and `notifyMembership` (member
//! list) payloads to each consumer service that holds a current
//! `SpaceCredential`. The set of recipient services lives in the per-actor
//! `space_credential_recipient` table; delivery attempts (with retry +
//! exponential backoff) live in the shared `notify_attempt` DLQ.
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

use crate::errors::{PdsError, PdsResult};
use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Default initial retry backoff (1s).
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 1000;
/// Default max retry attempts (8 → cumulative ~1.5h with exponential backoff).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

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
/// `payload_cbor` is the dag-cbor-encoded request body the consumer will see;
/// `nsid` distinguishes `com.atproto.space.notifyWrite` vs
/// `com.atproto.space.notifyMembership` for the worker's POST.
pub async fn enqueue_notification(
    pool: &SqlitePool,
    target_service_did: &str,
    target_endpoint: &str,
    payload_cbor: Vec<u8>,
    nsid: &str,
) -> PdsResult<String> {
    let id = format!("n-{}-{}", Utc::now().timestamp_millis(), random_suffix(8));
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO notify_attempt
         (id, target_service_did, target_endpoint, payload_cbor, nsid,
          attempt_count, next_attempt_at, state)
         VALUES (?, ?, ?, ?, ?, 0, ?, 'pending')",
    )
    .bind(&id)
    .bind(target_service_did)
    .bind(target_endpoint)
    .bind(&payload_cbor)
    .bind(nsid)
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
    /// DAG-CBOR-encoded request body.
    pub payload_cbor: Vec<u8>,
    /// XRPC NSID — appended to the endpoint to compose the POST URL.
    pub nsid: String,
    /// How many times we've already tried this row.
    pub attempt_count: u32,
}

/// Read all `pending` rows whose `next_attempt_at <= now`. Caller is
/// responsible for marking each row as delivered/failed/retry after the POST.
pub async fn due_now(pool: &SqlitePool, limit: u32) -> PdsResult<Vec<DueAttempt>> {
    let now = Utc::now().to_rfc3339();
    let limit = limit.clamp(1, 1000);
    let rows: Vec<(String, String, String, Vec<u8>, String, i64)> = sqlx::query_as(
        "SELECT id, target_service_did, target_endpoint, payload_cbor, nsid, attempt_count
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
        .map(|(id, did, endpoint, payload, nsid, attempts)| DueAttempt {
            id,
            target_service_did: did,
            target_endpoint: endpoint,
            payload_cbor: payload,
            nsid,
            attempt_count: attempts as u32,
        })
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
            client: reqwest::Client::new(),
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
            let result = self
                .client
                .post(&endpoint)
                .header(reqwest::header::CONTENT_TYPE, "application/cbor")
                .body(attempt.payload_cbor.clone())
                .send()
                .await;
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
    async fn enqueue_then_due_round_trip() {
        let pool = fresh_pool().await;
        let id = enqueue_notification(
            &pool,
            "did:web:appview.example",
            "https://appview.example",
            b"payload-bytes".to_vec(),
            "com.atproto.space.notifyWrite",
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
        )
        .await
        .unwrap();
        // After 2 failures with max=2 the row goes to `failed`.
        record_failure(&pool, &id, "fail-1", 10, 2).await.unwrap();
        let final_state = record_failure(&pool, &id, "fail-2", 10, 2).await.unwrap();
        assert_eq!(final_state, AttemptState::Failed);
    }
}
