//! Outbox reader and event types for the per-actor sequencer.
//!
//! The `outbox` table is per-actor under the SQLite profile (see G2). Each
//! row carries one firehose event encoded as DAG-CBOR plus a monotonic `seq`
//! and an `event_type` discriminator.

use crate::errors::{PdsError, PdsResult};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Firehose event-type discriminator from the `com.atproto.sync.subscribeRepos` lexicon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Repo update: CAR diff + ops list (Sync 1.1 includes `prevData`).
    Commit,
    /// Sync 1.1: force-set repo state without diff.
    Sync,
    /// DID document or handle change.
    Identity,
    /// Account state change (`active` + optional `status`).
    Account,
    /// Out-of-band info (e.g., `OutdatedCursor`).
    Info,
}

impl EventType {
    /// String form for SQL persistence.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Commit => "commit",
            EventType::Sync => "sync",
            EventType::Identity => "identity",
            EventType::Account => "account",
            EventType::Info => "info",
        }
    }

    /// Parse from string. Returns `None` on unknown.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "commit" => Some(EventType::Commit),
            "sync" => Some(EventType::Sync),
            "identity" => Some(EventType::Identity),
            "account" => Some(EventType::Account),
            "info" => Some(EventType::Info),
            _ => None,
        }
    }
}

/// One outbox row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRow {
    /// Monotonic sequence number (per-actor under SQLite profile).
    pub seq: i64,
    /// Event type.
    pub event_type: EventType,
    /// DAG-CBOR-encoded event payload.
    pub payload: Vec<u8>,
    /// ISO-8601 timestamp of publication.
    pub created_at: String,
}

/// Wire-frame for a `subscribeRepos` event sent to subscribers.
///
/// CBOR is the spec-default frame encoding; JSON is a browser-dev
/// convenience kept on purpose (see `sequencer::frame::Encoding`,
/// where the rationale lives in the variant docs). Negotiation is
/// handled in `sequencer::frame::Encoding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFrame {
    /// Event-type tag.
    pub t: String,
    /// Sequence number.
    pub seq: i64,
    /// Repo DID this event pertains to.
    pub did: String,
    /// Payload — raw bytes for CBOR clients, JSON for debug clients.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Created-at timestamp.
    pub time: String,
}

/// Read-side of the per-actor outbox.
///
/// Supports paginated backfill-by-cursor; the live-tail broadcast
/// channel + writer side live alongside in `Sequencer::publish` and
/// the `EventBus`.
///
/// Two backends:
///
/// - **Legacy SQL path** (`OutboxReader::new(pool)`) — binds to a
///   per-actor SQLite pool. Used by the bulk of the codebase
///   pre-.
/// - **Dispatch path** (`OutboxReader::dispatch(storage, did)`) —
///   routes through the `OutboxStorage` trait surface for either
///   SQLite or fjall. Used by code paths that have a
///   `PublicRealmBackend` wired.
pub enum OutboxReader {
    /// Legacy SQLite-pool backend.
    Sql {
        /// Per-actor SQLite pool.
        pool: SqlitePool,
    },
    /// Trait-dispatch backend.
    Dispatch {
        /// Backend storage.
        storage: std::sync::Arc<dyn crate::actor_store::OutboxStorage>,
        /// DID this reader is bound to.
        did: String,
    },
}

impl OutboxReader {
    /// Construct over a per-actor pool. **Legacy** — prefer
    /// [`Self::dispatch`] when a `PublicRealmBackend` is available.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self::Sql { pool }
    }

    /// Construct over a trait-dispatch backend. The `did` is bound
    /// once and threaded through every method, matching the per-DID
    /// scope of the legacy pool form.
    #[must_use]
    pub fn dispatch(
        storage: std::sync::Arc<dyn crate::actor_store::OutboxStorage>,
        did: impl Into<String>,
    ) -> Self {
        Self::Dispatch {
            storage,
            did: did.into(),
        }
    }

    /// Read up to `limit` events with `seq > cursor`. `cursor=None` reads
    /// from the beginning.
    pub async fn read_after(&self, cursor: Option<i64>, limit: u32) -> PdsResult<Vec<OutboxRow>> {
        let limit = limit.clamp(1, 1000);
        match self {
            Self::Sql { pool } => {
                let rows: Vec<(i64, String, Vec<u8>, String)> = match cursor {
                    Some(c) => {
                        sqlx::query_as(
                            "SELECT seq, event_type, payload, created_at
                         FROM outbox WHERE seq > ?
                         ORDER BY seq ASC LIMIT ?",
                        )
                        .bind(c)
                        .bind(limit as i64)
                        .fetch_all(pool)
                        .await
                    }
                    None => {
                        sqlx::query_as(
                            "SELECT seq, event_type, payload, created_at
                         FROM outbox ORDER BY seq ASC LIMIT ?",
                        )
                        .bind(limit as i64)
                        .fetch_all(pool)
                        .await
                    }
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("outbox read_after: {e}"),
                })?;
                Ok(rows
                    .into_iter()
                    .map(|(seq, event_type, payload, created_at)| OutboxRow {
                        seq,
                        event_type: EventType::parse(&event_type).unwrap_or(EventType::Info),
                        payload,
                        created_at,
                    })
                    .collect())
            }
            Self::Dispatch { storage, did } => {
                // Trait-side seq is u64; legacy clients pass i64 cursors.
                // Normalize at the boundary.
                let after = cursor.map(|c| c.max(0) as u64);
                let rows = storage.read_after(did, after, limit).await?;
                Ok(rows
                    .into_iter()
                    .map(|r| OutboxRow {
                        seq: r.seq.min(i64::MAX as u64) as i64,
                        event_type: EventType::parse(&r.event_type).unwrap_or(EventType::Info),
                        payload: r.payload,
                        created_at: r.created_at,
                    })
                    .collect())
            }
        }
    }

    /// Highest `seq` currently stored, or `None` if outbox is empty.
    pub async fn latest_seq(&self) -> PdsResult<Option<i64>> {
        match self {
            Self::Sql { pool } => {
                let row: Option<(i64,)> =
                    sqlx::query_as("SELECT MAX(seq) FROM outbox WHERE seq IS NOT NULL")
                        .fetch_optional(pool)
                        .await
                        .map_err(|e| PdsError::Storage {
                            reason: format!("outbox latest_seq: {e}"),
                        })?;
                Ok(row.and_then(|(s,)| if s == 0 { None } else { Some(s) }))
            }
            Self::Dispatch { storage, did } => {
                let s = storage.latest_seq(did).await?;
                Ok(s.map(|v| v.min(i64::MAX as u64) as i64))
            }
        }
    }

    /// Insert a new event. Returns the assigned `seq`.
    ///
    /// Also used by tests and the admin CLI's CAR-import helper as a
    /// no-frills writer; production publish goes through
    /// `Sequencer::publish` which broadcasts on the `EventBus` after
    /// the row is durably committed.
    pub async fn append(&self, event_type: EventType, payload: Vec<u8>) -> PdsResult<i64> {
        match self {
            Self::Sql { pool } => {
                let now = chrono::Utc::now().to_rfc3339();
                let result = sqlx::query(
                    "INSERT INTO outbox (event_type, payload, created_at) VALUES (?, ?, ?)",
                )
                .bind(event_type.as_str())
                .bind(&payload)
                .bind(&now)
                .execute(pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("outbox append: {e}"),
                })?;
                Ok(result.last_insert_rowid())
            }
            Self::Dispatch { storage, did } => {
                let seq = storage.append(did, event_type.as_str(), payload).await?;
                Ok(seq.min(i64::MAX as u64) as i64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;

    async fn fresh_outbox() -> OutboxReader {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        OutboxReader::new(store.pool().clone())
    }

    #[test]
    fn event_type_round_trip() {
        for s in ["commit", "sync", "identity", "account", "info"] {
            let e = EventType::parse(s).unwrap();
            assert_eq!(e.as_str(), s);
        }
        assert!(EventType::parse("bogus").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_outbox_reads_nothing() {
        let outbox = fresh_outbox().await;
        let rows = outbox.read_after(None, 10).await.unwrap();
        assert!(rows.is_empty());
        assert_eq!(outbox.latest_seq().await.unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn append_then_read() {
        let outbox = fresh_outbox().await;
        let s1 = outbox
            .append(EventType::Commit, b"payload1".to_vec())
            .await
            .unwrap();
        let s2 = outbox
            .append(EventType::Identity, b"payload2".to_vec())
            .await
            .unwrap();
        assert!(s2 > s1);

        let all = outbox.read_after(None, 10).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, s1);
        assert_eq!(all[0].event_type, EventType::Commit);
        assert_eq!(all[1].event_type, EventType::Identity);

        let after = outbox.read_after(Some(s1), 10).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].seq, s2);

        assert_eq!(outbox.latest_seq().await.unwrap(), Some(s2));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_after_pagination() {
        let outbox = fresh_outbox().await;
        for i in 0..5 {
            outbox
                .append(EventType::Info, format!("p{i}").into_bytes())
                .await
                .unwrap();
        }
        let page1 = outbox.read_after(None, 3).await.unwrap();
        assert_eq!(page1.len(), 3);
        let cursor = page1.last().unwrap().seq;
        let page2 = outbox.read_after(Some(cursor), 3).await.unwrap();
        assert_eq!(page2.len(), 2);
    }
}
