//! The firehose stream — one ordered event log for the whole server.
//!
//! `com.atproto.sync.subscribeRepos` hands each subscriber a `seq` and takes it
//! back as a resume cursor. That contract is about the *stream*: one number
//! space for the server, strictly increasing in the order frames go out, never
//! reissued. A per-repository counter cannot express it — every repository's
//! first event is `seq = 1`, so the same cursor value denotes different events
//! in different repositories and a resuming relay cannot tell them apart.
//!
//! # Why the log is global rather than a global counter over per-actor storage
//!
//! Handing out globally-unique numbers is not enough. If the rows still live in
//! per-actor storage, a subscriber has to merge them, and there is no order it
//! can trust: poll A (empty) → B commits seq 11 → emit 11 → A's seq 10 commits
//! → emit 10. Allocating `seq` inside the INSERT into a single table makes
//! allocation order *be* commit order, which is the property subscribers
//! actually depend on.
//!
//! # Why it lives in the accounts database
//!
//! The accounts database is server-global and is opened under every storage
//! profile, so one schema serves both the SQLite and fjall deployments with no
//! backend-specific work.
//!
//! The cost is that a `#commit` is no longer written in the same transaction as
//! the commit it describes: the repository lives in a per-actor store and the
//! event lives here. A crash between the two loses an event rather than
//! recording a wrong one, which is the failure `#sync` and `getRepo`
//! re-anchoring exist to repair. The reference implementation splits them the
//! same way.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// One row of the stream, ready to be framed for a subscriber.
#[derive(Debug, Clone)]
pub struct StreamRow {
    /// Position in the stream. Unique server-wide and strictly increasing.
    pub seq: i64,
    /// DID of the repository the event came from.
    pub did: String,
    /// Event discriminator without the leading `#`, e.g. `commit`.
    pub event_type: String,
    /// DAG-CBOR body in the shape its lexicon member declares, less `seq` and
    /// `time`.
    pub payload: Vec<u8>,
    /// When the event was recorded, RFC 3339.
    pub created_at: String,
}

/// Advisory-lock key serializing `stream_event` sequence allocation.
///
/// An arbitrary constant, but a *stable* one: it identifies this lock across
/// every connection in the pool and across every process sharing the database,
/// which is what makes it a lock rather than a local mutex. Postgres advisory
/// locks share one namespace per database, so the value only has to be
/// unlikely to collide with another application's.
#[cfg(feature = "postgres")]
pub const STREAM_SEQ_LOCK_KEY: i64 = 0x0a79_0705_5e90_0001;

/// Append-and-read handle on the stream.
///
/// Cheap to clone — it holds a connection pool.
#[derive(Clone)]
pub struct Sequencer {
    pool: AccountPool,
}

impl Sequencer {
    /// Construct a sequencer over the accounts pool.
    #[must_use]
    pub fn new(pool: AccountPool) -> Self {
        Self { pool }
    }

    /// Record an event and return the `seq` the stream assigned it.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if the row cannot be written.
    pub async fn append(&self, did: &str, event_type: &str, payload: Vec<u8>) -> PdsResult<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let result = sqlx::query(
                    "INSERT INTO stream_event (did, event_type, payload, created_at)
                     VALUES (?, ?, ?, ?)",
                )
                .bind(did)
                .bind(event_type)
                .bind(&payload)
                .bind(&now)
                .execute(self.pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("stream append: {e}"),
                })?;
                Ok(result.last_insert_rowid())
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                // `BIGSERIAL` alone is not enough, and the difference is a
                // permanent event skip rather than a reordering.
                //
                // `nextval` is deliberately non-transactional: it hands out
                // numbers without waiting and never rolls them back, so two
                // concurrent appends can take 10 and 11 and then commit in the
                // other order. A subscriber polling `seq > cursor` in the
                // window between those commits reads 11, sends it, and sets its
                // cursor to 11. Seq 10 becomes visible a moment later, behind a
                // cursor that has already passed it, and no live subscriber
                // ever reads it. The event is not late; it is gone.
                //
                // So the allocation is serialized against commit. The advisory
                // lock is transaction-scoped, which is the whole point: it is
                // held from before `nextval` until the COMMIT that makes the
                // row visible, so no second append can allocate inside another
                // append's window. Allocation order becomes commit order --
                // the property the SQLite schema comment claims for the stream
                // and gets for free from a single writer.
                //
                // This serializes appends. That is not a cost being accepted
                // reluctantly: the firehose is a total order, SQLite already
                // serializes every write, and a stream whose numbering is
                // allowed to race is not a stream.
                let mut tx =
                    self.pool
                        .as_postgres()
                        .begin()
                        .await
                        .map_err(|e| PdsError::Storage {
                            reason: format!("stream append: begin: {e}"),
                        })?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(STREAM_SEQ_LOCK_KEY)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("stream append: lock: {e}"),
                    })?;
                let row: (i64,) = sqlx::query_as(
                    "INSERT INTO stream_event (did, event_type, payload, created_at)
                     VALUES ($1, $2, $3, $4) RETURNING seq",
                )
                .bind(did)
                .bind(event_type)
                .bind(&payload)
                .bind(&now)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("stream append: {e}"),
                })?;
                tx.commit().await.map_err(|e| PdsError::Storage {
                    reason: format!("stream append: commit: {e}"),
                })?;
                Ok(row.0)
            }
            #[allow(unreachable_patterns)]
            _ => Err(PdsError::Storage {
                reason: "stream append: no accounts backend compiled in".to_string(),
            }),
        }
    }

    /// Read up to `limit` events after `after`, in stream order.
    ///
    /// `None` for `after` starts at the beginning. `did` restricts the read to
    /// one repository without changing the numbering — the `seq` values are
    /// still the stream's, so a filtered subscriber's cursor stays valid
    /// against the unfiltered stream.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if the read fails.
    pub async fn read_after(
        &self,
        after: Option<i64>,
        did: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<StreamRow>> {
        let limit = i64::from(limit.clamp(1, 1000));
        let after = after.unwrap_or(0);
        let rows: Vec<(i64, String, String, Vec<u8>, String)> = match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => match did {
                Some(did) => {
                    sqlx::query_as(
                        "SELECT seq, did, event_type, payload, created_at FROM stream_event
                     WHERE seq > ? AND did = ? ORDER BY seq ASC LIMIT ?",
                    )
                    .bind(after)
                    .bind(did)
                    .bind(limit)
                    .fetch_all(self.pool.as_sqlite())
                    .await
                }
                None => {
                    sqlx::query_as(
                        "SELECT seq, did, event_type, payload, created_at FROM stream_event
                     WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                    )
                    .bind(after)
                    .bind(limit)
                    .fetch_all(self.pool.as_sqlite())
                    .await
                }
            },
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => match did {
                Some(did) => {
                    sqlx::query_as(
                        "SELECT seq, did, event_type, payload, created_at FROM stream_event
                     WHERE seq > $1 AND did = $2 ORDER BY seq ASC LIMIT $3",
                    )
                    .bind(after)
                    .bind(did)
                    .bind(limit)
                    .fetch_all(self.pool.as_postgres())
                    .await
                }
                None => {
                    sqlx::query_as(
                        "SELECT seq, did, event_type, payload, created_at FROM stream_event
                     WHERE seq > $1 ORDER BY seq ASC LIMIT $2",
                    )
                    .bind(after)
                    .bind(limit)
                    .fetch_all(self.pool.as_postgres())
                    .await
                }
            },
            #[allow(unreachable_patterns)]
            _ => {
                return Err(PdsError::Storage {
                    reason: "stream read: no accounts backend compiled in".to_string(),
                });
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("stream read_after: {e}"),
        })?;

        Ok(rows
            .into_iter()
            .map(|(seq, did, event_type, payload, created_at)| StreamRow {
                seq,
                did,
                event_type,
                payload,
                created_at,
            })
            .collect())
    }

    /// Highest `seq` the stream has issued, or `None` when it is empty.
    ///
    /// This is the high-water mark a cursor is compared against.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if the read fails.
    pub async fn latest_seq(&self) -> PdsResult<Option<i64>> {
        let row: Option<(Option<i64>,)> = match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT MAX(seq) FROM stream_event")
                    .fetch_optional(self.pool.as_sqlite())
                    .await
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT MAX(seq) FROM stream_event")
                    .fetch_optional(self.pool.as_postgres())
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => {
                return Err(PdsError::Storage {
                    reason: "stream latest_seq: no accounts backend compiled in".to_string(),
                });
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("stream latest_seq: {e}"),
        })?;
        // MAX over an empty table is a row holding NULL, not an absent row.
        Ok(row.and_then(|(seq,)| seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    async fn sequencer() -> Sequencer {
        let accounts = AccountDirectory::open_memory().await.unwrap();
        Sequencer::new(accounts.account_pool())
    }

    /// The defect this module exists to fix: two repositories, two numbers.
    #[tokio::test]
    async fn repositories_share_one_number_space() {
        let stream = sequencer().await;
        let a = stream.append("did:plc:alice", "commit", vec![1]).await;
        let b = stream.append("did:plc:bob", "commit", vec![2]).await;
        assert_eq!(a.unwrap(), 1);
        assert_eq!(
            b.unwrap(),
            2,
            "bob continues the stream, he does not restart"
        );
    }

    #[tokio::test]
    async fn read_after_pages_in_stream_order() {
        let stream = sequencer().await;
        for i in 0..5u8 {
            let did = if i % 2 == 0 { "did:plc:a" } else { "did:plc:b" };
            stream.append(did, "commit", vec![i]).await.unwrap();
        }

        let all = stream.read_after(None, None, 100).await.unwrap();
        let seqs: Vec<i64> = all.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);

        let tail = stream.read_after(Some(2), None, 100).await.unwrap();
        assert_eq!(
            tail.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "a cursor is exclusive"
        );
    }

    /// Filtering to one repository must not renumber it.
    #[tokio::test]
    async fn a_did_filter_keeps_the_stream_numbering() {
        let stream = sequencer().await;
        stream.append("did:plc:a", "commit", vec![1]).await.unwrap();
        stream.append("did:plc:b", "commit", vec![2]).await.unwrap();
        stream.append("did:plc:a", "commit", vec![3]).await.unwrap();

        let only_a = stream
            .read_after(None, Some("did:plc:a"), 100)
            .await
            .unwrap();
        assert_eq!(
            only_a.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 3],
            "a filtered subscriber sees the stream's numbers, with gaps"
        );
    }

    #[tokio::test]
    async fn latest_seq_reports_the_high_water_mark() {
        let stream = sequencer().await;
        assert_eq!(stream.latest_seq().await.unwrap(), None);
        stream.append("did:plc:a", "commit", vec![1]).await.unwrap();
        let last = stream.append("did:plc:b", "sync", vec![2]).await.unwrap();
        assert_eq!(stream.latest_seq().await.unwrap(), Some(last));
    }

    #[tokio::test]
    async fn payloads_round_trip_as_bytes() {
        let stream = sequencer().await;
        let payload = vec![0xa1, 0x63, 0x72, 0x65, 0x76, 0x00];
        stream
            .append("did:plc:a", "commit", payload.clone())
            .await
            .unwrap();
        let rows = stream.read_after(None, None, 10).await.unwrap();
        assert_eq!(rows[0].payload, payload);
        assert_eq!(rows[0].event_type, "commit");
        assert_eq!(rows[0].did, "did:plc:a");
    }
}
