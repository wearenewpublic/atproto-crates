//! `#sync` event publishing helper.
//!
//! Sync 1.1 introduces a `#sync` event whose semantics are "force-set repo
//! state without diff." Subscribers that miss the in-band `#commit` chain —
//! either because of broadcast lag or because the actor was just imported
//! from a CAR — apply the `#sync` payload to overwrite their cached head.
//!
//! Two call sites today:
//!
//! 1. **`importRepo` completion** — after a successful CAR import, emit a
//!    `#sync` so any tailing peer rebuilds their cache around the new head.
//! 2. **`com.atproto.admin.forceRepoSync`** — operator-initiated drift fix.
//!
//! The helper is intentionally minimal — it just appends the canonical
//! payload shape into the per-actor outbox via [`OutboxReader::append`].
//! Best-effort: the caller logs and continues on storage failure.

use crate::actor_store::PublicRealmBackend;
use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::sequencer::{EventType, OutboxReader};
use std::path::Path;

/// Per-spec `#sync` payload. `did` is the repo whose state is being
/// force-set; `head` is the head commit CID; `rev` is its TID; `blocks`
/// is the byte count of the imported repo (informational — not the
/// spec `blocks` CARv1 field, which a future enhancement may populate
/// for hold-over consumers).
#[derive(Debug, Clone)]
pub struct SyncEvent<'a> {
    /// Repo DID.
    pub did: &'a str,
    /// Head commit CID (string form).
    pub head: &'a str,
    /// Head rev (TID).
    pub rev: &'a str,
    /// Block count from the source CAR (informational).
    pub blocks: usize,
}

/// Append a `#sync` event into the per-actor outbox at `data_dir`.
///
/// Legacy SQLite-direct entry point. Returns the assigned outbox `seq`
/// on success. On storage failure the caller is expected to
/// `tracing::warn!` and continue — `#sync` is recoverable: subscribers
/// fall back to `getRepo` for cold rebuild.
pub async fn publish_sync(data_dir: &Path, event: &SyncEvent<'_>) -> PdsResult<i64> {
    let store = SqlActorStore::open(data_dir, event.did).await?;
    let bytes = encode_payload(event)?;
    let outbox = OutboxReader::new(store.pool().clone());
    outbox.append(EventType::Sync, bytes).await
}

/// Same as [`publish_sync`] but routes through the
/// `PublicRealmBackend` dispatch surface. The fjall profile reaches the right keyspace via this
/// path; the SQLite profile produces an identical row to the legacy
/// `publish_sync` entry point.
pub async fn publish_sync_via_backend(
    backend: &PublicRealmBackend,
    event: &SyncEvent<'_>,
) -> PdsResult<i64> {
    let bytes = encode_payload(event)?;
    let outbox = OutboxReader::dispatch(backend.outbox.clone(), event.did);
    outbox.append(EventType::Sync, bytes).await
}

fn encode_payload(event: &SyncEvent<'_>) -> PdsResult<Vec<u8>> {
    let payload = serde_json::json!({
        "did": event.did,
        "rev": event.rev,
        "head": event.head,
        "blocks": event.blocks,
    });
    serde_json::to_vec(&payload).map_err(|e| PdsError::Storage {
        reason: format!("encode #sync payload: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use tempfile::TempDir;

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_sync_appends_outbox_row() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        // Bootstrap the accounts DB so AccountDirectory exists.
        let _ = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();

        let event = SyncEvent {
            did: "did:plc:alice",
            head: "bafyalice",
            rev: "3kmev",
            blocks: 42,
        };
        let seq = publish_sync(&dir, &event).await.unwrap();
        assert!(seq > 0);

        // Verify the row is in alice's outbox with type=sync.
        let store = SqlActorStore::open(&dir, "did:plc:alice").await.unwrap();
        let row: (String, Vec<u8>) =
            sqlx::query_as("SELECT event_type, payload FROM outbox WHERE seq = ?")
                .bind(seq)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(row.0, "sync");
        let payload: serde_json::Value = serde_json::from_slice(&row.1).unwrap();
        assert_eq!(payload["did"], "did:plc:alice");
        assert_eq!(payload["head"], "bafyalice");
        assert_eq!(payload["rev"], "3kmev");
        assert_eq!(payload["blocks"], 42);
    }
}
