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
use crate::errors::PdsResult;
use crate::sequencer::{EventType, OutboxReader};
use std::path::Path;

/// Inputs a caller has on hand when it wants a `#sync` published.
///
/// This is not the wire shape — [`crate::sequencer::payload::SyncBody`] is.
/// `head` and `blocks` are what the caller knows about the import that
/// prompted the event; neither is a field of `#sync`, which carries only
/// `did`, `blocks` (a CARv1) and `rev`.
#[derive(Debug, Clone)]
pub struct SyncEvent<'a> {
    /// Repo DID.
    pub did: &'a str,
    /// Head commit CID (string form). Diagnostic only.
    pub head: &'a str,
    /// Head rev (TID).
    pub rev: &'a str,
    /// Block count from the source CAR. Diagnostic only.
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
    // `blocks` is a CARv1, not a count. It is empty until the commit path
    // builds one (F-FIRE-02); `head` is not a field of `#sync` at all.
    crate::sequencer::payload::encode(&crate::sequencer::payload::SyncBody {
        did: event.did.to_string(),
        blocks: Vec::new(),
        rev: event.rev.to_string(),
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
        // Stored as DAG-CBOR in the lexicon's `#sync` shape: `did`, `blocks`,
        // `rev` and nothing else. `head` and the source block count are the
        // caller's context, not fields of the event.
        let atproto_dasl::Ipld::Map(payload) = atproto_dasl::from_slice(&row.1).unwrap() else {
            panic!("a #sync body is a map")
        };
        assert_eq!(
            payload["did"],
            atproto_dasl::Ipld::String("did:plc:alice".to_string())
        );
        assert_eq!(
            payload["rev"],
            atproto_dasl::Ipld::String("3kmev".to_string())
        );
        assert!(matches!(payload["blocks"], atproto_dasl::Ipld::Bytes(_)));
        assert!(!payload.contains_key("head"), "{payload:?}");
    }
}
