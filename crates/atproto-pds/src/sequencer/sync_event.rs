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
//! The helper appends the lexicon-shaped body to the firehose stream.
//! Best-effort: the caller logs and continues on storage failure, because
//! `#sync` is itself the recovery path — a subscriber that misses one falls
//! back to `getRepo`.

use crate::errors::PdsResult;
use crate::sequencer::{EventType, Sequencer};

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

/// Append a `#sync` event to the firehose stream.
///
/// Returns the assigned stream `seq`.
///
/// # Errors
///
/// Returns [`crate::errors::PdsError::Storage`] if the event cannot be
/// encoded or recorded.
pub async fn publish_sync(sequencer: &Sequencer, event: &SyncEvent<'_>) -> PdsResult<i64> {
    // `blocks` is a CARv1, not a count. It is empty until the commit path
    // builds one (F-FIRE-02); `head` is not a field of `#sync` at all.
    let bytes = crate::sequencer::payload::encode(&crate::sequencer::payload::SyncBody {
        did: event.did.to_string(),
        blocks: Vec::new(),
        rev: event.rev.to_string(),
    })?;
    sequencer
        .append(event.did, EventType::Sync.as_str(), bytes)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    #[tokio::test]
    async fn publish_sync_records_the_lexicon_shape() {
        let accounts = AccountDirectory::open_memory().await.unwrap();
        let sequencer = Sequencer::new(accounts.account_pool());

        let event = SyncEvent {
            did: "did:plc:alice",
            head: "bafyalice",
            rev: "3kmev",
            blocks: 42,
        };
        let seq = publish_sync(&sequencer, &event).await.unwrap();
        assert!(seq > 0);

        let rows = sequencer.read_after(None, None, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "sync");
        assert_eq!(rows[0].did, "did:plc:alice");

        // Stored as DAG-CBOR in the lexicon's `#sync` shape: `did`, `blocks`,
        // `rev` and nothing else. `head` and the source block count are the
        // caller's context, not fields of the event.
        let atproto_dasl::Ipld::Map(payload) = atproto_dasl::from_slice(&rows[0].payload).unwrap()
        else {
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
