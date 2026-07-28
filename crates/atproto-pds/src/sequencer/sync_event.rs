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
//! `blocks` is a CARv1 rooted at the head commit and carrying that commit
//! block — the lexicon's shape, and the minimum a consumer needs to re-anchor.
//!
//! The helper appends the lexicon-shaped body to the firehose stream.
//! Best-effort: the caller logs and continues on storage failure, because
//! `#sync` is itself the recovery path — a subscriber that misses one falls
//! back to `getRepo`.

use crate::errors::PdsResult;
use crate::sequencer::{EventType, Sequencer};

/// The head a `#sync` force-sets.
///
/// The caller supplies the commit block itself rather than a reference to it:
/// `#sync` exists so a consumer that lost the `#commit` chain can re-anchor,
/// and one that carries no commit gives it nothing to anchor to.
#[derive(Debug, Clone)]
pub struct SyncEvent<'a> {
    /// Repo DID.
    pub did: &'a str,
    /// Head rev (TID).
    pub rev: &'a str,
    /// CID of the head commit — the CAR's root.
    pub commit_cid: &'a cid::Cid,
    /// DAG-CBOR bytes of the head commit.
    pub commit_block: &'a [u8],
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
    let blocks =
        crate::repo::commit_car::build_sync_car(event.commit_cid, event.commit_block).await?;
    let bytes = crate::sequencer::payload::encode(&crate::sequencer::payload::SyncBody {
        did: event.did.to_string(),
        blocks,
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

        let commit_block = b"pretend commit block".to_vec();
        let commit_cid = atproto_dasl::cid::compute_cid(&commit_block);
        let event = SyncEvent {
            did: "did:plc:alice",
            rev: "3kmev",
            commit_cid: &commit_cid,
            commit_block: &commit_block,
        };
        let seq = publish_sync(&sequencer, &event).await.unwrap();
        assert!(seq > 0);

        let rows = sequencer.read_after(None, None, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "sync");
        assert_eq!(rows[0].did, "did:plc:alice");

        // Stored as DAG-CBOR in the lexicon's `#sync` shape: `did`, `blocks`,
        // `rev` and nothing else.
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
        let atproto_dasl::Ipld::Bytes(car) = &payload["blocks"] else {
            panic!("`blocks` is typed bytes")
        };
        assert!(!payload.contains_key("head"), "{payload:?}");

        // A real CAR, rooted at the commit, carrying it.
        let mut reader = atproto_dasl::car::CarReader::new(std::io::Cursor::new(car.clone()))
            .await
            .unwrap();
        assert_eq!(reader.root().cloned().unwrap().0, commit_cid);
        let block = reader.next_block().await.unwrap().expect("one block");
        assert_eq!(block.data, commit_block);
        assert!(reader.next_block().await.unwrap().is_none());
    }
}
