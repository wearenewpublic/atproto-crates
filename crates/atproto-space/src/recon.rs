//! Set reconciliation primitives — Phase 8 evaluation surface.
//!
//!  Spaces sync today
//! uses `(SetHash digest equality + oplog catchup since rev)` for state
//! reconciliation: cheap when both sides agree, O(diff) over the wire when
//! they disagree, but fundamentally O(distance) — a peer that's been offline
//! for N revs has to replay N oplog entries.
//!
//! [RIBLT (Rateless IBLT)](https://www.usenix.org/conference/nsdi24/presentation/yang)
//! offers an O(symmetric-difference) reconciliation: encode set membership
//! into a small "sketch," exchange sketches with the peer, and the peer can
//! recover exactly which elements differ — independent of how far back the
//! divergence is. Useful when peers are long-disconnected (think: AppView
//! that just came back online after a multi-day outage).
//!
//! # Status
//!
//! This module ships the **OplogReconciler** baseline that captures the
//! current "since-rev catchup" semantics, plus the **trait surface** an
//! eventual RIBLT impl would slot into. The RIBLT impl itself is research-
//! grade work (≈1,000 LOC of cell-encoding + polynomial decoding) and is
//! deferred to a future spec round.
//! When upstream picks an algorithm, swap in an `RibltReconciler` behind
//! this trait.
//!
//! For now, exposing the trait + baseline impl lets us:
//! - Document the design space.
//! - Run benchmarks comparing baselines.
//! - Preserve the call sites so swapping in RIBLT is a small refactor.

use crate::storage::{OplogEntry, RepoState};

/// One side of a set-reconciliation exchange.
///
/// In oplog-catchup mode the "sketch" is just `(set_hash, rev)`: the peer
/// observes whether they match and either no-ops or fetches `OplogPage(since=peer_rev)`.
/// In RIBLT mode the sketch is a polynomial-encoded multiset of set elements
/// the local side believes are present.
pub trait Sketch: Clone + Send + Sync {
    /// Compact byte serialization for over-the-wire transport.
    fn to_bytes(&self) -> Vec<u8>;
}

/// A reconciliation reply telling the asking side what to do next.
#[derive(Debug, Clone)]
pub enum ReconcileOutcome {
    /// Both sides agree on state — no further action needed.
    InSync,
    /// The asking side is behind. Replay these ops in order to catch up.
    CatchUp {
        /// Ops the asking side hasn't applied yet, in `(rev, idx)` order.
        ops: Vec<OplogEntry>,
        /// New `RepoState` after the peer's latest apply.
        peer_state: RepoState,
    },
    /// The two sides have diverged in incompatible ways (e.g., the asking
    /// side has ops the peer never saw). The peer cannot reconcile and the
    /// asking side must escalate to a fork-resolution protocol.
    Diverged {
        /// Description of the divergence for diagnostic display.
        reason: String,
    },
}

/// Reconciler trait — local "what should I send back to a peer who showed me
/// their sketch?"
#[allow(async_fn_in_trait)]
pub trait Reconciler {
    /// The sketch shape this reconciler emits.
    type Sketch: Sketch;

    /// Build a sketch of the local state.
    async fn local_sketch(&self) -> Self::Sketch;

    /// Compare against a peer's sketch and return a reconciliation step.
    ///
    /// `peer_sketch_bytes` is the raw bytes the peer transmitted (so impls
    /// own deserialization to validate the format).
    async fn reconcile(&self, peer_sketch_bytes: &[u8]) -> ReconcileOutcome;
}

/// The current Spaces sync mechanism: `(set_hash, rev)` equality + oplog catchup.
///
/// This is the in-memory baseline; production Spaces sync wires this through
/// the SQL or fjall storage trait so the oplog read goes through persistent
/// state.
pub mod oplog_catchup {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Sketch: `(set_hash, rev)` pair.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OplogSketch {
        /// Hex-encoded SetHash digest.
        pub set_hash: Option<Vec<u8>>,
        /// Latest rev (TID).
        pub rev: Option<String>,
    }

    impl Sketch for OplogSketch {
        fn to_bytes(&self) -> Vec<u8> {
            serde_json::to_vec(self).unwrap_or_default()
        }
    }

    impl OplogSketch {
        /// Construct from a `RepoState`.
        #[must_use]
        pub fn from_state(state: &RepoState) -> Self {
            Self {
                set_hash: state.set_hash.clone(),
                rev: state.rev.clone(),
            }
        }
    }

    /// Decide what to send back to a peer who reported their sketch.
    ///
    /// Pure function — does not touch storage. Storage-backed callers feed
    /// in `local_state` + the appropriate oplog page.
    #[must_use]
    pub fn reconcile_pure(
        local_state: &RepoState,
        peer_sketch: &OplogSketch,
        oplog_since_peer_rev: Vec<OplogEntry>,
    ) -> ReconcileOutcome {
        if local_state.set_hash == peer_sketch.set_hash && local_state.rev == peer_sketch.rev {
            return ReconcileOutcome::InSync;
        }
        // Local has data the peer hasn't seen. Hand them the oplog page.
        ReconcileOutcome::CatchUp {
            ops: oplog_since_peer_rev,
            peer_state: local_state.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oplog_catchup::*;

    fn state(set: Option<&[u8]>, rev: Option<&str>) -> RepoState {
        RepoState {
            set_hash: set.map(|s| s.to_vec()),
            rev: rev.map(String::from),
        }
    }

    #[test]
    fn in_sync_when_state_matches() {
        let local = state(Some(&[1, 2, 3]), Some("3jab"));
        let peer = OplogSketch::from_state(&local);
        let outcome = reconcile_pure(&local, &peer, vec![]);
        assert!(matches!(outcome, ReconcileOutcome::InSync));
    }

    #[test]
    fn catchup_when_local_ahead() {
        let local = state(Some(&[9, 9]), Some("3jcd"));
        let peer = OplogSketch::from_state(&state(Some(&[1, 1]), Some("3jab")));
        let ops = vec![OplogEntry {
            rev: "3jcd".to_string(),
            idx: 0,
            action: "create".to_string(),
            collection: Some("c".to_string()),
            rkey: Some("k".to_string()),
            cid: Some("cid".to_string()),
            prev: None,
            did: None,
        }];
        let outcome = reconcile_pure(&local, &peer, ops.clone());
        match outcome {
            ReconcileOutcome::CatchUp {
                ops: returned,
                peer_state,
            } => {
                assert_eq!(returned.len(), 1);
                assert_eq!(peer_state.rev.as_deref(), Some("3jcd"));
            }
            _ => panic!("expected CatchUp"),
        }
    }

    #[test]
    fn sketch_round_trips_through_bytes() {
        let s = OplogSketch::from_state(&state(Some(&[1, 2]), Some("rev")));
        let bytes = s.to_bytes();
        let back: OplogSketch = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.set_hash, Some(vec![1, 2]));
        assert_eq!(back.rev.as_deref(), Some("rev"));
    }

    #[test]
    fn empty_local_in_sync_with_empty_peer() {
        let local = state(None, None);
        let peer = OplogSketch::from_state(&local);
        assert!(matches!(
            reconcile_pure(&local, &peer, vec![]),
            ReconcileOutcome::InSync
        ));
    }
}
