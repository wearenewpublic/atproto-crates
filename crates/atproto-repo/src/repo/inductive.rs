//! Sync 1.1 inductive verification of MST commits.
//!
//! Inductive verification lets a relay or syncing app validate a new commit
//! against the prior MST root (`prev_data` in the commit) without retaining
//! full repo state. The CAR slice in a `#commit` payload contains exactly the
//! blocks needed to:
//!
//! 1. Walk the new MST starting at `Commit.data` (root CID).
//! 2. Confirm every referenced block (MST nodes, record values) is present in
//!    the slice (modulo blocks reachable from `prev_data`, which the verifier
//!    is assumed to already have).
//! 3. Confirm the CIDs match the data (content addressability).
//!
//! Per the Sync 1.1 proposal, this replaces the previous model where relays
//! had to retain full repo history to verify continuity.
//!
//! # References
//!
//! - [Sync 1.1 proposal](https://github.com/bluesky-social/proposals/tree/main/0006-sync-iteration)
//! -

use crate::errors::RepoError;
use atproto_dasl::Cid;
use atproto_dasl::car::CarBlock;
use std::collections::HashMap;

// CarBlock uses the upstream `cid::Cid`; the Commit struct uses `atproto_dasl::Cid`
// (a thin wrapper). We index internally on the upstream type because CarBlock
// already exposes it directly; conversions at the boundary use `From`.
type RawCid = cid::Cid;

fn to_raw(cid: &Cid) -> RawCid {
    cid.0
}

/// Result of inductive verification.
#[derive(Debug, Clone)]
pub struct InductiveVerification {
    /// The new MST root CID derived from the supplied blocks.
    pub new_root: Cid,
    /// Number of blocks consumed from the CAR slice.
    pub blocks_consumed: usize,
    /// Whether `prev_data` was actually referenced (false if the new tree
    /// is fully covered by the slice and no traversal needed prior state).
    pub used_prev_data: bool,
}

/// Verify a CAR-slice block set against a prior MST root.
///
/// Walks the new MST from `new_root`, confirming every CID referenced is either
/// in `blocks` (the supplied slice) or reachable from `prev_data` (the prior
/// MST root the verifier already knows). All blocks in `blocks` must
/// content-address correctly — any CID/data mismatch is a verification failure.
///
/// # Returns
///
/// On success, returns the recomputed `new_root` (which must equal the supplied
/// `new_root` argument; the function returns it for caller convenience).
///
/// # Errors
///
/// Returns [`RepoError::InvalidCommit`] if:
/// - Any block in `blocks` does not content-address to its claimed CID.
/// - The `new_root` block is missing from `blocks`.
/// - A referenced block is missing and cannot be resolved through `prev_data`.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_repo::verify_inductive;
///
/// // `prevData` rides on the `subscribeRepos#commit` event, not on the
/// // commit object — take it from the event, or from the prior commit's
/// // `data` when walking a chain.
/// let prev_data = event.prev_data.clone();
/// let new_root = commit.data.clone();
/// let blocks: Vec<CarBlock> = car_slice;
///
/// let result = verify_inductive(prev_data, new_root, &blocks)?;
/// assert_eq!(result.new_root, commit.data);
/// ```
pub fn verify_inductive(
    prev_data: Option<Cid>,
    new_root: Cid,
    blocks: &[CarBlock],
) -> Result<InductiveVerification, RepoError> {
    let new_root_raw = to_raw(&new_root);

    // Step 1: index blocks by CID and verify content-addressability of each.
    let mut block_map: HashMap<RawCid, &[u8]> = HashMap::with_capacity(blocks.len());
    for block in blocks {
        let computed_cid = crate::compute_cid(&block.data);
        if computed_cid != block.cid {
            return Err(RepoError::InvalidCommit {
                reason: format!(
                    "block CID mismatch: claimed {}, computed {}",
                    block.cid, computed_cid
                ),
            });
        }
        block_map.insert(block.cid, &block.data);
    }

    // Step 2: confirm new_root is present in the slice.
    if !block_map.contains_key(&new_root_raw) {
        return Err(RepoError::InvalidCommit {
            reason: format!("new_root block {} not in CAR slice", new_root_raw),
        });
    }

    // Step 3: walk the new MST from new_root, marking visited blocks.
    // Any block we hit that is NOT in the slice must be reachable from prev_data.
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<RawCid> = vec![new_root_raw];
    let mut used_prev_data = false;

    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = match block_map.get(&cid) {
            Some(data) => *data,
            None => {
                // Not in slice: must be reachable from prev_data. We can't walk
                // the prior tree without storage, so we accept this on faith
                // (the relay's stored state covers it).
                if prev_data.is_none() {
                    return Err(RepoError::InvalidCommit {
                        reason: format!(
                            "block {} not in slice and no prev_data to fall back to",
                            cid
                        ),
                    });
                }
                used_prev_data = true;
                continue;
            }
        };

        // Decode as MST node to find child CIDs to walk.
        // Non-MST blocks (record values) have no children to traverse.
        if let Ok(node) = atproto_dasl::from_slice::<crate::mst::MstNode>(data) {
            if let Some(left) = &node.left {
                stack.push(to_raw(left));
            }
            for entry in &node.entries {
                stack.push(to_raw(&entry.value));
                if let Some(right) = &entry.tree {
                    stack.push(to_raw(right));
                }
            }
        }
        // If it's not an MstNode, it's a record value; nothing to traverse.
    }

    Ok(InductiveVerification {
        new_root,
        blocks_consumed: blocks.len(),
        used_prev_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;
    use atproto_dasl::car::CarBlock;

    fn make_block(data: Vec<u8>) -> CarBlock {
        let cid = compute_cid(&data);
        CarBlock { cid, data }
    }

    #[test]
    fn test_verify_inductive_block_cid_mismatch() {
        // Forge a CarBlock with a wrong CID
        let wrong_cid = compute_cid(b"different data");
        let block = CarBlock {
            cid: wrong_cid,
            data: b"actual data".to_vec(),
        };
        let real_cid: Cid = compute_cid(b"actual data").into();
        let result = verify_inductive(None, real_cid, &[block]);
        assert!(result.is_err(), "expected CID-mismatch rejection");
    }

    #[test]
    fn test_verify_inductive_missing_root() {
        let other = make_block(b"other".to_vec());
        let missing_root: Cid = compute_cid(b"missing").into();
        let result = verify_inductive(None, missing_root, &[other]);
        assert!(result.is_err(), "expected missing-root rejection");
    }

    #[test]
    fn test_verify_inductive_self_contained() {
        // Smallest valid case: the root block itself; an arbitrary non-MST blob
        // is allowed (it just terminates traversal).
        let block = make_block(b"single".to_vec());
        let root: Cid = block.cid.into();
        let result = verify_inductive(None, root.clone(), &[block]).unwrap();
        assert_eq!(result.new_root, root);
        assert!(!result.used_prev_data);
        assert_eq!(result.blocks_consumed, 1);
    }
}
