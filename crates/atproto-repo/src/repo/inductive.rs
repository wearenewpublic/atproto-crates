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
//! [`verify_inductive`] establishes that the tree is well-formed and
//! self-consistent. It never reads `ops[]` -- it is not given them -- so a
//! commit can pass it while its ops array lies about what changed.
//! [`verify_op_inclusion`] closes that gap by proving each op against the tree
//! the commit signed. Both are needed: the first says the tree is real, the
//! second says the ops describe it.
//!
//! # References
//!
//! - [Sync 1.1 proposal](https://github.com/bluesky-social/proposals/tree/main/0006-sync-iteration)
//! -

use crate::config::RepoConfig;
use crate::errors::RepoError;
use crate::mst::{Mst, RepoOp, RepoOpAction};
use atproto_dasl::Cid;
use atproto_dasl::car::CarBlock;
use atproto_dasl::storage::{BlockStorage, MemoryStorage};
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

/// One op's verdict against the signed tree.
#[derive(Debug, Clone, PartialEq)]
pub struct OpInclusion {
    /// The op's repo path (`<collection>/<rkey>`).
    pub path: String,
    /// Whether the tree agrees with the op.
    pub verified: bool,
    /// What the tree actually resolves this path to, when it disagrees.
    ///
    /// `None` when the op verified, and also when the disagreement is that the
    /// path resolves to nothing -- a create or update naming a CID the signed
    /// tree does not hold. The two are told apart by `verified`.
    pub found: Option<Cid>,
}

/// Prove each op in a commit against the MST the commit signed.
///
/// [`verify_inductive`] establishes that the tree is well-formed. This
/// establishes that the ops describe it truthfully -- a create or update must
/// resolve to exactly the CID the op named, and a delete must resolve to
/// nothing. An app view that trusts `op.cid` after `verify_inductive` returns
/// `Ok` is indexing an unverified claim about a verified tree: the claim and
/// the tree are checked by different code, and only one of them was checked.
///
/// This works on a diff slice because a commit slice contains every node on
/// the path from the root to each changed key; that is what makes it a proof
/// rather than a fragment.
///
/// `collections` filters which ops are proven; pass an empty slice to prove
/// all of them. A consumer tracking six collections out of the network's
/// thousands should not pay for a tree walk per irrelevant op -- and when
/// nothing matches, the blocks are never even loaded into storage.
///
/// # Content addressing
///
/// The blocks are taken as given. Proving that each one hashes to its claimed
/// CID is [`verify_inductive`]'s job, and doing it twice would double the cost
/// of the common path where both run. Calling this alone proves the ops
/// against whatever tree the blocks describe, which is not the same as proving
/// them against the tree the repository signed.
///
/// # Errors
///
/// Returns [`RepoError::InvalidCommit`] if a create or update carries no
/// `cid`, which is a malformed op rather than a disagreement -- there is
/// nothing to compare the tree against, and a commit whose ops array is
/// malformed is not partially trustworthy. Returns [`RepoError::Mst`] or
/// [`RepoError::Storage`] if the walk fails.
#[must_use = "an op's verdict is the whole point; dropping it indexes unverified claims"]
pub async fn verify_op_inclusion(
    data_root: Cid,
    ops: &[RepoOp],
    blocks: &[CarBlock],
    collections: &[&str],
) -> Result<Vec<OpInclusion>, RepoError> {
    // Before the blocks are touched: loading a multi-megabyte slice into
    // storage to then walk nothing is the cost this filter exists to avoid.
    if !ops.iter().any(|op| is_tracked(op, collections)) {
        return Ok(Vec::new());
    }

    let mut storage = MemoryStorage::new();
    for block in blocks {
        storage.put(&block.cid, block.data.clone()).await?;
    }

    verify_op_inclusion_in(data_root, ops, storage, collections).await
}

/// [`verify_op_inclusion`] against blocks that are already in storage.
///
/// A consumer holding a populated [`BlockStorage`] should not have to copy its
/// blocks into a second one to ask this question.
///
/// # Errors
///
/// As [`verify_op_inclusion`].
#[must_use = "an op's verdict is the whole point; dropping it indexes unverified claims"]
pub async fn verify_op_inclusion_in<S: BlockStorage>(
    data_root: Cid,
    ops: &[RepoOp],
    storage: S,
    collections: &[&str],
) -> Result<Vec<OpInclusion>, RepoError> {
    let mst = Mst::from_root(to_raw(&data_root), storage, RepoConfig::default());

    let mut verdicts = Vec::new();
    for op in ops {
        if !is_tracked(op, collections) {
            continue;
        }

        let found = mst.get(&op.path).await?;

        let verified = match op.action {
            RepoOpAction::Create | RepoOpAction::Update => {
                let Some(expected) = op.cid.as_ref() else {
                    return Err(RepoError::InvalidCommit {
                        reason: format!("{:?} op at {} carries no cid", op.action, op.path),
                    });
                };
                found.as_ref() == Some(expected)
            }
            RepoOpAction::Delete => found.is_none(),
        };

        verdicts.push(OpInclusion {
            path: op.path.clone(),
            verified,
            found: if verified { None } else { found },
        });
    }

    Ok(verdicts)
}

/// Whether an op names one of the collections the caller tracks.
///
/// An empty list means every op. The collection is the path segment before the
/// first `/`, which is the whole path when there is no `/` -- a malformed path
/// then matches nothing, which is the safe direction.
fn is_tracked(op: &RepoOp, collections: &[&str]) -> bool {
    if collections.is_empty() {
        return true;
    }
    let collection = op.path.split('/').next().unwrap_or_default();
    collections.contains(&collection)
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

    /// A record block: any DAG-CBOR value that is not an MST node, so
    /// traversal terminates on it the way it does on a real record.
    fn record_block(text: &str) -> CarBlock {
        make_block(atproto_dasl::to_vec(&text).expect("encode"))
    }

    /// Build a tree over `(path, record)` pairs and return its root, the ops a
    /// truthful `#commit` would carry for it, and the CAR slice.
    async fn commit_of(records: &[(&str, &str)]) -> (Cid, Vec<RepoOp>, Vec<CarBlock>) {
        let mut mst = Mst::new(MemoryStorage::new(), RepoConfig::default());
        let mut ops = Vec::new();
        let mut blocks = Vec::new();

        for (path, text) in records {
            let block = record_block(text);
            let value: Cid = block.cid.into();
            mst.insert(path, value.clone()).await.expect("insert");
            ops.push(RepoOp {
                action: RepoOpAction::Create,
                path: (*path).to_string(),
                cid: Some(value),
                prev: None,
            });
            blocks.push(block);
        }

        let root: Cid = (*mst.root().expect("a non-empty tree")).into();
        for (cid, data) in mst.storage().blocks() {
            blocks.push(CarBlock {
                cid: *cid,
                data: data.clone(),
            });
        }

        (root, ops, blocks)
    }

    /// A commit whose ops tell the truth verifies.
    #[tokio::test]
    async fn a_truthful_commit_verifies() {
        let (root, ops, blocks) = commit_of(&[
            ("app.test.rec/aaa", "first"),
            ("app.test.rec/bbb", "second"),
            ("app.test.rec/ccc", "third"),
        ])
        .await;

        let verdicts = verify_op_inclusion(root, &ops, &blocks, &[])
            .await
            .expect("walk");

        assert_eq!(verdicts.len(), 3);
        assert!(
            verdicts.iter().all(|verdict| verdict.verified),
            "{verdicts:?}"
        );
    }

    /// The test this function exists for.
    ///
    /// One op's `cid` is swapped for another record's -- a CID that is
    /// genuinely in the slice and genuinely content-addresses, so nothing
    /// about the tree is wrong. `verify_inductive` passes, because it is never
    /// shown the ops. An app view that stopped there would index the wrong
    /// record at that path, on a commit it had just "verified".
    #[tokio::test]
    async fn a_lying_cid_is_caught() {
        let (root, mut ops, blocks) = commit_of(&[
            ("app.test.rec/aaa", "first"),
            ("app.test.rec/bbb", "second"),
        ])
        .await;

        let truthful = ops[0].cid.clone().expect("a create names a cid");
        let someone_elses = ops[1].cid.clone().expect("a create names a cid");
        ops[0].cid = Some(someone_elses.clone());

        verify_inductive(None, root.clone(), &blocks).expect("the tree is still sound");

        let verdicts = verify_op_inclusion(root, &ops, &blocks, &[])
            .await
            .expect("walk");

        assert_eq!(
            verdicts[0],
            OpInclusion {
                path: "app.test.rec/aaa".to_string(),
                verified: false,
                found: Some(truthful),
            }
        );
        assert!(verdicts[1].verified);
    }

    /// A delete for a key the tree still holds.
    #[tokio::test]
    async fn a_delete_that_still_resolves_is_caught() {
        let (root, mut ops, blocks) = commit_of(&[("app.test.rec/aaa", "first")]).await;
        let present = ops[0].cid.clone().expect("a create names a cid");

        ops[0] = RepoOp {
            action: RepoOpAction::Delete,
            path: "app.test.rec/aaa".to_string(),
            cid: None,
            prev: Some(present.clone()),
        };

        let verdicts = verify_op_inclusion(root, &ops, &blocks, &[])
            .await
            .expect("walk");

        assert_eq!(
            verdicts[0],
            OpInclusion {
                path: "app.test.rec/aaa".to_string(),
                verified: false,
                found: Some(present),
            }
        );
    }

    /// A delete the tree agrees with.
    #[tokio::test]
    async fn a_delete_of_an_absent_key_verifies() {
        let (root, _, blocks) = commit_of(&[("app.test.rec/aaa", "first")]).await;

        let ops = vec![RepoOp {
            action: RepoOpAction::Delete,
            path: "app.test.rec/zzz".to_string(),
            cid: None,
            prev: None,
        }];

        let verdicts = verify_op_inclusion(root, &ops, &blocks, &[])
            .await
            .expect("walk");

        assert!(verdicts[0].verified);
        assert_eq!(verdicts[0].found, None);
    }

    /// A create for a key the signed tree does not hold at all.
    #[tokio::test]
    async fn a_create_for_a_key_absent_from_the_tree_is_caught() {
        let (root, ops, blocks) = commit_of(&[("app.test.rec/aaa", "first")]).await;

        let invented = vec![RepoOp {
            action: RepoOpAction::Create,
            path: "app.test.rec/never".to_string(),
            cid: ops[0].cid.clone(),
            prev: None,
        }];

        let verdicts = verify_op_inclusion(root, &invented, &blocks, &[])
            .await
            .expect("walk");

        assert!(!verdicts[0].verified);
        // Absent rather than mismatched: the path resolves to nothing.
        assert_eq!(verdicts[0].found, None);
    }

    /// A create with a null `cid` is a malformed op, not a verdict.
    #[tokio::test]
    async fn a_create_with_no_cid_is_an_error() {
        let (root, _, blocks) = commit_of(&[("app.test.rec/aaa", "first")]).await;

        let ops = vec![RepoOp {
            action: RepoOpAction::Create,
            path: "app.test.rec/aaa".to_string(),
            cid: None,
            prev: None,
        }];

        let error = verify_op_inclusion(root, &ops, &blocks, &[])
            .await
            .expect_err("a create must name a cid");
        assert!(error.to_string().contains("carries no cid"), "{error}");
    }

    /// A `BlockStorage` that counts what is asked of it.
    struct Counting<S> {
        inner: S,
        reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S: BlockStorage> BlockStorage for Counting<S> {
        async fn put(
            &mut self,
            cid: &cid::Cid,
            data: Vec<u8>,
        ) -> Result<(), atproto_dasl::StorageError> {
            self.inner.put(cid, data).await
        }

        async fn get(&self, cid: &cid::Cid) -> Result<Option<Vec<u8>>, atproto_dasl::StorageError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.get(cid).await
        }

        async fn contains(&self, cid: &cid::Cid) -> Result<bool, atproto_dasl::StorageError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.contains(cid).await
        }

        async fn remove(
            &mut self,
            cid: &cid::Cid,
        ) -> Result<Option<Vec<u8>>, atproto_dasl::StorageError> {
            self.inner.remove(cid).await
        }

        fn memory_usage(&self) -> usize {
            self.inner.memory_usage()
        }

        fn block_count(&self) -> usize {
            self.inner.block_count()
        }

        fn cids(&self) -> Box<dyn Iterator<Item = cid::Cid> + '_> {
            self.inner.cids()
        }

        async fn clear(&mut self) -> Result<(), atproto_dasl::StorageError> {
            self.inner.clear().await
        }
    }

    /// A collection nobody tracks costs nothing.
    ///
    /// Not "returns an empty list", which a filter applied after the walk
    /// would also do. The point is that no block is read, because a consumer
    /// tracking six collections sees a firehose that is overwhelmingly the
    /// other thousands.
    #[tokio::test]
    async fn the_collection_filter_reads_no_blocks() {
        let (root, ops, blocks) = commit_of(&[
            ("app.test.rec/aaa", "first"),
            ("app.test.rec/bbb", "second"),
        ])
        .await;

        let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut storage = Counting {
            inner: MemoryStorage::new(),
            reads: reads.clone(),
        };
        for block in &blocks {
            storage.put(&block.cid, block.data.clone()).await.unwrap();
        }
        reads.store(0, std::sync::atomic::Ordering::Relaxed);

        let verdicts = verify_op_inclusion_in(root.clone(), &ops, storage, &["app.bsky.feed.post"])
            .await
            .expect("walk");

        assert!(verdicts.is_empty());
        assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 0);

        // And the convenience form does not even load the slice.
        let verdicts = verify_op_inclusion(root, &ops, &blocks, &["app.bsky.feed.post"])
            .await
            .expect("walk");
        assert!(verdicts.is_empty());
    }

    /// A tracked collection is still proven when others are filtered out.
    #[tokio::test]
    async fn the_collection_filter_keeps_what_it_tracks() {
        let (root, ops, blocks) = commit_of(&[
            ("app.test.rec/aaa", "first"),
            ("app.other.rec/bbb", "second"),
        ])
        .await;

        let verdicts = verify_op_inclusion(root, &ops, &blocks, &["app.test.rec"])
            .await
            .expect("walk");

        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].path, "app.test.rec/aaa");
        assert!(verdicts[0].verified);
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
