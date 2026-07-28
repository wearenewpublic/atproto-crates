//! The CARv1 slice a `#commit` or `#sync` event carries in `blocks`.
//!
//! `com.atproto.sync.subscribeRepos#commit` types `blocks` as `bytes` and
//! describes it as a CAR whose first root is the commit block, carrying the
//! blocks this commit touched. Without it the firehose is an existence
//! notification: a consumer learns a record changed and must come back over
//! XRPC to learn what it says. With it, the stream is a data feed and
//! federation works off the stream alone.
//!
//! # How the block set is determined
//!
//! [`RecordingBlockStorage`] wraps the storage the MST writes through and keeps
//! a copy of every block written during the commit. That is the diff *by
//! construction* — the writer puts exactly the record blocks and MST nodes the
//! commit creates — rather than something re-derived afterwards by comparing
//! two trees.
//!
//! Recording alone over-collects. Applying several operations in one batch
//! rewrites intermediate MST nodes that the final root does not reference, and
//! a re-written record whose bytes are unchanged is put again. So the recorded
//! set is filtered to what is reachable from the new commit, which drops both.
//!
//! # What this is not
//!
//! This is not the Sync 1.1 covering proof (F-FIRE-06). A proof also carries
//! the blocks needed to verify the *prior* state of every touched key, so an
//! inductive consumer can check the operation without holding the repository.
//! The vendored `firehose/commit-proof-fixtures.json` describes that larger
//! set. Until that work lands, consumers that verify inductively will still
//! reject these frames; consumers that trust the PDS can read the records.

use crate::errors::{PdsError, PdsResult};
use atproto_dasl::StorageError;
use atproto_dasl::car::{CarBlock, CarWriter};
use atproto_dasl::storage::BlockStorage;
use atproto_repo::mst::MstNode;
use std::collections::{BTreeMap, HashSet};

/// Block storage that remembers everything written through it.
///
/// Delegates every operation to the wrapped storage; the only addition is that
/// `put` keeps a copy of the block. Reads are untouched, so the MST behaves
/// exactly as it would without the wrapper.
pub struct RecordingBlockStorage<S: BlockStorage> {
    inner: S,
    written: BTreeMap<cid::Cid, Vec<u8>>,
}

impl<S: BlockStorage> RecordingBlockStorage<S> {
    /// Wrap `inner`, recording blocks from this point on.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            written: BTreeMap::new(),
        }
    }

    /// The blocks written so far, by CID.
    #[must_use]
    pub fn written(&self) -> &BTreeMap<cid::Cid, Vec<u8>> {
        &self.written
    }

    /// Give back the wrapped storage along with what was recorded.
    pub fn into_parts(self) -> (S, BTreeMap<cid::Cid, Vec<u8>>) {
        (self.inner, self.written)
    }
}

impl<S: BlockStorage> BlockStorage for RecordingBlockStorage<S> {
    async fn put(&mut self, cid: &cid::Cid, data: Vec<u8>) -> Result<(), StorageError> {
        self.written.insert(*cid, data.clone());
        self.inner.put(cid, data).await
    }

    async fn get(&self, cid: &cid::Cid) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cid).await
    }

    async fn contains(&self, cid: &cid::Cid) -> Result<bool, StorageError> {
        self.inner.contains(cid).await
    }

    async fn remove(&mut self, cid: &cid::Cid) -> Result<Option<Vec<u8>>, StorageError> {
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

    async fn clear(&mut self) -> Result<(), StorageError> {
        self.written.clear();
        self.inner.clear().await
    }
}

/// Follow the links out of a block, if it is one that has any.
///
/// A block is a commit, an MST node, or a record. Only the first two carry
/// structural links; a record's own links point at other repositories' data and
/// are not part of this repository's tree.
fn children(data: &[u8]) -> Vec<cid::Cid> {
    if let Ok(node) = atproto_dasl::from_slice::<MstNode>(data) {
        let mut out = Vec::with_capacity(node.entries.len() * 2 + 1);
        if let Some(left) = &node.left {
            out.push(left.0);
        }
        for entry in &node.entries {
            out.push(entry.value.0);
            if let Some(right) = &entry.tree {
                out.push(right.0);
            }
        }
        return out;
    }
    if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(data) {
        return vec![commit.data.0];
    }
    Vec::new()
}

/// Build the `blocks` CAR for a commit.
///
/// `root` is the new commit's CID and `commit_block` its encoded bytes;
/// `written` is what [`RecordingBlockStorage`] recorded during the commit. The
/// CAR carries the commit block plus every recorded block reachable from it.
///
/// Blocks that the commit did not write are not included even when reachable —
/// they are, by definition, blocks the consumer already has from an earlier
/// event, which is what makes this a diff rather than a snapshot.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the CAR cannot be written.
pub async fn build_commit_car(
    root: &cid::Cid,
    commit_block: &[u8],
    written: &BTreeMap<cid::Cid, Vec<u8>>,
) -> PdsResult<Vec<u8>> {
    let mut selected: Vec<CarBlock> = Vec::new();
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![*root];

    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        // The commit block is not in `written` — it is built after the MST
        // work finishes — so it is supplied separately.
        let data = if cid == *root {
            commit_block.to_vec()
        } else {
            match written.get(&cid) {
                Some(data) => data.clone(),
                // Reachable but not written by this commit: the consumer
                // already has it. Not an error, and not a link to follow —
                // everything below it is equally unchanged.
                None => continue,
            }
        };
        stack.extend(children(&data));
        selected.push(CarBlock { cid, data });
    }

    write_car(root, &selected).await
}

/// Build the `blocks` CAR for a `#sync`.
///
/// `#sync` force-sets a consumer's view of the head without a diff, so it
/// carries the commit block alone — enough to re-anchor on, with the tree
/// fetched through `getRepo` if the consumer needs it.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the CAR cannot be written.
pub async fn build_sync_car(root: &cid::Cid, commit_block: &[u8]) -> PdsResult<Vec<u8>> {
    write_car(
        root,
        &[CarBlock {
            cid: *root,
            data: commit_block.to_vec(),
        }],
    )
    .await
}

async fn write_car(root: &cid::Cid, blocks: &[CarBlock]) -> PdsResult<Vec<u8>> {
    let mut buffer: Vec<u8> = Vec::with_capacity(blocks.iter().map(|b| b.data.len() + 64).sum());
    let mut writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(*root)])
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("firehose CAR header: {e}"),
        })?;
    for block in blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("firehose CAR block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("firehose CAR finish: {e}"),
    })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::cid::compute_cid;
    use atproto_dasl::storage::MemoryStorage;

    async fn read_back(car: &[u8]) -> (cid::Cid, BTreeMap<cid::Cid, Vec<u8>>) {
        let mut reader = atproto_dasl::car::CarReader::new(std::io::Cursor::new(car.to_vec()))
            .await
            .expect("CAR should parse");
        let root = reader.root().cloned().expect("CAR should carry a root").0;
        let mut blocks = BTreeMap::new();
        while let Some(block) = reader.next_block().await.expect("block should read") {
            blocks.insert(block.cid, block.data);
        }
        (root, blocks)
    }

    /// A block written through the wrapper is both stored and recorded.
    #[tokio::test]
    async fn recording_does_not_disturb_the_wrapped_storage() {
        let mut storage = RecordingBlockStorage::new(MemoryStorage::new());
        let data = b"a record".to_vec();
        let cid = compute_cid(&data);
        storage.put(&cid, data.clone()).await.unwrap();

        assert_eq!(storage.get(&cid).await.unwrap(), Some(data.clone()));
        assert!(storage.contains(&cid).await.unwrap());
        assert_eq!(storage.written().get(&cid), Some(&data));
    }

    /// Blocks present before the wrapper was applied are readable but are not
    /// part of the diff.
    #[tokio::test]
    async fn only_blocks_written_through_the_wrapper_are_recorded() {
        let mut inner = MemoryStorage::new();
        let old = b"an earlier record".to_vec();
        let old_cid = compute_cid(&old);
        inner.put(&old_cid, old.clone()).await.unwrap();

        let mut storage = RecordingBlockStorage::new(inner);
        let new = b"a new record".to_vec();
        let new_cid = compute_cid(&new);
        storage.put(&new_cid, new).await.unwrap();

        assert_eq!(
            storage.get(&old_cid).await.unwrap(),
            Some(old),
            "the earlier block is still readable"
        );
        let (_, written) = storage.into_parts();
        assert_eq!(written.len(), 1);
        assert!(!written.contains_key(&old_cid));
    }

    /// The CAR is rooted at the commit and carries it.
    #[tokio::test]
    async fn a_car_is_rooted_at_the_commit_block() {
        let commit = b"pretend commit".to_vec();
        let root = compute_cid(&commit);
        let car = build_commit_car(&root, &commit, &BTreeMap::new())
            .await
            .unwrap();

        let (car_root, blocks) = read_back(&car).await;
        assert_eq!(car_root, root);
        assert_eq!(blocks.get(&root), Some(&commit));
    }

    /// Recorded blocks the new root cannot reach are dropped.
    ///
    /// Applying several operations in one batch leaves intermediate MST nodes
    /// behind; shipping them would inflate every frame with blocks no consumer
    /// can use.
    #[tokio::test]
    async fn unreachable_recorded_blocks_are_dropped() {
        let orphan = b"a superseded intermediate node".to_vec();
        let orphan_cid = compute_cid(&orphan);
        let commit = b"pretend commit".to_vec();
        let root = compute_cid(&commit);

        let mut written = BTreeMap::new();
        written.insert(orphan_cid, orphan);

        let car = build_commit_car(&root, &commit, &written).await.unwrap();
        let (_, blocks) = read_back(&car).await;
        assert!(!blocks.contains_key(&orphan_cid));
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn a_sync_car_carries_the_commit_alone() {
        let commit = b"pretend commit".to_vec();
        let root = compute_cid(&commit);
        let car = build_sync_car(&root, &commit).await.unwrap();

        let (car_root, blocks) = read_back(&car).await;
        assert_eq!(car_root, root);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks.get(&root), Some(&commit));
    }
}
