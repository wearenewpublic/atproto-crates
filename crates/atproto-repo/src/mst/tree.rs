//! MST tree operations.
//!
//! The main `Mst` struct provides CRUD operations on the Merkle Search Tree.

use super::MstNode;
use super::entries::{self, NodeEntry};
use super::key::key_height;
use crate::config::RepoConfig;
use crate::errors::MstError;
use atproto_dasl::Cid;
use atproto_dasl::storage::{BlockStorage, MemoryStorage};
use std::collections::HashMap;

/// Merkle Search Tree backed by pluggable block storage.
///
/// Supports streaming traversal for memory-efficient processing of large trees.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_repo::mst::Mst;
/// use atproto_repo::storage::MemoryStorage;
///
/// async fn example() -> anyhow::Result<()> {
///     let storage = MemoryStorage::new();
///     let mut mst = Mst::new(storage, RepoConfig::default());
///
///     // Insert a key-value pair
///     let cid = compute_cid(b"record data");
///     let new_root = mst.insert("app.bsky.feed.post/abc", cid.into()).await?;
///
///     // Lookup
///     let value = mst.get("app.bsky.feed.post/abc").await?;
///
///     Ok(())
/// }
/// ```
pub struct Mst<S: BlockStorage> {
    /// Block storage backend.
    storage: S,
    /// Root CID (None if empty tree).
    root: Option<cid::Cid>,
    /// Configuration with limits.
    config: RepoConfig,
}

impl<S: BlockStorage> Mst<S> {
    /// Create an empty MST with storage backend.
    #[must_use]
    pub fn new(storage: S, config: RepoConfig) -> Self {
        Self {
            storage,
            root: None,
            config,
        }
    }

    /// Create MST from an existing root CID.
    #[must_use]
    pub fn from_root(root: cid::Cid, storage: S, config: RepoConfig) -> Self {
        Self {
            storage,
            root: Some(root),
            config,
        }
    }

    /// Get the root CID.
    #[must_use]
    pub fn root(&self) -> Option<&cid::Cid> {
        self.root.as_ref()
    }

    /// Check if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Get reference to the storage backend.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get mutable reference to the storage backend.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Consume MST and return storage.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// Load a node from storage.
    async fn load_node(&self, cid: &cid::Cid) -> Result<MstNode, MstError> {
        let bytes = self
            .storage
            .get(cid)
            .await?
            .ok_or_else(|| MstError::NodeNotFound {
                cid: cid.to_string(),
            })?;

        MstNode::from_bytes(&bytes)
    }

    /// Store a node in storage.
    async fn store_node(&mut self, node: &MstNode) -> Result<cid::Cid, MstError> {
        let bytes = node.to_bytes()?;
        let cid = crate::compute_cid(&bytes);
        self.storage.put(&cid, bytes).await?;
        Ok(cid)
    }

    /// Get a value by key.
    ///
    /// Lazily loads nodes from storage as needed.
    ///
    /// # Errors
    ///
    /// Returns `MstError` if the key is invalid or node loading fails.
    pub async fn get(&self, key: &str) -> Result<Option<Cid>, MstError> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        self.get_at(&root, key, 0).await
    }

    /// Look for `key` in the node at `cid`, descending as needed.
    ///
    /// Descent is structural rather than heuristic: the first leaf at or after
    /// `key` bounds the search, and anything smaller lives in the child
    /// immediately before that position — `l` when the position is the front of
    /// the node, otherwise the preceding leaf's `t`.
    async fn get_at(
        &self,
        cid: &cid::Cid,
        key: &str,
        depth: usize,
    ) -> Result<Option<Cid>, MstError> {
        self.check_depth(depth)?;
        let entries = entries::from_node(&self.load_node(cid).await?)?;
        let index = entries::find_leaf_index(&entries, key);

        if let Some(NodeEntry::Leaf { key: found, value }) = entries.get(index)
            && found == key
        {
            return Ok(Some(value.clone()));
        }

        match index.checked_sub(1).and_then(|i| entries.get(i)) {
            Some(NodeEntry::Tree(child)) => Box::pin(self.get_at(child, key, depth + 1)).await,
            _ => Ok(None),
        }
    }

    /// Insert a key-value pair. Returns the new root CID.
    ///
    /// # Errors
    ///
    /// Returns `MstError` if the key is invalid or storage fails.
    pub async fn insert(&mut self, key: &str, value: Cid) -> Result<cid::Cid, MstError> {
        super::key::validate_key(key).map_err(|reason| MstError::InvalidNode { reason })?;
        let height = key_height(key);

        let new_root = match self.root {
            Some(root) => {
                let layer = self.layer_of(&root, 0).await?;
                self.insert_at(&root, layer, key, value, height, 0).await?
            }
            None => {
                // The first key placed defines the tree's layer.
                self.store_entries(&[NodeEntry::Leaf {
                    key: key.to_string(),
                    value,
                }])
                .await?
            }
        };

        self.root = Some(new_root);
        Ok(new_root)
    }

    /// Insert into the node at `cid`, which sits at `layer`.
    ///
    /// A key's layer is fixed by its hash, so there are exactly three cases:
    /// the key belongs at this layer, below it, or above it. Placing a key
    /// anywhere else produces a tree that is internally consistent and hashes
    /// differently from every other implementation's.
    async fn insert_at(
        &mut self,
        cid: &cid::Cid,
        layer: u32,
        key: &str,
        value: Cid,
        height: u32,
        depth: usize,
    ) -> Result<cid::Cid, MstError> {
        self.check_depth(depth)?;
        let mut entries = entries::from_node(&self.load_node(cid).await?)?;
        let index = entries::find_leaf_index(&entries, key);

        if height == layer {
            if let Some(NodeEntry::Leaf { key: found, .. }) = entries.get(index)
                && found == key
            {
                entries[index] = NodeEntry::Leaf {
                    key: key.to_string(),
                    value,
                };
                return self.store_entries(&entries).await;
            }

            let leaf = NodeEntry::Leaf {
                key: key.to_string(),
                value,
            };
            match index.checked_sub(1).and_then(|i| entries.get(i)).cloned() {
                // A subtree occupies the gap the key falls into, so it spans
                // the key and has to be cut in two around it.
                Some(NodeEntry::Tree(child)) => {
                    let (left, right) = Box::pin(self.split_around(&child, key, depth + 1)).await?;
                    let mut replacement = Vec::new();
                    replacement.extend(left.map(NodeEntry::Tree));
                    replacement.push(leaf);
                    replacement.extend(right.map(NodeEntry::Tree));
                    entries.splice(index - 1..index, replacement);
                }
                // Otherwise the key slots straight in.
                _ => entries.insert(index, leaf),
            }
            return self.store_entries(&entries).await;
        }

        if height < layer {
            // Belongs further down: descend into the child before this
            // position, creating it when that gap is empty.
            match index.checked_sub(1).and_then(|i| entries.get(i)).cloned() {
                Some(NodeEntry::Tree(child)) => {
                    let updated =
                        Box::pin(self.insert_at(&child, layer - 1, key, value, height, depth + 1))
                            .await?;
                    entries[index - 1] = NodeEntry::Tree(updated);
                }
                _ => {
                    let mut child = self
                        .store_entries(&[NodeEntry::Leaf {
                            key: key.to_string(),
                            value,
                        }])
                        .await?;
                    // The leaf may belong several layers down; wrap it until it
                    // reaches the layer directly below this node.
                    for _ in (height + 1)..layer {
                        child = self.store_entries(&[NodeEntry::Tree(child)]).await?;
                    }
                    entries.insert(index, NodeEntry::Tree(child));
                }
            }
            return self.store_entries(&entries).await;
        }

        // Belongs above the current root. Split what is there around the key
        // and hang both halves off a new node, inserting bare structural
        // layers between when the jump is more than one.
        let (mut left, mut right) = Box::pin(self.split_around(cid, key, depth + 1)).await?;
        for _ in 1..(height - layer) {
            if let Some(cid) = left {
                left = Some(self.store_entries(&[NodeEntry::Tree(cid)]).await?);
            }
            if let Some(cid) = right {
                right = Some(self.store_entries(&[NodeEntry::Tree(cid)]).await?);
            }
        }
        let mut top = Vec::new();
        top.extend(left.map(NodeEntry::Tree));
        top.push(NodeEntry::Leaf {
            key: key.to_string(),
            value,
        });
        top.extend(right.map(NodeEntry::Tree));
        self.store_entries(&top).await
    }

    /// Cut the subtree at `cid` into the parts below and above `key`.
    ///
    /// Either side is `None` when it would be empty. A subtree straddling the
    /// boundary is itself split, recursively, so both halves stay well-formed
    /// all the way down.
    async fn split_around(
        &mut self,
        cid: &cid::Cid,
        key: &str,
        depth: usize,
    ) -> Result<(Option<cid::Cid>, Option<cid::Cid>), MstError> {
        self.check_depth(depth)?;
        let entries = entries::from_node(&self.load_node(cid).await?)?;
        let index = entries::find_leaf_index(&entries, key);
        let mut left: Vec<NodeEntry> = entries[..index].to_vec();
        let mut right: Vec<NodeEntry> = entries[index..].to_vec();

        if let Some(NodeEntry::Tree(child)) = left.last().cloned() {
            left.pop();
            let (inner_left, inner_right) =
                Box::pin(self.split_around(&child, key, depth + 1)).await?;
            left.extend(inner_left.map(NodeEntry::Tree));
            if let Some(cid) = inner_right {
                right.insert(0, NodeEntry::Tree(cid));
            }
        }

        let left = if left.is_empty() {
            None
        } else {
            Some(self.store_entries(&left).await?)
        };
        let right = if right.is_empty() {
            None
        } else {
            Some(self.store_entries(&right).await?)
        };
        Ok((left, right))
    }

    /// Delete a key. Returns the new root CID (or None if tree is now empty).
    ///
    /// # Errors
    ///
    /// Returns `MstError` if the key is invalid or storage fails.
    pub async fn delete(&mut self, key: &str) -> Result<Option<cid::Cid>, MstError> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        self.root = match self.delete_at(&root, key, 0).await? {
            Some(cid) => Some(self.trim_top(cid, 0).await?),
            None => None,
        };
        Ok(self.root)
    }

    /// Remove `key` from the node at `cid`, descending the way `get` does.
    ///
    /// Returns `None` when the node is left with no children at all.
    async fn delete_at(
        &mut self,
        cid: &cid::Cid,
        key: &str,
        depth: usize,
    ) -> Result<Option<cid::Cid>, MstError> {
        self.check_depth(depth)?;
        let mut entries = entries::from_node(&self.load_node(cid).await?)?;
        let index = entries::find_leaf_index(&entries, key);

        let found_here = matches!(
            entries.get(index),
            Some(NodeEntry::Leaf { key: found, .. }) if found == key
        );

        if found_here {
            entries.remove(index);
            // Removing a leaf can leave the subtrees that flanked it side by
            // side. Nothing separates them any more, so they are one subtree
            // and have to be joined — every key in the left is below every key
            // in the right, which is what makes the join a simple append.
            if index > 0
                && let (Some(NodeEntry::Tree(left)), Some(NodeEntry::Tree(right))) =
                    (entries.get(index - 1).cloned(), entries.get(index).cloned())
            {
                let merged = Box::pin(self.append_merge(&left, &right, depth + 1)).await?;
                entries.splice(index - 1..=index, [NodeEntry::Tree(merged)]);
            }
        } else {
            match index.checked_sub(1).and_then(|i| entries.get(i)).cloned() {
                Some(NodeEntry::Tree(child)) => {
                    match Box::pin(self.delete_at(&child, key, depth + 1)).await? {
                        Some(updated) => entries[index - 1] = NodeEntry::Tree(updated),
                        None => {
                            entries.remove(index - 1);
                        }
                    }
                }
                // Not in this tree; leave it untouched.
                _ => return Ok(Some(*cid)),
            }
        }

        if entries.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.store_entries(&entries).await?))
    }

    /// Join two adjacent subtrees of the same layer into one.
    ///
    /// Only valid when every key in `left` sorts below every key in `right`,
    /// which is exactly the situation a deletion creates. When the seam itself
    /// is two subtrees — the last child of `left` and the first of `right` —
    /// they meet the same condition one layer down, so the join recurses.
    async fn append_merge(
        &mut self,
        left: &cid::Cid,
        right: &cid::Cid,
        depth: usize,
    ) -> Result<cid::Cid, MstError> {
        self.check_depth(depth)?;
        let left_entries = entries::from_node(&self.load_node(left).await?)?;
        let right_entries = entries::from_node(&self.load_node(right).await?)?;

        let joined = match (left_entries.last().cloned(), right_entries.first().cloned()) {
            (Some(NodeEntry::Tree(inner_left)), Some(NodeEntry::Tree(inner_right))) => {
                let merged =
                    Box::pin(self.append_merge(&inner_left, &inner_right, depth + 1)).await?;
                let mut joined = left_entries[..left_entries.len() - 1].to_vec();
                joined.push(NodeEntry::Tree(merged));
                joined.extend_from_slice(&right_entries[1..]);
                joined
            }
            _ => {
                let mut joined = left_entries;
                joined.extend(right_entries);
                joined
            }
        };

        self.store_entries(&joined).await
    }

    /// Drop layers above the highest one that still holds a key.
    ///
    /// A deletion can leave the root as a chain of nodes that carry nothing but
    /// a pointer to the next one down. Those layers are real structure to a
    /// hash, so leaving them in place gives a different root CID than the same
    /// content built from scratch.
    async fn trim_top(&self, mut cid: cid::Cid, depth: usize) -> Result<cid::Cid, MstError> {
        for step in 0.. {
            self.check_depth(depth + step)?;
            let entries = entries::from_node(&self.load_node(&cid).await?)?;
            match entries.as_slice() {
                [NodeEntry::Tree(child)] => cid = *child,
                _ => break,
            }
        }
        Ok(cid)
    }

    /// The layer a node sits at, descending until a leaf reveals it.
    ///
    /// A node of pure structure carries no key to derive a layer from, so its
    /// layer is one above whatever its child resolves to.
    async fn layer_of(&self, cid: &cid::Cid, depth: usize) -> Result<u32, MstError> {
        self.check_depth(depth)?;
        let entries = entries::from_node(&self.load_node(cid).await?)?;
        if let Some(layer) = entries::layer_for_entries(&entries) {
            return Ok(layer);
        }
        match entries.first() {
            Some(NodeEntry::Tree(child)) => {
                Ok(Box::pin(self.layer_of(child, depth + 1)).await? + 1)
            }
            _ => Ok(0),
        }
    }

    /// Serialize an interleaved child list and persist it.
    async fn store_entries(&mut self, entries: &[NodeEntry]) -> Result<cid::Cid, MstError> {
        let node = entries::to_node(entries)?;
        self.store_node(&node).await
    }

    /// Guard against a cycle or a pathologically deep tree.
    fn check_depth(&self, depth: usize) -> Result<(), MstError> {
        if depth > self.config.limits.max_depth {
            return Err(MstError::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.limits.max_depth),
            });
        }
        Ok(())
    }

    /// Iterate over all key-value pairs in sorted order.
    ///
    /// Returns pairs as `(key, cid)`.
    ///
    /// # Errors
    ///
    /// Returns `MstError` if traversal fails.
    /// Blocks proving what this tree says about `key`.
    ///
    /// A Sync 1.1 consumer verifies a commit *inductively*: from the previous
    /// root and the frame's blocks alone, without holding the repository. To do
    /// that for an operation on `key` it must be able to walk from the root to
    /// where `key` sits — or would sit — and to see the neighbours that decide
    /// the shape of that path. The blocks a commit happens to write are not
    /// enough: a node whose child was untouched still needs that child present
    /// to be checked, which is why a consumer without this proof reports
    /// "partial MST, can't determine insertion order" and rejects the frame.
    ///
    /// The proof is the union of three descents, matching the reference
    /// (`packages/repo/src/mst/mst.ts:784-849`): the path to the key itself and
    /// the paths to its left and right neighbouring subtrees. The neighbours
    /// matter because an insert or delete can rebalance across them, so their
    /// prior shape is part of what the new root asserts.
    ///
    /// Call on the tree *after* the commit, as the reference does.
    ///
    /// Written as three loops rather than three recursive calls. Each descent
    /// is a tail descent, and `BlockStorage::get` is an `async fn` in a trait —
    /// its future is not automatically `Send`, so a boxed recursive future
    /// cannot satisfy the `Send` bound axum requires of a handler.
    pub async fn covering_proof(&self, key: &str) -> Result<HashMap<cid::Cid, Vec<u8>>, MstError> {
        let mut out = HashMap::new();
        let Some(root) = self.root else {
            return Ok(out);
        };
        self.proof_for_key(root, key, &mut out).await?;
        self.proof_for_left_sib(root, key, &mut out).await?;
        self.proof_for_right_sib(root, key, &mut out).await?;
        Ok(out)
    }

    /// Add every node on `path` to the proof.
    async fn add_path(
        &self,
        path: &[cid::Cid],
        out: &mut HashMap<cid::Cid, Vec<u8>>,
    ) -> Result<(), MstError> {
        for cid in path {
            if out.contains_key(cid) {
                continue;
            }
            let node = self.load_node(cid).await?;
            out.insert(*cid, node.to_bytes()?);
        }
        Ok(())
    }

    /// The path from the root down to `key`.
    async fn proof_for_key(
        &self,
        root: cid::Cid,
        key: &str,
        out: &mut HashMap<cid::Cid, Vec<u8>>,
    ) -> Result<(), MstError> {
        let mut path = Vec::new();
        let mut cid = root;
        loop {
            let entries = entries::from_node(&self.load_node(&cid).await?)?;
            path.push(cid);

            let index = entries::find_leaf_index(&entries, key);
            if matches!(entries.get(index), Some(NodeEntry::Leaf { key: k, .. }) if k == key) {
                break;
            }
            let prev = if index == 0 {
                None
            } else {
                entries.get(index - 1)
            };
            match prev {
                Some(NodeEntry::Tree(child)) => cid = *child,
                // The descent runs out here. The reference returns an empty map
                // from this level *without* adding the node it stopped at, so
                // this node is dropped while its ancestors are kept. A proof
                // that differs from the reference's is not interoperable even
                // where it is arguably sufficient.
                _ => {
                    path.pop();
                    break;
                }
            }
        }
        self.add_path(&path, out).await
    }

    /// The path down the left-hand neighbour of `key`.
    async fn proof_for_left_sib(
        &self,
        root: cid::Cid,
        key: &str,
        out: &mut HashMap<cid::Cid, Vec<u8>>,
    ) -> Result<(), MstError> {
        let mut path = Vec::new();
        let mut cid = root;
        loop {
            let entries = entries::from_node(&self.load_node(&cid).await?)?;
            path.push(cid);

            let index = entries::find_leaf_index(&entries, key);
            let prev = if index == 0 {
                None
            } else {
                entries.get(index - 1)
            };
            match prev {
                Some(NodeEntry::Tree(child)) => cid = *child,
                _ => break,
            }
        }
        self.add_path(&path, out).await
    }

    /// The path down the right-hand neighbour of `key`.
    ///
    /// Asymmetric with the left descent: which neighbour to follow depends on
    /// whether the entry at the key's position is a subtree, the key itself, or
    /// some other leaf.
    async fn proof_for_right_sib(
        &self,
        root: cid::Cid,
        key: &str,
        out: &mut HashMap<cid::Cid, Vec<u8>>,
    ) -> Result<(), MstError> {
        let mut path = Vec::new();
        let mut cid = root;
        loop {
            let entries = entries::from_node(&self.load_node(&cid).await?)?;
            path.push(cid);

            let index = entries::find_leaf_index(&entries, key);
            // Fall back to the entry before the position when the position is
            // past the end.
            let found = match entries.get(index) {
                Some(entry) => Some(entry),
                None if index > 0 => entries.get(index - 1),
                None => None,
            };

            let next = match found {
                None => None,
                Some(NodeEntry::Tree(child)) => Some(*child),
                Some(NodeEntry::Leaf { key: found_key, .. }) => {
                    // Past the key, look one further right; otherwise one left.
                    let neighbour = if found_key == key {
                        entries.get(index + 1)
                    } else if index == 0 {
                        None
                    } else {
                        entries.get(index - 1)
                    };
                    match neighbour {
                        Some(NodeEntry::Tree(child)) => Some(*child),
                        _ => None,
                    }
                }
            };

            match next {
                Some(child) => cid = child,
                None => break,
            }
        }
        self.add_path(&path, out).await
    }

    /// Iterate over all key-value pairs in sorted order.
    ///
    /// Returns pairs as `(key, cid)`.
    ///
    /// # Errors
    ///
    /// Returns `MstError` if traversal fails.
    pub async fn entries(&self) -> Result<Vec<(String, Cid)>, MstError> {
        let mut results = Vec::new();

        if let Some(ref root_cid) = self.root {
            self.collect_entries(root_cid, &mut results, 0).await?;
        }

        Ok(results)
    }

    async fn collect_entries(
        &self,
        cid: &cid::Cid,
        results: &mut Vec<(String, Cid)>,
        depth: usize,
    ) -> Result<(), MstError> {
        if depth > self.config.limits.max_depth {
            return Err(MstError::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.limits.max_depth),
            });
        }

        let node = self.load_node(cid).await?;

        // First, traverse left subtree
        if let Some(ref left_cid) = node.left {
            Box::pin(self.collect_entries(left_cid, results, depth + 1)).await?;
        }

        // Then collect entries from this node, traversing subtrees in order
        let mut prev_key = String::new();
        for entry in &node.entries {
            let key = entry.reconstruct_key(&prev_key)?;
            results.push((key.clone(), entry.value.clone()));

            if let Some(ref tree_cid) = entry.tree {
                Box::pin(self.collect_entries(tree_cid, results, depth + 1)).await?;
            }

            prev_key = key;
        }

        Ok(())
    }

    /// Get all entries in a collection (by NSID prefix).
    ///
    /// # Errors
    ///
    /// Returns `MstError` if traversal fails.
    pub async fn list_collection(&self, collection: &str) -> Result<Vec<(String, Cid)>, MstError> {
        let entries = self.entries().await?;
        let prefix = format!("{}/", collection);

        Ok(entries
            .into_iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .collect())
    }
}

/// Convenience type alias for in-memory MST.
pub type MemoryMst = Mst<MemoryStorage>;

impl MemoryMst {
    /// Create an empty in-memory MST.
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self::new(MemoryStorage::new(), RepoConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;

    fn test_cid(data: &[u8]) -> Cid {
        compute_cid(data).into()
    }

    #[tokio::test]
    async fn test_empty_tree() {
        let mst = MemoryMst::new_in_memory();
        assert!(mst.is_empty());
        assert!(mst.root().is_none());

        let result = mst.get("any/key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid.clone())
            .await
            .unwrap();

        assert!(!mst.is_empty());

        let result = mst.get("app.bsky.feed.post/abc").await.unwrap();
        assert_eq!(result, Some(cid));
    }

    #[tokio::test]
    async fn test_insert_multiple() {
        let mut mst = MemoryMst::new_in_memory();

        let cids: Vec<Cid> = (0..5)
            .map(|i| test_cid(format!("v{}", i).as_bytes()))
            .collect();

        for (i, cid) in cids.iter().enumerate() {
            let key = format!("app.bsky.feed.post/{}", i);
            mst.insert(&key, cid.clone()).await.unwrap();
        }

        // Verify all inserted
        for (i, cid) in cids.iter().enumerate() {
            let key = format!("app.bsky.feed.post/{}", i);
            let result = mst.get(&key).await.unwrap();
            assert_eq!(result, Some(cid.clone()));
        }
    }

    #[tokio::test]
    async fn test_update_existing() {
        let mut mst = MemoryMst::new_in_memory();

        let cid1 = test_cid(b"v1");
        let cid2 = test_cid(b"v2");

        mst.insert("app.bsky.feed.post/abc", cid1).await.unwrap();
        mst.insert("app.bsky.feed.post/abc", cid2.clone())
            .await
            .unwrap();

        let result = mst.get("app.bsky.feed.post/abc").await.unwrap();
        assert_eq!(result, Some(cid2));
    }

    #[tokio::test]
    async fn test_delete() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid).await.unwrap();

        let new_root = mst.delete("app.bsky.feed.post/abc").await.unwrap();
        assert!(new_root.is_none());
        assert!(mst.is_empty());
    }

    #[tokio::test]
    async fn test_delete_nonexistent() {
        let mut mst = MemoryMst::new_in_memory();

        let cid = test_cid(b"value");
        mst.insert("app.bsky.feed.post/abc", cid).await.unwrap();

        // Delete non-existent key
        mst.delete("app.bsky.feed.post/xyz").await.unwrap();

        // Original should still exist
        assert!(!mst.is_empty());
    }

    #[tokio::test]
    async fn test_entries() {
        let mut mst = MemoryMst::new_in_memory();

        let keys = vec![
            "app.bsky.feed.post/c",
            "app.bsky.feed.post/a",
            "app.bsky.feed.post/b",
        ];

        for key in &keys {
            let cid = test_cid(key.as_bytes());
            mst.insert(key, cid).await.unwrap();
        }

        let entries = mst.entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        // Should be sorted
        let entry_keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            entry_keys,
            vec![
                "app.bsky.feed.post/a",
                "app.bsky.feed.post/b",
                "app.bsky.feed.post/c"
            ]
        );
    }

    #[tokio::test]
    async fn test_list_collection() {
        let mut mst = MemoryMst::new_in_memory();

        mst.insert("app.bsky.feed.post/a", test_cid(b"1"))
            .await
            .unwrap();
        mst.insert("app.bsky.feed.post/b", test_cid(b"2"))
            .await
            .unwrap();
        mst.insert("app.bsky.graph.follow/c", test_cid(b"3"))
            .await
            .unwrap();

        let posts = mst.list_collection("app.bsky.feed.post").await.unwrap();
        assert_eq!(posts.len(), 2);

        let follows = mst.list_collection("app.bsky.graph.follow").await.unwrap();
        assert_eq!(follows.len(), 1);
    }
}
