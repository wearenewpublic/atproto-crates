//! MST tree operations.
//!
//! The main `Mst` struct provides CRUD operations on the Merkle Search Tree.

use super::MstNode;
use super::entry::TreeEntry;
use super::key::key_height;
use crate::config::RepoConfig;
use crate::errors::MstError;
use atproto_dasl::Cid;
use atproto_dasl::storage::{BlockStorage, MemoryStorage};

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
        let root_cid = match &self.root {
            Some(cid) => cid,
            None => return Ok(None),
        };

        self.get_recursive(root_cid, key, 0).await
    }

    async fn get_recursive(
        &self,
        cid: &cid::Cid,
        key: &str,
        depth: usize,
    ) -> Result<Option<Cid>, MstError> {
        // Check depth limit
        if depth > self.config.limits.max_depth {
            return Err(MstError::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.limits.max_depth),
            });
        }

        let node = self.load_node(cid).await?;
        let target_height = key_height(key);

        // Find the entry or subtree
        let mut prev_key = String::new();

        for entry in &node.entries {
            let entry_key = entry.reconstruct_key(&prev_key)?;

            if entry_key == key {
                return Ok(Some(entry.value.clone()));
            }

            if entry_key.as_str() > key {
                // Key would be before this entry - check left or entry's tree
                // First check if we should go into a subtree
                break;
            }

            // Check if we should descend into this entry's subtree
            if let Some(ref tree_cid) = entry.tree {
                let entry_height = key_height(&entry_key);
                if target_height <= entry_height && key > entry_key.as_str() {
                    // Key might be in this subtree
                    if let result @ Some(_) =
                        Box::pin(self.get_recursive(tree_cid, key, depth + 1)).await?
                    {
                        return Ok(result);
                    }
                }
            }

            prev_key = entry_key;
        }

        // Check left subtree
        if let Some(ref left_cid) = node.left {
            return Box::pin(self.get_recursive(left_cid, key, depth + 1)).await;
        }

        Ok(None)
    }

    /// Insert a key-value pair. Returns the new root CID.
    ///
    /// Creates new nodes in storage for the modified path.
    ///
    /// # Errors
    ///
    /// Returns `MstError` if the key is invalid or storage fails.
    pub async fn insert(&mut self, key: &str, value: Cid) -> Result<cid::Cid, MstError> {
        super::key::validate_key(key).map_err(|reason| MstError::InvalidNode { reason })?;

        let new_root = match &self.root {
            Some(root_cid) => {
                let root_cid = *root_cid;
                self.insert_recursive(&root_cid, key, value, 0).await?
            }
            None => {
                // Empty tree - create root node with single entry
                let entry = TreeEntry::first(key, value);
                let node = MstNode::new(vec![entry]);
                self.store_node(&node).await?
            }
        };

        self.root = Some(new_root);
        Ok(new_root)
    }

    async fn insert_recursive(
        &mut self,
        cid: &cid::Cid,
        key: &str,
        value: Cid,
        depth: usize,
    ) -> Result<cid::Cid, MstError> {
        if depth > self.config.limits.max_depth {
            return Err(MstError::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.limits.max_depth),
            });
        }

        let node = self.load_node(cid).await?;
        let _target_height = key_height(key);

        // Simple case: insert into entries
        let (insert_idx, exists) = node.find_insertion_point(key)?;

        if exists {
            // Update existing entry
            let mut new_entries = node.entries.clone();
            let mut prev_key = String::new();
            for (i, entry) in new_entries.iter().enumerate() {
                if i == insert_idx {
                    break;
                }
                prev_key = entry.reconstruct_key(&prev_key)?;
            }

            let entry_key = new_entries[insert_idx].reconstruct_key(&prev_key)?;
            let prefix_len = if insert_idx > 0 {
                super::key::common_prefix_len(&prev_key, &entry_key) as u32
            } else {
                0
            };

            new_entries[insert_idx] = TreeEntry {
                prefix_len,
                key_suffix: entry_key.as_bytes()[prefix_len as usize..].to_vec(),
                value,
                tree: new_entries[insert_idx].tree.clone(),
            };

            let new_node = MstNode {
                left: node.left.clone(),
                entries: new_entries,
            };
            return self.store_node(&new_node).await;
        }

        // Insert new entry
        let mut new_entries = node.entries.clone();

        // Calculate the new entry with proper prefix compression
        let prev_key = if insert_idx > 0 {
            let mut k = String::new();
            for (i, entry) in node.entries.iter().enumerate() {
                k = entry.reconstruct_key(&k)?;
                if i == insert_idx - 1 {
                    break;
                }
            }
            k
        } else {
            String::new()
        };

        let new_entry = TreeEntry::with_prefix(&prev_key, key, value);
        new_entries.insert(insert_idx, new_entry);

        // Fix prefix compression for the next entry if it exists
        if insert_idx + 1 < new_entries.len() {
            let next_entry = &new_entries[insert_idx + 1];
            let next_key = next_entry.reconstruct_key(&prev_key)?;

            // Recompute with new previous key
            let new_prefix_len = super::key::common_prefix_len(key, &next_key) as u32;
            new_entries[insert_idx + 1] = TreeEntry {
                prefix_len: new_prefix_len,
                key_suffix: next_key.as_bytes()[new_prefix_len as usize..].to_vec(),
                value: next_entry.value.clone(),
                tree: next_entry.tree.clone(),
            };
        }

        let new_node = MstNode {
            left: node.left.clone(),
            entries: new_entries,
        };

        self.store_node(&new_node).await
    }

    /// Delete a key. Returns the new root CID (or None if tree is now empty).
    ///
    /// # Errors
    ///
    /// Returns `MstError` if the key is invalid or storage fails.
    pub async fn delete(&mut self, key: &str) -> Result<Option<cid::Cid>, MstError> {
        let root_cid = match &self.root {
            Some(cid) => *cid,
            None => return Ok(None),
        };

        let new_root = self.delete_recursive(&root_cid, key, 0).await?;

        // Check if root is now empty
        if let Some(ref cid) = new_root {
            let node = self.load_node(cid).await?;
            if node.is_empty() {
                self.root = None;
                return Ok(None);
            }
        }

        self.root = new_root;
        Ok(self.root)
    }

    async fn delete_recursive(
        &mut self,
        cid: &cid::Cid,
        key: &str,
        depth: usize,
    ) -> Result<Option<cid::Cid>, MstError> {
        if depth > self.config.limits.max_depth {
            return Err(MstError::StructureViolation {
                reason: format!("max depth {} exceeded", self.config.limits.max_depth),
            });
        }

        let node = self.load_node(cid).await?;
        let (delete_idx, exists) = node.find_insertion_point(key)?;

        if !exists {
            // Key not found, return unchanged
            return Ok(Some(*cid));
        }

        // Rebuild the entry list from full keys rather than patching the
        // compression of the entry that follows the deleted one.
        //
        // Entries are prefix-compressed against the *full key of the preceding
        // entry*, so removing one changes the base its successor was encoded
        // against. Repairing that in place needs two steps in the right order —
        // reconstruct the successor's key against the entry being deleted, then
        // re-compress it against the entry before that — and getting the order
        // wrong silently rewrites a neighbouring record's key rather than
        // failing. Worse, every later entry reconstructs against the corrupted
        // key, so the damage runs to the end of the node.
        //
        // Deriving all the keys first and re-compressing the whole list makes
        // that class of error unrepresentable: there is no index arithmetic to
        // get backwards. It is also what the reference and every port do, at
        // serialization time.
        let mut full_keys = Vec::with_capacity(node.entries.len());
        let mut previous = String::new();
        for entry in &node.entries {
            let key = entry.reconstruct_key(&previous)?;
            previous = key.clone();
            full_keys.push(key);
        }

        let mut surviving = node.entries.clone();
        surviving.remove(delete_idx);
        full_keys.remove(delete_idx);

        let mut new_entries = Vec::with_capacity(surviving.len());
        let mut previous = String::new();
        for (entry, key) in surviving.iter().zip(full_keys.iter()) {
            let mut rebuilt = TreeEntry::with_prefix(&previous, key, entry.value.clone());
            rebuilt.tree = entry.tree.clone();
            new_entries.push(rebuilt);
            previous = key.clone();
        }

        if new_entries.is_empty() && node.left.is_none() {
            return Ok(None);
        }

        let new_node = MstNode {
            left: node.left.clone(),
            entries: new_entries,
        };

        let new_cid = self.store_node(&new_node).await?;
        Ok(Some(new_cid))
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
