//! MST node structure.
//!
//! Nodes contain entries and an optional left subtree pointer.

use super::entry::{KeyReconstructor, TreeEntry};
use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

/// An MST node containing tree entries and optional left subtree.
///
/// # Structure
///
/// - `left`: Optional CID of left subtree (contains keys < first entry's key)
/// - `entries`: Array of tree entries at this node
///
/// # DAG-CBOR Format
///
/// ```json
/// {
///   "l": CID,                    // optional left subtree
///   "e": [                       // entries array
///     { "p": 0, "k": "...", "v": CID, "t": CID },
///     ..
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MstNode {
    /// Optional CID of left subtree (contains keys < first entry's key).
    #[serde(rename = "l", skip_serializing_if = "Option::is_none")]
    pub left: Option<Cid>,

    /// Array of tree entries at this node.
    #[serde(rename = "e")]
    pub entries: Vec<TreeEntry>,
}

impl MstNode {
    /// Create an empty node.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            left: None,
            entries: Vec::new(),
        }
    }

    /// Create a node with entries but no left subtree.
    #[must_use]
    pub fn new(entries: Vec<TreeEntry>) -> Self {
        Self {
            left: None,
            entries,
        }
    }

    /// Create a node with a left subtree and entries.
    #[must_use]
    pub fn with_left(left: Cid, entries: Vec<TreeEntry>) -> Self {
        Self {
            left: Some(left),
            entries,
        }
    }

    /// Check if the node is empty (no entries and no left subtree).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.left.is_none()
    }

    /// Check if the node is a leaf (no subtrees at all).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.entries.iter().all(|e| e.tree.is_none())
    }

    /// Get the number of entries in this node.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Get all keys in this node (reconstructed from prefix compression).
    ///
    /// # Errors
    ///
    /// Returns error if key reconstruction fails.
    pub fn keys(&self) -> Result<Vec<String>, crate::errors::MstError> {
        let mut reconstructor = KeyReconstructor::new();
        let mut keys = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            keys.push(reconstructor.next(entry)?);
        }

        Ok(keys)
    }

    /// Get all key-value pairs in this node.
    ///
    /// # Errors
    ///
    /// Returns error if key reconstruction fails.
    pub fn key_values(&self) -> Result<Vec<(String, Cid)>, crate::errors::MstError> {
        let mut reconstructor = KeyReconstructor::new();
        let mut pairs = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            let key = reconstructor.next(entry)?;
            pairs.push((key, entry.value.clone()));
        }

        Ok(pairs)
    }

    /// Find an entry by key.
    ///
    /// Returns the entry and its index if found.
    ///
    /// # Errors
    ///
    /// Returns error if key reconstruction fails.
    pub fn find_entry(
        &self,
        key: &str,
    ) -> Result<Option<(usize, &TreeEntry)>, crate::errors::MstError> {
        let mut reconstructor = KeyReconstructor::new();

        for (i, entry) in self.entries.iter().enumerate() {
            let entry_key = reconstructor.next(entry)?;
            if entry_key == key {
                return Ok(Some((i, entry)));
            }
            if entry_key.as_str() > key {
                // Keys are sorted, so we can stop
                break;
            }
        }

        Ok(None)
    }

    /// Find the insertion point for a key.
    ///
    /// Returns:
    /// - `(index, true)` if the key exists at that index
    /// - `(index, false)` if the key should be inserted at that index
    ///
    /// # Errors
    ///
    /// Returns error if key reconstruction fails.
    pub fn find_insertion_point(
        &self,
        key: &str,
    ) -> Result<(usize, bool), crate::errors::MstError> {
        let mut reconstructor = KeyReconstructor::new();

        for (i, entry) in self.entries.iter().enumerate() {
            let entry_key = reconstructor.next(entry)?;
            match entry_key.as_str().cmp(key) {
                std::cmp::Ordering::Equal => return Ok((i, true)),
                std::cmp::Ordering::Greater => return Ok((i, false)),
                std::cmp::Ordering::Less => continue,
            }
        }

        Ok((self.entries.len(), false))
    }

    /// Get all subtree CIDs (left and entry trees).
    #[must_use]
    pub fn subtree_cids(&self) -> Vec<&Cid> {
        let mut cids = Vec::new();

        if let Some(ref left) = self.left {
            cids.push(left);
        }

        for entry in &self.entries {
            if let Some(ref tree) = entry.tree {
                cids.push(tree);
            }
        }

        cids
    }

    /// Count total subtrees.
    #[must_use]
    pub fn subtree_count(&self) -> usize {
        let left_count = if self.left.is_some() { 1 } else { 0 };
        let entry_count = self.entries.iter().filter(|e| e.tree.is_some()).count();
        left_count + entry_count
    }
}

impl Default for MstNode {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;
    use crate::mst::TreeEntry;

    fn test_cid(data: &[u8]) -> Cid {
        compute_cid(data).into()
    }

    #[test]
    fn test_empty_node() {
        let node = MstNode::empty();
        assert!(node.is_empty());
        assert!(node.is_leaf());
        assert_eq!(node.len(), 0);
    }

    #[test]
    fn test_node_with_entries() {
        let entries = vec![
            TreeEntry::first("app.bsky.feed.post/abc", test_cid(b"1")),
            TreeEntry::new(19, b"def".to_vec(), test_cid(b"2")),
        ];

        let node = MstNode::new(entries);
        assert!(!node.is_empty());
        assert!(node.is_leaf());
        assert_eq!(node.len(), 2);

        let keys = node.keys().unwrap();
        assert_eq!(
            keys,
            vec!["app.bsky.feed.post/abc", "app.bsky.feed.post/def"]
        );
    }

    #[test]
    fn test_node_with_left() {
        let left_cid = test_cid(b"left");
        let entries = vec![TreeEntry::first("key", test_cid(b"value"))];

        let node = MstNode::with_left(left_cid.clone(), entries);
        assert!(!node.is_empty());
        assert!(!node.is_leaf());
        assert_eq!(node.left, Some(left_cid));
    }

    #[test]
    fn test_find_entry() {
        let entries = vec![
            TreeEntry::first("a", test_cid(b"1")),
            TreeEntry::new(0, b"b".to_vec(), test_cid(b"2")),
            TreeEntry::new(0, b"c".to_vec(), test_cid(b"3")),
        ];

        let node = MstNode::new(entries);

        // Find existing
        let result = node.find_entry("b").unwrap();
        assert!(result.is_some());
        let (idx, _entry) = result.unwrap();
        assert_eq!(idx, 1);

        // Find non-existing
        let result = node.find_entry("d").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_find_insertion_point() {
        let entries = vec![
            TreeEntry::first("b", test_cid(b"1")),
            TreeEntry::new(0, b"d".to_vec(), test_cid(b"2")),
        ];

        let node = MstNode::new(entries);

        // Before first
        let (idx, exists) = node.find_insertion_point("a").unwrap();
        assert_eq!(idx, 0);
        assert!(!exists);

        // At first
        let (idx, exists) = node.find_insertion_point("b").unwrap();
        assert_eq!(idx, 0);
        assert!(exists);

        // Between
        let (idx, exists) = node.find_insertion_point("c").unwrap();
        assert_eq!(idx, 1);
        assert!(!exists);

        // After last
        let (idx, exists) = node.find_insertion_point("e").unwrap();
        assert_eq!(idx, 2);
        assert!(!exists);
    }

    #[test]
    fn test_subtree_cids() {
        let left_cid = test_cid(b"left");
        let tree_cid = test_cid(b"tree");

        let entries = vec![
            TreeEntry::first("a", test_cid(b"1")),
            TreeEntry::with_tree(0, b"b".to_vec(), test_cid(b"2"), tree_cid.clone()),
        ];

        let node = MstNode::with_left(left_cid.clone(), entries);

        let cids = node.subtree_cids();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&&left_cid));
        assert!(cids.contains(&&tree_cid));
    }

    #[test]
    fn test_key_values() {
        let cid1 = test_cid(b"1");
        let cid2 = test_cid(b"2");

        let entries = vec![
            TreeEntry::first("key1", cid1.clone()),
            TreeEntry::new(3, b"2".to_vec(), cid2.clone()),
        ];

        let node = MstNode::new(entries);
        let pairs = node.key_values().unwrap();

        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("key1".to_string(), cid1));
        assert_eq!(pairs[1], ("key2".to_string(), cid2));
    }
}
