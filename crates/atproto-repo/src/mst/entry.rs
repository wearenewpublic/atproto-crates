//! Tree entry structure with prefix compression.
//!
//! Entries use prefix compression to reduce storage size by storing
//! only the suffix of each key relative to the previous key.

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

/// A single entry in an MST node.
///
/// Entries use prefix compression: each entry stores how many characters
/// are shared with the previous key's suffix (not the full previous key).
///
/// # DAG-CBOR Format
///
/// ```json
/// {
///   "p": 19,                    // prefix_len: chars shared with previous
///   "k": "def",                 // key_suffix: remaining chars after prefix
///   "v": CID,                   // value: CID of the record
///   "t": CID                    // tree: optional CID of right subtree
/// }
/// ```
///
/// # Prefix Compression Example
///
/// For keys `["app.bsky.feed.post/abc", "app.bsky.feed.post/def"]`:
///
/// | Entry | Full Key | prefix_len | key_suffix |
/// |-------|----------|------------|------------|
/// | 0 | `app.bsky.feed.post/abc` | 0 | `app.bsky.feed.post/abc` |
/// | 1 | `app.bsky.feed.post/def` | 19 | `def` |
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreeEntry {
    /// Number of characters shared with previous key (prefix compression).
    ///
    /// For the first entry in a node, this is 0.
    #[serde(rename = "p")]
    pub prefix_len: u32,

    /// Key suffix (characters after shared prefix).
    ///
    /// Stored as bytes to preserve exact encoding.
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_suffix: Vec<u8>,

    /// CID of the record value.
    #[serde(rename = "v")]
    pub value: Cid,

    /// Optional CID of right subtree.
    ///
    /// Contains keys > this key and < next key (if any).
    #[serde(rename = "t", skip_serializing_if = "Option::is_none")]
    pub tree: Option<Cid>,
}

impl TreeEntry {
    /// Create a new entry without a subtree.
    #[must_use]
    pub fn new(prefix_len: u32, key_suffix: Vec<u8>, value: Cid) -> Self {
        Self {
            prefix_len,
            key_suffix,
            value,
            tree: None,
        }
    }

    /// Create a new entry with a subtree.
    #[must_use]
    pub fn with_tree(prefix_len: u32, key_suffix: Vec<u8>, value: Cid, tree: Cid) -> Self {
        Self {
            prefix_len,
            key_suffix,
            value,
            tree: Some(tree),
        }
    }

    /// Create an entry for the first key in a node (no prefix compression).
    #[must_use]
    pub fn first(key: &str, value: Cid) -> Self {
        Self {
            prefix_len: 0,
            key_suffix: key.as_bytes().to_vec(),
            value,
            tree: None,
        }
    }

    /// Create an entry with prefix compression relative to the previous key.
    #[must_use]
    pub fn with_prefix(prev_key: &str, key: &str, value: Cid) -> Self {
        let common = super::key::common_prefix_len(prev_key, key);
        Self {
            prefix_len: common as u32,
            key_suffix: key.as_bytes()[common..].to_vec(),
            value,
            tree: None,
        }
    }

    /// Get the key suffix as a string.
    ///
    /// # Errors
    ///
    /// Returns error if the suffix is not valid UTF-8.
    pub fn key_suffix_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.key_suffix)
    }

    /// Reconstruct the full key given the previous key.
    ///
    /// # Errors
    ///
    /// Returns error if the key cannot be reconstructed.
    pub fn reconstruct_key(&self, prev_key: &str) -> Result<String, crate::errors::MstError> {
        let prefix_len = self.prefix_len as usize;

        if prefix_len > prev_key.len() {
            return Err(crate::errors::MstError::InvalidPrefix {
                reason: format!(
                    "prefix_len {} exceeds previous key length {}",
                    prefix_len,
                    prev_key.len()
                ),
            });
        }

        let suffix = std::str::from_utf8(&self.key_suffix).map_err(|e| {
            crate::errors::MstError::InvalidPrefix {
                reason: format!("invalid UTF-8 in key suffix: {}", e),
            }
        })?;

        let key = format!("{}{}", &prev_key[..prefix_len], suffix);
        Ok(key)
    }

    /// Check if this entry has a subtree.
    #[must_use]
    pub fn has_tree(&self) -> bool {
        self.tree.is_some()
    }
}

/// Helper for reconstructing keys from a sequence of entries.
pub struct KeyReconstructor {
    current_key: String,
}

impl KeyReconstructor {
    /// Create a new reconstructor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_key: String::new(),
        }
    }

    /// Reconstruct the next key from an entry.
    ///
    /// # Errors
    ///
    /// Returns error if the key cannot be reconstructed.
    pub fn next(&mut self, entry: &TreeEntry) -> Result<String, crate::errors::MstError> {
        let key = entry.reconstruct_key(&self.current_key)?;
        self.current_key = key.clone();
        Ok(key)
    }

    /// Get the current key.
    #[must_use]
    #[allow(dead_code)]
    pub fn current(&self) -> &str {
        &self.current_key
    }
}

impl Default for KeyReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;

    fn test_cid() -> Cid {
        compute_cid(b"test").into()
    }

    #[test]
    fn test_entry_first() {
        let entry = TreeEntry::first("app.bsky.feed.post/abc", test_cid());

        assert_eq!(entry.prefix_len, 0);
        assert_eq!(entry.key_suffix, b"app.bsky.feed.post/abc");
        assert!(entry.tree.is_none());
    }

    #[test]
    fn test_entry_with_prefix() {
        let prev_key = "app.bsky.feed.post/abc";
        let key = "app.bsky.feed.post/def";

        let entry = TreeEntry::with_prefix(prev_key, key, test_cid());

        assert_eq!(entry.prefix_len, 19); // "app.bsky.feed.post/" = 19 chars
        assert_eq!(entry.key_suffix, b"def");
    }

    #[test]
    fn test_reconstruct_key() {
        let cid = test_cid();

        // First entry - full key
        let entry1 = TreeEntry::first("app.bsky.feed.post/abc", cid.clone());
        let key1 = entry1.reconstruct_key("").unwrap();
        assert_eq!(key1, "app.bsky.feed.post/abc");

        // Second entry - with prefix compression
        let entry2 = TreeEntry::with_prefix(&key1, "app.bsky.feed.post/def", cid);
        let key2 = entry2.reconstruct_key(&key1).unwrap();
        assert_eq!(key2, "app.bsky.feed.post/def");
    }

    #[test]
    fn test_key_reconstructor() {
        let cid = test_cid();

        let entries = [
            TreeEntry::first("app.bsky.feed.post/abc", cid.clone()),
            TreeEntry::new(19, b"def".to_vec(), cid.clone()),
            TreeEntry::new(19, b"ghi".to_vec(), cid),
        ];

        let mut reconstructor = KeyReconstructor::new();

        let key1 = reconstructor.next(&entries[0]).unwrap();
        assert_eq!(key1, "app.bsky.feed.post/abc");

        let key2 = reconstructor.next(&entries[1]).unwrap();
        assert_eq!(key2, "app.bsky.feed.post/def");

        let key3 = reconstructor.next(&entries[2]).unwrap();
        assert_eq!(key3, "app.bsky.feed.post/ghi");
    }

    #[test]
    fn test_entry_with_tree() {
        let cid = test_cid();
        let tree_cid: Cid = compute_cid(b"tree").into();

        let entry = TreeEntry::with_tree(0, b"key".to_vec(), cid, tree_cid.clone());

        assert!(entry.has_tree());
        assert_eq!(entry.tree, Some(tree_cid));
    }

    #[test]
    fn test_invalid_prefix_len() {
        let entry = TreeEntry::new(100, b"suffix".to_vec(), test_cid());

        // Previous key is too short
        let result = entry.reconstruct_key("short");
        assert!(result.is_err());
    }
}
