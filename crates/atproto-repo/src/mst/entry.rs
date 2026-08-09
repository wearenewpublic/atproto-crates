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

    /// CID of the right subtree, or `None`.
    ///
    /// Contains keys > this key and < next key (if any).
    ///
    /// Serialized as an explicit `null` when absent, never omitted: the MST
    /// schema types this as nullable-and-required, so dropping the key changes
    /// the enclosing node's CID and with it every ancestor up to the repo root.
    #[serde(rename = "t")]
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
    /// `prefix_len` and `key_suffix` both come off the wire, so neither is
    /// known to be anything until checked. The prefix is a byte count into
    /// `prev_key`, and a count that lands inside a multi-byte character is a
    /// number this function cannot use — `&prev_key[..prefix_len]` would panic
    /// on it rather than return, which in a parser reached from an uploaded CAR
    /// is a denial of service and, once a half-applied import has stored the
    /// node, a repository that panics on every subsequent read of it.
    ///
    /// The two halves are joined as bytes and validated once, so a split that
    /// lands mid-character and a suffix that is not UTF-8 arrive at the same
    /// place: an error naming the key that could not be built.
    ///
    /// # Errors
    ///
    /// Returns [`MstError::InvalidPrefix`](crate::errors::MstError::InvalidPrefix)
    /// when `prefix_len` exceeds the previous key, when it does not fall on a
    /// character boundary, or when the two halves do not form valid UTF-8.
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

        let mut key = Vec::with_capacity(prefix_len + self.key_suffix.len());
        key.extend_from_slice(&prev_key.as_bytes()[..prefix_len]);
        key.extend_from_slice(&self.key_suffix);

        String::from_utf8(key).map_err(|e| crate::errors::MstError::InvalidPrefix {
            reason: format!(
                "prefix_len {prefix_len} and key suffix do not form a valid UTF-8 key: {e}"
            ),
        })
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

    /// A prefix that lands inside a multi-byte character is refused, not
    /// panicked on.
    ///
    /// `prefix_len` is a byte count off the wire and `&prev_key[..n]` panics
    /// when `n` is not a character boundary. The length check that stood here
    /// does not catch it: 1 is a perfectly good index into a two-byte key and
    /// still splits it in half. Two entries are enough — one establishing a
    /// key whose first character is multi-byte, the next claiming one byte of
    /// it — and the whole thing is valid canonical DAG-CBOR that
    /// content-addresses correctly, so nothing upstream refuses it first.
    ///
    /// Reached from an uploaded CAR, so the panic is a denial of service; and
    /// because the import that carried it has already written blocks by the
    /// time keys are reconstructed, the node stays and every later read of
    /// that repository panics on it again.
    #[test]
    fn a_prefix_splitting_a_character_is_refused() {
        // "é" is two bytes, so a prefix of 1 falls inside it.
        let previous = "é";
        let entry = TreeEntry::new(1, b"x".to_vec(), test_cid());

        let result = entry.reconstruct_key(previous);

        assert!(
            result.is_err(),
            "a prefix landing mid-character produced {result:?}"
        );
    }

    /// The same prefix on a key where it *is* a boundary still reconstructs,
    /// so the check refuses the split and not the character.
    #[test]
    fn a_multibyte_key_still_reconstructs_on_a_boundary() {
        let previous = "éb";
        // 2 is the boundary after "é".
        let entry = TreeEntry::new(2, "c".as_bytes().to_vec(), test_cid());

        let key = entry
            .reconstruct_key(previous)
            .expect("a prefix on a character boundary is valid");
        assert_eq!(key, "éc");
    }

    /// Halves that are each invalid UTF-8 but concatenate to a valid key are
    /// accepted, because the key is the concatenation. Validating the suffix
    /// alone would refuse this.
    #[test]
    fn halves_are_validated_as_the_key_they_form() {
        // "é" split across the prefix and the suffix.
        let previous = "é";
        let entry = TreeEntry::new(1, vec![0xA9], test_cid());

        let key = entry
            .reconstruct_key(previous)
            .expect("the halves form a valid key");
        assert_eq!(key, "é");
    }

    #[test]
    fn test_invalid_prefix_len() {
        let entry = TreeEntry::new(100, b"suffix".to_vec(), test_cid());

        // Previous key is too short
        let result = entry.reconstruct_key("short");
        assert!(result.is_err());
    }
}
