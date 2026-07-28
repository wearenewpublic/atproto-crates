//! The interleaved child list of an MST node.
//!
//! A node serializes as `{l, e: [{p, k, v, t}]}` — a left pointer plus leaves
//! that each carry an optional right-hand subtree. That layout is compact but
//! awkward to compute over, because a node's children are really a single
//! ordered sequence alternating between subtrees and leaves:
//!
//! ```text
//!   l   e0   e0.t   e1   e1.t   e2 …
//!   ↓    ↓     ↓     ↓     ↓     ↓
//! Tree Leaf  Tree  Leaf  Tree  Leaf …
//! ```
//!
//! Every structural operation — insert, split, merge, delete — is stated in
//! terms of that sequence. Working on the serialized form instead means
//! reasoning about `left` and `tree` as special cases of the same idea, which
//! is where index arithmetic goes wrong.
//!
//! [`NodeEntry`] is that sequence. [`to_node`] and [`from_node`] convert at the
//! storage boundary, and prefix compression is re-derived on the way out rather
//! than carried around, so it cannot drift from the keys it describes.

use atproto_dasl::Cid;

use super::entry::TreeEntry;
use super::node::MstNode;
use crate::errors::MstError;

/// One child of a node: either a record, or a pointer to a subtree.
///
/// Subtrees always sit one layer below the node holding them, and hold keys
/// strictly between their neighbouring leaves.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeEntry {
    /// A record at this node's layer.
    Leaf {
        /// Full key, uncompressed.
        key: String,
        /// CID of the record value.
        value: Cid,
    },
    /// A pointer to a subtree one layer down.
    Tree(cid::Cid),
}

impl NodeEntry {
    /// The key, when this is a leaf.
    #[must_use]
    pub fn leaf_key(&self) -> Option<&str> {
        match self {
            NodeEntry::Leaf { key, .. } => Some(key),
            NodeEntry::Tree(_) => None,
        }
    }

    /// The subtree pointer, when this is a tree.
    #[must_use]
    pub fn tree_cid(&self) -> Option<cid::Cid> {
        match self {
            NodeEntry::Tree(cid) => Some(*cid),
            NodeEntry::Leaf { .. } => None,
        }
    }

    /// Whether this entry is a subtree pointer.
    #[must_use]
    pub fn is_tree(&self) -> bool {
        matches!(self, NodeEntry::Tree(_))
    }
}

/// Expand a stored node into its interleaved child sequence.
///
/// # Errors
///
/// Returns [`MstError::InvalidPrefix`] if an entry's prefix compression does
/// not resolve against the preceding key.
pub fn from_node(node: &MstNode) -> Result<Vec<NodeEntry>, MstError> {
    let mut entries = Vec::with_capacity(node.entries.len() * 2 + 1);
    if let Some(left) = &node.left {
        entries.push(NodeEntry::Tree(left.0));
    }
    let mut previous = String::new();
    for entry in &node.entries {
        let key = entry.reconstruct_key(&previous)?;
        entries.push(NodeEntry::Leaf {
            key: key.clone(),
            value: entry.value.clone(),
        });
        if let Some(tree) = &entry.tree {
            entries.push(NodeEntry::Tree(tree.0));
        }
        previous = key;
    }
    Ok(entries)
}

/// Collapse an interleaved child sequence back into a stored node.
///
/// Prefix compression is derived here, from the full keys, so a caller never
/// has to maintain it — the reason the sequence carries uncompressed keys.
///
/// # Errors
///
/// Returns [`MstError::StructureViolation`] if two subtrees are adjacent, which
/// no valid node contains: consecutive subtrees at the same layer would have no
/// key separating them.
pub fn to_node(entries: &[NodeEntry]) -> Result<MstNode, MstError> {
    let mut left = None;
    let mut index = 0;
    if let Some(NodeEntry::Tree(cid)) = entries.first() {
        left = Some(Cid(*cid));
        index = 1;
    }

    let mut tree_entries = Vec::new();
    let mut previous = String::new();
    while index < entries.len() {
        let NodeEntry::Leaf { key, value } = &entries[index] else {
            return Err(MstError::StructureViolation {
                reason: "two adjacent subtrees in one node".to_string(),
            });
        };
        let mut entry = TreeEntry::with_prefix(&previous, key, value.clone());
        if let Some(NodeEntry::Tree(cid)) = entries.get(index + 1) {
            entry.tree = Some(Cid(*cid));
            index += 2;
        } else {
            index += 1;
        }
        previous = key.clone();
        tree_entries.push(entry);
    }

    Ok(MstNode {
        left,
        entries: tree_entries,
    })
}

/// Index of the first leaf whose key is greater than or equal to `key`.
///
/// Returns `entries.len()` when every leaf sorts below it. Subtrees are skipped
/// — only leaves carry keys — so the returned index is where a leaf with this
/// key belongs, and `index - 1` is the child immediately before that position.
#[must_use]
pub fn find_leaf_index(entries: &[NodeEntry], key: &str) -> usize {
    entries
        .iter()
        .position(|entry| entry.leaf_key().is_some_and(|k| k >= key))
        .unwrap_or(entries.len())
}

/// The layer a node sits at, derived from its first leaf.
///
/// `None` when the node holds no leaf at all — a node of pure structure, whose
/// layer can only be known from its parent.
#[must_use]
pub fn layer_for_entries(entries: &[NodeEntry]) -> Option<u32> {
    entries
        .iter()
        .find_map(NodeEntry::leaf_key)
        .map(super::key::key_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;

    fn value(seed: &[u8]) -> Cid {
        compute_cid(seed).into()
    }

    fn leaf(key: &str) -> NodeEntry {
        NodeEntry::Leaf {
            key: key.to_string(),
            value: value(key.as_bytes()),
        }
    }

    fn tree(seed: &[u8]) -> NodeEntry {
        NodeEntry::Tree(compute_cid(seed))
    }

    #[test]
    fn round_trips_a_leaf_only_node() {
        let entries = vec![
            leaf("app.bsky.feed.post/aaa"),
            leaf("app.bsky.feed.post/bbb"),
        ];
        let node = to_node(&entries).unwrap();
        assert!(node.left.is_none());
        assert_eq!(node.entries.len(), 2);
        assert_eq!(from_node(&node).unwrap(), entries);
    }

    /// A leading subtree becomes `l`, and a subtree after a leaf becomes that
    /// leaf's `t`.
    #[test]
    fn round_trips_interleaved_subtrees() {
        let entries = vec![
            tree(b"left"),
            leaf("app.bsky.feed.post/aaa"),
            tree(b"middle"),
            leaf("app.bsky.feed.post/bbb"),
        ];
        let node = to_node(&entries).unwrap();
        assert!(node.left.is_some(), "a leading subtree is the node's `l`");
        assert_eq!(node.entries.len(), 2);
        assert!(
            node.entries[0].tree.is_some(),
            "the subtree after aaa is its `t`"
        );
        assert!(node.entries[1].tree.is_none());
        assert_eq!(from_node(&node).unwrap(), entries);
    }

    #[test]
    fn round_trips_a_trailing_subtree() {
        let entries = vec![leaf("app.bsky.feed.post/aaa"), tree(b"right")];
        let node = to_node(&entries).unwrap();
        assert!(node.entries[0].tree.is_some());
        assert_eq!(from_node(&node).unwrap(), entries);
    }

    /// Two subtrees in a row have no key separating them, so no valid node
    /// contains that shape.
    #[test]
    fn rejects_adjacent_subtrees() {
        let entries = vec![leaf("app.bsky.feed.post/aaa"), tree(b"one"), tree(b"two")];
        assert!(to_node(&entries).is_err());
    }

    #[test]
    fn finds_the_insertion_position_skipping_subtrees() {
        let entries = vec![
            tree(b"left"),
            leaf("app.bsky.feed.post/bbb"),
            tree(b"mid"),
            leaf("app.bsky.feed.post/ddd"),
        ];
        // Before every leaf, but after the leading subtree.
        assert_eq!(find_leaf_index(&entries, "app.bsky.feed.post/aaa"), 1);
        // Exactly on a leaf.
        assert_eq!(find_leaf_index(&entries, "app.bsky.feed.post/bbb"), 1);
        // Between the two leaves.
        assert_eq!(find_leaf_index(&entries, "app.bsky.feed.post/ccc"), 3);
        // Past the end.
        assert_eq!(find_leaf_index(&entries, "app.bsky.feed.post/zzz"), 4);
    }

    #[test]
    fn layer_comes_from_the_first_leaf() {
        let entries = vec![tree(b"left"), leaf("app.bsky.feed.post/aaa")];
        assert_eq!(
            layer_for_entries(&entries),
            Some(super::super::key::key_height("app.bsky.feed.post/aaa"))
        );
    }

    #[test]
    fn a_node_of_pure_structure_has_no_derivable_layer() {
        assert_eq!(layer_for_entries(&[tree(b"only")]), None);
        assert_eq!(layer_for_entries(&[]), None);
    }
}
