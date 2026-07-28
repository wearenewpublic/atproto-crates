//! Tree diffing operations for repository sync.
//!
//! Computes the differences between two MST versions efficiently.

use atproto_dasl::Cid;

/// Represents a change between two MST versions.
#[derive(Debug, Clone, PartialEq)]
pub enum MstDiff {
    /// Key was added.
    Add {
        /// The key that was added.
        key: String,
        /// CID of the new value.
        cid: Cid,
    },
    /// Key was updated (value changed).
    Update {
        /// The key that was updated.
        key: String,
        /// CID of the old value.
        old_cid: Cid,
        /// CID of the new value.
        new_cid: Cid,
    },
    /// Key was deleted.
    Delete {
        /// The key that was deleted.
        key: String,
        /// CID of the deleted value.
        cid: Cid,
    },
}

impl MstDiff {
    /// Get the key associated with this diff.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            MstDiff::Add { key, .. } => key,
            MstDiff::Update { key, .. } => key,
            MstDiff::Delete { key, .. } => key,
        }
    }

    /// Check if this is an add operation.
    #[must_use]
    pub fn is_add(&self) -> bool {
        matches!(self, MstDiff::Add { .. })
    }

    /// Check if this is an update operation.
    #[must_use]
    pub fn is_update(&self) -> bool {
        matches!(self, MstDiff::Update { .. })
    }

    /// Check if this is a delete operation.
    #[must_use]
    pub fn is_delete(&self) -> bool {
        matches!(self, MstDiff::Delete { .. })
    }
}

/// Compute differences between two sets of key-value pairs.
///
/// Both inputs should be sorted by key.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_repo::mst::diff_entries;
///
/// let old = vec![("a".to_string(), cid1), ("b".to_string(), cid2)];
/// let new = vec![("b".to_string(), cid3), ("c".to_string(), cid4)];
///
/// let diffs = diff_entries(&old, &new);
/// // diffs contains: Delete("a"), Update("b"), Add("c")
/// ```
pub fn diff_entries(old: &[(String, Cid)], new: &[(String, Cid)]) -> Vec<MstDiff> {
    let mut diffs = Vec::new();
    let mut old_iter = old.iter().peekable();
    let mut new_iter = new.iter().peekable();

    loop {
        match (old_iter.peek(), new_iter.peek()) {
            (None, None) => break,
            (Some((key, cid)), None) => {
                // Key deleted
                diffs.push(MstDiff::Delete {
                    key: key.clone(),
                    cid: (*cid).clone(),
                });
                old_iter.next();
            }
            (None, Some((key, cid))) => {
                // Key added
                diffs.push(MstDiff::Add {
                    key: key.clone(),
                    cid: (*cid).clone(),
                });
                new_iter.next();
            }
            (Some((old_key, old_cid)), Some((new_key, new_cid))) => {
                match old_key.cmp(new_key) {
                    std::cmp::Ordering::Less => {
                        // Old key not in new - deleted
                        diffs.push(MstDiff::Delete {
                            key: old_key.clone(),
                            cid: (*old_cid).clone(),
                        });
                        old_iter.next();
                    }
                    std::cmp::Ordering::Greater => {
                        // New key not in old - added
                        diffs.push(MstDiff::Add {
                            key: new_key.clone(),
                            cid: (*new_cid).clone(),
                        });
                        new_iter.next();
                    }
                    std::cmp::Ordering::Equal => {
                        // Same key - check if value changed
                        if old_cid != new_cid {
                            diffs.push(MstDiff::Update {
                                key: old_key.clone(),
                                old_cid: (*old_cid).clone(),
                                new_cid: (*new_cid).clone(),
                            });
                        }
                        old_iter.next();
                        new_iter.next();
                    }
                }
            }
        }
    }

    diffs
}

/// Action kind for Sync 1.1 repository operation.
///
/// Wire-format value strings: `"create"`, `"update"`, `"delete"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoOpAction {
    /// New record created.
    Create,
    /// Existing record updated.
    Update,
    /// Record deleted.
    Delete,
}

/// A Sync 1.1 repository operation as it appears in `#commit` payloads.
///
/// This is the wire shape produced by [`ops_with_prev_cids`] and consumed by
/// firehose subscribers. The `prev` field carries the prior record CID for
/// `Update` and `Delete` ops (and is `None` for `Create`), enabling subscribers
/// to invert operations against their local state without retaining the full
/// history.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RepoOp {
    /// Action kind: create, update, or delete.
    pub action: RepoOpAction,
    /// Repo path (`<collection>/<rkey>`).
    pub path: String,
    /// New record CID; `null` for a delete.
    ///
    /// Serialized as an explicit `null` when absent, never omitted:
    /// `#repoOp.cid` is required-and-nullable, so dropping the key produces an
    /// object no subscriber can decode against the lexicon.
    pub cid: Option<Cid>,
    /// Prior record CID. Required by Sync 1.1 for update and delete; `None` for create.
    ///
    /// Omitted when absent, unlike `cid`: the lexicon declares `prev` optional
    /// — "for creations, field should not be defined" — rather than nullable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<Cid>,
}

/// Convert a slice of [`MstDiff`] entries into Sync 1.1 [`RepoOp`] wire format.
///
/// `Add` → `Create` with `cid=Some(new)`, `prev=None`.
/// `Update` → `Update` with `cid=Some(new)`, `prev=Some(old)`.
/// `Delete` → `Delete` with `cid=None`, `prev=Some(old)`.
#[must_use]
pub fn ops_with_prev_cids(diffs: &[MstDiff]) -> Vec<RepoOp> {
    diffs
        .iter()
        .map(|diff| match diff {
            MstDiff::Add { key, cid } => RepoOp {
                action: RepoOpAction::Create,
                path: key.clone(),
                cid: Some(cid.clone()),
                prev: None,
            },
            MstDiff::Update {
                key,
                old_cid,
                new_cid,
            } => RepoOp {
                action: RepoOpAction::Update,
                path: key.clone(),
                cid: Some(new_cid.clone()),
                prev: Some(old_cid.clone()),
            },
            MstDiff::Delete { key, cid } => RepoOp {
                action: RepoOpAction::Delete,
                path: key.clone(),
                cid: None,
                prev: Some(cid.clone()),
            },
        })
        .collect()
}

/// Statistics about a diff operation.
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    /// Number of keys added.
    pub adds: usize,
    /// Number of keys updated.
    pub updates: usize,
    /// Number of keys deleted.
    pub deletes: usize,
}

impl DiffStats {
    /// Create stats from a list of diffs.
    #[must_use]
    pub fn from_diffs(diffs: &[MstDiff]) -> Self {
        let mut stats = Self::default();
        for diff in diffs {
            match diff {
                MstDiff::Add { .. } => stats.adds += 1,
                MstDiff::Update { .. } => stats.updates += 1,
                MstDiff::Delete { .. } => stats.deletes += 1,
            }
        }
        stats
    }

    /// Total number of changes.
    #[must_use]
    pub fn total(&self) -> usize {
        self.adds + self.updates + self.deletes
    }

    /// Check if there are no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;

    fn test_cid(data: &[u8]) -> Cid {
        compute_cid(data).into()
    }

    #[test]
    fn test_diff_no_changes() {
        let cid = test_cid(b"v");
        let entries = vec![("a".to_string(), cid.clone()), ("b".to_string(), cid)];

        let diffs = diff_entries(&entries, &entries);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_diff_all_added() {
        let old: Vec<(String, Cid)> = vec![];
        let new = vec![
            ("a".to_string(), test_cid(b"1")),
            ("b".to_string(), test_cid(b"2")),
        ];

        let diffs = diff_entries(&old, &new);
        assert_eq!(diffs.len(), 2);
        assert!(diffs.iter().all(|d| d.is_add()));
    }

    #[test]
    fn test_diff_all_deleted() {
        let old = vec![
            ("a".to_string(), test_cid(b"1")),
            ("b".to_string(), test_cid(b"2")),
        ];
        let new: Vec<(String, Cid)> = vec![];

        let diffs = diff_entries(&old, &new);
        assert_eq!(diffs.len(), 2);
        assert!(diffs.iter().all(|d| d.is_delete()));
    }

    #[test]
    fn test_diff_update() {
        let old = vec![("a".to_string(), test_cid(b"old"))];
        let new = vec![("a".to_string(), test_cid(b"new"))];

        let diffs = diff_entries(&old, &new);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].is_update());
    }

    #[test]
    fn test_diff_mixed() {
        let old = vec![
            ("a".to_string(), test_cid(b"1")),
            ("b".to_string(), test_cid(b"2")),
            ("c".to_string(), test_cid(b"3")),
        ];
        let new = vec![
            ("b".to_string(), test_cid(b"2-updated")),
            ("c".to_string(), test_cid(b"3")),
            ("d".to_string(), test_cid(b"4")),
        ];

        let diffs = diff_entries(&old, &new);

        let stats = DiffStats::from_diffs(&diffs);
        assert_eq!(stats.deletes, 1); // "a" deleted
        assert_eq!(stats.updates, 1); // "b" updated
        assert_eq!(stats.adds, 1); // "d" added
    }

    #[test]
    fn test_ops_with_prev_cids_create() {
        let diffs = vec![MstDiff::Add {
            key: "app.bsky.feed.post/3jui7kd2z2y2e".to_string(),
            cid: test_cid(b"new"),
        }];
        let ops = ops_with_prev_cids(&diffs);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].action, RepoOpAction::Create);
        assert_eq!(ops[0].path, "app.bsky.feed.post/3jui7kd2z2y2e");
        assert!(ops[0].cid.is_some());
        assert!(ops[0].prev.is_none());
    }

    #[test]
    fn test_ops_with_prev_cids_update() {
        let diffs = vec![MstDiff::Update {
            key: "app.bsky.actor.profile/self".to_string(),
            old_cid: test_cid(b"old"),
            new_cid: test_cid(b"new"),
        }];
        let ops = ops_with_prev_cids(&diffs);
        assert_eq!(ops[0].action, RepoOpAction::Update);
        assert!(ops[0].cid.is_some());
        assert!(ops[0].prev.is_some());
    }

    #[test]
    fn test_ops_with_prev_cids_delete() {
        let diffs = vec![MstDiff::Delete {
            key: "app.bsky.feed.post/3jui7kd2z2y2e".to_string(),
            cid: test_cid(b"deleted"),
        }];
        let ops = ops_with_prev_cids(&diffs);
        assert_eq!(ops[0].action, RepoOpAction::Delete);
        assert!(ops[0].cid.is_none());
        assert!(ops[0].prev.is_some());
    }

    #[test]
    fn test_diff_stats() {
        let diffs = vec![
            MstDiff::Add {
                key: "a".to_string(),
                cid: test_cid(b"1"),
            },
            MstDiff::Add {
                key: "b".to_string(),
                cid: test_cid(b"2"),
            },
            MstDiff::Delete {
                key: "c".to_string(),
                cid: test_cid(b"3"),
            },
        ];

        let stats = DiffStats::from_diffs(&diffs);
        assert_eq!(stats.adds, 2);
        assert_eq!(stats.deletes, 1);
        assert_eq!(stats.updates, 0);
        assert_eq!(stats.total(), 3);
    }
}
