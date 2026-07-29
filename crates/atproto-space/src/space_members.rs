//! `SpaceMembers` orchestrator — owner-only member-list management.
//!
//! Mirrors `SpaceRepo` in shape but operates over the owner's `space_member`
//! commitment. Add and Remove are the two op kinds; the SetHash is over DID
//! UTF-8 bytes per the 0016 Permissioned Data draft.

use crate::errors::{SpaceError, SpaceResult};
use crate::set_hash::{SetHash, member_element_bytes};
use crate::storage::{
    MemberChange, MemberPage, MemberRow, MemberState, OplogEntry, PreparedCommitMembers,
    SpaceMembersStorage,
};
use crate::types::SpaceUri;
use atproto_record::tid::Tid;
use chrono::Utc;

/// Member-op action kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberOpAction {
    /// Add a DID.
    Add,
    /// Remove a DID.
    Remove,
}

impl MemberOpAction {
    fn as_str(self) -> &'static str {
        match self {
            MemberOpAction::Add => "add",
            MemberOpAction::Remove => "remove",
        }
    }
}

/// One member-op inside a batch.
#[derive(Debug, Clone)]
pub struct MemberOp {
    /// Action kind.
    pub action: MemberOpAction,
    /// DID being added or removed.
    pub did: String,
}

/// A pre-applied member-commit ready for `apply_commit`.
#[derive(Debug, Clone)]
pub struct PreparedMemberCommit<H: SetHash> {
    /// New member-set SetHash.
    pub set_hash: H,
    /// Rev for this commit.
    pub rev: String,
    /// Storage-layer prepared commit.
    pub storage_commit: PreparedCommitMembers,
}

/// Owner-only member-list orchestrator.
pub struct SpaceMembers<S: SpaceMembersStorage, H: SetHash> {
    space: SpaceUri,
    storage: S,
    _set_hash: std::marker::PhantomData<H>,
}

impl<S: SpaceMembersStorage, H: SetHash> SpaceMembers<S, H> {
    /// Construct a new orchestrator.
    pub fn new(space: SpaceUri, storage: S) -> Self {
        Self {
            space,
            storage,
            _set_hash: std::marker::PhantomData,
        }
    }

    /// Get the bound space URI.
    #[must_use]
    pub fn space(&self) -> &SpaceUri {
        &self.space
    }

    /// Read current member-list `{set_hash, rev}`.
    pub async fn current_state(&self) -> SpaceResult<MemberState> {
        self.storage.current_state(&self.space).await
    }

    /// Check membership.
    pub async fn is_member(&self, did: &str) -> SpaceResult<bool> {
        self.storage.is_member(&self.space, did).await
    }

    /// List members.
    pub async fn list_members(&self, cursor: Option<&str>, limit: u32) -> SpaceResult<MemberPage> {
        self.storage.list_members(&self.space, cursor, limit).await
    }

    /// Format a batch of member ops into a `PreparedMemberCommit`.
    pub async fn format_commit(&self, ops: &[MemberOp]) -> SpaceResult<PreparedMemberCommit<H>> {
        let state = self.storage.current_state(&self.space).await?;
        let mut set_hash = match state.set_hash {
            Some(bytes) => H::from_state_bytes(&bytes)?,
            None => H::empty(),
        };

        let rev = Tid::new().to_string();
        let now_iso = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let mut member_changes = Vec::with_capacity(ops.len());
        let mut oplog_entries = Vec::with_capacity(ops.len());

        for (idx, op) in ops.iter().enumerate() {
            let already_member = self.storage.is_member(&self.space, &op.did).await?;

            match op.action {
                MemberOpAction::Add => {
                    if already_member {
                        return Err(SpaceError::MemberAlreadyExists {
                            did: op.did.clone(),
                        });
                    }
                    set_hash.add(&member_element_bytes(&op.did));
                    member_changes.push(MemberChange::Add(MemberRow {
                        did: op.did.clone(),
                        member_rev: rev.clone(),
                        added_at: now_iso.clone(),
                    }));
                }
                MemberOpAction::Remove => {
                    if !already_member {
                        return Err(SpaceError::NotAMember {
                            did: op.did.clone(),
                        });
                    }
                    set_hash.remove(&member_element_bytes(&op.did));
                    member_changes.push(MemberChange::Remove(op.did.clone()));
                }
            }
            oplog_entries.push(OplogEntry {
                rev: rev.clone(),
                idx: idx as u32,
                action: op.action.as_str().to_string(),
                collection: None,
                rkey: None,
                cid: None,
                prev: None,
                did: Some(op.did.clone()),
                // Member ops name a DID, not a record; there is no value.
                value: None,
            });
        }

        // Persist the full lattice state (rehydrated via `from_state_bytes`).
        let new_state = set_hash.state_bytes();
        Ok(PreparedMemberCommit {
            set_hash,
            rev: rev.clone(),
            storage_commit: PreparedCommitMembers {
                new_set_hash: new_state,
                rev,
                member_changes,
                oplog_entries,
            },
        })
    }

    /// Persist a `PreparedMemberCommit` atomically.
    pub async fn apply_commit(&self, prepared: PreparedMemberCommit<H>) -> SpaceResult<()> {
        self.storage
            .apply_commit(&self.space, prepared.storage_commit)
            .await
    }
}

/// In-memory `SpaceMembersStorage` for testing.
pub mod memory {
    use super::*;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    /// In-memory member-store. Not for production.
    pub struct InMemorySpaceMembersStorage {
        inner: Mutex<Inner>,
    }

    struct Inner {
        members: BTreeMap<(SpaceUri, String), MemberRow>,
        states: BTreeMap<SpaceUri, MemberState>,
    }

    impl InMemorySpaceMembersStorage {
        /// Construct a fresh in-memory store.
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(Inner {
                    members: BTreeMap::new(),
                    states: BTreeMap::new(),
                }),
            }
        }
    }

    impl Default for InMemorySpaceMembersStorage {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl SpaceMembersStorage for InMemorySpaceMembersStorage {
        async fn current_state(&self, space: &SpaceUri) -> SpaceResult<MemberState> {
            let inner = self.inner.lock().unwrap();
            Ok(inner
                .states
                .get(space)
                .cloned()
                .unwrap_or_else(MemberState::empty))
        }

        async fn is_member(&self, space: &SpaceUri, did: &str) -> SpaceResult<bool> {
            let inner = self.inner.lock().unwrap();
            Ok(inner
                .members
                .contains_key(&(space.clone(), did.to_string())))
        }

        async fn list_members(
            &self,
            space: &SpaceUri,
            cursor: Option<&str>,
            limit: u32,
        ) -> SpaceResult<MemberPage> {
            let inner = self.inner.lock().unwrap();
            let mut rows: Vec<MemberRow> = inner
                .members
                .iter()
                .filter(|((s, _), _)| s == space)
                .filter(|((_, did), _)| match cursor {
                    Some(c) => did.as_str() > c,
                    None => true,
                })
                .map(|(_, row)| row.clone())
                .collect();
            rows.sort_by(|a, b| a.did.cmp(&b.did));
            let cursor_out = if rows.len() > limit as usize {
                rows.truncate(limit as usize);
                rows.last().map(|r| r.did.clone())
            } else {
                None
            };
            Ok(MemberPage {
                members: rows,
                cursor: cursor_out,
            })
        }

        async fn apply_commit(
            &self,
            space: &SpaceUri,
            commit: PreparedCommitMembers,
        ) -> SpaceResult<()> {
            let mut inner = self.inner.lock().unwrap();
            // dedup-add safety: the formatter already checks
            let mut seen = BTreeSet::new();
            for change in commit.member_changes {
                match change {
                    MemberChange::Add(row) => {
                        seen.insert(row.did.clone());
                        inner.members.insert((space.clone(), row.did.clone()), row);
                    }
                    MemberChange::Remove(did) => {
                        seen.insert(did.clone());
                        inner.members.remove(&(space.clone(), did));
                    }
                }
            }
            // The 0016 Permissioned Data draft has no member-list oplog read
            // path, so `commit.oplog_entries` is not retained in this test
            // store; only the member set + state commitment are updated.
            inner.states.insert(
                space.clone(),
                MemberState {
                    set_hash: Some(commit.new_set_hash),
                    rev: Some(commit.rev),
                },
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::InMemorySpaceMembersStorage;
    use super::*;
    use crate::set_hash::LtHash;
    use crate::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    type TestMembers = SpaceMembers<InMemorySpaceMembersStorage, LtHash>;

    #[tokio::test]
    async fn add_then_remove() {
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space, InMemorySpaceMembersStorage::new());

        m.apply_commit(
            m.format_commit(&[MemberOp {
                action: MemberOpAction::Add,
                did: "did:plc:alice".to_string(),
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(m.is_member("did:plc:alice").await.unwrap());

        m.apply_commit(
            m.format_commit(&[MemberOp {
                action: MemberOpAction::Remove,
                did: "did:plc:alice".to_string(),
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(!m.is_member("did:plc:alice").await.unwrap());
    }

    #[tokio::test]
    async fn duplicate_add_rejected() {
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space, InMemorySpaceMembersStorage::new());

        let op = MemberOp {
            action: MemberOpAction::Add,
            did: "did:plc:alice".to_string(),
        };
        m.apply_commit(m.format_commit(std::slice::from_ref(&op)).await.unwrap())
            .await
            .unwrap();

        let result = m.format_commit(&[op]).await;
        assert!(matches!(
            result,
            Err(SpaceError::MemberAlreadyExists { .. })
        ));
    }

    #[tokio::test]
    async fn remove_non_member_rejected() {
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space, InMemorySpaceMembersStorage::new());

        let result = m
            .format_commit(&[MemberOp {
                action: MemberOpAction::Remove,
                did: "did:plc:alice".to_string(),
            }])
            .await;
        assert!(matches!(result, Err(SpaceError::NotAMember { .. })));
    }
}
