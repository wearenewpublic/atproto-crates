//! `FjallSpaceMembersStorage` — `SpaceMembersStorage` impl over fjall.

use super::keyspace::{FjallActorStore, member_key, member_prefix, oplog_key};
use async_trait::async_trait;
use atproto_space::SpaceError;
use atproto_space::errors::SpaceResult;
use atproto_space::storage::{
    MemberChange, MemberPage, MemberRow, MemberState, PreparedCommitMembers, SpaceMembersStorage,
};
use atproto_space::types::SpaceUri;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberValue {
    member_rev: String,
    added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberStateRow {
    set_hash: Vec<u8>,
    rev: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemberOplogRow {
    action: String,
    did: String,
}

/// Fjall-backed `SpaceMembersStorage`.
pub struct FjallSpaceMembersStorage {
    store: FjallActorStore,
}

impl FjallSpaceMembersStorage {
    /// Construct.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }
}

fn fjall_err(msg: String) -> SpaceError {
    SpaceError::Storage { reason: msg }
}

fn encode<T: Serialize>(v: &T) -> SpaceResult<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| fjall_err(format!("encode: {e}")))
}
fn decode<T: for<'de> Deserialize<'de>>(b: &[u8]) -> SpaceResult<T> {
    serde_json::from_slice(b).map_err(|e| fjall_err(format!("decode: {e}")))
}

#[async_trait]
impl SpaceMembersStorage for FjallSpaceMembersStorage {
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<MemberState> {
        let key = space.to_string().into_bytes();
        let part = self.store.space_member_state();
        match part
            .get(&key)
            .map_err(|e| fjall_err(format!("get state: {e}")))?
        {
            None => Ok(MemberState::empty()),
            Some(bytes) => {
                let r: MemberStateRow = decode(&bytes)?;
                Ok(MemberState {
                    set_hash: Some(r.set_hash),
                    rev: Some(r.rev),
                })
            }
        }
    }

    async fn is_member(&self, space: &SpaceUri, did: &str) -> SpaceResult<bool> {
        let key = member_key(&space.to_string(), did);
        let part = self.store.space_member();
        Ok(part
            .get(&key)
            .map_err(|e| fjall_err(format!("get member: {e}")))?
            .is_some())
    }

    async fn list_members(
        &self,
        space: &SpaceUri,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<MemberPage> {
        let limit = limit.clamp(1, 100) as usize;
        let prefix = member_prefix(&space.to_string());
        let part = self.store.space_member();

        let cursor_key = cursor.map(|c| {
            let mut buf = prefix.clone();
            buf.extend_from_slice(c.as_bytes());
            buf
        });

        let mut members = Vec::with_capacity(limit);
        for kv in part.prefix(&prefix) {
            let (k, v) = kv
                .into_inner()
                .map_err(|e| fjall_err(format!("scan members: {e}")))?;
            if let Some(c) = cursor_key.as_ref()
                && k.as_ref() <= c.as_slice()
            {
                continue;
            }
            let suffix = &k[prefix.len()..];
            let did = std::str::from_utf8(suffix)
                .map_err(|e| fjall_err(format!("did utf-8: {e}")))?
                .to_string();
            let value: MemberValue = decode(&v)?;
            members.push(MemberRow {
                did,
                member_rev: value.member_rev,
                added_at: value.added_at,
            });
            if members.len() >= limit {
                break;
            }
        }
        let cursor = members.last().map(|m| m.did.clone());
        Ok(MemberPage { members, cursor })
    }

    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitMembers,
    ) -> SpaceResult<()> {
        let space_uri = space.to_string();
        let mut batch = self.store.db().batch();

        for change in commit.member_changes {
            match change {
                MemberChange::Add(row) => {
                    let key = member_key(&space_uri, &row.did);
                    let value = encode(&MemberValue {
                        member_rev: row.member_rev,
                        added_at: row.added_at,
                    })?;
                    batch.insert(self.store.space_member(), &key, &value);
                }
                MemberChange::Remove(did) => {
                    let key = member_key(&space_uri, &did);
                    batch.remove(self.store.space_member(), &key);
                }
            }
        }

        for entry in commit.oplog_entries {
            let key = oplog_key(&space_uri, &entry.rev, entry.idx);
            let value = encode(&MemberOplogRow {
                action: entry.action,
                did: entry.did.unwrap_or_default(),
            })?;
            batch.insert(self.store.space_member_oplog(), &key, &value);
        }

        let state_key = space_uri.into_bytes();
        let state_value = encode(&MemberStateRow {
            set_hash: commit.new_set_hash,
            rev: commit.rev,
        })?;
        batch.insert(self.store.space_member_state(), &state_key, &state_value);

        batch
            .commit()
            .map_err(|e| fjall_err(format!("commit batch: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_space::set_hash::LtHash;
    use atproto_space::space_members::{MemberOp, MemberOpAction, SpaceMembers};
    use atproto_space::types::{SpaceKey, SpaceType};
    use tempfile::TempDir;

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    type TestMembers = SpaceMembers<FjallSpaceMembersStorage, LtHash>;

    fn fresh() -> (FjallSpaceMembersStorage, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        (FjallSpaceMembersStorage::new(store), tmp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_then_remove() {
        let (storage, _tmp) = fresh();
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space.clone(), storage);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates() {
        let (storage, _tmp) = fresh();
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space.clone(), storage);
        for did in ["did:plc:a", "did:plc:b", "did:plc:c"] {
            m.apply_commit(
                m.format_commit(&[MemberOp {
                    action: MemberOpAction::Add,
                    did: did.to_string(),
                }])
                .await
                .unwrap(),
            )
            .await
            .unwrap();
        }
        let page = m.list_members(None, 2).await.unwrap();
        assert_eq!(page.members.len(), 2);
        assert_eq!(page.members[0].did, "did:plc:a");
        assert_eq!(page.cursor.as_deref(), Some("did:plc:b"));
    }
}
