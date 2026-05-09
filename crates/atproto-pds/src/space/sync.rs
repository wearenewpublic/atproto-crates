//! `SpaceSync` — sync-side reads of state and oplog.
//!
//!  syncing apps poll:
//! - `getRepoState {space, member}` → `{set_hash, rev}` for the per-member
//!   record commitment.
//! - `getRepoOplog {space, member, since?, limit?}` → ordered ops since `rev`.
//! - `getMemberState {space}` → owner-only member-list commitment.
//! - `getMemberOplog {space, since?, limit?}` → owner-only member-list ops.
//!
//! Auth is performed at the HTTP layer; this struct just queries the
//! per-actor SQLite store. The owner's per-actor store backs both member-list
//! state and (for their own member-DID) record state. Per-member record
//! state lives in *each member's* per-actor store (since they wrote it).
//!
//! / G35, **the PDS does not enforce membership at sync
//! time** — consumers verify membership inductively from the owner's
//! member-list oplog.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceMembersStorage, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use atproto_space::space_members::SpaceMembers;
use atproto_space::space_repo::SpaceRepo;
use atproto_space::storage::{MemberState, OplogPage, RepoState};
use atproto_space::types::SpaceUri;
use std::path::PathBuf;

/// Spaces sync orchestrator (read-only, per-actor-store-backed).
pub struct SpaceSync {
    data_dir: PathBuf,
}

impl SpaceSync {
    /// Construct.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// `getRepoState` — current `{set_hash, rev}` for `(space, member)`'s
    /// record commitment. Reads from the *member's* per-actor store, since
    /// each member's writes live in their own store.
    pub async fn get_repo_state(&self, space: &SpaceUri, member_did: &str) -> PdsResult<RepoState> {
        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.current_state().await.map_err(PdsError::Space)
    }

    /// `getRepoOplog` — per-member record oplog from `since` (exclusive),
    /// up to `limit` ops.
    pub async fn get_repo_oplog(
        &self,
        space: &SpaceUri,
        member_did: &str,
        since: Option<&str>,
        limit: u32,
    ) -> PdsResult<OplogPage> {
        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.read_oplog(since, limit).await.map_err(PdsError::Space)
    }

    /// `getMemberState` — owner-only member-list commitment.
    ///
    /// Reads from the owner's per-actor store. Caller is responsible for
    /// verifying that the request is authorized (e.g. owner-self-auth or
    /// member-with-credential).
    pub async fn get_member_state(&self, space: &SpaceUri) -> PdsResult<MemberState> {
        let store = SqlActorStore::open(&self.data_dir, &space.owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(space.clone(), storage);
        members.current_state().await.map_err(PdsError::Space)
    }

    /// `getMemberOplog` — owner-only member-list oplog.
    pub async fn get_member_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&str>,
        limit: u32,
    ) -> PdsResult<OplogPage> {
        let store = SqlActorStore::open(&self.data_dir, &space.owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(space.clone(), storage);
        members
            .read_oplog(since, limit)
            .await
            .map_err(PdsError::Space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use crate::space::service::SpaceService;
    use crate::space::writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
    use atproto_identity::key::KeyType;
    use atproto_space::types::{SpaceKey, SpaceType};
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn fresh_manager(dir: &std::path::Path) -> Arc<AccountManager> {
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        for did in ["did:plc:owner", "did:plc:alice"] {
            manager
                .create_account(CreateAccountParams {
                    did,
                    handle: &format!("{}.example", did.trim_start_matches("did:plc:")),
                    email: None,
                    password: "pw",
                    pds_managed_rotation: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        manager
    }

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_repo_state_is_empty() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let _ = manager;
        let sync = SpaceSync::new(dir);
        let state = sync
            .get_repo_state(&test_space(), "did:plc:alice")
            .await
            .unwrap();
        assert!(state.set_hash.is_none());
        assert!(state.rev.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn writes_advance_repo_state_and_oplog() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let writer = SpaceWriter::new(manager.clone(), dir.clone());
        let uri = test_space();
        writer
            .apply_writes(
                "did:plc:alice",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "c".to_string(),
                    rkey: "k".to_string(),
                    value: Some(serde_json::json!({"v": 1})),
                }],
            )
            .await
            .unwrap();

        let sync = SpaceSync::new(dir);
        let state = sync.get_repo_state(&uri, "did:plc:alice").await.unwrap();
        assert!(state.set_hash.is_some());
        assert!(state.rev.is_some());

        let oplog = sync
            .get_repo_oplog(&uri, "did:plc:alice", None, 100)
            .await
            .unwrap();
        assert_eq!(oplog.ops.len(), 1);
        assert_eq!(oplog.ops[0].action, "create");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn member_oplog_observes_add_remove() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let _manager = fresh_manager(&dir).await;
        let svc = SpaceService::new(dir.clone());
        svc.create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        let uri = test_space();
        svc.add_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        svc.remove_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();

        let sync = SpaceSync::new(dir);
        let state = sync.get_member_state(&uri).await.unwrap();
        assert!(state.set_hash.is_some());

        let oplog = sync.get_member_oplog(&uri, None, 100).await.unwrap();
        assert_eq!(oplog.ops.len(), 2);
        assert_eq!(oplog.ops[0].action, "add");
        assert_eq!(oplog.ops[1].action, "remove");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn since_filter_excludes_prior_revs() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let writer = SpaceWriter::new(manager, dir.clone());
        let uri = test_space();
        let first = writer
            .apply_writes(
                "did:plc:alice",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "c".to_string(),
                    rkey: "a".to_string(),
                    value: Some(serde_json::json!({})),
                }],
            )
            .await
            .unwrap();
        writer
            .apply_writes(
                "did:plc:alice",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "c".to_string(),
                    rkey: "b".to_string(),
                    value: Some(serde_json::json!({})),
                }],
            )
            .await
            .unwrap();

        let sync = SpaceSync::new(dir);
        let oplog = sync
            .get_repo_oplog(&uri, "did:plc:alice", Some(&first.rev), 100)
            .await
            .unwrap();
        // Only the second commit's ops should be returned.
        assert_eq!(oplog.ops.len(), 1);
        assert_eq!(oplog.ops[0].rkey.as_deref(), Some("b"));
    }
}
