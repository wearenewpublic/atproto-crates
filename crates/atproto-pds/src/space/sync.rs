//! `SpaceSync` — sync-side reads of state and oplog.
//!
//! Syncing apps poll:
//! - `getRepoState {space, repo}` → the per-account record commitment as a
//!   [`RepoState`] (full 2048-byte SetHash state + rev); the HTTP layer signs
//!   it into a `com.atproto.space.defs#signedCommit`.
//! - `listRepoOps {space, repo, since?, limit?}` → ordered ops since `rev`.
//!
//! This module returns the raw [`RepoState`] / [`OplogPage`]; commit signing
//! (rehydrating [`PdsSetHash`] and building a signed commit) happens in
//! `crate::http::space_handlers`, which holds the account signing keys.
//!
//! Auth is performed at the HTTP layer; this struct just queries the
//! per-actor SQLite store. Per-member record state lives in *each member's*
//! per-actor store (since they wrote it).
//!
//! The 0016 Permissioned Data draft has no member commits or member-list sync:
//! consumers learn the writer set from `listRepos`, not from a signed
//! member-list oplog.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::config::ensure_space_live;
use atproto_space::space_repo::SpaceRepo;
use atproto_space::storage::{OplogCursor, OplogPage, RepoState};
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

    /// `getRepoState` — current `{set_hash, rev}` for `(space, repo)`'s
    /// record commitment. Reads from the *repo account's* per-actor store,
    /// since each account's writes live in their own store.
    ///
    /// `own_account` exempts the read from the deleted-space gate: a member
    /// keeps reading their own repo after the space is deleted, which is only
    /// visible here when one PDS hosts both the authority and the member, and
    /// is always the case for a personal-data space.
    pub async fn get_repo_state(
        &self,
        space: &SpaceUri,
        repo_did: &str,
        own_account: bool,
    ) -> PdsResult<RepoState> {
        if !own_account {
            ensure_space_live(&self.data_dir, space).await?;
        }
        let store = SqlActorStore::open(&self.data_dir, repo_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.current_state().await.map_err(PdsError::Space)
    }

    /// `listRepoOps` — per-repo record oplog strictly after the `(rev, idx)`
    /// `since` cursor, up to `limit` ops.
    pub async fn list_repo_ops(
        &self,
        space: &SpaceUri,
        repo_did: &str,
        since: Option<&OplogCursor>,
        limit: u32,
    ) -> PdsResult<OplogPage> {
        let store = SqlActorStore::open(&self.data_dir, repo_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.read_oplog(since, limit).await.map_err(PdsError::Space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
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
            .get_repo_state(&test_space(), "did:plc:alice", false)
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
        let state = sync
            .get_repo_state(&uri, "did:plc:alice", false)
            .await
            .unwrap();
        assert!(state.set_hash.is_some());
        assert!(state.rev.is_some());

        let oplog = sync
            .list_repo_ops(&uri, "did:plc:alice", None, 100)
            .await
            .unwrap();
        assert_eq!(oplog.ops.len(), 1);
        assert_eq!(oplog.ops[0].action, "create");
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
        let cursor = OplogCursor::new(first.rev.clone(), 0);
        let oplog = sync
            .list_repo_ops(&uri, "did:plc:alice", Some(&cursor), 100)
            .await
            .unwrap();
        // Only the second commit's ops should be returned.
        assert_eq!(oplog.ops.len(), 1);
        assert_eq!(oplog.ops[0].rkey.as_deref(), Some("b"));
    }
}
