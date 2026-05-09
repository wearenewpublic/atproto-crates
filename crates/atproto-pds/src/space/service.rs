//! `SpaceService` — owner-side management endpoints.
//!
//! `createSpace`, `getSpace`, `listSpaces`, `addMember`, `removeMember`,
//! `getMembers`. Operates against the per-actor SQLite store.

use crate::account::AccountManager;
use crate::actor_store::sql::{SqlActorStore, SqlSpaceMembersStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::notify::{NotifyMembershipPayload, enqueue_membership};
use atproto_space::commit::{CommitScope, SpaceContext, create_commit};
use atproto_space::set_hash::SetHash;
use atproto_space::space_members::{MemberOp, MemberOpAction, SpaceMembers};
use atproto_space::storage::{MemberPage, MemberState};
use atproto_space::types::{SpaceKey, SpaceType, SpaceUri};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// Space-management orchestrator.
pub struct SpaceService {
    data_dir: PathBuf,
    /// Optional accounts manager — required for `notifyMembership` fan-out
    /// (signing the membership commit + enqueuing into the shared queue).
    /// Test fixtures pass `None`; production wiring in `bin/pds.rs` always
    /// supplies an instance.
    accounts: Option<Arc<AccountManager>>,
}

impl SpaceService {
    /// Construct without account-manager wiring. Suitable for tests that
    /// don't exercise membership-notification fan-out; `add_member` /
    /// `remove_member` will silently skip the `notifyMembership` enqueue.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            accounts: None,
        }
    }

    /// Construct with account-manager wiring for full `notifyMembership`
    /// fan-out. Production binaries call this; the manager backs both the
    /// signing-key lookup (to sign the membership commit) and the shared
    /// notify-attempt queue.
    #[must_use]
    pub fn with_accounts(data_dir: PathBuf, accounts: Arc<AccountManager>) -> Self {
        Self {
            data_dir,
            accounts: Some(accounts),
        }
    }

    /// `createSpace` — owner-side. Inserts a `space` row marked `is_owner=1`
    /// in the owner's per-actor store and seeds an empty member-list state.
    /// Idempotent: re-creating the same URI yields the existing row.
    pub async fn create_space(
        &self,
        owner_did: &str,
        space_type: &str,
        space_key: &str,
    ) -> PdsResult<SpaceInfo> {
        let space_type = SpaceType::new(space_type).map_err(space_err)?;
        let space_key = SpaceKey::new(space_key).map_err(space_err)?;
        let uri = SpaceUri::new(owner_did.to_string(), space_type, space_key);
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;

        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO space (uri, is_owner, is_member, created_at) VALUES (?, 1, 1, ?)
             ON CONFLICT(uri) DO UPDATE SET is_owner = 1, is_member = 1",
        )
        .bind(uri.to_string())
        .bind(&now)
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("createSpace: {e}"),
        })?;

        // Seed empty member state if absent.
        sqlx::query(
            "INSERT OR IGNORE INTO space_member_state (space, set_hash, rev) VALUES (?, NULL, NULL)",
        )
        .bind(uri.to_string())
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("createSpace seed member_state: {e}"),
        })?;

        Ok(SpaceInfo {
            uri: uri.to_string(),
            is_owner: true,
            is_member: true,
            created_at: now,
        })
    }

    /// `getSpace` — return the row by URI.
    pub async fn get_space(
        &self,
        viewer_did: &str,
        uri: &SpaceUri,
    ) -> PdsResult<Option<SpaceInfo>> {
        let store = SqlActorStore::open(&self.data_dir, viewer_did).await?;
        let row: Option<(i64, i64, String)> =
            sqlx::query_as("SELECT is_owner, is_member, created_at FROM space WHERE uri = ?")
                .bind(uri.to_string())
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("getSpace: {e}"),
                })?;
        Ok(row.map(|(is_owner, is_member, created_at)| SpaceInfo {
            uri: uri.to_string(),
            is_owner: is_owner != 0,
            is_member: is_member != 0,
            created_at,
        }))
    }

    /// `listSpaces` — paginated listing for a viewer DID. `filter` is one of
    /// `"owned"`, `"member"`, or `"all"`.
    pub async fn list_spaces(
        &self,
        viewer_did: &str,
        filter: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<SpaceInfo>> {
        let store = SqlActorStore::open(&self.data_dir, viewer_did).await?;
        let limit = limit.clamp(1, 100);
        let mut clauses: Vec<String> = Vec::new();
        match filter {
            "owned" => clauses.push("is_owner = 1".to_string()),
            "member" => clauses.push("is_member = 1".to_string()),
            "all" | "" => {}
            other => {
                return Err(PdsError::Storage {
                    reason: format!("invalid filter {other}"),
                });
            }
        }
        let mut bindings: Vec<String> = Vec::new();
        if let Some(cur) = cursor {
            clauses.push("uri > ?".to_string());
            bindings.push(cur.to_string());
        }
        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT uri, is_owner, is_member, created_at FROM space {where_clause}
             ORDER BY uri ASC LIMIT ?"
        );
        let mut q = sqlx::query_as::<_, (String, i64, i64, String)>(&sql);
        for b in &bindings {
            q = q.bind(b);
        }
        let rows = q
            .bind(limit as i64)
            .fetch_all(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("listSpaces: {e}"),
            })?;
        Ok(rows
            .into_iter()
            .map(|(uri, is_owner, is_member, created_at)| SpaceInfo {
                uri,
                is_owner: is_owner != 0,
                is_member: is_member != 0,
                created_at,
            })
            .collect())
    }

    /// `addMember` — owner-side. Atomic via `SpaceMembers::format_commit` +
    /// `apply_commit`. Caller is responsible for verifying that
    /// `caller_did == uri.owner_did` (auth check) before invoking.
    pub async fn add_member(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        new_member_did: &str,
    ) -> PdsResult<()> {
        self.apply_member_op(owner_did, uri, MemberOpAction::Add, new_member_did)
            .await
    }

    /// `removeMember` — owner-side.
    pub async fn remove_member(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        member_did: &str,
    ) -> PdsResult<()> {
        self.apply_member_op(owner_did, uri, MemberOpAction::Remove, member_did)
            .await
    }

    /// Shared body of `add_member` / `remove_member`. Formats + applies the
    /// commit, then (when an `AccountManager` is wired) signs the commit and
    /// enqueues a `notifyMembership` row per registered recipient.
    async fn apply_member_op(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        action: MemberOpAction,
        target_did: &str,
    ) -> PdsResult<()> {
        if uri.owner_did != owner_did {
            return Err(PdsError::AuthDenied {
                reason: format!(
                    "{owner_did} is not the owner of {} (owner is {})",
                    uri, uri.owner_did
                ),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(uri.clone(), storage);
        let prepared = members
            .format_commit(&[MemberOp {
                action,
                did: target_did.to_string(),
            }])
            .await
            .map_err(space_err)?;

        let action_str = match action {
            MemberOpAction::Add => "add",
            MemberOpAction::Remove => "remove",
        };
        let rev = prepared.rev.clone();
        let set_hash_digest = prepared.storage_commit.new_set_hash.clone();

        // Drop the storage borrow before any await on the notifier path.
        members.apply_commit(prepared).await.map_err(space_err)?;

        // `notifyMembership` fan-out — only when wiring is complete.
        if let Some(ref accounts) = self.accounts
            && let Err(e) = self
                .enqueue_membership_notification(
                    accounts,
                    uri,
                    action_str,
                    target_did,
                    &rev,
                    &set_hash_digest,
                )
                .await
        {
            tracing::warn!(
                error = ?e,
                space = %uri,
                action = action_str,
                member = target_did,
                "notifyMembership enqueue failed; recipients catch up via getMemberOplog"
            );
        }

        Ok(())
    }

    /// Sign a membership commit with the owner's atproto signing key and
    /// enqueue one `notify_attempt` per registered recipient.
    async fn enqueue_membership_notification(
        &self,
        accounts: &Arc<AccountManager>,
        uri: &SpaceUri,
        action_str: &str,
        target_did: &str,
        rev: &str,
        set_hash_digest: &[u8],
    ) -> PdsResult<()> {
        // Resolve the owner's signing key.
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(&uri.owner_did)
                .fetch_optional(accounts.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {} has no signing_key_ref", uri.owner_did),
            })?
            .0;
        let signing_key = accounts.key_store().get(&key_ref).await?;

        // Build the SpaceContext — `userDid` is the owner since they're the
        // one mutating the member list (owner is the only
        // writer of member-list commits).
        let context = SpaceContext {
            space_did: uri.owner_did.clone(),
            space_type: uri.space_type.to_string(),
            space_key: uri.space_key.to_string(),
            user_did: uri.owner_did.clone(),
            scope: CommitScope::Members,
            rev: rev.to_string(),
        };
        let set_hash = PdsSetHash::from_digest(set_hash_digest).map_err(PdsError::Space)?;
        let signed = create_commit(&set_hash, &context, &signing_key).map_err(PdsError::Space)?;

        let payload = NotifyMembershipPayload {
            space: uri.to_string(),
            action: action_str.to_string(),
            member: target_did.to_string(),
            commit: signed,
        };
        enqueue_membership(accounts.pool(), &self.data_dir, uri, &payload).await?;
        Ok(())
    }

    /// `getMembers` — paginated.
    pub async fn list_members(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<MemberPage> {
        if uri.owner_did != owner_did {
            return Err(PdsError::AuthDenied {
                reason: format!("{owner_did} is not the owner of {uri}"),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(uri.clone(), storage);
        members.list_members(cursor, limit).await.map_err(space_err)
    }

    /// Read the member-list commitment.
    pub async fn member_state(&self, owner_did: &str, uri: &SpaceUri) -> PdsResult<MemberState> {
        if uri.owner_did != owner_did {
            return Err(PdsError::AuthDenied {
                reason: format!("{owner_did} is not the owner of {uri}"),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(uri.clone(), storage);
        members.current_state().await.map_err(space_err)
    }
}

/// Lexicon-shape of a space row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceInfo {
    /// Full `ats://` URI.
    pub uri: String,
    /// Whether the viewer is the owner.
    #[serde(rename = "isOwner")]
    pub is_owner: bool,
    /// Whether the viewer is a member.
    #[serde(rename = "isMember")]
    pub is_member: bool,
    /// ISO-8601 creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

fn space_err(err: atproto_space::SpaceError) -> PdsError {
    PdsError::Space(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn fresh_service() -> (SpaceService, TempDir) {
        let tmp = TempDir::new().unwrap();
        let svc = SpaceService::new(tmp.path().to_path_buf());
        (svc, tmp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_then_get_space() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        assert!(info.is_owner);
        assert!(info.is_member);

        let uri = info.uri.parse::<SpaceUri>().unwrap();
        let got = svc.get_space("did:plc:owner", &uri).await.unwrap().unwrap();
        assert_eq!(got.uri, info.uri);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_then_list_members() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        svc.add_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        svc.add_member("did:plc:owner", &uri, "did:plc:bob")
            .await
            .unwrap();

        let page = svc
            .list_members("did:plc:owner", &uri, None, 10)
            .await
            .unwrap();
        assert_eq!(page.members.len(), 2);
        let dids: Vec<_> = page.members.iter().map(|m| m.did.clone()).collect();
        assert!(dids.contains(&"did:plc:alice".to_string()));
        assert!(dids.contains(&"did:plc:bob".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_member_by_non_owner_rejected() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();
        let result = svc.add_member("did:plc:eve", &uri, "did:plc:alice").await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_member_round_trip() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();
        svc.add_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        svc.remove_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        let page = svc
            .list_members("did:plc:owner", &uri, None, 10)
            .await
            .unwrap();
        assert_eq!(page.members.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_spaces_filters() {
        let (svc, _tmp) = fresh_service().await;
        svc.create_space("did:plc:owner", "app.bsky.group", "a")
            .await
            .unwrap();
        svc.create_space("did:plc:owner", "app.bsky.group", "b")
            .await
            .unwrap();
        let owned = svc
            .list_spaces("did:plc:owner", "owned", None, 10)
            .await
            .unwrap();
        assert_eq!(owned.len(), 2);
        for s in &owned {
            assert!(s.is_owner);
        }
    }
}
