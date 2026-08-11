//! `SpaceService` — owner-side management endpoints.
//!
//! `createSpace`, `getSpace`, `listSpaces`, `addMember`, `removeMember`,
//! `listMembers`. Operates against the per-actor SQLite store.

use crate::account::AccountManager;
use crate::actor_store::sql::{SqlActorStore, SqlSpaceMembersStorage, actor_db_path};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::config::{SpaceConfig, SpaceConfigPatch, ensure_not_deleted};
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
}

impl SpaceService {
    /// Construct a space-management orchestrator rooted at `data_dir`.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Construct with account-manager wiring. The 0016 Permissioned Data draft
    /// has no membership-notification flow, so the manager is no longer needed
    /// for member management; this constructor is retained for call-site
    /// compatibility and is equivalent to [`SpaceService::new`].
    #[must_use]
    pub fn with_accounts(data_dir: PathBuf, _accounts: Arc<AccountManager>) -> Self {
        Self { data_dir }
    }

    /// `createSpace` — owner-side. Inserts a `space` row marked `is_owner=1`
    /// in the owner's per-actor store, seeds the member-list state, and adds
    /// the owner as the first member of the space. Idempotent: re-creating the
    /// same URI is a no-op on the second call (the duplicate member-add is
    /// skipped via the `INSERT OR IGNORE` semantics in `SpaceMembersStorage`).
    pub async fn create_space(
        &self,
        owner_did: &str,
        space_type: &str,
        space_key: &str,
        config: SpaceConfig,
    ) -> PdsResult<SpaceInfo> {
        let space_type = SpaceType::new(space_type).map_err(space_err)?;
        let space_key = SpaceKey::new(space_key).map_err(space_err)?;
        let uri = SpaceUri::new(owner_did.to_string(), space_type, space_key);
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;

        let now = Utc::now().to_rfc3339();
        let mint_policy = config.mint_policy.as_str().to_string();
        let app_access = config.app_access.to_storage_json()?;
        // Use INSERT … ON CONFLICT here so the existing `created_at` is
        // preserved on re-creation; the conflict branch reasserts the
        // owner/member flags in case they were unset by a prior takedown.
        let inserted = sqlx::query(
            "INSERT INTO space (uri, is_owner, is_member, created_at, mint_policy, app_access, managing_app)
             VALUES (?, 1, 1, ?, ?, ?, ?)
             ON CONFLICT(uri) DO UPDATE SET is_owner = 1, is_member = 1",
        )
        .bind(uri.to_string())
        .bind(&now)
        .bind(&mint_policy)
        .bind(&app_access)
        .bind(config.managing_app.as_deref())
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

        // On first creation, add the owner as the initial member so the
        // member set contains them from t=0. Skipped on idempotent re-create
        // (rows_affected == 0) since a second `Add` for the same DID would
        // fail the SpaceMembers duplicate-add check.
        if inserted.rows_affected() > 0 {
            let storage = SqlSpaceMembersStorage::new(store.pool().clone());
            let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
                SpaceMembers::new(uri.clone(), storage);
            let prepared = members
                .format_commit(&[MemberOp {
                    action: MemberOpAction::Add,
                    did: owner_did.to_string(),
                }])
                .await
                .map_err(space_err)?;
            members.apply_commit(prepared).await.map_err(space_err)?;
        }

        // Re-read created_at so the response reflects the persisted row even
        // on idempotent re-create (where the INSERT was a no-op).
        let created_at: String = sqlx::query_scalar("SELECT created_at FROM space WHERE uri = ?")
            .bind(uri.to_string())
            .fetch_one(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("createSpace re-read created_at: {e}"),
            })?;

        Ok(SpaceInfo {
            uri: uri.to_string(),
            is_owner: true,
            is_member: true,
            created_at,
        })
    }

    /// `getSpace` — return `{uri, config}` for a non-deleted space.
    ///
    /// The `config` is the `com.atproto.simplespace.defs#spaceConfig` open
    /// union (mintPolicy + appAccess + optional managingApp). A tombstoned
    /// space (`deleted_at IS NOT NULL`) or a missing row both yield
    /// [`PdsError::SpaceNotFound`].
    ///
    /// Reads the **authority's** store, never the caller's. The draft lexicon
    /// describes this endpoint as "served by the space host", and the authority
    /// is the only party holding the real config.
    ///
    /// There is deliberately no viewer parameter. This used to take one and open
    /// the caller's store, which was wrong twice over: `ensure_space_row`
    /// (`actor_store/sql/space_repo_storage.rs`) gives a member's store a space
    /// row with column defaults the moment they write, so a client asking about
    /// an `allowList` space was told `open`; and a member who had never written
    /// had no row at all and got `SpaceNotFound` for a space they belong to.
    /// [`GetSpaceOutput`] carries no viewer-dependent field, so the parameter
    /// only ever selected the wrong store — removing it makes that
    /// unrepresentable rather than merely fixed.
    pub async fn get_space(&self, uri: &SpaceUri) -> PdsResult<GetSpaceOutput> {
        let store = SqlActorStore::open(&self.data_dir, &uri.space_did).await?;
        let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT mint_policy, app_access, managing_app, deleted_at FROM space WHERE uri = ?",
        )
        .bind(uri.to_string())
        .fetch_optional(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("getSpace: {e}"),
        })?;
        let (mint_policy, app_access, managing_app, deleted_at) =
            row.ok_or_else(|| PdsError::SpaceNotFound {
                uri: uri.to_string(),
            })?;
        if deleted_at.is_some() {
            return Err(PdsError::SpaceNotFound {
                uri: uri.to_string(),
            });
        }
        let config = SpaceConfig::from_columns(&mint_policy, &app_access, managing_app)?;
        Ok(GetSpaceOutput {
            uri: uri.to_string(),
            policy: config.policy_to_wire(),
            app_access: config.app_access.to_wire(),
            config: Some(config.to_wire()),
        })
    }

    /// Load the mint-time authorization inputs for `getSpaceCredential`:
    /// the space's persisted [`SpaceConfig`], whether the row exists, whether
    /// it has been tombstoned, and whether the requesting `member_did` is in
    /// the space's member list.
    ///
    /// Unlike [`Self::get_space`], this does **not** collapse the deleted and
    /// missing states — the credential-mint handler must distinguish
    /// `SpaceNotFound` from `SpaceDeleted` per the `getSpaceCredential`
    /// lexicon. The query runs against the space authority's own per-actor
    /// store (`uri.space_did`).
    ///
    /// # Errors
    /// Returns [`PdsError::Storage`] on a query failure.
    pub async fn load_mint_authz_inputs(
        &self,
        uri: &SpaceUri,
        member_did: &str,
    ) -> PdsResult<MintAuthzInputs> {
        let store = SqlActorStore::open(&self.data_dir, &uri.space_did).await?;
        let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT mint_policy, app_access, managing_app, deleted_at FROM space WHERE uri = ?",
        )
        .bind(uri.to_string())
        .fetch_optional(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("load_mint_authz_inputs: {e}"),
        })?;

        let Some((mint_policy, app_access, managing_app, deleted_at)) = row else {
            return Ok(MintAuthzInputs {
                found: false,
                deleted: false,
                config: SpaceConfig::default(),
                is_member: false,
            });
        };
        if deleted_at.is_some() {
            return Ok(MintAuthzInputs {
                found: true,
                deleted: true,
                config: SpaceConfig::default(),
                is_member: false,
            });
        }

        let config = SpaceConfig::from_columns(&mint_policy, &app_access, managing_app)?;
        let is_member: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM space_member WHERE space = ? AND did = ? LIMIT 1")
                .bind(uri.to_string())
                .bind(member_did)
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("load_mint_authz_inputs member check: {e}"),
                })?;

        Ok(MintAuthzInputs {
            found: true,
            deleted: false,
            config,
            is_member: is_member.is_some(),
        })
    }

    /// `updateSpace` — owner-only. Applies a [`SpaceConfigPatch`]; omitted
    /// fields are left unchanged and `managingApp == ""` clears the column to
    /// `NULL`. Fails with [`PdsError::SpaceNotFound`] for a missing or
    /// tombstoned space and [`PdsError::NotSpaceOwner`] when the caller is not
    /// the space authority.
    pub async fn update_space(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        patch: SpaceConfigPatch,
    ) -> PdsResult<()> {
        if uri.space_did != owner_did {
            return Err(PdsError::NotSpaceOwner {
                uri: uri.to_string(),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        // Confirm the row exists and is not tombstoned before mutating.
        let exists: Option<Option<String>> =
            sqlx::query_scalar("SELECT deleted_at FROM space WHERE uri = ?")
                .bind(uri.to_string())
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("updateSpace lookup: {e}"),
                })?;
        match exists {
            Some(None) => {}
            _ => {
                return Err(PdsError::SpaceNotFound {
                    uri: uri.to_string(),
                });
            }
        }

        if let Some(policy) = patch.mint_policy {
            sqlx::query("UPDATE space SET mint_policy = ? WHERE uri = ?")
                .bind(policy.as_str())
                .bind(uri.to_string())
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("updateSpace mint_policy: {e}"),
                })?;
        }
        if let Some(ref access) = patch.app_access {
            sqlx::query("UPDATE space SET app_access = ? WHERE uri = ?")
                .bind(access.to_storage_json()?)
                .bind(uri.to_string())
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("updateSpace app_access: {e}"),
                })?;
        }
        if let Some(ref app) = patch.managing_app {
            // Empty string clears to NULL; any other value sets it.
            let value = if app.is_empty() {
                None
            } else {
                Some(app.as_str())
            };
            sqlx::query("UPDATE space SET managing_app = ? WHERE uri = ?")
                .bind(value)
                .bind(uri.to_string())
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("updateSpace managing_app: {e}"),
                })?;
        }
        Ok(())
    }

    /// `deleteSpace` — owner-only tombstone. Sets `deleted_at`; after this all
    /// reads and writes against the space fail with
    /// [`PdsError::SpaceNotFound`]. Idempotent on an already-deleted space.
    pub async fn delete_space(&self, owner_did: &str, uri: &SpaceUri) -> PdsResult<()> {
        if uri.space_did != owner_did {
            return Err(PdsError::NotSpaceOwner {
                uri: uri.to_string(),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        let now = Utc::now().to_rfc3339();
        let affected =
            sqlx::query("UPDATE space SET deleted_at = ? WHERE uri = ? AND deleted_at IS NULL")
                .bind(&now)
                .bind(uri.to_string())
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("deleteSpace: {e}"),
                })?;
        if affected.rows_affected() == 0 {
            // Either no such row, or already deleted. Confirm existence so we
            // return SpaceNotFound only for a genuinely absent space.
            let exists: Option<String> = sqlx::query_scalar("SELECT uri FROM space WHERE uri = ?")
                .bind(uri.to_string())
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("deleteSpace recheck: {e}"),
                })?;
            if exists.is_none() {
                return Err(PdsError::SpaceNotFound {
                    uri: uri.to_string(),
                });
            }
        }

        // Per the 0016 Permissioned Data draft (line 363): "The authority also
        // deletes its own repo in the space." The `space` row itself is kept as
        // a tombstone (repo-host flag behavior, spec line 365 — the host flags
        // rather than erases), but the authority's *own* repo data within the
        // space (records, repo set-hash state, and the record oplog) is erased.
        //
        // Note: spec line 367's "a syncer should delete every copy" is a
        // *syncer-role* behavior, not applicable to this PDS acting as the
        // repo-host/authority; see `notify_space_deleted` for the recipient side.
        for table in ["space_record", "space_record_oplog", "space_repo"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE space = ?"))
                .bind(uri.to_string())
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("deleteSpace purge {table}: {e}"),
                })?;
        }
        Ok(())
    }

    /// Whether `did` is a member of `space` (reference `store.space.isMember`).
    ///
    /// Membership is the `space_member` table; the space owner is implicitly a
    /// member (owner-as-member). Used by the owner-side `notifyWrite` fan-out to
    /// reject notifications from non-members. A missing or tombstoned space
    /// yields `false`.
    pub async fn is_member(&self, uri: &SpaceUri, did: &str) -> PdsResult<bool> {
        if uri.space_did == did {
            return Ok(true);
        }
        let store = SqlActorStore::open(&self.data_dir, &uri.space_did).await?;
        let row: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM space_member WHERE space = ? AND did = ? LIMIT 1")
                .bind(uri.to_string())
                .bind(did)
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("is_member: {e}"),
                })?;
        Ok(row.is_some())
    }

    /// `listSpaces` — paginated listing for a viewer DID.
    ///
    /// `space_type` and `authority_did` are the lexicon's optional `type` and
    /// `did` filters. Neither is a column: the space table is keyed by URI, so
    /// both are matched as a `LIKE` prefix over `at://{did}/space/{type}/…`.
    ///
    /// Returns a page and, when the page is full, a cursor to resume from.
    pub async fn list_spaces(
        &self,
        viewer_did: &str,
        space_type: Option<&str>,
        authority_did: Option<&str>,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<SpacePage> {
        let store = SqlActorStore::open(&self.data_dir, viewer_did).await?;
        let limit = limit.clamp(1, 100);
        // Tombstoned spaces are never listed.
        let mut clauses: Vec<String> = vec!["deleted_at IS NULL".to_string()];
        let mut bindings: Vec<String> = Vec::new();
        if space_type.is_some() || authority_did.is_some() {
            // `_` and `%` in a DID or NSID would otherwise act as wildcards
            // and widen the filter rather than narrow it.
            let did_pat = authority_did.map_or_else(|| "%".to_string(), like_escape);
            let type_pat = space_type.map_or_else(|| "%".to_string(), like_escape);
            clauses.push("uri LIKE ? ESCAPE '\\'".to_string());
            bindings.push(format!(
                "{}{did_pat}/{}/{type_pat}/%",
                atproto_space::types::AT_SCHEME,
                atproto_space::types::SPACE_MARKER
            ));
        }
        if let Some(cur) = cursor {
            clauses.push("uri > ?".to_string());
            bindings.push(cur.to_string());
        }
        let where_clause = format!("WHERE {}", clauses.join(" AND "));
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
        // A short page is the last page. Emitting a cursor there would invite
        // a request that can only ever come back empty.
        let cursor = if rows.len() as u32 == limit {
            rows.last().map(|(uri, ..)| uri.clone())
        } else {
            None
        };
        let spaces = rows
            .into_iter()
            .map(|(uri, is_owner, is_member, created_at)| SpaceInfo {
                uri,
                is_owner: is_owner != 0,
                is_member: is_member != 0,
                created_at,
            })
            .collect();
        Ok(SpacePage { spaces, cursor })
    }

    /// `addMember` — owner-side. Atomic via `SpaceMembers::format_commit` +
    /// `apply_commit`. Caller is responsible for verifying that
    /// `caller_did == uri.space_did` (auth check) before invoking.
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
    /// member-list change against the owner's per-actor store.
    ///
    /// The 0016 Permissioned Data draft has no member commits or
    /// membership-notification flow: the member list is plain owner-managed
    /// state backing `mintPolicy=member-list`, not a signed-commit log.
    async fn apply_member_op(
        &self,
        owner_did: &str,
        uri: &SpaceUri,
        action: MemberOpAction,
        target_did: &str,
    ) -> PdsResult<()> {
        if uri.space_did != owner_did {
            return Err(PdsError::NotSpaceOwner {
                uri: uri.to_string(),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        ensure_not_deleted(store.pool(), uri).await?;
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
        members.apply_commit(prepared).await.map_err(space_err)?;
        Ok(())
    }

    /// `listMembers` — paginated.
    pub async fn list_members(
        &self,
        uri: &SpaceUri,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<MemberPage> {
        // The member list belongs to the space authority, so this always reads
        // the authority's store rather than the caller's. It used to take the
        // caller's DID and refuse unless it *was* the authority, which
        // conflated "whose store holds the list" with "who is allowed to read
        // it" — the first is a fact about the space, the second is the
        // caller's business and is settled before this is called.
        //
        // A space whose authority is hosted elsewhere has no list here to
        // read, and `SqlActorStore::open` would create an empty store and
        // report a space with no members rather than a space this host does
        // not answer for.
        if !actor_db_path(&self.data_dir, &uri.space_did).exists() {
            return Err(PdsError::SpaceNotFound {
                uri: uri.to_string(),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, &uri.space_did).await?;
        ensure_not_deleted(store.pool(), uri).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(uri.clone(), storage);
        members.list_members(cursor, limit).await.map_err(space_err)
    }

    /// Read the member-list commitment.
    pub async fn member_state(&self, owner_did: &str, uri: &SpaceUri) -> PdsResult<MemberState> {
        if uri.space_did != owner_did {
            return Err(PdsError::NotSpaceOwner {
                uri: uri.to_string(),
            });
        }
        let store = SqlActorStore::open(&self.data_dir, owner_did).await?;
        let storage = SqlSpaceMembersStorage::new(store.pool().clone());
        let members: SpaceMembers<SqlSpaceMembersStorage, PdsSetHash> =
            SpaceMembers::new(uri.clone(), storage);
        members.current_state().await.map_err(space_err)
    }
}

/// Escape SQL `LIKE` metacharacters so a filter value matches literally.
///
/// Paired with `ESCAPE '\\'` on the clause.
fn like_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// One page of [`SpaceInfo`] from `listSpaces`, with the resume cursor.
#[derive(Debug, Clone)]
pub struct SpacePage {
    /// Spaces in this page, ordered by URI.
    pub spaces: Vec<SpaceInfo>,
    /// Cursor for the next page. `None` when this is the last page.
    pub cursor: Option<String>,
}

/// Internal view of a space row for `createSpace` / `listSpaces` (viewer
/// relationship + creation time). Not the `getSpace` wire shape — see
/// [`GetSpaceOutput`] for that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceInfo {
    /// Full space URI.
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

/// `com.atproto.simplespace.getSpace` output: `{uri, policy, appAccess}`.
///
/// The two config fields are open unions at the top level, which is where the
/// lexicon puts them. `managingApp` has no field of its own — it belongs to
/// the `#managingAppPolicy` variant that names it.
///
/// `config` is the shape this server returned before the unions were lifted
/// out of a wrapper. It is emitted only by the deprecated
/// `com.atproto.space.getSpace` alias, which is the one endpoint whose callers
/// were written against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpaceOutput {
    /// URI of the space.
    pub uri: String,
    /// User-authorization policy, as an open union.
    pub policy: serde_json::Value,
    /// App-authorization policy, as an open union.
    #[serde(rename = "appAccess")]
    pub app_access: serde_json::Value,
    /// Legacy `#spaceConfig` wrapper; omitted on the lexicon endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

/// Mint-time authorization inputs loaded by
/// [`SpaceService::load_mint_authz_inputs`].
#[derive(Debug, Clone)]
pub struct MintAuthzInputs {
    /// Whether a `space` row exists for the URI in the authority's store.
    pub found: bool,
    /// Whether the existing row is tombstoned (`deleted_at IS NOT NULL`).
    pub deleted: bool,
    /// The persisted space configuration (default when missing/deleted).
    pub config: SpaceConfig,
    /// Whether the requesting member DID is in the space member list.
    pub is_member: bool,
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
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        assert!(info.is_owner);
        assert!(info.is_member);

        let uri = info.uri.parse::<SpaceUri>().unwrap();
        let got = svc.get_space(&uri).await.unwrap();
        assert_eq!(got.uri, info.uri);
        // Defaults surface as the #memberListPolicy + #open unions.
        assert_eq!(
            got.policy["$type"],
            crate::space::config::POLICY_MEMBER_LIST_TYPE
        );
        assert_eq!(
            got.app_access["$type"],
            crate::space::config::APP_ACCESS_OPEN_TYPE
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn update_then_get_space_reflects_config() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        let patch = SpaceConfigPatch {
            mint_policy: Some(crate::space::config::MintPolicy::Public),
            app_access: Some(crate::space::config::AppAccess::AllowList {
                allowed: vec!["c1".to_string()],
            }),
            managing_app: Some("did:web:m.example#svc".to_string()),
        };
        svc.update_space("did:plc:owner", &uri, patch)
            .await
            .unwrap();

        let got = svc.get_space(&uri).await.unwrap();
        assert_eq!(
            got.policy["$type"],
            crate::space::config::POLICY_PUBLIC_TYPE
        );
        assert_eq!(
            got.app_access["$type"],
            crate::space::config::APP_ACCESS_ALLOW_LIST_TYPE
        );
        // `#publicPolicy` consults no managing app, so the one still stored
        // against the row is not described as though it gated anything.
        assert!(got.policy.get("managingApp").is_none());
        // The deprecated alias still carries the old wrapper verbatim.
        let legacy = got.config.as_ref().unwrap();
        assert_eq!(legacy["policy"], "public");
        assert_eq!(legacy["managingApp"], "did:web:m.example#svc");

        // Clearing managingApp with empty string drops the field.
        let clear = SpaceConfigPatch {
            managing_app: Some(String::new()),
            ..Default::default()
        };
        svc.update_space("did:plc:owner", &uri, clear)
            .await
            .unwrap();
        let got = svc.get_space(&uri).await.unwrap();
        assert!(got.policy.get("managingApp").is_none());
        assert!(got.config.as_ref().unwrap().get("managingApp").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_mint_authz_inputs_reports_membership_and_config() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig {
                    mint_policy: crate::space::config::MintPolicy::MemberList,
                    app_access: crate::space::config::AppAccess::AllowList {
                        allowed: vec!["https://app.example".to_string()],
                    },
                    managing_app: None,
                },
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        // Owner is auto-added as the first member.
        let owner_in = svc
            .load_mint_authz_inputs(&uri, "did:plc:owner")
            .await
            .unwrap();
        assert!(owner_in.found);
        assert!(!owner_in.deleted);
        assert!(owner_in.is_member);
        assert_eq!(
            owner_in.config.mint_policy,
            crate::space::config::MintPolicy::MemberList
        );

        // A stranger is not a member.
        let stranger = svc
            .load_mint_authz_inputs(&uri, "did:plc:stranger")
            .await
            .unwrap();
        assert!(stranger.found);
        assert!(!stranger.is_member);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_mint_authz_inputs_missing_space_not_found() {
        let (svc, _tmp) = fresh_service().await;
        // No createSpace — the owner store has no row for this URI.
        let uri: SpaceUri = "at://did:plc:owner/space/app.bsky.group/missing"
            .parse()
            .unwrap();
        let inputs = svc
            .load_mint_authz_inputs(&uri, "did:plc:owner")
            .await
            .unwrap();
        assert!(!inputs.found);
        assert!(!inputs.deleted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_mint_authz_inputs_deleted_space_flagged() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        // Tombstone the row directly.
        let store = SqlActorStore::open(svc.data_dir.as_path(), "did:plc:owner")
            .await
            .unwrap();
        sqlx::query("UPDATE space SET deleted_at = ? WHERE uri = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(uri.to_string())
            .execute(store.pool())
            .await
            .unwrap();

        let inputs = svc
            .load_mint_authz_inputs(&uri, "did:plc:owner")
            .await
            .unwrap();
        assert!(inputs.found);
        assert!(inputs.deleted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn update_space_by_non_owner_rejected() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();
        let result = svc
            .update_space("did:plc:eve", &uri, SpaceConfigPatch::default())
            .await;
        assert!(matches!(result, Err(PdsError::NotSpaceOwner { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_space_tombstones_reads_and_writes() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        // Seed an authority-owned record in the space so we can assert the
        // authority's own repo is erased on delete (spec line 363).
        {
            let store = SqlActorStore::open(&svc.data_dir, "did:plc:owner")
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO space_record (space, collection, rkey, cid, value, repo_rev, indexed_at)
                 VALUES (?, 'app.bsky.feed.post', 'rk1', 'bafycid', X'00', '3jui', '2026-06-25T00:00:00Z')",
            )
            .bind(uri.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        }

        svc.delete_space("did:plc:owner", &uri).await.unwrap();

        // getSpace now reports SpaceNotFound.
        assert!(matches!(
            svc.get_space(&uri).await,
            Err(PdsError::SpaceNotFound { .. })
        ));
        // The authority's own repo data within the space is erased.
        {
            let store = SqlActorStore::open(&svc.data_dir, "did:plc:owner")
                .await
                .unwrap();
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM space_record WHERE space = ?")
                    .bind(uri.to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            assert_eq!(
                remaining, 0,
                "authority's own repo records should be purged"
            );
        }
        // Member mutations are gated.
        assert!(matches!(
            svc.add_member("did:plc:owner", &uri, "did:plc:alice").await,
            Err(PdsError::SpaceNotFound { .. })
        ));
        // listSpaces excludes the tombstoned space.
        let owned = svc
            .list_spaces("did:plc:owner", None, None, None, 10)
            .await
            .unwrap();
        assert!(owned.spaces.is_empty());
        // Re-deleting is idempotent.
        svc.delete_space("did:plc:owner", &uri).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_unknown_space_is_not_found() {
        let (svc, _tmp) = fresh_service().await;
        let uri: SpaceUri = "at://did:plc:owner/space/app.bsky.group/missing"
            .parse()
            .unwrap();
        assert!(matches!(
            svc.delete_space("did:plc:owner", &uri).await,
            Err(PdsError::SpaceNotFound { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_then_list_members() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();

        svc.add_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        svc.add_member("did:plc:owner", &uri, "did:plc:bob")
            .await
            .unwrap();

        let page = svc.list_members(&uri, None, 10).await.unwrap();
        // createSpace seeds the owner as the first member, then add_member
        // appends alice + bob.
        assert_eq!(page.members.len(), 3);
        let dids: Vec<_> = page.members.iter().map(|m| m.did.clone()).collect();
        assert!(dids.contains(&"did:plc:owner".to_string()));
        assert!(dids.contains(&"did:plc:alice".to_string()));
        assert!(dids.contains(&"did:plc:bob".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_member_by_non_owner_rejected() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();
        let result = svc.add_member("did:plc:eve", &uri, "did:plc:alice").await;
        assert!(matches!(result, Err(PdsError::NotSpaceOwner { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_member_round_trip() {
        let (svc, _tmp) = fresh_service().await;
        let info = svc
            .create_space(
                "did:plc:owner",
                "app.bsky.group",
                "default",
                SpaceConfig::default(),
            )
            .await
            .unwrap();
        let uri = info.uri.parse::<SpaceUri>().unwrap();
        svc.add_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        svc.remove_member("did:plc:owner", &uri, "did:plc:alice")
            .await
            .unwrap();
        let page = svc.list_members(&uri, None, 10).await.unwrap();
        // Owner remains after alice is removed.
        assert_eq!(page.members.len(), 1);
        assert_eq!(page.members[0].did, "did:plc:owner");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_spaces_filters() {
        let (svc, _tmp) = fresh_service().await;
        svc.create_space(
            "did:plc:owner",
            "app.bsky.group",
            "a",
            SpaceConfig::default(),
        )
        .await
        .unwrap();
        svc.create_space(
            "did:plc:owner",
            "app.bsky.group",
            "b",
            SpaceConfig::default(),
        )
        .await
        .unwrap();
        let owned = svc
            .list_spaces("did:plc:owner", None, None, None, 10)
            .await
            .unwrap();
        assert_eq!(owned.spaces.len(), 2);
        for s in &owned.spaces {
            assert!(s.is_owner);
        }
    }
}
