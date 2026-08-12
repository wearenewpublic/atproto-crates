//! `SqlSpaceMembersStorage` — `SpaceMembersStorage` impl over per-actor
//! SQLite. Owner-only — backs the member-list commitment + oplog using
//! `space_member`, `space_member_state`, and `space_member_oplog`.

use async_trait::async_trait;
use atproto_space::SpaceError;
use atproto_space::errors::SpaceResult;
use atproto_space::storage::{
    MemberChange, MemberPage, MemberRow, MemberState, PreparedCommitMembers, SpaceMembersStorage,
};
use atproto_space::types::SpaceUri;
use sqlx::SqlitePool;

/// SQLite-backed `SpaceMembersStorage`.
pub struct SqlSpaceMembersStorage {
    pool: SqlitePool,
}

impl SqlSpaceMembersStorage {
    /// Construct over a per-actor pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn sql_err(reason: String) -> SpaceError {
    SpaceError::Storage { reason }
}

async fn ensure_space_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceUri,
) -> SpaceResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at) VALUES (?, 1, 0, ?)",
    )
    .bind(space.to_string())
    .bind(&now)
    .execute(&mut **tx)
    .await
    .map_err(|e| sql_err(format!("ensure_space_row: {e}")))?;
    Ok(())
}

#[async_trait]
impl SpaceMembersStorage for SqlSpaceMembersStorage {
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<MemberState> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> =
            sqlx::query_as("SELECT set_hash, rev FROM space_member_state WHERE space = ?")
                .bind(space.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| sql_err(format!("current_state: {e}")))?;
        Ok(match row {
            Some((set_hash, rev)) => MemberState { set_hash, rev },
            None => MemberState::empty(),
        })
    }

    async fn is_member(&self, space: &SpaceUri, did: &str) -> SpaceResult<bool> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM space_member WHERE space = ? AND did = ? LIMIT 1")
                .bind(space.to_string())
                .bind(did)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| sql_err(format!("is_member: {e}")))?;
        Ok(row.is_some())
    }

    async fn list_members(
        &self,
        space: &SpaceUri,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<MemberPage> {
        let limit = limit.clamp(1, 100);
        // One row past the page, never returned to the caller. A cursor is a
        // statement that a further page exists, and a `LIMIT limit` query cannot
        // tell a full last page from a full page with more behind it -- so the
        // cursor was emitted for every non-empty page, including the final one.
        // A client reading "cursor present" as "more members exist" then tells
        // its user there are more members after showing all of them.
        //
        // Over-fetching one row answers the question the page cannot, and makes
        // this agree exactly with the in-memory storage in
        // `atproto_space::space_members`, which sees the whole set and so has
        // always reported the last page correctly.
        let probe = i64::from(limit) + 1;
        let mut rows: Vec<(String, String, String)> = match cursor {
            Some(cur) => {
                sqlx::query_as(
                    "SELECT did, member_rev, added_at FROM space_member
                 WHERE space = ? AND did > ? ORDER BY did ASC LIMIT ?",
                )
                .bind(space.to_string())
                .bind(cur)
                .bind(probe)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT did, member_rev, added_at FROM space_member
                 WHERE space = ? ORDER BY did ASC LIMIT ?",
                )
                .bind(space.to_string())
                .bind(probe)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| sql_err(format!("list_members: {e}")))?;
        let cursor = if rows.len() > limit as usize {
            rows.truncate(limit as usize);
            rows.last().map(|(did, _, _)| did.clone())
        } else {
            None
        };
        let members = rows
            .into_iter()
            .map(|(did, member_rev, added_at)| MemberRow {
                did,
                member_rev,
                added_at,
            })
            .collect();
        Ok(MemberPage { members, cursor })
    }

    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitMembers,
    ) -> SpaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| sql_err(format!("apply_commit begin: {e}")))?;
        ensure_space_row(&mut tx, space).await?;

        for change in commit.member_changes {
            match change {
                MemberChange::Add(row) => {
                    sqlx::query(
                        "INSERT INTO space_member (space, did, member_rev, added_at)
                         VALUES (?, ?, ?, ?)",
                    )
                    .bind(space.to_string())
                    .bind(&row.did)
                    .bind(&row.member_rev)
                    .bind(&row.added_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| sql_err(format!("apply_commit add: {e}")))?;
                }
                MemberChange::Remove(did) => {
                    sqlx::query("DELETE FROM space_member WHERE space = ? AND did = ?")
                        .bind(space.to_string())
                        .bind(&did)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| sql_err(format!("apply_commit remove: {e}")))?;
                }
            }
        }

        for entry in commit.oplog_entries {
            sqlx::query(
                "INSERT INTO space_member_oplog (space, rev, idx, action, did)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(space.to_string())
            .bind(&entry.rev)
            .bind(entry.idx as i64)
            .bind(&entry.action)
            .bind(entry.did.unwrap_or_default())
            .execute(&mut *tx)
            .await
            .map_err(|e| sql_err(format!("apply_commit oplog: {e}")))?;
        }

        sqlx::query(
            "INSERT INTO space_member_state (space, set_hash, rev) VALUES (?, ?, ?)
             ON CONFLICT(space) DO UPDATE SET set_hash = excluded.set_hash, rev = excluded.rev",
        )
        .bind(space.to_string())
        .bind(&commit.new_set_hash)
        .bind(&commit.rev)
        .execute(&mut *tx)
        .await
        .map_err(|e| sql_err(format!("apply_commit member_state: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| sql_err(format!("apply_commit commit: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;
    use atproto_space::set_hash::LtHash;
    use atproto_space::space_members::{MemberOp, MemberOpAction, SpaceMembers};
    use atproto_space::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    async fn fresh_storage() -> SqlSpaceMembersStorage {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        SqlSpaceMembersStorage::new(store.pool().clone())
    }

    type TestMembers = SpaceMembers<SqlSpaceMembersStorage, LtHash>;

    #[tokio::test(flavor = "multi_thread")]
    async fn add_then_remove() {
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space.clone(), fresh_storage().await);
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
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space.clone(), fresh_storage().await);
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

    /// A cursor is a promise that a further page exists, so the last page must
    /// not carry one.
    ///
    /// Every non-empty page used to, because `LIMIT limit` cannot distinguish a
    /// full final page from a full page with more behind it and the cursor was
    /// taken from the last row either way. A client that reads "cursor present"
    /// as "more members exist" then reports more members while displaying all of
    /// them — which is what a membership dialog did against a live server.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_final_page_carries_no_cursor() {
        let space = test_space();
        let m: TestMembers = SpaceMembers::new(space.clone(), fresh_storage().await);
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

        // Room to spare: everyone fits, so there is nothing to page to.
        let page = m.list_members(None, 10).await.unwrap();
        assert_eq!(page.members.len(), 3);
        assert_eq!(page.cursor, None, "a short page is the last page");

        // Exactly full, and still the last page. This is the case a
        // `rows.len() == limit` test cannot tell apart, and where this storage
        // has to agree with the in-memory one in `atproto_space`.
        let page = m.list_members(None, 3).await.unwrap();
        assert_eq!(page.members.len(), 3);
        assert_eq!(
            page.cursor, None,
            "a page that exactly consumes the members is still the last page"
        );

        // Walking with a cursor ends without one, and the final request is not
        // an empty page.
        let first = m.list_members(None, 2).await.unwrap();
        let cursor = first.cursor.expect("a further page exists");
        let second = m.list_members(Some(&cursor), 2).await.unwrap();
        assert_eq!(second.members.len(), 1);
        assert_eq!(second.cursor, None, "the walk terminates");
    }
}
