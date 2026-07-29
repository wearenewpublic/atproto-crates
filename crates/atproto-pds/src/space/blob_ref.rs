//! Space-scoped blob references.
//!
//! Permissioned blobs are uploaded through the ordinary
//! `com.atproto.repo.uploadBlob` — there is no `com.atproto.space.uploadBlob` —
//! so they land in the same `repo_blob` table as public ones. Nothing recorded
//! *which space* a blob belonged to, which produced two defects:
//!
//! - `com.atproto.sync.getBlob` served permissioned bytes to anyone holding the
//!   CID, with no credential at all.
//! - `com.atproto.space.getBlob` gated on `space` and then looked up by
//!   `(repo, cid)`, so the parameter never reached the query.
//!
//! This module maintains the association, mirroring what
//! [`crate::blob`] does for the public realm with the same
//! [`walk_blob_refs`](crate::blob::walk_blob_refs) walker.
//!
//! # Why the association is recorded at write time
//!
//! Upload cannot know the space: the blob arrives on a public endpoint before
//! any record names it. contrail rejects records referencing blobs not uploaded
//! to the space, which is the same rule read from the other end. Here the
//! reference is what creates the association, so a blob becomes readable in a
//! space exactly when a record in that space names it — and stops being
//! readable there when the last such record goes.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};

/// Record that `record_uri` in `space` references `blob_cid`.
///
/// Idempotent: the same reference written twice is one row.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn add_ref(
    store: &SqlActorStore,
    space: &str,
    record_uri: &str,
    blob_cid: &str,
) -> PdsResult<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO space_blob_ref (space, record_uri, blob_cid) VALUES (?, ?, ?)",
    )
    .bind(space)
    .bind(record_uri)
    .bind(blob_cid)
    .execute(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_blob_ref insert: {e}"),
    })?;
    Ok(())
}

/// Drop every reference held by one record.
///
/// Called before re-adding on update and on delete. Adding without dropping
/// would leave a blob readable in a space after the only record naming it
/// stopped naming it — the revocation half of the fix, and the half that is
/// easy to omit because nothing observably breaks.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn drop_record_refs(store: &SqlActorStore, record_uri: &str) -> PdsResult<u64> {
    let result = sqlx::query("DELETE FROM space_blob_ref WHERE record_uri = ?")
        .bind(record_uri)
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("space_blob_ref delete: {e}"),
        })?;
    Ok(result.rows_affected())
}

/// Whether `blob_cid` is referenced by any record in `space`.
///
/// This is the predicate `com.atproto.space.getBlob` was missing: it gated on
/// the space and then fetched by CID alone.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn is_referenced_in_space(
    store: &SqlActorStore,
    space: &str,
    blob_cid: &str,
) -> PdsResult<bool> {
    let row: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM space_blob_ref WHERE space = ? AND blob_cid = ? LIMIT 1")
            .bind(space)
            .bind(blob_cid)
            .fetch_optional(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("space_blob_ref lookup: {e}"),
            })?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SPACE_A: &str = "at://did:plc:owner/space/app.bsky.group/a";
    const SPACE_B: &str = "at://did:plc:owner/space/app.bsky.group/b";
    const REC_A: &str = "at://did:plc:owner/space/app.bsky.group/a/did:plc:alice/c.d.e/one";
    const REC_A2: &str = "at://did:plc:owner/space/app.bsky.group/a/did:plc:alice/c.d.e/two";
    const CID: &str = "bafkreiabc";

    async fn store() -> (SqlActorStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = SqlActorStore::open(tmp.path(), "did:plc:alice")
            .await
            .unwrap();
        (store, tmp)
    }

    #[tokio::test]
    async fn a_reference_makes_a_blob_readable_in_exactly_one_space() {
        let (s, _tmp) = store().await;
        assert!(!is_referenced_in_space(&s, SPACE_A, CID).await.unwrap());

        add_ref(&s, SPACE_A, REC_A, CID).await.unwrap();
        assert!(is_referenced_in_space(&s, SPACE_A, CID).await.unwrap());
        // The whole point of F-SPACE-12: the same CID in the same account's
        // store is not readable through a different space.
        assert!(!is_referenced_in_space(&s, SPACE_B, CID).await.unwrap());
    }

    #[tokio::test]
    async fn adding_the_same_reference_twice_is_one_row() {
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, CID).await.unwrap();
        add_ref(&s, SPACE_A, REC_A, CID).await.unwrap();
        assert_eq!(drop_record_refs(&s, REC_A).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn dropping_one_record_leaves_another_records_reference() {
        // Two records naming the same blob: losing one must not revoke the
        // other. A ref count that dropped by CID rather than by record would
        // get this wrong and nothing would visibly break until a read failed.
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, CID).await.unwrap();
        add_ref(&s, SPACE_A, REC_A2, CID).await.unwrap();

        drop_record_refs(&s, REC_A).await.unwrap();
        assert!(
            is_referenced_in_space(&s, SPACE_A, CID).await.unwrap(),
            "the second record still references it"
        );

        drop_record_refs(&s, REC_A2).await.unwrap();
        assert!(
            !is_referenced_in_space(&s, SPACE_A, CID).await.unwrap(),
            "with no record naming it, the blob is no longer readable in the space"
        );
    }

    #[tokio::test]
    async fn dropping_refs_for_an_unknown_record_is_a_no_op() {
        let (s, _tmp) = store().await;
        assert_eq!(drop_record_refs(&s, REC_A).await.unwrap(), 0);
    }
}
