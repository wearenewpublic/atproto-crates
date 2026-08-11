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

/// Record that `record_uri` in `space` references `blob_cid`, as of `rev`.
///
/// `rev` is the commit revision of the write that created the reference — the
/// same revision `listRepoOps` reports for that record, so a consumer can use
/// one cursor for records and blobs alike.
///
/// Idempotent: the same reference written twice is one row. A record that is
/// updated has its references dropped and re-added, so the stored `rev` is
/// always that of the write that last named the blob, not the first.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn add_ref(
    store: &SqlActorStore,
    space: &str,
    record_uri: &str,
    blob_cid: &str,
    rev: &str,
) -> PdsResult<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO space_blob_ref (space, record_uri, blob_cid, rev)
         VALUES (?, ?, ?, ?)",
    )
    .bind(space)
    .bind(record_uri)
    .bind(blob_cid)
    .bind(rev)
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

/// The blob CIDs referenced by records in `space`, ordered by CID.
///
/// `since` filters to blobs a record named at a revision *after* it, which is
/// how a syncer catches up without re-listing a whole repo and how a migration
/// carries only what it has not carried already. A blob named by two records
/// appears once, and is included when either naming is recent enough — the
/// question is which blobs to fetch, not how many times they were named.
///
/// Paging is by CID rather than by revision: revisions repeat across the rows
/// of one commit, so a rev cursor could not say which of them had been
/// delivered. `cursor` is the last CID of the previous page.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn list_refs(
    store: &SqlActorStore,
    space: &str,
    since: Option<&str>,
    cursor: Option<&str>,
    limit: u32,
) -> PdsResult<Vec<String>> {
    let cids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT blob_cid FROM space_blob_ref
         WHERE space = ?
           AND (?2 IS NULL OR rev > ?2)
           AND (?3 IS NULL OR blob_cid > ?3)
         ORDER BY blob_cid
         LIMIT ?4",
    )
    .bind(space)
    .bind(since)
    .bind(cursor)
    .bind(i64::from(limit))
    .fetch_all(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_blob_ref list: {e}"),
    })?;
    Ok(cids)
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
    /// A commit revision. These tests predate `since` filtering and only need
    /// the column populated; the listing tests below choose theirs.
    const REV: &str = "3jui7kd2z2y2e";

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

        add_ref(&s, SPACE_A, REC_A, CID, REV).await.unwrap();
        assert!(is_referenced_in_space(&s, SPACE_A, CID).await.unwrap());
        // The whole point of F-SPACE-12: the same CID in the same account's
        // store is not readable through a different space.
        assert!(!is_referenced_in_space(&s, SPACE_B, CID).await.unwrap());
    }

    #[tokio::test]
    async fn adding_the_same_reference_twice_is_one_row() {
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, CID, REV).await.unwrap();
        add_ref(&s, SPACE_A, REC_A, CID, REV).await.unwrap();
        assert_eq!(drop_record_refs(&s, REC_A).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn dropping_one_record_leaves_another_records_reference() {
        // Two records naming the same blob: losing one must not revoke the
        // other. A ref count that dropped by CID rather than by record would
        // get this wrong and nothing would visibly break until a read failed.
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, CID, REV).await.unwrap();
        add_ref(&s, SPACE_A, REC_A2, CID, REV).await.unwrap();

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

    /// `since` answers "which blobs were named after this revision", which is
    /// what lets a syncer catch up instead of re-listing a whole repo.
    #[tokio::test]
    async fn since_lists_only_blobs_named_after_that_revision() {
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, "bafkrei-old", "3aaa")
            .await
            .unwrap();
        add_ref(&s, SPACE_A, REC_A2, "bafkrei-new", "3bbb")
            .await
            .unwrap();

        let all = list_refs(&s, SPACE_A, None, None, 100).await.unwrap();
        assert_eq!(all, vec!["bafkrei-new", "bafkrei-old"], "ordered by CID");

        let since = list_refs(&s, SPACE_A, Some("3aaa"), None, 100)
            .await
            .unwrap();
        assert_eq!(since, vec!["bafkrei-new"], "strictly after the given rev");

        // A caller already at the tip has nothing to fetch.
        assert!(
            list_refs(&s, SPACE_A, Some("3bbb"), None, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Rows written before the revision column existed sort before every TID,
    /// so a full listing still finds them and a `since` listing does not.
    ///
    /// That is the safe direction: a caller passing `since` is resuming from a
    /// point it has already seen, and these rows predate any such point, while
    /// a caller that has never listed passes no `since` and receives them.
    #[tokio::test]
    async fn references_predating_the_revision_column_are_listed_without_since() {
        let (s, _tmp) = store().await;
        // What the migration's DEFAULT '' leaves behind.
        add_ref(&s, SPACE_A, REC_A, CID, "").await.unwrap();

        assert_eq!(
            list_refs(&s, SPACE_A, None, None, 100).await.unwrap(),
            vec![CID]
        );
        assert!(
            list_refs(&s, SPACE_A, Some("3aaa"), None, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// One blob named by two records is one entry: the question is which blobs
    /// to fetch, not how many times they were named.
    #[tokio::test]
    async fn a_blob_named_twice_is_listed_once() {
        let (s, _tmp) = store().await;
        add_ref(&s, SPACE_A, REC_A, CID, "3aaa").await.unwrap();
        add_ref(&s, SPACE_A, REC_A2, CID, "3bbb").await.unwrap();

        assert_eq!(
            list_refs(&s, SPACE_A, None, None, 100).await.unwrap(),
            vec![CID]
        );
        // And it is still one entry when only the later naming is in range.
        assert_eq!(
            list_refs(&s, SPACE_A, Some("3aaa"), None, 100)
                .await
                .unwrap(),
            vec![CID]
        );
    }

    /// Paging walks CIDs, and a listing is scoped to its own space.
    #[tokio::test]
    async fn listing_pages_by_cid_within_one_space() {
        let (s, _tmp) = store().await;
        for (i, cid) in ["bafkrei-a", "bafkrei-b", "bafkrei-c"].iter().enumerate() {
            add_ref(&s, SPACE_A, REC_A, cid, &format!("3aa{i}"))
                .await
                .unwrap();
        }
        add_ref(&s, SPACE_B, REC_A2, "bafkrei-other", "3aaa")
            .await
            .unwrap();

        let first = list_refs(&s, SPACE_A, None, None, 2).await.unwrap();
        assert_eq!(first, vec!["bafkrei-a", "bafkrei-b"]);
        let second = list_refs(&s, SPACE_A, None, first.last().map(String::as_str), 2)
            .await
            .unwrap();
        assert_eq!(
            second,
            vec!["bafkrei-c"],
            "cursor resumes after the last CID"
        );

        // The other space's blob never appears, which is the same isolation
        // `is_referenced_in_space` enforces for reads.
        assert!(
            !list_refs(&s, SPACE_A, None, None, 100)
                .await
                .unwrap()
                .contains(&"bafkrei-other".to_string())
        );
    }

    #[tokio::test]
    async fn dropping_refs_for_an_unknown_record_is_a_no_op() {
        let (s, _tmp) = store().await;
        assert_eq!(drop_record_refs(&s, REC_A).await.unwrap(), 0);
    }
}
