//! Public-realm record- and blob-level takedown.
//!
//! `account.state` is an all-or-nothing lever: an operator asked to remove one
//! illegal post had to take down the whole account. `com.atproto.admin.defs`
//! has always declared three subject kinds for `updateSubjectStatus` —
//! `#repoRef`, `com.atproto.repo.strongRef` and `#repoBlobRef` — and this
//! module is the storage the latter two needed.
//!
//! Rows live in the per-actor SQLite regardless of storage profile. Records and
//! blobs dispatch through [`PublicRealmBackend`](crate::realm::PublicRealmBackend),
//! so on the fjall profile their bytes are not in this database; a takedown
//! column on `repo_record` would cover one profile and not the other. The
//! per-actor SQLite is always present, which is the same reasoning behind
//! `space_record_takedown` and the `preference` table.
//!
//! Presence of a row means "taken down". `takedown_ref` is the moderation
//! service's own identifier for the action — the PDS stores it and hands it
//! back, and never interprets it.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};

/// A recorded takedown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Takedown {
    /// The moderation service's identifier for the action, if it supplied one.
    pub reference: Option<String>,
    /// When this server applied it.
    pub taken_at: String,
}

/// Apply or lift a takedown on a single record.
///
/// Applying twice is a no-op that refreshes the reference; lifting a record
/// that was never taken down succeeds. Moderation actions arrive from a queue
/// that may retry, so both directions are idempotent by design.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn set_record(
    store: &SqlActorStore,
    uri: &str,
    applied: bool,
    reference: Option<&str>,
) -> PdsResult<()> {
    if applied {
        sqlx::query(
            "INSERT INTO public_record_takedown (uri, takedown_ref, taken_at)
             VALUES (?, ?, ?)
             ON CONFLICT(uri) DO UPDATE SET takedown_ref = excluded.takedown_ref",
        )
        .bind(uri)
        .bind(reference)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("public_record_takedown insert: {e}"),
        })?;
    } else {
        sqlx::query("DELETE FROM public_record_takedown WHERE uri = ?")
            .bind(uri)
            .execute(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("public_record_takedown delete: {e}"),
            })?;
    }
    Ok(())
}

/// Read the takedown on a single record, if any.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn get_record(store: &SqlActorStore, uri: &str) -> PdsResult<Option<Takedown>> {
    let row: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT takedown_ref, taken_at FROM public_record_takedown WHERE uri = ?")
            .bind(uri)
            .fetch_optional(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("public_record_takedown lookup: {e}"),
            })?;
    Ok(row.map(|(reference, taken_at)| Takedown {
        reference,
        taken_at,
    }))
}

/// Every taken-down record URI in one collection.
///
/// `listRecords` filters a page at a time, and a collection's takedown set is
/// almost always empty or tiny, so this is one query per page rather than one
/// per record.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn taken_down_in_collection(
    store: &SqlActorStore,
    did: &str,
    collection: &str,
) -> PdsResult<std::collections::HashSet<String>> {
    let prefix = format!("at://{did}/{collection}/");
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT uri FROM public_record_takedown WHERE uri LIKE ? || '%'")
            .bind(&prefix)
            .fetch_all(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("public_record_takedown list: {e}"),
            })?;
    Ok(rows.into_iter().map(|(uri,)| uri).collect())
}

/// Apply or lift a takedown on a single blob. Idempotent in both directions.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn set_blob(
    store: &SqlActorStore,
    cid: &str,
    applied: bool,
    reference: Option<&str>,
) -> PdsResult<()> {
    if applied {
        sqlx::query(
            "INSERT INTO public_blob_takedown (cid, takedown_ref, taken_at)
             VALUES (?, ?, ?)
             ON CONFLICT(cid) DO UPDATE SET takedown_ref = excluded.takedown_ref",
        )
        .bind(cid)
        .bind(reference)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("public_blob_takedown insert: {e}"),
        })?;
    } else {
        sqlx::query("DELETE FROM public_blob_takedown WHERE cid = ?")
            .bind(cid)
            .execute(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("public_blob_takedown delete: {e}"),
            })?;
    }
    Ok(())
}

/// Read the takedown on a single blob, if any.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn get_blob(store: &SqlActorStore, cid: &str) -> PdsResult<Option<Takedown>> {
    let row: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT takedown_ref, taken_at FROM public_blob_takedown WHERE cid = ?")
            .bind(cid)
            .fetch_optional(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("public_blob_takedown lookup: {e}"),
            })?;
    Ok(row.map(|(reference, taken_at)| Takedown {
        reference,
        taken_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn store() -> (SqlActorStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = SqlActorStore::open(tmp.path(), "did:plc:alice")
            .await
            .unwrap();
        (store, tmp)
    }

    #[tokio::test]
    async fn a_record_takedown_round_trips_with_its_reference() {
        let (s, _tmp) = store().await;
        let uri = "at://did:plc:alice/app.bsky.feed.post/abc";
        assert!(get_record(&s, uri).await.unwrap().is_none());

        set_record(&s, uri, true, Some("mod-action-42"))
            .await
            .unwrap();
        let t = get_record(&s, uri).await.unwrap().expect("taken down");
        assert_eq!(t.reference.as_deref(), Some("mod-action-42"));

        set_record(&s, uri, false, None).await.unwrap();
        assert!(get_record(&s, uri).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn applying_and_lifting_are_both_idempotent() {
        // Moderation actions arrive from a queue that retries.
        let (s, _tmp) = store().await;
        let uri = "at://did:plc:alice/app.bsky.feed.post/abc";
        set_record(&s, uri, true, Some("first")).await.unwrap();
        set_record(&s, uri, true, Some("second")).await.unwrap();
        assert_eq!(
            get_record(&s, uri)
                .await
                .unwrap()
                .unwrap()
                .reference
                .as_deref(),
            Some("second")
        );
        set_record(&s, uri, false, None).await.unwrap();
        set_record(&s, uri, false, None).await.unwrap();
        assert!(get_record(&s, uri).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_takedown_without_a_reference_is_still_a_takedown() {
        // `#statusAttr.ref` is optional. A missing reference must not read as
        // "not taken down".
        let (s, _tmp) = store().await;
        let uri = "at://did:plc:alice/app.bsky.feed.post/abc";
        set_record(&s, uri, true, None).await.unwrap();
        let t = get_record(&s, uri).await.unwrap().expect("taken down");
        assert!(t.reference.is_none());
    }

    #[tokio::test]
    async fn the_collection_query_matches_only_that_collection() {
        let (s, _tmp) = store().await;
        set_record(&s, "at://did:plc:alice/app.bsky.feed.post/one", true, None)
            .await
            .unwrap();
        set_record(&s, "at://did:plc:alice/app.bsky.feed.like/two", true, None)
            .await
            .unwrap();
        let posts = taken_down_in_collection(&s, "did:plc:alice", "app.bsky.feed.post")
            .await
            .unwrap();
        assert_eq!(posts.len(), 1);
        assert!(posts.contains("at://did:plc:alice/app.bsky.feed.post/one"));
    }

    #[tokio::test]
    async fn a_blob_takedown_round_trips() {
        let (s, _tmp) = store().await;
        let cid = "bafkreiabc";
        assert!(get_blob(&s, cid).await.unwrap().is_none());
        set_blob(&s, cid, true, Some("mod-action-7")).await.unwrap();
        assert_eq!(
            get_blob(&s, cid)
                .await
                .unwrap()
                .unwrap()
                .reference
                .as_deref(),
            Some("mod-action-7")
        );
        set_blob(&s, cid, false, None).await.unwrap();
        assert!(get_blob(&s, cid).await.unwrap().is_none());
    }
}
