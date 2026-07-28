//! Blob storage — `com.atproto.repo.uploadBlob` + `listMissingBlobs` impl.
//!
//!  blobs are
//! content-addressed binaries (images, videos, etc.) referenced from records.
//! Each blob is stored once per account in the per-actor SQLite store and
//! ref-counted via the `repo_blob_ref` table; rows are pruned when the last
//! reference is deleted.
//!
//! The CID is `cidv1 raw sha256` of the blob bytes (matching the upstream
//! atproto blob spec). Returns the canonical blob ref envelope used in
//! record values.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use atproto_dasl::cid::compute_raw_cid;
use atproto_record::lexicon::{Blob, Link, TypedBlob};
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Default ceiling for `uploadBlob` (16 MiB, matching upstream defaults).
///
/// A default, not a constant: operators raise it for video and lower it for
/// abuse control via `PDS_BLOB_UPLOAD_LIMIT`. It was previously a `const` that
/// nothing could override — and, because no body limit was configured, one that
/// axum's own 2 MiB default pre-empted, so the number here described nothing
/// the server actually did.
pub const DEFAULT_BLOB_UPLOAD_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// One ref-tracked blob row in `repo_blob_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRefRow {
    /// Blob CID (CIDv1 raw sha256).
    pub cid: String,
    /// MIME type as declared at upload.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Byte length.
    pub size: u64,
    /// AT-URI of the record that references this blob.
    #[serde(rename = "recordUri")]
    pub record_uri: String,
}

/// The canonical blob-ref envelope embedded in record values.
///
/// Serializes as the typed lexicon form, which is one of only two shapes the
/// AT Protocol data model accepts and the only one still valid at write time:
///
/// ```json
/// { "$type": "blob",
///   "ref": { "$link": "bafkrei…" },
///   "mimeType": "image/jpeg",
///   "size": 10000 }
/// ```
///
/// Note that the CID is nested under `ref` as a cid-link, not spliced into the
/// envelope as a top-level `$link`. Both schemas are declared strict upstream,
/// so an envelope carrying an unexpected key is rejected outright rather than
/// having the extra key ignored.
pub type BlobRef = TypedBlob;

/// Build the canonical blob-ref envelope for a stored blob.
#[must_use]
pub fn blob_ref(cid: String, mime_type: String, size: u64) -> BlobRef {
    TypedBlob::new(Blob {
        ref_: Link { link: cid },
        mime_type,
        size,
    })
}

/// Persist blob bytes to the per-actor store.
///
/// Returns the blob's CID; idempotent (re-uploading the same bytes returns
/// the same CID and is a no-op). The MIME type is recorded on first upload
/// and ignored on subsequent ones (the first wins).
///
/// # Errors
///
/// - [`PdsError::Storage`] for any underlying SQL error.
/// - [`PdsError::AuthDenied`] if `bytes.len() > limit`.
pub async fn put_blob(
    store: &SqlActorStore,
    bytes: &[u8],
    mime_type: &str,
    limit: usize,
) -> PdsResult<BlobRef> {
    if bytes.len() > limit {
        return Err(PdsError::AuthDenied {
            reason: format!("blob too large: {} bytes (max {limit})", bytes.len()),
        });
    }
    let cid = compute_raw_cid(bytes);
    let cid_str = cid.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT OR IGNORE INTO repo_blob (cid, mime_type, size, data, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&cid_str)
    .bind(mime_type)
    .bind(bytes.len() as i64)
    .bind(bytes)
    .bind(&now)
    .execute(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("put_blob: {e}"),
    })?;

    Ok(blob_ref(cid_str, mime_type.to_string(), bytes.len() as u64))
}

/// Retrieve raw blob bytes by CID.
///
/// Returns `Ok(None)` when the blob is absent.
pub async fn get_blob(store: &SqlActorStore, cid: &str) -> PdsResult<Option<(Vec<u8>, String)>> {
    let row: Option<(Vec<u8>, String)> =
        sqlx::query_as("SELECT data, mime_type FROM repo_blob WHERE cid = ?")
            .bind(cid)
            .fetch_optional(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("get_blob: {e}"),
            })?;
    Ok(row)
}

/// Record a record→blob reference (ref-count++).
///
/// Called from the writer after a record write that contains a blob ref so
/// `listMissingBlobs` can detect referenced-but-absent blobs.
pub async fn add_ref(store: &SqlActorStore, record_uri: &str, blob: &BlobRef) -> PdsResult<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
         VALUES (?, ?, ?, ?)",
    )
    .bind(record_uri)
    .bind(&blob.inner.ref_.link)
    .bind(&blob.inner.mime_type)
    .bind(blob.inner.size as i64)
    .execute(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("add_ref: {e}"),
    })?;
    Ok(())
}

/// Remove all refs from `record_uri`. GC any orphan blobs (zero refs).
///
/// Returns the count of orphan blob rows removed.
pub async fn drop_record_refs(store: &SqlActorStore, record_uri: &str) -> PdsResult<u64> {
    // Snapshot which CIDs this record used to reference.
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT blob_cid FROM repo_blob_ref WHERE record_uri = ?")
            .bind(record_uri)
            .fetch_all(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("drop_record_refs select: {e}"),
            })?;
    sqlx::query("DELETE FROM repo_blob_ref WHERE record_uri = ?")
        .bind(record_uri)
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("drop_record_refs delete: {e}"),
        })?;

    let mut orphans = 0u64;
    for (cid,) in rows {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_blob_ref WHERE blob_cid = ?")
            .bind(&cid)
            .fetch_one(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("orphan-count: {e}"),
            })?;
        if row.0 == 0 {
            sqlx::query("DELETE FROM repo_blob WHERE cid = ?")
                .bind(&cid)
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("orphan-delete: {e}"),
                })?;
            orphans += 1;
        }
    }
    Ok(orphans)
}

/// List **all stored** blobs in this account (CIDs only). For
/// `com.atproto.sync.listBlobs`.
pub async fn list_all(
    store: &SqlActorStore,
    cursor: Option<&str>,
    limit: u32,
) -> PdsResult<Vec<String>> {
    let limit = limit.clamp(1, 1000);
    let rows: Vec<(String,)> = match cursor {
        Some(c) => {
            sqlx::query_as("SELECT cid FROM repo_blob WHERE cid > ? ORDER BY cid ASC LIMIT ?")
                .bind(c)
                .bind(limit as i64)
                .fetch_all(store.pool())
                .await
        }
        None => {
            sqlx::query_as("SELECT cid FROM repo_blob ORDER BY cid ASC LIMIT ?")
                .bind(limit as i64)
                .fetch_all(store.pool())
                .await
        }
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("list_all: {e}"),
    })?;
    Ok(rows.into_iter().map(|(c,)| c).collect())
}

/// List blobs that are *referenced* but absent from `repo_blob`.
///
/// `cursor` is an opaque "last cid seen" pointer; `limit` is clamped to
/// [1, 1000].
pub async fn list_missing(
    store: &SqlActorStore,
    cursor: Option<&str>,
    limit: u32,
) -> PdsResult<Vec<BlobRefRow>> {
    let limit = limit.clamp(1, 1000);
    let sql = match cursor {
        Some(_) => {
            "SELECT DISTINCT r.blob_cid, r.mime_type, r.size, r.record_uri
             FROM repo_blob_ref r
             LEFT JOIN repo_blob b ON b.cid = r.blob_cid
             WHERE b.cid IS NULL AND r.blob_cid > ?
             ORDER BY r.blob_cid ASC
             LIMIT ?"
        }
        None => {
            "SELECT DISTINCT r.blob_cid, r.mime_type, r.size, r.record_uri
             FROM repo_blob_ref r
             LEFT JOIN repo_blob b ON b.cid = r.blob_cid
             WHERE b.cid IS NULL
             ORDER BY r.blob_cid ASC
             LIMIT ?"
        }
    };
    let mut q = sqlx::query(sql);
    if let Some(c) = cursor {
        q = q.bind(c);
    }
    q = q.bind(limit as i64);
    let rows = q
        .fetch_all(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("list_missing: {e}"),
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(BlobRefRow {
            cid: row.try_get::<String, _>("blob_cid").unwrap_or_default(),
            mime_type: row.try_get::<String, _>("mime_type").unwrap_or_default(),
            size: row.try_get::<i64, _>("size").unwrap_or(0) as u64,
            record_uri: row.try_get::<String, _>("record_uri").unwrap_or_default(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_store() -> SqlActorStore {
        SqlActorStore::open_memory("did:plc:test").await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_get_round_trip() {
        let store = fresh_store().await;
        let blob = put_blob(
            &store,
            b"hello world",
            "text/plain",
            DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
        )
        .await
        .unwrap();
        assert!(
            blob.inner.ref_.link.starts_with("bafkrei") || blob.inner.ref_.link.starts_with("bafy")
        );
        assert_eq!(blob.inner.size, 11);
        let (data, mime) = get_blob(&store, &blob.inner.ref_.link)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, b"hello world");
        assert_eq!(mime, "text/plain");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_blob_is_idempotent() {
        let store = fresh_store().await;
        let a = put_blob(
            &store,
            b"abc",
            "text/plain",
            DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
        )
        .await
        .unwrap();
        let b = put_blob(
            &store,
            b"abc",
            "text/plain",
            DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
        )
        .await
        .unwrap();
        assert_eq!(a.inner.ref_.link, b.inner.ref_.link);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversize_blob_rejected() {
        let store = fresh_store().await;
        // Cheap: the limit under test is the argument, not a 16 MiB constant.
        let huge = vec![0u8; 65];
        let result = put_blob(&store, &huge, "application/octet-stream", 64).await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_missing_reports_unreferenced_uploads_correctly() {
        let store = fresh_store().await;
        // No blobs yet.
        let missing = list_missing(&store, None, 100).await.unwrap();
        assert_eq!(missing.len(), 0);

        // Add a ref to a CID that hasn't been uploaded.
        let fake_cid = "bafkreig000000000000000000000000000000000000000000000fake";
        sqlx::query(
            "INSERT INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
             VALUES (?, ?, ?, ?)",
        )
        .bind("at://did:plc:test/app.bsky.feed.post/x")
        .bind(fake_cid)
        .bind("image/png")
        .bind(1234i64)
        .execute(store.pool())
        .await
        .unwrap();

        let missing = list_missing(&store, None, 100).await.unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].cid, fake_cid);
        assert_eq!(missing[0].mime_type, "image/png");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drop_record_refs_gcs_orphan_blobs() {
        let store = fresh_store().await;
        let blob = put_blob(
            &store,
            b"data",
            "text/plain",
            DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
        )
        .await
        .unwrap();
        add_ref(&store, "at://x/c/k1", &blob).await.unwrap();
        // Second reference keeps the blob alive after dropping the first.
        add_ref(&store, "at://x/c/k2", &blob).await.unwrap();
        let orphans = drop_record_refs(&store, "at://x/c/k1").await.unwrap();
        assert_eq!(orphans, 0, "blob still referenced");
        assert!(
            get_blob(&store, &blob.inner.ref_.link)
                .await
                .unwrap()
                .is_some()
        );

        // Dropping the last ref garbage-collects.
        let orphans = drop_record_refs(&store, "at://x/c/k2").await.unwrap();
        assert_eq!(orphans, 1, "blob should be GCd");
        assert!(
            get_blob(&store, &blob.inner.ref_.link)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The blob-ref envelope must serialize to the typed lexicon shape.
    ///
    /// Byte-for-byte against the canonical form rather than a round trip: this
    /// envelope is what `uploadBlob` hands a client to embed in a record, and
    /// both upstream schemas are declared strict, so a wrong key set is not
    /// leniently ignored — the record is rejected by the validator and
    /// `@atproto/api` throws on the upload call itself.
    ///
    /// The shape here matches the `blob` value in the vendored interop corpus
    /// at `tests/interop/data-model/data-model-fixtures.json`.
    #[test]
    fn blob_ref_serializes_as_the_typed_lexicon_envelope() {
        let envelope = blob_ref(
            "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity".to_string(),
            "image/jpeg".to_string(),
            10_000,
        );
        let actual = serde_json::to_value(&envelope).expect("blob ref should serialize");

        assert_eq!(
            actual,
            serde_json::json!({
                "$type": "blob",
                "ref": { "$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity" },
                "mimeType": "image/jpeg",
                "size": 10_000,
            })
        );

        // The old shape spliced the CID into the envelope as a top-level
        // `$link` and carried no `$type`. Neither key set is accepted.
        let object = actual.as_object().unwrap();
        assert!(
            !object.contains_key("$link"),
            "`$link` must be nested under `ref`, never a top-level key"
        );
        assert_eq!(object.len(), 4, "the typed envelope has exactly four keys");
    }
}
