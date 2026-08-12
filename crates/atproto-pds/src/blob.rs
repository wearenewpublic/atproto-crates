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

/// Collect every blob reference embedded anywhere in a record value.
///
/// A record carries blobs as the lexicon's typed envelope:
///
/// ```json
/// { "$type": "blob", "ref": { "$link": "bafkrei…" }, "mimeType": "image/jpeg", "size": 10000 }
/// ```
///
/// They appear at arbitrary depth — `embed.images[0].image`, `embed.media.video`,
/// inside a record union — so this recurses rather than checking a fixed set of
/// paths. A walker that knew about `embed.images` would silently miss every
/// lexicon it had not been taught, which is the same failure mode as not
/// walking at all: a blob referenced and never tracked.
///
/// The whole envelope is validated before a reference is accepted. A record may
/// legitimately contain a map carrying `$type: "blob"` and nothing else, or a
/// `ref` that is not a `$link`; treating those as references would write rows
/// with an empty CID that `listMissingBlobs` would then report forever.
#[must_use]
pub fn walk_blob_refs(value: &serde_json::Value) -> Vec<BlobRef> {
    let mut found = Vec::new();
    collect_blob_refs(value, &mut found);
    found
}

fn collect_blob_refs(value: &serde_json::Value, out: &mut Vec<BlobRef>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(blob) = parse_blob_envelope(map) {
                out.push(blob);
                // A blob envelope's own fields are scalars, so there is nothing
                // below it to walk.
                return;
            }
            for nested in map.values() {
                collect_blob_refs(nested, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_blob_refs(item, out);
            }
        }
        _ => {}
    }
}

/// Recognise a complete blob envelope, or `None`.
fn parse_blob_envelope(map: &serde_json::Map<String, serde_json::Value>) -> Option<BlobRef> {
    if map.get("$type").and_then(serde_json::Value::as_str) != Some("blob") {
        return None;
    }
    let link = map
        .get("ref")?
        .as_object()?
        .get("$link")?
        .as_str()
        .filter(|link| !link.is_empty())?;
    let mime_type = map.get("mimeType")?.as_str()?;
    let size = map.get("size")?.as_u64()?;
    Some(blob_ref(link.to_string(), mime_type.to_string(), size))
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

/// Retrieve raw blob bytes by CID, without asking why the blob exists.
///
/// Returns `Ok(None)` when the blob is absent.
///
/// **Do not call this from an unauthenticated path.** `repo_blob` holds public
/// and permissioned bytes together — permissioned blobs arrive through the
/// ordinary `uploadBlob`, because there is no space-specific upload endpoint —
/// so serving straight from it is what let anyone holding a CID read
/// permissioned content with no credential. Public paths want
/// [`get_public_blob`]; space paths gate on `space::blob_ref` first.
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

/// Whether a **public** record references `cid`.
///
/// The join is the authorization. `repo_blob_ref` is populated from the public
/// write path only, and `repo_record` holds public records only, so a blob
/// reachable through both is one a public record put on the open internet. A
/// blob referenced solely from a permissioned record is not — and neither is one
/// uploaded but never referenced, which is why an upload is not publicly
/// fetchable until a record names it.
///
/// This is zds's `getPublicBlob` join expressed in this schema; zds is the only
/// other 0016 implementation and the one that got this right.
///
/// A predicate rather than a joined `SELECT … data` because the bytes may not be
/// in this database at all: on the fjall profile they come from a fjall
/// keyspace through `PublicRealmBackend`. The per-actor SQLite always exists, so
/// asking it the *question* works on both profiles while asking it for the
/// *bytes* would not.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn is_publicly_referenced(store: &SqlActorStore, cid: &str) -> PdsResult<bool> {
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM repo_blob_ref r
         JOIN repo_record c ON c.uri = r.record_uri
         WHERE r.blob_cid = ? LIMIT 1",
    )
    .bind(cid)
    .fetch_optional(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("is_publicly_referenced: {e}"),
    })?;
    Ok(row.is_some())
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
    // Same join as `get_public_blob`, for the same reason: enumerating every
    // stored CID hands out the identifiers of permissioned blobs, and a CID is
    // all the public endpoint used to require. zds joins the same way in its
    // public `listBlobs`.
    const PUBLIC: &str = "AND EXISTS (
             SELECT 1 FROM repo_blob_ref r
             JOIN repo_record c ON c.uri = r.record_uri
             WHERE r.blob_cid = b.cid
           )";
    // `AssertSqlSafe`: the only interpolation is `PUBLIC`, a `const` defined
    // directly above. The caller's cursor and limit are bound, not formatted.
    let rows: Vec<(String,)> =
        match cursor {
            Some(c) => sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT b.cid FROM repo_blob b WHERE b.cid > ? {PUBLIC} ORDER BY b.cid ASC LIMIT ?"
            )))
            .bind(c)
            .bind(limit as i64)
            .fetch_all(store.pool())
            .await,
            None => {
                sqlx::query_as(sqlx::AssertSqlSafe(format!(
                    "SELECT b.cid FROM repo_blob b WHERE 1 = 1 {PUBLIC} ORDER BY b.cid ASC LIMIT ?"
                )))
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

/// One page of publicly-referenced blob CIDs.
#[derive(Debug, Clone)]
pub struct PublicBlobPage {
    /// The CIDs on this page that a public record references.
    pub cids: Vec<String>,
    /// Cursor for the next page: the last CID **scanned**, not the last kept.
    ///
    /// `None` when the scan found nothing at all, which is the end of the list.
    pub cursor: Option<String>,
    /// How many CIDs the scan returned before the public filter ran.
    ///
    /// The only honest way to tell "this page was short because the list ended"
    /// from "this page was short because its blobs were permissioned" — the two
    /// look identical from `cids` alone, and a caller deciding whether to fetch
    /// another page needs to distinguish them.
    pub scanned: usize,
}

/// One page of the blobs a public record references, on either storage profile.
///
/// Both callers — `com.atproto.sync.listBlobs` and the portal's repository
/// browser — need the same answer, and it is not a single query: on the SQLite
/// profile the join runs in SQL and every row returned is kept, while on the
/// fjall profile the bytes live in a keyspace that knows nothing about records,
/// so the page is enumerated first and filtered afterwards through
/// [`is_publicly_referenced`]. Reimplementing that split per caller would be a
/// second place for a permissioned CID to leak.
///
/// `backend` is the `BlobStorage` handle when one is wired up, and `None` for
/// the SQLite-direct path. `store` is required either way: on the fjall profile
/// it is what answers the public-reference question.
///
/// # Errors
///
/// [`PdsError::Storage`] on backend failure.
pub async fn list_public(
    store: &SqlActorStore,
    backend: Option<&dyn crate::actor_store::traits::BlobStorage>,
    did: &str,
    cursor: Option<&str>,
    limit: u32,
) -> PdsResult<PublicBlobPage> {
    let Some(backend) = backend else {
        // This path joins in SQL, so every row returned is kept and the last
        // row is both the last scanned and the last kept.
        let page = list_all(store, cursor, limit).await?;
        return Ok(PublicBlobPage {
            cursor: page.last().cloned(),
            scanned: page.len(),
            cids: page,
        });
    };

    // The trait cannot express the join, so the page is filtered after the fact.
    // A page may therefore come back shorter than `limit`; the cursor still
    // advances over the underlying CIDs, so pagination terminates.
    let all = backend.list_all_cids(did, cursor, limit).await?;
    let scanned = all.len();
    let last_scanned = all.last().cloned();
    let mut kept = Vec::with_capacity(all.len());
    for cid in all {
        if is_publicly_referenced(store, &cid).await? {
            kept.push(cid);
        }
    }
    Ok(PublicBlobPage {
        cids: kept,
        cursor: last_scanned,
        scanned,
    })
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
    // Both reference tables, because a migrating account has to be told about
    // every blob it is missing and not merely the public ones.
    //
    // The prescribed migration flow is: import the repo, upload the blobs
    // `listMissingBlobs` reports, activate. A permissioned blob that never
    // appeared in that report was never asked for and never uploaded, so the
    // records naming it arrived at the new host pointing at bytes that were
    // left behind — and the account was activated as though the move were
    // complete.
    //
    // `space_blob_ref` carries no `mime_type` or `size`; the columns are
    // padded because `BlobRefRow` has them, and `listMissingBlobs` emits
    // neither — a caller is being told which CIDs to upload, and it is
    // uploading bytes it already holds.
    let sql = match cursor {
        Some(_) => {
            "SELECT blob_cid, MIN(mime_type) AS mime_type, MIN(size) AS size,
                     MIN(record_uri) AS record_uri FROM (
                 SELECT r.blob_cid, r.mime_type, r.size, r.record_uri
                 FROM repo_blob_ref r
                 LEFT JOIN repo_blob b ON b.cid = r.blob_cid
                 WHERE b.cid IS NULL
                 UNION
                 SELECT s.blob_cid, '' AS mime_type, 0 AS size, s.record_uri
                 FROM space_blob_ref s
                 LEFT JOIN repo_blob b ON b.cid = s.blob_cid
                 WHERE b.cid IS NULL
             )
             WHERE blob_cid > ?
             GROUP BY blob_cid
             ORDER BY blob_cid ASC
             LIMIT ?"
        }
        None => {
            "SELECT blob_cid, MIN(mime_type) AS mime_type, MIN(size) AS size,
                     MIN(record_uri) AS record_uri FROM (
                 SELECT r.blob_cid, r.mime_type, r.size, r.record_uri
                 FROM repo_blob_ref r
                 LEFT JOIN repo_blob b ON b.cid = r.blob_cid
                 WHERE b.cid IS NULL
                 UNION
                 SELECT s.blob_cid, '' AS mime_type, 0 AS size, s.record_uri
                 FROM space_blob_ref s
                 LEFT JOIN repo_blob b ON b.cid = s.blob_cid
                 WHERE b.cid IS NULL
             )
             GROUP BY blob_cid
             ORDER BY blob_cid ASC
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

    // --- the walker (F-BLOB-02) -------------------------------------------

    fn envelope(cid: &str) -> serde_json::Value {
        serde_json::json!({
            "$type": "blob",
            "ref": { "$link": cid },
            "mimeType": "image/jpeg",
            "size": 1234,
        })
    }

    #[test]
    fn a_top_level_blob_is_found() {
        let record = serde_json::json!({
            "$type": "app.bsky.actor.profile",
            "avatar": envelope("bafkreiavatar"),
        });
        let found = walk_blob_refs(&record);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].inner.ref_.link, "bafkreiavatar");
        assert_eq!(found[0].inner.mime_type, "image/jpeg");
        assert_eq!(found[0].inner.size, 1234);
    }

    /// Blobs sit at arbitrary depth, including inside arrays.
    ///
    /// A walker that knew about `embed.images` would miss every lexicon it had
    /// not been taught — the same outcome as not walking at all.
    #[test]
    fn nested_and_repeated_blobs_are_all_found() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    { "alt": "one", "image": envelope("bafkreione") },
                    { "alt": "two", "image": envelope("bafkreitwo") },
                ],
                "media": { "video": envelope("bafkreivideo") },
            },
        });
        let mut links: Vec<String> = walk_blob_refs(&record)
            .into_iter()
            .map(|b| b.inner.ref_.link)
            .collect();
        links.sort();
        assert_eq!(links, vec!["bafkreione", "bafkreitwo", "bafkreivideo"]);
    }

    /// A partial or malformed envelope is not a reference.
    ///
    /// Accepting one would write a row with an empty or nonsense CID that
    /// `listMissingBlobs` would then report as missing forever.
    #[test]
    fn malformed_lookalikes_are_ignored() {
        let record = serde_json::json!({
            "bare_type":    { "$type": "blob" },
            "no_link":      { "$type": "blob", "ref": {}, "mimeType": "image/png", "size": 1 },
            "empty_link":   { "$type": "blob", "ref": { "$link": "" }, "mimeType": "image/png", "size": 1 },
            "ref_not_map":  { "$type": "blob", "ref": "bafkrei", "mimeType": "image/png", "size": 1 },
            "no_mime":      { "$type": "blob", "ref": { "$link": "bafkrei" }, "size": 1 },
            "no_size":      { "$type": "blob", "ref": { "$link": "bafkrei" }, "mimeType": "image/png" },
            "wrong_type":   { "$type": "notablob", "ref": { "$link": "bafkrei" }, "mimeType": "image/png", "size": 1 },
            "plain_link":   { "$link": "bafkrei" },
        });
        assert!(
            walk_blob_refs(&record).is_empty(),
            "{:?}",
            walk_blob_refs(&record)
        );
    }

    #[test]
    fn a_record_with_no_blobs_yields_none() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "no media here",
            "langs": ["en"],
        });
        assert!(walk_blob_refs(&record).is_empty());
    }
    /// A blob referenced only by a permissioned record is reported as missing.
    ///
    /// The prescribed migration flow is: import the repo, upload the blobs
    /// `listMissingBlobs` reports, activate. A permissioned blob absent from
    /// that report is never asked for and never uploaded, so the records
    /// naming it arrive at the new host pointing at bytes left behind — and
    /// the account is activated as though the move had completed. Nothing
    /// fails; the data is simply gone.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_permissioned_blob_is_reported_missing_like_a_public_one() {
        let store = fresh_store().await;
        const SPACE: &str = "at://did:plc:test/space/app.bsky.group/default";
        const PUBLIC_CID: &str = "bafkreipublicmissing";
        const SPACE_CID: &str = "bafkreispacemissing";

        sqlx::query(
            "INSERT INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
             VALUES (?, ?, 'image/png', 7)",
        )
        .bind("at://did:plc:test/app.t.rec/pub")
        .bind(PUBLIC_CID)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO space_blob_ref (space, record_uri, blob_cid, rev)
             VALUES (?, ?, ?, '3jui7kd2z2y2e')",
        )
        .bind(SPACE)
        .bind(format!("{SPACE}/did:plc:test/app.t.rec/priv"))
        .bind(SPACE_CID)
        .execute(store.pool())
        .await
        .unwrap();

        let missing: Vec<String> = list_missing(&store, None, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.cid)
            .collect();
        assert!(missing.contains(&PUBLIC_CID.to_string()), "{missing:?}");
        assert!(
            missing.contains(&SPACE_CID.to_string()),
            "a permissioned reference must be reported too: {missing:?}"
        );

        // And uploading the bytes retires the report, from either table.
        for (cid, bytes) in [(PUBLIC_CID, &b"public!"[..]), (SPACE_CID, &b"private"[..])] {
            sqlx::query(
                "INSERT INTO repo_blob (cid, mime_type, size, data, created_at)
                 VALUES (?, ?, ?, ?, '2026-08-11T00:00:00Z')",
            )
            .bind(cid)
            .bind("image/png")
            .bind(bytes.len() as i64)
            .bind(bytes)
            .execute(store.pool())
            .await
            .unwrap();
        }
        assert!(
            list_missing(&store, None, 100).await.unwrap().is_empty(),
            "nothing is missing once the bytes are present"
        );
    }

    /// One blob named by both a public and a permissioned record is reported
    /// once, not twice. A migrating client uploads bytes, not references.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_blob_named_from_both_realms_is_reported_once() {
        let store = fresh_store().await;
        const CID: &str = "bafkreisharedmissing";
        sqlx::query(
            "INSERT INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
             VALUES (?, ?, 'image/png', 7)",
        )
        .bind("at://did:plc:test/app.t.rec/pub")
        .bind(CID)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO space_blob_ref (space, record_uri, blob_cid, rev)
             VALUES (?, ?, ?, '3jui7kd2z2y2e')",
        )
        .bind("at://did:plc:test/space/app.bsky.group/default")
        .bind("at://did:plc:test/space/app.bsky.group/default/did:plc:test/app.t.rec/priv")
        .bind(CID)
        .execute(store.pool())
        .await
        .unwrap();

        let missing = list_missing(&store, None, 100).await.unwrap();
        assert_eq!(
            missing.iter().filter(|r| r.cid == CID).count(),
            1,
            "one CID, one upload to perform: {missing:?}"
        );
    }
}
