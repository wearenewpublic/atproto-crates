//! S3-compatible blob storage.
//!
//! When the `s3` feature is enabled and `PDS_BLOB_STORE_URL` is
//! prefixed with `s3://<bucket>`, blob *bytes* are stored in the
//! configured S3 bucket instead of the per-actor SQLite `repo_blob`
//! table. Ref operations (`repo_blob_ref`) remain SQLite-backed —
//! they're inherently relational and cheap to keep alongside the
//! per-actor metadata.
//!
//! ## Object naming
//!
//! Each blob is stored as `<key_prefix>/<did>/<cid>` so multi-tenant
//! deployments can safely share a bucket. The key prefix defaults to
//! `atproto-pds` (overridable via the URL fragment, e.g.
//! `s3://my-bucket?prefix=blobs`).
//!
//! ## Credentials
//!
//! Standard AWS SDK resolution — env vars (`AWS_ACCESS_KEY_ID`,
//! `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`), shared profile config
//! (`~/.aws/`), or IMDS for in-cluster deployments. No PDS-side
//! credential plumbing required.
//!
//! ## Trait wiring
//!
//! [`HybridS3BlobStorage`] implements [`BlobStorage`] by delegating
//! ref operations to a wrapped backend (`Arc<dyn BlobStorage>`,
//! typically a `SqlBlobStorage`) and routing blob bytes
//! (`put`/`get`/`delete_blob`/`list_all_cids`) to S3. The hybrid
//! layout lets operators flip the bytes layer to S3 without
//! re-engineering the ref tracking — minimum surgery for the most
//! common deployment shape.

use crate::actor_store::traits::{BlobRefRow, BlobRow, BlobStorage};
use crate::errors::{PdsError, PdsResult};
use async_trait::async_trait;
use std::sync::Arc;

/// Hybrid S3 + (relational) ref storage.
///
/// Blob bytes go to the configured S3 bucket; refs stay with the
/// wrapped backend. Cloning is cheap — both fields are `Arc`-wrapped.
#[derive(Clone)]
pub struct HybridS3BlobStorage {
    /// AWS SDK client.
    client: aws_sdk_s3::Client,
    /// Bucket name (no scheme, no path).
    bucket: String,
    /// Key prefix prepended to every object (e.g. `atproto-pds`).
    prefix: String,
    /// Backend for ref operations + missing-ref discovery. Typically a
    /// `SqlBlobStorage` so per-actor SQLite still tracks
    /// `repo_blob_ref`.
    refs: Arc<dyn BlobStorage>,
}

impl HybridS3BlobStorage {
    /// Open an S3-backed blob store.
    ///
    /// `url` must start with `s3://<bucket>` and may include a
    /// `?prefix=<key>` query parameter. AWS SDK config (region,
    /// credentials) follows the standard resolution order.
    ///
    /// `refs` is the backend that handles ref tracking — ordinarily
    /// the per-actor `SqlBlobStorage`.
    pub async fn open(url: &str, refs: Arc<dyn BlobStorage>) -> PdsResult<Self> {
        let (bucket, prefix) = parse_s3_url(url)?;
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let client = aws_sdk_s3::Client::new(&aws_config);
        Ok(Self {
            client,
            bucket,
            prefix,
            refs,
        })
    }

    /// Construct directly from an existing AWS SDK client. Useful
    /// for tests + advanced configuration paths that need to override
    /// the SDK config builder.
    pub fn from_parts(
        client: aws_sdk_s3::Client,
        bucket: String,
        prefix: String,
        refs: Arc<dyn BlobStorage>,
    ) -> Self {
        Self {
            client,
            bucket,
            prefix,
            refs,
        }
    }

    fn key(&self, did: &str, cid: &str) -> String {
        if self.prefix.is_empty() {
            format!("{did}/{cid}")
        } else {
            format!("{}/{did}/{cid}", self.prefix)
        }
    }
}

#[async_trait]
impl BlobStorage for HybridS3BlobStorage {
    async fn put(&self, did: &str, row: &BlobRow) -> PdsResult<()> {
        let key = self.key(did, &row.cid);
        // PutObject is idempotent at the storage layer — same key with
        // identical bytes yields the same content. The MIME type goes
        // on the object metadata so `get` round-trips correctly.
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(row.data.clone().into())
            .content_type(&row.mime_type)
            .content_length(row.data.len() as i64)
            .send()
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("s3 put_object {key}: {e}"),
            })?;
        Ok(())
    }

    async fn get(&self, did: &str, cid: &str) -> PdsResult<Option<(Vec<u8>, String)>> {
        let key = self.key(did, cid);
        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await;
        match result {
            Ok(out) => {
                let mime = out
                    .content_type()
                    .map(str::to_string)
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                let bytes = out
                    .body
                    .collect()
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("s3 get_object body {key}: {e}"),
                    })?
                    .into_bytes()
                    .to_vec();
                Ok(Some((bytes, mime)))
            }
            Err(e) => {
                // The SDK returns a structured error; the simplest
                // not-found check is the service-error code.
                let svc = e.into_service_error();
                if svc.is_no_such_key() {
                    Ok(None)
                } else {
                    Err(PdsError::Storage {
                        reason: format!("s3 get_object {key}: {svc}"),
                    })
                }
            }
        }
    }

    async fn add_ref(&self, did: &str, row: &BlobRefRow) -> PdsResult<()> {
        self.refs.add_ref(did, row).await
    }

    async fn drop_refs_for_record(&self, did: &str, record_uri: &str) -> PdsResult<Vec<String>> {
        self.refs.drop_refs_for_record(did, record_uri).await
    }

    async fn delete_blob(&self, did: &str, cid: &str) -> PdsResult<bool> {
        let key = self.key(did, cid);
        let result = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(e) => Err(PdsError::Storage {
                reason: format!("s3 delete_object {key}: {e}"),
            }),
        }
    }

    async fn list_all_cids(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<String>> {
        let limit = limit.clamp(1, 1000);
        let prefix = if self.prefix.is_empty() {
            format!("{did}/")
        } else {
            format!("{}/{did}/", self.prefix)
        };
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&prefix)
            .max_keys(limit as i32);
        if let Some(c) = cursor {
            // S3 ListObjectsV2 uses `start_after` for cursored paging
            // — we expose the same semantics as the SQLite backend
            // ("after this CID, exclusive").
            req = req.start_after(format!("{prefix}{c}"));
        }
        let resp = req.send().await.map_err(|e| PdsError::Storage {
            reason: format!("s3 list_objects_v2: {e}"),
        })?;
        let mut out = Vec::new();
        for obj in resp.contents() {
            if let Some(key) = obj.key()
                && let Some(suffix) = key.strip_prefix(&prefix)
            {
                out.push(suffix.to_string());
            }
        }
        Ok(out)
    }

    async fn list_missing_refs(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<BlobRefRow>> {
        // Missing-ref discovery requires joining `repo_blob_ref`
        // against the bytes inventory. The wrapped relational backend
        // already implements this; we delegate.
        self.refs.list_missing_refs(did, cursor, limit).await
    }
}

/// Parse a `s3://<bucket>[?prefix=<key>]` URL into bucket + prefix.
fn parse_s3_url(url: &str) -> PdsResult<(String, String)> {
    let rest = url.strip_prefix("s3://").ok_or_else(|| PdsError::Config {
        issues: vec![format!("blob store URL must start with s3://, got: {url}")],
    })?;
    let (bucket, query) = match rest.split_once('?') {
        Some((b, q)) => (b, q),
        None => (rest, ""),
    };
    if bucket.is_empty() {
        return Err(PdsError::Config {
            issues: vec![format!("blob store URL missing bucket name: {url}")],
        });
    }
    let mut prefix = "atproto-pds".to_string();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = kv.split_once('=')
            && k == "prefix"
        {
            prefix = v.trim_matches('/').to_string();
        }
    }
    Ok((bucket.trim_end_matches('/').to_string(), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_bucket() {
        let (bucket, prefix) = parse_s3_url("s3://my-bucket").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(prefix, "atproto-pds");
    }

    #[test]
    fn parse_with_prefix() {
        let (bucket, prefix) = parse_s3_url("s3://my-bucket?prefix=blobs").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(prefix, "blobs");
    }

    #[test]
    fn parse_with_nested_prefix() {
        let (bucket, prefix) = parse_s3_url("s3://b?prefix=tenant1/blobs").unwrap();
        assert_eq!(bucket, "b");
        assert_eq!(prefix, "tenant1/blobs");
    }

    #[test]
    fn parse_rejects_non_s3_scheme() {
        let err = parse_s3_url("https://my-bucket.s3.amazonaws.com").unwrap_err();
        assert!(matches!(err, PdsError::Config { .. }));
    }

    #[test]
    fn parse_rejects_missing_bucket() {
        let err = parse_s3_url("s3://").unwrap_err();
        assert!(matches!(err, PdsError::Config { .. }));
    }
}
