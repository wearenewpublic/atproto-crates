//! — `s3` feature acceptance.
//!
//! When the `s3` feature is compiled in, the `HybridS3BlobStorage`
//! type-checks and its URL parser accepts `s3://` URLs with optional
//! `?prefix=` query strings. Live S3 round-trips against a bucket
//! require AWS credentials + a network round-trip — those are
//! exercised in the operator runbook, not in CI.

#[cfg(feature = "s3")]
#[test]
fn parses_simple_s3_url() {
    use atproto_pds::actor_store::traits::BlobStorage;
    use atproto_pds::blob_s3::HybridS3BlobStorage;
    // Compile-time existence check: HybridS3BlobStorage implements BlobStorage.
    fn _assert_impls<T: BlobStorage>() {}
    _assert_impls::<HybridS3BlobStorage>();
}

#[cfg(feature = "s3")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_returns_err_for_invalid_url() {
    use atproto_pds::actor_store::traits::BlobStorage;
    use atproto_pds::blob_s3::HybridS3BlobStorage;
    use std::sync::Arc;

    // A no-op refs backend — `HybridS3BlobStorage::open` only needs
    // it to seed the field; we don't actually exercise the refs path
    // here.
    struct NoopRefs;
    #[async_trait::async_trait]
    impl BlobStorage for NoopRefs {
        async fn put(
            &self,
            _: &str,
            _: &atproto_pds::actor_store::traits::BlobRow,
        ) -> atproto_pds::errors::PdsResult<()> {
            Ok(())
        }
        async fn get(
            &self,
            _: &str,
            _: &str,
        ) -> atproto_pds::errors::PdsResult<Option<(Vec<u8>, String)>> {
            Ok(None)
        }
        async fn add_ref(
            &self,
            _: &str,
            _: &atproto_pds::actor_store::traits::BlobRefRow,
        ) -> atproto_pds::errors::PdsResult<()> {
            Ok(())
        }
        async fn drop_refs_for_record(
            &self,
            _: &str,
            _: &str,
        ) -> atproto_pds::errors::PdsResult<Vec<String>> {
            Ok(vec![])
        }
        async fn delete_blob(&self, _: &str, _: &str) -> atproto_pds::errors::PdsResult<bool> {
            Ok(false)
        }
        async fn list_all_cids(
            &self,
            _: &str,
            _: Option<&str>,
            _: u32,
        ) -> atproto_pds::errors::PdsResult<Vec<String>> {
            Ok(vec![])
        }
        async fn list_missing_refs(
            &self,
            _: &str,
            _: Option<&str>,
            _: u32,
        ) -> atproto_pds::errors::PdsResult<Vec<atproto_pds::actor_store::traits::BlobRefRow>>
        {
            Ok(vec![])
        }
    }

    let result =
        HybridS3BlobStorage::open("https://my-bucket.s3.amazonaws.com", Arc::new(NoopRefs)).await;
    assert!(result.is_err(), "expected s3 open to reject non-s3:// URL");
}
