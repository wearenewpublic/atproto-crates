//! Helpers for resolving AT Protocol records referenced by URI.
//!
//! Two shapes, and the difference between them is the whole point.
//! [`RecordResolver::resolve`] fetches whatever is at an address now.
//! [`RecordResolver::resolve_pinned`] fetches what a
//! `com.atproto.repo.strongRef` names -- an address *and* a CID -- and checks
//! that it got it.
//!
//! A strongRef pins a CID, and a CID names one byte sequence. So a record
//! fetched at `(uri, cid)` is immutable: a cache row keyed on that pair can
//! never go stale, and a consumer needs no TTL, no invalidation pass and no
//! firehose subscription to the target collection. A resolver that ignores the
//! CID converts "I fetched what this reference names" into "I fetched what was
//! at this address", and every caching decision built on the first is unsound
//! under the second.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use atproto_identity::traits::IdentityResolver;
use atproto_record::aturi::ATURI;

use crate::{
    client::Auth,
    com::atproto::repo::{GetRecordResponse, get_record},
};

/// Trait for resolving AT Protocol records by `at://` URI.
///
/// Implementations perform the network lookup and deserialize the response into
/// the requested type.
#[async_trait]
pub trait RecordResolver: Send + Sync {
    /// Resolve an AT URI to a typed record.
    ///
    /// Whatever is at that address now. For a `strongRef`, use
    /// [`resolve_pinned`](Self::resolve_pinned).
    async fn resolve<T>(&self, aturi: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned + Send;

    /// Resolve a `com.atproto.repo.strongRef`: the record at `aturi` **as of**
    /// `cid`, verified.
    ///
    /// The CID is both requested and checked. Requesting it asks the server
    /// for that version; checking it is what makes the answer trustworthy when
    /// the server ignores the parameter, which some do.
    ///
    /// Checked by recomputing the CID over the DAG-CBOR encoding of the value
    /// that came back, not by comparing the `cid` field of the response
    /// envelope. That field is the server's claim about the bytes it sent, and
    /// a claim checked against itself is not a check.
    ///
    /// A mismatch is an error rather than a fallback. A strongRef whose target
    /// has moved is a broken reference, and silently returning the current
    /// version turns an immutable claim into a mutable one -- which is exactly
    /// the confusion the pin exists to prevent.
    async fn resolve_pinned<T>(&self, aturi: &str, cid: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned + Send;
}

/// Resolver that fetches records using public XRPC endpoints.
///
/// Uses an identity resolver to dynamically determine the PDS endpoint for each record.
#[derive(Clone)]
pub struct HttpRecordResolver {
    http_client: reqwest::Client,
    identity_resolver: Arc<dyn IdentityResolver>,
}

impl HttpRecordResolver {
    /// Create a new resolver using the provided HTTP client and identity resolver.
    ///
    /// The identity resolver is used to dynamically determine the PDS endpoint for each record
    /// based on the authority (DID or handle) in the AT URI.
    pub fn new(http_client: reqwest::Client, identity_resolver: Arc<dyn IdentityResolver>) -> Self {
        Self {
            http_client,
            identity_resolver,
        }
    }
}

impl HttpRecordResolver {
    /// Fetch a record's JSON value, optionally at a specific version.
    async fn fetch(&self, aturi: &str, cid: Option<&str>) -> Result<serde_json::Value> {
        let parsed = ATURI::from_str(aturi).map_err(|error| anyhow!(error))?;

        // Resolve the authority (DID or handle) to get the DID document
        let document = self
            .identity_resolver
            .resolve(&parsed.authority)
            .await
            .map_err(|error| {
                anyhow!(
                    "Failed to resolve identity for {}: {}",
                    parsed.authority,
                    error
                )
            })?;

        // Extract PDS endpoint from the DID document
        let pds_endpoints = document.pds_endpoints();
        let base_url = pds_endpoints
            .first()
            .ok_or_else(|| anyhow!("No PDS endpoint found for {}", parsed.authority))?;

        let auth = Auth::None;

        let response = get_record(
            &self.http_client,
            &auth,
            base_url,
            &parsed.authority,
            &parsed.collection,
            &parsed.record_key,
            cid,
        )
        .await?;

        match response {
            GetRecordResponse::Record { value, .. } => Ok(value),
            GetRecordResponse::Error(error) => {
                let message = error.error_message();
                if message.is_empty() {
                    bail!("Record resolution failed without additional error details");
                }

                bail!(message);
            }
        }
    }
}

/// The CID of a record value, recomputed from the value itself.
///
/// The JSON goes through `ipld_from_json` rather than straight into the
/// DAG-CBOR encoder, because AT Protocol's JSON spells a `cid-link` as
/// `{"$link": …}` and a byte string as `{"$bytes": …}`. Encoding those as
/// ordinary maps would produce different bytes and therefore a different CID
/// from the one the repository computed -- so every pinned resolution would
/// fail, and the failure would look like a lying server.
pub fn record_cid(value: &serde_json::Value) -> Result<String> {
    let ipld = atproto_dasl::ipld_from_json(value)
        .map_err(|error| anyhow!("record is not AT Protocol JSON: {error}"))?;
    let bytes = atproto_dasl::to_vec(&ipld)
        .map_err(|error| anyhow!("record could not be encoded as DAG-CBOR: {error}"))?;
    Ok(atproto_dasl::cid::compute_cid(&bytes).to_string())
}

#[async_trait]
impl RecordResolver for HttpRecordResolver {
    async fn resolve<T>(&self, aturi: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let value = self.fetch(aturi, None).await?;
        serde_json::from_value(value).map_err(|error| anyhow!(error))
    }

    async fn resolve_pinned<T>(&self, aturi: &str, cid: &str) -> Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let value = self.fetch(aturi, Some(cid)).await?;

        let computed = record_cid(&value)?;
        if computed != cid {
            bail!(
                "error-atproto-client-http-6 Pinned record does not match its CID: \
                 {aturi} pins {cid}, the server answered with {computed}"
            );
        }

        serde_json::from_value(value).map_err(|error| anyhow!(error))
    }
}
