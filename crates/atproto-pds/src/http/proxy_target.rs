//! Resolving an `Atproto-Proxy` header to a service endpoint.
//!
//! A client names the service it wants a request forwarded to with
//! `Atproto-Proxy: <did>#<service-id>`. Honouring that is what lets a PDS reach
//! a labeler, a feed generator, a chat service or a third-party AppView, rather
//! than only the one endpoint its operator pinned.
//!
//! Resolution is: fetch the DID's document, find the service whose fragment
//! matches `service-id`, and take its endpoint.
//!
//! # Security
//!
//! The DID comes from the request, so the endpoint it names is attacker-chosen
//! and forwarding to it is an SSRF sink. Endpoints are read through
//! [`Document::service_endpoint_validated`], which applies the workspace's URL
//! policy — HTTPS only, no address literals in any resolver-accepted form, no
//! embedded userinfo, no ports other than 443, no reserved suffixes. The guard
//! is syntactic: it does not resolve DNS, so it does not defend against
//! rebinding or a public name pointing into a private range.

#[cfg(test)]
use std::collections::HashMap;
use std::time::Duration;

use atproto_identity::model::Document;

/// How long a resolved service endpoint stays usable before it is re-fetched.
///
/// A DID document changes rarely, and a proxied request is on the hot path —
/// resolving one per call would put a network round trip in front of every
/// timeline fetch.
pub const DEFAULT_PROXY_CACHE_TTL: Duration = Duration::from_secs(300);

/// Where a proxied request should be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    /// DID of the receiving service, used as the service-auth `aud`.
    pub did: String,
    /// Base URL to forward to.
    pub url: String,
}

/// Resolves a DID to its document.
///
/// A trait so the proxy can be tested without a network, and so an operator
/// could substitute a different resolution strategy.
#[async_trait::async_trait]
pub trait DidDocumentResolver: Send + Sync {
    /// Fetch the DID document for `did`.
    async fn resolve(&self, did: &str) -> Option<Document>;
}

/// How many resolutions this cache holds.
///
/// Large enough that a real working set stays resident, small enough that a
/// caller producing distinct keys cannot turn the cache into a memory leak.
const CACHE_CAPACITY: usize = 4_096;

/// A [`DidDocumentResolver`] with a TTL cache in front of it.
///
/// Negative results are cached too: a DID that does not resolve is usually
/// still not resolving a second later, and re-fetching on every request would
/// let an unresolvable DID in a header drive one outbound request per inbound
/// one.
pub struct CachingProxyResolver {
    inner: std::sync::Arc<dyn DidDocumentResolver>,
    cache: crate::ttl_cache::TtlCache<Option<ProxyTarget>>,
}

impl CachingProxyResolver {
    /// Wrap `inner` with a TTL cache.
    #[must_use]
    pub fn new(inner: std::sync::Arc<dyn DidDocumentResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            cache: crate::ttl_cache::TtlCache::new(ttl, CACHE_CAPACITY),
        }
    }

    /// Resolve `did#service_id` to a forwarding target.
    ///
    /// Returns `None` when the DID does not resolve, carries no service with
    /// that fragment, or names an endpoint the URL policy rejects.
    pub async fn resolve(&self, did: &str, service_id: &str) -> Option<ProxyTarget> {
        let key = format!("{did}#{service_id}");
        if let Some(cached) = self.cached(&key) {
            return cached;
        }

        let target = self.inner.resolve(did).await.and_then(|document| {
            document
                .service_endpoint_validated(service_id)
                .map(|endpoint| ProxyTarget {
                    did: did.to_string(),
                    url: endpoint.to_string(),
                })
        });

        if target.is_none() {
            tracing::warn!(
                did,
                service_id,
                "Atproto-Proxy target did not resolve to a usable service endpoint"
            );
        }
        self.store(&key, target.clone());
        target
    }

    fn cached(&self, key: &str) -> Option<Option<ProxyTarget>> {
        self.cache.get(key)
    }

    fn store(&self, key: &str, target: Option<ProxyTarget>) {
        self.cache.put(key, target);
    }
}

/// Resolves DIDs over the network, by method.
pub struct NetworkDidDocumentResolver {
    http: reqwest::Client,
    plc_hostname: String,
}

impl NetworkDidDocumentResolver {
    /// Construct with the PLC directory to consult for `did:plc`.
    #[must_use]
    pub fn new(http: reqwest::Client, plc_hostname: impl Into<String>) -> Self {
        Self {
            http,
            plc_hostname: plc_hostname.into(),
        }
    }
}

#[async_trait::async_trait]
impl DidDocumentResolver for NetworkDidDocumentResolver {
    async fn resolve(&self, did: &str) -> Option<Document> {
        let result = if did.starts_with("did:plc:") {
            atproto_identity::plc::query(&self.http, &self.plc_hostname, did)
                .await
                .map_err(|err| err.to_string())
        } else if did.starts_with("did:web:") {
            atproto_identity::web::query(&self.http, did)
                .await
                .map_err(|err| err.to_string())
        } else if did.starts_with("did:webvh:") {
            atproto_identity::webvh::query(&self.http, did)
                .await
                .map_err(|err| err.to_string())
        } else {
            Err(format!("unsupported DID method: {did}"))
        };

        match result {
            Ok(document) => Some(document),
            Err(error) => {
                tracing::warn!(did, %error, "could not resolve proxy target DID");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::model::DocumentBuilder;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A resolver that answers from a fixed table and counts its calls.
    struct StubResolver {
        documents: HashMap<String, Document>,
        calls: AtomicUsize,
    }

    impl StubResolver {
        fn new(documents: Vec<(&str, Document)>) -> Self {
            Self {
                documents: documents
                    .into_iter()
                    .map(|(did, doc)| (did.to_string(), doc))
                    .collect(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl DidDocumentResolver for StubResolver {
        async fn resolve(&self, did: &str) -> Option<Document> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.documents.get(did).cloned()
        }
    }

    fn document_with(did: &str, fragment: &str, endpoint: &str) -> Document {
        DocumentBuilder::new()
            .id(did.to_string())
            .add_service(atproto_identity::model::Service {
                id: format!("#{fragment}"),
                r#type: "AtprotoLabeler".to_string(),
                service_endpoint: endpoint.to_string(),
                extra: Default::default(),
            })
            .build()
            .expect("test document should build")
    }

    #[tokio::test]
    async fn resolves_a_service_by_fragment() {
        let stub = Arc::new(StubResolver::new(vec![(
            "did:web:labeler.example",
            document_with(
                "did:web:labeler.example",
                "atproto_labeler",
                "https://labeler.example",
            ),
        )]));
        let resolver = CachingProxyResolver::new(stub, DEFAULT_PROXY_CACHE_TTL);

        let target = resolver
            .resolve("did:web:labeler.example", "atproto_labeler")
            .await
            .expect("the service should resolve");
        assert_eq!(target.url, "https://labeler.example");
        assert_eq!(target.did, "did:web:labeler.example");
    }

    #[tokio::test]
    async fn a_missing_fragment_does_not_resolve() {
        let stub = Arc::new(StubResolver::new(vec![(
            "did:web:labeler.example",
            document_with(
                "did:web:labeler.example",
                "atproto_labeler",
                "https://labeler.example",
            ),
        )]));
        let resolver = CachingProxyResolver::new(stub, DEFAULT_PROXY_CACHE_TTL);
        assert!(
            resolver
                .resolve("did:web:labeler.example", "bsky_notif")
                .await
                .is_none()
        );
    }

    /// The endpoint comes from an attacker-supplied DID, so a document naming
    /// an internal address must not be forwarded to.
    #[tokio::test]
    async fn an_endpoint_failing_the_url_policy_does_not_resolve() {
        for hostile in [
            "http://169.254.169.254",
            "https://169.254.169.254",
            "https://2852039166",
            "https://user:pw@evil.example",
            "https://metadata.google.internal",
        ] {
            let stub = Arc::new(StubResolver::new(vec![(
                "did:web:evil.example",
                document_with("did:web:evil.example", "atproto_labeler", hostile),
            )]));
            let resolver = CachingProxyResolver::new(stub, DEFAULT_PROXY_CACHE_TTL);
            assert!(
                resolver
                    .resolve("did:web:evil.example", "atproto_labeler")
                    .await
                    .is_none(),
                "{hostile} should be refused"
            );
        }
    }

    #[tokio::test]
    async fn a_resolved_target_is_cached() {
        let stub = Arc::new(StubResolver::new(vec![(
            "did:web:labeler.example",
            document_with(
                "did:web:labeler.example",
                "atproto_labeler",
                "https://labeler.example",
            ),
        )]));
        let resolver = CachingProxyResolver::new(stub.clone(), DEFAULT_PROXY_CACHE_TTL);

        for _ in 0..5 {
            assert!(
                resolver
                    .resolve("did:web:labeler.example", "atproto_labeler")
                    .await
                    .is_some()
            );
        }
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            1,
            "five proxied requests should cost one resolution"
        );
    }

    /// A DID that does not resolve must not drive one outbound request per
    /// inbound one.
    #[tokio::test]
    async fn a_failed_resolution_is_cached_too() {
        let stub = Arc::new(StubResolver::new(vec![]));
        let resolver = CachingProxyResolver::new(stub.clone(), DEFAULT_PROXY_CACHE_TTL);

        for _ in 0..5 {
            assert!(
                resolver
                    .resolve("did:web:nope.example", "svc")
                    .await
                    .is_none()
            );
        }
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_entry_is_re_resolved() {
        let stub = Arc::new(StubResolver::new(vec![(
            "did:web:labeler.example",
            document_with(
                "did:web:labeler.example",
                "atproto_labeler",
                "https://labeler.example",
            ),
        )]));
        let resolver = CachingProxyResolver::new(stub.clone(), Duration::from_millis(0));

        resolver
            .resolve("did:web:labeler.example", "atproto_labeler")
            .await;
        resolver
            .resolve("did:web:labeler.example", "atproto_labeler")
            .await;
        assert_eq!(stub.calls.load(Ordering::SeqCst), 2);
    }
}
