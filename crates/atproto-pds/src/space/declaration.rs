//! Space-type **declaration** resolution — maps a space-type NSID to the
//! `com.atproto.lexicon.schema` record that publishes it and extracts the
//! `defs.main` space declaration (spec lines 100-130, 407-413).
//!
//! A bare `space:<concreteType>` OAuth grant (one that omits `collection`)
//! defaults its write targets to the **declared** `collections` of the space
//! type (spec line 413). To honor that default the PDS must resolve the
//! declaration at request time. The resolution path mirrors AT Protocol
//! lexicon resolution:
//!
//! 1. NSID → `_lexicon.<name>.<reversed-authority>` DNS TXT → authority DID.
//! 2. Authority DID → DID document → `AtprotoPersonalDataServer` endpoint.
//! 3. `com.atproto.repo.getRecord` of `com.atproto.lexicon.schema` keyed by the
//!    NSID → parse `defs.main` as a [`SpaceSchema`].
//!
//! Resolution is **fail-closed**: any failure yields `None`, which the scope
//! gate treats as an empty collection set (a bare grant then confers no write
//! targets). Results are cached with a short TTL via
//! [`CachingSpaceDeclarationResolver`] so a hot path does not re-resolve on
//! every request.
//!
//! ## Operational caveat
//!
//! [`NetworkSpaceDeclarationResolver`] requires a configured DNS resolver and
//! PLC directory hostname (the same prerequisites as handle resolution). When
//! the PDS runs without a DNS resolver, declaration resolution is disabled and
//! bare `space:` grants confer no write targets until the operator configures
//! one. The resolver is expressed as a trait so it can be exercised in unit
//! tests with a stub (see [`StubSpaceDeclarationResolver`]).

use atproto_lexicon::validation::schema::SchemaDef;
use atproto_lexicon::validation::schema_file::SchemaFile;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A resolved space-type declaration (`defs.main` with `"type": "space"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceDeclaration {
    /// Human-readable name for the space type (consent-screen label).
    pub name: String,
    /// Recommended space-key (`skey`) type for spaces of this type.
    pub key: String,
    /// Declared record-collection NSIDs — the default `collection` set for a
    /// bare `space:` grant of this type (spec line 413).
    pub collections: Vec<String>,
}

/// Resolves a space-type NSID to its [`SpaceDeclaration`].
///
/// Implementations are fail-closed: a `None` result is treated by the scope
/// gate as "no declared collections", so a bare grant confers no write
/// targets. The trait exists so the resolver can be swapped for a stub in
/// tests where full network resolution is infeasible.
#[async_trait::async_trait]
pub trait SpaceDeclarationResolver: Send + Sync {
    /// Resolve `nsid` to its declaration, or `None` on any failure.
    async fn resolve(&self, nsid: &str) -> Option<SpaceDeclaration>;
}

/// Network-backed resolver following the AT Protocol lexicon-resolution path.
///
/// Holds the same dependencies as handle resolution (a DNS resolver, the PLC
/// directory hostname, and an HTTP client). Construct one only when a DNS
/// resolver is available; otherwise leave declaration resolution unconfigured.
pub struct NetworkSpaceDeclarationResolver {
    /// DNS resolver for the `_lexicon.` authority TXT lookup.
    dns_resolver: Arc<dyn atproto_identity::traits::DnsResolver>,
    /// PLC directory hostname for `did:plc` document resolution.
    plc_hostname: String,
    /// HTTP client for DID-document and record retrieval.
    http_client: reqwest::Client,
}

impl NetworkSpaceDeclarationResolver {
    /// Construct a network resolver from its dependencies.
    #[must_use]
    pub fn new(
        dns_resolver: Arc<dyn atproto_identity::traits::DnsResolver>,
        plc_hostname: String,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            dns_resolver,
            plc_hostname,
            http_client,
        }
    }
}

#[async_trait::async_trait]
impl SpaceDeclarationResolver for NetworkSpaceDeclarationResolver {
    async fn resolve(&self, nsid: &str) -> Option<SpaceDeclaration> {
        let dns_name = nsid_to_lexicon_dns_name(nsid)?;
        let did = lexicon_authority_did(self.dns_resolver.as_ref(), &dns_name).await?;

        let resolver = atproto_identity::resolve::InnerIdentityResolver {
            dns_resolver: self.dns_resolver.clone(),
            http_client: self.http_client.clone(),
            plc_hostname: self.plc_hostname.clone(),
        };
        let document = resolver.resolve(&did).await.ok()?;
        let pds = document
            .service
            .iter()
            .find(|s| s.r#type == "AtprotoPersonalDataServer")
            .map(|s| s.service_endpoint.clone())?;

        let url = format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            pds.trim_end_matches('/')
        );
        let resp = self
            .http_client
            .get(&url)
            .query(&[
                ("repo", did.as_str()),
                ("collection", "com.atproto.lexicon.schema"),
                ("rkey", nsid),
            ])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        // The lexicon doc lives under `value`; parse it and read `defs.main`.
        let value = body.get("value")?;
        parse_space_declaration(value)
    }
}

/// Reads space declarations through the shared [`LexiconResolver`] chain.
///
/// A space declaration *is* a lexicon document — `defs.main` with
/// `type: "space"` — so there is no reason for it to have its own way of
/// finding one. [`NetworkSpaceDeclarationResolver`] walks DNS, PLC and
/// `getRecord` itself, which duplicates the lexicon resolver's job and, more to
/// the point, sees only what is on the network: a schema bundled with the
/// binary or supplied on disk is invisible to it.
///
/// That gap had teeth. A PDS writing genesis operations to a local PLC
/// directory cannot resolve a DID registered in the production one, so an
/// application's own space type would not resolve — and `declared_collections`
/// is fail-closed, so a bare `space:` grant silently conferred no write
/// collections and space creation was refused. Configuring `PDS_LEXICON_DIR`
/// with the very document that would have answered changed nothing, because
/// this path never consulted it.
///
/// Going through the chain fixes all of that at once: bundled, then disk, then
/// network, in one order, with one cache, for both kinds of lookup.
pub struct LexiconSpaceDeclarationResolver {
    lexicons: Arc<dyn crate::repo::lexicon::LexiconResolver>,
}

impl LexiconSpaceDeclarationResolver {
    /// Wrap a lexicon resolver.
    #[must_use]
    pub fn new(lexicons: Arc<dyn crate::repo::lexicon::LexiconResolver>) -> Self {
        Self { lexicons }
    }
}

#[async_trait::async_trait]
impl SpaceDeclarationResolver for LexiconSpaceDeclarationResolver {
    async fn resolve(&self, nsid: &str) -> Option<SpaceDeclaration> {
        let document = self.lexicons.resolve(nsid).await?;
        parse_space_declaration(&document)
    }
}

/// Parse a `com.atproto.lexicon.schema` record `value` into a
/// [`SpaceDeclaration`] when its `defs.main` is a `space` declaration.
///
/// Returns `None` when the value is not a valid lexicon document or its main
/// definition is not a space declaration.
fn parse_space_declaration(value: &serde_json::Value) -> Option<SpaceDeclaration> {
    let file = SchemaFile::from_value(value.clone()).ok()?;
    match file.main()? {
        SchemaDef::Space(space) => Some(SpaceDeclaration {
            name: space.name.clone(),
            key: space.key.clone(),
            collections: space.collections.clone(),
        }),
        _ => None,
    }
}

/// Convert a lexicon NSID to its DNS authority name
/// (`_lexicon.<name>.<reversed-authority>`), per the AT Protocol lexicon
/// resolution scheme. Returns `None` for NSIDs with fewer than three segments.
fn nsid_to_lexicon_dns_name(nsid: &str) -> Option<String> {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let name_idx = parts.len() - 2;
    let mut dns_parts = vec!["_lexicon".to_string(), parts[name_idx].to_string()];
    for i in (0..name_idx).rev() {
        dns_parts.push(parts[i].to_string());
    }
    Some(dns_parts.join("."))
}

/// Look up the single authority DID published in the `_lexicon.` TXT record(s)
/// for `dns_name`. Returns `None` when no record, no `did=`/`did:` prefix, or
/// more than one distinct DID is found.
async fn lexicon_authority_did(
    dns_resolver: &dyn atproto_identity::traits::DnsResolver,
    dns_name: &str,
) -> Option<String> {
    let records = dns_resolver.resolve_txt(dns_name).await.ok()?;
    let mut dids: Vec<String> = records
        .iter()
        .filter_map(|r| {
            r.strip_prefix("did=")
                .map(|d| d.to_string())
                .or_else(|| r.starts_with("did:").then(|| r.to_string()))
        })
        .collect();
    dids.dedup();
    if dids.len() == 1 { dids.pop() } else { None }
}

/// One cache slot: the resolution result (positive or fail-closed `None`) and
/// when it was stored.
#[derive(Clone)]
struct CacheEntry {
    stored_at: Instant,
    result: Option<SpaceDeclaration>,
}

/// TTL cache wrapper over any [`SpaceDeclarationResolver`].
///
/// Caches both successful resolutions and fail-closed `None` results (negative
/// caching) for `ttl`, so a hot authorization path does not re-resolve — or
/// re-fail — on every request. The cache is unbounded; the space-type NSID
/// keyspace is small and operator-controlled in practice.
pub struct CachingSpaceDeclarationResolver {
    inner: Arc<dyn SpaceDeclarationResolver>,
    ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl CachingSpaceDeclarationResolver {
    /// Wrap `inner` with a TTL cache.
    #[must_use]
    pub fn new(inner: Arc<dyn SpaceDeclarationResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return a cached, non-expired result for `nsid`, if any.
    fn cached(&self, nsid: &str) -> Option<Option<SpaceDeclaration>> {
        let guard = self.cache.lock().ok()?;
        let entry = guard.get(nsid)?;
        if entry.stored_at.elapsed() < self.ttl {
            Some(entry.result.clone())
        } else {
            None
        }
    }

    /// Store a resolution result for `nsid`.
    fn store(&self, nsid: &str, result: Option<SpaceDeclaration>) {
        if let Ok(mut guard) = self.cache.lock() {
            guard.insert(
                nsid.to_string(),
                CacheEntry {
                    stored_at: Instant::now(),
                    result,
                },
            );
        }
    }
}

#[async_trait::async_trait]
impl SpaceDeclarationResolver for CachingSpaceDeclarationResolver {
    async fn resolve(&self, nsid: &str) -> Option<SpaceDeclaration> {
        if let Some(hit) = self.cached(nsid) {
            return hit;
        }
        let result = self.inner.resolve(nsid).await;
        self.store(nsid, result.clone());
        result
    }
}

/// In-memory stub resolver for tests. Maps NSID → [`SpaceDeclaration`]
/// directly, with no network access.
#[cfg(test)]
pub struct StubSpaceDeclarationResolver {
    map: HashMap<String, SpaceDeclaration>,
}

#[cfg(test)]
impl StubSpaceDeclarationResolver {
    /// Build a stub from an NSID → declaration map.
    pub fn new(map: HashMap<String, SpaceDeclaration>) -> Self {
        Self { map }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl SpaceDeclarationResolver for StubSpaceDeclarationResolver {
    async fn resolve(&self, nsid: &str) -> Option<SpaceDeclaration> {
        self.map.get(nsid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn nsid_to_lexicon_dns_name_reverses_authority() {
        assert_eq!(
            nsid_to_lexicon_dns_name("com.atmoboards.forum").as_deref(),
            Some("_lexicon.atmoboards.com")
        );
        assert_eq!(
            nsid_to_lexicon_dns_name("app.bsky.feed.post").as_deref(),
            Some("_lexicon.feed.bsky.app")
        );
        assert_eq!(nsid_to_lexicon_dns_name("too.short").as_deref(), None);
    }

    #[test]
    fn parse_space_declaration_reads_collections() {
        let value = serde_json::json!({
            "lexicon": 1,
            "id": "com.atmoboards.forum",
            "defs": {
                "main": {
                    "type": "space",
                    "key": "any",
                    "name": "AtmoBoards Forum",
                    "collections": ["com.atmoboards.thread", "com.atmoboards.reply"]
                }
            }
        });
        let decl = parse_space_declaration(&value).expect("space declaration");
        assert_eq!(decl.name, "AtmoBoards Forum");
        assert_eq!(decl.key, "any");
        assert_eq!(
            decl.collections,
            vec![
                "com.atmoboards.thread".to_string(),
                "com.atmoboards.reply".to_string()
            ]
        );
    }

    #[test]
    fn parse_space_declaration_rejects_non_space_main() {
        let value = serde_json::json!({
            "lexicon": 1,
            "id": "com.example.thing",
            "defs": { "main": { "type": "record", "key": "tid", "record": {"type": "object"} } }
        });
        assert!(parse_space_declaration(&value).is_none());
    }

    /// Counts inner resolutions so the cache's hit/miss behavior is observable.
    struct CountingResolver {
        calls: AtomicUsize,
        decl: SpaceDeclaration,
    }

    #[async_trait::async_trait]
    impl SpaceDeclarationResolver for CountingResolver {
        async fn resolve(&self, _nsid: &str) -> Option<SpaceDeclaration> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Some(self.decl.clone())
        }
    }

    #[tokio::test]
    async fn caching_resolver_serves_within_ttl_and_refetches_after() {
        let inner = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
            decl: SpaceDeclaration {
                name: "Forum".to_string(),
                key: "any".to_string(),
                collections: vec!["com.atmoboards.thread".to_string()],
            },
        });
        let resolver =
            CachingSpaceDeclarationResolver::new(inner.clone(), Duration::from_millis(40));

        // First call resolves; second is served from cache.
        let a = resolver.resolve("com.atmoboards.forum").await;
        let b = resolver.resolve("com.atmoboards.forum").await;
        assert_eq!(a, b);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        // After the TTL elapses the entry expires and we re-resolve.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = resolver.resolve("com.atmoboards.forum").await;
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stub_resolver_returns_declared_collections() {
        let mut map = HashMap::new();
        map.insert(
            "com.atmoboards.forum".to_string(),
            SpaceDeclaration {
                name: "Forum".to_string(),
                key: "any".to_string(),
                collections: vec![
                    "com.atmoboards.thread".to_string(),
                    "com.atmoboards.reply".to_string(),
                ],
            },
        );
        let resolver = StubSpaceDeclarationResolver::new(map);
        let decl = resolver.resolve("com.atmoboards.forum").await.unwrap();
        assert_eq!(decl.collections.len(), 2);
        assert!(resolver.resolve("com.unknown.type").await.is_none());
    }

    /// A declaration held by the lexicon resolver resolves through the chain.
    ///
    /// The regression: `NetworkSpaceDeclarationResolver` walked DNS, PLC and
    /// `getRecord` on its own, so a declaration the lexicon chain could already
    /// answer for -- a bundled one, or one an operator supplied -- was invisible
    /// to it while resolving fine for every other lookup. On a PDS whose PLC
    /// directory does not hold the authority DID, resolution fails outright --
    /// and because `declared_collections` is fail-closed, that comes out as a
    /// bare `space:` grant with no write collections and a space the holder
    /// cannot create.
    ///
    /// The document is the one `app.bulleted.space` actually ships.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_declaration_resolves_through_the_lexicon_chain() {
        struct OneDocument(serde_json::Value);

        #[async_trait::async_trait]
        impl crate::repo::lexicon::LexiconResolver for OneDocument {
            async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
                (nsid == "app.bulleted.space").then(|| self.0.clone())
            }
        }

        let document = serde_json::json!({
            "lexicon": 1,
            "id": "app.bulleted.space",
            "defs": {"main": {
                "type": "space",
                "name": "Bulleted outline",
                "key": "any",
                "description": "An outline shared with a named set of people.",
                "collections": [
                    "app.bulleted.node", "app.bulleted.note", "app.bulleted.outline",
                    "app.bulleted.mirror", "app.bulleted.comment", "app.bulleted.commentPolicy"
                ]
            }}
        });

        let resolver = LexiconSpaceDeclarationResolver::new(Arc::new(OneDocument(document)));
        let decl = resolver
            .resolve("app.bulleted.space")
            .await
            .expect("the chain holds this declaration and must resolve it");

        assert_eq!(decl.name, "Bulleted outline");
        assert_eq!(decl.key, "any");
        // These six are what a bare `space:` grant expands to; an empty list
        // here is the fail-closed path that refuses space creation.
        assert_eq!(decl.collections.len(), 6, "{:?}", decl.collections);
        assert!(
            decl.collections
                .contains(&"app.bulleted.outline".to_string())
        );

        // A type the chain does not hold still resolves to nothing.
        assert!(resolver.resolve("app.bulleted.nosuch").await.is_none());
    }
}
