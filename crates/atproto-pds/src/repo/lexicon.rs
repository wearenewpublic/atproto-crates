//! Lexicon resolution for record validation.
//!
//! `com.atproto.repo.createRecord` and its siblings take a `validate` flag the
//! lexicon describes as: "Can be set to 'false' to skip Lexicon schema
//! validation of record data, 'true' to require it, or leave unset to validate
//! only for known Lexicons."
//!
//! "Known" is the operative word, and this module is what decides it. A schema
//! is known when it can be resolved over the network by the AT Protocol
//! lexicon-resolution path:
//!
//! 1. NSID → `_lexicon.<name>.<reversed-authority>` DNS TXT → authority DID.
//! 2. Authority DID → DID document → `AtprotoPersonalDataServer` endpoint.
//! 3. `com.atproto.repo.getRecord` of `com.atproto.lexicon.schema` keyed by the
//!    NSID.
//!
//! That is the same path `space::declaration` already walks for space types;
//! this generalises it to return the whole schema document rather than one
//! declaration, and `space::declaration` is built on top of it.
//!
//! # Why the transitive closure
//!
//! A schema is rarely self-contained. `app.bsky.feed.post` references
//! `app.bsky.richtext.facet`, `app.bsky.embed.images` and several more, and an
//! unresolved reference is a *validation error*
//! ([`DataValidationError::UnresolvedReference`]), not a skipped check. So
//! resolving one schema and validating against it alone would reject records
//! that are perfectly valid. [`resolve_catalog`] follows references until the
//! set closes or a budget is spent.
//!
//! References are collected from the raw lexicon JSON — every `"ref"` string
//! and every entry of every `"refs"` array — rather than by walking typed
//! schema nodes. The schema grammar grows; `"ref"` and `"refs"` are how a
//! reference is spelled regardless of which node carries it, so reading the
//! JSON stays correct as new node types appear.

use atproto_lexicon::validation::schema_file::SchemaFile;
use atproto_lexicon::validation::validate::BaseCatalog;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many schema documents one validation may pull in.
///
/// A record cites a schema, which cites others; without a ceiling a hostile or
/// merely sprawling lexicon could make one write fan out into an unbounded
/// number of network fetches. Twenty-four covers the `app.bsky` record types,
/// which are the deepest in common use.
const MAX_SCHEMAS: usize = 24;

/// Resolves a lexicon NSID to its schema document.
#[async_trait::async_trait]
pub trait LexiconResolver: Send + Sync {
    /// The raw `com.atproto.lexicon.schema` record value, or `None` when the
    /// NSID cannot be resolved.
    ///
    /// `None` means "not known", never "invalid": a caller distinguishes a
    /// schema that does not resolve from a record that fails validation, and
    /// they lead to different answers.
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value>;
}

/// Network-backed resolver following the AT Protocol lexicon-resolution path.
pub struct NetworkLexiconResolver {
    dns_resolver: Arc<dyn atproto_identity::traits::DnsResolver>,
    http_client: reqwest::Client,
    plc_hostname: String,
}

impl NetworkLexiconResolver {
    /// Construct a resolver. Requires the same dependencies as handle
    /// resolution; without a DNS resolver, lexicon resolution is unavailable
    /// and the caller should leave it unconfigured rather than pass a stub.
    #[must_use]
    pub fn new(
        dns_resolver: Arc<dyn atproto_identity::traits::DnsResolver>,
        http_client: reqwest::Client,
        plc_hostname: String,
    ) -> Self {
        Self {
            dns_resolver,
            http_client,
            plc_hostname,
        }
    }
}

#[async_trait::async_trait]
impl LexiconResolver for NetworkLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
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
        body.get("value").cloned()
    }
}

/// A resolver that remembers answers, including the negative ones.
///
/// Caching a miss matters as much as caching a hit: an unresolvable NSID costs
/// a DNS lookup and a DID resolution to discover, and a repo writing records in
/// an unpublished collection would pay it on every single write.
pub struct CachingLexiconResolver {
    inner: Arc<dyn LexiconResolver>,
    ttl: Duration,
    entries: Mutex<HashMap<String, (Instant, Option<serde_json::Value>)>>,
}

impl CachingLexiconResolver {
    /// Wrap a resolver with a time-to-live.
    #[must_use]
    pub fn new(inner: Arc<dyn LexiconResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, nsid: &str) -> Option<Option<serde_json::Value>> {
        let entries = self.entries.lock().ok()?;
        let (at, value) = entries.get(nsid)?;
        if at.elapsed() > self.ttl {
            return None;
        }
        Some(value.clone())
    }
}

#[async_trait::async_trait]
impl LexiconResolver for CachingLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
        if let Some(hit) = self.cached(nsid) {
            return hit;
        }
        let result = self.inner.resolve(nsid).await;
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(nsid.to_string(), (Instant::now(), result.clone()));
        }
        result
    }
}

/// Every NSID referenced anywhere in a lexicon document.
///
/// Reads the raw JSON for `"ref"` strings and `"refs"` arrays. A reference may
/// be `com.example.thing#defName`, `com.example.thing`, or a local `#defName`;
/// only the first two name another document, so a leading `#` is skipped.
fn referenced_nsids(value: &serde_json::Value, out: &mut HashSet<String>) {
    fn push(raw: &str, out: &mut HashSet<String>) {
        let nsid = raw.split('#').next().unwrap_or("");
        // Local reference — same document, nothing to fetch.
        if nsid.is_empty() {
            return;
        }
        out.insert(nsid.to_string());
    }

    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child) {
                    ("ref", serde_json::Value::String(s)) => push(s, out),
                    ("refs", serde_json::Value::Array(items)) => {
                        for item in items {
                            if let serde_json::Value::String(s) = item {
                                push(s, out);
                            }
                        }
                    }
                    _ => referenced_nsids(child, out),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                referenced_nsids(item, out);
            }
        }
        _ => {}
    }
}

/// The outcome of trying to build a validation catalog for one collection.
pub enum CatalogOutcome {
    /// The schema and everything it references resolved.
    Ready(Box<BaseCatalog>),
    /// The collection's own schema could not be resolved — it is not a known
    /// lexicon.
    Unresolvable,
    /// The schema resolved but something it references did not, so validating
    /// against it would fail on the missing reference rather than on the
    /// record. Reported separately because it is a different situation from
    /// "nobody publishes this lexicon": the schema exists and the gap is
    /// upstream of us.
    IncompleteClosure {
        /// The reference that could not be resolved.
        missing: String,
    },
}

/// Resolve `nsid` and everything it references into a catalog.
///
/// The traversal is breadth-first and bounded by [`MAX_SCHEMAS`]. Exceeding the
/// bound is reported as an incomplete closure rather than validating against a
/// partial catalog, because a partial catalog produces
/// `UnresolvedReference` errors that look like the record is malformed when it
/// is not.
pub async fn resolve_catalog(resolver: &dyn LexiconResolver, nsid: &str) -> CatalogOutcome {
    let Some(root) = resolver.resolve(nsid).await else {
        return CatalogOutcome::Unresolvable;
    };

    let mut catalog = BaseCatalog::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, serde_json::Value)> = VecDeque::new();
    queue.push_back((nsid.to_string(), root));
    seen.insert(nsid.to_string());

    while let Some((current, value)) = queue.pop_front() {
        let Ok(file) = SchemaFile::from_value(value.clone()) else {
            // The document resolved but is not a lexicon. Treat it as
            // unresolvable rather than as a validation failure: whatever is
            // published there, it is not a schema we can hold a record to.
            return if current == nsid {
                CatalogOutcome::Unresolvable
            } else {
                CatalogOutcome::IncompleteClosure { missing: current }
            };
        };
        catalog.add_schema(file);

        let mut refs = HashSet::new();
        referenced_nsids(&value, &mut refs);
        for referenced in refs {
            if referenced == current || seen.contains(&referenced) {
                continue;
            }
            if seen.len() >= MAX_SCHEMAS {
                return CatalogOutcome::IncompleteClosure {
                    missing: format!("{referenced} (schema budget of {MAX_SCHEMAS} exhausted)"),
                };
            }
            let Some(doc) = resolver.resolve(&referenced).await else {
                return CatalogOutcome::IncompleteClosure {
                    missing: referenced,
                };
            };
            seen.insert(referenced.clone());
            queue.push_back((referenced, doc));
        }
    }

    CatalogOutcome::Ready(Box::new(catalog))
}

/// Map an NSID to the DNS name its authority publishes.
///
/// `com.atmoboards.forum` → `_lexicon.atmoboards.com`: the last segment is the
/// name, the rest is the authority, reversed.
fn nsid_to_lexicon_dns_name(nsid: &str) -> Option<String> {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let name_idx = parts.len() - 2;
    let mut dns_parts = vec!["_lexicon".to_string(), parts[name_idx].to_string()];
    for part in parts[..name_idx].iter().rev() {
        dns_parts.push((*part).to_string());
    }
    Some(dns_parts.join("."))
}

/// Read the authority DID from a `_lexicon.` TXT record set.
///
/// More than one answer is ambiguous rather than a matter of preference, so it
/// resolves to nothing: picking one would make which authority governs a
/// lexicon depend on DNS ordering.
async fn lexicon_authority_did(
    dns_resolver: &dyn atproto_identity::traits::DnsResolver,
    dns_name: &str,
) -> Option<String> {
    let records = dns_resolver.resolve_txt(dns_name).await.ok()?;
    let mut dids: Vec<String> = records
        .iter()
        .filter_map(|r| r.strip_prefix("did=").map(str::trim).map(str::to_string))
        .collect();
    dids.dedup();
    if dids.len() == 1 { dids.pop() } else { None }
}

// ---------------------------------------------------------------------------
//  The bundled corpus
// ---------------------------------------------------------------------------

include!(concat!(env!("OUT_DIR"), "/bundled_lexicons.rs"));

/// Serves the lexicons vendored into this binary.
///
/// `app.bsky.*`, `com.atproto.*` and `tools.ozone.*` are bundled because they
/// are the schemas a PDS is asked to validate against constantly and cannot
/// afford to be unable to. Resolving them over the network is possible in
/// principle -- Bluesky publishes `_lexicon.feed.bsky.app` and the rest -- but
/// it makes every first write of a collection wait on DNS and two HTTP round
/// trips, and it makes validation fail whenever the network or the authority's
/// PDS is unavailable. A schema that ships with the binary is knowable
/// offline, which is what "known lexicon" ought to mean for the vocabulary the
/// protocol itself defines.
///
/// The corpus is generated at build time from `lexicons/`, vendored from
/// bluesky-social/atproto (dual MIT / Apache-2.0, the same terms as this
/// workspace).
pub struct BundledLexiconResolver {
    schemas: HashMap<&'static str, &'static str>,
}

impl BundledLexiconResolver {
    /// Build the index over the embedded corpus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schemas: BUNDLED_LEXICONS.iter().copied().collect(),
        }
    }

    /// How many lexicons are bundled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether the corpus is empty, which would mean the build embedded
    /// nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }
}

impl Default for BundledLexiconResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LexiconResolver for BundledLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
        let raw = self.schemas.get(nsid)?;
        serde_json::from_str(raw).ok()
    }
}

/// Tries each resolver in order and takes the first answer.
///
/// Used to put the bundled corpus in front of the network: a bundled schema is
/// authoritative for the vocabulary this server ships, and anything else --
/// an application's own lexicons -- falls through to resolution. The order
/// matters and is not a preference for speed: a bundled schema is the one this
/// build was tested against, so letting the network override it would make
/// validation depend on what a third party published today.
pub struct ChainedLexiconResolver {
    resolvers: Vec<Arc<dyn LexiconResolver>>,
}

impl ChainedLexiconResolver {
    /// Chain resolvers, first match wins.
    #[must_use]
    pub fn new(resolvers: Vec<Arc<dyn LexiconResolver>>) -> Self {
        Self { resolvers }
    }
}

#[async_trait::async_trait]
impl LexiconResolver for ChainedLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
        for resolver in &self.resolvers {
            if let Some(found) = resolver.resolve(nsid).await {
                return Some(found);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsid_to_lexicon_dns_name_reverses_the_authority() {
        assert_eq!(
            nsid_to_lexicon_dns_name("com.atmoboards.forum").as_deref(),
            Some("_lexicon.atmoboards.com")
        );
        assert_eq!(
            nsid_to_lexicon_dns_name("app.bsky.feed.post").as_deref(),
            Some("_lexicon.feed.bsky.app")
        );
        assert_eq!(nsid_to_lexicon_dns_name("tooshort").as_deref(), None);
    }

    #[test]
    fn references_are_collected_from_ref_and_refs() {
        let doc = serde_json::json!({
            "lexicon": 1,
            "id": "app.example.post",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "facets": {
                                "type": "array",
                                "items": {"type": "ref", "ref": "app.example.facet#main"}
                            },
                            "embed": {
                                "type": "union",
                                "refs": ["app.example.images", "app.example.video#main"]
                            },
                            "self": {"type": "ref", "ref": "#other"}
                        }
                    }
                }
            }
        });
        let mut refs = HashSet::new();
        referenced_nsids(&doc, &mut refs);
        assert!(refs.contains("app.example.facet"));
        assert!(refs.contains("app.example.images"));
        assert!(refs.contains("app.example.video"));
        // A local `#other` names this document, so there is nothing to fetch.
        assert_eq!(refs.len(), 3, "unexpected refs: {refs:?}");
    }

    /// A resolver that answers from a fixed map, for exercising the closure
    /// walk without a network.
    struct StubResolver(HashMap<String, serde_json::Value>);

    #[async_trait::async_trait]
    impl LexiconResolver for StubResolver {
        async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
            self.0.get(nsid).cloned()
        }
    }

    fn record_schema(id: &str, ref_to: Option<&str>) -> serde_json::Value {
        let properties = match ref_to {
            Some(r) => serde_json::json!({"other": {"type": "ref", "ref": r}}),
            None => serde_json::json!({"text": {"type": "string"}}),
        };
        serde_json::json!({
            "lexicon": 1,
            "id": id,
            "defs": {"main": {"type": "record", "key": "tid",
                "record": {"type": "object", "properties": properties}}}
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unresolvable_collection_is_not_a_known_lexicon() {
        let stub = StubResolver(HashMap::new());
        assert!(matches!(
            resolve_catalog(&stub, "com.example.nope").await,
            CatalogOutcome::Unresolvable
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_self_contained_schema_resolves() {
        let mut map = HashMap::new();
        map.insert(
            "com.example.simple".to_string(),
            record_schema("com.example.simple", None),
        );
        assert!(matches!(
            resolve_catalog(&StubResolver(map), "com.example.simple").await,
            CatalogOutcome::Ready(_)
        ));
    }

    /// The case that makes the closure necessary: a schema whose reference is
    /// missing would otherwise validate every record to
    /// `UnresolvedReference`, which reads as "your record is wrong" when the
    /// gap is in the published lexicons.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_reference_is_reported_as_an_incomplete_closure() {
        let mut map = HashMap::new();
        map.insert(
            "com.example.post".to_string(),
            record_schema("com.example.post", Some("com.example.facet#main")),
        );
        match resolve_catalog(&StubResolver(map), "com.example.post").await {
            CatalogOutcome::IncompleteClosure { missing } => {
                assert_eq!(missing, "com.example.facet");
            }
            _ => panic!("expected an incomplete closure"),
        }
    }

    #[test]
    fn the_bundled_corpus_covers_the_protocol_vocabulary() {
        let bundled = BundledLexiconResolver::new();
        assert!(
            bundled.len() > 300,
            "expected the full corpus, got {} lexicons",
            bundled.len()
        );
        for nsid in [
            "app.bsky.feed.post",
            "app.bsky.actor.profile",
            "com.atproto.repo.createRecord",
            "tools.ozone.moderation.defs",
        ] {
            assert!(
                BUNDLED_LEXICONS.iter().any(|(id, _)| *id == nsid),
                "{nsid} should be bundled",
            );
        }
    }

    /// The closure has to resolve entirely from the bundle, with no network.
    /// `app.bsky.feed.post` references facets and several embed types, so this
    /// is the case that would otherwise reject every real post.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bundled_schema_resolves_its_whole_closure_offline() {
        let bundled = BundledLexiconResolver::new();
        match resolve_catalog(&bundled, "app.bsky.feed.post").await {
            CatalogOutcome::Ready(catalog) => {
                assert!(catalog.get_schema("app.bsky.feed.post").is_some());
                assert!(
                    catalog.get_schema("app.bsky.richtext.facet").is_some(),
                    "a referenced schema should have come from the bundle too",
                );
            }
            CatalogOutcome::Unresolvable => panic!("app.bsky.feed.post is bundled"),
            CatalogOutcome::IncompleteClosure { missing } => {
                panic!("closure incomplete offline, missing {missing}")
            }
        }
    }

    /// A real post validates against the bundled schema, and one missing a
    /// required field does not. Without both halves the bundle could be
    /// present and inert.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_bundled_schema_accepts_a_good_post_and_rejects_a_bad_one() {
        let bundled = BundledLexiconResolver::new();
        let CatalogOutcome::Ready(catalog) = resolve_catalog(&bundled, "app.bsky.feed.post").await
        else {
            panic!("app.bsky.feed.post is bundled")
        };
        let schema = catalog.get_schema("app.bsky.feed.post").unwrap().clone();
        let flags = atproto_lexicon::validation::flags::ValidateFlags::default();

        let good = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "a perfectly ordinary post",
            "createdAt": "2026-01-01T00:00:00.000Z",
        });
        atproto_lexicon::validation::validate::validate_record_with_schema(
            &good,
            &schema,
            catalog.as_ref(),
            flags,
        )
        .expect("a valid post should validate");

        let bad = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "no createdAt",
        });
        let err = atproto_lexicon::validation::validate::validate_record_with_schema(
            &bad,
            &schema,
            catalog.as_ref(),
            flags,
        )
        .expect_err("a post without createdAt should be rejected");
        assert!(err.to_string().contains("createdAt"), "got: {err}");
    }

    /// The bundle answers before the network, so a bundled schema cannot be
    /// replaced by whatever an authority publishes today.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_chain_prefers_the_bundle() {
        let mut map = HashMap::new();
        map.insert(
            "app.bsky.feed.post".to_string(),
            record_schema("app.bsky.feed.post", None),
        );
        let chain = ChainedLexiconResolver::new(vec![
            Arc::new(BundledLexiconResolver::new()),
            Arc::new(StubResolver(map)),
        ]);
        let resolved = chain.resolve("app.bsky.feed.post").await.expect("resolves");
        // The stub's stand-in has a single `text` property; the real one has
        // many more, so a shallow document means the stub won.
        let props = resolved
            .pointer("/defs/main/record/properties")
            .and_then(|v| v.as_object())
            .map(serde_json::Map::len)
            .unwrap_or(0);
        assert!(props > 1, "the network stub overrode the bundled schema");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_resolved_reference_completes_the_closure() {
        let mut map = HashMap::new();
        map.insert(
            "com.example.post".to_string(),
            record_schema("com.example.post", Some("com.example.facet#main")),
        );
        map.insert(
            "com.example.facet".to_string(),
            record_schema("com.example.facet", None),
        );
        assert!(matches!(
            resolve_catalog(&StubResolver(map), "com.example.post").await,
            CatalogOutcome::Ready(_)
        ));
    }
}
