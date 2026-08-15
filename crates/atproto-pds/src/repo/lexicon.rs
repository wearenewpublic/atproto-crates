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
use std::sync::Arc;
use std::time::Duration;

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

        // SSRF egress guard. `pds` is a service endpoint from a DID document an
        // attacker-chosen collection NSID resolved to, and this server is about
        // to GET it during record validation. Without this the endpoint is a
        // request generator pointed wherever the attacker names — a cloud
        // metadata service, an internal admin port, loopback. This applies the
        // same syntactic policy the OAuth client-metadata path uses (HTTPS only,
        // no address literals, no embedded credentials, port 443). It does not
        // resolve DNS, so a public name pointing inside is caught instead by the
        // resolver's redirect policy, which is set to none where the client is
        // built.
        if let Err(e) = atproto_identity::validation::validate_service_endpoint(&pds) {
            tracing::warn!(
                endpoint = %pds,
                error = %e,
                "lexicon resolution: refusing a non-permitted service endpoint"
            );
            return None;
        }

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

/// How many resolutions each resolver cache holds.
///
/// Large enough that a real working set -- the collections one server writes,
/// the services it proxies to -- stays resident, small enough that a caller
/// producing distinct keys cannot turn the cache into a memory leak. The
/// number is a bound, not a target: nothing pre-allocates it.
const CACHE_CAPACITY: usize = 4_096;

/// A resolver that remembers answers, including the negative ones.
///
/// Caching a miss matters as much as caching a hit: an unresolvable NSID costs
/// a DNS lookup and a DID resolution to discover, and a repo writing records in
/// an unpublished collection would pay it on every single write.
///
/// The cache is bounded. It was a `HashMap` that only ever grew: the read path
/// ignored an expired entry and the write path only inserted, so a caller
/// writing records in many distinct collections could grow it without limit.
pub struct CachingLexiconResolver {
    inner: Arc<dyn LexiconResolver>,
    entries: crate::ttl_cache::TtlCache<Option<serde_json::Value>>,
}

impl CachingLexiconResolver {
    /// Wrap a resolver with a time-to-live.
    #[must_use]
    pub fn new(inner: Arc<dyn LexiconResolver>, ttl: Duration) -> Self {
        Self {
            inner,
            entries: crate::ttl_cache::TtlCache::new(ttl, CACHE_CAPACITY),
        }
    }
}

#[async_trait::async_trait]
impl LexiconResolver for CachingLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
        if let Some(hit) = self.entries.get(nsid) {
            return hit;
        }
        let result = self.inner.resolve(nsid).await;
        self.entries.put(nsid, result.clone());
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
///
/// `Clone`, with the catalog behind an `Arc`, so the result can be cached.
/// Building one parses every schema in the closure, and the closure for a
/// collection does not change between two records written to it a millisecond
/// apart.
#[derive(Clone)]
pub enum CatalogOutcome {
    /// The schema and everything it references resolved.
    Ready(Arc<BaseCatalog>),
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

    CatalogOutcome::Ready(Arc::new(catalog))
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
/// `app.bsky.*`, `chat.bsky.*`, `com.atproto.*` and `tools.ozone.*` are bundled
/// because they are the schemas a PDS is asked to validate against constantly
/// and cannot afford to be unable to.
///
/// `chat.bsky.*` earns its place for a reason the other three do not: a PDS
/// does not serve those methods, it forwards them (see `PROXIED_NAMESPACES` in
/// `http/proxy_handlers.rs`). But `chat.bsky.actor.declaration` is a record
/// type that lives in the account holder\'s own repo, so this PDS validates it
/// on write like any other, and the rest of the namespace is what makes the
/// declaration\'s references resolvable offline. Resolving them over the network is possible in
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

/// Schemas an operator supplied on disk, read once at startup.
///
/// The bundled corpus covers the vocabulary the protocol itself defines, and
/// the network resolver covers everything published on the open network. This
/// covers the gap between them: a schema that is real but not reachable from
/// where this server is standing.
///
/// That gap is not hypothetical. A rig whose PDS writes genesis operations to a
/// *local* PLC directory cannot resolve any DID registered in the production
/// one — including the DID that publishes an application's own lexicons. The
/// symptom is remote from the cause: `include:` scopes silently expand to
/// nothing, and every write is refused with `InsufficientScope` long after the
/// resolution that failed. Pointing this at the application's `lexicons/`
/// directory answers the question locally and takes the network out of it.
///
/// # NSID from the document, not the path
///
/// A lexicon document carries its own `id`, and that is what is used. The
/// bundled corpus derives NSIDs from file paths because it is generated from a
/// vendored tree whose layout is known; an operator's directory is not this
/// server's to arrange, and a document that says what it is should be believed
/// over its location. The path is the fallback for a document with no `id`.
///
/// # Read once
///
/// Loaded at startup, like the bundled corpus. Editing a file needs a restart —
/// which is the honest behaviour: re-reading per request would make two
/// consecutive writes validate against different schemas with nothing in the
/// logs to say so.
pub struct DirectoryLexiconResolver {
    schemas: HashMap<String, serde_json::Value>,
}

impl DirectoryLexiconResolver {
    /// Read every `*.json` under `dir`, recursively.
    ///
    /// Returns the resolver and the paths that could not be used, so the caller
    /// can report them. A malformed file is skipped rather than fatal: one bad
    /// schema in a directory of twenty should not keep the server down.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when `dir` cannot be read at all. That *is* fatal, and
    /// deliberately so — a mistyped path would otherwise load nothing and leave
    /// a server that looks configured and resolves exactly as it did before.
    pub fn load(
        dir: &std::path::Path,
    ) -> std::io::Result<(Self, Vec<(std::path::PathBuf, String)>)> {
        let mut schemas = HashMap::new();
        let mut skipped = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        // Iterative rather than recursive: a directory tree is operator input,
        // and a symlink loop should not be a stack overflow.
        let mut seen_dirs = HashSet::new();
        while let Some(current) = stack.pop() {
            let canonical = current.canonicalize().unwrap_or_else(|_| current.clone());
            if !seen_dirs.insert(canonical) {
                continue;
            }
            for entry in std::fs::read_dir(&current)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "json") {
                    continue;
                }
                let raw = match std::fs::read_to_string(&path) {
                    Ok(raw) => raw,
                    Err(e) => {
                        skipped.push((path, e.to_string()));
                        continue;
                    }
                };
                let doc: serde_json::Value = match serde_json::from_str(&raw) {
                    Ok(doc) => doc,
                    Err(e) => {
                        skipped.push((path, e.to_string()));
                        continue;
                    }
                };
                let nsid = doc["id"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| nsid_from_path(dir, &path));
                let Some(nsid) = nsid else {
                    skipped.push((
                        path,
                        "no `id` and no NSID derivable from the path".to_string(),
                    ));
                    continue;
                };
                schemas.insert(nsid, doc);
            }
        }
        Ok((Self { schemas }, skipped))
    }

    /// How many schemas were loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// Whether the directory yielded nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// The NSIDs this resolver answers for, sorted.
    ///
    /// Used at startup to report what was picked up, and to warn about any that
    /// the bundled corpus already covers and will therefore answer first.
    #[must_use]
    pub fn nsids(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.schemas.keys().map(String::as_str).collect();
        out.sort_unstable();
        out
    }
}

/// Derive an NSID from a file's path relative to the corpus root.
fn nsid_from_path(root: &std::path::Path, path: &std::path::Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let nsid = rel
        .with_extension("")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(".");
    (!nsid.is_empty()).then_some(nsid)
}

#[async_trait::async_trait]
impl LexiconResolver for DirectoryLexiconResolver {
    async fn resolve(&self, nsid: &str) -> Option<serde_json::Value> {
        self.schemas.get(nsid).cloned()
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
            "chat.bsky.actor.declaration",
            "chat.bsky.convo.defs",
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

    /// `chat.bsky.actor.declaration` is the one `chat.bsky` type a PDS stores
    /// rather than forwards -- it lives in the account holder\'s own repo, so
    /// this server validates it on write. Bundling the namespace is what makes
    /// that possible with no network at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_bundled_chat_declaration_validates_offline() {
        let bundled = BundledLexiconResolver::new();
        let CatalogOutcome::Ready(catalog) =
            resolve_catalog(&bundled, "chat.bsky.actor.declaration").await
        else {
            panic!("chat.bsky.actor.declaration is bundled")
        };
        let schema = catalog
            .get_schema("chat.bsky.actor.declaration")
            .unwrap()
            .clone();
        let flags = atproto_lexicon::validation::flags::ValidateFlags::default();

        let good = serde_json::json!({
            "$type": "chat.bsky.actor.declaration",
            "allowIncoming": "following",
        });
        atproto_lexicon::validation::validate::validate_record_with_schema(
            &good,
            &schema,
            catalog.as_ref(),
            flags,
        )
        .expect("a well-formed declaration validates");

        // `allowIncoming` is the one required property; without it the record
        // must be refused, or the schema is present but inert.
        let bad = serde_json::json!({ "$type": "chat.bsky.actor.declaration" });
        assert!(
            atproto_lexicon::validation::validate::validate_record_with_schema(
                &bad,
                &schema,
                catalog.as_ref(),
                flags,
            )
            .is_err(),
            "a declaration missing allowIncoming should not validate"
        );
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

    // --- the on-disk corpus ------------------------------------------------

    /// Write a lexicon document into a temp tree and read it back.
    fn write(dir: &std::path::Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// The document's own `id` decides the NSID, not where the file sits.
    ///
    /// An operator's directory is not this server's to arrange, and the two
    /// disagreeing is the case that matters: a file at `weird/place.json`
    /// carrying `"id": "app.bulleted.authFull"` has to answer for the NSID it
    /// claims, or configuring the directory silently does nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_document_is_keyed_by_its_own_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "weird/place.json",
            r#"{"lexicon":1,"id":"app.bulleted.authFull","defs":{}}"#,
        );

        let (resolver, skipped) = DirectoryLexiconResolver::load(tmp.path()).unwrap();

        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(resolver.resolve("app.bulleted.authFull").await.is_some());
        assert!(
            resolver.resolve("weird.place").await.is_none(),
            "the path must not shadow the id"
        );
    }

    /// A document with no `id` still resolves, by path, like the bundled corpus.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_document_without_an_id_falls_back_to_its_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "app/bulleted/note.json",
            r#"{"lexicon":1,"defs":{}}"#,
        );

        let (resolver, _) = DirectoryLexiconResolver::load(tmp.path()).unwrap();

        assert!(resolver.resolve("app.bulleted.note").await.is_some());
    }

    /// Nested directories are walked, and non-JSON is left alone.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_tree_is_walked_and_only_json_is_read() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "app/bulleted/node.json",
            r#"{"lexicon":1,"id":"app.bulleted.node","defs":{}}"#,
        );
        write(
            tmp.path(),
            "app/bulleted/admin/deny.json",
            r#"{"lexicon":1,"id":"app.bulleted.admin.deny","defs":{}}"#,
        );
        write(tmp.path(), "README.md", "not a lexicon");

        let (resolver, skipped) = DirectoryLexiconResolver::load(tmp.path()).unwrap();

        assert_eq!(resolver.len(), 2, "{:?}", resolver.nsids());
        assert!(
            skipped.is_empty(),
            "a non-JSON file is not a skipped lexicon"
        );
        assert!(resolver.resolve("app.bulleted.admin.deny").await.is_some());
    }

    /// One malformed file costs its own schema and nothing else.
    ///
    /// Fatal would be the wrong call: a directory of twenty schemas with one
    /// bad comma should not keep the server down. It is reported rather than
    /// swallowed, which is what `skipped` is for.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_malformed_document_is_skipped_not_fatal() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "good.json",
            r#"{"lexicon":1,"id":"app.bulleted.good","defs":{}}"#,
        );
        write(tmp.path(), "bad.json", "{not json");

        let (resolver, skipped) = DirectoryLexiconResolver::load(tmp.path()).unwrap();

        assert!(resolver.resolve("app.bulleted.good").await.is_some());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].0.ends_with("bad.json"), "{skipped:?}");
    }

    /// A directory that cannot be read is an error, not an empty corpus.
    ///
    /// A mistyped path would otherwise leave a server that looks configured and
    /// resolves exactly as it did before -- the failure this whole knob exists
    /// to make visible.
    #[test]
    fn an_unreadable_directory_is_an_error() {
        assert!(DirectoryLexiconResolver::load(std::path::Path::new("/no/such/lexicons")).is_err());
    }

    /// The chain prefers disk over network, and the bundle over both.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_chain_prefers_the_earlier_resolver() {
        let tmp = tempfile::TempDir::new().unwrap();
        write(
            tmp.path(),
            "a.json",
            r#"{"lexicon":1,"id":"app.example.thing","defs":{"from":"disk"}}"#,
        );
        let (disk, _) = DirectoryLexiconResolver::load(tmp.path()).unwrap();

        let mut net = HashMap::new();
        net.insert(
            "app.example.thing".to_string(),
            serde_json::json!({"defs": {"from": "network"}}),
        );

        let chain = ChainedLexiconResolver::new(vec![Arc::new(disk), Arc::new(StubResolver(net))]);

        let doc = chain.resolve("app.example.thing").await.expect("resolved");
        assert_eq!(
            doc["defs"]["from"], "disk",
            "the network answered ahead of disk"
        );
    }
}
