//! Shared HTTP state — passed to every handler via the axum extractor.

use crate::account::AccountManager;
use crate::actor_store::PublicRealmBackend;
use crate::email::EmailService;
use crate::oauth::state::OAuthState;
use crate::plc::PlcService;
use crate::repo::{RepoReader, RepoWriter};
use crate::security::{JtiReplayGuard, SlidingWindowLimiter};
use crate::sequencer::EventBus;
use crate::space::{SpaceDeclarationResolver, SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_identity::key::KeyData;
use atproto_identity::traits::DnsResolver;
use std::sync::Arc;
use std::time::Duration;

/// Default ceiling for `importRepo`, in bytes (1 GiB).
///
/// Matches what `README.md` tells operators to size their reverse proxy for. It
/// was previously bounded by axum's 2 MiB default instead, so inbound migration
/// failed for any non-trivial repository.
pub const DEFAULT_IMPORT_LIMIT_BYTES: usize = 1024 * 1024 * 1024;

/// A policy document set the portal asks new accounts to accept.
#[derive(Debug, Clone)]
pub struct PolicyDocuments {
    /// Identifier of the set, recorded verbatim in the acceptance record.
    ///
    /// A dated content hash names an immutable set, so revising the documents
    /// produces a different identifier and a fresh acceptance rather than
    /// silently re-pointing an old one.
    pub set_id: String,
    /// Where the documents are published, shown to the holder before they
    /// agree and recorded alongside the identifier.
    pub url: String,
}

/// How long a built validation catalog stays usable.
///
/// Matched to the lexicon resolver's own TTL: a catalog is a parse of the
/// documents that resolver returns, so outliving them would mean validating
/// against a schema the server would no longer fetch.
const LEXICON_CATALOG_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// How many collections' catalogs are held.
///
/// The collection NSID comes from the record being written, so this is
/// caller-supplied and bounded for the same reason the resolver caches are.
const LEXICON_CATALOG_CAPACITY: usize = 512;
/// Shared state for the HTTP layer.
///
/// `Arc`-wrapped so axum can `Clone` the state cheaply across handlers.
#[derive(Clone)]
pub struct HttpState {
    /// Public-realm read handlers.
    pub reader: Arc<RepoReader>,
    /// Account-management orchestrator.
    pub account_manager: Option<Arc<AccountManager>>,
    /// Public-realm write handlers.
    pub writer: Option<Arc<RepoWriter>>,
    /// PDS service DID (e.g., `did:web:pds.example.com`).
    pub service_did: String,
    /// HMAC secret for app-password session JWTs.
    pub jwt_secret: Arc<Vec<u8>>,
    /// Whether `createAccount` requires an invite code.
    pub invite_required: bool,
    /// OAuth in-flight state (PAR / auth-codes / refresh tokens).
    pub oauth: OAuthState,
    /// Admin password for `com.atproto.admin.*` Basic-auth.
    pub admin_password: Option<String>,
    /// Spaces management orchestrator.
    pub space_service: Option<Arc<SpaceService>>,
    /// Spaces record writer.
    pub space_writer: Option<Arc<SpaceWriter>>,
    /// Spaces dual-auth record reader.
    pub space_reader: Option<Arc<SpaceReader>>,
    /// Spaces sync (state + oplog) reader.
    pub space_sync: Option<Arc<SpaceSync>>,
    /// Resolver for space-type declarations (NSID → declared `collections`),
    /// used to expand a bare `space:` grant's omitted-`collection` default
    /// (spec line 413). `None` disables the default (bare grants confer no
    /// write targets); typically a TTL-cached network resolver.
    pub space_declaration_resolver: Option<Arc<dyn SpaceDeclarationResolver>>,
    /// Resolves lexicon NSIDs to schema documents, for record validation.
    ///
    /// `None` when no DNS resolver is configured, which makes every lexicon
    /// unresolvable -- and so `validate: true` is refused rather than silently
    /// passing. That is the same fail-closed shape as space-declaration
    /// resolution above.
    pub lexicon_resolver: Option<Arc<dyn crate::repo::lexicon::LexiconResolver>>,
    /// PLC genesis service (None disables PLC-managed DID creation).
    pub plc_service: Option<Arc<PlcService>>,
    /// Cancelled when the process is shutting down.
    ///
    /// Only `subscribeRepos` consults it. A firehose socket has no reason to
    /// close on its own, and `axum::serve` waits for every open connection
    /// before its graceful shutdown returns -- so without this, one attached
    /// consumer makes every deploy sit out the full shutdown deadline before
    /// being cut off mid-frame anyway.
    ///
    /// `None` in tests and for embedders that do not run a shutdown
    /// controller; the subscription then lasts as long as the socket does.
    pub shutdown: Option<tokio_util::sync::CancellationToken>,
    /// Validation catalogs, keyed by collection NSID.
    ///
    /// Building one parses every schema in the closure -- up to
    /// `MAX_SCHEMAS` documents -- and `applyWrites` validates every entry in a
    /// batch, so a hundred records written to one collection rebuilt the same
    /// catalog a hundred times before any storage work happened. The documents
    /// were already cached; the parsing of them was not.
    ///
    /// Per-state rather than global: a catalog is only meaningful against the
    /// resolver that produced it, and two servers in one process -- which every
    /// test is -- resolve the same NSID to different documents.
    pub lexicon_catalogs: Arc<crate::ttl_cache::TtlCache<crate::repo::lexicon::CatalogOutcome>>,
    /// How many reverse proxies the operator says sit in front of this server.
    ///
    /// Zero means none, and therefore that `X-Forwarded-*` is caller-supplied
    /// text rather than infrastructure. The rate limiter has always read it
    /// that way; the DPoP `htu` and the portal cookie's `Secure` flag did not,
    /// and trusted the headers unconditionally.
    pub trusted_proxy_hops: usize,
    /// Issues and checks server-provided DPoP nonces.
    ///
    /// `None` disables the requirement, which is what tests and embedders that
    /// have not configured one get. The specification calls nonces mandatory,
    /// so the binary sets this; the option exists because an operator upgrading
    /// a live server needs a way to turn it off if a client of theirs has not
    /// implemented the retry.
    pub dpop_nonce: Option<crate::oauth::nonce::NonceIssuer>,
    /// JWT-jti replay guard (always populated; in-memory by default).
    pub jti_guard: JtiReplayGuard,
    /// Brief memory of what each rotated refresh token was exchanged for, so a
    /// client with two refreshes in flight is not logged out by its own race.
    pub refresh_grace: Arc<crate::account::refresh_grace::RefreshGrace>,
    /// Per-key sliding-window rate limiter (always populated).
    pub rate_limiter: SlidingWindowLimiter,
    /// In-process broadcast bus for `subscribeRepos` low-latency
    /// fan-out. The durable firehose stream remains the source of truth;
    /// the bus is a wakeup-on-write optimization.
    pub event_bus: EventBus,
    /// PDS-level signing key (typically P-256 or K-256). When `Some`, its
    /// public form is published via `/oauth/jwks` for federation. Reserved
    /// for future ES256K-signed access tokens; today access tokens are
    /// HS256-only.
    pub pds_signing_key: Option<Arc<KeyData>>,
    /// Outbound email — SMTP-backed when the `smtp` feature is enabled and
    /// `PDS_EMAIL_SMTP_URL` + `PDS_EMAIL_FROM_ADDRESS` are set; otherwise a
    /// disabled stub that logs the would-be confirmation URL.
    pub email: EmailService,
    /// Identities the operator has granted administrative authority, by DID.
    ///
    /// An alternative to the admin password for the endpoints that accept one.
    /// A password is a shared secret that has to be transported to whoever
    /// needs it and cannot say who used it; a DID is an identity that signs,
    /// so the request carries proof of who made it and the operator can revoke
    /// authority by editing a list rather than rotating a secret everyone
    /// holds.
    pub admin_dids: Vec<String>,
    /// Policy documents the account holder must accept, when the operator has
    /// configured a set.
    ///
    /// Both halves are load-bearing and neither is useful alone: the
    /// identifier is what gets recorded, and the URL is what the holder
    /// actually reads before agreeing. A set configured with only one of them
    /// would either record an agreement to something unnamed or show a
    /// document that nothing attests to, so the portal treats the pair as
    /// present or absent together.
    pub policy: Option<PolicyDocuments>,
    /// Resolves an `Atproto-Proxy` DID to a forwarding target, with a TTL
    /// cache. `None` disables per-request proxy targets, leaving only the
    /// operator-pinned AppView reachable.
    pub proxy_resolver: Option<Arc<crate::http::proxy_target::CachingProxyResolver>>,

    /// DNS resolver for handle-to-DID resolution via TXT records
    /// When `Some`, `resolveHandle` performs the
    /// dual DNS+HTTP resolution per `atproto_identity::resolve::resolve_handle`;
    /// when `None`, it falls back to HTTP-only via `resolve_handle_http`.
    pub dns_resolver: Option<Arc<dyn DnsResolver>>,
    /// Audience DID of the moderation report service.
    /// Set via `PDS_REPORT_SERVICE_DID`. Required alongside
    /// `report_service_url` for `createReport` to forward.
    pub report_service_did: Option<String>,
    /// Base URL of the moderation report service. Set via
    /// `PDS_REPORT_SERVICE_URL`. The `createReport` handler POSTs to
    /// `<url>/xrpc/com.atproto.moderation.createReport`.
    pub report_service_url: Option<String>,
    /// Public-realm storage backend dispatch.
    /// `Some(...)` selects the trait-dispatched code path; `None` keeps
    /// the legacy direct-sqlx path for back-compat.
    pub public_realm_backend: Option<PublicRealmBackend>,
    /// Largest blob `uploadBlob` will accept, in bytes. Default
    /// [`crate::blob::DEFAULT_BLOB_UPLOAD_LIMIT_BYTES`] (16 MiB). Set via
    /// `PDS_BLOB_UPLOAD_LIMIT`.
    ///
    /// Enforced by the handler rather than by an axum body limit, so an
    /// over-sized upload is refused as an XRPC error and not as a bare 413.
    pub blob_upload_limit_bytes: usize,
    /// Largest CAR `importRepo` will accept, in bytes. Default
    /// [`DEFAULT_IMPORT_LIMIT_BYTES`] (1 GiB). Set via `PDS_IMPORT_LIMIT`.
    ///
    /// Separate from the blob ceiling because the two bound different things:
    /// one media file against a whole repository.
    pub import_limit_bytes: usize,
    /// OAuth access-token TTL. Default
    /// [`crate::oauth::state::DEFAULT_ACCESS_TTL_SECS`] (15 min). Set via
    /// `PDS_OAUTH_ACCESS_TOKEN_TTL_SECONDS`.
    pub oauth_access_ttl_secs: u64,
    /// OAuth refresh-token TTL. Default
    /// [`crate::oauth::state::DEFAULT_REFRESH_TTL_SECS`] (30 days). Set via
    /// `PDS_OAUTH_REFRESH_TOKEN_TTL_SECONDS`.
    pub oauth_refresh_ttl_secs: u64,
    /// Additional PDS signing keys for JWK rotation.
    /// `pds_signing_key` (the field above) is the *current* signer; this
    /// vec holds prior keys whose public form should remain in
    /// `/oauth/jwks` so consumers verifying older tokens see them.
    pub pds_extra_signing_keys: Vec<Arc<KeyData>>,
    /// SpaceCredential TTL in seconds. Default
    /// `atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS` (7200 / 2h);
    /// operators tighten/loosen via `PDS_SPACE_CREDENTIAL_TTL_SECONDS`.
    pub space_credential_ttl_secs: u64,
    /// Allowed handle suffix domains. Empty means
    /// any handle is accepted (back-compat). Set via
    /// `PDS_SERVICE_HANDLE_DOMAINS`.
    pub service_handle_domains: Vec<String>,
    /// Crawler hostnames notified by `requestCrawl`.
    /// Comma-separated `PDS_CRAWLERS`.
    pub crawlers: Vec<String>,
    /// AppView audience DID for `app.bsky.*` proxying.
    /// `Atproto-Proxy` header overrides at runtime; this is the default
    /// pin when no header is supplied.
    pub bsky_app_view_did: Option<String>,
    /// AppView base URL for `app.bsky.*` proxying. Default for the
    /// `Atproto-Proxy` middleware when the header is absent.
    pub bsky_app_view_url: Option<String>,
}

impl HttpState {
    /// Construct read-only state (compat shim used by tests).
    pub fn new(reader: Arc<RepoReader>) -> Self {
        Self {
            reader,
            account_manager: None,
            writer: None,
            service_did: "did:web:localhost".to_string(),
            jwt_secret: Arc::new(b"dev-only-jwt-secret-32-bytes-min!".to_vec()),
            invite_required: false,
            admin_dids: Vec::new(),
            policy: None,
            oauth: OAuthState::new(),
            admin_password: None,
            space_service: None,
            space_writer: None,
            space_reader: None,
            space_sync: None,
            space_declaration_resolver: None,
            lexicon_resolver: None,
            plc_service: None,
            shutdown: None,
            lexicon_catalogs: Arc::new(crate::ttl_cache::TtlCache::new(
                LEXICON_CATALOG_TTL,
                LEXICON_CATALOG_CAPACITY,
            )),
            trusted_proxy_hops: 0,
            dpop_nonce: None,
            jti_guard: JtiReplayGuard::new(100_000),
            refresh_grace: Arc::new(crate::account::refresh_grace::RefreshGrace::default()),
            rate_limiter: SlidingWindowLimiter::new(300, Duration::from_secs(60), 100_000),
            event_bus: EventBus::default(),
            pds_signing_key: None,
            email: EmailService::default(),
            proxy_resolver: None,
            dns_resolver: None,
            report_service_did: None,
            report_service_url: None,
            public_realm_backend: None,
            blob_upload_limit_bytes: crate::blob::DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
            import_limit_bytes: DEFAULT_IMPORT_LIMIT_BYTES,
            oauth_access_ttl_secs: crate::oauth::state::DEFAULT_ACCESS_TTL_SECS,
            oauth_refresh_ttl_secs: crate::oauth::state::DEFAULT_REFRESH_TTL_SECS,
            pds_extra_signing_keys: Vec::new(),
            space_credential_ttl_secs: atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
            service_handle_domains: Vec::new(),
            crawlers: Vec::new(),
            bsky_app_view_did: None,
            bsky_app_view_url: None,
        }
    }

    /// Construct full state with the account manager + writer attached.
    pub fn with_account_manager(
        reader: Arc<RepoReader>,
        account_manager: Arc<AccountManager>,
        service_did: String,
        jwt_secret: Vec<u8>,
        invite_required: bool,
    ) -> Self {
        Self {
            reader,
            account_manager: Some(account_manager),
            writer: None,
            service_did,
            jwt_secret: Arc::new(jwt_secret),
            invite_required,
            admin_dids: Vec::new(),
            policy: None,
            oauth: OAuthState::new(),
            admin_password: None,
            space_service: None,
            space_writer: None,
            space_reader: None,
            space_sync: None,
            space_declaration_resolver: None,
            lexicon_resolver: None,
            plc_service: None,
            shutdown: None,
            lexicon_catalogs: Arc::new(crate::ttl_cache::TtlCache::new(
                LEXICON_CATALOG_TTL,
                LEXICON_CATALOG_CAPACITY,
            )),
            trusted_proxy_hops: 0,
            dpop_nonce: None,
            jti_guard: JtiReplayGuard::new(100_000),
            refresh_grace: Arc::new(crate::account::refresh_grace::RefreshGrace::default()),
            rate_limiter: SlidingWindowLimiter::new(300, Duration::from_secs(60), 100_000),
            event_bus: EventBus::default(),
            pds_signing_key: None,
            email: EmailService::default(),
            proxy_resolver: None,
            dns_resolver: None,
            report_service_did: None,
            report_service_url: None,
            public_realm_backend: None,
            blob_upload_limit_bytes: crate::blob::DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
            import_limit_bytes: DEFAULT_IMPORT_LIMIT_BYTES,
            oauth_access_ttl_secs: crate::oauth::state::DEFAULT_ACCESS_TTL_SECS,
            oauth_refresh_ttl_secs: crate::oauth::state::DEFAULT_REFRESH_TTL_SECS,
            pds_extra_signing_keys: Vec::new(),
            space_credential_ttl_secs: atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
            service_handle_domains: Vec::new(),
            crawlers: Vec::new(),
            bsky_app_view_did: None,
            bsky_app_view_url: None,
        }
    }

    /// Attach a `RepoWriter` for the public-realm write endpoints.
    #[must_use]
    pub fn with_writer(mut self, writer: Arc<RepoWriter>) -> Self {
        self.writer = Some(writer);
        self
    }

    /// Set the admin password used by `com.atproto.admin.*` Basic-auth.
    #[must_use]
    pub fn with_admin_password(mut self, password: String) -> Self {
        self.admin_password = Some(password);
        self
    }

    /// Attach a PLC genesis service for `createAccount` without a supplied DID.
    #[must_use]
    pub fn with_plc_service(mut self, plc: Arc<PlcService>) -> Self {
        self.plc_service = Some(plc);
        self
    }

    /// Declare how many trusted reverse proxies sit in front of this server.
    #[must_use]
    pub fn with_trusted_proxy_hops(mut self, hops: usize) -> Self {
        self.trusted_proxy_hops = hops;
        self
    }

    /// Require and issue DPoP nonces.
    #[must_use]
    pub fn with_dpop_nonce(mut self, issuer: crate::oauth::nonce::NonceIssuer) -> Self {
        self.dpop_nonce = Some(issuer);
        self
    }

    /// Let `subscribeRepos` close its sockets when the process shuts down.
    #[must_use]
    pub fn with_shutdown(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    /// Override the JTI replay guard (lets ops swap in a Valkey-backed impl
    /// behind the same trait surface).
    #[must_use]
    pub fn with_jti_guard(mut self, guard: JtiReplayGuard) -> Self {
        self.jti_guard = guard;
        self
    }

    /// Swap the in-memory OAuth state for a different backend (e.g. the
    /// SQL-backed variant in production). Lets `bin/pds.rs` upgrade the
    /// default memory backend to one persisted in `accounts.sqlite`.
    #[must_use]
    pub fn with_oauth_state(mut self, oauth: OAuthState) -> Self {
        self.oauth = oauth;
        self
    }

    /// Override the rate limiter.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: SlidingWindowLimiter) -> Self {
        self.rate_limiter = limiter;
        self
    }

    /// Attach the PDS-level signing key. Its public form is published via
    /// `/oauth/jwks`. Pass a private key here; we surface only the public
    /// component.
    #[must_use]
    pub fn with_pds_signing_key(mut self, key: Arc<KeyData>) -> Self {
        self.pds_signing_key = Some(key);
        self
    }

    /// Attach the outbound email service. Default is the disabled stub
    /// that logs the would-be confirmation URL at INFO.
    #[must_use]
    /// Configure the policy documents new accounts must accept.
    /// Grant administrative authority to a set of DIDs.
    pub fn with_admin_dids(mut self, dids: Vec<String>) -> Self {
        self.admin_dids = dids;
        self
    }

    /// Configure the policy documents new accounts must accept.
    pub fn with_policy_documents(mut self, policy: Option<PolicyDocuments>) -> Self {
        self.policy = policy;
        self
    }

    /// Attach the outbound email service.
    pub fn with_email_service(mut self, email: EmailService) -> Self {
        self.email = email;
        self
    }

    /// Attach a resolver for per-request `Atproto-Proxy` targets.
    ///
    /// Without one, only the operator-configured AppView is reachable and any
    /// other DID in the header is refused.
    #[must_use]
    pub fn with_proxy_resolver(
        mut self,
        resolver: Arc<crate::http::proxy_target::CachingProxyResolver>,
    ) -> Self {
        self.proxy_resolver = Some(resolver);
        self
    }

    /// Attach a DNS resolver for `resolveHandle`.
    /// When set, the handler performs the dual DNS+HTTP resolution
    /// `atproto_identity::resolve::resolve_handle`; when unset, it falls
    /// back to HTTP-only via `resolve_handle_http`.
    #[must_use]
    pub fn with_dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Attach a space-type declaration resolver. When set, a bare `space:`
    /// grant's omitted-`collection` default expands to the declaration's
    /// `collections` (spec line 413). Typically a
    /// [`CachingSpaceDeclarationResolver`](crate::space::CachingSpaceDeclarationResolver)
    /// wrapping a
    /// [`NetworkSpaceDeclarationResolver`](crate::space::NetworkSpaceDeclarationResolver).
    #[must_use]
    pub fn with_space_declaration_resolver(
        mut self,
        resolver: Arc<dyn SpaceDeclarationResolver>,
    ) -> Self {
        self.space_declaration_resolver = Some(resolver);
        self
    }

    /// Attach a lexicon resolver, enabling record validation.
    #[must_use]
    pub fn with_lexicon_resolver(
        mut self,
        resolver: Arc<dyn crate::repo::lexicon::LexiconResolver>,
    ) -> Self {
        self.lexicon_resolver = Some(resolver);
        self
    }

    /// Attach moderation-service forwarding configuration. When both `did` and `url` are set, `createReport` mints a
    /// service-auth token (`aud=did`, `lxm=com.atproto.moderation.createReport`)
    /// and POSTs the report payload to `<url>/xrpc/...`. Without these
    /// the handler returns `503 ModerationServiceUnavailable`.
    #[must_use]
    pub fn with_report_service(mut self, did: String, url: String) -> Self {
        self.report_service_did = Some(did);
        self.report_service_url = Some(url);
        self
    }

    /// Attach a public-realm storage backend. When
    /// set, the public-realm code paths that have been refactored
    /// through the trait dispatch (currently the blob layer) use this
    /// backend instead of the legacy direct-sqlx path. `bin/pds.rs`
    /// constructs either [`PublicRealmBackend::sql`] or
    /// [`PublicRealmBackend::fjall`] based on `PDS_STORAGE_PROFILE`.
    #[must_use]
    pub fn with_public_realm_backend(mut self, backend: PublicRealmBackend) -> Self {
        self.public_realm_backend = Some(backend);
        self
    }

    /// Override the `uploadBlob` ceiling.
    #[must_use]
    pub fn with_blob_upload_limit(mut self, bytes: usize) -> Self {
        self.blob_upload_limit_bytes = bytes;
        self
    }

    /// Override the `importRepo` ceiling.
    #[must_use]
    pub fn with_import_limit(mut self, bytes: usize) -> Self {
        self.import_limit_bytes = bytes;
        self
    }

    /// Override the OAuth access-token TTL.
    /// Default is [`crate::oauth::state::DEFAULT_ACCESS_TTL_SECS`] (15 min).
    #[must_use]
    pub fn with_oauth_access_ttl(mut self, ttl_secs: u64) -> Self {
        self.oauth_access_ttl_secs = ttl_secs;
        self
    }

    /// Override the OAuth refresh-token TTL.
    /// Default is [`crate::oauth::state::DEFAULT_REFRESH_TTL_SECS`] (30d).
    #[must_use]
    pub fn with_oauth_refresh_ttl(mut self, ttl_secs: u64) -> Self {
        self.oauth_refresh_ttl_secs = ttl_secs;
        self
    }

    /// Attach additional historical PDS signing keys.
    /// `pds_signing_key` (set via `with_pds_signing_key`) remains the
    /// *current* signer; the keys passed here are prior signers kept in
    /// `/oauth/jwks` so consumers verifying older tokens see them.
    #[must_use]
    pub fn with_extra_signing_keys(mut self, keys: Vec<Arc<KeyData>>) -> Self {
        self.pds_extra_signing_keys = keys;
        self
    }

    /// Override the SpaceCredential TTL.
    ///
    /// Clamped to
    /// [`SPACE_CREDENTIAL_TTL_MIN_SECS`](atproto_space::credential::SPACE_CREDENTIAL_TTL_MIN_SECS)
    /// ..=[`SPACE_CREDENTIAL_TTL_MAX_SECS`](atproto_space::credential::SPACE_CREDENTIAL_TTL_MAX_SECS).
    /// A SpaceCredential cannot be revoked once minted, so an unbounded TTL
    /// here would silently become an unbounded grant; a zero TTL would mint
    /// credentials that are already expired.
    #[must_use]
    pub fn with_space_credential_ttl(mut self, ttl_secs: u64) -> Self {
        let clamped = ttl_secs.clamp(
            atproto_space::credential::SPACE_CREDENTIAL_TTL_MIN_SECS,
            atproto_space::credential::SPACE_CREDENTIAL_TTL_MAX_SECS,
        );
        if clamped != ttl_secs {
            tracing::warn!(
                requested = ttl_secs,
                applied = clamped,
                "space credential ttl outside the permitted range; clamped"
            );
        }
        self.space_credential_ttl_secs = clamped;
        self
    }

    /// Set the allowed handle suffix domains. When
    /// non-empty, `createAccount` rejects handles whose suffix isn't in
    /// the list.
    #[must_use]
    pub fn with_service_handle_domains(mut self, domains: Vec<String>) -> Self {
        self.service_handle_domains = domains;
        self
    }

    /// Set the crawler hostnames notified by `requestCrawl` (§11b).
    #[must_use]
    pub fn with_crawlers(mut self, crawlers: Vec<String>) -> Self {
        self.crawlers = crawlers;
        self
    }

    /// Configure default Atproto-Proxy pinning to a Bluesky AppView
    /// Both `did` and `url` must be set together;
    /// the inbound `Atproto-Proxy: <did>#<service-id>` header overrides
    /// per-request.
    #[must_use]
    pub fn with_bsky_app_view(mut self, did: String, url: String) -> Self {
        self.bsky_app_view_did = Some(did);
        self.bsky_app_view_url = Some(url);
        self
    }

    /// Attach the full Spaces stack (service / writer / reader / sync).
    #[must_use]
    pub fn with_spaces(
        mut self,
        service: Arc<SpaceService>,
        writer: Arc<SpaceWriter>,
        reader: Arc<SpaceReader>,
        sync: Arc<SpaceSync>,
    ) -> Self {
        self.space_service = Some(service);
        self.space_writer = Some(writer);
        self.space_reader = Some(reader);
        self.space_sync = Some(sync);
        self
    }
}
