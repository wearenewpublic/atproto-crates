//! Shared HTTP state — passed to every handler via the axum extractor.

use crate::account::AccountManager;
use crate::actor_store::PublicRealmBackend;
use crate::email::EmailService;
use crate::oauth::state::OAuthState;
use crate::plc::PlcService;
use crate::repo::{RepoReader, RepoWriter};
use crate::security::{JtiReplayGuard, SlidingWindowLimiter};
use crate::sequencer::EventBus;
use crate::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_identity::key::KeyData;
use atproto_identity::traits::DnsResolver;
use std::sync::Arc;
use std::time::Duration;

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
    /// PLC genesis service (None disables PLC-managed DID creation).
    pub plc_service: Option<Arc<PlcService>>,
    /// JWT-jti replay guard (always populated; in-memory by default).
    pub jti_guard: JtiReplayGuard,
    /// Per-key sliding-window rate limiter (always populated).
    pub rate_limiter: SlidingWindowLimiter,
    /// In-process broadcast bus for `subscribeRepos` low-latency
    /// fan-out. The durable per-actor outbox remains the source of truth;
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
    /// `atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS` (3h);
    /// operators tighten/loosen via `PDS_SPACE_CREDENTIAL_TTL_SECONDS`.
    pub space_credential_ttl_secs: u64,
    /// Allowed handle suffix domains. Empty means
    /// any handle is accepted (back-compat). Set via
    /// `PDS_SERVICE_HANDLE_DOMAINS`.
    pub service_handle_domains: Vec<String>,
    /// Whether to send a notification email on space membership changes
    /// Set via `PDS_NOTIFY_MEMBERSHIP_EMAIL`.
    pub notify_membership_email: bool,
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
            oauth: OAuthState::new(),
            admin_password: None,
            space_service: None,
            space_writer: None,
            space_reader: None,
            space_sync: None,
            plc_service: None,
            jti_guard: JtiReplayGuard::new(100_000),
            rate_limiter: SlidingWindowLimiter::new(300, Duration::from_secs(60), 100_000),
            event_bus: EventBus::default(),
            pds_signing_key: None,
            email: EmailService::default(),
            dns_resolver: None,
            report_service_did: None,
            report_service_url: None,
            public_realm_backend: None,
            oauth_access_ttl_secs: crate::oauth::state::DEFAULT_ACCESS_TTL_SECS,
            oauth_refresh_ttl_secs: crate::oauth::state::DEFAULT_REFRESH_TTL_SECS,
            pds_extra_signing_keys: Vec::new(),
            space_credential_ttl_secs: atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
            service_handle_domains: Vec::new(),
            notify_membership_email: false,
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
            oauth: OAuthState::new(),
            admin_password: None,
            space_service: None,
            space_writer: None,
            space_reader: None,
            space_sync: None,
            plc_service: None,
            jti_guard: JtiReplayGuard::new(100_000),
            rate_limiter: SlidingWindowLimiter::new(300, Duration::from_secs(60), 100_000),
            event_bus: EventBus::default(),
            pds_signing_key: None,
            email: EmailService::default(),
            dns_resolver: None,
            report_service_did: None,
            report_service_url: None,
            public_realm_backend: None,
            oauth_access_ttl_secs: crate::oauth::state::DEFAULT_ACCESS_TTL_SECS,
            oauth_refresh_ttl_secs: crate::oauth::state::DEFAULT_REFRESH_TTL_SECS,
            pds_extra_signing_keys: Vec::new(),
            space_credential_ttl_secs: atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
            service_handle_domains: Vec::new(),
            notify_membership_email: false,
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
    pub fn with_email_service(mut self, email: EmailService) -> Self {
        self.email = email;
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
    #[must_use]
    pub fn with_space_credential_ttl(mut self, ttl_secs: u64) -> Self {
        self.space_credential_ttl_secs = ttl_secs;
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

    /// Enable membership-change email notifications.
    #[must_use]
    pub fn with_notify_membership_email(mut self, enabled: bool) -> Self {
        self.notify_membership_email = enabled;
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
