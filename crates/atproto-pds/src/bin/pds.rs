//! `pds` — the AT Protocol Personal Data Server binary.
//!
//! Wires the full atproto-pds surface: accounts DB, per-actor stores, the
//! repo reader/writer, the OAuth provider, the Spaces stack, the PLC
//! genesis service, the broadcast event bus, and the production-hardening
//! primitives (JTI replay guard + sliding-window rate limiter). Drains
//! gracefully on SIGTERM/SIGINT.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::actor_store::StorageProfile;
use atproto_pds::config::{StartupConfig, validate_production_safety};
use atproto_pds::email::EmailService;
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{FileKeyStore, KeyStore};
use atproto_pds::notifier::Notifier;
use atproto_pds::oauth::state::OAuthState;
use atproto_pds::plc::{PlcConfig, PlcService};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::shutdown::ShutdownController;
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_pds::{BUILD_REV, CRATE_VERSION, user_agent};
use clap::Parser;
use sqlx::SqlitePool;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, instrument};

/// AT Protocol Personal Data Server.
#[derive(Parser, Debug)]
#[command(
    name = "pds",
    version,
    about = "AT Protocol Personal Data Server",
    long_about = "Single-binary AT Protocol PDS supporting public-realm CRUD, \
                  Sync 1.1 firehose, OAuth 2.1 (PAR + PKCE + DPoP), Spaces \
                  permissioned data, and account migration."
)]
struct Args {
    /// Optional config file path (env > --config > /etc/atproto-pds/config.toml > defaults).
    #[arg(long)]
    config: Option<PathBuf>,

    /// HTTP listen port (default 4800).
    #[arg(long, env = "PDS_PORT", default_value_t = 4800)]
    port: u16,

    /// HTTP listen address (default 127.0.0.1).
    #[arg(long, env = "PDS_BIND", default_value = "127.0.0.1")]
    bind: String,

    /// Data directory (default ./data).
    #[arg(long, env = "PDS_DATA_DIRECTORY", default_value = "./data")]
    data_dir: PathBuf,

    /// Log filter (e.g., "info,atproto_pds=debug").
    #[arg(long, env = "RUST_LOG", default_value = "info,atproto_pds=debug")]
    log: String,

    /// Service DID for this PDS (e.g., `did:web:pds.example.com`).
    #[arg(long, env = "PDS_SERVICE_DID", default_value = "did:web:localhost")]
    service_did: String,

    /// Public-facing hostname for service-endpoint construction (defaults
    /// derive from service_did when did:web).
    #[arg(long, env = "PDS_HOSTNAME")]
    hostname: Option<String>,

    /// HMAC secret for app-password sessions and OAuth tokens (>=32 bytes).
    #[arg(
        long,
        env = "PDS_JWT_SECRET",
        default_value = "dev-only-jwt-secret-32-bytes-min!"
    )]
    jwt_secret: String,

    /// Admin password for `com.atproto.admin.*` Basic-auth.
    #[arg(
        long,
        env = "PDS_ADMIN_PASSWORD",
        default_value = "admin-default-CHANGE-ME"
    )]
    admin_password: String,

    /// Whether `createAccount` requires an invite code.
    #[arg(long, env = "PDS_INVITE_REQUIRED", default_value_t = false)]
    invite_required: bool,

    /// PLC directory hostname (e.g., `plc.directory`). When unset, PLC genesis
    /// is disabled and `createAccount` requires a caller-supplied DID.
    #[arg(long, env = "PDS_DID_PLC_URL")]
    plc_directory: Option<String>,

    /// Refuse startup with development-default secrets. Set this in production.
    #[arg(long, env = "PDS_PRODUCTION", default_value_t = false)]
    production: bool,

    /// Spaces notifier worker tick interval in seconds. The worker drains
    /// pending `notify_attempt` rows on this cadence. Lower values mean
    /// faster delivery at the cost of more SQLite traffic on idle systems.
    #[arg(
        long,
        env = "PDS_NOTIFIER_INTERVAL_SECS",
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..=3600),
    )]
    notifier_interval_secs: u64,

    /// Account deletion-GC tick interval in seconds. The worker walks
    /// `deactivated` accounts whose `delete_after <= now` and transitions
    /// them to `Deleted`. Default 3600s (1h).
    #[arg(
        long,
        env = "PDS_ACCOUNT_GC_INTERVAL_SECS",
        default_value_t = 3600,
        value_parser = clap::value_parser!(u64).range(1..=86400),
    )]
    account_gc_interval_secs: u64,

    /// SMTP server URL for outbound email (lettre-style:
    /// `smtps://user:pass@host:port`). Unset means email is disabled and
    /// confirmation URLs are logged at INFO instead.
    #[arg(long, env = "PDS_EMAIL_SMTP_URL")]
    smtp_url: Option<String>,

    /// `From:` address for outbound email. Required when `--smtp-url` is
    /// set; ignored otherwise.
    #[arg(long, env = "PDS_EMAIL_FROM_ADDRESS")]
    email_from_address: Option<String>,

    /// Durability profile for the JTI replay guard + sliding-window rate
    /// limiter. `memory` (default) keeps both in
    /// process — fast but loses state on restart. `sql` persists both to
    /// the accounts DB so OAuth refresh-rotation JTIs survive restart.
    #[arg(
        long,
        env = "PDS_DURABILITY_PROFILE",
        default_value = "memory",
        value_parser = ["memory", "sql"],
    )]
    durability_profile: String,

    /// Unified GC tick interval in seconds. The GC
    /// loop prunes notify_attempt, email_token, service_auth_blacklist,
    /// oauth_par/oauth_code, jti_replay, and rate_limit_window rows past
    /// their retention. Default 86400s (1 day).
    #[arg(
        long,
        env = "PDS_GC_INTERVAL_SECS",
        default_value_t = 86400,
        value_parser = clap::value_parser!(u64).range(60..=604800),
    )]
    gc_interval_secs: u64,

    /// Audience DID of the moderation report service. When set alongside
    /// `--report-service-url`, `com.atproto.moderation.createReport`
    /// forwards user reports to that service with a service-auth bearer
    /// Without these, the route returns
    /// `503 ModerationServiceUnavailable`.
    #[arg(long, env = "PDS_REPORT_SERVICE_DID")]
    report_service_did: Option<String>,

    /// Base URL of the moderation report service (e.g.
    /// `https://mod.example`). The handler POSTs to
    /// `<url>/xrpc/com.atproto.moderation.createReport`. See
    /// `--report-service-did`.
    #[arg(long, env = "PDS_REPORT_SERVICE_URL")]
    report_service_url: Option<String>,

    /// OAuth access-token TTL in seconds. Default
    /// 900 (15 minutes); operators tighten for higher-security deployments.
    #[arg(
        long,
        env = "PDS_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
        default_value_t = 900,
        value_parser = clap::value_parser!(u64).range(60..=86400),
    )]
    oauth_access_token_ttl_seconds: u64,

    /// OAuth refresh-token TTL in seconds. Default
    /// 2_592_000 (30 days); operators may shorten for tighter session
    /// lifetimes.
    #[arg(
        long,
        env = "PDS_OAUTH_REFRESH_TOKEN_TTL_SECONDS",
        default_value_t = 2_592_000,
        value_parser = clap::value_parser!(u64).range(60..=31_536_000),
    )]
    oauth_refresh_token_ttl_seconds: u64,

    /// Retention window in days for `space_record_oplog` +
    /// `space_member_oplog` rows. The unified GC
    /// loop walks each per-actor store on each tick and prunes oplog
    /// rows whose TID sorts below the cutoff. `0` disables the sweep.
    /// Receivers that lag behind this window must re-sync via
    /// `getRepoState`.
    #[arg(
        long,
        env = "PDS_SPACE_OPLOG_RETENTION_DAYS",
        default_value_t = 30,
        value_parser = clap::value_parser!(i64).range(0..=3650),
    )]
    space_oplog_retention_days: i64,

    /// Notifier retry initial backoff in milliseconds.
    /// Default 1000 (1s). Doubles per retry up to `max_attempts`.
    #[arg(
        long,
        env = "PDS_SPACE_NOTIFY_RETRY_INITIAL_BACKOFF_MS",
        default_value_t = 1000,
        value_parser = clap::value_parser!(u64).range(50..=600_000),
    )]
    space_notify_retry_initial_backoff_ms: u64,

    /// Notifier maximum attempts before marking a delivery failed
    /// Default 8 (≈ 4 min total backoff).
    #[arg(
        long,
        env = "PDS_SPACE_NOTIFY_RETRY_MAX_ATTEMPTS",
        default_value_t = 8,
        value_parser = clap::value_parser!(u32).range(1..=32),
    )]
    space_notify_retry_max_attempts: u32,

    /// SpaceCredential TTL in seconds. Default
    /// 7200 (2h, matching `atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS`).
    #[arg(
        long,
        env = "PDS_SPACE_CREDENTIAL_TTL_SECONDS",
        default_value_t = atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
        value_parser = clap::value_parser!(u64).range(60..=86_400),
    )]
    space_credential_ttl_seconds: u64,

    /// Comma-separated list of allowed handle suffix domains (REMAINING-
    /// WORK §11e). When set, `createAccount` rejects handles whose
    /// suffix isn't in the list. Empty (default) means any handle is
    /// accepted (back-compat for dev / test deployments).
    #[arg(long, env = "PDS_SERVICE_HANDLE_DOMAINS", value_delimiter = ',')]
    service_handle_domains: Vec<String>,

    /// Comma-separated list of crawler hostnames to notify via
    /// `com.atproto.sync.requestCrawl`. Each
    /// entry is a base URL like `https://relay.example`. The handler
    /// accepts the crawler's name in the request body and POSTs the
    /// PDS's hostname back to it so it starts subscribing to the
    /// firehose.
    #[arg(long, env = "PDS_CRAWLERS", value_delimiter = ',')]
    crawlers: Vec<String>,

    /// AppView DID for `app.bsky.*` request proxying.
    /// When both `--bsky-app-view-did` and `--bsky-app-view-url` are set,
    /// the PDS proxies inbound `app.bsky.*` XRPC calls to that AppView
    /// (with a service-auth bearer scoped to the caller). Clients can
    /// override per-request via the `Atproto-Proxy: <did>#<service-id>`
    /// header.
    #[arg(long, env = "PDS_BSKY_APP_VIEW_DID")]
    bsky_app_view_did: Option<String>,

    /// AppView base URL (e.g. `https://api.bsky.app`). The proxy POSTs
    /// to `<url>/xrpc/<lxm>`. See `--bsky-app-view-did`.
    #[arg(long, env = "PDS_BSKY_APP_VIEW_URL")]
    bsky_app_view_url: Option<String>,

    /// PLC rotation key — externally supplied. When
    /// set, the PDS uses this key (instead of generating one) for new
    /// PLC operations on accounts that opt into PDS-managed rotation.
    /// Format: `did:key:<multibase>` for the public form, plus the
    /// matching private bytes encoded as base64url at
    /// `--plc-rotation-key-private`. K-256 + P-256 are accepted.
    #[arg(long, env = "PDS_PLC_ROTATION_KEY_DID_KEY")]
    plc_rotation_key_did_key: Option<String>,

    /// PLC rotation key — private form, base64url-encoded. Required when
    /// `--plc-rotation-key-did-key` is set.
    #[arg(long, env = "PDS_PLC_ROTATION_KEY_PRIVATE")]
    plc_rotation_key_private: Option<String>,

    /// JWK Set in JSON form for the PDS OAuth signing keys
    /// When set, the PDS publishes every key on
    /// `/oauth/jwks` and signs with the most-recent (last) entry. Format:
    /// `{"keys": [<jwk>, ...]}` per RFC 7517.
    #[arg(long, env = "PDS_OAUTH_KEYS_JWK_SET")]
    oauth_keys_jwk_set: Option<String>,

    /// OTLP collector endpoint. When the `otel`
    /// feature is compiled in and this URL is set, the tracing
    /// subscriber attaches an OTLP HTTP exporter so spans + events flow
    /// to the collector at this address. When unset (or the feature is
    /// off), the export layer is omitted.
    #[arg(long, env = "PDS_OTEL_ENDPOINT")]
    otel_endpoint: Option<String>,

    /// Bind address for the Prometheus metrics endpoint
    /// When the `metrics` feature is compiled in
    /// and this address is set, the PDS exposes `GET /metrics` on the
    /// main HTTP listener and an axum middleware records request
    /// counters + status code histograms. When unset (or the feature is
    /// off), the endpoint is not mounted.
    #[arg(long, env = "PDS_METRICS_BIND")]
    metrics_bind: Option<String>,

    /// Valkey/Redis URL for durable JTI replay + rate-limit storage
    /// When the `valkey` feature is compiled in
    /// and this URL is set, both subsystems use the configured
    /// instance instead of the SQL-backed defaults.
    #[arg(long, env = "PDS_VALKEY_URL")]
    valkey_url: Option<String>,

    /// Key-prefix on Valkey/Redis keys (default `atproto-pds:`).
    #[arg(long, env = "PDS_VALKEY_KEY_PREFIX", default_value = "atproto-pds:")]
    valkey_key_prefix: String,

    /// Blob-store URL — when prefixed with `s3://<bucket>` (and the
    /// `s3` feature is compiled in), the binary uses an
    /// AWS-SDK-backed `S3BlobStore` instead of the per-actor SQLite
    /// blob tables. AWS credentials follow the standard SDK
    /// resolution order (env vars, profile, IMDS).
    #[arg(long, env = "PDS_BLOB_STORE_URL")]
    blob_store_url: Option<String>,

    /// PostgreSQL DSN for the accounts directory. When the `postgres` feature is compiled in and this
    /// URL is set, the PDS routes every accounts-DB call site through
    /// the runtime-dispatch [`atproto_pds::account::AccountPool`] enum against the supplied
    /// pool. Per-actor stores remain SQLite-or-fjall regardless.
    #[arg(long, env = "PDS_POSTGRES_URL")]
    postgres_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(&args.log, args.otel_endpoint.as_deref());

    info!(
        version = CRATE_VERSION,
        build_rev = BUILD_REV,
        user_agent = %user_agent(),
        data_dir = %args.data_dir.display(),
        service_did = %args.service_did,
        invite_required = args.invite_required,
        plc_directory = ?args.plc_directory,
        production = args.production,
        "atproto-pds starting"
    );

    // Production-safety gate: refuse to boot with dev-sentinel secrets when
    // PDS_PRODUCTION=true. See.
    let startup = StartupConfig {
        production: args.production,
        jwt_secret: args.jwt_secret.clone(),
        admin_password: args.admin_password.clone(),
        service_did: args.service_did.clone(),
    };
    validate_production_safety(&startup).map_err(|e| {
        error!(error = ?e, "startup config rejected");
        anyhow::anyhow!("{e}")
    })?;

    // §1.1: validate `PDS_STORAGE_PROFILE` against the compiled-in storage
    // backend. Fail fast on mismatch so an operator who set
    // PDS_STORAGE_PROFILE=fjall but installed the SQLite binary (or vice
    // versa) sees the conflict at startup rather than discovering it
    // later via missing data on disk.
    let storage_profile = StorageProfile::from_env().map_err(|e| {
        error!(error = ?e, "PDS_STORAGE_PROFILE rejected");
        anyhow::anyhow!("{e}")
    })?;
    info!(
        profile = storage_profile.as_str(),
        "storage profile resolved"
    );
    // §1.2: open the storage backend up-front so I/O issues surface at
    // startup, and capture a `PublicRealmBackend` dispatcher that routes
    // refactored call sites (currently the blob layer) through the
    // chosen backend. The legacy SQLite-direct paths in
    // RepoReader/Writer/OutboxReader continue to work alongside the
    // dispatch — the §1.2 part 2 refactor is incremental.
    let public_realm_backend = match storage_profile {
        StorageProfile::Sqlite => {
            atproto_pds::actor_store::PublicRealmBackend::sql(args.data_dir.clone())
        }
        #[cfg(feature = "fjall")]
        StorageProfile::Fjall => {
            let fjall_root = args.data_dir.join("fjall");
            std::fs::create_dir_all(&fjall_root).map_err(|e| {
                anyhow::anyhow!("create fjall data dir {}: {e}", fjall_root.display())
            })?;
            let store = atproto_pds::actor_store::fjall::FjallActorStore::open(&fjall_root)
                .map_err(|e| {
                    error!(error = ?e, path = %fjall_root.display(), "open FjallActorStore");
                    anyhow::anyhow!("open FjallActorStore: {e}")
                })?;
            tracing::info!(
                path = %fjall_root.display(),
                "fjall storage profile active — refactored call sites (blobs) dispatch through fjall"
            );
            atproto_pds::actor_store::PublicRealmBackend::fjall(store)
        }
        #[cfg(not(feature = "fjall"))]
        StorageProfile::Fjall => {
            return Err(anyhow::anyhow!(
                "PDS_STORAGE_PROFILE=fjall requires building with --features fjall"
            ));
        }
    };
    info!(
        backend = public_realm_backend.backend_label,
        "public-realm storage backend wired"
    );

    // Open the accounts DB.
    let accounts_path = args.data_dir.join("accounts.sqlite");
    let accounts = AccountDirectory::open(&accounts_path).await.map_err(|e| {
        error!(error = ?e, path = %accounts_path.display(), "open accounts DB");
        anyhow::anyhow!("open accounts DB: {e}")
    })?;
    info!(path = %accounts_path.display(), "accounts DB ready");

    // KeyStore + AccountManager.
    let keys_dir = args.data_dir.join("keys");
    let key_store: Arc<dyn KeyStore> = Arc::new(FileKeyStore::new(keys_dir));
    let account_manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        args.data_dir.clone(),
        key_store.clone(),
        KeyType::K256Private,
    ));

    // RepoWriter + RepoReader. The writer goes through `with_backend`
    // so its atomic-commit lockstep dispatches via the trait surface
    // — fjall + sqlite both
    // route through `AtomicCommitWriter::apply_atomic_commit`.
    let writer = Arc::new(RepoWriter::with_backend(
        account_manager.clone(),
        args.data_dir.clone(),
        Arc::new(public_realm_backend.clone()),
    ));
    let reader = Arc::new(RepoReader::with_backend(
        accounts,
        args.data_dir.clone(),
        Arc::new(public_realm_backend.clone()),
    ));

    // Spaces wiring (always enabled at this build — gated by
    // service-availability checks at the HTTP layer for individual endpoints).
    let space_service = Arc::new(SpaceService::with_accounts(
        args.data_dir.clone(),
        account_manager.clone(),
    ));
    let space_writer = Arc::new(
        SpaceWriter::new(account_manager.clone(), args.data_dir.clone())
            .with_plc_directory(args.plc_directory.clone()),
    );
    let space_reader = Arc::new(SpaceReader::new(
        account_manager.clone(),
        args.data_dir.clone(),
    ));
    let space_sync = Arc::new(SpaceSync::new(args.data_dir.clone()));

    // §11d — externally-supplied PLC rotation key (optional).
    let external_plc_key = parse_external_plc_rotation_key(
        args.plc_rotation_key_did_key.as_deref(),
        args.plc_rotation_key_private.as_deref(),
    )?;
    if external_plc_key.is_some() {
        info!("externally-supplied PLC rotation key loaded — included in every genesis op");
    }

    // PLC genesis service. Constructed when a PLC directory is configured;
    // otherwise `createAccount` requires a caller-supplied DID.
    let plc_service = if let Some(directory) = args.plc_directory.as_deref() {
        let endpoint = service_endpoint_url(&args.hostname, &args.service_did);
        info!(
            directory,
            endpoint, "PlcService configured for createAccount"
        );
        let mut config = PlcConfig::new(directory.to_string(), args.service_did.clone(), endpoint);
        if let Some(k) = external_plc_key.clone() {
            config = config.with_rotation_key(k);
        }
        Some(Arc::new(PlcService::new(config, key_store)))
    } else {
        info!("PlcService disabled (PDS_DID_PLC_URL unset)");
        None
    };

    // PDS-level signing key for federation (JWKS publication). Either reuse
    // a pre-existing key in the KeyStore (label `__pds_oauth__`) or generate
    // a P-256 key on first boot and persist it.
    let pds_signing_key = load_or_create_pds_signing_key(&account_manager).await?;

    // §10.3 — when an operator supplies a JWK set via env, the first
    // entry is the *current* signer (overrides the load_or_create
    // default) and the rest are historical rotations published in
    // `/oauth/jwks` so consumers verifying older tokens still find them.
    let (current_signing_key, extra_signing_keys): (
        atproto_identity::key::KeyData,
        Vec<Arc<atproto_identity::key::KeyData>>,
    ) = match args.oauth_keys_jwk_set.as_deref() {
        None => (pds_signing_key, Vec::new()),
        Some(raw) => {
            let mut parsed = parse_jwk_set_env(raw)?;
            if parsed.is_empty() {
                (pds_signing_key, Vec::new())
            } else {
                let head = parsed.remove(0);
                let tail: Vec<Arc<atproto_identity::key::KeyData>> =
                    parsed.into_iter().map(Arc::new).collect();
                info!(
                    extras = tail.len(),
                    "PDS_OAUTH_KEYS_JWK_SET parsed; current + historical signers wired"
                );
                (head, tail)
            }
        }
    };

    // Outbound email — SMTP-backed when both URL + from-address are set
    // and the `smtp` feature is enabled at compile time; otherwise the
    // disabled stub that logs the confirmation URL at INFO.
    let email_service =
        EmailService::from_env(args.smtp_url.as_deref(), args.email_from_address.as_deref())?;

    // §6.1 + §6.2: select durable backends for the JTI replay guard +
    // sliding-window rate limiter when `PDS_DURABILITY_PROFILE=sql`.
    // §5.2: when `valkey` is on AND `PDS_VALKEY_URL` is set, the
    // Valkey/Redis backend wins regardless of `--durability-profile`.
    // Memory is the default for backwards compatibility — operators who
    // need restart-survival opt in.
    let (jti_guard, rate_limiter) = {
        // §5.2 valkey precedence: if the feature is compiled and an URL
        // is configured, prefer it over SQL/memory. Off-feature builds
        // collapse this branch to a no-op.
        #[cfg(feature = "valkey")]
        {
            if let Some(ref url) = args.valkey_url
                && !url.trim().is_empty()
            {
                info!(url = %url, prefix = %args.valkey_key_prefix, "durability profile: valkey");
                let client = atproto_pds::valkey_backend::ValkeyClient::connect(
                    url,
                    &args.valkey_key_prefix,
                )
                .await?;
                (
                    atproto_pds::security::JtiReplayGuard::new_valkey(client.clone()),
                    atproto_pds::security::SlidingWindowLimiter::new_valkey(
                        client,
                        300,
                        Duration::from_secs(60),
                    ),
                )
            } else {
                durability_profile_sql_or_memory(&args, account_manager.pool().clone())
            }
        }
        #[cfg(not(feature = "valkey"))]
        {
            durability_profile_sql_or_memory(&args, account_manager.pool().clone())
        }
    };

    // §8.1: DNS resolver for `resolveHandle` dual lookup. The hickory-dns
    // feature is in default; the resolver uses the system nameservers.
    #[cfg(feature = "hickory-dns")]
    let dns_resolver: Arc<dyn atproto_identity::traits::DnsResolver> = {
        let resolver = atproto_identity::resolve::HickoryDnsResolver::create_resolver(&[]);
        info!("DNS resolver: HickoryDnsResolver (system nameservers)");
        Arc::new(resolver)
    };

    let mut state = HttpState::with_account_manager(
        reader,
        account_manager.clone(),
        args.service_did.clone(),
        args.jwt_secret.into_bytes(),
        args.invite_required,
    )
    .with_writer(writer)
    .with_spaces(space_service, space_writer, space_reader, space_sync)
    .with_admin_password(args.admin_password)
    .with_pds_signing_key(Arc::new(current_signing_key))
    .with_extra_signing_keys(extra_signing_keys)
    .with_oauth_access_ttl(args.oauth_access_token_ttl_seconds)
    .with_oauth_refresh_ttl(args.oauth_refresh_token_ttl_seconds)
    .with_email_service(email_service)
    .with_jti_guard(jti_guard.clone())
    .with_rate_limiter(rate_limiter.clone())
    .with_public_realm_backend(public_realm_backend.clone())
    .with_space_credential_ttl(args.space_credential_ttl_seconds)
    .with_service_handle_domains(args.service_handle_domains.clone())
    .with_crawlers(args.crawlers.clone())
    // Persist OAuth in-flight state (PAR / auth-codes / refresh handles)
    // to the accounts DB so the lifecycle survives PDS restart. See
    // for the gap this closes.
    .with_oauth_state(OAuthState::sql(account_manager.pool().clone()));
    if let (Some(did), Some(url)) = (
        args.bsky_app_view_did.as_deref(),
        args.bsky_app_view_url.as_deref(),
    ) {
        info!(
            did,
            url, "Atproto-Proxy default: app.bsky.* pinned to AppView"
        );
        state = state.with_bsky_app_view(did.to_string(), url.to_string());
    }
    if let Some(plc) = plc_service {
        state = state.with_plc_service(plc);
    }
    #[cfg(feature = "hickory-dns")]
    {
        // Space-type declaration resolver (NSID → declared `collections`) for
        // the bare `space:` grant default (spec line 413). Reuses the same
        // DNS resolver + PLC hostname as handle resolution; results are
        // TTL-cached to avoid resolving on every authorization check.
        let plc_hostname = args
            .plc_directory
            .as_deref()
            .and_then(|url| url.split("://").nth(1).map(|h| h.to_string()))
            .unwrap_or_else(|| "plc.directory".to_string());
        let decl_http = reqwest::Client::builder()
            .user_agent(user_agent())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let network = atproto_pds::space::NetworkSpaceDeclarationResolver::new(
            dns_resolver.clone(),
            plc_hostname,
            decl_http,
        );
        let cached = atproto_pds::space::CachingSpaceDeclarationResolver::new(
            Arc::new(network),
            std::time::Duration::from_secs(300),
        );
        state = state.with_space_declaration_resolver(Arc::new(cached));
        state = state.with_dns_resolver(dns_resolver);
    }
    if let (Some(did), Some(url)) = (
        args.report_service_did.as_deref(),
        args.report_service_url.as_deref(),
    ) {
        info!(
            report_service_did = did,
            report_service_url = url,
            "moderation report forwarding configured"
        );
        state = state.with_report_service(did.to_string(), url.to_string());
    } else {
        info!(
            "moderation report forwarding disabled (PDS_REPORT_SERVICE_DID / _URL unset); createReport will return 503"
        );
    }

    // Capture the accounts pool *before* moving state into the router; the
    // notifier task needs an independent handle.
    let notifier_pool = state
        .account_manager
        .as_ref()
        .expect("account_manager wired in startup")
        .pool()
        .clone();

    let app = build_router(state);

    // §5.1 metrics — when the feature is on AND `--metrics-bind` is
    // set, mount `/metrics` + the request-counter middleware. The
    // off-feature `with_metrics` is a no-op.
    #[cfg(feature = "metrics")]
    let app = if args.metrics_bind.is_some() {
        atproto_pds::http::router::with_metrics(app, atproto_pds::metrics::Metrics::new())
    } else {
        app
    };
    #[cfg(not(feature = "metrics"))]
    let app = atproto_pds::http::router::with_metrics(app, ());

    // Bind and serve.
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind addr: {e}"))?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "HTTP listening");

    // Wire shutdown.
    let ctrl = ShutdownController::new();
    let token = ctrl.token();
    let tracker = ctrl.tracker();
    tracker.spawn(heartbeat_loop(token.clone()));

    // Spaces notifier worker — drains the `notify_attempt` DLQ on a fixed
    // cadence. G8.
    let notifier_interval = Duration::from_secs(args.notifier_interval_secs);
    info!(
        interval_secs = args.notifier_interval_secs,
        "spawning Spaces notifier worker"
    );
    tracker.spawn(notifier_loop(
        notifier_pool.clone(),
        notifier_interval,
        args.space_notify_retry_initial_backoff_ms,
        args.space_notify_retry_max_attempts,
        token.clone(),
    ));

    // Account deletion-GC worker — walks `deactivated` accounts whose
    // `delete_after` has elapsed and transitions them to `deleted`. Per.
    let gc_account_manager = account_manager.clone();
    let gc_interval = Duration::from_secs(args.account_gc_interval_secs);
    info!(
        interval_secs = args.account_gc_interval_secs,
        "spawning account deletion-GC worker"
    );
    tracker.spawn(account_deletion_loop(
        gc_account_manager,
        gc_interval,
        token.clone(),
    ));

    // Unified GC loop — daily prune of
    // notify_attempt, email_token, service_auth_blacklist, oauth_par,
    // oauth_code, jti_replay, rate_limit_window past their retention.
    let unified_gc_pool = notifier_pool.clone();
    let unified_gc_jti = jti_guard.clone();
    let unified_gc_rate = rate_limiter.clone();
    let unified_gc_interval = Duration::from_secs(args.gc_interval_secs);
    info!(
        interval_secs = args.gc_interval_secs,
        "spawning unified GC worker"
    );
    tracker.spawn(unified_gc_loop(
        unified_gc_pool,
        unified_gc_jti,
        unified_gc_rate,
        args.data_dir.clone(),
        args.space_oplog_retention_days,
        unified_gc_interval,
        token.clone(),
    ));

    // Run axum with graceful shutdown.
    let shutdown_token = token.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_token.cancelled().await;
    });

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!(error = ?e, "HTTP server exited with error");
            }
        }
        signal_result = ctrl.wait_for_signal() => {
            if let Err(e) = signal_result {
                error!(error = ?e, "signal handler error");
            }
        }
    }

    info!("draining tasks");
    drop(token);
    drop(tracker);
    // §5.5 otel — flush pending OTLP spans before exit. No-op on
    // off-feature builds.
    atproto_pds::telemetry::shutdown();
    info!("shutdown complete");
    Ok(())
}

#[instrument(skip(token))]
async fn heartbeat_loop(token: tokio_util::sync::CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("heartbeat exiting");
                return;
            }
            _ = interval.tick() => {
                tracing::debug!("heartbeat");
            }
        }
    }
}

/// Account deletion-GC worker. Periodically walks accounts whose
/// `delete_after <= now` and transitions them from `deactivated` to
/// `deleted`.
///
/// State transitions are run through `AccountManager::set_state` so the
/// `#account` firehose event is emitted alongside the SQL update.
#[instrument(skip(manager, token), fields(interval_secs = interval.as_secs()))]
async fn account_deletion_loop(
    manager: Arc<AccountManager>,
    interval: Duration,
    token: tokio_util::sync::CancellationToken,
) {
    use atproto_pds::account::AccountState;

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick — same rationale as the notifier loop.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("account deletion-GC exiting");
                return;
            }
            _ = ticker.tick() => {
                // §5.4 — dispatch helper picks SQL dialect.
                let now = chrono::Utc::now().to_rfc3339();
                let dids = match manager.list_pending_deletions(&now).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = ?e, "deletion-GC: select failed");
                        continue;
                    }
                };
                if dids.is_empty() {
                    tracing::debug!("deletion-GC: no accounts due");
                    continue;
                }
                tracing::info!(count = dids.len(), "deletion-GC: processing accounts");
                for did in dids {
                    if let Err(e) = manager.set_state(&did, AccountState::Deleted).await {
                        tracing::warn!(did = %did, error = ?e, "deletion-GC: set_state failed");
                    } else {
                        tracing::info!(did = %did, "deletion-GC: account deleted");
                    }
                }
            }
        }
    }
}

/// Spaces notifier worker. Calls `Notifier::tick` on a fixed cadence until
/// the shutdown token fires. Each tick drains a bounded batch of due
/// `notify_attempt` rows; successful POSTs are marked `delivered`, transient
/// failures get retried with exponential backoff (see [`Notifier`] docs).
#[instrument(skip(pool, token), fields(interval_secs = interval.as_secs()))]
async fn notifier_loop(
    pool: SqlitePool,
    interval: Duration,
    initial_backoff_ms: u64,
    max_attempts: u32,
    token: tokio_util::sync::CancellationToken,
) {
    // §11g — retry knobs come from CLI/env; defaults match the constants
    // exposed on `Notifier::default()`.
    let notifier = Notifier {
        client: reqwest::Client::new(),
        initial_backoff_ms,
        max_attempts,
        batch_size: 50,
    };
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately — skip it so we don't hammer the DB on
    // boot before any rows could possibly exist.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("notifier worker exiting");
                return;
            }
            _ = ticker.tick() => {
                match notifier.tick(&pool).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(delivered = n, "notifier tick delivered batch"),
                    Err(e) => tracing::warn!(error = ?e, "notifier tick failed"),
                }
            }
        }
    }
}

/// Unified daily GC loop. Calls `gc::tick_with`
/// on a fixed cadence until the shutdown token fires. Each tick prunes:
///
/// - `notify_attempt` rows past delivered/failed retention.
/// - `email_token` past `expires_at`.
/// - `service_auth_blacklist` past `expires_at`.
/// - `oauth_par` + `oauth_code` past `expires_at`.
/// - `jti_replay` past `expires_at` (§6.1 SQL backend).
/// - `rate_limit_window` past `now - window` (§6.2 SQL backend).
/// - per-actor `space_record_oplog` + `space_member_oplog` past
///   `space_oplog_retention_days` (§11h).
///
/// Per-table failures are logged at WARN; the tick continues.
#[instrument(skip(pool, jti_guard, rate_limiter, token), fields(interval_secs = interval.as_secs()))]
async fn unified_gc_loop(
    pool: SqlitePool,
    jti_guard: atproto_pds::security::JtiReplayGuard,
    rate_limiter: atproto_pds::security::SlidingWindowLimiter,
    data_dir: PathBuf,
    space_oplog_retention_days: i64,
    interval: Duration,
    token: tokio_util::sync::CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately; skip it so we don't pile work on the
    // accounts pool right at boot.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("unified GC worker exiting");
                return;
            }
            _ = ticker.tick() => {
                let opts = atproto_pds::gc::TickOptions {
                    data_dir: Some(&data_dir),
                    space_oplog_retention_days,
                };
                let report = atproto_pds::gc::tick_with(&pool, &jti_guard, &rate_limiter, &opts).await;
                tracing::info!(
                    notify_delivered = report.notify_delivered,
                    notify_failed = report.notify_failed,
                    email_tokens = report.email_tokens,
                    service_auth_blacklist = report.service_auth_blacklist,
                    oauth_state = report.oauth_state,
                    jti_replay = report.jti_replay,
                    rate_limit_window = report.rate_limit_window,
                    space_oplog = report.space_oplog,
                    "unified GC tick complete"
                );
            }
        }
    }
}

/// Reuse the PDS-level signing key from the KeyStore (label `__pds_oauth__`)
/// or generate + persist a fresh P-256 key on first boot. Never panics; any
/// error is returned. Used to populate the `pds_signing_key` slot on
/// `HttpState` so `/oauth/jwks` publishes a real federation key.
async fn load_or_create_pds_signing_key(
    manager: &AccountManager,
) -> anyhow::Result<atproto_identity::key::KeyData> {
    use atproto_identity::key::{KeyType, generate_key};
    let label = "__pds_oauth__";
    if let Ok(existing) = manager.key_store().get(label).await {
        info!(label, "PDS signing key loaded from KeyStore");
        return Ok(existing);
    }
    let key = generate_key(KeyType::P256Private)
        .map_err(|e| anyhow::anyhow!("generate PDS signing key: {e}"))?;
    let key_ref = manager.key_store().put(&key).await?;
    info!(label, key_ref, "PDS signing key generated + persisted");
    Ok(key)
}

/// Derive a public service endpoint URL from `hostname` (when set) or by
/// stripping the `did:web:` prefix off the service DID. Returns
/// `http://<host>` for `localhost` and `https://<host>` otherwise.
fn service_endpoint_url(hostname: &Option<String>, service_did: &str) -> String {
    let host = hostname.clone().unwrap_or_else(|| {
        service_did
            .strip_prefix("did:web:")
            .unwrap_or("localhost")
            .to_string()
    });
    let scheme = if host.starts_with("localhost") || host.starts_with("127.") {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{host}")
}

/// Parse `PDS_OAUTH_KEYS_JWK_SET` into a vec of
/// `KeyData`. Format: standard JWKS `{"keys": [<jwk>, ...]}`. The first
/// entry is the *current* signer; subsequent entries are historical
/// rotations (kept in `/oauth/jwks` so consumers verifying older tokens
/// still find the matching `kid`). EC curves only (P-256 / P-384 /
/// secp256k1).
fn parse_jwk_set_env(raw: &str) -> anyhow::Result<Vec<atproto_identity::key::KeyData>> {
    use atproto_identity::key::{KeyData, KeyType};
    use elliptic_curve::JwkEcKey;
    use elliptic_curve::sec1::ToEncodedPoint;
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("parse JWK set JSON: {e}"))?;
    let keys = value
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("JWK set missing `keys` array"))?;
    let mut out: Vec<KeyData> = Vec::with_capacity(keys.len());
    for jwk in keys {
        let parsed: JwkEcKey = serde_json::from_value(jwk.clone())
            .map_err(|e| anyhow::anyhow!("parse JwkEcKey: {e}"))?;
        let has_private = jwk.get("d").is_some_and(|d| d.is_string());
        let kd = match (parsed.crv(), has_private) {
            ("P-256", true) => {
                let secret = p256::SecretKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("P-256 priv from jwk: {e}"))?;
                KeyData::new(KeyType::P256Private, secret.to_bytes().to_vec())
            }
            ("P-256", false) => {
                let pk = p256::PublicKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("P-256 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::P256Public,
                    pk.to_encoded_point(true).as_bytes().to_vec(),
                )
            }
            ("P-384", true) => {
                let secret = p384::SecretKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("P-384 priv from jwk: {e}"))?;
                KeyData::new(KeyType::P384Private, secret.to_bytes().to_vec())
            }
            ("P-384", false) => {
                let pk = p384::PublicKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("P-384 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::P384Public,
                    pk.to_encoded_point(true).as_bytes().to_vec(),
                )
            }
            ("secp256k1", true) => {
                let secret = k256::SecretKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("K-256 priv from jwk: {e}"))?;
                KeyData::new(KeyType::K256Private, secret.to_bytes().to_vec())
            }
            ("secp256k1", false) => {
                let pk = k256::PublicKey::from_jwk(&parsed)
                    .map_err(|e| anyhow::anyhow!("K-256 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::K256Public,
                    pk.to_encoded_point(true).as_bytes().to_vec(),
                )
            }
            (other, _) => return Err(anyhow::anyhow!("unsupported JWK curve {other}")),
        };
        out.push(kd);
    }
    if out.is_empty() {
        return Err(anyhow::anyhow!("JWK set is empty"));
    }
    Ok(out)
}

/// Parse the externally-supplied PLC rotation key
/// from the configured env vars. Returns `None` when neither is set,
/// `Err` when only one half is provided. The DID-key string identifies
/// the curve; the private bytes are base64url-decoded.
fn parse_external_plc_rotation_key(
    did_key: Option<&str>,
    private_b64: Option<&str>,
) -> anyhow::Result<Option<atproto_identity::key::KeyData>> {
    use atproto_identity::key::{KeyData, KeyType, identify_key};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    match (did_key, private_b64) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(anyhow::anyhow!(
            "PDS_PLC_ROTATION_KEY_DID_KEY and PDS_PLC_ROTATION_KEY_PRIVATE must both be set"
        )),
        (Some(did_key), Some(b64)) => {
            // Identify the public key from the DID-key form to learn the curve.
            let public = identify_key(did_key)
                .map_err(|e| anyhow::anyhow!("identify PLC rotation public key: {e}"))?;
            let priv_bytes = B64URL
                .decode(b64.as_bytes())
                .map_err(|e| anyhow::anyhow!("decode PLC rotation private bytes: {e}"))?;
            let priv_type = match public.key_type() {
                &KeyType::P256Public => KeyType::P256Private,
                &KeyType::P384Public => KeyType::P384Private,
                &KeyType::K256Public => KeyType::K256Private,
                other => {
                    return Err(anyhow::anyhow!(
                        "PLC rotation key must be P-256, P-384, or K-256; got {other:?}"
                    ));
                }
            };
            Ok(Some(KeyData::new(priv_type, priv_bytes)))
        }
    }
}

/// Select the SQL or memory durability profile for the JTI guard +
/// rate limiter. Factored out of `main`
/// so the §5.2 valkey precedence path can fall back to it when the
/// feature is on but no URL is configured.
fn durability_profile_sql_or_memory(
    args: &Args,
    pool: sqlx::SqlitePool,
) -> (
    atproto_pds::security::JtiReplayGuard,
    atproto_pds::security::SlidingWindowLimiter,
) {
    match args.durability_profile.as_str() {
        "sql" => {
            info!("durability profile: SQL (jti_replay + rate_limit_window persisted)");
            (
                atproto_pds::security::JtiReplayGuard::new_sql(pool.clone()),
                atproto_pds::security::SlidingWindowLimiter::new_sql(
                    pool,
                    300,
                    Duration::from_secs(60),
                ),
            )
        }
        _ => {
            info!("durability profile: memory (default; loses state on restart)");
            (
                atproto_pds::security::JtiReplayGuard::new(100_000),
                atproto_pds::security::SlidingWindowLimiter::new(
                    300,
                    Duration::from_secs(60),
                    100_000,
                ),
            )
        }
    }
}

fn init_tracing(filter: &str, otel_endpoint: Option<&str>) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};
    let env_filter =
        EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info,atproto_pds=debug"));
    // The OTLP layer is gated behind the `otel` feature — `init_otlp_layer`
    // returns `None` on off-feature builds, leaving the registry unchanged.
    let otel_layer = otel_endpoint
        .filter(|e| !e.trim().is_empty())
        .and_then(|endpoint| atproto_pds::telemetry::init_otlp_layer(endpoint, "atproto-pds"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true))
        .with(otel_layer)
        .init();
}
