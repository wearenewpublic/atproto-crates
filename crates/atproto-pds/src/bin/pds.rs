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
use atproto_pds::repo::lexicon::LexiconResolver as _;
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
use tracing::{error, info, instrument, warn};

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
    ///
    /// The default is the dev sentinel `validate_production_safety` refuses, so
    /// it is named from `config` rather than written out a second time: two
    /// copies of the same literal, one the gate matches on, is a gate that stops
    /// working the moment somebody edits the other.
    #[arg(
        long,
        env = "PDS_JWT_SECRET",
        default_value = atproto_pds::config::DEV_SENTINEL_JWT_SECRET
    )]
    jwt_secret: String,

    /// Admin password for `com.atproto.admin.*` Basic-auth.
    ///
    /// Also the dev sentinel; see `jwt_secret`.
    #[arg(
        long,
        env = "PDS_ADMIN_PASSWORD",
        default_value = atproto_pds::config::DEV_SENTINEL_ADMIN_PASSWORD
    )]
    admin_password: String,

    /// Whether `createAccount` requires an invite code.
    #[arg(long, env = "PDS_INVITE_REQUIRED", default_value_t = false)]
    invite_required: bool,

    /// DIDs granted administrative authority on this server.
    ///
    /// An alternative to `--admin-password` for the endpoints that accept one.
    /// The holder proves control by signing an inter-service auth token with
    /// the `#atproto` key in their own DID document, so the request says who
    /// made it -- which a shared password cannot -- and authority is withdrawn
    /// by editing this list rather than rotating a secret every holder has a
    /// copy of.
    ///
    /// The identity does not need an account on this server. A code minted by
    /// one that has none is attributed to nobody.
    #[arg(long, env = "PDS_ADMIN_DIDS", value_delimiter = ',')]
    admin_dids: Vec<String>,

    /// Identifier of the policy document set new accounts must accept.
    ///
    /// Recorded verbatim in the `com.atproto-crates.pds.policyAcceptance`
    /// record written to the account's own repository. A dated content hash
    /// -- `2026-08-05-bafkrei...` -- names an immutable set, so revising the
    /// documents yields a different identifier and a fresh acceptance rather
    /// than silently re-pointing an old one.
    ///
    /// Takes effect only alongside `--policy-url`: an identifier with nothing
    /// to read is an agreement to something the holder was never shown.
    #[arg(long, env = "PDS_POLICY_SET_ID")]
    policy_set_id: Option<String>,

    /// Where the policy documents are published.
    ///
    /// Shown to the holder before they agree, and recorded next to the
    /// identifier because the identifier alone does not say what was read.
    #[arg(long, env = "PDS_POLICY_URL")]
    policy_url: Option<String>,

    /// PLC directory hostname (e.g., `plc.directory`). When unset, PLC genesis
    /// is disabled and `createAccount` requires a caller-supplied DID.
    #[arg(long, env = "PDS_DID_PLC_URL")]
    plc_directory: Option<String>,

    /// Permit the development-default admin password. Without this the PDS
    /// refuses to start when `PDS_ADMIN_PASSWORD` is the sentinel, because
    /// that value is a constant in this crate and therefore public. Set it
    /// only for a deployment nobody else can reach.
    #[arg(long, env = "PDS_ALLOW_DEV_DEFAULTS", default_value_t = false)]
    allow_dev_defaults: bool,

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

    /// Requests per window allowed from one client address on ordinary
    /// routes. `0` disables the global tier.
    ///
    /// 3000 over the default 300s window is 600/minute, matching the
    /// reference's `global-ip` bucket (3000 points per 5 minutes,
    /// packages/pds/src/rate-limits.ts).
    ///
    /// The previous default of 300 per 60s was half that rate, and measurably
    /// too low for a real client: the official Bluesky app polls
    /// `getTrends`, `getPreferences`, `getProfile`, `getUnreadCounts`,
    /// `getDrafts` and `getSession` on a ~2s cycle, which is ~180 requests a
    /// minute from a single idle signed-in tab. Every proxied `app.bsky.*`
    /// call is counted here too, because this server forwards them rather
    /// than the client reaching an AppView directly. One user browsing
    /// normally saturated the bucket and the client degraded to constant
    /// failure.
    #[arg(long, env = "PDS_RATE_LIMIT", default_value_t = 3000)]
    rate_limit: usize,

    /// Requests per window allowed from one client address on the
    /// authentication and account-creation endpoints. Tighter than the global
    /// tier: a hundred `getRecord` calls a minute is a busy client, a hundred
    /// `createSession` calls a minute is someone guessing. `0` disables it.
    /// 150 over the default 300s window preserves the previous effective rate
    /// of 30/minute; only the window changed.
    #[arg(long, env = "PDS_RATE_LIMIT_AUTH", default_value_t = 150)]
    rate_limit_auth: usize,

    /// Sliding-window length in seconds for both rate-limit tiers.
    #[arg(long, env = "PDS_RATE_LIMIT_WINDOW_SECS", default_value_t = 300)]
    rate_limit_window_secs: u64,

    /// Client addresses exempt from rate limiting — a relay, an AppView, a
    /// backfill job. Comma-separated. Without this an operator has to choose
    /// between limiting attackers and letting their own infrastructure work.
    #[arg(long, env = "PDS_RATE_LIMIT_BYPASS_IPS", value_delimiter = ',')]
    rate_limit_bypass_ips: Vec<String>,

    /// How many trusted reverse proxies sit in front of this server.
    ///
    /// `0` (default) uses the TCP peer address and ignores
    /// `X-Forwarded-For` entirely — a header any client can set is not an
    /// identity. Set this to the number of proxies you operate and the client
    /// address is taken that many entries from the right of the header.
    #[arg(long, env = "PDS_TRUSTED_PROXY_HOPS", default_value_t = 0)]
    trusted_proxy_hops: usize,

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

    /// Largest blob `uploadBlob` accepts, in bytes. Default 16 MiB.
    /// Raise it for video, lower it for abuse control. Previously a
    /// compile-time constant that axum's 2 MiB body default pre-empted, so
    /// neither the number nor the operator had any say.
    #[arg(
        long,
        env = "PDS_BLOB_UPLOAD_LIMIT",
        default_value_t = atproto_pds::blob::DEFAULT_BLOB_UPLOAD_LIMIT_BYTES,
        value_parser = clap::value_parser!(usize),
    )]
    blob_upload_limit: usize,

    /// Largest repository CAR `importRepo` accepts, in bytes. Default 1 GiB,
    /// matching what the README tells operators to size their proxy for.
    #[arg(
        long,
        env = "PDS_IMPORT_LIMIT",
        default_value_t = atproto_pds::http::state::DEFAULT_IMPORT_LIMIT_BYTES,
        value_parser = clap::value_parser!(usize),
    )]
    import_limit: usize,

    /// How long one `subscribeRepos` frame may take to reach a consumer
    /// before the subscription is closed with `ConsumerTooSlow`. Default 60
    /// seconds; `0` restores the unbounded await.
    #[arg(
        long,
        env = "PDS_FIREHOSE_SEND_TIMEOUT",
        default_value_t = atproto_pds::http::state::DEFAULT_FIREHOSE_SEND_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64),
    )]
    firehose_send_timeout: u64,

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

    /// How long an unreferenced blob is kept before the unified GC deletes
    /// its bytes, in hours. Default 24. `0` disables the sweep, which
    /// means blob storage grows without bound.
    ///
    /// A blob is legitimately unreferenced for a while: `uploadBlob` stores
    /// bytes before any record names them, and an update that keeps the same
    /// image drops the old references and adds the new ones as two steps. The
    /// window has to outlast both, and a day does so comfortably.
    #[arg(
        long,
        env = "PDS_BLOB_GRACE_HOURS",
        default_value_t = 24,
        value_parser = clap::value_parser!(i64).range(0..=8760),
    )]
    blob_grace_hours: i64,

    /// How long the firehose log keeps an event, in hours. Default 72. `0`
    /// disables the sweep, which means the log grows without bound.
    ///
    /// Every event is a second copy of a record, as a DAG-CBOR CAR, in the
    /// shared accounts database -- so this is not one account's storage that
    /// fills but the database sessions, OAuth and the sequencer all live in.
    ///
    /// The window exists so a relay or AppView that falls over can reconnect
    /// and resume rather than backfilling from `getRepo`. Three days covers a
    /// weekend outage. A consumer that lags further gets `OutdatedCursor` and
    /// re-syncs, which is the documented path and not a failure.
    ///
    /// The newest event is never deleted regardless of age: it is what
    /// `subscribeRepos` compares a resume cursor against, and an empty log
    /// would make every valid cursor read as `FutureCursor`.
    #[arg(
        long,
        env = "PDS_STREAM_EVENT_RETENTION_HOURS",
        default_value_t = 72,
        value_parser = clap::value_parser!(i64).range(0..=8760),
    )]
    stream_event_retention_hours: i64,

    /// How long to wait for in-flight requests and background workers after a
    /// SIGTERM before exiting anyway. Default 25 seconds.
    ///
    /// This has to fit *inside* the supervisor's own grace period, not match
    /// it. A platform that sends SIGTERM and then SIGKILL 30 seconds later
    /// will kill the process at the exact moment a 30-second deadline
    /// expires -- losing both the "deadline elapsed" warning that says the
    /// drain failed and the telemetry flush that follows it. The five seconds
    /// of headroom buy those.
    #[arg(
        long,
        env = "PDS_SHUTDOWN_DEADLINE_SECS",
        default_value_t = 25,
        value_parser = clap::value_parser!(u64).range(1..=600),
    )]
    shutdown_deadline_secs: u64,

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

    /// Require server-provided DPoP nonces. Default true.
    ///
    /// The specification calls these mandatory, and without them a captured
    /// proof is replayable for its whole freshness window with only the JTI
    /// guard in the way.
    ///
    /// The escape hatch exists because turning this on changes what clients
    /// must do: a client that does not handle a `use_dpop_nonce` challenge and
    /// retry will start failing. Conformant clients do handle it -- the retry
    /// is part of the flow and this workspace's own client implements it --
    /// but an operator upgrading a live server should be able to turn it off
    /// while a client of theirs catches up, rather than choosing between a
    /// conformant server and a working one.
    #[arg(
        long,
        env = "PDS_DPOP_NONCE_REQUIRED",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    dpop_nonce_required: bool,

    /// Notifier per-delivery HTTP timeout in seconds. Default 10.
    ///
    /// Deliveries run serially in a background task, which is the one
    /// outbound path on the server that no request timeout covers. Without
    /// this bound a recipient that accepts the connection and never answers
    /// stalls every other space's notifications behind it.
    #[arg(
        long,
        env = "PDS_SPACE_NOTIFY_TIMEOUT_SECS",
        default_value_t = atproto_pds::notifier::DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=300),
    )]
    space_notify_timeout_secs: u64,

    /// SpaceCredential TTL in seconds. Default
    /// 7200 (2h, matching `atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS`).
    #[arg(
        long,
        env = "PDS_SPACE_CREDENTIAL_TTL_SECONDS",
        default_value_t = atproto_space::credential::SPACE_CREDENTIAL_TTL_SECS,
        value_parser = clap::value_parser!(u64).range(
            atproto_space::credential::SPACE_CREDENTIAL_TTL_MIN_SECS
                ..=atproto_space::credential::SPACE_CREDENTIAL_TTL_MAX_SECS,
        ),
    )]
    space_credential_ttl_seconds: u64,

    /// How long a `registerNotify` subscription lasts, in seconds. Default
    /// 5184000 (60 days).
    ///
    /// A syncer renews by calling `registerNotify` again before this elapses;
    /// the expiry is returned to it as `expiresAt`. Nothing reminds a
    /// subscriber that has stopped renewing — a lapsed registration is skipped
    /// at fan-out without an error — so this is the window a syncer that only
    /// registers at startup keeps hearing about writes.
    ///
    /// It is also the backstop revocation for a subscription: `unregisterNotify`
    /// is the subscriber's own call, and neither removing a member nor deleting
    /// a space prunes their registrations, so a lower value bounds how long a
    /// syncer that should no longer receive `notifyWrite` still does.
    #[arg(
        long,
        env = "PDS_SPACE_REGISTER_NOTIFY_TTL_SECONDS",
        default_value_t = atproto_pds::space::notify::DEFAULT_REGISTER_NOTIFY_TTL_SECS,
        value_parser = clap::value_parser!(u64).range(
            atproto_pds::space::notify::REGISTER_NOTIFY_TTL_MIN_SECS
                ..=atproto_pds::space::notify::REGISTER_NOTIFY_TTL_MAX_SECS,
        ),
    )]
    space_register_notify_ttl_seconds: u64,

    /// Comma-separated list of allowed handle suffix domains (REMAINING-
    /// WORK §11e). When set, `createAccount` rejects handles whose
    /// suffix isn't in the list. Empty (default) means any handle is
    /// accepted (back-compat for dev / test deployments).
    #[arg(long, env = "PDS_SERVICE_HANDLE_DOMAINS", value_delimiter = ',')]
    service_handle_domains: Vec<String>,

    /// Directory of lexicon documents to resolve from disk, searched after the
    /// bundled corpus and before the network.
    ///
    /// For schemas that are real but not reachable from where this server is
    /// standing — most often an application's own lexicons, published under a
    /// DID in the production PLC directory by a server configured against a
    /// local one. Without them an `include:` scope expands to nothing and every
    /// write is refused with `InsufficientScope`.
    ///
    /// `*.json` is read recursively; each document is keyed by its own `id`,
    /// falling back to its path. Read once at startup — editing a file needs a
    /// restart. A path that cannot be read is fatal rather than empty, because
    /// a typo would otherwise leave a server that looks configured and resolves
    /// exactly as it did before.
    #[arg(long, env = "PDS_LEXICON_DIR")]
    lexicon_dir: Option<std::path::PathBuf>,

    /// Comma-separated list of crawler hostnames to notify via
    /// `com.atproto.sync.requestCrawl`. Each
    /// entry is a base URL like `https://relay.example`. The handler
    /// accepts the crawler's name in the request body and POSTs the
    /// PDS's hostname back to it so it starts subscribing to the
    /// firehose.
    #[arg(long, env = "PDS_CRAWLERS", value_delimiter = ',')]
    crawlers: Vec<String>,

    /// Seconds to wait before the first crawl announcement.
    ///
    /// A relay checks that it can reach this host before accepting, and on a
    /// platform that swaps containers the first attempt lands during the swap
    /// and is refused every deploy. The retry recovers, so this changes no
    /// outcome -- it moves the first attempt to when the deployment is
    /// actually reachable, so a healthy deploy stops logging a warning.
    ///
    /// `0` announces immediately, which is right when the host is already
    /// reachable at process start. Around `15` suits a rolling deploy.
    #[arg(long, env = "PDS_CRAWLER_ANNOUNCE_DELAY_SECS", default_value_t = 0)]
    crawler_announce_delay_secs: u64,

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

    /// Operator-wide PLC rotation key, listed on every genesis operation this
    /// server signs.
    ///
    /// One value, in the form key generators actually print:
    /// `did:key:z42t…` for a P-256 private key or `did:key:z3vL…` for K-256.
    /// Those are the two curves PLC accepts for a rotation key.
    ///
    /// This used to be two variables -- a public `did:key` plus the raw
    /// private scalar in base64url -- which meant taking the one string
    /// `goat key generate` prints and splitting it into two encodings by
    /// hand. Neither half was independently useful and getting either wrong
    /// stopped the server from booting.
    ///
    /// Keep this key. It is the operator's recovery path for every identity
    /// this server issues, and nothing here can reproduce it.
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

    /// Blob-store URL. **Unsupported** — setting this refuses at boot.
    ///
    /// `HybridS3BlobStorage` exists and is tested, and nothing constructs
    /// it. The flag is still declared so that setting it produces an error
    /// naming the gap rather than being silently ignored, which is what
    /// used to happen: an operator configured S3 and got per-actor SQLite
    /// with no indication.
    #[arg(long, env = "PDS_BLOB_STORE_URL")]
    blob_store_url: Option<String>,

    /// PostgreSQL DSN for the accounts directory. **Unsupported** —
    /// setting this refuses at boot.
    ///
    /// `AccountDirectory::open_postgres` exists and most accounts-DB
    /// queries already dispatch per dialect, but thirteen production call
    /// sites take a SQLite-only pool accessor that panics on a Postgres
    /// pool. Declared for the same reason as `blob_store_url`: so the
    /// refusal is loud.
    #[arg(long, env = "PDS_POSTGRES_URL")]
    postgres_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    // Platform-assigned port. Railway, Fly, Heroku and the rest hand the
    // container a port in `PORT` and route to it; a service that ignores it
    // binds somewhere the platform is not looking and reads as failing its
    // health check for reasons nothing explains.
    //
    // `PDS_PORT` still wins when set, so an operator who names a port gets it.
    if std::env::var_os("PDS_PORT").is_none()
        && let Ok(port) = std::env::var("PORT")
        && let Ok(port) = port.parse::<u16>()
    {
        args.port = port;
    }
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

    report_tls_trust_anchors();

    // Backends that are configured but cannot be used. These flags used to
    // parse and be ignored, so an operator who set one believed they had it and
    // got neither.
    //
    // Refusing here rather than dropping the flags: an unrecognised environment
    // variable is also silent, and silence is the failure being fixed.
    //
    // Ahead of the production gate on purpose. `PDS_VALKEY_URL` on a build
    // without the feature leaves the durability profile at its default, so the
    // gate would refuse first and say memory durability is not allowed in
    // production -- true, and the symptom rather than the cause. The operator
    // set a variable to avoid exactly that and needs to be told it did nothing,
    // not told the consequence.
    atproto_pds::config::validate_supported_backends(
        args.postgres_url.as_deref(),
        args.blob_store_url.as_deref(),
        args.valkey_url.as_deref(),
    )
    .map_err(|e| {
        error!(error = ?e, "unsupported backend configured");
        anyhow::anyhow!("{e}")
    })?;

    // Production-safety gate: refuse to boot with dev-sentinel secrets when
    // PDS_PRODUCTION=true. See.
    let startup = StartupConfig {
        production: args.production,
        allow_dev_defaults: args.allow_dev_defaults,
        jwt_secret: args.jwt_secret.clone(),
        admin_password: args.admin_password.clone(),
        service_did: args.service_did.clone(),
        // Valkey overrides the flag when a URL is configured, so report what
        // will actually back the guard rather than what was typed.
        //
        // `cfg!` and not just the URL: the runtime selection below is compiled
        // out without the feature, so on such a build the URL changes nothing
        // and saying "valkey" here would be reporting a backend that is not
        // going to be used. `validate_supported_backends` refuses that
        // combination outright a few lines down, and this is the second half of
        // the same statement -- what is configured has to be what runs.
        durability_profile: if cfg!(feature = "valkey")
            && args
                .valkey_url
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty())
        {
            "valkey".to_string()
        } else {
            args.durability_profile.clone()
        },
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
    let space_reader = Arc::new(
        SpaceReader::new(account_manager.clone(), args.data_dir.clone())
            // Without this the reader can only verify credentials from
            // authorities this PDS itself hosts, which confines every
            // permissioned space to a single host.
            .with_plc_directory(args.plc_directory.clone()),
    );
    let space_sync = Arc::new(SpaceSync::new(args.data_dir.clone()));

    // §11d — externally-supplied PLC rotation key (optional).
    let external_plc_key =
        parse_external_plc_rotation_key(args.plc_rotation_key_private.as_deref())?;
    if let Some(key) = external_plc_key.as_ref() {
        // The public form, so an operator can check the running server against
        // the key they hold without the log ever carrying the secret.
        let public = atproto_identity::key::to_public(key)
            .map(|p| format!("{p}"))
            .unwrap_or_else(|_| "<underivable>".to_string());
        info!(
            public_key = %public,
            "externally-supplied PLC rotation key loaded — included in every genesis op"
        );
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
    let pds_signing_key =
        atproto_pds::keys::load_or_create_pds_signing_key(&account_manager).await?;

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
            let mut parsed = atproto_pds::oauth::jwks::parse_jwk_set_env(raw)?;
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
    //
    // The per-IP tiers are built from the same backend as everything else. On
    // a multi-node deployment a rate limit that is not shared across nodes is
    // a rate limit multiplied by the node count, which is not what the
    // operator configured.
    let (jti_guard, rate_limiter, ip_limiter, auth_limiter) = {
        // §5.2 valkey precedence: if the feature is compiled and an URL
        // is configured, prefer it over SQL/memory. Off-feature builds
        // collapse this branch to a no-op.
        #[cfg(feature = "valkey")]
        {
            if let Some(ref url) = args.valkey_url
                && !url.trim().is_empty()
            {
                info!(url = %url, prefix = %args.valkey_key_prefix, "durability profile: valkey");
                let rate_window = Duration::from_secs(args.rate_limit_window_secs);
                let client = atproto_pds::valkey_backend::ValkeyClient::connect(
                    url,
                    &args.valkey_key_prefix,
                )
                .await?;
                (
                    atproto_pds::security::JtiReplayGuard::new_valkey(client.clone()),
                    atproto_pds::security::SlidingWindowLimiter::new_valkey(
                        client.clone(),
                        if args.rate_limit == 0 {
                            usize::MAX
                        } else {
                            args.rate_limit
                        },
                        rate_window,
                    ),
                    atproto_pds::security::SlidingWindowLimiter::new_valkey(
                        client.clone(),
                        if args.rate_limit == 0 {
                            usize::MAX
                        } else {
                            args.rate_limit
                        },
                        rate_window,
                    ),
                    atproto_pds::security::SlidingWindowLimiter::new_valkey(
                        client,
                        if args.rate_limit_auth == 0 {
                            usize::MAX
                        } else {
                            args.rate_limit_auth
                        },
                        rate_window,
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

    // Policy documents. Both halves or neither: an identifier with no URL
    // records an agreement to something the holder was never shown, and a URL
    // with no identifier shows a document that nothing attests to. Half a
    // configuration is more likely a typo than an intention, so it is refused
    // at boot rather than silently ignored at signup.
    let policy_documents = match (&args.policy_set_id, &args.policy_url) {
        (Some(set_id), Some(url)) => {
            info!(policy_set_id = %set_id, policy_url = %url, "policy acceptance required at signup");
            Some(atproto_pds::http::state::PolicyDocuments {
                set_id: set_id.clone(),
                url: url.clone(),
            })
        }
        (None, None) => None,
        (Some(_), None) => {
            error!("PDS_POLICY_SET_ID is set without PDS_POLICY_URL; refusing to start");
            std::process::exit(2);
        }
        (None, Some(_)) => {
            error!("PDS_POLICY_URL is set without PDS_POLICY_SET_ID; refusing to start");
            std::process::exit(2);
        }
    };

    // Derived from the JWT secret rather than configured separately: that
    // secret is already required, already at least 32 bytes, already stable
    // across restarts and already shared by every instance, which is the whole
    // list of properties a nonce key needs.
    let dpop_nonce = args.dpop_nonce_required.then(|| {
        atproto_pds::oauth::nonce::NonceIssuer::new(std::sync::Arc::new(
            args.jwt_secret.clone().into_bytes(),
        ))
    });
    if dpop_nonce.is_none() {
        warn!(
            "DPoP nonces are disabled; a captured proof is replayable for its \
             freshness window. Set PDS_DPOP_NONCE_REQUIRED=true once clients support it"
        );
    }

    // Wire shutdown before the state, which wants the token: `subscribeRepos`
    // holds sockets open indefinitely and needs to know when to let go.
    let ctrl = ShutdownController::with_deadline(Duration::from_secs(args.shutdown_deadline_secs));
    let token = ctrl.token();

    // Captured before `args` is partially moved into `HttpState` below.
    let rate_policy_inputs = RateLimitInputs {
        global: args.rate_limit,
        auth: args.rate_limit_auth,
        window_secs: args.rate_limit_window_secs,
        trusted_proxy_hops: args.trusted_proxy_hops,
        bypass_ips: args.rate_limit_bypass_ips.clone(),
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
    .with_blob_upload_limit(args.blob_upload_limit)
    .with_import_limit(args.import_limit)
    .with_firehose_send_timeout(args.firehose_send_timeout)
    .with_oauth_access_ttl(args.oauth_access_token_ttl_seconds)
    .with_oauth_refresh_ttl(args.oauth_refresh_token_ttl_seconds)
    .with_email_service(email_service)
    .with_trusted_proxy_hops(args.trusted_proxy_hops)
    .with_shutdown(token.clone())
    .with_jti_guard(jti_guard.clone())
    .with_rate_limiter(rate_limiter.clone())
    .with_public_realm_backend(public_realm_backend.clone())
    .with_space_credential_ttl(args.space_credential_ttl_seconds)
    .with_space_register_notify_ttl(args.space_register_notify_ttl_seconds)
    .with_service_handle_domains(args.service_handle_domains.clone())
    .with_crawlers(args.crawlers.clone())
    .with_policy_documents(policy_documents)
    .with_admin_dids(args.admin_dids.clone())
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

    // Per-request `Atproto-Proxy` targets. Without this only the pinned
    // AppView above is reachable, which is what keeps labelers, feed
    // generators, chat and Ozone out of reach.
    {
        let http = reqwest::Client::builder()
            .user_agent(atproto_pds::user_agent())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let plc_hostname = args
            .plc_directory
            .clone()
            .unwrap_or_else(|| "plc.directory".to_string());
        let resolver = atproto_pds::http::proxy_target::NetworkDidDocumentResolver::new(
            http,
            plc_hostname.clone(),
        );
        info!(
            plc_hostname,
            ttl_secs = atproto_pds::http::proxy_target::DEFAULT_PROXY_CACHE_TTL.as_secs(),
            "Atproto-Proxy targets resolve from DID documents"
        );
        state = state.with_proxy_resolver(std::sync::Arc::new(
            atproto_pds::http::proxy_target::CachingProxyResolver::new(
                std::sync::Arc::new(resolver),
                atproto_pds::http::proxy_target::DEFAULT_PROXY_CACHE_TTL,
            ),
        ));
    }
    // Resolvers for record validation, assembled below: the bundled corpus is
    // always present, and network resolution is added when DNS is available.
    // Assigned by the `hickory-dns` block below when a DNS resolver exists.
    // Declared without an initialiser so the compiled-out case is a genuine
    // "never set" rather than a value assigned and immediately overwritten.
    let network_lexicon_resolver: Option<Arc<dyn atproto_pds::repo::lexicon::LexiconResolver>>;
    #[cfg(not(feature = "hickory-dns"))]
    {
        network_lexicon_resolver = None;
    }

    #[cfg(feature = "hickory-dns")]
    {
        let lexicon_plc_hostname = args
            .plc_directory
            .as_deref()
            .and_then(|url| url.split("://").nth(1).map(|h| h.to_string()))
            .unwrap_or_else(|| "plc.directory".to_string());

        // Application lexicons -- anything outside the bundled vocabulary --
        // are resolved over the same path space declarations use, so network
        // resolution is available exactly when DNS is. The bundled corpus is
        // attached unconditionally below and sits in front of this.
        let lexicon_http = reqwest::Client::builder()
            .user_agent(user_agent())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let lexicon_network = atproto_pds::repo::lexicon::NetworkLexiconResolver::new(
            dns_resolver.clone(),
            lexicon_http,
            lexicon_plc_hostname,
        );
        network_lexicon_resolver = Some(Arc::new(
            atproto_pds::repo::lexicon::CachingLexiconResolver::new(
                Arc::new(lexicon_network),
                std::time::Duration::from_secs(300),
            ),
        ));
        state = state.with_dns_resolver(dns_resolver);
    }
    // The bundled vocabulary first, then the network. Order is deliberate: a
    // bundled schema is the one this build was tested against, so letting a
    // network answer override it would make validation depend on what an
    // authority published today. The bundle needs no DNS, so `validate: true`
    // works for `app.bsky.*`, `chat.bsky.*`, `com.atproto.*` and `tools.ozone.*`
    // on a server with no resolver configured at all.
    {
        let bundled = Arc::new(atproto_pds::repo::lexicon::BundledLexiconResolver::new());
        info!(
            lexicons = bundled.len(),
            network = network_lexicon_resolver.is_some(),
            "lexicon corpus loaded for record validation"
        );
        let mut chain: Vec<Arc<dyn atproto_pds::repo::lexicon::LexiconResolver>> =
            vec![bundled.clone()];

        // Between the bundle and the network. The bundle stays first because it
        // is the vocabulary this build was tested against, and an operator's
        // directory is the wrong place for `com.atproto.*` to come from; the
        // directory goes ahead of the network because answering locally is the
        // whole point of configuring it.
        if let Some(dir) = args.lexicon_dir.as_deref() {
            let (from_disk, skipped) =
                atproto_pds::repo::lexicon::DirectoryLexiconResolver::load(dir).map_err(|e| {
                    anyhow::anyhow!("PDS_LEXICON_DIR: cannot read {}: {e}", dir.display())
                })?;
            for (path, reason) in &skipped {
                warn!(path = %path.display(), reason = %reason, "skipped a lexicon document");
            }
            // A schema the bundle already answers for is never reached, and
            // silently ignoring it would look like it had taken effect.
            let mut shadowed = Vec::new();
            for nsid in from_disk.nsids() {
                if bundled.resolve(nsid).await.is_some() {
                    shadowed.push(nsid.to_string());
                }
            }
            if !shadowed.is_empty() {
                warn!(
                    nsids = ?shadowed,
                    "these lexicons are also bundled; the bundled copy answers and the file on disk is ignored"
                );
            }
            if from_disk.is_empty() {
                warn!(
                    dir = %dir.display(),
                    "PDS_LEXICON_DIR is set but no lexicon documents were found"
                );
            } else {
                info!(
                    dir = %dir.display(),
                    lexicons = from_disk.len(),
                    skipped = skipped.len(),
                    "lexicons loaded from disk"
                );
            }
            chain.push(Arc::new(from_disk));
        }

        if let Some(network) = network_lexicon_resolver {
            chain.push(network);
        }
        let lexicons: Arc<dyn atproto_pds::repo::lexicon::LexiconResolver> = Arc::new(
            atproto_pds::repo::lexicon::ChainedLexiconResolver::new(chain),
        );

        // Space-type declarations (NSID → declared `collections`, for the bare
        // `space:` grant default, the spec's "Matching" section) come off the same chain.
        //
        // A declaration is a lexicon document, so resolving it a second way was
        // always duplication -- and the second way was network-only, which made
        // it a different answer rather than the same one twice. A space type
        // this build ships, or one an operator supplies, was invisible here
        // while resolving fine everywhere else; `declared_collections` is
        // fail-closed, so that surfaced as a space the holder could not create,
        // with the resolution failure several log lines away from the refusal.
        state = state.with_space_declaration_resolver(Arc::new(
            atproto_pds::space::CachingSpaceDeclarationResolver::new(
                Arc::new(atproto_pds::space::LexiconSpaceDeclarationResolver::new(
                    lexicons.clone(),
                )),
                std::time::Duration::from_secs(300),
            ),
        ));
        state = state.with_lexicon_resolver(lexicons);
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

    if let Some(issuer) = dpop_nonce.clone() {
        state = state.with_dpop_nonce(issuer);
    }

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

    // Per-IP rate limiting over every route. The existing per-identifier
    // limits at `createSession` and friends stay: they bound one account being
    // attacked from many addresses, which a per-IP limit cannot see.
    let rate_policy = build_rate_limit_policy(&rate_policy_inputs, ip_limiter, auth_limiter)?;
    let app = atproto_pds::http::with_rate_limit(app, rate_policy);
    let app = match dpop_nonce {
        Some(issuer) => atproto_pds::http::with_dpop_nonce(app, issuer),
        None => app,
    };

    // Bind and serve.
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind addr: {e}"))?;
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "HTTP listening");

    let tracker = ctrl.tracker();
    tracker.spawn(heartbeat_loop(token.clone()));

    // Announce to the configured crawlers now that the listener is up.
    //
    // Nothing discovers a PDS on its own. Without this the server runs
    // correctly and is never read: writes commit, the repo serves, the firehose
    // upgrades, and no relay has been told any of it exists. Setting
    // PDS_CRAWLERS is the operator saying they want to be crawled, so it should
    // be the whole of what they have to do.
    //
    // Spawned rather than awaited, and after the bind: a relay that is down or
    // slow must not hold up a server that is otherwise ready to serve.
    //
    // It retries, because the relay checks that it can reach this host before
    // accepting, and at process start the deployment is routinely not reachable
    // yet -- the listener is up locally while the platform is still health-
    // checking the new container or draining the old one. A single attempt here
    // fails for a server that is fine a minute later.
    let announce_crawlers = args.crawlers.clone();
    let announce_hostname =
        atproto_pds::crawl::public_hostname(args.hostname.as_deref(), &args.service_did);
    let announce_delay = Duration::from_secs(args.crawler_announce_delay_secs);
    tracker.spawn(async move {
        atproto_pds::crawl::announce_with_retry(
            &announce_crawlers,
            &announce_hostname,
            announce_delay,
        )
        .await;
    });

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
        Duration::from_secs(args.space_notify_timeout_secs),
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
        GcRetention {
            space_oplog_days: args.space_oplog_retention_days,
            blob_grace_hours: args.blob_grace_hours,
            stream_event_hours: args.stream_event_retention_hours,
        },
        unified_gc_interval,
        token.clone(),
    ));

    // Run axum with graceful shutdown.
    let shutdown_token = token.clone();
    // `into_make_service_with_connect_info` is what puts the peer address in
    // request extensions. Without it the rate limiter has no address to key on
    // and silently limits nothing.
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_token.cancelled().await;
    });

    // Hand the server to the controller rather than racing it against the
    // signal. `with_graceful_shutdown` only drains while the future above is
    // still being polled, so whoever owns the shutdown has to own the await.
    if let Err(e) = ctrl.serve_and_drain(server).await {
        error!(error = ?e, "HTTP server exited with error");
    }
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
    timeout: Duration,
    token: tokio_util::sync::CancellationToken,
) {
    // §11g — retry knobs come from CLI/env; defaults match the constants
    // exposed on `Notifier::default()`.
    let notifier = Notifier {
        client: atproto_pds::notifier::build_client(timeout),
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

/// Retention knobs for the unified GC, grouped because they travel together
/// and are read together.
#[derive(Debug, Clone, Copy)]
struct GcRetention {
    /// Days of `space_*_oplog` history kept. `0` disables that sweep.
    space_oplog_days: i64,
    /// Hours an unreferenced blob is kept. `0` disables that sweep.
    blob_grace_hours: i64,
    /// Hours of firehose log kept. `0` disables that sweep.
    stream_event_hours: i64,
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
    retention: GcRetention,
    interval: Duration,
    token: tokio_util::sync::CancellationToken,
) {
    // First tick fires immediately; skip it so we don't pile work on the
    // accounts pool right at boot -- but do not then wait a whole interval.
    //
    // With a daily interval that meant a process restarted once a day never
    // swept at all: every restart put the next tick 24 hours out and the
    // process rarely lived that long. The sweep that never runs is
    // indistinguishable from the sweep that does not exist, which is how the
    // firehose log grew unbounded while a GC loop was ostensibly running.
    //
    // A minute is enough to be clear of boot -- migrations, key loading, the
    // listener coming up -- and short enough that the first sweep is
    // observable while an operator is still watching the deploy.
    const FIRST_TICK_DELAY: Duration = Duration::from_secs(60);
    tokio::select! {
        _ = token.cancelled() => {
            info!("unified GC worker exiting before its first tick");
            return;
        }
        _ = tokio::time::sleep(FIRST_TICK_DELAY) => {}
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("unified GC worker exiting");
                return;
            }
            _ = ticker.tick() => {
                let opts = atproto_pds::gc::TickOptions {
                    data_dir: Some(&data_dir),
                    space_oplog_retention_days: retention.space_oplog_days,
                    blob_grace_hours: retention.blob_grace_hours,
                    stream_event_retention_hours: retention.stream_event_hours,
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
                    orphan_blobs = report.orphan_blobs,
                    stream_event = report.stream_event,
                    "unified GC tick complete"
                );
            }
        }
    }
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

/// Parse the externally-supplied PLC rotation key
/// from the configured env vars. Returns `None` when neither is set,
/// `Err` when only one half is provided. The DID-key string identifies
/// the curve; the private bytes are base64url-decoded.
fn parse_external_plc_rotation_key(
    private_did_key: Option<&str>,
) -> anyhow::Result<Option<atproto_identity::key::KeyData>> {
    use atproto_identity::key::{KeyType, identify_key};
    let Some(raw) = private_did_key else {
        return Ok(None);
    };
    let raw = raw.trim();
    // `did:key:z…` and a bare `z…` are the same key written two ways.
    let bare = raw.strip_prefix("did:key:").unwrap_or(raw);
    let key = identify_key(bare)
        .map_err(|e| anyhow::anyhow!("PDS_PLC_ROTATION_KEY_PRIVATE is not a usable key: {e}"))?;
    match key.key_type() {
        // The two curves PLC accepts for a rotation key.
        KeyType::P256Private | KeyType::K256Private => Ok(Some(key)),
        // A public key would let the server list the operator's key and
        // never sign with it, which fails later and further away.
        KeyType::P256Public | KeyType::K256Public => Err(anyhow::anyhow!(
            "PDS_PLC_ROTATION_KEY_PRIVATE is a public key; it must be the private form \
             (did:key:z42t… for P-256, did:key:z3vL… for K-256)"
        )),
        other => Err(anyhow::anyhow!(
            "PDS_PLC_ROTATION_KEY_PRIVATE must be a P-256 or K-256 private key; got {other:?}"
        )),
    }
}

/// Select the SQL or memory durability profile for the JTI guard +
/// rate limiter. Factored out of `main`
/// so the §5.2 valkey precedence path can fall back to it when the
/// feature is on but no URL is configured.
/// Build the JTI guard and the three rate limiters from the durability
/// profile.
///
/// The three limiters are separate instances rather than one shared one so a
/// flood on the auth tier cannot consume the global tier's budget, and so the
/// two tiers can carry different limits at all.
fn durability_profile_sql_or_memory(
    args: &Args,
    pool: sqlx::SqlitePool,
) -> (
    atproto_pds::security::JtiReplayGuard,
    atproto_pds::security::SlidingWindowLimiter,
    atproto_pds::security::SlidingWindowLimiter,
    atproto_pds::security::SlidingWindowLimiter,
) {
    let window = Duration::from_secs(args.rate_limit_window_secs);
    // `0` means "disable this tier", which is what both the CLI help and
    // `build_rate_limit_policy` document. It has to become an unbounded budget,
    // not a small one.
    //
    // This was `max(1)`, which turned the documented way to switch a tier off
    // into the most restrictive setting the server can have: one request per
    // window, refusing essentially everything. An operator reaching for the
    // documented escape hatch got the opposite of what it says, and the
    // failure looks like the limiter working rather than like a
    // misconfiguration.
    let disabled_or = |configured: usize| {
        if configured == 0 {
            usize::MAX
        } else {
            configured
        }
    };
    let global = disabled_or(args.rate_limit);
    let auth = disabled_or(args.rate_limit_auth);
    match args.durability_profile.as_str() {
        "sql" => {
            info!("durability profile: SQL (jti_replay + rate_limit_window persisted)");
            (
                atproto_pds::security::JtiReplayGuard::new_sql(pool.clone()),
                atproto_pds::security::SlidingWindowLimiter::new_sql(pool.clone(), global, window),
                atproto_pds::security::SlidingWindowLimiter::new_sql(pool.clone(), global, window),
                atproto_pds::security::SlidingWindowLimiter::new_sql(pool, auth, window),
            )
        }
        _ => {
            info!("durability profile: memory (loses state on restart)");
            (
                atproto_pds::security::JtiReplayGuard::new(100_000),
                atproto_pds::security::SlidingWindowLimiter::new(global, window, 100_000),
                atproto_pds::security::SlidingWindowLimiter::new(global, window, 100_000),
                atproto_pds::security::SlidingWindowLimiter::new(auth, window, 100_000),
            )
        }
    }
}

/// The subset of `Args` the rate-limit policy needs.
///
/// Copied out before `Args` is partially moved into `HttpState`, which is the
/// only reason this exists rather than passing `&Args`.
struct RateLimitInputs {
    global: usize,
    auth: usize,
    window_secs: u64,
    trusted_proxy_hops: usize,
    bypass_ips: Vec<String>,
}

/// Assemble the per-IP rate-limit policy from operator configuration.
///
/// A tier configured to `0` is disabled by giving it an effectively unbounded
/// budget rather than by branching in the middleware: the hot path stays one
/// shape, and "disabled" is a number rather than a code path that might drift.
fn build_rate_limit_policy(
    args: &RateLimitInputs,
    global: atproto_pds::security::SlidingWindowLimiter,
    auth: atproto_pds::security::SlidingWindowLimiter,
) -> anyhow::Result<atproto_pds::http::RateLimitPolicy> {
    let mut bypass = std::collections::HashSet::new();
    for raw in &args.bypass_ips {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ip: std::net::IpAddr = trimmed.parse().map_err(|e| {
            anyhow::anyhow!("PDS_RATE_LIMIT_BYPASS_IPS: {trimmed} is not an IP address: {e}")
        })?;
        bypass.insert(ip);
    }
    if args.trusted_proxy_hops == 0 {
        info!(
            "rate limiting keyed on the TCP peer address; X-Forwarded-For is ignored (set PDS_TRUSTED_PROXY_HOPS if this server is behind a proxy)"
        );
    } else {
        info!(
            hops = args.trusted_proxy_hops,
            "rate limiting keyed on X-Forwarded-For, counted from the right"
        );
    }
    info!(
        global = args.global,
        auth = args.auth,
        window_secs = args.window_secs,
        bypass = bypass.len(),
        "per-IP rate limit configured"
    );
    Ok(atproto_pds::http::RateLimitPolicy::new(
        global,
        auth,
        args.trusted_proxy_hops,
        bypass,
    ))
}

/// Log how many TLS trust anchors the platform offers, and warn when there are
/// none.
///
/// `reqwest` used to compile the Mozilla root set into the binary. It no longer
/// ships one — 0.13 removed the bundled-roots feature entirely — so every
/// outbound HTTPS call now verifies against the host's trust store: the PLC
/// directory, PDS-to-PDS traffic, AppView proxying, crawler notifications.
///
/// On a container that is missing `/etc/ssl/certs/ca-certificates.crt` that
/// failure looks like every remote call failing certificate verification at
/// once, with nothing at boot to say why. This reads the same store the TLS
/// stack will (`rustls-native-certs`, which is what `rustls-platform-verifier`
/// uses on Linux), so the count cannot drift from what verification actually
/// sees.
///
/// Reporting only. An empty store is fatal to outbound TLS but not to serving
/// requests, and refusing to boot would take down a PDS that is still able to
/// answer its own clients.
fn report_tls_trust_anchors() {
    let result = rustls_native_certs::load_native_certs();
    let count = result.certs.len();
    if count == 0 {
        tracing::warn!(
            errors = ?result.errors,
            "no TLS trust anchors found; outbound HTTPS will fail certificate \
             verification. On a container image this usually means the runtime \
             stage has no ca-certificates package. SSL_CERT_FILE or SSL_CERT_DIR \
             override the search."
        );
    } else {
        tracing::debug!(count, "TLS trust anchors loaded from the platform store");
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
