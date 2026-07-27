//! Configuration loaded from environment variables.
//!
//! Mirrors the env-var table in the cluster plan (§3.11). OAuth and attestation
//! are enabled only when both `OAUTH_PRIVATE_KEYS` and `COOKIE_SECRET` are set.

use atproto_identity::key::{KeyData, identify_key, to_public};
use atproto_space::types::SpaceUri;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::error::ConfigError;

/// Application configuration, cloneable and shared via `WebContext`.
#[derive(Clone)]
pub struct Config {
    /// SQLite database URL, e.g. `sqlite:/data/walking_club.sqlite?mode=rwc`.
    pub database_url: String,
    /// Maximum sqlx pool connections.
    pub database_max_connections: u32,
    /// External base host (no scheme), e.g. `walking-club-appview.ngerakines.dev`.
    pub http_external_base: String,
    /// Listener port.
    pub http_port: u16,
    /// Bind address.
    pub http_bind: String,
    /// Static asset directory served by `ServeDir`.
    pub http_static_path: String,
    /// OAuth private signing keys (P-256). First is the active signer.
    pub oauth_private_keys: Vec<KeyData>,
    /// AES-256-GCM cookie secret (32 bytes).
    pub cookie_secret: Option<[u8; 32]>,
    /// Admin basic-auth password.
    pub admin_password: Option<String>,
    /// The club's space URI (`ats://<ownerDid>/<type>/<skey>`).
    pub space_uri: Option<SpaceUri>,
    /// The authority DID for the space.
    pub space_owner_did: Option<String>,
    /// PLC directory hostname (bare, no scheme).
    pub plc_hostname: String,
    /// Hickory resolver nameservers (empty = system DNS).
    pub dns_nameservers: Vec<std::net::IpAddr>,
    /// Firehose sources as `(name, ws_url)` pairs.
    pub firehose_sources: Vec<(String, String)>,
    /// Whether the built-in public-plane indexer is enabled.
    pub public_index_enabled: bool,
    /// Collections to project into `public_records`.
    pub tracked_collections: Vec<String>,
    /// Early-expiry skew (seconds) on cached space credentials.
    pub space_cred_skew_secs: u64,
    /// `registerNotify` keepalive interval (seconds).
    pub notify_reregister_secs: u64,
    /// Debounce (ms) for notify-triggered re-pulls.
    pub read_debounce_ms: u64,
    /// Requests per 15-minute window for the in-memory rate limiter.
    pub rate_limit_count: u32,
}

/// Read a required environment variable (used by module authors when wiring
/// up endpoints that demand a value).
#[allow(dead_code)]
fn require_env(name: &str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::MissingEnv(name.to_string()))
}

fn default_env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = default_env("DATABASE_URL", "sqlite:/data/walking_club.sqlite?mode=rwc");
        let database_max_connections = default_env("DATABASE_MAX_CONNECTIONS", "5")
            .parse()
            .map_err(|e| {
                ConfigError::InvalidValue("DATABASE_MAX_CONNECTIONS".into(), format!("{e}"))
            })?;
        let http_external_base =
            default_env("HTTP_EXTERNAL_BASE", "walking-club-appview.ngerakines.dev");
        let http_port = default_env("HTTP_PORT", "8080")
            .parse()
            .map_err(|e| ConfigError::InvalidValue("HTTP_PORT".into(), format!("{e}")))?;
        let http_bind = default_env("HTTP_BIND", "0.0.0.0");
        let http_static_path = default_env("HTTP_STATIC_PATH", "static");

        let oauth_private_keys = match optional_env("OAUTH_PRIVATE_KEYS") {
            Some(raw) => parse_oauth_private_keys(&raw)?,
            None => Vec::new(),
        };

        let cookie_secret = match optional_env("COOKIE_SECRET") {
            Some(raw) => Some(parse_cookie_secret(&raw)?),
            None => None,
        };

        let admin_password = optional_env("ADMIN_PASSWORD");

        let space_uri = match optional_env("SPACE_URI") {
            Some(raw) => Some(
                SpaceUri::parse(&raw)
                    .map_err(|e| ConfigError::InvalidValue("SPACE_URI".into(), format!("{e}")))?,
            ),
            None => None,
        };
        let space_owner_did = optional_env("SPACE_OWNER_DID");

        let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");

        let dns_nameservers = optional_env("DNS_NAMESERVERS")
            .map(|raw| {
                raw.split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let firehose_sources = parse_firehose_sources(&default_env(
            "FIREHOSE_SOURCES",
            "pds1=ws://pds1:3000,pds2=ws://pds2:3000,space-host=ws://space-host:3000",
        ));

        let public_index_enabled = parse_bool_env("PUBLIC_INDEX_ENABLED", true);

        let tracked_collections = default_env(
            "TRACKED_COLLECTIONS",
            "community.lexicon.calendar.event app.bsky.feed.post",
        )
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

        let space_cred_skew_secs = default_env("SPACE_CRED_SKEW_SECS", "120")
            .parse()
            .unwrap_or(120);
        let notify_reregister_secs = default_env("NOTIFY_REREGISTER_SECS", "43200")
            .parse()
            .unwrap_or(43200);
        let read_debounce_ms = default_env("READ_DEBOUNCE_MS", "500")
            .parse()
            .unwrap_or(500);
        let rate_limit_count = default_env("RATE_LIMIT_COUNT", "120")
            .parse()
            .unwrap_or(120);

        Ok(Self {
            database_url,
            database_max_connections,
            http_external_base,
            http_port,
            http_bind,
            http_static_path,
            oauth_private_keys,
            cookie_secret,
            admin_password,
            space_uri,
            space_owner_did,
            plc_hostname,
            dns_nameservers,
            firehose_sources,
            public_index_enabled,
            tracked_collections,
            space_cred_skew_secs,
            notify_reregister_secs,
            read_debounce_ms,
            rate_limit_count,
        })
    }

    /// The external base URL (with `https://`).
    pub fn external_base_url(&self) -> String {
        format!("https://{}", self.http_external_base)
    }

    /// Whether OAuth + attestation are enabled (keys and cookie secret present).
    pub fn oauth_enabled(&self) -> bool {
        !self.oauth_private_keys.is_empty() && self.cookie_secret.is_some()
    }

    /// The active OAuth signing key (first private key), if any.
    pub fn oauth_signing_key(&self) -> Option<&KeyData> {
        self.oauth_private_keys.first()
    }

    /// All public keys derived from the configured private keys (for JWKS).
    pub fn oauth_public_keys(&self) -> Vec<KeyData> {
        self.oauth_private_keys
            .iter()
            .filter_map(|k| to_public(k).ok())
            .collect()
    }

    /// The OAuth client id (the `client-metadata.json` URL).
    pub fn oauth_client_id(&self) -> String {
        format!("{}/client-metadata.json", self.external_base_url())
    }

    /// The OAuth redirect URI.
    pub fn oauth_redirect_uri(&self) -> String {
        format!("{}/callback", self.external_base_url())
    }

    /// The JWKS URI (published separately so the space host can fetch keys).
    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks.json", self.external_base_url())
    }

    /// The AppView's own did:web identifier.
    pub fn appview_did(&self) -> String {
        format!("did:web:{}", self.http_external_base)
    }
}

/// Parse a comma-separated list of `did:key` private keys (P-256/384/K-256).
pub fn parse_oauth_private_keys(raw: &str) -> Result<Vec<KeyData>, ConfigError> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| identify_key(s).map_err(|e| ConfigError::InvalidKey(format!("{e}"))))
        .collect()
}

/// Parse a base64-encoded 32-byte cookie secret.
pub fn parse_cookie_secret(raw: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = BASE64_STANDARD
        .decode(raw.trim())
        .map_err(|e| ConfigError::InvalidCookieSecret(format!("{e}")))?;
    bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidCookieSecret("expected 32 bytes".into()))
}

/// Parse `name=wsurl,name=wsurl` into `(name, url)` pairs.
pub fn parse_firehose_sources(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            let (name, url) = pair.split_once('=')?;
            Some((name.trim().to_string(), url.trim().to_string()))
        })
        .collect()
}
