//! AT Protocol Personal Data Server.
//!
//! `atproto-pds` provides a server library plus two binaries: `pds` (the
//! production server) and `atproto-pds-admin` (the admin CLI).
//!
//! # Surface
//!
//! Library modules (all stable):
//!
//! - **`account`** — accounts directory, manager, app passwords, invite codes.
//! - **`actor_store`** — per-account storage. SQLite (`sql::SqlActorStore`,
//!   default) and fjall (`fjall::FjallActorStore`, gated `fjall` feature).
//! - **`admin`** — moderator/operator endpoints + HTML dashboard.
//! - **`config`** — startup-config validation; rejects dev-sentinel secrets in
//!   production mode.
//! - **`http`** — axum router, handlers, shared `HttpState`, error mapping.
//! - **`keys`** — pluggable `KeyStore` (`MemoryKeyStore`, `FileKeyStore`).
//! - **`oauth`** — OAuth 2.1 (PAR + PKCE + DPoP-thumbprint binding +
//!   refresh-rotation + consent HTML + revoke).
//! - **`plc`** — `PlcService` for createAccount-time PLC genesis.
//! - **`realm`** — public/permissioned realm distinction.
//! - **`repo`** — `RepoReader`, `RepoWriter`, CAR export, `RepoImporter`.
//! - **`security`** — JTI replay guard + sliding-window rate limiter.
//! - **`sequencer`** — durable per-actor outbox + in-process broadcast bus.
//! - **`shutdown`** — graceful-shutdown controller.
//! - **`space`** — `SpaceService`/`Writer`/`Reader`/`Sync` over `atproto-space`.
//!
//! See `crates/atproto-pds/README.md` for the XRPC + OAuth surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod account;
pub mod actor_store;
#[cfg(feature = "http")]
pub mod admin;
pub mod blob;
#[cfg(feature = "s3")]
pub mod blob_s3;
pub mod config;
pub mod denylist;
pub mod email;
pub mod errors;
pub mod gc;
#[cfg(feature = "http")]
pub mod http;
pub mod keys;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod notifier;
#[cfg(feature = "http")]
pub mod oauth;
pub mod plc;
pub mod realm;
pub mod repo;
pub mod security;
pub mod sequencer;
pub mod service_auth_blacklist;
pub mod shutdown;
pub mod space;
pub mod telemetry;
#[cfg(feature = "valkey")]
pub mod valkey_backend;

/// The `BUILD_REV` git rev (or fallback timestamp) stamped at compile time.
///
/// Used in:
/// - User-Agent on outbound HTTP requests
/// - `/xrpc/_health` `version` field
/// - OAuth metadata ETag seed
/// - Static asset cache busting
pub const BUILD_REV: &str = env!("BUILD_REV");

/// Crate version string from `Cargo.toml`.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Combined version string for outbound traffic and `_health` reporting.
///
/// Format: `atproto-pds/<crate-version>+<build-rev>`.
pub fn user_agent() -> String {
    format!("atproto-pds/{}+{}", CRATE_VERSION, BUILD_REV)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rev_is_populated() {
        assert!(!BUILD_REV.is_empty());
    }

    #[test]
    fn user_agent_format() {
        let ua = user_agent();
        assert!(ua.starts_with("atproto-pds/"));
        assert!(ua.contains('+'));
    }
}
