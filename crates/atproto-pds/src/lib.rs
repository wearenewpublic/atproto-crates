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
//! - **`sequencer`** — the durable firehose stream (one ordered log for the
//!   whole server) + in-process broadcast bus.
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

    /// The User-Agent is well formed and carries a non-empty build rev.
    ///
    /// Asserted through [`user_agent`] rather than against [`BUILD_REV`]
    /// directly. `BUILD_REV` is a `const` filled by `env!`, so
    /// `BUILD_REV.is_empty()` is decided by the compiler, and clippy's
    /// `const_is_empty` rejects the check as one that can never do any work at
    /// run time. Reading the rev back out of the formatted string keeps the
    /// property under test — `build.rs` stamped something — while testing the
    /// value that actually ships on outbound requests.
    #[test]
    fn user_agent_is_well_formed_and_carries_a_build_rev() {
        let ua = user_agent();
        assert!(
            ua.starts_with("atproto-pds/"),
            "user agent should name the product: {ua}"
        );
        let (version, rev) = ua
            .rsplit_once('+')
            .unwrap_or_else(|| panic!("user agent should carry a `+<build-rev>` suffix: {ua}"));
        assert_eq!(version, format!("atproto-pds/{CRATE_VERSION}"));
        assert!(
            !rev.is_empty(),
            "build.rs should stamp a non-empty BUILD_REV: {ua}"
        );
    }
}
