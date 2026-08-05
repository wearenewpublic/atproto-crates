//! Account management — the shared accounts DB and per-account lifecycle.
//!
//! The accounts DB is one shared SQLite (or Postgres) at
//! `PDS_DATA_DIRECTORY/accounts.sqlite`, holding cross-account state
//! Per-actor state lives in
//! per-actor SQLite files via `actor_store::sql::SqlActorStore`.
//!
//! Surface: `AccountDirectory` (open/migrate + lookup), `AccountManager`
//! (createAccount, sessions, app-password lifecycle), and the
//! supporting modules for sessions / app passwords / invite codes /
//! email tokens.

pub mod state;

/// Runtime-dispatched accounts pool (SQLite | Postgres). Built behind
/// the corresponding Cargo features; see `pool.rs` for the dispatch
/// shape and for the per-table port.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub mod pool;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub use pool::{AccountPool, AccountPoolKind};

#[cfg(feature = "sqlite")]
pub mod app_password;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub mod email_token;

#[cfg(feature = "sqlite")]
pub mod directory;

#[cfg(feature = "sqlite")]
pub mod invite;

#[cfg(feature = "sqlite")]
pub mod manager;

/// PostgreSQL accounts adapter.
#[cfg(feature = "postgres")]
pub mod postgres;

/// A grace window making a refresh idempotent for a few seconds, so a client
/// racing two refreshes against itself is not logged out.
/// The account portal's storage: the session epoch that backs "log out
/// everywhere", and the browser sessions the portal itself runs on.
pub mod portal;

pub mod refresh_grace;

pub mod session;

#[cfg(feature = "sqlite")]
pub use app_password::{AppPasswordRow, CreatedAppPassword};

#[cfg(feature = "sqlite")]
pub use directory::{AccountDirectory, AccountRow};

#[cfg(feature = "sqlite")]
pub use invite::InviteCodeRow;

#[cfg(feature = "sqlite")]
pub use manager::{AccountManager, CreateAccountParams, hash_password, verify_password};

pub use session::{
    DEFAULT_ACCESS_TTL_SECS, DEFAULT_REFRESH_TTL_SECS, SessionClaims, SessionTokens, issue_pair,
    verify_access, verify_refresh,
};

pub use state::AccountState;
