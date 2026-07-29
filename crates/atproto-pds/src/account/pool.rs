//! `AccountPool` — runtime dispatch over the accounts-database backend.
//!
//! The accounts database stores cross-account state (`account`,
//! `app_password`, `invite_code`, `email_token`, `notify_attempt`,
//! `service_auth_blacklist`, `denylist`, `oauth_*`, `jti_replay`,
//! `rate_limit_window`). This module is the dispatch surface between SQLite
//! and PostgreSQL.
//!
//! **PostgreSQL is not a supported deployment mode.** The dispatch below is
//! real and most of it works, but thirteen production call sites take the
//! SQLite-only `pool()` accessor, which panics on a Postgres pool — see
//! `crates/atproto-pds/README.md` § "Unsupported deployment modes". Setting
//! `PDS_POSTGRES_URL` refuses at boot. The accounts DB is SQLite.
//!
//! ## How the dispatch is wired
//!
//! Every accounts-DB call site — `AccountManager`, `AccountDirectory`,
//! and the per-table helpers (`app_password`, `invite`, `email_token`,
//! `denylist`, `service_auth_blacklist`) — accepts `&AccountPool` and
//! branches per `pool.kind()`. The SQLite branch uses `?` placeholders
//! plus the SQLite-flavored upsert syntax (`INSERT OR IGNORE`,
//! `INSERT OR REPLACE`); the Postgres branch uses `$N` placeholders
//! plus `ON CONFLICT DO NOTHING` / `ON CONFLICT DO UPDATE`. Boolean
//! columns are `INTEGER` on SQLite and `BOOLEAN` on Postgres; the
//! per-row mapper coerces back to `bool` at the boundary.
//!
//! Both backends are exercised end-to-end:
//!
//! - the per-helper unit tests cover the SQLite branch in-memory;
//! - `tests/feature_postgres_live.rs` (gated on `--features
//!   postgres-live-tests` + `PDS_POSTGRES_TEST_URL`) round-trips the
//!   Postgres branch against an operator-supplied DSN.

#[cfg(feature = "sqlite")]
use sqlx::SqlitePool;
#[cfg(feature = "postgres")]
use sqlx::postgres::PgPool;

/// Runtime backend tag. Used for SQL-string selection and operator
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPoolKind {
    /// SQLite (single-node default).
    Sqlite,
    /// PostgreSQL (horizontal-scale).
    Postgres,
}

impl AccountPoolKind {
    /// Static label for log lines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// Connection pool dispatched at runtime. Holds an `Arc`-equivalent
/// pool handle that's cheap to clone.
///
/// The variants are gated on their respective Cargo features so a
/// build with only `sqlite` (the default) compiles without pulling in
/// the postgres driver.
#[derive(Clone)]
pub enum AccountPool {
    /// SQLite-backed accounts pool.
    #[cfg(feature = "sqlite")]
    Sqlite(SqlitePool),
    /// Postgres-backed accounts pool.
    #[cfg(feature = "postgres")]
    Postgres(PgPool),
}

impl AccountPool {
    /// Backend kind for log lines + SQL-dialect dispatch.
    #[must_use]
    pub fn kind(&self) -> AccountPoolKind {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => AccountPoolKind::Sqlite,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => AccountPoolKind::Postgres,
            #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
            _ => unreachable!("AccountPool: no backend feature enabled"),
        }
    }

    /// Borrow the SQLite pool, panicking if the backend is Postgres.
    /// Used inside the SQLite arms of the per-helper dispatch matches,
    /// and by a small set of legacy call sites in `bin/pds.rs` (the
    /// durability profile + OAuth state SQL adapter) that haven't yet
    /// grown a Postgres implementation. Production handlers go through
    /// the typed `AccountManager` / `AccountDirectory` / per-table
    /// helpers, which dispatch through `kind()` and never touch this.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn as_sqlite(&self) -> &SqlitePool {
        match self {
            Self::Sqlite(p) => p,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => {
                panic!("AccountPool::as_sqlite called on a Postgres pool")
            }
        }
    }

    /// Borrow the Postgres pool, panicking if the backend is SQLite.
    /// Symmetric mirror of `as_sqlite`; used inside the Postgres arms
    /// of the per-helper dispatch matches.
    #[cfg(feature = "postgres")]
    #[must_use]
    pub fn as_postgres(&self) -> &PgPool {
        match self {
            Self::Postgres(p) => p,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(_) => {
                panic!("AccountPool::as_postgres called on a SQLite pool")
            }
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<SqlitePool> for AccountPool {
    fn from(pool: SqlitePool) -> Self {
        Self::Sqlite(pool)
    }
}

#[cfg(feature = "postgres")]
impl From<PgPool> for AccountPool {
    fn from(pool: PgPool) -> Self {
        Self::Postgres(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_pool_kind_label() {
        assert_eq!(AccountPoolKind::Sqlite.as_str(), "sqlite");
        assert_eq!(AccountPoolKind::Postgres.as_str(), "postgres");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_pool_round_trips_through_dispatch() {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        use std::str::FromStr;
        let opts = SqliteConnectOptions::from_str(":memory:").unwrap();
        let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
        let dispatch: AccountPool = pool.into();
        assert_eq!(dispatch.kind(), AccountPoolKind::Sqlite);
        let _: &SqlitePool = dispatch.as_sqlite();
    }
}
