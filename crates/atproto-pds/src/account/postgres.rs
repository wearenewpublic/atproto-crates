//! PostgreSQL accounts directory adapter.
//!
//! `PostgresAccountStore` wraps a `PgPool`, runs the bundled schema
//! migration, and exposes the same `account_pool()` accessor pattern as
//! the SQLite [`crate::account::AccountDirectory`]. Operators select it
//! at boot via `PDS_POSTGRES_URL`; every accounts-DB call site routes
//! through the runtime-dispatch [`crate::account::AccountPool`] enum so
//! SQLite and Postgres deployments share a single code path.
//!
//! ## Schema
//!
//! The DDL lives under `crates/atproto-pds/migrations/postgres/` —
//! a consolidated mirror of the SQLite schema with the Postgres-side
//! type adjustments (`INTEGER` → `BIGINT`, `BLOB` → `BYTEA`,
//! `INTEGER NOT NULL DEFAULT 0/1` (booleans-as-int) → `BOOLEAN`).
//! `PostgresAccountStore::connect` runs the migrator on connect via
//! `sqlx::migrate!("./migrations/postgres")`.
//!
//! ## Tests
//!
//! `tests/feature_postgres.rs` exercises the URL parser + confirms the
//! pool builder type-checks under `--features postgres`. End-to-end
//! CRUD is covered by `tests/feature_postgres_live.rs`, which is gated
//! on `--features postgres-live-tests` and reads its target DSN from
//! `PDS_POSTGRES_TEST_URL` (skips with INFO when the env var is unset).

use crate::account::AccountPool;
use crate::errors::{PdsError, PdsResult};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Postgres-backed accounts pool.
#[derive(Clone)]
pub struct PostgresAccountStore {
    pool: PgPool,
}

impl PostgresAccountStore {
    /// Connect to `dsn`, verify reachability via a `SELECT 1`, and run
    /// the bundled `migrations/postgres/*.sql` schema migrations.
    ///
    /// The DSN follows the standard libpq form, e.g.
    /// `postgres://user:pass@host:5432/dbname?sslmode=require`. AWS
    /// RDS / GCP CloudSQL / managed instances are all supported via
    /// the underlying sqlx driver.
    pub async fn connect(dsn: &str, max_connections: u32) -> PdsResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect(dsn)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("postgres: connect {dsn}: {e}"),
            })?;
        // Liveness check so misconfigured deployments fail fast at boot.
        let _: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("postgres: SELECT 1: {e}"),
            })?;
        // Apply the bundled DDL. Idempotent on re-connect to an
        // already-migrated database.
        sqlx::migrate!("./migrations/postgres")
            .run(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("postgres: run migrations: {e}"),
            })?;
        Ok(Self { pool })
    }

    /// Hand out the raw `PgPool` for downstream queries. Prefer the
    /// `account_pool()` accessor when sites need to dispatch through
    /// the runtime-backend `AccountPool` enum.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Wrap the pool in the dispatch enum so the `account/*.rs`
    /// helpers + `AccountManager` + `AccountDirectory` route their
    /// query SQL through `pool.kind()` at runtime.
    #[must_use]
    pub fn account_pool(&self) -> AccountPool {
        AccountPool::Postgres(self.pool.clone())
    }
}

#[cfg(test)]
mod tests {
    /// Compile-only sanity: the `PostgresAccountStore` type resolves
    /// and exposes the pool accessor. Live Postgres round-trips run via
    /// `tests/feature_postgres_live.rs` (gated on
    /// `--features postgres-live-tests` against `PDS_POSTGRES_TEST_URL`).
    #[test]
    #[allow(clippy::type_complexity)] // boxed future signature is the point of the compile-only check.
    fn postgres_account_store_type_resolves() {
        let _: fn(
            &str,
            u32,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = crate::errors::PdsResult<super::PostgresAccountStore>,
                    > + Send,
            >,
        > = |dsn, max| {
            let dsn = dsn.to_string();
            Box::pin(async move { super::PostgresAccountStore::connect(&dsn, max).await })
        };
    }
}
