//! sqlx migration sources for the accounts DB and per-actor stores.
//!
//! These are bundled at compile time so the binary is self-contained and
//! migrations always match the binary they ship in (no drift between
//! deployed schema and code expecting it).

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;

/// Compile-time-bundled migrations for the shared accounts DB.
pub static ACCOUNTS_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/accounts");

/// Compile-time-bundled migrations for per-actor SQLite files.
pub static ACTOR_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/actor");

/// Apply pending accounts-DB migrations.
///
/// # Errors
///
/// Returns the underlying sqlx error if migration application fails.
pub async fn run_accounts_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ACCOUNTS_MIGRATIONS
        .run(pool)
        .await
        .map_err(sqlx::Error::from)
}

/// Apply pending per-actor migrations.
///
/// # Errors
///
/// Returns the underlying sqlx error if migration application fails.
pub async fn run_actor_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    ACTOR_MIGRATIONS.run(pool).await.map_err(sqlx::Error::from)
}
