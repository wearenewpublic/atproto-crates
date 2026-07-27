//! SQLite connection pool setup and migration runner.
//!
//! Opens the database in WAL mode with a busy timeout so the firehose indexer
//! can write while request handlers read, then runs the embedded migrations.

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use std::time::Duration;

use crate::error::AppResult;

/// Shared SQLite pool type used across the AppView.
pub type DbPool = SqlitePool;

/// Open the SQLite pool (WAL + busy_timeout) and run migrations.
pub async fn connect(database_url: &str, max_connections: u32) -> AppResult<DbPool> {
    let connect_options = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| anyhow::anyhow!("invalid DATABASE_URL: {e}"))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5000));

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(connect_options)
        .await?;

    run_migrations(&pool).await?;
    Ok(pool)
}

/// Run the embedded SQL migrations.
pub async fn run_migrations(pool: &DbPool) -> AppResult<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
    Ok(())
}
