//! — `postgres` feature acceptance.
//!
//! When the `postgres` feature is compiled in, the
//! `PostgresAccountStore` type resolves and its `connect` builder
//! type-checks. Live Postgres round-trips require a running database —
//! Phase 1 of the rollout (this batch) ships only the connection
//! plumbing; per-table parity with the SQLite accounts adapter is a
//! follow-up.

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_connect_fails_fast_on_invalid_dsn() {
    // libpq DSN parser rejects malformed schemes — exercises the
    // typed error path without needing a live database.
    let result =
        atproto_pds::account::postgres::PostgresAccountStore::connect("not-a-postgres-dsn", 1)
            .await;
    assert!(
        result.is_err(),
        "expected connect to reject malformed DSN, got Ok"
    );
}
