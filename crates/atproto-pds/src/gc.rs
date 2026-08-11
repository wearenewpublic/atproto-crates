//! Unified daily GC for time-bounded state.
//!
//! Several subsystems write rows that have a known expiry/retention but no
//! scheduled pruner. Without a sweep, those tables grow forever — a chronic
//! issue on long-running PDS instances. The retention rules per design:
//!
//! - `notify_attempt WHERE state='delivered' AND last_attempt_at < now-7d`
//! - `notify_attempt WHERE state='failed' AND last_attempt_at < now-30d`
//! - `email_token WHERE expires_at < now`
//! - `service_auth_blacklist WHERE expires_at < now`
//! - `oauth_revoked_token WHERE expires_at < now`
//! - `oauth_par WHERE expires_at < now` and `oauth_code WHERE expires_at < now`
//!   (the SQL-backed `OAuthState` does opportunistic GC on every write; this
//!   sweep catches leftovers from low-traffic periods)
//! - `jti_replay WHERE expires_at < now` (§6.1 SQL backend)
//! - `rate_limit_window WHERE request_at_ms < now - <window>` (§6.2 SQL backend)
//! - **Per-actor**: `space_record_oplog` and `space_member_oplog` past the
//!   configured retention. The GC walks each account
//!   in the directory and prunes oplog rows whose `rev` (TID) sorts below
//!   the cutoff TID for the retention window.
//!
//! All operations run as best-effort — a single table failure logs at WARN and
//! the tick continues. Returns a [`GcReport`] summarizing the row counts so
//! tests can observe behavior and the loop can log a single structured line.

use crate::errors::PdsResult;
use crate::security::{JtiReplayGuard, SlidingWindowLimiter};
use sqlx::SqlitePool;

/// Default retention for delivered notify_attempts (G8).
pub const DEFAULT_NOTIFY_DELIVERED_RETENTION_DAYS: i64 = 7;
/// Default retention for failed notify_attempts (long enough to investigate).
pub const DEFAULT_NOTIFY_FAILED_RETENTION_DAYS: i64 = 30;
/// Default retention for `space_*_oplog` rows.
/// Receivers that lag behind this window need a full re-sync via
/// `getRepoState`. Operators tighten via
/// `PDS_SPACE_OPLOG_RETENTION_DAYS`.
pub const DEFAULT_SPACE_OPLOG_RETENTION_DAYS: i64 = 30;

/// How long a blob nothing refers to is kept before it is collected.
///
/// A blob is unreferenced for a while in the ordinary course of things, and
/// deleting on sight would delete live data. `uploadBlob` stores bytes before
/// any record mentions them -- that is the whole upload-then-write flow -- and
/// an update to a record that keeps the same image drops the old refs and adds
/// the new ones as two steps, so the blob is momentarily unreferenced while
/// still very much in use.
///
/// A day is far longer than either window needs and short enough that a deleted
/// video is not billed for a month.
pub const DEFAULT_BLOB_GRACE_HOURS: i64 = 24;

/// Per-table prune counts. `Ok(rows_pruned)` per table; `None` indicates the
/// helper failed and the caller logged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Delivered notify_attempts past retention.
    pub notify_delivered: u64,
    /// Failed notify_attempts past retention.
    pub notify_failed: u64,
    /// Expired email tokens.
    pub email_tokens: u64,
    /// Expired service-auth-blacklist rows.
    pub service_auth_blacklist: u64,
    /// Revoked OAuth access tokens dropped once past their own `exp`.
    pub oauth_revoked_token: u64,
    /// Expired OAuth PAR + auth-code rows (combined).
    pub oauth_state: u64,
    /// Expired JTI replay rows (`jti_replay` table; §6.1 SQL backend).
    pub jti_replay: u64,
    /// Expired rate-limit-window rows (`rate_limit_window`; §6.2 SQL backend).
    pub rate_limit_window: u64,
    /// Pruned `space_record_oplog` + `space_member_oplog` rows summed across
    /// all accounts (`§11h`). Includes rows from per-actor stores that
    /// exceed the configured `space_oplog_retention_days`.
    pub space_oplog: u64,
    /// Blob rows deleted because nothing referenced them any more, summed
    /// across all accounts.
    pub orphan_blobs: u64,
    /// Lapsed `space_credential_recipient` rows deleted, summed across all
    /// accounts.
    pub expired_notify_registrations: u64,
}

/// Optional knobs the unified GC tick honors.
#[derive(Debug, Clone)]
pub struct TickOptions<'a> {
    /// Path to the PDS data directory; required for the per-actor oplog
    /// sweep. When `None`, the oplog step is skipped.
    pub data_dir: Option<&'a std::path::Path>,
    /// Retention window for `space_*_oplog` rows in days. Defaults to
    /// [`DEFAULT_SPACE_OPLOG_RETENTION_DAYS`] (30). When `0`, the oplog
    /// step is skipped (operator-disabled).
    pub space_oplog_retention_days: i64,
    /// How long an unreferenced blob is kept before it is collected, in
    /// hours. Defaults to [`DEFAULT_BLOB_GRACE_HOURS`] (24). When `0`, the
    /// blob sweep is skipped (operator-disabled).
    pub blob_grace_hours: i64,
}

impl Default for TickOptions<'_> {
    fn default() -> Self {
        Self {
            data_dir: None,
            space_oplog_retention_days: DEFAULT_SPACE_OPLOG_RETENTION_DAYS,
            blob_grace_hours: DEFAULT_BLOB_GRACE_HOURS,
        }
    }
}

/// Run one GC pass over the accounts pool + the optional JTI/limiter SQL
/// backends. Best-effort: per-table failures log at WARN and the tick
/// continues. The returned [`GcReport`] sums successful prune counts so the
/// caller can emit a single structured log line.
///
/// Back-compat shim — defaults [`TickOptions::data_dir`] to `None` so the
/// per-actor oplog sweep is skipped. Callers that want it should use
/// [`tick_with`].
pub async fn tick(
    pool: &SqlitePool,
    jti_guard: &JtiReplayGuard,
    rate_limiter: &SlidingWindowLimiter,
) -> GcReport {
    tick_with(pool, jti_guard, rate_limiter, &TickOptions::default()).await
}

/// As [`tick`], but with explicit options. The unified GC loop in
/// `bin/pds.rs::unified_gc_loop` calls this with `data_dir` set so the
/// per-actor oplog sweep runs.
pub async fn tick_with(
    pool: &SqlitePool,
    jti_guard: &JtiReplayGuard,
    rate_limiter: &SlidingWindowLimiter,
    opts: &TickOptions<'_>,
) -> GcReport {
    let mut report = GcReport::default();
    let now = chrono::Utc::now();
    let now_iso = now.to_rfc3339();
    let cutoff_delivered =
        (now - chrono::Duration::days(DEFAULT_NOTIFY_DELIVERED_RETENTION_DAYS)).to_rfc3339();
    let cutoff_failed =
        (now - chrono::Duration::days(DEFAULT_NOTIFY_FAILED_RETENTION_DAYS)).to_rfc3339();

    report.notify_delivered = run_or_log(
        "notify_attempt(delivered)",
        prune_notify(pool, "delivered", &cutoff_delivered),
    )
    .await;
    report.notify_failed = run_or_log(
        "notify_attempt(failed)",
        prune_notify(pool, "failed", &cutoff_failed),
    )
    .await;
    report.email_tokens = run_or_log(
        "email_token",
        prune_simple(
            pool,
            "DELETE FROM email_token WHERE expires_at < ?",
            &now_iso,
        ),
    )
    .await;
    let account_pool = crate::account::AccountPool::Sqlite(pool.clone());
    report.oauth_revoked_token = run_or_log(
        "oauth_revoked_token",
        crate::oauth::revoked::gc(&account_pool),
    )
    .await;
    report.service_auth_blacklist = run_or_log(
        "service_auth_blacklist",
        crate::service_auth_blacklist::gc(&account_pool),
    )
    .await;
    report.oauth_state = run_or_log("oauth_par+oauth_code", prune_oauth(pool, &now_iso)).await;
    report.jti_replay = run_or_log("jti_replay", jti_guard.gc()).await;
    report.rate_limit_window = run_or_log("rate_limit_window", rate_limiter.gc()).await;

    // Per-actor sweeps. Both walk every account, so they share one pass and one
    // store handle each rather than opening every actor database twice.
    if let Some(dir) = opts.data_dir {
        let cutoff_tid = (opts.space_oplog_retention_days > 0).then(|| {
            atproto_record::tid::Tid::new_with_time(
                (now - chrono::Duration::days(opts.space_oplog_retention_days)).timestamp_micros()
                    as u64,
            )
            .encode()
        });
        let blob_cutoff = (opts.blob_grace_hours > 0)
            .then(|| (now - chrono::Duration::hours(opts.blob_grace_hours)).to_rfc3339());

        // The sweep runs whenever a data dir is configured: lapsed notify
        // registrations are collected unconditionally, so disabling the oplog
        // and blob windows must not also disable that.
        {
            match prune_per_actor(
                pool,
                dir,
                cutoff_tid.as_deref(),
                blob_cutoff.as_deref(),
                &now.to_rfc3339(),
            )
            .await
            {
                Ok((oplog, blobs, registrations)) => {
                    report.space_oplog = oplog;
                    report.orphan_blobs = blobs;
                    report.expired_notify_registrations = registrations;
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "unified GC: per-actor sweep failed");
                }
            }
        }
    }

    report
}

/// Helper that runs a fallible u64-yielding future, logs and substitutes 0
/// on error. Keeps `tick` linear without nested `match` blocks.
async fn run_or_log<F: std::future::Future<Output = PdsResult<u64>>>(label: &str, fut: F) -> u64 {
    match fut.await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = ?e, table = %label, "unified GC: prune failed");
            0
        }
    }
}

async fn prune_notify(pool: &SqlitePool, state: &str, cutoff: &str) -> PdsResult<u64> {
    let result = sqlx::query(
        "DELETE FROM notify_attempt
         WHERE state = ? AND last_attempt_at IS NOT NULL AND last_attempt_at < ?",
    )
    .bind(state)
    .bind(cutoff)
    .execute(pool)
    .await
    .map_err(|e| crate::errors::PdsError::Storage {
        reason: format!("notify_attempt prune {state}: {e}"),
    })?;
    Ok(result.rows_affected())
}

async fn prune_simple(pool: &SqlitePool, sql: &str, bind: &str) -> PdsResult<u64> {
    let result = sqlx::query(sql)
        .bind(bind)
        .execute(pool)
        .await
        .map_err(|e| crate::errors::PdsError::Storage {
            reason: format!("prune {sql}: {e}"),
        })?;
    Ok(result.rows_affected())
}

/// Walk every account in the directory, open its per-actor store, and
/// prune `space_record_oplog` + `space_member_oplog` rows whose `rev`
/// (TID) sorts below the cutoff. Sums the row counts across actors.
/// One pass over every account, running whichever per-actor sweeps are enabled.
///
/// Returns `(oplog rows, blob rows)`.
///
/// Both sweeps walk the same account list and need the same store handle, so
/// they share a pass: opening a per-actor database is the dominant cost here,
/// and doing it twice per account per tick is the sort of thing that only
/// shows up once there are enough accounts for it to matter.
///
/// Opened through [`SqlActorStore::open_for_sweep`] rather than the ordinary
/// path, because a job that visits every account must not evict the pool cache
/// that live requests depend on, run migrations across the whole server, or
/// create a database for an account that never wrote one.
async fn prune_per_actor(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    cutoff_tid: Option<&str>,
    blob_cutoff: Option<&str>,
    now_iso: &str,
) -> PdsResult<(u64, u64, u64)> {
    use crate::actor_store::sql::SqlActorStore;
    let mut oplog_total = 0u64;
    let mut blob_total = 0u64;
    let mut registration_total = 0u64;
    let mut cursor: Option<String> = None;
    loop {
        let rows: Vec<(String,)> = match cursor.as_deref() {
            Some(c) => {
                sqlx::query_as("SELECT did FROM account WHERE did > ? ORDER BY did ASC LIMIT 200")
                    .bind(c)
                    .fetch_all(accounts_pool)
                    .await
            }
            None => {
                sqlx::query_as("SELECT did FROM account ORDER BY did ASC LIMIT 200")
                    .fetch_all(accounts_pool)
                    .await
            }
        }
        .map_err(|e| crate::errors::PdsError::Storage {
            reason: format!("per-actor sweep: list accounts: {e}"),
        })?;
        if rows.is_empty() {
            break;
        }
        let last = rows.last().map(|(d,)| d.clone());
        for (did,) in rows {
            // Best-effort: if the per-actor store can't be opened (deleted
            // account, fjall-only deployments, etc.), log + continue.
            let store = match SqlActorStore::open_for_sweep(data_dir, &did).await {
                Ok(Some(s)) => s,
                // An account with no database yet has nothing to collect, and
                // creating one to discover that is the opposite of the job.
                Ok(None) => continue,
                Err(e) => {
                    tracing::debug!(did = %did, error = ?e, "per-actor sweep: open store skipped");
                    continue;
                }
            };

            if let Some(cutoff_tid) = cutoff_tid {
                for table in ["space_record_oplog", "space_member_oplog"] {
                    let sql = format!("DELETE FROM {table} WHERE rev < ?");
                    match sqlx::query(&sql)
                        .bind(cutoff_tid)
                        .execute(store.pool())
                        .await
                    {
                        Ok(r) => oplog_total = oplog_total.saturating_add(r.rows_affected()),
                        Err(e) => {
                            tracing::warn!(did = %did, table, error = ?e, "space oplog: prune failed");
                        }
                    }
                }
            }

            if let Some(blob_cutoff) = blob_cutoff {
                match prune_orphan_blobs(&store, blob_cutoff).await {
                    Ok(n) => blob_total = blob_total.saturating_add(n),
                    Err(e) => {
                        tracing::warn!(did = %did, error = ?e, "orphan blobs: prune failed");
                    }
                }
            }

            // Lapsed notify registrations. Delivery has always skipped rows
            // past their `expires_at`, so these are already inert -- but
            // nothing ever deleted them, and a registration is renewed by
            // re-registering, so a subscriber that renews on a timer leaves
            // one dead row behind per renewal, for ever. Skipping a row on
            // every fan-out is cheap; storing it for ever is not.
            //
            // Rows with a NULL `expires_at` are left alone: those are the
            // perpetual registrations `getSpaceCredential` creates, which are
            // withdrawn through `unregisterNotify` rather than aged out.
            match sqlx::query(
                "DELETE FROM space_credential_recipient WHERE expires_at IS NOT NULL AND expires_at <= ?",
            )
            .bind(now_iso)
            .execute(store.pool())
            .await
            {
                Ok(r) => {
                    registration_total = registration_total.saturating_add(r.rows_affected());
                }
                Err(e) => {
                    tracing::warn!(did = %did, error = ?e, "expired notify registrations: prune failed");
                }
            }
        }
        cursor = last;
    }
    Ok((oplog_total, blob_total, registration_total))
}

/// Delete blob bytes nothing refers to any more.
///
/// Nothing did this. `drop_refs_for_record` has always returned the CIDs whose
/// last reference it removed, documented as "caller GCs the blob bytes", and no
/// caller ever did; `delete_blob` had no production call site at all. So the
/// bytes of every replaced avatar and every deleted video stayed, and an account
/// could grow its store without bound by writing records and deleting them.
///
/// Both reference tables are consulted, not just the public one. A blob uploaded
/// through `com.atproto.repo.uploadBlob` and referenced only from a permissioned
/// record has no `repo_blob_ref` row and is very much in use; collecting on the
/// public table alone would delete live data out of spaces.
///
/// The age condition is what makes this safe to run against a live server rather
/// than a courtesy: see [`DEFAULT_BLOB_GRACE_HOURS`].
async fn prune_orphan_blobs(
    store: &crate::actor_store::sql::SqlActorStore,
    cutoff: &str,
) -> PdsResult<u64> {
    let result = sqlx::query(
        "DELETE FROM repo_blob
         WHERE created_at < ?
           AND cid NOT IN (SELECT blob_cid FROM repo_blob_ref)
           AND cid NOT IN (SELECT blob_cid FROM space_blob_ref)",
    )
    .bind(cutoff)
    .execute(store.pool())
    .await
    .map_err(|e| crate::errors::PdsError::Storage {
        reason: format!("prune orphan blobs: {e}"),
    })?;
    Ok(result.rows_affected())
}

async fn prune_oauth(pool: &SqlitePool, now_iso: &str) -> PdsResult<u64> {
    let par = sqlx::query("DELETE FROM oauth_par WHERE expires_at < ?")
        .bind(now_iso)
        .execute(pool)
        .await
        .map_err(|e| crate::errors::PdsError::Storage {
            reason: format!("oauth_par prune: {e}"),
        })?;
    let code = sqlx::query("DELETE FROM oauth_code WHERE expires_at < ?")
        .bind(now_iso)
        .execute(pool)
        .await
        .map_err(|e| crate::errors::PdsError::Storage {
            reason: format!("oauth_code prune: {e}"),
        })?;
    Ok(par.rows_affected() + code.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use std::time::Duration;

    async fn fresh_pool() -> SqlitePool {
        AccountDirectory::open_memory()
            .await
            .unwrap()
            .pool()
            .clone()
    }

    /// On an empty DB, the GC tick is a no-op and produces a zero report.
    #[tokio::test(flavor = "multi_thread")]
    async fn gc_tick_on_empty_db() {
        let pool = fresh_pool().await;
        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let report = tick(&pool, &jti_guard, &rate_limiter).await;
        assert_eq!(report, GcReport::default());
    }

    /// A blob nothing refers to is collected; one that is still referenced,
    /// from either realm, is not.
    ///
    /// The space case is the one worth stating. Permissioned blobs are uploaded
    /// through the ordinary `com.atproto.repo.uploadBlob` and land in the same
    /// `repo_blob` table, so a blob referenced only from a permissioned record
    /// has no `repo_blob_ref` row at all. Sweeping on the public table alone
    /// would read that as unreferenced and delete live data out of a space.
    #[tokio::test(flavor = "multi_thread")]
    async fn orphan_blobs_are_collected_and_referenced_ones_are_not() {
        use crate::actor_store::sql::SqlActorStore;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let pool = accounts.pool().clone();
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
             VALUES ('did:plc:alice', 'alice.example', '$argon2id$x', '2026-05-01T00:00:00Z',
                     'active', 'file:x', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let store = SqlActorStore::open(&dir, "did:plc:alice").await.unwrap();
        // Four blobs, all older than any grace window.
        for cid in ["orphan", "public", "spaceonly", "recent"] {
            let created = if cid == "recent" {
                "2099-01-01T00:00:00Z"
            } else {
                "2020-01-01T00:00:00Z"
            };
            sqlx::query(
                "INSERT INTO repo_blob (cid, mime_type, size, data, created_at)
                 VALUES (?, 'image/png', 3, X'010203', ?)",
            )
            .bind(cid)
            .bind(created)
            .execute(store.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
             VALUES ('at://did:plc:alice/c/1', 'public', 'image/png', 3)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO space_blob_ref (space, record_uri, blob_cid)
             VALUES ('at://did:plc:alice/space/t/k', 'at://did:plc:alice/space/t/k/a/c/1', 'spaceonly')",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let opts = TickOptions {
            data_dir: Some(&dir),
            ..Default::default()
        };
        let report = tick_with(&pool, &jti_guard, &rate_limiter, &opts).await;

        assert_eq!(
            report.orphan_blobs, 1,
            "only the unreferenced blob should go"
        );

        let remaining: Vec<(String,)> =
            sqlx::query_as("SELECT cid FROM repo_blob ORDER BY cid ASC")
                .fetch_all(store.pool())
                .await
                .unwrap();
        let remaining: Vec<&str> = remaining.iter().map(|(c,)| c.as_str()).collect();
        assert_eq!(
            remaining,
            vec!["public", "recent", "spaceonly"],
            "a referenced or too-new blob must survive"
        );
    }

    /// The grace window is what makes the sweep safe to run against a live
    /// server: `uploadBlob` stores bytes before any record names them, so a
    /// blob is unreferenced for as long as the client takes to write the
    /// record that uses it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_freshly_uploaded_blob_is_not_collected() {
        use crate::actor_store::sql::SqlActorStore;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let pool = accounts.pool().clone();
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
             VALUES ('did:plc:alice', 'alice.example', '$argon2id$x', '2026-05-01T00:00:00Z',
                     'active', 'file:x', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let store = SqlActorStore::open(&dir, "did:plc:alice").await.unwrap();
        sqlx::query(
            "INSERT INTO repo_blob (cid, mime_type, size, data, created_at)
             VALUES ('justuploaded', 'image/png', 3, X'010203', ?)",
        )
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(store.pool())
        .await
        .unwrap();

        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let opts = TickOptions {
            data_dir: Some(&dir),
            ..Default::default()
        };
        let report = tick_with(&pool, &jti_guard, &rate_limiter, &opts).await;

        assert_eq!(
            report.orphan_blobs, 0,
            "a blob uploaded moments ago is not yet an orphan"
        );
    }

    /// Stale email_token rows past `expires_at` get pruned; live ones survive.
    #[tokio::test(flavor = "multi_thread")]
    async fn gc_prunes_expired_email_tokens() {
        let pool = fresh_pool().await;
        // Seed: alice's account so the FK on email_token.did is satisfied.
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
             VALUES ('did:plc:alice', 'alice.example', '$argon2id$x', '2026-05-01T00:00:00Z',
                     'active', 'file:x', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Two tokens: one expired, one live.
        sqlx::query(
            "INSERT INTO email_token (token, did, purpose, expires_at)
             VALUES ('expired', 'did:plc:alice', 'update_email', '2020-01-01T00:00:00Z'),
                    ('live', 'did:plc:alice', 'update_email', '2099-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let report = tick(&pool, &jti_guard, &rate_limiter).await;
        assert_eq!(report.email_tokens, 1);

        let live: Option<(String,)> =
            sqlx::query_as("SELECT token FROM email_token WHERE token = 'live'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(live.is_some(), "live token must remain");
        let expired: Option<(String,)> =
            sqlx::query_as("SELECT token FROM email_token WHERE token = 'expired'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(expired.is_none(), "expired token must be pruned");
    }

    /// Stale `service_auth_blacklist` rows get pruned.
    #[tokio::test(flavor = "multi_thread")]
    async fn gc_prunes_expired_service_auth_blacklist() {
        let pool = fresh_pool().await;
        sqlx::query(
            "INSERT INTO service_auth_blacklist (jti, expires_at)
             VALUES ('expired', '2020-01-01T00:00:00Z'),
                    ('live', '2099-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let report = tick(&pool, &jti_guard, &rate_limiter).await;
        assert_eq!(report.service_auth_blacklist, 1);
        let row: Option<(String,)> =
            sqlx::query_as("SELECT jti FROM service_auth_blacklist WHERE jti = 'expired'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(row.is_none());
    }

    /// Notify-attempt rows past delivered/failed retention get pruned;
    /// pending rows are untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn gc_prunes_old_notify_attempts() {
        let pool = fresh_pool().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
        sqlx::query(
            "INSERT INTO notify_attempt
                (id, target_service_did, target_endpoint, payload_cbor, nsid,
                 attempt_count, last_attempt_at, next_attempt_at, state)
             VALUES
                ('a', 'did:web:peer', 'https://peer/x', X'00', 'com.atproto.space.notifyWrite',
                 1, ?, '2099-01-01T00:00:00Z', 'delivered'),
                ('b', 'did:web:peer', 'https://peer/x', X'00', 'com.atproto.space.notifyWrite',
                 1, NULL, '2099-01-01T00:00:00Z', 'pending')",
        )
        .bind(&cutoff)
        .execute(&pool)
        .await
        .unwrap();

        let jti_guard = JtiReplayGuard::new_sql(pool.clone());
        let rate_limiter =
            SlidingWindowLimiter::new_sql(pool.clone(), 100, Duration::from_secs(60));
        let report = tick(&pool, &jti_guard, &rate_limiter).await;
        assert_eq!(report.notify_delivered, 1);
        let pending: Option<(String,)> =
            sqlx::query_as("SELECT id FROM notify_attempt WHERE id = 'b'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(pending.is_some(), "pending row untouched");
    }

    /// The sweep does not create a database for an account that has none.
    ///
    /// It used to open every account through the ordinary path, which has
    /// `create_if_missing(true)` and runs migrations -- so a nightly job whose
    /// purpose is to remove data materialised a fresh SQLite file, with a full
    /// schema, for every account row that had never written one.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_sweep_does_not_create_databases() {
        let pool = fresh_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref)
             VALUES ('did:plc:neverwrote', 'nw.example', 'x', '2026-01-01T00:00:00Z', 'active', 'k')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let (oplog, blobs, _) = prune_per_actor(
            &pool,
            tmp.path(),
            Some("3zzzzzzzzzzzz"),
            Some("2099-01-01T00:00:00Z"),
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .expect("sweep");
        assert_eq!((oplog, blobs), (0, 0));

        let actors = tmp.path().join("actors");
        let created = tokio::fs::try_exists(&actors).await.unwrap_or(false);
        assert!(
            !created,
            "the sweep created {} for an account with no data",
            actors.display()
        );
    }

    /// The sweep does not evict the pool cache that live requests use.
    ///
    /// The cache holds a bounded number of pools. A sweep over more accounts
    /// than that, opening each through the ordinary path, evicts every pool
    /// serving live traffic -- so the cache that exists to keep request
    /// latency down was emptied by the one job with nothing to gain from it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_sweep_leaves_the_pool_cache_alone() {
        use crate::actor_store::sql::SqlActorStore;
        let pool = fresh_pool().await;
        let tmp = tempfile::tempdir().unwrap();

        // Enough sweep-visited accounts to overrun any bounded cache, each
        // with a database on disk so the sweep actually opens it. Seeded
        // first: creating them goes through the ordinary path, which is
        // itself enough to evict anything already cached.
        let live = "did:plc:livetraffic";
        for i in 0..300 {
            let did = format!("did:plc:swept{i:04}");
            SqlActorStore::open(tmp.path(), &did).await.unwrap();
            sqlx::query(
                "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref)
                 VALUES (?, ?, 'x', '2026-01-01T00:00:00Z', 'active', 'k')",
            )
            .bind(&did)
            .bind(format!("s{i:04}.example"))
            .execute(&pool)
            .await
            .unwrap();
        }

        // Now the account under live traffic, so it is in the cache when the
        // sweep starts -- which is the state the sweep must not disturb.
        SqlActorStore::open(tmp.path(), live).await.unwrap();
        let before = crate::actor_store::sql::pools_built_for_did(tmp.path(), live);
        prune_per_actor(
            &pool,
            tmp.path(),
            Some("3zzzzzzzzzzzz"),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .expect("sweep");
        SqlActorStore::open(tmp.path(), live).await.unwrap();
        let after = crate::actor_store::sql::pools_built_for_did(tmp.path(), live);

        assert_eq!(
            before, after,
            "the live account's pool was rebuilt after the sweep, so the sweep \
             evicted it from the cache"
        );
    }

    /// The retention prune seeks the cutoff instead of reading the table.
    ///
    /// Both oplog tables are keyed `(space, rev, idx)`, so `rev` is the second
    /// column and `WHERE rev < ?` could not seek on it. Every tick scanned
    /// both tables in full in every account, including -- overwhelmingly the
    /// common case -- ticks where nothing has aged past the cutoff at all.
    ///
    /// The plan is asserted rather than a duration, for the same reason as
    /// everywhere else: a threshold either flakes on a shared machine or is
    /// loose enough to stop catching the regression.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_oplog_prune_seeks_the_cutoff() {
        use crate::actor_store::sql::SqlActorStore;
        let tmp = tempfile::tempdir().unwrap();
        let store = SqlActorStore::open(tmp.path(), "did:plc:planned")
            .await
            .unwrap();

        for table in ["space_record_oplog", "space_member_oplog"] {
            let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(&format!(
                "EXPLAIN QUERY PLAN DELETE FROM {table} WHERE rev < ?"
            ))
            .bind("3zzzzzzzzzzzz")
            .fetch_all(store.pool())
            .await
            .expect("explain");
            let rendered = plan
                .into_iter()
                .map(|(_, _, _, detail)| detail)
                .collect::<Vec<_>>()
                .join("\n");
            // "USING INDEX" or "USING COVERING INDEX" -- which of the two
            // SQLite picks is not the point, and pinning it would make this
            // fail on a planner improvement rather than on a regression.
            assert!(
                rendered.contains(&format!("idx_{table}_rev")) && rendered.contains("SEARCH"),
                "{table} prune should seek its rev index; plan was:\n{rendered}"
            );
            assert!(
                !rendered.contains(&format!("SCAN {table}")),
                "{table} prune still reads the whole table; plan was:\n{rendered}"
            );
        }
    }
    /// Lapsed notify registrations are collected; live and perpetual ones are
    /// not.
    ///
    /// Delivery already skips a row past its expiry, so these are inert — but
    /// nothing deleted them, and a subscriber renews by re-registering, so a
    /// syncer on a renewal timer left one dead row behind per renewal for
    /// ever. The rows with no expiry are the ones `getSpaceCredential`
    /// creates; those are withdrawn deliberately through `unregisterNotify`,
    /// not aged out underneath their owner.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_sweep_collects_lapsed_notify_registrations() {
        use crate::actor_store::sql::SqlActorStore;
        let pool = fresh_pool().await;
        let tmp = tempfile::tempdir().unwrap();
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref)
             VALUES ('did:plc:owner', 'owner.example', 'x', '2026-01-01T00:00:00Z', 'active', 'k')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = SqlActorStore::open(tmp.path(), "did:plc:owner")
            .await
            .unwrap();
        let space = "at://did:plc:owner/space/app.bsky.group/default";
        sqlx::query("INSERT INTO space (uri, is_owner, is_member, created_at) VALUES (?, 1, 1, ?)")
            .bind(space)
            .bind("2026-01-01T00:00:00Z")
            .execute(store.pool())
            .await
            .unwrap();
        for (service, expires) in [
            ("did:web:lapsed.example", Some("2000-01-01T00:00:00Z")),
            ("did:web:live.example", Some("2099-01-01T00:00:00Z")),
            ("did:web:perpetual.example", None),
        ] {
            sqlx::query(
                "INSERT INTO space_credential_recipient
                   (space, repo, service_did, service_endpoint, last_issued_at, expires_at)
                 VALUES (?, '', ?, 'https://x.example', '2026-01-01T00:00:00Z', ?)",
            )
            .bind(space)
            .bind(service)
            .bind(expires)
            .execute(store.pool())
            .await
            .unwrap();
        }

        let (_, _, collected) = prune_per_actor(
            &pool,
            tmp.path(),
            None,
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .unwrap();
        assert_eq!(collected, 1, "only the lapsed registration");

        let left: Vec<String> = sqlx::query_scalar(
            "SELECT service_did FROM space_credential_recipient ORDER BY service_did",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(
            left,
            vec![
                "did:web:live.example".to_string(),
                "did:web:perpetual.example".to_string()
            ],
            "a live registration and one with no expiry both survive"
        );
    }
}
