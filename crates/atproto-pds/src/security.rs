//! Production-hardening primitives: JTI replay guard, sliding-window
//! rate limiter, and supporting plumbing.
//!
//! Every JWT-verify step in OAuth / DPoP / delegation-token /
//! client-attestation / service-auth checks the token's `jti` against a replay
//! filter; every authenticated XRPC call passes through a rate limiter.
//!
//! Two backends per primitive:
//!
//! - **Memory** (default) — in-process bounded structures. Loses all state
//!   on PDS restart. Fine for DPoP (60s-bounded), gap for OAuth refresh
//!   rotation (30-day TTL, single-use per RFC 6749 §6) and service-auth.
//! - **Sql** — SQLite-backed against the accounts pool. Survives restart;
//!   the unified GC loop in `bin/pds.rs` (§6.3) prunes expired rows daily.
//!
//! - **Valkey** — Redis-protocol-backed. Compiled in via the `valkey` Cargo feature;
//!   wins over `--durability-profile=sql|memory` when `PDS_VALKEY_URL`
//!   is configured. JTI keys use `SET key 1 NX EX <ttl>` and rate-limit
//!   keys use a per-key `ZSET` with `EXPIRE` for GC.

use dashmap::DashMap;
use sqlx::SqlitePool;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::errors::{PdsError, PdsResult};

/// Compare two secrets without leaking their contents through timing.
///
/// A `!=` on `&str` short-circuits at the first differing byte, so the time it
/// takes to reject a guess reveals how much of the prefix was right — enough to
/// recover a secret one byte at a time against an endpoint an attacker can call
/// repeatedly.
///
/// Both sides are MAC'd under a key generated for this call and the tags are
/// compared through HMAC's own verifier. That is constant-time in the contents
/// *and* independent of length: hashing first means a 4-byte guess and a
/// 400-byte guess take the same path, so the comparison leaks neither the
/// secret nor its size. The per-call key means the tags are useless to an
/// attacker who somehow observes them.
#[must_use]
pub fn secret_eq(presented: &str, expected: &str) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    use rand::RngExt;
    use sha2::Sha256;

    let mut key = [0u8; 32];
    rand::rng().fill(&mut key);

    let tag = |value: &str| {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
            .expect("HMAC accepts a key of any length");
        mac.update(value.as_bytes());
        mac.finalize().into_bytes()
    };

    let mut verifier =
        <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC accepts a key of any length");
    verifier.update(presented.as_bytes());
    verifier.verify_slice(&tag(expected)).is_ok()
}

// ---------------------------------------------------------------------------
//  JTI replay guard
// ---------------------------------------------------------------------------

/// Replay guard for JWT `jti` claims.
///
/// On verify: check membership; if present, the token is a replay (reject).
/// If absent, insert with TTL = `exp - iat`. Two backends per §6.1:
///
/// - [`JtiReplayGuard::Memory`] — in-process bounded LRU.
/// - [`JtiReplayGuard::Sql`] — SQLite-backed; survives PDS restart.
///
/// Cheap to clone (`Arc`-wrapped internally; the SQL pool is also `Clone`).
#[derive(Clone)]
pub enum JtiReplayGuard {
    /// In-process bounded LRU.
    Memory(MemoryJtiInner),
    /// SQLite-backed (table `jti_replay`).
    Sql(SqlJtiInner),
    /// Valkey/Redis-backed. Per-key TTL handles
    /// expiry; no separate prune loop needed. Boxed to keep the
    /// non-feature variants compact.
    #[cfg(feature = "valkey")]
    Valkey(Box<crate::valkey_backend::ValkeyJtiInner>),
}

/// In-memory replay guard internals. Public for type-naming purposes; not
/// constructed directly — call [`JtiReplayGuard::new`] instead.
#[derive(Clone)]
pub struct MemoryJtiInner {
    inner: Arc<MemoryJtiState>,
}

struct MemoryJtiState {
    seen: DashMap<String, Instant>,
    insertion_order: Mutex<VecDeque<(String, Instant)>>,
    max_entries: usize,
}

/// SQL-backed replay guard internals.
#[derive(Clone)]
pub struct SqlJtiInner {
    pool: SqlitePool,
}

impl JtiReplayGuard {
    /// Construct a new in-memory JTI replay guard.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self::Memory(MemoryJtiInner {
            inner: Arc::new(MemoryJtiState {
                seen: DashMap::new(),
                insertion_order: Mutex::new(VecDeque::with_capacity(max_entries.min(1024))),
                max_entries,
            }),
        })
    }

    /// Construct a new SQL-backed JTI replay guard.
    ///
    /// `pool` must be the accounts DB; the migration creates the
    /// `jti_replay` table.
    #[must_use]
    pub fn new_sql(pool: SqlitePool) -> Self {
        Self::Sql(SqlJtiInner { pool })
    }

    /// Construct a Valkey/Redis-backed JTI replay guard
    /// Available only when the `valkey` feature
    /// is on.
    #[cfg(feature = "valkey")]
    #[must_use]
    pub fn new_valkey(client: crate::valkey_backend::ValkeyClient) -> Self {
        Self::Valkey(Box::new(crate::valkey_backend::ValkeyJtiInner::new(client)))
    }

    /// Check and (if absent) record a JTI.
    ///
    /// Returns `Ok(())` on first sight; returns `Err(JtiReplay)` if the JTI
    /// was already recorded within its TTL.
    ///
    /// `ttl` is the remaining lifetime of the token (i.e. `exp - now`).
    pub async fn check_and_insert(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplay> {
        match self {
            Self::Memory(g) => g.check_and_insert(jti, ttl).await,
            Self::Sql(g) => g.check_and_insert(jti, ttl).await,
            #[cfg(feature = "valkey")]
            Self::Valkey(g) => g.check_and_insert(jti, ttl).await,
        }
    }

    /// Current entry count (mostly useful for tests). Returns 0 for the
    /// SQL backend without hitting the DB; call [`JtiReplayGuard::sql_count`]
    /// for that. Always 0 for the Valkey backend (live counting is
    /// O(N) on a key scan; not worth the round-trip for a debug
    /// observable).
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Memory(g) => g.inner.seen.len(),
            Self::Sql(_) => 0,
            #[cfg(feature = "valkey")]
            Self::Valkey(_) => 0,
        }
    }

    /// Whether the in-memory guard is empty. Always true for the SQL
    /// backend; this is a `len() == 0` convenience for tests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Live count from the SQL backend. Returns `Ok(0)` for the memory
    /// backend.
    pub async fn sql_count(&self) -> PdsResult<i64> {
        match self {
            Self::Memory(_) => Ok(0),
            Self::Sql(g) => {
                let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM jti_replay")
                    .fetch_one(&g.pool)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("jti_replay count: {e}"),
                    })?;
                Ok(row.0)
            }
            #[cfg(feature = "valkey")]
            Self::Valkey(_) => Ok(0),
        }
    }

    /// GC expired rows from the SQL backend; no-op for memory + Valkey
    /// (Valkey relies on per-key TTL). Returns the number of rows
    /// pruned. Called by the unified GC loop (§6.3).
    pub async fn gc(&self) -> PdsResult<u64> {
        match self {
            Self::Memory(_) => Ok(0),
            Self::Sql(g) => {
                let now = chrono::Utc::now().to_rfc3339();
                let result = sqlx::query("DELETE FROM jti_replay WHERE expires_at < ?")
                    .bind(&now)
                    .execute(&g.pool)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("jti_replay gc: {e}"),
                    })?;
                Ok(result.rows_affected())
            }
            #[cfg(feature = "valkey")]
            Self::Valkey(_) => Ok(0),
        }
    }
}

impl MemoryJtiInner {
    async fn check_and_insert(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplay> {
        let now = Instant::now();
        let deadline = now + ttl;

        // First check membership; if present and not expired, reject.
        if let Some(existing) = self.inner.seen.get(jti)
            && *existing >= now
        {
            return Err(JtiReplay {
                jti: jti.to_string(),
            });
        }
        // Expired — fall through to refresh + insert below.

        // Insert.
        self.inner.seen.insert(jti.to_string(), deadline);
        let mut order = self.inner.insertion_order.lock().await;
        order.push_back((jti.to_string(), deadline));

        // Opportunistic eviction: drop expired front entries until we hit a
        // live one or shrink under the cap.
        while let Some((front_jti, front_deadline)) = order.front() {
            if *front_deadline >= now && order.len() <= self.inner.max_entries {
                break;
            }
            self.inner.seen.remove(front_jti);
            order.pop_front();
        }

        Ok(())
    }
}

impl SqlJtiInner {
    async fn check_and_insert(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplay> {
        let now = chrono::Utc::now();
        let expires_at = (now
            + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(60)))
        .to_rfc3339();
        // Atomic INSERT — UNIQUE constraint on `jti` rejects replays. We
        // also opportunistically drop a row whose `expires_at` < now so
        // an expired token can be re-issued and presented again. This is
        // the SQL equivalent of the in-memory guard's expiry-then-insert
        // path.
        //
        // Two-step: first try an INSERT; if it fails on UNIQUE, fetch the
        // existing row and decide.
        let result = sqlx::query("INSERT INTO jti_replay (jti, expires_at) VALUES (?, ?)")
            .bind(jti)
            .bind(&expires_at)
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                // Existing row — check if expired.
                let row: Option<(String,)> =
                    sqlx::query_as("SELECT expires_at FROM jti_replay WHERE jti = ?")
                        .bind(jti)
                        .fetch_optional(&self.pool)
                        .await
                        .ok()
                        .flatten();
                let live = match row {
                    Some((exp,)) => match chrono::DateTime::parse_from_rfc3339(&exp) {
                        Ok(dt) => dt > now,
                        Err(_) => true,
                    },
                    None => false,
                };
                if live {
                    Err(JtiReplay {
                        jti: jti.to_string(),
                    })
                } else {
                    // Refresh the expired row and accept the JTI.
                    let _ = sqlx::query("UPDATE jti_replay SET expires_at = ? WHERE jti = ?")
                        .bind(&expires_at)
                        .bind(jti)
                        .execute(&self.pool)
                        .await;
                    Ok(())
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, jti = %jti, "jti_replay insert failed");
                // Fail-open on storage error so PDS keeps serving traffic;
                // the operator alarm should fire on the structured error.
                Ok(())
            }
        }
    }
}

/// Returned by [`JtiReplayGuard::check_and_insert`] on a replayed JTI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JtiReplay {
    /// The replayed JTI.
    pub jti: String,
}

impl std::fmt::Display for JtiReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JWT jti {} has already been used (replay)", self.jti)
    }
}

impl std::error::Error for JtiReplay {}

// ---------------------------------------------------------------------------
//  Sliding-window rate limiter
// ---------------------------------------------------------------------------

/// Per-key sliding-window rate limiter — fair under bursty load.
///
/// Each key has a deque (memory) or a per-row history (SQL) of request
/// timestamps. A request is allowed if the count of in-window entries is
/// below `limit`. Per §6.2, two backends:
///
/// - [`SlidingWindowLimiter::Memory`] — in-process per-key deque, bounded
///   by `max_keys`.
/// - [`SlidingWindowLimiter::Sql`] — `rate_limit_window` table, survives
///   restart. SQL-backed limiting under heavy load can become a
///   bottleneck; Valkey is the recommended production path.
#[derive(Clone)]
pub enum SlidingWindowLimiter {
    /// In-process per-key deques.
    Memory(MemoryLimiterInner),
    /// SQLite-backed (`rate_limit_window`).
    Sql(SqlLimiterInner),
    /// Valkey/Redis-backed. Per-key sorted-set
    /// (`ZSET`) of request timestamps; `EXPIRE` handles GC. Boxed
    /// to keep the non-feature variants compact.
    #[cfg(feature = "valkey")]
    Valkey(Box<crate::valkey_backend::ValkeyLimiterInner>),
}

/// In-memory limiter internals. See [`SlidingWindowLimiter::new`].
#[derive(Clone)]
pub struct MemoryLimiterInner {
    inner: Arc<MemoryLimiterState>,
}

struct MemoryLimiterState {
    /// Per-key bucket. We use `Arc<Mutex<…>>` (not `DashMap<…, Mutex<…>>`)
    /// so we can `clone()` the Arc out of the dashmap and immediately drop
    /// the shard ref before awaiting the bucket lock — avoiding deadlocks
    /// against any sibling `iter()` for keyspace pruning.
    buckets: DashMap<String, Arc<Mutex<VecDeque<Instant>>>>,
    limit: usize,
    window: Duration,
    max_keys: usize,
}

/// SQL-backed limiter internals.
#[derive(Clone)]
pub struct SqlLimiterInner {
    pool: SqlitePool,
    limit: usize,
    window: Duration,
}

impl SlidingWindowLimiter {
    /// Construct an in-memory rate limiter.
    ///
    /// - `limit` — max requests allowed within `window`.
    /// - `window` — the rolling time window.
    /// - `max_keys` — distinct-key ceiling. Old entries dropped on overflow.
    #[must_use]
    pub fn new(limit: usize, window: Duration, max_keys: usize) -> Self {
        Self::Memory(MemoryLimiterInner {
            inner: Arc::new(MemoryLimiterState {
                buckets: DashMap::new(),
                limit,
                window,
                max_keys,
            }),
        })
    }

    /// Construct a SQL-backed rate limiter against the accounts pool.
    #[must_use]
    pub fn new_sql(pool: SqlitePool, limit: usize, window: Duration) -> Self {
        Self::Sql(SqlLimiterInner {
            pool,
            limit,
            window,
        })
    }

    /// Construct a Valkey/Redis-backed rate limiter. Available only when the `valkey` feature is on.
    #[cfg(feature = "valkey")]
    #[must_use]
    pub fn new_valkey(
        client: crate::valkey_backend::ValkeyClient,
        limit: usize,
        window: Duration,
    ) -> Self {
        Self::Valkey(Box::new(crate::valkey_backend::ValkeyLimiterInner::new(
            client, limit, window,
        )))
    }

    /// Configured limit (max requests per window).
    #[must_use]
    pub fn limit(&self) -> usize {
        match self {
            Self::Memory(m) => m.inner.limit,
            Self::Sql(s) => s.limit,
            #[cfg(feature = "valkey")]
            Self::Valkey(v) => v.limit,
        }
    }

    /// Configured rolling window.
    #[must_use]
    pub fn window(&self) -> Duration {
        match self {
            Self::Memory(m) => m.inner.window,
            Self::Sql(s) => s.window,
            #[cfg(feature = "valkey")]
            Self::Valkey(v) => v.window,
        }
    }

    /// Try to record a request for `key`. Returns `Ok(remaining)` on accept
    /// (where `remaining = limit - new-count`) or `Err(retry_after)` on
    /// rate-limit hit.
    pub async fn try_acquire(&self, key: &str) -> Result<usize, RateLimited> {
        match self {
            Self::Memory(m) => m.try_acquire(key).await,
            Self::Sql(s) => s.try_acquire(key).await,
            #[cfg(feature = "valkey")]
            Self::Valkey(v) => v.try_acquire(key).await,
        }
    }

    /// GC expired window rows from the SQL backend; no-op for memory
    /// and Valkey (Valkey relies on per-key `EXPIRE`). Returns the
    /// number of rows pruned. Drops everything older than `now -
    /// max_window` where `max_window = window` for the configured
    /// limiter — gives some safety margin without bloating the table.
    pub async fn gc(&self) -> PdsResult<u64> {
        match self {
            Self::Memory(_) => Ok(0),
            Self::Sql(s) => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let cutoff = now_ms - (s.window.as_millis() as i64);
                let result = sqlx::query("DELETE FROM rate_limit_window WHERE request_at_ms < ?")
                    .bind(cutoff)
                    .execute(&s.pool)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("rate_limit_window gc: {e}"),
                    })?;
                Ok(result.rows_affected())
            }
            #[cfg(feature = "valkey")]
            Self::Valkey(_) => Ok(0),
        }
    }
}

impl MemoryLimiterInner {
    async fn try_acquire(&self, key: &str) -> Result<usize, RateLimited> {
        let now = Instant::now();
        let window_start = now - self.inner.window;

        // Acquire-or-insert the per-key bucket arc, then *immediately drop
        // the dashmap shard reference* before awaiting the inner mutex. This
        // is the key to avoiding deadlocks against any concurrent iter() for
        // pruning.
        let bucket = {
            let entry = self
                .inner
                .buckets
                .entry(key.to_string())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(VecDeque::with_capacity(self.inner.limit + 1)))
                });
            entry.value().clone()
        };

        let mut deque = bucket.lock().await;
        // Trim expired.
        while let Some(t) = deque.front() {
            if *t < window_start {
                deque.pop_front();
            } else {
                break;
            }
        }
        if deque.len() >= self.inner.limit {
            let oldest = *deque.front().expect("non-empty after limit check");
            let retry_after = (oldest + self.inner.window).saturating_duration_since(now);
            return Err(RateLimited { retry_after });
        }
        deque.push_back(now);
        let remaining = self.inner.limit.saturating_sub(deque.len());
        drop(deque);

        // Approximate-LRU keyspace cap. Safe to call now that no shard
        // references are held by the local stack.
        if self.inner.buckets.len() > self.inner.max_keys {
            let first = self
                .inner
                .buckets
                .iter()
                .map(|kv| kv.key().clone())
                .find(|k| k != key);
            if let Some(victim) = first {
                self.inner.buckets.remove(&victim);
            }
        }

        Ok(remaining)
    }
}

impl SqlLimiterInner {
    async fn try_acquire(&self, key: &str) -> Result<usize, RateLimited> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let window_start_ms = now_ms - (self.window.as_millis() as i64);

        // Single-pass: count in-window rows BEFORE inserting (so a request
        // at the cap doesn't transiently push count to limit+1). This is
        // a benign race under high contention — two concurrent requests
        // can both observe count = limit-1 and both insert; the practical
        // effect is one extra slot, well under the limit's safety margin.
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM rate_limit_window
             WHERE key = ? AND request_at_ms >= ?",
        )
        .bind(key)
        .bind(window_start_ms)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, key = %key, "rate_limit_window count failed");
            // Fail-open on storage error.
            RateLimited {
                retry_after: Duration::from_millis(0),
            }
        })?;

        if (count.0 as usize) >= self.limit {
            // Compute retry_after by finding the oldest in-window timestamp.
            let oldest: Option<(i64,)> = sqlx::query_as(
                "SELECT MIN(request_at_ms) FROM rate_limit_window
                 WHERE key = ? AND request_at_ms >= ?",
            )
            .bind(key)
            .bind(window_start_ms)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
            let retry_after = match oldest {
                Some((ms,)) => {
                    let expire_at = ms + self.window.as_millis() as i64;
                    let delta = (expire_at - now_ms).max(0) as u64;
                    Duration::from_millis(delta)
                }
                None => Duration::from_millis(0),
            };
            return Err(RateLimited { retry_after });
        }

        let _ = sqlx::query("INSERT INTO rate_limit_window (key, request_at_ms) VALUES (?, ?)")
            .bind(key)
            .bind(now_ms)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, key = %key, "rate_limit_window insert failed");
            });

        let remaining = self.limit.saturating_sub((count.0 as usize) + 1);
        Ok(remaining)
    }
}

/// Returned when [`SlidingWindowLimiter::try_acquire`] rejects a request.
#[derive(Debug, Clone)]
pub struct RateLimited {
    /// Suggested retry-after duration (until the oldest in-window request expires).
    pub retry_after: Duration,
}

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rate-limited; retry after {} ms",
            self.retry_after.as_millis()
        )
    }
}

impl std::error::Error for RateLimited {}

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

    // ---- JTI replay guard (memory) ----

    #[tokio::test(flavor = "multi_thread")]
    async fn jti_first_seen_accepts() {
        let guard = JtiReplayGuard::new(100);
        guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jti_replay_rejects() {
        let guard = JtiReplayGuard::new(100);
        guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap();
        let err = guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(err.jti, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jti_distinct_jtis_independent() {
        let guard = JtiReplayGuard::new(100);
        for jti in ["a", "b", "c"] {
            guard
                .check_and_insert(jti, Duration::from_secs(60))
                .await
                .unwrap();
        }
        assert_eq!(guard.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jti_eviction_cap_holds() {
        let guard = JtiReplayGuard::new(2);
        guard
            .check_and_insert("a", Duration::from_secs(60))
            .await
            .unwrap();
        guard
            .check_and_insert("b", Duration::from_secs(60))
            .await
            .unwrap();
        guard
            .check_and_insert("c", Duration::from_secs(60))
            .await
            .unwrap();
        // Cap is 2; oldest ("a") was evicted to make room.
        assert!(guard.len() <= 2);
        // Re-inserting "a" should succeed (we've forgotten it).
        guard
            .check_and_insert("a", Duration::from_secs(60))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jti_expired_entry_can_be_re_added() {
        let guard = JtiReplayGuard::new(100);
        guard
            .check_and_insert("z", Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        // After expiry the JTI can be re-added without being treated as a replay.
        guard
            .check_and_insert("z", Duration::from_secs(60))
            .await
            .unwrap();
    }

    // ---- JTI replay guard (SQL) ----

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_jti_first_seen_accepts() {
        let pool = fresh_pool().await;
        let guard = JtiReplayGuard::new_sql(pool);
        guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(guard.sql_count().await.unwrap(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_jti_replay_rejects() {
        let pool = fresh_pool().await;
        let guard = JtiReplayGuard::new_sql(pool);
        guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap();
        let err = guard
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(err.jti, "abc");
    }

    /// SQL backend survives a guard rebuild — same pool, fresh `JtiReplayGuard`
    /// still sees the prior insert.
    #[tokio::test(flavor = "multi_thread")]
    async fn sql_jti_survives_guard_rebuild() {
        let pool = fresh_pool().await;
        let guard1 = JtiReplayGuard::new_sql(pool.clone());
        guard1
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap();
        // Drop guard1 entirely; rebuild from the same pool.
        drop(guard1);
        let guard2 = JtiReplayGuard::new_sql(pool);
        let err = guard2
            .check_and_insert("abc", Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(err.jti, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_jti_gc_drops_expired_rows() {
        let pool = fresh_pool().await;
        let guard = JtiReplayGuard::new_sql(pool.clone());
        // Insert one row that's already expired (1ms TTL + sleep) and one
        // that's live.
        guard
            .check_and_insert("expired", Duration::from_millis(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        guard
            .check_and_insert("live", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(guard.sql_count().await.unwrap(), 2);
        let pruned = guard.gc().await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(guard.sql_count().await.unwrap(), 1);
    }

    // ---- Sliding-window rate limiter (memory) ----

    #[tokio::test(flavor = "multi_thread")]
    async fn limiter_allows_under_cap() {
        let limiter = SlidingWindowLimiter::new(3, Duration::from_secs(60), 100);
        for _ in 0..3 {
            limiter.try_acquire("alice").await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn limiter_rejects_over_cap() {
        let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60), 100);
        limiter.try_acquire("alice").await.unwrap();
        limiter.try_acquire("alice").await.unwrap();
        let err = limiter.try_acquire("alice").await.unwrap_err();
        assert!(err.retry_after.as_millis() > 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn limiter_distinct_keys_isolated() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60), 100);
        limiter.try_acquire("alice").await.unwrap();
        limiter.try_acquire("bob").await.unwrap();
        // Both should have used their single allowance.
        assert!(limiter.try_acquire("alice").await.is_err());
        assert!(limiter.try_acquire("bob").await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn limiter_window_expiry_re_admits() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_millis(50), 100);
        limiter.try_acquire("alice").await.unwrap();
        assert!(limiter.try_acquire("alice").await.is_err());
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Window has rolled forward; new request should succeed.
        limiter.try_acquire("alice").await.unwrap();
    }

    // ---- Sliding-window rate limiter (SQL) ----

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_limiter_allows_under_cap() {
        let pool = fresh_pool().await;
        let limiter = SlidingWindowLimiter::new_sql(pool, 3, Duration::from_secs(60));
        for _ in 0..3 {
            limiter.try_acquire("alice").await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_limiter_rejects_over_cap() {
        let pool = fresh_pool().await;
        let limiter = SlidingWindowLimiter::new_sql(pool, 2, Duration::from_secs(60));
        limiter.try_acquire("alice").await.unwrap();
        limiter.try_acquire("alice").await.unwrap();
        let err = limiter.try_acquire("alice").await.unwrap_err();
        assert!(err.retry_after.as_millis() > 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_limiter_window_expiry_re_admits() {
        let pool = fresh_pool().await;
        let limiter = SlidingWindowLimiter::new_sql(pool, 1, Duration::from_millis(80));
        limiter.try_acquire("alice").await.unwrap();
        assert!(limiter.try_acquire("alice").await.is_err());
        tokio::time::sleep(Duration::from_millis(120)).await;
        limiter.try_acquire("alice").await.unwrap();
    }

    /// SQL backend survives restart: a fresh limiter against the same pool
    /// keeps observing the prior in-window inserts.
    #[tokio::test(flavor = "multi_thread")]
    async fn sql_limiter_survives_rebuild() {
        let pool = fresh_pool().await;
        let limiter1 = SlidingWindowLimiter::new_sql(pool.clone(), 1, Duration::from_secs(60));
        limiter1.try_acquire("alice").await.unwrap();
        drop(limiter1);
        let limiter2 = SlidingWindowLimiter::new_sql(pool, 1, Duration::from_secs(60));
        // Same key under same window — must reject.
        assert!(limiter2.try_acquire("alice").await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sql_limiter_gc_drops_expired_rows() {
        let pool = fresh_pool().await;
        let limiter = SlidingWindowLimiter::new_sql(pool.clone(), 5, Duration::from_millis(50));
        limiter.try_acquire("alice").await.unwrap();
        let count_before: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM rate_limit_window WHERE key = 'alice'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count_before.0, 1);
        tokio::time::sleep(Duration::from_millis(80)).await;
        let pruned = limiter.gc().await.unwrap();
        assert!(pruned >= 1);
        let count_after: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM rate_limit_window WHERE key = 'alice'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count_after.0, 0);
    }
}
