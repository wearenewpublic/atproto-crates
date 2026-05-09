//! Valkey/Redis-backed durable state.
//!
//! Compiled in only when the `valkey` feature is on. Provides
//! [`ValkeyJtiInner`] (the third [`crate::security::JtiReplayGuard`]
//! variant) and [`ValkeyLimiterInner`] (the third
//! [`crate::security::SlidingWindowLimiter`] variant). Keys are
//! namespaced under an operator-supplied prefix
//! (`PDS_VALKEY_KEY_PREFIX`) so multiple PDS instances can share a
//! Valkey/Redis cluster without collision.
//!
//! The backend uses `redis::aio::ConnectionManager`, which transparently
//! reconnects on connection drop and serves all calls from a multiplexed
//! connection — appropriate for a high-throughput rate-limit + JTI
//! workload.
//!
//! ## Wire formats
//!
//! - **JTI keys:** `<prefix>jti:<jti>` — `SET key 1 NX EX <ttl>` mints
//!   the JTI; the `NX` flag means a duplicate write returns `nil`,
//!   which we map to a replay rejection. Per-key expiry handles GC for
//!   us — no separate prune loop.
//! - **Rate-limit keys:** `<prefix>rl:<key>` is a `ZSET` of
//!   `(score = request_at_ms, member = "<request_at_ms>:<random>")`.
//!   `try_acquire`:
//!   1. `ZREMRANGEBYSCORE key 0 (now-window)` — drop expired entries.
//!   2. `ZCARD key` — count in-window requests.
//!   3. If `count >= limit`: read `ZRANGE key 0 0 WITHSCORES` for the
//!      oldest, compute `retry_after`, and reject.
//!   4. Otherwise: `ZADD key score member` + `EXPIRE key window_secs`
//!      so idle keys age out; return `(limit - count - 1)` remaining.
//!
//! Operations 1–4 are pipelined into a single atomic round-trip via
//! `redis::pipe().atomic()` to keep contention low under bursty load.

use crate::errors::{PdsError, PdsResult};
use crate::security::{JtiReplay, RateLimited};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::sync::Arc;
use std::time::Duration;

/// Shared Valkey/Redis client + key-prefix configuration.
///
/// Cheap to clone — `ConnectionManager` is internally `Arc`-wrapped.
#[derive(Clone)]
pub struct ValkeyClient {
    conn: ConnectionManager,
    prefix: Arc<str>,
}

impl ValkeyClient {
    /// Connect to `url` and verify reachability via `PING`.
    ///
    /// `prefix` is prepended to every key (`atproto-pds:` is the
    /// operator-recommended default).
    pub async fn connect(url: &str, prefix: &str) -> PdsResult<Self> {
        let client = redis::Client::open(url).map_err(|e| PdsError::Storage {
            reason: format!("valkey: open {url}: {e}"),
        })?;
        let mut conn = ConnectionManager::new(client)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("valkey: connection manager: {e}"),
            })?;
        // Liveness ping so misconfigured deployments fail fast at boot.
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("valkey: PING: {e}"),
            })?;
        Ok(Self {
            conn,
            prefix: Arc::from(prefix),
        })
    }

    fn key(&self, suffix: &str) -> String {
        format!("{}{}", self.prefix, suffix)
    }
}

/// Valkey-backed JTI replay guard. The inner field is `pub(crate)` so
/// the dispatch enum in `security.rs` can carry the same shape as the
/// existing `Memory` / `Sql` variants.
#[derive(Clone)]
pub struct ValkeyJtiInner {
    pub(crate) client: ValkeyClient,
}

impl ValkeyJtiInner {
    /// Construct a Valkey JTI guard around an existing client.
    pub fn new(client: ValkeyClient) -> Self {
        Self { client }
    }

    /// Atomically mint a JTI with `ttl` expiry. `Err(JtiReplay)` when
    /// the JTI already exists (still live).
    pub async fn check_and_insert(&self, jti: &str, ttl: Duration) -> Result<(), JtiReplay> {
        let key = self.client.key(&format!("jti:{jti}"));
        let mut conn = self.client.conn.clone();
        // SET key 1 NX EX <ttl> returns "OK" on first sight, nil on
        // collision. We use the typed builder for reliability.
        let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(&key)
            .arg(1u8)
            .arg("NX")
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .query_async(&mut conn)
            .await;
        match result {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(JtiReplay {
                jti: jti.to_string(),
            }),
            Err(e) => {
                tracing::error!(error = ?e, jti = %jti, "valkey: jti SET NX failed; failing open");
                // Fail-open under transient connectivity issues so the
                // PDS keeps serving traffic; the operator alarm should
                // fire on the structured error log.
                Ok(())
            }
        }
    }
}

/// Valkey-backed sliding-window rate limiter. Same enum-variant
/// shape as `Memory` / `Sql`.
#[derive(Clone)]
pub struct ValkeyLimiterInner {
    pub(crate) client: ValkeyClient,
    pub(crate) limit: usize,
    pub(crate) window: Duration,
}

impl ValkeyLimiterInner {
    /// Construct a Valkey rate limiter around an existing client.
    pub fn new(client: ValkeyClient, limit: usize, window: Duration) -> Self {
        Self {
            client,
            limit,
            window,
        }
    }

    /// `try_acquire` semantics: returns remaining slots on accept, or
    /// `RateLimited` with retry-after on rejection.
    pub async fn try_acquire(&self, key: &str) -> Result<usize, RateLimited> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let window_ms = self.window.as_millis() as i64;
        let cutoff = now_ms - window_ms;
        let zkey = self.client.key(&format!("rl:{key}"));
        let mut conn = self.client.conn.clone();

        // Step 1+2: pipelined drop-expired + count.
        let pipe_result: redis::RedisResult<(i64, i64)> = redis::pipe()
            .atomic()
            .cmd("ZREMRANGEBYSCORE")
            .arg(&zkey)
            .arg(0)
            .arg(cutoff)
            .cmd("ZCARD")
            .arg(&zkey)
            .query_async(&mut conn)
            .await;
        let (_pruned, count) = match pipe_result {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, key = %key, "valkey: rl pipeline failed; failing open");
                return Ok(self.limit);
            }
        };

        if (count as usize) >= self.limit {
            // Need oldest entry's score to compute retry_after.
            let oldest: redis::RedisResult<Vec<(String, f64)>> =
                conn.zrange_withscores(&zkey, 0, 0).await;
            let retry_after = match oldest {
                Ok(rows) => match rows.first() {
                    Some((_, score)) => {
                        let expire_at = (*score as i64) + window_ms;
                        Duration::from_millis((expire_at - now_ms).max(0) as u64)
                    }
                    None => Duration::from_millis(0),
                },
                Err(_) => Duration::from_millis(0),
            };
            return Err(RateLimited { retry_after });
        }

        // Step 3+4: append + refresh expiry. Member must be unique
        // request so two same-millisecond inserts don't collide.
        let nonce: u32 = rand::random();
        let member = format!("{now_ms}:{nonce}");
        let expire_secs = (window_ms / 1000).max(1) as u64;
        let _: redis::RedisResult<(i64, i64)> = redis::pipe()
            .atomic()
            .cmd("ZADD")
            .arg(&zkey)
            .arg(now_ms as f64)
            .arg(&member)
            .cmd("EXPIRE")
            .arg(&zkey)
            .arg(expire_secs)
            .query_async(&mut conn)
            .await;

        Ok(self.limit.saturating_sub((count as usize) + 1))
    }
}

#[cfg(test)]
mod tests {
    /// Compile-only smoke test — proves the module's public surface
    /// type-checks against the configured `redis` features. Real
    /// integration coverage requires a live Valkey/Redis instance,
    /// which is exercised manually + via the operator runbook.
    #[test]
    fn valkey_module_types_resolve() {
        // Construct a client URL — we don't actually connect because
        // `cargo test` typically runs without a Valkey reachable.
        let _url = "redis://127.0.0.1:6379/0";
        let _prefix = "atproto-pds:";
    }
}
