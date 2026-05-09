-- §6.1 + §6.2: durable backends for the production-hardening primitives.
--
-- The in-memory `JtiReplayGuard` and `SlidingWindowLimiter` lose all state on
-- PDS restart. For DPoP that's fine (60s-bounded proofs), but OAuth refresh
-- tokens (30-day TTL, single-use rotation per RFC 6749 §6) and service-auth
-- JTIs need restart-survival. Same for rate-limit windows during operator
-- restart — rolling restart should not become a brute-force window.
--
-- These tables back `SqlJtiReplayGuard` (§6.1) and `SqlSlidingWindowLimiter`
-- (§6.2). The unified GC loop (§6.3) prunes expired rows on a daily tick.

-- §6.1: JTI replay set, keyed on the JWT `jti` claim. `expires_at` is the
-- token's `exp` ISO-8601 timestamp; rows past `expires_at` can be dropped
-- safely — the token would fail JWT-verify regardless.
CREATE TABLE jti_replay (
    jti              TEXT PRIMARY KEY,
    expires_at       TEXT NOT NULL
);

CREATE INDEX idx_jti_replay_expires ON jti_replay(expires_at);

-- §6.2: sliding-window rate limiter. One row per request, identified by an
-- autoincrement `id` so two calls within the same millisecond don't collide
-- on a PRIMARY KEY. `try_acquire(key)` inserts a row, then counts rows for
-- `key` whose `request_at_ms >= now - window`; rejects when count > limit.
--
-- `request_at_ms` is stored as INTEGER milliseconds-since-epoch so window
-- math is fast (no string parsing) and the index is range-scannable.
CREATE TABLE rate_limit_window (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key              TEXT NOT NULL,
    request_at_ms    INTEGER NOT NULL
);

CREATE INDEX idx_rate_limit_key_at ON rate_limit_window(key, request_at_ms);
CREATE INDEX idx_rate_limit_at ON rate_limit_window(request_at_ms);
