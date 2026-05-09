-- — durable backing for OAuth in-flight state.
--
-- Without this, every OAuth flow's PAR / auth-code / refresh-token row
-- lives in process memory. PDS restart drops every active flow, breaking
-- multi-process deployments and even single-process upgrades. Persist all
-- three to `accounts.sqlite` so the lifecycle survives restarts.
--
-- All three tables carry a TTL via `expires_at` so the periodic GC can
-- prune stale rows without scanning per-row metadata.

CREATE TABLE oauth_par (
    request_uri          TEXT PRIMARY KEY,
    client_id            TEXT NOT NULL,
    redirect_uri         TEXT NOT NULL,
    scope                TEXT NOT NULL,
    state_param          TEXT NOT NULL,
    code_challenge       TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    dpop_jkt             TEXT,
    login_hint           TEXT,
    created_at           TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

CREATE INDEX idx_oauth_par_expires ON oauth_par(expires_at);

CREATE TABLE oauth_code (
    code                 TEXT PRIMARY KEY,
    did                  TEXT NOT NULL,
    -- The originating PAR request snapshotted as JSON so the consent
    -- decision binds against the same parameters even if the underlying
    -- PAR row is later deleted.
    request_json         TEXT NOT NULL,
    issued_at            TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

CREATE INDEX idx_oauth_code_expires ON oauth_code(expires_at);

CREATE TABLE oauth_refresh (
    jti                  TEXT PRIMARY KEY,
    did                  TEXT NOT NULL,
    client_id            TEXT NOT NULL,
    dpop_jkt             TEXT NOT NULL,
    scope                TEXT NOT NULL,
    issued_at            TEXT NOT NULL
);

CREATE INDEX idx_oauth_refresh_did ON oauth_refresh(did);
