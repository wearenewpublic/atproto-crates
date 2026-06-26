-- PostgreSQL accounts DB schema.
--
-- Mirrors `migrations/accounts/*.sql` (the SQLite schema) into a single
-- consolidated init for Postgres. Per-table parity ports come next:
-- the `account/manager.rs` / `directory.rs` / `invite.rs` /
-- `app_password.rs` / `email_token.rs` queries lift to dispatch
-- through `account::AccountPool`, branching their SQL strings on the
-- pool variant.
--
-- Type adjustments vs SQLite:
--   - `INTEGER`        → `BIGINT` (avoid 32-bit overflow on `BIGSERIAL` columns).
--   - `BLOB`           → `BYTEA`.
--   - `INTEGER NOT NULL DEFAULT 0/1` (booleans-as-int) → `BOOLEAN NOT NULL DEFAULT FALSE/TRUE`.
--   - `TEXT` for ISO-8601 timestamps stays `TEXT` for now — Postgres
--     `TIMESTAMPTZ` is preferable but lifting that requires updating
--     every binding site, which is part of the per-table port.
--
-- The schema is the consolidated "current state" — all SQLite migrations
-- through 20260506000003_durable_state.sql collapsed into one Postgres
-- DDL. Future Postgres-side migrations append below.

-- -- account ----------------------------------------------------------------

CREATE TABLE account (
    did                    TEXT PRIMARY KEY,
    handle                 TEXT NOT NULL UNIQUE,
    email                  TEXT UNIQUE,
    email_confirmed_at     TEXT,
    password_hash          TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'active',
    signing_key_ref        TEXT NOT NULL,
    pds_managed_rotation   BOOLEAN NOT NULL DEFAULT TRUE,
    rotation_key_ref       TEXT,
    delete_after           TEXT,
    can_issue_invites      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_account_handle ON account(handle);
CREATE INDEX idx_account_state ON account(state);

-- -- app_password ----------------------------------------------------------

CREATE TABLE app_password (
    id             TEXT PRIMARY KEY,
    did            TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    privileged     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_app_password_did ON app_password(did);

-- -- invite_code -----------------------------------------------------------

CREATE TABLE invite_code (
    code            TEXT PRIMARY KEY,
    created_by_did  TEXT REFERENCES account(did) ON DELETE SET NULL,
    available_uses  BIGINT NOT NULL DEFAULT 1,
    used_by         TEXT REFERENCES account(did) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    disabled        BOOLEAN NOT NULL DEFAULT FALSE
);

-- -- email_token -----------------------------------------------------------

CREATE TABLE email_token (
    token       TEXT PRIMARY KEY,
    did         TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    purpose     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    new_email   TEXT
);

CREATE INDEX idx_email_token_did ON email_token(did);

-- -- signing_key ----------------------------------------------------------

CREATE TABLE signing_key (
    id          TEXT PRIMARY KEY,
    did         TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    key_ref     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_signing_key_did ON signing_key(did);

-- -- service_auth_blacklist + denylist ------------------------------------

CREATE TABLE service_auth_blacklist (
    jti         TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
);

CREATE INDEX idx_service_auth_expires ON service_auth_blacklist(expires_at);

CREATE TABLE denylist (
    hash_metro64  BYTEA PRIMARY KEY,
    kind          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    note          TEXT
);

-- -- notify_attempt --------------------------------------------------------

CREATE TABLE notify_attempt (
    id                  TEXT PRIMARY KEY,
    target_service_did  TEXT NOT NULL,
    target_endpoint     TEXT NOT NULL,
    payload_cbor        BYTEA NOT NULL,
    nsid                TEXT NOT NULL,
    content_type        TEXT NOT NULL DEFAULT 'application/cbor',
    auth_token          TEXT,
    attempt_count       BIGINT NOT NULL DEFAULT 0,
    last_attempt_at     TEXT,
    next_attempt_at     TEXT NOT NULL,
    state               TEXT NOT NULL DEFAULT 'pending',
    last_error          TEXT
);

CREATE INDEX idx_notify_attempt_due ON notify_attempt(state, next_attempt_at);

-- -- oauth_par + oauth_code + oauth_refresh -------------------------------

CREATE TABLE oauth_par (
    request_uri            TEXT PRIMARY KEY,
    client_id              TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    state_param            TEXT NOT NULL,
    code_challenge         TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL,
    dpop_jkt               TEXT,
    login_hint             TEXT,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL
);

CREATE INDEX idx_oauth_par_expires ON oauth_par(expires_at);

CREATE TABLE oauth_code (
    code           TEXT PRIMARY KEY,
    did            TEXT NOT NULL,
    request_json   TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    expires_at     TEXT NOT NULL
);

CREATE INDEX idx_oauth_code_expires ON oauth_code(expires_at);

CREATE TABLE oauth_refresh (
    jti        TEXT PRIMARY KEY,
    did        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    dpop_jkt   TEXT NOT NULL,
    scope      TEXT NOT NULL,
    issued_at  TEXT NOT NULL
);

CREATE INDEX idx_oauth_refresh_did ON oauth_refresh(did);

-- -- jti_replay + rate_limit_window ---------------------------------------

CREATE TABLE jti_replay (
    jti          TEXT PRIMARY KEY,
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_jti_replay_expires ON jti_replay(expires_at);

CREATE TABLE rate_limit_window (
    id              BIGSERIAL PRIMARY KEY,
    key             TEXT NOT NULL,
    request_at_ms   BIGINT NOT NULL
);

CREATE INDEX idx_rate_limit_window_key_at
    ON rate_limit_window(key, request_at_ms);
