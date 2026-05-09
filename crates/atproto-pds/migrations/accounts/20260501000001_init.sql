-- Accounts DB initial schema (Phase 2 + Phase 3 columns).
--
-- This schema lives in the *shared* accounts DB (one per PDS instance), which
-- holds cross-account state. Per-actor data lives in per-actor SQLite files
-- under PDS_DATA_DIRECTORY/actors/<sha256(did)>.sqlite.
--
--

CREATE TABLE account (
    did                    TEXT PRIMARY KEY,
    handle                 TEXT NOT NULL UNIQUE,
    email                  TEXT UNIQUE,
    email_confirmed_at     TEXT,
    password_hash          TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'active',
    signing_key_ref        TEXT NOT NULL,
    pds_managed_rotation   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_account_handle ON account(handle);
CREATE INDEX idx_account_state ON account(state);

CREATE TABLE app_password (
    id                     TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    name                   TEXT NOT NULL,
    password_hash          TEXT NOT NULL,
    privileged             INTEGER NOT NULL DEFAULT 0,
    created_at             TEXT NOT NULL
);

CREATE INDEX idx_app_password_did ON app_password(did);

CREATE TABLE oauth_session (
    id                     TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    client_id              TEXT NOT NULL,
    dpop_jkt               TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    issued_at              TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    refreshed_at           TEXT
);

CREATE INDEX idx_oauth_session_did ON oauth_session(did);
CREATE INDEX idx_oauth_session_expires ON oauth_session(expires_at);

CREATE TABLE invite_code (
    code                   TEXT PRIMARY KEY,
    created_by_did         TEXT REFERENCES account(did) ON DELETE SET NULL,
    available_uses         INTEGER NOT NULL DEFAULT 1,
    used_by                TEXT REFERENCES account(did) ON DELETE SET NULL,
    created_at             TEXT NOT NULL,
    disabled               INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE email_token (
    token                  TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    purpose                TEXT NOT NULL,
    expires_at             TEXT NOT NULL
);

CREATE INDEX idx_email_token_did ON email_token(did);

CREATE TABLE plc_op_token (
    token                  TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    expires_at             TEXT NOT NULL
);

CREATE TABLE signing_key (
    id                     TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    algorithm              TEXT NOT NULL,
    key_ref                TEXT NOT NULL,
    created_at             TEXT NOT NULL
);

CREATE INDEX idx_signing_key_did ON signing_key(did);

CREATE TABLE service_auth_blacklist (
    jti                    TEXT PRIMARY KEY,
    expires_at             TEXT NOT NULL
);

CREATE INDEX idx_service_auth_expires ON service_auth_blacklist(expires_at);

-- Notifier DLQ for outbound notifyWrite/notifyMembership.
-- G8.
CREATE TABLE notify_attempt (
    id                     TEXT PRIMARY KEY,
    target_service_did     TEXT NOT NULL,
    target_endpoint        TEXT NOT NULL,
    payload_cbor           BLOB NOT NULL,
    nsid                   TEXT NOT NULL,
    attempt_count          INTEGER NOT NULL DEFAULT 0,
    last_attempt_at        TEXT,
    next_attempt_at        TEXT NOT NULL,
    state                  TEXT NOT NULL DEFAULT 'pending',
    last_error             TEXT
);

CREATE INDEX idx_notify_attempt_due ON notify_attempt(state, next_attempt_at);

-- Privacy-preserving denylist: stores only MetroHash64 of the identifier.
--
CREATE TABLE denylist (
    hash_metro64           BLOB PRIMARY KEY,
    kind                   TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    note                   TEXT
);
