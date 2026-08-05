-- The account portal: a session epoch, and browser sessions to hold.
--
-- Postgres counterpart of `migrations/accounts/20260805000001_account_portal.sql`;
-- the reasoning for both objects is written out there.
ALTER TABLE account ADD COLUMN session_epoch BIGINT NOT NULL DEFAULT 0;

CREATE TABLE portal_session (
    id                     TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    epoch                  BIGINT NOT NULL DEFAULT 0,
    user_agent             TEXT
);

CREATE INDEX idx_portal_session_did ON portal_session(did);
CREATE INDEX idx_portal_session_expires ON portal_session(expires_at);

ALTER TABLE app_password ADD COLUMN last_used_at TEXT;
