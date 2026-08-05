-- The account portal: a session epoch, and browser sessions to hold.
--
-- `session_epoch` is what makes "log out everywhere" possible at all. Both
-- kinds of credential this PDS issues -- app-password sessions and OAuth
-- grants -- are HMAC JWTs, which is to say they are stateless: once minted,
-- nothing consults storage to decide whether they are still wanted, so there
-- is no row to delete to end them early. Revoking an app password already
-- fails to end sessions minted from it for exactly this reason.
--
-- So the tokens carry the epoch they were minted under, and the auth layer
-- refuses any token whose epoch is behind the account's. Bumping this one
-- integer invalidates every outstanding access and refresh token for the
-- account at once, which is the guarantee "log out everywhere" has to make.
-- It costs one indexed read per authenticated request.
ALTER TABLE account ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;

-- Browser sessions for the portal, deliberately not JWTs.
--
-- The portal is where an account holder revokes things, so its own session
-- must be revocable in the same breath -- a stateless cookie that outlived
-- "log out everywhere" would be the one credential the button could not
-- reach. A row here can simply be deleted.
--
-- `id` is the SHA-256 of the cookie value, never the value itself. The
-- accounts database is the thing an attacker who gets a backup copy reads,
-- and a stolen session identifier is a live login.
CREATE TABLE portal_session (
    id                     TEXT PRIMARY KEY,
    did                    TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    -- The epoch this session was signed in under, so "log out everywhere"
    -- ends other browsers without ending the one that pressed the button.
    epoch                  INTEGER NOT NULL DEFAULT 0,
    user_agent             TEXT
);

CREATE INDEX idx_portal_session_did ON portal_session(did);
CREATE INDEX idx_portal_session_expires ON portal_session(expires_at);

-- So the portal can show "last used" beside each app password rather than
-- only when it was created. An app password the holder does not recognise is
-- the reason they came to the page.
ALTER TABLE app_password ADD COLUMN last_used_at TEXT;
