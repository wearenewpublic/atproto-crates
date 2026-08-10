-- When a grant began, and when this particular refresh token dies.
--
-- The specification sets two different limits and this table could express
-- neither. For an untrusted public client "overall session lifetime and the
-- lifetime of individual refresh tokens should both be limited to 2 weeks";
-- for a confidential client "the overall session lifetime may be unlimited"
-- while individual tokens are held to 180 days.
--
-- `issued_at` is rewritten on every rotation, so after the first refresh
-- nothing recorded when the session had started -- a public client's session
-- could be extended indefinitely, a rotation at a time, and each rotation
-- looked identical to the first. `grant_started_at` is set once and carried
-- through every rotation unchanged, which is what makes the overall cap
-- measurable.
--
-- `expires_at` gives the row an end the way `oauth_par` and `oauth_code`
-- already have one. Without it nothing ever deleted from this table: rotation
-- replaces a row, but a session that is simply abandoned leaves its last row
-- behind for good, and the GC sweep did not mention `oauth_refresh` at all.
--
-- Existing rows are backfilled from `issued_at`. That understates the age of a
-- session already in progress, so those get one more full window rather than
-- being cut off at upgrade -- and they become GC-able, which they were not.
ALTER TABLE oauth_refresh ADD COLUMN grant_started_at TEXT;
ALTER TABLE oauth_refresh ADD COLUMN expires_at TEXT;

UPDATE oauth_refresh SET grant_started_at = issued_at WHERE grant_started_at IS NULL;

CREATE INDEX idx_oauth_refresh_expires ON oauth_refresh(expires_at);
