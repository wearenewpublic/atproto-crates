-- The authorization grant a refresh token descends from.
--
-- Rotation replaces one refresh token with the next, so a grant is a chain:
-- the token issued at the code exchange, then its successor, then its
-- successor's successor. OAuth 2.1 requires that presenting an already-rotated
-- token revoke every token in that chain, because the only two explanations
-- for a second presentation are a leaked token being used or the legitimate
-- client racing itself, and the safe response to both is to end the grant.
--
-- Nothing recorded which tokens belonged together, so nothing could be
-- revoked. A replayed token got a generic `invalid_grant` while whoever held
-- the successor -- possibly the attacker -- kept refreshing indefinitely.
--
-- Existing rows each become their own family, keyed on the jti they already
-- have. That is correct rather than merely convenient: without a record of
-- what preceded them there is no chain to reconstruct, and one token per
-- family degrades to exactly today's behaviour until the next rotation
-- issues a real one.
ALTER TABLE oauth_refresh ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
UPDATE oauth_refresh SET family_id = jti WHERE family_id = '';

CREATE INDEX idx_oauth_refresh_family ON oauth_refresh(family_id);
