-- Access tokens revoked before their natural expiry.
--
-- `/oauth/revoke` reported success on an access token and did nothing. It
-- inserted the token's `jti` into the JTI replay guard, but nothing reads that
-- value: the guard is consulted for the *DPoP proof's* jti, a different claim
-- from a different JWT, and a token presented as `Bearer` never reaches the
-- guard at all. A user revoking a lost device's token got 200 OK while the
-- token kept authenticating every call for its remaining lifetime.
--
-- The replay guard was also the wrong home for it. It is memory-backed by
-- default and evicts by insertion order once over cap, and it fails open on a
-- storage error. Both are defensible for replay -- a missed replay costs one
-- duplicated request -- and neither is acceptable for revocation, where
-- forgetting an entry silently restores the credential the user asked to
-- destroy.
--
-- Rows are needed only until the token would be refused for being expired
-- anyway, so `expires_at` is the token's own `exp` and the GC sweep drops
-- anything past it.
CREATE TABLE oauth_revoked_token (
    jti                    TEXT PRIMARY KEY,
    expires_at             TEXT NOT NULL
);

CREATE INDEX idx_oauth_revoked_expires ON oauth_revoked_token(expires_at);
