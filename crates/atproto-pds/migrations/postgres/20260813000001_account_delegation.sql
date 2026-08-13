-- Account delegation: one identity naming others that may act as it.
--
-- Until now an account holder had exactly two ways to let something else
-- reach their account, and both are credentials somebody has to hold: an app
-- password, or an OAuth grant to a client application. Neither can express
-- "this *person*, signing in as themselves, may act as me" -- which is what a
-- shared account, a co-maintainer or a delegate managing an account on
-- someone's behalf actually needs. The alternative people reach for is
-- handing over the password, which cannot be revoked without changing it and
-- cannot be attributed to anyone afterwards.
--
-- A delegation is deliberately not a credential. It is a name: the delegate
-- proves who they are against their own PDS, by OAuth, and this server
-- decides whether that identity is on the list. Nothing here is secret and
-- nothing here can be stolen and replayed.
CREATE TABLE account_delegation (
    -- The account being acted for. `ON DELETE CASCADE` because a delegation
    -- to a deleted account is not a row worth keeping: there is nothing left
    -- to act as.
    core_did        TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    -- The identity permitted to act. Any AT Protocol DID, on this server or
    -- any other -- which is the whole point, and why this is not a foreign
    -- key onto `account`.
    delegate_did    TEXT NOT NULL,
    -- What the delegate's handle was when the delegation was made.
    --
    -- Display only, and never authority: handles move, and a row that decided
    -- who may act on a string the delegate's DNS controls would let a handle
    -- change hand someone else this account. The DID is what is checked.
    -- The portal re-resolves for display and falls back to this.
    delegate_handle TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    -- One row per pair. Adding a delegate twice is the same request arriving
    -- twice, and the primary key is what makes the second one a no-op rather
    -- than a duplicate the portal would list twice.
    PRIMARY KEY (core_did, delegate_did)
);

CREATE INDEX idx_account_delegation_core ON account_delegation(core_did);

-- A delegated sign-in that is part-way through.
--
-- The delegate's round trip -- out to their own PDS, sign in there, come back
-- -- takes minutes. The authorization request it belongs to lives in
-- `oauth_par` with a sixty-second TTL, so it cannot simply be left there and
-- picked up on return. It is taken out of that table and parked here instead,
-- which also settles the race for free: `oauth_par` is consumed exactly once,
-- so a second click on the same request finds nothing to start.
--
-- The PKCE verifier and the DPoP private key are per-flow secrets that exist
-- only to finish this one exchange. They are written here because the
-- callback is a different request, and possibly a different process, from the
-- one that generated them; they are deleted the moment the callback reads the
-- row, and swept if it never comes.
CREATE TABLE delegation_login (
    -- The OAuth `state` this server sent to the delegate's authorization
    -- server, and the only thing the callback carries that can find this row.
    state            TEXT PRIMARY KEY,
    -- The account this login is for, decided before the redirect from the
    -- authorization request's `login_hint` and never from anything the
    -- delegate types on the way back.
    core_did         TEXT NOT NULL REFERENCES account(did) ON DELETE CASCADE,
    -- The DID the flow was begun for. The token endpoint's `sub` must equal
    -- it, which is what stops a delegate's server naming somebody else.
    delegate_did     TEXT NOT NULL,
    -- Issuer identifier the callback's `iss` must match (RFC 9207).
    issuer           TEXT NOT NULL,
    -- Where the token exchange goes back to.
    token_endpoint   TEXT NOT NULL,
    -- The parked authorization request, serialized as it was pushed.
    request_json     TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    pkce_verifier    TEXT NOT NULL,
    dpop_private_key TEXT NOT NULL,
    -- SHA-256 of a cookie set on the browser that began this sign-in.
    --
    -- Without it the flow is completable by anyone holding the `state`, and
    -- the `state` is handed to the delegate's authorization server as a query
    -- parameter -- so it is in their logs, and in the URL that server redirects
    -- to. The attack that opens up is not subtle: someone starts a delegated
    -- sign-in for an account they want, points it at a real delegate of that
    -- account, and mails that delegate the authorization URL. The delegate
    -- signs in on their *own* server, sees a consent screen for scope
    -- `atproto` from a client named after their own PDS, approves it, and the
    -- callback issues an authorization code for somebody else's account to the
    -- application that started it.
    --
    -- The step that would have shown the delegate what they were agreeing to
    -- -- the handle-entry page, which names the client and lists its scopes --
    -- is the step this binds the flow to.
    --
    -- Only the hash, for the same reason `portal_session.id` is only a hash:
    -- the accounts database is what an attacker who obtains a backup reads,
    -- and a live flow identifier in it would be usable.
    browser_binding  TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL
);

CREATE INDEX idx_delegation_login_expires ON delegation_login(expires_at);

-- Which identity actually authenticated, when it was not the account holder.
--
-- Every token minted through a delegation is a token for the *core* account:
-- that is what the client asked for and what it has to be able to use. But
-- "who signed in" and "whose account this is" have stopped being the same
-- question, and a grant that records only the second one cannot answer the
-- first afterwards -- not for the access log, not for the portal's session
-- list, and not for the holder deciding whether to remove a delegate.
--
-- NULL for every grant an account holder made themselves, which is every row
-- that exists today.
ALTER TABLE oauth_code    ADD COLUMN acting_did TEXT;
ALTER TABLE oauth_refresh ADD COLUMN acting_did TEXT;

-- Removing a delegation ends the grants it minted, which is a lookup by
-- (account, delegate).
CREATE INDEX idx_oauth_refresh_acting ON oauth_refresh(did, acting_did);
