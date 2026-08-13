-- Applications this account refuses to serve its permissioned records to.
--
-- A space credential is minted by the space authority and cannot be revoked:
-- nothing invalidates one before it expires, and removing a member only stops
-- the *next* one being issued. The account holding the records has exactly one
-- lever over a credential already in the wild, which is to refuse it at its own
-- door. This table is that refusal.
--
-- `identity` matches the key `space_access_log` records under: the attested
-- `client_id` when the credential carried one, otherwise `jkt:<thumbprint>`. A
-- block on the second kind holds only until that application's credential is
-- renewed, because the thumbprint is all there is to name it by and the draft
-- recommends rotating it -- so the portal says as much rather than implying a
-- durable block.
--
-- Scope worth stating: this refuses reads of *this* account's records on *this*
-- server. The same credential keeps working against every other member's repo,
-- wherever those are hosted.
CREATE TABLE space_access_block (
    space            TEXT NOT NULL,
    identity         TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (space, identity)
);
