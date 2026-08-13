-- Which applications have read this account's records in a space.
--
-- A space credential is minted by the space authority, so this server never
-- witnesses its issuance -- it only ever sees one arrive on a read. That makes
-- the read path the single place the question "who has been reading my
-- permissioned records" can be answered from, and this table is where the
-- answer accumulates.
--
-- `identity` is the row's key and is derived, not supplied: the attested
-- `client_id` when the credential carries one, otherwise the DPoP key
-- thumbprint prefixed `jkt:`. The distinction is not cosmetic. A credential
-- only carries `client_id` when the request that minted it presented a client
-- attestation, and the permissioned-data draft recommends a fresh DPoP keypair
-- per credential -- so an application that does not attest appears here as a
-- new anonymous row every time its credential rotates, and cannot be
-- attributed or acted on. `client_id` is kept as its own nullable column so a
-- reader of this table can tell the two cases apart rather than parsing the key.
--
-- Deliberately no foreign key to `space`: a read can arrive for a space this
-- account has never written to, and so has no local `space` row for. Refusing
-- to record that read would drop exactly the entries an account most wants to
-- see.
CREATE TABLE space_access_log (
    space            TEXT NOT NULL,
    identity         TEXT NOT NULL,
    client_id        TEXT,
    jkt              TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    reads            INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (space, identity)
);

CREATE INDEX idx_space_access_log_seen ON space_access_log(space, last_seen DESC);
