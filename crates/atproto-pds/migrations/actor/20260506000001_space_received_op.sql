-- — inbound notifyWrite / notifyMembership receipts.
--
-- When a remote peer pushes a notify-* payload to this PDS, we verify
-- the embedded signed commit and persist the receipt here for dedup
-- (so re-deliveries of the same `(space, rev)` are idempotent) and for
-- audit (operators can inspect which ops were received from where).
--
-- The actual application of the op into a local read-only mirror lives
-- in a Phase 2 follow-up; this Phase 1 table is the security-critical
-- audit trail.
--
-- Per-actor — one row per inbound notify pinned to the recipient DID
-- (owner-side this is the *peer* DID; member-side this is the local
-- account that holds the SpaceCredential).

CREATE TABLE space_received_op (
    space            TEXT NOT NULL,
    rev              TEXT NOT NULL,
    nsid             TEXT NOT NULL,
    issuer_did       TEXT NOT NULL,
    set_hash         BLOB NOT NULL,
    received_at      TEXT NOT NULL,
    PRIMARY KEY (space, rev, nsid)
);

CREATE INDEX idx_space_received_op_space ON space_received_op(space, received_at);
