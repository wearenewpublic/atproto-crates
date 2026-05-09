-- Per-actor SQLite schema (Phase 2 + Phase 3 + Phase 7 columns).
--
-- This schema is applied to each per-actor SQLite file at
-- PDS_DATA_DIRECTORY/actors/<sha256(did)>.sqlite. Holds the public-realm
-- repository state plus (Phase 7) the eight Spaces tables.
--
--

-- Public realm: signed commit chain.
CREATE TABLE commit_obj (
    cid              TEXT PRIMARY KEY,
    rev              TEXT NOT NULL,
    data_cid         TEXT NOT NULL,
    prev_cid         TEXT,
    prev_data_cid    TEXT,
    signature_blob   BLOB NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_commit_rev ON commit_obj(rev);

-- Public realm: blockstore for MST nodes and DAG-CBOR record bytes.
-- The CID column is base32lower form ("bafy…"); BLOB is the raw bytes.
CREATE TABLE repo_block (
    cid              TEXT PRIMARY KEY,
    data             BLOB NOT NULL,
    indexed_at       TEXT NOT NULL
);

-- Public realm: record index for fast (collection, rkey) lookup.
CREATE TABLE repo_record (
    uri              TEXT PRIMARY KEY,
    cid              TEXT NOT NULL,
    collection       TEXT NOT NULL,
    rkey             TEXT NOT NULL,
    rev              TEXT NOT NULL,
    indexed_at       TEXT NOT NULL,
    UNIQUE (collection, rkey)
);

CREATE INDEX idx_repo_record_collection ON repo_record(collection);
CREATE INDEX idx_repo_record_cid ON repo_record(cid);

-- Public realm: blob ref-counting.
CREATE TABLE repo_blob_ref (
    record_uri       TEXT NOT NULL,
    blob_cid         TEXT NOT NULL,
    mime_type        TEXT NOT NULL,
    size             INTEGER NOT NULL,
    PRIMARY KEY (record_uri, blob_cid)
);

CREATE INDEX idx_repo_blob_ref_blob ON repo_blob_ref(blob_cid);

-- Public realm: durable firehose outbox (per-actor under SQLite per G2).
CREATE TABLE outbox (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type       TEXT NOT NULL,
    payload          BLOB NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_outbox_created ON outbox(created_at);

-- ---- Phase 7: Spaces realm tables () ----
-- Created up-front so Phase 2 doesn't need a separate migration to enable them.
-- Reads/writes against these tables are gated by the Phase 7 service layer.

CREATE TABLE space (
    uri              TEXT PRIMARY KEY,
    is_owner         INTEGER NOT NULL DEFAULT 0,
    is_member        INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL
);

CREATE TABLE space_member_state (
    space            TEXT PRIMARY KEY REFERENCES space(uri) ON DELETE CASCADE,
    set_hash         BLOB,
    rev              TEXT
);

CREATE TABLE space_repo (
    space            TEXT PRIMARY KEY REFERENCES space(uri) ON DELETE CASCADE,
    set_hash         BLOB,
    rev              TEXT
);

CREATE TABLE space_record (
    space            TEXT NOT NULL REFERENCES space(uri) ON DELETE CASCADE,
    collection       TEXT NOT NULL,
    rkey             TEXT NOT NULL,
    cid              TEXT NOT NULL,
    value            BLOB NOT NULL,
    repo_rev         TEXT NOT NULL,
    indexed_at       TEXT NOT NULL,
    PRIMARY KEY (space, collection, rkey)
);

CREATE INDEX idx_space_record_rev ON space_record(space, repo_rev);

CREATE TABLE space_member (
    space            TEXT NOT NULL REFERENCES space(uri) ON DELETE CASCADE,
    did              TEXT NOT NULL,
    member_rev       TEXT NOT NULL,
    added_at         TEXT NOT NULL,
    PRIMARY KEY (space, did)
);

CREATE TABLE space_record_oplog (
    space            TEXT NOT NULL REFERENCES space(uri) ON DELETE CASCADE,
    rev              TEXT NOT NULL,
    idx              INTEGER NOT NULL,
    action           TEXT NOT NULL,
    collection       TEXT NOT NULL,
    rkey             TEXT NOT NULL,
    cid              TEXT,
    prev             TEXT,
    PRIMARY KEY (space, rev, idx)
);

CREATE TABLE space_member_oplog (
    space            TEXT NOT NULL REFERENCES space(uri) ON DELETE CASCADE,
    rev              TEXT NOT NULL,
    idx              INTEGER NOT NULL,
    action           TEXT NOT NULL,
    did              TEXT NOT NULL,
    PRIMARY KEY (space, rev, idx)
);

CREATE TABLE space_credential_recipient (
    space            TEXT NOT NULL REFERENCES space(uri) ON DELETE CASCADE,
    service_did      TEXT NOT NULL,
    service_endpoint TEXT NOT NULL,
    last_issued_at   TEXT NOT NULL,
    PRIMARY KEY (space, service_did)
);
