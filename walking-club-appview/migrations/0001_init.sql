-- Walking Club AppView schema (SQLite, WAL).
-- All tables IF NOT EXISTS; timestamps are ISO-8601 TEXT; JSON stored as TEXT.

CREATE TABLE IF NOT EXISTS writers (
  space TEXT NOT NULL,
  writer_did TEXT NOT NULL,
  rev TEXT NOT NULL,
  pds_host TEXT NOT NULL,
  cursor TEXT,
  last_commit_hash TEXT,
  verified_at TEXT,
  PRIMARY KEY (space, writer_did)
);

CREATE TABLE IF NOT EXISTS events (
  space TEXT NOT NULL,
  writer_did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  cid TEXT NOT NULL,
  name TEXT,
  starts_at TEXT,
  ends_at TEXT,
  value TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (space, writer_did, rkey)
);

CREATE INDEX IF NOT EXISTS events_starts_idx ON events (space, starts_at);

CREATE TABLE IF NOT EXISTS posts (
  space TEXT NOT NULL,
  writer_did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  cid TEXT NOT NULL,
  text_body TEXT,
  created_at TEXT,
  value TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (space, writer_did, rkey)
);

CREATE TABLE IF NOT EXISTS members (
  space TEXT NOT NULL,
  member_did TEXT NOT NULL,
  member_rev TEXT,
  added_at TEXT,
  PRIMARY KEY (space, member_did)
);

CREATE TABLE IF NOT EXISTS public_records (
  did TEXT NOT NULL,
  collection TEXT NOT NULL,
  rkey TEXT NOT NULL,
  cid TEXT,
  record TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (did, collection, rkey)
);

CREATE TABLE IF NOT EXISTS firehose_cursors (
  source TEXT PRIMARY KEY,
  seq INTEGER NOT NULL
);

-- ex-Redis transient state, now local to the same SQLite DB:

CREATE TABLE IF NOT EXISTS oauth_request (
  state TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS space_credential_cache (
  space TEXT NOT NULL,
  member_did TEXT NOT NULL,
  credential TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (space, member_did)
);

CREATE TABLE IF NOT EXISTS notify_jti (
  jti TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);
