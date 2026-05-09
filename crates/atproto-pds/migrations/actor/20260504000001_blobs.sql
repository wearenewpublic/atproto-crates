-- Per-actor blob storage (Phase 9 / audit follow-up).
--
-- The Phase 0 migration declared `repo_blob_ref` (record_uri ↔ blob_cid
-- ref-counting) but no table to hold the blob bytes themselves. This
-- migration adds it.
--
-- We use SQLite BLOB storage rather than spilling to the filesystem so the
-- per-actor SQLite file remains the single durable artifact and account
-- migration via `getRepo` + `listMissingBlobs` + `uploadBlob` works without
-- chasing file paths.

CREATE TABLE repo_blob (
    cid              TEXT PRIMARY KEY,
    mime_type        TEXT NOT NULL,
    size             INTEGER NOT NULL,
    data             BLOB NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_repo_blob_created ON repo_blob(created_at);
