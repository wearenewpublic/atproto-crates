-- Space-scoped blob references.
--
-- There is no `com.atproto.space.uploadBlob`: permissioned blobs are uploaded
-- through the ordinary `com.atproto.repo.uploadBlob` and land in the same
-- `repo_blob` table as public ones. Two things followed from that, both
-- security defects:
--
--  * `com.atproto.sync.getBlob` served permissioned bytes to anyone holding the
--    CID, with no credential at all (F-BLOB-03); and
--  * `com.atproto.space.getBlob` gated on `space` and then looked the blob up by
--    `(repo, cid)` alone, so the parameter never reached the query and a member
--    of one space could read a blob referenced only from another (F-SPACE-12).
--
-- This table is the missing association: which space a blob is referenced from,
-- and by which permissioned record. It is the space-realm counterpart of
-- `repo_blob_ref`, which the public write path has maintained since blob-ref
-- walking was wired up.
--
-- `record_uri` is the full permissioned record URI
-- (`at://<did>/space/<type>/<skey>/<author>/<collection>/<rkey>`), so dropping a
-- record's references is a prefix-free exact-match delete and a blob referenced
-- by two records survives losing one of them.
--
-- Rows live in the writer's own per-actor store — the author's, not the
-- authority's — because that is where the bytes are and where `space.getBlob`
-- opens the store to serve them.

CREATE TABLE space_blob_ref (
    space            TEXT NOT NULL,
    record_uri       TEXT NOT NULL,
    blob_cid         TEXT NOT NULL,
    PRIMARY KEY (space, record_uri, blob_cid)
);

-- `space.getBlob` asks "is this CID referenced anywhere in this space?", which
-- is a two-column lookup that must not scan the table.
CREATE INDEX idx_space_blob_ref_lookup ON space_blob_ref(space, blob_cid);

-- Dropping a record's references on update or delete is keyed by URI alone.
CREATE INDEX idx_space_blob_ref_record ON space_blob_ref(record_uri);
