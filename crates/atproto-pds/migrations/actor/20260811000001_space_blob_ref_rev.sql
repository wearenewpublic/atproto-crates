-- Stamp each space blob reference with the revision that created it.
--
-- `com.atproto.space.listBlobs` takes an optional `since` (a repo revision) and
-- answers with the blobs referenced by records written after it. That is what
-- lets a syncer catch up on blobs the way `listRepoOps` lets it catch up on
-- records, instead of re-listing an entire repo's blobs on every pass, and it
-- is what an account migration needs in order to carry only what it has not
-- already carried.
--
-- `space_blob_ref` had no revision to filter on. The table records which record
-- in which space names which blob, and nothing about when — so `since` was not
-- merely unimplemented, it was unanswerable from the data.
--
-- The rev is the commit rev of the write that created the reference, which is
-- also the rev `listRepoOps` reports for the same record. A consumer can
-- therefore use one cursor for both: the `since` it passes here is the `since`
-- it passed there.
--
-- Existing rows get `''`, which sorts before every TID. A full listing (no
-- `since`) includes them, and a `since` listing excludes them — which is the
-- safe direction. A caller passing `since` is catching up from a point it has
-- already seen, and rows written before this migration predate any such point;
-- a caller that has never listed passes no `since` and receives everything.
ALTER TABLE space_blob_ref ADD COLUMN rev TEXT NOT NULL DEFAULT '';

-- `listBlobs` filters on `(space, rev)` and pages by `blob_cid`. Without this
-- index a `since` listing scans every reference the account holds, in every
-- space, to answer a question about one of them.
CREATE INDEX idx_space_blob_ref_since ON space_blob_ref(space, rev);
