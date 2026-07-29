-- Public-realm record- and blob-level takedown.
--
-- Until now the only moderation lever on the public realm was `account.state`,
-- which is all-or-nothing: an operator asked to remove one illegal post or one
-- illegal image had to take down the whole account. `com.atproto.admin.defs`
-- has always declared `com.atproto.repo.strongRef` and `#repoBlobRef` as
-- subjects of `updateSubjectStatus` alongside `#repoRef`; these tables are the
-- storage those two subject kinds needed.
--
-- Separate tables rather than columns on `repo_record` / `repo_blob`, for the
-- same reason `space_record_takedown` and `preference` are separate: records
-- and blobs are dispatched through `PublicRealmBackend`, so on the fjall
-- profile their bytes do not live in this database at all. A column here would
-- silently cover one storage profile and not the other. The per-actor SQLite is
-- always present, so a takedown recorded here is enforceable either way.
--
-- Presence of a row means "taken down". `takedown_ref` is the moderation
-- service's own identifier for the action, carried through from
-- `#statusAttr.ref` and handed back unchanged by `getSubjectStatus` — the PDS
-- does not interpret it. `taken_at` is informational and audit-friendly.

CREATE TABLE public_record_takedown (
    uri              TEXT PRIMARY KEY,
    takedown_ref     TEXT,
    taken_at         TEXT NOT NULL
);

-- `listRecords` filters a whole collection at a time, so the lookup is by
-- URI prefix rather than by exact key.
CREATE INDEX idx_public_record_takedown_uri ON public_record_takedown(uri);

CREATE TABLE public_blob_takedown (
    cid              TEXT PRIMARY KEY,
    takedown_ref     TEXT,
    taken_at         TEXT NOT NULL
);
