-- §4.4: per-(space, collection, rkey) record-level takedown for Spaces.
--
-- The public realm gates reads on the *account* state (`account.state`).
-- The permissioned realm needs finer-grained control: a single record in a
-- shared space can be moderated without takingdown the whole owner account.
--
-- Mirror of the public-realm `repo::reader` takedown gate, but at the
-- record level: a row in this table hides the corresponding record from
-- `SpaceReader::get_record` and `SpaceReader::list_records`.
--
-- The table lives in the *owner's* per-actor SQLite (where `space_record`
-- rows live for owner-side reads); admins lifting/applying takedowns
-- target the owner's store. `taken_at` is informational + audit-friendly.
--
--

CREATE TABLE space_record_takedown (
    space            TEXT NOT NULL,
    collection       TEXT NOT NULL,
    rkey             TEXT NOT NULL,
    taken_at         TEXT NOT NULL,
    PRIMARY KEY (space, collection, rkey)
);

CREATE INDEX idx_space_record_takedown_space
    ON space_record_takedown(space, collection);
