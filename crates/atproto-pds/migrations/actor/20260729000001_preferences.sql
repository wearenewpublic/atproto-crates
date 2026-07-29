-- Private per-account preferences (`app.bsky.actor.{get,put}Preferences`).
--
-- The lexicon types this `app.bsky.actor.defs#preferences`: an array of
-- open-union objects — muted words, feed settings, content-label choices. The
-- PDS has no reason to interpret any of them, and parsing them would mean
-- tracking every preference type an AppView ever adds. So the array is stored
-- as the JSON it arrived as and returned verbatim.
--
-- One row per actor store, hence the fixed primary key: the store is already
-- per-account, so a `did` column would only restate that.
CREATE TABLE preference (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    preferences_json TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
