-- What the last check of an account's handle saw.
--
-- A handle is a claim in two halves: the DID document says `alsoKnownAs`, and
-- the domain says, over DNS or HTTPS, which DID it belongs to. Both must
-- agree, and the second half can stop being true at any time without anyone
-- here doing anything -- a DNS record expires, a domain changes hands, a
-- host is rebuilt without its `.well-known`. This server never looked again
-- after the handle was first proven, so it went on serving a handle nobody
-- else would confirm, and `describeRepo` reported `handleIsCorrect: true`
-- while every consumer that checked disagreed.
--
-- Its own table rather than a column on `account`: this is an observation
-- about the outside world with its own lifecycle, not part of the account's
-- identity, and keeping it separate leaves the account row -- read on nearly
-- every authenticated request -- the shape it already has.
--
-- No row means never checked, which is not the same as invalid and is not
-- served as such. `invalidated_at` NULL means the last check confirmed the
-- handle.
CREATE TABLE handle_validation (
    did            TEXT PRIMARY KEY REFERENCES account(did) ON DELETE CASCADE,
    checked_at     TEXT NOT NULL,
    invalidated_at TEXT
);

CREATE INDEX idx_handle_validation_invalidated ON handle_validation(invalidated_at);
