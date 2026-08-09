-- A durable home for the handful of settings the PDS generates for itself.
--
-- The immediate occupant is the PDS-level OAuth signing key reference.
-- `KeyStore::put` returns an opaque `key_ref` and content-addresses the
-- storage, so a caller that wants the same key back on the next boot has to
-- remember that ref. Every account key does: `account.signing_key_ref` and
-- `account.rotation_key_ref` are exactly this. The PDS-level key was the one
-- key in the system with no row to hold its ref, so nothing ever found it
-- again and every restart minted a replacement.
--
-- Keyed by name rather than a fixed column per setting: these are singleton
-- process-level values, and a table that takes a new one without a migration
-- is the point.
CREATE TABLE pds_setting (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
