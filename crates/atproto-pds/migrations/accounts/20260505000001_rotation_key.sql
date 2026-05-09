-- §1.2 follow-up: track the PDS-managed rotation key separately from the
-- atproto signing key.
--
-- The original `account.signing_key_ref` column points at the K-256
-- *signing* key the user signs records with. The *rotation* key (used to
-- sign PLC operations) is a separate ECDSA key generated alongside during
-- PLC genesis. Without this column the rotation key was being dropped on
-- the floor; `signPlcOperation` could never find it.
--
-- New rows during PLC genesis populate this. Pre-existing rows have it
-- NULL — `signPlcOperation` reports `NoRotationKey` for those (they
-- predate the rotation-key model and need an admin to register one).

ALTER TABLE account ADD COLUMN rotation_key_ref TEXT;
