-- Point `account.password_hash` at the password that is actually in force.
--
-- The account password is stored twice: in `account.password_hash`, which
-- `verify_password` reads and the OAuth consent form falls back to, and in the
-- `__primary__` app-password row, which `createSession` and the portal read.
-- The portal's password change wrote only the second of those, so for any
-- account that used it the first still held the hash set at signup.
--
-- `20260809000001` removed the duplicate `__primary__` rows that same defect
-- produced, which stopped the old password opening a session. It did not touch
-- this column, so the original signup password still authenticates at the OAuth
-- consent screen: a credential the holder replaced, on the one screen whose job
-- is collecting a password, surviving a change that reported success.
--
-- Copying the surviving `__primary__` hash across leaves the database in the
-- state the fixed `set_primary_password` now produces directly — it hashes the
-- password once and writes both stores from the same value.
--
-- Safe for every row, not only the affected ones:
--
--   * changed through the portal — the column is stale; this corrects it;
--   * changed through `resetPassword` or the admin path — both stores were
--     already written from one hash, so this rewrites the same value;
--   * never changed — both hold a valid hash of the current password, and the
--     account keeps working with either.
--
-- Accounts with no `__primary__` row are left alone. They cannot sign in at all
-- (`createSession` verifies against that row), so there is nothing to repair and
-- inventing a value would be worse than leaving the state visible.
UPDATE account
SET password_hash = (
    SELECT ap.password_hash
    FROM app_password ap
    WHERE ap.did = account.did
      AND ap.name = '__primary__'
)
WHERE EXISTS (
    SELECT 1
    FROM app_password ap
    WHERE ap.did = account.did
      AND ap.name = '__primary__'
);
