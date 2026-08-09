-- One `__primary__` app-password row per account.
--
-- The portal's password change called a helper that inserted a row rather than
-- replacing one, so every change appended a `__primary__` carrying the new
-- hash and left the previous one in place. `verify` accepts the first row whose
-- hash matches and does not care which, so the old password kept opening the
-- account -- at `createSession`, at the portal sign-in, and at the OAuth
-- consent form -- with nothing in the interface to say so. The change reported
-- success, revoked the sessions, and left the credential it was issued to
-- revoke still working.
--
-- The delete keeps the newest row per account, which is the one holding the
-- password in force; `id` breaks a tie that timestamps at nanosecond precision
-- should never produce. Any account that changed its password through the
-- portal has rows to remove here, and until they are removed the fix in code is
-- only half of it.
DELETE FROM app_password
WHERE name = '__primary__'
  AND id NOT IN (
      SELECT id FROM (
          SELECT id,
                 ROW_NUMBER() OVER (
                     PARTITION BY did ORDER BY created_at DESC, id DESC
                 ) AS rn
          FROM app_password
          WHERE name = '__primary__'
      ) ranked
      WHERE rn = 1
  );

-- Partial rather than a plain UNIQUE(did, name): the names of ordinary app
-- passwords are the holder's own text and nothing has ever required them to be
-- distinct, so constraining all of them would refuse writes the account portal
-- currently accepts. `__primary__` is this server's name, not theirs, and one
-- per account is the invariant that was violated.
CREATE UNIQUE INDEX idx_app_password_primary
    ON app_password(did)
    WHERE name = '__primary__';
