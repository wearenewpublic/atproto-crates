--
-- §1.9: `email_token` needs a `new_email` column so `requestEmailUpdate` can
-- record the address the user wants to switch to. The companion endpoint
-- `confirmEmailUpdate` reads this column when the user redeems the token.
--
-- §1.11: `account` needs a `delete_after` column so `deactivateAccount`
-- can record the operator-requested hard-delete deadline. A periodic
-- background task in `bin/pds.rs` walks accounts where state='deactivated'
-- and `delete_after <= now`, transitioning each to `Deleted`.
--
-- Both columns are nullable + default NULL so pre-existing rows aren't
-- affected. Backfilling is unnecessary: pre-existing rows had neither a
-- pending email change nor a scheduled deletion.

ALTER TABLE email_token ADD COLUMN new_email TEXT;
ALTER TABLE account ADD COLUMN delete_after TEXT;
