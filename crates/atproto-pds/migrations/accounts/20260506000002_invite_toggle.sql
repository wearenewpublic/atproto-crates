-- §4.6: per-account invite-issuance toggle.
--
-- Adds a `can_issue_invites` BOOLEAN flag to `account` so admins can disable
-- invite issuance for individual users via `disableAccountInvites`. The flag
-- is gated in `createInviteCode`; existing accounts default to enabled.
--
--

ALTER TABLE account ADD COLUMN can_issue_invites INTEGER NOT NULL DEFAULT 1;
