//! Account lifecycle states.
//!
//! `active`, `deactivated`,
//! `takendown`, `suspended`, plus the implicit `deleted` state. State changes
//! emit `#account` firehose events with `active` boolean and optional `status`
//! reason.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Account lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccountState {
    /// Normal operation — reads and writes allowed.
    #[default]
    Active,
    /// Voluntary deactivation — identity may be served, repo not accessible
    /// to public sync.
    Deactivated,
    /// Moderator-initiated takedown — blocks reads and writes; emits firehose
    /// `#account active=false status=takendown`.
    Takendown,
    /// Temporary admin suspension.
    Suspended,
    /// Account hard-deleted.
    Deleted,
}

impl AccountState {
    /// String form for SQL persistence and JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AccountState::Active => "active",
            AccountState::Deactivated => "deactivated",
            AccountState::Takendown => "takendown",
            AccountState::Suspended => "suspended",
            AccountState::Deleted => "deleted",
        }
    }

    /// Parse from the string form. Returns `None` on unknown value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(AccountState::Active),
            "deactivated" => Some(AccountState::Deactivated),
            "takendown" => Some(AccountState::Takendown),
            "suspended" => Some(AccountState::Suspended),
            "deleted" => Some(AccountState::Deleted),
            _ => None,
        }
    }

    /// `true` if the account can be read from the public realm.
    #[must_use]
    pub fn allows_public_read(self) -> bool {
        matches!(self, AccountState::Active | AccountState::Deactivated)
    }

    /// The `active` / `status` pair the sync lexicon asks for.
    ///
    /// One function because there were three, and one of them disagreed.
    /// `getRepoStatus` derived `active` from `allows_public_read`, which is
    /// true for `Deactivated` as well as `Active` -- so it answered
    /// `active: true` beside `status: "deactivated"`, which is not a state an
    /// account can be in. A relay told through the firehose that an account is
    /// inactive would call `getRepoStatus`, be told it is active, and resume
    /// indexing it.
    ///
    /// `status` is only meaningful when `active` is false, and the lexicon's
    /// `knownValues` are exactly the non-active states. Reading from a repo and
    /// being active are different questions: a deactivated account is still
    /// readable, and is still not active.
    #[must_use]
    pub fn active_and_status(self) -> (bool, Option<String>) {
        match self {
            AccountState::Active => (true, None),
            other => (false, Some(other.as_str().to_string())),
        }
    }

    /// `true` if the account can perform writes.
    #[must_use]
    pub fn allows_writes(self) -> bool {
        matches!(self, AccountState::Active)
    }
}

impl fmt::Display for AccountState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deactivated account is readable and is not active. Deriving `active`
    /// from `allows_public_read` conflated the two, so `getRepoStatus`
    /// answered `active: true` beside `status: "deactivated"`.
    #[test]
    fn a_deactivated_account_is_not_active() {
        let (active, status) = AccountState::Deactivated.active_and_status();
        assert!(!active, "deactivated is not active, however readable it is");
        assert_eq!(status.as_deref(), Some("deactivated"));
        assert!(
            AccountState::Deactivated.allows_public_read(),
            "and it is still readable, which is the distinction that was lost"
        );
    }

    /// `status` is only meaningful when `active` is false, so an active
    /// account carries none.
    #[test]
    fn an_active_account_carries_no_status() {
        assert_eq!(AccountState::Active.active_and_status(), (true, None));
    }

    /// Every non-active state reports itself, and none of them claims to be
    /// active.
    #[test]
    fn no_non_active_state_reports_itself_active() {
        for state in [
            AccountState::Deactivated,
            AccountState::Suspended,
            AccountState::Takendown,
            AccountState::Deleted,
        ] {
            let (active, status) = state.active_and_status();
            assert!(!active, "{state} must not report active");
            assert_eq!(status.as_deref(), Some(state.as_str()));
        }
    }

    #[test]
    fn round_trip() {
        for s in ["active", "deactivated", "takendown", "suspended", "deleted"] {
            let state = AccountState::parse(s).unwrap();
            assert_eq!(state.as_str(), s);
        }
        assert!(AccountState::parse("bogus").is_none());
    }

    #[test]
    fn permissions_match_design_spec() {
        assert!(AccountState::Active.allows_public_read());
        assert!(AccountState::Active.allows_writes());

        assert!(AccountState::Deactivated.allows_public_read());
        assert!(!AccountState::Deactivated.allows_writes());

        assert!(!AccountState::Takendown.allows_public_read());
        assert!(!AccountState::Takendown.allows_writes());

        assert!(!AccountState::Suspended.allows_public_read());
        assert!(!AccountState::Suspended.allows_writes());

        assert!(!AccountState::Deleted.allows_public_read());
        assert!(!AccountState::Deleted.allows_writes());
    }
}
