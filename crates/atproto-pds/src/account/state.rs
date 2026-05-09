//! Account lifecycle states.
//!
//! `active`, `deactivated`,
//! `takendown`, `suspended`, plus the implicit `deleted` state. State changes
//! emit `#account` firehose events with `active` boolean and optional `status`
//! reason.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Account lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountState {
    /// Normal operation — reads and writes allowed.
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
