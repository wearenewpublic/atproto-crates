//! A grace window for concurrent refresh-token use.
//!
//! Refresh tokens are single-use: `refreshSession` rotates the token and the
//! old one is refused thereafter. That is worth keeping — a replayed refresh
//! token is how a stolen one gets used — but as a bare rule it also refuses a
//! case that is not an attack at all.
//!
//! A client with two requests in flight can have both meet a 401, and both
//! then refresh with the same stored token. One wins; without this the other
//! gets `AuthenticationRequired`. The official Bluesky client treats a refresh
//! that returns no session as the session being gone and logs the user out
//! (`social-app`, `src/state/session/reducer.ts`: "Log out if expired"), so a
//! benign race costs the account holder their session. The reference does not
//! rotate at all, so it never sees this.
//!
//! The reconciliation is to make a refresh *idempotent for a few seconds*:
//! remember what was issued for a token, and if the same token arrives again
//! inside the window, hand back the same successor rather than an error. The
//! client's two racing requests then agree, and neither is logged out.
//!
//! What this does not weaken: a token replayed after the window is still
//! refused, so a stolen token surfacing later is caught exactly as before. The
//! window only covers the interval where a legitimate client could still have
//! the superseded token in flight.
//!
//! The record is in memory. It is not durability-critical — losing it across a
//! restart costs at most one racing client one 401, which is the behaviour
//! before this existed.

use crate::account::session::SessionTokens;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a rotated token keeps returning its successor.
///
/// Long enough to cover a client's in-flight requests and a retry, short
/// enough that a token lifted from a log or a proxy is almost certainly past
/// it. Ten seconds is the same order as the HTTP timeouts a client uses.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(10);

/// Bound on remembered rotations, so a burst of refreshes cannot grow this
/// without limit. Entries expire on their own; this is the backstop.
const MAX_ENTRIES: usize = 10_000;

/// A grace-window hit.
pub struct GraceHit {
    /// The successor pair the token was already exchanged for.
    pub tokens: SessionTokens,
    /// Whether this presentation came from a different address than the
    /// exchange that created the entry.
    ///
    /// `false` when either address is unknown: that is "cannot tell", and it
    /// should not read as "same".
    pub from_elsewhere: bool,
}

/// Remembers, briefly, what each rotated refresh token was exchanged for.
pub struct RefreshGrace {
    window: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    at: Instant,
    tokens: SessionTokens,
    from: Option<IpAddr>,
}

impl RefreshGrace {
    /// Build a grace window of the given length.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// What this token was already exchanged for, if it was, and recently.
    ///
    /// `from` is the address presenting it now. It is compared against the
    /// address that performed the original exchange, and a difference is
    /// reported rather than refused.
    ///
    /// Reported rather than refused deliberately. Whoever presents this token
    /// already holds the credential -- they could have refreshed first and
    /// received a session that way, so withholding the successor denies them
    /// nothing. What the grace window does take away is the *signal*: without
    /// it one of the two racing parties gets a 401, and a client that has been
    /// robbed logs its user out, which the user notices. Restoring the signal
    /// is therefore the fix, and refusing is not: a legitimate client that
    /// changed address between two in-flight requests -- a phone moving
    /// between networks -- would be refused and logged out, which is the exact
    /// harm this window exists to prevent.
    #[must_use]
    pub fn get(&self, jti: &str, from: Option<IpAddr>) -> Option<GraceHit> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(jti)?;
        if entry.at.elapsed() > self.window {
            return None;
        }
        let from_elsewhere = match (entry.from, from) {
            (Some(first), Some(now)) => first != now,
            _ => false,
        };
        Some(GraceHit {
            tokens: entry.tokens.clone(),
            from_elsewhere,
        })
    }

    /// Record what a token was exchanged for, and from where.
    pub fn insert(&self, jti: &str, tokens: &SessionTokens, from: Option<IpAddr>) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= MAX_ENTRIES {
            // Drop everything already past the window before resorting to
            // refusing new records; in steady state this keeps the map small.
            let window = self.window;
            entries.retain(|_, entry| entry.at.elapsed() <= window);
        }
        if entries.len() < MAX_ENTRIES {
            entries.insert(
                jti.to_string(),
                Entry {
                    at: Instant::now(),
                    tokens: tokens.clone(),
                    from,
                },
            );
        }
    }
}

impl Default for RefreshGrace {
    fn default() -> Self {
        Self::new(DEFAULT_GRACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(tag: &str) -> SessionTokens {
        SessionTokens {
            access_jwt: format!("access-{tag}"),
            refresh_jwt: format!("refresh-{tag}"),
        }
    }

    /// The racing client's second request gets the same successor, so both of
    /// its in-flight requests end up agreeing on one session.
    #[test]
    fn a_replay_inside_the_window_returns_the_same_successor() {
        let grace = RefreshGrace::new(Duration::from_secs(10));
        let from = Some("198.51.100.7".parse().unwrap());
        grace.insert("jti-1", &tokens("a"), from);
        let again = grace.get("jti-1", from).expect("inside the window");
        assert_eq!(again.tokens.access_jwt, "access-a");
        assert_eq!(again.tokens.refresh_jwt, "refresh-a");
        assert!(!again.from_elsewhere, "the same address is not elsewhere");
    }

    /// Past the window the token is unknown again, so the caller falls through
    /// to the replay check and refuses it. This is the property that keeps
    /// reuse detection meaningful.
    #[test]
    fn a_replay_outside_the_window_is_not_served() {
        let grace = RefreshGrace::new(Duration::from_millis(1));
        grace.insert("jti-2", &tokens("b"), None);
        std::thread::sleep(Duration::from_millis(20));
        assert!(grace.get("jti-2", None).is_none());
    }

    #[test]
    fn an_unknown_token_is_not_served() {
        let grace = RefreshGrace::new(Duration::from_secs(10));
        assert!(grace.get("never-seen", None).is_none());
    }

    /// The same token exchanged from a second address inside ten seconds is
    /// not a client racing itself. The successor is still returned -- whoever
    /// holds the token could have refreshed first and got a session anyway --
    /// but the caller is told, because the window would otherwise make the
    /// second exchange invisible and that is what a stolen token needs.
    #[test]
    fn an_exchange_from_a_second_address_is_reported_and_still_served() {
        let grace = RefreshGrace::new(Duration::from_secs(10));
        let first = Some("198.51.100.7".parse().unwrap());
        let second = Some("203.0.113.9".parse().unwrap());
        grace.insert("jti-3", &tokens("c"), first);

        let hit = grace.get("jti-3", second).expect("inside the window");
        assert!(
            hit.from_elsewhere,
            "a different address must be reported as such"
        );
        assert_eq!(
            hit.tokens.access_jwt, "access-c",
            "the successor is still served: refusing it denies nothing to \
             someone already holding the token, and would log out a client \
             that changed network mid-flight"
        );
    }

    /// An address this server could not attribute is "cannot tell", not
    /// "same". Behind an undeclared proxy every caller looks alike, and
    /// reporting that as agreement would be a claim the data does not support.
    #[test]
    fn an_unknown_address_is_not_reported_as_a_match() {
        let grace = RefreshGrace::new(Duration::from_secs(10));
        grace.insert("jti-4", &tokens("d"), Some("198.51.100.7".parse().unwrap()));
        let hit = grace.get("jti-4", None).expect("inside the window");
        assert!(!hit.from_elsewhere);
    }

    /// The map cannot grow without bound even if every refresh is remembered.
    #[test]
    fn the_record_is_bounded() {
        let grace = RefreshGrace::new(Duration::from_secs(3600));
        for i in 0..(MAX_ENTRIES + 500) {
            grace.insert(&format!("jti-{i}"), &tokens("x"), None);
        }
        let len = grace.entries.lock().unwrap().len();
        assert!(len <= MAX_ENTRIES, "grew to {len}");
    }
}
