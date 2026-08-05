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

/// Remembers, briefly, what each rotated refresh token was exchanged for.
pub struct RefreshGrace {
    window: Duration,
    entries: Mutex<HashMap<String, (Instant, SessionTokens)>>,
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
    #[must_use]
    pub fn get(&self, jti: &str) -> Option<SessionTokens> {
        let entries = self.entries.lock().ok()?;
        let (at, tokens) = entries.get(jti)?;
        if at.elapsed() > self.window {
            return None;
        }
        Some(tokens.clone())
    }

    /// Record what a token was exchanged for.
    pub fn insert(&self, jti: &str, tokens: &SessionTokens) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= MAX_ENTRIES {
            // Drop everything already past the window before resorting to
            // refusing new records; in steady state this keeps the map small.
            let window = self.window;
            entries.retain(|_, (at, _)| at.elapsed() <= window);
        }
        if entries.len() < MAX_ENTRIES {
            entries.insert(jti.to_string(), (Instant::now(), tokens.clone()));
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
        grace.insert("jti-1", &tokens("a"));
        let again = grace.get("jti-1").expect("inside the window");
        assert_eq!(again.access_jwt, "access-a");
        assert_eq!(again.refresh_jwt, "refresh-a");
    }

    /// Past the window the token is unknown again, so the caller falls through
    /// to the replay check and refuses it. This is the property that keeps
    /// reuse detection meaningful.
    #[test]
    fn a_replay_outside_the_window_is_not_served() {
        let grace = RefreshGrace::new(Duration::from_millis(1));
        grace.insert("jti-2", &tokens("b"));
        std::thread::sleep(Duration::from_millis(20));
        assert!(grace.get("jti-2").is_none());
    }

    #[test]
    fn an_unknown_token_is_not_served() {
        let grace = RefreshGrace::new(Duration::from_secs(10));
        assert!(grace.get("never-seen").is_none());
    }

    /// The map cannot grow without bound even if every refresh is remembered.
    #[test]
    fn the_record_is_bounded() {
        let grace = RefreshGrace::new(Duration::from_secs(3600));
        for i in 0..(MAX_ENTRIES + 500) {
            grace.insert(&format!("jti-{i}"), &tokens("x"));
        }
        let len = grace.entries.lock().unwrap().len();
        assert!(len <= MAX_ENTRIES, "grew to {len}");
    }
}
