//! Serializing refresh attempts, so a client does not race itself.
//!
//! Under OAuth 2.1 §4.14.2 a replayed refresh token revokes the whole grant,
//! and **the specification does not distinguish a leaked token from a client
//! racing itself**. `atproto-pds` implements that rule. So two concurrent
//! requests for one session, each finding the access token expired and each
//! spending the same refresh token, sign the user out.
//!
//! The failure mode is the expensive kind. The user is signed out at random,
//! nothing anywhere names the cause, and it only reproduces under concurrency
//! -- which is to say, in production and not in a test somebody wrote.
//!
//! [`oauth_refresh`](crate::workflow::oauth_refresh) is a bare async function
//! and cannot prevent this; nothing about one call knows another is in flight.
//! [`RefreshCoordinator`] is the thing that does.
//!
//! # In-process
//!
//! This is correct for a single-node deployment and would have to become a
//! distributed lock for more than one. That is worth saying at the call site
//! rather than discovering under load, and it is why the type is a
//! coordinator a caller holds rather than something hidden inside
//! `oauth_refresh`.

#![deny(clippy::await_holding_lock)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::OAuthClientError;
use crate::workflow::TokenResponse;

/// How long a completed refresh answers for a waiter that arrives just after
/// it.
///
/// Without a memo, a caller that blocks on an in-flight refresh acquires the
/// lock the moment it finishes and immediately spends the token that refresh
/// just issued -- which is the race, one step later.
pub const DEFAULT_MEMO_TTL: Duration = Duration::from_secs(60);

/// Backoff after a failed refresh, indexed by consecutive failures.
///
/// An authorization server that is refusing should not be asked again by every
/// request that arrives, and the last entry is the ceiling.
pub const DEFAULT_BACKOFF: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
];

/// What happened when a caller asked to refresh.
pub enum RefreshOutcome {
    /// A refresh happened, and these are the new tokens.
    Refreshed(Box<TokenResponse>),

    /// A refresh completed recently enough that this caller should re-read its
    /// session rather than refresh again.
    ///
    /// Not an error, and not a reason to retry: somebody else already did the
    /// work, and the tokens are wherever that caller stored them.
    AlreadyFresh,

    /// Inside the backoff after a failure. Do not call the server.
    Backoff {
        /// When the next attempt is allowed.
        until: Instant,
    },
}

/// Prints the outcome without the tokens.
///
/// `TokenResponse` deliberately has no `Debug`, and deriving one here through
/// a `Box` would put an access token in whatever log line formatted the
/// outcome.
impl std::fmt::Debug for RefreshOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshOutcome::Refreshed(_) => f.write_str("Refreshed(..)"),
            RefreshOutcome::AlreadyFresh => f.write_str("AlreadyFresh"),
            RefreshOutcome::Backoff { until } => {
                f.debug_struct("Backoff").field("until", until).finish()
            }
        }
    }
}

/// One subject's refresh state.
#[derive(Debug, Default)]
struct RefreshState {
    /// When the last successful refresh finished.
    settled_at: Option<Instant>,
    /// When the next attempt is allowed, after a failure.
    retry_after: Option<Instant>,
    /// Consecutive failures, indexing the backoff table.
    failures: usize,
}

impl RefreshState {
    /// Whether this state still says anything, and so is worth keeping.
    fn is_live(&self, now: Instant, memo_ttl: Duration) -> bool {
        let memo_live = self
            .settled_at
            .is_some_and(|settled| now.duration_since(settled) < memo_ttl);
        let backoff_live = self.retry_after.is_some_and(|until| until > now);
        memo_live || backoff_live
    }
}

/// Serializes refresh attempts per subject.
///
/// See the module documentation for what this is preventing and why it is
/// in-process.
pub struct RefreshCoordinator {
    /// Keyed by subject DID.
    ///
    /// The `std` mutex guards only the map. It is held long enough to clone an
    /// `Arc` and never across an await -- the per-subject `tokio` mutex inside
    /// is what a caller actually waits on.
    slots: Mutex<HashMap<String, Arc<tokio::sync::Mutex<RefreshState>>>>,
    memo_ttl: Duration,
    backoff: Vec<Duration>,
}

impl Default for RefreshCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshCoordinator {
    /// A coordinator with the default memo and backoff.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            memo_ttl: DEFAULT_MEMO_TTL,
            backoff: DEFAULT_BACKOFF.to_vec(),
        }
    }

    /// Set how long a completed refresh answers for later arrivals.
    #[must_use]
    pub fn memo_ttl(mut self, memo_ttl: Duration) -> Self {
        self.memo_ttl = memo_ttl;
        self
    }

    /// Set the backoff schedule. An empty schedule disables backoff.
    #[must_use]
    pub fn backoff(mut self, backoff: Vec<Duration>) -> Self {
        self.backoff = backoff;
        self
    }

    /// How many subjects are currently tracked.
    ///
    /// Exposed so a caller can assert the map is bounded, which is the one
    /// property of this type that is invisible from its behaviour.
    pub fn tracked(&self) -> usize {
        self.slots.lock().expect("refresh slot map").len()
    }

    /// Refresh for `subject`, at most once concurrently.
    ///
    /// A caller arriving while a refresh is in flight waits for it and is then
    /// told [`RefreshOutcome::AlreadyFresh`] -- the work is done and the
    /// tokens are wherever the winner stored them. A caller arriving inside
    /// the backoff after a failure is told [`RefreshOutcome::Backoff`] without
    /// the future being polled at all.
    ///
    /// `refresh` is taken as a future rather than as the refresh token, so the
    /// coordinator stays independent of where that token is stored -- which is
    /// the part every consumer does differently.
    ///
    /// # Errors
    ///
    /// Returns whatever the future returned, after recording the failure.
    pub async fn refresh<F>(
        &self,
        subject: &str,
        refresh: F,
    ) -> Result<RefreshOutcome, OAuthClientError>
    where
        F: Future<Output = Result<TokenResponse, OAuthClientError>>,
    {
        let slot = self.slot(subject);

        // The await is on the per-subject mutex; the map's lock was released
        // inside `slot` above.
        let mut state = slot.lock().await;
        let now = Instant::now();

        if let Some(settled) = state.settled_at
            && now.duration_since(settled) < self.memo_ttl
        {
            return Ok(RefreshOutcome::AlreadyFresh);
        }

        if let Some(until) = state.retry_after
            && until > now
        {
            return Ok(RefreshOutcome::Backoff { until });
        }

        match refresh.await {
            Ok(tokens) => {
                state.settled_at = Some(Instant::now());
                state.retry_after = None;
                state.failures = 0;
                Ok(RefreshOutcome::Refreshed(Box::new(tokens)))
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                if !self.backoff.is_empty() {
                    let index = (state.failures - 1).min(self.backoff.len() - 1);
                    state.retry_after = Some(Instant::now() + self.backoff[index]);
                }
                Err(error)
            }
        }
    }

    /// The slot for `subject`, creating it if needed.
    ///
    /// Every eviction and insertion happens here, under the map's lock and
    /// with nothing awaited inside it.
    fn slot(&self, subject: &str) -> Arc<tokio::sync::Mutex<RefreshState>> {
        let mut slots = self.slots.lock().expect("refresh slot map");

        // Without this the map grows one entry per DID that has ever signed
        // in, which on a busy node is a slow leak nobody attributes to the
        // refresh path.
        let now = Instant::now();
        let memo_ttl = self.memo_ttl;
        slots.retain(|_, slot| {
            // `try_lock` rather than `lock`: this runs under a `std` mutex and
            // must not await. A slot somebody is holding is one to keep
            // anyway, so failing to lock is the right answer either way.
            Arc::strong_count(slot) > 1
                || slot
                    .try_lock()
                    .is_ok_and(|state| state.is_live(now, memo_ttl))
        });

        slots.entry(subject.to_string()).or_default().clone()
    }
}
