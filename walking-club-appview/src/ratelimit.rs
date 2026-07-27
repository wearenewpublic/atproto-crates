//! In-memory token-bucket rate limiter.
//!
//! Best-effort, per-process — appropriate for a single-node test AppView. Keyed
//! by client IP with a fixed window.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A fixed-window counter for one client.
#[derive(Debug, Clone)]
struct Window {
    count: u32,
    reset_at: Instant,
}

/// In-memory rate limiter shared across handlers.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Window>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    /// Create a new limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }

    /// Create a limiter with the default 15-minute window.
    pub fn with_count(max_requests: u32) -> Self {
        Self::new(max_requests, Duration::from_secs(15 * 60))
    }

    /// Returns `true` if the request from `ip` is allowed (and records it).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let entry = buckets.entry(ip).or_insert(Window {
            count: 0,
            reset_at: now + self.window,
        });
        if now >= entry.reset_at {
            entry.count = 0;
            entry.reset_at = now + self.window;
        }
        if entry.count >= self.max_requests {
            return false;
        }
        entry.count += 1;
        true
    }

    /// Drop expired windows to bound memory.
    pub fn prune(&self) {
        let now = Instant::now();
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.retain(|_, w| now < w.reset_at);
        }
    }
}
