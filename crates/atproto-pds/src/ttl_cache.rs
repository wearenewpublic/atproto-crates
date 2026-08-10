//! A bounded, time-to-live cache for resolver results.
//!
//! The three resolvers in this crate that cache -- lexicon documents, proxy
//! targets, space-type declarations -- each held a `Mutex<HashMap<String, _>>`
//! with no capacity and no reaping. Their read path *ignored* an expired entry
//! and their write path only ever inserted, so nothing was ever removed: the
//! maps grew for the life of the process.
//!
//! That is a leak driven by request volume rather than by data, because in
//! every case the key comes from the caller. A collection NSID is whatever a
//! record being written names, a proxy target is whatever an `Atproto-Proxy`
//! header says, and a space type is whatever a request asks about. Distinct
//! keys are free to produce and each one costs a permanent entry.
//!
//! Bounding is the fix. An LRU discards the least recently used key when full,
//! which for a cache is the right thing to lose: a key nobody has asked for
//! recently is a key whose absence costs one resolution.
//!
//! Expiry is still checked on read rather than swept. A stale entry occupies a
//! slot until capacity pressure reaches it, which is a bounded amount of waste
//! and no correctness difference -- a stale entry is never served.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cache of `V` keyed by `String`, bounded by entry count and by age.
pub struct TtlCache<V> {
    ttl: Duration,
    entries: Mutex<lru::LruCache<String, (Instant, V)>>,
}

impl<V: Clone> TtlCache<V> {
    /// Build a cache holding at most `capacity` entries for `ttl` each.
    ///
    /// A zero capacity is treated as one: a cache that can hold nothing is
    /// almost certainly a configuration mistake rather than an intent, and
    /// refusing to construct would push that decision onto every caller.
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            entries: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN),
            )),
        }
    }

    /// The cached value for `key`, if it is present and not expired.
    ///
    /// A hit promotes the key, so what the cache keeps under pressure is what
    /// is actually being asked for.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<V> {
        let mut entries = self.entries.lock().ok()?;
        let (at, value) = entries.get(key)?;
        if at.elapsed() > self.ttl {
            return None;
        }
        Some(value.clone())
    }

    /// Record `value` for `key`, evicting the least recently used entry if the
    /// cache is full.
    pub fn put(&self, key: &str, value: V) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.put(key.to_string(), (Instant::now(), value));
        }
    }

    /// How many entries are held, expired or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }

    /// Whether the cache holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hit_inside_the_ttl_is_served() {
        let cache: TtlCache<u32> = TtlCache::new(Duration::from_secs(60), 8);
        cache.put("a", 1);
        assert_eq!(cache.get("a"), Some(1));
    }

    #[test]
    fn a_stale_entry_is_not_served() {
        let cache: TtlCache<u32> = TtlCache::new(Duration::from_millis(1), 8);
        cache.put("a", 1);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.get("a"), None);
    }

    /// The property the `HashMap` did not have: distinct keys are free to
    /// produce and each one used to cost a permanent entry.
    #[test]
    fn the_cache_does_not_grow_past_its_capacity() {
        let cache: TtlCache<u32> = TtlCache::new(Duration::from_secs(3600), 16);
        for i in 0..10_000 {
            cache.put(&format!("key-{i}"), i);
        }
        assert_eq!(cache.len(), 16, "an LRU is bounded by its capacity");
    }

    /// Under pressure the cache keeps what is being asked for, which is the
    /// reason to evict by recency rather than by insertion.
    #[test]
    fn a_key_that_keeps_being_read_survives_eviction() {
        let cache: TtlCache<u32> = TtlCache::new(Duration::from_secs(3600), 4);
        cache.put("hot", 1);
        for i in 0..100 {
            cache.put(&format!("cold-{i}"), i);
            assert_eq!(cache.get("hot"), Some(1), "reading it keeps it");
        }
    }
}
