//! Live event bus for `subscribeRepos` — broadcast-channel low-latency
//! firehose path.
//!
//! [`crate::sequencer::stream`] is the durable record and the source of truth.
//! This in-process broadcast channel exists only so a connected subscriber
//! wakes on the write itself rather than waiting out the poll interval.
//!
//! # The bus is a wakeup, not a delivery
//!
//! An event on this channel says *something was written*; it does not say what,
//! and a subscriber does not send it. Frames are read from the durable stream
//! in `seq` order, always, and the bus only decides when to go and look.
//!
//! That distinction is the whole safety property. Carrying the frame here
//! instead made delivery depend on the bus being right about *which* event a
//! write produced, and it was not: the publisher re-derived it from the
//! server-global `MAX(seq)` filtered by DID, outside the per-DID write lock, so
//! two overlapping writes could publish one event twice and never publish the
//! other. A subscriber that advanced its cursor to what it received then read
//! `seq >` that, and the skipped event was gone for good.
//!
//! With a wakeup, neither failure exists. A missed signal costs latency and
//! nothing else — the poll interval covers it. A spurious or duplicated signal
//! costs one query that returns no rows. Ordering and completeness belong to
//! [`crate::sequencer::stream`], which is the only thing that can guarantee
//! them, because it is the thing that allocates `seq` inside the insert.

use std::sync::Arc;
use tokio::sync::broadcast;

/// A signal that the stream advanced.
///
/// Deliberately carries no frame. See the module note: the payload used to live
/// here, and having it made the bus a second, weaker source of truth alongside
/// the durable log.
#[derive(Debug, Clone)]
pub struct SubscribeEvent {
    /// DID of the actor that produced the write.
    ///
    /// Present only so a subscriber filtering on one DID can ignore a wakeup
    /// that cannot concern it. Skipping on it is safe in the direction that
    /// matters: a wakeup wrongly ignored is picked up by the next poll, and the
    /// events that are not broadcast at all (`#account`, `#identity`) already
    /// rely on that path.
    pub did: String,
}

/// Cheap-to-clone handle to the bus.
#[derive(Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<SubscribeEvent>>,
}

impl EventBus {
    /// Construct an event bus with the given subscriber-buffer capacity.
    /// Events delivered while a subscriber is behind by more than `capacity`
    /// are dropped from the broadcast — the durable stream makes this safe
    /// (consumers self-heal on the next poll).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _rx) = broadcast::channel(capacity);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Publish an event. Returns the number of active subscribers that
    /// received it (0 is fine — the durable stream covers them).
    pub fn publish(&self, event: SubscribeEvent) -> usize {
        // `send` returns `Err(SendError)` when there are no receivers; that's
        // not actually an error from the publisher's perspective.
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe a new receiver. Each subscriber observes events published
    /// after `subscribe()` is called.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<SubscribeEvent> {
        self.sender.subscribe()
    }

    /// Number of currently-active subscribers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(did: &str) -> SubscribeEvent {
        SubscribeEvent {
            did: did.to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_with_no_subscribers_is_ok() {
        let bus = EventBus::new(16);
        assert_eq!(bus.publish(ev("did:plc:a")), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_subscriber_receives_one_event() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(ev("did:plc:a"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.did, "did:plc:a");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multi_subscriber_fanout() {
        let bus = EventBus::new(16);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        bus.publish(ev("did:plc:x"));
        assert_eq!(a.recv().await.unwrap().did, "did:plc:x");
        assert_eq!(b.recv().await.unwrap().did, "did:plc:x");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lag_drops_old_events() {
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();
        for _ in 0..5 {
            bus.publish(ev("did:plc:x"));
        }
        // The first recv() should report Lagged because the buffer overflowed.
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn receiver_count_tracks_active_subscribers() {
        let bus = EventBus::new(4);
        assert_eq!(bus.receiver_count(), 0);
        let _r1 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);
        let _r2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);
        drop(_r1);
        assert_eq!(bus.receiver_count(), 1);
    }
}
