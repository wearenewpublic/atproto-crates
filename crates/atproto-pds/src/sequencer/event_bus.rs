//! Live event bus for `subscribeRepos` — broadcast-channel low-latency
//! firehose path.
//!
//! [`crate::sequencer::stream`] is the durable record and the source of truth.
//! This in-process broadcast channel exists only so a connected subscriber
//! wakes on the write itself rather than waiting out the poll interval.
//!
//! When a subscriber receives a [`SubscribeEvent`] it advances its cursor and
//! skips that `seq` on the next poll cycle — so a missed broadcast (lagged
//! subscriber, restart, an event published by another process) costs latency
//! and nothing else: the poll path delivers it from the stream.

use std::sync::Arc;
use tokio::sync::broadcast;

/// One firehose event published to live subscribers.
#[derive(Debug, Clone)]
pub struct SubscribeEvent {
    /// DID of the actor that produced this event.
    pub did: String,
    /// Stream position (matches the corresponding `stream_event` row).
    pub seq: i64,
    /// `event_type` string (e.g. "#commit", "#account").
    pub event_type: String,
    /// DAG-CBOR body bytes — the same bytes the poll path sends.
    pub payload: Vec<u8>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
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

    fn ev(did: &str, seq: i64) -> SubscribeEvent {
        SubscribeEvent {
            did: did.to_string(),
            seq,
            event_type: "#commit".to_string(),
            payload: b"{}".to_vec(),
            created_at: "2026-05-04T00:00:00Z".to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_with_no_subscribers_is_ok() {
        let bus = EventBus::new(16);
        assert_eq!(bus.publish(ev("did:plc:a", 1)), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_subscriber_receives_one_event() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        bus.publish(ev("did:plc:a", 7));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.did, "did:plc:a");
        assert_eq!(got.seq, 7);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multi_subscriber_fanout() {
        let bus = EventBus::new(16);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        bus.publish(ev("did:plc:x", 1));
        assert_eq!(a.recv().await.unwrap().seq, 1);
        assert_eq!(b.recv().await.unwrap().seq, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lag_drops_old_events() {
        let bus = EventBus::new(2);
        let mut rx = bus.subscribe();
        for i in 0..5 {
            bus.publish(ev("did:plc:x", i));
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
