//! Per-actor firehose sequencer.
//!
//! and decision G2: the
//! SQLite profile uses a **per-actor Sequencer task**, each draining its own
//! `outbox` table. The fjall profile uses a single global Sequencer over
//! the shared `outbox` partition.
//!
//! Surface: `OutboxReader` for paginated backfill of stored events,
//! `SubscribeReposState` shared event-frame types, the writer side
//! (`Sequencer::publish` / `publish_sync`), and the broadcast channel
//! for live-tail subscribers.

pub mod event_bus;
pub mod frame;
pub mod outbox;
pub mod sync_event;

pub use event_bus::{EventBus, SubscribeEvent};
pub use frame::{Encoding, FrameHeader, encode_event, encode_info};
pub use outbox::{EventFrame, EventType, OutboxReader, OutboxRow};
pub use sync_event::{publish_sync, publish_sync_via_backend};
