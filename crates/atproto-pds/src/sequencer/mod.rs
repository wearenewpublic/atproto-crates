//! Firehose sequencing.
//!
//! [`stream::Sequencer`] is the firehose: one ordered event log for the whole
//! server, living in the accounts database so it is shared by every storage
//! profile. `seq` numbers the stream, and it is what subscribers resume on.
//!
//! Surface: [`stream::Sequencer`] for append and paginated read, [`payload`]
//! for the lexicon-shaped event bodies, [`frame`] for the wire encoding,
//! [`publish_sync`] for the `#sync` helper, and [`EventBus`] for waking live
//! subscribers without waiting on the poll interval.
//!
//! [`outbox`] remains for the per-actor event table. It is no longer the
//! firehose source — nothing writes to it — and is retained only so that
//! removing the table is a separate change from redirecting the stream.

pub mod event_bus;
pub mod frame;
pub mod outbox;
pub mod payload;
pub mod stream;
pub mod sync_event;

pub use event_bus::{EventBus, SubscribeEvent};
pub use frame::{Encoding, FrameHeader, encode_event, encode_info};
pub use outbox::{EventFrame, EventType, OutboxReader, OutboxRow};
pub use stream::{Sequencer, StreamRow};
pub use sync_event::publish_sync;
