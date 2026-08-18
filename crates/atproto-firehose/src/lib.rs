//! A `com.atproto.sync.subscribeRepos` consumer.
//!
//! The workspace already has a Jetstream consumer, a TAP consumer, and a
//! `subscribeRepos` **producer** inside `atproto-pds`. What it did not have is
//! a `subscribeRepos` consumer, so every app view that wanted full-fidelity
//! verified events wrote one.
//!
//! ## Modules
//!
//! - [`wire`]: the frame format, the five-member event union, and the
//!   two-stage decode that makes a consumer affordable.
//! - [`verify`]: proving a commit against the repository that claims to have
//!   made it, at a level the caller picks.
//! - [`consumer`]: the WebSocket loop, its reconnect policy, and the cursor
//!   contract.
//!
//! ## What this crate does not decide
//!
//! The tracked-collection list, where events are written, and how a cursor is
//! stored are all the caller's, through [`consumer::IngestSink`] and
//! [`consumer::CursorStore`]. So is the signing-key cache, through
//! [`verify::SigningKeyResolver`] -- a firehose consumer resolves the same few
//! thousand DIDs repeatedly, and the right cache policy depends on whether the
//! consumer also watches `#identity`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod consumer;
pub mod errors;
pub mod verify;
pub mod wire;

pub use errors::{ConsumerError, FrameError, VerifyFailure};
pub use verify::{SigningKeyResolver, Verification, VerificationLevel, verify_commit};
pub use wire::{
    AccountPayload, CommitBlocks, CommitEnvelope, ErrorPayload, Event, Frame, FrameHeader,
    IdentityPayload, InfoPayload, SyncPayload, matches_tracked, split_frame,
};
