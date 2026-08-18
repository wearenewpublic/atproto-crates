//! The WebSocket loop: connect, decode, deliver, advance the cursor.
//!
//! # The cursor advances behind durable writes, never ahead
//!
//! A batch is delivered to the [`IngestSink`], the `await` resolves meaning
//! the write committed, and only then does the cursor move. A crash in that
//! window re-processes one commit, which is harmless as long as every
//! downstream write is keyed by `(did, collection, rkey)`. The reverse
//! ordering would skip it, which is not harmless and is not recoverable
//! without a backfill.
//!
//! Frames that match nothing still advance the stream. Writing the cursor for
//! each of them would mean a storage write per firehose frame -- hundreds a
//! second, to record that nothing happened -- so those are coalesced and
//! flushed at most once per [`ConsumerConfig::cursor_flush_interval`]. That is
//! safe for the same reason the ordering is: frames are processed strictly in
//! sequence, so when frame N finishes, everything up to N is durable by
//! construction.
//!
//! # Reconnecting
//!
//! Exponential backoff with jitter, capped. The jitter is not decoration: a
//! relay that restarts drops every consumer at once, and an unjittered backoff
//! has them all come back at the same instant, repeatedly.
//!
//! An `#info` naming `OutdatedCursor` clears the stored cursor before
//! reconnecting. The stored value has been refused once and reconnecting with
//! it would only be refused again; what follows is a gap the consumer has to
//! close by backfilling, which is the caller's to do and is why the sink is
//! told about it.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use tokio_websockets::ClientBuilder;

use crate::errors::ConsumerError;
use crate::verify::{SigningKeyResolver, VerificationLevel, verify_commit};
use crate::wire::{
    AccountPayload, CommitEnvelope, Event, IdentityPayload, InfoPayload, SyncPayload,
    matches_tracked, split_frame,
};

/// One message handed to the sink.
///
/// `Commit` is much larger than the rest, and for the same reason as
/// [`crate::wire::Event`] it is not boxed: almost every message is one.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum IngestMessage {
    /// A commit whose ops the consumer tracks, with its verified CAR slice.
    Commit {
        /// Everything but `blocks`.
        envelope: CommitEnvelope,
        /// The CAR slice, as it arrived.
        blocks: Vec<u8>,
    },
    /// The repository's state was asserted out of band.
    ///
    /// Not a record event. The consumer cannot get to the current state by
    /// applying anything, so the response is to re-read the repository.
    Resync(SyncPayload),
    /// A handle, signing key, or PDS endpoint changed.
    Identity(IdentityPayload),
    /// Hosting status changed.
    Account(AccountPayload),
    /// The cursor was refused as too old and has been cleared.
    ///
    /// Everything between the refused cursor and the stream's current head is
    /// a gap. Closing it is a backfill, which this crate does not do.
    CursorLost {
        /// The cursor the server refused, when one was stored.
        refused: Option<i64>,
        /// What the server said.
        info: InfoPayload,
    },
}

/// What the sink says about a message it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack;

/// Where events go, and when they are durable.
#[async_trait]
pub trait IngestSink: Send + Sync {
    /// Apply one message, returning only once the write is durable.
    ///
    /// Returning `Err` tells the consumer the message was **not** applied. It
    /// will log it and leave the cursor where it is, so the message is seen
    /// again on the next reconnect. An implementation that can never apply a
    /// particular message should therefore log and return `Ok` rather than
    /// wedging the stream behind it forever.
    async fn deliver(&self, message: IngestMessage) -> Result<Ack, String>;
}

/// Where the resume position lives.
#[async_trait]
pub trait CursorStore: Send + Sync {
    /// The last sequence durably processed for `source`.
    async fn load(&self, source: &str) -> Result<Option<i64>, String>;

    /// Record that everything up to `seq` is durable.
    async fn store(&self, source: &str, seq: i64) -> Result<(), String>;

    /// Forget the stored position.
    ///
    /// Called on `OutdatedCursor`: the stored value has been refused once, and
    /// reconnecting with it would only be refused again.
    async fn clear(&self, source: &str) -> Result<(), String>;
}

/// Sharing a sink between a consumer and whatever else holds it is the
/// ordinary case, so `Arc` delegates rather than making callers wrap.
#[async_trait]
impl<T: IngestSink + ?Sized> IngestSink for std::sync::Arc<T> {
    async fn deliver(&self, message: IngestMessage) -> Result<Ack, String> {
        (**self).deliver(message).await
    }
}

#[async_trait]
impl<T: CursorStore + ?Sized> CursorStore for std::sync::Arc<T> {
    async fn load(&self, source: &str) -> Result<Option<i64>, String> {
        (**self).load(source).await
    }

    async fn store(&self, source: &str, seq: i64) -> Result<(), String> {
        (**self).store(source, seq).await
    }

    async fn clear(&self, source: &str) -> Result<(), String> {
        (**self).clear(source).await
    }
}

/// How the consumer connects and what it tracks.
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// The relay or PDS to subscribe to, as a URL or a bare hostname.
    pub host: String,
    /// The key the cursor is stored under. Defaults to `host`.
    pub source: String,
    /// Collections whose commits are delivered. Empty means every commit.
    pub collections: Vec<String>,
    /// How much of a commit to prove before delivering it.
    pub verification: VerificationLevel,
    /// The `User-Agent` to connect with.
    pub user_agent: String,
    /// First reconnect delay.
    pub initial_reconnect_delay: Duration,
    /// Ceiling on the reconnect delay.
    pub max_reconnect_delay: Duration,
    /// How often a cursor that only skipped frames is flushed.
    pub cursor_flush_interval: Duration,
}

impl ConsumerConfig {
    /// A configuration for `host` with the defaults.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            source: host.clone(),
            host,
            collections: Vec::new(),
            verification: VerificationLevel::Full,
            user_agent: concat!("atproto-firehose/", env!("CARGO_PKG_VERSION")).to_string(),
            initial_reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(60),
            // Five seconds of skipped frames re-read after a crash is cheaper
            // than a storage write per frame, hundreds a second, recording
            // that nothing happened.
            cursor_flush_interval: Duration::from_secs(5),
        }
    }

    /// Only deliver commits touching these collections.
    #[must_use]
    pub fn collections(mut self, collections: Vec<String>) -> Self {
        self.collections = collections;
        self
    }

    /// Set how much of a commit to prove.
    #[must_use]
    pub fn verification(mut self, level: VerificationLevel) -> Self {
        self.verification = level;
        self
    }
}

/// What one frame did to the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameOutcome {
    /// Delivered to the sink. The cursor may move to this sequence.
    Delivered(i64),
    /// Not tracked, or not a member this build knows. The cursor may move.
    Skipped(Option<i64>),
    /// The sink refused it. The cursor must not move.
    Held(Option<i64>),
    /// The server sent a terminal error frame.
    Terminal(ConsumerError),
    /// The cursor was refused and cleared; reconnect without one.
    CursorCleared,
}

/// A reconnecting `subscribeRepos` consumer.
pub struct FirehoseConsumer<S, C, R> {
    config: ConsumerConfig,
    sink: S,
    cursors: C,
    resolver: R,
}

impl<S, C, R> FirehoseConsumer<S, C, R>
where
    S: IngestSink,
    C: CursorStore,
    R: SigningKeyResolver,
{
    /// Assemble a consumer from its three seams.
    pub fn new(config: ConsumerConfig, sink: S, cursors: C, resolver: R) -> Self {
        Self {
            config,
            sink,
            cursors,
            resolver,
        }
    }

    /// The configuration this consumer runs with.
    pub fn config(&self) -> &ConsumerConfig {
        &self.config
    }

    /// The sink events are delivered to.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// The store the cursor lives in.
    pub fn cursors(&self) -> &C {
        &self.cursors
    }

    /// Connect, consume, and reconnect until `shutdown` resolves.
    ///
    /// Returns only on shutdown or on a terminal error frame, which is the one
    /// refusal that reconnecting cannot fix.
    ///
    /// # Errors
    ///
    /// Returns [`ConsumerError::ServerError`] when the server sends a terminal
    /// error frame.
    pub async fn run(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ConsumerError> {
        let mut delay = self.config.initial_reconnect_delay;

        loop {
            if *shutdown.borrow() {
                return Ok(());
            }

            match self.connect_and_consume(&mut shutdown).await {
                Ok(()) => return Ok(()),
                Err(error @ ConsumerError::ServerError { .. }) => return Err(error),
                Err(error) => {
                    tracing::warn!(error = %error, "firehose connection ended; reconnecting");
                }
            }

            // Jittered, because a relay that restarts drops every consumer at
            // once and an unjittered backoff has them all come back together,
            // repeatedly.
            let jittered = jitter(delay);
            tokio::select! {
                () = tokio::time::sleep(jittered) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }

            delay = (delay * 2).min(self.config.max_reconnect_delay);
        }
    }

    /// One connection's worth of frames.
    async fn connect_and_consume(
        &self,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), ConsumerError> {
        let cursor = self
            .cursors
            .load(&self.config.source)
            .await
            .unwrap_or_else(|reason| {
                tracing::error!(
                    reason,
                    "cursor could not be read; starting at the live edge"
                );
                None
            });

        let url =
            atproto_client::com::atproto::sync::subscribe_repos_url(&self.config.host, cursor)
                .map_err(|error| ConsumerError::InvalidUrl {
                    host: self.config.host.clone(),
                    reason: error.to_string(),
                })?;

        let uri: http::Uri =
            url.parse()
                .map_err(|error: http::uri::InvalidUri| ConsumerError::InvalidUrl {
                    host: self.config.host.clone(),
                    reason: error.to_string(),
                })?;

        let (mut stream, _) = ClientBuilder::from_uri(uri)
            .add_header(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent).map_err(|error| {
                    ConsumerError::InvalidUrl {
                        host: self.config.host.clone(),
                        reason: error.to_string(),
                    }
                })?,
            )
            .map_err(|error| ConsumerError::ConnectionFailed {
                host: self.config.host.clone(),
                reason: error.to_string(),
            })?
            .connect()
            .await
            .map_err(|error| ConsumerError::ConnectionFailed {
                host: self.config.host.clone(),
                reason: error.to_string(),
            })?;

        tracing::info!(host = %self.config.host, ?cursor, "firehose connected");

        // Coalesced skips: the highest sequence seen but not yet written.
        let mut pending: Option<i64> = None;
        let mut last_flush = tokio::time::Instant::now();

        loop {
            let message = tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        self.flush(&mut pending).await;
                        return Ok(());
                    }
                    continue;
                }
                item = stream.next() => item,
            };

            let Some(message) = message else {
                self.flush(&mut pending).await;
                return Err(ConsumerError::StreamEnded {
                    host: self.config.host.clone(),
                    reason: "the server closed the connection".to_string(),
                });
            };

            let message = message.map_err(|error| ConsumerError::StreamEnded {
                host: self.config.host.clone(),
                reason: error.to_string(),
            })?;

            if !message.is_binary() {
                // Text frames are proposal 0015's `xrpc.v1.json`, which this
                // consumer does not negotiate, and pings, which the transport
                // answers. Either way there is nothing here to decode.
                continue;
            }

            match self.handle_frame(message.as_payload()).await {
                FrameOutcome::Delivered(seq) => {
                    pending = Some(seq);
                    // A delivered message is durable by contract, so its
                    // cursor is written now rather than coalesced: the whole
                    // point of the ordering is that the cursor never leads the
                    // write, and coalescing here would let it lag one crash
                    // behind instead.
                    self.flush(&mut pending).await;
                    last_flush = tokio::time::Instant::now();
                }
                FrameOutcome::Skipped(seq) => {
                    if let Some(seq) = seq {
                        pending = Some(seq);
                    }
                    if last_flush.elapsed() >= self.config.cursor_flush_interval {
                        self.flush(&mut pending).await;
                        last_flush = tokio::time::Instant::now();
                    }
                }
                FrameOutcome::Held(seq) => {
                    // The sink did not apply it, so nothing after it is
                    // durable either. Drop whatever was coalesced rather than
                    // writing a cursor past a message that was refused.
                    tracing::warn!(?seq, "sink refused a message; holding the cursor");
                    pending = None;
                }
                FrameOutcome::CursorCleared => {
                    // Deliberately not flushed: the cursor was just cleared,
                    // and writing a coalesced one back would restore the value
                    // the server refused.
                    return Err(ConsumerError::StreamEnded {
                        host: self.config.host.clone(),
                        reason: "cursor was refused as outdated; reconnecting without one"
                            .to_string(),
                    });
                }
                FrameOutcome::Terminal(error) => {
                    self.flush(&mut pending).await;
                    return Err(error);
                }
            }
        }
    }

    /// Write the coalesced cursor, if there is one.
    async fn flush(&self, pending: &mut Option<i64>) {
        let Some(seq) = pending.take() else {
            return;
        };
        if let Err(reason) = self.cursors.store(&self.config.source, seq).await {
            tracing::error!(reason, seq, "cursor could not be written");
        }
    }

    /// Decode one frame, verify it if it is wanted, and deliver it.
    ///
    /// Public so a caller can drive it over recorded frames without a socket,
    /// which is the only way the tracked/untracked split gets tested.
    pub async fn handle_frame(&self, frame: &[u8]) -> FrameOutcome {
        let split = match split_frame(frame) {
            Ok(split) => split,
            Err(error) => {
                tracing::warn!(error = %error, "undecodable frame; skipping");
                return FrameOutcome::Skipped(None);
            }
        };

        let event = match split.event() {
            Ok(event) => event,
            Err(error) => {
                tracing::warn!(error = %error, "undecodable frame body; skipping");
                return FrameOutcome::Skipped(None);
            }
        };

        match event {
            Event::Commit(envelope) => {
                // The hot path. No CAR, no MST, no DID resolution, and no
                // allocation of the blocks byte string.
                if !matches_tracked(&envelope, &self.config.collections) {
                    return FrameOutcome::Skipped(Some(envelope.seq));
                }

                // Now the CAR is worth paying for.
                let blocks = match split.commit_blocks() {
                    Ok(blocks) => blocks,
                    Err(error) => {
                        tracing::warn!(error = %error, seq = envelope.seq, "commit carried no blocks");
                        return FrameOutcome::Skipped(Some(envelope.seq));
                    }
                };

                let tracked: Vec<&str> =
                    self.config.collections.iter().map(String::as_str).collect();
                if let Err(failure) = verify_commit(
                    self.config.verification,
                    &envelope,
                    &blocks,
                    &self.resolver,
                    &tracked,
                )
                .await
                {
                    tracing::warn!(error = %failure, seq = envelope.seq, "commit did not verify; skipping");
                    return FrameOutcome::Skipped(Some(envelope.seq));
                }

                let seq = envelope.seq;
                self.deliver(IngestMessage::Commit { envelope, blocks }, Some(seq))
                    .await
            }
            Event::Sync(payload) => {
                let seq = payload.seq;
                self.deliver(IngestMessage::Resync(payload), Some(seq))
                    .await
            }
            Event::Identity(payload) => {
                let seq = payload.seq;
                self.deliver(IngestMessage::Identity(payload), Some(seq))
                    .await
            }
            Event::Account(payload) => {
                let seq = payload.seq;
                self.deliver(IngestMessage::Account(payload), Some(seq))
                    .await
            }
            Event::Info(info) => {
                if !info.is_outdated_cursor() {
                    tracing::info!(name = %info.name, "firehose notice");
                    return FrameOutcome::Skipped(None);
                }

                let refused = self.cursors.load(&self.config.source).await.ok().flatten();
                if let Err(reason) = self.cursors.clear(&self.config.source).await {
                    tracing::error!(reason, "cursor could not be cleared");
                }
                let _ = self
                    .sink
                    .deliver(IngestMessage::CursorLost { refused, info })
                    .await;
                FrameOutcome::CursorCleared
            }
            Event::Error(payload) => FrameOutcome::Terminal(ConsumerError::ServerError {
                error: payload.error,
                message: payload.message.unwrap_or_default(),
            }),
            Event::Unknown { type_tag } => {
                tracing::debug!(type_tag, "unknown event type; skipping");
                FrameOutcome::Skipped(None)
            }
        }
    }

    /// Hand a message to the sink and turn its answer into an outcome.
    async fn deliver(&self, message: IngestMessage, seq: Option<i64>) -> FrameOutcome {
        match self.sink.deliver(message).await {
            Ok(Ack) => match seq {
                Some(seq) => FrameOutcome::Delivered(seq),
                None => FrameOutcome::Skipped(None),
            },
            Err(reason) => {
                tracing::error!(reason, ?seq, "sink refused a message");
                FrameOutcome::Held(seq)
            }
        }
    }
}

/// Spread a reconnect delay over `[50%, 100%]` of itself.
fn jitter(delay: Duration) -> Duration {
    let millis = delay.as_millis().max(1) as u64;
    let half = millis / 2;
    Duration::from_millis(half + rand::random_range(0..=millis - half))
}
