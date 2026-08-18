//! The `com.atproto.sync.subscribeRepos` wire format.
//!
//! A frame is a single binary WebSocket message holding **two consecutive
//! DAG-CBOR objects with no length prefix between them**: a header naming what
//! the frame is, and a body carrying the event. Splitting them is done by
//! decoding the header and asking the reader where it stopped, because there
//! is nothing else in the frame that says.
//!
//! # Two-stage decoding, and why it is the whole performance story
//!
//! The network firehose is overwhelmingly `app.bsky.feed.post` and
//! `app.bsky.feed.like`. What a consumer costs is decided almost entirely by
//! what happens to the frames it is *not* interested in, and the saving grace
//! of the format is that `ops[].path` lives in the outer payload next to
//! `blocks` rather than inside it.
//!
//! So [`CommitEnvelope`] omits `blocks` and [`CommitBlocks`] carries only
//! `blocks`. A consumer decodes the envelope, decides from `ops[].path`
//! whether it cares, and only then decodes the CAR. The DAG-CBOR decoder skips
//! a byte string by its length prefix rather than copying it, so an
//! uninteresting commit costs no allocation for a payload that can reach two
//! megabytes. Adding `blocks` to [`CommitEnvelope`] would quietly reintroduce
//! that copy for every post on the network.
//!
//! # The union has five members, and three names are gone
//!
//! `#commit`, `#sync`, `#identity`, `#account` and `#info`. `#handle`,
//! `#migrate` and `#tombstone` were **removed from the union**, not deprecated
//! in place; a consumer still branching on them is reading a lexicon several
//! years stale, and this one reports them as [`Event::Unknown`].
//!
//! Three required `#commit` fields are tombstones the schema cannot drop
//! without breaking encoders: `rebase` ("DEPRECATED -- unused"), `blobs`
//! ("DEPRECATED -- will soon always be empty"), and `tooBig` ("DEPRECATED --
//! replaced by #sync event and data limits"). None is modelled here. Because
//! `tooBig` commits no longer happen, the correct handling of an oversized
//! repository change is to wait for `#sync` and re-backfill, not to branch on
//! the flag.
//!
//! # Framing versions
//!
//! This decodes the `xrpc.v0.cbor` framing, which is the default and what
//! every server speaks. Proposal 0015 adds `xrpc.v1.json` and `xrpc.v1.cbor`
//! -- one self-describing object per frame, with no separate header -- and
//! they are reached by negotiating a WebSocket subprotocol. Nothing here
//! negotiates one, so nothing here receives one.

use std::io::Cursor as IoCursor;

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

use crate::errors::FrameError;

/// The lexicon these frames belong to.
pub const SUBSCRIBE_REPOS_NSID: &str = "com.atproto.sync.subscribeRepos";

/// The first of a frame's two DAG-CBOR objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// `1` for a message, `-1` for an error.
    pub op: i8,
    /// The event type with its leading `#`, e.g. `#commit`.
    ///
    /// Absent on an error frame, which is the one frame shape that carries no
    /// type tag -- the body's `error` field is what a client switches on.
    /// Optional rather than always-present so the same type can encode both,
    /// which is what keeps an encoder and a decoder from drifting apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

impl FrameHeader {
    /// A message frame of the given type.
    #[must_use]
    pub fn message(type_tag: &str) -> Self {
        Self {
            op: 1,
            t: Some(type_tag_of(type_tag)),
        }
    }

    /// An error frame, which carries no type tag.
    #[must_use]
    pub fn error() -> Self {
        Self { op: -1, t: None }
    }

    /// Whether this is the terminal error frame.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.op == -1
    }
}

/// Hash-prefix a bare event type (`commit` -> `#commit`), idempotently.
#[must_use]
pub fn type_tag_of(event_type: &str) -> String {
    if event_type.starts_with('#') {
        event_type.to_string()
    } else {
        format!("#{event_type}")
    }
}

/// A `#commit` payload with everything **except** `blocks`.
///
/// Omitting `blocks` is the entire performance story of this module. See the
/// module docs before adding the field.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CommitEnvelope {
    /// The stream sequence number. Ordering, and the cursor to resume from.
    pub seq: i64,
    /// Repository DID.
    ///
    /// The one message type that says `repo` rather than `did`; the other four
    /// all say `did`, and a decoder that assumes otherwise fails on the member
    /// that matters most.
    pub repo: String,
    /// Revision (TID) of the new commit.
    pub rev: String,
    /// Revision of the previous commit from this repository.
    #[serde(default)]
    pub since: Option<String>,
    /// When the server broadcast the event.
    #[serde(default)]
    pub time: Option<String>,
    /// CID of the new commit object.
    pub commit: Cid,
    /// MST root of the previous commit.
    ///
    /// Optional in the schema, but without it inductive verification of
    /// anything but a repository's first commit is impossible: there is
    /// nothing to walk the new tree against.
    #[serde(rename = "prevData", default)]
    pub prev_data: Option<Cid>,
    /// The record operations this commit performed.
    pub ops: Vec<atproto_repo::RepoOp>,
}

/// A `#commit` payload with **only** `blocks`.
///
/// Decoded on the second pass, from the same bytes, once the envelope has said
/// the commit is worth the CAR.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CommitBlocks {
    /// The CARv1 slice carrying this commit's blocks.
    ///
    /// `serde_bytes` because DAG-CBOR carries this as a byte string; without
    /// it serde would deserialize that byte string element-by-element into a
    /// `Vec<u8>` as if it were an array.
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
}

/// A `#sync` payload: repository state asserted out of band.
///
/// Sent when a consumer cannot get to the current state by applying commits --
/// after an account migration, a backfill, or an oversized change. The
/// response is to re-read the repository, not to apply anything.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SyncPayload {
    /// The stream sequence number.
    pub seq: i64,
    /// Repository DID.
    pub did: String,
    /// Revision (TID) of the commit being asserted.
    pub rev: String,
    /// When the server broadcast the event.
    #[serde(default)]
    pub time: Option<String>,
    // `blocks` is omitted here for the same reason it is omitted from
    // `CommitEnvelope`: it is a byte string, and a consumer that only wants to
    // know a repository moved should not pay to copy it. Read it with
    // [`Frame::sync_blocks`] when the head commit is wanted.
}

/// An `#identity` payload: a handle, signing key, or PDS endpoint changed.
///
/// Carries at most the new handle. Everything else has to be re-resolved:
/// the event says the DID document moved, not what it moved to.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IdentityPayload {
    /// The stream sequence number.
    pub seq: i64,
    /// The DID whose identity changed.
    pub did: String,
    /// The new handle, when the server knows one.
    #[serde(default)]
    pub handle: Option<String>,
    /// When the server broadcast the event.
    #[serde(default)]
    pub time: Option<String>,
}

/// An `#account` payload: hosting status changed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AccountPayload {
    /// The stream sequence number.
    pub seq: i64,
    /// The DID whose account state changed.
    pub did: String,
    /// Whether the repository is being served at all.
    pub active: bool,
    /// Why it is not, when it is not: `takendown`, `suspended`, `deactivated`.
    #[serde(default)]
    pub status: Option<String>,
    /// When the server broadcast the event.
    #[serde(default)]
    pub time: Option<String>,
}

/// An `#info` payload: a stream notice.
///
/// A message, not an error -- the stream continues after it. The one that
/// matters is `OutdatedCursor`, which says the cursor the consumer connected
/// with is older than anything the server still holds.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct InfoPayload {
    /// The notice name; `OutdatedCursor` is the one worth branching on.
    pub name: String,
    /// Human-readable detail.
    #[serde(default)]
    pub message: Option<String>,
}

impl InfoPayload {
    /// The notice that the connecting cursor was older than the server's
    /// retention.
    pub const OUTDATED_CURSOR: &'static str = "OutdatedCursor";

    /// Whether this notice says the cursor was refused as too old.
    #[must_use]
    pub fn is_outdated_cursor(&self) -> bool {
        self.name == Self::OUTDATED_CURSOR
    }
}

/// The body of an error frame. Terminal: the subscription ends after it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ErrorPayload {
    /// The error name, which is what a client switches on.
    pub error: String,
    /// Human-readable detail.
    #[serde(default)]
    pub message: Option<String>,
}

/// One decoded frame.
///
/// `Commit` is much larger than the other variants, and boxing it -- which is
/// what the lint asks for -- would put an allocation on the hot path to save
/// stack on the frames that are not commits. On the network firehose almost
/// every frame is a commit, so the padding this "wastes" is padding that is
/// almost always in use.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Repository mutations. The only member carrying records.
    Commit(CommitEnvelope),
    /// State asserted out of band, without the commits that got there.
    Sync(SyncPayload),
    /// A handle, signing key, or PDS endpoint changed.
    Identity(IdentityPayload),
    /// Hosting status changed.
    Account(AccountPayload),
    /// A stream notice. The stream continues.
    Info(InfoPayload),
    /// A terminal error. The stream does not continue.
    Error(ErrorPayload),
    /// A type tag this build does not know.
    ///
    /// The union is closed, so this is either a server ahead of this build or
    /// one still emitting `#handle`, `#migrate` or `#tombstone`. Skipping is
    /// the only safe response to both; failing would wedge the stream behind a
    /// frame no version of this code will ever understand.
    Unknown {
        /// The tag the header carried.
        type_tag: String,
    },
}

/// A frame split into its header and the bytes of its body.
///
/// The body is borrowed, and decoding it is deliberately a separate step: a
/// consumer that does not care about a commit should never pay for its CAR.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
    /// What the frame says it is.
    pub header: FrameHeader,
    /// The undecoded second DAG-CBOR object.
    pub body: &'a [u8],
}

/// Split a frame into its header and the bytes of its body.
///
/// A frame is two concatenated DAG-CBOR objects with no length prefix between
/// them, so the split is found by decoding the header and asking the reader
/// where it stopped.
///
/// The header is decoded **non-strict**. A relay emitting a technically
/// non-canonical header is not a reason to drop the frame: nothing in the
/// header is content-addressed, so a relaxed decoding of it commits to
/// nothing. Record blocks are the opposite and are decoded strictly -- a
/// block's CID is a commitment to exactly those bytes being canonical
/// DAG-CBOR, so a block that decodes only under relaxed rules has an ambiguous
/// relationship to its own CID.
///
/// # Errors
///
/// Returns [`FrameError::Header`] if the first object is not a frame header,
/// and [`FrameError::Truncated`] if decoding it consumed more bytes than the
/// frame holds.
pub fn split_frame(frame: &[u8]) -> Result<Frame<'_>, FrameError> {
    let mut reader = IoCursor::new(frame);
    let header: FrameHeader = atproto_dasl::from_reader_non_strict(&mut reader)
        .map_err(|error| FrameError::Header { error })?;

    let offset = reader.position() as usize;
    if offset > frame.len() {
        return Err(FrameError::Truncated {
            consumed: offset,
            len: frame.len(),
        });
    }

    Ok(Frame {
        header,
        body: &frame[offset..],
    })
}

impl Frame<'_> {
    /// Decode the body according to the header's type tag.
    ///
    /// This is pass one: a `#commit` yields a [`CommitEnvelope`] with no
    /// `blocks`, at the cost of decoding the ops array and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Body`] if the body does not match the shape its
    /// type tag names.
    pub fn event(&self) -> Result<Event, FrameError> {
        if self.header.is_error() {
            return Ok(Event::Error(self.decode()?));
        }

        let tag = self.header.t.as_deref().unwrap_or_default();
        Ok(match tag {
            "#commit" => Event::Commit(self.decode()?),
            "#sync" => Event::Sync(self.decode()?),
            "#identity" => Event::Identity(self.decode()?),
            "#account" => Event::Account(self.decode()?),
            "#info" => Event::Info(self.decode()?),
            other => Event::Unknown {
                type_tag: other.to_string(),
            },
        })
    }

    /// Decode the `blocks` byte string from a `#sync` body.
    ///
    /// A `#sync` carries a CAR rooted at the head commit, so a consumer that
    /// wants to verify the asserted state rather than re-fetch it can. Like
    /// [`Frame::commit_blocks`] this is a second pass, and for the same
    /// reason.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Body`] if the body carries no `blocks`.
    pub fn sync_blocks(&self) -> Result<Vec<u8>, FrameError> {
        self.commit_blocks()
    }

    /// Decode the `blocks` byte string from a `#commit` body.
    ///
    /// This is pass two, and the only thing that should call it is a consumer
    /// that has already decided from [`Frame::event`] that it wants the CAR.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Body`] if the body carries no `blocks`.
    pub fn commit_blocks(&self) -> Result<Vec<u8>, FrameError> {
        let blocks: CommitBlocks = self.decode()?;
        Ok(blocks.blocks)
    }

    /// Decode the body as `T`, non-strict for the same reason the header is.
    fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T, FrameError> {
        atproto_dasl::from_slice_non_strict(self.body).map_err(|error| FrameError::Body {
            type_tag: self
                .header
                .t
                .clone()
                .unwrap_or_else(|| "#error".to_string()),
            error,
        })
    }
}

/// Whether any of a commit's ops names a collection the caller tracks.
///
/// An empty list means every commit, which is what a relay wants and what an
/// app view almost never does. The collection is the path segment before the
/// first `/`.
///
/// This is the hot path. It reads only `ops[].path`, which is why
/// [`CommitEnvelope`] is worth having as a separate shape: deciding this
/// costs no CAR parse, no MST walk, no DID resolution, and no allocation of
/// the blocks byte string.
#[must_use]
pub fn matches_tracked(envelope: &CommitEnvelope, collections: &[String]) -> bool {
    if collections.is_empty() {
        return true;
    }
    envelope.ops.iter().any(|op| {
        let collection = op.path.split('/').next().unwrap_or_default();
        collections.iter().any(|tracked| tracked == collection)
    })
}
