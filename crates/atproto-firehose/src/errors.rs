//! Structured error types for firehose consumption.
//!
//! ## Error categories
//!
//! - **`FrameError`** (frame-1 to frame-3): decoding a wire frame
//! - **`VerifyFailure`** (verify-1 to verify-7): a commit that did not check out
//! - **`ConsumerError`** (consumer-1 to consumer-4): the connection and its loop

use thiserror::Error;

/// Errors decoding a `subscribeRepos` frame.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The first DAG-CBOR object was not a frame header.
    #[error("error-atproto-firehose-frame-1 Frame header could not be decoded: {error}")]
    Header {
        /// The underlying decoding error.
        error: atproto_dasl::DecodeError,
    },

    /// Decoding the header consumed more bytes than the frame holds.
    #[error(
        "error-atproto-firehose-frame-2 Frame header consumed more bytes than the frame holds: {consumed} of {len}"
    )]
    Truncated {
        /// Bytes the header decoder claimed.
        consumed: usize,
        /// Bytes the frame actually holds.
        len: usize,
    },

    /// The body did not match the shape its type tag names.
    #[error(
        "error-atproto-firehose-frame-3 Frame body for {type_tag} could not be decoded: {error}"
    )]
    Body {
        /// The type tag the header carried.
        type_tag: String,
        /// The underlying decoding error.
        error: atproto_dasl::DecodeError,
    },
}

/// Why a commit did not verify.
///
/// One variant per cause rather than one `InvalidCommit` with a string,
/// because these mean different things to an operator: a signature that does
/// not check out is a repository lying about itself, a tree that does not walk
/// is a relay serving a bad slice, and an unresolvable DID is somebody else's
/// host being down.
#[derive(Debug, Error)]
pub enum VerifyFailure {
    /// The CAR slice could not be read.
    #[error("error-atproto-firehose-verify-1 Commit slice could not be read: {repo} {error}")]
    Car {
        /// Repository DID.
        repo: String,
        /// The underlying CAR error.
        error: atproto_dasl::CarError,
    },

    /// The commit block named by the event was not in the slice.
    #[error("error-atproto-firehose-verify-2 Commit block {commit} absent from the slice: {repo}")]
    CommitBlockMissing {
        /// Repository DID.
        repo: String,
        /// The commit CID the event named.
        commit: String,
    },

    /// The commit block was there but is not a commit.
    #[error("error-atproto-firehose-verify-3 Commit block could not be decoded: {repo} {reason}")]
    CommitMalformed {
        /// Repository DID.
        repo: String,
        /// What was wrong with it.
        reason: String,
    },

    /// The repository's signing key could not be resolved.
    ///
    /// Not a verdict on the commit. The usual cause is the DID's host being
    /// unreachable, and treating it as a bad signature would report somebody
    /// else's outage as this repository lying.
    #[error(
        "error-atproto-firehose-verify-4 Signing key for {repo} could not be resolved: {reason}"
    )]
    SigningKeyUnresolved {
        /// Repository DID.
        repo: String,
        /// Why the resolution failed.
        reason: String,
    },

    /// The signature does not check out against the repository's signing key.
    #[error("error-atproto-firehose-verify-5 Commit signature is invalid: {repo} {rev}")]
    Signature {
        /// Repository DID.
        repo: String,
        /// Revision of the commit that failed.
        rev: String,
    },

    /// The tree does not walk from the root the commit signed.
    #[error("error-atproto-firehose-verify-6 Commit tree did not verify: {repo} {reason}")]
    Tree {
        /// Repository DID.
        repo: String,
        /// What the walk found.
        reason: String,
    },

    /// An op does not describe the tree the commit signed.
    ///
    /// The commit is real and the tree is sound; the ops array is lying about
    /// what changed. See [`atproto_repo::verify_op_inclusion`].
    #[error(
        "error-atproto-firehose-verify-7 Op at {path} does not match the signed tree: {repo} {detail}"
    )]
    OpInclusion {
        /// Repository DID.
        repo: String,
        /// The op's repo path.
        path: String,
        /// What the tree said instead.
        detail: String,
    },
}

/// Errors from the consumer's connection and loop.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConsumerError {
    /// The subscription URL could not be built.
    #[error("error-atproto-firehose-consumer-1 Subscription URL is not valid: {host} {reason}")]
    InvalidUrl {
        /// The host as configured.
        host: String,
        /// Why it could not be turned into a URL.
        reason: String,
    },

    /// The WebSocket connection could not be established.
    #[error("error-atproto-firehose-consumer-2 Connection to {host} failed: {reason}")]
    ConnectionFailed {
        /// The host that refused.
        host: String,
        /// Why.
        reason: String,
    },

    /// The stream ended.
    #[error("error-atproto-firehose-consumer-3 Stream from {host} ended: {reason}")]
    StreamEnded {
        /// The host.
        host: String,
        /// Why.
        reason: String,
    },

    /// The server sent a terminal error frame.
    #[error("error-atproto-firehose-consumer-4 Server refused the subscription: {error} {message}")]
    ServerError {
        /// The error name the server sent.
        error: String,
        /// The message it sent with it.
        message: String,
    },
}
