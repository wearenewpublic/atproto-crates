//! Error types for `atproto-space`.
//!
//! All errors follow the workspace convention `error-atproto-space-<domain>-<n>`.
//! Domains: `commit`, `credential`, `members`, `repo`, `set_hash`, `storage`, `types`.

use thiserror::Error;

/// Errors returned by `atproto-space` operations.
#[derive(Debug, Error)]
pub enum SpaceError {
    /// A commit carries a format version this build does not implement.
    ///
    /// Distinct from a MAC failure: the bytes may be perfectly valid, signed
    /// over a `ctx` construction this build cannot rebuild.
    #[error("error-atproto-space-commit-2 unsupported commit version: {ver}, expected 1")]
    UnsupportedCommitVersion {
        /// The version the commit declared.
        ver: u32,
    },

    /// error-atproto-space-types-1: invalid space URI.
    #[error("error-atproto-space-types-1 invalid space URI: {uri}")]
    InvalidSpaceUri {
        /// The URI string that failed parsing.
        uri: String,
    },

    /// error-atproto-space-types-2: invalid space type (must be a valid NSID).
    #[error("error-atproto-space-types-2 invalid space type: {value}")]
    InvalidSpaceType {
        /// The value that was not a valid NSID.
        value: String,
    },

    /// error-atproto-space-types-3: invalid space key (must satisfy `rkey` syntax:
    /// 1-512 bytes, charset `[A-Za-z0-9._:~-]`, not `.` or `..`).
    #[error("error-atproto-space-types-3 invalid space key: {value}")]
    InvalidSpaceKey {
        /// The value that was not a valid space key.
        value: String,
    },

    /// error-atproto-space-set_hash-1: digest serialization or deserialization failed.
    #[error("error-atproto-space-set_hash-1 set hash codec error: {reason}")]
    SetHashCodec {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-commit-1: HKDF key derivation failed.
    #[error("error-atproto-space-commit-1 HKDF derivation failed: {reason}")]
    Hkdf {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-commit-2: signature operation failed.
    #[error("error-atproto-space-commit-2 signature operation failed: {reason}")]
    Signature {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-commit-3: HMAC tag verification failed (commit was tampered).
    #[error("error-atproto-space-commit-3 commit HMAC tag mismatch")]
    CommitTagMismatch,

    /// error-atproto-space-commit-4: ECDSA signature verification failed.
    #[error("error-atproto-space-commit-4 commit ECDSA signature verification failed")]
    CommitSignatureInvalid,

    /// error-atproto-space-commit-5: CBOR encoding of `SpaceContext` failed.
    #[error("error-atproto-space-commit-5 SpaceContext CBOR encoding failed: {reason}")]
    ContextEncoding {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-credential-1: JWT encoding failed.
    #[error("error-atproto-space-credential-1 JWT encoding failed: {reason}")]
    JwtEncoding {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-credential-2: JWT decoding/parsing failed.
    #[error("error-atproto-space-credential-2 JWT decoding failed: {reason}")]
    JwtDecoding {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-credential-3: JWT signature verification failed.
    #[error("error-atproto-space-credential-3 JWT signature invalid")]
    JwtSignatureInvalid,

    /// error-atproto-space-credential-4: JWT has expired.
    #[error("error-atproto-space-credential-4 JWT expired (exp={exp}, now={now})")]
    JwtExpired {
        /// `exp` claim value (seconds since epoch).
        exp: u64,
        /// Current time (seconds since epoch).
        now: u64,
    },

    /// error-atproto-space-credential-5: JWT issuer/audience/space/lxm mismatch.
    #[error(
        "error-atproto-space-credential-5 JWT claim mismatch: {field} expected={expected}, got={actual}"
    )]
    JwtClaimMismatch {
        /// Which claim mismatched.
        field: String,
        /// Expected value.
        expected: String,
        /// Actual value.
        actual: String,
    },

    /// error-atproto-space-credential-7: JWT was issued too far in the future.
    #[error("error-atproto-space-credential-7 JWT issued in the future (iat={iat}, now={now})")]
    JwtIssuedInFuture {
        /// `iat` claim value (seconds since epoch).
        iat: u64,
        /// Current time (seconds since epoch).
        now: u64,
    },

    /// error-atproto-space-credential-6: JWT missing required claim.
    #[error("error-atproto-space-credential-6 JWT missing claim: {field}")]
    JwtMissingClaim {
        /// Missing claim name.
        field: String,
    },

    /// error-atproto-space-repo-1: attempt to add a record that already exists.
    #[error("error-atproto-space-repo-1 record already exists: {collection}/{rkey}")]
    RecordAlreadyExists {
        /// NSID collection.
        collection: String,
        /// Record key.
        rkey: String,
    },

    /// error-atproto-space-repo-2: attempt to update or delete a non-existent record.
    #[error("error-atproto-space-repo-2 record not found: {collection}/{rkey}")]
    RecordNotFound {
        /// NSID collection.
        collection: String,
        /// Record key.
        rkey: String,
    },

    /// error-atproto-space-members-1: attempt to add a duplicate member.
    #[error("error-atproto-space-members-1 member already exists: {did}")]
    MemberAlreadyExists {
        /// DID of the member.
        did: String,
    },

    /// error-atproto-space-members-2: attempt to remove a non-member.
    #[error("error-atproto-space-members-2 not a member: {did}")]
    NotAMember {
        /// DID that is not in the member list.
        did: String,
    },

    /// error-atproto-space-storage-1: storage backend error.
    #[error("error-atproto-space-storage-1 storage error: {reason}")]
    Storage {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-space-storage-2: oplog gap — `since` cursor predates retained range.
    #[error("error-atproto-space-storage-2 oplog gap: since={since:?} earliest={earliest:?}")]
    OplogGap {
        /// `since` rev requested by the caller.
        since: Option<String>,
        /// Earliest rev still retained.
        earliest: Option<String>,
    },

    /// error-atproto-space-storage-3: malformed oplog cursor token.
    #[error("error-atproto-space-storage-3 invalid oplog cursor: {token}")]
    InvalidCursor {
        /// The cursor token that failed to parse.
        token: String,
    },
}

/// Convenience alias for results from this crate.
pub type SpaceResult<T> = std::result::Result<T, SpaceError>;
