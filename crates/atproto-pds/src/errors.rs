//! Error types for `atproto-pds`.
//!
//! All errors follow the workspace convention `error-atproto-pds-<domain>-<n>`.
//! Domains: `account`, `repo`, `sync`, `space`, `oauth`, `admin`, `auth`,
//! `config`, `storage`, `notify`.

use thiserror::Error;

/// Top-level error for `atproto-pds` operations.
#[derive(Debug, Error)]
pub enum PdsError {
    /// error-atproto-pds-config-1: configuration validation failed; one or
    /// more required environment variables were missing or invalid. Per,
    /// startup collects every issue and reports them all at once rather than
    /// failing on the first.
    #[error("error-atproto-pds-config-1 configuration error(s):\n{}", issues.join("\n"))]
    Config {
        /// All collected validation failures, one per line.
        issues: Vec<String>,
    },

    /// error-atproto-pds-config-2: storage profile mismatch — the runtime
    /// `PDS_STORAGE_PROFILE` does not match the profile compiled in via
    /// Cargo features.
    #[error(
        "error-atproto-pds-config-2 storage profile mismatch: configured {configured}, compiled {compiled}"
    )]
    StorageProfileMismatch {
        /// Profile requested by `PDS_STORAGE_PROFILE`.
        configured: String,
        /// Profile compiled into this binary.
        compiled: String,
    },

    /// error-atproto-pds-config-3: ambiguous or missing PLC rotation key.
    #[error("error-atproto-pds-config-3 PLC rotation key configuration: {reason}")]
    PlcRotationKey {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-pds-storage-1: storage backend error.
    #[error("error-atproto-pds-storage-1 storage error: {reason}")]
    Storage {
        /// Description of the failure.
        reason: String,
    },

    /// error-atproto-pds-storage-2: account or per-actor data was not found.
    #[error("error-atproto-pds-storage-2 not found: {what}")]
    NotFound {
        /// What was not found.
        what: String,
    },

    /// error-atproto-pds-space-2: the referenced space does not exist or has
    /// been tombstoned (`deleted_at IS NOT NULL`). Surfaced to clients as the
    /// `SpaceNotFound` XRPC error.
    #[error("error-atproto-pds-space-2 space not found: {uri}")]
    SpaceNotFound {
        /// URI of the missing or deleted space.
        uri: String,
    },

    /// error-atproto-pds-space-3: the caller is not the owner of the space.
    /// Surfaced to clients as the `NotSpaceOwner` XRPC error.
    #[error("error-atproto-pds-space-3 not the space owner: {uri}")]
    NotSpaceOwner {
        /// URI of the space.
        uri: String,
    },

    /// error-atproto-pds-account-1: account state transition rejected.
    #[error("error-atproto-pds-account-1 invalid account state transition: {from} -> {to}")]
    InvalidAccountTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
    },

    /// error-atproto-pds-repo-2: a compare-and-swap guard did not match.
    ///
    /// `swapCommit` exists so a client that read the repo, decided something,
    /// and is now writing can be told its decision was made against a state
    /// that has since moved — rather than silently clobbering whoever wrote in
    /// between.
    #[error(
        "error-atproto-pds-repo-2 swapCommit mismatch: expected {expected}, repo is at {actual}"
    )]
    InvalidSwap {
        /// The commit CID the caller expected the repo to be at.
        expected: String,
        /// The commit CID the repo is actually at, or `none` for an empty repo.
        actual: String,
    },

    /// error-atproto-pds-identity-1: the handle is not usable.
    ///
    /// Covers both syntax and the policy rules that apply to handles issued
    /// under a domain this server operates. The lexicons name this
    /// `InvalidHandle`.
    #[error("error-atproto-pds-identity-1 invalid handle {handle}: {reason}")]
    InvalidHandle {
        /// The handle as supplied, or its normalized form once known.
        handle: String,
        /// Why it was refused.
        reason: String,
    },

    /// error-atproto-pds-identity-2: the handle is already taken or reserved.
    ///
    /// Separate from [`PdsError::InvalidHandle`] because the caller's remedy
    /// differs — a different handle rather than a corrected one — and because
    /// the lexicons name it `HandleNotAvailable`.
    #[error("error-atproto-pds-identity-2 handle not available: {handle}")]
    HandleNotAvailable {
        /// The handle that could not be issued.
        handle: String,
    },

    /// error-atproto-pds-identity-3: a handle outside this server's domains
    /// did not resolve back to the account claiming it.
    ///
    /// Claiming `example.com` is a statement about a domain the caller says
    /// they control. Syntax cannot establish that; only resolution can.
    #[error(
        "error-atproto-pds-identity-3 handle {handle} does not resolve to {did}: resolved to {resolved}"
    )]
    HandleOwnershipUnproven {
        /// The handle being claimed.
        handle: String,
        /// The DID claiming it.
        did: String,
        /// What the handle actually resolved to, or `nothing`.
        resolved: String,
    },

    /// error-atproto-pds-identity-4: a PLC operation would leave the account
    /// unreachable through this server.
    ///
    /// `submitPlcOperation` exists to catch exactly this before the operation
    /// becomes part of an append-only log that this server cannot rewrite.
    #[error("error-atproto-pds-identity-4 refusing to submit PLC operation: {reason}")]
    InvalidPlcOperation {
        /// Which constraint the operation violated.
        reason: String,
    },

    /// error-atproto-pds-admin-1: a moderation subject could not be addressed.
    ///
    /// `updateSubjectStatus` takes an open union, so an unrecognized `$type`
    /// or an unparseable AT-URI is a client error rather than a server one —
    /// and naming which is which is the difference between a moderator
    /// retrying correctly and retrying identically.
    #[error("error-atproto-pds-admin-1 invalid moderation subject: {reason}")]
    InvalidSubject {
        /// What was wrong with the subject.
        reason: String,
    },

    /// error-atproto-pds-auth-2: the repository is not available to callers.
    ///
    /// Distinct from [`PdsError::AuthDenied`] because the sync and blob
    /// lexicons declare a named error per state — `RepoTakendown`,
    /// `RepoSuspended`, `RepoDeactivated` — and a caller is expected to act on
    /// which one it got. Collapsing them to `Forbidden` is what made all three
    /// unreachable on the five endpoints that declare them.
    #[error("error-atproto-pds-auth-2 repository {did} is {state}")]
    RepoUnavailable {
        /// DID of the repository.
        did: String,
        /// The account state that disallows the operation.
        state: String,
    },

    /// error-atproto-pds-auth-1: authorization rejected.
    #[error("error-atproto-pds-auth-1 authorization denied: {reason}")]
    AuthDenied {
        /// Description of the rejection.
        reason: String,
    },

    /// error-atproto-pds-notify-1: notifier delivery failed (after retries exhausted).
    #[error("error-atproto-pds-notify-1 notifier delivery failed after retries: {reason}")]
    NotifierDelivery {
        /// Description of the final failure.
        reason: String,
    },

    /// error-atproto-pds-space-1: forwarded from `atproto-space`.
    #[error(transparent)]
    Space(#[from] atproto_space::SpaceError),

    /// error-atproto-pds-repo-1: forwarded from `atproto-repo`.
    #[error(transparent)]
    Repo(#[from] atproto_repo::errors::RepoError),

    /// error-atproto-pds-storage-3: forwarded from `atproto-dasl`.
    #[error(transparent)]
    Dasl(#[from] atproto_dasl::CarError),

    /// error-atproto-pds-storage-4: forwarded I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `PdsError`.
pub type PdsResult<T> = std::result::Result<T, PdsError>;
