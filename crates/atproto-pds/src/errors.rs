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

    /// error-atproto-pds-account-1: account state transition rejected.
    #[error("error-atproto-pds-account-1 invalid account state transition: {from} -> {to}")]
    InvalidAccountTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
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
