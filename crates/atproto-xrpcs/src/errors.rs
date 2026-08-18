//! # Structured Error Types for XRPC Services
//!
//! Comprehensive error handling for AT Protocol XRPC service operations using structured error types
//! with the `thiserror` library. All errors follow the project convention of prefixed error codes
//! with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`AuthorizationError`** (authorization-1 to authorization-9): JWT validation, DID resolution, and authorization errors
//! - **`ServiceAuthError`** (service-auth-1 to service-auth-14): inter-service auth token minting and verification
//!
//! ## Error Format
//!
//! All errors use the standardized format: `error-atproto-xrpcs-{domain}-{number} {message}: {details}`

use thiserror::Error;

/// Error types that can occur during XRPC authorization operations.
///
/// These errors represent failures in JWT validation, DID document resolution,
/// and cryptographic verification during authorization processing.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// Occurs when JWT does not have the expected 3-part format (header.payload.signature)
    #[error("error-atproto-xrpcs-authorization-1 Invalid JWT format: expected 3 parts")]
    InvalidJWTFormat,

    /// Occurs when JWT claims cannot be base64 decoded
    #[error("error-atproto-xrpcs-authorization-2 Failed to decode JWT claims: {error}")]
    ClaimsDecodeError {
        /// The underlying base64 decode error
        error: base64::DecodeError,
    },

    /// Occurs when JWT claims cannot be parsed as JSON
    #[error("error-atproto-xrpcs-authorization-3 Failed to parse JWT claims: {error}")]
    ClaimsParseError {
        /// The underlying JSON parse error
        error: serde_json::Error,
    },

    /// Occurs when no issuer is found in JWT claims
    #[error("error-atproto-xrpcs-authorization-4 No issuer found in JWT claims")]
    NoIssuerInClaims,

    /// Occurs when no verification keys are found in DID document
    #[error("error-atproto-xrpcs-authorization-5 No verification keys found in DID document")]
    NoVerificationKeys,

    /// Occurs when JWT header cannot be base64 decoded
    #[error("error-atproto-xrpcs-authorization-6 Failed to decode JWT header: {error}")]
    HeaderDecodeError {
        /// The underlying base64 decode error
        error: base64::DecodeError,
    },

    /// Occurs when JWT header cannot be parsed as JSON
    #[error("error-atproto-xrpcs-authorization-7 Failed to parse JWT header: {error}")]
    HeaderParseError {
        /// The underlying JSON parse error
        error: serde_json::Error,
    },

    /// Occurs when JWT validation fails with all available keys
    #[error("error-atproto-xrpcs-authorization-8 JWT validation failed with all available keys")]
    ValidationFailedAllKeys,

    /// Occurs when subject resolution fails during DID document lookup
    #[error("error-atproto-xrpcs-authorization-9 Subject resolution failed: {issuer} {error}")]
    SubjectResolutionFailed {
        /// The issuer that failed to resolve
        issuer: String,
        /// The underlying resolution error
        error: anyhow::Error,
    },
}

/// Why a service-auth token was refused.
///
/// One variant per cause rather than one denial with a string, because these
/// mean different things to whoever reads the log. A bad signature is a peer
/// lying about itself; an unresolvable issuer is somebody else's host being
/// down; a token scoped to no method is a client bug that would have been a
/// wildcard credential.
#[derive(Debug, Error)]
pub enum ServiceAuthError {
    /// The token is not a service-auth JWT.
    #[error("error-atproto-xrpcs-service-auth-1 Service-auth token is malformed: {reason}")]
    Malformed {
        /// What was wrong with its shape.
        reason: String,
    },

    /// The token names a different audience.
    #[error(
        "error-atproto-xrpcs-service-auth-2 Service-auth audience mismatch: token={token}, expected={expected}"
    )]
    Audience {
        /// The `aud` the token carried.
        token: String,
        /// The audience the verifier required.
        expected: String,
    },

    /// The token is scoped to a different method.
    #[error(
        "error-atproto-xrpcs-service-auth-3 Service-auth method mismatch: token={token}, expected={expected}"
    )]
    Method {
        /// The `lxm` the token carried.
        token: String,
        /// The method the verifier required.
        expected: String,
    },

    /// The token is scoped to no method at all.
    ///
    /// Separate from [`ServiceAuthError::Method`] because it is a different
    /// mistake with a much worse consequence: a token scoped to nothing
    /// satisfies every method that gates on one.
    #[error(
        "error-atproto-xrpcs-service-auth-4 Service-auth token is scoped to no method; expected {expected}"
    )]
    Unscoped {
        /// The method the verifier required.
        expected: String,
    },

    /// The `kid` names a verification method that is not this issuer's
    /// `#atproto`.
    #[error("error-atproto-xrpcs-service-auth-5 Service-auth kid {kid} is not {iss}#atproto")]
    KeyIdentifier {
        /// The `kid` the token carried.
        kid: String,
        /// The issuer it claimed to be from.
        iss: String,
    },

    /// The token has expired.
    #[error("error-atproto-xrpcs-service-auth-6 Service-auth token expired at {exp}, now {now}")]
    Expired {
        /// The `exp` the token carried.
        exp: u64,
        /// The verifier's clock.
        now: u64,
    },

    /// The token says it was issued in the future.
    #[error("error-atproto-xrpcs-service-auth-7 Service-auth token was issued at {iat}, now {now}")]
    IssuedInTheFuture {
        /// The `iat` the token carried.
        iat: u64,
        /// The verifier's clock.
        now: u64,
    },

    /// The token is valid for longer than the verifier's ceiling.
    #[error(
        "error-atproto-xrpcs-service-auth-8 Service-auth lifetime {lifetime}s exceeds the {ceiling}s ceiling"
    )]
    LifetimeTooLong {
        /// `exp - iat`.
        lifetime: u64,
        /// The ceiling the policy set.
        ceiling: u64,
    },

    /// The token has been revoked.
    #[error("error-atproto-xrpcs-service-auth-9 Service-auth token {jti} has been revoked")]
    Revoked {
        /// The revoked `jti`.
        jti: String,
    },

    /// The revocation list could not be read.
    ///
    /// Refuses the token: "I could not check" is not "no".
    #[error(
        "error-atproto-xrpcs-service-auth-10 Service-auth revocation list is unavailable: {reason}"
    )]
    RevocationUnavailable {
        /// Why it could not be read.
        reason: String,
    },

    /// The issuer's DID document could not be resolved.
    ///
    /// Not a verdict on the token. The usual cause is the issuer's host being
    /// unreachable, and reporting it as a bad signature would blame the peer
    /// for somebody else's outage.
    #[error(
        "error-atproto-xrpcs-service-auth-11 Service-auth issuer {iss} could not be resolved: {reason}"
    )]
    IssuerUnresolved {
        /// The issuer DID.
        iss: String,
        /// Why resolution failed.
        reason: String,
    },

    /// The issuer's DID document has no `#atproto` signing key.
    #[error(
        "error-atproto-xrpcs-service-auth-12 Service-auth issuer {iss} publishes no #atproto Multikey"
    )]
    NoSigningKey {
        /// The issuer DID.
        iss: String,
    },

    /// The signature does not check out against the issuer's published key.
    #[error("error-atproto-xrpcs-service-auth-13 Service-auth signature is invalid: {iss}")]
    Signature {
        /// The issuer DID.
        iss: String,
    },

    /// A token could not be minted.
    #[error("error-atproto-xrpcs-service-auth-14 Service-auth token could not be minted: {reason}")]
    Minting {
        /// Why.
        reason: String,
    },
}
