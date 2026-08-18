//! OAuth 2.0 implementation for AT Protocol.
//!
//! Comprehensive OAuth support with DPoP, PKCE, JWT operations,
//! and secure storage abstractions for AT Protocol authentication.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// DPoP (Demonstrating Proof of Possession) implementation for OAuth 2.0.
pub mod dpop;
/// Base64 encoding and decoding utilities.
pub mod encoding;
/// Error types and handling.
pub mod errors;
/// JSON Web Key (JWK) generation and management.
pub mod jwk;
/// JSON Web Token (JWT) minting and verification.
pub mod jwt;
/// PKCE (Proof Key for Code Exchange) implementation for OAuth 2.0 security.
pub mod pkce;
pub mod refresh;
/// OAuth resource and authorization server management.
pub mod resources;
/// OAuth 2.0 scope definitions and parsing for AT Protocol.
pub mod scopes;
/// OAuth request storage abstraction for CRUD operations.
pub mod storage;
/// LRU-based implementation of OAuth request storage (requires `lru` feature).
#[cfg(feature = "lru")]
pub mod storage_lru;
/// OAuth workflow implementation for AT Protocol authorization flows.
pub mod workflow;
