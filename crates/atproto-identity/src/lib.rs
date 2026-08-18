//! AT Protocol identity management for DID resolution, handle resolution, and cryptographic operations.
//!
//! This crate provides core identity functionality for AT Protocol applications including multi-method
//! DID resolution (plc, web, key), DNS/HTTP handle resolution, and P-256/P-384/K-256 key operations.
//!
//! When built with the `clap` feature, provides comprehensive CLI tools:
//!
//! - **`atproto-identity-resolve`**: Resolve AT Protocol handles and DIDs to canonical identifiers
//! - **`atproto-identity-key`**: Generate and manage cryptographic keys (P-256, P-384, K-256)
//! - **`atproto-identity-sign`**: Create cryptographic signatures of JSON data
//! - **`atproto-identity-validate`**: Validate cryptographic signatures
//!
//! ## Features
//!
//! `resolve` (default) turns on identity resolution over the network. Without
//! it the crate is pure -- keys, the DID document model, validation, AT-URI
//! input parsing, JWKs and URL construction -- and pulls in no HTTP client,
//! async runtime, or DNS resolver. Build with `default-features = false` to
//! depend on the types without the network stack.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod errors;
pub mod host;
pub mod jwk;
pub mod key;
pub mod model;
/// The PLC directory client. Requires the `resolve` feature.
#[cfg(feature = "resolve")]
pub mod plc;
pub mod resolve;
#[cfg(feature = "lru")]
pub mod storage_lru;
pub mod traits;
pub mod url;
pub mod validation;
/// The did:web client. Requires the `resolve` feature.
#[cfg(feature = "resolve")]
pub mod web;
/// The did:webvh client. Requires the `resolve` feature.
#[cfg(feature = "resolve")]
pub mod webvh;
