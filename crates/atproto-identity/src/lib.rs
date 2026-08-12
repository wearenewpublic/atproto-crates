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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod errors;
pub mod host;
pub mod jwk;
pub mod key;
pub mod model;
pub mod plc;
pub mod resolve;
#[cfg(feature = "lru")]
pub mod storage_lru;
pub mod traits;
pub mod url;
pub mod validation;
pub mod web;
pub mod webvh;
