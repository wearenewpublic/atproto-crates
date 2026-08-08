//! XRPC service framework for AT Protocol applications.
//!
//! Build AT Protocol services with JWT authorization, DID resolution,
//! and cryptographic identity verification middleware.
//! - **`errors`**: Specialized error types for authorization and XRPC operations
//!
//! ## Example Applications
//!
//! Complete example services demonstrating framework usage:
//!

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// JWT authorization extractors for XRPC services.
pub mod authorization;
/// Structured error types for XRPC operations.
pub mod errors;
