//! Axum web framework integration for AT Protocol OAuth.
//!
//! Production-ready OAuth handlers for authorization flows, callbacks,
//! JWKS endpoints, and metadata with secure state management.
//! - **`handle_complete`**: OAuth callback and completion handler
//! - **`handle_jwks`**: JWKS (JSON Web Key Set) endpoint handler
//! - **`handler_metadata`**: OAuth authorization server metadata handler
//! - **`state`**: Shared application state management for OAuth operations
//! - **`errors`**: Specialized error types for web handler operations
//!
//! ## Command-Line Tools
//!
//! When built with the `clap` feature, provides OAuth management tools:
//!
//! - **`atproto-oauth-tool`**: Command-line OAuth login, token management, and workflow testing

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod handle_complete;
pub mod handle_jwks;
pub mod handler_metadata;
pub mod state;
