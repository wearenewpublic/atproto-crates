//! HTTP layer — axum router and shared state.
//!
//! Wires the full XRPC surface: read-only `com.atproto.repo.*` and
//! `com.atproto.sync.*` handlers, OAuth provider, write endpoints,
//! admin, and Spaces.

pub mod auth;
pub mod auth_handlers;
pub mod blob_handlers;
pub mod discovery_handlers;
pub mod errors;
pub mod extract;
pub mod handlers;
pub mod identity_handlers;
pub mod moderation_handlers;
pub mod preference_handlers;
pub mod proxy_handlers;
pub mod proxy_target;
pub mod router;
pub mod service_auth_handlers;
pub mod space_auth;
pub mod space_handlers;
pub mod state;
pub mod subscribe_handlers;
pub mod write_handlers;

pub use router::build_router;
pub use state::HttpState;
