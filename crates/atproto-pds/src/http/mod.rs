//! HTTP layer — axum router and shared state.
//!
//! Wires the full XRPC surface: read-only `com.atproto.repo.*` and
//! `com.atproto.sync.*` handlers, OAuth provider, write endpoints,
//! admin, and Spaces.

pub mod auth;
pub mod auth_handlers;
pub mod blob_handlers;
pub mod browse;
pub mod discovery_handlers;
pub mod errors;
pub mod extract;
pub mod handlers;

pub mod identity_handlers;
pub mod moderation_handlers;
/// The account portal -- what an account holder can do with only a browser.
pub mod portal;
pub mod preference_handlers;
pub mod proxy_handlers;
pub mod proxy_target;
pub mod rate_limit;
pub mod router;
pub mod service_auth_handlers;
pub mod service_describe;
pub mod space_auth;
pub mod space_handlers;
pub mod state;
pub mod subscribe_handlers;
pub mod write_handlers;

pub use rate_limit::RateLimitPolicy;
pub use router::{build_router, with_rate_limit};
pub use state::HttpState;
