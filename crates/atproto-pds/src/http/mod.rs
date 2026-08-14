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

pub mod icons;
pub mod identity_handlers;
pub mod moderation_handlers;
pub mod portal;
pub mod portal_spaces;
pub mod preference_handlers;
pub mod proxy_handlers;
pub mod proxy_target;
pub mod rate_limit;
/// The Repository section of the portal -- a browser over this account's records.
pub mod repository;
pub mod router;
pub mod security_headers;
pub mod service_auth_handlers;
pub mod service_describe;
pub mod space_auth;
pub mod space_handlers;
pub mod state;
/// The account portal -- what an account holder can do with only a browser.
pub mod static_assets;
pub mod subscribe_handlers;
pub mod write_handlers;

pub use rate_limit::RateLimitPolicy;
pub use router::{
    build_router, build_router_with_request_timeout, build_router_with_timeouts, with_dpop_nonce,
    with_rate_limit,
};
pub use state::HttpState;
