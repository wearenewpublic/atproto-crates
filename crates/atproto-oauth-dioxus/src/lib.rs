//! Dioxus fullstack integration for AT Protocol OAuth authentication.
//!
//! This crate provides a turnkey OAuth PKCE + DPoP flow for Dioxus fullstack
//! applications, wrapping the [`atproto-oauth`] and [`atproto-identity`] crates
//! into ergonomic Dioxus components, hooks, and server functions.
//!
//! # Quick Start
//!
//! 1. Add the dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! atproto-oauth-dioxus = "0.15"
//!
//! [features]
//! server = ["atproto-oauth-dioxus/server"]
//! ```
//!
//! 2. Define the callback route in your app's `Route` enum:
//!
//! ```rust,ignore
//! #[derive(Routable, Clone, PartialEq)]
//! enum Route {
//!     #[route("/oauth/callback")]
//!     OAuthCallback {},
//!     #[route("/")]
//!     Home {},
//! }
//! ```
//!
//! 3. Wrap your app with the provider and mount the callback:
//!
//! ```rust,ignore
//! use atproto_oauth_dioxus::components::AtprotoOAuthProvider;
//! use atproto_oauth_dioxus::config::AtprotoOAuthConfig;
//!
//! fn App() -> Element {
//!     rsx! {
//!         AtprotoOAuthProvider {
//!             config: AtprotoOAuthConfig::new("/oauth/callback"),
//!             Router::<Route> {}
//!         }
//!     }
//! }
//! ```
//!
//! 4. Use the [`use_atproto_auth`] hook in your login page:
//!
//! ```rust,ignore
//! use atproto_oauth_dioxus::hooks::{use_atproto_auth, do_atproto_login};
//!
//! fn LoginPage() -> Element {
//!     let auth = use_atproto_auth();
//!     let mut handle = use_signal(String::new);
//!
//!     rsx! {
//!         input { oninput: move |e| handle.set(e.value()) }
//!         button {
//!             onclick: move |_| do_atproto_login(
//!                 handle(), auth.authorization_url, auth.error, auth.is_loading,
//!             ),
//!             "Login with AT Protocol"
//!         }
//!     }
//! }
//! ```
//!
//! # Server Configuration
//!
//! Set the following environment variables for server deployments:
//!
//! - `OAUTH_KEY_SEED` — 64 hex characters (32 bytes) seed for the P-256
//!   signing key. On server restarts, the same seed regenerates the same key.
//! - `HOST_DOMAIN` or `RAILWAY_PUBLIC_DOMAIN` — The public hostname of the
//!   deployment. Used to construct the `client_id` and `redirect_uri`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Dioxus components for the AT Protocol OAuth flow.
pub mod components;
/// Configuration for the AT Protocol OAuth Dioxus integration.
pub mod config;
/// Error types for the AT Protocol OAuth Dioxus integration.
pub mod errors;
/// Reactive hooks for AT Protocol OAuth authentication state.
pub mod hooks;
/// Client-side session persistence via localStorage.
pub mod state;
/// Shared data types used across the client and server.
pub mod types;

/// Server functions for AT Protocol OAuth flows.
pub mod server_fns;

/// Server-side OAuth orchestration and session management.
#[cfg(feature = "server")]
pub mod server;
