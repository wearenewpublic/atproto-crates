//! Walking Club AppView library.
//!
//! A confidential OAuth backend-for-frontend plus a 0016 permissioned-data
//! space consumer for the atproto-crates test cluster. Server-rendered HTML
//! (minijinja) backed by a single SQLite file; no JS toolchain, no external
//! datastore.

pub mod config;
pub mod db;
pub mod error;
pub mod firehose_processor;
pub mod handlers;
pub mod oauth;
pub mod ratelimit;
pub mod server;
pub mod space;
pub mod state;
pub mod templates;
pub mod xrpc;

pub use config::Config;
pub use error::{AppError, AppResult, ConfigError, WebError};
pub use state::{Metrics, WebContext};
