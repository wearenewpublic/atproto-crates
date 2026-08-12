//! AT Protocol lexicon resolution and validation library.
//!
//! This library provides functionality for resolving and validating AT Protocol lexicons,
//! which define the schema and structure of AT Protocol data.
//!
//! ## Overview
//!
//! Lexicons in AT Protocol serve as schema definitions that describe the structure
//! and types of data that can be stored and transmitted. This library implements
//! the full lexicon resolution chain as specified by the AT Protocol:
//!
//! 1. Convert NSID to DNS name with `_lexicon` prefix
//! 2. Perform DNS TXT lookup to get the authoritative DID
//! 3. Resolve the DID to get the DID document
//! 4. Extract PDS endpoint from the DID document
//! 5. Make XRPC call to fetch the lexicon schema
//!
//! ## Modules
//!
//! - [`errors`]: Structured error types for all lexicon operations
//! - [`resolve`]: Core lexicon resolution implementation
//! - [`resolve_recursive`]: Recursive resolution with dependency tracking
//! - [`validation`]: NSID validation, parsing, and helper functions
//!
//! ## Example Usage
//!
//! ```no_run
//! # use anyhow::Result;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! use atproto_lexicon::resolve::{DefaultLexiconResolver, LexiconResolver};
//! use atproto_identity::resolve::HickoryDnsResolver;
//!
//! let http_client = reqwest::Client::new();
//! let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
//! let resolver = DefaultLexiconResolver::new(http_client, dns_resolver);
//!
//! // Resolve a lexicon
//! let lexicon = resolver.resolve("app.bsky.feed.post").await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod errors;
pub mod resolve;
pub mod resolve_recursive;
pub mod validation;
