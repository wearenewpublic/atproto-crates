//! 0016 permissioned-data space consumer.
//!
//! The AppView is a space *consumer*: it mints client attestations, exchanges
//! delegation tokens for space credentials, pulls repo state + ops, verifies
//! deniable commits against the LtHash, projects records into SQLite, and keeps
//! its notify registration alive.

pub mod attestation;
pub mod credential;
pub mod delegation;
pub mod notify;
pub mod reader;
pub mod verify;
pub mod writer;
