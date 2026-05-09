//! Permissioned-data spaces subsystem — wires `atproto-space` orchestrators
//! into the per-actor SQLite store and exposes them via XRPC.
//!
//!
//! - `SpaceService` — `createSpace`, `getSpace`, `listSpaces`, `addMember`,
//!   `removeMember`, `getMembers`.
//! - `SpaceWriter` — `createRecord` / `putRecord` / `deleteRecord` /
//!   `applyWrites` against a permissioned repo (per-(DID, space-URI) lock).
//! - `SpaceReader` — dual-auth `getRecord` / `listRecords` (own-PDS OAuth
//!   or remote SpaceCredential).
//! - `SpaceSync` — `getRepoState`, `getRepoOplog`, `getMemberState`,
//!   `getMemberOplog`.
//! - Credential mint/verify wired to `atproto-space::credential`.
//!
//! The auth-extractor extensions for MemberGrant/SpaceCredential JWTs
//! live in the HTTP layer alongside the app-password sessions.

pub mod export;
pub mod inbound;
pub mod notify;
pub mod reader;
pub mod recipient;
pub mod service;
pub mod sync;
pub mod writer;

pub use reader::SpaceReader;
pub use service::{SpaceInfo, SpaceService};
pub use sync::SpaceSync;
pub use writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
