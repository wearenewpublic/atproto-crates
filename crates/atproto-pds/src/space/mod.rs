//! Permissioned-data spaces subsystem — wires `atproto-space` orchestrators
//! into the per-actor SQLite store and exposes them via XRPC.
//!
//! Components:
//!
//! - `SpaceService` — `createSpace`, `getSpace`, `listSpaces`, `addMember`,
//!   `removeMember`, `listMembers`.
//! - `SpaceWriter` — `createRecord` / `putRecord` / `deleteRecord` /
//!   `applyWrites` against a permissioned repo (per-(DID, space-URI) lock).
//! - `SpaceReader` — dual-auth `getRecord` / `listRecords` (own-PDS OAuth
//!   or remote SpaceCredential).
//! - `SpaceSync` — `getRepoState`, `listRepoOps`.
//! - Credential mint/verify wired to `atproto-space::credential`.
//!
//! The auth-extractor extensions for delegation-token/SpaceCredential JWTs
//! live in the HTTP layer alongside the app-password sessions.

pub mod blob_ref;
pub mod config;
pub mod declaration;
pub mod export_car;
pub mod inbound;
pub mod lex_bytes;
pub mod mint_authz;
pub mod notify;
pub mod reader;
pub mod recipient;
pub mod service;
pub mod service_auth;
pub mod sync;
pub mod writer;

pub use config::{AppAccess, MintPolicy, SpaceConfig, SpaceConfigPatch};
pub use declaration::{
    CachingSpaceDeclarationResolver, LexiconSpaceDeclarationResolver,
    NetworkSpaceDeclarationResolver, SpaceDeclaration, SpaceDeclarationResolver,
};
pub use reader::SpaceReader;
pub use service::{GetSpaceOutput, Membership, SpaceInfo, SpaceService};
pub use sync::SpaceSync;
pub use writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
