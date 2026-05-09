//! AT Protocol permissioned-data spaces — primitives.
//!
//! This crate implements the protocol primitives from the
//! [Spaces Design Spec](https://github.com/bluesky-social/atproto/blob/main/docs/superpowers/specs/2026-04-22-permissioned-data-pds-design.md):
//!
//! - **`SetHash`** trait + `XorSha256SetHash` placeholder + `EcmhSetHash` (production target).
//! - **`Commit`** — HKDF-derived HMAC + ECDSA-signed commit over a `SetHash` digest with
//!   per-commit random IKM for deniability and `scope` domain separation.
//! - **`SpaceRepo`** / **`SpaceMembers`** — orchestrators over storage trait surfaces.
//! - **`MemberGrant`** / **`SpaceCredential`** — JWT shapes for the two-step credential flow.
//!
//! The crate is **server-agnostic** — it does no IO directly and has no network
//! dependencies. It composes with `atproto-pds` (and AppView consumers) via the
//! `SpaceRepoStorage` and `SpaceMembersStorage` traits.
//!
//! # Status
//!
//! Experimental. The Spaces Design Spec is still settling. Several primitives
//! (notably the `SetHash` algorithm) are explicitly marked as "placeholder until
//! upstream picks ECMH or ltHash" by the spec itself.
//!
//! # References
//!
//! - [Spaces Design Spec](https://github.com/bluesky-social/atproto/blob/main/docs/superpowers/specs/2026-04-22-permissioned-data-pds-design.md)
//! - Design document: see `` §15.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commit;
pub mod credential;
pub mod errors;
pub mod recon;
pub mod set_hash;
#[cfg(feature = "ecmh")]
pub mod set_hash_ecmh;
pub mod space_members;
pub mod space_repo;
pub mod storage;
pub mod types;

// Re-exports for the canonical public API surface.
pub use commit::{Commit, CommitScope, SpaceContext, create_commit, verify_commit};
pub use credential::{
    MemberGrant, SpaceCredential, create_member_grant, create_space_credential,
    verify_member_grant, verify_space_credential,
};
pub use errors::SpaceError;
pub use set_hash::{SetHash, XorSha256SetHash};
#[cfg(feature = "ecmh")]
pub use set_hash_ecmh::EcmhSetHash;
pub use space_members::{MemberOp, MemberOpAction, SpaceMembers};
pub use space_repo::{Op, OpAction, PreparedCommit, SpaceRepo};
pub use storage::{
    MemberPage, MemberRow, MemberState, OplogEntry, OplogPage, RecordPage, RecordRow, RepoState,
    SpaceMembersStorage, SpaceRepoStorage,
};
pub use types::{SpaceKey, SpaceType, SpaceUri};
