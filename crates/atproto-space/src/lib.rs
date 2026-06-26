//! AT Protocol permissioned-data spaces — primitives.
//!
//! This crate implements the protocol primitives from the
//! [0016 Permissioned Data][spec] draft, which is the authoritative alignment
//! target for this crate:
//!
//! - **`SetHash`** trait + **`LtHash`** (the production primitive).
//! - **`Commit`** — a signed commit (`com.atproto.space.defs#signedCommit`):
//!   `mac = HMAC(HKDF(ikm, ctx), hash)` binds the repo hash to the per-commit
//!   context, while `sig` covers only `ctx` (the space URI, rev, and per-commit
//!   random `ikm`) — never the hash — so a leaked commit is deniable (spec
//!   lines 285-316).
//! - **`SpaceRepo`** — per-(user, space) record orchestrator over the storage
//!   trait surface. **`SpaceMembers`** — the `simplespace` member-list
//!   orchestrator (the spec carries no member commits or member sync).
//! - **`DelegationToken`** / **`SpaceCredential`** — JWT shapes for the two-step credential flow.
//!
//! The crate is **server-agnostic** — it does no IO directly and has no network
//! dependencies. It composes with `atproto-pds` (and AppView consumers) via the
//! `SpaceRepoStorage` and `SpaceMembersStorage` traits.
//!
//! # Status
//!
//! Experimental. 0016 is a draft; details may still change upstream.
//!
//! # References
//!
//! - [0016 Permissioned Data][spec]
//!
//! [spec]: https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commit;
pub mod credential;
pub mod errors;
pub mod set_hash;
pub mod space_members;
pub mod space_repo;
pub mod storage;
pub mod types;

// Re-exports for the canonical public API surface.
pub use commit::{
    Commit, SpaceContext, create_commit, encode_ctx, verify_commit, verify_commit_signature,
};
pub use credential::{
    DelegationToken, SpaceCredential, create_delegation_token, create_space_credential,
    verify_delegation_token, verify_space_credential,
};
pub use errors::SpaceError;
pub use set_hash::{LtHash, SetHash};
pub use space_members::{MemberOp, MemberOpAction, SpaceMembers};
pub use space_repo::{Op, OpAction, PreparedCommit, SpaceRepo};
pub use storage::{
    MemberPage, MemberRow, MemberState, OplogCursor, OplogEntry, OplogPage, RecordPage, RecordRow,
    RepoState, SpaceMembersStorage, SpaceRepoStorage,
};
pub use types::{RecordUri, SpaceKey, SpaceType, SpaceUri};
