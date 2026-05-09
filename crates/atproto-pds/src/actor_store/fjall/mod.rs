//! Fjall-backed actor store.
//!
//! one fjall
//! `Keyspace` per data-dir, with separate `Partition`s for each table.
//! This contrasts with the SQLite profile which keeps one SQLite file
//! account; fjall's keyspace + partition model lets us colocate all actors
//! in a single LSM tree while still segregating by partition.
//!
//! the G3 partition split (one keyspace per logical Spaces table), the
//! Spaces tables (`space_repo` + `space_record` + `space_record_oplog` +
//! `space_member` + `space_member_state` + `space_member_oplog`) live in
//! their own partitions so they can be opened/recovered independently of the
//! public-realm tables (`commit_obj`, `repo_block`, `repo_record`, `outbox`).
//!
//! # Status
//!
//! - **Spaces subset** — fully shipped end-to-end:
//!   `FjallSpaceRepoStorage` + `FjallSpaceMembersStorage` implementing
//!   the `atproto_space` storage traits.
//! - **Public realm** — both `BlockStorage` and the four
//!   `actor_store::traits::*Storage` impls are wired through the
//!   `PublicRealmBackend` dispatch. The high-level `RepoReader` / `RepoWriter` /
//!   `OutboxReader` / `RepoImporter` call sites also route through the
//!   dispatch.

#[cfg(feature = "fjall")]
mod block_storage;
#[cfg(feature = "fjall")]
mod keyspace;
#[cfg(feature = "fjall")]
mod public_realm;
#[cfg(feature = "fjall")]
mod space_members_storage;
#[cfg(feature = "fjall")]
mod space_repo_storage;

#[cfg(feature = "fjall")]
pub use block_storage::FjallBlockStorage;
#[cfg(feature = "fjall")]
pub use keyspace::FjallActorStore;
#[cfg(feature = "fjall")]
pub use public_realm::{
    FjallAtomicCommitWriter, FjallBlobStorage, FjallCommitObjStorage, FjallOutboxStorage,
    FjallRepoRecordStorage,
};
#[cfg(feature = "fjall")]
pub use space_members_storage::FjallSpaceMembersStorage;
#[cfg(feature = "fjall")]
pub use space_repo_storage::FjallSpaceRepoStorage;
