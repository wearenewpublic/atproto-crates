//! SQLite-backed actor store implementation.
//!
//! one SQLite file
//! per account at `PDS_DATA_DIRECTORY/actors/<sha256(did)>.sqlite`. The
//! shared accounts DB at `PDS_DATA_DIRECTORY/accounts.sqlite` holds
//! cross-account state (accounts, sessions, invites, etc.).

mod block_storage;
mod migrations;
mod public_realm;
mod space_members_storage;
mod space_repo_storage;
mod store;

pub use block_storage::SqlBlockStorage;
pub use migrations::{
    ACCOUNTS_MIGRATIONS, ACTOR_MIGRATIONS, run_accounts_migrations, run_actor_migrations,
};
pub use public_realm::{
    SqlAtomicCommitWriter, SqlBlobStorage, SqlCommitObjStorage, SqlOutboxStorage,
    SqlRepoRecordStorage,
};
pub use space_members_storage::SqlSpaceMembersStorage;
pub use space_repo_storage::SqlSpaceRepoStorage;
pub use store::{SqlActorStore, actor_db_path, did_filename};
