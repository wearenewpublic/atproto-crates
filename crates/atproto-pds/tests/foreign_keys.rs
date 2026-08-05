//! Foreign-key enforcement in the SQLite stores.
//!
//! The schemas declare fifteen foreign keys, most with `ON DELETE CASCADE`,
//! and SQLite ignores every one of them unless `PRAGMA foreign_keys` is on for
//! the connection. SQLite itself defaults it *off*; sqlx overrides that and
//! turns it on for every connection it opens, so the constraints are live.
//!
//! That is a library default holding up a schema-level guarantee, which is
//! exactly the kind of thing that is true until someone changes a driver. The
//! pools now ask for the pragma explicitly, and these tests fail if it ever
//! stops being applied — by either route.
//!
//! What this is *not*: `deleteAccount` soft-deletes, setting `state` rather
//! than removing the row, so the account-side cascades do not fire in that
//! flow and no credential outlives a deletion because of this.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams, portal};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::space::SpaceWriter;
use atproto_space::types::SpaceUri;
use std::sync::Arc;
use tempfile::TempDir;

const DID: &str = "did:plc:foreignkeyfixture0000000000";
const HANDLE: &str = "fk.pds.test";

async fn manager() -> (Arc<AccountManager>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    (manager, tmp)
}

/// A row referencing an account that does not exist is refused.
///
/// Without enforcement this would insert happily, leaving a portal session
/// whose account had never existed — a live login pointing at nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_for_an_unknown_account_is_refused() {
    let (manager, _tmp) = manager().await;

    let result = portal::create_session(
        &manager.account_pool(),
        "cookie-value",
        "did:plc:thisaccountdoesnotexist0000",
        0,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "a portal session was created for an account that does not exist"
    );
}

/// Removing an account row takes its portal sessions with it.
///
/// `deleteAccount` soft-deletes rather than reaching this, so this pins the
/// cascade itself: any path that does remove the row must not leave a session
/// behind that would still authenticate.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_an_account_row_cascades_to_its_sessions() {
    let (manager, _tmp) = manager().await;
    let pool = manager.account_pool();
    portal::create_session(&pool, "cookie-value", DID, 0, None)
        .await
        .expect("fixture session");
    assert!(
        portal::lookup_session(&pool, "cookie-value")
            .await
            .unwrap()
            .is_some(),
        "fixture session was not created"
    );

    sqlx::query("DELETE FROM account WHERE did = ?")
        .bind(DID)
        .execute(pool.as_sqlite())
        .await
        .expect("account row should delete");

    assert!(
        portal::lookup_session(&pool, "cookie-value")
            .await
            .unwrap()
            .is_none(),
        "a portal session outlived the account row it belonged to"
    );
}

/// Writing into an unknown space *materialises* it rather than failing.
///
/// This looks like the orphan the foreign key should have caught, and it is
/// not one: `ensure_space_row` does an `INSERT OR IGNORE INTO space` ahead of
/// every record write, so the parent always exists by the time the child is
/// inserted.
///
/// That is deliberate and federation depends on it. A member whose space
/// authority lives on another PDS has no space row until they receive
/// something for it, so a write that refused to create one would make
/// cross-PDS spaces unusable.
///
/// The consequence is the point: storage cannot be the thing that decides
/// whether a caller may write to a space, because storage will always say yes.
/// Authorisation has to happen above it, which is what the portal's
/// membership check does — and this test is what says that check cannot be
/// delegated downwards later.
#[tokio::test(flavor = "multi_thread")]
async fn writing_into_an_unknown_space_creates_it_rather_than_failing() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");

    let space_writer = SpaceWriter::new(manager.clone(), dir.clone());
    let space = SpaceUri::parse("at://did:plc:nosuchspaceauthority00000/space/app.bsky.group/x")
        .expect("a syntactically valid space uri");

    let result = space_writer
        .put_record(
            DID,
            &space,
            "app.bsky.feed.post".to_string(),
            "3kaaaaaaaaaa2".to_string(),
            serde_json::json!({"$type": "app.bsky.feed.post", "text": "materialised"}),
        )
        .await;

    assert!(
        result.is_ok(),
        "the space row is created on demand, so this write must succeed: {result:?}"
    );
}
