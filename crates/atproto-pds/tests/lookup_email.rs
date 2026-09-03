//! `AccountDirectory::lookup_email` — the by-email lookup that
//! `createSessionFromToken` matches gateway tokens on.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use std::sync::Arc;
use tempfile::TempDir;

async fn directory_and_manager() -> (AccountDirectory, Arc<AccountManager>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir,
        key_store,
        KeyType::K256Private,
    ));
    (accounts, manager, tmp)
}

/// The gateway passes the address Google or the magic link saw; the operator
/// typed whatever they typed when provisioning. The two must meet regardless
/// of case, because email local parts are case-insensitive in practice and
/// the column is stored verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn finds_an_account_regardless_of_email_case() {
    let (directory, manager, _tmp) = directory_and_manager().await;
    manager
        .create_account(
            CreateAccountParams::new("did:web:admin.example", "admin.example", "pw")
                .with_email(Some("Admin@Example.com")),
        )
        .await
        .unwrap();

    let row = directory
        .lookup_email("admin@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.did, "did:web:admin.example");
    assert_eq!(row.email.as_deref(), Some("Admin@Example.com"));
}

/// Absent is `Ok(None)`, not an error — the handler turns it into
/// `AccountNotFound`.
#[tokio::test(flavor = "multi_thread")]
async fn missing_email_is_none() {
    let (directory, _manager, _tmp) = directory_and_manager().await;
    assert!(
        directory
            .lookup_email("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

/// The column is UNIQUE but not case-folded, so two rows can differ only by
/// case. Picking one silently would sign one person into another's account;
/// refuse instead.
#[tokio::test(flavor = "multi_thread")]
async fn two_rows_differing_only_by_case_are_refused() {
    let (directory, manager, _tmp) = directory_and_manager().await;
    for (did, handle, email) in [
        ("did:web:a.example", "a.example", "Dup@Example.com"),
        ("did:web:b.example", "b.example", "dup@example.com"),
    ] {
        manager
            .create_account(CreateAccountParams::new(did, handle, "pw").with_email(Some(email)))
            .await
            .unwrap();
    }
    assert!(directory.lookup_email("DUP@example.com").await.is_err());
}
