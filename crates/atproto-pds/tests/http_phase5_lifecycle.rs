//! Phase 5 HTTP integration tests — account lifecycle + migration scaffolds.
//!
//! Coverage:
//! - `activateAccount` / `deactivateAccount` round-trip
//! - `checkAccountStatus` reports state correctly
//! - `listMissingBlobs` returns empty page (Phase 5 scaffold)
//! - `importRepo` returns 501 NotImplemented with structured error

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), manager, tmp)
}

async fn create_account(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
    // Created through the internal API rather than the XRPC endpoint. That
    // endpoint now requires a service-auth token proving control of the DID,
    // signed by a key published in the DID's own document, which a test DID
    // cannot have. Fixture setup is not the thing under test; where
    // `createAccount` itself is the subject, the test calls the endpoint.
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("fixture account needs a session password");
    session_token(app, handle).await
}

async fn post_json(
    app: axum::Router,
    path: &str,
    body: Value,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get_json(app: axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req.body(Body::empty()).unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn deactivate_then_activate_round_trip() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Initially active.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.checkAccountStatus",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["activated"], true);

    // Deactivate.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deactivateAccount",
        json!({"deleteAfter": null}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.checkAccountStatus",
        Some(&token),
    )
    .await;
    assert_eq!(body["activated"], false);

    // Activate.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.activateAccount",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = get_json(
        app,
        "/xrpc/com.atproto.server.checkAccountStatus",
        Some(&token),
    )
    .await;
    assert_eq!(body["activated"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_endpoints_require_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deactivateAccount",
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.checkAccountStatus",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_missing_blobs_empty_until_phase8() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) =
        get_json(app, "/xrpc/com.atproto.repo.listMissingBlobs", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["blobs"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_repo_rejects_malformed_car() {
    // Phase 5/8 path: importRepo now actually attempts to parse the body as
    // a CAR. A garbage body fails CAR-header validation and is rejected with
    // a 4xx; we don't expect 501 anymore.
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.importRepo")
        .method("POST")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/vnd.ipld.car")
        .body(Body::from(b"placeholder-not-a-real-CAR".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "garbage CAR should be rejected, got {:?}",
        resp.status()
    );
}

/// acceptance: `requestEmailUpdate` writes a row into
/// `email_token`; `confirmEmailUpdate` consumes it and updates
/// `account.email`.
/// The email-change flow as the lexicon defines it: `requestEmailUpdate`
/// takes no input and reports whether a token is needed, then `updateEmail`
/// carries the new address.
///
/// An unconfirmed address needs no token -- there is nothing to prove -- so
/// this half exercises the direct path.
#[tokio::test(flavor = "multi_thread")]
async fn email_update_without_a_token_when_the_address_is_unconfirmed() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let accounts_pool = accounts.pool().clone();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);

    let bearer = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    // An address on file but never confirmed: the account holder has stated it
    // and not demonstrated it, which is the state a fresh signup is in.
    manager
        .set_email("did:plc:alice", Some("old@example.com"))
        .await
        .unwrap();

    // No body: the lexicon declares no input for this method. Demanding one
    // is what made a spec-conformant client fail here.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailUpdate",
        json!({}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["tokenRequired"], false,
        "an unconfirmed address needs no token: {body}",
    );

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "new@example.com"}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let email: (Option<String>,) = sqlx::query_as("SELECT email FROM account WHERE did = ?")
        .bind("did:plc:alice")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    assert_eq!(email.0.as_deref(), Some("new@example.com"));
}

/// A confirmed address needs a token, and the token is mailed to the address
/// being moved *away from* -- so completing the change proves continued
/// control of the mailbox on file, not merely of the destination.
#[tokio::test(flavor = "multi_thread")]
async fn email_update_requires_a_token_when_the_address_is_confirmed() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let accounts_pool = accounts.pool().clone();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);

    let bearer = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    manager
        .set_email("did:plc:alice", Some("old@example.com"))
        .await
        .unwrap();
    manager
        .set_email_confirmed_at("did:plc:alice", Some(&chrono::Utc::now().to_rfc3339()))
        .await
        .unwrap();

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailUpdate",
        json!({}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tokenRequired"], true, "body: {body}");

    // Without the token the change is refused by the name the lexicon
    // declares, so a client knows to go and get one.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "new@example.com"}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "TokenRequired", "body: {body}");

    let row: (String,) =
        sqlx::query_as("SELECT token FROM email_token WHERE purpose = 'update_email'")
            .fetch_one(&accounts_pool)
            .await
            .unwrap();

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "new@example.com", "token": row.0}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The token is spent, and the new address is unconfirmed: it has been
    // stated, not demonstrated.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "third@example.com", "token": row.0}),
        Some(&bearer),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a spent token changed the address again"
    );

    let account: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT email, email_confirmed_at FROM account WHERE did = ?")
            .bind("did:plc:alice")
            .fetch_one(&accounts_pool)
            .await
            .unwrap();
    assert_eq!(account.0.as_deref(), Some("new@example.com"));
    assert!(
        account.1.is_none(),
        "the new address should land unconfirmed, got {:?}",
        account.1,
    );
}

/// acceptance: setting `deleteAfter` to a past
/// timestamp persists it on the `account` row, and a manual GC pass moves
/// the account to `deleted`.
#[tokio::test(flavor = "multi_thread")]
async fn deactivate_with_delete_after_in_past_then_gc_deletes() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let accounts_pool = accounts.pool().clone();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);

    let bearer = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Use a `delete_after` already in the past so the GC immediately
    // qualifies the account.
    let one_sec_ago = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deactivateAccount",
        json!({"deleteAfter": one_sec_ago}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify the column is set.
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT state, delete_after FROM account WHERE did = ?")
            .bind("did:plc:alice")
            .fetch_one(&accounts_pool)
            .await
            .unwrap();
    assert_eq!(row.0, "deactivated");
    assert!(row.1.is_some());

    // Run the same SELECT + set_state(Deleted) the binary loop runs, but
    // inline so the test doesn't need to spawn the loop.
    let now = chrono::Utc::now().to_rfc3339();
    let due: Vec<(String,)> = sqlx::query_as(
        "SELECT did FROM account WHERE state = 'deactivated'
         AND delete_after IS NOT NULL AND delete_after <= ?",
    )
    .bind(&now)
    .fetch_all(&accounts_pool)
    .await
    .unwrap();
    assert_eq!(due.len(), 1, "alice should be due for deletion");
    for (did,) in due {
        manager
            .set_state(&did, atproto_pds::account::AccountState::Deleted)
            .await
            .unwrap();
    }

    let final_state: (String,) = sqlx::query_as("SELECT state FROM account WHERE did = ?")
        .bind("did:plc:alice")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    assert_eq!(final_state.0, "deleted");
}

/// acceptance: `requestAccountDelete` issues a token
/// and `deleteAccount` consumes it to transition the account to `Deleted`.
#[tokio::test(flavor = "multi_thread")]
async fn account_delete_request_then_confirm() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let accounts_pool = accounts.pool().clone();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);

    // Create an account with an email so requestAccountDelete can target it.
    manager
        .create_account(
            CreateAccountParams::new("did:plc:alice", "alice.example", "pw")
                .with_email(Some("alice@example.com")),
        )
        .await
        .expect("fixture account");
    manager
        .set_primary_password("did:plc:alice", "pw")
        .await
        .expect("session password");
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "identifier": "alice.example",
                "password": "pw"
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();

    // requestAccountDelete → 200; observe a row in email_token.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestAccountDelete",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let confirm: (String,) =
        sqlx::query_as("SELECT token FROM email_token WHERE purpose = 'delete_account'")
            .fetch_one(&accounts_pool)
            .await
            .unwrap();

    // The token alone is not enough. It arrives by email, so treating it as a
    // single factor means anyone who reads the message can destroy the
    // account.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deleteAccount",
        json!({"did": "did:plc:alice", "password": "not-the-password", "token": confirm.0}),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an account was deleted with the wrong password",
    );

    // A token issued for one account cannot delete another.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deleteAccount",
        json!({"did": "did:plc:someone-else", "password": "pw", "token": confirm.0}),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a token deleted an account it was not issued for",
    );

    // Still intact after both refusals — a rejected delete must not have
    // consumed the token or half-applied the state change.
    let state_row: (String,) = sqlx::query_as("SELECT state FROM account WHERE did = ?")
        .bind("did:plc:alice")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    assert_ne!(
        state_row.0, "deleted",
        "a refused delete deleted the account"
    );

    // deleteAccount(did + password + token) → 200; state flips to deleted.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deleteAccount",
        json!({"did": "did:plc:alice", "password": "pw", "token": confirm.0}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let state_row: (String,) = sqlx::query_as("SELECT state FROM account WHERE did = ?")
        .bind("did:plc:alice")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    assert_eq!(state_row.0, "deleted");
}

/// acceptance: a denylisted handle is rejected at
/// `createAccount`. The plaintext handle is never persisted; only the
/// 8-byte hash lives in the `denylist` table.
#[tokio::test(flavor = "multi_thread")]
async fn denylisted_handle_blocks_create_account() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let accounts_pool = accounts.pool().clone();
    let account_pool = atproto_pds::account::AccountPool::Sqlite(accounts_pool.clone());

    // Block "alice.example" before constructing the rest of the app.
    atproto_pds::denylist::add(
        &account_pool,
        atproto_pds::denylist::KIND_HANDLE,
        "alice.example",
        Some("test"),
    )
    .await
    .unwrap();

    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);

    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "did": "did:plc:alice",
                "handle": "alice.example",
                "password": "pw"
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "BlockedHandle");
}

/// acceptance: `getAccountInviteCodes` returns codes
/// the caller has issued.
#[tokio::test(flavor = "multi_thread")]
async fn get_account_invite_codes_returns_caller_codes() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Issue two codes via the existing createInviteCode endpoint.
    for _ in 0..2 {
        let (status, _) = post_json(
            app.clone(),
            "/xrpc/com.atproto.server.createInviteCode",
            json!({"useCount": 1}),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.server.getAccountInviteCodes",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let codes = body["codes"].as_array().unwrap();
    assert_eq!(codes.len(), 2);
    for c in codes {
        assert!(c["code"].as_str().unwrap().len() > 5);
        assert_eq!(c["disabled"], false);
    }
}

/// Log in as a fixture account and return its access token.
async fn session_token(app: &axum::Router, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "identifier": handle, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"]
        .as_str()
        .expect("createSession should return an access token")
        .to_string()
}
