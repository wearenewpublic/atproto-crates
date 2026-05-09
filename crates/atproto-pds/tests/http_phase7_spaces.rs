//! Phase 7 HTTP integration tests — `com.atproto.space.*` endpoints.
//!
//! Coverage:
//! - createSpace / getSpace / listSpaces (owner-OAuth gated)
//! - addMember / removeMember / getMembers (owner-OAuth, 403 for non-owner)
//! - applyWrites against a permissioned repo (member-OAuth)
//! - getRecord / listRecords (own-PDS OAuth + remote SpaceCredential paths)
//! - getRepoState / getRepoOplog / getMemberState / getMemberOplog
//! - getMemberGrant + getSpaceCredential round-trip

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, TempDir) {
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

    // Phase 7 wiring — `with_accounts` enables the notifyMembership fan-out
    // path (signing the membership commit + enqueuing into `notify_attempt`).
    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));

    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);

    let app = build_router(state);
    (app, tmp)
}

async fn create_account_and_token(app: &axum::Router, did: &str, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "did": did,
                "handle": handle,
                "password": "pw"
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"].as_str().unwrap().to_string()
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
async fn create_space_round_trip() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let uri = body["uri"].as_str().unwrap();
    assert_eq!(uri, "ats://did:plc:owner/app.bsky.group/default");
    assert_eq!(body["isOwner"], true);

    // Look it up.
    let (status, info) = get_json(
        app,
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(uri)),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {info}");
    assert_eq!(info["uri"], uri);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_space_requires_auth() {
    let (app, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn add_then_list_members() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getMembers?space={}",
            urlencode(uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["members"].as_array().unwrap().len(), 1);
    assert_eq!(body["members"][0]["did"], "did:plc:alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn add_member_by_non_owner_rejected() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let eve_token = create_account_and_token(&app, "did:plc:eve", "eve.example").await;

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";

    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&eve_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_then_read_back() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";

    // Add Alice as member (owner-side).
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    // Alice writes a record into the permissioned repo.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "space": uri,
            "writes": [{
                "action": "create",
                "collection": "app.bsky.group.message",
                "rkey": "first",
                "value": {"text": "hi"}
            }]
        }),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(!body["rev"].as_str().unwrap().is_empty());
    assert!(!body["setHash"].as_str().unwrap().is_empty());

    // Read it back via Alice's OAuth.
    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=app.bsky.group.message&rkey=first",
            urlencode(uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["value"]["text"], "hi");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_state_advances_with_writes() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";

    // Empty state first.
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&member=did:plc:alice",
            urlencode(uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["setHash"].is_null());

    // Write something, then state should be populated.
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "space": uri,
            "writes": [{
                "action": "create",
                "collection": "c",
                "rkey": "k",
                "value": {"v": 1}
            }]
        }),
        Some(&alice_token),
    )
    .await;
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&member=did:plc:alice",
            urlencode(uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["setHash"].as_str().is_some());
    assert!(body["rev"].as_str().is_some());

    // Oplog should report 1 op.
    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRepoOplog?space={}&member=did:plc:alice",
            urlencode(uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["ops"].as_array().unwrap().len(), 1);
    assert_eq!(body["ops"][0]["action"], "create");
}

#[tokio::test(flavor = "multi_thread")]
async fn member_grant_then_credential_then_read() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    // Alice writes a record (so there's something to credential-read later).
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "space": uri,
            "writes": [{
                "action": "create",
                "collection": "c",
                "rkey": "k",
                "value": {"v": "secret"}
            }]
        }),
        Some(&alice_token),
    )
    .await;

    // Step 1: Alice mints a MemberGrant for client-id `app1`.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.getMemberGrant",
        json!({"space": uri, "clientId": "https://app.example/client-metadata.json"}),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let grant = body["token"].as_str().unwrap().to_string();

    // Step 2: App swaps the grant for a SpaceCredential at the owner's PDS.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.getSpaceCredential",
        json!({"grant": grant}),
        None, // No auth — the grant *is* the auth.
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let credential = body["token"].as_str().unwrap().to_string();

    // Step 3: App reads a record from the *owner's* per-actor store using the
    // credential. (Note: this reads from the owner's store, which won't have
    // Alice's record. So we test the negative path here — a successful
    // verify but no record present at the owner's store.)
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=k",
            urlencode(uri)
        ),
        Some(&credential),
    )
    .await;
    // Expect 404 since the owner hasn't written this record (Alice did, in
    // her own per-actor store). The credential auth path itself succeeded —
    // the request reached the reader and returned RecordNotFound.
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn applywrites_empty_batch_rejected() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.applyWrites",
        json!({"space": uri, "writes": []}),
        Some(&owner_token),
    )
    .await;
    // Either 400 InvalidRequest or 400 SpaceError — both communicate the
    // empty-batch problem. Just assert it's a 4xx.
    assert!(status.is_client_error());
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_returns_paginated() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    for r in ["a", "b", "c"] {
        post_json(
            app.clone(),
            "/xrpc/com.atproto.space.applyWrites",
            json!({
                "space": uri,
                "writes": [{
                    "action": "create",
                    "collection": "c",
                    "rkey": r,
                    "value": {"k": r}
                }]
            }),
            Some(&alice_token),
        )
        .await;
    }

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRecords?space={}&collection=c&limit=2",
            urlencode(uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
    assert!(body["cursor"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn member_state_and_oplog() {
    let (app, _tmp) = build_app().await;
    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.removeMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getMemberState?space={}",
            urlencode(uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["setHash"].as_str().is_some());

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getMemberOplog?space={}",
            urlencode(uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0]["action"], "add");
    assert_eq!(ops[1]["action"], "remove");
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// acceptance: two `getSpaceCredential` calls from the
/// same `clientId` produce one `space_credential_recipient` row (idempotent
/// on `(space, service_did)`).
#[tokio::test(flavor = "multi_thread")]
async fn get_space_credential_registers_recipient_idempotently() {
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
    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);
    let app = build_router(state);

    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri = "ats://did:plc:owner/app.bsky.group/default";
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    let client_id = "https://app.example/client-metadata.json";

    // Call getSpaceCredential twice with the same clientId. The second
    // grant must be minted at a different `iat` second so its synthesized
    // jti differs (otherwise the replay guard rejects it). One second of
    // wall-clock sleep is the cheapest way to satisfy that.
    for i in 0..2 {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let (status, body) = post_json(
            app.clone(),
            "/xrpc/com.atproto.space.getMemberGrant",
            json!({"space": uri, "clientId": client_id}),
            Some(&alice_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "getMemberGrant: {body}");
        let grant = body["token"].as_str().unwrap().to_string();

        let (status, body) = post_json(
            app.clone(),
            "/xrpc/com.atproto.space.getSpaceCredential",
            json!({"grant": grant}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "getSpaceCredential: {body}");
    }

    // Inspect the owner's per-actor `space_credential_recipient` table — we
    // expect exactly one row, even after two credential mints.
    let owner_store = atproto_pds::actor_store::sql::SqlActorStore::open(&dir, "did:plc:owner")
        .await
        .unwrap();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT space, service_did, service_endpoint FROM space_credential_recipient",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one recipient row, got: {rows:?}"
    );
    assert_eq!(rows[0].0, uri);
    assert_eq!(rows[0].2, "https://app.example");
}

/// acceptance (HTTP-end-to-end): a space write enqueues
/// one `notify_attempt` row per registered recipient. We pre-seed the
/// recipient table directly (so we don't need the full credential-mint
/// flow), then assert the enqueue count.
#[tokio::test(flavor = "multi_thread")]
async fn space_write_enqueues_one_notify_per_recipient() {
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
    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);
    let app = build_router(state);

    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri_str = "ats://did:plc:owner/app.bsky.group/default";
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri_str, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    // Pre-seed two recipients on the owner's per-actor store.
    let owner_store = atproto_pds::actor_store::sql::SqlActorStore::open(&dir, "did:plc:owner")
        .await
        .unwrap();
    let space_uri: atproto_space::types::SpaceUri = uri_str.parse().unwrap();
    atproto_pds::space::notify::upsert_recipient(
        owner_store.pool(),
        &space_uri,
        "did:web:a.example",
        "https://a.example",
    )
    .await
    .unwrap();
    atproto_pds::space::notify::upsert_recipient(
        owner_store.pool(),
        &space_uri,
        "did:web:b.example",
        "https://b.example",
    )
    .await
    .unwrap();

    // Snapshot the queue length before the write.
    let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notify_attempt")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();

    // Alice writes a record.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "space": uri_str,
            "writes": [{"action": "create", "collection": "c", "rkey": "k", "value": {"v": 1}}]
        }),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "applyWrites: {body}");

    let after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notify_attempt")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    // 2 new rows (one per recipient) for the write commit. addMember
    // happened before the seed so it didn't fan out (and it has no recipient
    // entries until we seeded them).
    assert_eq!(after.0 - before.0, 2);
}

/// acceptance (membership variant): owner-side
/// `addMember` after the recipient table is populated enqueues one
/// `notifyMembership` row per recipient.
#[tokio::test(flavor = "multi_thread")]
async fn add_member_enqueues_membership_notification() {
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
    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);
    let app = build_router(state);

    let owner_token = create_account_and_token(&app, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createSpace",
        json!({"spaceType": "app.bsky.group", "spaceKey": "default"}),
        Some(&owner_token),
    )
    .await;
    let uri_str = "ats://did:plc:owner/app.bsky.group/default";
    let space_uri: atproto_space::types::SpaceUri = uri_str.parse().unwrap();

    // Seed one recipient before the membership op so the addMember below
    // produces exactly one notify row.
    let owner_store = atproto_pds::actor_store::sql::SqlActorStore::open(&dir, "did:plc:owner")
        .await
        .unwrap();
    atproto_pds::space::notify::upsert_recipient(
        owner_store.pool(),
        &space_uri,
        "did:web:appview.example",
        "https://appview.example",
    )
    .await
    .unwrap();

    let before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notify_attempt")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();

    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.addMember",
        json!({"space": uri_str, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    let after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notify_attempt")
        .fetch_one(&accounts_pool)
        .await
        .unwrap();
    assert_eq!(after.0 - before.0, 1);

    let (target_did, nsid): (String, String) = sqlx::query_as(
        "SELECT target_service_did, nsid FROM notify_attempt ORDER BY next_attempt_at DESC LIMIT 1",
    )
    .fetch_one(&accounts_pool)
    .await
    .unwrap();
    assert_eq!(target_did, "did:web:appview.example");
    assert_eq!(nsid, "com.atproto.space.notifyMembership");
}
