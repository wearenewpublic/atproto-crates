//! Phase 3 HTTP integration tests — write endpoints.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
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
async fn create_record_round_trip_over_http() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "app.bsky.feed.post",
            "rkey": "abc",
            "record": {"text": "hello"}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["uri"], "at://did:plc:alice/app.bsky.feed.post/abc");
    assert!(body["cid"].as_str().is_some());
    assert!(body["commit"]["cid"].as_str().is_some());

    // Read it back via the read endpoint.
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=app.bsky.feed.post&rkey=abc",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["text"], "hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_without_auth_rejected() {
    let (app, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": "did:plc:alice", "collection": "x.y.z", "rkey": "k", "record": {}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_account_write_rejected() {
    let (app, _tmp) = build_app().await;
    // Two accounts.
    let alice_token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    let _ = create_account_and_token(&app, "did:plc:bob", "bob.example").await;

    // Alice tries to write to bob's repo.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:bob",
            "collection": "x.y.z",
            "rkey": "k",
            "record": {}
        }),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_then_delete_round_trip() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.putRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "c.col",
            "rkey": "k",
            "record": {"v": 1}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Update it.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.putRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "c.col",
            "rkey": "k",
            "record": {"v": 2}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete it.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.deleteRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "c.col",
            "rkey": "k"
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify gone.
    let (status, _) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=c.col&rkey=k",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_atomic_batch() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "writes": [
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "c.col", "rkey": "a", "value": {"v": 1}},
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "c.col", "rkey": "b", "value": {"v": 2}},
                {"$type": "com.atproto.repo.applyWrites#create",
                 "collection": "c.col", "rkey": "c", "value": {"v": 3}},
            ]
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["results"].as_array().unwrap().len(), 3);
    // One commit covers the whole batch, reported once at the top level.
    // Per-result `commit` is not part of the `applyWrites` result union — the
    // members are `#createResult`, `#updateResult` and `#deleteResult`, and
    // each carries a `$type` naming which it is.
    assert!(body["commit"]["rev"].as_str().is_some());
    for result in body["results"].as_array().unwrap() {
        assert!(
            result["$type"]
                .as_str()
                .is_some_and(|t| t.starts_with("com.atproto.repo.applyWrites#")),
            "each result is a discriminated union member: {result}"
        );
        assert!(result.get("commit").is_none());
    }

    // Verify the records are listable.
    let (status, list) = get_json(
        app,
        "/xrpc/com.atproto.repo.listRecords?repo=did:plc:alice&collection=c.col",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["records"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_with_auto_rkey_generates_tid() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "app.bsky.feed.post",
            "record": {"text": "hi"}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let uri = body["uri"].as_str().unwrap();
    // TID rkeys are 13 chars.
    let rkey = uri.split('/').next_back().unwrap();
    assert_eq!(rkey.len(), 13);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_create_rejected_over_http() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "c.col",
            "rkey": "k",
            "record": {}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "c.col",
            "rkey": "k",
            "record": {}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn write_advances_latest_commit_endpoint() {
    let (app, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    // Pre-write: no commits → 404.
    let (status, _) = get_json(
        app.clone(),
        "/xrpc/com.atproto.sync.getLatestCommit?did=did:plc:alice",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Write a record.
    let _ = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "x.y.z",
            "rkey": "k",
            "record": {}
        }),
        Some(&token),
    )
    .await;

    // Now getLatestCommit returns the commit.
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.sync.getLatestCommit?did=did:plc:alice",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["cid"].as_str().is_some());
    assert!(body["rev"].as_str().is_some());
}
