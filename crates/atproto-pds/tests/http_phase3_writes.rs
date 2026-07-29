//! Phase 3 HTTP integration tests — write endpoints.

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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);
    (app, manager, tmp)
}

async fn create_account_and_token(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
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
async fn create_record_round_trip_over_http() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

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
    let (app, _manager, _tmp) = build_app().await;
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
    let (app, manager, _tmp) = build_app().await;
    // Two accounts.
    let alice_token =
        create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:bob", "bob.example").await;

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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

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

// ---------------------------------------------------------------------------
//  swapCommit (F-REC-04).
//
//  Declared on all four write methods and never read, so two clients that each
//  read, decided and wrote both received HTTP 200 and the second silently
//  discarded the first's work.
// ---------------------------------------------------------------------------

/// The repo's current commit CID.
async fn head_commit(app: &axum::Router, did: &str, token: &str) -> String {
    let req = Request::builder()
        .uri(format!("/xrpc/com.atproto.sync.getLatestCommit?did={did}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["cid"]
        .as_str()
        .expect("a written repo has a head")
        .to_string()
}

async fn post_with(
    app: &axum::Router,
    token: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn a_post(text: &str) -> Value {
    json!({ "$type": "app.bsky.feed.post", "text": text })
}

/// A stale `swapCommit` is refused on every write method.
///
/// This is the whole point: a client that read the repo, decided something, and
/// is now writing gets told its decision was made against a state that has
/// moved — instead of silently clobbering whoever wrote in between.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_swap_commit_is_refused_on_every_write_path() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:alice";
    let token = create_account_and_token(&app, &manager, did, "alice.example").await;

    // Establish a head, then move it so the captured value is stale.
    post_with(&app, &token, "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "seed", "record": a_post("seed")})).await;
    let stale = head_commit(&app, did, &token).await;
    post_with(&app, &token, "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "moved", "record": a_post("moved")})).await;

    let cases: Vec<(&str, Value)> = vec![
        (
            "/xrpc/com.atproto.repo.createRecord",
            json!({
            "repo": did, "collection": "app.bsky.feed.post", "rkey": "c",
            "record": a_post("c"), "swapCommit": stale }),
        ),
        (
            "/xrpc/com.atproto.repo.putRecord",
            json!({
            "repo": did, "collection": "app.bsky.feed.post", "rkey": "seed",
            "record": a_post("p"), "swapCommit": stale }),
        ),
        (
            "/xrpc/com.atproto.repo.deleteRecord",
            json!({
            "repo": did, "collection": "app.bsky.feed.post", "rkey": "seed",
            "swapCommit": stale }),
        ),
        (
            "/xrpc/com.atproto.repo.applyWrites",
            json!({
            "repo": did, "swapCommit": stale, "writes": [{
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post", "rkey": "b", "value": a_post("b") }] }),
        ),
    ];

    for (path, body) in cases {
        let (status, response) = post_with(&app, &token, path, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{path} accepted a stale swapCommit: {response}"
        );
        assert_eq!(response["error"], "InvalidSwap", "{path}: {response}");
    }
}

/// A current `swapCommit` is accepted on every write method.
///
/// The refusal above is only correct if the guard also lets a well-behaved
/// caller through; a check that refuses everything would pass that test too.
#[tokio::test(flavor = "multi_thread")]
async fn a_current_swap_commit_is_accepted_on_every_write_path() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:alice";
    let token = create_account_and_token(&app, &manager, did, "alice.example").await;

    post_with(&app, &token, "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "seed", "record": a_post("seed")})).await;

    /// Builds a request body around the caller's expected commit.
    type BodyFor = Box<dyn Fn(&str) -> Value>;

    // Each write moves the head, so the guard is re-read every time.
    let paths: Vec<(&str, BodyFor)> = vec![
        (
            "/xrpc/com.atproto.repo.createRecord",
            Box::new(|c: &str| {
                json!({
            "repo": "did:plc:alice", "collection": "app.bsky.feed.post", "rkey": "c",
            "record": { "$type": "app.bsky.feed.post", "text": "c" }, "swapCommit": c })
            }),
        ),
        (
            "/xrpc/com.atproto.repo.putRecord",
            Box::new(|c: &str| {
                json!({
            "repo": "did:plc:alice", "collection": "app.bsky.feed.post", "rkey": "seed",
            "record": { "$type": "app.bsky.feed.post", "text": "p" }, "swapCommit": c })
            }),
        ),
        (
            "/xrpc/com.atproto.repo.applyWrites",
            Box::new(|c: &str| {
                json!({
            "repo": "did:plc:alice", "swapCommit": c, "writes": [{
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post", "rkey": "b",
                "value": { "$type": "app.bsky.feed.post", "text": "b" } }] })
            }),
        ),
        (
            "/xrpc/com.atproto.repo.deleteRecord",
            Box::new(|c: &str| {
                json!({
            "repo": "did:plc:alice", "collection": "app.bsky.feed.post", "rkey": "seed",
            "swapCommit": c })
            }),
        ),
    ];

    for (path, build) in paths {
        let current = head_commit(&app, did, &token).await;
        let (status, response) = post_with(&app, &token, path, build(&current)).await;
        assert!(
            status.is_success(),
            "{path} refused a current swapCommit: {response}"
        );
    }
}

/// Omitting `swapCommit` still writes — the guard is opt-in.
#[tokio::test(flavor = "multi_thread")]
async fn omitting_swap_commit_writes_as_before() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:alice";
    let token = create_account_and_token(&app, &manager, did, "alice.example").await;

    let (status, body) = post_with(&app, &token, "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "x", "record": a_post("x")})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The second of two writers racing on the same read loses, rather than both
/// reporting success.
#[tokio::test(flavor = "multi_thread")]
async fn two_writers_on_one_read_do_not_both_succeed() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:alice";
    let token = create_account_and_token(&app, &manager, did, "alice.example").await;

    post_with(&app, &token, "/xrpc/com.atproto.repo.createRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "seed", "record": a_post("seed")})).await;

    // Both clients read the same head and each writes against it.
    let shared = head_commit(&app, did, &token).await;
    let (first, _) = post_with(
        &app,
        &token,
        "/xrpc/com.atproto.repo.putRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "seed",
               "record": a_post("first writer"), "swapCommit": shared}),
    )
    .await;
    let (second, body) = post_with(
        &app,
        &token,
        "/xrpc/com.atproto.repo.putRecord",
        json!({"repo": did, "collection": "app.bsky.feed.post", "rkey": "seed",
               "record": a_post("second writer"), "swapCommit": shared}),
    )
    .await;

    assert!(first.is_success(), "the first writer should win");
    assert_eq!(
        second,
        StatusCode::BAD_REQUEST,
        "the second writer clobbered the first and was told it succeeded: {body}"
    );

    // And the first writer's value is what survived.
    let req = Request::builder()
        .uri(format!(
            "/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey=seed"
        ))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["value"]["text"], "first writer");
}
