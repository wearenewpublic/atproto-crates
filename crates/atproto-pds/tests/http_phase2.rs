//! Phase 2 integration tests — exercise the read-only HTTP router end-to-end.
//!
//! Uses `tower::ServiceExt::oneshot` to drive requests through the axum
//! router without binding to a network port.

use atproto_dasl::cid::compute_cid;
use atproto_dasl::storage::BlockStorage;
use atproto_pds::account::{AccountDirectory, AccountRow, AccountState};
use atproto_pds::actor_store::sql::{SqlActorStore, SqlBlockStorage};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::repo::RepoReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    accounts
        .insert_account(&AccountRow {
            did: "did:plc:alice".to_string(),
            handle: "alice.example".to_string(),
            email: None,
            email_confirmed_at: None,
            password_hash: "$argon2id$x".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            state: AccountState::Active,
            signing_key_ref: "file:alice".to_string(),
            pds_managed_rotation: true,
        })
        .await
        .unwrap();

    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::new(reader);
    let app = build_router(state);
    (app, tmp)
}

async fn seed_record(
    data_dir: &std::path::Path,
    did: &str,
    collection: &str,
    rkey: &str,
    value: serde_json::Value,
) -> String {
    let store = SqlActorStore::open(data_dir, did).await.unwrap();
    let cbor = atproto_dasl::to_vec(&value).unwrap();
    let cid = compute_cid(&cbor);
    let cid_str = cid.to_string();

    let mut block_storage = SqlBlockStorage::open(store.pool().clone()).await.unwrap();
    block_storage.put(&cid, cbor).await.unwrap();

    let now = chrono::Utc::now().to_rfc3339();
    let uri = format!("at://{}/{}/{}", did, collection, rkey);
    sqlx::query(
        "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at) VALUES (?,?,?,?,?,?)",
    )
    .bind(&uri)
    .bind(&cid_str)
    .bind(collection)
    .bind(rkey)
    .bind("3jui7kd2z2y2e")
    .bind(&now)
    .execute(store.pool())
    .await
    .unwrap();
    cid_str
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn xrpc_health_responds() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(app, "/xrpc/_health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].as_str().unwrap().contains("+"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alive_and_ready() {
    let (app, _tmp) = build_app().await;
    let response_alive = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/_alive")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_alive.status(), StatusCode::OK);

    let response_ready = app
        .oneshot(
            Request::builder()
                .uri("/_ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_ready.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_record_round_trip_over_http() {
    let (app, tmp) = build_app().await;
    let value = serde_json::json!({"text": "hello"});
    seed_record(
        tmp.path(),
        "did:plc:alice",
        "app.bsky.feed.post",
        "abc",
        value.clone(),
    )
    .await;

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=app.bsky.feed.post&rkey=abc",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], value);
    assert_eq!(body["uri"], "at://did:plc:alice/app.bsky.feed.post/abc");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_record_missing_returns_400() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=x.y.z&rkey=absent",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "NotFound");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_paginates_over_http() {
    let (app, tmp) = build_app().await;
    for r in ["a", "b", "c"] {
        seed_record(
            tmp.path(),
            "did:plc:alice",
            "c.col",
            r,
            serde_json::json!({"r": r}),
        )
        .await;
    }
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.listRecords?repo=did:plc:alice&collection=c.col&limit=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert!(body["cursor"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn describe_repo_includes_collections() {
    let (app, tmp) = build_app().await;
    seed_record(
        tmp.path(),
        "did:plc:alice",
        "app.bsky.feed.post",
        "1",
        serde_json::json!({}),
    )
    .await;
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["did"], "did:plc:alice");
    assert_eq!(body["handle"], "alice.example");
    let cols = body["collections"].as_array().unwrap();
    assert!(
        cols.iter()
            .any(|c| c.as_str() == Some("app.bsky.feed.post"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_status_for_active_account() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true);
    assert_eq!(body["did"], "did:plc:alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn handle_resolves_for_lookups() {
    let (app, tmp) = build_app().await;
    seed_record(
        tmp.path(),
        "did:plc:alice",
        "x.y.z",
        "k",
        serde_json::json!({}),
    )
    .await;
    // Use the handle instead of the DID.
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=alice.example&collection=x.y.z&rkey=k",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["uri"], "at://did:plc:alice/x.y.z/k");
}
