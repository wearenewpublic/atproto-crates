//! HTTP integration tests for `com.atproto.repo.uploadBlob` +
//! `listMissingBlobs`. Together with `migration_e2e` these cover the audit
//! follow-up that previously had `listMissingBlobs` returning an unconditional
//! empty list.

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
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), tmp)
}

async fn create_account(app: &axum::Router, did: &str, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "did": did,
                "handle": handle,
                "password": "pw",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_blob_round_trip() {
    let (app, _tmp) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;

    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "image/png")
        .body(Body::from(b"\x89PNG\r\n\x1a\nfake-png-bytes".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let link = body["blob"]["$link"].as_str().unwrap();
    assert!(link.starts_with("bafkrei") || link.starts_with("bafy"));
    assert_eq!(body["blob"]["mimeType"], "image/png");
    let actual_size = body["blob"]["size"].as_u64().unwrap();
    assert!(actual_size > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_blob_requires_auth() {
    let (app, _tmp) = build_app().await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/png")
        .body(Body::from(b"some-bytes".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_missing_blobs_starts_empty() {
    let (app, _tmp) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.listMissingBlobs")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["blobs"].as_array().unwrap().len(), 0);
}
