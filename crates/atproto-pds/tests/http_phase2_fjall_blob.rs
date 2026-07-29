//! acceptance — fjall-backed blob round-trip.
//!
//! Verifies that with a `PublicRealmBackend::fjall(...)` wired into
//! `HttpState`, the `uploadBlob` / `getBlob` / `listBlobs` /
//! `listMissingBlobs` HTTP handlers dispatch through the
//! `BlobStorage` trait against a fjall keyspace — not through the
//! legacy SQLite-direct path.

#![cfg(feature = "fjall")]

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::actor_store::{PublicRealmBackend, fjall::FjallActorStore};
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

async fn build_fjall_app() -> (axum::Router, TempDir) {
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

    // Open a fjall store rooted under the temp dir + wire it into a
    // `PublicRealmBackend`. The handlers dispatch through this backend
    // for blob ops.
    let fjall_root = dir.join("fjall");
    std::fs::create_dir_all(&fjall_root).unwrap();
    let fjall_store = FjallActorStore::open(&fjall_root).unwrap();
    let backend = PublicRealmBackend::fjall(fjall_store);
    assert_eq!(backend.backend_label, "fjall");

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_public_realm_backend(backend);
    (build_router(state), manager, tmp)
}

async fn create_account_session(app: &axum::Router) -> String {
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

async fn post_blob(app: axum::Router, token: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/png")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(bytes))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn fjall_blob_upload_get_list_round_trip() {
    let (app, _tmp) = build_fjall_app().await;
    let token = create_account_session(&app).await;

    // Upload.
    let (status, body) = post_blob(app.clone(), &token, b"hello fjall".to_vec()).await;
    assert_eq!(status, StatusCode::OK, "uploadBlob body: {body}");
    let cid = body["blob"]["$link"].as_str().unwrap().to_string();
    assert!(cid.starts_with("bafkrei") || cid.starts_with("bafy"));
    assert_eq!(body["blob"]["size"], 11);

    // getBlob — verify the bytes round-trip through the fjall keyspace.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.sync.getBlob?did=did:plc:alice&cid={cid}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mime = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(mime, "image/png");
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(body, b"hello fjall");

    // listBlobs reports the new CID.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.sync.listBlobs?did=did:plc:alice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let listed: Vec<&str> = body["cids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(listed, vec![cid.as_str()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn fjall_blob_get_unknown_returns_404() {
    let (app, _tmp) = build_fjall_app().await;
    let _ = create_account_session(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.sync.getBlob?did=did:plc:alice&cid=bafkreig999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn fjall_blob_upload_idempotent() {
    let (app, _tmp) = build_fjall_app().await;
    let token = create_account_session(&app).await;
    let (s1, b1) = post_blob(app.clone(), &token, b"abc".to_vec()).await;
    let (s2, b2) = post_blob(app, &token, b"abc".to_vec()).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b1["blob"]["$link"], b2["blob"]["$link"]);
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
