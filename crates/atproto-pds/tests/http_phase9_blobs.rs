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
    // The typed lexicon envelope: `$type`, a nested `ref` cid-link, `mimeType`
    // and `size`. This is what a client embeds verbatim into a record value,
    // so the shape returned here is the shape the reference validator sees.
    let blob = &body["blob"];
    assert_eq!(blob["$type"], "blob", "blob envelope: {blob}");
    let link = blob["ref"]["$link"].as_str().unwrap_or_else(|| {
        panic!("blob ref must nest the CID under `ref.$link`, got {blob}");
    });
    assert!(link.starts_with("bafkrei") || link.starts_with("bafy"));
    assert_eq!(blob["mimeType"], "image/png");
    assert!(blob["size"].as_u64().unwrap() > 0);
    assert!(
        blob.get("$link").is_none(),
        "`$link` must not appear at the top level of the envelope: {blob}"
    );
    assert_eq!(blob.as_object().unwrap().len(), 4);
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

/// An uploaded blob must never render as a document on this origin.
///
/// The MIME type comes from the client's `content-type` header and is not
/// validated, so a caller can declare `text/html`. This origin also serves the
/// OAuth consent screen and session cookies, so a blob that renders is stored
/// XSS against the authorization server — a victim who opens the blob URL runs
/// the uploader's script with this origin's cookies in scope.
///
/// Three headers together prevent it: `nosniff` stops a browser second-guessing
/// a benign declared type, `content-disposition: attachment` makes the response
/// a download rather than a document, and the CSP neuters it if it is rendered
/// anyway.
#[tokio::test(flavor = "multi_thread")]
async fn get_blob_refuses_to_render_as_a_document() {
    let (app, _tmp) = build_app().await;
    let did = "did:plc:blobxss";
    let token = create_account(&app, did, "xss.test.example").await;

    // Upload something a browser would happily execute, declared as such.
    let payload = b"<script>alert(document.domain)</script>".to_vec();
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "text/html")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(payload))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let cid = body["blob"]["ref"]["$link"]
        .as_str()
        .or_else(|| body["blob"]["$link"].as_str())
        .expect("uploadBlob should return the blob ref")
        .to_string();

    let request = Request::builder()
        .uri(format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();

    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "without nosniff a browser may execute a blob whose declared type is benign"
    );
    let disposition = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        disposition.starts_with("attachment"),
        "a blob must download, not render; content-disposition was {disposition:?}"
    );
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        csp.contains("default-src 'none'") && csp.contains("sandbox"),
        "the CSP must neuter a blob that is rendered anyway; was {csp:?}"
    );
}
