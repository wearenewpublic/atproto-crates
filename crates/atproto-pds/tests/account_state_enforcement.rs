//! A takedown has to take something down.
//!
//! Account state was enforced on two public read paths and nowhere else, so a
//! moderation action removed record-level reads while the account's complete
//! repository CAR, its raw blocks and every blob stayed anonymously
//! downloadable — and the account kept writing, kept refreshing its session,
//! and could restore itself with one unprivileged call.
//!
//! These tests assert the whole surface rather than one endpoint each, because
//! the defect was never in any single handler: it was that the check existed in
//! two places and the other nine did not have it.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, AccountState};
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

const DID: &str = "did:plc:subject";
const HANDLE: &str = "subject.test.example";

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

async fn create_account(app: &axum::Router) -> String {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": DID, "handle": HANDLE, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"].as_str().unwrap().to_string()
}

/// Write a record, returning its rkey so `getRecord` can ask for a real one.
async fn write_a_record_rkey(app: &axum::Router, token: &str) -> String {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": DID,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hello" }
            }))
            .unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let uri = body["uri"].as_str().expect("createRecord returns a uri");
    uri.rsplit('/').next().unwrap().to_string()
}

async fn write_a_record(app: &axum::Router, token: &str) -> StatusCode {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": DID,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hello" }
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

/// Upload a blob and return its CID, so `getBlob` has something real to serve.
async fn upload_a_blob(app: &axum::Router, token: &str) -> String {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/png")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(b"not really a png".to_vec()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["blob"]["ref"]["$link"]
        .as_str()
        .or_else(|| body["blob"]["$link"].as_str())
        .expect("uploadBlob should return a blob ref")
        .to_string()
}

/// The head commit CID, which is a real block `getBlocks` can return.
async fn head_commit_cid(app: &axum::Router) -> String {
    let request = Request::builder()
        .uri(format!("/xrpc/com.atproto.sync.getLatestCommit?did={DID}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["cid"]
        .as_str()
        .expect("a written repo has a head")
        .to_string()
}

async fn get(app: &axum::Router, path: &str) -> StatusCode {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

/// Every public read path a repository exposes.
fn public_read_paths(blob_cid: &str, block_cid: &str, rkey: &str) -> Vec<String> {
    vec![
        format!(
            "/xrpc/com.atproto.repo.getRecord?repo={DID}&collection=app.bsky.feed.post&rkey={rkey}"
        ),
        format!("/xrpc/com.atproto.repo.listRecords?repo={DID}&collection=app.bsky.feed.post"),
        format!("/xrpc/com.atproto.repo.describeRepo?repo={DID}"),
        format!("/xrpc/com.atproto.sync.getRepo?did={DID}"),
        format!("/xrpc/com.atproto.sync.getBlocks?did={DID}&cids={block_cid}"),
        format!("/xrpc/com.atproto.sync.getLatestCommit?did={DID}"),
        format!("/xrpc/com.atproto.sync.getBlob?did={DID}&cid={blob_cid}"),
        format!("/xrpc/com.atproto.sync.listBlobs?did={DID}"),
    ]
}

/// A takedown must close every public read path, not two of them.
///
/// A takedown for illegal content that leaves the repository CAR, the raw
/// blocks and the blobs anonymously downloadable has not removed the content.
#[tokio::test(flavor = "multi_thread")]
async fn a_takedown_closes_every_public_read_path() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app).await;
    let rkey = write_a_record_rkey(&app, &token).await;

    // Every path answers before the takedown, so a refusal afterwards is the
    // takedown and not a route that never worked or a CID that never existed.
    let blob_cid = upload_a_blob(&app, &token).await;
    let block_cid = head_commit_cid(&app).await;
    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        let status = get(&app, &path).await;
        assert!(
            status.is_success(),
            "{path} did not serve an active repository ({status}); a later \
             refusal would prove nothing"
        );
    }

    manager
        .set_state(DID, AccountState::Takendown)
        .await
        .unwrap();

    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        let status = get(&app, &path).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{path} still served a taken-down repository"
        );
    }
}

/// The refusal names the state, because a caller acts on which one it got.
#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_names_the_state() {
    for (state, expected) in [
        (AccountState::Takendown, "RepoTakendown"),
        (AccountState::Suspended, "RepoSuspended"),
    ] {
        let (app, manager, _tmp) = build_app().await;
        let token = create_account(&app).await;
        write_a_record(&app, &token).await;
        manager.set_state(DID, state).await.unwrap();

        let request = Request::builder()
            .uri(format!("/xrpc/com.atproto.sync.getRepo?did={DID}"))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap_or(Value::Null);
        assert_eq!(
            body["error"], expected,
            "{state} should surface as {expected}: {body}"
        );
    }
}

/// A taken-down account cannot write.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_down_account_cannot_write() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app).await;
    assert_eq!(write_a_record(&app, &token).await, StatusCode::OK);

    manager
        .set_state(DID, AccountState::Takendown)
        .await
        .unwrap();
    assert_eq!(
        write_a_record(&app, &token).await,
        StatusCode::FORBIDDEN,
        "the access token was minted before the takedown and still worked"
    );
}

/// A taken-down account cannot refresh its way back to a working token.
///
/// Without this, the write gate above is bounded by the refresh TTL rather than
/// by the moderation action: a 90-day token minted before a takedown keeps
/// producing access tokens for 90 days after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_down_account_cannot_refresh() {
    let (app, manager, _tmp) = build_app().await;

    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": DID, "handle": HANDLE, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let refresh = body["refreshJwt"].as_str().unwrap().to_string();

    manager
        .set_state(DID, AccountState::Takendown)
        .await
        .unwrap();

    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.refreshSession")
        .method("POST")
        .header("authorization", format!("Bearer {refresh}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a refresh token minted before the takedown still rotated"
    );
}

/// A taken-down account cannot restore itself.
///
/// `activateAccount` took no account state into consideration, so an admin
/// takedown was reversible by its subject with one unprivileged call.
#[tokio::test(flavor = "multi_thread")]
async fn a_taken_down_account_cannot_activate_itself() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app).await;
    manager
        .set_state(DID, AccountState::Takendown)
        .await
        .unwrap();

    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.activateAccount")
        .method("POST")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a taken-down account restored itself"
    );

    assert_eq!(
        manager.account_state(DID).await.unwrap(),
        Some(AccountState::Takendown),
        "state changed anyway"
    );
}

/// Deactivation stays self-service.
///
/// It is a pause the user chose, not a moderation decision, and the whole
/// inbound-migration flow depends on being able to undo it.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_account_can_still_activate_itself() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app).await;
    manager
        .set_state(DID, AccountState::Deactivated)
        .await
        .unwrap();

    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.activateAccount")
        .method("POST")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert!(
        app.clone()
            .oneshot(request)
            .await
            .unwrap()
            .status()
            .is_success(),
        "a deactivated account could not reactivate itself"
    );
}

/// An unknown DID materialises no storage.
///
/// `SqlActorStore::open` runs `create_dir_all` and migrations, so a blob
/// handler that opened the store before checking the account let any
/// unauthenticated caller create a SQLite file per DID it cared to invent.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_did_creates_no_store() {
    let (app, _manager, tmp) = build_app().await;

    let before: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    for path in [
        "/xrpc/com.atproto.sync.getBlob?did=did:plc:invented&cid=bafyx",
        "/xrpc/com.atproto.sync.listBlobs?did=did:plc:invented",
        "/xrpc/com.atproto.sync.getRepo?did=did:plc:invented",
    ] {
        let status = get(&app, path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    let after: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();

    assert_eq!(
        before.len(),
        after.len(),
        "an unauthenticated request for an invented DID created storage on disk"
    );
}
