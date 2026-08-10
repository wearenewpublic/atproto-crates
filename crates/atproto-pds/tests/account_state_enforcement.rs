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
use atproto_pds::account::{AccountDirectory, AccountManager, AccountState, CreateAccountParams};
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

async fn create_account(app: &axum::Router, manager: &AccountManager) -> String {
    // Created through the internal API rather than the XRPC endpoint. That
    // endpoint now requires a service-auth token proving control of the DID,
    // signed by a key published in the DID's own document, which a test DID
    // cannot have. Fixture setup is not the thing under test; where
    // `createAccount` itself is the subject, the test calls the endpoint.
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(DID, "pw")
        .await
        .expect("fixture account needs a session password");
    session_token(app, HANDLE).await
}

/// Write a record, returning its rkey so `getRecord` can ask for a real one.
/// Write a record, optionally referencing `blob_cid`.
///
/// A public record referencing the blob is what makes the blob publicly
/// fetchable: `sync.getBlob` serves only blobs a public record names, because
/// `repo_blob` holds permissioned bytes alongside public ones. An
/// uploaded-but-unreferenced blob is not public, so a fixture that skipped the
/// reference would be asserting against a 404 that is correct.
async fn write_a_record_rkey_with_blob(
    app: &axum::Router,
    token: &str,
    blob_cid: Option<&str>,
) -> String {
    let mut record = json!({ "$type": "app.bsky.feed.post", "text": "hello" });
    if let Some(cid) = blob_cid {
        record["embed"] = json!({
            "$type": "blob",
            "ref": { "$link": cid },
            "mimeType": "image/png",
            "size": 16,
        });
    }
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": DID,
                "collection": "app.bsky.feed.post",
                "record": record,
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

/// The same, as an authenticated caller.
async fn get_as(app: &axum::Router, path: &str, token: &str) -> StatusCode {
    let request = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
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
    let token = create_account(&app, &manager).await;

    // Upload the blob first, then write a record that references it. The
    // reference is what makes the blob publicly fetchable — an
    // uploaded-but-unreferenced blob is 404 from `sync.getBlob` by design.
    let blob_cid = upload_a_blob(&app, &token).await;
    let rkey = write_a_record_rkey_with_blob(&app, &token, Some(&blob_cid)).await;

    // Every path answers before the takedown, so a refusal afterwards is the
    // takedown and not a route that never worked or a CID that never existed.
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
        (AccountState::Deactivated, "RepoDeactivated"),
    ] {
        let (app, manager, _tmp) = build_app().await;
        let token = create_account(&app, &manager).await;
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
    let token = create_account(&app, &manager).await;
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

    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(DID, "pw")
        .await
        .expect("fixture account needs a session password");
    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "identifier": HANDLE, "password": "pw" })).unwrap(),
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
    let token = create_account(&app, &manager).await;
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
    let token = create_account(&app, &manager).await;
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

/// Activation is gated on the DID document naming this server.
///
/// This is the last step of an inbound migration. Without the gate an account
/// activates while its DID still names the source PDS, and two servers both
/// consider themselves authoritative for one identity — both answer
/// `describeRepo` and `getRepo`, both sequence commits, and nothing reconciles
/// it afterwards.
///
/// The directory configured here does not resolve the test DID, which
/// exercises the unresolvable arm: activation refuses rather than assuming.
/// Assuming is what the endpoint used to do for every account.
#[tokio::test(flavor = "multi_thread")]
async fn activation_refuses_when_the_did_document_cannot_be_checked() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store.clone(),
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));

    // A directory on a reserved-for-documentation address, so the lookup fails
    // rather than reaching anything real.
    let plc = Arc::new(atproto_pds::plc::PlcService::new(
        atproto_pds::plc::PlcConfig::new(
            "192.0.2.1:1".to_string(),
            "did:web:test.example".to_string(),
            "https://test.example".to_string(),
        ),
        key_store,
    ));

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_plc_service(plc);
    let app = build_router(state);

    let token = create_account(&app, &manager).await;
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
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "activation proceeded without verifying the DID document",
    );

    assert_eq!(
        manager.account_state(DID).await.unwrap(),
        Some(AccountState::Deactivated),
        "the account activated anyway",
    );
}

/// A deactivated repository is not served to the public.
///
/// Every endpoint that reads repository contents declares `RepoDeactivated`
/// and none of them could raise it: the read gate treated deactivated as
/// publicly readable, so a repository its owner had withdrawn was served in
/// full to anyone who asked. The same gap covered an account being migrated
/// *in*, which is deactivated for the whole window in which its repository is
/// half imported.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_repository_is_not_served_to_the_public() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager).await;
    let blob_cid = upload_a_blob(&app, &token).await;
    let rkey = write_a_record_rkey_with_blob(&app, &token, Some(&blob_cid)).await;
    let block_cid = head_commit_cid(&app).await;

    // Answering first, so a refusal afterwards is the state and not a route
    // that never worked.
    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        assert!(
            get(&app, &path).await.is_success(),
            "{path} did not serve an active repository"
        );
    }

    manager
        .set_state(DID, AccountState::Deactivated)
        .await
        .unwrap();

    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        assert_eq!(
            get(&app, &path).await,
            StatusCode::BAD_REQUEST,
            "{path} still served a deactivated repository to an anonymous caller"
        );
    }
}

/// Its owner still reads it.
///
/// Deactivation is a pause, not a lock: an account holder who cannot reach
/// their own repository cannot export it, and the migration path imports into
/// an account that stays deactivated until it is activated -- so the owner
/// carve-out is what makes the state usable rather than a trap. Takedown and
/// suspension have no such carve-out, because those are not the account
/// holder's decision.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_repository_is_still_served_to_its_owner() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager).await;
    let blob_cid = upload_a_blob(&app, &token).await;
    let rkey = write_a_record_rkey_with_blob(&app, &token, Some(&blob_cid)).await;
    let block_cid = head_commit_cid(&app).await;

    manager
        .set_state(DID, AccountState::Deactivated)
        .await
        .unwrap();

    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        assert!(
            get_as(&app, &path, &token).await.is_success(),
            "{path} refused the account its own repository while deactivated"
        );
    }
}

/// A takedown is not undone by holding the account's own token.
///
/// The owner carve-out is for deactivation alone. Reading it as "an
/// authenticated caller sees more" would hand every taken-down account a way
/// to keep serving the content that was taken down.
#[tokio::test(flavor = "multi_thread")]
async fn a_takedown_is_not_lifted_by_the_owners_token() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager).await;
    let blob_cid = upload_a_blob(&app, &token).await;
    let rkey = write_a_record_rkey_with_blob(&app, &token, Some(&blob_cid)).await;
    let block_cid = head_commit_cid(&app).await;

    manager
        .set_state(DID, AccountState::Takendown)
        .await
        .unwrap();

    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        assert_eq!(
            get_as(&app, &path, &token).await,
            StatusCode::BAD_REQUEST,
            "{path} served a taken-down repository to the account itself"
        );
    }
}

/// Another account's token buys nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_deactivated_repository_is_not_served_to_a_different_account() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager).await;
    let blob_cid = upload_a_blob(&app, &token).await;
    let rkey = write_a_record_rkey_with_blob(&app, &token, Some(&blob_cid)).await;
    let block_cid = head_commit_cid(&app).await;

    manager
        .create_account(CreateAccountParams::new(
            "did:plc:onlooker",
            "onlooker.test.example",
            "pw",
        ))
        .await
        .unwrap();
    manager
        .set_primary_password("did:plc:onlooker", "pw")
        .await
        .unwrap();
    let other = session_token(&app, "onlooker.test.example").await;

    manager
        .set_state(DID, AccountState::Deactivated)
        .await
        .unwrap();

    for path in public_read_paths(&blob_cid, &block_cid, &rkey) {
        assert_eq!(
            get_as(&app, &path, &other).await,
            StatusCode::BAD_REQUEST,
            "{path} served a deactivated repository to an unrelated account"
        );
    }
}
