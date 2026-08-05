//! Membership enforcement on the space write endpoints.
//!
//! Space writes over XRPC are authorised by OAuth scopes, and
//! `assert_space_scope` opens with `if !subject.is_oauth() { return Ok(()) }`.
//! An app-password session is not OAuth: it carries no scopes and is
//! full-authority over its own account, so the assertion has nothing to assert
//! and returns success. Underneath it the writer checks only that the space is
//! not tombstoned, and `SpaceRepo` storage creates the space row on demand.
//!
//! Nothing in that chain asks whether the caller belongs to the space. The
//! same hole was found and closed in the portal's browser; these endpoints are
//! the wider version of it, because app passwords are what account holders
//! hand to third-party clients.
//!
//! What a non-member could do is bounded but real: `require_repo_matches_subject`
//! keeps them writing into their *own* repository, so this is not a way to put
//! records in someone else's. It is a way to hold records filed under a space
//! they have no claim to, which sync will then offer to that space's members.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
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

const JWT_SECRET: &[u8] = b"test-secret-do-not-use-in-prod-32!";
const OWNER_DID: &str = "did:plc:spaceownerfixture00000000000";
const OWNER_HANDLE: &str = "owner.test.example";
const OUTSIDER_DID: &str = "did:plc:spaceoutsiderfixture000000000";
const OUTSIDER_HANDLE: &str = "outsider.test.example";
const COLLECTION: &str = "app.bsky.feed.post";

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

    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        JWT_SECRET.to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);

    (build_router(state), manager, tmp)
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// An app-password session token — no OAuth scopes, full account authority.
async fn app_password_session(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .expect("fixture account");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("fixture password");
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": handle, "password": "pw"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSession failed: {body}");
    body["accessJwt"].as_str().unwrap().to_string()
}

/// Owner creates a space; returns its URI and the outsider's session token.
async fn owner_space_and_an_outsider(
    app: &axum::Router,
    manager: &AccountManager,
) -> (String, String) {
    let owner_token = app_password_session(app, manager, OWNER_DID, OWNER_HANDLE).await;
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group", "skey": "default"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSpace failed: {body}");
    let uri = body["uri"].as_str().unwrap().to_string();

    let outsider_token = app_password_session(app, manager, OUTSIDER_DID, OUTSIDER_HANDLE).await;
    (uri, outsider_token)
}

/// A non-member cannot put a record into someone else's space.
#[tokio::test(flavor = "multi_thread")]
async fn put_record_refuses_a_non_member() {
    let (app, manager, _tmp) = build_app().await;
    let (space, outsider) = owner_space_and_an_outsider(&app, &manager).await;

    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.space.putRecord",
        json!({
            "repo": OUTSIDER_DID,
            "space": space,
            "collection": COLLECTION,
            "rkey": "3kaaaaaaaaaa2",
            "record": {"$type": COLLECTION, "text": "intruder"},
        }),
        Some(&outsider),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-member wrote into a space with an app-password session: {body}"
    );
}

/// The same for `applyWrites`, which takes a batch.
#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_refuses_a_non_member() {
    let (app, manager, _tmp) = build_app().await;
    let (space, outsider) = owner_space_and_an_outsider(&app, &manager).await;

    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": OUTSIDER_DID,
            "space": space,
            "writes": [{
                "action": "create",
                "collection": COLLECTION,
                "rkey": "3kaaaaaaaaaa3",
                "value": {"$type": COLLECTION, "text": "intruder"},
            }],
        }),
        Some(&outsider),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-member batch-wrote into a space: {body}"
    );
}

/// And for deletes.
#[tokio::test(flavor = "multi_thread")]
async fn delete_record_refuses_a_non_member() {
    let (app, manager, _tmp) = build_app().await;
    let (space, outsider) = owner_space_and_an_outsider(&app, &manager).await;

    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.space.deleteRecord",
        json!({
            "repo": OUTSIDER_DID,
            "space": space,
            "collection": COLLECTION,
            "rkey": "3kaaaaaaaaaa2",
        }),
        Some(&outsider),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-member deleted from a space: {body}"
    );
}

/// The owner is a member and must still be able to write.
///
/// The guard has to refuse strangers without refusing the people the space is
/// for — a check that turned every space write into a 403 would pass the tests
/// above and be worthless.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_can_still_write() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token = app_password_session(&app, &manager, OWNER_DID, OWNER_HANDLE).await;
    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group", "skey": "default"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSpace failed: {body}");
    let space = body["uri"].as_str().unwrap().to_string();

    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.space.putRecord",
        json!({
            "repo": OWNER_DID,
            "space": space,
            "collection": COLLECTION,
            "rkey": "3kaaaaaaaaaa2",
            "record": {"$type": COLLECTION, "text": "mine"},
        }),
        Some(&owner_token),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the space owner was refused a write to their own space: {body}"
    );
}

/// A space whose authority is not on this server is not refused.
///
/// Membership lives in the authority's per-actor store. For a cross-PDS space
/// that store is not here, and `is_member` would open an empty database, find
/// no row, and call every legitimate remote member a stranger — turning a
/// check meant to stop outsiders into an outage for cross-host spaces.
///
/// So the guard runs only where it can answer. This is what says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_authority_is_deferred_to_rather_than_refused() {
    let (app, manager, _tmp) = build_app().await;
    let token = app_password_session(&app, &manager, OUTSIDER_DID, OUTSIDER_HANDLE).await;

    let (status, body) = post_json(
        &app,
        "/xrpc/com.atproto.space.putRecord",
        json!({
            "repo": OUTSIDER_DID,
            // An authority with no account, and so no store, on this server.
            "space": "at://did:plc:authorityonanotherpds000000/space/app.bsky.group/default",
            "collection": COLLECTION,
            "rkey": "3kaaaaaaaaaa4",
            "record": {"$type": COLLECTION, "text": "cross-host"},
        }),
        Some(&token),
    )
    .await;

    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "a cross-PDS space write was refused as though the caller were a \
         non-member, which this server cannot know: {body}"
    );
}
