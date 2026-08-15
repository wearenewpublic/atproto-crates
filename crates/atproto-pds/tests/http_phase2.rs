//! Phase 2 integration tests — exercise the read-only HTTP router end-to-end.
//!
//! Uses `tower::ServiceExt::oneshot` to drive requests through the axum
//! router without binding to a network port.

use atproto_dasl::cid::compute_cid;
use atproto_dasl::storage::BlockStorage;
use atproto_pds::account::{AccountDirectory, AccountRow, AccountState};
use atproto_pds::actor_store::PublicRealmBackend;
use atproto_pds::actor_store::sql::{SqlActorStore, SqlBlockStorage};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::repo::RepoReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

/// Open an accounts directory under `dir` holding one active account.
async fn seed_accounts(dir: &std::path::Path) -> AccountDirectory {
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
    accounts
}

async fn build_app() -> (axum::Router, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = seed_accounts(&dir).await;

    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::new(reader);
    let app = build_router(state);
    (app, tmp)
}

/// Build the router with the reader wired the way `bin/pds.rs` wires it —
/// [`RepoReader::with_backend`] over a `PublicRealmBackend` — rather than the
/// legacy `RepoReader::new` branch every other test in this file uses.
async fn build_app_with_backend() -> (axum::Router, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = seed_accounts(&dir).await;

    let backend = Arc::new(PublicRealmBackend::sql(dir.clone()));
    let reader = Arc::new(RepoReader::with_backend(accounts, dir.clone(), backend));
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

/// The health response is `version` and `status`, and nothing else.
///
/// Asserted as an exact key set rather than by naming the fields that must be
/// absent, because the thing being prevented is a field nobody thought to
/// forbid. This endpoint is unauthenticated, so anything added here is
/// published to the world; it once carried the SetHash implementation name,
/// which told an anonymous caller which of a protocol's optional
/// constructions to attempt against this server.
///
/// A build identifier is the exception and stays: it says which build is
/// running, not what the build can do.
#[tokio::test(flavor = "multi_thread")]
async fn xrpc_health_publishes_no_capabilities() {
    let (app, _tmp) = build_app().await;
    let (_, body) = get_json(app, "/xrpc/_health").await;
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("the health response is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["status", "version"],
        "the health response gained a field; if it names a capability it does \
         not belong in an unauthenticated endpoint, and if it names the \
         deployment it belongs in `version`"
    );
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

/// `com.atproto.repo.getRecord` declares exactly one error, `RecordNotFound`.
/// It used to answer with `NotFound`, a name that appears in no lexicon, so a
/// client matching on the declared name matched nothing.
#[tokio::test(flavor = "multi_thread")]
async fn get_record_missing_returns_400() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=x.y.z&rkey=absent",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RecordNotFound", "body: {body}");
}

/// A record that existed and was removed reads back the same way as one that
/// never existed: the lexicon has one name for both.
#[tokio::test(flavor = "multi_thread")]
async fn get_record_after_delete_returns_record_not_found() {
    let (app, tmp) = build_app().await;
    seed_record(
        tmp.path(),
        "did:plc:alice",
        "app.bsky.feed.post",
        "gone",
        serde_json::json!({"text": "bye"}),
    )
    .await;
    let store = SqlActorStore::open(tmp.path(), "did:plc:alice")
        .await
        .unwrap();
    sqlx::query("DELETE FROM repo_record WHERE collection = ? AND rkey = ?")
        .bind("app.bsky.feed.post")
        .bind("gone")
        .execute(store.pool())
        .await
        .unwrap();
    drop(store);

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=app.bsky.feed.post&rkey=gone",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RecordNotFound", "body: {body}");
}

/// The same answer over the wiring the running server uses. `bin/pds.rs`
/// builds the reader with `RepoReader::with_backend`, so the missing-record
/// path there goes through `PublicRealmBackend::repo_record`, not the SQL
/// branch the tests above take. This pins the name end to end on the
/// production constructor, so refactoring it cannot bypass the fix and still
/// leave the suite green.
#[tokio::test(flavor = "multi_thread")]
async fn get_record_missing_returns_record_not_found_through_backend_wiring() {
    let (app, tmp) = build_app_with_backend().await;
    seed_record(
        tmp.path(),
        "did:plc:alice",
        "app.bsky.feed.post",
        "here",
        serde_json::json!({"text": "hi"}),
    )
    .await;

    // Positive control: reads do resolve through this wiring, so the 400 below
    // is about the record being absent rather than the backend being inert.
    let (ok_status, ok_body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=app.bsky.feed.post&rkey=here",
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "body: {ok_body}");
    assert_eq!(ok_body["value"]["text"], "hi", "body: {ok_body}");

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=app.bsky.feed.post&rkey=absent",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RecordNotFound", "body: {body}");
}

/// A repository this server does not host is not `RecordNotFound` — claiming
/// it would say the repo is here and the record is not. `getRecord` names no
/// error for it, so it degrades to the generic `InvalidRequest`, which is what
/// the reference implementation returns for the same case.
#[tokio::test(flavor = "multi_thread")]
async fn get_record_unknown_repo_returns_invalid_request() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:doesnotexist&collection=x.y.z&rkey=k",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest", "body: {body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("did:plc:doesnotexist"),
        "body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_paginates_over_http() {
    let (app, tmp) = build_app().await;
    for r in ["a", "b", "c"] {
        seed_record(
            tmp.path(),
            "did:plc:alice",
            "com.example.record",
            r,
            serde_json::json!({"r": r}),
        )
        .await;
    }
    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.listRecords?repo=did:plc:alice&collection=com.example.record&limit=2",
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
