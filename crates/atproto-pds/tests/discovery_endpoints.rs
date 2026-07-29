//! Integration tests for the four discovery endpoints.
//!
//! Each returned 404 before these routes existed, and each 404 breaks
//! something concrete: migration stops at step two without `describeServer`,
//! a relay cannot learn what to backfill without `sync.listRepos`, a handle on
//! the server's own domain cannot resolve without `/.well-known/atproto-did`,
//! and peers cannot resolve the server's own `did:web` without
//! `/.well-known/did.json`.

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
    .with_writer(writer)
    .with_service_handle_domains(vec!["test.example".to_string()]);
    (build_router(state), manager, tmp)
}

async fn get(app: axum::Router, path: &str, host: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().uri(path);
    if let Some(h) = host {
        req = req.header("host", h);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let (status, bytes) = get(app, path, None).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create_account(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
    // Created through the internal API rather than the XRPC endpoint. That
    // endpoint now requires a service-auth token proving control of the DID,
    // signed by a key published in the DID's own document, which a test DID
    // cannot have. Fixture setup is not the thing under test; where
    // `createAccount` itself is the subject, the test calls the endpoint.
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

/// Write one record so the account has a commit for `listRepos` to report.
async fn write_a_record(app: &axum::Router, did: &str, token: &str) {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": {"$type": "app.bsky.feed.post", "text": "hello"}
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "createRecord failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn describe_server_reports_did_and_domains() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, body) = get_json(app, "/xrpc/com.atproto.server.describeServer").await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Migration reads `did` from here to learn the `aud` for the service-auth
    // token the old PDS must mint.
    assert_eq!(body["did"], "did:web:test.example");
    assert_eq!(body["availableUserDomains"], json!(["test.example"]));
    assert_eq!(body["inviteCodeRequired"], false);
    assert_eq!(body["phoneVerificationRequired"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_reports_did_head_and_rev() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test.example").await;
    write_a_record(&app, "did:plc:alice", &token).await;

    let (status, body) = get_json(app, "/xrpc/com.atproto.sync.listRepos").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let repos = body["repos"].as_array().expect("repos array");
    assert_eq!(repos.len(), 1, "body: {body}");
    // `head` and `rev` are required by the lexicon — a relay uses them to
    // decide whether it needs to backfill.
    assert_eq!(repos[0]["did"], "did:plc:alice");
    assert!(repos[0]["head"].as_str().unwrap().starts_with("bafy"));
    assert!(!repos[0]["rev"].as_str().unwrap().is_empty());
    assert_eq!(repos[0]["active"], true);
    assert!(
        repos[0].get("status").is_none(),
        "active repos carry no status"
    );
}

/// An account with no commits has no `head` to report, so it is omitted rather
/// than announced with a value a relay would then fail to fetch.
#[tokio::test(flavor = "multi_thread")]
async fn list_repos_omits_accounts_with_no_commits() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.test.example").await;

    let (status, body) = get_json(app, "/xrpc/com.atproto.sync.listRepos").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"].as_array().unwrap().len(), 0, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_reports_inactive_accounts_with_a_status() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test.example").await;
    write_a_record(&app, "did:plc:alice", &token).await;
    manager
        .set_state("did:plc:alice", AccountState::Takendown)
        .await
        .unwrap();

    let (status, body) = get_json(app, "/xrpc/com.atproto.sync.listRepos").await;
    assert_eq!(status, StatusCode::OK);
    let repos = body["repos"].as_array().unwrap();
    assert_eq!(repos[0]["active"], false, "body: {body}");
    assert_eq!(repos[0]["status"], "takendown");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_paginates() {
    let (app, manager, _tmp) = build_app().await;
    for i in 0..3 {
        let did = format!("did:plc:user{i}");
        let token = create_account(&app, &manager, &did, &format!("user{i}.test.example")).await;
        write_a_record(&app, &did, &token).await;
    }

    let (status, body) = get_json(app.clone(), "/xrpc/com.atproto.sync.listRepos?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"].as_array().unwrap().len(), 2, "body: {body}");
    let cursor = body["cursor"]
        .as_str()
        .expect("a full page carries a cursor");

    let (status, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.sync.listRepos?limit=2&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"].as_array().unwrap().len(), 1, "body: {body}");
    assert!(
        body.get("cursor").is_none(),
        "the last page carries no cursor: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn well_known_atproto_did_resolves_a_hosted_handle() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.test.example").await;

    let (status, body) = get(app, "/.well-known/atproto-did", Some("alice.test.example")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(body).unwrap(), "did:plc:alice");
}

/// A port in the `Host` header must not defeat the lookup.
#[tokio::test(flavor = "multi_thread")]
async fn well_known_atproto_did_ignores_the_host_port() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.test.example").await;

    let (status, body) = get(
        app,
        "/.well-known/atproto-did",
        Some("alice.test.example:8443"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(body).unwrap(), "did:plc:alice");
}

/// A resolver has to be able to tell "not here" from "here, but blank".
#[tokio::test(flavor = "multi_thread")]
async fn well_known_atproto_did_404s_for_an_unknown_handle() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = get(app, "/.well-known/atproto-did", Some("nobody.test.example")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn well_known_did_json_serves_the_service_document() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, body) = get_json(app, "/.well-known/did.json").await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["id"], "did:web:test.example");
    let services = body["service"].as_array().expect("service array");
    let pds = services
        .iter()
        .find(|s| s["id"] == "#atproto_pds")
        .expect("an #atproto_pds service entry");
    assert_eq!(pds["type"], "AtprotoPersonalDataServer");
    assert_eq!(pds["serviceEndpoint"], "https://test.example");
}

// ---------------------------------------------------------------------------
//  CORS.
//
//  A browser OAuth client runs on some other origin. Without CORS headers the
//  browser refuses to hand it the response body, so discovery fails before the
//  authorization request is even attempted — and after that, every XRPC call
//  fails the same way.
// ---------------------------------------------------------------------------

/// The routes a browser client has to reach cross-origin.
const CROSS_ORIGIN_ROUTES: &[&str] = &[
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/did.json",
    "/.well-known/atproto-did",
    "/oauth/jwks",
    "/oauth/par",
    "/oauth/token",
    "/oauth/revoke",
    "/xrpc/com.atproto.server.describeServer",
    "/xrpc/com.atproto.repo.createRecord",
    "/xrpc/com.atproto.sync.getBlob",
];

/// A preflight must be answered, and answered without credentials.
///
/// `Allow-Origin: *` together with `Allow-Credentials: true` is both forbidden
/// by the spec and the one combination that would turn this into a real
/// vulnerability — it is what lets a hostile page make authenticated requests
/// with the visitor's ambient credentials. AT Protocol authenticates with
/// `Authorization` and `DPoP` headers rather than cookies, so the wildcard on
/// its own grants a page nothing it could not get from its own server.
#[tokio::test(flavor = "multi_thread")]
async fn preflight_is_answered_without_credentials() {
    let (app, _mgr, _tmp) = build_app().await;

    for route in CROSS_ORIGIN_ROUTES {
        let request = Request::builder()
            .uri(*route)
            .method("OPTIONS")
            .header("origin", "https://client.example")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,dpop,content-type",
            )
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let headers = response.headers().clone();

        assert!(
            headers.get("access-control-allow-origin").is_some(),
            "{route} answered a preflight with no Access-Control-Allow-Origin; \
             a browser client cannot call it"
        );
        assert!(
            headers.get("access-control-allow-credentials").is_none(),
            "{route} allows credentials alongside a wildcard origin — a hostile \
             page could then act as the visitor"
        );

        let allowed = headers
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        for header in ["authorization", "dpop", "content-type"] {
            assert!(
                allowed.contains(header),
                "{route} preflight does not allow `{header}`: {allowed:?}"
            );
        }
    }
}

/// A real response carries the header too, and exposes what a client must read.
#[tokio::test(flavor = "multi_thread")]
async fn a_simple_request_carries_the_origin_header() {
    let (app, _mgr, _tmp) = build_app().await;

    let request = Request::builder()
        .uri("/.well-known/oauth-protected-resource")
        .header("origin", "https://client.example")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();

    assert!(
        headers.get("access-control-allow-origin").is_some(),
        "the protected-resource document is unreadable by a browser client"
    );
    let exposed = headers
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    for header in ["dpop-nonce", "www-authenticate"] {
        assert!(
            exposed.contains(header),
            "`{header}` is unreadable cross-origin, so a client cannot act on it: {exposed:?}"
        );
    }
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
