//! Every rejection the HTTP layer can emit before a handler runs must still be
//! an XRPC error.
//!
//! A request that never reaches its handler is the one case where axum, not
//! this crate, writes the response — and axum writes `text/plain` with a status
//! (422, 415) that XRPC does not define. A conformant client parses the body as
//! `{"error", "message"}` and has nothing to report when it cannot.
//!
//! These assert on the status, the error name and the wire body rather than on
//! a Rust value, because the defect was the *shape* of the response: a round
//! trip through this crate's own types cannot see it. One case asserts the
//! status did *not* move: an over-long body keeps its 413, since putting a
//! rejection in the envelope is not a reason to stop telling a caller which
//! remedy applies.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
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

/// The raw response, not a parsed one: whether the body *is* JSON is the thing
/// under test, so it cannot be assumed while reading it.
async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn post_json(path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap()
}

/// Assert the XRPC envelope with a given status and error name, and hand back
/// the parsed body.
fn envelope_named(
    status: StatusCode,
    body: &str,
    expected_status: StatusCode,
    expected_name: &str,
) -> Value {
    assert_eq!(status, expected_status, "body was: {body}");
    let parsed: Value =
        serde_json::from_str(body).unwrap_or_else(|_| panic!("body was not JSON: {body}"));
    assert_eq!(parsed["error"], expected_name, "body was: {body}");
    assert!(
        parsed["message"].is_string(),
        "envelope needs a message: {body}"
    );
    parsed
}

/// Assert the XRPC envelope for an undecodable request and hand back the
/// parsed body.
fn envelope(status: StatusCode, body: &str) -> Value {
    envelope_named(status, body, StatusCode::BAD_REQUEST, "InvalidRequest")
}

#[tokio::test]
async fn malformed_json_body_is_an_xrpc_error() {
    let (app, _tmp) = build_app().await;
    let (status, body) = send(
        app,
        post_json("/xrpc/com.atproto.server.createAccount", r#"{"handle":"#),
    )
    .await;

    let parsed = envelope(status, &body);
    let message = parsed["message"].as_str().unwrap();
    assert!(message.contains("not valid JSON"), "{message}");
}

/// The reported case: `{}` used to come back as HTTP 422 `text/plain`.
#[tokio::test]
async fn body_missing_a_required_field_is_an_xrpc_error() {
    let (app, _tmp) = build_app().await;
    let (status, body) = send(
        app,
        post_json("/xrpc/com.atproto.server.createAccount", "{}"),
    )
    .await;

    let parsed = envelope(status, &body);
    let message = parsed["message"].as_str().unwrap();
    assert!(message.contains("missing field `handle`"), "{message}");
}

#[tokio::test]
async fn bad_query_parameter_is_an_xrpc_error() {
    let (app, _tmp) = build_app().await;
    // `collection` and `rkey` are required; only `repo` is supplied.
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.getRecord?repo=did:web:test.example")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(app, req).await;

    let parsed = envelope(status, &body);
    let message = parsed["message"].as_str().unwrap();
    assert!(message.starts_with("invalid query parameters"), "{message}");
    assert!(message.contains("missing field `collection`"), "{message}");
}

/// axum answers a body with no content type with a bare 415, which is not one
/// of the statuses XRPC defines.
#[tokio::test]
async fn body_without_a_content_type_is_an_xrpc_error() {
    let (app, _tmp) = build_app().await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .body(Body::from(r#"{"handle":"a.test","password":"pw"}"#))
        .unwrap();
    let (status, body) = send(app, req).await;

    let parsed = envelope(status, &body);
    assert!(
        parsed["message"]
            .as_str()
            .unwrap()
            .contains("application/json"),
        "{body}"
    );
}

/// Putting the rejection in the envelope must not cost the status. axum caps
/// every request body at 2 MiB (`http_body_util::Limited`, and this crate
/// installs no `DefaultBodyLimit`), so this is reachable on every JSON endpoint
/// — an `applyWrites` batch past the cap being the realistic case. A caller
/// that sees 400 for both this and a syntax error cannot tell "split the batch"
/// from "fix the encoder".
#[tokio::test]
async fn oversized_body_is_a_413_in_the_envelope() {
    let (app, _tmp) = build_app().await;
    let mut body = String::from(r#"{"repo":"did:web:test.example","writes":""#);
    body.push_str(&"a".repeat(3 * 1024 * 1024));
    body.push_str(r#""}"#);

    let (status, body) = send(app, post_json("/xrpc/com.atproto.repo.applyWrites", body)).await;

    let parsed = envelope_named(
        status,
        &body,
        StatusCode::PAYLOAD_TOO_LARGE,
        "RequestTooLarge",
    );
    let message = parsed["message"].as_str().unwrap();
    assert!(message.contains("exceeds"), "{message}");
}

/// The name of the Rust struct behind an endpoint is not part of the wire
/// contract and must not reach a caller.
#[tokio::test]
async fn rejection_does_not_leak_rust_type_names() {
    let (app, _tmp) = build_app().await;
    let (status, body) = send(
        app,
        post_json("/xrpc/com.atproto.server.createAccount", "[]"),
    )
    .await;

    envelope(status, &body);
    assert!(!body.contains("CreateAccountInput"), "{body}");
    assert!(!body.contains("target type"), "{body}");
}

/// Guards the other half of the change: swapping the extractor must not alter
/// what a well-formed request decodes to. A fully-specified `getRecord` gets
/// past decoding and fails on the repo instead.
///
/// The assertion is on the message, not the error name. "the name is not
/// `InvalidRequest`" looks like a reasonable proxy for "decoding succeeded" and
/// is not one: a handler is free to answer `InvalidRequest` for its own
/// reasons once it has been reached, so the proxy reports a false failure the
/// moment this handler does. Reaching the handler is what this test is about,
/// and the repo-lookup message is the evidence for it.
#[tokio::test]
async fn a_well_formed_query_still_reaches_the_handler() {
    let (app, _tmp) = build_app().await;
    let req = Request::builder()
        .uri(
            "/xrpc/com.atproto.repo.getRecord\
             ?repo=did:web:absent.example&collection=app.bsky.feed.post&rkey=abc",
        )
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(app, req).await;

    let parsed: Value = serde_json::from_str(&body).expect("XRPC errors are JSON");
    let message = parsed["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("repo not found"),
        "query should have decoded and reached the repo lookup: {body}"
    );
    assert_ne!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
