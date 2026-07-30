//! acceptance tests — the router's fallback.
//!
//! Coverage:
//! - An `/xrpc/` path this server does not route answers 501 with the
//!   `MethodNotImplemented` error envelope, for any HTTP method, and that
//!   envelope is JSON-typed and readable cross-origin.
//! - A non-XRPC path this server does not route still answers a bare 404,
//!   so the XRPC envelope does not leak onto `/.well-known/*`, `/oauth/*`
//!   or `/metrics`.
//! - A path under `/xrpc/` that cannot name a method — no segment, or more
//!   than one — is a bare 404 too, since an NSID is a single path segment.
//! - A routed method called with the wrong HTTP verb does not reach the
//!   fallback at all.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
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
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), tmp)
}

/// Issue a request and return the status and headers alongside the raw body,
/// because the point of several of these assertions is whether a body exists at
/// all and which headers travelled with it.
async fn call(app: axum::Router, method: &str, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let request = Request::builder()
        .uri(path)
        .method(method)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

/// A method this server does not route is a named XRPC error, not a bodiless
/// 404. A client cannot distinguish an empty 404 from a wrong hostname or an
/// intercepting proxy, so it cannot report "that method is unimplemented".
#[tokio::test(flavor = "multi_thread")]
async fn unrouted_xrpc_method_is_method_not_implemented() {
    let (app, _tmp) = build_app().await;

    for method in ["GET", "POST"] {
        let (status, headers, body) =
            call(app.clone(), method, "/xrpc/com.example.doesNotExist").await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "{method} /xrpc/com.example.doesNotExist"
        );

        // A client that cannot tell the body is JSON will not parse it, which
        // puts it back where the bodiless 404 left it.
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("application/json"),
            "{method}: envelope is typed {content_type:?}, not application/json"
        );

        let value: Value = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("{method}: body is not JSON ({e}): {body:?}"));
        assert_eq!(value["error"], "MethodNotImplemented", "{method}: {value}");
        assert!(
            value["message"].as_str().is_some_and(|m| !m.is_empty()),
            "{method}: envelope carries no message: {value}"
        );
    }
}

/// The 501 envelope has to survive `cors_layer()`, or a browser client is
/// handed a network error instead of the error name and is no better off than
/// with the bodiless 404.
///
/// This holds only because `.fallback()` is registered before `.layer()` in
/// `build_router`: `Router::layer` wraps the fallback router along with the
/// routes, so a fallback added afterwards would sit outside the CORS layer.
/// Nothing else pins that ordering, so this test does.
#[tokio::test(flavor = "multi_thread")]
async fn the_not_implemented_envelope_is_readable_cross_origin() {
    let (app, _tmp) = build_app().await;

    let request = Request::builder()
        .uri("/xrpc/com.example.doesNotExist")
        .method("GET")
        .header(axum::http::header::ORIGIN, "https://client.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "the 501 envelope escaped the CORS layer; a browser client cannot read it"
    );
}

/// The envelope is a claim about which protocol a path speaks, and it is only
/// true under `/xrpc/`. Everything else keeps the bare 404 it had, so an OAuth
/// or discovery client reading a miss is not told the server is a broken XRPC
/// implementation.
#[tokio::test(flavor = "multi_thread")]
async fn unrouted_non_xrpc_path_is_still_a_bare_404() {
    let (app, _tmp) = build_app().await;

    for path in [
        "/nope",
        "/.well-known/does-not-exist",
        "/oauth/does-not-exist",
        "/metrics",
    ] {
        let (status, _, body) = call(app.clone(), "GET", path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "GET {path}");
        assert!(
            body.is_empty(),
            "GET {path} grew a body: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

/// An NSID is a single path segment. A path under `/xrpc/` with no segment, or
/// with more than one, names no method, so there is no method to report as
/// unimplemented — and the reference route `/xrpc/:methodId` reaches no handler
/// for these either, because an express `:param` does not span a `/`.
///
/// `/xrpc/foo/` is the one entry here the reference would read as `foo`, its
/// router having `strict routing` off. This server normalizes no trailing
/// slashes anywhere — `/xrpc/com.atproto.repo.createRecord/` matches its route
/// no better — so the fallback does not invent the normalization for itself.
#[tokio::test(flavor = "multi_thread")]
async fn an_xrpc_path_that_names_no_method_is_a_bare_404() {
    let (app, _tmp) = build_app().await;

    for path in [
        "/xrpc",
        "/xrpc/",
        "/xrpc//bar",
        "/xrpc/com.example.doesNotExist/",
        "/xrpc/a/b/c",
    ] {
        let (status, _, body) = call(app.clone(), "GET", path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "GET {path}");
        assert!(
            body.is_empty(),
            "GET {path} grew a body: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

/// A routed path called with the wrong verb is a method-not-allowed decision
/// axum makes while routing, and it never reaches the fallback: the per-route
/// `MethodRouter` answers 405 with an empty body before the router-level
/// fallback is consulted. A wrong-verb call to a method this server *does*
/// implement must not be relabelled as unimplemented.
///
/// The reference server answers this case with 400 `InvalidRequest` and
/// "Incorrect HTTP method (GET) expected POST", so 405 is itself a conformance
/// gap — a separate defect with a separate fix. Pinned as the exact status the
/// server gives today so that changing it is a deliberate act rather than a
/// silent one.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_verb_on_a_routed_method_does_not_reach_the_fallback() {
    let (app, _tmp) = build_app().await;

    let (status, _, body) = call(app.clone(), "GET", "/xrpc/com.atproto.repo.createRecord").await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "a POST-only method answered GET with {status}, not 405"
    );
    assert!(
        body.is_empty(),
        "the 405 grew a body: {}",
        String::from_utf8_lossy(&body)
    );
}
