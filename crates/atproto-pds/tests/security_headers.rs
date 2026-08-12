//! The server's HTML surfaces carry security headers, and its JSON does not
//! pretend to.
//!
//! These go through `build_router` rather than calling the middleware, because
//! what is being pinned is that the layer is *mounted* and outermost. A test of
//! the function on its own would have passed just as well with nothing wired
//! up, and "the header is computed correctly somewhere nobody calls" is the
//! shape of defect this layer exists to prevent.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::Request;
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
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), tmp)
}

/// The sign-in page is HTML, unauthenticated, and reachable with a plain GET —
/// the simplest of the three HTML surfaces to ask for.
#[tokio::test(flavor = "multi_thread")]
async fn an_html_page_carries_the_full_set() {
    let (app, _tmp) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/account/signin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let headers = response.headers();
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("text/html")),
        Some(true),
        "the fixture must actually be serving HTML for this test to mean anything"
    );

    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY",
        "a password prompt must not be frameable"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");

    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("HTML carries a policy");
    // The three directives that hold even with 'unsafe-inline' present.
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(
        csp.contains("form-action 'self'"),
        "an injected form must not be able to post a password elsewhere: {csp}"
    );
    assert!(
        csp.contains("base-uri 'none'"),
        "a <base> tag must not be able to re-point a relative form action: {csp}"
    );
}

/// `nosniff` is the one that goes everywhere. A JSON error body a browser
/// decides to render as HTML is the whole of that class of bug.
#[tokio::test(flavor = "multi_thread")]
async fn a_json_response_is_not_sniffable() {
    let (app, _tmp) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.describeServer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(
        response.headers().get("content-security-policy").is_none(),
        "a JSON API response has no HTML to constrain, and a policy there would \
         only be noise a reader has to discount"
    );
}

/// The layer is outermost, so a response no handler produced still carries the
/// headers. An unmatched path is served by the router's own fallback.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_no_handler_produced_still_carries_them() {
    let (app, _tmp) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/no/such/path")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}
