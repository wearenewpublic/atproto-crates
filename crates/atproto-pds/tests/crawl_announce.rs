//! Integration tests for announcing this PDS to crawlers.
//!
//! These run against a real HTTP server rather than a mock, because the thing
//! worth pinning is the shape that goes out on the wire: a relay receives a
//! POST to `com.atproto.sync.requestCrawl` carrying `{"hostname": ...}`, and
//! anything else leaves the PDS uncrawled while looking like it announced.
//!
//! The failure this guards against is silent from both ends. The PDS logs an
//! announcement and serves normally; the relay never subscribes; writes commit
//! to a repo nobody reads.

use atproto_pds::account::AccountDirectory;
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::repo::RepoReader;
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use base64::Engine as _;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt as _;

/// A crawler that records what it was told. Returns its base URL and the log.
async fn recording_crawler(status: axum::http::StatusCode) -> (String, Arc<Mutex<Vec<Value>>>) {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new()
        .route(
            "/xrpc/com.atproto.sync.requestCrawl",
            post(
                move |State(seen): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>| async move {
                    seen.lock().unwrap().push(body);
                    status
                },
            ),
        )
        .with_state(seen.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), seen)
}

/// The announcement reaches the crawler, naming this server.
#[tokio::test(flavor = "multi_thread")]
async fn announcing_tells_the_crawler_which_host_to_crawl() {
    let (base, seen) = recording_crawler(axum::http::StatusCode::OK).await;

    atproto_pds::crawl::announce(&[base], "pds.example").await;

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "the crawler was not told anything");
    assert_eq!(
        seen[0].get("hostname").and_then(Value::as_str),
        Some("pds.example"),
        "the crawler was told to crawl the wrong host, so it will find nothing"
    );
}

/// A trailing slash on the configured base must not produce a double slash.
///
/// `https://relay.example/` is how an operator naturally writes a base URL, and
/// a `//xrpc/...` path is a 404 at some relays — an announcement that silently
/// does nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_trailing_slash_on_the_base_url_is_tolerated() {
    let (base, seen) = recording_crawler(axum::http::StatusCode::OK).await;

    atproto_pds::crawl::announce(&[format!("{base}/")], "pds.example").await;

    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "a trailing slash on the crawler base URL lost the announcement"
    );
}

/// Every crawler is told, and one failing does not silence the rest.
///
/// Operators list more than one relay precisely so no single one is critical.
/// Aborting the loop on the first failure would invert that.
#[tokio::test(flavor = "multi_thread")]
async fn one_bad_crawler_does_not_stop_the_others() {
    let (dead, _) = recording_crawler(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
    let (live, seen) = recording_crawler(axum::http::StatusCode::OK).await;

    // Unroutable, refusing, and healthy — in that order, so the healthy one is
    // reached only if neither earlier failure ends the loop.
    atproto_pds::crawl::announce(
        &["http://127.0.0.1:1".to_string(), dead, live],
        "pds.example",
    )
    .await;

    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "a crawler listed after a failing one was never told"
    );
}

// ---------------------------------------------------------------------------
//  The inbound endpoint.
// ---------------------------------------------------------------------------

/// A PDS whose only configured crawler is `crawler`, with an admin password.
async fn pds_announcing_to(crawler: String) -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::new(reader)
        .with_crawlers(vec![crawler])
        .with_admin_password("hunter2".to_string());
    (build_router(state), tmp)
}

async fn post_request_crawl(
    app: &axum::Router,
    body: Value,
    admin: Option<&str>,
) -> axum::http::StatusCode {
    let mut request = Request::builder()
        .uri("/xrpc/com.atproto.sync.requestCrawl")
        .method("POST")
        .header("content-type", "application/json");
    if let Some(password) = admin {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{password}"));
        request = request.header("authorization", format!("Basic {encoded}"));
    }
    let request = request
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

/// An anonymous caller cannot make this server announce.
///
/// `requestCrawl` is a relay's method and this is not a relay; what it does
/// here is the mirror image, firing outbound requests -- with retries -- at
/// every configured crawler. Serving that to anyone made a bare POST into a
/// free round of outbound traffic.
#[tokio::test(flavor = "multi_thread")]
async fn an_anonymous_caller_cannot_trigger_an_announcement() {
    let (crawler, seen) = recording_crawler(StatusCode::OK).await;
    let (app, _tmp) = pds_announcing_to(crawler).await;

    let status = post_request_crawl(&app, json!({}), None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "anyone could announce");
    assert!(
        seen.lock().unwrap().is_empty(),
        "the crawler was contacted on an unauthenticated request"
    );
}

/// A wrong password is no better than none.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_admin_password_cannot_trigger_an_announcement() {
    let (crawler, seen) = recording_crawler(StatusCode::OK).await;
    let (app, _tmp) = pds_announcing_to(crawler).await;

    let status = post_request_crawl(&app, json!({}), Some("wrong")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(seen.lock().unwrap().is_empty());
}

/// The announcement names this server, whatever the caller asked for.
///
/// The hostname used to come from the request body, so a caller could make
/// this server introduce a host of their choosing to relays that trust it.
/// A PDS can only answer for itself.
#[tokio::test(flavor = "multi_thread")]
async fn the_announcement_names_this_server_and_not_the_callers_host() {
    let (crawler, seen) = recording_crawler(StatusCode::OK).await;
    let (app, _tmp) = pds_announcing_to(crawler).await;

    let status = post_request_crawl(
        &app,
        json!({"hostname": "attacker.example"}),
        Some("hunter2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "the operator's announcement did not go out");
    let told = seen[0].get("hostname").and_then(Value::as_str);
    assert_ne!(
        told,
        Some("attacker.example"),
        "this server announced a host the caller named"
    );
    assert_eq!(
        told,
        Some("localhost"),
        "the announcement should name this server's own host"
    );
}
