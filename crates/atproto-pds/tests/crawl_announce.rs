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

use axum::Json;
use axum::extract::State;
use axum::routing::post;
use serde_json::Value;
use std::sync::{Arc, Mutex};

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
