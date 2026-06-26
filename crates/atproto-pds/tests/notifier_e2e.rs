//! acceptance test — `Notifier::tick` is spawned and
//! drains pending `notify_attempt` rows by POSTing them to the recipient
//! service.
//!
//! Strategy: stand up a tiny axum server bound to an ephemeral port that
//! counts incoming POSTs and returns 200, enqueue a `notify_attempt`
//! pointing at it, then loop the notifier until the row's state flips to
//! `delivered` (or the test times out). This mirrors the production
//! `notifier_loop` in `bin/pds.rs` without dragging in the full PDS
//! shutdown controller.

use atproto_pds::account::AccountDirectory;
use atproto_pds::notifier::{Notifier, enqueue_notification};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

#[derive(Clone, Default)]
struct Counter(Arc<AtomicUsize>);

async fn count_handler(State(counter): State<Counter>) -> StatusCode {
    counter.0.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

async fn spawn_test_server() -> (Counter, std::net::SocketAddr) {
    let counter = Counter::default();
    // The notifier delivers contentless `notifyWrite` events to registered
    // recipients (spec lines 343-351). The member-sync `notifyMembership` route
    // was removed in the 0016 re-alignment, so only `notifyWrite` is served.
    let app: Router = Router::new()
        .route("/xrpc/com.atproto.space.notifyWrite", post(count_handler))
        .with_state(counter.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (counter, addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn notifier_tick_delivers_to_recipient_within_timeout() {
    let (counter, addr) = spawn_test_server().await;
    let endpoint = format!("http://{addr}");

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let pool = accounts.pool().clone();

    enqueue_notification(
        &pool,
        "did:web:test-recipient",
        &endpoint,
        b"payload-bytes".to_vec(),
        "com.atproto.space.notifyWrite",
        "application/json",
        None,
    )
    .await
    .unwrap();

    // Run the notifier on a tight loop with a short tick. We bail after at
    // most 5 seconds; the row should flip to `delivered` on the very first
    // tick (the test server returns 200 immediately).
    let notifier = Notifier::default();
    let pool_for_loop = pool.clone();
    let handle = tokio::spawn(async move {
        for _ in 0..50 {
            let _ = notifier.tick(&pool_for_loop).await;
            sleep(Duration::from_millis(100)).await;
        }
    });

    // Poll the row state.
    let mut state = String::new();
    for _ in 0..50 {
        let row: Option<(String,)> = sqlx::query_as("SELECT state FROM notify_attempt LIMIT 1")
            .fetch_optional(&pool)
            .await
            .unwrap();
        if let Some((s,)) = row {
            state = s.clone();
            if s == "delivered" {
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    handle.abort();

    assert_eq!(state, "delivered", "row never reached delivered state");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "test server should have received exactly one POST"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notifier_tick_marks_failure_on_5xx() {
    // Stand up a server that always returns 500.
    let app = Router::new().route(
        "/xrpc/com.atproto.space.notifyWrite",
        post(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let pool = accounts.pool().clone();

    enqueue_notification(
        &pool,
        "did:web:fail",
        &format!("http://{addr}"),
        b"x".to_vec(),
        "com.atproto.space.notifyWrite",
        "application/json",
        None,
    )
    .await
    .unwrap();

    // Use a tight retry budget so the test finishes fast: max_attempts=1
    // means a single failure flips the row directly to `failed`.
    let notifier = Notifier {
        max_attempts: 1,
        initial_backoff_ms: 1,
        ..Notifier::default()
    };
    let _ = notifier.tick(&pool).await.unwrap();

    let (state, attempt_count): (String, i64) =
        sqlx::query_as("SELECT state, attempt_count FROM notify_attempt LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "failed");
    assert!(attempt_count >= 1);
}
