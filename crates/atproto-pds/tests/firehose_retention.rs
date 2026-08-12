//! A subscriber whose cursor predates the retention window is told so.
//!
//! The firehose log is swept now, which means a resume cursor can name events
//! this server no longer holds. The spec's answer is an `#info` message called
//! `OutdatedCursor`: the subscription continues from the oldest event still
//! held, and the consumer learns there is a gap.
//!
//! Silence is the harmful alternative, and it is what this server did. The
//! subscriber is handed the oldest retained event as though it were the next
//! one after its cursor, so a relay carries a repository forward across a hole
//! it cannot detect — the same silent, permanent gap the firehose publish race
//! used to produce, arriving by a different route.
//!
//! Asserted through a real socket, because the notice is only worth anything if
//! it reaches the wire ahead of the events it qualifies.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use futures::StreamExt as _;
use std::sync::Arc;
use tempfile::TempDir;
use tokio_websockets::ClientBuilder;

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

async fn serve(app: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Produce some stream history, then drop everything below `keep_from` the way
/// a completed retention sweep would have.
async fn history_with_floor(manager: &AccountManager, keep_from: i64) {
    for i in 0..4 {
        manager
            .create_account(CreateAccountParams::new(
                &format!("did:plc:retention{i:04}"),
                &format!("r{i}.retention.example"),
                "pw",
            ))
            .await
            .expect("account creation seeds the stream");
    }
    let pool = manager.pool();
    sqlx::query("DELETE FROM stream_event WHERE seq < ?")
        .bind(keep_from)
        .execute(pool)
        .await
        .unwrap();
    let min: Option<i64> = sqlx::query_scalar("SELECT MIN(seq) FROM stream_event")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        min,
        Some(keep_from),
        "the fixture set the floor it meant to"
    );
}

/// Read frames until one is an `#info`, or give up.
async fn first_info(
    socket: &mut tokio_websockets::WebSocketStream<
        tokio_websockets::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<String> {
    for _ in 0..5 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(20), socket.next())
            .await
            .ok()??
            .ok()?;
        let text = String::from_utf8_lossy(message.as_payload()).to_string();
        if text.contains("#info") {
            return Some(text);
        }
    }
    None
}

/// A cursor below the retained floor gets the notice, before any event.
#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_below_the_retention_floor_gets_outdated_cursor() {
    let (app, manager, _tmp) = build_app().await;
    history_with_floor(&manager, 5).await;

    let addr = serve(app).await;
    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json&cursor=1")
            .parse()
            .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    // The very first frame, not merely one somewhere in the stream: a notice
    // that arrives after the events it qualifies has already been too late.
    let message = tokio::time::timeout(std::time::Duration::from_secs(20), socket.next())
        .await
        .expect("a subscriber with an outdated cursor is answered promptly")
        .expect("the socket stays open — this is a notice, not an error")
        .expect("the frame is well formed");
    let text = String::from_utf8_lossy(message.as_payload()).to_string();

    assert!(
        text.contains("#info"),
        "expected an #info frame, got: {text}"
    );
    assert!(
        text.contains("OutdatedCursor"),
        "the notice has to be named so a consumer can match on it: {text}"
    );
}

/// A cursor exactly at the floor is contiguous and must NOT be told otherwise.
///
/// `read_after` returns rows strictly after the cursor, so a cursor of
/// `earliest - 1` is asking for the oldest row this server still holds and has
/// missed nothing. Crying `OutdatedCursor` there would push a healthy consumer
/// into an unnecessary full re-sync every time it reconnected near the window.
#[tokio::test(flavor = "multi_thread")]
async fn a_contiguous_cursor_gets_no_notice() {
    let (app, manager, _tmp) = build_app().await;
    history_with_floor(&manager, 5).await;

    let addr = serve(app).await;
    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json&cursor=4")
            .parse()
            .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    assert!(
        first_info(&mut socket).await.is_none(),
        "cursor 4 asks for seq 5, which is exactly the floor — nothing was missed"
    );
}
