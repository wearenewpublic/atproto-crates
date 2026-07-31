//! The firehose stream sequence must be global, monotonic and durable.
//!
//! `com.atproto.sync.subscribeRepos` hands each subscriber a `seq` and accepts
//! it back as a resume cursor. That contract only holds if `seq` orders the
//! *stream*: one number space for the whole server, strictly increasing in the
//! order frames go out, and never reissued.
//!
//! These tests assert that contract from the outside — through a real socket
//! where possible — rather than against the storage layer, because the defect
//! they cover (F-FIRE-05) was invisible from inside a single actor's outbox.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures::StreamExt as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tokio_websockets::ClientBuilder;
use tower::ServiceExt;

/// Build a PDS router backed by a temporary directory.
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

/// Create an account and return its access token.
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

/// Write one record, asserting the write succeeded.
async fn write_record(app: &axum::Router, did: &str, token: &str, text: &str) {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": text }
            }))
            .unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "createRecord should succeed: {:?}",
        response.into_body().collect().await.unwrap().to_bytes()
    );
}

/// Pull `seq` out of a binary frame.
///
/// A frame is two concatenated DAG-CBOR objects. Decoding the header
/// non-strictly ignores the body that follows it; re-encoding the result gives
/// the header's byte length exactly, because DAG-CBOR is canonical — there is
/// only one encoding of a given value.
fn frame_seq(frame: &[u8]) -> i64 {
    let header: atproto_dasl::Ipld = atproto_dasl::from_reader_non_strict(frame)
        .expect("frame header should decode as DAG-CBOR");
    let atproto_dasl::Ipld::Map(ref fields) = header else {
        panic!("a frame header is a map, got {header:?}")
    };
    assert!(fields.contains_key("t"), "a frame header carries `t`");
    let header_len = atproto_dasl::to_vec(&header)
        .expect("a decoded header should re-encode")
        .len();

    let body: atproto_dasl::Ipld =
        atproto_dasl::from_slice(&frame[header_len..]).expect("frame body should decode");
    let atproto_dasl::Ipld::Map(body) = body else {
        panic!("a frame body is a map, got {body:?}")
    };
    match body.get("seq") {
        Some(atproto_dasl::Ipld::Integer(seq)) => *seq as i64,
        other => panic!("every event body carries an integer `seq`, got {other:?}"),
    }
}

/// Serve `app` on an ephemeral port and return the address.
async fn serve(app: axum::Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Creating an account announces it on the firehose.
///
/// A relay or appview learns that an account exists from `#identity` and
/// `#account`. Without them a new account is invisible to the network until it
/// happens to write a record, and a consumer that indexes identity separately
/// never learns its handle at all.
#[tokio::test(flavor = "multi_thread")]
async fn creating_an_account_emits_identity_and_account() {
    let (app, manager, _tmp) = build_app().await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json")
        .parse()
        .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    let did = "did:plc:announcealice";
    let _token = create_account(&app, &manager, did, "alice.announce.example").await;

    // Both events, in whichever order they are sequenced.
    let mut seen: Vec<String> = Vec::new();
    while seen.len() < 2 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("creating an account should announce it within 30s")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        let text = String::from_utf8_lossy(message.as_payload()).to_string();
        if text.contains("#identity") {
            seen.push("identity".to_string());
        } else if text.contains("#account") {
            seen.push("account".to_string());
        }
    }

    seen.sort();
    assert_eq!(
        seen,
        vec!["account".to_string(), "identity".to_string()],
        "a new account must be announced with both #identity and #account"
    );
}

/// Two repositories must never be handed the same `seq`.
///
/// This is the core of F-FIRE-05: with an `AUTOINCREMENT` column in each
/// per-actor database, every account's first event is `seq = 1`. A relay
/// consuming the stream sees the same cursor value denote two different events.
#[tokio::test(flavor = "multi_thread")]
async fn two_repositories_never_share_a_seq() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:seqalice";
    let bob = "did:plc:seqbob";
    let alice_token = create_account(&app, &manager, alice, "alice.seq.example").await;
    let bob_token = create_account(&app, &manager, bob, "bob.seq.example").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri).connect().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    write_record(&app, alice, &alice_token, "from alice").await;
    write_record(&app, bob, &bob_token, "from bob").await;

    let mut seqs = Vec::new();
    while seqs.len() < 2 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("frames should arrive within 30s of the writes")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            seqs.push(frame_seq(message.as_payload()));
        }
    }

    assert_ne!(
        seqs[0], seqs[1],
        "`seq` numbers the stream, not a repository — two repositories were \
         both handed {}; a resuming subscriber cannot tell those events apart",
        seqs[0]
    );
}

/// Frames must leave in strictly increasing `seq` order.
///
/// Distinct numbers are not enough. `seq` is a resume cursor, so a subscriber
/// that reconnects at the last value it saw is entitled to assume everything at
/// or below it has been delivered. A frame arriving out of order silently
/// strands every event between the two.
#[tokio::test(flavor = "multi_thread")]
async fn seq_increases_strictly_in_wire_order() {
    let (app, manager, _tmp) = build_app().await;
    let dids = ["did:plc:seqmono1", "did:plc:seqmono2", "did:plc:seqmono3"];
    let mut tokens = Vec::new();
    for (index, did) in dids.iter().enumerate() {
        tokens.push(create_account(&app, &manager, did, &format!("mono{index}.seq.example")).await);
    }

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri).connect().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Interleave writes across all three repositories.
    const ROUNDS: usize = 3;
    for round in 0..ROUNDS {
        for (did, token) in dids.iter().zip(tokens.iter()) {
            write_record(&app, did, token, &format!("round {round}")).await;
        }
    }

    let expected = ROUNDS * dids.len();
    let mut seqs = Vec::new();
    while seqs.len() < expected {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("frames should arrive within 30s of the writes")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            seqs.push(frame_seq(message.as_payload()));
        }
    }

    for pair in seqs.windows(2) {
        assert!(
            pair[1] > pair[0],
            "`seq` must increase strictly in the order frames go out; \
             got {} after {} in {seqs:?}",
            pair[1],
            pair[0]
        );
    }
}

/// A number the stream has issued is never issued again.
///
/// An account created after the stream is already running must continue it, not
/// restart it. The per-actor counter restarted at 1 for every new repository,
/// so a relay holding a cursor would silently discard the new account's entire
/// history as already-seen.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_repository_continues_the_stream_rather_than_restarting_it() {
    let (app, manager, _tmp) = build_app().await;
    let first = "did:plc:seqfirst";
    let first_token = create_account(&app, &manager, first, "first.seq.example").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    write_record(&app, first, &first_token, "one").await;
    write_record(&app, first, &first_token, "two").await;

    // Only now does the second account exist.
    let second = "did:plc:seqsecond";
    let second_token = create_account(&app, &manager, second, "second.seq.example").await;
    write_record(&app, second, &second_token, "three").await;

    let mut seqs = Vec::new();
    while seqs.len() < 3 {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("frames should arrive within 30s")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            seqs.push(frame_seq(message.as_payload()));
        }
    }

    let highest_before = seqs[..2].iter().copied().max().unwrap();
    assert!(
        seqs[2] > highest_before,
        "a repository created mid-stream must take the next `seq`, not restart \
         at 1; the stream had reached {highest_before} and the new repository \
         was handed {} in {seqs:?}",
        seqs[2]
    );
}

/// Resuming at a cursor returns the tail exactly — no skips, no repeats.
#[tokio::test(flavor = "multi_thread")]
async fn resume_from_a_cursor_returns_the_exact_tail() {
    let (app, manager, _tmp) = build_app().await;
    let dids = ["did:plc:seqres1", "did:plc:seqres2"];
    let mut tokens = Vec::new();
    for (index, did) in dids.iter().enumerate() {
        tokens.push(create_account(&app, &manager, did, &format!("res{index}.seq.example")).await);
    }

    let addr = serve(app.clone()).await;
    let connect = |cursor: Option<i64>| {
        let query = match cursor {
            Some(c) => format!("?encoding=cbor&cursor={c}"),
            None => "?encoding=cbor".to_string(),
        };
        let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos{query}")
            .parse()
            .unwrap();
        async move { ClientBuilder::from_uri(uri).connect().await.unwrap().0 }
    };

    let mut socket = connect(None).await;
    const WRITES: usize = 4;
    for round in 0..WRITES {
        let index = round % dids.len();
        write_record(&app, dids[index], &tokens[index], &format!("w{round}")).await;
    }

    let mut seqs = Vec::new();
    while seqs.len() < WRITES {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("frames should arrive within 30s")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            seqs.push(frame_seq(message.as_payload()));
        }
    }
    drop(socket);

    // Reconnect mid-stream: everything after the second event, and nothing else.
    let resume_at = seqs[1];
    let expected: Vec<i64> = seqs.iter().copied().filter(|s| *s > resume_at).collect();

    let mut resumed = connect(Some(resume_at)).await;
    let mut replayed = Vec::new();
    while replayed.len() < expected.len() {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), resumed.next())
            .await
            .expect("the tail should replay within 30s")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            replayed.push(frame_seq(message.as_payload()));
        }
    }

    assert_eq!(
        replayed, expected,
        "resuming at {resume_at} must replay exactly the events above it"
    );
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
