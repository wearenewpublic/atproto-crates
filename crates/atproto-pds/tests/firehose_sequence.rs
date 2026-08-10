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
    build_app_with(|state| state).await
}

/// The same, with a chance to adjust the state before the router is built.
async fn build_app_with(
    tune: impl FnOnce(HttpState) -> HttpState,
) -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    (build_router(tune(state)), manager, tmp)
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

/// Every committed event reaches a connected subscriber, exactly once.
///
/// `seq_increases_strictly_in_wire_order` awaits each write before starting the
/// next, so the publish path never overlapped with itself and this was
/// invisible to it. Ordering was also the wrong property to assert: a stream
/// missing an event is still strictly increasing. What has to hold is that
/// nothing is dropped and nothing is repeated.
///
/// The defect needed two writes in flight at once, anywhere on the server —
/// not even to the same repository. The publisher re-read the newest row for
/// its own DID starting from the server-global `MAX(seq)`, so when another
/// account's insert landed first, the filter matched nothing and the write
/// published no event at all, while the other handler published its own. A
/// subscriber advanced its cursor to what it received and then read `seq >`
/// that, so the skipped event was never delivered by the poll path either.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_writes_deliver_every_event_exactly_once() {
    const ACCOUNTS: usize = 4;
    const PER_ACCOUNT: usize = 5;

    let (app, manager, _tmp) = build_app().await;
    let mut dids = Vec::new();
    let mut tokens = Vec::new();
    for index in 0..ACCOUNTS {
        let did = format!("did:plc:concurrentwriter{index}");
        tokens.push(create_account(&app, &manager, &did, &format!("cw{index}.seq.example")).await);
        dids.push(did);
    }

    // Connect before any of the writes, and with no cursor, so the frames that
    // arrive are exactly the ones these writes produce.
    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri).connect().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Every write in flight at once. The per-DID lock still serialises the
    // commits themselves; what overlaps is the publish that follows each.
    let mut handles = Vec::new();
    for (did, token) in dids.iter().zip(tokens.iter()) {
        for round in 0..PER_ACCOUNT {
            let app = app.clone();
            let did = did.clone();
            let token = token.clone();
            handles.push(tokio::spawn(async move {
                write_record(&app, &did, &token, &format!("round {round}")).await;
            }));
        }
    }
    for handle in handles {
        handle.await.expect("a write task should not panic");
    }

    let expected = ACCOUNTS * PER_ACCOUNT;
    let mut seqs = Vec::new();
    while seqs.len() < expected {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "only {} of {expected} events were delivered; the rest are lost, \
                     not late -- the poll path reads past a cursor the broadcast \
                     already advanced. got {seqs:?}",
                    seqs.len()
                )
            })
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        if message.is_binary() {
            seqs.push(frame_seq(message.as_payload()));
        }
    }

    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    let mut unique = sorted.clone();
    unique.dedup();
    assert_eq!(
        unique.len(),
        sorted.len(),
        "an event was delivered more than once: {seqs:?}"
    );

    // Contiguous: the stream is one number space and these writes are all of
    // it, so first..=last with nothing missing is the whole claim.
    let first = *sorted.first().expect("at least one event");
    let last = *sorted.last().expect("at least one event");
    assert_eq!(
        last - first + 1,
        expected as i64,
        "the delivered range has a hole in it: {sorted:?}"
    );
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

/// A subscription outlives the request deadline.
///
/// The deadline applies to this route like any other, and the subscription
/// survives it anyway: what a timeout bounds is producing a response, and a
/// subscription's response is the 101 it answers with immediately. Everything
/// after that is a socket hyper hands off, outside the future the layer wraps.
///
/// This was worth finding out rather than assuming. The first version of this
/// change routed `subscribeRepos` outside the timeout layer on the assumption
/// that a live tail would be cut at thirty seconds; the test passed with the
/// route moved back inside, which is what showed the exclusion was doing
/// nothing. The ordering came out and this stayed.
///
/// What it guards is quiet: a body-level timeout, a connection-level one, or a
/// different server underneath, any of which would start cutting every firehose
/// consumer on a fixed interval — each reconnecting, and each appearing to work.
///
/// Built with a one-second deadline so the test costs seconds, not thirty.
#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_is_not_subject_to_the_request_deadline() {
    let (_, manager, _tmp) = build_app().await;
    let did = "did:plc:seqdeadline";
    let dir = manager.data_dir().to_path_buf();

    // Rebuild the router with a deadline short enough to trip inside the test.
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = atproto_pds::http::build_router_with_request_timeout(
        state,
        std::time::Duration::from_secs(1),
    );

    let token = create_account(&app, &manager, did, "deadline.seq.example").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri).connect().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Well past the deadline, with the subscription idle throughout.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Still connected, and still delivering.
    write_record(&app, did, &token, "after the deadline").await;
    let message = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .expect("a frame should arrive")
        .expect("the subscription must outlive the request deadline")
        .expect("the frame should not be a protocol error");
    assert!(message.is_binary(), "expected a firehose frame");
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

/// A subscriber that supplies no cursor is served live events only.
///
/// `read_after(None, ..)` treats a missing cursor as the start of the log, so a
/// cursor-less subscriber used to receive the entire retained history. Every
/// reconnect then re-read everything, and a fresh consumer inherited a backlog
/// it had no way to decline. The reference leaves its outbox cursor unset here
/// and streams only what arrives next.
#[tokio::test(flavor = "multi_thread")]
async fn no_cursor_streams_only_new_events() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:tailalice";
    let token = create_account(&app, &manager, alice, "alice.tail.example").await;

    // History the subscriber must NOT be sent.
    write_record(&app, alice, &token, "before the subscriber existed").await;
    write_record(&app, alice, &token, "also before").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri).connect().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Nothing should arrive until something new happens. A short window is
    // enough: the backlog was delivered immediately on connect.
    let early = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await;
    assert!(
        early.is_err(),
        "a cursor-less subscriber was sent history it did not ask for"
    );

    write_record(&app, alice, &token, "after the subscriber connected").await;
    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("the new write should arrive")
        .expect("the socket should stay open")
        .expect("the frame should not be a protocol error");
    assert!(message.is_binary(), "expected a CBOR frame");
}

/// An explicit cursor still backfills.
///
/// The guard above must not be implemented by refusing to read history at all —
/// `cursor=0` is how a consumer legitimately asks for everything.
#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_cursor_still_backfills() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:backfillalice";
    let token = create_account(&app, &manager, alice, "alice.backfill.example").await;
    write_record(&app, alice, &token, "historic").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor&cursor=0")
            .parse()
            .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("cursor=0 must replay the log")
        .expect("the socket should stay open")
        .expect("the frame should not be a protocol error");
    assert!(message.is_binary(), "expected a replayed CBOR frame");
}

/// A cursor beyond the head is refused with `FutureCursor` rather than waited
/// out.
///
/// Holding the socket open leaves a consumer that mangled its cursor believing
/// it is caught up and idle, with no way to tell that apart from a quiet
/// server. The lexicon declares the error and the reference raises it.
#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_past_the_head_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:futurealice";
    let token = create_account(&app, &manager, alice, "alice.future.example").await;
    write_record(&app, alice, &token, "one event").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json&cursor=999999")
            .parse()
            .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    let message = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .expect("an error frame should arrive promptly")
        .expect("the socket should stay open long enough to deliver it")
        .expect("the frame should not be a protocol error");
    let text = String::from_utf8_lossy(message.as_payload()).to_string();
    assert!(
        text.contains("FutureCursor"),
        "expected a FutureCursor frame, got: {text}"
    );
}

// ---------------------------------------------------------------------------
//  F-FIRE-20 — the genesis commit.
//
//  A signup produces an account whose repository exists and is empty, not one
//  that has no repository. Without a genesis commit `getLatestCommit` answers
//  `RepoNotFound` for a valid account and the account announcement can carry
//  neither `#commit` nor `#sync`, because there is no commit to name.
//
//  These exercise `RepoWriter::create_genesis_commit` directly. The
//  `createAccount` handler calls it on the active-signup path, which is not
//  reachable from a crate test: that path mints the DID through PLC, and the
//  only PLC service the test suite constructs points at an unroutable host on
//  purpose. That wiring is covered by the external conformance harness against
//  a live server instead, which is where it was verified.
// ---------------------------------------------------------------------------

/// The genesis commit is a real, signed commit over an empty repository.
#[tokio::test(flavor = "multi_thread")]
async fn genesis_commit_gives_a_fresh_account_an_empty_repository() {
    let (app, manager, tmp) = build_app().await;
    let did = "did:plc:genesisalice";
    let _token = create_account(&app, &manager, did, "alice.genesis.example").await;

    let writer = RepoWriter::new(manager.clone(), tmp.path().to_path_buf());
    let result = writer
        .create_genesis_commit(did)
        .await
        .expect("a fresh account should take a genesis commit");

    assert!(!result.commit_cid.is_empty(), "the commit needs a CID");
    assert!(!result.rev.is_empty(), "the commit needs a rev");
    assert!(
        result.writes.is_empty(),
        "a genesis commit writes no records, got {:?}",
        result.writes
    );

    // And it is visible as the repository head, which is the whole point:
    // before this, `getLatestCommit` answered RepoNotFound for a valid
    // account.
    let request = Request::builder()
        .uri(format!("/xrpc/com.atproto.sync.getLatestCommit?did={did}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "getLatestCommit should find the genesis commit"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body["cid"], result.commit_cid,
        "getLatestCommit should name the genesis commit"
    );
}

/// It announces itself with **both** `#commit` and `#sync`.
///
/// `#sync` is what a consumer needs for a repository it has never seen — it
/// force-sets state without a diff, where `#commit` is a diff against a head
/// the consumer is assumed to hold. For a genesis commit there is no such
/// head, so `#commit` alone would leave a fresh consumer unable to anchor.
/// The reference sequences both together in `sequenceAccountCreation`.
#[tokio::test(flavor = "multi_thread")]
async fn genesis_commit_emits_both_commit_and_sync() {
    let (app, manager, tmp) = build_app().await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json")
        .parse()
        .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    let did = "did:plc:genesissync";
    let _token = create_account(&app, &manager, did, "alice.gsync.example").await;

    let writer = RepoWriter::new(manager.clone(), tmp.path().to_path_buf());
    writer.create_genesis_commit(did).await.expect("genesis");

    let mut seen: Vec<String> = Vec::new();
    while !(seen.iter().any(|s| s == "commit") && seen.iter().any(|s| s == "sync")) {
        let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
            .await
            .expect("a genesis commit should announce itself within 30s")
            .expect("the socket should stay open")
            .expect("the frame should not be a protocol error");
        let text = String::from_utf8_lossy(message.as_payload()).to_string();
        if !text.contains(did) {
            continue;
        }
        if text.contains("#commit") {
            seen.push("commit".to_string());
        } else if text.contains("#sync") {
            seen.push("sync".to_string());
        }
    }

    seen.sort();
    seen.dedup();
    assert_eq!(
        seen,
        vec!["commit".to_string(), "sync".to_string()],
        "a genesis commit must be announced with both #commit and #sync"
    );
}

/// `applyWrites` with no operations stays an error.
///
/// The genesis path commits an empty batch, so the guard that refuses one had
/// to move rather than disappear. A client asking to write nothing is still a
/// client error, and widening the endpoint would have been the easy way to
/// make the genesis commit work.
#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_still_refuses_an_empty_batch() {
    let (_app, manager, tmp) = build_app().await;
    let writer = RepoWriter::new(manager.clone(), tmp.path().to_path_buf());

    let result = writer.apply_writes("did:plc:emptybatch", Vec::new()).await;
    assert!(
        result.is_err(),
        "applyWrites with no ops must stay an error, got {result:?}"
    );
}

/// A consumer that stops reading is dropped, not waited on forever.
///
/// `send` was awaited with no bound. Once a consumer stops reading, TCP
/// backpressure reaches that await and it parks: the task, the socket and the
/// connection slot are held for as long as the peer leaves the connection
/// open, which can be indefinitely, and nothing tells that apart from a
/// subscriber idling on a quiet stream. The lexicon declares `ConsumerTooSlow`
/// for exactly this and nothing raised it.
///
/// The client here connects and then does not poll the socket at all, which is
/// what a wedged consumer looks like from this side: the connection is open,
/// the peer is reachable, and nothing is being taken off the wire. Records are
/// large enough to fill the buffers between the two ends, because a consumer
/// only counts as slow once there is something it is failing to take.
#[tokio::test(flavor = "multi_thread")]
async fn a_consumer_that_stops_reading_is_dropped() {
    let (app, manager, _tmp) = build_app_with(|state| state.with_firehose_send_timeout(1)).await;
    let alice = "did:plc:slowalice";
    let token = create_account(&app, &manager, alice, "alice.slow.example").await;

    // Under the per-record ceiling, and enough of them to overrun the socket
    // buffers on either side of loopback.
    let bulk = "x".repeat(900_000);
    for _ in 0..16 {
        write_record(&app, alice, &token, &bulk).await;
    }

    let addr = serve(app.clone()).await;
    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=json&cursor=0")
            .parse()
            .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    // Not reading is the point: the server fills what it can and then blocks
    // on a send that will not complete.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Now drain. Whatever the server managed to write is buffered locally, so
    // this reads it out and then finds the stream ended.
    let mut frames = 0usize;
    let mut saw_too_slow = false;
    loop {
        let next = tokio::time::timeout(std::time::Duration::from_secs(20), socket.next()).await;
        let Ok(next) = next else {
            panic!(
                "the subscription is still open after {frames} frames; a stalled consumer was never dropped"
            );
        };
        match next {
            None => break,
            Some(Err(_)) => break,
            Some(Ok(message)) => {
                frames += 1;
                let text = String::from_utf8_lossy(message.as_payload()).to_string();
                if text.contains("ConsumerTooSlow") {
                    saw_too_slow = true;
                }
            }
        }
    }

    // The discriminating fact is that the stream ended. Sixteen records were
    // written and a server that waits out a stalled consumer delivers all of
    // them once reading resumes.
    assert!(
        frames < 16 || saw_too_slow,
        "the whole backlog arrived ({frames} frames) with no ConsumerTooSlow: the consumer was waited out"
    );
}

// ---------------------------------------------------------------------------
//  Proposal 0015 — subprotocol negotiation.
// ---------------------------------------------------------------------------

/// Connect offering `protocols`, returning the socket and the echoed
/// subprotocol.
async fn connect_offering(
    addr: std::net::SocketAddr,
    protocols: Option<&str>,
) -> (
    tokio_websockets::WebSocketStream<tokio_websockets::MaybeTlsStream<tokio::net::TcpStream>>,
    Option<String>,
) {
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0")
        .parse()
        .unwrap();
    let mut builder = ClientBuilder::from_uri(uri);
    if let Some(protocols) = protocols {
        builder = builder
            .add_header(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_str(protocols).unwrap(),
            )
            .unwrap();
    }
    let (socket, response) = builder.connect().await.unwrap();
    let echoed = response
        .headers()
        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (socket, echoed)
}

/// A client that asks for JSON gets JSON, and is told so in the handshake.
///
/// The server had no subprotocol negotiation at all: the only way to a JSON
/// stream was a private `?encoding=json` query parameter producing a private
/// frame shape. A consumer written against proposal 0015 had no way to ask,
/// and no way to discover what it was going to be sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_can_negotiate_the_json_subprotocol() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:protoalice";
    let token = create_account(&app, &manager, alice, "alice.proto.example").await;
    write_record(&app, alice, &token, "negotiated").await;
    let addr = serve(app).await;

    let (mut socket, echoed) = connect_offering(addr, Some("xrpc.v1.json")).await;
    assert_eq!(
        echoed.as_deref(),
        Some("xrpc.v1.json"),
        "the server must echo the subprotocol it selected"
    );

    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("a frame should arrive")
        .expect("the socket should stay open")
        .expect("no protocol error");
    assert!(message.is_text(), "xrpc.v1.json travels in text frames");

    let value: serde_json::Value =
        serde_json::from_slice(message.as_payload()).expect("frames must be JSON");
    assert_eq!(value["$type"], "message", "{value}");
    let payload_type = value["payload"]["$type"].as_str().unwrap_or_default();
    assert!(
        payload_type.starts_with("com.atproto.sync.subscribeRepos#"),
        "the payload must name its lexicon type in full: {value}"
    );
    assert!(
        value.get("op").is_none(),
        "v1 carries no header fields: {value}"
    );
}

/// A client that offers nothing still gets the legacy stream.
///
/// This is the compatibility guarantee the proposal is built around, and the
/// reason negotiation could be added at all: every consumer in the network
/// today sends no `Sec-WebSocket-Protocol`, and must keep receiving
/// `xrpc.v0.cbor` binary frames.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_offers_nothing_gets_the_legacy_stream() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:legacyalice";
    let token = create_account(&app, &manager, alice, "alice.legacy.example").await;
    write_record(&app, alice, &token, "unnegotiated").await;
    let addr = serve(app).await;

    let (mut socket, echoed) = connect_offering(addr, None).await;
    assert_eq!(echoed, None, "nothing was negotiated, so nothing is echoed");

    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("a frame should arrive")
        .expect("the socket should stay open")
        .expect("no protocol error");
    assert!(
        message.is_binary(),
        "an unnegotiated connection must still be given CBOR"
    );
}

/// An offer the server does not speak falls back rather than failing.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_offer_falls_back_to_the_legacy_stream() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:unknownalice";
    let token = create_account(&app, &manager, alice, "alice.unknown.example").await;
    write_record(&app, alice, &token, "unknown offer").await;
    let addr = serve(app).await;

    let (mut socket, echoed) = connect_offering(addr, Some("graphql-ws")).await;
    assert_eq!(
        echoed, None,
        "the server must not claim a protocol it refused"
    );

    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("a frame should arrive")
        .expect("the socket should stay open")
        .expect("no protocol error");
    assert!(message.is_binary());
}

/// Backing off the idle poll must not slow live delivery.
///
/// The backstop poll used to run every five seconds per subscriber whether or
/// not anything had happened -- at a thousand subscribers, 200 queries a
/// second against the shared accounts database to learn that nothing had
/// changed. It now backs off while the stream is quiet, which is only safe
/// because delivery does not come from it: the broadcast wakes the subscriber
/// the moment the stream moves.
///
/// So this waits past the first poll, by which point the interval has already
/// doubled, and then requires the next write to arrive in less time than the
/// backed-off poll would take. A frame that only turned up on the timer would
/// miss that window.
#[tokio::test(flavor = "multi_thread")]
async fn a_backed_off_subscriber_still_gets_events_immediately() {
    let (app, manager, _tmp) = build_app().await;
    let alice = "did:plc:idlealice";
    let token = create_account(&app, &manager, alice, "alice.idle.example").await;

    let addr = serve(app.clone()).await;
    let uri: http::Uri = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?encoding=cbor")
        .parse()
        .unwrap();
    let (mut socket, _) = ClientBuilder::from_uri(uri).connect().await.unwrap();

    // Past the first backstop fire, so the interval has doubled at least once.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    write_record(&app, alice, &token, "after the poll backed off").await;

    let started = std::time::Instant::now();
    let message = tokio::time::timeout(std::time::Duration::from_secs(3), socket.next())
        .await
        .expect("a backed-off subscriber must still be woken by the broadcast")
        .expect("the socket should stay open")
        .expect("the frame should not be a protocol error");
    assert!(message.is_binary(), "expected a CBOR frame");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "delivery waited for the backstop poll rather than the broadcast"
    );
}
