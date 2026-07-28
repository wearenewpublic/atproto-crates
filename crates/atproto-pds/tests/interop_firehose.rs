//! Known-answer and end-to-end conformance tests for the `subscribeRepos` firehose.
//!
//! The unit tests in `src/sequencer/frame.rs` assert the encoder against
//! itself: they re-encode the expected header with the same function under
//! test, and they read `body["payload"]["rev"]`, which pins the *current*
//! envelope rather than the one the lexicon specifies. Nothing opens a
//! WebSocket. Both gaps are why the frame divergences in the gap analysis
//! survived to a release candidate.
//!
//! These tests close them from the outside:
//!
//! * [`interop_cbor_header_bytes`] and [`interop_info_header_bytes`] assert the
//!   frame header against hand-decoded DAG-CBOR bytes written out from the CBOR
//!   spec, not produced by this crate's encoder.
//! * [`interop_commit_body_matches_lexicon`] asserts the body against the field
//!   set in `com.atproto.sync.subscribeRepos#commit`.
//! * [`subscribe_repos_end_to_end`] runs a real server on a real socket and
//!   reads a real frame off a real WebSocket.
//!
//! # Known failures
//!
//! [`KNOWN_FAILURES`] names each assertion this crate does not yet satisfy,
//! together with the gap-analysis finding that explains why. A listed check is
//! **required to fail**: if it starts passing, the harness fails and tells you
//! to delete the entry, so the table cannot silently rot.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::sequencer::frame::{Encoding, encode_event, encode_info};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures::StreamExt as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tokio_websockets::ClientBuilder;
use tower::ServiceExt;

/// Checks that do not pass yet, each mapped to the finding that explains it.
///
/// Every entry here is a statement that a known, filed defect is still open —
/// never add one to silence a genuine regression.
const KNOWN_FAILURES: &[(&str, &str)] = &[
    // F-FIRE-01 — the CBOR body is an envelope, `{seq, repo, time, payload}`,
    // with the event's own fields nested one level down under `payload`. No
    // member of the `com.atproto.sync.subscribeRepos` union has that shape, so
    // a relay decoding against the lexicon finds none of the required fields.
    // The lexicon body is flat. See gap-analysis roadmap item M1.13.
    ("commit body is flat", "F-FIRE-01"),
    // F-FIRE-04 — payloads are stored as JSON and re-encoded to DAG-CBOR on the
    // way out (see the comment at `sequencer/frame.rs:107-114`). JSON has no
    // byte-string type, so `blocks` — which the lexicon types as `bytes` and
    // which must carry a CARv1 slice — comes back out as a text string.
    ("commit blocks is a CBOR byte string", "F-FIRE-04"),
];

/// Look up a check in [`KNOWN_FAILURES`], returning the finding ID if listed.
fn known_failure(check: &str) -> Option<&'static str> {
    KNOWN_FAILURES
        .iter()
        .find(|(name, _)| *name == check)
        .map(|(_, finding)| *finding)
}

/// Reconcile a check's outcome against [`KNOWN_FAILURES`].
fn reconcile(check: &str, detail: Option<String>, failures: &mut Vec<String>) {
    match (detail, known_failure(check)) {
        (None, None) => {}
        (Some(detail), Some(finding)) => eprintln!("  XFAIL {check} ({finding}): {detail}"),
        (Some(detail), None) => failures.push(format!(
            "REGRESSION: check {check:?} fails and is not in KNOWN_FAILURES: {detail}"
        )),
        (None, Some(finding)) => failures.push(format!(
            "check {check:?} now PASSES — {finding} appears to be fixed. \
             Remove it from KNOWN_FAILURES in this file."
        )),
    }
}

/// Canonical DAG-CBOR encoding of the `#commit` frame header, `{op: 1, t: "#commit"}`.
///
/// Written out from the CBOR spec rather than produced by this crate, so the
/// assertion is not circular. DAG-CBOR orders map keys by length first, then
/// bytewise, which puts `t` ahead of `op`:
///
/// ```text
/// a2                          map(2)
///   61 74                     text(1) "t"
///   67 23 63 6f 6d 6d 69 74   text(7) "#commit"
///   62 6f 70                  text(2) "op"
///   01                        unsigned(1)
/// ```
const COMMIT_HEADER_CBOR: &[u8] = &[
    0xa2, 0x61, 0x74, 0x67, 0x23, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x62, 0x6f, 0x70, 0x01,
];

/// Canonical DAG-CBOR encoding of the `#info` frame header, `{op: -1, t: "#info"}`.
///
/// ```text
/// a2                    map(2)
///   61 74               text(1) "t"
///   65 23 69 6e 66 6f   text(5) "#info"
///   62 6f 70            text(2) "op"
///   20                  negative(-1)
/// ```
const INFO_HEADER_CBOR: &[u8] = &[
    0xa2, 0x61, 0x74, 0x65, 0x23, 0x69, 0x6e, 0x66, 0x6f, 0x62, 0x6f, 0x70, 0x20,
];

/// Required fields of `com.atproto.sync.subscribeRepos#commit`.
///
/// Taken from the canonical lexicon. `prevData` is optional and deliberately
/// excluded; `since` is required but nullable.
const COMMIT_REQUIRED_FIELDS: &[&str] = &[
    "blobs", "blocks", "commit", "ops", "rebase", "repo", "rev", "seq", "since", "time", "tooBig",
];

/// A representative `#commit` payload in the shape the lexicon specifies.
fn lexicon_commit_payload() -> Value {
    json!({
        "seq": 42,
        "rebase": false,
        "tooBig": false,
        "repo": "did:plc:a",
        "commit": { "$link": "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454" },
        "rev": "3kmev",
        "since": Value::Null,
        "blocks": { "$bytes": "oQFiaGk" },
        "ops": [],
        "blobs": [],
        "time": "2026-07-28T00:00:00.000Z",
    })
}

/// Split a CBOR frame into its header and body halves.
///
/// The frame is two concatenated DAG-CBOR objects. `atproto_dasl` rejects
/// trailing data, so the header length has to be known to split them — here it
/// comes from the hand-written constant, which is the point.
fn split_frame<'a>(frame: &'a [u8], expected_header: &[u8]) -> &'a [u8] {
    &frame[expected_header.len()..]
}

#[test]
fn interop_cbor_header_bytes() {
    let payload = serde_json::to_vec(&lexicon_commit_payload()).unwrap();
    let (frame, is_text) = encode_event(
        Encoding::Cbor,
        "commit",
        42,
        "did:plc:a",
        &payload,
        "2026-07-28T00:00:00.000Z",
    )
    .expect("commit frame should encode");

    assert!(
        !is_text,
        "CBOR frames must be sent as binary WebSocket messages"
    );
    assert!(
        frame.starts_with(COMMIT_HEADER_CBOR),
        "frame header is not the canonical DAG-CBOR of {{op: 1, t: \"#commit\"}}\n  \
         expected prefix: {}\n  got frame start:  {}",
        hex::encode(COMMIT_HEADER_CBOR),
        hex::encode(&frame[..frame.len().min(COMMIT_HEADER_CBOR.len())])
    );
}

#[test]
fn interop_info_header_bytes() {
    let (frame, is_text) = encode_info(Encoding::Cbor, "OutdatedCursor", "cursor too old");

    assert!(
        !is_text,
        "CBOR frames must be sent as binary WebSocket messages"
    );
    assert!(
        frame.starts_with(INFO_HEADER_CBOR),
        "info frame header is not the canonical DAG-CBOR of {{op: -1, t: \"#info\"}}\n  \
         expected prefix: {}\n  got frame start:  {}",
        hex::encode(INFO_HEADER_CBOR),
        hex::encode(&frame[..frame.len().min(INFO_HEADER_CBOR.len())])
    );
}

/// Assert the `#commit` body against the lexicon's field set.
///
/// This is the assertion the gap analysis identifies as the one that would have
/// caught the frame divergences. It is deliberately structural rather than
/// byte-for-byte: the encoder does not yet emit this shape at all, so pinning
/// exact bytes would only record how far off it is.
#[test]
fn interop_commit_body_matches_lexicon() {
    let payload = serde_json::to_vec(&lexicon_commit_payload()).unwrap();
    let (frame, _) = encode_event(
        Encoding::Cbor,
        "commit",
        42,
        "did:plc:a",
        &payload,
        "2026-07-28T00:00:00.000Z",
    )
    .expect("commit frame should encode");

    let body: Value = atproto_dasl::from_slice(split_frame(&frame, COMMIT_HEADER_CBOR))
        .expect("frame body should decode as DAG-CBOR");
    let map = body.as_object().expect("frame body should be a map");

    let mut failures = Vec::new();

    let missing: Vec<&str> = COMMIT_REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|field| !map.contains_key(*field))
        .collect();
    reconcile(
        "commit body is flat",
        (!missing.is_empty()).then(|| {
            let mut present: Vec<&str> = map.keys().map(String::as_str).collect();
            present.sort_unstable();
            format!("missing required lexicon fields {missing:?}; body carries {present:?}")
        }),
        &mut failures,
    );

    // `blocks` is typed `bytes` in the lexicon. Once decoded from DAG-CBOR into
    // `serde_json::Value`, a CBOR byte string surfaces as the `$bytes` sentinel
    // object; a CBOR text string surfaces as a plain string.
    let blocks_is_bytes = map
        .get("blocks")
        .is_some_and(|value| value.get("$bytes").is_some());
    reconcile(
        "commit blocks is a CBOR byte string",
        (!blocks_is_bytes).then(|| match map.get("blocks") {
            Some(value) => format!("blocks decoded as {value}"),
            None => "blocks absent from the body entirely".to_string(),
        }),
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "{} firehose check(s) need attention:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Build a PDS router backed by a temporary directory.
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

/// Create an account and return its access token.
async fn create_account(app: &axum::Router, did: &str, handle: &str) -> String {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "did": did, "handle": handle, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"]
        .as_str()
        .expect("createAccount should return an access token")
        .to_string()
}

/// Connect a WebSocket subscriber to a live `subscribeRepos` and read one frame.
///
/// No test in this crate had ever opened the firehose socket. Everything about
/// the handler above the encoder — the upgrade, the outbox drain, the broadcast
/// wakeup, the framing on the wire — was untested. This covers that path end to
/// end: a real listener, a real HTTP upgrade, a real record write and a real
/// binary frame read back off the socket.
#[tokio::test(flavor = "multi_thread")]
async fn subscribe_repos_end_to_end() {
    let (app, _tmp) = build_app().await;
    let did = "did:plc:firehosee2e";
    let token = create_account(&app, did, "e2e.test.example").await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = app.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, served).await;
    });

    let uri: http::Uri =
        format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?did={did}&encoding=cbor")
            .parse()
            .unwrap();
    let (mut socket, response) = ClientBuilder::from_uri(uri)
        .connect()
        .await
        .expect("subscribeRepos should accept a WebSocket upgrade");
    assert_eq!(
        response.status(),
        StatusCode::SWITCHING_PROTOCOLS,
        "subscribeRepos should complete the WebSocket handshake"
    );

    // Write a record so the sequencer has an event to broadcast.
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hello firehose" }
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

    let message = tokio::time::timeout(std::time::Duration::from_secs(30), socket.next())
        .await
        .expect("a frame should arrive within 30s of the write")
        .expect("the socket should stay open")
        .expect("the frame should not be a protocol error");

    assert!(
        message.is_binary(),
        "CBOR subscribers must receive binary frames, got {message:?}"
    );
    let frame = message.as_payload();
    assert!(
        frame.starts_with(COMMIT_HEADER_CBOR),
        "first frame is not a #commit event\n  expected header: {}\n  got frame start: {}",
        hex::encode(COMMIT_HEADER_CBOR),
        hex::encode(&frame[..frame.len().min(COMMIT_HEADER_CBOR.len())])
    );
}
