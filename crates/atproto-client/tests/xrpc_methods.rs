//! The repository and sync methods added on top of the status-preserving
//! transport.
//!
//! Two kinds of assertion here. The wire shapes -- `$type` discriminators, an
//! omitted `rkey`, an absent `results` -- are pure serde and would be invisible
//! in Rust: a discriminator wrong by a word compiles and is refused by every
//! server. The rest drive a scripted socket, because "sent the content type it
//! was given" and "read the status before the body" are properties of the
//! request, not of the return value.

use atproto_client::client::{AppPasswordAuth, Auth};
use atproto_client::com::atproto::repo::{
    ApplyWritesRequest, ApplyWritesResponse, MAX_WRITES_PER_COMMIT, WriteOp, WriteResult,
    apply_writes, upload_blob,
};
use atproto_client::com::atproto::sync::{get_record, get_repo, subscribe_repos_url};
use atproto_client::errors::XrpcError;

mod support;
use support::{Reply, Scripted};

fn auth() -> Auth {
    Auth::AppPassword(AppPasswordAuth {
        access_token: "app-password-token".to_string(),
    })
}

// ---------------------------------------------------------------------------
//  Wire shapes.
// ---------------------------------------------------------------------------

/// A discriminator wrong by a word is a batch every PDS refuses, and it is
/// invisible in Rust.
#[test]
fn every_write_op_carries_its_lexicon_type() {
    let create = serde_json::to_value(WriteOp::Create {
        collection: "app.test.rec".to_string(),
        rkey: Some("abc".to_string()),
        value: serde_json::json!({"text": "hi"}),
    })
    .expect("serialize");
    assert_eq!(
        create,
        serde_json::json!({
            "$type": "com.atproto.repo.applyWrites#create",
            "collection": "app.test.rec",
            "rkey": "abc",
            "value": {"text": "hi"},
        })
    );

    let update = serde_json::to_value(WriteOp::Update {
        collection: "app.test.rec".to_string(),
        rkey: "abc".to_string(),
        value: serde_json::json!({"text": "bye"}),
    })
    .expect("serialize");
    assert_eq!(update["$type"], "com.atproto.repo.applyWrites#update");

    let delete = serde_json::to_value(WriteOp::Delete {
        collection: "app.test.rec".to_string(),
        rkey: "abc".to_string(),
    })
    .expect("serialize");
    assert_eq!(
        delete,
        serde_json::json!({
            "$type": "com.atproto.repo.applyWrites#delete",
            "collection": "app.test.rec",
            "rkey": "abc",
        })
    );
}

/// A create with no `rkey` omits the key rather than sending `null`.
///
/// The lexicon declares it optional, not nullable, and a server reading
/// `"rkey": null` as "the empty record key" writes to a key nobody asked for.
#[test]
fn a_create_without_a_key_omits_the_field() {
    let create = serde_json::to_value(WriteOp::Create {
        collection: "app.test.rec".to_string(),
        rkey: None,
        value: serde_json::json!({}),
    })
    .expect("serialize");

    let object = create.as_object().expect("an object");
    assert!(!object.contains_key("rkey"), "{create}");
}

/// The regression test for the note on `ApplyWritesResponse::results`.
///
/// Some PDS builds answer a successful batch with a bare commit and no
/// per-op results. Failing there turns a write that happened into an error the
/// caller retries, which creates a duplicate.
#[test]
fn a_response_with_no_results_still_decodes() {
    let response: ApplyWritesResponse = serde_json::from_value(serde_json::json!({
        "commit": {"cid": "bafycommit", "rev": "3lb2"}
    }))
    .expect("decode");

    assert_eq!(response.results, None);
    assert_eq!(response.commit.expect("commit").rev, "3lb2");
}

/// A `$type` this build does not know does not sink the whole response.
#[test]
fn an_unknown_result_type_decodes_as_unknown() {
    let response: ApplyWritesResponse = serde_json::from_value(serde_json::json!({
        "commit": {"cid": "bafycommit", "rev": "3lb2"},
        "results": [
            {"$type": "com.atproto.repo.applyWrites#createResult",
             "uri": "at://did:plc:x/app.test.rec/abc", "cid": "bafyrec"},
            {"$type": "com.atproto.repo.applyWrites#deleteResult"},
            {"$type": "com.atproto.repo.applyWrites#somethingLaterResult"},
        ]
    }))
    .expect("decode");

    let results = response.results.expect("results");
    assert!(matches!(results[0], WriteResult::Create { .. }));
    assert_eq!(results[1], WriteResult::Delete);
    assert_eq!(results[2], WriteResult::Unknown);
}

/// The batch limit is the protocol's, and the server refuses the whole commit
/// past it rather than the excess.
#[test]
fn the_batch_limit_is_the_one_the_specification_states() {
    assert_eq!(MAX_WRITES_PER_COMMIT, 200);
}

// ---------------------------------------------------------------------------
//  Requests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_writes_posts_the_batch_and_reads_the_results() {
    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"commit":{"cid":"bafycommit","rev":"3lb2"},
            "results":[{"$type":"com.atproto.repo.applyWrites#createResult",
                        "uri":"at://did:plc:x/app.test.rec/abc","cid":"bafyrec"}]}"#,
    )])
    .await;

    let request = ApplyWritesRequest {
        repo: "did:plc:x".to_string(),
        validate: Some(true),
        writes: vec![WriteOp::Create {
            collection: "app.test.rec".to_string(),
            rkey: None,
            value: serde_json::json!({"text": "hi"}),
        }],
        swap_commit: None,
    };

    let response = apply_writes(&reqwest::Client::new(), &auth(), &server.base_url, &request)
        .await
        .expect("apply");

    assert_eq!(response.results.expect("results").len(), 1);

    let requests = server.requests().await;
    assert!(
        requests[0]
            .request_line
            .starts_with("POST /xrpc/com.atproto.repo.applyWrites "),
        "{}",
        requests[0].request_line
    );
    let sent: serde_json::Value = serde_json::from_str(&requests[0].body).expect("json body");
    assert_eq!(
        sent["writes"][0]["$type"],
        "com.atproto.repo.applyWrites#create"
    );
    assert!(sent["writes"][0].get("rkey").is_none());
    // Absent rather than null: the lexicon declares it optional.
    assert!(sent.get("swapCommit").is_none());
}

/// `InvalidSwap` reaches the caller as a typed error rather than as a body it
/// has to inspect, which is the whole reason these are built on a transport
/// that keeps the status.
#[tokio::test]
async fn a_refused_batch_is_a_typed_error() {
    let server = Scripted::start(vec![Reply::new(
        400,
        r#"{"error":"InvalidSwap","message":"Commit was at bafyother"}"#,
    )])
    .await;

    let request = ApplyWritesRequest {
        repo: "did:plc:x".to_string(),
        validate: None,
        writes: vec![WriteOp::Delete {
            collection: "app.test.rec".to_string(),
            rkey: "abc".to_string(),
        }],
        swap_commit: Some("bafycommit".to_string()),
    };

    let error = apply_writes(&reqwest::Client::new(), &auth(), &server.base_url, &request)
        .await
        .expect_err("refused");

    assert_eq!(
        error.downcast_ref::<XrpcError>(),
        Some(&XrpcError::InvalidSwap {
            message: "Commit was at bafyother".to_string()
        })
    );
}

/// The blob's content type is what the server records on it, so it has to be
/// the one the caller determined from the bytes.
#[tokio::test]
async fn upload_blob_sends_the_given_content_type_and_the_exact_bytes() {
    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"blob":{"$type":"blob","ref":{"$link":"bafkreiblob"},
                   "mimeType":"image/png","size":16}}"#,
    )])
    .await;

    let response = upload_blob(
        &reqwest::Client::new(),
        &auth(),
        &server.base_url,
        "image/png",
        b"not-really-a-png".to_vec(),
    )
    .await
    .expect("upload");

    assert_eq!(response.blob.mime_type, "image/png");
    assert_eq!(response.blob.size, 16);

    let requests = server.requests().await;
    assert_eq!(requests[0].header("content-type"), Some("image/png"));
    assert_eq!(
        requests[0].header("authorization"),
        Some("Bearer app-password-token")
    );
    assert_eq!(requests[0].body, "not-really-a-png");
}

// ---------------------------------------------------------------------------
//  Sync.
// ---------------------------------------------------------------------------

/// A CAR is not JSON, so the status has to decide before the body is read.
#[tokio::test]
async fn a_car_export_comes_back_as_bytes() {
    // Not valid CAR, deliberately: parsing one is `atproto-repo`'s job and
    // this is asserting that the transport hands the bytes over untouched.
    let server = Scripted::start(vec![Reply::new(200, "\x3aroots-and-blocks")]).await;

    let bytes = get_repo(
        &reqwest::Client::new(),
        &Auth::None,
        &server.base_url,
        "did:plc:x",
        Some("3lb2"),
    )
    .await
    .expect("export");

    assert_eq!(&bytes[..], b"\x3aroots-and-blocks");

    let requests = server.requests().await;
    assert!(
        requests[0].request_line.contains("since=3lb2"),
        "{}",
        requests[0].request_line
    );
}

/// And a refusal on the same method is still a typed error rather than "the
/// body was not JSON".
#[tokio::test]
async fn a_refused_export_is_a_typed_error() {
    let server = Scripted::start(vec![Reply::new(
        404,
        r#"{"error":"RecordNotFound","message":"no such record"}"#,
    )])
    .await;

    let error = get_record(
        &reqwest::Client::new(),
        &Auth::None,
        &server.base_url,
        "did:plc:x",
        "app.test.rec",
        "abc",
    )
    .await
    .expect_err("refused");

    assert_eq!(
        error.downcast_ref::<XrpcError>(),
        Some(&XrpcError::Lexicon {
            status: 404,
            code: "RecordNotFound".to_string(),
            message: "no such record".to_string(),
        })
    );
}

/// The firehose URL takes its scheme from the host's, so a local plaintext PDS
/// develops against `ws://` without a second argument saying so.
#[test]
fn the_firehose_url_follows_the_hosts_scheme() {
    assert_eq!(
        subscribe_repos_url("https://bsky.network", None).expect("url"),
        "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
    );
    assert_eq!(
        subscribe_repos_url("http://127.0.0.1:2583", Some(42)).expect("url"),
        "ws://127.0.0.1:2583/xrpc/com.atproto.sync.subscribeRepos?cursor=42"
    );
    // A bare hostname is https, as everywhere else in this crate.
    assert_eq!(
        subscribe_repos_url("bsky.network", None).expect("url"),
        "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
    );
}
