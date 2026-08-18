//! Decoding frames, and what the consumer does with them.
//!
//! Frames are hand-built here rather than produced by an encoder, because this
//! is a decoder and the point is to pin what it accepts off the wire. That the
//! decoder and `atproto-pds`'s encoder agree is a separate question, asked by
//! `atproto-pds`'s own round-trip test against these same types.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use atproto_dasl::Cid;
use atproto_firehose::consumer::{
    ConsumerConfig, CursorStore, FirehoseConsumer, FrameOutcome, IngestMessage, IngestSink,
};
use atproto_firehose::verify::{SigningKeyResolver, VerificationLevel};
use atproto_firehose::wire::{Event, FrameHeader, InfoPayload, matches_tracked, split_frame};
use atproto_identity::key::KeyData;
use atproto_repo::{RepoOp, RepoOpAction};
use serde::Serialize;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
//  Frame construction.
// ---------------------------------------------------------------------------

/// A `#commit` body as it appears on the wire.
#[derive(Serialize)]
struct CommitBody {
    seq: i64,
    repo: String,
    rev: String,
    time: String,
    commit: Cid,
    #[serde(rename = "prevData", skip_serializing_if = "Option::is_none")]
    prev_data: Option<Cid>,
    ops: Vec<RepoOp>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    // The three tombstones the schema cannot drop. Present on the wire,
    // ignored by the decoder, and here so the test frames are the shape a real
    // server sends.
    rebase: bool,
    #[serde(rename = "tooBig")]
    too_big: bool,
    blobs: Vec<Cid>,
}

fn a_cid(bytes: &[u8]) -> Cid {
    Cid(atproto_dasl::compute_cid_for(&bytes).expect("cid"))
}

fn frame(header: &FrameHeader, body: &impl Serialize) -> Vec<u8> {
    let mut out = atproto_dasl::to_vec(header).expect("header");
    out.extend_from_slice(&atproto_dasl::to_vec(body).expect("body"));
    out
}

fn commit_frame(seq: i64, collections: &[&str], blocks: Vec<u8>) -> Vec<u8> {
    let body = CommitBody {
        seq,
        repo: "did:plc:example".to_string(),
        rev: "3lb2abc".to_string(),
        time: "2026-08-18T00:00:00Z".to_string(),
        commit: a_cid(b"commit"),
        prev_data: Some(a_cid(b"prev")),
        ops: collections
            .iter()
            .enumerate()
            .map(|(index, collection)| RepoOp {
                action: RepoOpAction::Create,
                path: format!("{collection}/rkey{index}"),
                cid: Some(a_cid(collection.as_bytes())),
                prev: None,
            })
            .collect(),
        blocks,
        rebase: false,
        too_big: false,
        blobs: Vec::new(),
    };
    frame(&FrameHeader::message("#commit"), &body)
}

// ---------------------------------------------------------------------------
//  Wire.
// ---------------------------------------------------------------------------

#[test]
fn a_frame_splits_into_a_header_and_a_body() {
    let bytes = commit_frame(42, &["app.test.rec"], b"car".to_vec());
    let split = split_frame(&bytes).expect("split");

    assert_eq!(split.header, FrameHeader::message("#commit"));
    assert!(!split.header.is_error());

    let Event::Commit(envelope) = split.event().expect("event") else {
        panic!("a #commit frame decodes as a commit");
    };
    assert_eq!(envelope.seq, 42);
    assert_eq!(envelope.repo, "did:plc:example");
    assert_eq!(envelope.rev, "3lb2abc");
    assert_eq!(envelope.ops.len(), 1);
    assert_eq!(envelope.ops[0].path, "app.test.rec/rkey0");
    assert!(envelope.prev_data.is_some());

    // Pass two, and only on request.
    assert_eq!(split.commit_blocks().expect("blocks"), b"car");
}

/// The `blocks` byte string is a byte string, not an array of integers.
///
/// `serde_bytes` is what keeps it one. Without it the decoder would walk a
/// two-megabyte payload element by element, which is the cost the two-stage
/// decode exists to avoid paying at all.
#[test]
fn the_blocks_field_survives_as_bytes() {
    let payload: Vec<u8> = (0..=255).collect();
    let bytes = commit_frame(1, &["app.test.rec"], payload.clone());
    let split = split_frame(&bytes).expect("split");
    assert_eq!(split.commit_blocks().expect("blocks"), payload);
}

/// An error frame carries no type tag, which is what tells it apart.
#[test]
fn an_error_frame_has_no_type_tag() {
    let bytes = frame(
        &FrameHeader::error(),
        &serde_json::json!({"error": "FutureCursor", "message": "too far"}),
    );
    let split = split_frame(&bytes).expect("split");
    assert!(split.header.is_error());
    assert_eq!(split.header.t, None);

    let Event::Error(payload) = split.event().expect("event") else {
        panic!("an error frame decodes as an error");
    };
    assert_eq!(payload.error, "FutureCursor");
}

/// The three names removed from the union decode as unknown rather than
/// failing, so a server still emitting them cannot wedge the stream.
#[test]
fn the_retired_members_decode_as_unknown() {
    for retired in ["#handle", "#migrate", "#tombstone"] {
        let bytes = frame(
            &FrameHeader::message(retired),
            &serde_json::json!({"seq": 1, "did": "did:plc:example"}),
        );
        let event = split_frame(&bytes).expect("split").event().expect("event");
        assert_eq!(
            event,
            Event::Unknown {
                type_tag: retired.to_string()
            }
        );
    }
}

#[test]
fn the_tracked_filter_reads_only_the_op_paths() {
    let bytes = commit_frame(1, &["app.bsky.feed.post", "app.bsky.feed.like"], Vec::new());
    let Event::Commit(envelope) = split_frame(&bytes).expect("split").event().expect("event")
    else {
        panic!("a commit")
    };

    assert!(matches_tracked(&envelope, &[]));
    assert!(matches_tracked(
        &envelope,
        &["app.bsky.feed.like".to_string()]
    ));
    assert!(!matches_tracked(
        &envelope,
        &["app.test.rec".to_string(), "app.other.rec".to_string()]
    ));
}

/// A frame whose header decoder overruns is refused rather than indexed into.
#[test]
fn a_truncated_frame_is_refused() {
    let bytes = commit_frame(1, &["app.test.rec"], Vec::new());
    let error = split_frame(&bytes[..2]).expect_err("truncated");
    assert!(error.to_string().contains("error-atproto-firehose-frame-"));
}

// ---------------------------------------------------------------------------
//  Consumer.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Recorder {
    delivered: Mutex<Vec<IngestMessage>>,
    refuse: bool,
}

#[async_trait]
impl IngestSink for Recorder {
    async fn deliver(
        &self,
        message: IngestMessage,
    ) -> Result<atproto_firehose::consumer::Ack, String> {
        self.delivered.lock().await.push(message);
        if self.refuse {
            return Err("the sink is refusing".to_string());
        }
        Ok(atproto_firehose::consumer::Ack)
    }
}

#[derive(Default)]
struct Cursors {
    value: Mutex<Option<i64>>,
    writes: AtomicUsize,
    clears: AtomicUsize,
}

#[async_trait]
impl CursorStore for Cursors {
    async fn load(&self, _source: &str) -> Result<Option<i64>, String> {
        Ok(*self.value.lock().await)
    }

    async fn store(&self, _source: &str, seq: i64) -> Result<(), String> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        *self.value.lock().await = Some(seq);
        Ok(())
    }

    async fn clear(&self, _source: &str) -> Result<(), String> {
        self.clears.fetch_add(1, Ordering::Relaxed);
        *self.value.lock().await = None;
        Ok(())
    }
}

/// A resolver that records whether it was asked at all.
#[derive(Default)]
struct CountingResolver {
    asked: AtomicUsize,
}

#[async_trait]
impl SigningKeyResolver for CountingResolver {
    async fn signing_key(&self, _did: &str) -> Result<KeyData, String> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        Err("no key here".to_string())
    }
}

fn consumer(
    collections: &[&str],
    refuse: bool,
) -> FirehoseConsumer<Recorder, Arc<Cursors>, Arc<CountingResolver>> {
    let config = ConsumerConfig::new("https://relay.example")
        .collections(collections.iter().map(|c| (*c).to_string()).collect())
        .verification(VerificationLevel::Off);
    FirehoseConsumer::new(
        config,
        Recorder {
            refuse,
            ..Recorder::default()
        },
        Arc::new(Cursors::default()),
        Arc::new(CountingResolver::default()),
    )
}

/// The hot path: an untracked commit never touches its CAR.
///
/// The frame's `blocks` field is deliberate nonsense, so anything that tried
/// to parse it would fail rather than quietly succeed. Asserting on the
/// outcome alone would pass against a consumer that parsed the CAR and then
/// discarded it, which is the cost this exists to avoid.
#[tokio::test]
async fn an_untracked_commit_is_skipped_without_parsing_its_car() {
    let consumer = consumer(&["app.test.rec"], false);
    let frame = commit_frame(7, &["app.bsky.feed.post"], b"not a car at all".to_vec());

    assert_eq!(
        consumer.handle_frame(&frame).await,
        FrameOutcome::Skipped(Some(7))
    );
}

/// And a tracked one is delivered with its blocks.
#[tokio::test]
async fn a_tracked_commit_is_delivered_with_its_blocks() {
    let consumer = consumer(&["app.test.rec"], false);
    let frame = commit_frame(8, &["app.test.rec"], b"car bytes".to_vec());

    assert_eq!(
        consumer.handle_frame(&frame).await,
        FrameOutcome::Delivered(8)
    );
}

/// Verification off means the resolver is never asked, which is what makes
/// `VerificationLevel::Off` worth naming rather than leaving implicit.
#[tokio::test]
async fn verification_off_resolves_no_keys() {
    let resolver = Arc::new(CountingResolver::default());
    let config = ConsumerConfig::new("https://relay.example").verification(VerificationLevel::Off);
    let consumer = FirehoseConsumer::new(
        config,
        Recorder::default(),
        Arc::new(Cursors::default()),
        resolver.clone(),
    );

    let frame = commit_frame(9, &["app.test.rec"], b"car".to_vec());
    assert_eq!(
        consumer.handle_frame(&frame).await,
        FrameOutcome::Delivered(9)
    );
    assert_eq!(resolver.asked.load(Ordering::Relaxed), 0);
}

/// A `#sync` is a request to re-read the repository, not a record event.
#[tokio::test]
async fn a_sync_frame_asks_for_a_resync() {
    let consumer = consumer(&[], false);
    let bytes = frame(
        &FrameHeader::message("#sync"),
        &serde_json::json!({
            "seq": 11, "did": "did:plc:example", "rev": "3lb2", "time": "now"
        }),
    );

    assert_eq!(
        consumer.handle_frame(&bytes).await,
        FrameOutcome::Delivered(11)
    );
    let delivered = consumer_messages(&consumer).await;
    assert!(
        matches!(delivered.first(), Some(IngestMessage::Resync(payload)) if payload.rev == "3lb2"),
        "{delivered:?}"
    );
}

async fn consumer_messages(
    consumer: &FirehoseConsumer<Recorder, Arc<Cursors>, Arc<CountingResolver>>,
) -> Vec<IngestMessage> {
    consumer.sink().delivered.lock().await.clone()
}

/// `OutdatedCursor` clears the stored cursor and tells the sink there is a gap.
#[tokio::test]
async fn an_outdated_cursor_is_cleared_and_reported() {
    let cursors = Arc::new(Cursors::default());
    *cursors.value.lock().await = Some(500);

    let consumer = FirehoseConsumer::new(
        ConsumerConfig::new("https://relay.example").verification(VerificationLevel::Off),
        Recorder::default(),
        cursors.clone(),
        Arc::new(CountingResolver::default()),
    );

    let bytes = frame(
        &FrameHeader::message("#info"),
        &serde_json::json!({"name": "OutdatedCursor", "message": "too old"}),
    );

    assert_eq!(
        consumer.handle_frame(&bytes).await,
        FrameOutcome::CursorCleared
    );
    assert_eq!(*cursors.value.lock().await, None);
    assert_eq!(cursors.clears.load(Ordering::Relaxed), 1);

    let delivered = consumer.sink().delivered.lock().await.clone();
    assert!(
        matches!(
            delivered.first(),
            Some(IngestMessage::CursorLost {
                refused: Some(500),
                ..
            })
        ),
        "{delivered:?}"
    );
}

/// Any other `#info` is a notice the stream continues past.
#[tokio::test]
async fn an_ordinary_notice_does_not_clear_the_cursor() {
    let consumer = consumer(&[], false);
    let bytes = frame(
        &FrameHeader::message("#info"),
        &serde_json::json!({"name": "SomethingElse"}),
    );
    assert_eq!(
        consumer.handle_frame(&bytes).await,
        FrameOutcome::Skipped(None)
    );
    assert_eq!(consumer.cursors().clears.load(Ordering::Relaxed), 0);
}

/// A sink that refuses holds the cursor where it was.
#[tokio::test]
async fn a_refused_message_holds_the_cursor() {
    let consumer = consumer(&["app.test.rec"], true);
    let frame = commit_frame(12, &["app.test.rec"], b"car".to_vec());

    assert_eq!(
        consumer.handle_frame(&frame).await,
        FrameOutcome::Held(Some(12))
    );
    // Nothing was written: `Held` is what tells the loop not to.
    assert_eq!(consumer.cursors().writes.load(Ordering::Relaxed), 0);
    assert_eq!(*consumer.cursors().value.lock().await, None);
}

/// An error frame is terminal and names what the server said.
#[tokio::test]
async fn an_error_frame_is_terminal() {
    let consumer = consumer(&[], false);
    let bytes = frame(
        &FrameHeader::error(),
        &serde_json::json!({"error": "FutureCursor", "message": "too far ahead"}),
    );

    let FrameOutcome::Terminal(error) = consumer.handle_frame(&bytes).await else {
        panic!("an error frame ends the subscription");
    };
    assert_eq!(
        error,
        atproto_firehose::ConsumerError::ServerError {
            error: "FutureCursor".to_string(),
            message: "too far ahead".to_string(),
        }
    );
}

/// A member this build does not know is skipped, not fatal.
#[tokio::test]
async fn an_unknown_member_is_skipped() {
    let consumer = consumer(&[], false);
    let bytes = frame(
        &FrameHeader::message("#somethingLater"),
        &serde_json::json!({"seq": 13}),
    );
    assert_eq!(
        consumer.handle_frame(&bytes).await,
        FrameOutcome::Skipped(None)
    );
}

#[test]
fn the_outdated_cursor_notice_is_recognised_by_name() {
    let info = InfoPayload {
        name: "OutdatedCursor".to_string(),
        message: None,
    };
    assert!(info.is_outdated_cursor());
}

// ---------------------------------------------------------------------------
//  Verification.
// ---------------------------------------------------------------------------

/// A resolver that answers with one key.
struct FixedKey(KeyData);

#[async_trait]
impl SigningKeyResolver for FixedKey {
    async fn signing_key(&self, _did: &str) -> Result<KeyData, String> {
        Ok(self.0.clone())
    }
}

/// Build a signed commit over one record, and the CAR slice for it.
///
/// Returns the private key, the envelope a `#commit` would carry, and the
/// slice. Everything is real: a real MST, a real commit object, a real
/// signature over its real signing bytes.
async fn signed_commit(path: &str) -> (KeyData, atproto_firehose::wire::CommitEnvelope, Vec<u8>) {
    use atproto_dasl::car::{CarBlock, CarWriter};
    use atproto_repo::{Commit, MemoryStorage, Mst, RepoConfig};

    let key = atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
        .expect("key");
    let did = "did:plc:example";

    let record = atproto_dasl::to_vec(&"a record").expect("record");
    let record_cid = atproto_dasl::cid::compute_cid(&record);

    let mut mst = Mst::new(MemoryStorage::new(), RepoConfig::default());
    mst.insert(path, record_cid.into()).await.expect("insert");
    let data: Cid = (*mst.root().expect("root")).into();

    let unsigned = Commit::new_unsigned(did.to_string(), data.clone(), "3lb2abc".to_string(), None);
    let signing_bytes = atproto_dasl::to_vec(&unsigned).expect("signing bytes");
    let signature = atproto_identity::key::sign(&key, &signing_bytes).expect("sign");
    let commit = unsigned.sign(signature);
    let commit_bytes = commit.to_bytes().expect("commit bytes");
    let commit_cid = atproto_dasl::cid::compute_cid(&commit_bytes);

    let mut blocks = vec![
        CarBlock {
            cid: commit_cid,
            data: commit_bytes,
        },
        CarBlock {
            cid: record_cid,
            data: record,
        },
    ];
    for (cid, bytes) in mst.storage().blocks() {
        blocks.push(CarBlock {
            cid: *cid,
            data: bytes.clone(),
        });
    }

    let mut writer = CarWriter::new(Vec::new(), vec![Cid(commit_cid)])
        .await
        .expect("writer");
    for block in &blocks {
        writer.write_block(block).await.expect("write");
    }
    let car = writer.finish().await.expect("finish");

    let envelope = atproto_firehose::wire::CommitEnvelope {
        seq: 1,
        repo: did.to_string(),
        rev: "3lb2abc".to_string(),
        since: None,
        time: None,
        commit: commit_cid.into(),
        prev_data: None,
        ops: vec![RepoOp {
            action: RepoOpAction::Create,
            path: path.to_string(),
            cid: Some(record_cid.into()),
            prev: None,
        }],
    };

    (key, envelope, car)
}

/// A real signed commit verifies at every level.
#[tokio::test]
async fn a_signed_commit_verifies_in_full() {
    let (key, envelope, car) = signed_commit("app.test.rec/abc").await;
    let public = atproto_identity::key::to_public(&key).expect("public");
    let resolver = FixedKey(public);

    for (level, expected) in [
        (
            VerificationLevel::Off,
            atproto_firehose::Verification::Skipped,
        ),
        (
            VerificationLevel::SignatureOnly,
            atproto_firehose::Verification::Signature,
        ),
        (
            VerificationLevel::Full,
            atproto_firehose::Verification::Full,
        ),
    ] {
        let verdict = atproto_firehose::verify_commit(level, &envelope, &car, &resolver, &[])
            .await
            .unwrap_or_else(|error| panic!("{level:?} should verify: {error}"));
        assert_eq!(verdict, expected);
    }
}

/// A signature from the wrong key is refused, and named as a signature
/// failure rather than as an unresolvable key.
#[tokio::test]
async fn a_commit_signed_by_someone_else_is_refused() {
    let (_, envelope, car) = signed_commit("app.test.rec/abc").await;
    let other = atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
        .expect("key");
    let resolver = FixedKey(atproto_identity::key::to_public(&other).expect("public"));

    let failure =
        atproto_firehose::verify_commit(VerificationLevel::Full, &envelope, &car, &resolver, &[])
            .await
            .expect_err("a foreign signature");
    assert!(
        failure
            .to_string()
            .contains("error-atproto-firehose-verify-5"),
        "{failure}"
    );
}

/// A lying op is caught even though the signature and the tree are both real.
///
/// This is the half `verify_inductive` cannot do. The commit is genuinely
/// signed, the tree genuinely walks, and the ops array names a CID the tree
/// does not hold at that path -- so a consumer that stopped at the tree would
/// index the wrong record on a commit it had just verified.
#[tokio::test]
async fn a_lying_op_is_refused_after_the_signature_checks_out() {
    let (key, mut envelope, car) = signed_commit("app.test.rec/abc").await;
    let public = atproto_identity::key::to_public(&key).expect("public");
    let resolver = FixedKey(public);

    // A different CID, still a real one.
    envelope.ops[0].cid = Some(a_cid(b"something else entirely"));

    // The signature still checks out, because the ops are not signed.
    let signature_only = atproto_firehose::verify_commit(
        VerificationLevel::SignatureOnly,
        &envelope,
        &car,
        &resolver,
        &[],
    )
    .await
    .expect("the signature is over the commit, not the ops");
    assert_eq!(signature_only, atproto_firehose::Verification::Signature);

    let failure =
        atproto_firehose::verify_commit(VerificationLevel::Full, &envelope, &car, &resolver, &[])
            .await
            .expect_err("a lying op");
    assert!(
        failure
            .to_string()
            .contains("error-atproto-firehose-verify-7"),
        "{failure}"
    );
}

/// A commit that says it belongs to another repository is refused.
///
/// The signature would be real and the tree would be sound; what would be
/// wrong is that the event delivered somebody else's commit under this DID.
#[tokio::test]
async fn a_commit_for_another_repository_is_refused() {
    let (key, mut envelope, car) = signed_commit("app.test.rec/abc").await;
    let resolver = FixedKey(atproto_identity::key::to_public(&key).expect("public"));
    envelope.repo = "did:plc:someone-else".to_string();

    let failure =
        atproto_firehose::verify_commit(VerificationLevel::Full, &envelope, &car, &resolver, &[])
            .await
            .expect_err("a mismatched repository");
    assert!(
        failure
            .to_string()
            .contains("error-atproto-firehose-verify-3"),
        "{failure}"
    );
}
