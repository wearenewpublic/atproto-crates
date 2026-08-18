//! The encoder here and the decoder in `atproto-firehose` agree.
//!
//! `interop_firehose.rs` asserts the frame header against hand-decoded bytes
//! written out from the CBOR specification, which is the right check for "does
//! this match the wire format". It does not answer "can a consumer read what
//! this produces", and the two are different questions: a frame can be
//! byte-correct and still be one no decoder in this workspace parses, because
//! the encoder and the decoder were never run against each other.
//!
//! They share their header type now, so the two cannot drift silently. These
//! tests are what makes that sharing load-bearing rather than decorative:
//! every frame shape this server emits is split, decoded, and compared field
//! by field against what went in.

use atproto_dasl::Cid;
use atproto_firehose::wire::{Event, split_frame};
use atproto_pds::sequencer::frame::{Encoding, encode_error, encode_event, encode_info};
use atproto_pds::sequencer::payload::{
    AccountBody, CommitBody, IdentityBody, SyncBody, encode as encode_body,
};
use atproto_repo::{RepoOp, RepoOpAction};

fn a_cid(text: &str) -> Cid {
    Cid(text.parse().expect("a cid"))
}

const COMMIT_CID: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
const PREV_DATA_CID: &str = "bafyreidfuxwyqcmxrpqzurbfvyyfvjrmatlsn3vczyfvsjnjyyxsxvymqu";
const RECORD_CID: &str = "bafyreibxrjhrzcyqvqfgvhrrrqcnbkuoqrqgpyqvzsxvfpsbdgrqvqxvme";

/// A `#commit` survives the trip with every field this consumer reads.
#[test]
fn a_commit_frame_round_trips() {
    let body = encode_body(&CommitBody {
        rebase: false,
        too_big: false,
        repo: "did:plc:a".to_string(),
        commit: a_cid(COMMIT_CID),
        rev: "3kmev".to_string(),
        since: Some("3kmeu".to_string()),
        blocks: b"a car slice".to_vec(),
        ops: vec![RepoOp {
            action: RepoOpAction::Create,
            path: "app.test.rec/abc".to_string(),
            cid: Some(a_cid(RECORD_CID)),
            prev: None,
        }],
        blobs: Vec::new(),
        prev_data: Some(a_cid(PREV_DATA_CID)),
    })
    .expect("body");

    let (frame, is_text) = encode_event(
        Encoding::Cbor,
        "commit",
        42,
        "did:plc:a",
        &body,
        "2026-08-18T00:00:00.000Z",
    )
    .expect("frame");
    assert!(!is_text);

    let split = split_frame(&frame).expect("split");
    assert_eq!(split.header.op, 1);
    assert_eq!(split.header.t.as_deref(), Some("#commit"));

    let Event::Commit(envelope) = split.event().expect("event") else {
        panic!("a #commit frame decodes as a commit");
    };

    // `seq` and `time` belong to the delivery and are spliced in by the
    // encoder, so the round trip is what proves they arrive at all.
    assert_eq!(envelope.seq, 42);
    assert_eq!(envelope.time.as_deref(), Some("2026-08-18T00:00:00.000Z"));

    assert_eq!(envelope.repo, "did:plc:a");
    assert_eq!(envelope.rev, "3kmev");
    assert_eq!(envelope.since.as_deref(), Some("3kmeu"));
    assert_eq!(envelope.commit, a_cid(COMMIT_CID));
    assert_eq!(envelope.prev_data, Some(a_cid(PREV_DATA_CID)));

    assert_eq!(envelope.ops.len(), 1);
    assert_eq!(envelope.ops[0].action, RepoOpAction::Create);
    assert_eq!(envelope.ops[0].path, "app.test.rec/abc");
    assert_eq!(envelope.ops[0].cid, Some(a_cid(RECORD_CID)));

    // Pass two, from the same bytes.
    assert_eq!(split.commit_blocks().expect("blocks"), b"a car slice");
}

/// A `#sync` names the repository `did`, not `repo`.
#[test]
fn a_sync_frame_round_trips() {
    let body = encode_body(&SyncBody {
        did: "did:plc:a".to_string(),
        blocks: b"head commit".to_vec(),
        rev: "3kmev".to_string(),
    })
    .expect("body");

    let (frame, _) =
        encode_event(Encoding::Cbor, "sync", 7, "did:plc:a", &body, "now").expect("frame");

    let Event::Sync(payload) = split_frame(&frame).expect("split").event().expect("event") else {
        panic!("a #sync frame decodes as a sync");
    };
    assert_eq!(payload.seq, 7);
    assert_eq!(payload.did, "did:plc:a");
    assert_eq!(payload.rev, "3kmev");
}

#[test]
fn an_identity_frame_round_trips() {
    let body = encode_body(&IdentityBody {
        did: "did:plc:a".to_string(),
        handle: Some("alice.example".to_string()),
    })
    .expect("body");

    let (frame, _) =
        encode_event(Encoding::Cbor, "identity", 8, "did:plc:a", &body, "now").expect("frame");

    let Event::Identity(payload) = split_frame(&frame).expect("split").event().expect("event")
    else {
        panic!("an #identity frame decodes as an identity");
    };
    assert_eq!(payload.seq, 8);
    assert_eq!(payload.handle.as_deref(), Some("alice.example"));
}

#[test]
fn an_account_frame_round_trips() {
    let body = encode_body(&AccountBody {
        did: "did:plc:a".to_string(),
        active: false,
        status: Some("takendown".to_string()),
    })
    .expect("body");

    let (frame, _) =
        encode_event(Encoding::Cbor, "account", 9, "did:plc:a", &body, "now").expect("frame");

    let Event::Account(payload) = split_frame(&frame).expect("split").event().expect("event")
    else {
        panic!("an #account frame decodes as an account");
    };
    assert_eq!(payload.seq, 9);
    assert!(!payload.active);
    assert_eq!(payload.status.as_deref(), Some("takendown"));
}

/// `#info` is a message frame, and the consumer recognises `OutdatedCursor` by
/// name. Emitting it as an error frame -- which this encoder once did -- would
/// tell the consumer to disconnect over a notice that its cursor was old.
#[test]
fn an_info_frame_round_trips_as_a_message() {
    let (frame, is_text) = encode_info(Encoding::Cbor, "OutdatedCursor", "cursor too old");
    assert!(!is_text);

    let split = split_frame(&frame).expect("split");
    assert!(!split.header.is_error(), "#info is a message frame");

    let Event::Info(payload) = split.event().expect("event") else {
        panic!("an #info frame decodes as info");
    };
    assert!(payload.is_outdated_cursor());
    assert_eq!(payload.message.as_deref(), Some("cursor too old"));
}

/// An error frame carries no type tag, and the consumer treats it as terminal.
#[test]
fn an_error_frame_round_trips_without_a_type_tag() {
    let (frame, is_text) = encode_error(Encoding::Cbor, "FutureCursor", "too far ahead");
    assert!(!is_text);

    let split = split_frame(&frame).expect("split");
    assert!(split.header.is_error());
    assert_eq!(
        split.header.t, None,
        "an error frame must not carry a type tag"
    );

    let Event::Error(payload) = split.event().expect("event") else {
        panic!("an error frame decodes as an error");
    };
    assert_eq!(payload.error, "FutureCursor");
    assert_eq!(payload.message.as_deref(), Some("too far ahead"));
}
