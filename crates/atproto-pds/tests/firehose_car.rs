//! `#commit.blocks` and `#sync.blocks` must carry a real CARv1.
//!
//! The firehose is what federation runs on, and a `#commit` that names record
//! CIDs without shipping the record bytes is an existence notification rather
//! than a data feed — a consumer learns that something changed and has to come
//! back over XRPC to find out what. The lexicon types `blocks` as `bytes` and
//! describes it as a CAR whose first root is the commit block.
//!
//! These tests read the events the write path actually recorded and parse
//! `blocks` as a CAR, so they fail if the slice is absent, empty, malformed,
//! wrongly rooted, or missing the blocks the same event's `ops` refer to.
//!
//! What is *not* asserted here: the covering proof (F-FIRE-06). A CAR built
//! from the blocks a commit newly wrote is not yet the inductive proof Sync 1.1
//! wants, and `blocksInProof` in the vendored `commit-proof-fixtures.json`
//! describes that different, larger set. Asserting it belongs with that work.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoWriter, WriteAction, WriteOp};
use atproto_pds::sequencer::{Sequencer, StreamRow};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

/// A writer over a temporary data directory, with `did:plc:alice` created.
async fn fresh_writer() -> (RepoWriter, Sequencer, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let sequencer = Sequencer::new(accounts.account_pool());
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    manager
        .create_account(CreateAccountParams {
            did: "did:plc:alice",
            handle: "alice.example",
            email: None,
            password: "pw",
            pds_managed_rotation: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let writer = RepoWriter::new(manager, dir);
    (writer, sequencer, tmp)
}

fn create(rkey: &str, text: &str) -> WriteOp {
    WriteOp {
        action: WriteAction::Create,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        value: Some(serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": text,
        })),
        swap_record: None,
    }
}

fn delete(rkey: &str) -> WriteOp {
    WriteOp {
        action: WriteAction::Delete,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        value: None,
        swap_record: None,
    }
}

/// Decode a stored event body into its DAG-CBOR map.
fn body_of(row: &StreamRow) -> BTreeMap<String, atproto_dasl::Ipld> {
    match atproto_dasl::from_slice(&row.payload).expect("an event body should decode") {
        atproto_dasl::Ipld::Map(map) => map,
        other => panic!("an event body is a map, got {other:?}"),
    }
}

/// The `#commit` rows of a stream read, in order.
///
/// Account creation also emits `#identity` and `#account`, so the first row of
/// a stream is no longer necessarily the commit. These tests are about what a
/// commit carries, so they select commits rather than assuming a position.
fn commit_rows(
    rows: Vec<atproto_pds::sequencer::StreamRow>,
) -> Vec<atproto_pds::sequencer::StreamRow> {
    rows.into_iter()
        .filter(|row| row.event_type == atproto_pds::sequencer::EventType::Commit.as_str())
        .collect()
}

fn blocks_field(body: &BTreeMap<String, atproto_dasl::Ipld>) -> Vec<u8> {
    match body.get("blocks") {
        Some(atproto_dasl::Ipld::Bytes(bytes)) => bytes.clone(),
        other => panic!("`blocks` is typed `bytes` in the lexicon, got {other:?}"),
    }
}

/// Parse a CAR, returning its first root and its blocks keyed by CID.
async fn read_car(bytes: &[u8]) -> (cid::Cid, BTreeMap<String, Vec<u8>>) {
    assert!(
        !bytes.is_empty(),
        "`blocks` carries no CAR at all — the event names records it does not ship"
    );
    let mut reader = atproto_dasl::car::CarReader::new(std::io::Cursor::new(bytes.to_vec()))
        .await
        .expect("`blocks` should parse as a CARv1");
    let root = reader
        .root()
        .cloned()
        .expect("a CAR in `blocks` carries the commit as its first root");

    let mut blocks = BTreeMap::new();
    while let Some(block) = reader
        .next_block()
        .await
        .expect("every block in the CAR should be readable")
    {
        blocks.insert(block.cid.to_string(), block.data);
    }
    (root.0, blocks)
}

/// The CIDs an event's `ops` name, in order.
fn op_cids(body: &BTreeMap<String, atproto_dasl::Ipld>) -> Vec<Option<String>> {
    let atproto_dasl::Ipld::List(ops) = &body["ops"] else {
        panic!("`ops` is a list")
    };
    ops.iter()
        .map(|op| {
            let atproto_dasl::Ipld::Map(op) = op else {
                panic!("an op is a map")
            };
            match op.get("cid") {
                Some(atproto_dasl::Ipld::Link(cid)) => Some(cid.0.to_string()),
                _ => None,
            }
        })
        .collect()
}

/// `#commit.blocks` is a CAR rooted at the commit this event announces, and it
/// carries the record the event says was created.
#[tokio::test(flavor = "multi_thread")]
async fn a_commit_ships_the_record_it_announces() {
    let (writer, stream, _tmp) = fresh_writer().await;
    let result = writer
        .apply_writes("did:plc:alice", vec![create("aaa", "hello firehose")])
        .await
        .unwrap();

    let rows = commit_rows(stream.read_after(None, None, 10).await.unwrap());
    assert_eq!(rows.len(), 1);
    let body = body_of(&rows[0]);
    let (root, blocks) = read_car(&blocks_field(&body)).await;

    assert_eq!(
        root.to_string(),
        result.commit_cid,
        "the CAR's first root is the commit this event announces"
    );
    assert!(
        blocks.contains_key(&result.commit_cid),
        "the commit block itself must be in the CAR"
    );

    let record_cid = op_cids(&body)[0]
        .clone()
        .expect("a create op names the record's CID");
    assert!(
        blocks.contains_key(&record_cid),
        "the CAR must carry the record block the op names ({record_cid}); \
         it ships {:?}",
        blocks.keys().collect::<Vec<_>>()
    );

    // The record block must be the bytes that hash to that CID, and must
    // decode to the record that was written.
    let record = blocks.get(&record_cid).unwrap();
    let value: serde_json::Value = atproto_dasl::atproto_json::from_slice(record).unwrap();
    assert_eq!(value["text"], "hello firehose");
}

/// The MST root the commit points at must be reachable inside the CAR.
///
/// Without it a consumer holds a commit whose `data` link dangles, and cannot
/// verify that the records shipped alongside are the ones the tree names.
#[tokio::test(flavor = "multi_thread")]
async fn a_commit_ships_the_tree_its_root_points_at() {
    let (writer, stream, _tmp) = fresh_writer().await;
    let result = writer
        .apply_writes("did:plc:alice", vec![create("aaa", "one")])
        .await
        .unwrap();

    let rows = commit_rows(stream.read_after(None, None, 10).await.unwrap());
    let (_, blocks) = read_car(&blocks_field(&body_of(&rows[0]))).await;
    assert!(
        blocks.contains_key(&result.data_cid),
        "the MST root {} must be in the CAR; it ships {:?}",
        result.data_cid,
        blocks.keys().collect::<Vec<_>>()
    );
}

/// A commit ships its diff, not the whole repository.
///
/// `blocks` is described as a diff since the previous state. Re-sending every
/// block on every commit would be correct-but-useless — the cost of the
/// firehose would grow with repository size rather than with change size.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_commit_ships_only_what_it_changed() {
    let (writer, stream, _tmp) = fresh_writer().await;
    let first = writer
        .apply_writes("did:plc:alice", vec![create("aaa", "one")])
        .await
        .unwrap();
    writer
        .apply_writes("did:plc:alice", vec![create("bbb", "two")])
        .await
        .unwrap();

    let rows = commit_rows(stream.read_after(None, None, 10).await.unwrap());
    assert_eq!(rows.len(), 2);
    let (_, second_blocks) = read_car(&blocks_field(&body_of(&rows[1]))).await;

    assert!(
        !second_blocks.contains_key(&first.commit_cid),
        "the second commit re-shipped the first commit's block"
    );
    let first_record = op_cids(&body_of(&rows[0]))[0].clone().unwrap();
    assert!(
        !second_blocks.contains_key(&first_record),
        "the second commit re-shipped the first commit's record block; \
         `blocks` is a diff, not a snapshot"
    );
}

/// A delete ships the proof it happened, and no record block.
#[tokio::test(flavor = "multi_thread")]
async fn a_delete_ships_a_tree_but_no_record() {
    let (writer, stream, _tmp) = fresh_writer().await;
    let created = writer
        .apply_writes("did:plc:alice", vec![create("aaa", "one")])
        .await
        .unwrap();
    let deleted = writer
        .apply_writes("did:plc:alice", vec![delete("aaa")])
        .await
        .unwrap();

    let rows = commit_rows(stream.read_after(None, None, 10).await.unwrap());
    let body = body_of(&rows[1]);
    let (root, blocks) = read_car(&blocks_field(&body)).await;

    assert_eq!(root.to_string(), deleted.commit_cid);
    assert_eq!(
        op_cids(&body),
        vec![None],
        "a delete op carries a null cid — required and nullable"
    );
    assert!(
        blocks.contains_key(&deleted.data_cid),
        "the post-delete MST root must be in the CAR"
    );

    let removed_record = op_cids(&body_of(&rows[0]))[0].clone().unwrap();
    assert!(
        !blocks.contains_key(&removed_record),
        "a delete must not ship the record it removed"
    );
    assert_ne!(created.data_cid, deleted.data_cid);
}

/// `#sync` carries the commit it force-sets.
///
/// `#sync` exists so a consumer that lost the `#commit` chain can re-anchor.
/// One that carries no commit block gives it nothing to anchor to.
#[tokio::test(flavor = "multi_thread")]
async fn a_sync_event_ships_its_commit() {
    let (writer, stream, tmp) = fresh_writer().await;
    let result = writer
        .apply_writes("did:plc:alice", vec![create("aaa", "one")])
        .await
        .unwrap();

    // Read the head commit block back the way `forceRepoSync` does.
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(tmp.path(), "did:plc:alice")
        .await
        .unwrap();
    let commit_cid: cid::Cid = result.commit_cid.parse().unwrap();
    let (commit_block,): (Vec<u8>,) = sqlx::query_as("SELECT data FROM repo_block WHERE cid = ?")
        .bind(&result.commit_cid)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let event = atproto_pds::sequencer::sync_event::SyncEvent {
        did: "did:plc:alice",
        rev: &result.rev,
        commit_cid: &commit_cid,
        commit_block: &commit_block,
    };
    atproto_pds::sequencer::publish_sync(&stream, &event)
        .await
        .unwrap();

    // This one wants the #sync row, not a commit — filtering to commits here
    // would select the wrong event and assert against it.
    let rows = stream.read_after(None, None, 10).await.unwrap();
    let sync = rows
        .iter()
        .find(|row| row.event_type == atproto_pds::sequencer::EventType::Sync.as_str())
        .expect("publish_sync should have appended a #sync event");
    assert_eq!(sync.event_type, "sync");
    let (root, blocks) = read_car(&blocks_field(&body_of(sync))).await;

    assert_eq!(root.to_string(), result.commit_cid);
    assert!(
        blocks.contains_key(&result.commit_cid),
        "#sync must ship the commit block it names"
    );
}
