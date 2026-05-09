//! part 3 / — cross-trait acceptance.
//!
//! The per-trait round-trip tests in
//! `actor_store::{sql,fjall}::public_realm::tests` cover each
//! `*Storage` impl in isolation. This integration suite goes one
//! level higher: it constructs a full `PublicRealmBackend` and
//! exercises **all four traits in lockstep** the way `RepoWriter`
//! and `RepoReader` would once the call-site sweep lands.
//!
//! The same suite runs against both backends:
//!
//! - `sqlite_*` tests use `PublicRealmBackend::sql(data_dir)`.
//! - `fjall_*` tests use `PublicRealmBackend::fjall(store)` and
//!   are gated on the `fjall` Cargo feature.
//!
//! Acceptance criterion proved here: every per-trait operation the
//! writer/reader/import would call resolves through the dispatch for
//! both backends. (closed in `21c1345` + `cfb17c0`) lifted
//! the high-level call sites; this file remains as the cross-trait
//! integration check that exercises the dispatch in isolation.
//!
//! Each scenario simulates one chunk of the writer's atomic-commit
//! lockstep: insert a commit row, upsert the records the commit
//! introduces, append the `#commit` outbox event, attach a blob via
//! a record-blob ref. The reader-side checks then verify
//! `latest()` / `get_by_uri()` / `read_after()` / `get()` all see
//! the just-written rows.

use atproto_pds::actor_store::{BlobRefRow, BlobRow, CommitRow, PublicRealmBackend, RecordRow};
use tempfile::TempDir;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";

// ---------------------------------------------------------------------------
//  Scenario builders — backend-agnostic.
// ---------------------------------------------------------------------------

/// Build a synthetic commit row with the given rev + cid.
fn synth_commit(rev: &str, cid: &str, data_cid: &str) -> CommitRow {
    CommitRow {
        cid: cid.to_string(),
        rev: rev.to_string(),
        data_cid: data_cid.to_string(),
        prev_cid: None,
        prev_data_cid: None,
        signature: vec![0xAA; 64],
        created_at: "2026-05-07T00:00:00Z".to_string(),
    }
}

/// Build a synthetic record row attached to a synthetic commit's rev.
fn synth_record(uri: &str, cid: &str, collection: &str, rkey: &str, rev: &str) -> RecordRow {
    RecordRow {
        uri: uri.to_string(),
        cid: cid.to_string(),
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        rev: rev.to_string(),
        indexed_at: "2026-05-07T00:00:00Z".to_string(),
    }
}

/// Apply the lockstep "writer batch" against a `PublicRealmBackend`:
/// commit → records → outbox event → blob bytes → blob refs. Mirrors
/// the order `RepoWriter::apply_writes` performs in a single SQL
/// transaction today.
async fn apply_writer_batch(backend: &PublicRealmBackend, did: &str) {
    let commit = synth_commit("3kmev1", "bafyrei-commit-1", "bafyrei-mst-1");
    backend
        .commit_obj
        .insert(did, &commit)
        .await
        .expect("insert commit");

    let r1 = synth_record(
        &format!("at://{did}/app.bsky.feed.post/k1"),
        "bafyrei-rec-1",
        "app.bsky.feed.post",
        "k1",
        &commit.rev,
    );
    let r2 = synth_record(
        &format!("at://{did}/app.bsky.feed.post/k2"),
        "bafyrei-rec-2",
        "app.bsky.feed.post",
        "k2",
        &commit.rev,
    );
    backend
        .repo_record
        .upsert(did, &r1)
        .await
        .expect("upsert r1");
    backend
        .repo_record
        .upsert(did, &r2)
        .await
        .expect("upsert r2");

    let event_payload = serde_json::json!({
        "did": did,
        "rev": commit.rev,
        "commit": commit.cid,
        "ops": []
    });
    let payload_bytes = serde_json::to_vec(&event_payload).unwrap();
    backend
        .outbox
        .append(did, "commit", payload_bytes)
        .await
        .expect("outbox append");

    let blob = BlobRow {
        cid: "bafkreig000000000000000000000000000000000000000000000aaaaaa".to_string(),
        mime_type: "image/png".to_string(),
        size: 4,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        created_at: "2026-05-07T00:00:00Z".to_string(),
    };
    backend.blob.put(did, &blob).await.expect("put blob");
    backend
        .blob
        .add_ref(
            did,
            &BlobRefRow {
                record_uri: r1.uri.clone(),
                blob_cid: blob.cid.clone(),
                mime_type: blob.mime_type.clone(),
                size: blob.size,
            },
        )
        .await
        .expect("add ref");
}

/// Reader-side sanity. Verify every trait method sees the writes that
/// `apply_writer_batch` just performed.
async fn verify_writer_batch_visible(backend: &PublicRealmBackend, did: &str) {
    // commit_obj
    let latest = backend.commit_obj.latest(did).await.unwrap().unwrap();
    assert_eq!(latest.cid, "bafyrei-commit-1");
    assert_eq!(latest.rev, "3kmev1");
    assert_eq!(latest.data_cid, "bafyrei-mst-1");
    let by_cid = backend
        .commit_obj
        .get_by_cid(did, "bafyrei-commit-1")
        .await
        .unwrap();
    assert!(by_cid.is_some(), "commit missing from get_by_cid");
    let by_rev = backend.commit_obj.get_by_rev(did, "3kmev1").await.unwrap();
    assert!(by_rev.is_some(), "commit missing from get_by_rev");

    // repo_record
    let r1 = backend
        .repo_record
        .get_by_uri(did, &format!("at://{did}/app.bsky.feed.post/k1"))
        .await
        .unwrap();
    assert!(r1.is_some(), "record k1 missing");
    let page = backend
        .repo_record
        .list_by_collection(did, "app.bsky.feed.post", None, 10)
        .await
        .unwrap();
    assert_eq!(page.len(), 2, "should list both k1 + k2");

    // outbox
    let latest_seq = backend.outbox.latest_seq(did).await.unwrap();
    assert!(latest_seq.is_some(), "outbox should have one event");
    let events = backend.outbox.read_after(did, None, 10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "commit");

    // blob
    let blob = backend
        .blob
        .get(
            did,
            "bafkreig000000000000000000000000000000000000000000000aaaaaa",
        )
        .await
        .unwrap();
    assert!(blob.is_some(), "blob missing");
    let (data, _mime) = blob.unwrap();
    assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

/// Cross-DID isolation — writes against ALICE must not leak into BOB.
async fn verify_did_isolation(backend: &PublicRealmBackend) {
    let alice_latest = backend.commit_obj.latest(ALICE).await.unwrap();
    let bob_latest = backend.commit_obj.latest(BOB).await.unwrap();
    assert!(alice_latest.is_some(), "alice should have a commit");
    assert!(bob_latest.is_none(), "bob should NOT see alice's commit");

    let alice_records = backend
        .repo_record
        .list_by_collection(ALICE, "app.bsky.feed.post", None, 10)
        .await
        .unwrap();
    let bob_records = backend
        .repo_record
        .list_by_collection(BOB, "app.bsky.feed.post", None, 10)
        .await
        .unwrap();
    assert_eq!(alice_records.len(), 2);
    assert!(bob_records.is_empty(), "bob should have no records");
}

/// Delete + re-write — verify the trait surface handles the
/// `Update` (overwrite) path that `apply_writes` uses with
/// `WriteAction::Update`.
async fn verify_overwrite(backend: &PublicRealmBackend, did: &str) {
    let r1_uri = format!("at://{did}/app.bsky.feed.post/k1");
    // Original cid was bafyrei-rec-1; overwrite with -1b.
    let r1_v2 = synth_record(
        &r1_uri,
        "bafyrei-rec-1b",
        "app.bsky.feed.post",
        "k1",
        "3kmev2",
    );
    backend.repo_record.upsert(did, &r1_v2).await.unwrap();
    let got = backend
        .repo_record
        .get_by_uri(did, &r1_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.cid, "bafyrei-rec-1b", "upsert should overwrite cid");
    assert_eq!(got.rev, "3kmev2", "upsert should bump rev");
}

/// Outbox cursor — verify `read_after(cursor)` paginates correctly.
async fn verify_outbox_cursor(backend: &PublicRealmBackend, did: &str) {
    // Append two more events so we have at least 3.
    backend
        .outbox
        .append(did, "sync", b"second".to_vec())
        .await
        .unwrap();
    backend
        .outbox
        .append(did, "identity", b"third".to_vec())
        .await
        .unwrap();
    let total = backend.outbox.read_after(did, None, 100).await.unwrap();
    assert!(total.len() >= 3, "expected at least 3 outbox events");

    // Page after the first event.
    let first_seq = total[0].seq;
    let after_first = backend
        .outbox
        .read_after(did, Some(first_seq), 100)
        .await
        .unwrap();
    assert_eq!(
        after_first.len(),
        total.len() - 1,
        "read_after(first_seq) should drop the first row"
    );
}

// ---------------------------------------------------------------------------
//  SQLite — runs unconditionally in the default feature set.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_dispatch_writer_batch_round_trip() {
    let tmp = TempDir::new().unwrap();
    let backend = PublicRealmBackend::sql(tmp.path().to_path_buf());
    assert_eq!(backend.backend_label, "sqlite");
    apply_writer_batch(&backend, ALICE).await;
    verify_writer_batch_visible(&backend, ALICE).await;
    verify_did_isolation(&backend).await;
    verify_overwrite(&backend, ALICE).await;
    verify_outbox_cursor(&backend, ALICE).await;
}

// ---------------------------------------------------------------------------
//  fjall — runs only with `--features fjall`.
// ---------------------------------------------------------------------------

#[cfg(feature = "fjall")]
mod fjall_dispatch {
    use super::*;
    use atproto_pds::actor_store::fjall::FjallActorStore;

    #[tokio::test(flavor = "multi_thread")]
    async fn fjall_dispatch_writer_batch_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        let backend = PublicRealmBackend::fjall(store);
        assert_eq!(backend.backend_label, "fjall");
        apply_writer_batch(&backend, ALICE).await;
        verify_writer_batch_visible(&backend, ALICE).await;
        verify_did_isolation(&backend).await;
        verify_overwrite(&backend, ALICE).await;
        verify_outbox_cursor(&backend, ALICE).await;
    }

    /// Re-open round-trip — fjall persists across `Database` drops, so a
    /// fresh handle should still see the write.
    #[tokio::test(flavor = "multi_thread")]
    async fn fjall_dispatch_persists_across_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let store = FjallActorStore::open(tmp.path()).unwrap();
            let backend = PublicRealmBackend::fjall(store);
            apply_writer_batch(&backend, ALICE).await;
        }
        // Drop the first handle, re-open the same data directory.
        let store2 = FjallActorStore::open(tmp.path()).unwrap();
        let backend2 = PublicRealmBackend::fjall(store2);
        verify_writer_batch_visible(&backend2, ALICE).await;
    }
}
