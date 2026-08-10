//! — live Postgres CRUD acceptance.
//!
//! Gated by `--features postgres-live-tests`. The harness reads the
//! target DSN from `PDS_POSTGRES_TEST_URL`; when the env var is unset
//! the suite skips with an INFO log so CI without a Postgres instance
//! still passes.
//!
//! ## What this proves
//!
//! For each `account/*.rs` helper that lifted to the `AccountPool`
//! dispatch shape, this suite exercises the Postgres branch end-to-end
//! against a real `PgPool`:
//!
//! - `AccountDirectory` — `insert_account` / `lookup_did` /
//!   `lookup_handle` / `list_accounts` / `search_accounts`.
//! - `email_token::insert` / `lookup` / `delete`.
//! - `invite::create` / `peek` / `redeem` / `list_for_did` / `disable`.
//! - `app_password::create` / `list` / `verify` / `update_primary_hash`
//!   / `revoke`.
//! - `denylist::add` / `contains` / `remove`.
//! - `service_auth_blacklist::add` / `contains` / `gc`.
//!
//! ## Operator runbook
//!
//! ```text
//! docker run --rm -d \
//!     --name pds-postgres-live \
//!     -e POSTGRES_USER=pds \
//!     -e POSTGRES_PASSWORD=pds \
//!     -e POSTGRES_DB=pds_live \
//!     -p 5432:5432 \
//!     postgres:17-alpine
//!
//! PDS_POSTGRES_TEST_URL=postgres://pds:pds@127.0.0.1:5432/pds_live \
//!     cargo test -p atproto-pds --features postgres-live-tests \
//!         --test feature_postgres_live
//! ```
//!
//! Each test isolates its rows by namespacing on a unique-per-test
//! DID prefix so multiple runs against the same database don't
//! collide. The suite does **not** truncate tables — leave that to
//! operators.

#![cfg(feature = "postgres-live-tests")]

use atproto_pds::account::email_token::{self, PURPOSE_RESET_PASSWORD, PURPOSE_UPDATE_EMAIL};
use atproto_pds::account::state::AccountState;
use atproto_pds::account::{
    AccountDirectory, AccountPool, AccountPoolKind, AccountRow, app_password, invite,
};
use atproto_pds::{denylist, service_auth_blacklist};
use chrono::{Duration as ChronoDuration, Utc};

/// Resolve the test DSN. Returns `None` (and logs an INFO skip) when
/// the env var is unset — enabling CI runs without Docker to pass.
fn test_dsn() -> Option<String> {
    match std::env::var("PDS_POSTGRES_TEST_URL") {
        Ok(s) if !s.trim().is_empty() => Some(s),
        _ => {
            tracing::info!(
                "PDS_POSTGRES_TEST_URL not set — skipping postgres-live-tests; \
                 set the env var to a libpq DSN (e.g. \
                 postgres://pds:pds@127.0.0.1:5432/pds_live) to run."
            );
            None
        }
    }
}

/// Open a Postgres-backed `AccountDirectory` for the test, running
/// migrations on connect. Returns `None` when the DSN is unset.
async fn fresh_directory() -> Option<AccountDirectory> {
    let dsn = test_dsn()?;
    let dir = AccountDirectory::open_postgres(&dsn, 4)
        .await
        .expect("open_postgres against PDS_POSTGRES_TEST_URL");
    assert_eq!(dir.account_pool().kind(), AccountPoolKind::Postgres);
    Some(dir)
}

/// Build a deterministic-but-unique DID for the calling test so
/// repeated runs against the same DB don't collide. Suffix is a
/// nanosecond timestamp.
fn unique_did(prefix: &str) -> String {
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    format!("did:plc:{prefix}_{nanos}")
}

/// Seed an `account` row through the dispatch — every helper test that
/// touches a foreign-key target needs this scaffolding.
async fn insert_test_account(pool: &AccountPool, did: &str, handle: &str) {
    let row = AccountRow {
        did: did.to_string(),
        handle: handle.to_string(),
        email: Some(format!("{}@example.test", did.replace([':'], "_"))),
        email_confirmed_at: None,
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$abcd$efgh".to_string(),
        created_at: Utc::now().to_rfc3339(),
        state: AccountState::Active,
        signing_key_ref: format!("file:stub:{did}"),
        pds_managed_rotation: true,
    };
    let dir = AccountDirectory::from_pool(pool.clone());
    dir.insert_account(&row)
        .await
        .expect("insert_account on postgres");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_insert_lookup_list_search_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let did = unique_did("dirsearch");
    let handle = format!("dir-{}.example.test", &did[did.len().saturating_sub(8)..]);

    let row = AccountRow {
        did: did.clone(),
        handle: handle.clone(),
        email: Some(format!("{handle}@example.test")),
        email_confirmed_at: Some(Utc::now().to_rfc3339()),
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$pq$rs".to_string(),
        created_at: Utc::now().to_rfc3339(),
        state: AccountState::Active,
        signing_key_ref: format!("file:stub:{did}"),
        pds_managed_rotation: false,
    };
    dir.insert_account(&row).await.expect("insert_account");

    let by_did = dir.lookup_did(&did).await.expect("lookup_did").unwrap();
    assert_eq!(by_did, row, "lookup_did round-trip");

    let by_handle = dir
        .lookup_handle(&handle)
        .await
        .expect("lookup_handle")
        .unwrap();
    assert_eq!(by_handle, row, "lookup_handle round-trip");

    // `list_accounts` paginates by DID — find our row by feeding the
    // immediate predecessor as the cursor and asking for one row.
    let mut chars: Vec<char> = did.chars().collect();
    if let Some(last) = chars.last_mut()
        && *last as u32 > 0
    {
        *last = char::from_u32((*last as u32).saturating_sub(1)).unwrap_or(*last);
    }
    let cursor: String = chars.into_iter().collect();
    let listed = dir
        .list_accounts(Some(&cursor), 1)
        .await
        .expect("list_accounts");
    assert!(
        listed.iter().any(|r| r.did == did),
        "list_accounts did not include the just-inserted DID {did} (cursor={cursor}) — got {:?}",
        listed.iter().map(|r| &r.did).collect::<Vec<_>>()
    );

    // Search by a unique substring of the handle.
    let needle = handle.split('.').next().unwrap();
    let hits = dir
        .search_accounts(needle, None, 5)
        .await
        .expect("search_accounts");
    assert!(
        hits.iter().any(|r| r.did == did),
        "search_accounts({needle}) missed inserted DID"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_token_insert_lookup_delete_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let did = unique_did("emailtok");
    let handle = format!("etok-{}.example.test", &did[did.len().saturating_sub(8)..]);
    insert_test_account(&pool, &did, &handle).await;

    let token = format!("tok-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
    let expires = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
    email_token::insert(
        &pool,
        &token,
        &did,
        PURPOSE_UPDATE_EMAIL,
        &expires,
        Some("new@example.test"),
    )
    .await
    .expect("email_token::insert");

    let row = email_token::lookup(&pool, &token)
        .await
        .expect("email_token::lookup")
        .expect("token row should exist");
    assert_eq!(row.did, did);
    assert_eq!(row.purpose, PURPOSE_UPDATE_EMAIL);
    assert_eq!(row.new_email.as_deref(), Some("new@example.test"));

    email_token::delete(&pool, &token)
        .await
        .expect("email_token::delete");
    assert!(
        email_token::lookup(&pool, &token)
            .await
            .expect("post-delete lookup")
            .is_none()
    );

    // Idempotent delete.
    email_token::delete(&pool, &token)
        .await
        .expect("email_token::delete idempotent");

    // Reset-password token (no `new_email`).
    let reset_token = format!(
        "tok-reset-{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    email_token::insert(
        &pool,
        &reset_token,
        &did,
        PURPOSE_RESET_PASSWORD,
        &expires,
        None,
    )
    .await
    .expect("email_token::insert reset");
    let row = email_token::lookup(&pool, &reset_token)
        .await
        .expect("lookup reset")
        .unwrap();
    assert!(row.new_email.is_none());
    email_token::delete(&pool, &reset_token).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invite_create_peek_redeem_disable_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let issuer = unique_did("inviteissuer");
    insert_test_account(&pool, &issuer, &format!("{issuer}.example.test")).await;
    let consumer = unique_did("inviteconsumer");
    insert_test_account(&pool, &consumer, &format!("{consumer}.example.test")).await;

    let row = invite::create(&pool, Some(&issuer), 2)
        .await
        .expect("invite::create");
    assert_eq!(row.available_uses, 2);
    assert!(!row.disabled);

    assert!(invite::peek(&pool, &row.code).await.expect("peek"));

    let owned = invite::list_for_did(&pool, &issuer)
        .await
        .expect("list_for_did");
    assert!(owned.iter().any(|r| r.code == row.code));

    // Redeem twice — first should keep available_uses=1, second should
    // exhaust and stamp `used_by`.
    assert!(
        invite::redeem(&pool, &row.code, &consumer)
            .await
            .expect("redeem 1")
    );
    assert!(
        invite::redeem(&pool, &row.code, &consumer)
            .await
            .expect("redeem 2")
    );
    // Third redeem fails — exhausted.
    assert!(
        !invite::redeem(&pool, &row.code, &consumer)
            .await
            .expect("redeem 3 exhausted")
    );

    // Disable via admin path is idempotent on consumed codes.
    invite::disable(&pool, &row.code).await.expect("disable");
    assert!(
        !invite::peek(&pool, &row.code)
            .await
            .expect("peek after disable")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn app_password_create_verify_update_revoke_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let did = unique_did("apppwd");
    insert_test_account(&pool, &did, &format!("{did}.example.test")).await;

    let created = app_password::create(&pool, &did, "primary-test", true)
        .await
        .expect("app_password::create");
    assert_eq!(created.row.did, did);
    assert!(created.row.privileged);
    assert!(!created.plaintext.is_empty());

    let listed = app_password::list(&pool, &did)
        .await
        .expect("app_password::list");
    assert!(listed.iter().any(|r| r.id == created.row.id));

    let verified = app_password::verify(&pool, &did, &created.plaintext)
        .await
        .expect("verify happy path")
        .expect("verify should match");
    assert_eq!(verified.id, created.row.id);

    let bogus = app_password::verify(&pool, &did, "obviously-wrong")
        .await
        .expect("verify wrong path");
    assert!(bogus.is_none());

    // `update_primary_hash` is a no-op on accounts without a
    // `__primary__` row but must not fail.
    app_password::update_primary_hash(&pool, &did, "$argon2id$replaced")
        .await
        .expect("update_primary_hash should be idempotent");

    // Revoke the just-created row by its name.
    let revoked = app_password::revoke(&pool, &did, "primary-test")
        .await
        .expect("revoke");
    assert!(revoked, "revoke should report removed=true");
    let listed = app_password::list(&pool, &did)
        .await
        .expect("list after revoke");
    assert!(!listed.iter().any(|r| r.id == created.row.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denylist_add_contains_remove_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let unique = format!(
        "denylist-{}@example.test",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );

    assert!(
        !denylist::contains(&pool, denylist::KIND_EMAIL, &unique)
            .await
            .expect("contains pre-add")
    );

    denylist::add(
        &pool,
        denylist::KIND_EMAIL,
        &unique,
        Some("test-only marker"),
    )
    .await
    .expect("denylist::add");
    assert!(
        denylist::contains(&pool, denylist::KIND_EMAIL, &unique)
            .await
            .expect("contains post-add")
    );

    // Add is idempotent on (hash, kind).
    denylist::add(&pool, denylist::KIND_EMAIL, &unique, None)
        .await
        .expect("denylist::add idempotent");

    denylist::remove(&pool, denylist::KIND_EMAIL, &unique)
        .await
        .expect("denylist::remove");
    assert!(
        !denylist::contains(&pool, denylist::KIND_EMAIL, &unique)
            .await
            .expect("contains post-remove")
    );
    // Idempotent re-remove.
    denylist::remove(&pool, denylist::KIND_EMAIL, &unique)
        .await
        .expect("denylist::remove idempotent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_auth_blacklist_add_contains_gc_round_trip() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let live_jti = format!("jti-live-{nanos}");
    let stale_jti = format!("jti-stale-{nanos}");

    let live_exp = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
    let stale_exp = (Utc::now() - ChronoDuration::hours(1)).to_rfc3339();

    service_auth_blacklist::add(&pool, &live_jti, &live_exp)
        .await
        .expect("blacklist::add live");
    service_auth_blacklist::add(&pool, &stale_jti, &stale_exp)
        .await
        .expect("blacklist::add stale");

    assert!(
        service_auth_blacklist::contains(&pool, &live_jti)
            .await
            .expect("contains live")
    );
    assert!(
        !service_auth_blacklist::contains(&pool, &stale_jti)
            .await
            .expect("contains stale (expired)")
    );

    let dropped = service_auth_blacklist::gc(&pool).await.expect("gc");
    // We can't assert a hard equality (other tests may co-exist), but
    // we expect *at least* the stale row we just inserted to be reaped.
    assert!(dropped >= 1, "gc reported {dropped} rows reaped");
    assert!(
        !service_auth_blacklist::contains(&pool, &stale_jti)
            .await
            .expect("contains stale post-gc")
    );
    assert!(
        service_auth_blacklist::contains(&pool, &live_jti)
            .await
            .expect("contains live post-gc")
    );
}

// ---------------------------------------------------------------------------
//  The stream sequence.
// ---------------------------------------------------------------------------

/// A `BIGSERIAL` alone lets a subscriber skip an event permanently.
///
/// This characterises Postgres rather than this server: `nextval` is
/// non-transactional by design, so an unserialized insert can take seq 10 and
/// commit after an insert that took seq 11. It is written down because the
/// SQLite schema comment claims allocation order is commit order, which is
/// true for a single writer and false here, and because it is the exact
/// mechanism the fix has to close.
///
/// The reader below is the subscriber's loop in miniature: read everything
/// after the cursor, advance the cursor to the last row read. Once it has
/// passed 11, nothing brings it back to 10.
#[tokio::test(flavor = "multi_thread")]
async fn a_raw_bigserial_insert_can_be_committed_out_of_order() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let pool = dir.account_pool();
    let AccountPool::Postgres(pg) = pool.clone() else {
        panic!("expected a postgres pool");
    };
    let did = unique_did("seqskew");

    // Two transactions, allocating in one order and committing in the other.
    let mut first = pg.begin().await.unwrap();
    let (early,): (i64,) = sqlx::query_as(
        "INSERT INTO stream_event (did, event_type, payload, created_at)
         VALUES ($1, 'commit', $2, '2026-01-01T00:00:00Z') RETURNING seq",
    )
    .bind(&did)
    .bind(vec![1u8])
    .fetch_one(&mut *first)
    .await
    .unwrap();

    let mut second = pg.begin().await.unwrap();
    let (late,): (i64,) = sqlx::query_as(
        "INSERT INTO stream_event (did, event_type, payload, created_at)
         VALUES ($1, 'commit', $2, '2026-01-01T00:00:00Z') RETURNING seq",
    )
    .bind(&did)
    .bind(vec![2u8])
    .fetch_one(&mut *second)
    .await
    .unwrap();
    assert!(early < late, "allocation order: {early} then {late}");

    // The later allocation becomes visible first.
    second.commit().await.unwrap();

    let cursor: Option<i64> = sqlx::query_as::<_, (i64,)>(
        "SELECT seq FROM stream_event WHERE did = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(&did)
    .fetch_optional(&pg)
    .await
    .unwrap()
    .map(|(seq,)| seq);
    assert_eq!(
        cursor,
        Some(late),
        "a subscriber polling in this window sees only the later event"
    );

    first.commit().await.unwrap();

    let after_cursor: Vec<(i64,)> =
        sqlx::query_as("SELECT seq FROM stream_event WHERE did = $1 AND seq > $2 ORDER BY seq")
            .bind(&did)
            .bind(cursor.unwrap())
            .fetch_all(&pg)
            .await
            .unwrap();
    assert!(
        after_cursor.is_empty(),
        "nothing follows the cursor, so seq {early} is behind it forever"
    );
}

/// `append` serializes allocation against commit.
///
/// Holding the same advisory lock from outside must stop an append from
/// allocating at all. That is the guarantee: the lock spans `nextval` through
/// COMMIT, so no second append can allocate inside another's window, and
/// allocation order becomes commit order.
#[tokio::test(flavor = "multi_thread")]
async fn append_cannot_allocate_while_the_stream_lock_is_held() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let AccountPool::Postgres(pg) = dir.account_pool() else {
        panic!("expected a postgres pool");
    };
    let sequencer = atproto_pds::sequencer::Sequencer::new(dir.account_pool());
    let did = unique_did("seqlock");

    // A session lock rather than a transaction one, so the test holds it
    // without holding a transaction open.
    let mut holder = pg.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(atproto_pds::sequencer::stream::STREAM_SEQ_LOCK_KEY)
        .execute(&mut *holder)
        .await
        .unwrap();

    let blocked = tokio::spawn({
        let sequencer = sequencer.clone();
        let did = did.clone();
        async move { sequencer.append(&did, "commit", vec![7u8]).await }
    });

    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(750), &mut { blocked })
        .await
        .is_err();
    assert!(
        timed_out,
        "append allocated a sequence number while another holder had the lock;          allocation is not serialized against commit"
    );

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(atproto_pds::sequencer::stream::STREAM_SEQ_LOCK_KEY)
        .execute(&mut *holder)
        .await
        .unwrap();
}

/// A subscriber reading while writes are in flight sees every event.
///
/// This is the defect, end to end. The reader is the subscription loop:
/// read everything after the cursor, advance the cursor to the last row read.
/// Without serialized allocation a poll can land between two commits, take the
/// higher sequence number, and leave the lower one behind a cursor that has
/// already passed it -- so the event is not delayed, it is never delivered.
///
/// Filtered to this test's DID so that other tests appending to the same
/// database cannot affect the result: the cursor only ever advances to a
/// sequence number belonging to this run.
#[tokio::test(flavor = "multi_thread")]
async fn a_reader_polling_during_concurrent_appends_misses_nothing() {
    let Some(dir) = fresh_directory().await else {
        return;
    };
    let sequencer = atproto_pds::sequencer::Sequencer::new(dir.account_pool());
    let did = unique_did("seqpoll");
    const EVENTS: usize = 96;

    let start = sequencer.latest_seq().await.unwrap().unwrap_or(0);

    let writers = tokio::spawn({
        let sequencer = sequencer.clone();
        let did = did.clone();
        async move {
            let mut tasks = Vec::new();
            for i in 0..EVENTS {
                let sequencer = sequencer.clone();
                let did = did.clone();
                tasks.push(tokio::spawn(async move {
                    sequencer
                        .append(&did, "commit", vec![u8::try_from(i % 251).unwrap()])
                        .await
                        .unwrap()
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        }
    });

    // Poll as hard as a subscriber ever would, so the window between two
    // commits is landed in rather than waited out.
    let mut cursor = Some(start);
    let mut seen: Vec<i64> = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while seen.len() < EVENTS && std::time::Instant::now() < deadline {
        let rows = sequencer
            .read_after(cursor, Some(&did), 100)
            .await
            .expect("read");
        for row in rows {
            cursor = Some(row.seq);
            seen.push(row.seq);
        }
        tokio::task::yield_now().await;
    }
    writers.await.unwrap();

    // Drain anything written after the last poll, the way a live subscriber
    // would on its next wakeup.
    loop {
        let rows = sequencer
            .read_after(cursor, Some(&did), 100)
            .await
            .expect("drain");
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = Some(row.seq);
            seen.push(row.seq);
        }
    }

    let stored: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM stream_event WHERE did = $1")
        .bind(&did)
        .fetch_one(match dir.account_pool() {
            AccountPool::Postgres(ref pg) => pg,
            _ => panic!("expected a postgres pool"),
        })
        .await
        .unwrap();
    assert_eq!(stored.0 as usize, EVENTS, "fixture");
    assert_eq!(
        seen.len(),
        EVENTS,
        "the subscriber's cursor stepped over {} event(s) that are durably stored",
        EVENTS - seen.len()
    );
}
