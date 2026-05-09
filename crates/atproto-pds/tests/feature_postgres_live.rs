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
