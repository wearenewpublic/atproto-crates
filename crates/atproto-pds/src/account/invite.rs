#![allow(clippy::type_complexity)] // SQL 6-tuple invite-row types are clearer inline.
//! Invite-code lifecycle.
//!
//! Invite codes are optional, controlled by `PDS_INVITE_REQUIRED`. Reference TS PDS, cocoon,
//! rsky-pds, and tranquil-pds all support invite issuance, single-use
//! enforcement, and per-account interval-based reissuance. Surface:
//!
//! - `create` — generate a fresh code and store it.
//! - `redeem` — atomically mark a code used and decrement available uses.
//! - `list_for_did` — show codes owned by an account.
//! - `disable` — admin-disable a code.
//!
//! All functions accept `&AccountPool` and dispatch to the correct
//! backend at runtime.
//! SQLite uses `?` placeholders; Postgres uses `$1`, `$2`, etc. The
//! dispatch keeps both branches localized at each call site.

use crate::account::AccountPool;
#[cfg(any(feature = "sqlite", feature = "postgres"))]
use crate::account::AccountPoolKind;
use crate::errors::{PdsError, PdsResult};
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// One row from the `invite_code` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCodeRow {
    /// The code string itself (also the primary key).
    pub code: String,
    /// DID that issued the code (nullable when admin-issued).
    pub created_by_did: Option<String>,
    /// Remaining uses (decremented at `redeem`).
    pub available_uses: u32,
    /// DID that consumed the code (set when fully consumed).
    pub used_by: Option<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// `true` if admin-disabled.
    pub disabled: bool,
}

/// Create a fresh invite code with `available_uses` slots.
///
/// `created_by_did` is `None` for admin-issued codes; the resulting code is
/// returned. Format: `pds-<10-char-base32>`.
pub async fn create(
    pool: &AccountPool,
    created_by_did: Option<&str>,
    available_uses: u32,
) -> PdsResult<InviteCodeRow> {
    let code = generate_code();
    let now = Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT INTO invite_code (code, created_by_did, available_uses, used_by, created_at, disabled)
                 VALUES (?, ?, ?, NULL, ?, 0)",
            )
            .bind(&code)
            .bind(created_by_did)
            .bind(available_uses as i64)
            .bind(&now)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create invite_code: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO invite_code (code, created_by_did, available_uses, used_by, created_at, disabled)
                 VALUES ($1, $2, $3, NULL, $4, FALSE)",
            )
            .bind(&code)
            .bind(created_by_did)
            .bind(available_uses as i64)
            .bind(&now)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create invite_code: {e}"),
            })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
    Ok(InviteCodeRow {
        code,
        created_by_did: created_by_did.map(str::to_string),
        available_uses,
        used_by: None,
        created_at: now,
        disabled: false,
    })
}

/// Cheap pre-check: would the supplied code redeem successfully right now?
///
/// Returns `true` when the code exists, is not disabled, and has at least
/// one remaining use. Does *not* consume a slot — useful for validating
/// the invite *before* an expensive side effect (e.g. PLC genesis) so the
/// real `redeem` call afterwards can attribute consumption to the
/// just-minted DID rather than a placeholder.
///
/// **TOCTOU caveat:** between `peek` and `redeem`, another caller may
/// exhaust the code. The race window is small but real; the failure mode
/// is "second user sees `false` from `redeem` and is told invalid invite".
/// In `createAccount` that means the user lost the side effect (a PLC
/// genesis) and gets a 400. Operators handle the orphan PLC entry
/// out-of-band; the alternative (transactional spanning a network call)
/// is impossible.
pub async fn peek(pool: &AccountPool, code: &str) -> PdsResult<bool> {
    let (avail, disabled): (i64, bool) = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: Option<(i64, i64)> =
                sqlx::query_as("SELECT available_uses, disabled FROM invite_code WHERE code = ?")
                    .bind(code)
                    .fetch_optional(pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("invite peek: {e}"),
                    })?;
            match row {
                Some((a, d)) => (a, d != 0),
                None => return Ok(false),
            }
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: Option<(i64, bool)> =
                sqlx::query_as("SELECT available_uses, disabled FROM invite_code WHERE code = $1")
                    .bind(code)
                    .fetch_optional(pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("invite peek: {e}"),
                    })?;
            match row {
                Some(r) => r,
                None => return Ok(false),
            }
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    };
    Ok(!disabled && avail > 0)
}

/// Atomically redeem a code on behalf of `did`.
///
/// Decrements `available_uses` if > 0 and not disabled; sets `used_by` when
/// `available_uses` falls to 0. Returns `true` if a slot was consumed,
/// `false` if the code is unknown, disabled, or exhausted.
pub async fn redeem(pool: &AccountPool, code: &str, did: &str) -> PdsResult<bool> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let p = pool.as_sqlite();
            let mut tx = p.begin().await.map_err(|e| PdsError::Storage {
                reason: format!("invite redeem begin: {e}"),
            })?;
            let row: Option<(i64, i64)> =
                sqlx::query_as("SELECT available_uses, disabled FROM invite_code WHERE code = ?")
                    .bind(code)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("invite lookup: {e}"),
                    })?;
            let Some((avail, disabled)) = row else {
                return Ok(false);
            };
            if disabled != 0 || avail <= 0 {
                return Ok(false);
            }
            let new_avail = avail - 1;
            let used_by = if new_avail == 0 { Some(did) } else { None };
            sqlx::query(
                "UPDATE invite_code SET available_uses = ?, used_by = COALESCE(?, used_by) WHERE code = ?",
            )
            .bind(new_avail)
            .bind(used_by)
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite update: {e}"),
            })?;
            tx.commit().await.map_err(|e| PdsError::Storage {
                reason: format!("invite commit: {e}"),
            })?;
            Ok(true)
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let p = pool.as_postgres();
            let mut tx = p.begin().await.map_err(|e| PdsError::Storage {
                reason: format!("invite redeem begin: {e}"),
            })?;
            let row: Option<(i64, bool)> = sqlx::query_as(
                "SELECT available_uses, disabled FROM invite_code WHERE code = $1 FOR UPDATE",
            )
            .bind(code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite lookup: {e}"),
            })?;
            let Some((avail, disabled)) = row else {
                return Ok(false);
            };
            if disabled || avail <= 0 {
                return Ok(false);
            }
            let new_avail = avail - 1;
            let used_by = if new_avail == 0 { Some(did) } else { None };
            sqlx::query(
                "UPDATE invite_code SET available_uses = $1, used_by = COALESCE($2, used_by) WHERE code = $3",
            )
            .bind(new_avail)
            .bind(used_by)
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite update: {e}"),
            })?;
            tx.commit().await.map_err(|e| PdsError::Storage {
                reason: format!("invite commit: {e}"),
            })?;
            Ok(true)
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// Atomically reserve one slot of an invite code, without recording who used it.
///
/// A single conditional `UPDATE` — decrement only while a slot remains and the
/// code is live — so exactly `available_uses` concurrent callers succeed and
/// the rest see zero rows affected. This is what gates account creation: run
/// before the account row exists, it stops one single-use code from minting N
/// accounts, which the non-consuming [`peek`] could not. It deliberately does
/// not write `used_by` — the account the FK `invite_code.used_by ->
/// account(did)` points at does not exist yet — so [`record_invite_use`] records
/// the pairing afterward.
///
/// Returns `true` when a slot was consumed, `false` when the code is unknown,
/// disabled, or exhausted.
pub async fn reserve(pool: &AccountPool, code: &str) -> PdsResult<bool> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let res = sqlx::query(
                "UPDATE invite_code SET available_uses = available_uses - 1
                 WHERE code = ? AND disabled = 0 AND available_uses > 0",
            )
            .bind(code)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite reserve: {e}"),
            })?;
            Ok(res.rows_affected() == 1)
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let res = sqlx::query(
                "UPDATE invite_code SET available_uses = available_uses - 1
                 WHERE code = $1 AND disabled = false AND available_uses > 0",
            )
            .bind(code)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite reserve: {e}"),
            })?;
            Ok(res.rows_affected() == 1)
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// Record which account used a code, after the account row exists and a slot has
/// already been consumed by [`reserve`].
///
/// Sets `used_by` on the row when it is exhausted and not yet attributed,
/// preserving the "who used the last slot" audit semantics. Never decrements —
/// the single-use guarantee was already enforced by [`reserve`]. Best-effort: a
/// failure here loses the pairing, not a slot.
pub async fn record_invite_use(pool: &AccountPool, code: &str, did: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "UPDATE invite_code SET used_by = ?
                 WHERE code = ? AND available_uses = 0 AND used_by IS NULL",
            )
            .bind(did)
            .bind(code)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite record use: {e}"),
            })?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "UPDATE invite_code SET used_by = $1
                 WHERE code = $2 AND available_uses = 0 AND used_by IS NULL",
            )
            .bind(did)
            .bind(code)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("invite record use: {e}"),
            })?;
            Ok(())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// List codes issued by a DID (excludes admin-issued codes where
/// `created_by_did` is null).
///
/// Answered from `idx_invite_code_creator`, which is what keeps this
/// proportional to one account's codes rather than to every code on the
/// server. Without it the filter had nothing to seek with and the ordering
/// needed a temp b-tree over the whole table.
///
/// Deliberately uncapped: `com.atproto.server.getAccountInviteCodes` declares
/// neither a limit nor a cursor, so a truncated response has no way to say it
/// was truncated, and the row count is bounded by what this server chose to
/// issue to the account.
pub async fn list_for_did(pool: &AccountPool, did: &str) -> PdsResult<Vec<InviteCodeRow>> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, i64)> =
                sqlx::query_as(
                    "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                     FROM invite_code WHERE created_by_did = ? ORDER BY created_at DESC",
                )
                .bind(did)
                .fetch_all(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("list invite codes: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_sqlite).collect())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, bool)> =
                sqlx::query_as(
                    "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                     FROM invite_code WHERE created_by_did = $1 ORDER BY created_at DESC",
                )
                .bind(did)
                .fetch_all(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("list invite codes: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_pg).collect())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// List the `limit` most recent invite codes (any creator). Backs the
/// admin dashboard's "Recent invite codes" pane. Sorted by
/// `created_at DESC`.
pub async fn list_recent(pool: &AccountPool, limit: u32) -> PdsResult<Vec<InviteCodeRow>> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, i64)> =
                sqlx::query_as(
                    "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                     FROM invite_code ORDER BY created_at DESC LIMIT ?",
                )
                .bind(limit as i64)
                .fetch_all(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_recent invite_code: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_sqlite).collect())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, bool)> =
                sqlx::query_as(
                    "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                     FROM invite_code ORDER BY created_at DESC LIMIT $1",
                )
                .bind(limit as i64)
                .fetch_all(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_recent invite_code: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_pg).collect())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// List all invite codes, optionally filtered by `created_by_did`.
/// Backs the admin `getInviteCodes` endpoint. When `created_by` is
/// `None`, returns every code in the table — admin-issued + user-issued
/// alike.
pub async fn list_all(
    pool: &AccountPool,
    created_by: Option<&str>,
) -> PdsResult<Vec<InviteCodeRow>> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, i64)> =
                match created_by {
                    Some(did) => sqlx::query_as(
                        "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                         FROM invite_code WHERE created_by_did = ? ORDER BY created_at DESC",
                    )
                    .bind(did)
                    .fetch_all(pool.as_sqlite())
                    .await,
                    None => sqlx::query_as(
                        "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                         FROM invite_code ORDER BY created_at DESC",
                    )
                    .fetch_all(pool.as_sqlite())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_all invite_code: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_sqlite).collect())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let rows: Vec<(String, Option<String>, i64, Option<String>, String, bool)> =
                match created_by {
                    Some(did) => sqlx::query_as(
                        "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                         FROM invite_code WHERE created_by_did = $1 ORDER BY created_at DESC",
                    )
                    .bind(did)
                    .fetch_all(pool.as_postgres())
                    .await,
                    None => sqlx::query_as(
                        "SELECT code, created_by_did, available_uses, used_by, created_at, disabled
                         FROM invite_code ORDER BY created_at DESC",
                    )
                    .fetch_all(pool.as_postgres())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_all invite_code: {e}"),
                })?;
            Ok(rows.into_iter().map(map_row_pg).collect())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
}

/// Disable a code (admin action).
pub async fn disable(pool: &AccountPool, code: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("UPDATE invite_code SET disabled = 1 WHERE code = ?")
                .bind(code)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("disable invite_code: {e}"),
                })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE invite_code SET disabled = TRUE WHERE code = $1")
                .bind(code)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("disable invite_code: {e}"),
                })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => {
            unreachable!("AccountPool::Sqlite without `sqlite` feature");
        }
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature");
        }
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
fn map_row_sqlite(
    row: (String, Option<String>, i64, Option<String>, String, i64),
) -> InviteCodeRow {
    let (code, created_by_did, available_uses, used_by, created_at, disabled) = row;
    InviteCodeRow {
        code,
        created_by_did,
        available_uses: available_uses.max(0) as u32,
        used_by,
        created_at,
        disabled: disabled != 0,
    }
}

#[cfg(feature = "postgres")]
fn map_row_pg(row: (String, Option<String>, i64, Option<String>, String, bool)) -> InviteCodeRow {
    let (code, created_by_did, available_uses, used_by, created_at, disabled) = row;
    InviteCodeRow {
        code,
        created_by_did,
        available_uses: available_uses.max(0) as u32,
        used_by,
        created_at,
        disabled,
    }
}

fn generate_code() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 10];
    rand::rng().fill(&mut bytes);
    let suffix: String = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) & 0x1f] as char)
        .collect();
    format!("pds-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    async fn fresh_pool() -> AccountPool {
        let dir = AccountDirectory::open_memory().await.unwrap();
        // Insert stub accounts so used_by FK is satisfied for redeem tests.
        for did in [
            "did:plc:alice",
            "did:plc:bob",
            "did:plc:c",
            "did:plc:d",
            "did:plc:a",
            "did:plc:b",
        ] {
            sqlx::query(
                "INSERT OR IGNORE INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
                 VALUES (?, ?, '$argon2id$x', '2026-05-01T00:00:00Z', 'active', 'file:x', 1)",
            )
            .bind(did)
            .bind(format!("{}.example", did.replace([':'], "_")))
            .execute(dir.pool())
            .await
            .unwrap();
        }
        dir.account_pool()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_redeem_single_use() {
        let pool = fresh_pool().await;
        let row = create(&pool, None, 1).await.unwrap();
        assert!(row.code.starts_with("pds-"));
        assert_eq!(row.available_uses, 1);
        let consumed = redeem(&pool, &row.code, "did:plc:alice").await.unwrap();
        assert!(consumed);
        // Re-redeem fails (exhausted).
        let consumed2 = redeem(&pool, &row.code, "did:plc:bob").await.unwrap();
        assert!(!consumed2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multi_use_invite() {
        let pool = fresh_pool().await;
        let row = create(&pool, None, 3).await.unwrap();
        assert!(redeem(&pool, &row.code, "did:plc:a").await.unwrap());
        assert!(redeem(&pool, &row.code, "did:plc:b").await.unwrap());
        assert!(redeem(&pool, &row.code, "did:plc:c").await.unwrap());
        assert!(!redeem(&pool, &row.code, "did:plc:d").await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_code_is_not_redeemed() {
        let pool = fresh_pool().await;
        let consumed = redeem(&pool, "pds-nosuch", "did:plc:alice").await.unwrap();
        assert!(!consumed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn disabled_code_cannot_be_redeemed() {
        let pool = fresh_pool().await;
        let row = create(&pool, None, 5).await.unwrap();
        disable(&pool, &row.code).await.unwrap();
        assert!(!redeem(&pool, &row.code, "did:plc:alice").await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_for_did_filters_correctly() {
        // fresh_pool already inserts did:plc:alice so the FK on created_by_did is satisfied.
        let pool = fresh_pool().await;
        create(&pool, Some("did:plc:alice"), 2).await.unwrap();
        create(&pool, Some("did:plc:alice"), 1).await.unwrap();
        create(&pool, None, 1).await.unwrap(); // admin-issued
        let rows = list_for_did(&pool, "did:plc:alice").await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn generated_codes_are_unique() {
        let pool = fresh_pool().await;
        let a = create(&pool, None, 1).await.unwrap();
        let b = create(&pool, None, 1).await.unwrap();
        assert_ne!(a.code, b.code);
    }

    /// One account's codes are found by seeking, not by reading every code on
    /// the server.
    ///
    /// `invite_code` is keyed on `code` alone, so the filter on
    /// `created_by_did` had nothing to seek with: the listing scanned the
    /// whole table and then built a temp b-tree to order the few rows that
    /// matched. Over 200k codes, returning one account's ten cost 5ms of
    /// scanning.
    ///
    /// The plan is asserted rather than a duration, for the usual reason: a
    /// timing threshold on a shared machine either flakes or is loose enough
    /// to stop catching the regression.
    #[tokio::test(flavor = "multi_thread")]
    async fn listing_an_account_s_codes_seeks_the_creator_index() {
        let pool = fresh_pool().await;
        create(&pool, Some("did:plc:alice"), 1).await.unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN
             SELECT code, created_by_did, available_uses, used_by, created_at, disabled
             FROM invite_code WHERE created_by_did = ? ORDER BY created_at DESC",
        )
        .bind("did:plc:alice")
        .fetch_all(pool.as_sqlite())
        .await
        .expect("explain");
        let rendered = plan
            .into_iter()
            .map(|(_, _, _, detail)| detail)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            rendered.contains("idx_invite_code_creator"),
            "the listing should seek the creator index; plan was:\n{rendered}"
        );
        assert!(
            !rendered.contains("SCAN invite_code"),
            "the listing still reads every code on the server; plan was:\n{rendered}"
        );
        assert!(
            !rendered.contains("TEMP B-TREE"),
            "the order should come from the index rather than a sort; plan was:\n{rendered}"
        );
    }
}
