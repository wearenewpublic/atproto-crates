//! Spaces notification fan-out — payload definitions + enqueue helpers.
//!
//! and
//! after every successful Spaces commit the owner's PDS
//! must broadcast to every registered consumer service. This module
//! encapsulates:
//!
//! - The on-the-wire DAG-CBOR payload shapes for `notifyWrite` (records) and
//!   `notifyMembership` (member list).
//! - Helpers that look up `space_credential_recipient` rows on the owner's
//!   per-actor store and append one `notify_attempt` row per recipient on the
//!   shared accounts pool.
//!
//! The actual delivery happens in [`crate::notifier::Notifier::tick`].
//!
//! Recipient registration is owned by [`crate::http::space_handlers`] —
//! [`upsert_recipient`] is the helper called from `getSpaceCredential`.
//!
//! # Recipient discovery
//!
//! (closed in commit `9cbdd7f`) wired DID-document
//! resolution to find each consumer's declared `atproto_pds` service
//! endpoint. The `recipient.rs` resolver picks the path automatically;
//! see for the soft-fail contract on consumers
//! whose DID document doesn't expose a discoverable PDS endpoint.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::notifier::enqueue_notification;
use atproto_space::commit::Commit;
use atproto_space::space_repo::{Op, OpAction};
use atproto_space::types::SpaceUri;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// NSID for outbound `notifyWrite` POSTs.
pub const NOTIFY_WRITE_NSID: &str = "com.atproto.space.notifyWrite";

/// NSID for outbound `notifyMembership` POSTs.
pub const NOTIFY_MEMBERSHIP_NSID: &str = "com.atproto.space.notifyMembership";

/// One op inside a [`NotifyWritePayload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyOp {
    /// `"create"` | `"update"` | `"delete"`.
    pub action: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the value (`None` for delete).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// DAG-CBOR-encoded record value (`None` for delete).
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub value: Option<Vec<u8>>,
}

/// Wire-shape of `com.atproto.space.notifyWrite` request body (DAG-CBOR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyWritePayload {
    /// Space URI.
    pub space: String,
    /// DID of the member who wrote.
    pub member: String,
    /// Signed commit (set_hash, rev, ikm, tag, sig).
    pub commit: Commit,
    /// Per-op detail.
    pub ops: Vec<NotifyOp>,
}

/// Wire-shape of `com.atproto.space.notifyMembership` request body (DAG-CBOR).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyMembershipPayload {
    /// Space URI.
    pub space: String,
    /// `"add"` | `"remove"`.
    pub action: String,
    /// DID of the member affected.
    pub member: String,
    /// Signed commit covering this membership change.
    pub commit: Commit,
}

/// Translate a [`crate::space::writer::SpaceWriter`]-style [`Op`] into the
/// notify-payload shape (drops the value bytes for deletes).
#[must_use]
pub fn op_to_notify(op: &Op) -> NotifyOp {
    NotifyOp {
        action: match op.action {
            OpAction::Create => "create".to_string(),
            OpAction::Update => "update".to_string(),
            OpAction::Delete => "delete".to_string(),
        },
        collection: op.collection.clone(),
        rkey: op.rkey.clone(),
        cid: op.cid.clone(),
        value: op.value.clone(),
    }
}

/// One row from `space_credential_recipient` for a given space.
#[derive(Debug, Clone)]
pub struct Recipient {
    /// Recipient service DID.
    pub service_did: String,
    /// HTTPS endpoint base.
    pub service_endpoint: String,
}

/// Read all recipients for `space` from the owner's per-actor store.
pub async fn list_recipients(
    owner_actor_pool: &SqlitePool,
    space: &SpaceUri,
) -> PdsResult<Vec<Recipient>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT service_did, service_endpoint
         FROM space_credential_recipient
         WHERE space = ?",
    )
    .bind(space.to_string())
    .fetch_all(owner_actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("list_recipients: {e}"),
    })?;
    Ok(rows
        .into_iter()
        .map(|(service_did, service_endpoint)| Recipient {
            service_did,
            service_endpoint,
        })
        .collect())
}

/// INSERT-OR-REPLACE into the owner's per-actor `space_credential_recipient`
/// table. Idempotent on `(space, service_did)` — re-issuing a credential to
/// the same client just bumps `last_issued_at`.
pub async fn upsert_recipient(
    owner_actor_pool: &SqlitePool,
    space: &SpaceUri,
    service_did: &str,
    service_endpoint: &str,
) -> PdsResult<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO space_credential_recipient
            (space, service_did, service_endpoint, last_issued_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(space, service_did) DO UPDATE SET
            service_endpoint = excluded.service_endpoint,
            last_issued_at = excluded.last_issued_at",
    )
    .bind(space.to_string())
    .bind(service_did)
    .bind(service_endpoint)
    .bind(&now)
    .execute(owner_actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("upsert_recipient: {e}"),
    })?;
    Ok(())
}

/// Encode `payload` as DAG-CBOR and enqueue one `notify_attempt` row
/// recipient. Returns the count of rows appended.
///
/// Failures here are non-fatal to the caller — e.g. if a recipient lookup
/// returns zero rows, the writer's commit is still durable. The caller
/// passes both pools because the recipient table lives on the owner's
/// per-actor store while the queue lives on the shared accounts pool.
pub async fn enqueue_writes(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    space: &SpaceUri,
    payload: &NotifyWritePayload,
) -> PdsResult<u32> {
    enqueue_for_space(accounts_pool, data_dir, space, NOTIFY_WRITE_NSID, payload).await
}

/// Encode `payload` as DAG-CBOR and enqueue one `notify_attempt` row
/// recipient — membership flavor.
pub async fn enqueue_membership(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    space: &SpaceUri,
    payload: &NotifyMembershipPayload,
) -> PdsResult<u32> {
    enqueue_for_space(
        accounts_pool,
        data_dir,
        space,
        NOTIFY_MEMBERSHIP_NSID,
        payload,
    )
    .await
}

async fn enqueue_for_space<P: serde::Serialize>(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    space: &SpaceUri,
    nsid: &str,
    payload: &P,
) -> PdsResult<u32> {
    let owner_store = SqlActorStore::open(data_dir, &space.owner_did).await?;
    let recipients = list_recipients(owner_store.pool(), space).await?;
    if recipients.is_empty() {
        return Ok(0);
    }

    let body = atproto_dasl::to_vec(payload).map_err(|e| PdsError::Storage {
        reason: format!("encode notify payload: {e}"),
    })?;

    let mut count = 0u32;
    for r in recipients {
        enqueue_notification(
            accounts_pool,
            &r.service_did,
            &r.service_endpoint,
            body.clone(),
            nsid,
        )
        .await?;
        count += 1;
    }
    Ok(count)
}

/// `serde_bytes`-style adapter for `Option<Vec<u8>>` so the payload encodes
/// the raw bytes as a CBOR byte string instead of an array of integers.
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serde_bytes::ByteBuf::from(bytes.clone()).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use atproto_space::types::{SpaceKey, SpaceType};
    use chrono::Utc;
    use tempfile::TempDir;

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    /// Insert a `space` row so the FK on `space_credential_recipient.space`
    /// is satisfied. Production wiring goes through
    /// `SpaceService::create_space`; the unit tests here don't need the rest
    /// of that flow's invariants (`is_owner`, member-state seed).
    async fn ensure_space_row(pool: &SqlitePool, uri: &SpaceUri) {
        sqlx::query(
            "INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at)
             VALUES (?, 1, 1, ?)",
        )
        .bind(uri.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upsert_recipient_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let owner_store = SqlActorStore::open(dir, "did:plc:owner").await.unwrap();
        let uri = test_space();
        ensure_space_row(owner_store.pool(), &uri).await;

        upsert_recipient(
            owner_store.pool(),
            &uri,
            "did:web:appview.example",
            "https://appview.example",
        )
        .await
        .unwrap();
        upsert_recipient(
            owner_store.pool(),
            &uri,
            "did:web:appview.example",
            "https://appview.example",
        )
        .await
        .unwrap();

        let recipients = list_recipients(owner_store.pool(), &uri).await.unwrap();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].service_did, "did:web:appview.example");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enqueue_writes_with_no_recipients_is_zero() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        // Pre-create the owner's per-actor store so the recipients query has
        // a table to read from.
        let _ = SqlActorStore::open(&dir, "did:plc:owner").await.unwrap();

        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let payload = NotifyWritePayload {
            space: test_space().to_string(),
            member: "did:plc:alice".to_string(),
            commit: Commit {
                set_hash: vec![0u8; 32],
                rev: "rev".to_string(),
                ikm: vec![0u8; 32],
                tag: vec![0u8; 32],
                sig: vec![0u8; 64],
            },
            ops: vec![],
        };
        let count = enqueue_writes(accounts.pool(), &dir, &test_space(), &payload)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enqueue_writes_fans_out_to_each_recipient() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let owner_store = SqlActorStore::open(&dir, "did:plc:owner").await.unwrap();
        let uri = test_space();
        ensure_space_row(owner_store.pool(), &uri).await;
        upsert_recipient(
            owner_store.pool(),
            &uri,
            "did:web:a.example",
            "https://a.example",
        )
        .await
        .unwrap();
        upsert_recipient(
            owner_store.pool(),
            &uri,
            "did:web:b.example",
            "https://b.example",
        )
        .await
        .unwrap();

        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let payload = NotifyWritePayload {
            space: uri.to_string(),
            member: "did:plc:alice".to_string(),
            commit: Commit {
                set_hash: vec![0u8; 32],
                rev: "3kmev".to_string(),
                ikm: vec![0u8; 32],
                tag: vec![0u8; 32],
                sig: vec![0u8; 64],
            },
            ops: vec![NotifyOp {
                action: "create".to_string(),
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: Some("bafy...".to_string()),
                value: Some(b"v".to_vec()),
            }],
        };
        let count = enqueue_writes(accounts.pool(), &dir, &uri, &payload)
            .await
            .unwrap();
        assert_eq!(count, 2);

        let due = crate::notifier::due_now(accounts.pool(), 100)
            .await
            .unwrap();
        assert_eq!(due.len(), 2);
        assert!(due.iter().all(|d| d.nsid == NOTIFY_WRITE_NSID));
    }
}
