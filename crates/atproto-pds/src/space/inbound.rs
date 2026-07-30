//! Inbound `notifyWrite` receipt.
//!
//! `notifyWrite` is contentless `{ space, repo, rev }` (`application/json`)
//! authenticated by service auth at the HTTP layer; this module simply records
//! a lightweight receipt for dedup + audit. There is no commit to verify in the
//! payload — consumers PULL the actual ops via `listRepoOps`.
//!
//! The 0016 Permissioned Data draft has no membership-notification flow, so
//! there is no inbound member-commit verification here.
//!
//! Replay (already-seen `(space, rev)`) → 200 (idempotent ack).

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::space::notify::NotifyWritePayload;
use atproto_space::types::SpaceUri;

/// Decode + persist an inbound contentless `notifyWrite` `{ space, repo, rev }`.
///
/// The payload carries no commit (the write itself is not replicated through
/// the notification — consumers PULL ops via `listRepoOps`), so there is
/// nothing cryptographic to verify here. Authentication is enforced by the
/// service-auth bearer at the HTTP handler before this is called. The receipt
/// is keyed `(space, rev, nsid)` so re-delivery is idempotent.
pub async fn receive_write(
    _http: &reqwest::Client,
    _plc_directory_hostname: Option<&str>,
    data_dir: &std::path::Path,
    recipient_did: &str,
    body: &[u8],
) -> PdsResult<()> {
    let payload: NotifyWritePayload =
        serde_json::from_slice(body).map_err(|e| PdsError::Storage {
            reason: format!("decode notifyWrite payload: {e}"),
        })?;
    let space = SpaceUri::parse(&payload.space).map_err(PdsError::Space)?;
    // The commit hash the writer reported. Empty when the peer sent none —
    // `notifyWrite` is best-effort and older peers do not carry it — in which
    // case `listRepos` reports no hash for that repo rather than a wrong one.
    let set_hash = payload
        .hash
        .as_ref()
        .map(|h| h.as_slice().to_vec())
        .unwrap_or_default();
    if set_hash.is_empty() {
        tracing::debug!(
            space = %space,
            repo = %payload.repo,
            "notifyWrite carried no hash; listRepos will report none for this repo"
        );
    }
    persist_receipt(
        data_dir,
        recipient_did,
        &space,
        &payload.rev,
        "notifyWrite",
        &payload.repo,
        &set_hash,
    )
    .await
}

async fn persist_receipt(
    data_dir: &std::path::Path,
    recipient_did: &str,
    space: &SpaceUri,
    rev: &str,
    nsid: &str,
    issuer_did: &str,
    set_hash: &[u8],
) -> PdsResult<()> {
    let store = SqlActorStore::open(data_dir, recipient_did).await?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO space_received_op
            (space, rev, nsid, issuer_did, set_hash, received_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(space.to_string())
    .bind(rev)
    .bind(nsid)
    .bind(issuer_did)
    .bind(set_hash)
    .bind(&now)
    .execute(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("persist space_received_op: {e}"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_space::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    /// `persist_receipt` is idempotent on `(space, rev, nsid)`.
    #[tokio::test(flavor = "multi_thread")]
    async fn persist_is_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let recipient = "did:plc:test";
        let space = test_space();
        for _ in 0..3 {
            persist_receipt(
                &dir,
                recipient,
                &space,
                "3kmev1",
                "notifyWrite",
                "did:plc:alice",
                &[0u8; 32],
            )
            .await
            .unwrap();
        }
        let store = SqlActorStore::open(&dir, recipient).await.unwrap();
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM space_received_op")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    /// The contentless `notifyWrite` payload round-trips through JSON and is
    /// persisted as a receipt keyed `(space, rev, nsid)`.
    #[tokio::test(flavor = "multi_thread")]
    async fn notify_write_receipt_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let space = test_space();
        let payload = NotifyWritePayload {
            hash: None,
            space: space.to_string(),
            repo: "did:plc:alice".to_string(),
            rev: "3kmev1".to_string(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let http = reqwest::Client::new();
        receive_write(&http, None, &dir, "did:plc:peer", &body)
            .await
            .unwrap();

        let store = SqlActorStore::open(&dir, "did:plc:peer").await.unwrap();
        let row: (String, String, String) =
            sqlx::query_as("SELECT rev, nsid, issuer_did FROM space_received_op WHERE space = ?")
                .bind(space.to_string())
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(row.0, "3kmev1");
        assert_eq!(row.1, "notifyWrite");
        assert_eq!(row.2, "did:plc:alice");
    }
}
