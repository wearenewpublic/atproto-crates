//! Spaces notification fan-out — payload definitions + enqueue helpers.
//!
//! Spaces writes don't fan out over the public firehose. Instead the owner's
//! PDS broadcasts to every registered consumer service. This module
//! encapsulates:
//!
//! - The on-the-wire payload shape for `notifyWrite` (contentless;
//!   `{ space, repo, rev }`).
//! - Helpers that read/write `space_credential_recipient` subscription rows on
//!   the owner's per-actor store and append one `notify_attempt` row per
//!   recipient on the shared accounts pool.
//!
//! The actual delivery happens in [`crate::notifier::Notifier::tick`].
//!
//! # Notify payloads
//!
//! `notifyWrite` carries **no record data** per the 0016 Permissioned Data
//! draft lexicon `com.atproto.space.notifyWrite`: the body is exactly
//! `{ space, repo, rev }` and is encoded as `application/json`. Consumers PULL
//! the actual ops via `listRepoOps`/`getRepoState`. The 0016 draft has no
//! membership-notification flow.
//!
//! # Recipient discovery
//!
//! Subscriptions are recorded two ways:
//! - `getSpaceCredential` self-registers the credential consumer for the whole
//!   space (`repo` NULL, no expiry).
//! - `registerNotify` records an endpoint subscription, either whole-space
//!   (`repo` NULL) or for a single repo (`repo` = that DID), with an
//!   `expires_at` registration lifetime.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::notifier::enqueue_notification;
use crate::space::service_auth::{NOTIFY_SERVICE_AUTH_TTL_SECS, mint_service_auth};
use atproto_identity::key::KeyData;
use atproto_space::types::SpaceUri;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// NSID for outbound `notifyWrite` POSTs.
pub const NOTIFY_WRITE_NSID: &str = "com.atproto.space.notifyWrite";

/// Wire-shape of `com.atproto.space.notifyWrite` request body
/// (`application/json`). Near-contentless: it announces that `repo` advanced to
/// `rev` within `space`, and carries the resulting commit hash; consumers PULL
/// the ops via `listRepoOps`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyWritePayload {
    /// Space URI.
    pub space: String,
    /// DID of the account whose repo advanced.
    pub repo: String,
    /// The revision of the write.
    pub rev: String,
    /// The repo's commit hash (sha256 of the LtHash state) after the write.
    ///
    /// The lexicon requires this, and it exists so *"the space host can
    /// maintain each repo's hash for listRepos"* — without it the authority has
    /// no way to tell a syncer which repos actually changed, and the
    /// hash-propagation loop from repo host to space host does not close.
    ///
    /// **Optional on the way in, always sent on the way out.** `notifyWrite` is
    /// declared best-effort, this is the only implementation that emits a hash
    /// at all, and rejecting a payload without one would drop write
    /// notifications from every peer running older code — including this
    /// server's own previous releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<crate::space::lex_bytes::BytesValue>,
}

/// One subscription row from `space_credential_recipient` for a given space.
#[derive(Debug, Clone)]
pub struct Recipient {
    /// Recipient service DID.
    pub service_did: String,
    /// HTTPS endpoint base.
    pub service_endpoint: String,
}

/// Read recipients for `space` from the owner's per-actor store, expanding the
/// per-repo subscription filter: whole-space rows (`repo = ''`) always match;
/// per-repo rows match only when `repo == writer_repo`. Expired rows
/// (`expires_at` in the past) are skipped.
///
/// `writer_repo` is the DID of the account that wrote (for `notifyWrite`
/// fan-out); pass `None` for membership fan-out, which targets whole-space
/// subscribers only.
pub async fn list_recipients(
    owner_actor_pool: &SqlitePool,
    space: &SpaceUri,
    writer_repo: Option<&str>,
) -> PdsResult<Vec<Recipient>> {
    let now = Utc::now().to_rfc3339();
    let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT service_did, service_endpoint, repo, expires_at
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
        .filter(|(_, _, repo, expires_at)| {
            // Skip expired registrations.
            if let Some(exp) = expires_at
                && exp.as_str() <= now.as_str()
            {
                return false;
            }
            // Whole-space rows always match; per-repo rows match the writer.
            repo.is_empty() || writer_repo == Some(repo.as_str())
        })
        .map(|(service_did, service_endpoint, _, _)| Recipient {
            service_did,
            service_endpoint,
        })
        .collect())
}

/// INSERT-OR-REPLACE a whole-space subscription into the owner's per-actor
/// `space_credential_recipient` table (the `getSpaceCredential` self-register
/// path). Idempotent on `(space, '', service_did)` — re-issuing a credential to
/// the same client just bumps `last_issued_at`. Leaves `expires_at` unset.
pub async fn upsert_recipient(
    owner_actor_pool: &SqlitePool,
    space: &SpaceUri,
    service_did: &str,
    service_endpoint: &str,
) -> PdsResult<()> {
    upsert_subscription(
        owner_actor_pool,
        space,
        None,
        service_did,
        service_endpoint,
        None,
    )
    .await
}

/// INSERT-OR-REPLACE a subscription, keyed `(space, repo-or-empty,
/// service_did)`. `repo = None` is the whole-space sentinel; `expires_at` is
/// the optional RFC 3339 registration lifetime. Used by both the
/// `getSpaceCredential` self-register path ([`upsert_recipient`]) and
/// `registerNotify`.
pub async fn upsert_subscription(
    owner_actor_pool: &SqlitePool,
    space: &SpaceUri,
    repo: Option<&str>,
    service_did: &str,
    service_endpoint: &str,
    expires_at: Option<&str>,
) -> PdsResult<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO space_credential_recipient
            (space, repo, service_did, service_endpoint, last_issued_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(space, repo, service_did) DO UPDATE SET
            service_endpoint = excluded.service_endpoint,
            last_issued_at = excluded.last_issued_at,
            expires_at = excluded.expires_at",
    )
    .bind(space.to_string())
    .bind(repo.unwrap_or(""))
    .bind(service_did)
    .bind(service_endpoint)
    .bind(&now)
    .bind(expires_at)
    .execute(owner_actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("upsert_subscription: {e}"),
    })?;
    Ok(())
}

/// Encode the contentless `notifyWrite` payload as JSON and enqueue one
/// `notify_attempt` row per matching recipient (HOP 2 fan-out). `writer_repo`
/// filters per-repo subscriptions. Each row carries a fresh service-auth token
/// signed by the owner (`iss = space.space_did`, `aud = recipient service`).
/// Returns the count of rows appended.
///
/// Failures here are non-fatal to the caller — if a recipient lookup returns
/// zero rows, the writer's commit is still durable. The caller passes both
/// pools because the subscription table lives on the owner's per-actor store
/// while the queue lives on the shared accounts pool.
pub async fn enqueue_writes(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    space: &SpaceUri,
    payload: &NotifyWritePayload,
    owner_signing_key: &KeyData,
) -> PdsResult<u32> {
    enqueue_for_space(
        accounts_pool,
        data_dir,
        space,
        Some(payload.repo.as_str()),
        NOTIFY_WRITE_NSID,
        "application/json",
        &serde_json::to_vec(payload).map_err(|e| PdsError::Storage {
            reason: format!("encode notifyWrite payload: {e}"),
        })?,
        Some(owner_signing_key),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_for_space(
    accounts_pool: &SqlitePool,
    data_dir: &std::path::Path,
    space: &SpaceUri,
    writer_repo: Option<&str>,
    nsid: &str,
    content_type: &str,
    body: &[u8],
    owner_signing_key: Option<&KeyData>,
) -> PdsResult<u32> {
    let owner_store = SqlActorStore::open(data_dir, &space.space_did).await?;
    let recipients = list_recipients(owner_store.pool(), space, writer_repo).await?;
    if recipients.is_empty() {
        return Ok(0);
    }

    let mut count = 0u32;
    for r in recipients {
        // Re-check what was stored, before anything is signed for it.
        //
        // Validating only at registration would leave every row written
        // before that guard existed live, and those are exactly the rows an
        // attacker would have planted. Checking here means a hostile endpoint
        // has to survive both the write and every read, and it is refused
        // ahead of `mint_service_auth` so no token is ever produced for it.
        if let Err(err) =
            atproto_identity::validation::validate_service_endpoint(&r.service_endpoint)
        {
            tracing::warn!(
                space = %space,
                service_did = %r.service_did,
                endpoint = %r.service_endpoint,
                error = %err,
                "skipping a notify subscription whose endpoint is not a permitted service endpoint"
            );
            continue;
        }

        // Mint a per-recipient service-auth token when a signing key is
        // supplied (notifyWrite). aud is the recipient service DID.
        let auth_token = match owner_signing_key {
            Some(key) => Some(mint_service_auth(
                key,
                &space.space_did,
                &r.service_did,
                nsid,
                NOTIFY_SERVICE_AUTH_TTL_SECS,
            )?),
            None => None,
        };
        enqueue_notification(
            accounts_pool,
            &r.service_did,
            &r.service_endpoint,
            body.to_vec(),
            nsid,
            content_type,
            auth_token.as_deref(),
        )
        .await?;
        count += 1;
    }
    Ok(count)
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

        let recipients = list_recipients(owner_store.pool(), &uri, None)
            .await
            .unwrap();
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
            hash: None,
            space: test_space().to_string(),
            repo: "did:plc:alice".to_string(),
            rev: "rev".to_string(),
        };
        let owner_key =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
                .unwrap();
        let count = enqueue_writes(accounts.pool(), &dir, &test_space(), &payload, &owner_key)
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
            hash: None,
            space: uri.to_string(),
            repo: "did:plc:alice".to_string(),
            rev: "3kmev".to_string(),
        };
        let owner_key =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
                .unwrap();
        let count = enqueue_writes(accounts.pool(), &dir, &uri, &payload, &owner_key)
            .await
            .unwrap();
        assert_eq!(count, 2);

        let due = crate::notifier::due_now(accounts.pool(), 100)
            .await
            .unwrap();
        assert_eq!(due.len(), 2);
        assert!(due.iter().all(|d| d.nsid == NOTIFY_WRITE_NSID));
    }

    /// A subscription row whose endpoint would not be accepted today is
    /// skipped rather than delivered to.
    ///
    /// Validating only at registration would leave every row written before
    /// that guard existed live, and those are the rows that matter. Nothing
    /// is signed for a skipped recipient: the check runs ahead of
    /// `mint_service_auth`, so a hostile endpoint never causes the space
    /// authority's key to produce a token at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_recipient_with_an_impermissible_endpoint_is_skipped() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let owner_store = SqlActorStore::open(&dir, "did:plc:owner").await.unwrap();
        let uri = test_space();
        ensure_space_row(owner_store.pool(), &uri).await;

        // Written straight to the table, as a row predating the guard would be.
        for (did, endpoint) in [
            ("did:web:good.example", "https://good.example"),
            // The SSRF shapes: cleartext, an address literal reaching inside
            // the network, cloud metadata, and a non-standard port.
            ("did:web:plain.example", "http://plain.example"),
            ("did:web:internal.example", "https://10.0.0.5"),
            ("did:web:metadata.example", "https://169.254.169.254"),
            ("did:web:port.example", "https://port.example:8080"),
        ] {
            upsert_recipient(owner_store.pool(), &uri, did, endpoint)
                .await
                .unwrap();
        }

        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let payload = NotifyWritePayload {
            hash: None,
            space: uri.to_string(),
            repo: "did:plc:alice".to_string(),
            rev: "3kmev".to_string(),
        };
        let owner_key =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::P256Private)
                .unwrap();
        let count = enqueue_writes(accounts.pool(), &dir, &uri, &payload, &owner_key)
            .await
            .unwrap();

        assert_eq!(
            count, 1,
            "only the permitted endpoint should be delivered to"
        );
        let due = crate::notifier::due_now(accounts.pool(), 100)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(
            due[0].target_endpoint, "https://good.example",
            "a notification was queued for an endpoint that is not permitted"
        );
    }

    /// A per-repo subscription only matches notifyWrite fan-out for that repo.
    #[tokio::test(flavor = "multi_thread")]
    async fn per_repo_subscription_filters_by_writer() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let owner_store = SqlActorStore::open(dir, "did:plc:owner").await.unwrap();
        let uri = test_space();
        ensure_space_row(owner_store.pool(), &uri).await;
        // Subscribe `svc` to alice's repo only.
        upsert_subscription(
            owner_store.pool(),
            &uri,
            Some("did:plc:alice"),
            "did:web:svc.example",
            "https://svc.example",
            None,
        )
        .await
        .unwrap();

        // Writer = alice → matches.
        let for_alice = list_recipients(owner_store.pool(), &uri, Some("did:plc:alice"))
            .await
            .unwrap();
        assert_eq!(for_alice.len(), 1);

        // Writer = bob → no match.
        let for_bob = list_recipients(owner_store.pool(), &uri, Some("did:plc:bob"))
            .await
            .unwrap();
        assert_eq!(for_bob.len(), 0);
    }

    /// Expired registrations are skipped by `list_recipients`.
    #[tokio::test(flavor = "multi_thread")]
    async fn expired_subscription_is_skipped() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let owner_store = SqlActorStore::open(dir, "did:plc:owner").await.unwrap();
        let uri = test_space();
        ensure_space_row(owner_store.pool(), &uri).await;
        upsert_subscription(
            owner_store.pool(),
            &uri,
            None,
            "did:web:svc.example",
            "https://svc.example",
            Some("2000-01-01T00:00:00Z"),
        )
        .await
        .unwrap();
        let recipients = list_recipients(owner_store.pool(), &uri, Some("did:plc:alice"))
            .await
            .unwrap();
        assert_eq!(recipients.len(), 0);
    }
}
