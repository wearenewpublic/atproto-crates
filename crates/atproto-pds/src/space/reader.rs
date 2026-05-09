//! `SpaceReader` — dual-auth permissioned-record reads.
//!
//!  Spaces reads accept
//! either:
//! - **Own-PDS OAuth** — the caller holds an OAuth bearer for the local
//!   member's account and can read whatever rows their per-actor store has.
//!   The PDS itself is the auth boundary.
//! - **Remote `SpaceCredential`** — a JWT minted by the space owner via
//!   `getSpaceCredential` and bound to a `clientId`. The owner's PDS verifies
//!   the credential against its own signing key, then serves rows from the
//!   *owner's* per-actor store.
//!
//! `SpaceReader` is intentionally storage-agnostic above the
//! `SpaceRepoStorage` trait: **the PDS does not enforce
//! membership at read time** for own-PDS-OAuth callers (G35) — the consumer
//! is responsible for membership checks at sync. For SpaceCredential callers,
//! the credential itself acts as proof that the owner has authorized this
//! `clientId` to read the space.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use atproto_identity::key::{KeyData, to_public};
use atproto_space::credential::{SpaceCredential, verify_space_credential};
use atproto_space::space_repo::SpaceRepo;
use atproto_space::storage::{RecordPage, RecordRow};
use atproto_space::types::SpaceUri;
use std::path::PathBuf;
use std::sync::Arc;

/// Authentication mode for a Spaces read.
#[derive(Debug, Clone)]
pub enum SpaceReadAuth<'a> {
    /// Caller holds an OAuth bearer for the named account on this PDS.
    /// Reads happen against that account's per-actor store. No membership
    /// check is performed here (G35) — consumers verify at sync time.
    OwnPds {
        /// DID of the local account whose per-actor store to read from.
        account_did: &'a str,
    },
    /// Caller presented a `SpaceCredential` JWT minted by the space owner.
    /// Reads happen against the *owner's* per-actor store.
    SpaceCredential {
        /// The compact-form JWT.
        token: &'a str,
        /// `client_id` the credential is expected to be bound to (from the
        /// HTTP-layer DPoP/auth check).
        expected_client_id: &'a str,
    },
}

/// Permissioned-record reader.
pub struct SpaceReader {
    data_dir: PathBuf,
    accounts: Arc<crate::account::AccountManager>,
}

impl SpaceReader {
    /// Construct.
    #[must_use]
    pub fn new(accounts: Arc<crate::account::AccountManager>, data_dir: PathBuf) -> Self {
        Self { data_dir, accounts }
    }

    /// `getRecord` — fetch a single record by `(collection, rkey)`.
    ///
    /// Returns `Ok(None)` when the record does not exist OR is taken-down
    /// per §4.4 (`space_record_takedown`); returns [`PdsError::AuthDenied`]
    /// for invalid SpaceCredentials.
    pub async fn get_record(
        &self,
        space: &SpaceUri,
        auth: SpaceReadAuth<'_>,
        collection: &str,
        rkey: &str,
    ) -> PdsResult<Option<RecordRow>> {
        let owner_did_for_read = self.resolve_read_target(space, &auth).await?;
        let store = SqlActorStore::open(&self.data_dir, &owner_did_for_read).await?;

        // §4.4 takedown gate — admin moderation hides the record at read time.
        if is_record_taken_down(store.pool(), space, collection, rkey).await? {
            return Ok(None);
        }

        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.get_record(collection, rkey)
            .await
            .map_err(PdsError::Space)
    }

    /// `listRecords` — paginated listing within a collection.
    pub async fn list_records(
        &self,
        space: &SpaceUri,
        auth: SpaceReadAuth<'_>,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<RecordPage> {
        let owner_did_for_read = self.resolve_read_target(space, &auth).await?;
        let store = SqlActorStore::open(&self.data_dir, &owner_did_for_read).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        let mut page = repo
            .list_records(collection, cursor, limit)
            .await
            .map_err(PdsError::Space)?;

        // §4.4 takedown filter — drop taken-down rkeys from the page.
        // We hit the takedown table once per page rather than per record.
        let taken: std::collections::HashSet<String> =
            taken_down_rkeys(store.pool(), space, collection).await?;
        if !taken.is_empty() {
            page.records.retain(|r| !taken.contains(&r.rkey));
        }
        Ok(page)
    }

    /// Verify the read auth and return the DID of the per-actor store to read.
    ///
    /// - `OwnPds { account_did }` → that account.
    /// - `SpaceCredential { .. }` → the space owner (after JWT verification).
    async fn resolve_read_target(
        &self,
        space: &SpaceUri,
        auth: &SpaceReadAuth<'_>,
    ) -> PdsResult<String> {
        match auth {
            SpaceReadAuth::OwnPds { account_did } => Ok((*account_did).to_string()),
            SpaceReadAuth::SpaceCredential {
                token,
                expected_client_id,
            } => {
                // Verify with the owner's *public* signing key. The owner is
                // an account managed by this PDS (otherwise we could not have
                // minted the credential), so we look up the signing-key ref
                // from `account` and convert to public form for verification.
                let owner_did = &space.owner_did;
                let owner_pub = self.owner_public_key(owner_did).await?;
                let _payload: SpaceCredential =
                    verify_space_credential(token, owner_did, space, &owner_pub).map_err(|e| {
                        PdsError::AuthDenied {
                            reason: format!("invalid SpaceCredential: {e}"),
                        }
                    })?;
                // Re-verify the bound client_id matches the HTTP-layer
                // expected value (the JWT carries this in payload.client_id;
                // verify_space_credential already returns the payload).
                let payload: SpaceCredential =
                    verify_space_credential(token, owner_did, space, &owner_pub).map_err(|e| {
                        PdsError::AuthDenied {
                            reason: format!("invalid SpaceCredential: {e}"),
                        }
                    })?;
                if &payload.client_id != expected_client_id {
                    return Err(PdsError::AuthDenied {
                        reason: format!(
                            "SpaceCredential clientId mismatch: token={}, expected={}",
                            payload.client_id, expected_client_id
                        ),
                    });
                }
                Ok(owner_did.clone())
            }
        }
    }

    /// Resolve an account's atproto signing key in *public* form. Used to
    /// verify SpaceCredentials minted by this PDS for one of its owners.
    async fn owner_public_key(&self, owner_did: &str) -> PdsResult<KeyData> {
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(owner_did)
                .fetch_optional(self.accounts.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {owner_did} (signing_key_ref)"),
            })?
            .0;
        let private = self.accounts.key_store().get(&key_ref).await?;
        to_public(&private).map_err(|e| PdsError::Storage {
            reason: format!("derive public key: {e}"),
        })
    }
}

/// Returns true when a row in `space_record_takedown` matches the
/// `(space, collection, rkey)` triple. Per §4.4.
pub(crate) async fn is_record_taken_down(
    pool: &sqlx::SqlitePool,
    space: &SpaceUri,
    collection: &str,
    rkey: &str,
) -> PdsResult<bool> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM space_record_takedown
         WHERE space = ? AND collection = ? AND rkey = ?",
    )
    .bind(space.to_string())
    .bind(collection)
    .bind(rkey)
    .fetch_optional(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_record_takedown lookup: {e}"),
    })?;
    Ok(row.is_some())
}

/// Returns the set of rkeys taken down within `(space, collection)`. Used
/// by `list_records` to filter a page in one round-trip.
pub(crate) async fn taken_down_rkeys(
    pool: &sqlx::SqlitePool,
    space: &SpaceUri,
    collection: &str,
) -> PdsResult<std::collections::HashSet<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT rkey FROM space_record_takedown
         WHERE space = ? AND collection = ?",
    )
    .bind(space.to_string())
    .bind(collection)
    .fetch_all(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_record_takedown list: {e}"),
    })?;
    Ok(rows.into_iter().map(|(r,)| r).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use crate::space::writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
    use atproto_identity::key::KeyType;
    use atproto_space::credential::{SPACE_CREDENTIAL_TTL_SECS, create_space_credential};
    use atproto_space::types::{SpaceKey, SpaceType};
    use tempfile::TempDir;

    async fn fresh_manager(dir: &std::path::Path) -> Arc<AccountManager> {
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:owner",
                handle: "owner.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        manager
    }

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    async fn seed_record(manager: Arc<AccountManager>, dir: PathBuf, uri: SpaceUri) {
        let writer = SpaceWriter::new(manager, dir);
        writer
            .apply_writes(
                "did:plc:owner",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "app.bsky.group.message".to_string(),
                    rkey: "abc".to_string(),
                    value: Some(serde_json::json!({"text": "hi"})),
                }],
            )
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_pds_get_record_round_trip() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner",
                },
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.collection, "app.bsky.group.message");
        assert_eq!(row.rkey, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_pds_list_records_paginates() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let reader = SpaceReader::new(manager, dir);
        let page = reader
            .list_records(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner",
                },
                "app.bsky.group.message",
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.records.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn space_credential_round_trip() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        // Look up the owner's signing key and mint a credential bound to a
        // synthetic clientId.
        let key_ref: (String,) =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind("did:plc:owner")
                .fetch_one(manager.pool())
                .await
                .unwrap();
        let signing_key = manager.key_store().get(&key_ref.0).await.unwrap();
        let token = create_space_credential(
            "did:plc:owner",
            &uri,
            "https://app.example/client-metadata.json",
            &signing_key,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::SpaceCredential {
                    token: &token,
                    expected_client_id: "https://app.example/client-metadata.json",
                },
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.rkey, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn space_credential_wrong_client_rejected() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let key_ref: (String,) =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind("did:plc:owner")
                .fetch_one(manager.pool())
                .await
                .unwrap();
        let signing_key = manager.key_store().get(&key_ref.0).await.unwrap();
        let token = create_space_credential(
            "did:plc:owner",
            &uri,
            "client-A",
            &signing_key,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        let result = reader
            .get_record(
                &uri,
                SpaceReadAuth::SpaceCredential {
                    token: &token,
                    expected_client_id: "client-B",
                },
                "app.bsky.group.message",
                "abc",
            )
            .await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nonexistent_record_returns_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner",
                },
                "app.bsky.group.message",
                "missing",
            )
            .await
            .unwrap();
        assert!(row.is_none());
    }

    /// §4.4 takedown gate: a row in `space_record_takedown` hides the
    /// record from `get_record` even when the underlying `space_record`
    /// row is intact. Re-inserting via `list_records` confirms the
    /// page-level filter is also wired.
    #[tokio::test(flavor = "multi_thread")]
    async fn takedown_hides_record_from_get_and_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        // Insert a takedown row directly into the owner's per-actor store.
        let store = crate::actor_store::sql::SqlActorStore::open(&dir, "did:plc:owner")
            .await
            .unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO space_record_takedown (space, collection, rkey, taken_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(uri.to_string())
        .bind("app.bsky.group.message")
        .bind("abc")
        .bind(&now)
        .execute(store.pool())
        .await
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        // get_record returns None for taken-down rows.
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner",
                },
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap();
        assert!(row.is_none(), "taken-down record must hide from get_record");

        // list_records page is empty.
        let page = reader
            .list_records(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner",
                },
                "app.bsky.group.message",
                None,
                10,
            )
            .await
            .unwrap();
        assert!(
            page.records.is_empty(),
            "taken-down record must be filtered from list_records"
        );
    }
}
