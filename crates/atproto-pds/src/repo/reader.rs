//! Read-only XRPC handlers for `com.atproto.repo.*` and `com.atproto.sync.*`.
//!
//! - `com.atproto.repo.getRecord` — fetch a single record by `(collection, rkey)`.
//! - `com.atproto.repo.listRecords` — paginate records in a collection.
//! - `com.atproto.repo.describeRepo` — list collections, return DID + handle.
//! - `com.atproto.sync.getLatestCommit` — current head commit CID + rev.
//! - `com.atproto.sync.getRepoStatus` — `{did, active, status, rev}`.
//!
//! `RepoReader` exposes them as plain async fns so they can be tested
//! independently of the axum router.

use crate::account::{AccountDirectory, AccountState};
use crate::actor_store::PublicRealmBackend;
use crate::actor_store::sql::{SqlActorStore, SqlBlockStorage};
use crate::errors::{PdsError, PdsResult};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Shared reader state — bundles the accounts-DB handle and the data-directory
/// root so per-actor stores can be opened on demand.
///
/// When constructed via [`Self::with_backend`], read methods route through the
/// `PublicRealmBackend` trait surface. The legacy
/// SQLite-direct path remains for tests that build `RepoReader::new(...)`
/// without a backend.
pub struct RepoReader {
    accounts: AccountDirectory,
    data_dir: std::path::PathBuf,
    backend: Option<Arc<PublicRealmBackend>>,
}

impl RepoReader {
    /// Construct a reader without a public-realm backend (legacy
    /// SQLite-direct path).
    #[must_use]
    pub fn new(accounts: AccountDirectory, data_dir: std::path::PathBuf) -> Self {
        Self {
            accounts,
            data_dir,
            backend: None,
        }
    }

    /// Construct a reader with a public-realm backend wired. Every
    /// read method routes through the trait surface (`commit_obj`,
    /// `repo_record`, `open_block_storage`).
    #[must_use]
    pub fn with_backend(
        accounts: AccountDirectory,
        data_dir: std::path::PathBuf,
        backend: Arc<PublicRealmBackend>,
    ) -> Self {
        Self {
            accounts,
            data_dir,
            backend: Some(backend),
        }
    }

    /// Get the accounts directory.
    #[must_use]
    pub fn accounts(&self) -> &AccountDirectory {
        &self.accounts
    }

    /// Get the configured data directory (used by handlers that need to open
    /// per-actor stores directly).
    #[must_use]
    pub fn data_dir(&self) -> &std::path::PathBuf {
        &self.data_dir
    }

    /// Borrow the wired backend, if any. `None` when the reader was
    /// built via [`Self::new`].
    #[must_use]
    pub fn backend(&self) -> Option<&Arc<PublicRealmBackend>> {
        self.backend.as_ref()
    }

    /// Resolve `repo` (DID or handle) to a (DID, AccountRow) pair.
    async fn resolve(&self, repo: &str) -> PdsResult<crate::account::AccountRow> {
        let row = if repo.starts_with("did:") {
            self.accounts.lookup_did(repo).await?
        } else {
            self.accounts.lookup_handle(repo).await?
        };
        row.ok_or_else(|| PdsError::NotFound {
            what: format!("repo not found: {repo}"),
        })
    }

    /// Open the per-actor store for a DID.
    async fn open_actor(&self, did: &str) -> PdsResult<SqlActorStore> {
        SqlActorStore::open(&self.data_dir, did).await
    }

    /// Implementation of `com.atproto.repo.getRecord`.
    pub async fn get_record(
        &self,
        repo: &str,
        collection: &str,
        rkey: &str,
        cid: Option<&str>,
    ) -> PdsResult<RecordResponse> {
        let account = self.resolve(repo).await?;
        require_public_read(&account.state, &account.did)?;

        // Resolve the record CID through the trait surface when a backend
        // is wired; otherwise fall back to the legacy SQL-direct path.
        let cid_str = if let Some(backend) = self.backend.as_ref() {
            let uri = format!("at://{}/{}/{}", account.did, collection, rkey);
            let row = backend
                .repo_record
                .get_by_uri(&account.did, &uri)
                .await?
                .ok_or_else(|| PdsError::NotFound {
                    what: format!("record {collection}/{rkey} not found"),
                })?;
            if let Some(c) = cid
                && c != row.cid
            {
                return Err(PdsError::NotFound {
                    what: format!("record {collection}/{rkey} cid mismatch"),
                });
            }
            row.cid
        } else {
            let store = self.open_actor(&account.did).await?;
            let pool = store.pool();
            let row: Option<(String,)> = match cid {
                Some(c) => sqlx::query_as(
                    "SELECT cid FROM repo_record WHERE collection = ? AND rkey = ? AND cid = ? LIMIT 1",
                )
                .bind(collection)
                .bind(rkey)
                .bind(c)
                .fetch_optional(pool)
                .await,
                None => sqlx::query_as(
                    "SELECT cid FROM repo_record WHERE collection = ? AND rkey = ? LIMIT 1",
                )
                .bind(collection)
                .bind(rkey)
                .fetch_optional(pool)
                .await,
            }
            .map_err(|e| PdsError::Storage {
                reason: format!("get_record query: {e}"),
            })?;
            row.ok_or_else(|| PdsError::NotFound {
                what: format!("record {collection}/{rkey} not found"),
            })?
            .0
        };

        // Fetch the block bytes through the dispatch factory (when
        // wired) or a per-actor SQLite block store (legacy).
        let parsed_cid: cid::Cid = cid_str.parse().map_err(|e: cid::Error| PdsError::Storage {
            reason: format!("invalid CID stored: {e}"),
        })?;
        let block = if let Some(backend) = self.backend.as_ref() {
            let block_storage = backend.open_block_storage(&account.did).await?;
            atproto_dasl::storage::BlockStorage::get(&block_storage, &parsed_cid)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("get_record block fetch: {e}"),
                })?
        } else {
            let store = self.open_actor(&account.did).await?;
            let pool = store.pool();
            let block_storage =
                SqlBlockStorage::open(pool.clone())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("open block_storage: {e}"),
                    })?;
            atproto_dasl::storage::BlockStorage::get(&block_storage, &parsed_cid)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("get_record block fetch: {e}"),
                })?
        }
        .ok_or_else(|| PdsError::NotFound {
            what: format!("block {cid_str} not present"),
        })?;
        let value: serde_json::Value =
            atproto_dasl::from_slice(&block).map_err(|e| PdsError::Storage {
                reason: format!("decode record DAG-CBOR: {e}"),
            })?;

        Ok(RecordResponse {
            uri: format!("at://{}/{}/{}", account.did, collection, rkey),
            cid: cid_str,
            value,
        })
    }

    /// Implementation of `com.atproto.repo.listRecords`.
    pub async fn list_records(
        &self,
        repo: &str,
        collection: &str,
        limit: u32,
        cursor: Option<&str>,
        reverse: bool,
    ) -> PdsResult<ListRecordsResponse> {
        let account = self.resolve(repo).await?;
        require_public_read(&account.state, &account.did)?;
        let limit = limit.clamp(1, 100);

        // Trait dispatch path: forward-paginate via the trait, then —
        // when reverse is requested — reverse the page in memory. The
        // trait's `list_by_collection` doesn't expose direction (its
        // shape is "after-cursor, ascending"); reversing in-memory
        // gives equivalent results for the typical page-of-100 use.
        if let Some(backend) = self.backend.as_ref()
            && !reverse
        {
            let rows = backend
                .repo_record
                .list_by_collection(&account.did, collection, cursor, limit)
                .await?;
            let block_storage = backend.open_block_storage(&account.did).await?;
            let mut records = Vec::with_capacity(rows.len());
            for r in &rows {
                let parsed_cid: cid::Cid =
                    r.cid.parse().map_err(|e: cid::Error| PdsError::Storage {
                        reason: format!("invalid CID stored: {e}"),
                    })?;
                let block = atproto_dasl::storage::BlockStorage::get(&block_storage, &parsed_cid)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("list_records block fetch: {e}"),
                    })?
                    .unwrap_or_default();
                let value: serde_json::Value = if block.is_empty() {
                    serde_json::Value::Null
                } else {
                    atproto_dasl::from_slice(&block).map_err(|e| PdsError::Storage {
                        reason: format!("decode list_records DAG-CBOR: {e}"),
                    })?
                };
                records.push(ListRecordsItem {
                    uri: r.uri.clone(),
                    cid: r.cid.clone(),
                    value,
                });
            }
            // Only a full page can have more behind it. Emitting a cursor for
            // a partial page costs the client an extra round trip and lands it
            // on a response that used to carry `"cursor": null`.
            let next_cursor = (rows.len() as u32 == limit)
                .then(|| rows.last().map(|r| r.rkey.clone()))
                .flatten();
            return Ok(ListRecordsResponse {
                cursor: next_cursor,
                records,
            });
        }

        // Legacy SQLite-direct path. Also serves the reverse=true
        // dispatch case until the trait surface gains a direction
        // parameter.
        let store = self.open_actor(&account.did).await?;
        let pool = store.pool();
        let order_clause = if reverse { "DESC" } else { "ASC" };
        let comparator = if reverse { "<" } else { ">" };

        let rows: Vec<(String, String, String)> = match cursor {
            Some(cur) => {
                sqlx::query_as(&format!(
                    "SELECT uri, cid, rkey FROM repo_record
                 WHERE collection = ? AND rkey {comparator} ?
                 ORDER BY rkey {order_clause} LIMIT ?"
                ))
                .bind(collection)
                .bind(cur)
                .bind(limit as i64)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as(&format!(
                    "SELECT uri, cid, rkey FROM repo_record
                 WHERE collection = ?
                 ORDER BY rkey {order_clause} LIMIT ?"
                ))
                .bind(collection)
                .bind(limit as i64)
                .fetch_all(pool)
                .await
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("list_records: {e}"),
        })?;

        // Rehydrate each block to JSON.
        let block_storage =
            SqlBlockStorage::open(pool.clone())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("open block_storage: {e}"),
                })?;
        let mut records = Vec::with_capacity(rows.len());
        for (uri, cid_str, _rkey) in &rows {
            let parsed_cid: cid::Cid =
                cid_str.parse().map_err(|e: cid::Error| PdsError::Storage {
                    reason: format!("invalid CID stored: {e}"),
                })?;
            let block = atproto_dasl::storage::BlockStorage::get(&block_storage, &parsed_cid)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_records block fetch: {e}"),
                })?
                .unwrap_or_default();
            let value: serde_json::Value = if block.is_empty() {
                serde_json::Value::Null
            } else {
                atproto_dasl::from_slice(&block).map_err(|e| PdsError::Storage {
                    reason: format!("decode list_records DAG-CBOR: {e}"),
                })?
            };
            records.push(ListRecordsItem {
                uri: uri.clone(),
                cid: cid_str.clone(),
                value,
            });
        }

        let next_cursor = (rows.len() as u32 == limit)
            .then(|| rows.last().map(|(_, _, rkey)| rkey.clone()))
            .flatten();
        Ok(ListRecordsResponse {
            cursor: next_cursor,
            records,
        })
    }

    /// Implementation of `com.atproto.repo.describeRepo`.
    pub async fn describe_repo(&self, repo: &str) -> PdsResult<DescribeRepoResponse> {
        let account = self.resolve(repo).await?;
        if let Some(backend) = self.backend.as_ref() {
            let collections = backend.repo_record.list_collections(&account.did).await?;
            let latest = backend.commit_obj.latest(&account.did).await?;
            return Ok(DescribeRepoResponse {
                handle: account.handle,
                did: account.did,
                handle_is_correct: true,
                did_doc: None,
                collections,
                head_cid: latest.as_ref().map(|c| c.cid.clone()),
                head_rev: latest.as_ref().map(|c| c.rev.clone()),
                head_data: latest.map(|c| c.data_cid),
            });
        }
        let store = self.open_actor(&account.did).await?;
        let pool = store.pool();
        let collections: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT collection FROM repo_record ORDER BY collection ASC")
                .fetch_all(pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("describe_repo collections: {e}"),
                })?;
        let collections: Vec<String> = collections.into_iter().map(|(c,)| c).collect();

        // Lookup the latest commit's data CID for the response.
        let latest_commit: Option<(String, String, String)> =
            sqlx::query_as("SELECT cid, rev, data_cid FROM commit_obj ORDER BY rev DESC LIMIT 1")
                .fetch_optional(pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("describe_repo commit: {e}"),
                })?;

        Ok(DescribeRepoResponse {
            handle: account.handle,
            did: account.did,
            handle_is_correct: true,
            did_doc: None,
            collections,
            head_cid: latest_commit.as_ref().map(|(c, _, _)| c.clone()),
            head_rev: latest_commit.as_ref().map(|(_, r, _)| r.clone()),
            head_data: latest_commit.map(|(_, _, d)| d),
        })
    }

    /// Implementation of `com.atproto.sync.getLatestCommit`.
    pub async fn get_latest_commit(&self, did: &str) -> PdsResult<Option<LatestCommitResponse>> {
        let account = self.resolve(did).await?;
        if let Some(backend) = self.backend.as_ref() {
            let row = backend.commit_obj.latest(&account.did).await?;
            return Ok(row.map(|c| LatestCommitResponse {
                cid: c.cid,
                rev: c.rev,
            }));
        }
        let store = self.open_actor(&account.did).await?;
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT cid, rev FROM commit_obj ORDER BY rev DESC LIMIT 1")
                .fetch_one_or_none(store.pool())
                .await?;
        Ok(row.map(|(cid, rev)| LatestCommitResponse { cid, rev }))
    }

    /// Implementation of `com.atproto.sync.getRepoStatus`.
    pub async fn get_repo_status(&self, did: &str) -> PdsResult<RepoStatusResponse> {
        let account = self.resolve(did).await?;
        let rev = if let Some(backend) = self.backend.as_ref() {
            backend
                .commit_obj
                .latest(&account.did)
                .await?
                .map(|c| c.rev)
        } else {
            let store = self.open_actor(&account.did).await?;
            let row: Option<(String,)> =
                sqlx::query_as("SELECT rev FROM commit_obj ORDER BY rev DESC LIMIT 1")
                    .fetch_optional(store.pool())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("get_repo_status: {e}"),
                    })?;
            row.map(|(r,)| r)
        };
        Ok(RepoStatusResponse {
            did: account.did,
            active: account.state.allows_public_read(),
            status: if account.state == AccountState::Active {
                None
            } else {
                Some(account.state.as_str().to_string())
            },
            rev,
        })
    }
}

/// Lexicon-shape of a `getRecord` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordResponse {
    /// AT-URI of the record.
    pub uri: String,
    /// CID of the record value.
    pub cid: String,
    /// Decoded record value as JSON.
    pub value: serde_json::Value,
}

/// One item in a `listRecords` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRecordsItem {
    /// AT-URI.
    pub uri: String,
    /// CID.
    pub cid: String,
    /// Decoded value.
    pub value: serde_json::Value,
}

/// Lexicon-shape of a `listRecords` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRecordsResponse {
    /// Next-page cursor, omitted when the listing is exhausted.
    ///
    /// Omitted rather than emitted as `null`: the lexicon types `cursor` as a
    /// plain string, so a null makes the last page of every pagination loop
    /// throw in a validating client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Records on this page.
    pub records: Vec<ListRecordsItem>,
}

/// Lexicon-shape of a `describeRepo` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeRepoResponse {
    /// Handle for the repo.
    pub handle: String,
    /// DID for the repo.
    pub did: String,
    /// Whether the handle resolves correctly.
    #[serde(rename = "handleIsCorrect")]
    pub handle_is_correct: bool,
    /// The account's DID document.
    ///
    /// Required by the lexicon. Populated by the HTTP layer, which holds the
    /// service DID and key store needed to build it; `None` here means the
    /// reader was used directly rather than through the route.
    #[serde(rename = "didDoc", skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
    /// Collections present in the repo.
    pub collections: Vec<String>,
    /// Current head commit CID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_cid: Option<String>,
    /// Current head commit rev, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_rev: Option<String>,
    /// Current MST root data CID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_data: Option<String>,
}

/// Lexicon-shape of a `getLatestCommit` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestCommitResponse {
    /// Commit CID.
    pub cid: String,
    /// Commit rev (TID).
    pub rev: String,
}

/// Lexicon-shape of a `getRepoStatus` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoStatusResponse {
    /// DID of the repo.
    pub did: String,
    /// `true` if the repo is publicly readable.
    pub active: bool,
    /// Status reason if not active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Current rev, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
}

fn require_public_read(state: &AccountState, did: &str) -> PdsResult<()> {
    if state.allows_public_read() {
        Ok(())
    } else {
        Err(PdsError::AuthDenied {
            reason: format!("{did} is {state}, public reads disallowed"),
        })
    }
}

// Internal helper for sqlx::query_as → Option without panicking on missing.
trait QueryAsExt<'a, R> {
    async fn fetch_one_or_none(self, pool: &'a SqlitePool) -> PdsResult<Option<R>>;
}

impl<'a, R> QueryAsExt<'a, R>
    for sqlx::query::QueryAs<'a, sqlx::Sqlite, R, sqlx::sqlite::SqliteArguments<'a>>
where
    R: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    async fn fetch_one_or_none(self, pool: &'a SqlitePool) -> PdsResult<Option<R>> {
        self.fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("query: {e}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountRow;
    use crate::actor_store::sql::SqlActorStore;
    use atproto_dasl::cid::compute_cid;
    use atproto_dasl::storage::BlockStorage;
    use chrono::Utc;
    use tempfile::TempDir;

    async fn fresh_reader() -> (RepoReader, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        accounts
            .insert_account(&AccountRow {
                did: "did:plc:alice".to_string(),
                handle: "alice.example".to_string(),
                email: None,
                email_confirmed_at: None,
                password_hash: "$argon2id$x".to_string(),
                created_at: Utc::now().to_rfc3339(),
                state: AccountState::Active,
                signing_key_ref: "file:alice".to_string(),
                pds_managed_rotation: true,
            })
            .await
            .unwrap();
        let reader = RepoReader::new(accounts, dir);
        (reader, tmp)
    }

    async fn seed_record(
        store: &SqlActorStore,
        collection: &str,
        rkey: &str,
        value: serde_json::Value,
    ) -> String {
        let cbor = atproto_dasl::to_vec(&value).unwrap();
        let cid = compute_cid(&cbor);
        let cid_str = cid.to_string();

        let mut block_storage = SqlBlockStorage::open(store.pool().clone()).await.unwrap();
        block_storage.put(&cid, cbor).await.unwrap();

        let now = Utc::now().to_rfc3339();
        let uri = format!("at://did:plc:alice/{}/{}", collection, rkey);
        sqlx::query(
            "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at) VALUES (?,?,?,?,?,?)",
        )
        .bind(&uri)
        .bind(&cid_str)
        .bind(collection)
        .bind(rkey)
        .bind("3jui7kd2z2y2e")
        .bind(&now)
        .execute(store.pool())
        .await
        .unwrap();
        cid_str
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_round_trip() {
        let (reader, _tmp) = fresh_reader().await;
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        let value = serde_json::json!({"text": "hello"});
        let cid = seed_record(&store, "app.bsky.feed.post", "abc", value.clone()).await;
        drop(store);

        let response = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "abc", None)
            .await
            .unwrap();
        assert_eq!(response.cid, cid);
        assert_eq!(response.uri, "at://did:plc:alice/app.bsky.feed.post/abc");
        assert_eq!(response.value, value);

        // Lookup by handle works too.
        let response2 = reader
            .get_record("alice.example", "app.bsky.feed.post", "abc", None)
            .await
            .unwrap();
        assert_eq!(response2.cid, cid);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_missing_returns_not_found() {
        let (reader, _tmp) = fresh_reader().await;
        let result = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "absent", None)
            .await;
        assert!(matches!(result, Err(PdsError::NotFound { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_unknown_repo_returns_not_found() {
        let (reader, _tmp) = fresh_reader().await;
        let result = reader.get_record("did:plc:bob", "x.y.z", "k", None).await;
        assert!(matches!(result, Err(PdsError::NotFound { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_records_paginates() {
        let (reader, _tmp) = fresh_reader().await;
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        for r in ["a", "b", "c", "d"] {
            seed_record(&store, "c.col", r, serde_json::json!({"r": r})).await;
        }
        drop(store);
        let page1 = reader
            .list_records("did:plc:alice", "c.col", 2, None, false)
            .await
            .unwrap();
        assert_eq!(page1.records.len(), 2);
        assert_eq!(page1.records[0].uri, "at://did:plc:alice/c.col/a");
        let page2 = reader
            .list_records("did:plc:alice", "c.col", 2, page1.cursor.as_deref(), false)
            .await
            .unwrap();
        assert_eq!(page2.records.len(), 2);
        assert_eq!(page2.records[0].uri, "at://did:plc:alice/c.col/c");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn describe_repo_lists_collections() {
        let (reader, _tmp) = fresh_reader().await;
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        seed_record(&store, "app.bsky.feed.post", "1", serde_json::json!({})).await;
        seed_record(
            &store,
            "app.bsky.actor.profile",
            "self",
            serde_json::json!({}),
        )
        .await;
        drop(store);

        let described = reader.describe_repo("did:plc:alice").await.unwrap();
        assert_eq!(described.did, "did:plc:alice");
        assert_eq!(described.handle, "alice.example");
        assert!(
            described
                .collections
                .contains(&"app.bsky.feed.post".to_string())
        );
        assert!(
            described
                .collections
                .contains(&"app.bsky.actor.profile".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_takendown_account_denied() {
        let (reader, _tmp) = fresh_reader().await;
        // Mark the account takendown.
        sqlx::query("UPDATE account SET state = 'takendown' WHERE did = 'did:plc:alice'")
            .execute(reader.accounts().pool())
            .await
            .unwrap();
        let result = reader.get_record("did:plc:alice", "x.y.z", "k", None).await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_repo_status_active() {
        let (reader, _tmp) = fresh_reader().await;
        let status = reader.get_repo_status("did:plc:alice").await.unwrap();
        assert!(status.active);
        assert!(status.status.is_none());
        assert_eq!(status.did, "did:plc:alice");
    }
}
