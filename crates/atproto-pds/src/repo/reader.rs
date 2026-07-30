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

    /// Handle on the firehose stream.
    ///
    /// Read-side callers reach the stream through the accounts directory the
    /// reader already holds, which is what lets `subscribeRepos` tail one log
    /// instead of every actor's outbox.
    #[must_use]
    pub fn sequencer(&self) -> crate::sequencer::Sequencer {
        crate::sequencer::Sequencer::new(self.accounts.account_pool())
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

    /// Resolve a repository identifier and refuse it if the account is not
    /// publicly readable.
    ///
    /// This is the gate the five sync endpoints and both blob endpoints
    /// declare in their lexicons and did not have: a takedown removed
    /// record-level reads while the whole repository CAR, its raw blocks and
    /// every blob stayed anonymously downloadable. A takedown for illegal
    /// content did not remove the content.
    ///
    /// Resolution happens **before** any per-actor store is opened, which also
    /// closes the second half of that problem: `SqlActorStore::open` creates
    /// the directory and runs migrations, so a handler that opened first let an
    /// unauthenticated caller materialise a SQLite file per DID it invented.
    ///
    /// # Errors
    ///
    /// [`PdsError::RepoUnavailable`] when the repository is unknown or its
    /// state disallows public reads.
    pub async fn require_available(&self, repo: &str) -> PdsResult<crate::account::AccountRow> {
        let row = if repo.starts_with("did:") {
            self.accounts.lookup_did(repo).await?
        } else {
            self.accounts.lookup_handle(repo).await?
        };
        let account = row.ok_or_else(|| PdsError::RepoUnavailable {
            did: repo.to_string(),
            state: "not found".to_string(),
        })?;
        if !account.state.allows_public_read() {
            return Err(PdsError::RepoUnavailable {
                did: account.did.clone(),
                state: account.state.as_str().to_string(),
            });
        }
        Ok(account)
    }

    /// Open the per-actor store for a DID.
    async fn open_actor(&self, did: &str) -> PdsResult<SqlActorStore> {
        SqlActorStore::open(&self.data_dir, did).await
    }

    /// Implementation of `com.atproto.repo.getRecord`.
    ///
    /// # Errors
    ///
    /// [`PdsError::RecordNotFound`] when the record is absent, superseded or
    /// taken down — the one error the lexicon declares. [`PdsError::NotFound`]
    /// when the *repository* is not hosted here, which is a different
    /// condition the lexicon does not name. [`PdsError::RepoUnavailable`] when
    /// the account exists but disallows public reads.
    pub async fn get_record(
        &self,
        repo: &str,
        collection: &str,
        rkey: &str,
        cid: Option<&str>,
    ) -> PdsResult<RecordResponse> {
        let account = self.resolve(repo).await?;
        require_public_read(&account.state, &account.did)?;

        // A record-level takedown hides the record from every public read, the
        // same way `space_record_takedown` does in the permissioned realm.
        // Checked before the CID is resolved so a taken-down record is
        // indistinguishable from one that was never written — a moderator
        // removing something should not leave a probe that says "still here".
        //
        // The store is opened once and reused by the legacy branch below.
        // `SqlActorStore::open` builds a fresh connection pool and runs
        // migrations on each call, so opening it twice per read would be a
        // real cost rather than a bookkeeping detail.
        let uri = format!("at://{}/{}/{}", account.did, collection, rkey);
        let store = self.open_actor(&account.did).await?;
        if crate::takedown::get_record(&store, &uri).await?.is_some() {
            return Err(PdsError::RecordNotFound { uri });
        }

        // Resolve the record CID through the trait surface when a backend
        // is wired; otherwise fall back to the legacy SQL-direct path.
        let cid_str = if let Some(backend) = self.backend.as_ref() {
            let row = backend
                .repo_record
                .get_by_uri(&account.did, &uri)
                .await?
                .ok_or_else(|| PdsError::RecordNotFound { uri: uri.clone() })?;
            // A `cid` that does not match the current version asks for a
            // version this repository no longer holds, which is the same
            // answer as "no such record" — the lexicon has one name for both.
            if let Some(c) = cid
                && c != row.cid
            {
                return Err(PdsError::RecordNotFound {
                    uri: format!("{uri} at cid {c}"),
                });
            }
            row.cid
        } else {
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
            row.ok_or_else(|| PdsError::RecordNotFound { uri: uri.clone() })?
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
            let block_storage = SqlBlockStorage::open(store.pool().clone())
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
        .ok_or_else(|| PdsError::Storage {
            // The index says this record exists and the block store disagrees:
            // a `repo_record` row pointing at a block nobody holds. Reported as
            // the server's own error and logged rather than as "no such
            // record", because a 400 here reads as routine and buries the
            // inconsistency.
            //
            // This is not unreachable. `com.atproto.repo.importRepo` can
            // produce it: `verify_inductive` accepts blocks missing from the
            // CAR whenever `prev_data` is `Some` (i.e. for every non-genesis
            // commit), and the MST walk that builds the index only loads node
            // blocks, never record leaves — so a multi-commit CAR that omits
            // record leaves indexes rows whose blocks were never stored.
            //
            // An operator who sees this in the log should treat it as a
            // damaged actor store for that DID, not as a bad request: check
            // whether the account recently ran `importRepo`, and repair by
            // re-importing a complete CAR for the DID or deleting the orphaned
            // `repo_record` rows. Tightening `importRepo` so it cannot create
            // the state is tracked separately.
            reason: format!("record {uri} indexed at block {cid_str}, which is not in the store"),
        })?;
        // Render back into the JSON representation: links stored as tag 42
        // become `$link` objects again, so a record reads out in the shape it
        // was written in.
        let value =
            atproto_dasl::atproto_json::from_slice(&block).map_err(|e| PdsError::Storage {
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
            // One query for the collection's takedown set rather than one per
            // record; it is almost always empty.
            let takedown_store = self.open_actor(&account.did).await?;
            let taken_down = crate::takedown::taken_down_in_collection(
                &takedown_store,
                &account.did,
                collection,
            )
            .await?;
            let block_storage = backend.open_block_storage(&account.did).await?;
            let mut records = Vec::with_capacity(rows.len());
            for r in &rows {
                if taken_down.contains(&r.uri) {
                    continue;
                }
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
                let value = if block.is_empty() {
                    serde_json::Value::Null
                } else {
                    atproto_dasl::atproto_json::from_slice(&block).map_err(|e| {
                        PdsError::Storage {
                            reason: format!("decode list_records DAG-CBOR: {e}"),
                        }
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
        let taken_down =
            crate::takedown::taken_down_in_collection(&store, &account.did, collection).await?;
        let mut records = Vec::with_capacity(rows.len());
        for (uri, cid_str, _rkey) in &rows {
            if taken_down.contains(uri) {
                continue;
            }
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
            let value = if block.is_empty() {
                serde_json::Value::Null
            } else {
                atproto_dasl::atproto_json::from_slice(&block).map_err(|e| PdsError::Storage {
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
        let account = self.require_available(repo).await?;
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
    /// Latest commit for a DID, without an availability check.
    ///
    /// Deliberately ungated: `com.atproto.sync.listRepos` enumerates every
    /// repository including taken-down ones, reporting `active: false` and a
    /// `status` rather than refusing them. The gate belongs on the
    /// `getLatestCommit` *endpoint*, which answers about one repository and
    /// declares the takedown errors; putting it here made `listRepos` fail
    /// outright the moment any account was taken down.
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

/// Refuse a public read against a repository whose state disallows it.
///
/// Reports [`PdsError::RepoUnavailable`] rather than a generic denial so that
/// `getRecord` and `listRecords` answer with the same named errors —
/// `RepoTakendown`, `RepoSuspended`, `RepoDeactivated` — as the sync and blob
/// endpoints. Their lexicons declare those too, and a caller that has to branch
/// on which state it hit should not need a different branch per endpoint.
fn require_public_read(state: &AccountState, did: &str) -> PdsResult<()> {
    if state.allows_public_read() {
        Ok(())
    } else {
        Err(PdsError::RepoUnavailable {
            did: did.to_string(),
            state: state.as_str().to_string(),
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

    /// Open an accounts directory under `dir` holding one active account.
    async fn seed_accounts(dir: &std::path::Path) -> AccountDirectory {
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
        accounts
    }

    async fn fresh_reader() -> (RepoReader, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = seed_accounts(&dir).await;
        let reader = RepoReader::new(accounts, dir);
        (reader, tmp)
    }

    /// Build the reader the way `bin/pds.rs` builds it: through
    /// [`RepoReader::with_backend`], so reads resolve across the
    /// `PublicRealmBackend` trait surface instead of the legacy SQLite-direct
    /// branch that [`fresh_reader`] exercises. The backend is rooted at the
    /// same `data_dir` as the reader so `seed_record` writes to the per-actor
    /// store the backend reads from.
    async fn fresh_reader_with_backend() -> (RepoReader, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = seed_accounts(&dir).await;
        let backend = Arc::new(PublicRealmBackend::sql(dir.clone()));
        let reader = RepoReader::with_backend(accounts, dir, backend);
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
    async fn get_record_missing_returns_record_not_found() {
        let (reader, _tmp) = fresh_reader().await;
        let result = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "absent", None)
            .await;
        assert!(matches!(result, Err(PdsError::RecordNotFound { .. })));
    }

    /// A record that was written and then removed must read back as the
    /// lexicon's `RecordNotFound`, not as the repository being unknown.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_after_delete_returns_record_not_found() {
        let (reader, _tmp) = fresh_reader().await;
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        seed_record(
            &store,
            "app.bsky.feed.post",
            "gone",
            serde_json::json!({"text": "bye"}),
        )
        .await;
        sqlx::query("DELETE FROM repo_record WHERE collection = ? AND rkey = ?")
            .bind("app.bsky.feed.post")
            .bind("gone")
            .execute(store.pool())
            .await
            .unwrap();
        drop(store);

        let result = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "gone", None)
            .await;
        assert!(matches!(result, Err(PdsError::RecordNotFound { uri }) if uri.contains("gone")));
    }

    /// Asking for a `cid` the record is no longer at is the same answer as the
    /// record being gone: the lexicon names only `RecordNotFound`.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_with_stale_cid_returns_record_not_found() {
        let (reader, _tmp) = fresh_reader().await;
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        seed_record(
            &store,
            "app.bsky.feed.post",
            "abc",
            serde_json::json!({"text": "hello"}),
        )
        .await;
        drop(store);

        let result = reader
            .get_record(
                "did:plc:alice",
                "app.bsky.feed.post",
                "abc",
                Some("bafyreib2rxk3rh6kzwq5oaczjqpygxpk4vt6zdgxc2iaskgm2wlpxzsuwm"),
            )
            .await;
        assert!(matches!(result, Err(PdsError::RecordNotFound { .. })));
    }

    /// The same two outcomes over the wiring the running server actually uses.
    ///
    /// Every other test here builds the reader with [`RepoReader::new`], which
    /// takes the legacy SQLite-direct branch; `bin/pds.rs` builds it with
    /// [`RepoReader::with_backend`], which resolves records through
    /// `PublicRealmBackend::repo_record`. Without this test both
    /// `RecordNotFound` sites on the backend branch are unexecuted, and the
    /// `at cid <cid>` message is reachable *only* from that branch — the legacy
    /// one filters on `cid` in SQL and cannot say which CID was asked for.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_record_reports_record_not_found_through_backend_wiring() {
        let (reader, _tmp) = fresh_reader_with_backend().await;
        assert!(
            reader.backend().is_some(),
            "this test proves nothing if the reader falls back to the legacy branch"
        );
        let store = reader.open_actor("did:plc:alice").await.unwrap();
        let value = serde_json::json!({"text": "hello"});
        let cid = seed_record(&store, "app.bsky.feed.post", "abc", value.clone()).await;
        drop(store);

        // Positive control: the seeded record does resolve through the trait
        // surface, so the assertions below are about absence rather than about
        // a harness that never finds anything.
        let found = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "abc", None)
            .await
            .unwrap();
        assert_eq!(found.cid, cid);
        assert_eq!(found.value, value);

        let missing = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "absent", None)
            .await;
        assert!(
            matches!(&missing, Err(PdsError::RecordNotFound { uri }) if uri.ends_with("/absent")),
            "expected RecordNotFound, got {missing:?}"
        );

        let stale = "bafyreib2rxk3rh6kzwq5oaczjqpygxpk4vt6zdgxc2iaskgm2wlpxzsuwm";
        let result = reader
            .get_record("did:plc:alice", "app.bsky.feed.post", "abc", Some(stale))
            .await;
        let Err(PdsError::RecordNotFound { uri }) = result else {
            panic!("expected RecordNotFound, got {result:?}")
        };
        assert!(uri.contains("at cid"), "uri: {uri}");
        assert!(uri.contains(stale), "uri: {uri}");
    }

    /// A repository this server does not host is a different condition, and
    /// `getRecord` has no lexicon name for it — it stays [`PdsError::NotFound`]
    /// so the HTTP layer can report the generic `InvalidRequest`.
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
        // Reports `RepoUnavailable` rather than a generic denial so the state
        // survives to the wire as `RepoTakendown`, matching what this endpoint's
        // lexicon declares and what every other public read path now answers.
        let result = reader.get_record("did:plc:alice", "x.y.z", "k", None).await;
        let Err(PdsError::RepoUnavailable { state, .. }) = result else {
            panic!("expected RepoUnavailable, got {result:?}")
        };
        assert_eq!(state, "takendown");
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
