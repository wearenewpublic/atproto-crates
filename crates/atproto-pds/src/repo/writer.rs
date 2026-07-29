//! Public-realm repo writer — `createRecord`, `putRecord`, `deleteRecord`,
//! `applyWrites`, signed-commit construction, Sync 1.1 `#commit` event emission.
//!
//! and G2: serializes
//! writes per-DID via a per-DID async mutex (`Arc<Mutex<()>>` keyed in a
//! `DashMap`). For each batch:
//!
//! 1. Acquire the per-DID mutex.
//! 2. Open the per-actor `SqlActorStore` and `SqlBlockStorage`.
//! 3. Load the current MST root from the latest commit (or empty).
//! 4. For each op: encode the record as DAG-CBOR, compute its CID, insert/
//!    delete from the MST, write to `repo_block` and `repo_record`.
//! 5. Build a signed `Commit` via `atproto-repo::UnsignedCommit::sign` using
//!    the account's KeyStore-resolved signing key.
//! 6. Append the commit row to `commit_obj`, then — once that is durable —
//!    record a Sync 1.1 `#commit` on the firehose stream. The stream is
//!    server-global and so lives outside the per-actor transaction; see
//!    [`crate::sequencer::stream`].
//!
//! `getRepo` CAR streaming and `subscribeRepos` live tail land alongside in
//! sibling files; this module is the source of truth for "what changed" and
//! "what got signed".

use crate::account::AccountManager;
use crate::actor_store::sql::{SqlActorStore, SqlBlockStorage};
use crate::actor_store::traits::CommitBatch;
use crate::actor_store::{
    CommitRow as ActorCommitRow, PublicRealmBackend, RecordRow as ActorRecordRow,
};
use crate::errors::{PdsError, PdsResult};
use crate::repo::commit_car::{RecordingBlockStorage, build_commit_car};
use crate::sequencer::{EventType, OutboxReader};
use atproto_dasl::cid::compute_cid;
use atproto_dasl::storage::BlockStorage;
use atproto_repo::RepoConfig;
use atproto_repo::mst::Mst;
use atproto_repo::{Commit, MstDiff, RepoOp, RepoOpAction, UnsignedCommit, ops_with_prev_cids};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Action discriminator on a `WriteOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteAction {
    /// Create a new record. Fails if `(collection, rkey)` already exists.
    Create,
    /// Upsert a record. Always succeeds.
    Update,
    /// Delete a record. Fails if `(collection, rkey)` is absent.
    Delete,
}

/// One write inside a batch.
#[derive(Debug, Clone)]
pub struct WriteOp {
    /// Action.
    pub action: WriteAction,
    /// NSID collection.
    pub collection: String,
    /// Record key (auto-generated from TID if empty on Create).
    pub rkey: String,
    /// Decoded value (None for Delete).
    pub value: Option<serde_json::Value>,
    /// Optional prior-CID swap guard for Update/Delete.
    pub swap_record: Option<String>,
}

/// Result of a successful write.
#[derive(Debug, Clone, Serialize)]
pub struct WriteResult {
    /// AT-URI of the affected record (`at://<did>/<collection>/<rkey>`).
    pub uri: String,
    /// CID of the record value (None for Delete).
    pub cid: Option<String>,
    /// Sync 1.1 op shape (action + path + cid + prev) for firehose payload.
    pub op: RepoOp,
}

/// Result of a successful batch.
#[derive(Debug, Clone, Serialize)]
pub struct CommitResult {
    /// New commit CID.
    pub commit_cid: String,
    /// New rev (TID).
    pub rev: String,
    /// New MST root CID.
    pub data_cid: String,
    /// Per-op results, in input order.
    pub writes: Vec<WriteResult>,
}

/// Per-DID mutex map — serializes writes per account so commits are
/// linearized.
type WriteLocks = Arc<DashMap<String, Arc<Mutex<()>>>>;

/// Repo writer state shared across handlers.
pub struct RepoWriter {
    accounts: Arc<AccountManager>,
    data_dir: PathBuf,
    /// Public-realm backend dispatch. When `Some`, the writer goes
    /// through the trait surface (commit_obj, repo_record, outbox,
    /// atomic-commit) for both backends. When `None`, the legacy
    /// SQLite-direct path runs.
    backend: Option<Arc<PublicRealmBackend>>,
    write_locks: WriteLocks,
}

impl RepoWriter {
    /// Construct without a public-realm backend wired (legacy SQLite
    /// path). `bin/pds.rs` calls [`Self::with_backend`] instead so the
    /// writer goes through trait dispatch.
    pub fn new(accounts: Arc<AccountManager>, data_dir: PathBuf) -> Self {
        Self {
            accounts,
            data_dir,
            backend: None,
            write_locks: Arc::new(DashMap::new()),
        }
    }

    /// Construct with a public-realm backend wired. The writer's
    /// `apply_writes` uses the trait dispatch (commit_obj read +
    /// `AtomicCommitWriter` for the lockstep insert) instead of the
    /// SQLite-direct legacy path. Required for fjall deployments.
    pub fn with_backend(
        accounts: Arc<AccountManager>,
        data_dir: PathBuf,
        backend: Arc<PublicRealmBackend>,
    ) -> Self {
        Self {
            accounts,
            data_dir,
            backend: Some(backend),
            write_locks: Arc::new(DashMap::new()),
        }
    }

    fn lock_for(&self, did: &str) -> Arc<Mutex<()>> {
        self.write_locks
            .entry(did.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Apply a batch of write ops as one signed commit.
    ///
    /// Holds the per-DID mutex for the duration; concurrent writes to the
    /// same account block until this returns. Returns the per-op results +
    /// the new commit metadata.
    ///
    /// When [`Self::with_backend`] supplied a [`PublicRealmBackend`], the
    /// reads + atomic write dispatch through its trait surface. Otherwise
    /// the legacy SQLite-direct path runs.
    pub async fn apply_writes(&self, did: &str, ops: Vec<WriteOp>) -> PdsResult<CommitResult> {
        self.apply_writes_with_swap(did, ops, None).await
    }

    /// Apply a batch, optionally guarded by a compare-and-swap on the repo's
    /// current commit.
    ///
    /// `swap_commit` is the lexicons' `swapCommit`: the caller states the
    /// commit it believes the repository is at, and the write is refused with
    /// [`PdsError::InvalidSwap`] if it has moved. Without it, two clients that
    /// each read, decided, and wrote would both receive HTTP 200 and the second
    /// would silently discard the first's work.
    ///
    /// The comparison happens inside the per-DID write mutex, after the prior
    /// commit is loaded and before anything is written — so it is a genuine
    /// compare-and-swap against concurrent writers on this server, not a
    /// check-then-hope.
    pub async fn apply_writes_with_swap(
        &self,
        did: &str,
        ops: Vec<WriteOp>,
        swap_commit: Option<&str>,
    ) -> PdsResult<CommitResult> {
        if ops.is_empty() {
            return Err(PdsError::NotFound {
                what: "applyWrites called with empty ops".to_string(),
            });
        }

        // Structural checks before the lock is taken and before anything is
        // encoded. The repository is append-only: a record key containing `/`
        // produces a record whose MST path and its own AT-URI disagree, and
        // nothing rewrites that once the commit is signed and sequenced.
        //
        // Applied here rather than in either write path so both get it, and so
        // a batch is refused whole — `applyWrites` says "the entire operation
        // will fail", and half a batch landing because op 3 was malformed
        // would be worse than the malformed op itself.
        let ops = Self::prepare_ops(ops)?;

        let lock = self.lock_for(did);
        let _guard = lock.lock().await;

        match self.backend.as_ref() {
            Some(backend) => {
                self.apply_writes_dispatch(did, ops, backend.clone(), swap_commit)
                    .await
            }
            None => self.apply_writes_legacy(did, ops, swap_commit).await,
        }
    }

    /// Apply the structural checks to a batch, returning the ops to write.
    ///
    /// `$type` is filled in from the collection when absent, which is what the
    /// reference does — a record with no `$type` is undecodable by every
    /// consumer, and supplying it is what makes it decodable. A `$type` that
    /// disagrees with the collection is refused.
    ///
    /// Deletes carry no value, so only their collection and key are checked.
    ///
    /// # Errors
    ///
    /// [`PdsError::InvalidRecord`] naming the op and the check that failed.
    fn prepare_ops(ops: Vec<WriteOp>) -> PdsResult<Vec<WriteOp>> {
        use crate::repo::prepare;
        ops.into_iter()
            .map(|mut op| {
                prepare::check_collection(&op.collection)?;
                // An empty key on create means "generate a TID", which the
                // handler does before this point; anything that arrives here
                // is a key the caller chose.
                prepare::check_rkey(&op.rkey)?;
                if let Some(value) = op.value.take() {
                    op.value = Some(prepare::reconcile_type(&op.collection, value)?);
                }
                Ok(op)
            })
            .collect()
    }

    /// Refuse the write when the caller's expected commit is not the current
    /// one.
    ///
    /// An absent `swap_commit` means the caller made no claim, so nothing to
    /// check. A caller that names a commit for an empty repository is wrong in
    /// a way worth reporting rather than ignoring.
    fn check_swap(swap_commit: Option<&str>, current: Option<&str>) -> PdsResult<()> {
        let Some(expected) = swap_commit else {
            return Ok(());
        };
        if current == Some(expected) {
            return Ok(());
        }
        Err(PdsError::InvalidSwap {
            expected: expected.to_string(),
            actual: current.unwrap_or("none").to_string(),
        })
    }

    /// Maintain the record→blob reference index for a committed batch.
    ///
    /// Every piece of this existed — the trait method, three backend
    /// implementations, the free functions, unit tests — and nothing called it.
    /// So `listMissingBlobs` answered `{"blobs": []}` forever and
    /// `checkAccountStatus.expectedBlobs` stayed `0`: a migrating client
    /// concluded there was nothing to transfer and activated an account with
    /// none of its media, while every step reported success.
    ///
    /// Updates and deletes drop the record's existing refs first. Adding
    /// without dropping would make the counts only ever grow, which is a
    /// different wrong answer rather than a fix — and blob GC reads those
    /// counts to decide what is orphaned.
    ///
    /// Best-effort, like the firehose publish: the commit is already durable,
    /// and failing the write here would report a record that exists as not
    /// written. A failure is logged at ERROR because the consequence — media
    /// silently absent after a migration — is invisible to the client.
    async fn maintain_blob_refs(&self, did: &str, ops: &[WriteOp]) {
        for op in ops {
            let uri = format!("at://{}/{}/{}", did, op.collection, op.rkey);
            if let Err(error) = self.maintain_one(did, &uri, op).await {
                tracing::error!(
                    error = ?error,
                    did,
                    uri,
                    "failed to update blob references; listMissingBlobs will under-report"
                );
            }
        }
    }

    async fn maintain_one(&self, did: &str, uri: &str, op: &WriteOp) -> PdsResult<()> {
        let replacing = matches!(op.action, WriteAction::Update | WriteAction::Delete);
        let refs = match (&op.action, &op.value) {
            (WriteAction::Delete, _) | (_, None) => Vec::new(),
            (_, Some(value)) => crate::blob::walk_blob_refs(value),
        };

        if let Some(backend) = self.backend.as_ref() {
            if replacing {
                backend.blob.drop_refs_for_record(did, uri).await?;
            }
            for blob in &refs {
                backend
                    .blob
                    .add_ref(
                        did,
                        &crate::actor_store::BlobRefRow {
                            blob_cid: blob.inner.ref_.link.clone(),
                            mime_type: blob.inner.mime_type.clone(),
                            size: blob.inner.size,
                            record_uri: uri.to_string(),
                        },
                    )
                    .await?;
            }
        } else {
            let store = SqlActorStore::open(&self.data_dir, did).await?;
            if replacing {
                crate::blob::drop_record_refs(&store, uri).await?;
            }
            for blob in &refs {
                crate::blob::add_ref(&store, uri, blob).await?;
            }
        }
        Ok(())
    }

    /// Record a `#commit` on the firehose stream.
    ///
    /// Called after the repository write is durable, never inside it: the
    /// stream log is server-global and lives in the accounts database, so it
    /// cannot share the per-actor transaction. Best-effort in consequence — a
    /// failure here leaves a commit that no event announced, which subscribers
    /// repair by re-anchoring through `#sync` or `getRepo`. Returning an error
    /// would report a write as failed that in fact succeeded.
    async fn publish_commit(&self, did: &str, payload: Vec<u8>) {
        let result = self
            .accounts
            .sequencer()
            .append(did, EventType::Commit.as_str(), payload)
            .await;
        match result {
            Ok(seq) => tracing::debug!(did, seq, "firehose: sequenced #commit"),
            Err(error) => {
                tracing::error!(error = ?error, did, "firehose: failed to sequence #commit");
            }
        }
    }

    /// Legacy SQLite-direct path. Kept for back-compat with tests
    /// that build `RepoWriter::new(...)` without a backend.
    async fn apply_writes_legacy(
        &self,
        did: &str,
        ops: Vec<WriteOp>,
        swap_commit: Option<&str>,
    ) -> PdsResult<CommitResult> {
        let store = SqlActorStore::open(&self.data_dir, did).await?;
        let pool = store.pool();

        // Load the current commit (if any) to seed the MST.
        let prior: Option<(String, String, String)> =
            sqlx::query_as("SELECT cid, rev, data_cid FROM commit_obj ORDER BY rev DESC LIMIT 1")
                .fetch_optional(pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("load prior commit: {e}"),
                })?;
        let (prev_commit_cid, prev_data_cid) = match prior.as_ref() {
            Some((cid, _, data)) => (Some(cid.clone()), Some(data.clone())),
            None => (None, None),
        };
        Self::check_swap(swap_commit, prev_commit_cid.as_deref())?;

        // Prepare an MST over a fresh SqlBlockStorage that shares the pool.
        let block_storage =
            SqlBlockStorage::open(pool.clone())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("open block storage: {e}"),
                })?;
        let config = RepoConfig::default();
        let mut mst = match prev_data_cid.as_deref() {
            Some(root_str) => {
                let root: cid::Cid =
                    root_str
                        .parse()
                        .map_err(|e: cid::Error| PdsError::Storage {
                            reason: format!("parse prior data CID: {e}"),
                        })?;
                Mst::from_root(root, RecordingBlockStorage::new(block_storage), config)
            }
            None => Mst::new(RecordingBlockStorage::new(block_storage), config),
        };

        // Apply ops to the MST + persist record bytes to repo_block.
        let mut diffs: Vec<MstDiff> = Vec::with_capacity(ops.len());
        let mut record_rows: Vec<(String, String, String, String)> = Vec::with_capacity(ops.len()); // (uri, cid, collection, rkey)
        let mut delete_rkeys: Vec<(String, String)> = Vec::new(); // (collection, rkey)

        let now = Utc::now().to_rfc3339();
        for op in &ops {
            let mst_key = format!("{}/{}", op.collection, op.rkey);
            match op.action {
                WriteAction::Create | WriteAction::Update => {
                    let value = op.value.clone().ok_or_else(|| PdsError::NotFound {
                        what: format!("write {} requires value", mst_key),
                    })?;
                    // Read the JSON representation into the data model before
                    // encoding: `$link` names a link and `$bytes` a byte
                    // string, and encoding them as literal maps produces a
                    // record no peer computes the same CID for.
                    let bytes = atproto_dasl::atproto_json::to_vec(&value).map_err(|e| {
                        PdsError::Storage {
                            reason: format!("encode value: {e}"),
                        }
                    })?;
                    let cid = compute_cid(&bytes);

                    // Persist record block (idempotent — same value yields same CID).
                    {
                        let storage = mst.storage_mut();
                        BlockStorage::put(storage, &cid, bytes.clone())
                            .await
                            .map_err(|e| PdsError::Storage {
                                reason: format!("put record block: {e}"),
                            })?;
                    }

                    let prior_value = mst.get(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst get: {e}"),
                    })?;
                    if matches!(op.action, WriteAction::Create) && prior_value.is_some() {
                        return Err(PdsError::NotFound {
                            what: format!("record {} already exists", mst_key),
                        });
                    }
                    if let Some(swap_str) = op.swap_record.as_deref() {
                        let prior_cid = prior_value.as_ref().map(|c| c.0.to_string());
                        if prior_cid.as_deref() != Some(swap_str) {
                            return Err(PdsError::AuthDenied {
                                reason: format!(
                                    "swapRecord mismatch on {}: expected {swap_str}, found {:?}",
                                    mst_key, prior_cid
                                ),
                            });
                        }
                    }

                    let dasl_cid: atproto_dasl::Cid = cid.into();
                    mst.insert(&mst_key, dasl_cid.clone()).await.map_err(|e| {
                        PdsError::Storage {
                            reason: format!("mst insert: {e}"),
                        }
                    })?;
                    let cid_str = cid.to_string();
                    let uri = format!("at://{}/{}/{}", did, op.collection, op.rkey);
                    record_rows.push((
                        uri,
                        cid_str.clone(),
                        op.collection.clone(),
                        op.rkey.clone(),
                    ));

                    diffs.push(if let Some(old) = prior_value {
                        MstDiff::Update {
                            key: mst_key,
                            old_cid: old,
                            new_cid: dasl_cid,
                        }
                    } else {
                        MstDiff::Add {
                            key: mst_key,
                            cid: dasl_cid,
                        }
                    });
                }
                WriteAction::Delete => {
                    let prior_value = mst.get(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst get: {e}"),
                    })?;
                    let prior_cid = prior_value.ok_or_else(|| PdsError::NotFound {
                        what: format!("record {} not found for delete", mst_key),
                    })?;
                    if let Some(swap_str) = op.swap_record.as_deref()
                        && swap_str != prior_cid.0.to_string()
                    {
                        return Err(PdsError::AuthDenied {
                            reason: format!("swapRecord mismatch on delete: {}", mst_key),
                        });
                    }
                    mst.delete(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst delete: {e}"),
                    })?;
                    delete_rkeys.push((op.collection.clone(), op.rkey.clone()));
                    diffs.push(MstDiff::Delete {
                        key: mst_key,
                        cid: prior_cid,
                    });
                }
            }
        }

        // After all-records-deleted, the MST root is None. Substitute the CID
        // of an empty MstNode so the commit always references a real block.
        let new_root = match mst.root().cloned() {
            Some(c) => c,
            None => {
                let empty_node = atproto_repo::mst::MstNode::empty();
                let bytes = atproto_dasl::to_vec(&empty_node).map_err(|e| PdsError::Storage {
                    reason: format!("encode empty MST node: {e}"),
                })?;
                let cid = compute_cid(&bytes);
                let storage = mst.storage_mut();
                BlockStorage::put(storage, &cid, bytes)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("put empty MST node: {e}"),
                    })?;
                cid
            }
        };

        // Build the unsigned commit + sign with the account's signing key.
        let rev = atproto_record::tid::Tid::new().to_string();
        let prev_cid_parsed: Option<atproto_dasl::Cid> = prev_commit_cid
            .as_deref()
            .map(|s| s.parse::<cid::Cid>().map(atproto_dasl::Cid::from))
            .transpose()
            .map_err(|e: cid::Error| PdsError::Storage {
                reason: format!("parse prev commit cid: {e}"),
            })?;

        // `prevData` is deliberately absent from the signed commit body: it is
        // a `com.atproto.sync.subscribeRepos#commit` event field, not
        // repository state, and it is not part of what the account signs.
        // Subscribers still receive it, from the outbox payload built below.
        let unsigned = UnsignedCommit::new(
            did.to_string(),
            atproto_dasl::Cid::from(new_root),
            rev.clone(),
            prev_cid_parsed,
        );
        let signing_bytes = atproto_dasl::to_vec(&unsigned).map_err(|e| PdsError::Storage {
            reason: format!("encode unsigned commit: {e}"),
        })?;

        // Resolve the account's signing key via KeyStore.
        let row = self.accounts.pool();
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(row)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {did} has no signing_key_ref"),
            })?
            .0;
        let signing_key = self.accounts.key_store().get(&key_ref).await?;
        let sig = atproto_identity::key::sign(&signing_key, &signing_bytes).map_err(|e| {
            PdsError::Storage {
                reason: format!("sign commit: {e}"),
            }
        })?;
        let signed: Commit = unsigned.sign(sig);
        let commit_bytes = atproto_dasl::to_vec(&signed).map_err(|e| PdsError::Storage {
            reason: format!("encode signed commit: {e}"),
        })?;
        let commit_cid = compute_cid(&commit_bytes);
        // The CARv1 slice this event carries. `mst` is finished with by now, so
        // the recorder can be unwrapped for the blocks the commit wrote.
        let (_, written_blocks) = mst.into_storage().into_parts();
        let blocks_car = build_commit_car(&commit_cid, &commit_bytes, &written_blocks).await?;

        // Persist commit + record-rows + outbox event in one tx.
        let mut tx = pool.begin().await.map_err(|e| PdsError::Storage {
            reason: format!("begin commit tx: {e}"),
        })?;

        sqlx::query(
            "INSERT INTO commit_obj (cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(commit_cid.to_string())
        .bind(&rev)
        .bind(new_root.to_string())
        .bind(&prev_commit_cid)
        .bind(&prev_data_cid)
        .bind(&signed.sig)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| PdsError::Storage { reason: format!("insert commit_obj: {e}") })?;

        // Persist the commit block itself for getRepo / inductive verifiers.
        sqlx::query("INSERT OR IGNORE INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)")
            .bind(commit_cid.to_string())
            .bind(&commit_bytes)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("insert commit block: {e}"),
            })?;

        // repo_record rows.
        for (uri, cid_str, collection, rkey) in &record_rows {
            sqlx::query(
                "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT (collection, rkey) DO UPDATE SET cid = excluded.cid, rev = excluded.rev, indexed_at = excluded.indexed_at",
            )
            .bind(uri)
            .bind(cid_str)
            .bind(collection)
            .bind(rkey)
            .bind(&rev)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage { reason: format!("insert repo_record: {e}") })?;
        }
        for (collection, rkey) in &delete_rkeys {
            sqlx::query("DELETE FROM repo_record WHERE collection = ? AND rkey = ?")
                .bind(collection)
                .bind(rkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("delete repo_record: {e}"),
                })?;
        }

        // The `#commit` body, in the shape the subscription's union declares.
        // `seq` and `time` belong to the delivery and are added when the frame
        // is built.
        let repo_ops = ops_with_prev_cids(&diffs);
        let payload_bytes = crate::sequencer::payload::encode(&commit_body(
            did,
            &commit_cid,
            &rev,
            prior.as_ref().map(|(_, rev, _)| rev.clone()),
            prev_data_cid.as_deref(),
            repo_ops.clone(),
            blocks_car,
        )?)?;

        tx.commit().await.map_err(|e| PdsError::Storage {
            reason: format!("commit tx: {e}"),
        })?;

        // The stream log is server-global and so lives in a different database
        // from this repository — the event cannot ride in the transaction
        // above. It is published only after the commit is durable, so the
        // ordering failure is a missed event rather than one announcing a
        // commit that does not exist.
        self.publish_commit(did, payload_bytes).await;
        self.maintain_blob_refs(did, &ops).await;

        // Compose the per-op WriteResult from the diffs + repo_ops aligned positions.
        let mut writes = Vec::with_capacity(ops.len());
        for (op, repo_op) in ops.iter().zip(repo_ops.iter()) {
            let uri = format!("at://{}/{}/{}", did, op.collection, op.rkey);
            let cid = match repo_op.action {
                RepoOpAction::Delete => None,
                _ => repo_op.cid.as_ref().map(|c| c.0.to_string()),
            };
            writes.push(WriteResult {
                uri,
                cid,
                op: repo_op.clone(),
            });
        }

        Ok(CommitResult {
            commit_cid: commit_cid.to_string(),
            rev,
            data_cid: new_root.to_string(),
            writes,
        })
    }

    /// Backend-dispatched writer path. Reads the prior commit via
    /// `commit_obj.latest`, opens a per-actor `BlockStorage` through
    /// the dispatch factory, runs the MST work, then commits the
    /// final lockstep through `AtomicCommitWriter::apply_atomic_commit`
    /// — which uses the backend's native atomicity primitive (sqlx
    /// `Transaction` for SQL, `fjall::WriteBatch` for fjall).
    async fn apply_writes_dispatch(
        &self,
        did: &str,
        ops: Vec<WriteOp>,
        backend: Arc<PublicRealmBackend>,
        swap_commit: Option<&str>,
    ) -> PdsResult<CommitResult> {
        // Load the prior commit via trait dispatch.
        let prior = backend.commit_obj.latest(did).await?;
        let (prev_commit_cid, prev_data_cid) = match prior.as_ref() {
            Some(row) => (Some(row.cid.clone()), Some(row.data_cid.clone())),
            None => (None, None),
        };
        Self::check_swap(swap_commit, prev_commit_cid.as_deref())?;

        // Open a per-actor block storage handle through the dispatch
        // factory. The MST builder takes ownership.
        let block_storage = backend.open_block_storage(did).await?;
        let config = RepoConfig::default();
        let mut mst = match prev_data_cid.as_deref() {
            Some(root_str) => {
                let root: cid::Cid =
                    root_str
                        .parse()
                        .map_err(|e: cid::Error| PdsError::Storage {
                            reason: format!("parse prior data CID: {e}"),
                        })?;
                Mst::from_root(root, RecordingBlockStorage::new(block_storage), config)
            }
            None => Mst::new(RecordingBlockStorage::new(block_storage), config),
        };

        // Apply ops to the MST + persist record bytes.
        let mut diffs: Vec<MstDiff> = Vec::with_capacity(ops.len());
        let mut record_rows: Vec<(String, String, String, String)> = Vec::with_capacity(ops.len());
        let mut delete_rkeys: Vec<(String, String)> = Vec::new();
        let now = Utc::now().to_rfc3339();
        for op in &ops {
            let mst_key = format!("{}/{}", op.collection, op.rkey);
            match op.action {
                WriteAction::Create | WriteAction::Update => {
                    let value = op.value.clone().ok_or_else(|| PdsError::NotFound {
                        what: format!("write {} requires value", mst_key),
                    })?;
                    // Read the JSON representation into the data model before
                    // encoding: `$link` names a link and `$bytes` a byte
                    // string, and encoding them as literal maps produces a
                    // record no peer computes the same CID for.
                    let bytes = atproto_dasl::atproto_json::to_vec(&value).map_err(|e| {
                        PdsError::Storage {
                            reason: format!("encode value: {e}"),
                        }
                    })?;
                    let cid = compute_cid(&bytes);
                    {
                        let storage = mst.storage_mut();
                        BlockStorage::put(storage, &cid, bytes.clone())
                            .await
                            .map_err(|e| PdsError::Storage {
                                reason: format!("put record block: {e}"),
                            })?;
                    }
                    let prior_value = mst.get(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst get: {e}"),
                    })?;
                    if matches!(op.action, WriteAction::Create) && prior_value.is_some() {
                        return Err(PdsError::NotFound {
                            what: format!("record {} already exists", mst_key),
                        });
                    }
                    if let Some(swap_str) = op.swap_record.as_deref() {
                        let prior_cid = prior_value.as_ref().map(|c| c.0.to_string());
                        if prior_cid.as_deref() != Some(swap_str) {
                            return Err(PdsError::AuthDenied {
                                reason: format!(
                                    "swapRecord mismatch on {}: expected {swap_str}, found {:?}",
                                    mst_key, prior_cid
                                ),
                            });
                        }
                    }
                    let dasl_cid: atproto_dasl::Cid = cid.into();
                    mst.insert(&mst_key, dasl_cid.clone()).await.map_err(|e| {
                        PdsError::Storage {
                            reason: format!("mst insert: {e}"),
                        }
                    })?;
                    let cid_str = cid.to_string();
                    let uri = format!("at://{}/{}/{}", did, op.collection, op.rkey);
                    record_rows.push((
                        uri,
                        cid_str.clone(),
                        op.collection.clone(),
                        op.rkey.clone(),
                    ));
                    diffs.push(if let Some(old) = prior_value {
                        MstDiff::Update {
                            key: mst_key,
                            old_cid: old,
                            new_cid: dasl_cid,
                        }
                    } else {
                        MstDiff::Add {
                            key: mst_key,
                            cid: dasl_cid,
                        }
                    });
                }
                WriteAction::Delete => {
                    let prior_value = mst.get(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst get: {e}"),
                    })?;
                    let prior_cid = prior_value.ok_or_else(|| PdsError::NotFound {
                        what: format!("record {} not found for delete", mst_key),
                    })?;
                    if let Some(swap_str) = op.swap_record.as_deref()
                        && swap_str != prior_cid.0.to_string()
                    {
                        return Err(PdsError::AuthDenied {
                            reason: format!("swapRecord mismatch on delete: {}", mst_key),
                        });
                    }
                    mst.delete(&mst_key).await.map_err(|e| PdsError::Storage {
                        reason: format!("mst delete: {e}"),
                    })?;
                    delete_rkeys.push((op.collection.clone(), op.rkey.clone()));
                    diffs.push(MstDiff::Delete {
                        key: mst_key,
                        cid: prior_cid,
                    });
                }
            }
        }

        // Empty-MST sentinel.
        let new_root = match mst.root().cloned() {
            Some(c) => c,
            None => {
                let empty_node = atproto_repo::mst::MstNode::empty();
                let bytes = atproto_dasl::to_vec(&empty_node).map_err(|e| PdsError::Storage {
                    reason: format!("encode empty MST node: {e}"),
                })?;
                let cid = compute_cid(&bytes);
                let storage = mst.storage_mut();
                BlockStorage::put(storage, &cid, bytes)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("put empty MST node: {e}"),
                    })?;
                cid
            }
        };

        // Build + sign the commit.
        let rev = atproto_record::tid::Tid::new().to_string();
        let prev_cid_parsed: Option<atproto_dasl::Cid> = prev_commit_cid
            .as_deref()
            .map(|s| s.parse::<cid::Cid>().map(atproto_dasl::Cid::from))
            .transpose()
            .map_err(|e: cid::Error| PdsError::Storage {
                reason: format!("parse prev commit cid: {e}"),
            })?;
        // `prevData` is deliberately absent from the signed commit body: it is
        // a `com.atproto.sync.subscribeRepos#commit` event field, not
        // repository state, and it is not part of what the account signs.
        // Subscribers still receive it, from the outbox payload built below.
        let unsigned = UnsignedCommit::new(
            did.to_string(),
            atproto_dasl::Cid::from(new_root),
            rev.clone(),
            prev_cid_parsed,
        );
        let signing_bytes = atproto_dasl::to_vec(&unsigned).map_err(|e| PdsError::Storage {
            reason: format!("encode unsigned commit: {e}"),
        })?;
        let row = self.accounts.pool();
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(row)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {did} has no signing_key_ref"),
            })?
            .0;
        let signing_key = self.accounts.key_store().get(&key_ref).await?;
        let sig = atproto_identity::key::sign(&signing_key, &signing_bytes).map_err(|e| {
            PdsError::Storage {
                reason: format!("sign commit: {e}"),
            }
        })?;
        let signed: Commit = unsigned.sign(sig);
        let commit_bytes = atproto_dasl::to_vec(&signed).map_err(|e| PdsError::Storage {
            reason: format!("encode signed commit: {e}"),
        })?;
        let commit_cid = compute_cid(&commit_bytes);
        // The CARv1 slice this event carries. `mst` is finished with by now, so
        // the recorder can be unwrapped for the blocks the commit wrote.
        let (_, written_blocks) = mst.into_storage().into_parts();
        let blocks_car = build_commit_car(&commit_cid, &commit_bytes, &written_blocks).await?;

        // Build the atomic-commit batch.
        let commit_row = ActorCommitRow {
            cid: commit_cid.to_string(),
            rev: rev.clone(),
            data_cid: new_root.to_string(),
            prev_cid: prev_commit_cid,
            prev_data_cid,
            signature: signed.sig.clone(),
            created_at: now.clone(),
        };
        let upserts: Vec<ActorRecordRow> = record_rows
            .iter()
            .map(|(uri, cid, collection, rkey)| ActorRecordRow {
                uri: uri.clone(),
                cid: cid.clone(),
                collection: collection.clone(),
                rkey: rkey.clone(),
                rev: rev.clone(),
                indexed_at: now.clone(),
            })
            .collect();
        let repo_ops = ops_with_prev_cids(&diffs);
        let payload_bytes = crate::sequencer::payload::encode(&commit_body(
            did,
            &commit_cid,
            &rev,
            prior.as_ref().map(|row| row.rev.clone()),
            commit_row.prev_data_cid.as_deref(),
            repo_ops.clone(),
            blocks_car,
        )?)?;
        let commit_cid_str = commit_cid.to_string();
        let batch = CommitBatch {
            commit: &commit_row,
            commit_block_cid: &commit_cid_str,
            commit_block_bytes: &commit_bytes,
            record_upserts: &upserts,
            record_deletes: &delete_rkeys,
        };
        backend.atomic.apply_atomic_commit(did, batch).await?;

        // Published after the commit is durable — see the comment on the same
        // call in `apply_writes_legacy`.
        self.publish_commit(did, payload_bytes).await;
        self.maintain_blob_refs(did, &ops).await;

        let mut writes = Vec::with_capacity(ops.len());
        for (op, repo_op) in ops.iter().zip(repo_ops.iter()) {
            let uri = format!("at://{}/{}/{}", did, op.collection, op.rkey);
            let cid = match repo_op.action {
                RepoOpAction::Delete => None,
                _ => repo_op.cid.as_ref().map(|c| c.0.to_string()),
            };
            writes.push(WriteResult {
                uri,
                cid,
                op: repo_op.clone(),
            });
        }
        Ok(CommitResult {
            commit_cid: commit_cid.to_string(),
            rev,
            data_cid: new_root.to_string(),
            writes,
        })
    }
}

/// Helper for the read-side: load the latest outbox seq for monitoring.
pub async fn outbox_latest_seq(store: &SqlActorStore) -> PdsResult<Option<i64>> {
    let outbox = OutboxReader::new(store.pool().clone());
    outbox.latest_seq().await
}

/// Assemble a `#commit` body for the firehose.
///
/// `since` is the revision of the previous commit from this repo — the point a
/// subscriber would be resuming from — and is null for a repository's first
/// commit. `blocks` is the CARv1 slice carrying what this commit wrote.
/// `blobs` remains empty pending F-BLOB-02.
#[allow(clippy::too_many_arguments)]
fn commit_body(
    did: &str,
    commit_cid: &cid::Cid,
    rev: &str,
    since: Option<String>,
    prev_data_cid: Option<&str>,
    ops: Vec<atproto_repo::mst::RepoOp>,
    blocks: Vec<u8>,
) -> PdsResult<crate::sequencer::payload::CommitBody> {
    let prev_data = prev_data_cid
        .map(|text| {
            text.parse::<cid::Cid>()
                .map(atproto_dasl::Cid::from)
                .map_err(|e: cid::Error| PdsError::Storage {
                    reason: format!("parse prevData for #commit: {e}"),
                })
        })
        .transpose()?;
    Ok(crate::sequencer::payload::CommitBody {
        rebase: false,
        too_big: false,
        repo: did.to_string(),
        commit: atproto_dasl::Cid::from(*commit_cid),
        rev: rev.to_string(),
        since,
        blocks,
        ops,
        blobs: Vec::new(),
        prev_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::MemoryKeyStore;
    use atproto_identity::key::KeyType;
    use tempfile::TempDir;

    /// Open the firehose stream backing a test data directory.
    ///
    /// The stream log lives in the accounts DB, not in the actor store, which
    /// is the whole point of the change these tests cover.
    async fn stream_of(dir: &std::path::Path) -> crate::sequencer::Sequencer {
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        crate::sequencer::Sequencer::new(accounts.account_pool())
    }

    async fn fresh_writer() -> (RepoWriter, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn crate::keys::KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.clone(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let writer = RepoWriter::new(manager, dir);
        (writer, tmp)
    }

    fn make_op(action: WriteAction, rkey: &str, value: serde_json::Value) -> WriteOp {
        WriteOp {
            action,
            collection: "app.bsky.feed.post".to_string(),
            rkey: rkey.to_string(),
            value: Some(value),
            swap_record: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_record_round_trip() {
        let (writer, _tmp) = fresh_writer().await;
        let value = serde_json::json!({"text": "hello"});
        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(WriteAction::Create, "abc", value)],
            )
            .await
            .unwrap();
        assert_eq!(result.writes.len(), 1);
        assert_eq!(
            result.writes[0].uri,
            "at://did:plc:alice/app.bsky.feed.post/abc"
        );
        assert_eq!(result.writes[0].op.action, RepoOpAction::Create);
        assert!(!result.commit_cid.is_empty());
        assert!(!result.rev.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_then_update_then_delete() {
        let (writer, _tmp) = fresh_writer().await;
        let r1 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k1",
                    serde_json::json!({"v": 1}),
                )],
            )
            .await
            .unwrap();
        let cid_v1 = r1.writes[0].cid.clone().unwrap();

        let r2 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Update,
                    "k1",
                    serde_json::json!({"v": 2}),
                )],
            )
            .await
            .unwrap();
        assert_eq!(r2.writes[0].op.action, RepoOpAction::Update);
        assert_eq!(r2.writes[0].op.prev.as_ref().unwrap().0.to_string(), cid_v1);

        let r3 = writer
            .apply_writes(
                "did:plc:alice",
                vec![WriteOp {
                    action: WriteAction::Delete,
                    collection: "app.bsky.feed.post".to_string(),
                    rkey: "k1".to_string(),
                    value: None,
                    swap_record: None,
                }],
            )
            .await
            .unwrap();
        assert_eq!(r3.writes[0].op.action, RepoOpAction::Delete);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_create_rejected() {
        let (writer, _tmp) = fresh_writer().await;
        writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(WriteAction::Create, "k1", serde_json::json!({}))],
            )
            .await
            .unwrap();
        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(WriteAction::Create, "k1", serde_json::json!({}))],
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_missing_rejected() {
        let (writer, _tmp) = fresh_writer().await;
        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![WriteOp {
                    action: WriteAction::Delete,
                    collection: "c".to_string(),
                    rkey: "absent".to_string(),
                    value: None,
                    swap_record: None,
                }],
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_atomic_commit_emits_one_stream_event() {
        let (writer, _tmp) = fresh_writer().await;
        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![
                    make_op(WriteAction::Create, "a", serde_json::json!({"n": 1})),
                    make_op(WriteAction::Create, "b", serde_json::json!({"n": 2})),
                    make_op(WriteAction::Create, "c", serde_json::json!({"n": 3})),
                ],
            )
            .await
            .unwrap();
        assert_eq!(result.writes.len(), 3);
        // All three writes share one rev and one commit.
        let rev = &result.rev;
        let events = stream_of(_tmp.path())
            .await
            .read_after(None, None, 100)
            .await
            .unwrap();
        assert_eq!(events.len(), 1, "one batch → one #commit event");
        assert_eq!(events[0].did, "did:plc:alice");
        assert_eq!(
            events[0].seq, 1,
            "the stream numbers from 1 regardless of which repository wrote"
        );
        // The stored body is DAG-CBOR in the lexicon's `#commit` shape.
        let atproto_dasl::Ipld::Map(payload) =
            atproto_dasl::from_slice(&events[0].payload).unwrap()
        else {
            panic!("a #commit body is a map")
        };
        assert_eq!(payload["rev"], atproto_dasl::Ipld::String(rev.clone()));
        assert_eq!(
            payload["repo"],
            atproto_dasl::Ipld::String("did:plc:alice".to_string())
        );
        let atproto_dasl::Ipld::List(ops) = &payload["ops"] else {
            panic!("ops is a list")
        };
        assert_eq!(ops.len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_commit_carries_prev_and_prev_data() {
        let (writer, _tmp) = fresh_writer().await;
        let r1 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "a",
                    serde_json::json!({"n": 1}),
                )],
            )
            .await
            .unwrap();
        let r2 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "b",
                    serde_json::json!({"n": 2}),
                )],
            )
            .await
            .unwrap();
        let store = SqlActorStore::open(_tmp.path(), "did:plc:alice")
            .await
            .unwrap();
        let row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT prev_cid, prev_data_cid FROM commit_obj WHERE rev = ?")
                .bind(&r2.rev)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(row.0.as_deref(), Some(r1.commit_cid.as_str()));
        assert_eq!(row.1.as_deref(), Some(r1.data_cid.as_str()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn swap_record_mismatch_rejected() {
        let (writer, _tmp) = fresh_writer().await;
        writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k",
                    serde_json::json!({"n": 1}),
                )],
            )
            .await
            .unwrap();
        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![WriteOp {
                    action: WriteAction::Update,
                    collection: "app.bsky.feed.post".to_string(),
                    rkey: "k".to_string(),
                    value: Some(serde_json::json!({"n": 2})),
                    swap_record: Some("bafy-bogus-cid".to_string()),
                }],
            )
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    //  part 3 / — writer-through-dispatch
    //  acceptance.
    //
    //  Verifies that `RepoWriter::with_backend(...)` runs `apply_writes`
    //  end-to-end via the trait surface — `commit_obj.latest`,
    //  `open_block_storage`, and `AtomicCommitWriter::apply_atomic_commit`
    //  — and that a follow-up read through the same dispatch sees the
    //  write. Both backends covered: SQL (default) and fjall (gated on
    //  the `fjall` feature).
    // -----------------------------------------------------------------------

    async fn fresh_writer_with_backend(
        backend: Arc<crate::actor_store::PublicRealmBackend>,
    ) -> (RepoWriter, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn crate::keys::KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.clone(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let writer = RepoWriter::with_backend(manager, dir, backend);
        (writer, tmp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_sqlite_create_then_read_round_trip() {
        let tmp_data = TempDir::new().unwrap();
        let backend = Arc::new(crate::actor_store::PublicRealmBackend::sql(
            tmp_data.path().to_path_buf(),
        ));
        // The writer's data_dir must match the backend's so SqlActorStore
        // opens the same per-actor file the backend writes to.
        let key_store: Arc<dyn crate::keys::KeyStore> = Arc::new(MemoryKeyStore::new());
        let accounts_db = AccountDirectory::open(&tmp_data.path().join("accounts.sqlite"))
            .await
            .unwrap();
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            tmp_data.path().to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let writer =
            RepoWriter::with_backend(manager, tmp_data.path().to_path_buf(), backend.clone());

        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k1",
                    serde_json::json!({"text": "hello-sql-dispatch"}),
                )],
            )
            .await
            .unwrap();
        assert_eq!(result.writes.len(), 1);
        assert!(!result.commit_cid.is_empty());

        // Read back via the dispatch surface.
        let latest = backend.commit_obj.latest("did:plc:alice").await.unwrap();
        assert!(latest.is_some(), "commit should land via dispatch");
        let rec = backend
            .repo_record
            .get_by_uri("did:plc:alice", "at://did:plc:alice/app.bsky.feed.post/k1")
            .await
            .unwrap();
        assert!(rec.is_some(), "record should land via dispatch");
        let seq = stream_of(tmp_data.path()).await.latest_seq().await.unwrap();
        assert!(seq.is_some(), "#commit should land on the firehose stream");
    }

    #[cfg(feature = "fjall")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_fjall_create_then_read_round_trip() {
        use crate::actor_store::PublicRealmBackend;
        use crate::actor_store::fjall::FjallActorStore;

        let tmp_data = TempDir::new().unwrap();
        let fjall_root = tmp_data.path().join("fjall");
        std::fs::create_dir_all(&fjall_root).unwrap();
        let store = FjallActorStore::open(&fjall_root).unwrap();
        let backend = Arc::new(PublicRealmBackend::fjall(store));

        let key_store: Arc<dyn crate::keys::KeyStore> = Arc::new(MemoryKeyStore::new());
        let accounts_db = AccountDirectory::open(&tmp_data.path().join("accounts.sqlite"))
            .await
            .unwrap();
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            tmp_data.path().to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let writer =
            RepoWriter::with_backend(manager, tmp_data.path().to_path_buf(), backend.clone());

        let result = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k1",
                    serde_json::json!({"text": "hello-fjall-dispatch"}),
                )],
            )
            .await
            .expect("apply_writes through fjall dispatch should succeed");
        assert_eq!(result.writes.len(), 1);
        assert!(!result.commit_cid.is_empty());
        assert!(!result.rev.is_empty());

        // Read back via the dispatch surface — every per-trait method
        // must see what AtomicCommitWriter::apply_atomic_commit just
        // committed.
        let latest = backend
            .commit_obj
            .latest("did:plc:alice")
            .await
            .unwrap()
            .expect("fjall commit should land via dispatch");
        assert_eq!(latest.cid, result.commit_cid);
        assert_eq!(latest.rev, result.rev);
        assert_eq!(latest.data_cid, result.data_cid);

        let rec = backend
            .repo_record
            .get_by_uri("did:plc:alice", "at://did:plc:alice/app.bsky.feed.post/k1")
            .await
            .unwrap()
            .expect("fjall repo_record should land via dispatch");
        assert_eq!(rec.collection, "app.bsky.feed.post");
        assert_eq!(rec.rkey, "k1");

        // The event is on the firehose stream, not in the fjall keyspace: the
        // stream is server-global and lives in the accounts DB under every
        // storage profile.
        let events = stream_of(tmp_data.path())
            .await
            .read_after(None, None, 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].did, "did:plc:alice");
        assert_eq!(events[0].event_type, "commit");
    }

    #[cfg(feature = "fjall")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dispatch_fjall_two_commits_extend_chain() {
        use crate::actor_store::PublicRealmBackend;
        use crate::actor_store::fjall::FjallActorStore;

        let tmp_data = TempDir::new().unwrap();
        let fjall_root = tmp_data.path().join("fjall");
        std::fs::create_dir_all(&fjall_root).unwrap();
        let store = FjallActorStore::open(&fjall_root).unwrap();
        let backend = Arc::new(PublicRealmBackend::fjall(store));

        let key_store: Arc<dyn crate::keys::KeyStore> = Arc::new(MemoryKeyStore::new());
        let accounts_db = AccountDirectory::open(&tmp_data.path().join("accounts.sqlite"))
            .await
            .unwrap();
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            tmp_data.path().to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let writer =
            RepoWriter::with_backend(manager, tmp_data.path().to_path_buf(), backend.clone());

        let r1 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k1",
                    serde_json::json!({"v": 1}),
                )],
            )
            .await
            .unwrap();
        let r2 = writer
            .apply_writes(
                "did:plc:alice",
                vec![make_op(
                    WriteAction::Create,
                    "k2",
                    serde_json::json!({"v": 2}),
                )],
            )
            .await
            .unwrap();

        // Second commit must point back at the first via prev/prev_data.
        let latest = backend
            .commit_obj
            .latest("did:plc:alice")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.cid, r2.commit_cid);
        assert_eq!(
            latest.prev_cid.as_deref(),
            Some(r1.commit_cid.as_str()),
            "second commit should chain to first"
        );

        // Both records present.
        let page = backend
            .repo_record
            .list_by_collection("did:plc:alice", "app.bsky.feed.post", None, 10)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);

        // Two stream events, one per commit — and numbered by the stream even
        // though the repository lives in fjall.
        assert_eq!(
            stream_of(tmp_data.path()).await.latest_seq().await.unwrap(),
            Some(2)
        );
    }

    // Use the `fresh_writer_with_backend` helper in a smoke test to
    // exercise its lookup path (otherwise dead-code-warned).
    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_writer_with_backend_helper_smoke() {
        let tmp = TempDir::new().unwrap();
        let backend = Arc::new(crate::actor_store::PublicRealmBackend::sql(
            tmp.path().to_path_buf(),
        ));
        let _ = fresh_writer_with_backend(backend).await;
    }
}
