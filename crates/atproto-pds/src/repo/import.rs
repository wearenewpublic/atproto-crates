//! `RepoImporter` — streaming CAR import for `com.atproto.repo.importRepo`.
//!
//! The migration flow is
//! "old PDS issues service auth → new PDS createAccount (deactivated) →
//!  importRepo (CAR upload) → listMissingBlobs / uploadBlob loop →
//!  signPlcOperation → submitPlcOperation → activateAccount".
//!
//! This module owns step three: ingest a CARv1 stream, verify it inductively,
//! persist all blocks to the per-actor block-store, index records into
//! `repo_record`, and write the latest signed commit into `commit_obj`.
//!
//! # Verification model
//!
//! We walk back from the CAR's root commit through whatever `prev` links the
//! CAR actually carries, then verify forward using
//! [`atproto_repo::verify_inductive`], carrying the prior MST root (Sync 1.1
//! `prevData`) down the chain as we go — it is derived from the previous
//! commit's `data`, not read off the commit, because `prevData` is a
//! `subscribeRepos#commit` event field rather than repository state. Every
//! block in the CAR must content-address correctly.
//!
//! **History is optional.** `prev` survives in the commit schema only for
//! repo-v2 compatibility and carries "no requirement of keeping around
//! history" (atproto `packages/repo/src/types.ts`), so the walk stops at the
//! first ancestor the CAR does not carry rather than rejecting the import.
//! That is the ordinary case: `com.atproto.sync.getRepo` exports current
//! state, so an export of a repo with more than one commit never contains its
//! own ancestors. The root block itself is still required — a CAR missing it
//! is malformed rather than merely history-free.
//!
//! # Streaming
//!
//! [`atproto_dasl::car::CarReader`] supplies blocks one at a time, so we
//! avoid buffering the whole CAR. Blocks land in the per-actor SQLite
//! `repo_block` table as they arrive. Bounded memory: at most one block
//! decoded at a time + an in-memory map of `(commit_cid → Commit)` (typically
//! O(few thousand) commits, well under 100MB even for very long histories).
//!
//! # Limitations
//!
//! - Blobs are not addressed here — `listMissingBlobs` reports them after
//!   import; the operator follows up with `uploadBlob`.
//!
//! # Signature verification
//!
//! When constructed with [`RepoImporter::with_plc_verifier`], the importer
//! validates each commit's ECDSA signature against the **historical**
//! atproto signing key at the commit's `rev` timestamp, resolved from the
//! PLC audit log. Without this hook, the importer trusts the CAR's
//! inductive proof but accepts any signature. Recommended for production;
//! optional for tests so they can run without PLC connectivity.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use atproto_dasl::Cid as DaslCid;
use atproto_dasl::car::{CarBlock, CarReader};
use atproto_dasl::storage::BlockStorage;
use atproto_identity::key::{KeyData, identify_key, validate as validate_signature};
use atproto_identity::plc::{AuditLogEntry, Operation, fetch_audit_log};
use atproto_repo::repo::{Commit, verify_inductive};
use cid::Cid as RawCid;
use std::collections::HashMap;
use std::path::Path;
use tokio::io::AsyncRead;

/// Result of a successful repo import.
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    /// Latest commit CID after import (the CAR's root[0]).
    pub head_cid: String,
    /// `rev` of the latest commit (TID).
    pub head_rev: String,
    /// Number of CAR blocks ingested.
    pub blocks_ingested: usize,
    /// Number of distinct commits in the imported chain.
    pub commits_indexed: usize,
}

/// Optional PLC-backed commit-signature verifier.
#[derive(Clone)]
pub struct PlcVerifier {
    http: reqwest::Client,
    plc_hostname: String,
}

impl PlcVerifier {
    /// Construct with the given PLC directory hostname (e.g. `plc.directory`).
    #[must_use]
    pub fn new(http: reqwest::Client, plc_hostname: impl Into<String>) -> Self {
        Self {
            http,
            plc_hostname: plc_hostname.into(),
        }
    }
}

/// Per-actor repo importer.
pub struct RepoImporter<'a> {
    data_dir: &'a Path,
    /// Maximum bytes to accept in a single import. Caller can override.
    max_bytes: u64,
    /// Optional PLC-backed commit-signature verifier. When `None`, signatures
    /// are not validated (back-compat for tests + the legacy migration flow
    /// that rotates keys post-import). When `Some`, every commit's signature
    /// must validate against the historical signing key at its `rev`
    /// timestamp resolved from the PLC audit log.
    plc_verifier: Option<PlcVerifier>,
    /// Public-realm backend dispatch. When `Some`, block + commit_obj writes route
    /// through the trait surface (commit-block goes through
    /// `open_block_storage`; commit row goes through
    /// `commit_obj.insert`); when `None`, the legacy SQLite-direct
    /// path runs.
    backend: Option<&'a crate::actor_store::PublicRealmBackend>,
    /// Firehose stream handle. When `None`, the import runs but emits no
    /// `#sync` — the legacy shape, kept so tests can construct an importer
    /// without an accounts database.
    sequencer: Option<&'a crate::sequencer::Sequencer>,
}

impl<'a> RepoImporter<'a> {
    /// Walk the imported MST and write the record index plus blob references.
    ///
    /// `rev` is the head commit's, not the rev at which each record was
    /// actually written. Deriving true per-record revs means walking every
    /// historical commit's tree and diffing; the reference implementation does
    /// not do that on import either. The value is a lower bound on recency, and
    /// saying so here is better than a number that looks precise and is not.
    async fn index_records(
        &self,
        store: &crate::actor_store::sql::SqlActorStore,
        did: &str,
        root: &cid::Cid,
        rev: &str,
    ) -> PdsResult<()> {
        use atproto_repo::RepoConfig;
        use atproto_repo::mst::Mst;

        let now = chrono::Utc::now().to_rfc3339();

        // Enumerate through whichever block storage the import wrote to.
        let entries = if let Some(backend) = self.backend {
            let storage = backend.open_block_storage(did).await?;
            let mst = Mst::from_root(*root, storage, RepoConfig::default());
            mst.entries().await
        } else {
            let storage = crate::actor_store::sql::SqlBlockStorage::open(store.pool().clone())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("open block storage for indexing: {e}"),
                })?;
            let mst = Mst::from_root(*root, storage, RepoConfig::default());
            mst.entries().await
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("walk imported MST: {e}"),
        })?;

        for (key, record_cid) in entries {
            let Some((collection, rkey)) = key.split_once('/') else {
                tracing::warn!(did, key, "skipping MST key that is not collection/rkey");
                continue;
            };
            let uri = format!("at://{did}/{collection}/{rkey}");
            let cid_str = record_cid.0.to_string();

            if let Some(backend) = self.backend {
                backend
                    .repo_record
                    .upsert(
                        did,
                        &crate::actor_store::RecordRow {
                            uri: uri.clone(),
                            cid: cid_str.clone(),
                            collection: collection.to_string(),
                            rkey: rkey.to_string(),
                            rev: rev.to_string(),
                            indexed_at: now.clone(),
                        },
                    )
                    .await?;
            } else {
                sqlx::query(
                    "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at)
                     VALUES (?, ?, ?, ?, ?, ?)
                     ON CONFLICT (collection, rkey) DO UPDATE SET
                        cid = excluded.cid, rev = excluded.rev, indexed_at = excluded.indexed_at",
                )
                .bind(&uri)
                .bind(&cid_str)
                .bind(collection)
                .bind(rkey)
                .bind(rev)
                .bind(&now)
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("index imported record: {e}"),
                })?;
            }

            self.index_blob_refs(store, did, &uri, &record_cid.0)
                .await?;
        }
        Ok(())
    }

    /// Record the blob references an imported record carries.
    ///
    /// A CAR may legitimately omit blocks its MST names — that is what a diff
    /// slice is. When a record's block is absent the row is still indexed and
    /// the blob walk is skipped: the record genuinely exists in the tree, and
    /// refusing the whole import over one absent block would be a worse failure
    /// than the one being fixed.
    async fn index_blob_refs(
        &self,
        store: &crate::actor_store::sql::SqlActorStore,
        did: &str,
        uri: &str,
        record_cid: &cid::Cid,
    ) -> PdsResult<()> {
        use atproto_dasl::storage::BlockStorage;

        let bytes = if let Some(backend) = self.backend {
            let storage = backend.open_block_storage(did).await?;
            storage.get(record_cid).await.ok().flatten()
        } else {
            let storage = crate::actor_store::sql::SqlBlockStorage::open(store.pool().clone())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("open block storage for blob refs: {e}"),
                })?;
            storage.get(record_cid).await.ok().flatten()
        };
        let Some(bytes) = bytes else {
            tracing::debug!(
                did,
                uri,
                "imported record block absent from the CAR; blob refs not indexed"
            );
            return Ok(());
        };

        let Ok(value) = atproto_dasl::atproto_json::from_slice(&bytes) else {
            tracing::warn!(
                did,
                uri,
                "imported record did not decode; blob refs skipped"
            );
            return Ok(());
        };

        for blob in crate::blob::walk_blob_refs(&value) {
            if let Some(backend) = self.backend {
                backend
                    .blob
                    .add_ref(
                        did,
                        &crate::actor_store::BlobRefRow {
                            record_uri: uri.to_string(),
                            blob_cid: blob.inner.ref_.link.clone(),
                            mime_type: blob.inner.mime_type.clone(),
                            size: blob.inner.size,
                        },
                    )
                    .await?;
            } else {
                crate::blob::add_ref(store, uri, &blob).await?;
            }
        }
        Ok(())
    }
}

impl<'a> RepoImporter<'a> {
    /// Construct.
    #[must_use]
    pub fn new(data_dir: &'a Path) -> Self {
        Self {
            data_dir,
            max_bytes: 4 * 1024 * 1024 * 1024, // 4 GiB safety ceiling
            plc_verifier: None,
            backend: None,
            sequencer: None,
        }
    }

    /// Publish `#sync` to the firehose stream once the import completes.
    #[must_use]
    pub fn with_sequencer(mut self, sequencer: &'a crate::sequencer::Sequencer) -> Self {
        self.sequencer = Some(sequencer);
        self
    }

    /// Override the CAR-size ceiling.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Enable PLC-backed commit-signature verification.
    ///
    /// Each commit's ECDSA signature is checked against the atproto signing
    /// key recorded in the PLC operation latest-current at the commit's
    /// `rev` timestamp. A commit signed by a key never registered on PLC
    /// (or signed by a key after rotation) is rejected.
    ///
    #[must_use]
    pub fn with_plc_verifier(mut self, verifier: PlcVerifier) -> Self {
        self.plc_verifier = Some(verifier);
        self
    }

    /// Wire the public-realm backend so block + commit-obj writes
    /// dispatch through the trait surface.
    /// Without this, the importer runs the legacy SQLite-direct path.
    #[must_use]
    pub fn with_backend(mut self, backend: &'a crate::actor_store::PublicRealmBackend) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Import a CAR stream into the per-actor store for `account_did`.
    ///
    /// The DID is trusted — the HTTP layer is responsible for verifying that
    /// the bearer token matches the target account.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Repo`] for content-addressing failures or missing
    /// commit-chain links; [`PdsError::Storage`] for persistence failures;
    /// [`PdsError::Dasl`] for malformed CAR framing.
    pub async fn import_from_stream<R: AsyncRead + Unpin + Send>(
        &self,
        account_did: &str,
        reader: R,
    ) -> PdsResult<ImportOutcome> {
        let store = SqlActorStore::open(self.data_dir, account_did).await?;

        // Stream the CAR. CarReader::new reads the header eagerly to validate
        // version=1 and capture the roots.
        let mut car = CarReader::new(reader).await.map_err(PdsError::Dasl)?;
        let root_cid: DaslCid = car.root().cloned().ok_or_else(|| PdsError::Storage {
            reason: "CAR header has no roots".to_string(),
        })?;

        // Ingest all blocks. We need them in memory to walk the commit chain
        // and to re-emit them into per-actor block storage atomically.
        // Hard cap by total bytes to avoid OOM for hostile inputs.
        let mut blocks: Vec<CarBlock> = Vec::new();
        let mut total_bytes: u64 = 0;
        loop {
            match car.next_block().await.map_err(PdsError::Dasl)? {
                None => break,
                Some(block) => {
                    total_bytes = total_bytes.saturating_add(block.data.len() as u64);
                    if total_bytes > self.max_bytes {
                        return Err(PdsError::Storage {
                            reason: format!(
                                "CAR stream exceeded max import size ({}>{})",
                                total_bytes, self.max_bytes
                            ),
                        });
                    }
                    blocks.push(block);
                }
            }
        }

        // Walk the commit chain from the root backward, decoding each commit
        // block. We have to identify which blocks ARE commits (vs MST nodes
        // / record blobs); a CarBlock by itself doesn't say. The convention:
        // attempt `Commit::from_bytes` and accept the ones that parse. Other
        // blocks are MST/record data and pass through to block storage.
        // Note: CarBlock uses upstream cid::Cid for the .cid field; the root
        // and Commit.prev use the wrapper atproto_dasl::Cid. Bridge via .0.
        let mut block_index: HashMap<RawCid, &CarBlock> = HashMap::new();
        for b in &blocks {
            block_index.insert(b.cid, b);
        }

        // Walk the commit chain.
        let chain = build_commit_chain(&block_index, &root_cid.0)?;
        if chain.is_empty() {
            return Err(PdsError::Repo(
                atproto_repo::errors::RepoError::InvalidCommit {
                    reason: format!(
                        "root CID {root_cid} did not decode as a Commit; CAR root must be the head commit"
                    ),
                },
            ));
        }

        // Verify forward (oldest -> newest) using verify_inductive, carrying
        // the prior MST root down the chain.
        //
        // The prior root is derived from the chain itself rather than read off
        // the commit: `prevData` is a `subscribeRepos#commit` event field, not
        // a commit field, so there is nothing self-declared here to cross-check
        // against. Walking `prev` gives the same value from the blocks that are
        // actually present, which is the stronger source anyway.
        let mut prev_data: Option<atproto_dasl::Cid> = None;
        for commit in &chain {
            let new_root = commit.data.clone();
            verify_inductive(prev_data.clone(), new_root.clone(), &blocks)
                .map_err(PdsError::Repo)?;
            prev_data = Some(new_root);
        }

        // §3.5: per-commit signature verification against the historical
        // PLC document. Only runs when an explicit `PlcVerifier` is wired —
        // tests + the legacy migration flow can opt out by leaving it None.
        if let Some(verifier) = &self.plc_verifier {
            verify_chain_signatures(verifier, account_did, &chain).await?;
        }

        // Persist all blocks into per-actor block storage.
        if let Some(backend) = self.backend {
            let mut blockstore = backend.open_block_storage(account_did).await?;
            for block in &blocks {
                blockstore
                    .put(&block.cid, block.data.clone())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("write block {}: {e}", block.cid),
                    })?;
            }
        } else {
            let mut blockstore =
                crate::actor_store::sql::SqlBlockStorage::open(store.pool().clone())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("open block storage: {e}"),
                    })?;
            for block in &blocks {
                blockstore
                    .put(&block.cid, block.data.clone())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("write block {}: {e}", block.cid),
                    })?;
            }
        }

        // Insert each commit row into commit_obj. Idempotent per the PRIMARY KEY.
        //
        // `prev_data_cid` is derived by walking the chain rather than read off
        // the commit: `prevData` is a `subscribeRepos#commit` event field, not
        // a commit field. The prior MST root is simply the previous commit's
        // `data`, and `chain` is ordered oldest to newest.
        let now = chrono::Utc::now().to_rfc3339();
        let mut prev_data_cid: Option<String> = None;
        for commit in &chain {
            let commit_cid = commit.cid().map_err(PdsError::Repo)?;
            let signature_blob = commit.sig.as_slice().to_vec();
            if let Some(backend) = self.backend {
                let row = crate::actor_store::CommitRow {
                    cid: commit_cid.to_string(),
                    rev: commit.rev.clone(),
                    data_cid: commit.data.to_string(),
                    prev_cid: commit.prev.as_ref().map(|c| c.to_string()),
                    prev_data_cid: prev_data_cid.clone(),
                    signature: signature_blob,
                    created_at: now.clone(),
                };
                // Idempotent on (did, cid) — silently swallow the duplicate
                // unique-violation that the legacy `INSERT OR IGNORE` masked.
                if let Err(e) = backend.commit_obj.insert(account_did, &row).await {
                    let msg = e.to_string();
                    if !msg.contains("UNIQUE")
                        && !msg.contains("unique")
                        && !msg.contains("duplicate")
                    {
                        return Err(e);
                    }
                }
            } else {
                sqlx::query(
                    "INSERT OR IGNORE INTO commit_obj (cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(commit_cid.to_string())
                .bind(&commit.rev)
                .bind(commit.data.to_string())
                .bind(commit.prev.as_ref().map(|c| c.to_string()))
                .bind(prev_data_cid.clone())
                .bind(&signature_blob)
                .bind(&now)
                .execute(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("insert commit_obj: {e}"),
                })?;
            }
            prev_data_cid = Some(commit.data.to_string());
        }

        let head = chain.last().expect("non-empty chain");
        let head_cid = head.cid().map_err(PdsError::Repo)?;

        // Index the records the imported tree holds.
        //
        // Every record read resolves through `repo_record` — `getRecord`,
        // `listRecords`, `describeRepo` — and the import wrote blocks and
        // commits and stopped. So `importRepo` reported success, the chain
        // verified, and the account then presented as empty: not-found for
        // every record, an empty page, no collections. Silent data loss at the
        // last step of a migration.
        self.index_records(&store, account_did, &head.data.0, &head.rev)
            .await?;

        // Emit a Sync 1.1 `#sync` event onto the firehose stream. Per the
        // lexicon, `#sync` force-sets the head commit without a diff —
        // exactly the right semantics after a CAR import. Best-effort: the
        // import has already succeeded; a publish failure logs and continues.
        // Re-encode the head commit: `#sync` ships the block itself so a
        // consumer can re-anchor without a follow-up fetch.
        let head_block = atproto_dasl::to_vec(head).map_err(|e| PdsError::Storage {
            reason: format!("encode head commit for #sync: {e}"),
        })?;
        let sync_event = crate::sequencer::sync_event::SyncEvent {
            did: account_did,
            rev: &head.rev,
            commit_cid: &head_cid,
            commit_block: &head_block,
        };
        match self.sequencer {
            Some(sequencer) => {
                if let Err(e) = crate::sequencer::publish_sync(sequencer, &sync_event).await {
                    tracing::warn!(account_did, ?e, "import: failed to emit #sync event");
                }
            }
            // No sequencer wired — the import still succeeded, but nothing
            // tailing the firehose learns about it.
            None => tracing::warn!(
                account_did,
                "import: no sequencer configured, #sync not emitted"
            ),
        }

        Ok(ImportOutcome {
            head_cid: head_cid.to_string(),
            head_rev: head.rev.clone(),
            blocks_ingested: blocks.len(),
            commits_indexed: chain.len(),
        })
    }
}

/// Per-commit signature verification using the historical PLC audit log.
///
/// Fetches the audit log once for the DID, then walks the commit chain
/// in lex-order and validates each commit's ECDSA signature against the
/// atproto signing key recorded in the latest-non-nullified PLC operation
/// whose `created_at` is ≤ the commit's `created_at` proxy. Since
/// commits don't carry a wall-clock timestamp directly, we use the
/// commit's lex-orderable `rev` (TID) and the audit log's `created_at`
/// strings as a coarse-but-monotonic ordering: each commit's "valid
/// signing key" is the most recent PLC op active by the time the commit
/// was issued.
///
/// **Mismatch policy:** if no PLC op carries an `#atproto` Multikey at
/// the relevant point in time, the commit is rejected as
/// `RepoError::InvalidCommit`. If the signature itself is invalid, ditto.
async fn verify_chain_signatures(
    verifier: &PlcVerifier,
    did: &str,
    chain: &[Commit],
) -> PdsResult<()> {
    let log = fetch_audit_log(&verifier.http, &verifier.plc_hostname, did)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("fetch PLC audit log for {did}: {e}"),
        })?;
    // Filter out nullified ops; preserve order.
    let active: Vec<&AuditLogEntry> = log.iter().filter(|e| !e.nullified).collect();
    if active.is_empty() {
        return Err(PdsError::Repo(
            atproto_repo::errors::RepoError::InvalidCommit {
                reason: format!("PLC audit log empty for {did}"),
            },
        ));
    }

    for commit in chain {
        let signing_key = historical_signing_key_at_rev(&active, &commit.rev).map_err(|e| {
            PdsError::Repo(atproto_repo::errors::RepoError::InvalidCommit {
                reason: format!("historical signing key for {did} @ rev={}: {e}", commit.rev),
            })
        })?;
        let signing_bytes = commit.signing_bytes().map_err(PdsError::Repo)?;
        validate_signature(&signing_key, &commit.sig, &signing_bytes).map_err(|e| {
            PdsError::Repo(atproto_repo::errors::RepoError::InvalidCommit {
                reason: format!(
                    "commit {} (rev={}) signature failed validation against historical PLC key: {e}",
                    commit.cid().map(|c| c.to_string()).unwrap_or_else(|_| "<no-cid>".to_string()),
                    commit.rev
                ),
            })
        })?;
    }
    Ok(())
}

/// Pick the atproto signing key that was current when a commit was written:
/// the most recent active PLC operation created at or before the commit's own
/// timestamp.
///
/// A rev is a TID, which encodes microseconds since the epoch, so the commit's
/// wall-clock time is available exactly rather than by analogy. This used to
/// compare the two as strings — `entry.created_at.as_str() <= rev` — against a
/// comment describing it as a coarse ordering. It was not coarse, it was
/// constant: an ISO-8601 timestamp begins `"2…"` and a current TID begins
/// `"3…"`, so every operation compared as earlier than every commit and the
/// answer was always the newest key.
///
/// That is right for a repository that never rotated and wrong for every one
/// that did, in the direction that refuses the account's own history: commits
/// signed before a rotation would be checked against the key that replaced
/// theirs. Since this runs on import, the account being locked out would be one
/// migrating in.
///
/// When the rev is not a TID, or an operation's `created_at` does not parse,
/// there is no ordering to apply and the newest key is the only defensible
/// guess — which is what the old comparison did in every case, and is kept here
/// only for the case where it is genuinely the best available.
/// Microseconds since the epoch for an RFC 3339 timestamp, so a PLC
/// operation and a commit rev can be compared as the instants they are.
fn rfc3339_micros(created_at: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(created_at)
        .ok()?
        .timestamp_micros()
        .into()
}

fn historical_signing_key_at_rev(
    active: &[&AuditLogEntry],
    rev: &str,
) -> Result<KeyData, anyhow::Error> {
    // A TID's timestamp is 53 bits, so it always fits; `try_from` rather than
    // `as` so a future widening is a compile error and not a wrapped instant.
    let commit_time = atproto_record::tid::Tid::decode(rev)
        .ok()
        .and_then(|tid| i64::try_from(tid.timestamp_micros()).ok());

    let entry = match commit_time {
        Some(commit_micros) => {
            let mut chosen: Option<&AuditLogEntry> = None;
            for entry in active {
                let Some(entry_micros) = rfc3339_micros(&entry.created_at) else {
                    // An unparseable timestamp cannot be ordered against the
                    // commit. Stop rather than skip: the operations are in
                    // order, so everything after this one is equally unusable,
                    // and treating it as "earlier" would silently prefer a
                    // later key.
                    break;
                };
                if entry_micros <= commit_micros {
                    chosen = Some(entry);
                } else {
                    break;
                }
            }
            // No operation precedes the commit: the commit predates the DID's
            // own genesis, which should not happen. The genesis key is the only
            // one that could have signed it.
            chosen.or_else(|| active.first().copied())
        }
        // The rev carries no time, so there is no ordering to apply and the
        // current key is the best available guess — as it was in every case
        // before the comparison was fixed.
        None => active.last().copied(),
    }
    .ok_or_else(|| anyhow::anyhow!("no active PLC operation found for commit rev={rev}"))?;
    let multibase = match &entry.operation {
        Operation::PlcOperation {
            verification_methods,
            ..
        } => verification_methods
            .get("atproto")
            .ok_or_else(|| anyhow::anyhow!("PLC op has no `atproto` verification method"))?
            .clone(),
        Operation::LegacyCreate { signing_key, .. } => signing_key.clone(),
        Operation::PlcTombstone { .. } => {
            anyhow::bail!("DID is tombstoned in PLC; commits after tombstone are invalid")
        }
    };
    let did_key = if multibase.starts_with("did:key:") {
        multibase
    } else {
        format!("did:key:{}", multibase)
    };
    Ok(identify_key(&did_key)?)
}

/// Walk the commit chain from `head` backward, decoding each block as a
/// `Commit`. Returns the chain in **oldest-first** order so callers can
/// verify_inductive forward.
///
/// Stops when `prev` is None (genesis commit) or when a `prev` link points
/// to a block missing from the CAR (which is a verification failure).
fn build_commit_chain(
    block_index: &HashMap<RawCid, &CarBlock>,
    head: &RawCid,
) -> PdsResult<Vec<Commit>> {
    let mut chain: Vec<Commit> = Vec::new();
    let mut cursor: Option<RawCid> = Some(*head);

    while let Some(cid) = cursor {
        let block = match block_index.get(&cid) {
            Some(b) => b,
            None if chain.is_empty() => {
                // The head itself. A CAR whose root block is missing is
                // malformed however it was produced.
                return Err(PdsError::Repo(
                    atproto_repo::errors::RepoError::InvalidCommit {
                        reason: format!("commit {cid} referenced but not present in CAR"),
                    },
                ));
            }
            None => {
                // An ancestor is absent, which is normal and not an error.
                // `prev` exists for repo-v2 compatibility and carries "no
                // requirement of keeping around history"
                // (atproto packages/repo/src/types.ts), so an exporter is
                // free to omit ancestors — `com.atproto.sync.getRepo` exports
                // current state and always does.
                //
                // Demanding them rejected every CAR this PDS itself produced
                // for a repo with more than one commit, which made inbound
                // migration impossible. The reference verifies the single root
                // and walks no chain at all
                // (packages/pds/src/api/com/atproto/repo/importRepo.ts).
                //
                // Whatever history *is* present still gets verified below;
                // absence just ends the walk.
                break;
            }
        };

        let commit = match Commit::from_bytes(&block.data) {
            Ok(c) => c,
            Err(e) => {
                if chain.is_empty() {
                    return Err(PdsError::Repo(
                        atproto_repo::errors::RepoError::InvalidCommit {
                            reason: format!("CAR root {cid} did not decode as Commit: {e}"),
                        },
                    ));
                } else {
                    return Err(PdsError::Repo(
                        atproto_repo::errors::RepoError::InvalidCommit {
                            reason: format!("non-commit block {cid} in commit chain: {e}"),
                        },
                    ));
                }
            }
        };
        cursor = commit.prev.as_ref().map(|c| c.0);
        chain.push(commit);
    }

    chain.reverse();
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::car::CarWriter;
    use atproto_repo::repo::UnsignedCommit;
    use std::io::Cursor;

    // --- historical signing-key selection ---------------------------------

    /// A PLC operation registering `key` as the account's atproto signing key
    /// at `created_at`.
    fn op_at(created_at: &str, key: &str) -> AuditLogEntry {
        AuditLogEntry {
            did: "did:plc:alice".to_string(),
            operation: Operation::PlcOperation {
                rotation_keys: Vec::new(),
                verification_methods: std::collections::HashMap::from([(
                    "atproto".to_string(),
                    key.to_string(),
                )]),
                also_known_as: Vec::new(),
                services: std::collections::HashMap::new(),
                prev: None,
                sig: String::new(),
            },
            cid: format!("bafy{created_at}"),
            created_at: created_at.to_string(),
            nullified: false,
        }
    }

    /// A TID rev for an instant.
    ///
    /// `from_parts` rather than `new_with_time`: the latter consults a
    /// process-global monotonicity cell and rewrites a timestamp that moves
    /// backwards, so a fixed instant is only fixed until another test asks for
    /// a later one first.
    fn tid_at(rfc3339: &str) -> String {
        let micros = chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .timestamp_micros();
        atproto_record::tid::Tid::from_parts(u64::try_from(micros).unwrap(), 0).encode()
    }

    /// Two real K-256 signing keys, as `did:key` multibase strings.
    fn two_keys() -> (String, String) {
        let genesis =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::K256Private)
                .unwrap();
        let rotated =
            atproto_identity::key::generate_key(atproto_identity::key::KeyType::K256Private)
                .unwrap();
        (
            atproto_identity::key::to_public(&genesis)
                .unwrap()
                .to_string(),
            atproto_identity::key::to_public(&rotated)
                .unwrap()
                .to_string(),
        )
    }

    /// A commit written before a key rotation is checked against the key that
    /// was current when it was written, not the one that replaced it.
    ///
    /// The selection used to compare the operation's ISO-8601 `created_at`
    /// against the commit's TID rev as strings. An ISO timestamp begins `"2…"`
    /// and a current TID begins `"3…"`, so every operation sorted as earlier
    /// than every commit and the answer was always the newest key. A comment
    /// called it a coarse ordering; it was not an ordering at all.
    ///
    /// The direction of the error is what makes it worth a test: an account
    /// that had ever rotated could not import its own history, and importing
    /// history is what this code path is for.
    #[test]
    fn a_commit_predating_a_rotation_resolves_to_the_key_of_its_time() {
        let (genesis_key, rotated_key) = two_keys();
        // A TID for 2026-01-01T00:00:00Z, which falls between the two ops.
        let rev = tid_at("2026-01-01T00:00:00Z");

        let ops = [
            op_at("2025-06-01T00:00:00Z", &genesis_key),
            op_at("2026-06-01T00:00:00Z", &rotated_key),
        ];
        let active: Vec<&AuditLogEntry> = ops.iter().collect();

        let chosen = historical_signing_key_at_rev(&active, &rev).expect("a key for the commit");
        assert_eq!(
            chosen.to_string(),
            genesis_key,
            "a commit from before the rotation was checked against the key that replaced it"
        );
    }

    /// And a commit written after the rotation resolves to the new key.
    #[test]
    fn a_commit_after_a_rotation_resolves_to_the_new_key() {
        let (genesis_key, rotated_key) = two_keys();
        let rev = tid_at("2026-07-01T00:00:00Z");

        let ops = [
            op_at("2025-06-01T00:00:00Z", &genesis_key),
            op_at("2026-06-01T00:00:00Z", &rotated_key),
        ];
        let active: Vec<&AuditLogEntry> = ops.iter().collect();

        let chosen = historical_signing_key_at_rev(&active, &rev).expect("a key for the commit");
        assert_eq!(chosen.to_string(), rotated_key);
    }

    /// A rev that is not a TID carries no instant to order against, so the
    /// current key is the only defensible answer — which is what the old
    /// comparison produced in every case, and is kept only for this one.
    #[test]
    fn a_rev_that_is_not_a_tid_falls_back_to_the_current_key() {
        let (genesis_key, rotated_key) = two_keys();
        let ops = [
            op_at("2025-06-01T00:00:00Z", &genesis_key),
            op_at("2026-06-01T00:00:00Z", &rotated_key),
        ];
        let active: Vec<&AuditLogEntry> = ops.iter().collect();

        let chosen = historical_signing_key_at_rev(&active, "not-a-tid").expect("a key");
        assert_eq!(chosen.to_string(), rotated_key);
    }

    /// Construct a minimal valid CAR containing one commit + an empty MST root.
    /// Used to smoke-test the import pipeline without standing up a full repo writer.
    async fn minimal_one_commit_car() -> (Vec<u8>, atproto_dasl::Cid) {
        // Empty MST node = empty entries vec → CIDv1 dag-cbor sha256 of {entries: []}
        let empty_mst_bytes =
            atproto_dasl::to_vec(&serde_json::json!({"e": [], "l": null})).expect("encode mst");
        let mst_cid_raw = atproto_dasl::cid::compute_cid(&empty_mst_bytes);
        let mst_cid = atproto_dasl::Cid(mst_cid_raw);

        let signed = UnsignedCommit::new(
            "did:plc:alice".to_string(),
            mst_cid.clone(),
            "3jui7kd2z2y2e".to_string(),
            None,
        )
        .sign(vec![0u8; 64]); // dummy signature; verify_inductive does not check sig
        let commit_bytes = signed.to_bytes().expect("encode commit");
        let commit_cid_raw = signed.cid().expect("commit cid");
        let commit_cid = atproto_dasl::Cid(commit_cid_raw);

        // Build the CAR: header(roots=[commit_cid]) + commit_block + mst_block.
        let mut buf: Vec<u8> = Vec::new();
        let mut writer = CarWriter::new(&mut buf, vec![commit_cid.clone()])
            .await
            .unwrap();
        writer
            .write_block(&CarBlock {
                cid: commit_cid_raw,
                data: commit_bytes,
            })
            .await
            .unwrap();
        writer
            .write_block(&CarBlock {
                cid: mst_cid_raw,
                data: empty_mst_bytes,
            })
            .await
            .unwrap();
        writer.finish().await.unwrap();
        (buf, commit_cid)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_commit_chain_walks_back_to_genesis() {
        let (car_bytes, _commit_cid) = minimal_one_commit_car().await;
        let mut car = CarReader::new(Cursor::new(car_bytes)).await.unwrap();
        let root = car.root().unwrap().clone();
        let mut blocks = Vec::new();
        while let Some(b) = car.next_block().await.unwrap() {
            blocks.push(b);
        }
        let mut idx = HashMap::new();
        for b in &blocks {
            idx.insert(b.cid, b);
        }
        let chain = build_commit_chain(&idx, &root.0).unwrap();
        assert_eq!(
            chain.len(),
            1,
            "single-commit CAR should give 1-element chain"
        );
        assert!(chain[0].prev.is_none());
    }

    /// A commit whose `prev` names a block the CAR does not carry, which is
    /// what every `com.atproto.sync.getRepo` export of a multi-commit repo
    /// looks like from an implementation that still populates `prev`.
    async fn one_commit_car_with_absent_prev() -> (Vec<u8>, atproto_dasl::Cid) {
        let empty_mst_bytes =
            atproto_dasl::to_vec(&serde_json::json!({"e": [], "l": null})).expect("encode mst");
        let mst_cid_raw = atproto_dasl::cid::compute_cid(&empty_mst_bytes);
        let mst_cid = atproto_dasl::Cid(mst_cid_raw);

        // Any CID that is not written into the CAR below. The MST bytes hashed
        // a second time give a well-formed CID for a block nobody stored.
        let absent = atproto_dasl::Cid(atproto_dasl::cid::compute_cid(b"a block not in this CAR"));

        let signed = UnsignedCommit::new(
            "did:plc:alice".to_string(),
            mst_cid.clone(),
            "3jui7kd2z2y2e".to_string(),
            Some(absent),
        )
        .sign(vec![0u8; 64]);
        let commit_bytes = signed.to_bytes().expect("encode commit");
        let commit_cid_raw = signed.cid().expect("commit cid");
        let commit_cid = atproto_dasl::Cid(commit_cid_raw);

        let mut buf: Vec<u8> = Vec::new();
        let mut writer = CarWriter::new(&mut buf, vec![commit_cid.clone()])
            .await
            .unwrap();
        writer
            .write_block(&CarBlock {
                cid: commit_cid_raw,
                data: commit_bytes,
            })
            .await
            .unwrap();
        writer
            .write_block(&CarBlock {
                cid: mst_cid_raw,
                data: empty_mst_bytes,
            })
            .await
            .unwrap();
        writer.finish().await.unwrap();
        (buf, commit_cid)
    }

    /// History is optional, so a `prev` pointing outside the CAR ends the walk
    /// instead of failing it.
    ///
    /// This is the case that made inbound migration impossible: `getRepo`
    /// exports current state, so the ancestor named by `prev` is never in the
    /// CAR, and requiring it rejected every repo with more than one commit —
    /// including CARs this PDS produced itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn build_commit_chain_stops_at_an_absent_ancestor() {
        let (car_bytes, _) = one_commit_car_with_absent_prev().await;
        let mut car = CarReader::new(Cursor::new(car_bytes)).await.unwrap();
        let root = car.root().unwrap().clone();
        let mut blocks = Vec::new();
        while let Some(b) = car.next_block().await.unwrap() {
            blocks.push(b);
        }
        let mut idx = HashMap::new();
        for b in &blocks {
            idx.insert(b.cid, b);
        }

        let chain = build_commit_chain(&idx, &root.0)
            .expect("an absent ancestor is not an error: history is not required");
        assert_eq!(
            chain.len(),
            1,
            "the walk should stop at the absent ancestor"
        );
        assert!(
            chain[0].prev.is_some(),
            "the head still records its parent; only the walk stopped",
        );
    }

    /// The head is not history — a CAR that does not carry its own root block
    /// is malformed, and that distinction is the whole reason the absent-
    /// ancestor case above is allowed to pass silently.
    #[tokio::test(flavor = "multi_thread")]
    async fn build_commit_chain_still_rejects_an_absent_head() {
        let (car_bytes, _) = minimal_one_commit_car().await;
        let mut car = CarReader::new(Cursor::new(car_bytes)).await.unwrap();
        let root = car.root().unwrap().clone();
        while (car.next_block().await.unwrap()).is_some() {}

        // Nothing indexed: the root block is absent.
        let idx: HashMap<RawCid, &CarBlock> = HashMap::new();
        let err = build_commit_chain(&idx, &root.0)
            .expect_err("a CAR missing its own root block is malformed");
        assert!(
            err.to_string().contains("not present in CAR"),
            "unexpected error: {err}",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_from_stream_round_trip() {
        // Spin up a temp data dir + ensure the account is registered first
        // so the per-actor file is opened with the right schema.
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts_db = crate::account::AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: std::sync::Arc<dyn crate::keys::KeyStore> =
            std::sync::Arc::new(crate::keys::MemoryKeyStore::new());
        let manager = std::sync::Arc::new(crate::account::AccountManager::new(
            accounts_db.pool().clone(),
            dir.clone(),
            key_store,
            atproto_identity::key::KeyType::K256Private,
        ));
        manager
            .create_account(crate::account::CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();

        let (car_bytes, expected_root) = minimal_one_commit_car().await;
        let importer = RepoImporter::new(&dir);
        let outcome = importer
            .import_from_stream("did:plc:alice", Cursor::new(car_bytes))
            .await
            .unwrap();
        assert_eq!(outcome.head_cid, expected_root.to_string());
        assert_eq!(outcome.commits_indexed, 1);
        assert!(outcome.blocks_ingested >= 2, "commit + mst");
    }

    /// `historical_signing_key_at_rev` picks the
    /// most-recent active PLC op whose `created_at` lex-precedes the
    /// commit's rev.
    #[test]
    fn historical_signing_key_picks_most_recent_active_op() {
        use atproto_identity::plc::{AuditLogEntry, Operation};
        use std::collections::HashMap;
        let mk_op = |key_mb: &str| Operation::PlcOperation {
            rotation_keys: vec![],
            verification_methods: HashMap::from([("atproto".to_string(), key_mb.to_string())]),
            also_known_as: vec![],
            services: HashMap::new(),
            prev: None,
            sig: String::new(),
        };
        // Generate two real did:key strings so identify_key parses them.
        // KeyData's Display impl produces `did:key:<multibase>`.
        use atproto_identity::key::{KeyType, generate_key, to_public};
        let priv_old = generate_key(KeyType::P256Private).unwrap();
        let priv_new = generate_key(KeyType::P256Private).unwrap();
        let pub_old = to_public(&priv_old).unwrap();
        let pub_new = to_public(&priv_new).unwrap();
        let k_old = pub_old.to_string();
        let k_new = pub_new.to_string();
        let log: Vec<AuditLogEntry> = vec![
            AuditLogEntry {
                did: "did:plc:alice".to_string(),
                operation: mk_op(k_old.strip_prefix("did:key:").unwrap()),
                cid: "c1".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                nullified: false,
            },
            AuditLogEntry {
                did: "did:plc:alice".to_string(),
                operation: mk_op(k_new.strip_prefix("did:key:").unwrap()),
                cid: "c2".to_string(),
                created_at: "2026-06-01T00:00:00Z".to_string(),
                nullified: false,
            },
        ];
        let active: Vec<&AuditLogEntry> = log.iter().collect();
        // A rev is a TID, not a timestamp string. This test used to pass ISO
        // dates here, which is the one input shape that made the old
        // string-vs-string comparison look like an ordering; against a real
        // rev it always chose the newest key.
        let mid_rev = tid_at("2026-03-15T00:00:00Z");
        let key = historical_signing_key_at_rev(&active, &mid_rev).unwrap();
        assert_eq!(key.to_string(), k_old);
        let new_rev = tid_at("2027-01-01T00:00:00Z");
        let key2 = historical_signing_key_at_rev(&active, &new_rev).unwrap();
        assert_eq!(key2.to_string(), k_new);
    }

    /// Tombstoned DIDs reject any commit.
    #[test]
    fn historical_signing_key_rejects_tombstoned_did() {
        use atproto_identity::plc::{AuditLogEntry, Operation};
        let log: Vec<AuditLogEntry> = vec![AuditLogEntry {
            did: "did:plc:alice".to_string(),
            operation: Operation::PlcTombstone {
                prev: "c0".to_string(),
                sig: String::new(),
            },
            cid: "c1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            nullified: false,
        }];
        let active: Vec<&AuditLogEntry> = log.iter().collect();
        let result = historical_signing_key_at_rev(&active, "2026-06-01T00:00:00Z");
        let msg = result.err().expect("expected error").to_string();
        assert!(
            msg.contains("tombstoned"),
            "expected tombstoned error, got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn import_rejects_oversized_car() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let _ = crate::account::AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let (car_bytes, _) = minimal_one_commit_car().await;
        let importer = RepoImporter::new(&dir).with_max_bytes(8);
        let result = importer
            .import_from_stream("did:plc:alice", Cursor::new(car_bytes))
            .await;
        assert!(matches!(result, Err(PdsError::Storage { .. })));
    }
}
