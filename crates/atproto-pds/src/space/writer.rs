//! `SpaceWriter` — permissioned-record CRUD via per-(DID, space) lock.
//!
//! Each write batch holds a per-(member-DID, space-URI) async mutex, computes a
//! new SetHash, signs the commit (HKDF + HMAC + ECDSA via
//! `atproto-space::create_commit`), and atomically persists changes + oplog. The
//! PDS does not enforce membership at write time; consumers check at sync.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::config::ensure_space_live;
use crate::space::notify::{NOTIFY_WRITE_NSID, NotifyWritePayload};
use crate::space::service_auth::{NOTIFY_SERVICE_AUTH_TTL_SECS, mint_service_auth};
use atproto_identity::key::KeyData;
use atproto_record::tid::Tid;
use atproto_space::commit::{SpaceContext, create_commit};
use atproto_space::space_repo::{Op, OpAction, SpaceRepo};
use atproto_space::types::SpaceUri;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Action variants for a `SpaceWriteOp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceWriteAction {
    /// Create.
    Create,
    /// Upsert.
    Update,
    /// Delete.
    Delete,
}

/// One write inside a permissioned-batch.
#[derive(Debug, Clone)]
pub struct SpaceWriteOp {
    /// Action.
    pub action: SpaceWriteAction,
    /// NSID collection.
    pub collection: String,
    /// Record key (TID auto-generated when empty + Create).
    pub rkey: String,
    /// Record value (None for Delete).
    pub value: Option<serde_json::Value>,
}

/// Result of a successful permissioned commit.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceCommitResult {
    /// Rev (TID) for this commit.
    pub rev: String,
    /// New SetHash (hex-encoded). Serialized as `setHash`.
    pub set_hash: String,
    /// Per-op AT-URIs (`at://…/space/…` form).
    pub uris: Vec<String>,
    /// Per-op record CIDs, parallel to `uris`. `None` for delete ops.
    pub cids: Vec<Option<String>>,
}

type WriteLocks = Arc<DashMap<(String, String), Arc<Mutex<()>>>>;

/// Permissioned-record writer.
pub struct SpaceWriter {
    data_dir: PathBuf,
    accounts: Arc<crate::account::AccountManager>,
    locks: WriteLocks,
    /// PLC directory hostname for resolving the owner PDS endpoint on the
    /// outbound `notifyWrite` hop. `None` uses the upstream default.
    plc_directory: Option<String>,
}

/// Build the `notifyWrite` body a repo host sends to a space host.
///
/// Extracted so the payload can be tested without a network hop: the send path
/// resolves the owner's `#atproto_pds` endpoint from their DID document, which
/// a test harness has no way to provide.
///
/// `hash` is the commit hash after the write. The lexicon requires it and says
/// why — *"Lets the space host maintain each repo's hash for listRepos"* —
/// which is the loop that lets a syncer see which repos actually changed.
#[must_use]
pub fn build_notify_payload(
    space: &SpaceUri,
    writer_did: &str,
    rev: &str,
    commit_hash: &[u8],
) -> NotifyWritePayload {
    NotifyWritePayload {
        space: space.to_string(),
        repo: writer_did.to_string(),
        rev: rev.to_string(),
        hash: Some(crate::space::lex_bytes::BytesValue(commit_hash.to_vec())),
    }
}

impl SpaceWriter {
    /// Construct.
    pub fn new(accounts: Arc<crate::account::AccountManager>, data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            accounts,
            locks: Arc::new(DashMap::new()),
            plc_directory: None,
        }
    }

    /// Set the PLC directory hostname used to resolve the owner PDS endpoint
    /// for the outbound `notifyWrite` hop (HOP 1, writer PDS → owner PDS).
    #[must_use]
    pub fn with_plc_directory(mut self, plc_directory: Option<String>) -> Self {
        self.plc_directory = plc_directory;
        self
    }

    fn lock_for(&self, did: &str, uri: &SpaceUri) -> Arc<Mutex<()>> {
        self.locks
            .entry((did.to_string(), uri.to_string()))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Apply a batch of writes against the user's permissioned repo for
    /// `space`. Holds the per-(member, space) lock for the duration.
    pub async fn apply_writes(
        &self,
        member_did: &str,
        space: &SpaceUri,
        ops: Vec<SpaceWriteOp>,
    ) -> PdsResult<SpaceCommitResult> {
        if ops.is_empty() {
            return Err(PdsError::Storage {
                reason: "applyWrites called with empty ops".to_string(),
            });
        }

        let lock = self.lock_for(member_did, space);
        let _guard = lock.lock().await;

        ensure_space_live(&self.data_dir, space).await?;
        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);

        self.apply_writes_locked(member_did, space, &repo, ops)
            .await
    }

    /// `createRecord` — single-op `Create`. Errors if the record already
    /// exists. An empty `rkey` auto-generates a TID.
    pub async fn create_record(
        &self,
        member_did: &str,
        space: &SpaceUri,
        collection: String,
        rkey: String,
        value: serde_json::Value,
    ) -> PdsResult<SpaceCommitResult> {
        self.apply_writes(
            member_did,
            space,
            vec![SpaceWriteOp {
                action: SpaceWriteAction::Create,
                collection,
                rkey,
                value: Some(value),
            }],
        )
        .await
    }

    /// `putRecord` — single-op create-or-update. Resolves to `Update` when
    /// a record already exists at `(collection, rkey)`, else `Create`. The
    /// existence check runs under the per-(member, space) lock so the chosen
    /// action cannot race a concurrent write.
    pub async fn put_record(
        &self,
        member_did: &str,
        space: &SpaceUri,
        collection: String,
        rkey: String,
        value: serde_json::Value,
    ) -> PdsResult<SpaceCommitResult> {
        let lock = self.lock_for(member_did, space);
        let _guard = lock.lock().await;

        ensure_space_live(&self.data_dir, space).await?;
        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);

        let exists = repo
            .get_record(&collection, &rkey)
            .await
            .map_err(space_err)?
            .is_some();
        let action = if exists {
            SpaceWriteAction::Update
        } else {
            SpaceWriteAction::Create
        };
        self.apply_writes_locked(
            member_did,
            space,
            &repo,
            vec![SpaceWriteOp {
                action,
                collection,
                rkey,
                value: Some(value),
            }],
        )
        .await
    }

    /// `deleteRecord` — single-op delete that is idempotent: when no record
    /// exists at `(collection, rkey)` it is a no-op returning the current
    /// `{rev, set_hash}` rather than erroring. The existence check runs under
    /// the per-(member, space) lock.
    pub async fn delete_record(
        &self,
        member_did: &str,
        space: &SpaceUri,
        collection: String,
        rkey: String,
    ) -> PdsResult<SpaceCommitResult> {
        let lock = self.lock_for(member_did, space);
        let _guard = lock.lock().await;

        ensure_space_live(&self.data_dir, space).await?;
        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);

        let exists = repo
            .get_record(&collection, &rkey)
            .await
            .map_err(space_err)?
            .is_some();
        if !exists {
            // Idempotent no-op: report current state without a new commit.
            let state = repo.current_state().await.map_err(space_err)?;
            let uri = atproto_space::RecordUri::new(
                space.clone(),
                member_did.to_string(),
                collection.to_string(),
                rkey.to_string(),
            )
            .to_string();
            return Ok(SpaceCommitResult {
                rev: state.rev.unwrap_or_default(),
                set_hash: state.set_hash.map(hex::encode).unwrap_or_default(),
                uris: vec![uri],
                cids: vec![None],
            });
        }
        self.apply_writes_locked(
            member_did,
            space,
            &repo,
            vec![SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection,
                rkey,
                value: None,
            }],
        )
        .await
    }

    /// Commit a batch of writes against an already-opened `repo`, with the
    /// per-(member, space) lock already held by the caller. Shared by
    /// `apply_writes` and the single-op `createRecord` / `putRecord` /
    /// `deleteRecord` wrappers.
    async fn apply_writes_locked(
        &self,
        member_did: &str,
        space: &SpaceUri,
        repo: &SpaceRepo<SqlSpaceRepoStorage, PdsSetHash>,
        ops: Vec<SpaceWriteOp>,
    ) -> PdsResult<SpaceCommitResult> {
        // Translate ops + auto-generate TIDs for empty rkeys on Create.
        let mut translated = Vec::with_capacity(ops.len());
        let mut output_uris = Vec::with_capacity(ops.len());
        let mut output_cids = Vec::with_capacity(ops.len());
        // `(record_uri, value)` per op, for blob-ref maintenance after the
        // commit is durable. `None` for a delete — the refs still get dropped,
        // there is just nothing to re-add.
        let mut ref_work: Vec<(String, Option<serde_json::Value>)> = Vec::with_capacity(ops.len());
        for op in ops {
            let rkey = if matches!(op.action, SpaceWriteAction::Create) && op.rkey.is_empty() {
                Tid::new().to_string()
            } else {
                op.rkey.clone()
            };
            // Permissioned record URI, including the author DID:
            // at://<spaceDid>/space/<spaceType>/<skey>/<authorDid>/<collection>/<rkey>.
            // The author segment is required — records are not colocated, so two
            // members writing the same (collection, rkey) must not collide.
            //
            // Built through `RecordUri` rather than a format string so the
            // scheme and marker live in one place; the two hand-rolled copies
            // this replaces were the reason the format change had to be found
            // by grep.
            let record_uri = atproto_space::RecordUri::new(
                space.clone(),
                member_did.to_string(),
                op.collection.clone(),
                rkey.clone(),
            )
            .to_string();
            ref_work.push((record_uri.clone(), op.value.clone()));
            output_uris.push(record_uri);
            // Compute the value's CID (from DAG-CBOR) for create/update.
            let (cid, value_bytes) = match op.action {
                SpaceWriteAction::Create | SpaceWriteAction::Update => {
                    let value = op.value.clone().ok_or_else(|| PdsError::Storage {
                        reason: format!("{:?} requires value", op.action),
                    })?;
                    let bytes = atproto_dasl::to_vec(&value).map_err(|e| PdsError::Storage {
                        reason: format!("encode value: {e}"),
                    })?;
                    let cid = atproto_dasl::cid::compute_cid(&bytes);
                    (Some(cid.to_string()), Some(bytes))
                }
                SpaceWriteAction::Delete => (None, None),
            };
            output_cids.push(cid.clone());
            translated.push(Op {
                action: match op.action {
                    SpaceWriteAction::Create => OpAction::Create,
                    SpaceWriteAction::Update => OpAction::Update,
                    SpaceWriteAction::Delete => OpAction::Delete,
                },
                collection: op.collection,
                rkey,
                cid,
                value: value_bytes,
            });
        }

        let prepared = repo.format_commit(&translated).await.map_err(space_err)?;
        let rev = prepared.rev.clone();
        let set_hash_hex = hex::encode(&prepared.storage_commit.new_set_hash);
        let context = SpaceContext {
            space: space.to_string(),
            author: member_did.to_string(),
            rev: rev.clone(),
        };

        // Resolve the user's signing key via KeyStore for the commit.
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(member_did)
                .fetch_optional(self.accounts.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {member_did} has no signing_key_ref"),
            })?
            .0;
        let signing_key = self.accounts.key_store().get(&key_ref).await?;

        // Sign the commit so the repo's signed state is persisted. The ops
        // themselves are not broadcast — consumers PULL them via
        // `listRepoOps` — but the commit's `hash` travels on `notifyWrite`, so
        // the space host can maintain each repo's hash for `listRepos`. This
        // commit used to be built and discarded.
        let signed_commit =
            create_commit(&prepared.set_hash, &context, &signing_key).map_err(space_err)?;
        let commit_hash = signed_commit.hash.clone();

        repo.apply_commit(prepared).await.map_err(space_err)?;

        // HOP 1 (writer PDS → owner PDS): announce that this repo advanced to
        // `rev`. Contentless payload `{ space, repo, rev }`, service-auth
        // signed by the writer's key. Best-effort: failures are logged but
        // never fail the (already-durable) write. The owner-side inbound
        // handler does the isMember check + fans out to registered recipients.
        // Record which blobs this space now references. Without it,
        // `space.getBlob` has no way to tell whether a CID belongs to the space
        // it was asked about, and the public `sync.getBlob` cannot tell a
        // permissioned blob from a public one.
        self.maintain_blob_refs(space, member_did, &rev, &ref_work)
            .await;

        self.fire_notify_write(space, member_did, &rev, &commit_hash, &signing_key)
            .await;

        Ok(SpaceCommitResult {
            rev,
            set_hash: set_hash_hex,
            uris: output_uris,
            cids: output_cids,
        })
    }

    /// Maintain `space_blob_ref` for a committed batch.
    ///
    /// Reuses the public realm's [`walk_blob_refs`](crate::blob::walk_blob_refs)
    /// walker, which recurses to arbitrary depth and validates the whole
    /// `{$type: "blob", ref: {$link}, mimeType, size}` envelope — a walker
    /// taught individual lexicons would silently miss every lexicon it had not
    /// been taught, which for permissioned data means a blob that quietly
    /// stays publicly readable.
    ///
    /// Every op drops its existing references first, including deletes. Adding
    /// without dropping would leave a blob readable in a space after the last
    /// record naming it stopped naming it, and nothing would visibly break.
    ///
    /// Best-effort, like `notifyWrite`: the commit is already durable, so
    /// failing here would report a written record as unwritten. Failures log at
    /// ERROR because the consequence — a blob readable in a space it no longer
    /// belongs to, or unreadable in one it does — is invisible to the caller.
    async fn maintain_blob_refs(
        &self,
        space: &SpaceUri,
        member_did: &str,
        rev: &str,
        work: &[(String, Option<serde_json::Value>)],
    ) {
        let store =
            match crate::actor_store::sql::SqlActorStore::open(&self.data_dir, member_did).await {
                Ok(s) => s,
                Err(error) => {
                    tracing::error!(error = ?error, did = %member_did, space = %space,
                    "space blob refs not maintained: cannot open actor store");
                    return;
                }
            };
        for (record_uri, value) in work {
            if let Err(error) = crate::space::blob_ref::drop_record_refs(&store, record_uri).await {
                tracing::error!(error = ?error, uri = %record_uri,
                    "space blob refs not dropped for record");
                continue;
            }
            let Some(value) = value else { continue };
            for blob in crate::blob::walk_blob_refs(value) {
                if let Err(error) = crate::space::blob_ref::add_ref(
                    &store,
                    &space.to_string(),
                    record_uri,
                    &blob.inner.ref_.link,
                    rev,
                )
                .await
                {
                    tracing::error!(error = ?error, uri = %record_uri,
                        "space blob ref not recorded");
                }
            }
        }
    }

    /// HOP 1 of the reference two-hop notify path: the writer's PDS POSTs a
    /// contentless `notifyWrite` `{ space, repo, rev }` to the OWNER's PDS,
    /// authenticated with service auth (iss = writer DID, aud = owner DID).
    ///
    /// Resolution: owner DID (`space.space_did`) → DID document →
    /// `#atproto_pds` service endpoint. Entirely best-effort — every failure
    /// path is logged and swallowed so a write never fails on a missed
    /// notification (the owner's `listRepoOps` is the authoritative catch-up
    /// source).
    async fn fire_notify_write(
        &self,
        space: &SpaceUri,
        writer_did: &str,
        rev: &str,
        commit_hash: &[u8],
        writer_signing_key: &KeyData,
    ) {
        let owner_did = space.space_did.clone();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(crate::user_agent())
            .build()
            .unwrap_or_default();

        // Resolve the owner's PDS endpoint from their DID document.
        let owner_pds = match crate::space::recipient::resolve_service_endpoint(
            &http,
            &format!("{owner_did}#atproto_pds"),
            self.plc_directory.as_deref(),
        )
        .await
        {
            Ok(Some(ep)) => ep,
            Ok(None) => {
                tracing::debug!(
                    space = %space,
                    owner = %owner_did,
                    "notifyWrite: owner DID document has no #atproto_pds service; skipping fan-out hop"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    space = %space,
                    owner = %owner_did,
                    "notifyWrite: failed to resolve owner PDS endpoint; skipping fan-out hop"
                );
                return;
            }
        };

        let token = match mint_service_auth(
            writer_signing_key,
            writer_did,
            &owner_did,
            NOTIFY_WRITE_NSID,
            NOTIFY_SERVICE_AUTH_TTL_SECS,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    space = %space,
                    "notifyWrite: failed to mint service-auth token; skipping fan-out hop"
                );
                return;
            }
        };

        let payload = build_notify_payload(space, writer_did, rev, commit_hash);
        let url = format!(
            "{}/xrpc/{}",
            owner_pds.trim_end_matches('/'),
            NOTIFY_WRITE_NSID
        );
        match http
            .post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(space = %space, owner = %owner_did, rev = %rev, "notifyWrite delivered to owner PDS");
            }
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    space = %space,
                    owner = %owner_did,
                    "notifyWrite: owner PDS rejected the notification (best-effort, ignored)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    space = %space,
                    owner = %owner_did,
                    "notifyWrite: transport error delivering to owner PDS (best-effort, ignored)"
                );
            }
        }
    }
}

fn space_err(err: atproto_space::SpaceError) -> PdsError {
    PdsError::Space(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use atproto_identity::key::KeyType;
    use atproto_space::types::{SpaceKey, SpaceType};
    use tempfile::TempDir;

    async fn fresh_writer() -> (SpaceWriter, TempDir, SpaceUri) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
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
        let writer = SpaceWriter::new(manager, dir);
        let uri = SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        );
        (writer, tmp, uri)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_record_in_space() {
        let (w, _tmp, uri) = fresh_writer().await;
        let result = w
            .apply_writes(
                "did:plc:alice",
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
        assert!(result.uris[0].starts_with("at://did:plc:owner/space/app.bsky.group/default/"));
        assert!(!result.set_hash.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_then_update_then_delete() {
        let (w, _tmp, uri) = fresh_writer().await;
        w.apply_writes(
            "did:plc:alice",
            &uri,
            vec![SpaceWriteOp {
                action: SpaceWriteAction::Create,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                value: Some(serde_json::json!({"v": 1})),
            }],
        )
        .await
        .unwrap();
        w.apply_writes(
            "did:plc:alice",
            &uri,
            vec![SpaceWriteOp {
                action: SpaceWriteAction::Update,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                value: Some(serde_json::json!({"v": 2})),
            }],
        )
        .await
        .unwrap();
        w.apply_writes(
            "did:plc:alice",
            &uri,
            vec![SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                value: None,
            }],
        )
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_batch_rejected() {
        let (w, _tmp, uri) = fresh_writer().await;
        let result = w.apply_writes("did:plc:alice", &uri, vec![]).await;
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn auto_tid_rkey_on_create() {
        let (w, _tmp, uri) = fresh_writer().await;
        let result = w
            .apply_writes(
                "did:plc:alice",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "c".to_string(),
                    rkey: String::new(),
                    value: Some(serde_json::json!({})),
                }],
            )
            .await
            .unwrap();
        let last_seg = result.uris[0].split('/').next_back().unwrap();
        assert_eq!(last_seg.len(), 13, "TID rkey is 13 chars");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_record_returns_uri_and_cid() {
        let (w, _tmp, uri) = fresh_writer().await;
        let result = w
            .create_record(
                "did:plc:alice",
                &uri,
                "c".to_string(),
                "k".to_string(),
                serde_json::json!({"v": 1}),
            )
            .await
            .unwrap();
        assert_eq!(result.uris.len(), 1);
        assert!(result.uris[0].ends_with("/c/k"));
        assert!(result.cids[0].is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_record_creates_then_updates() {
        let (w, _tmp, uri) = fresh_writer().await;
        // First put creates.
        let first = w
            .put_record(
                "did:plc:alice",
                &uri,
                "c".to_string(),
                "k".to_string(),
                serde_json::json!({"v": 1}),
            )
            .await
            .unwrap();
        // Second put updates the same rkey (does not error on existing).
        let second = w
            .put_record(
                "did:plc:alice",
                &uri,
                "c".to_string(),
                "k".to_string(),
                serde_json::json!({"v": 2}),
            )
            .await
            .unwrap();
        assert_eq!(first.uris[0], second.uris[0]);
        assert_ne!(first.cids[0], second.cids[0], "value changed → new CID");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_record_is_idempotent() {
        let (w, _tmp, uri) = fresh_writer().await;
        // Delete on a non-existent record is a no-op (does not error).
        let absent = w
            .delete_record("did:plc:alice", &uri, "c".to_string(), "k".to_string())
            .await
            .unwrap();
        assert!(absent.cids[0].is_none());

        // Create then delete succeeds.
        w.create_record(
            "did:plc:alice",
            &uri,
            "c".to_string(),
            "k".to_string(),
            serde_json::json!({"v": 1}),
        )
        .await
        .unwrap();
        w.delete_record("did:plc:alice", &uri, "c".to_string(), "k".to_string())
            .await
            .unwrap();
    }
}
