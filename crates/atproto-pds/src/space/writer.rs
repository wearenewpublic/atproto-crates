//! `SpaceWriter` — permissioned-record CRUD via per-(DID, space) lock.
//!
//! each write batch
//! holds a per-(member-DID, space-URI) async mutex, computes a new SetHash,
//! signs the commit (HKDF + HMAC + ECDSA via `atproto-space::create_commit`),
//! and atomically persists changes + oplog. **/ G35**, the
//! PDS does not enforce membership at write time; consumers check at sync.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::notify::{NotifyWritePayload, enqueue_writes, op_to_notify};
use atproto_record::tid::Tid;
use atproto_space::commit::{CommitScope, SpaceContext, create_commit};
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
    /// Per-op AT-URIs (`ats://` form).
    pub uris: Vec<String>,
}

type WriteLocks = Arc<DashMap<(String, String), Arc<Mutex<()>>>>;

/// Permissioned-record writer.
pub struct SpaceWriter {
    data_dir: PathBuf,
    accounts: Arc<crate::account::AccountManager>,
    locks: WriteLocks,
}

impl SpaceWriter {
    /// Construct.
    pub fn new(accounts: Arc<crate::account::AccountManager>, data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            accounts,
            locks: Arc::new(DashMap::new()),
        }
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

        let store = SqlActorStore::open(&self.data_dir, member_did).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);

        // Translate ops + auto-generate TIDs for empty rkeys on Create.
        let mut translated = Vec::with_capacity(ops.len());
        let mut output_uris = Vec::with_capacity(ops.len());
        for op in ops {
            let rkey = if matches!(op.action, SpaceWriteAction::Create) && op.rkey.is_empty() {
                Tid::new().to_string()
            } else {
                op.rkey.clone()
            };
            output_uris.push(format!(
                "ats://{}/{}/{}/{}/{}",
                space.owner_did, space.space_type, space.space_key, op.collection, rkey
            ));
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
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: member_did.to_string(),
            scope: CommitScope::Records,
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

        // Sign the commit. We keep the result here because the signed Commit
        // is broadcast via `notifyWrite` to subscribed consumers (peers don't
        // see our durable storage, so they need the signed commit + ops to
        // apply on their side).
        let signed_commit =
            create_commit(&prepared.set_hash, &context, &signing_key).map_err(space_err)?;

        repo.apply_commit(prepared).await.map_err(space_err)?;

        // Fan out a `notifyWrite` to every registered recipient. Failures
        // here are logged but non-fatal — the commit is durable; redelivery
        // of stale missed notifications is a sync-side problem, not a write
        // failure. (The owner's catch-up oplog at `getRepoOplog` is the
        // authoritative source.)
        let payload = NotifyWritePayload {
            space: space.to_string(),
            member: member_did.to_string(),
            commit: signed_commit,
            ops: translated.iter().map(op_to_notify).collect(),
        };
        if let Err(e) = enqueue_writes(self.accounts.pool(), &self.data_dir, space, &payload).await
        {
            tracing::warn!(
                error = ?e,
                space = %space,
                member = %member_did,
                "notifyWrite enqueue failed; recipients may miss this commit until next catch-up sync"
            );
        }

        Ok(SpaceCommitResult {
            rev,
            set_hash: set_hash_hex,
            uris: output_uris,
        })
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
        assert!(result.uris[0].starts_with("ats://did:plc:owner/app.bsky.group/default/"));
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
}
