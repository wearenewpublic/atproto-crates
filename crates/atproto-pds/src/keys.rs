//! `KeyStore` trait and built-in `FileKeyStore` impl.
//!
//! per-account
//! signing-key bytes never live in the SQL `signing_key` table. The row holds
//! only a `key_ref` (e.g., `file:abc123`, `kms:projects/foo/keyRings/...`)
//! that the configured `KeyStore` resolves to actual key material at sign-time.
//!
//! The default [`FileKeyStore`] writes one file per key under
//! `<data_dir>/keys/<key_ref>` with mode `0600`. HSM and KMS backends are
//! pluggable: implement [`KeyStore`] and pass it where applicable.

use crate::errors::{PdsError, PdsResult};
use async_trait::async_trait;
use atproto_identity::key::{KeyData, KeyType};
use std::path::PathBuf;

/// Pluggable key store for per-account signing keys (and the PDS rotation key).
///
/// Implementations are expected to encrypt at rest in some way appropriate to
/// their backend (e.g., filesystem ACLs for `FileKeyStore`, HSM/KMS for
/// `HsmKeyStore`).
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Persist a key, returning the opaque `key_ref` to store in the
    /// account-DB row.
    async fn put(&self, key_data: &KeyData) -> PdsResult<String>;

    /// Retrieve a key by `key_ref`.
    async fn get(&self, key_ref: &str) -> PdsResult<KeyData>;

    /// Delete a key by `key_ref`. Idempotent — missing keys do not error.
    async fn delete(&self, key_ref: &str) -> PdsResult<()>;
}

/// File-based `KeyStore` — writes one file per key under `<root>/`.
///
/// Filenames are hex-encoded SHA-256 of the public key form, prefixed `file:`
/// in the returned `key_ref`. The file format is the multibase-encoded
/// did:key string of the *private* key (round-trips through
/// `atproto_identity::key::generate_key`).
pub struct FileKeyStore {
    root: PathBuf,
}

impl FileKeyStore {
    /// Construct rooted at `root` (typically `<data_dir>/keys/`). The directory
    /// is created on first `put`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, key_ref: &str) -> PathBuf {
        // `key_ref` format: `file:<filename>`. We strip the prefix and append
        // ".key" to keep the on-disk surface predictable.
        let bare = key_ref.strip_prefix("file:").unwrap_or(key_ref);
        self.root.join(format!("{bare}.key"))
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn put(&self, key_data: &KeyData) -> PdsResult<String> {
        // Derive a stable filename from the key's public form so two `put`s
        // of the same key are idempotent.
        let public = atproto_identity::key::to_public(key_data).map_err(|e| PdsError::Storage {
            reason: format!("derive public key: {e}"),
        })?;
        let public_did_key = public.to_string();
        let mut hasher = sha2::Sha256::new_with_prefix(public_did_key.as_bytes());
        use sha2::Digest;
        let digest = hasher.finalize_reset();
        let filename = hex::encode(&digest[..16]);
        let key_ref = format!("file:{filename}");

        // Write the private key in the canonical did:key form.
        let private_did_key = key_data.to_string();
        let path = self.path_for(&key_ref);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("create_dir_all({}): {e}", parent.display()),
                })?;
        }
        write_key_durably(&path, private_did_key.as_bytes()).await?;
        Ok(key_ref)
    }

    async fn get(&self, key_ref: &str) -> PdsResult<KeyData> {
        let path = self.path_for(key_ref);
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| PdsError::NotFound {
                what: format!("key_ref {key_ref}: {e}"),
            })?;
        let did_key = String::from_utf8(bytes).map_err(|e| PdsError::Storage {
            reason: format!("invalid utf8 in key file: {e}"),
        })?;
        atproto_identity::key::identify_key(did_key.trim()).map_err(|e| PdsError::Storage {
            reason: format!("parse did:key: {e}"),
        })
    }

    async fn delete(&self, key_ref: &str) -> PdsResult<()> {
        let path = self.path_for(key_ref);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PdsError::Storage {
                reason: format!("remove({}): {e}", path.display()),
            }),
        }
    }
}

/// Write a private key so that returning `Ok` means the bytes are on the
/// device, and so that a crash leaves either the whole old file or the whole
/// new one.
///
/// A bare `fs::write` gave neither. It truncates the target in place and
/// returns once the bytes reach the page cache, so a power loss seconds later
/// leaves a file that is empty or half-written while the account row naming it
/// is already durable -- the accounts DB is WAL with `synchronous=FULL`, so it
/// is the *more* durable of the two by a wide margin, and it is the one holding
/// the reference rather than the secret.
///
/// What that costs is not a retry. Every write for the account fails at the
/// signing-key lookup from then on, and if the DID was published to PLC before
/// the loss, the `verificationMethods.atproto` key is one nobody holds -- and
/// the rotation key needed to replace it went the same way, in the same
/// directory, in the same instant. There is no recovery from that; the identity
/// is gone. Of everything this server stores, these bytes are the only ones
/// that cannot be rebuilt from somewhere else.
///
/// So: a temp file in the same directory, `sync_all` before the rename, the
/// rename itself (atomic on POSIX), then `sync_all` on the directory so the
/// rename is durable and not merely the contents. The mode is set by
/// `OpenOptions` rather than a `chmod` afterwards, which also closes the window
/// where a private key sat on disk under the process umask.
async fn write_key_durably(path: &std::path::Path, bytes: &[u8]) -> PdsResult<()> {
    use rand::RngExt as _;
    use tokio::io::AsyncWriteExt;

    let parent = path.parent().ok_or_else(|| PdsError::Storage {
        reason: format!("key path has no parent directory: {}", path.display()),
    })?;

    // A unique temp name per call: `put` is idempotent by key, so two callers
    // persisting the same key derive the same final path, and a shared temp
    // name would let them interleave into one torn file.
    let mut suffix = [0u8; 8];
    rand::rng().fill(&mut suffix);
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("key"),
        hex::encode(suffix)
    ));

    let result = async {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        // `tokio::fs::OpenOptions` exposes `mode` directly on unix.
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts.open(&tmp).await.map_err(|e| PdsError::Storage {
            reason: format!("create({}): {e}", tmp.display()),
        })?;
        file.write_all(bytes).await.map_err(|e| PdsError::Storage {
            reason: format!("write({}): {e}", tmp.display()),
        })?;
        // Before the rename, not after: a rename that lands ahead of the
        // contents publishes an empty file under the name that matters.
        file.sync_all().await.map_err(|e| PdsError::Storage {
            reason: format!("fsync({}): {e}", tmp.display()),
        })?;
        drop(file);

        tokio::fs::rename(&tmp, path)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("rename({} -> {}): {e}", tmp.display(), path.display()),
            })
    }
    .await;

    if result.is_err() {
        // Leaving the temp behind would accumulate unreadable key material in
        // the keys directory on every failure.
        let _ = tokio::fs::remove_file(&tmp).await;
        return result;
    }

    // The directory entry the rename created is itself buffered. Without this
    // the file's contents are durable and the name pointing at them is not.
    #[cfg(unix)]
    {
        let dir = tokio::fs::File::open(parent)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("open dir({}): {e}", parent.display()),
            })?;
        dir.sync_all().await.map_err(|e| PdsError::Storage {
            reason: format!("fsync dir({}): {e}", parent.display()),
        })?;
    }

    Ok(())
}

/// In-memory `KeyStore` for testing.
#[derive(Default)]
pub struct MemoryKeyStore {
    inner: tokio::sync::Mutex<std::collections::HashMap<String, KeyData>>,
}

impl MemoryKeyStore {
    /// Construct empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn put(&self, key_data: &KeyData) -> PdsResult<String> {
        let public = atproto_identity::key::to_public(key_data).map_err(|e| PdsError::Storage {
            reason: format!("derive public key: {e}"),
        })?;
        let key_ref = format!("memory:{}", public);
        self.inner
            .lock()
            .await
            .insert(key_ref.clone(), key_data.clone());
        Ok(key_ref)
    }

    async fn get(&self, key_ref: &str) -> PdsResult<KeyData> {
        self.inner
            .lock()
            .await
            .get(key_ref)
            .cloned()
            .ok_or_else(|| PdsError::NotFound {
                what: format!("key_ref {key_ref}"),
            })
    }

    async fn delete(&self, key_ref: &str) -> PdsResult<()> {
        self.inner.lock().await.remove(key_ref);
        Ok(())
    }
}

/// Generate a fresh per-account signing key.
///
/// Defaults to K-256 (matching the AT Protocol PLC default). Pass an explicit
/// `KeyType` if a P-256 signing key is desired.
///
/// # Errors
///
/// Forwards key-generation failures from `atproto_identity`.
pub fn generate_account_signing_key(key_type: KeyType) -> PdsResult<KeyData> {
    atproto_identity::key::generate_key(key_type).map_err(|e| PdsError::Storage {
        reason: format!("generate signing key: {e}"),
    })
}

/// Parse a `key_type` string from config (case-insensitive).
///
/// Recognized values: `k256private`, `k256public`, `p256private`, `p256public`,
/// `p384private`, `p384public`, `ed25519private`, `ed25519public`.
pub fn parse_key_type(s: &str) -> PdsResult<KeyType> {
    match s.to_ascii_lowercase().as_str() {
        "k256private" => Ok(KeyType::K256Private),
        "k256public" => Ok(KeyType::K256Public),
        "p256private" => Ok(KeyType::P256Private),
        "p256public" => Ok(KeyType::P256Public),
        "p384private" => Ok(KeyType::P384Private),
        "p384public" => Ok(KeyType::P384Public),
        "ed25519private" => Ok(KeyType::Ed25519Private),
        "ed25519public" => Ok(KeyType::Ed25519Public),
        _ => Err(PdsError::Storage {
            reason: format!("unknown key type: {s}"),
        }),
    }
}

/// Reuse the PDS-level signing key across restarts, or generate and persist a
/// fresh P-256 key on first boot. Never panics; any error is returned. Used to
/// populate the `pds_signing_key` slot on `HttpState` so `/oauth/jwks`
/// publishes a stable federation key.
///
/// The reference is recorded in `pds_setting`, which is the whole of the fix
/// this function once needed. It used to call `key_store().get("__pds_oauth__")`
/// -- but `put` never accepted a label. It content-addresses the key and
/// returns an opaque ref, so `__pds_oauth__` named nothing, the lookup missed
/// on every boot, and each restart generated a replacement key, published it
/// as the PDS's federation key, and left the previous one orphaned on disk.
/// Every account key already persists its ref in `account.signing_key_ref`;
/// this was the one key in the system with nowhere to write it down.
pub async fn load_or_create_pds_signing_key(
    manager: &crate::account::AccountManager,
) -> PdsResult<atproto_identity::key::KeyData> {
    use crate::account::setting::{PDS_SIGNING_KEY_REF, get_setting, put_setting};
    use atproto_identity::key::{KeyType, generate_key};

    let pool = manager.account_pool();
    if let Some(key_ref) = get_setting(&pool, PDS_SIGNING_KEY_REF).await? {
        match manager.key_store().get(&key_ref).await {
            Ok(existing) => {
                tracing::info!(key_ref, "PDS signing key loaded from KeyStore");
                return Ok(existing);
            }
            // The ref is recorded but the key is gone -- a restored database
            // without its keys directory, or a hand-pruned one. Minting a
            // replacement is the only way to serve, but it silently changes
            // the published federation key, so say so at a level that gets
            // read.
            Err(e) => {
                tracing::warn!(
                    key_ref,
                    error = ?e,
                    "PDS signing key reference is recorded but the key is missing; \
                     generating a replacement and republishing /oauth/jwks"
                );
            }
        }
    }

    let key = generate_key(KeyType::P256Private).map_err(|e| PdsError::Storage {
        reason: format!("generate PDS signing key: {e}"),
    })?;
    let key_ref = manager.key_store().put(&key).await?;
    put_setting(&pool, PDS_SIGNING_KEY_REF, &key_ref).await?;
    tracing::info!(key_ref, "PDS signing key generated + persisted");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::KeyType;
    use tempfile::TempDir;

    /// Boot the key loader against a directory and database that persist
    /// across calls -- a restart, with process state gone and only what was
    /// written down surviving.
    async fn boot(dir: &std::path::Path) -> atproto_identity::key::KeyData {
        use crate::account::{AccountDirectory, AccountManager};
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let store: std::sync::Arc<dyn KeyStore> =
            std::sync::Arc::new(FileKeyStore::new(dir.join("keys")));
        let manager = AccountManager::new(
            accounts.pool().clone(),
            dir.to_path_buf(),
            store,
            KeyType::K256Private,
        );
        load_or_create_pds_signing_key(&manager).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_pds_signing_key_survives_a_restart() {
        let tmp = TempDir::new().unwrap();

        let first = boot(tmp.path()).await;
        let second = boot(tmp.path()).await;

        assert_eq!(
            first.to_string(),
            second.to_string(),
            "a restart minted a new PDS signing key, so /oauth/jwks published a \
             different federation key than the one before it"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_recorded_key_that_has_gone_missing_is_replaced() {
        let tmp = TempDir::new().unwrap();
        let first = boot(tmp.path()).await;

        // A database restored without its keys directory. The ref is on record
        // and resolves to nothing.
        tokio::fs::remove_dir_all(tmp.path().join("keys"))
            .await
            .unwrap();

        let second = boot(tmp.path()).await;
        assert_ne!(
            first.to_string(),
            second.to_string(),
            "the key was gone, so a replacement was the only way to serve"
        );

        // And the replacement is itself durable, rather than the server
        // falling back into minting one per boot.
        let third = boot(tmp.path()).await;
        assert_eq!(second.to_string(), third.to_string());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_keystore_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = FileKeyStore::new(tmp.path().join("keys"));
        let key = generate_account_signing_key(KeyType::K256Private).unwrap();
        let key_ref = store.put(&key).await.unwrap();
        assert!(key_ref.starts_with("file:"));
        let loaded = store.get(&key_ref).await.unwrap();
        assert_eq!(loaded.to_string(), key.to_string());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_keystore_idempotent_put() {
        let tmp = TempDir::new().unwrap();
        let store = FileKeyStore::new(tmp.path().join("keys"));
        let key = generate_account_signing_key(KeyType::P256Private).unwrap();
        let r1 = store.put(&key).await.unwrap();
        let r2 = store.put(&key).await.unwrap();
        assert_eq!(r1, r2, "same key → same key_ref");
    }

    /// A key file is private from the moment it exists.
    ///
    /// The mode used to be applied by a `chmod` after the write, so the private
    /// key was on disk under the process umask first. `OpenOptions::mode` is
    /// what makes the permission a property of the file rather than of a later
    /// call that might not run.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_key_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("keys");
        let store = FileKeyStore::new(root.clone());
        let key = generate_account_signing_key(KeyType::K256Private).unwrap();
        let key_ref = store.put(&key).await.unwrap();

        let path = root.join(format!("{}.key", key_ref.strip_prefix("file:").unwrap()));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode is {mode:o}");
    }

    /// The rename is the publish step, so nothing else may be left in the
    /// directory that the key store would later read as a key.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_durable_write_leaves_no_temporary_behind() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("keys");
        let store = FileKeyStore::new(root.clone());
        for _ in 0..3 {
            let key = generate_account_signing_key(KeyType::K256Private).unwrap();
            store.put(&key).await.unwrap();
        }

        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp") || name.starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporaries left behind: {leftovers:?}"
        );
    }

    /// Rewriting an existing key replaces it, since the rename lands on a path
    /// that is already there. Re-persisting the same key is the ordinary case:
    /// `put` is idempotent by design and callers rely on it.
    #[tokio::test(flavor = "multi_thread")]
    async fn re_persisting_a_key_overwrites_it_intact() {
        let tmp = TempDir::new().unwrap();
        let store = FileKeyStore::new(tmp.path().join("keys"));
        let key = generate_account_signing_key(KeyType::P256Private).unwrap();

        let first = store.put(&key).await.unwrap();
        let second = store.put(&key).await.unwrap();
        assert_eq!(first, second);

        let loaded = store.get(&second).await.unwrap();
        assert_eq!(
            loaded.to_string(),
            key.to_string(),
            "the second write left the key unreadable"
        );
    }

    /// Two writers persisting the same key concurrently both succeed and the
    /// file is whole. With one shared temp name they would interleave into it.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_puts_of_one_key_do_not_tear_the_file() {
        let tmp = TempDir::new().unwrap();
        let store = std::sync::Arc::new(FileKeyStore::new(tmp.path().join("keys")));
        let key = generate_account_signing_key(KeyType::K256Private).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let key = key.clone();
            handles.push(tokio::spawn(async move { store.put(&key).await }));
        }
        let mut key_ref = None;
        for handle in handles {
            key_ref = Some(
                handle
                    .await
                    .unwrap()
                    .expect("a concurrent put should succeed"),
            );
        }

        let loaded = store.get(&key_ref.unwrap()).await.unwrap();
        assert_eq!(loaded.to_string(), key.to_string());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_keystore_get_missing_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let store = FileKeyStore::new(tmp.path().join("keys"));
        let result = store.get("file:absent").await;
        assert!(matches!(result, Err(PdsError::NotFound { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_keystore_delete_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = FileKeyStore::new(tmp.path().join("keys"));
        let key = generate_account_signing_key(KeyType::K256Private).unwrap();
        let key_ref = store.put(&key).await.unwrap();
        store.delete(&key_ref).await.unwrap();
        // second delete is fine
        store.delete(&key_ref).await.unwrap();
        assert!(matches!(
            store.get(&key_ref).await,
            Err(PdsError::NotFound { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn memory_keystore_round_trip() {
        let store = MemoryKeyStore::new();
        let key = generate_account_signing_key(KeyType::K256Private).unwrap();
        let key_ref = store.put(&key).await.unwrap();
        let loaded = store.get(&key_ref).await.unwrap();
        assert_eq!(loaded.to_string(), key.to_string());
    }

    #[test]
    fn parse_key_type_known_values() {
        assert!(parse_key_type("k256private").is_ok());
        assert!(parse_key_type("bogus").is_err());
    }
}
