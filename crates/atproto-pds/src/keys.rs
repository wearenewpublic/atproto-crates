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
        tokio::fs::write(&path, private_did_key.as_bytes())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("write({}): {e}", path.display()),
            })?;
        // Apply 0600 mode on Unix; Windows keeps default ACLs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&path, perms)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("chmod 0600({}): {e}", path.display()),
                })?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::KeyType;
    use tempfile::TempDir;

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
