//! `FjallBlockStorage` — `BlockStorage` impl over a fjall `repo_block`
//! partition.
//!
//! Mirrors `crate::actor_store::sql::SqlBlockStorage` semantics: store
//! DAG-CBOR-encoded MST nodes + record bytes addressed by their CIDs,
//! served out of the partition's per-(did, cid) namespace.
//!
//! The fjall layer doesn't enforce DID isolation by partition — one
//! partition holds all actors. Each row's key is `<did>\0<cid_str>`
//! (per `keyspace::repo_block_key`), which gives prefix-scannable
//! per-DID ranges so `cids()` and `clear()` stay scoped.

use super::keyspace::{FjallActorStore, repo_block_key, repo_block_prefix};
use atproto_dasl::StorageError;
use atproto_dasl::storage::BlockStorage;
use cid::Cid;
use fjall::Keyspace;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Fjall-backed `BlockStorage` for one DID's slice of the shared
/// `repo_block` partition.
pub struct FjallBlockStorage {
    keyspace: Keyspace,
    did: String,
    block_count: Arc<AtomicUsize>,
    memory_usage: Arc<AtomicUsize>,
}

impl FjallBlockStorage {
    /// Open a storage view over `did`'s slice of the shared `repo_block`
    /// partition. Block + memory counters are seeded by scanning the
    /// existing prefix; subsequent mutations keep them in sync.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` on fjall failure.
    pub fn open(store: &FjallActorStore, did: impl Into<String>) -> Result<Self, StorageError> {
        let did = did.into();
        let keyspace = store.repo_block().clone();
        let prefix = repo_block_prefix(&did);
        let mut count = 0usize;
        let mut bytes = 0usize;
        for kv in keyspace.prefix(&prefix) {
            let (_k, v) = kv.into_inner().map_err(fjall_io("seed scan"))?;
            count += 1;
            bytes += v.len();
        }
        Ok(Self {
            keyspace,
            did,
            block_count: Arc::new(AtomicUsize::new(count)),
            memory_usage: Arc::new(AtomicUsize::new(bytes)),
        })
    }
}

fn fjall_io(what: &'static str) -> impl FnOnce(fjall::Error) -> StorageError {
    move |e| StorageError::Io(std::io::Error::other(format!("fjall {what}: {e}")))
}

impl BlockStorage for FjallBlockStorage {
    async fn put(&mut self, cid: &Cid, data: Vec<u8>) -> Result<(), StorageError> {
        let key = repo_block_key(&self.did, &cid.to_string());
        // INSERT OR IGNORE semantics: skip if already present so the count
        // memory_usage tallies remain accurate under retries.
        if self
            .keyspace
            .contains_key(&key)
            .map_err(fjall_io("contains"))?
        {
            return Ok(());
        }
        let len = data.len();
        self.keyspace.insert(&key, data).map_err(fjall_io("put"))?;
        self.block_count.fetch_add(1, Ordering::Relaxed);
        self.memory_usage.fetch_add(len, Ordering::Relaxed);
        Ok(())
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let key = repo_block_key(&self.did, &cid.to_string());
        let value = self.keyspace.get(&key).map_err(fjall_io("get"))?;
        Ok(value.map(|slice| slice.to_vec()))
    }

    async fn contains(&self, cid: &Cid) -> Result<bool, StorageError> {
        let key = repo_block_key(&self.did, &cid.to_string());
        self.keyspace
            .contains_key(&key)
            .map_err(fjall_io("contains"))
    }

    async fn remove(&mut self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let existing = self.get(cid).await?;
        if let Some(ref data) = existing {
            let key = repo_block_key(&self.did, &cid.to_string());
            self.keyspace.remove(&key).map_err(fjall_io("remove"))?;
            self.block_count.fetch_sub(1, Ordering::Relaxed);
            self.memory_usage.fetch_sub(data.len(), Ordering::Relaxed);
        }
        Ok(existing)
    }

    fn memory_usage(&self) -> usize {
        self.memory_usage.load(Ordering::Relaxed)
    }

    fn block_count(&self) -> usize {
        self.block_count.load(Ordering::Relaxed)
    }

    fn cids(&self) -> Box<dyn Iterator<Item = Cid> + '_> {
        let prefix = repo_block_prefix(&self.did);
        let did_len = self.did.len() + 1; // +1 for the null separator
        let cids: Vec<Cid> = self
            .keyspace
            .prefix(&prefix)
            .filter_map(|kv| kv.into_inner().ok())
            .filter_map(|(k, _v)| {
                let bytes: &[u8] = k.as_ref();
                if bytes.len() <= did_len {
                    return None;
                }
                let cid_bytes = &bytes[did_len..];
                std::str::from_utf8(cid_bytes)
                    .ok()
                    .and_then(|s| Cid::from_str(s).ok())
            })
            .collect();
        Box::new(cids.into_iter())
    }

    async fn clear(&mut self) -> Result<(), StorageError> {
        let prefix = repo_block_prefix(&self.did);
        let keys: Vec<Vec<u8>> = self
            .keyspace
            .prefix(&prefix)
            .filter_map(|kv| kv.into_inner().ok())
            .map(|(k, _v)| k.to_vec())
            .collect();
        for k in keys {
            self.keyspace.remove(&k).map_err(fjall_io("clear remove"))?;
        }
        self.block_count.store(0, Ordering::Relaxed);
        self.memory_usage.store(0, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::cid::compute_cid;
    use tempfile::TempDir;

    fn fresh_storage() -> (TempDir, FjallActorStore, FjallBlockStorage) {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        let bs = FjallBlockStorage::open(&store, "did:plc:test").unwrap();
        (tmp, store, bs)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_get_roundtrip() {
        let (_tmp, _store, mut bs) = fresh_storage();
        let data = b"hello".to_vec();
        let cid = compute_cid(&data);
        bs.put(&cid, data.clone()).await.unwrap();
        assert_eq!(
            bs.get(&cid).await.unwrap().as_deref(),
            Some(data.as_slice())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_block_is_none() {
        let (_tmp, _store, bs) = fresh_storage();
        let cid = compute_cid(b"absent");
        assert!(bs.get(&cid).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_is_idempotent() {
        let (_tmp, _store, mut bs) = fresh_storage();
        let data = b"twice".to_vec();
        let cid = compute_cid(&data);
        bs.put(&cid, data.clone()).await.unwrap();
        bs.put(&cid, data.clone()).await.unwrap();
        assert_eq!(bs.block_count(), 1);
        assert_eq!(bs.memory_usage(), data.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn contains_and_remove() {
        let (_tmp, _store, mut bs) = fresh_storage();
        let data = b"x".to_vec();
        let cid = compute_cid(&data);
        assert!(!bs.contains(&cid).await.unwrap());
        bs.put(&cid, data.clone()).await.unwrap();
        assert!(bs.contains(&cid).await.unwrap());
        let removed = bs.remove(&cid).await.unwrap();
        assert_eq!(removed, Some(data));
        assert!(!bs.contains(&cid).await.unwrap());
        assert_eq!(bs.block_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_empties() {
        let (_tmp, _store, mut bs) = fresh_storage();
        for s in ["a", "b", "c"] {
            let data = s.as_bytes().to_vec();
            let cid = compute_cid(&data);
            bs.put(&cid, data).await.unwrap();
        }
        assert_eq!(bs.block_count(), 3);
        bs.clear().await.unwrap();
        assert_eq!(bs.block_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cids_iterates_inserted() {
        let (_tmp, _store, mut bs) = fresh_storage();
        let mut expected = Vec::new();
        for s in ["a", "b", "c"] {
            let data = s.as_bytes().to_vec();
            let cid = compute_cid(&data);
            expected.push(cid);
            bs.put(&cid, data).await.unwrap();
        }
        let mut got: Vec<_> = bs.cids().collect();
        got.sort();
        expected.sort();
        assert_eq!(got, expected);
    }

    /// Two DIDs sharing one fjall partition must not see each other's
    /// blocks. This is the per-DID prefix-scan invariant; if it broke,
    /// `cids()` would return another DID's blocks.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_dids_are_isolated() {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        let mut a = FjallBlockStorage::open(&store, "did:plc:alice").unwrap();
        let mut b = FjallBlockStorage::open(&store, "did:plc:bob").unwrap();

        let alice_data = b"alice-block".to_vec();
        let alice_cid = compute_cid(&alice_data);
        a.put(&alice_cid, alice_data.clone()).await.unwrap();

        let bob_data = b"bob-block".to_vec();
        let bob_cid = compute_cid(&bob_data);
        b.put(&bob_cid, bob_data.clone()).await.unwrap();

        // Each side sees only its own blocks.
        assert!(a.contains(&alice_cid).await.unwrap());
        assert!(!a.contains(&bob_cid).await.unwrap());
        assert!(b.contains(&bob_cid).await.unwrap());
        assert!(!b.contains(&alice_cid).await.unwrap());
        assert_eq!(a.block_count(), 1);
        assert_eq!(b.block_count(), 1);

        let alice_cids: Vec<_> = a.cids().collect();
        let bob_cids: Vec<_> = b.cids().collect();
        assert_eq!(alice_cids, vec![alice_cid]);
        assert_eq!(bob_cids, vec![bob_cid]);
    }

    /// Reopening a storage view across `FjallActorStore::open` calls must
    /// recover the on-disk block count + memory tally.
    #[tokio::test(flavor = "multi_thread")]
    async fn counters_recover_after_reopen() {
        let tmp = TempDir::new().unwrap();
        {
            let store = FjallActorStore::open(tmp.path()).unwrap();
            let mut bs = FjallBlockStorage::open(&store, "did:plc:test").unwrap();
            for s in ["a", "bb", "ccc"] {
                let data = s.as_bytes().to_vec();
                let cid = compute_cid(&data);
                bs.put(&cid, data).await.unwrap();
            }
            store.persist().unwrap();
        }
        let store = FjallActorStore::open(tmp.path()).unwrap();
        let bs = FjallBlockStorage::open(&store, "did:plc:test").unwrap();
        assert_eq!(bs.block_count(), 3);
        assert_eq!(bs.memory_usage(), 1 + 2 + 3);
    }
}
