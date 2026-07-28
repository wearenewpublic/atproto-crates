//! CAR streaming export — `com.atproto.sync.getRepo` and friends.
//!
//! Walks the per-actor blockstore from the latest commit, packing all
//! reachable blocks into a CAR v1 stream (root[0] = current commit CID).
//! Two shapes:
//!
//! - [`export_repo_car`] — full repo export (root + all reachable blocks).
//! - [`export_repo_car_since`] — diff slice from a `since` rev (REMAINING-
//!   WORK §7.3): only blocks reachable from `head` that aren't already in
//!   `since`'s reachable set are included.

use crate::actor_store::PublicRealmBackend;
use crate::actor_store::sql::{SqlActorStore, SqlBlockStorage};
use crate::errors::{PdsError, PdsResult};
use atproto_dasl::car::{CarBlock, CarWriter};
use atproto_dasl::storage::BlockStorage;
use atproto_repo::mst::MstNode;
use std::collections::HashSet;
use std::str::FromStr;

/// Build a complete CAR v1 byte buffer for the actor's repo.
///
/// `root[0]` is the current commit CID. The CAR contains the commit block,
/// every reachable MST node, and every reachable record block.
///
/// # Errors
///
/// Returns [`PdsError::NotFound`] if the actor has no commits;
/// [`PdsError::Storage`] for any backend failure.
pub async fn export_repo_car(store: &SqlActorStore) -> PdsResult<Vec<u8>> {
    let pool = store.pool();

    // Look up current head.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT cid, data_cid FROM commit_obj ORDER BY rev DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("getRepo head lookup: {e}"),
            })?;
    let (commit_cid_str, _data_cid_str) = row.ok_or_else(|| PdsError::NotFound {
        what: "no commits in repo".to_string(),
    })?;

    let commit_cid = cid::Cid::from_str(&commit_cid_str).map_err(|e| PdsError::Storage {
        reason: format!("parse commit CID: {e}"),
    })?;

    let storage = SqlBlockStorage::open(pool.clone())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("open block storage: {e}"),
        })?;

    // Collect all reachable CIDs starting from the commit.
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![commit_cid];
    let mut blocks: Vec<CarBlock> = Vec::new();

    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("get block {cid}: {e}"),
        })?;
        let Some(data) = data else {
            // Missing block — this can happen for record-value blocks if a
            // future writer rewrites without garbage-collecting. Skip.
            continue;
        };
        // Try to decode as MST node to discover children. Fall back: it's a
        // record value (no children).
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            // Commit block: enqueue MST root.
            stack.push(commit.data.0);
        }
        blocks.push(CarBlock { cid, data });
    }

    // Write CAR.
    let mut buffer: Vec<u8> = Vec::with_capacity(blocks.iter().map(|b| b.data.len() + 64).sum());
    let mut writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(commit_cid)])
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

/// CAR diff slice between `since` rev and current head.
///
/// Returns a CAR v1 byte buffer whose root is the current head commit and
/// whose blocks are exactly those reachable from `head` that aren't already
/// reachable from the `since` commit. Subscribers that hold the snapshot at
/// `since` apply the diff to advance their MST without re-downloading the
/// whole repo.
///
/// Implementation: compute the reachability set of `since` (CIDs of every
/// block reachable from the `since` commit's MST root), then walk from
/// `head` collecting only blocks NOT in that set. The resulting CAR's
/// blocks are a strict subset of the full export.
///
/// # Errors
///
/// - [`PdsError::NotFound`] if either the head or the `since` rev have no
///   matching commit row.
/// - [`PdsError::Storage`] for backend / parse failures.
pub async fn export_repo_car_since(store: &SqlActorStore, since: &str) -> PdsResult<Vec<u8>> {
    let pool = store.pool();

    // Look up head + since commits. `since` is the rev (TID), not a CID.
    let head_row: Option<(String,)> =
        sqlx::query_as("SELECT cid FROM commit_obj ORDER BY rev DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("getRepo head lookup: {e}"),
            })?;
    let head_cid_str = head_row
        .ok_or_else(|| PdsError::NotFound {
            what: "no commits in repo".to_string(),
        })?
        .0;
    let head_cid = cid::Cid::from_str(&head_cid_str).map_err(|e| PdsError::Storage {
        reason: format!("parse head CID: {e}"),
    })?;

    let since_row: Option<(String,)> =
        sqlx::query_as("SELECT cid FROM commit_obj WHERE rev = ? LIMIT 1")
            .bind(since)
            .fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("getRepo since lookup: {e}"),
            })?;
    let since_cid_str = since_row
        .ok_or_else(|| PdsError::NotFound {
            what: format!("no commit at rev {since}"),
        })?
        .0;
    let since_cid = cid::Cid::from_str(&since_cid_str).map_err(|e| PdsError::Storage {
        reason: format!("parse since CID: {e}"),
    })?;

    // Same-rev shortcut — emit a manifest-only CAR (root=head, no blocks).
    if since_cid == head_cid {
        let mut buffer = Vec::new();
        let writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(head_cid)])
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::new: {e}"),
            })?;
        writer.finish().await.map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::finish: {e}"),
        })?;
        return Ok(buffer);
    }

    let storage = SqlBlockStorage::open(pool.clone())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("open block storage: {e}"),
        })?;

    // Step 1: walk from `since`, collecting CIDs in the baseline set. We
    // do NOT emit these — they're the subscriber's prior knowledge.
    let baseline = walk_reachable(&storage, since_cid).await?;

    // Step 2: walk from `head`, collecting blocks not in baseline.
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![head_cid];
    let mut blocks: Vec<CarBlock> = Vec::new();

    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("get block {cid}: {e}"),
        })?;
        let Some(data) = data else {
            continue;
        };
        // Discover children regardless of whether we emit this block —
        // baseline-shared MST nodes have shared sub-trees we still need
        // to traverse (we just don't emit the shared blocks themselves).
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            stack.push(commit.data.0);
        }
        if !baseline.contains(&cid) {
            blocks.push(CarBlock { cid, data });
        }
    }

    // Write CAR with head as root, only delta blocks as body.
    let mut buffer: Vec<u8> = Vec::with_capacity(blocks.iter().map(|b| b.data.len() + 64).sum());
    let mut writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(head_cid)])
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

/// Walk the reachability set rooted at `start` and return the set of CIDs.
/// Used by `export_repo_car_since` to compute the subscriber's baseline.
async fn walk_reachable(
    storage: &SqlBlockStorage,
    start: cid::Cid,
) -> PdsResult<HashSet<cid::Cid>> {
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![start];
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("walk_reachable get {cid}: {e}"),
        })?;
        let Some(data) = data else {
            continue;
        };
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            stack.push(commit.data.0);
        }
    }
    Ok(visited)
}

/// Generic CAR export over any [`BlockStorage`] — used by both the
/// legacy `&SqlActorStore` and the dispatch-via-`PublicRealmBackend`
/// entry points. The caller supplies the head commit CID and a
/// connected block store; this walks reachability from the commit and
/// packs every reachable block into a CAR v1 stream.
async fn export_repo_car_from_storage<S>(storage: &S, head_cid: cid::Cid) -> PdsResult<Vec<u8>>
where
    S: BlockStorage + ?Sized,
{
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![head_cid];
    let mut blocks: Vec<CarBlock> = Vec::new();

    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("get block {cid}: {e}"),
        })?;
        let Some(data) = data else { continue };
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            stack.push(commit.data.0);
        }
        blocks.push(CarBlock { cid, data });
    }
    let mut buffer: Vec<u8> = Vec::with_capacity(blocks.iter().map(|b| b.data.len() + 64).sum());
    let mut writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(head_cid)])
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

/// `getRepo` exporter rooted at a [`PublicRealmBackend`]. Uses the
/// trait dispatch — `commit_obj.latest(did)` for the head CID,
/// `open_block_storage(did)` for the walk. Mirrors
/// [`export_repo_car`]'s legacy SQLite-direct shape.
pub async fn export_repo_car_via_backend(
    backend: &PublicRealmBackend,
    did: &str,
) -> PdsResult<Vec<u8>> {
    let head = backend
        .commit_obj
        .latest(did)
        .await?
        .ok_or_else(|| PdsError::NotFound {
            what: "no commits in repo".to_string(),
        })?;
    let head_cid = cid::Cid::from_str(&head.cid).map_err(|e| PdsError::Storage {
        reason: format!("parse commit CID: {e}"),
    })?;
    let storage = backend.open_block_storage(did).await?;
    export_repo_car_from_storage(&storage, head_cid).await
}

/// `getRepo?since=<rev>` exporter rooted at a `PublicRealmBackend`.
pub async fn export_repo_car_since_via_backend(
    backend: &PublicRealmBackend,
    did: &str,
    since: &str,
) -> PdsResult<Vec<u8>> {
    let head = backend
        .commit_obj
        .latest(did)
        .await?
        .ok_or_else(|| PdsError::NotFound {
            what: "no commits in repo".to_string(),
        })?;
    let head_cid = cid::Cid::from_str(&head.cid).map_err(|e| PdsError::Storage {
        reason: format!("parse head CID: {e}"),
    })?;

    let since_row = backend
        .commit_obj
        .get_by_rev(did, since)
        .await?
        .ok_or_else(|| PdsError::NotFound {
            what: format!("no commit at rev {since}"),
        })?;
    let since_cid = cid::Cid::from_str(&since_row.cid).map_err(|e| PdsError::Storage {
        reason: format!("parse since CID: {e}"),
    })?;

    if since_cid == head_cid {
        let mut buffer = Vec::new();
        let writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(head_cid)])
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::new: {e}"),
            })?;
        writer.finish().await.map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::finish: {e}"),
        })?;
        return Ok(buffer);
    }

    let storage = backend.open_block_storage(did).await?;
    let baseline = walk_reachable_dyn(&storage, since_cid).await?;
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![head_cid];
    let mut blocks: Vec<CarBlock> = Vec::new();
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("get block {cid}: {e}"),
        })?;
        let Some(data) = data else { continue };
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            stack.push(commit.data.0);
        }
        if !baseline.contains(&cid) {
            blocks.push(CarBlock { cid, data });
        }
    }
    let mut buffer: Vec<u8> = Vec::with_capacity(blocks.iter().map(|b| b.data.len() + 64).sum());
    let mut writer = CarWriter::new(&mut buffer, vec![atproto_dasl::Cid::from(head_cid)])
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

/// Generic reachability walk over any [`BlockStorage`]. Used by the
/// dispatch path's `since` diff slice.
async fn walk_reachable_dyn<S>(storage: &S, start: cid::Cid) -> PdsResult<HashSet<cid::Cid>>
where
    S: BlockStorage + ?Sized,
{
    let mut visited: HashSet<cid::Cid> = HashSet::new();
    let mut stack = vec![start];
    while let Some(cid) = stack.pop() {
        if !visited.insert(cid) {
            continue;
        }
        let data = storage.get(&cid).await.map_err(|e| PdsError::Storage {
            reason: format!("walk_reachable get {cid}: {e}"),
        })?;
        let Some(data) = data else { continue };
        if let Ok(node) = atproto_dasl::from_slice::<MstNode>(&data) {
            if let Some(left) = &node.left {
                stack.push(left.0);
            }
            for entry in &node.entries {
                stack.push(entry.value.0);
                if let Some(right) = &entry.tree {
                    stack.push(right.0);
                }
            }
        } else if let Ok(commit) = atproto_dasl::from_slice::<atproto_repo::Commit>(&data) {
            stack.push(commit.data.0);
        }
    }
    Ok(visited)
}

/// `com.atproto.sync.getBlocks` rooted at a [`PublicRealmBackend`].
pub async fn export_blocks_car_via_backend(
    backend: &PublicRealmBackend,
    did: &str,
    cids: &[String],
) -> PdsResult<Vec<u8>> {
    let storage = backend.open_block_storage(did).await?;
    let mut blocks = Vec::with_capacity(cids.len());
    let mut roots: Vec<atproto_dasl::Cid> = Vec::with_capacity(cids.len());
    for cid_str in cids {
        let cid = cid::Cid::from_str(cid_str).map_err(|e| PdsError::Storage {
            reason: format!("parse CID {cid_str}: {e}"),
        })?;
        let data = storage
            .get(&cid)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("get block {cid}: {e}"),
            })?
            .ok_or_else(|| PdsError::NotFound {
                what: format!("block {cid_str} not present"),
            })?;
        roots.push(atproto_dasl::Cid::from(cid));
        blocks.push(CarBlock { cid, data });
    }
    let mut buffer = Vec::new();
    let mut writer = CarWriter::new(&mut buffer, roots)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

/// `com.atproto.sync.getBlocks` — pack the requested CIDs into a CAR.
pub async fn export_blocks_car(store: &SqlActorStore, cids: &[String]) -> PdsResult<Vec<u8>> {
    let pool = store.pool();
    let storage = SqlBlockStorage::open(pool.clone())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("open block storage: {e}"),
        })?;
    let mut blocks = Vec::with_capacity(cids.len());
    let mut roots: Vec<atproto_dasl::Cid> = Vec::with_capacity(cids.len());
    for cid_str in cids {
        let cid = cid::Cid::from_str(cid_str).map_err(|e| PdsError::Storage {
            reason: format!("parse CID {cid_str}: {e}"),
        })?;
        let data = storage
            .get(&cid)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("get block {cid}: {e}"),
            })?
            .ok_or_else(|| PdsError::NotFound {
                what: format!("block {cid_str} not present"),
            })?;
        roots.push(atproto_dasl::Cid::from(cid));
        blocks.push(CarBlock { cid, data });
    }
    let mut buffer = Vec::new();
    let mut writer = CarWriter::new(&mut buffer, roots)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("CarWriter::new: {e}"),
        })?;
    for block in &blocks {
        writer
            .write_block(block)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("CarWriter::write_block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("CarWriter::finish: {e}"),
    })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::car::CarReader;
    use std::io::Cursor;

    async fn seed_store_with_commit(store: &SqlActorStore) {
        let pool = store.pool();
        // Insert a commit + dummy data block via direct SQL (sufficient to
        // exercise the export path).
        let dummy_block = b"hello".to_vec();
        let block_cid = atproto_dasl::cid::compute_cid(&dummy_block);
        sqlx::query("INSERT INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)")
            .bind(block_cid.to_string())
            .bind(&dummy_block)
            .bind("2026-05-01T00:00:00Z")
            .execute(pool)
            .await
            .unwrap();

        // Build a commit struct that references this block as data.
        let commit = atproto_repo::Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: atproto_dasl::Cid::from(block_cid),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };
        let commit_bytes = atproto_dasl::to_vec(&commit).unwrap();
        let commit_cid = atproto_dasl::cid::compute_cid(&commit_bytes);
        sqlx::query("INSERT INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)")
            .bind(commit_cid.to_string())
            .bind(&commit_bytes)
            .bind("2026-05-01T00:00:00Z")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO commit_obj (cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at)
             VALUES (?, ?, ?, NULL, NULL, ?, ?)",
        )
        .bind(commit_cid.to_string())
        .bind("3jui7kd2z2y2e")
        .bind(block_cid.to_string())
        .bind(vec![1u8, 2, 3, 4])
        .bind("2026-05-01T00:00:00Z")
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_repo_car_returns_valid_car() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        seed_store_with_commit(&store).await;

        let car_bytes = export_repo_car(&store).await.unwrap();
        assert!(!car_bytes.is_empty());

        // Parse it back as a CAR.
        let mut cursor = Cursor::new(car_bytes);
        let reader = CarReader::new(&mut cursor).await.unwrap();
        let root = reader.root().expect("CAR has a root");
        // Head commit is the root.
        let head_row: (String,) = sqlx::query_as("SELECT cid FROM commit_obj LIMIT 1")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(root.to_string(), head_row.0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_repo_car_empty_repo_returns_not_found() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        let result = export_repo_car(&store).await;
        assert!(matches!(result, Err(PdsError::NotFound { .. })));
    }

    /// `export_repo_car_since` returns a CAR rooted at head whose body
    /// excludes blocks reachable from `since`. With the same rev for both,
    /// the body is empty (root-only manifest CAR).
    #[tokio::test(flavor = "multi_thread")]
    async fn export_repo_car_since_same_rev_emits_root_only() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        seed_store_with_commit(&store).await;

        let car_bytes = export_repo_car_since(&store, "3jui7kd2z2y2e")
            .await
            .unwrap();
        let mut cursor = Cursor::new(&car_bytes);
        let mut reader = CarReader::new(&mut cursor).await.unwrap();
        let root = reader.root().expect("CAR has a root");
        let head_row: (String,) = sqlx::query_as("SELECT cid FROM commit_obj LIMIT 1")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(root.to_string(), head_row.0);
        // Same-rev shortcut: zero body blocks.
        let mut count = 0usize;
        while reader.next_block().await.unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 0);
    }

    /// `export_repo_car_since` returns 404 when the named rev has no commit row.
    #[tokio::test(flavor = "multi_thread")]
    async fn export_repo_car_since_unknown_rev_returns_not_found() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        seed_store_with_commit(&store).await;
        let result = export_repo_car_since(&store, "3jui7notexist").await;
        assert!(matches!(result, Err(PdsError::NotFound { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_blocks_car_packs_named_cids() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        let mut bs = SqlBlockStorage::open(store.pool().clone()).await.unwrap();
        let data = b"abc".to_vec();
        let cid = atproto_dasl::cid::compute_cid(&data);
        bs.put(&cid, data).await.unwrap();

        let car = export_blocks_car(&store, &[cid.to_string()]).await.unwrap();
        let mut cursor = Cursor::new(car);
        let reader = CarReader::new(&mut cursor).await.unwrap();
        assert_eq!(reader.root().unwrap().to_string(), cid.to_string());
    }
}
