//! Spaces export / import.
//!
//! `com.atproto.space.exportSpaces` streams the per-(member, space) data
//! as a CARv1: a manifest block at root[0] plus one block per record.
//! `com.atproto.space.importSpaces` is the inverse, restoring records on
//! a destination PDS.
//!
//! # Wire format (CARv1)
//!
//! - **Root[0]** = CID of the manifest block.
//! - **Block 0**: DAG-CBOR-encoded [`ExportManifest`].
//! - **Blocks 1..N**: one per record — DAG-CBOR record bytes, content
//!   addressed by their stored CIDs.
//!
//! Member-list export rides as a JSON sub-payload inside the manifest
//! (members are `(did, member_rev, added_at)` triples; small + bounded).
//!
//! # Current limitations
//!
//! - SetHash is preserved verbatim from the source — the import side
//!   accepts the manifest's claimed SetHash and writes it directly to the
//!   `space_repo` row. A future enhancement walks the imported records
//!   and recomputes the SetHash locally to detect tampering during
//!   transit. (`verify_inductive`-style guarantees aren't yet defined for
//!   the permissioned realm.)
//! - Oplog history is NOT exported; only the current set + commit head.
//!   Receivers needing oplog must catch up via `getRepoOplog`.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use atproto_dasl::Cid as DaslCid;
use atproto_dasl::car::{CarBlock, CarReader, CarWriter};
use atproto_dasl::cid::compute_cid;
use atproto_space::types::SpaceUri;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};

/// One record in the export manifest. Value bytes are stored separately
/// in the CAR; the manifest only carries the metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecord {
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the record value.
    pub cid: String,
    /// Rev (TID) at which the record was last written.
    pub rev: String,
}

/// One member-list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMember {
    /// Member DID.
    pub did: String,
    /// Rev at which the member was added.
    pub member_rev: String,
    /// ISO-8601 add timestamp.
    pub added_at: String,
}

/// Export manifest — root block of an `exportSpaces` CAR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    /// Wire-format version (currently `1`). Bumps on incompatible changes.
    pub version: u32,
    /// Space URI being exported.
    pub space: String,
    /// DID whose record set is being exported (None for owner-side
    /// exports of the member list only).
    pub member_did: Option<String>,
    /// Hex-encoded current SetHash digest, or `None` when empty.
    pub set_hash: Option<String>,
    /// Latest rev (TID) for the per-(member, space) repo.
    pub rev: Option<String>,
    /// Per-record metadata (value bytes are CAR blocks keyed on `cid`).
    pub records: Vec<ManifestRecord>,
    /// Owner-side member-list (only present when the caller is the
    /// space owner exporting the member list).
    pub members: Vec<ManifestMember>,
}

/// Stream a CAR of `(records, member-list)` for the given (space, member)
/// to `out`.
///
/// `member_did=None` exports the member list only (owner-side migration).
/// `member_did=Some(did)` exports that member's record set.
pub async fn export_to_writer<W: AsyncWrite + Unpin + Send>(
    data_dir: &Path,
    space: &SpaceUri,
    member_did: Option<&str>,
    out: W,
) -> PdsResult<()> {
    // Gather records for the per-member view. The records live in
    // `member_did`'s per-actor SQLite (or the owner's, when member_did is
    // the owner). Pull all rows for this space.
    let mut record_blocks: Vec<CarBlock> = Vec::new();
    let mut manifest_records: Vec<ManifestRecord> = Vec::new();
    if let Some(member) = member_did {
        let store = SqlActorStore::open(data_dir, member).await?;
        type Row = (String, String, String, Vec<u8>, String);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT collection, rkey, cid, value, repo_rev
             FROM space_record WHERE space = ?
             ORDER BY collection, rkey",
        )
        .bind(space.to_string())
        .fetch_all(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("export space_record select: {e}"),
        })?;
        for (collection, rkey, cid_str, value, rev) in rows {
            let cid = DaslCid::from_str(cid_str.as_str()).map_err(|e| PdsError::Storage {
                reason: format!("parse record cid {cid_str}: {e}"),
            })?;
            record_blocks.push(CarBlock {
                cid: cid.0,
                data: value,
            });
            manifest_records.push(ManifestRecord {
                collection,
                rkey,
                cid: cid_str,
                rev,
            });
        }
    }

    // Per-(member, space) repo state (set_hash + rev).
    let (state_set_hash, state_rev) = if let Some(member) = member_did {
        let store = SqlActorStore::open(data_dir, member).await?;
        let row: Option<(Option<Vec<u8>>, Option<String>)> =
            sqlx::query_as("SELECT set_hash, rev FROM space_repo WHERE space = ?")
                .bind(space.to_string())
                .fetch_optional(store.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("export space_repo select: {e}"),
                })?;
        match row {
            Some((sh, rev)) => (sh.map(hex::encode), rev),
            None => (None, None),
        }
    } else {
        (None, None)
    };

    // Owner-side member list — only when the caller is the owner. We
    // detect that by member_did being absent OR equal to the space owner.
    // Conservative: include when the member_did matches owner or is
    // absent (export the owner's view by default).
    let mut manifest_members: Vec<ManifestMember> = Vec::new();
    if member_did.is_none() || member_did == Some(space.owner_did.as_str()) {
        let store = SqlActorStore::open(data_dir, &space.owner_did).await?;
        type Row = (String, String, String);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT did, member_rev, added_at FROM space_member
             WHERE space = ? ORDER BY did",
        )
        .bind(space.to_string())
        .fetch_all(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("export space_member select: {e}"),
        })?;
        for (did, member_rev, added_at) in rows {
            manifest_members.push(ManifestMember {
                did,
                member_rev,
                added_at,
            });
        }
    }

    let manifest = ExportManifest {
        version: 1,
        space: space.to_string(),
        member_did: member_did.map(str::to_string),
        set_hash: state_set_hash,
        rev: state_rev,
        records: manifest_records,
        members: manifest_members,
    };
    let manifest_bytes = atproto_dasl::to_vec(&manifest).map_err(|e| PdsError::Storage {
        reason: format!("encode manifest: {e}"),
    })?;
    let manifest_cid_raw = compute_cid(&manifest_bytes);
    let manifest_cid = DaslCid(manifest_cid_raw);

    // Write the CAR: header(roots=[manifest_cid]) + manifest block + record blocks.
    let mut writer = CarWriter::new(out, vec![manifest_cid.clone()])
        .await
        .map_err(PdsError::Dasl)?;
    writer
        .write_block(&CarBlock {
            cid: manifest_cid_raw,
            data: manifest_bytes,
        })
        .await
        .map_err(PdsError::Dasl)?;
    for block in &record_blocks {
        writer.write_block(block).await.map_err(PdsError::Dasl)?;
    }
    writer.finish().await.map_err(PdsError::Dasl)?;
    Ok(())
}

/// Outcome of an `importSpaces` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Space URI restored.
    pub space: String,
    /// Imported member DID, when the export carried records for one.
    pub member_did: Option<String>,
    /// Number of records inserted.
    pub records_inserted: usize,
    /// Number of members inserted.
    pub members_inserted: usize,
}

/// Restore a previously-exported CAR onto the local PDS.
///
/// `target_member_did` overrides the manifest's `member_did` (useful when
/// the destination DID differs from the source's). `target_space` ditto.
/// Both default to the manifest values when `None`.
///
/// Inserts use `INSERT OR REPLACE` semantics — re-importing a previously-
/// imported CAR is idempotent.
pub async fn import_from_reader<R: AsyncRead + Unpin + Send>(
    data_dir: &Path,
    reader: R,
    target_space: Option<&SpaceUri>,
    target_member_did: Option<&str>,
) -> PdsResult<ImportOutcome> {
    let mut car = CarReader::new(reader).await.map_err(PdsError::Dasl)?;
    let root_cid = car.root().cloned().ok_or_else(|| PdsError::Storage {
        reason: "importSpaces CAR has no root".to_string(),
    })?;
    let mut blocks: Vec<CarBlock> = Vec::new();
    while let Some(b) = car.next_block().await.map_err(PdsError::Dasl)? {
        blocks.push(b);
    }
    let manifest_block =
        blocks
            .iter()
            .find(|b| b.cid == root_cid.0)
            .ok_or_else(|| PdsError::Storage {
                reason: "importSpaces: manifest CID not found in CAR blocks".to_string(),
            })?;
    let manifest: ExportManifest =
        atproto_dasl::from_slice(&manifest_block.data).map_err(|e| PdsError::Storage {
            reason: format!("decode manifest: {e}"),
        })?;
    if manifest.version != 1 {
        return Err(PdsError::Storage {
            reason: format!("unsupported export manifest version: {}", manifest.version),
        });
    }
    let space_uri: SpaceUri = match target_space {
        Some(s) => s.clone(),
        None => SpaceUri::parse(&manifest.space).map_err(PdsError::Space)?,
    };
    let member_did = target_member_did
        .map(str::to_string)
        .or_else(|| manifest.member_did.clone());

    // Insert records into the member's per-actor store.
    let mut records_inserted = 0usize;
    if let Some(ref m) = member_did {
        let store = SqlActorStore::open(data_dir, m).await?;
        // Ensure the destination per-actor store has a `space` row for
        // this URI — `space_record`, `space_repo`, and `space_member`
        // all FK into `space.uri`. Member-side perspective: `is_member=1`,
        // `is_owner=1` only when the importing DID equals the owner.
        let now = chrono::Utc::now().to_rfc3339();
        let is_owner_flag = if m == &space_uri.owner_did { 1 } else { 0 };
        sqlx::query(
            "INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at)
             VALUES (?, ?, 1, ?)",
        )
        .bind(space_uri.to_string())
        .bind(is_owner_flag)
        .bind(&now)
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("ensure member space row: {e}"),
        })?;

        // Build a CID → bytes index of the record data blocks (skip the
        // manifest itself).
        let mut block_index: std::collections::HashMap<String, &[u8]> =
            std::collections::HashMap::new();
        for b in &blocks {
            if b.cid == root_cid.0 {
                continue;
            }
            block_index.insert(b.cid.to_string(), &b.data);
        }
        for r in &manifest.records {
            let value = block_index
                .get(r.cid.as_str())
                .ok_or_else(|| PdsError::Storage {
                    reason: format!("record {} missing in CAR", r.cid),
                })?;
            sqlx::query(
                "INSERT OR REPLACE INTO space_record
                    (space, collection, rkey, cid, value, repo_rev, indexed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(space_uri.to_string())
            .bind(&r.collection)
            .bind(&r.rkey)
            .bind(&r.cid)
            .bind(value.to_vec())
            .bind(&r.rev)
            .bind(&now)
            .execute(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("insert space_record: {e}"),
            })?;
            records_inserted += 1;
        }
        // Update space_repo state to the manifest's claimed (set_hash, rev).
        sqlx::query("INSERT OR REPLACE INTO space_repo (space, set_hash, rev) VALUES (?, ?, ?)")
            .bind(space_uri.to_string())
            .bind(
                manifest
                    .set_hash
                    .as_deref()
                    .map(hex::decode)
                    .transpose()
                    .map_err(|e| PdsError::Storage {
                        reason: format!("decode set_hash hex: {e}"),
                    })?,
            )
            .bind(manifest.rev.as_deref())
            .execute(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("upsert space_repo: {e}"),
            })?;
    }

    // Insert member-list rows into the owner's per-actor store.
    let mut members_inserted = 0usize;
    if !manifest.members.is_empty() {
        let store = SqlActorStore::open(data_dir, &space_uri.owner_did).await?;
        // Ensure a `space` row exists (FK).
        sqlx::query(
            "INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at)
             VALUES (?, 1, 1, ?)",
        )
        .bind(space_uri.to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(store.pool())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("ensure space row: {e}"),
        })?;
        for m in &manifest.members {
            sqlx::query(
                "INSERT OR REPLACE INTO space_member
                    (space, did, member_rev, added_at)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(space_uri.to_string())
            .bind(&m.did)
            .bind(&m.member_rev)
            .bind(&m.added_at)
            .execute(store.pool())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("insert space_member: {e}"),
            })?;
            members_inserted += 1;
        }
    }

    Ok(ImportOutcome {
        space: space_uri.to_string(),
        member_did,
        records_inserted,
        members_inserted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use crate::space::service::SpaceService;
    use crate::space::writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
    use atproto_identity::key::KeyType;
    use atproto_space::types::{SpaceKey, SpaceType};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    async fn fresh_setup() -> (TempDir, Arc<AccountManager>, SpaceUri) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts.pool().clone(),
            dir.clone(),
            key_store,
            KeyType::K256Private,
        ));
        for did in ["did:plc:owner", "did:plc:alice"] {
            manager
                .create_account(CreateAccountParams {
                    did,
                    handle: &format!("{}.example", did.trim_start_matches("did:plc:")),
                    email: None,
                    password: "pw",
                    pds_managed_rotation: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let space = SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        );
        (tmp, manager, space)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_then_import_round_trip() {
        let (tmp, manager, space) = fresh_setup().await;
        let dir = tmp.path().to_path_buf();
        // Create the space + add alice as a member.
        let svc = SpaceService::with_accounts(dir.clone(), manager.clone());
        svc.create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        svc.add_member("did:plc:owner", &space, "did:plc:alice")
            .await
            .unwrap();
        // Alice writes two records.
        let writer = SpaceWriter::new(manager.clone(), dir.clone());
        for (rkey, value) in [
            ("k1", serde_json::json!({"n": 1})),
            ("k2", serde_json::json!({"n": 2})),
        ] {
            writer
                .apply_writes(
                    "did:plc:alice",
                    &space,
                    vec![SpaceWriteOp {
                        action: SpaceWriteAction::Create,
                        collection: "c".to_string(),
                        rkey: rkey.to_string(),
                        value: Some(value),
                    }],
                )
                .await
                .unwrap();
        }

        // Export.
        let mut car_bytes: Vec<u8> = Vec::new();
        export_to_writer(&dir, &space, Some("did:plc:alice"), &mut car_bytes)
            .await
            .unwrap();
        assert!(!car_bytes.is_empty());

        // Decode the manifest to check shape.
        {
            let mut car = CarReader::new(std::io::Cursor::new(&car_bytes))
                .await
                .unwrap();
            let root = car.root().cloned().unwrap();
            let mut found_manifest = false;
            while let Some(b) = car.next_block().await.unwrap() {
                if b.cid == root.0 {
                    let m: ExportManifest = atproto_dasl::from_slice(&b.data).unwrap();
                    assert_eq!(m.records.len(), 2);
                    // Member-side export of alice's records does NOT carry
                    // the owner's member-list — it would leak owner-side
                    // visibility into a member's migration bundle.
                    assert_eq!(m.members.len(), 0);
                    assert_eq!(m.member_did.as_deref(), Some("did:plc:alice"));
                    found_manifest = true;
                }
            }
            assert!(found_manifest);
        }

        // Now import onto a *separate* temp dir as a fresh PDS.
        let dest = TempDir::new().unwrap();
        let dest_dir = dest.path().to_path_buf();
        let _ = AccountDirectory::open(&dest_dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let outcome = import_from_reader(&dest_dir, std::io::Cursor::new(car_bytes), None, None)
            .await
            .unwrap();
        assert_eq!(outcome.records_inserted, 2);
        // No member list in the manifest, so 0 members inserted.
        assert_eq!(outcome.members_inserted, 0);

        // Verify on the destination: the records are present.
        let alice_store = SqlActorStore::open(&dest_dir, "did:plc:alice")
            .await
            .unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM space_record WHERE space = ?")
            .bind(space.to_string())
            .fetch_one(alice_store.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 2);
    }

    /// `importSpaces` re-applied is a no-op (idempotent on `(space, collection, rkey)`).
    #[tokio::test(flavor = "multi_thread")]
    async fn import_is_idempotent() {
        let (tmp, manager, space) = fresh_setup().await;
        let dir = tmp.path().to_path_buf();
        let svc = SpaceService::with_accounts(dir.clone(), manager.clone());
        svc.create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        svc.add_member("did:plc:owner", &space, "did:plc:alice")
            .await
            .unwrap();
        let writer = SpaceWriter::new(manager.clone(), dir.clone());
        writer
            .apply_writes(
                "did:plc:alice",
                &space,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "c".to_string(),
                    rkey: "k".to_string(),
                    value: Some(serde_json::json!({"v": 1})),
                }],
            )
            .await
            .unwrap();

        let mut car_bytes: Vec<u8> = Vec::new();
        export_to_writer(&dir, &space, Some("did:plc:alice"), &mut car_bytes)
            .await
            .unwrap();

        let dest = TempDir::new().unwrap();
        let dest_dir = dest.path().to_path_buf();
        let _ = AccountDirectory::open(&dest_dir.join("accounts.sqlite"))
            .await
            .unwrap();
        for _ in 0..2 {
            import_from_reader(
                &dest_dir,
                std::io::Cursor::new(car_bytes.clone()),
                None,
                None,
            )
            .await
            .unwrap();
        }
        let alice_store = SqlActorStore::open(&dest_dir, "did:plc:alice")
            .await
            .unwrap();
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM space_record WHERE space = ?")
            .bind(space.to_string())
            .fetch_one(alice_store.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 1, "re-import must not duplicate records");
    }

    /// Manifest version mismatch is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn import_rejects_unknown_manifest_version() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let _ = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let manifest = ExportManifest {
            version: 999,
            space: "ats://did:plc:owner/app.bsky.group/default".to_string(),
            member_did: None,
            set_hash: None,
            rev: None,
            records: vec![],
            members: vec![],
        };
        let bytes = atproto_dasl::to_vec(&manifest).unwrap();
        let cid = compute_cid(&bytes);
        let mut car_buf: Vec<u8> = Vec::new();
        let mut writer = CarWriter::new(&mut car_buf, vec![DaslCid(cid)])
            .await
            .unwrap();
        writer
            .write_block(&CarBlock { cid, data: bytes })
            .await
            .unwrap();
        writer.finish().await.unwrap();

        let result = import_from_reader(&dir, std::io::Cursor::new(car_buf), None, None).await;
        assert!(result.is_err());
    }

    /// Smoke: a CAR with no records still round-trips (member-list-only export).
    #[tokio::test(flavor = "multi_thread")]
    async fn export_with_no_records_yields_empty_record_list() {
        let (tmp, manager, space) = fresh_setup().await;
        let dir = tmp.path().to_path_buf();
        let svc = SpaceService::with_accounts(dir.clone(), manager);
        svc.create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();

        let mut car_bytes = Vec::new();
        export_to_writer(&dir, &space, None, &mut car_bytes)
            .await
            .unwrap();
        let mut car = CarReader::new(std::io::Cursor::new(car_bytes))
            .await
            .unwrap();
        let root = car.root().cloned().unwrap();
        let mut all_blocks = Vec::new();
        while let Some(b) = car.next_block().await.unwrap() {
            all_blocks.push(b);
        }
        assert_eq!(all_blocks.len(), 1, "manifest only");
        let manifest_block = &all_blocks[0];
        assert_eq!(manifest_block.cid, root.0);
        let m: ExportManifest = atproto_dasl::from_slice(&manifest_block.data).unwrap();
        assert!(m.records.is_empty());
    }

    /// Owner-side export (member_did=Some(owner)) carries the member list.
    #[tokio::test(flavor = "multi_thread")]
    async fn owner_side_export_includes_member_list() {
        let (tmp, manager, space) = fresh_setup().await;
        let dir = tmp.path().to_path_buf();
        let svc = SpaceService::with_accounts(dir.clone(), manager);
        svc.create_space("did:plc:owner", "app.bsky.group", "default")
            .await
            .unwrap();
        svc.add_member("did:plc:owner", &space, "did:plc:alice")
            .await
            .unwrap();

        let mut car_bytes = Vec::new();
        export_to_writer(&dir, &space, Some("did:plc:owner"), &mut car_bytes)
            .await
            .unwrap();

        let mut car = CarReader::new(std::io::Cursor::new(&car_bytes))
            .await
            .unwrap();
        let root = car.root().cloned().unwrap();
        let mut found_manifest = false;
        while let Some(b) = car.next_block().await.unwrap() {
            if b.cid == root.0 {
                let m: ExportManifest = atproto_dasl::from_slice(&b.data).unwrap();
                assert_eq!(m.member_did.as_deref(), Some("did:plc:owner"));
                // The owner is implicit in the space row (is_owner=1)
                // and is not duplicated into space_member; only alice
                // appears as an explicitly-added member.
                assert_eq!(m.members.len(), 1);
                assert_eq!(m.members[0].did, "did:plc:alice");
                found_manifest = true;
            }
        }
        assert!(found_manifest);
    }

    /// Sanity: a Cursor<Vec<u8>> can be passed directly as AsyncRead.
    #[tokio::test(flavor = "multi_thread")]
    async fn cursor_is_async_read() {
        let mut buf = Vec::new();
        let mut cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(b"abc".to_vec());
        cursor.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"abc");
    }
}
