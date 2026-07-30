//! The CAR a permissioned repo exports for full-state recovery.
//!
//! `com.atproto.space.getRepo` is the only recovery path for a syncer that has
//! fallen past its oplog retention. `listRepoOps` replays *changes*; it cannot
//! reconstruct a repo whose earliest ops have been pruned, and `listRecords`
//! carries no commit and no CID-addressed blocks. Without this endpoint a
//! syncer in that position has nowhere to go.
//!
//! # Layout
//!
//! The draft lexicon is prescriptive, so this is a transcription rather than a
//! design:
//!
//! > *"The CAR declares two roots in order: the signed commit, then a DRISL
//! > (DAG-CBOR) index mapping `'{collection}/{rkey}'` to record CID. Record
//! > blocks follow in lexicographic order. Blobs are not included and are
//! > fetched separately via getBlob."*
//!
//! So: header with `[commit_cid, index_cid]`, then the commit block, then the
//! index block, then record blocks ordered by `{collection}/{rkey}`.
//!
//! # Record blocks go in exactly as stored
//!
//! HappyView's equivalent (`src/spaces/car.rs:60-151`) re-encodes each record
//! as JSON and takes a RAW CID. That reflects how HappyView stores records, not
//! anything the lexicon asks for. Here the records are already DAG-CBOR and
//! `space_record.cid` is the CID `getRecord` reports, so the bytes and the CID
//! are used verbatim. Re-encoding would produce blocks whose CIDs disagreed
//! with the index, with `getRecord`, and with the commit — a CAR that cannot be
//! verified is worse than no CAR.

use crate::errors::{PdsError, PdsResult};
use atproto_dasl::car::{CarBlock, CarWriter};
use atproto_space::storage::RecordRow;
use std::collections::BTreeMap;

/// Page size used when draining a repo's records.
///
/// `list_records` clamps to the lexicon's 100 per page, so a whole-repo export
/// pages rather than issuing one unbounded query. Keeping to the same contract
/// every other reader uses is worth an extra round trip per hundred records.
pub const EXPORT_PAGE: u32 = 100;

/// Build the export CAR from a signed commit and the repo's records.
///
/// `records` need not be sorted; this sorts by `{collection}/{rkey}`, which is
/// both the index's key order and the block order the lexicon requires.
///
/// # Errors
///
/// [`PdsError::Storage`] when a stored CID does not parse, when the index
/// cannot be encoded, or on a CAR write failure.
pub async fn build_repo_car(commit_block: &[u8], records: Vec<RecordRow>) -> PdsResult<Vec<u8>> {
    let commit_cid = atproto_dasl::cid::compute_cid(commit_block);

    // A BTreeMap gives the lexicographic ordering the lexicon asks for, and it
    // is the same ordering the index needs — so sorting happens once, here,
    // rather than being asserted in two places.
    let mut by_key: BTreeMap<String, (cid::Cid, Vec<u8>)> = BTreeMap::new();
    for row in records {
        let parsed: cid::Cid = row.cid.parse().map_err(|e: cid::Error| PdsError::Storage {
            reason: format!(
                "stored permissioned record CID {} does not parse: {e}",
                row.cid
            ),
        })?;
        by_key.insert(
            format!("{}/{}", row.collection, row.rkey),
            (parsed, row.value),
        );
    }

    // The index is a DRISL map of key -> link. Built through the atproto-JSON
    // encoder — the same one that produced these record CIDs — so `$link`
    // becomes CBOR tag 42 and the map keys come out canonically ordered.
    let index_json = serde_json::Value::Object(
        by_key
            .iter()
            .map(|(key, (cid, _))| (key.clone(), serde_json::json!({ "$link": cid.to_string() })))
            .collect(),
    );
    let index_block =
        atproto_dasl::atproto_json::to_vec(&index_json).map_err(|e| PdsError::Storage {
            reason: format!("encode permissioned repo index: {e}"),
        })?;
    let index_cid = atproto_dasl::cid::compute_cid(&index_block);

    let mut buffer: Vec<u8> =
        Vec::with_capacity(by_key.values().map(|(_, v)| v.len() + 64).sum::<usize>() + 512);
    // Root order is part of the format: commit first, index second. A consumer
    // reads root 0 to verify the commit and root 1 to find the records.
    let mut writer = CarWriter::new(
        &mut buffer,
        vec![
            atproto_dasl::Cid::from(commit_cid),
            atproto_dasl::Cid::from(index_cid),
        ],
    )
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("permissioned repo CAR header: {e}"),
    })?;

    for (cid, data) in [
        (commit_cid, commit_block.to_vec()),
        (index_cid, index_block),
    ] {
        writer
            .write_block(&CarBlock { cid, data })
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("permissioned repo CAR root block: {e}"),
            })?;
    }
    for (cid, data) in by_key.into_values() {
        writer
            .write_block(&CarBlock { cid, data })
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("permissioned repo CAR record block: {e}"),
            })?;
    }
    writer.finish().await.map_err(|e| PdsError::Storage {
        reason: format!("permissioned repo CAR finish: {e}"),
    })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::car::CarReader;

    fn row(collection: &str, rkey: &str, value: serde_json::Value) -> RecordRow {
        let bytes = atproto_dasl::atproto_json::to_vec(&value).unwrap();
        let cid = atproto_dasl::cid::compute_cid(&bytes);
        RecordRow {
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: cid.to_string(),
            value: bytes,
            repo_rev: "3jui7kd2z2y2e".to_string(),
            indexed_at: "2026-07-31T00:00:00Z".to_string(),
        }
    }

    async fn read_back(car: &[u8]) -> (Vec<atproto_dasl::Cid>, Vec<(cid::Cid, Vec<u8>)>) {
        let mut reader = CarReader::new(std::io::Cursor::new(car.to_vec()))
            .await
            .unwrap();
        let roots = reader.header().roots.clone();
        let mut blocks = Vec::new();
        while let Some(block) = reader.next_block().await.unwrap() {
            blocks.push((block.cid, block.data));
        }
        (roots, blocks)
    }

    #[tokio::test]
    async fn the_car_declares_the_commit_root_then_the_index_root() {
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let car = build_repo_car(
            &commit,
            vec![row("c.d.e", "one", serde_json::json!({"v": 1}))],
        )
        .await
        .unwrap();

        let (roots, blocks) = read_back(&car).await;
        assert_eq!(roots.len(), 2, "the lexicon requires exactly two roots");
        let commit_cid = atproto_dasl::cid::compute_cid(&commit);
        assert_eq!(
            roots[0],
            atproto_dasl::Cid::from(commit_cid),
            "root 0 must be the signed commit"
        );
        // Root 1 is the index, and the block for it must be present.
        assert!(
            blocks
                .iter()
                .any(|(c, _)| atproto_dasl::Cid::from(*c) == roots[1]),
            "the index root must have a block in the CAR"
        );
        // Commit block, index block, one record.
        assert_eq!(blocks.len(), 3);
    }

    #[tokio::test]
    async fn every_block_hashes_to_its_own_cid() {
        // A CAR whose CIDs do not match its bytes cannot be verified, which is
        // the entire reason records are copied rather than re-encoded.
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let car = build_repo_car(
            &commit,
            vec![
                row("c.d.e", "one", serde_json::json!({"v": 1})),
                // A real CID, not a plausible-looking string: the encoder reads
                // `$link` into the data model and rejects anything that is not
                // a CID, so a fake one fails at encode time rather than
                // producing a wrong block.
                row(
                    "c.d.e",
                    "two",
                    serde_json::json!({"link": {
                        "$link": atproto_dasl::cid::compute_cid(b"linked").to_string()
                    }}),
                ),
            ],
        )
        .await
        .unwrap();

        let (_, blocks) = read_back(&car).await;
        for (cid, data) in &blocks {
            assert_eq!(
                atproto_dasl::cid::compute_cid(data),
                *cid,
                "block bytes must hash to the CID the CAR claims"
            );
        }
    }

    #[tokio::test]
    async fn the_index_maps_collection_slash_rkey_to_the_stored_cid() {
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let a = row("c.d.e", "one", serde_json::json!({"v": 1}));
        let b = row("c.d.f", "two", serde_json::json!({"v": 2}));
        let (a_cid, b_cid) = (a.cid.clone(), b.cid.clone());
        let car = build_repo_car(&commit, vec![b, a]).await.unwrap();

        let (roots, blocks) = read_back(&car).await;
        let index_bytes = blocks
            .iter()
            .find(|(c, _)| atproto_dasl::Cid::from(*c) == roots[1])
            .map(|(_, d)| d.clone())
            .expect("index block");
        let index: serde_json::Value =
            atproto_dasl::atproto_json::from_slice(&index_bytes).unwrap();

        assert_eq!(index["c.d.e/one"]["$link"], a_cid);
        assert_eq!(index["c.d.f/two"]["$link"], b_cid);
        assert_eq!(
            index.as_object().unwrap().len(),
            2,
            "one entry per record and nothing else"
        );
    }

    #[tokio::test]
    async fn record_blocks_follow_in_lexicographic_key_order() {
        // Records are handed in unsorted; the CAR must not be.
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let rows = vec![
            row("c.d.e", "zebra", serde_json::json!({"v": 3})),
            row("c.d.e", "apple", serde_json::json!({"v": 1})),
            row("c.d.a", "middle", serde_json::json!({"v": 2})),
        ];
        let expected: Vec<String> = {
            let mut keys = vec!["c.d.e/zebra", "c.d.e/apple", "c.d.a/middle"];
            keys.sort_unstable();
            keys.into_iter().map(str::to_string).collect()
        };
        let by_cid: BTreeMap<String, String> = rows
            .iter()
            .map(|r| (format!("{}/{}", r.collection, r.rkey), r.cid.clone()))
            .collect();

        let car = build_repo_car(&commit, rows).await.unwrap();
        let (_, blocks) = read_back(&car).await;
        // Skip the commit and index blocks.
        let record_cids: Vec<String> = blocks[2..].iter().map(|(c, _)| c.to_string()).collect();
        let expected_cids: Vec<String> = expected.iter().map(|k| by_cid[k].clone()).collect();
        assert_eq!(record_cids, expected_cids);
    }

    #[tokio::test]
    async fn an_empty_repo_still_produces_a_valid_two_root_car() {
        // A member who has never written is a real case: the syncer needs a
        // well-formed answer, not an error.
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let car = build_repo_car(&commit, Vec::new()).await.unwrap();
        let (roots, blocks) = read_back(&car).await;
        assert_eq!(roots.len(), 2);
        assert_eq!(blocks.len(), 2, "commit and an empty index");
        let index_bytes = blocks
            .iter()
            .find(|(c, _)| atproto_dasl::Cid::from(*c) == roots[1])
            .map(|(_, d)| d.clone())
            .unwrap();
        let index: serde_json::Value =
            atproto_dasl::atproto_json::from_slice(&index_bytes).unwrap();
        assert_eq!(index.as_object().unwrap().len(), 0);
    }
}
