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
//! > (DAG-CBOR) index mapping `'{collection}/{rkey}'` to record CID, with keys
//! > in canonical DAG-CBOR map order. Record blocks follow in the same order as
//! > their index entries. Blobs are not included and are fetched separately via
//! > getBlob."*
//!
//! So: header with `[commit_cid, index_cid]`, then the commit block, then the
//! index block, then record blocks ordered by `{collection}/{rkey}`.
//!
//! # The order is canonical, not lexicographic
//!
//! DAG-CBOR sorts map keys by their *encoded* bytes, and a definite-length text
//! string encodes its length first, so the effective order over the raw keys is
//! **shortest first, then bytewise** — not plain lexicographic. The two agree
//! only while every key is the same length. `c.d.e/apple` (11 bytes) precedes
//! `c.d.a/middle` (12) canonically and follows it lexicographically, and that
//! is reachable inside a single collection: rkey `b` sorts before rkey `ab`.
//!
//! The index gets this for free — the DRISL encoder sorts every map it writes —
//! so ordering the record blocks any other way produces a CAR that contradicts
//! its own index. [`RecordPath`] therefore carries the canonical order as its
//! `Ord`, which is what keeps the blocks and the index in step: they are
//! emitted from one `BTreeMap`, and the map's ordering is the format's.
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
    let mut sorted = SortedRecords::default();
    sorted.extend(records)?;
    build_repo_car_sorted(commit_block, sorted).await
}

/// A record's path within a repo (`{collection}/{rkey}`), ordered the way
/// DAG-CBOR orders map keys.
///
/// The order is the point of the type. DAG-CBOR compares *encoded* keys, and a
/// text string encodes its length ahead of its bytes, so keys sort shortest
/// first and only then bytewise — the opposite of `String`'s own `Ord` for any
/// pair whose lengths differ. Holding the paths in a `BTreeMap<RecordPath, _>`
/// makes the CAR's block order a property of the collection rather than
/// something the writer has to remember to sort, so it cannot drift from the
/// index the encoder canonicalises independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPath(String);

impl RecordPath {
    /// Build the path for a record.
    #[must_use]
    pub fn new(collection: &str, rkey: &str) -> Self {
        Self(format!("{collection}/{rkey}"))
    }

    /// The `{collection}/{rkey}` string, as it appears as an index key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for RecordPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Length first, then bytes: comparing the CBOR-encoded forms of two
        // definite-length text strings compares their length headers before
        // their contents, and a longer string always carries the larger
        // header.
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for RecordPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Records held in the order the CAR has to write them.
///
/// A `BTreeMap` because the sort is not optional: the format declares an index
/// root and requires the record blocks to follow in the same order as their
/// index entries, so every record has to be in hand before the first byte of
/// the header can be written. That is why an export is bounded by the size of
/// the repo rather than by a page — and why filling this incrementally, as the
/// pages arrive, is worth doing even though it cannot change that bound.
#[derive(Default)]
pub struct SortedRecords {
    by_key: BTreeMap<RecordPath, (cid::Cid, Vec<u8>)>,
}

impl SortedRecords {
    /// Add one page of records.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if a stored record CID does not parse.
    pub fn extend(&mut self, records: Vec<RecordRow>) -> PdsResult<()> {
        for row in records {
            let parsed: cid::Cid = row.cid.parse().map_err(|e: cid::Error| PdsError::Storage {
                reason: format!(
                    "stored permissioned record CID {} does not parse: {e}",
                    row.cid
                ),
            })?;
            self.by_key.insert(
                RecordPath::new(&row.collection, &row.rkey),
                (parsed, row.value),
            );
        }
        Ok(())
    }

    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether no records are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Total size of the record values, for the caller's own accounting.
    #[must_use]
    pub fn value_bytes(&self) -> usize {
        self.by_key.values().map(|(_, v)| v.len()).sum()
    }
}

/// [`build_repo_car`] over records a caller has already accumulated.
///
/// # Errors
///
/// As [`build_repo_car`].
pub async fn build_repo_car_sorted(
    commit_block: &[u8],
    sorted: SortedRecords,
) -> PdsResult<Vec<u8>> {
    let commit_cid = atproto_dasl::cid::compute_cid(commit_block);
    let by_key = sorted.by_key;

    // The index is a DRISL map of key -> link. Built through the atproto-JSON
    // encoder — the same one that produced these record CIDs — so `$link`
    // becomes CBOR tag 42 and the map keys come out canonically ordered. That
    // canonicalisation happens at encode time regardless of what order the
    // entries arrive in, which is why the block loop below has to sort the
    // same way rather than trusting insertion order: `RecordPath`'s `Ord` is
    // the one that has to agree with the encoder's.
    let index_json = serde_json::Value::Object(
        by_key
            .iter()
            .map(|(key, (cid, _))| {
                (
                    key.as_str().to_string(),
                    serde_json::json!({ "$link": cid.to_string() }),
                )
            })
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

    /// Byte offset of a key's encoded text-string form inside the index block.
    ///
    /// Reading the index back through `serde_json` would sort the keys again
    /// and prove nothing about the bytes on the wire. A key appears exactly
    /// once in the encoded map, so its offset orders the entries as a consumer
    /// streaming the block would see them.
    fn key_offset(index_bytes: &[u8], key: &str) -> usize {
        let needle = key.as_bytes();
        index_bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap_or_else(|| panic!("{key} does not appear in the encoded index"))
    }

    /// Record blocks follow in canonical DAG-CBOR key order — shortest key
    /// first, then bytewise — which is the order the index is encoded in.
    ///
    /// The dataset is chosen so the two candidate orders disagree.
    /// `c.d.a/middle` is 12 bytes and sorts *first* lexicographically but
    /// *last* canonically, so a writer draining a `BTreeMap<String, _>`
    /// emits blocks in an order its own index contradicts. That is a
    /// wire-format violation a consumer can detect and this test could not,
    /// because it used to assert the lexicographic order it was measuring.
    #[tokio::test]
    async fn record_blocks_follow_in_canonical_key_order() {
        // Records are handed in unsorted; the CAR must not be.
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        let rows = vec![
            row("c.d.e", "zebra", serde_json::json!({"v": 3})),
            row("c.d.e", "apple", serde_json::json!({"v": 1})),
            row("c.d.a", "middle", serde_json::json!({"v": 2})),
        ];
        // Length first, then bytes. Plain lexicographic would put
        // `c.d.a/middle` first.
        let expected = ["c.d.e/apple", "c.d.e/zebra", "c.d.a/middle"];
        assert_ne!(
            expected,
            {
                let mut lexicographic = expected;
                lexicographic.sort_unstable();
                lexicographic
            },
            "the dataset must distinguish canonical order from lexicographic"
        );
        let by_cid: BTreeMap<String, String> = rows
            .iter()
            .map(|r| (format!("{}/{}", r.collection, r.rkey), r.cid.clone()))
            .collect();

        let car = build_repo_car(&commit, rows).await.unwrap();
        let (_, blocks) = read_back(&car).await;
        // Skip the commit and index blocks.
        let record_cids: Vec<String> = blocks[2..].iter().map(|(c, _)| c.to_string()).collect();
        let expected_cids: Vec<String> = expected.iter().map(|k| by_cid[*k].clone()).collect();
        assert_eq!(record_cids, expected_cids);
    }

    /// The blocks and the index agree, whatever order that turns out to be.
    ///
    /// The two are produced by different code — the block loop walks the map,
    /// the index is sorted by the DRISL encoder as it writes — so agreement is
    /// a claim about both, not a restatement of either. Comparing them
    /// directly is what catches a change to one that does not reach the other.
    #[tokio::test]
    async fn the_blocks_arrive_in_the_order_the_index_lists_them() {
        let commit = atproto_dasl::atproto_json::to_vec(&serde_json::json!({"rev": "r"})).unwrap();
        // Mixed-length keys within one collection and across two, so the
        // agreement is not an accident of every key being the same size.
        let rows = vec![
            row("c.d.e", "b", serde_json::json!({"v": 1})),
            row("c.d.e", "ab", serde_json::json!({"v": 2})),
            row("c.d.a", "middle", serde_json::json!({"v": 3})),
            row("c.d.e", "zebra", serde_json::json!({"v": 4})),
        ];
        let cid_to_key: BTreeMap<String, String> = rows
            .iter()
            .map(|r| (r.cid.clone(), format!("{}/{}", r.collection, r.rkey)))
            .collect();

        let car = build_repo_car(&commit, rows).await.unwrap();
        let (roots, blocks) = read_back(&car).await;
        let index_bytes = blocks
            .iter()
            .find(|(c, _)| atproto_dasl::Cid::from(*c) == roots[1])
            .map(|(_, d)| d.clone())
            .expect("index block");

        let block_keys: Vec<String> = blocks[2..]
            .iter()
            .map(|(c, _)| cid_to_key[&c.to_string()].clone())
            .collect();
        let index_keys: Vec<String> = {
            let mut keys = block_keys.clone();
            keys.sort_by_key(|k| key_offset(&index_bytes, k));
            keys
        };
        assert_eq!(
            block_keys, index_keys,
            "record blocks must stream in the order the index lists them"
        );
        // And that shared order is the canonical one, not lexicographic.
        assert_eq!(
            block_keys,
            vec!["c.d.e/b", "c.d.e/ab", "c.d.e/zebra", "c.d.a/middle"],
        );
    }

    /// `RecordPath` orders by length before bytes, which is what makes the map
    /// it keys emit blocks in the encoder's order.
    #[test]
    fn record_path_orders_shortest_key_first() {
        let mut paths = [
            RecordPath::new("c.d.a", "middle"),
            RecordPath::new("c.d.e", "apple"),
            RecordPath::new("c.d.e", "b"),
        ];
        paths.sort();
        let ordered: Vec<&str> = paths.iter().map(RecordPath::as_str).collect();
        assert_eq!(ordered, vec!["c.d.e/b", "c.d.e/apple", "c.d.a/middle"]);

        // Equal lengths fall through to the bytewise comparison.
        assert!(RecordPath::new("c.d.e", "apple") < RecordPath::new("c.d.e", "zebra"));
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

    /// Paging an export does not rebuild the actor's pool per page.
    ///
    /// The audit read this as "two SQLite pools per 100-record page", which
    /// would make a 100k-record export two thousand pool builds and migration
    /// runs inside one request. That was true when it was written and is not
    /// now: every `SqlActorStore::open` reads through a process-wide pool
    /// cache, so the pages after the first cost a clone. Pinned here because
    /// the export is the path where losing that would be most expensive, and
    /// nothing else on it would notice.
    #[tokio::test(flavor = "multi_thread")]
    async fn paging_an_export_opens_the_actor_once() {
        use crate::actor_store::sql::{SqlActorStore, pools_built_for_did};
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:exportpaging";

        SqlActorStore::open(tmp.path(), did).await.unwrap();
        let after_first = pools_built_for_did(tmp.path(), did);

        // Twenty pages' worth of opens, which is what draining a 2,000-record
        // repo costs the export loop.
        for _ in 0..20 {
            SqlActorStore::open(tmp.path(), did).await.unwrap();
        }

        assert_eq!(
            pools_built_for_did(tmp.path(), did),
            after_first,
            "paging rebuilt the actor's pool; an export would pay a pool build \
             and a migration run per page"
        );
    }
}
