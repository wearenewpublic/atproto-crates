//! Known-answer MST conformance tests against the upstream interop vectors.
//!
//! Every other MST test in this workspace is a round trip: build a tree, encode
//! it, decode it, compare. A round trip proves the code agrees with itself. It
//! passes just as happily against a wrong encoding, which is precisely why
//! byte-level divergences survive into a release. These tests are the external
//! oracle — they compare against answers produced by the reference
//! implementation, so they can fail where a round trip cannot.
//!
//! Vectors are vendored at `tests/interop/`; see that directory's README for
//! provenance, licence and the upstream pin.
//!
//! # Known failures
//!
//! [`KNOWN_FAILURES`] names each vector this crate does not yet satisfy,
//! together with the gap-analysis finding that explains why. A listed vector is
//! **required to fail**: if it starts passing, the harness fails and tells you
//! to delete the entry, so the table cannot silently rot.

use atproto_dasl::Cid;
use atproto_dasl::storage::MemoryStorage;
use atproto_repo::mst::{Mst, common_prefix_len, key_height};
use serde::Deserialize;
use std::path::PathBuf;

/// Vectors that do not pass yet, each mapped to the finding that explains it.
///
/// Keyed by the vector's `comment` field in `commit-proof-fixtures.json`. Every
/// entry here is a statement that a known, filed defect is still open — never
/// add one to silence a genuine regression.
/// Vectors that do not pass yet, each mapped to the finding that explains it.
///
/// Keyed by the vector's `comment` field in `commit-proof-fixtures.json`. Every
/// entry here is a statement that a known, filed defect is still open — never
/// add one to silence a genuine regression.
///
/// Empty since height-aware insert with splitting and merging landed: all six
/// upstream commit-proof vectors match, before and after commit. F-REPO-01
/// corrected the node encoding and F-REPO-04 the tree shape; both were needed,
/// and neither alone moved a single vector.
const KNOWN_FAILURES: &[(&str, &str)] = &[];

/// Look up a vector in [`KNOWN_FAILURES`], returning the finding ID if listed.
fn known_failure(name: &str) -> Option<&'static str> {
    KNOWN_FAILURES
        .iter()
        .find(|(vector, _)| *vector == name)
        .map(|(_, finding)| *finding)
}

/// Absolute path to a file under the vendored `tests/interop/` corpus.
fn interop_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/interop")
        .join(relative)
}

/// Read and deserialize a vendored interop vector file.
fn load<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let path = interop_path(relative);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

/// Reconcile a vector's outcome against [`KNOWN_FAILURES`].
///
/// Records a hard failure when an unlisted vector fails (a regression) or when
/// a listed vector passes (a fix landed and the table is now stale).
fn reconcile(name: &str, mismatches: Vec<String>, failures: &mut Vec<String>) {
    match (mismatches.is_empty(), known_failure(name)) {
        (true, None) => {}
        (false, Some(finding)) => {
            eprintln!("  XFAIL {name} ({finding})");
            for line in &mismatches {
                eprintln!("        {line}");
            }
        }
        (false, None) => {
            failures.push(format!(
                "REGRESSION: vector {name:?} fails and is not in KNOWN_FAILURES:\n    {}",
                mismatches.join("\n    ")
            ));
        }
        (true, Some(finding)) => {
            failures.push(format!(
                "vector {name:?} now PASSES — {finding} appears to be fixed. \
                 Remove it from KNOWN_FAILURES in this file."
            ));
        }
    }
}

/// One entry of `mst/key_heights.json`: a key and its expected MST height.
#[derive(Deserialize)]
struct KeyHeightVector {
    key: String,
    height: u32,
}

/// One entry of `mst/common_prefix.json`: two keys and their shared prefix length.
#[derive(Deserialize)]
struct CommonPrefixVector {
    left: String,
    right: String,
    len: usize,
}

/// One entry of `firehose/commit-proof-fixtures.json`.
///
/// Only the root CIDs are asserted here. `blocksInProof` describes the covering
/// proof for Sync 1.1, which this workspace does not construct yet (F-FIRE-06,
/// roadmap item M2.26); asserting it belongs with that work.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitProofVector {
    comment: String,
    leaf_value: String,
    keys: Vec<String>,
    adds: Vec<String>,
    dels: Vec<String>,
    root_before_commit: String,
    root_after_commit: String,
    blocks_in_proof: Vec<String>,
}

#[test]
fn interop_key_heights() {
    let vectors: Vec<KeyHeightVector> = load("mst/key_heights.json");
    assert!(!vectors.is_empty(), "key_heights.json is empty");

    let mut failures = Vec::new();
    for vector in &vectors {
        let actual = key_height(&vector.key);
        if actual != vector.height {
            failures.push(format!(
                "key {:?}: expected height {}, got {actual}",
                vector.key, vector.height
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} key-height vectors failed:\n  {}",
        failures.len(),
        vectors.len(),
        failures.join("\n  ")
    );
}

#[test]
fn interop_common_prefix_len() {
    let vectors: Vec<CommonPrefixVector> = load("mst/common_prefix.json");
    assert!(!vectors.is_empty(), "common_prefix.json is empty");

    let mut failures = Vec::new();
    for vector in &vectors {
        let actual = common_prefix_len(&vector.left, &vector.right);
        if actual != vector.len {
            failures.push(format!(
                "({:?}, {:?}): expected {}, got {actual}",
                vector.left, vector.right, vector.len
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} common-prefix vectors failed:\n  {}",
        failures.len(),
        vectors.len(),
        failures.join("\n  ")
    );
}

/// Assert the MST root CID before and after a commit against upstream answers.
///
/// This is the test that makes F-REPO-01 provable. The root CID is the hash of
/// the encoded root node, so any divergence in the node encoding — an omitted
/// key, a wrong tag, a different tree shape — changes it. No round-trip test in
/// this workspace can observe that.
#[tokio::test]
async fn interop_commit_proof_roots() {
    let vectors: Vec<CommitProofVector> = load("firehose/commit-proof-fixtures.json");
    assert!(
        !vectors.is_empty(),
        "commit-proof-fixtures.json is empty; the interop corpus may be missing"
    );

    let mut failures = Vec::new();

    for vector in &vectors {
        let leaf: Cid = Cid(vector
            .leaf_value
            .parse()
            .unwrap_or_else(|err| panic!("{}: bad leafValue: {err}", vector.comment)));
        let mut mismatches = Vec::new();
        let mut tree: Mst<MemoryStorage> = Mst::new_in_memory();

        for key in &vector.keys {
            tree.insert(key, leaf.clone())
                .await
                .unwrap_or_else(|err| panic!("{}: insert {key:?} failed: {err}", vector.comment));
        }

        let actual_before = tree.root().map(ToString::to_string).unwrap_or_default();
        if actual_before != vector.root_before_commit {
            mismatches.push(format!(
                "rootBeforeCommit: expected {}, got {actual_before}",
                vector.root_before_commit
            ));
        }

        for key in &vector.adds {
            tree.insert(key, leaf.clone())
                .await
                .unwrap_or_else(|err| panic!("{}: add {key:?} failed: {err}", vector.comment));
        }
        for key in &vector.dels {
            tree.delete(key)
                .await
                .unwrap_or_else(|err| panic!("{}: del {key:?} failed: {err}", vector.comment));
        }

        let actual_after = tree.root().map(ToString::to_string).unwrap_or_default();
        if actual_after != vector.root_after_commit {
            mismatches.push(format!(
                "rootAfterCommit: expected {}, got {actual_after}",
                vector.root_after_commit
            ));
        }

        // The covering proof: the blocks an inductive consumer needs to verify
        // this commit's operations without holding the repository. Taken over
        // the post-commit tree and unioned across every touched key, matching
        // the reference (`packages/repo/src/repo.ts:145-152`).
        //
        // This is the assertion the fixtures exist for. Checking only the two
        // roots — which is all this test did before the proof was constructed —
        // says the tree ends up the right shape, not that a consumer can check
        // it, and those are the two different claims F-FIRE-06 was about.
        let mut proof: std::collections::HashMap<cid::Cid, Vec<u8>> =
            std::collections::HashMap::new();
        for key in vector.adds.iter().chain(vector.dels.iter()) {
            let blocks = tree.covering_proof(key).await.unwrap_or_else(|err| {
                panic!("{}: proof for {key:?} failed: {err}", vector.comment)
            });
            proof.extend(blocks);
        }

        let mut actual: Vec<String> = proof.keys().map(ToString::to_string).collect();
        actual.sort();
        let mut expected = vector.blocks_in_proof.clone();
        expected.sort();
        if actual != expected {
            let missing: Vec<_> = expected.iter().filter(|c| !actual.contains(c)).collect();
            let extra: Vec<_> = actual.iter().filter(|c| !expected.contains(c)).collect();
            mismatches.push(format!(
                "blocksInProof: {} expected, {} produced; missing {missing:?}; unexpected {extra:?}",
                expected.len(),
                actual.len()
            ));
        }

        reconcile(&vector.comment, mismatches, &mut failures);
    }

    assert!(
        failures.is_empty(),
        "{} commit-proof vector(s) need attention:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
}
