//! Known-answer data-model conformance tests against the upstream interop vectors.
//!
//! Each vector pairs an AT Protocol JSON value with the exact DAG-CBOR bytes it
//! must encode to and the CID those bytes must hash to. That makes them an
//! external oracle: unlike the round-trip and proptest suites in this crate,
//! which only prove the encoder and decoder agree with each other, these can
//! detect an encoding that is self-consistent and wrong.
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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

/// Vectors that do not pass yet, each mapped to the finding that explains it.
///
/// Keyed by the vector's index in `data-model-fixtures.json`, because the file
/// carries no per-vector name. Every entry here is a statement that a known,
/// filed defect is still open — never add one to silence a genuine regression.
const KNOWN_FAILURES: &[(usize, &str)] = &[
    // F-REPO-05 — the record encode path passes AT Protocol's JSON sentinel
    // objects through as ordinary maps instead of translating them to their
    // DAG-CBOR representations: `{"$link": "..."}` must become a CID under CBOR
    // tag 42, and `{"$bytes": "..."}` must become a byte string. Encoding them
    // as string-valued maps produces more bytes than the reference and a
    // different CID. See gap-analysis roadmap item M1.11.
    (1, "F-REPO-05"),
    (2, "F-REPO-05"),
];

/// Look up a vector in [`KNOWN_FAILURES`], returning the finding ID if listed.
fn known_failure(index: usize) -> Option<&'static str> {
    KNOWN_FAILURES
        .iter()
        .find(|(vector, _)| *vector == index)
        .map(|(_, finding)| *finding)
}

/// Read and deserialize a vendored interop vector file.
fn load<T: for<'de> Deserialize<'de>>(relative: &str) -> T {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/interop")
        .join(relative);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

/// One entry of `data-model/data-model-fixtures.json`.
#[derive(Deserialize)]
struct DataModelVector {
    /// The AT Protocol JSON representation of the value.
    json: Value,
    /// Base64 (standard alphabet, unpadded) of the canonical DAG-CBOR encoding.
    cbor_base64: String,
    /// The CIDv1 the DAG-CBOR bytes must hash to.
    cid: String,
}

/// Assert the DAG-CBOR bytes and CID of each vector against upstream answers.
#[test]
fn interop_data_model_fixtures() {
    let vectors: Vec<DataModelVector> = load("data-model/data-model-fixtures.json");
    assert!(
        !vectors.is_empty(),
        "data-model-fixtures.json is empty; the interop corpus may be missing"
    );

    let mut failures = Vec::new();

    for (index, vector) in vectors.iter().enumerate() {
        let expected_cbor = STANDARD_NO_PAD
            .decode(vector.cbor_base64.trim_end_matches('='))
            .unwrap_or_else(|err| panic!("#{index}: bad cbor_base64: {err}"));

        let mut mismatches = Vec::new();

        match atproto_dasl::to_vec(&vector.json) {
            Ok(actual_cbor) => {
                if actual_cbor != expected_cbor {
                    mismatches.push(format!(
                        "DAG-CBOR: expected {} bytes {}, got {} bytes {}",
                        expected_cbor.len(),
                        hex::encode(&expected_cbor),
                        actual_cbor.len(),
                        hex::encode(&actual_cbor)
                    ));
                }
            }
            Err(err) => mismatches.push(format!("DAG-CBOR: encode failed: {err}")),
        }

        match atproto_dasl::compute_cid_for(&vector.json) {
            Ok(actual_cid) => {
                let actual_cid = actual_cid.to_string();
                if actual_cid != vector.cid {
                    mismatches.push(format!("CID: expected {}, got {actual_cid}", vector.cid));
                }
            }
            Err(err) => mismatches.push(format!("CID: compute failed: {err}")),
        }

        match (mismatches.is_empty(), known_failure(index)) {
            (true, None) => {}
            (false, Some(finding)) => {
                eprintln!("  XFAIL vector #{index} ({finding})");
                for line in &mismatches {
                    eprintln!("        {line}");
                }
            }
            (false, None) => failures.push(format!(
                "REGRESSION: vector #{index} fails and is not in KNOWN_FAILURES:\n    {}",
                mismatches.join("\n    ")
            )),
            (true, Some(finding)) => failures.push(format!(
                "vector #{index} now PASSES — {finding} appears to be fixed. \
                 Remove it from KNOWN_FAILURES in this file."
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "{} data-model vector(s) need attention:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
}
