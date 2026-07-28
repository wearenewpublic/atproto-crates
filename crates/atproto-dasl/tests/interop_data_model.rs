//! Known-answer data-model conformance tests against the upstream interop vectors.
//!
//! Each vector pairs an AT Protocol JSON value with the exact DAG-CBOR bytes it
//! must encode to and the CID those bytes must hash to. That makes them an
//! external oracle: unlike the round-trip and proptest suites in this crate,
//! which only prove the encoder and decoder agree with each other, these can
//! detect an encoding that is self-consistent and wrong.
//!
//! The entry point under test is `atproto_json::to_vec`, not the generic
//! `to_vec`. AT Protocol's JSON representation spells links and byte strings as
//! reserved single-key objects, so encoding a `serde_json::Value` correctly
//! means reading it into the data model first. Teaching the generic serializer
//! to recognise those keys would change encoding for any type that happens to
//! have a `$link` field, which is action at a distance.
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
/// Vectors that do not pass yet, each mapped to the finding that explains it.
///
/// Keyed by the vector's index in `data-model-fixtures.json`, because the file
/// carries no per-vector name. Every entry here is a statement that a known,
/// filed defect is still open — never add one to silence a genuine regression.
///
/// Empty since the JSON representation is read into the data model before
/// encoding: `$link` becomes a link and `$bytes` a byte string, rather than
/// being encoded as literal maps with reserved keys.
const KNOWN_FAILURES: &[(usize, &str)] = &[];

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

        match atproto_dasl::atproto_json::to_vec(&vector.json) {
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

        match atproto_dasl::atproto_json::compute_cid(&vector.json) {
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

/// One entry of `data-model-valid.json` / `data-model-invalid.json`.
///
/// Both files describe whole records rather than bare values, and carry a
/// `note` naming the case.
#[derive(Deserialize)]
struct DataModelCase {
    note: String,
    json: Value,
}

/// Every value the data model admits must translate and encode.
#[test]
fn interop_data_model_valid() {
    let cases: Vec<DataModelCase> = load("data-model/data-model-valid.json");
    assert!(!cases.is_empty(), "data-model-valid.json is empty");

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = atproto_dasl::atproto_json::to_vec(&case.json) {
            failures.push(format!("{:?} should encode: {err}", case.note));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} valid cases were rejected:\n  {}",
        failures.len(),
        cases.len(),
        failures.join("\n  ")
    );
}

/// Values the data model cannot represent must be refused, not approximated.
///
/// Only the cases this layer is responsible for are asserted. The file also
/// covers record structure — a missing `$type`, a blob with a string `size` —
/// which is lexicon validation rather than encoding, and is not implemented
/// yet. Those are listed here by name so the exclusion is visible rather than
/// implied by a passing test.
#[test]
fn interop_data_model_invalid() {
    /// Cases this test deliberately does not cover, with the reason.
    const NOT_AN_ENCODING_CONCERN: &[&str] = &[
        "top-level not an object",
        "record with $type null",
        "record with $type wrong type",
        "record with empty $type string",
        "blob with string size",
        "blob with missing key",
    ];

    let cases: Vec<DataModelCase> = load("data-model/data-model-invalid.json");
    assert!(!cases.is_empty(), "data-model-invalid.json is empty");

    let mut failures = Vec::new();
    let mut checked = 0;
    for case in &cases {
        if NOT_AN_ENCODING_CONCERN.contains(&case.note.as_str()) {
            continue;
        }
        checked += 1;
        if atproto_dasl::atproto_json::to_vec(&case.json).is_ok() {
            failures.push(format!("{:?} should have been rejected", case.note));
        }
    }

    assert!(checked > 0, "every case was excluded; the filter is wrong");
    assert!(
        failures.is_empty(),
        "{} of {checked} encoding cases were accepted:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
