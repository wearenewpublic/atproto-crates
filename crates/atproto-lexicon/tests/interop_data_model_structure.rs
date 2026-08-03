//! Record-structure cases from the vendored data-model corpus.
//!
//! `data-model-invalid.json` mixes two kinds of case. Most are encoding
//! concerns — a map key that is not a string, a float where the data model has
//! no floats — and `atproto-dasl`'s `interop_data_model` owns those. Six are
//! *record structure*: what a `$type` may be, what a blob must carry, and
//! whether a record may be something other than an object. Those are this
//! crate's responsibility, and `interop_data_model` lists them in
//! `NOT_AN_ENCODING_CONCERN` precisely so the split is visible rather than
//! implied.
//!
//! They were listed there and asserted nowhere. Four of the six were in fact
//! already rejected by `parse_json`; the exclusion comment's claim that they
//! were "not implemented yet" was true only of the other two. That is the
//! hazard a coverage gap hides in both directions — an unasserted rule may be
//! missing, or may be present and one refactor away from silently going away.
//!
//! [`ASSERTED_CASES`] names every case this file owns. The names are the same
//! strings `interop_data_model` excludes, so the two lists can be diffed
//! against each other and neither can drift without the other noticing.

use atproto_lexicon::validation::flags::ValidateFlags;
use atproto_lexicon::validation::parse::parse_record_json;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

/// The record-structure cases this file asserts, by corpus `note`.
///
/// Every name here must also appear in `interop_data_model`'s
/// `NOT_AN_ENCODING_CONCERN`: one list says "not mine", this one says "mine".
/// A case in neither is a case nothing checks.
const ASSERTED_CASES: &[&str] = &[
    "top-level not an object",
    "record with $type null",
    "record with $type wrong type",
    "record with empty $type string",
    "blob with string size",
    "blob with missing key",
];

#[derive(Debug, Deserialize)]
struct DataModelCase {
    note: String,
    json: Value,
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

#[test]
fn interop_data_model_structure_invalid() {
    let cases: Vec<DataModelCase> = load("data-model/data-model-invalid.json");
    assert!(!cases.is_empty(), "data-model-invalid.json is empty");

    let mut failures = Vec::new();
    let mut checked = 0;
    for case in &cases {
        if !ASSERTED_CASES.contains(&case.note.as_str()) {
            continue;
        }
        checked += 1;
        if parse_record_json(&case.json, ValidateFlags::default()).is_ok() {
            failures.push(format!("{:?} should have been rejected", case.note));
        }
    }

    // A name that no longer matches a vector would otherwise be silently
    // skipped, leaving the list covering nothing while still reading as
    // coverage.
    assert_eq!(
        checked,
        ASSERTED_CASES.len(),
        "ASSERTED_CASES names {} cases but only {checked} were found in the corpus — a name is stale",
        ASSERTED_CASES.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
