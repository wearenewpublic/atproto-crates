//! The vendored lexicon corpus, run against this crate's record and schema
//! validation.
//!
//! Two questions, from four vector files and a five-schema catalog:
//!
//! * **`record-data-{valid,invalid}.json`** — 53 records to validate against
//!   `lexicon/catalog/`. The invalid file is the substantial half at 50 cases,
//!   and it is the half this crate cannot ask itself: a validator's own tests
//!   tend to cover the rules their author remembered, and these cover the
//!   rules the protocol actually has.
//! * **`lexicon-{valid,invalid}.json`** — 10 lexicon *documents*, validated as
//!   schemas rather than as data. A schema that parses when it should not is
//!   worse than one that fails, because everything validated against it
//!   inherits the mistake.
//!
//! [`KNOWN_FAILURES`] names each case this crate does not yet satisfy. A listed
//! case is **required to fail**: if it starts passing, the harness fails and
//! tells you to delete the entry, so the table cannot silently rot.

use atproto_lexicon::validation::flags::ValidateFlags;
use atproto_lexicon::validation::schema_file::SchemaFile;
use atproto_lexicon::validation::validate::{BaseCatalog, validate_record};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

/// Cases that do not pass yet, as `(file, case name, why)`.
///
/// Two, out of 63. Each was read against the vector and the reference before
/// being recorded; none is a corpus quirk. They are pinned rather than fixed
/// here because the harness is what makes them visible, and landing it first
/// turns the other 59 into a gate immediately.
const KNOWN_FAILURES: &[(&str, &str, &str)] = &[
    // `unknown` and `ref` are *field* types, not definition types. A top-level
    // def of either is not a schema anything can be validated against, and
    // accepting it is worse than accepting a bad record: everything validated
    // against that schema inherits the mistake.
    (
        "lexicon/lexicon-invalid.json",
        "defined unknown",
        "a def of type `unknown` is accepted",
    ),
    (
        "lexicon/lexicon-invalid.json",
        "defined ref",
        "a def of type `ref` is accepted",
    ),
    // Same finding as the catalog schema that will not parse — see
    // `permission_set_namespace_authority_is_enforced_at_parse_time`.
    (
        "lexicon/lexicon-valid.json",
        "basic permission-set",
        "grants across authorities; refused by the Namespace Authority rule",
    ),
];

fn is_known_failure(file: &str, name: &str) -> bool {
    KNOWN_FAILURES
        .iter()
        .any(|(f, n, _)| *f == file && *n == name)
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

/// The five schemas the record vectors are validated against.
const CATALOG: &[&str] = &[
    "lexicon/catalog/permission-set.json",
    "lexicon/catalog/procedure.json",
    "lexicon/catalog/query.json",
    "lexicon/catalog/record.json",
    "lexicon/catalog/subscription.json",
];

/// Catalog schemas this crate cannot currently parse, with the reason.
///
/// Kept as a table rather than a panic so one unparseable schema does not
/// take the record vectors down with it — and so the failure is stated
/// rather than worked around silently.
const CATALOG_KNOWN_FAILURES: &[(&str, &str)] = &[(
    "lexicon/catalog/permission-set.json",
    "namespace authority enforced at parse time; see the test that pins this",
)];

/// Load the catalog, returning it alongside the schemas that failed to parse.
fn catalog_with_failures() -> (BaseCatalog, Vec<(String, String)>) {
    let mut catalog = BaseCatalog::new();
    let mut failed = Vec::new();
    for relative in CATALOG {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/interop")
            .join(relative);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        if let Err(err) = catalog.add_schema_json(&raw) {
            failed.push(((*relative).to_string(), format!("{err:?}")));
        }
    }
    (catalog, failed)
}

fn catalog() -> BaseCatalog {
    catalog_with_failures().0
}

/// One entry of `record-data-{valid,invalid}.json`.
#[derive(Deserialize)]
struct RecordVector {
    name: String,
    data: Value,
}

/// One entry of `lexicon-{valid,invalid}.json`.
#[derive(Deserialize)]
struct LexiconVector {
    name: String,
    lexicon: Value,
}

/// Every catalog schema parses.
///
/// Checked separately from the record vectors so that a broken catalog is
/// reported as a broken catalog, rather than as 53 failing records.
#[test]
fn interop_lexicon_catalog_parses() {
    let (catalog, failed) = catalog_with_failures();
    for id in [
        "example.lexicon.record",
        "example.lexicon.query",
        "example.lexicon.procedure",
        "example.lexicon.subscription",
    ] {
        assert!(
            catalog.get_schema(id).is_some(),
            "catalog should contain {id}"
        );
    }

    let unexpected: Vec<&(String, String)> = failed
        .iter()
        .filter(|(f, _)| !CATALOG_KNOWN_FAILURES.iter().any(|(k, _)| k == f))
        .collect();
    assert!(
        unexpected.is_empty(),
        "catalog schema(s) failed to parse unexpectedly: {unexpected:?}"
    );

    let fixed: Vec<&(&str, &str)> = CATALOG_KNOWN_FAILURES
        .iter()
        .filter(|(k, _)| !failed.iter().any(|(f, _)| f == k))
        .collect();
    assert!(
        fixed.is_empty(),
        "catalog schema(s) listed as known failures now parse — delete the entries: {fixed:?}"
    );
}

/// The one catalog schema this crate refuses, and exactly why.
///
/// `permission-set.json` grants over `com.example.calendar.*` while living at
/// `example.lexicon.permissionset`. That crosses to an unrelated authority,
/// which the [Namespace Authority](https://atproto.com/specs/permission#namespace-authority)
/// rule forbids: a set may address its own NSID group and children, never
/// siblings or parents.
///
/// So the vector is not conformant, and the refusal is correct. The
/// reference's `lexPermissionSet` schema does no namespace check at all —
/// its Zod type accepts any `resource` with arbitrary fields — so the corpus
/// records what that parser accepts rather than what the specification
/// permits, and the two differ here.
///
/// Pinned rather than "fixed": there is nothing to fix. The rule is enforced
/// deliberately, and the spec is explicit that it admits no exceptions —
/// authority is computed "without \"siblings\" or special namespaces".
#[test]
fn permission_set_namespace_authority_is_enforced_at_parse_time() {
    let (_, failed) = catalog_with_failures();
    let (file, reason) = failed
        .first()
        .expect("the permission-set schema should currently fail to parse");
    assert_eq!(file, "lexicon/catalog/permission-set.json");
    assert!(
        reason.contains("PermissionNsidOutsideNamespace"),
        "expected a namespace-authority refusal, got {reason}"
    );
}

/// Run one record file, collecting every disagreement rather than the first.
fn check_records(file: &str, expect_valid: bool) -> (usize, Vec<String>, Vec<String>) {
    let vectors: Vec<RecordVector> = load(file);
    assert!(!vectors.is_empty(), "{file} is empty");
    let catalog = catalog();

    let mut asserted = 0;
    let mut wrong = Vec::new();
    let mut fixed = Vec::new();

    for v in &vectors {
        let Some(nsid) = v.data.get("$type").and_then(Value::as_str) else {
            // A record with no `$type` cannot name a schema. That is itself a
            // reason to refuse it, and is one of the invalid cases.
            let agrees = !expect_valid;
            if is_known_failure(file, &v.name) {
                if agrees {
                    fixed.push(v.name.clone());
                }
                continue;
            }
            asserted += 1;
            if !agrees {
                wrong.push(format!("{}: record has no $type", v.name));
            }
            continue;
        };

        let accepted = validate_record(nsid, &v.data, &catalog, ValidateFlags::empty()).is_ok();
        let agrees = accepted == expect_valid;

        if is_known_failure(file, &v.name) {
            if agrees {
                fixed.push(v.name.clone());
            }
            continue;
        }

        asserted += 1;
        if !agrees {
            let verb = if expect_valid {
                "rejected a valid"
            } else {
                "accepted an invalid"
            };
            wrong.push(format!("{file}: {verb} record: {:?}", v.name));
        }
    }

    (asserted, wrong, fixed)
}

fn report(label: &str, results: Vec<(usize, Vec<String>, Vec<String>)>) {
    let mut asserted = 0;
    let mut wrong = Vec::new();
    let mut fixed = Vec::new();
    for (n, mut w, mut f) in results {
        asserted += n;
        wrong.append(&mut w);
        fixed.append(&mut f);
    }
    assert!(
        fixed.is_empty(),
        "{label}: {} case(s) listed in KNOWN_FAILURES now pass — delete the entries:\n  {}",
        fixed.len(),
        fixed.join("\n  ")
    );
    assert!(asserted > 0, "{label}: no cases were asserted");
    assert!(
        wrong.is_empty(),
        "{label}: {} of {asserted} case(s) disagree with the reference corpus:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}

/// Records the corpus calls valid are accepted; records it calls invalid are
/// refused.
#[test]
fn interop_record_data() {
    report(
        "record-data",
        vec![
            check_records("lexicon/record-data-valid.json", true),
            check_records("lexicon/record-data-invalid.json", false),
        ],
    );
}

/// Run one lexicon-document file.
fn check_lexicons(file: &str, expect_valid: bool) -> (usize, Vec<String>, Vec<String>) {
    let vectors: Vec<LexiconVector> = load(file);
    assert!(!vectors.is_empty(), "{file} is empty");

    let mut asserted = 0;
    let mut wrong = Vec::new();
    let mut fixed = Vec::new();

    for v in &vectors {
        let json = serde_json::to_string(&v.lexicon).expect("re-encoding a parsed value");
        let accepted = SchemaFile::parse(&json).is_ok();
        let agrees = accepted == expect_valid;

        if is_known_failure(file, &v.name) {
            if agrees {
                fixed.push(v.name.clone());
            }
            continue;
        }

        asserted += 1;
        if !agrees {
            let verb = if expect_valid {
                "rejected a valid"
            } else {
                "accepted an invalid"
            };
            wrong.push(format!("{file}: {verb} lexicon: {:?}", v.name));
        }
    }

    (asserted, wrong, fixed)
}

/// Lexicon documents the corpus calls valid parse as schemas; ones it calls
/// invalid are refused.
#[test]
fn interop_lexicon_documents() {
    report(
        "lexicon-documents",
        vec![
            check_lexicons("lexicon/lexicon-valid.json", true),
            check_lexicons("lexicon/lexicon-invalid.json", false),
        ],
    );
}
