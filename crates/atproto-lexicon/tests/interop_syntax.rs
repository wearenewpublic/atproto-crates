//! The vendored syntax corpus, run against this crate's grammar validators.
//!
//! `crates/atproto-lexicon/src/validation/syntax/` implements a parser per
//! AT Protocol string grammar. Every test for them was written alongside the
//! parser it tests, which means each one encodes the same reading of the
//! grammar that the parser does — a round trip through one author's
//! understanding. These vectors are the external oracle: 536 cases that both
//! reference implementations run (atproto `packages/syntax/tests`, indigo
//! `atproto/syntax/*_test.go`), so agreeing with them is agreeing with the
//! network rather than with ourselves.
//!
//! Line format, matching the reference's `readInteropFile`: lines beginning
//! `#` are comments and empty lines are skipped. Nothing is trimmed — trailing
//! whitespace is part of a case, and several invalid vectors are invalid
//! precisely because of it.
//!
//! Three kinds of file:
//!
//! * `*_syntax_valid.txt` — the validator must accept.
//! * `*_syntax_invalid.txt` — the validator must reject.
//! * `*_parse_invalid.txt` — well-formed but semantically wrong, and the two
//!   grammars that have one want **opposite** answers. `datetime` folds the
//!   semantic check into validation, so `ensureValidDatetime` throws (month
//!   zero is not a datetime). `language` separates them: `isValidLanguage`
//!   returns *true* for a repeated variant subtag and only
//!   `parseLanguageString` returns null. Asserting one rule for both would
//!   manufacture a failure in whichever direction this crate got right.
//!
//! [`KNOWN_FAILURES`] names each case this crate does not yet satisfy. A listed
//! case is **required to fail**: if it starts passing, the harness fails and
//! tells you to delete the entry, so the table cannot silently rot.
//!
//! This file asserts *answers*, not *coverage*. Whether every vendored vector
//! file reaches a harness at all is checked from outside, against the corpus
//! directory — a reader that enumerates the directory it reads can only ever
//! confirm its own reach, so the question has to be asked somewhere that does
//! not depend on this file being complete.

use atproto_lexicon::validation::flags::ValidateFlags;
use atproto_lexicon::validation::syntax::{
    validate_at_identifier, validate_at_uri, validate_cid, validate_datetime, validate_did,
    validate_handle, validate_language, validate_nsid, validate_record_key, validate_tid,
    validate_uri,
};
use std::path::PathBuf;

/// Cases that do not pass yet, as `(file, case, why)`.
///
/// Keyed by the literal case text rather than a line number, so re-ordering or
/// a corpus bump does not silently re-point an entry at a different vector.
///
/// **31 of 536.** Every entry is a real disagreement with the network, not a
/// quirk of the corpus — each was read against the vector file's own comments
/// and against the grammar it comes from. They are pinned rather than fixed
/// here because the harness is what makes them visible: landing it first means
/// the remaining 505 cases become a gate immediately, and no fix can silently
/// regress one.
const KNOWN_FAILURES: &[(&str, &str, &str)] = &[
    // -- NSID -------------------------------------------------------------
    // The domain authority segments may begin with a digit; only the final
    // *name* segment may not. `org.4chan.lex.getThing` is a legitimate NSID
    // for a real domain, and an onion address is digits-first by construction.
    // Rejecting these refuses names that exist.
    (
        "syntax/nsid_syntax_valid.txt",
        "a.0.c",
        "digit-leading domain segment",
    ),
    (
        "syntax/nsid_syntax_valid.txt",
        "cn.8.lex.stuff",
        "digit-leading domain segment",
    ),
    (
        "syntax/nsid_syntax_valid.txt",
        "one.2.three",
        "digit-leading domain segment",
    ),
    (
        "syntax/nsid_syntax_valid.txt",
        "onion.2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.lex.deleteThing",
        "digit-leading domain segment (onion address)",
    ),
    (
        "syntax/nsid_syntax_valid.txt",
        "org.4chan.lex.getThing",
        "digit-leading domain segment",
    ),
    (
        "syntax/nsid_syntax_valid.txt",
        "test.12345.record",
        "digit-leading domain segment",
    ),
    // -- CID --------------------------------------------------------------
    // A CID is multibase-prefixed and base32 (`b`) is only the common case.
    // The corpus carries base58btc (`z`), base64 (`m`), base16 (`f`) and
    // base10 (`7`) — all legal, all rejected here.
    (
        "syntax/cid_syntax_valid.txt",
        "7134036155352661643226414134664076",
        "base10 multibase",
    ),
    (
        "syntax/cid_syntax_valid.txt",
        "f017012202c5f688262e0ece8569aa6f94d60aad55ca8d9d83734e4a7430d0cff6588ec2b",
        "base16 multibase",
    ),
    (
        "syntax/cid_syntax_valid.txt",
        "mBcDxtdWx0aWhhc2g+",
        "base64 multibase",
    ),
    (
        "syntax/cid_syntax_valid.txt",
        "z7x3CtScH765HvShXT",
        "base58btc multibase",
    ),
    (
        "syntax/cid_syntax_valid.txt",
        "zdj7WhuEjrB52m1BisYCtmjH1hSKa7yZ3jEZ9JcXaFRD51wVz",
        "base58btc multibase (CIDv0-style)",
    ),
    (
        "syntax/cid_syntax_valid.txt",
        "zdj7WWeQ43G6JJvLWQWZpyHuAMq6uYWRjkBXFad11vE2LHhQ7",
        "base58btc multibase (CIDv0-style)",
    ),
    // -- language ---------------------------------------------------------
    // Grandfathered irregular tags (RFC 5646 §2.2.8) are valid and are not
    // generated by the ordinary grammar, so they need an explicit list.
    (
        "syntax/language_syntax_valid.txt",
        "i-default",
        "grandfathered irregular tag",
    ),
    (
        "syntax/language_syntax_valid.txt",
        "i-navajo",
        "grandfathered irregular tag",
    ),
    // The corpus annotates this one itself: "private-use subtags are
    // case-insensitive (RFC 5646 §2.1.1)".
    (
        "syntax/language_syntax_valid.txt",
        "X-fr-CH",
        "uppercase private-use singleton",
    ),
    // The mirror image: an uppercase primary language subtag is *not*
    // accepted, where the private-use singleton is. Both implementations
    // agree on the asymmetry.
    (
        "syntax/language_syntax_invalid.txt",
        "JA",
        "uppercase primary language subtag",
    ),
    // -- TID --------------------------------------------------------------
    // A TID's first character encodes a clock identifier whose top bit must be
    // zero, so it is restricted to `234567abcdefghij`. `z...` and `k...` are
    // well-formed base32-sortable and still not TIDs.
    (
        "syntax/tid_syntax_invalid.txt",
        "kjzfcijpj2z2a",
        "first character out of range",
    ),
    (
        "syntax/tid_syntax_invalid.txt",
        "zzzzzzzzzzzzz",
        "first character out of range",
    ),
    // -- DID / at-identifier ----------------------------------------------
    // A `%` in the method-specific id must introduce a two-digit hex escape.
    // A bare trailing `%` is an incomplete escape.
    (
        "syntax/did_syntax_invalid.txt",
        "did:method:val%",
        "incomplete percent-escape",
    ),
    (
        "syntax/atidentifier_syntax_invalid.txt",
        "did:method:val%",
        "incomplete percent-escape (via DID)",
    ),
    // -- datetime ---------------------------------------------------------
    // RFC 3339 §4.3 makes `-00:00` mean "offset unknown", which the AT
    // Protocol datetime grammar excludes; `Z` or `+00:00` is required.
    (
        "syntax/datetime_syntax_invalid.txt",
        "1985-04-12T23:20:50.123-00:00",
        "negative zero UTC offset",
    ),
    // Year 0000 with a positive offset normalizes to before year 1.
    (
        "syntax/datetime_parse_invalid.txt",
        "0000-01-01T00:00:00+01:00",
        "normalizes below the representable range",
    ),
    // -- URI --------------------------------------------------------------
    // A raw space is never legal in a URI; it must be percent-encoded.
    // Trailing whitespace is the same defect, and is the more dangerous one
    // because it survives a careless copy-paste.
    (
        "syntax/uri_syntax_invalid.txt",
        "https://example.com/path gap",
        "raw space",
    ),
    (
        "syntax/uri_syntax_invalid.txt",
        "https://example.com/trailing-whitespace  ",
        "trailing whitespace",
    ),
];

fn is_known_failure(file: &str, case: &str) -> bool {
    KNOWN_FAILURES
        .iter()
        .any(|(f, c, _)| *f == file && *c == case)
}

/// Read a vendored vector file into its cases.
fn cases(file: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/interop")
        .join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let out: Vec<String> = raw
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(str::to_string)
        .collect();
    assert!(
        !out.is_empty(),
        "{} yielded no cases; the corpus may be missing",
        path.display()
    );
    out
}

/// What a file asserts about the validator's answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Accept,
    Reject,
}

/// Run one file against one validator, collecting **every** disagreement
/// rather than stopping at the first.
///
/// A grammar that is wrong is usually wrong about a class of input, and seeing
/// one case tells you much less than seeing the eleven that share a shape.
fn check(file: &str, expect: Expect, validate: impl Fn(&str) -> bool) -> (usize, Vec<String>) {
    let mut asserted = 0;
    let mut wrong = Vec::new();
    let mut fixed = Vec::new();

    for case in cases(file) {
        let accepted = validate(&case);
        let agrees = match expect {
            Expect::Accept => accepted,
            Expect::Reject => !accepted,
        };

        if is_known_failure(file, &case) {
            if agrees {
                fixed.push(case);
            }
            continue;
        }

        asserted += 1;
        if !agrees {
            let verb = if expect == Expect::Accept {
                "rejected a valid"
            } else {
                "accepted an invalid"
            };
            wrong.push(format!("{file}: {verb} case: {case:?}"));
        }
    }

    assert!(
        fixed.is_empty(),
        "{file}: {} case(s) listed in KNOWN_FAILURES now pass — delete the entries:\n  {}",
        fixed.len(),
        fixed.join("\n  ")
    );
    (asserted, wrong)
}

/// Run a grammar's whole file set and fail once with everything that
/// disagreed.
fn grammar(name: &str, files: &[(&str, Expect)], validate: impl Fn(&str) -> bool + Copy) {
    let mut asserted = 0;
    let mut wrong = Vec::new();
    for (file, expect) in files {
        let (n, mut w) = check(file, *expect, validate);
        asserted += n;
        wrong.append(&mut w);
    }
    assert!(asserted > 0, "{name}: no cases were asserted");
    assert!(
        wrong.is_empty(),
        "{name}: {} of {asserted} interop case(s) disagree with the reference corpus:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}

#[test]
fn interop_handle_syntax() {
    grammar(
        "handle",
        &[
            ("syntax/handle_syntax_valid.txt", Expect::Accept),
            ("syntax/handle_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_handle(v).is_ok(),
    );
}

#[test]
fn interop_did_syntax() {
    grammar(
        "did",
        &[
            ("syntax/did_syntax_valid.txt", Expect::Accept),
            ("syntax/did_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_did(v).is_ok(),
    );
}

#[test]
fn interop_at_identifier_syntax() {
    grammar(
        "at-identifier",
        &[
            ("syntax/atidentifier_syntax_valid.txt", Expect::Accept),
            ("syntax/atidentifier_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_at_identifier(v).is_ok(),
    );
}

#[test]
fn interop_nsid_syntax() {
    grammar(
        "nsid",
        &[
            ("syntax/nsid_syntax_valid.txt", Expect::Accept),
            ("syntax/nsid_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_nsid(v).is_ok(),
    );
}

#[test]
fn interop_at_uri_syntax() {
    grammar(
        "at-uri",
        &[
            ("syntax/aturi_syntax_valid.txt", Expect::Accept),
            ("syntax/aturi_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_at_uri(v).is_ok(),
    );
}

#[test]
fn interop_tid_syntax() {
    grammar(
        "tid",
        &[
            ("syntax/tid_syntax_valid.txt", Expect::Accept),
            ("syntax/tid_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_tid(v).is_ok(),
    );
}

#[test]
fn interop_record_key_syntax() {
    grammar(
        "record-key",
        &[
            ("syntax/recordkey_syntax_valid.txt", Expect::Accept),
            ("syntax/recordkey_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_record_key(v).is_ok(),
    );
}

/// `datetime_parse_invalid.txt` is **rejected**: the reference folds the
/// semantic check into validation, so `ensureValidDatetime` throws for month
/// zero even though the shape parses.
#[test]
fn interop_datetime_syntax() {
    grammar(
        "datetime",
        &[
            ("syntax/datetime_syntax_valid.txt", Expect::Accept),
            ("syntax/datetime_syntax_invalid.txt", Expect::Reject),
            ("syntax/datetime_parse_invalid.txt", Expect::Reject),
        ],
        // Strict flags: the corpus is the strict grammar, which is what
        // `ensureValidDatetime` enforces. `ALLOW_LENIENT_DATETIME` exists for
        // reading records already in the wild and would accept a chunk of
        // `datetime_syntax_invalid.txt` on purpose.
        |v| validate_datetime(v, ValidateFlags::empty()).is_ok(),
    );
}

/// `language_parse_invalid.txt` is **accepted**, unlike datetime's: the
/// reference's `isValidLanguage` returns true for a repeated variant subtag —
/// the string is well-formed BCP 47 — and only `parseLanguageString` returns
/// null. A validator that rejected these would be stricter than the network.
#[test]
fn interop_language_syntax() {
    grammar(
        "language",
        &[
            ("syntax/language_syntax_valid.txt", Expect::Accept),
            ("syntax/language_syntax_invalid.txt", Expect::Reject),
            ("syntax/language_parse_invalid.txt", Expect::Accept),
        ],
        |v| validate_language(v).is_ok(),
    );
}

#[test]
fn interop_uri_syntax() {
    grammar(
        "uri",
        &[
            ("syntax/uri_syntax_valid.txt", Expect::Accept),
            ("syntax/uri_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_uri(v).is_ok(),
    );
}

#[test]
fn interop_cid_syntax() {
    grammar(
        "cid",
        &[
            ("syntax/cid_syntax_valid.txt", Expect::Accept),
            ("syntax/cid_syntax_invalid.txt", Expect::Reject),
        ],
        |v| validate_cid(v).is_ok(),
    );
}
