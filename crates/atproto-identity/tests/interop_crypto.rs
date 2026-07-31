//! The vendored crypto corpus, run against this crate's key and signature code.
//!
//! Three files, answering two questions this workspace could not otherwise ask
//! itself:
//!
//! * **`signature-fixtures.json`** — six signatures with a stated verdict,
//!   including the ones a conforming verifier must *refuse*: high-S, and
//!   DER-encoded. This crate's own signature tests sign and then verify, which
//!   proves the two halves agree with each other and says nothing about
//!   whether either agrees with the network. A round trip cannot produce a
//!   high-S signature here, because `sign` normalises — so the malleable twin
//!   is a case the crate can only meet from outside.
//! * **`w3c_didkey_{K256,P256}.json`** — private key bytes with the `did:key`
//!   they derive to. `key.rs` pins `did:key` literals for keys it generates,
//!   which fixes the format but not the derivation: a wrong multicodec prefix
//!   would round-trip cleanly through this crate and be unreadable everywhere
//!   else.

use atproto_identity::key::{KeyData, KeyType, identify_key, to_public, validate};
use base64::Engine as _;
// The corpus uses the standard base64 alphabet, not the URL-safe one: the
// signatures carry `/` and `+`. The reference reads them with `'base64'`.
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use serde::Deserialize;
use std::path::PathBuf;

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

/// One entry of `crypto/signature-fixtures.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureVector {
    comment: String,
    message_base64: String,
    algorithm: String,
    public_key_did: String,
    signature_base64: String,
    valid_signature: bool,
    tags: Vec<String>,
    public_key_multibase: String,
}

/// Every signature vector gets the verdict the corpus states.
///
/// The two negative classes are the point. `high-s` is the malleable twin of a
/// valid signature: the same key and message verify under it, so accepting it
/// lets a third party alter a signature's bytes without invalidating it.
/// `der-encoded` is the same signature in ASN.1 wrapping, which is what most
/// crypto libraries emit by default — accepting it would mean this workspace
/// disagreed with the network about what bytes a signature *is*.
#[test]
fn interop_signature_fixtures() {
    let vectors: Vec<SignatureVector> = load("crypto/signature-fixtures.json");
    assert_eq!(
        vectors.len(),
        6,
        "signature-fixtures.json should carry 6 vectors"
    );

    let mut wrong = Vec::new();
    let mut high_s = 0;
    let mut der = 0;

    for v in &vectors {
        let key = match identify_key(&v.public_key_did) {
            Ok(k) => k,
            Err(e) => {
                wrong.push(format!("{}: public key did not parse: {e}", v.comment));
                continue;
            }
        };
        let message = B64
            .decode(&v.message_base64)
            .expect("messageBase64 should be base64url");
        let signature = B64
            .decode(&v.signature_base64)
            .expect("signatureBase64 should be base64url");

        let accepted = validate(&key, &signature, &message).is_ok();
        if accepted != v.valid_signature {
            wrong.push(format!(
                "{} ({}): expected valid={}, got {accepted}",
                v.comment, v.algorithm, v.valid_signature
            ));
        }

        // The fixture states the same key twice, as a `did:key` and as a bare
        // multibase string. They must agree, or a vector could be verifying
        // against a key other than the one it names.
        //
        // The reference asserts this as
        // `expect(uint8arrays.equals(keyBytes, didKey.keyBytes))` with no
        // matcher attached, which passes whatever the comparison returns. It
        // is a real check here.
        match multibase::decode(&v.public_key_multibase) {
            Ok((_, bytes)) => {
                if bytes != key.bytes() {
                    wrong.push(format!(
                        "{}: publicKeyMultibase and publicKeyDid name different keys",
                        v.comment
                    ));
                }
            }
            Err(e) => wrong.push(format!(
                "{}: publicKeyMultibase did not decode: {e}",
                v.comment
            )),
        }

        if v.tags.iter().any(|t| t == "high-s") {
            high_s += 1;
        }
        if v.tags.iter().any(|t| t == "der-encoded") {
            der += 1;
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} signature vector(s) disagree with the corpus:\n  {}",
        wrong.len(),
        vectors.len(),
        wrong.join("\n  ")
    );

    // The negative classes are what this file is for; if a corpus bump dropped
    // them the test above would still pass and prove much less.
    assert_eq!(high_s, 2, "expected two high-S vectors");
    assert_eq!(der, 2, "expected two DER-encoded vectors");
}

/// One entry of `crypto/w3c_didkey_K256.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidKeyHexVector {
    private_key_bytes_hex: String,
    public_did_key: String,
}

/// One entry of `crypto/w3c_didkey_P256.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidKeyBase58Vector {
    private_key_bytes_base58: String,
    public_did_key: String,
}

/// K-256 private keys derive to the `did:key` the W3C vectors state.
#[test]
fn interop_didkey_k256() {
    let vectors: Vec<DidKeyHexVector> = load("crypto/w3c_didkey_K256.json");
    assert!(!vectors.is_empty(), "w3c_didkey_K256.json is empty");

    let mut wrong = Vec::new();
    for v in &vectors {
        let bytes =
            hex::decode(&v.private_key_bytes_hex).expect("privateKeyBytesHex should be hex");
        let derived = to_public(&KeyData::new(KeyType::K256Private, bytes))
            .expect("K-256 private key should yield a public key")
            .to_string();
        if derived != v.public_did_key {
            wrong.push(format!("expected {}, got {derived}", v.public_did_key));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} K-256 did:key derivation(s) disagree:\n  {}",
        wrong.len(),
        vectors.len(),
        wrong.join("\n  ")
    );
}

/// P-256 private keys derive to the `did:key` the W3C vectors state.
#[test]
fn interop_didkey_p256() {
    let vectors: Vec<DidKeyBase58Vector> = load("crypto/w3c_didkey_P256.json");
    assert!(!vectors.is_empty(), "w3c_didkey_P256.json is empty");

    let mut wrong = Vec::new();
    for v in &vectors {
        // base58btc, without a multibase prefix — these are raw key bytes, not
        // a multibase string, so the `z` marker is not present to be stripped.
        let bytes = multibase::Base::Base58Btc
            .decode(&v.private_key_bytes_base58)
            .expect("privateKeyBytesBase58 should be base58btc");
        let derived = to_public(&KeyData::new(KeyType::P256Private, bytes))
            .expect("P-256 private key should yield a public key")
            .to_string();
        if derived != v.public_did_key {
            wrong.push(format!("expected {}, got {derived}", v.public_did_key));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} P-256 did:key derivation(s) disagree:\n  {}",
        wrong.len(),
        vectors.len(),
        wrong.join("\n  ")
    );
}
