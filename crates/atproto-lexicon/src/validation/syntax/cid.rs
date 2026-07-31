//! CID (Content Identifier) syntax validation
//!
//! Validates the lexicon `cid` string format: a CIDv1 whose multibase,
//! multicodec and multihash all decode, not merely a plausible-looking string.

use crate::validation::data_errors::DataValidationError;

fn invalid(value: &str, reason: impl Into<String>) -> DataValidationError {
    DataValidationError::StringFormatInvalid {
        format: "cid".to_string(),
        value: value.to_string(),
        reason: reason.into(),
    }
}

/// Validate a CID string.
///
/// The value must decode completely — multibase, then multicodec and
/// multihash — and be a CIDv1.
///
/// # Multibase
///
/// Base32lower (`b`) and base58btc (`z`) are accepted. That set is narrower
/// than multibase allows and wider than DASL requires, and both bounds are
/// deliberate.
///
/// This previously delegated to [`atproto_dasl::Cid`], which requires
/// base32lower because *the DASL spec* does. That is right for a CID used as a
/// DAG-CBOR link, and wrong here: this is the lexicon check for a CID
/// appearing as a **string field** in a record, which is a different question
/// with a different answer. Borrowing the link constraint made the PDS refuse
/// records that both reference implementations accept.
///
/// The two references do not agree on where the line falls. Indigo's
/// `syntax.ParseCID` is a character regex with no decoding at all —
/// documented as "an informal/incomplete helper... without parsing" — so it
/// accepts every multibase. The TypeScript lexicon calls `CID.parse`, which
/// auto-detects only base32, base36 and base58btc and throws on the rest. Both
/// accept base58btc, so refusing it was unambiguously wrong. Base16, base64
/// and base10 are contested between the references, and are left refused
/// rather than decided here.
///
/// # Errors
///
/// [`DataValidationError::StringFormatInvalid`] naming what failed to decode.
pub fn validate_cid(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(invalid(value, "CID cannot be empty"));
    }

    // Checked before decoding so an unsupported encoding is reported as such,
    // rather than as whatever the decoder makes of bytes it read under the
    // wrong alphabet.
    if !value.starts_with(['b', 'z']) {
        return Err(invalid(
            value,
            "CID must be base32lower (prefix 'b') or base58btc (prefix 'z')",
        ));
    }

    let cid = atproto_dasl::CidCore::try_from(value).map_err(|e| invalid(value, e.to_string()))?;

    // A bare `Qm...` is refused by the prefix gate above, but the version is
    // checked after decoding rather than inferred from the string, because the
    // prefix and the version are independent facts about the encoding.
    if cid.version() == atproto_dasl::CidVersion::V0 {
        return Err(invalid(value, "CIDv0 is not allowed; use CIDv1"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_cids() {
        let valid = [
            "bafyreidfayvfkicffzikfhbdrqvjobjzpmvcfc7kzbih2noclhf3vqywue",
            "bafyreie5cvv4h45feadgeuwhbcutmh6t7ceseocckahdoe6uat64zmz454",
        ];
        for cid in valid {
            assert!(validate_cid(cid).is_ok(), "should be valid: {}", cid);
        }
    }

    #[test]
    fn test_invalid_cids() {
        let invalid = [
            "",
            "not-a-cid",
            "QmYtUc4iTCbbfVSDNKvtQqrfyezPPnFvE33wFmutw9PBBk", // CIDv0 base58btc
            "baaaaaaa",   // valid base32lower chars but not a real CID
            "bafyfoobar", // starts with 'b' but invalid CID structure
        ];
        for cid in invalid {
            assert!(validate_cid(cid).is_err(), "should be invalid: {}", cid);
        }
    }

    /// base58btc (`z`) decodes, and both reference implementations accept it.
    ///
    /// Refusing it came from delegating to `atproto_dasl::Cid`, whose
    /// base32lower requirement is a DASL *link* constraint borrowed for a
    /// lexicon *string field* check.
    #[test]
    fn base58btc_cids_are_accepted() {
        for cid in [
            "zdj7WWeQ43G6JJvLWQWZpyHuAMq6uYWRjkBXFad11vE2LHhQ7",
            "zdj7WhuEjrB52m1BisYCtmjH1hSKa7yZ3jEZ9JcXaFRD51wVz",
        ] {
            assert!(validate_cid(cid).is_ok(), "should be valid: {cid}");
        }
    }

    /// Widening the multibase set did not weaken the decode.
    ///
    /// `z7x3CtScH765HvShXT` is base58btc and is in the corpus's *valid* file,
    /// but its multihash does not parse — indigo accepts it because indigo's
    /// helper does no decoding at all. Accepting anything that merely starts
    /// with `z` would have been the easy way to close one more vector.
    #[test]
    fn a_base58btc_string_that_does_not_decode_is_still_refused() {
        assert!(validate_cid("z7x3CtScH765HvShXT").is_err());
    }

    /// Multibase encodings outside base32lower and base58btc stay refused.
    ///
    /// The corpus calls these valid; the TypeScript lexicon's `CID.parse`
    /// rejects them too. Contested between the references, so not decided
    /// here.
    #[test]
    fn other_multibase_encodings_are_refused() {
        for cid in [
            "mBcDxtdWx0aWhhc2g+", // base64
            "f017012202c5f688262e0ece8569aa6f94d60aad55ca8d9d83734e4a7430d0cff6588ec2b", // base16
            "7134036155352661643226414134664076", // base10
        ] {
            assert!(validate_cid(cid).is_err(), "should be refused: {cid}");
        }
    }

    /// CIDv0 is refused after decoding, not by inspecting the prefix.
    ///
    /// A bare `Qm...` is caught by the multibase gate, but base58btc can also
    /// carry v0 bytes, so the version is a separate fact from the encoding.
    #[test]
    fn cidv0_is_refused_by_version_not_by_prefix() {
        let err = validate_cid("QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR").unwrap_err();
        let DataValidationError::StringFormatInvalid { .. } = &err else {
            panic!("unexpected error: {err:?}");
        };
    }
}
