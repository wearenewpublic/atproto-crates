//! Reading AT Protocol's JSON representation into the data model.
//!
//! The AT Protocol data model has one shape and two encodings. DAG-CBOR can
//! express links and byte strings directly; JSON cannot, so it spells them with
//! reserved single-key objects:
//!
//! | Data model | DAG-CBOR | JSON |
//! | --- | --- | --- |
//! | link | tag 42 | `{"$link": "bafy…"}` |
//! | bytes | byte string | `{"$bytes": "<base64>"}` |
//!
//! Handing a `serde_json::Value` straight to a DAG-CBOR encoder therefore does
//! *not* produce the record it describes. It produces a map with a literal
//! `$link` text key where a link belongs, which hashes to a CID no other
//! implementation computes and fails `blob`-typed validation downstream.
//!
//! [`ipld_from_json`] performs the translation, and [`to_vec`] /
//! [`compute_cid`] wrap it for the common cases.
//!
//! # Numbers
//!
//! The data model has no floating-point type. JSON does not distinguish `123`
//! from `123.0`, so an integral value written either way is an integer, while a
//! genuinely fractional one has no representation and is rejected. Both
//! behaviours are pinned by the upstream data-model fixtures.

use serde_json::Value;

use crate::cid::Cid;
use crate::errors::EncodeError;
use crate::value::Ipld;

/// Key naming a link in the JSON representation.
const LINK_KEY: &str = "$link";

/// Key naming a byte string in the JSON representation.
const BYTES_KEY: &str = "$bytes";

/// Translate AT Protocol JSON into the data model.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidValue`] for a number with a fractional part,
/// a malformed `$link` or `$bytes` object, or a link whose value is not a CID.
pub fn ipld_from_json(value: &Value) -> Result<Ipld, EncodeError> {
    match value {
        Value::Null => Ok(Ipld::Null),
        Value::Bool(b) => Ok(Ipld::Bool(*b)),
        Value::String(s) => Ok(Ipld::String(s.clone())),
        Value::Number(number) => number_to_ipld(number),
        Value::Array(items) => items
            .iter()
            .map(ipld_from_json)
            .collect::<Result<_, _>>()
            .map(Ipld::List),
        Value::Object(map) => {
            // A reserved key makes the whole object a link or a byte string,
            // and nothing else may accompany it — an extra key means the
            // sentinel was not what the writer meant, so guessing is worse
            // than refusing.
            if let Some(link) = map.get(LINK_KEY) {
                if map.len() != 1 {
                    return Err(invalid("$link object carries other keys"));
                }
                let Value::String(text) = link else {
                    return Err(invalid("$link value is not a string"));
                };
                let cid: Cid = text
                    .parse()
                    .map_err(|err| invalid(&format!("$link value is not a CID: {err}")))?;
                return Ok(Ipld::Link(cid));
            }
            if let Some(bytes) = map.get(BYTES_KEY) {
                if map.len() != 1 {
                    return Err(invalid("$bytes object carries other keys"));
                }
                let Value::String(text) = bytes else {
                    return Err(invalid("$bytes value is not a string"));
                };
                return decode_base64(text).map(Ipld::Bytes);
            }
            map.iter()
                .map(|(key, value)| Ok((key.clone(), ipld_from_json(value)?)))
                .collect::<Result<_, EncodeError>>()
                .map(Ipld::Map)
        }
    }
}

/// Render the data model back into AT Protocol's JSON representation.
///
/// The inverse of [`ipld_from_json`]: links and byte strings become their
/// reserved single-key objects, so a record survives a round trip through
/// storage unchanged.
///
/// Floats cannot arise from [`ipld_from_json`], but may appear in data decoded
/// from elsewhere; they are rendered as JSON numbers when finite.
#[must_use]
pub fn json_from_ipld(value: &Ipld) -> Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use serde_json::{Map, Number};

    match value {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(*b),
        Ipld::Integer(i) => i64::try_from(*i)
            .map(|i| Value::Number(Number::from(i)))
            .unwrap_or_else(|_| Value::String(i.to_string())),
        Ipld::Float(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
        Ipld::String(s) => Value::String(s.clone()),
        Ipld::Bytes(b) => {
            let mut map = Map::new();
            map.insert(
                BYTES_KEY.to_string(),
                Value::String(STANDARD_NO_PAD.encode(b)),
            );
            Value::Object(map)
        }
        Ipld::List(items) => Value::Array(items.iter().map(json_from_ipld).collect()),
        Ipld::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), json_from_ipld(value)))
                .collect(),
        ),
        Ipld::Link(cid) => {
            let mut map = Map::new();
            map.insert(LINK_KEY.to_string(), Value::String(cid.0.to_string()));
            Value::Object(map)
        }
    }
}

/// Decode canonical DAG-CBOR into AT Protocol's JSON representation.
///
/// # Errors
///
/// Returns [`crate::errors::DecodeError`] if the bytes are not valid DAG-CBOR.
pub fn from_slice(bytes: &[u8]) -> Result<Value, crate::errors::DecodeError> {
    Ok(json_from_ipld(&crate::from_slice::<Ipld>(bytes)?))
}

/// Encode AT Protocol JSON as canonical DAG-CBOR.
///
/// # Errors
///
/// Returns [`EncodeError`] if the value cannot be translated or encoded.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, EncodeError> {
    crate::to_vec(&ipld_from_json(value)?)
}

/// The CID of AT Protocol JSON encoded as canonical DAG-CBOR.
///
/// # Errors
///
/// Returns [`EncodeError`] if the value cannot be translated or encoded.
pub fn compute_cid(value: &Value) -> Result<cid::Cid, EncodeError> {
    crate::compute_cid_for(&ipld_from_json(value)?)
}

/// Map a JSON number onto the data model, which has no float type.
fn number_to_ipld(number: &serde_json::Number) -> Result<Ipld, EncodeError> {
    if let Some(unsigned) = number.as_u64() {
        return Ok(Ipld::Integer(i128::from(unsigned)));
    }
    if let Some(signed) = number.as_i64() {
        return Ok(Ipld::Integer(i128::from(signed)));
    }
    // Serde parses `123.0` as a float, but it names an integer and the data
    // model has nowhere else to put it. A fractional value has no
    // representation at all.
    let float = number
        .as_f64()
        .ok_or_else(|| invalid("number is out of range"))?;
    if float.fract() == 0.0 && float.is_finite() && float.abs() <= (i64::MAX as f64) {
        return Ok(Ipld::Integer(float as i128));
    }
    Err(invalid(&format!(
        "the data model has no floating-point type: {number}"
    )))
}

/// Decode the base64 body of a `$bytes` object.
///
/// The `$bytes` decoder, shared so that every layer agrees on what a `$bytes`
/// value is.
///
/// Standard alphabet, padding optional, and **trailing bits tolerated**.
///
/// The first two are uncontroversial: the specification's encoding is
/// unpadded, and encoders differ on whether to emit padding. The third is the
/// one worth explaining. A base64 value whose length is not a multiple of four
/// carries a few bits beyond the bytes it encodes, and those bits are not
/// necessarily zero — `"123"` decodes to two bytes with two bits left over.
/// The `base64` crate rejects that as non-canonical by default; JavaScript
/// does not, and neither does the interop corpus, which lists
/// `{"$bytes": "123"}` as a **valid** record.
///
/// A validator stricter than the network refuses records every other
/// implementation accepts, and that is the failure mode worth avoiding here.
/// Encoding remains canonical and unpadded, so nothing this workspace emits
/// depends on the tolerance.
static BYTES_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Decode a `$bytes` value.
///
/// See [`BYTES_ENGINE`] for what is accepted and why. Exposed so that
/// `atproto-lexicon` validates the same values this module can convert —
/// previously each had its own decoder and they disagreed, so a record could
/// pass validation and fail conversion, or the reverse.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidValue`] when the value is not base64 at all.
pub fn decode_bytes(text: &str) -> Result<Vec<u8>, EncodeError> {
    use base64::Engine as _;
    BYTES_ENGINE
        .decode(text)
        .map_err(|err| invalid(&format!("$bytes value is not base64: {err}")))
}

fn decode_base64(text: &str) -> Result<Vec<u8>, EncodeError> {
    decode_bytes(text)
}

fn invalid(reason: &str) -> EncodeError {
    EncodeError::InvalidValue {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CID_TEXT: &str = "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity";

    #[test]
    fn translates_a_link_sentinel_into_a_link() {
        let ipld = ipld_from_json(&json!({ "$link": CID_TEXT })).unwrap();
        assert!(matches!(ipld, Ipld::Link(_)), "got {ipld:?}");
    }

    #[test]
    fn translates_a_bytes_sentinel_into_bytes() {
        let ipld = ipld_from_json(&json!({ "$bytes": "aGVsbG8" })).unwrap();
        assert_eq!(ipld, Ipld::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn tolerates_padded_base64() {
        let ipld = ipld_from_json(&json!({ "$bytes": "aGVsbG8=" })).unwrap();
        assert_eq!(ipld, Ipld::Bytes(b"hello".to_vec()));
    }

    /// An integral value is an integer however it was written.
    #[test]
    fn accepts_an_integer_written_as_a_float() {
        assert_eq!(
            ipld_from_json(&json!(123.0)).unwrap(),
            Ipld::Integer(123),
            "123.0 names an integer"
        );
    }

    #[test]
    fn rejects_a_fractional_number() {
        let err = ipld_from_json(&json!(123.456)).expect_err("floats have no representation");
        assert!(err.to_string().contains("floating-point"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_sentinel() {
        for bad in [
            json!({ "$link": 1234 }),
            json!({ "$link": "." }),
            json!({ "$link": CID_TEXT, "other": "blah" }),
            json!({ "$bytes": [1, 2, 3] }),
            json!({ "$bytes": "aGVsbG8", "other": "blah" }),
        ] {
            assert!(ipld_from_json(&bad).is_err(), "{bad} should not translate");
        }
    }

    /// Sentinels nested anywhere are translated, not just at the top level.
    #[test]
    fn translates_sentinels_nested_in_structure() {
        let ipld = ipld_from_json(&json!({
            "images": [{ "image": { "$type": "blob", "ref": { "$link": CID_TEXT } } }]
        }))
        .unwrap();
        let Ipld::Map(root) = &ipld else {
            panic!("{ipld:?}")
        };
        let Ipld::List(images) = &root["images"] else {
            panic!()
        };
        let Ipld::Map(first) = &images[0] else {
            panic!()
        };
        let Ipld::Map(blob) = &first["image"] else {
            panic!()
        };
        assert!(matches!(blob["ref"], Ipld::Link(_)), "{blob:?}");
    }

    /// An ordinary object is left alone.
    #[test]
    fn passes_plain_structures_through() {
        let ipld = ipld_from_json(&json!({ "a": "b", "c": [1, true, null] })).unwrap();
        let Ipld::Map(map) = &ipld else { panic!() };
        assert_eq!(map["a"], Ipld::String("b".to_string()));
        assert_eq!(
            map["c"],
            Ipld::List(vec![Ipld::Integer(1), Ipld::Bool(true), Ipld::Null])
        );
    }
}
