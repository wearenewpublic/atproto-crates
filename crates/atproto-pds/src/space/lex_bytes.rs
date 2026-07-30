//! The atproto lex-data `bytes` wire form, `{"$bytes": "<base64>"}`.
//!
//! Lives here rather than beside the HTTP DTOs because both directions need it:
//! `notifyWrite` is *sent* by the writer, which is domain code, and *received*
//! by a handler. A single type serving both keeps the encoding in one place —
//! it is the kind of thing that quietly diverges when each side rolls its own.

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An atproto lex-data `bytes` value.
///
/// Standard base64 alphabet, unpadded — matching the encoding the rest of the
/// crate's `$bytes` values use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytesValue(pub Vec<u8>);

impl BytesValue {
    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the underlying bytes.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for BytesValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&self.0);
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &b64)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for BytesValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        // Accept padded input too. A peer that pads is still unambiguously
        // saying the same bytes, and refusing would drop a best-effort
        // notification over a formatting preference.
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(wire.bytes.trim_end_matches('='))
            .map_err(serde::de::Error::custom)?;
        Ok(BytesValue(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_form_is_a_dollar_bytes_object() {
        let v = BytesValue(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            serde_json::json!({"$bytes": "3q2+7w"})
        );
    }

    #[test]
    fn it_round_trips() {
        let v = BytesValue(vec![1, 2, 3, 250, 251, 252]);
        let json = serde_json::to_string(&v).unwrap();
        let back: BytesValue = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn padded_input_is_accepted() {
        // Refusing padding would drop a best-effort notification over a
        // formatting preference the peer is entitled to.
        let padded: BytesValue = serde_json::from_str(r#"{"$bytes":"3q2+7w=="}"#).unwrap();
        assert_eq!(padded.0, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn a_bare_string_is_not_a_bytes_value() {
        assert!(serde_json::from_str::<BytesValue>(r#""3q2+7w""#).is_err());
    }
}
