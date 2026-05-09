//! `subscribeRepos` wire-frame encoders — JSON (debug) + CBOR (spec).
//!
//! Sync 1.1 specifies a binary WebSocket frame format: each message is a
//! single binary blob containing two consecutive DAG-CBOR objects:
//!
//! 1. **Header** — `{"op": 1, "t": "#<event_type>"}` (`op = -1` for errors).
//! 2. **Body** — the event-shape payload (different per `t`).
//!
//! Subscribers concatenated-decode the two CBOR objects from the same byte
//! buffer. The JSON encoder remains for browser-dev consumers and easy
//! cassette debugging, selectable via `?encoding=json` or
//! `Accept: application/json` on the WS upgrade.
//!
//! Spec defaults to CBOR — production peers (relays, app-views) require it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Frame encoding selection for a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Spec-default: each WS message is a binary blob with two CBOR
    /// objects concatenated (header || body).
    Cbor,
    /// Browser-dev: each WS message is a JSON text frame combining the
    /// header + body fields into one object. NOT spec-compliant.
    Json,
}

impl Encoding {
    /// Pick an encoding from the optional `?encoding=` query param + the
    /// `Accept` header. CBOR is the default.
    pub fn negotiate(encoding_query: Option<&str>, accept_header: Option<&str>) -> Self {
        if let Some(enc) = encoding_query {
            return match enc.to_ascii_lowercase().as_str() {
                "json" => Self::Json,
                _ => Self::Cbor,
            };
        }
        if let Some(accept) = accept_header {
            let lower = accept.to_ascii_lowercase();
            if lower.contains("application/json") && !lower.contains("application/cbor") {
                return Self::Json;
            }
        }
        Self::Cbor
    }
}

/// Per-event frame header — encoded as the first CBOR object in CBOR mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameHeader {
    /// `1` = event, `-1` = error frame (the body carries `{name, message}`).
    pub op: i8,
    /// Event-type tag with leading `#`, e.g. `#commit`, `#sync`, `#info`.
    pub t: String,
}

/// Hash-prefix the bare event-type discriminator string (`commit` →
/// `#commit`). Also recognizes already-prefixed input.
pub fn type_tag(event_type: &str) -> String {
    if event_type.starts_with('#') {
        event_type.to_string()
    } else {
        format!("#{event_type}")
    }
}

/// Encode an event into a single WebSocket payload (binary in CBOR mode,
/// text in JSON mode). The caller wraps the bytes in the appropriate
/// `axum::extract::ws::Message` variant.
///
/// Returns `Some((bytes, is_text))` where `is_text=true` indicates the
/// caller should send `Message::Text`; `false` means `Message::Binary`.
/// Returns `None` if the body bytes cannot be re-encoded to the target
/// format — the caller should drop the event with a warn-log.
pub fn encode_event(
    encoding: Encoding,
    event_type: &str,
    seq: i64,
    did: &str,
    payload_json: &[u8],
    time: &str,
) -> Option<(Vec<u8>, bool)> {
    let t = type_tag(event_type);
    match encoding {
        Encoding::Json => {
            let payload: Value = serde_json::from_slice(payload_json).unwrap_or(Value::Null);
            let frame = serde_json::json!({
                "t": t,
                "seq": seq,
                "did": did,
                "payload": payload,
                "time": time,
            });
            Some((frame.to_string().into_bytes(), true))
        }
        Encoding::Cbor => {
            // Header CBOR object.
            let header = FrameHeader { op: 1, t };
            let mut out = match atproto_dasl::to_vec(&header) {
                Ok(b) => b,
                Err(_) => return None,
            };
            // Body CBOR object — re-encode the JSON payload + envelope
            // fields into one DAG-CBOR map.
            //
            // Decoding the JSON to a `serde_json::Value` then re-encoding
            // to DAG-CBOR is lossy for byte-array fields (DAG-CBOR has a
            // distinct bytes type that JSON encodes as base64). Spec-shape
            // commit/sync payloads use CIDs (strings) and CARv1 bytes; for
            // now we wrap the JSON-decoded payload as-is. A follow-up that
            // teaches the writer side to store DAG-CBOR payloads directly
            // skips this round-trip.
            let payload_value: Value = serde_json::from_slice(payload_json).unwrap_or(Value::Null);
            let body = serde_json::json!({
                "seq": seq,
                "repo": did,
                "time": time,
                "payload": payload_value,
            });
            let body_bytes = match atproto_dasl::to_vec(&body) {
                Ok(b) => b,
                Err(_) => return None,
            };
            out.extend_from_slice(&body_bytes);
            Some((out, false))
        }
    }
}

/// Encode an `#info`-style error frame (`op = -1`). Used to send
/// `OutdatedCursor` / `InternalError` notices.
pub fn encode_info(encoding: Encoding, name: &str, message: &str) -> (Vec<u8>, bool) {
    match encoding {
        Encoding::Json => {
            let frame = serde_json::json!({
                "t": "#info",
                "name": name,
                "message": message,
            });
            (frame.to_string().into_bytes(), true)
        }
        Encoding::Cbor => {
            let header = FrameHeader {
                op: -1,
                t: "#info".to_string(),
            };
            let mut out = atproto_dasl::to_vec(&header).unwrap_or_default();
            let body = serde_json::json!({
                "name": name,
                "message": message,
            });
            if let Ok(body_bytes) = atproto_dasl::to_vec(&body) {
                out.extend_from_slice(&body_bytes);
            }
            (out, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_query_overrides_accept() {
        assert_eq!(
            Encoding::negotiate(Some("json"), Some("application/cbor")),
            Encoding::Json
        );
        assert_eq!(
            Encoding::negotiate(Some("cbor"), Some("application/json")),
            Encoding::Cbor
        );
    }

    #[test]
    fn negotiate_accept_header_only() {
        assert_eq!(
            Encoding::negotiate(None, Some("application/json")),
            Encoding::Json
        );
        // Spec default when nothing's provided.
        assert_eq!(Encoding::negotiate(None, None), Encoding::Cbor);
        // Mixed accept (browser sending */*) defaults to CBOR.
        assert_eq!(Encoding::negotiate(None, Some("*/*")), Encoding::Cbor);
    }

    #[test]
    fn type_tag_idempotent() {
        assert_eq!(type_tag("commit"), "#commit");
        assert_eq!(type_tag("#commit"), "#commit");
    }

    #[test]
    fn json_frame_carries_envelope_and_payload() {
        let payload = serde_json::to_vec(&serde_json::json!({"rev": "3kmev"})).unwrap();
        let (bytes, is_text) =
            encode_event(Encoding::Json, "commit", 42, "did:plc:a", &payload, "now").unwrap();
        assert!(is_text);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["t"], "#commit");
        assert_eq!(v["seq"], 42);
        assert_eq!(v["did"], "did:plc:a");
        assert_eq!(v["time"], "now");
        assert_eq!(v["payload"]["rev"], "3kmev");
    }

    #[test]
    fn cbor_frame_carries_header_then_body() {
        let payload = serde_json::to_vec(&serde_json::json!({"rev": "3kmev"})).unwrap();
        let (bytes, is_text) =
            encode_event(Encoding::Cbor, "commit", 42, "did:plc:a", &payload, "now").unwrap();
        assert!(!is_text);
        // The frame is the concatenation of two DAG-CBOR objects:
        //   header_bytes || body_bytes
        // Re-encode the expected header to learn its byte length, then
        // verify each half independently. (`atproto_dasl::from_reader`
        // rejects trailing data, so we can't decode both halves from the
        // same buffer in one pass — subscribers split the frame using a
        // streaming CBOR reader instead.)
        let expected_header = FrameHeader {
            op: 1,
            t: "#commit".to_string(),
        };
        let header_bytes = atproto_dasl::to_vec(&expected_header).unwrap();
        assert!(bytes.starts_with(&header_bytes));
        let header: FrameHeader = atproto_dasl::from_slice(&header_bytes).unwrap();
        assert_eq!(header.op, 1);
        assert_eq!(header.t, "#commit");
        let body_bytes = &bytes[header_bytes.len()..];
        let body: Value = atproto_dasl::from_slice(body_bytes).unwrap();
        assert_eq!(body["seq"], 42);
        assert_eq!(body["repo"], "did:plc:a");
        assert_eq!(body["time"], "now");
        assert_eq!(body["payload"]["rev"], "3kmev");
    }

    #[test]
    fn cbor_info_frame_uses_op_minus_one() {
        let (bytes, is_text) = encode_info(Encoding::Cbor, "OutdatedCursor", "see ya");
        assert!(!is_text);
        let expected_header = FrameHeader {
            op: -1,
            t: "#info".to_string(),
        };
        let header_bytes = atproto_dasl::to_vec(&expected_header).unwrap();
        assert!(bytes.starts_with(&header_bytes));
        let body_bytes = &bytes[header_bytes.len()..];
        let body: Value = atproto_dasl::from_slice(body_bytes).unwrap();
        assert_eq!(body["name"], "OutdatedCursor");
        assert_eq!(body["message"], "see ya");
    }
}
