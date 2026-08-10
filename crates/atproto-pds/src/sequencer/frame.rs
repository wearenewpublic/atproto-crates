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

/// Frame encoding selection for a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `xrpc.v0.cbor` — each WS message is a binary blob with two CBOR
    /// objects concatenated (header || body). The default, and what every
    /// existing consumer speaks.
    Cbor,
    /// Browser-dev: each WS message is a JSON text frame combining the
    /// header + body fields into one object. NOT spec-compliant, reachable
    /// only through the private `?encoding=json` query parameter.
    Json,
    /// `xrpc.v1.json` — one self-describing object per text frame.
    V1Json,
    /// `xrpc.v1.cbor` — the same object, serialized as DRISL-CBOR.
    V1Cbor,
}

/// The legacy subprotocol, and the default when nothing is negotiated.
pub const XRPC_V0_CBOR: &str = "xrpc.v0.cbor";
/// Proposal 0015's JSON subprotocol.
pub const XRPC_V1_JSON: &str = "xrpc.v1.json";
/// Proposal 0015's CBOR subprotocol, the same framing as [`XRPC_V1_JSON`].
pub const XRPC_V1_CBOR: &str = "xrpc.v1.cbor";

/// The lexicon these frames belong to.
///
/// Proposal 0015 requires the payload's `$type` to be the full
/// `<nsid>#<fragment>`, so that a frame can be handed to a lexicon decoder
/// without unwrapping. This module serves one subscription; a second would
/// have to carry its own NSID rather than borrow this one.
pub const SUBSCRIBE_REPOS_NSID: &str = "com.atproto.sync.subscribeRepos";

impl Encoding {
    /// Pick the subprotocol from a `Sec-WebSocket-Protocol` request header.
    ///
    /// Returns the encoding and the exact token to echo back, or `None` when
    /// the client offered nothing this server speaks -- including when it
    /// offered no header at all, which is every consumer written before
    /// proposal 0015 and must keep getting `xrpc.v0.cbor`.
    ///
    /// The client's order wins. It offers in preference order, and there is
    /// no reason for a server that speaks both to overrule it.
    #[must_use]
    pub fn negotiate_subprotocol(header: Option<&str>) -> Option<(Self, &'static str)> {
        let header = header?;
        header.split(',').find_map(|offered| match offered.trim() {
            XRPC_V1_JSON => Some((Self::V1Json, XRPC_V1_JSON)),
            XRPC_V1_CBOR => Some((Self::V1Cbor, XRPC_V1_CBOR)),
            XRPC_V0_CBOR => Some((Self::Cbor, XRPC_V0_CBOR)),
            _ => None,
        })
    }

    /// Pick an encoding from the optional `?encoding=` query param + the
    /// `Accept` header. CBOR is the default.
    ///
    /// A private extension that predates proposal 0015 and stays for the
    /// browser consoles that use it. [`Self::negotiate_subprotocol`] takes
    /// precedence: a client that negotiates a subprotocol has said what it
    /// speaks in the standard way, and a query parameter should not overrule
    /// the handshake.
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
    _did: &str,
    payload: &[u8],
    time: &str,
) -> Option<(Vec<u8>, bool)> {
    let t = type_tag(event_type);
    // The stored body is already the lexicon's event shape in DAG-CBOR; only
    // `seq` and `time` belong to the delivery rather than the event, so those
    // are spliced in here. Nothing is re-encoded through JSON, which is what
    // used to turn a `cid-link` into text and made `blocks` unrepresentable.
    let body_bytes = crate::sequencer::payload::splice_envelope(payload, seq, time).ok()?;

    match encoding {
        Encoding::Json => {
            // Browser-dev only, and not the wire format: JSON has no link or
            // byte-string type, so this rendering spells them with the
            // `$link` / `$bytes` sentinels.
            let body = atproto_dasl::atproto_json::from_slice(&body_bytes).ok()?;
            let frame = serde_json::json!({ "t": t, "seq": seq, "body": body });
            Some((frame.to_string().into_bytes(), true))
        }
        Encoding::Cbor => {
            let header = FrameHeader { op: 1, t };
            let mut out = atproto_dasl::to_vec(&header).ok()?;
            out.extend_from_slice(&body_bytes);
            Some((out, false))
        }
        Encoding::V1Json | Encoding::V1Cbor => v1_bytes(encoding, &v1_message(&body_bytes, &t)?),
    }
}

/// Wrap a lexicon message in proposal 0015's `v1` envelope.
///
/// The payload is the event itself with its full `$type`, so a consumer hands
/// it straight to a lexicon decoder. `v0` carried that discriminator in a
/// separate header object, which is the unwrapping step this removes.
fn v1_message(body_bytes: &[u8], type_tag: &str) -> Option<atproto_dasl::Ipld> {
    use atproto_dasl::Ipld;
    let Ipld::Map(mut payload) = atproto_dasl::from_slice::<Ipld>(body_bytes).ok()? else {
        return None;
    };
    let fragment = type_tag.strip_prefix('#').unwrap_or(type_tag);
    payload.insert(
        "$type".to_string(),
        Ipld::String(format!("{SUBSCRIBE_REPOS_NSID}#{fragment}")),
    );
    let mut frame = std::collections::BTreeMap::new();
    frame.insert("$type".to_string(), Ipld::String("message".to_string()));
    frame.insert("payload".to_string(), Ipld::Map(payload));
    Some(Ipld::Map(frame))
}

/// Proposal 0015's `v1` error frame.
fn v1_error(error: &str, message: &str) -> atproto_dasl::Ipld {
    use atproto_dasl::Ipld;
    let mut frame = std::collections::BTreeMap::new();
    frame.insert("$type".to_string(), Ipld::String("error".to_string()));
    frame.insert("error".to_string(), Ipld::String(error.to_string()));
    frame.insert("message".to_string(), Ipld::String(message.to_string()));
    Ipld::Map(frame)
}

/// Serialize a `v1` frame in whichever encoding was negotiated.
///
/// Returns the bytes and whether they are a text frame.
fn v1_bytes(encoding: Encoding, frame: &atproto_dasl::Ipld) -> Option<(Vec<u8>, bool)> {
    match encoding {
        Encoding::V1Json => Some((
            atproto_dasl::atproto_json::json_from_ipld(frame)
                .to_string()
                .into_bytes(),
            true,
        )),
        Encoding::V1Cbor => Some((atproto_dasl::to_vec(frame).ok()?, false)),
        Encoding::Cbor | Encoding::Json => None,
    }
}

/// Encode an `#info` **message** frame. Used for `OutdatedCursor` notices.
///
/// `#info` is a message, not an error: the stream continues after it. The
/// reference yields it through the ordinary message path
/// (`subscribeRepos.ts:33-36`), so it carries `op = 1` and `t = "#info"`, and
/// its body is `{name, message}`.
///
/// This previously emitted `op = -1` — the error opcode — while keeping the
/// `#info` type tag and body. That frame is neither shape: a consumer matching
/// on the opcode reads it as a fatal error and disconnects, and one matching on
/// `t` finds a type tag the error frame is not supposed to carry.
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
                op: 1,
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
        Encoding::V1Json | Encoding::V1Cbor => {
            // `#info` stays a message in v1 for the same reason it is one in
            // v0: the stream continues after it.
            let body = serde_json::json!({ "name": name, "message": message });
            atproto_dasl::to_vec(&body)
                .ok()
                .and_then(|bytes| v1_message(&bytes, "#info"))
                .and_then(|frame| v1_bytes(encoding, &frame))
                .unwrap_or_default()
        }
    }
}

/// Encode an XRPC error frame (`op = -1`).
///
/// The shape is fixed by the XRPC stream contract: the header carries the
/// opcode and **no** `t`, and the body is `{error, message}` — the error name is
/// what a client switches on (`packages/xrpc-server/src/stream/types.ts:14-20`).
/// An error frame terminates the subscription.
pub fn encode_error(encoding: Encoding, error: &str, message: &str) -> (Vec<u8>, bool) {
    match encoding {
        Encoding::Json => {
            let frame = serde_json::json!({ "error": error, "message": message });
            (frame.to_string().into_bytes(), true)
        }
        Encoding::Cbor => {
            // `FrameHeader` always serializes `t`, which an error frame must not
            // carry, so the header is built directly here.
            let header = serde_json::json!({ "op": -1 });
            let mut out = atproto_dasl::to_vec(&header).unwrap_or_default();
            let body = serde_json::json!({ "error": error, "message": message });
            if let Ok(body_bytes) = atproto_dasl::to_vec(&body) {
                out.extend_from_slice(&body_bytes);
            }
            (out, false)
        }
        Encoding::V1Json | Encoding::V1Cbor => {
            v1_bytes(encoding, &v1_error(error, message)).unwrap_or_default()
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

    /// A stored `#commit` body, as the write path produces one.
    fn commit_payload() -> Vec<u8> {
        crate::sequencer::payload::encode(&crate::sequencer::payload::CommitBody {
            rebase: false,
            too_big: false,
            repo: "did:plc:a".to_string(),
            commit: atproto_dasl::Cid(
                "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                    .parse()
                    .unwrap(),
            ),
            rev: "3kmev".to_string(),
            since: None,
            blocks: Vec::new(),
            ops: Vec::new(),
            blobs: Vec::new(),
            prev_data: None,
        })
        .unwrap()
    }

    #[test]
    fn json_frame_body_is_the_event_not_an_envelope() {
        let (bytes, is_text) = encode_event(
            Encoding::Json,
            "commit",
            42,
            "did:plc:a",
            &commit_payload(),
            "now",
        )
        .unwrap();
        assert!(is_text);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["t"], "#commit");
        assert_eq!(v["seq"], 42);

        let body = &v["body"];
        assert_eq!(body["repo"], "did:plc:a");
        assert_eq!(body["rev"], "3kmev");
        assert_eq!(body["seq"], 42);
        assert_eq!(body["time"], "now");
        // JSON has no link or byte-string type, so this rendering spells them.
        assert!(body["commit"]["$link"].is_string(), "{body}");
        assert!(body["blocks"]["$bytes"].is_string(), "{body}");
        assert!(body["payload"].is_null(), "the body is not an envelope");
        assert!(body["did"].is_null(), "#commit names the repository `repo`");
    }

    #[test]
    fn cbor_frame_carries_header_then_body() {
        let (bytes, is_text) = encode_event(
            Encoding::Cbor,
            "commit",
            42,
            "did:plc:a",
            &commit_payload(),
            "now",
        )
        .unwrap();
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
        let atproto_dasl::Ipld::Map(body) = atproto_dasl::from_slice(body_bytes).unwrap() else {
            panic!("a #commit body is a map")
        };
        assert_eq!(body["seq"], atproto_dasl::Ipld::Integer(42));
        assert_eq!(
            body["repo"],
            atproto_dasl::Ipld::String("did:plc:a".to_string())
        );
        assert_eq!(body["rev"], atproto_dasl::Ipld::String("3kmev".to_string()));
        assert_eq!(body["time"], atproto_dasl::Ipld::String("now".to_string()));
        // The wire body must carry links and bytes as links and bytes.
        assert!(matches!(body["commit"], atproto_dasl::Ipld::Link(_)));
        assert!(matches!(body["blocks"], atproto_dasl::Ipld::Bytes(_)));
        assert!(!body.contains_key("payload"), "{body:?}");
    }

    /// `#info` is a message frame, so `op = 1`.
    ///
    /// This test previously asserted `op = -1`, pinning the bug rather than the
    /// contract: `FrameType.Message = 1` and `FrameType.Error = -1`
    /// (`packages/xrpc-server/src/stream/types.ts:3-6`), and the reference
    /// yields `OutdatedCursor` through the ordinary message path
    /// (`subscribeRepos.ts:33-36`) because the stream continues after it.
    #[test]
    fn cbor_info_frame_is_a_message_frame() {
        let (bytes, is_text) = encode_info(Encoding::Cbor, "OutdatedCursor", "see ya");
        assert!(!is_text);
        let expected_header = FrameHeader {
            op: 1,
            t: "#info".to_string(),
        };
        let header_bytes = atproto_dasl::to_vec(&expected_header).unwrap();
        assert!(bytes.starts_with(&header_bytes));
        let body_bytes = &bytes[header_bytes.len()..];
        let body: serde_json::Value = atproto_dasl::from_slice(body_bytes).unwrap();
        assert_eq!(body["name"], "OutdatedCursor");
        assert_eq!(body["message"], "see ya");
    }

    /// An error frame carries `op = -1`, no `t`, and `{error, message}`.
    ///
    /// The error *name* is what a client switches on, so a frame that spells it
    /// `name` — as the `#info` body does — is unreadable to a conforming client
    /// even though it looks similar.
    #[test]
    fn cbor_error_frame_has_no_type_tag_and_names_the_error() {
        let (bytes, is_text) = encode_error(Encoding::Cbor, "FutureCursor", "too far");
        assert!(!is_text);

        // A frame is two concatenated CBOR objects, so each is decoded from its
        // own slice rather than the buffer as a whole.
        let header_bytes = atproto_dasl::to_vec(&serde_json::json!({ "op": -1 })).unwrap();
        assert!(
            bytes.starts_with(&header_bytes),
            "error frame header should be exactly {{op: -1}}"
        );
        let header: serde_json::Value = atproto_dasl::from_slice(&header_bytes).unwrap();
        assert_eq!(header["op"], -1, "error frames use the error opcode");
        assert!(
            header.get("t").is_none(),
            "an error frame must not carry a type tag: {header}"
        );

        let body: serde_json::Value =
            atproto_dasl::from_slice(&bytes[header_bytes.len()..]).unwrap();
        assert_eq!(body["error"], "FutureCursor");
        assert_eq!(body["message"], "too far");
    }

    #[test]
    fn json_error_frame_names_the_error() {
        let (bytes, is_text) = encode_error(Encoding::Json, "FutureCursor", "too far");
        assert!(is_text);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["error"], "FutureCursor");
        assert!(value.get("t").is_none());
    }

    /// A consumer that offers nothing gets the legacy protocol.
    ///
    /// Every consumer written before proposal 0015 sends no
    /// `Sec-WebSocket-Protocol` at all, and the proposal is explicit that the
    /// existing firehose is untouched: absent negotiation means
    /// `xrpc.v0.cbor`.
    #[test]
    fn no_offer_negotiates_nothing() {
        assert_eq!(Encoding::negotiate_subprotocol(None), None);
        assert_eq!(Encoding::negotiate_subprotocol(Some("")), None);
        assert_eq!(Encoding::negotiate_subprotocol(Some("graphql-ws")), None);
    }

    /// The client's preference order wins.
    ///
    /// It offers in preference order; a server that speaks both has no reason
    /// to overrule it. axum's own selection walks the *server's* list, which
    /// is why the handler passes only the token it picked here.
    #[test]
    fn the_clients_order_decides() {
        assert_eq!(
            Encoding::negotiate_subprotocol(Some("xrpc.v1.json, xrpc.v1.cbor")),
            Some((Encoding::V1Json, XRPC_V1_JSON))
        );
        assert_eq!(
            Encoding::negotiate_subprotocol(Some("xrpc.v1.cbor, xrpc.v1.json")),
            Some((Encoding::V1Cbor, XRPC_V1_CBOR))
        );
        assert_eq!(
            Encoding::negotiate_subprotocol(Some("graphql-ws, xrpc.v1.json")),
            Some((Encoding::V1Json, XRPC_V1_JSON)),
            "an unknown offer must not stop the search"
        );
    }

    /// A `v1` message is one self-describing object carrying the whole
    /// lexicon message.
    ///
    /// The point of the framing is that `payload` can go straight to a lexicon
    /// decoder: no separate header object, and a `$type` that names the
    /// fragment in full rather than the bare `#commit` tag `v0` puts in its
    /// header.
    #[test]
    fn a_v1_message_carries_the_full_type_and_no_header() {
        let body = atproto_dasl::to_vec(&serde_json::json!({ "seq": 42, "repo": "did:plc:a" }))
            .expect("body");
        let frame = v1_message(&body, "#commit").expect("frame");
        let (bytes, is_text) = v1_bytes(Encoding::V1Json, &frame).expect("json");
        assert!(is_text, "the JSON encoding travels in text frames");

        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(value["$type"], "message");
        assert_eq!(
            value["payload"]["$type"],
            "com.atproto.sync.subscribeRepos#commit"
        );
        assert_eq!(value["payload"]["seq"], 42);
        assert!(
            value.get("op").is_none() && value.get("t").is_none(),
            "v1 has no header fields: {value}"
        );
    }

    /// The two `v1` encodings are the same object, and only the serialization
    /// differs.
    #[test]
    fn the_v1_encodings_agree() {
        let body =
            atproto_dasl::to_vec(&serde_json::json!({ "seq": 7, "repo": "did:plc:a" })).unwrap();
        let frame = v1_message(&body, "#sync").expect("frame");

        let (json_bytes, json_is_text) = v1_bytes(Encoding::V1Json, &frame).unwrap();
        let (cbor_bytes, cbor_is_text) = v1_bytes(Encoding::V1Cbor, &frame).unwrap();
        assert!(json_is_text && !cbor_is_text);

        let from_json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        let from_cbor = atproto_dasl::atproto_json::json_from_ipld(
            &atproto_dasl::from_slice::<atproto_dasl::Ipld>(&cbor_bytes).unwrap(),
        );
        assert_eq!(from_json, from_cbor);
    }

    /// A `v1` error frame names the error and nothing else.
    #[test]
    fn a_v1_error_is_a_single_object() {
        let (bytes, is_text) = encode_error(Encoding::V1Json, "FutureCursor", "too far");
        assert!(is_text);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["$type"], "error");
        assert_eq!(value["error"], "FutureCursor");
        assert_eq!(value["message"], "too far");
    }

    /// `#info` stays a message in `v1`, because the stream continues after it.
    ///
    /// Emitting it as an error frame would tell a consumer to disconnect over
    /// a notice that its cursor was old.
    #[test]
    fn v1_info_is_a_message_not_an_error() {
        let (bytes, _) = encode_info(Encoding::V1Json, "OutdatedCursor", "resuming from the head");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["$type"], "message");
        assert_eq!(
            value["payload"]["$type"],
            "com.atproto.sync.subscribeRepos#info"
        );
        assert_eq!(value["payload"]["name"], "OutdatedCursor");
    }
}
