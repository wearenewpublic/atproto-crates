//! `/oauth/jwks` — JSON Web Key Set publication.
//!
//! Per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) the PDS
//! publishes the public form of every key it uses to sign OAuth-adjacent
//! JWTs (service-auth tokens, future ES256K access tokens, etc.). The
//! current OAuth access/refresh tokens are HS256-signed and so do not
//! appear here, but service-auth tokens and any account-level signing keys
//! the PDS holds are surfaced via the `account.signing_key_ref` mechanism
//! (each user's atproto signing key is published via their DID document,
//! not via this JWKS).
//!
//! The PDS-level signing key (used for federation, including the upcoming
//! ES256K-signed access tokens) is configured via `PDS_OAUTH_KEY_JWK` or
//! generated at first startup and cached under the `__pds_oauth__` key in
//! the [`KeyStore`](crate::keys::KeyStore). When present, this handler
//! publishes its public form; when absent, returns an empty `keys` array
//! (RFC 7517 §5 permits this and OAuth metadata still validates).

use crate::http::state::HttpState;
use atproto_identity::jwk::Jwk;
use atproto_identity::key::{KeyData, to_public};
use axum::Json;
use axum::extract::State;
use serde::Serialize;

/// JWKS shape per RFC 7517.
#[derive(Debug, Serialize)]
pub struct Jwks {
    /// Set of published JWKs.
    pub keys: Vec<serde_json::Value>,
}

/// Handler for `GET /oauth/jwks`.
///
/// Publishes the PDS service signing key plus any rotated historical keys
/// in JWK form. The current signer (`pds_signing_key`)
/// is published first; historical signers (`pds_extra_signing_keys`) follow
/// so consumers verifying tokens issued before a rotation still find the
/// matching `kid`. Each entry includes `use=sig`, an `alg` derived from the
/// key type (`ES256` for P-256, `ES256K` for K-256, `ES384` for P-384), and
/// a `kid` (key ID) derived from the JWK thumbprint so consumers can pin.
pub async fn jwks_handler(State(state): State<HttpState>) -> Json<Jwks> {
    let mut keys: Vec<serde_json::Value> = Vec::new();
    let mut seen_kids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut publish = |key: &KeyData| match key_to_jwk_value(key) {
        Ok(value) => {
            let kid = value
                .get("kid")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if seen_kids.insert(kid) {
                keys.push(value);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "JWKS: failed to publish a PDS signing key");
        }
    };
    if let Some(signing_key) = state.pds_signing_key.as_deref() {
        publish(signing_key);
    }
    for extra in &state.pds_extra_signing_keys {
        publish(extra.as_ref());
    }
    Json(Jwks { keys })
}

/// Convert a private/public KeyData into a JWK with `use=sig`, `alg`, `kid`.
///
/// If the input is a private key, only the public component is published.
fn key_to_jwk_value(key: &KeyData) -> Result<serde_json::Value, String> {
    let public = to_public(key).map_err(|e| format!("derive pub: {e}"))?;
    let jwk: Jwk = (&public).try_into().map_err(|e| format!("to jwk: {e}"))?;
    let mut value: serde_json::Value =
        serde_json::to_value(&jwk).map_err(|e| format!("serialize jwk: {e}"))?;

    let alg = atproto_identity::key::jws_alg(&public);
    value["use"] = serde_json::Value::String("sig".to_string());
    value["alg"] = serde_json::Value::String(alg.to_string());
    value["kid"] = serde_json::Value::String(thumbprint_kid(&value));
    Ok(value)
}

/// Compute the JWK thumbprint per RFC 7638 to use as the `kid`. The
/// thumbprint is `base64url(SHA256(canonical JSON of {crv, kty, x, y}))`.
fn thumbprint_kid(jwk: &serde_json::Value) -> String {
    use base64::{Engine as _, engine::general_purpose};
    use sha2::{Digest, Sha256};
    let canonical = serde_json::json!({
        "crv": jwk.get("crv").cloned().unwrap_or(serde_json::Value::Null),
        "kty": jwk.get("kty").cloned().unwrap_or(serde_json::Value::Null),
        "x":   jwk.get("x").cloned().unwrap_or(serde_json::Value::Null),
        "y":   jwk.get("y").cloned().unwrap_or(serde_json::Value::Null),
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Parse `PDS_OAUTH_KEYS_JWK_SET` into a vec of
/// `KeyData`. Format: standard JWKS `{"keys": [<jwk>, ...]}`. The first
/// entry is the *current* signer; subsequent entries are historical
/// rotations (kept in `/oauth/jwks` so consumers verifying older tokens
/// still find the matching `kid`). EC curves only (P-256 / P-384 /
/// secp256k1).
pub fn parse_jwk_set_env(raw: &str) -> anyhow::Result<Vec<atproto_identity::key::KeyData>> {
    use atproto_identity::jwk::{CRV_K256, CRV_P256, CRV_P384, Jwk};
    use atproto_identity::key::{KeyData, KeyType};
    use elliptic_curve::sec1::ToSec1Point;
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("parse JWK set JSON: {e}"))?;
    let keys = value
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("JWK set missing `keys` array"))?;
    let mut out: Vec<KeyData> = Vec::with_capacity(keys.len());
    for jwk in keys {
        // Unknown members are ignored rather than refused. Every real JWKS
        // carries `alg`, `use` and `kid` (RFC 7517 §4), and the previous type
        // rejected the whole document on the first one -- so this variable
        // only ever accepted keys hand-written down to the curve members.
        let parsed: Jwk =
            serde_json::from_value(jwk.clone()).map_err(|e| anyhow::anyhow!("parse JWK: {e}"))?;
        let scalar = parsed
            .private_scalar()
            .map_err(|e| anyhow::anyhow!("jwk private scalar: {e}"))?;
        let point = parsed
            .to_sec1_uncompressed()
            .map_err(|e| anyhow::anyhow!("jwk point: {e}"))?;
        // Re-derive through the curve type: this is what rejects a point that
        // is not on the curve, or a scalar outside the field order.
        let kd = match (parsed.crv(), scalar) {
            (CRV_P256, Some(d)) => {
                let secret = p256::SecretKey::from_slice(&d)
                    .map_err(|e| anyhow::anyhow!("P-256 priv from jwk: {e}"))?;
                KeyData::new(KeyType::P256Private, secret.to_bytes().to_vec())
            }
            (CRV_P256, None) => {
                let pk = p256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| anyhow::anyhow!("P-256 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::P256Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            (CRV_P384, Some(d)) => {
                let secret = p384::SecretKey::from_slice(&d)
                    .map_err(|e| anyhow::anyhow!("P-384 priv from jwk: {e}"))?;
                KeyData::new(KeyType::P384Private, secret.to_bytes().to_vec())
            }
            (CRV_P384, None) => {
                let pk = p384::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| anyhow::anyhow!("P-384 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::P384Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            (CRV_K256, Some(d)) => {
                let secret = k256::SecretKey::from_slice(&d)
                    .map_err(|e| anyhow::anyhow!("K-256 priv from jwk: {e}"))?;
                KeyData::new(KeyType::K256Private, secret.to_bytes().to_vec())
            }
            (CRV_K256, None) => {
                let pk = k256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| anyhow::anyhow!("K-256 pub from jwk: {e}"))?;
                KeyData::new(
                    KeyType::K256Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            (other, _) => return Err(anyhow::anyhow!("unsupported JWK curve {other}")),
        };
        out.push(kd);
    }
    if out.is_empty() {
        return Err(anyhow::anyhow!("JWK set is empty"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PDS_OAUTH_KEYS_JWK_SET` must accept a JWKS as actually published,
    /// meaning one carrying `use`, `alg` and `kid` alongside the curve members.
    ///
    /// It did not. The previous JWK type deserialised exactly `kty`, `crv`,
    /// `x`, `y`, `d` and failed the whole document on anything else --
    /// `unknown field 'alg'` -- so an operator pasting a real key set got a
    /// boot failure, and only a JWK hand-stripped to the curve members worked.
    /// The sibling parser in `oauth/par.rs` filtered the document first, which
    /// is why client keys were unaffected and this went unnoticed.
    #[test]
    fn a_jwk_set_with_standard_metadata_is_accepted() {
        let raw = r#"{"keys":[{
            "kty":"EC","crv":"P-256",
            "x":"axDH7SohQqaxQH009D3qxF5VXmNoVQ8e_naICf0bwhU",
            "y":"mJdQpagD5VImZJSJZCCYAM7wEgv4tMbFEI923RSr0TY",
            "use":"sig","alg":"ES256","kid":"AdbV1IYmdPHVnFFHV14jWlzgZaQErfd2IgTM0IdU-os"
        }]}"#;
        let keys = parse_jwk_set_env(raw).expect("a published JWKS must parse");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            *keys[0].key_type(),
            atproto_identity::key::KeyType::P256Public
        );
    }

    /// A JWK carrying `d` yields the private key type, so the PDS can sign
    /// with a key set supplied by configuration rather than only verify.
    #[test]
    fn a_jwk_set_entry_with_d_parses_as_a_private_key() {
        use atproto_identity::jwk::Jwk;
        use atproto_identity::key::{KeyType, generate_key};

        let key = generate_key(KeyType::P256Private).expect("generate");
        let jwk: Jwk = (&key).try_into().expect("to jwk");
        let raw = format!(
            r#"{{"keys":[{}]}}"#,
            serde_json::to_string(&jwk).expect("serialise")
        );
        let keys = parse_jwk_set_env(&raw).expect("private JWKS parses");
        assert_eq!(*keys[0].key_type(), KeyType::P256Private);
        assert_eq!(keys[0].bytes(), key.bytes(), "round trip must be lossless");
    }

    /// Byte-exact JWK output for three fixed keys, one per supported curve.
    ///
    /// The other tests here generate a random key, so they can only assert
    /// shape — that `crv` says `P-256`, that `d` is absent, that `kid` is
    /// longer than ten characters. None of them would notice if the encoding
    /// of `x` changed, and that is the part consumers depend on: `kid` is a
    /// thumbprint over `crv`/`kty`/`x`/`y`, so any change to how a coordinate
    /// is serialised silently republishes every key under a new `kid`, and a
    /// consumer pinning the old one stops verifying our signatures.
    ///
    /// These values were captured from this code, so they assert continuity
    /// rather than correctness against an external authority — a deliberate
    /// tripwire for a JWK implementation swapped in underneath. Changing one
    /// is a decision about the wire format, not a test fix.
    ///
    /// Compared as parsed JSON, not as text. Field order here is not ours to
    /// pin: `atproto-attestation` enables `serde_json/preserve_order`, so
    /// whether a `Map` is an `IndexMap` or a `BTreeMap` depends on feature
    /// unification, and this object serialises in insertion order when the
    /// whole workspace builds and alphabetically when this crate builds
    /// alone. Neither matters — JSON object order carries no meaning, and
    /// `kid` is computed over a canonical object built field by field below,
    /// so it comes out identical either way. Asserting on the text would have
    /// pinned an artefact of the build graph.
    #[test]
    fn jwk_publication_is_byte_stable_across_curves() {
        use atproto_identity::key::identify_key;

        // Fixed private keys. `key_to_jwk_value` publishes the public half.
        const CASES: &[(&str, &str, &str)] = &[
            (
                "P-256",
                "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o",
                r#"{"alg":"ES256","crv":"P-256","kid":"AdbV1IYmdPHVnFFHV14jWlzgZaQErfd2IgTM0IdU-os","kty":"EC","use":"sig","x":"axDH7SohQqaxQH009D3qxF5VXmNoVQ8e_naICf0bwhU","y":"mJdQpagD5VImZJSJZCCYAM7wEgv4tMbFEI923RSr0TY"}"#,
            ),
            (
                "secp256k1",
                "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt",
                r#"{"alg":"ES256K","crv":"secp256k1","kid":"-DJpwrHF5YfkUEgq62OuQdgfYohyG8ocVOXJX-_xrVg","kty":"EC","use":"sig","x":"F3U6z00iOii8rUJDfYmLVk-shOvzBIvbSQpPoUm6Qps","y":"_MplUy_ZPGLCTE5YexuzNbz43w5-zBUWUlifYC3I1MQ"}"#,
            ),
            (
                "P-384",
                "did:key:zEanKnNAasQo4KSsY1qvS4hjB35sZ9DNxszP2urnkoEbb716dbDr2mtbTktSJYKbLNxvP",
                r#"{"alg":"ES384","crv":"P-384","kid":"cZY4m1sY7DgqyomUfOt91QJRXawYG_meUI9uCrr3tIo","kty":"EC","use":"sig","x":"hbDIFhBNCQEKJjJriBW04DluKh9S93_rFPzEmrgzy8X4Fu23DHmqMwwrXZgdLB7s","y":"QLpTdgr3E2NfuAaPPtDoMUaTuk9GwQwOSm_BPvDfEvWnpXEAFlH0whDn_fcOEyEm"}"#,
            ),
        ];

        for (curve, did_key, expected) in CASES {
            let key = identify_key(did_key).expect("fixture key parses");
            let value = key_to_jwk_value(&key).expect("fixture key converts to a JWK");
            let expected: serde_json::Value =
                serde_json::from_str(expected).expect("golden value is valid JSON");
            assert_eq!(
                value, expected,
                "{curve}: published JWK changed. If this is intended, the `kid` changed with it \
                 and every consumer pinning the old one must be considered."
            );
            // `d` would publish the private scalar.
            assert!(
                value.get("d").is_none(),
                "{curve}: JWK must never carry the private component"
            );
        }
    }

    /// The `kid` is a thumbprint of the key material, so two different keys
    /// must not collide, and the same key must produce the same `kid` on
    /// every call. `jwks_handler` deduplicates published keys by `kid`, so a
    /// collision would silently drop a rotated signer from the JWKS.
    #[test]
    fn kid_is_distinct_per_key_and_stable_per_call() {
        use atproto_identity::key::identify_key;

        let dids = [
            "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o",
            "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt",
            "did:key:zEanKnNAasQo4KSsY1qvS4hjB35sZ9DNxszP2urnkoEbb716dbDr2mtbTktSJYKbLNxvP",
        ];
        let mut kids = Vec::new();
        for did in dids {
            let key = identify_key(did).expect("fixture key parses");
            let first = key_to_jwk_value(&key).expect("converts");
            let again = key_to_jwk_value(&key).expect("converts");
            assert_eq!(first["kid"], again["kid"], "kid must be stable per key");
            kids.push(first["kid"].as_str().expect("kid is a string").to_string());
        }
        let unique: std::collections::HashSet<&String> = kids.iter().collect();
        assert_eq!(
            unique.len(),
            kids.len(),
            "kid collision across keys: {kids:?}"
        );
    }

    #[test]
    fn key_to_jwk_value_for_p256() {
        use atproto_identity::key::{KeyType, generate_key};
        let priv_key = generate_key(KeyType::P256Private).unwrap();
        let value = key_to_jwk_value(&priv_key).unwrap();
        assert_eq!(value["use"], "sig");
        assert_eq!(value["alg"], "ES256");
        assert!(value["kid"].as_str().unwrap().len() > 10);
        assert_eq!(value["kty"], "EC");
        assert_eq!(value["crv"], "P-256");
        // Private-component fields must NOT be present.
        assert!(value.get("d").is_none(), "JWK must publish public-only");
    }

    #[test]
    fn key_to_jwk_value_for_k256() {
        use atproto_identity::key::{KeyType, generate_key};
        let priv_key = generate_key(KeyType::K256Private).unwrap();
        let value = key_to_jwk_value(&priv_key).unwrap();
        assert_eq!(value["alg"], "ES256K");
        assert_eq!(value["crv"], "secp256k1");
    }

    #[test]
    fn thumbprint_is_url_safe_base64() {
        let v = serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        });
        let kid = thumbprint_kid(&v);
        assert!(!kid.contains('+'));
        assert!(!kid.contains('/'));
        assert!(!kid.contains('='));
        // SHA-256 is 32 bytes → 43 chars in url-safe base64 no-pad.
        assert_eq!(kid.len(), 43);
    }
}
