//! Minimal JWK representation for the EC curves this workspace signs with.
//!
//! [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) JSON Web Keys,
//! restricted to the `EC` key type over P-256, P-384 and secp256k1 — the three
//! curves `KeyType` covers. Ed25519 is `OKP` and is not represented here.
//!
//! This replaces `elliptic_curve::JwkEcKey`, which 0.14 removes along with the
//! `jwk` feature. RustCrypto's own successor, `jose-jwk`, is not a route out:
//! it was last published in 2023, pins `p256`/`p384` at 0.13 — the versions
//! this exists to move off — and depends on `rsa` 0.9, which carries
//! RUSTSEC-2023-0071 with no fixed release.
//!
//! The encoding is small enough to own. [RFC 7518 §6.2.1] defines `x` and `y`
//! as the affine coordinates, each base64url-encoded without padding and
//! left-padded to the curve's full coordinate size — 32 bytes for P-256 and
//! secp256k1, 48 for P-384. `d` is the private scalar, encoded the same way.
//! A public key is therefore the SEC1 uncompressed encoding (`0x04 || x || y`)
//! split in half, and reassembling one is the same operation backwards.
//!
//! The fixed width is the part worth care: a coordinate with leading zero
//! bytes must keep them. Dropping them still produces a decodable key, and
//! still verifies signatures, but changes the JWK thumbprint — which is the
//! `kid` this PDS publishes and the `jkt` a DPoP proof is bound to.
//!
//! [RFC 7518 §6.2.1]: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::errors::KeyError;

/// `crv` value for NIST P-256.
pub const CRV_P256: &str = "P-256";
/// `crv` value for NIST P-384.
pub const CRV_P384: &str = "P-384";
/// `crv` value for secp256k1, as used by AT Protocol `did:key` signing keys.
pub const CRV_K256: &str = "secp256k1";

/// Coordinate width in bytes for each supported curve.
fn coordinate_len(crv: &str) -> Option<usize> {
    match crv {
        CRV_P256 | CRV_K256 => Some(32),
        CRV_P384 => Some(48),
        _ => None,
    }
}

/// An elliptic-curve JSON Web Key.
///
/// Field order in the serialised form is not significant and is not relied
/// upon: `kid` is computed over a separately-built canonical object, and JSON
/// object order carries no meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type. Always `EC` for this type.
    pub kty: String,
    /// Curve name — one of [`CRV_P256`], [`CRV_P384`], [`CRV_K256`].
    pub crv: String,
    /// Base64url-encoded affine x coordinate.
    pub x: String,
    /// Base64url-encoded affine y coordinate.
    pub y: String,
    /// Base64url-encoded private scalar, when this JWK carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl Jwk {
    /// Build a public JWK from a curve name and the SEC1 encoding of a point.
    ///
    /// Accepts both the compressed (`0x02`/`0x03`) and uncompressed (`0x04`)
    /// forms; compressed input is rejected here rather than decompressed,
    /// because callers in this workspace hold uncompressed points and silently
    /// accepting a compressed one would produce a JWK with no `y`.
    pub fn from_sec1_uncompressed(crv: &str, point: &[u8]) -> Result<Self, KeyError> {
        let width = coordinate_len(crv).ok_or_else(|| KeyError::JWKConversionFailed {
            error: format!("unsupported curve for JWK: {crv}"),
        })?;
        if point.first() != Some(&0x04) || point.len() != 1 + 2 * width {
            return Err(KeyError::JWKConversionFailed {
                error: format!(
                    "expected an uncompressed SEC1 point of {} bytes for {crv}, got {}",
                    1 + 2 * width,
                    point.len()
                ),
            });
        }
        let (x, y) = point[1..].split_at(width);
        Ok(Self {
            kty: "EC".to_string(),
            crv: crv.to_string(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
            d: None,
        })
    }

    /// Attach a private scalar, left-padded to the curve's coordinate width.
    pub fn with_private_scalar(mut self, scalar: &[u8]) -> Result<Self, KeyError> {
        let width = coordinate_len(&self.crv).ok_or_else(|| KeyError::JWKConversionFailed {
            error: format!("unsupported curve for JWK: {}", self.crv),
        })?;
        if scalar.len() > width {
            return Err(KeyError::JWKConversionFailed {
                error: format!(
                    "private scalar of {} bytes is too wide for {}",
                    scalar.len(),
                    self.crv
                ),
            });
        }
        // Left-pad rather than encode as-is: a scalar that happens to start
        // with a zero byte must still encode to the curve's full width.
        let mut padded = vec![0u8; width - scalar.len()];
        padded.extend_from_slice(scalar);
        self.d = Some(URL_SAFE_NO_PAD.encode(&padded));
        Ok(self)
    }

    /// The `crv` value.
    pub fn crv(&self) -> &str {
        &self.crv
    }

    /// Reassemble the SEC1 uncompressed encoding (`0x04 || x || y`).
    ///
    /// Rejects coordinates that are not exactly the curve's width, rather than
    /// padding them. A short coordinate means the JWK was written by something
    /// that dropped leading zeros, and accepting it would let two encodings of
    /// one key produce two different thumbprints.
    pub fn to_sec1_uncompressed(&self) -> Result<Vec<u8>, KeyError> {
        let width = coordinate_len(&self.crv).ok_or_else(|| KeyError::JWKConversionFailed {
            error: format!("unsupported curve for JWK: {}", self.crv),
        })?;
        if self.kty != "EC" {
            return Err(KeyError::JWKConversionFailed {
                error: format!("expected kty=EC, got {}", self.kty),
            });
        }
        let x = decode_coordinate(&self.x, width, "x", &self.crv)?;
        let y = decode_coordinate(&self.y, width, "y", &self.crv)?;
        let mut out = Vec::with_capacity(1 + 2 * width);
        out.push(0x04);
        out.extend_from_slice(&x);
        out.extend_from_slice(&y);
        Ok(out)
    }

    /// The private scalar, when present.
    pub fn private_scalar(&self) -> Result<Option<Vec<u8>>, KeyError> {
        let Some(d) = self.d.as_deref() else {
            return Ok(None);
        };
        let width = coordinate_len(&self.crv).ok_or_else(|| KeyError::JWKConversionFailed {
            error: format!("unsupported curve for JWK: {}", self.crv),
        })?;
        Ok(Some(decode_coordinate(d, width, "d", &self.crv)?))
    }
}

/// Wipe the private scalar on drop, matching what `JwkEcKey` did.
///
/// Only `d` is cleared. `x` and `y` are the public point and are published in
/// the JWKS; treating them as secret would suggest they are.
#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Jwk {
    fn zeroize(&mut self) {
        use zeroize::Zeroize as _;
        if let Some(d) = &mut self.d {
            d.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for Jwk {}

fn decode_coordinate(
    value: &str,
    width: usize,
    field: &str,
    crv: &str,
) -> Result<Vec<u8>, KeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| KeyError::JWKConversionFailed {
            error: format!("JWK `{field}` is not base64url: {e}"),
        })?;
    if bytes.len() != width {
        return Err(KeyError::JWKConversionFailed {
            error: format!(
                "JWK `{field}` for {crv} must be {width} bytes, got {}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(width: usize, x_fill: u8, y_fill: u8) -> Vec<u8> {
        let mut p = vec![0x04];
        p.extend(std::iter::repeat_n(x_fill, width));
        p.extend(std::iter::repeat_n(y_fill, width));
        p
    }

    #[test]
    fn round_trips_an_uncompressed_point_for_each_curve() {
        for (crv, width) in [(CRV_P256, 32), (CRV_P384, 48), (CRV_K256, 32)] {
            let original = point(width, 0xAB, 0xCD);
            let jwk = Jwk::from_sec1_uncompressed(crv, &original).expect("encodes");
            assert_eq!(jwk.kty, "EC");
            assert_eq!(jwk.crv, crv);
            assert!(jwk.d.is_none());
            assert_eq!(jwk.to_sec1_uncompressed().expect("decodes"), original);
        }
    }

    /// A coordinate with leading zeros must keep its full width through the
    /// round trip. Trimming still yields a usable key but a different
    /// thumbprint, so it would silently change every published `kid`.
    #[test]
    fn leading_zero_coordinates_keep_their_width() {
        let mut original = vec![0x04];
        original.extend(std::iter::repeat_n(0x00, 4)); // x starts with zeros
        original.extend(std::iter::repeat_n(0x11, 28));
        original.extend(std::iter::repeat_n(0x00, 1)); // y too
        original.extend(std::iter::repeat_n(0x22, 31));

        let jwk = Jwk::from_sec1_uncompressed(CRV_P256, &original).expect("encodes");
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&jwk.x).unwrap().len(),
            32,
            "x must stay 32 bytes"
        );
        assert_eq!(jwk.to_sec1_uncompressed().expect("decodes"), original);
    }

    #[test]
    fn a_private_scalar_is_left_padded_to_the_curve_width() {
        let jwk = Jwk::from_sec1_uncompressed(CRV_P256, &point(32, 1, 2))
            .expect("encodes")
            .with_private_scalar(&[0x07])
            .expect("attaches");
        let d = jwk.private_scalar().expect("decodes").expect("present");
        assert_eq!(d.len(), 32, "scalar must be padded to the curve width");
        assert_eq!(d[31], 0x07);
        assert!(d[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_compressed_point_is_refused_rather_than_silently_halved() {
        let mut compressed = vec![0x02];
        compressed.extend(std::iter::repeat_n(0x11, 32));
        let err = Jwk::from_sec1_uncompressed(CRV_P256, &compressed).unwrap_err();
        assert!(format!("{err}").contains("uncompressed"), "{err}");
    }

    #[test]
    fn a_short_coordinate_is_refused() {
        let jwk = Jwk {
            kty: "EC".into(),
            crv: CRV_P256.into(),
            x: URL_SAFE_NO_PAD.encode([0x11; 31]), // one byte short
            y: URL_SAFE_NO_PAD.encode([0x22; 32]),
            d: None,
        };
        let err = jwk.to_sec1_uncompressed().unwrap_err();
        assert!(format!("{err}").contains("32 bytes"), "{err}");
    }

    #[test]
    fn public_jwks_omit_d_entirely() {
        let jwk = Jwk::from_sec1_uncompressed(CRV_P256, &point(32, 1, 2)).expect("encodes");
        let json = serde_json::to_string(&jwk).expect("serialises");
        assert!(
            !json.contains("\"d\""),
            "public JWK must not carry `d`: {json}"
        );
    }

    /// The private scalar is wiped; the public point is not, because it is
    /// published in the JWKS and pretending otherwise would be misleading.
    #[cfg(feature = "zeroize")]
    #[test]
    fn zeroize_clears_the_private_scalar_only() {
        use zeroize::Zeroize as _;
        let mut jwk = Jwk::from_sec1_uncompressed(CRV_P256, &point(32, 0xAA, 0xBB))
            .expect("encodes")
            .with_private_scalar(&[0x09; 32])
            .expect("attaches");
        let (x, y) = (jwk.x.clone(), jwk.y.clone());
        jwk.zeroize();
        assert!(
            jwk.d.as_deref().is_none_or(|d| d.bytes().all(|b| b == 0)),
            "private scalar must be wiped, got {:?}",
            jwk.d
        );
        assert_eq!(jwk.x, x, "public coordinates must be untouched");
        assert_eq!(jwk.y, y, "public coordinates must be untouched");
    }

    #[test]
    fn an_unsupported_curve_is_refused() {
        let err = Jwk::from_sec1_uncompressed("P-521", &point(66, 1, 2)).unwrap_err();
        assert!(format!("{err}").contains("unsupported curve"), "{err}");
    }
}
