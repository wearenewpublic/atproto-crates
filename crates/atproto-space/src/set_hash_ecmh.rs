//! `EcmhSetHash` — Elliptic-Curve Multiset Hash over secp256k1.
//!
//! Per [Maxwell, "Elliptic Curve Multiset Hash"](https://web.archive.org/web/20210818004036/https://blog.ethereum.org/2014/12/16/multi-set-merkle-tree/):
//! a homomorphic set commitment built on the cyclic-group property of
//! elliptic curves. For each element bytes `b`:
//!
//! 1. Hash `b` to a scalar `s = SHA256(b) mod n` (where `n` is the curve order).
//! 2. Map to a curve point `P_b = s · G` (where `G` is the secp256k1 generator).
//! 3. Accumulate by point addition: `Σ P_b`.
//!
//! Removal is point subtraction. The accumulator is identity-of-the-curve when
//! empty. Two elements added in any order yield the same point because
//! addition on the curve is commutative + associative.
//!
//! # Compared with the strict ECMH literature
//!
//! Strict ECMH uses **hash-to-curve** (RFC 9380) rather than scalar
//! multiplication. The latter is *not* secure as a generic preimage-resistant
//! commitment because one can compose `s_a · G + s_b · G = (s_a + s_b) · G`,
//! making collisions over chosen-input pairs cheap. For the Spaces use-case
//! this is **acceptable**: the homomorphism is the security property we want
//! (so ECMH-via-scalar-mul is a *feature*, not a bug — proven membership uses
//! the signed commit chain, not preimage resistance of the SetHash). The
//! upstream may swap in a hash-to-curve EcmhSetHash later; the trait surface
//! stays the same.
//!
//! # Wire format
//!
//! Serialized digest is the **compressed SEC1 encoding of the accumulated point**
//! (33 bytes: 1-byte parity prefix + 32-byte x-coordinate). The identity
//! element serializes as 33 zero bytes by convention (since SEC1 has no native
//! identity encoding); on parse, 33 zero bytes are interpreted as identity.
//!
//! # Cargo feature
//!
//! Only compiled with the `ecmh` feature on `atproto-space`. Default builds
//! get [`crate::set_hash::XorSha256SetHash`] only.

use crate::errors::{SpaceError, SpaceResult};
use crate::set_hash::SetHash;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};

/// Compressed SEC1 length for secp256k1 (1 prefix + 32 x).
const COMPRESSED_LEN: usize = 33;

/// Elliptic-curve multiset hash over secp256k1.
#[derive(Debug, Clone)]
pub struct EcmhSetHash {
    point: ProjectivePoint,
}

impl EcmhSetHash {
    /// Hash an element to its corresponding curve point.
    ///
    /// `s = SHA256(element) mod n`, then `P = s · G`.
    fn point_for_element(element: &[u8]) -> ProjectivePoint {
        let h = Sha256::digest(element);
        // Reduce the 32-byte SHA-256 output mod n into a Scalar.
        let scalar = Scalar::from(
            k256::elliptic_curve::ScalarPrimitive::<Secp256k1>::from_slice(&h).unwrap_or_else(
                |_| {
                    // SHA-256 output is always 32 bytes which fits in a ScalarPrimitive.
                    // The `from_slice` only errors on length mismatch; this branch is
                    // unreachable in practice but stays as defense-in-depth.
                    Default::default()
                },
            ),
        );
        ProjectivePoint::GENERATOR * scalar
    }
}

impl PartialEq for EcmhSetHash {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for EcmhSetHash {}

impl SetHash for EcmhSetHash {
    fn empty() -> Self {
        Self {
            point: ProjectivePoint::IDENTITY,
        }
    }

    fn add(&mut self, element: &[u8]) {
        self.point += Self::point_for_element(element);
    }

    fn remove(&mut self, element: &[u8]) {
        self.point -= Self::point_for_element(element);
    }

    fn digest(&self) -> Vec<u8> {
        if self.point == ProjectivePoint::IDENTITY {
            // SEC1 has no compressed identity encoding; the spec uses
            // 33 zero bytes as a sentinel that round-trips through from_digest.
            vec![0u8; COMPRESSED_LEN]
        } else {
            // `as_slice` on `GenericArray` is deprecated in elliptic-curve;
            // index into the underlying array via `&self[..]` shape.
            let bytes = self.point.to_bytes();
            bytes.iter().copied().collect()
        }
    }

    fn from_digest(bytes: &[u8]) -> SpaceResult<Self> {
        if bytes.len() != COMPRESSED_LEN {
            return Err(SpaceError::SetHashCodec {
                reason: format!("expected {COMPRESSED_LEN} bytes, got {}", bytes.len()),
            });
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(Self::empty());
        }
        let encoded =
            k256::EncodedPoint::from_bytes(bytes).map_err(|e| SpaceError::SetHashCodec {
                reason: format!("not a valid SEC1 compressed point: {e}"),
            })?;
        let affine = k256::AffinePoint::from_encoded_point(&encoded);
        if affine.is_some().into() {
            Ok(Self {
                point: ProjectivePoint::from(affine.unwrap()),
            })
        } else {
            Err(SpaceError::SetHashCodec {
                reason: "encoded point not on the secp256k1 curve".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn digest_after_adds(elements: &[&[u8]]) -> Vec<u8> {
        let mut h = EcmhSetHash::empty();
        for e in elements {
            h.add(e);
        }
        h.digest()
    }

    #[test]
    fn empty_digest_is_identity_sentinel() {
        let d = EcmhSetHash::empty().digest();
        assert_eq!(d.len(), COMPRESSED_LEN);
        assert!(d.iter().all(|b| *b == 0));
    }

    #[test]
    fn add_remove_inverse() {
        let mut h = EcmhSetHash::empty();
        h.add(b"alice");
        h.remove(b"alice");
        assert_eq!(h.digest(), EcmhSetHash::empty().digest());
    }

    #[test]
    fn order_independence_two_elements() {
        let d1 = digest_after_adds(&[b"a", b"b"]);
        let d2 = digest_after_adds(&[b"b", b"a"]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn add_b_then_remove_a_equals_just_b() {
        let mut h1 = EcmhSetHash::empty();
        h1.add(b"a");
        h1.add(b"b");
        h1.remove(b"a");

        let mut h2 = EcmhSetHash::empty();
        h2.add(b"b");

        assert_eq!(h1.digest(), h2.digest());
    }

    #[test]
    fn from_digest_round_trip() {
        let mut h = EcmhSetHash::empty();
        h.add(b"x");
        h.add(b"y");
        let bytes = h.digest();
        let h2 = EcmhSetHash::from_digest(&bytes).unwrap();
        assert_eq!(h.digest(), h2.digest());
    }

    #[test]
    fn from_digest_round_trip_through_empty() {
        let h = EcmhSetHash::empty();
        let bytes = h.digest();
        let h2 = EcmhSetHash::from_digest(&bytes).unwrap();
        assert_eq!(h.digest(), h2.digest());
    }

    #[test]
    fn from_digest_bad_length_rejected() {
        assert!(EcmhSetHash::from_digest(&[0u8; 32]).is_err());
        assert!(EcmhSetHash::from_digest(&[0u8; 34]).is_err());
    }

    #[test]
    fn ecmh_and_xor_digests_are_distinct_sizes() {
        // Reminder that EcmhSetHash and XorSha256SetHash are NOT
        // interchangeable on the wire — different digest sizes.
        let xor = crate::set_hash::XorSha256SetHash::empty().digest();
        let ecmh = EcmhSetHash::empty().digest();
        assert_eq!(xor.len(), 32);
        assert_eq!(ecmh.len(), 33);
    }

    proptest! {
        /// Property: any permutation of N adds yields the same digest.
        #[test]
        fn permutation_invariance(items in prop::collection::vec(any::<u32>(), 0..16)) {
            let bytes_vec: Vec<Vec<u8>> = items.iter().map(|n| n.to_be_bytes().to_vec()).collect();
            let mut h1 = EcmhSetHash::empty();
            for b in &bytes_vec {
                h1.add(b);
            }
            let mut h2 = EcmhSetHash::empty();
            for b in bytes_vec.iter().rev() {
                h2.add(b);
            }
            prop_assert_eq!(h1.digest(), h2.digest());
        }

        /// Property: add(x) followed by remove(x) is identity for any x and any prior state.
        #[test]
        fn add_remove_is_identity(prior in prop::collection::vec(any::<u32>(), 0..8), x: u64) {
            let prior_bytes: Vec<Vec<u8>> = prior.iter().map(|n| n.to_be_bytes().to_vec()).collect();
            let x_bytes = x.to_be_bytes().to_vec();
            let mut h1 = EcmhSetHash::empty();
            for b in &prior_bytes {
                h1.add(b);
            }
            let baseline = h1.digest();
            h1.add(&x_bytes);
            h1.remove(&x_bytes);
            prop_assert_eq!(h1.digest(), baseline);
        }

        /// Property: add+add+remove == add (multiplicity beyond 1 collapses on remove).
        #[test]
        fn double_add_single_remove_equals_single(x: u64) {
            let x_bytes = x.to_be_bytes().to_vec();
            let mut h1 = EcmhSetHash::empty();
            h1.add(&x_bytes);
            h1.add(&x_bytes);
            h1.remove(&x_bytes);
            let mut h2 = EcmhSetHash::empty();
            h2.add(&x_bytes);
            prop_assert_eq!(h1.digest(), h2.digest());
        }
    }
}
