//! Set hash primitives for permissioned-data spaces.
//!
//! The [`SetHash`] trait abstracts over a homomorphic, order-independent set
//! commitment. Two impls are planned:
//!
//! - [`XorSha256SetHash`] — XOR-of-SHA256 placeholder, matches the Spaces
//!   Design Spec's current default. Add and remove are both XOR (self-inverse),
//!   so add-then-remove reverts to the empty digest.
//! - `EcmhSetHash` — production target via the first-party `ecmh-rs` crate.
//!   Implemented in Phase 8 conditional on upstream picking ECMH (vs. ltHash).
//!
//! All impls share the same algebraic invariants:
//! - Order-independent: add(a); add(b) == add(b); add(a)
//! - Inverse: add(x); remove(x) returns to the prior digest
//! - Composable: digests can be compared by byte equality
//!
//! Different impls produce **different digest values** — a SetHash from one
//! impl is not comparable with another. The upstream picks one global default;
//! deployments mirror it.

use crate::errors::{SpaceError, SpaceResult};
use sha2::{Digest, Sha256};

/// Trait for set-hash commitment primitives.
///
/// Implementations must satisfy the algebraic invariants documented at the
/// crate level: order-independence, add/remove inverse, byte-equality of digests.
pub trait SetHash: Sized + Clone + Send + Sync {
    /// Construct an empty set hash.
    fn empty() -> Self;

    /// Add an element to the set.
    fn add(&mut self, element: &[u8]);

    /// Remove an element from the set.
    ///
    /// Removing an element that was never added (or removing more times than
    /// added) leaves the set in a "negative" state. Implementations must allow
    /// this — the algebra is total, not membership-checked. Use a separate
    /// membership data structure if you need that.
    fn remove(&mut self, element: &[u8]);

    /// Get the digest as raw bytes.
    fn digest(&self) -> Vec<u8>;

    /// Reconstruct from a serialized digest.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::SetHashCodec`] if the bytes do not deserialize
    /// for this impl's expected digest size or shape.
    fn from_digest(bytes: &[u8]) -> SpaceResult<Self>;
}

/// XOR-of-SHA256 set hash — the Spaces Design Spec's current placeholder primitive.
///
/// Hashes each element with SHA-256, then XOR-folds the 32-byte digest into
/// the running accumulator. Add and remove are both XOR (self-inverse), so
/// the algebra is naturally homomorphic over multiset deltas.
///
/// **Not cryptographically strong** — XOR-of-hash is forgeable by anyone who
/// can choose `~2^128` element pairs (birthday-bound). The Spec marks this as
/// "to be replaced by ECMH or ltHash before production."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorSha256SetHash([u8; 32]);

impl XorSha256SetHash {
    /// Construct from raw 32-byte digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the digest as a fixed-size array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SetHash for XorSha256SetHash {
    fn empty() -> Self {
        Self([0u8; 32])
    }

    fn add(&mut self, element: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(element);
        let h = hasher.finalize();
        for (i, b) in h.iter().enumerate() {
            self.0[i] ^= *b;
        }
    }

    fn remove(&mut self, element: &[u8]) {
        // XOR is self-inverse: remove == add.
        self.add(element);
    }

    fn digest(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_digest(bytes: &[u8]) -> SpaceResult<Self> {
        if bytes.len() != 32 {
            return Err(SpaceError::SetHashCodec {
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }
}

/// Format the spec-defined element bytes for a record entry in the SetHash.
///
/// records are hashed as
/// `<collection>/<rkey>:<cid>` (UTF-8 bytes).
#[must_use]
pub fn record_element_bytes(collection: &str, rkey: &str, cid: &str) -> Vec<u8> {
    format!("{collection}/{rkey}:{cid}").into_bytes()
}

/// Format the spec-defined element bytes for a member entry in the SetHash.
///
/// members are hashed as
/// the DID's UTF-8 bytes.
#[must_use]
pub fn member_element_bytes(did: &str) -> Vec<u8> {
    did.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Helper: apply a sequence of adds and check the digest after permutation.
    fn digest_after_adds(elements: &[&[u8]]) -> Vec<u8> {
        let mut h = XorSha256SetHash::empty();
        for e in elements {
            h.add(e);
        }
        h.digest()
    }

    #[test]
    fn empty_digest_is_zero() {
        assert_eq!(XorSha256SetHash::empty().digest(), vec![0u8; 32]);
    }

    #[test]
    fn add_remove_inverse() {
        let mut h = XorSha256SetHash::empty();
        h.add(b"alice");
        h.remove(b"alice");
        assert_eq!(h.digest(), vec![0u8; 32]);
    }

    #[test]
    fn order_independence_two_elements() {
        let d1 = digest_after_adds(&[b"a", b"b"]);
        let d2 = digest_after_adds(&[b"b", b"a"]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn add_b_then_remove_a_equals_just_b() {
        let mut h1 = XorSha256SetHash::empty();
        h1.add(b"a");
        h1.add(b"b");
        h1.remove(b"a");

        let mut h2 = XorSha256SetHash::empty();
        h2.add(b"b");

        assert_eq!(h1.digest(), h2.digest());
    }

    #[test]
    fn from_digest_round_trip() {
        let mut h = XorSha256SetHash::empty();
        h.add(b"x");
        h.add(b"y");
        let bytes = h.digest();
        let h2 = XorSha256SetHash::from_digest(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn from_digest_bad_length_rejected() {
        assert!(XorSha256SetHash::from_digest(&[0u8; 31]).is_err());
        assert!(XorSha256SetHash::from_digest(&[0u8; 33]).is_err());
    }

    #[test]
    fn record_element_format() {
        let bytes = record_element_bytes("app.bsky.feed.post", "3jui", "bafy...");
        assert_eq!(bytes, b"app.bsky.feed.post/3jui:bafy...");
    }

    #[test]
    fn member_element_format() {
        let bytes = member_element_bytes("did:plc:alice");
        assert_eq!(bytes, b"did:plc:alice");
    }

    proptest! {
        /// Property: any permutation of N adds yields the same digest.
        #[test]
        fn permutation_invariance(items in prop::collection::vec(any::<u32>(), 0..16)) {
            let bytes_vec: Vec<Vec<u8>> = items.iter().map(|n| n.to_be_bytes().to_vec()).collect();
            let mut h1 = XorSha256SetHash::empty();
            for b in &bytes_vec {
                h1.add(b);
            }
            // Permute by reversing.
            let mut h2 = XorSha256SetHash::empty();
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
            let mut h1 = XorSha256SetHash::empty();
            for b in &prior_bytes {
                h1.add(b);
            }
            let baseline = h1.digest();
            h1.add(&x_bytes);
            h1.remove(&x_bytes);
            prop_assert_eq!(h1.digest(), baseline);
        }
    }
}
