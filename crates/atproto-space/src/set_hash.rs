//! Set hash primitives for permissioned-data spaces.
//!
//! The [`SetHash`] trait abstracts over a homomorphic, order-independent set
//! commitment. The production primitive is [`LtHash`], per the
//! [0016 Permissioned Data][spec] draft (§ "Commit digest", lines 263-282):
//!
//! - [`LtHash`] — the **production** primitive. A homomorphic lattice hash
//!   (BLAKE3-XOF over a 2048-byte / 1024-lane `u16` state, add/sub mod 2^16).
//!   The carried commitment is `sha256(state)`. Quantum-secure per the spec.
//!
//! All impls share the same algebraic invariants:
//! - Order-independent: `add(a); add(b) == add(b); add(a)`
//! - Inverse: `add(x); remove(x)` returns to the prior state
//! - Composable: states/digests compare by byte equality
//!
//! Two byte forms are distinguished, because for `LtHash` they differ:
//! - [`SetHash::state_bytes`] — the full lattice **state**, persisted by a repo
//!   host and rehydrated via [`SetHash::from_state_bytes`] (2048 bytes for
//!   `LtHash`).
//! - [`SetHash::digest`] — the 32-byte **commitment** carried in a
//!   [`crate::commit::Commit`] (`hash` field). For `LtHash` this is
//!   `sha256(state_bytes())`.
//!
//! [spec]: https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md

use crate::errors::{SpaceError, SpaceResult};
use sha2::{Digest, Sha256};

/// Number of `u16` lanes in an [`LtHash`] state (per the reference).
const LANES: usize = 1024;
/// Byte length of an [`LtHash`] state (`LANES * 2`).
const STATE_BYTES: usize = LANES * 2;

/// Trait for set-hash commitment primitives.
///
/// Implementations must satisfy the algebraic invariants documented at the
/// crate level: order-independence, add/remove inverse, byte-equality of
/// states.
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

    /// The persistable lattice **state** bytes.
    ///
    /// A repo host stores this and rehydrates via [`SetHash::from_state_bytes`].
    /// For [`LtHash`] this is the full 2048-byte state, **not** the 32-byte
    /// commitment.
    fn state_bytes(&self) -> Vec<u8>;

    /// Reconstruct from previously persisted [`SetHash::state_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::SetHashCodec`] if the bytes are not the expected
    /// length for this impl's state.
    fn from_state_bytes(bytes: &[u8]) -> SpaceResult<Self>;

    /// The 32-byte commitment digest carried in a [`crate::commit::Commit`].
    ///
    /// For [`LtHash`] this is `sha256(state_bytes())`.
    fn digest(&self) -> Vec<u8>;
}

/// Homomorphic lattice set hash ([LtHash]), the production primitive.
///
/// State is a fixed 2048-byte buffer interpreted as 1024 little-endian `u16`
/// lanes. An element is expanded to 2048 bytes with BLAKE3 in XOF mode and its
/// 1024 lanes are added into (or subtracted from) the state, modulo 2^16. The
/// commitment [`digest`](SetHash::digest) is `sha256` of the 2048-byte state.
///
/// This follows the 0016 spec's LtHash construction (§ "Commit digest", lines
/// 263-282) exactly, so digests are comparable across implementations.
///
/// [LtHash]: https://eprint.iacr.org/2019/227
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtHash {
    /// 1024 little-endian `u16` lanes. Arithmetic wraps mod 2^16.
    lanes: [u16; LANES],
}

impl LtHash {
    /// Expand an element to 1024 `u16` lanes via BLAKE3 in XOF mode.
    fn expand(element: &[u8]) -> [u16; LANES] {
        let mut buf = [0u8; STATE_BYTES];
        let mut hasher = blake3::Hasher::new();
        hasher.update(element);
        hasher.finalize_xof().fill(&mut buf);
        let mut lanes = [0u16; LANES];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]);
        }
        lanes
    }
}

impl SetHash for LtHash {
    fn empty() -> Self {
        Self {
            lanes: [0u16; LANES],
        }
    }

    fn add(&mut self, element: &[u8]) {
        let other = Self::expand(element);
        for (lane, add) in self.lanes.iter_mut().zip(other.iter()) {
            *lane = lane.wrapping_add(*add);
        }
    }

    fn remove(&mut self, element: &[u8]) {
        let other = Self::expand(element);
        for (lane, sub) in self.lanes.iter_mut().zip(other.iter()) {
            *lane = lane.wrapping_sub(*sub);
        }
    }

    fn state_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; STATE_BYTES];
        for (i, lane) in self.lanes.iter().enumerate() {
            let [lo, hi] = lane.to_le_bytes();
            out[2 * i] = lo;
            out[2 * i + 1] = hi;
        }
        out
    }

    fn from_state_bytes(bytes: &[u8]) -> SpaceResult<Self> {
        if bytes.len() != STATE_BYTES {
            return Err(SpaceError::SetHashCodec {
                reason: format!(
                    "LtHash state must be {STATE_BYTES} bytes, got {}",
                    bytes.len()
                ),
            });
        }
        let mut lanes = [0u16; LANES];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        }
        Ok(Self { lanes })
    }

    fn digest(&self) -> Vec<u8> {
        Sha256::digest(self.state_bytes()).to_vec()
    }
}

/// Format the element bytes for a record entry in the SetHash.
///
/// Each record maps to one element, the UTF-8 bytes of
/// `{collection}/{rkey}/{record_cid}` — three slash-joined components, per the
/// 0016 spec (§ "Commit digest", line 270). The slash before the CID is
/// load-bearing: a spec-conformant peer's digest only agrees with this one when
/// the element byte strings match exactly.
#[must_use]
pub fn record_element_bytes(collection: &str, rkey: &str, cid: &str) -> Vec<u8> {
    format!("{collection}/{rkey}/{cid}").into_bytes()
}

/// Format the element bytes for a member entry in the SetHash.
///
/// Members are hashed as the bare DID's UTF-8 bytes. Used by the `simplespace`
/// member-list orchestrator's local digest; the spec carries no member commits.
#[must_use]
pub fn member_element_bytes(did: &str) -> Vec<u8> {
    did.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- LtHash -----

    /// Empty state is 2048 zero bytes; its commitment is `sha256(2048 zeros)`.
    #[test]
    fn lthash_empty_state_and_digest() {
        let h = LtHash::empty();
        assert_eq!(h.state_bytes(), vec![0u8; STATE_BYTES]);
        // Known-answer: sha256 of 2048 zero bytes — the empty repo's state is
        // all zeroes per the spec (line 280), so its commitment is
        // `sha256(zeros)`, NOT 32 zero bytes.
        let expected =
            hex_to_vec("e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad");
        assert_eq!(h.digest(), expected);
        assert_eq!(h.digest().len(), 32);
    }

    #[test]
    fn lthash_add_remove_inverse() {
        let mut h = LtHash::empty();
        let base = h.state_bytes();
        h.add(b"app.bsky.feed.post/3jui:bafy123");
        assert_ne!(h.state_bytes(), base);
        h.remove(b"app.bsky.feed.post/3jui:bafy123");
        assert_eq!(h.state_bytes(), base);
    }

    #[test]
    fn lthash_order_independence() {
        let mut a = LtHash::empty();
        a.add(b"one");
        a.add(b"two");
        let mut b = LtHash::empty();
        b.add(b"two");
        b.add(b"one");
        assert_eq!(a.state_bytes(), b.state_bytes());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn lthash_state_round_trip() {
        let mut h = LtHash::empty();
        h.add(b"x");
        h.add(b"y");
        let state = h.state_bytes();
        assert_eq!(state.len(), STATE_BYTES);
        let h2 = LtHash::from_state_bytes(&state).unwrap();
        assert_eq!(h, h2);
        assert_eq!(h.digest(), h2.digest());
    }

    #[test]
    fn lthash_from_state_bad_length_rejected() {
        assert!(LtHash::from_state_bytes(&[0u8; 2047]).is_err());
        assert!(LtHash::from_state_bytes(&[0u8; 32]).is_err());
        assert!(LtHash::from_state_bytes(&[0u8; STATE_BYTES]).is_ok());
    }

    /// Lane arithmetic wraps mod 2^16: adding the same element 65536 times
    /// returns to the empty state.
    #[test]
    fn lthash_lane_wraparound() {
        let mut h = LtHash::empty();
        for _ in 0..65_536u32 {
            h.add(b"wrap");
        }
        assert_eq!(h.state_bytes(), vec![0u8; STATE_BYTES]);
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn record_element_format() {
        // Spec line 270: `{collection}/{rkey}/{record_cid}` — slash before CID.
        let bytes = record_element_bytes("app.bsky.feed.post", "3jui", "bafy...");
        assert_eq!(bytes, b"app.bsky.feed.post/3jui/bafy...");
    }

    #[test]
    fn member_element_format() {
        let bytes = member_element_bytes("did:plc:alice");
        assert_eq!(bytes, b"did:plc:alice");
    }
}
