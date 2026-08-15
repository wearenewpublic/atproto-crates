//! SetHash dispatch for the PDS Spaces subsystem.
//!
//! Binds the SetHash algorithm used for all permissioned-data Spaces
//! commitments in one place, and exposes its operator-facing name.

// ---------------------------------------------------------------------------
//  SetHash dispatch
// ---------------------------------------------------------------------------
//
// The PDS instantiates `SpaceRepo<S, PdsSetHash>` and `SpaceMembers<S,
// PdsSetHash>` everywhere, binding the SetHash algorithm in one place.

/// The SetHash impl this build of the PDS uses for all Spaces commitments.
///
/// Aliases [`atproto_space::LtHash`] — the **production** primitive per
/// [0016 Permissioned Data] (§ "Commit digest", lines 263-282).
///
/// `LtHash` persists a 2048-byte lattice **state** (via
/// [`SetHash::state_bytes`](atproto_space::set_hash::SetHash::state_bytes));
/// its 32-byte commitment (`sha256(state)`) is the `hash` field of a signed
/// [`Commit`](atproto_space::Commit).
///
/// [0016 Permissioned Data]: https://github.com/bluesky-social/proposals/blob/main/0016-permissioned-data/README.md
pub type PdsSetHash = atproto_space::set_hash::LtHash;

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_space::set_hash::SetHash;

    #[test]
    fn pds_set_hash_can_be_constructed() {
        let mut h = PdsSetHash::empty();
        h.add(b"alice");
        let d = h.digest();
        assert!(!d.is_empty());
    }
}
