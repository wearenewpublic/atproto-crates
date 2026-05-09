//! Realm enum — distinguishes the public repo realm from permissioned-data spaces.
//!
//! The PDS handles two realms:
//!
//! - **Public**: the user's standard atproto repo (MST, signed commits, firehose).
//! - **Space(SpaceUri)**: a permissioned-data space — separate storage, separate
//!   commit primitive (SetHash + signed HMAC), separate sync (oplog + setHash),
//!   separate notification path (`notifyWrite` push, not firehose).
//!
//! Many subsystems (storage, auth, takedown, observability) need to dispatch on
//! realm. This enum is the canonical discriminator.

use atproto_space::SpaceUri;

/// Discriminator for which realm a request, write, or read targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Realm {
    /// The public atproto repo realm.
    Public,
    /// A permissioned-data space realm, identified by its `ats://` URI.
    Space(SpaceUri),
}

impl Realm {
    /// Returns `true` if this is the public realm.
    #[must_use]
    pub fn is_public(&self) -> bool {
        matches!(self, Realm::Public)
    }

    /// Returns `Some(SpaceUri)` if this is a space realm.
    #[must_use]
    pub fn as_space(&self) -> Option<&SpaceUri> {
        match self {
            Realm::Space(uri) => Some(uri),
            Realm::Public => None,
        }
    }
}

impl std::fmt::Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Realm::Public => f.write_str("public"),
            Realm::Space(uri) => write!(f, "{}", uri),
        }
    }
}

// ---------------------------------------------------------------------------
//  SetHash dispatch
// ---------------------------------------------------------------------------
//
// The PDS instantiates `SpaceRepo<S, PdsSetHash>` and `SpaceMembers<S,
// PdsSetHash>` everywhere, so swapping the SetHash algorithm is a single
// Cargo-feature decision. Two PDS deployments running different builds
// **cannot interop on Spaces** (digests are not comparable across impls);
// federations must align this flag.

/// The SetHash impl this build of the PDS uses for all Spaces commitments.
///
/// Aliases either `XorSha256SetHash` (default — placeholder per the upstream
/// Spaces Design Spec) or `EcmhSetHash` over secp256k1 (when the `ecmh`
/// Cargo feature is enabled — the production target).
#[cfg(not(feature = "ecmh"))]
pub type PdsSetHash = atproto_space::set_hash::XorSha256SetHash;

/// The SetHash impl this build of the PDS uses for all Spaces commitments
/// (ECMH variant — secp256k1 multiset hash).
#[cfg(feature = "ecmh")]
pub type PdsSetHash = atproto_space::set_hash_ecmh::EcmhSetHash;

/// Constant identifying the SetHash impl in use. Surfaced in `_health` so
/// operators + federation peers can compare.
#[cfg(not(feature = "ecmh"))]
pub const SET_HASH_NAME: &str = "xor-sha256";

/// Constant identifying the SetHash impl in use. Surfaced in `_health` so
/// operators + federation peers can compare.
#[cfg(feature = "ecmh")]
pub const SET_HASH_NAME: &str = "ecmh-secp256k1";

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_space::set_hash::SetHash;
    use atproto_space::{SpaceKey, SpaceType};

    #[test]
    fn realm_public_is_public() {
        assert!(Realm::Public.is_public());
        assert!(Realm::Public.as_space().is_none());
    }

    #[test]
    fn realm_space_is_not_public() {
        let space = SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        );
        let realm = Realm::Space(space.clone());
        assert!(!realm.is_public());
        assert_eq!(realm.as_space(), Some(&space));
    }

    #[test]
    fn pds_set_hash_can_be_constructed() {
        let mut h = PdsSetHash::empty();
        h.add(b"alice");
        let d = h.digest();
        assert!(!d.is_empty());
    }

    #[test]
    fn set_hash_name_matches_feature() {
        if cfg!(feature = "ecmh") {
            assert_eq!(SET_HASH_NAME, "ecmh-secp256k1");
        } else {
            assert_eq!(SET_HASH_NAME, "xor-sha256");
        }
    }
}
