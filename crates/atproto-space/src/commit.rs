//! Permissioned-data commit construction.
//!
//! A signed commit summarizes the current state of a permissioned repo. It is
//! built to match the 0016 Permissioned Data draft (§ Commit signature):
//!
//! ```text
//! hash := setHash.digest()                        // sha256 of the 2048-byte LtHash state (32 bytes)
//! ikm  := random(32 bytes)                         // per-commit, fresh
//! ctx  := encode_ctx(space, rev, ikm)              // TLS-1.3-style vlv (below)
//! sig  := sign(ctx)                                // user's atproto signing key, over the full ctx
//! mac  := HMAC-SHA256(HKDF-SHA256(ikm, ctx), hash) // binds the repo hash to this commit's context
//! commit := { hash, mac, ikm, sig, rev }
//! ```
//!
//! `ctx` is the single context string reused for both the signature and the
//! MAC's HKDF info. It uses the TLS 1.3 (§3.4) variable-length-vector encoding:
//! a fixed protocol tag followed by each field length-prefixed with a
//! big-endian `uint16`, per the spec's "Commit signature" section:
//!
//! ```text
//! ctx = "atproto-space-v1"                          // fixed protocol tag, NO length prefix
//!   || uint16be(len(space))  || space  // space URI (at://authority/space/type/skey)
//!   || uint16be(len(author)) || author // author DID of the repo
//!   || uint16be(len(rev))   || rev                  // commit revision (TID)
//!   || uint16be(len(ikm))   || ikm                  // per-commit nonce
//! ```
//!
//! Deniability: the signature covers only the random `ctx` (which binds
//! `space`, `rev`, and the public `ikm` — never the repo hash), so a leaked
//! commit proves nothing about repo contents. The repo hash is bound to the
//! context by the *symmetric* MAC (key derived from the public `ikm`), so anyone
//! holding the commit can recompute a valid MAC for any hash — authenticity of
//! the *content* is not transferable (the spec's "Commit signature" section).
//!
//! [`verify_commit`] recomputes the MAC and compares it; a consumer that wants
//! authenticity additionally calls [`verify_commit_signature`], which verifies
//! `sig` over the reconstructed `ctx`.

use crate::errors::{SpaceError, SpaceResult};
use crate::set_hash::SetHash;
use atproto_identity::key::{KeyData, sign as identity_sign, validate as identity_validate};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Fixed domain-separation tag prefixing the commit `ctx`.
const DOMAIN_PREFIX: &[u8] = b"atproto-space-v1";

/// Context bound into a commit via the signature and the MAC's HKDF info.
///
/// Per the 0016 draft the on-the-wire `ctx` is
/// `[space, author, rev, ikm]` length-prefixed; the `ikm` is supplied per
/// commit (it is part of the [`Commit`]), so this struct carries the stable
/// `[space, author, rev]` triple.
///
/// The author DID is what gives the signature domain separation *within* a
/// space: without it, a signature over one author's commit is a signature over
/// any author's commit at the same rev.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceContext {
    /// Full space URI (`at://{spaceDid}/space/{spaceType}/{skey}`).
    pub space: String,
    /// DID of the repo author this commit belongs to.
    pub author: String,
    /// Rev (TID) for this commit.
    pub rev: String,
}

/// Encode the commit `ctx` (signature message + HKDF info).
///
/// `"atproto-space-v1"` followed by each field length-prefixed with a
/// big-endian `uint16`, in the order `[space, author, rev, ikm]` — the TLS 1.3
/// §3.4 variable-length-vector encoding the draft specifies.
///
/// The lengths are big-endian here and little-endian in the LtHash lanes. That
/// is not an inconsistency to tidy up: the two come from different specs and
/// each keeps its native byte order.
#[must_use]
pub fn encode_ctx(context: &SpaceContext, ikm: &[u8]) -> Vec<u8> {
    let space = context.space.as_bytes();
    let author = context.author.as_bytes();
    let rev = context.rev.as_bytes();
    let mut out = Vec::with_capacity(
        DOMAIN_PREFIX.len() + space.len() + author.len() + rev.len() + ikm.len() + 8,
    );
    out.extend_from_slice(DOMAIN_PREFIX);
    for field in [space, author, rev, ikm] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// The only commit format version this build produces or accepts.
///
/// Corresponds to the `v1` in the `ctx` protocol tag `atproto-space-v1`; a
/// future ctx construction is expected to arrive with a new `ver`, which is
/// what makes this field the negotiation point rather than a decoration.
pub const COMMIT_VERSION: u32 = 1;

/// A signed permissioned-data commit (`com.atproto.space.defs#signedCommit`).
///
/// Carries the lexicon's full required set `[ver, hash, mac, ikm, sig, rev]`.
/// The order in that array is not a wire-order requirement — JSON objects are
/// unordered and canonical DAG-CBOR sorts keys by length then bytes — so what
/// matters is that every one of them is present, which `ver` previously was
/// not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Commit format version. Always [`COMMIT_VERSION`].
    pub ver: u32,
    /// `sha256` of the LtHash state (32 bytes).
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// `HMAC-SHA256` over `hash`, keyed by `HKDF-Expand(ikm, ctx)`.
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
    /// Per-commit fresh IKM (32 bytes), also bound into the `ctx`.
    #[serde(with = "serde_bytes")]
    pub ikm: Vec<u8>,
    /// Signature over `ctx` by the user's atproto signing key.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    /// Commit revision (TID), also bound into the `ctx`.
    pub rev: String,
}

/// Construct a signed commit from a SetHash and `SpaceContext`.
///
/// Uses a fresh per-commit IKM drawn from the OS RNG.
///
/// # Errors
///
/// - [`SpaceError::Hkdf`] — HKDF derivation failure.
/// - [`SpaceError::Signature`] — signing failure (e.g. a public key was given).
/// - [`SpaceError::ContextEncoding`] — `rev` is empty.
pub fn create_commit<H: SetHash>(
    set_hash: &H,
    context: &SpaceContext,
    signing_key: &KeyData,
) -> SpaceResult<Commit> {
    let mut ikm = [0u8; 32];
    rand::rng().fill(&mut ikm);
    create_commit_with_ikm(&set_hash.digest(), context, signing_key, &ikm)
}

/// Like [`create_commit`] but takes the commit `hash` and an explicit IKM.
///
/// For deterministic tests or caller-controlled randomness.
#[doc(hidden)]
pub fn create_commit_with_ikm(
    hash: &[u8],
    context: &SpaceContext,
    signing_key: &KeyData,
    ikm: &[u8; 32],
) -> SpaceResult<Commit> {
    if context.rev.is_empty() {
        return Err(SpaceError::ContextEncoding {
            reason: "rev must be non-empty".to_string(),
        });
    }

    let ctx = encode_ctx(context, ikm);
    let mac = derive_mac(ikm, hash, &ctx)?;
    // The signature is over the full `ctx` (space, author, rev, ikm) — never
    // the hash — so a leaked commit is deniable.
    let sig = identity_sign(signing_key, &ctx).map_err(|e| SpaceError::Signature {
        reason: e.to_string(),
    })?;

    Ok(Commit {
        ver: COMMIT_VERSION,
        hash: hash.to_vec(),
        mac,
        ikm: ikm.to_vec(),
        sig,
        rev: context.rev.clone(),
    })
}

/// Refuse a commit whose format version this build does not implement.
///
/// # Errors
///
/// [`SpaceError::UnsupportedCommitVersion`] when `ver` is not
/// [`COMMIT_VERSION`].
pub fn check_commit_version(commit: &Commit) -> SpaceResult<()> {
    if commit.ver != COMMIT_VERSION {
        return Err(SpaceError::UnsupportedCommitVersion { ver: commit.ver });
    }
    Ok(())
}

/// Derive `HMAC-SHA256(HKDF-Expand(ikm, ctx), hash)`.
///
/// HKDF is **expand-only** (ikm is the PRK; no extract step, no salt), per spec
/// line 303 (`HKDF-SHA256(ikm, ctx)`).
fn derive_mac(ikm: &[u8], hash: &[u8], ctx: &[u8]) -> SpaceResult<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(ikm).map_err(|e| SpaceError::Hkdf {
        reason: format!("invalid prk: {e}"),
    })?;
    let mut hmac_key = [0u8; 32];
    hkdf.expand(ctx, &mut hmac_key)
        .map_err(|e| SpaceError::Hkdf {
            reason: e.to_string(),
        })?;
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).map_err(|e| SpaceError::Hkdf {
            reason: format!("hmac key length: {e}"),
        })?;
    mac.update(hash);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify a commit's MAC against the supplied `SpaceContext`.
///
/// Recomputes `ctx` from `space`, `rev`, and the commit's `ikm`, then recomputes
/// the MAC over `hash` and compares it constant-time (the spec's "Commit signature" section). It does
/// **not** verify the signature (see [`verify_commit_signature`]).
///
/// # Errors
///
/// - [`SpaceError::CommitTagMismatch`] — the MAC does not match (commit
///   tampered, or wrong context).
/// - [`SpaceError::Hkdf`] — `ikm` is not 32 bytes, or derivation failed.
pub fn verify_commit(context: &SpaceContext, commit: &Commit) -> SpaceResult<()> {
    // Version before crypto. A commit carrying a `ver` this build does not know
    // was signed over a `ctx` this build does not know how to rebuild, so
    // proceeding would report a version mismatch as a MAC failure.
    check_commit_version(commit)?;
    if commit.ikm.len() != 32 {
        return Err(SpaceError::Hkdf {
            reason: format!("ikm must be 32 bytes, got {}", commit.ikm.len()),
        });
    }
    let ctx = encode_ctx(context, &commit.ikm);
    let mac = derive_mac(&commit.ikm, &commit.hash, &ctx)?;
    if mac.len() != commit.mac.len() {
        return Err(SpaceError::CommitTagMismatch);
    }
    // Constant-time compare via HMAC's verify path.
    let hkdf = Hkdf::<Sha256>::from_prk(&commit.ikm).map_err(|e| SpaceError::Hkdf {
        reason: format!("invalid prk: {e}"),
    })?;
    let mut hmac_key = [0u8; 32];
    hkdf.expand(&ctx, &mut hmac_key)
        .map_err(|e| SpaceError::Hkdf {
            reason: e.to_string(),
        })?;
    let mut verifier =
        <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).map_err(|e| SpaceError::Hkdf {
            reason: format!("hmac key length: {e}"),
        })?;
    verifier.update(&commit.hash);
    verifier
        .verify_slice(&commit.mac)
        .map_err(|_| SpaceError::CommitTagMismatch)
}

/// Verify that a commit's `sig` was produced over its `ctx` by `verifying_key`.
///
/// Per the spec's "Commit signature" section a reader verifies `sig` against the user's signing key for
/// authenticity. The `ctx` is reconstructed from `context` (`space`, `rev`) and
/// the commit's `ikm`.
///
/// # Errors
///
/// Returns [`SpaceError::CommitSignatureInvalid`] if the signature does not
/// verify over the reconstructed `ctx`.
pub fn verify_commit_signature(
    context: &SpaceContext,
    commit: &Commit,
    verifying_key: &KeyData,
) -> SpaceResult<()> {
    let ctx = encode_ctx(context, &commit.ikm);
    identity_validate(verifying_key, &commit.sig, &ctx)
        .map_err(|_| SpaceError::CommitSignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_hash::LtHash;
    use atproto_identity::key::{KeyType, generate_key, to_public};

    fn test_context() -> SpaceContext {
        SpaceContext {
            space: "at://did:plc:owner/space/app.bsky.group/default".to_string(),
            author: "did:plc:author".to_string(),
            rev: "3jui7kd2z2y2e".to_string(),
        }
    }

    fn test_keypair() -> (KeyData, KeyData) {
        let private = generate_key(KeyType::P256Private).unwrap();
        let public = to_public(&private).unwrap();
        (private, public)
    }

    fn fresh_set_hash() -> LtHash {
        let mut h = LtHash::empty();
        h.add(b"app.bsky.feed.post/3jui:bafy123");
        h
    }

    #[test]
    fn round_trip_create_and_verify() {
        let (priv_key, _pub_key) = test_keypair();
        let ctx = test_context();
        let h = fresh_set_hash();

        let commit = create_commit(&h, &ctx, &priv_key).unwrap();
        assert_eq!(commit.hash, h.digest());
        assert_eq!(commit.ikm.len(), 32);
        verify_commit(&ctx, &commit).expect("commit MAC must verify");
    }

    #[test]
    fn signature_is_over_ctx() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context();
        let h = fresh_set_hash();
        let commit = create_commit(&h, &ctx, &priv_key).unwrap();
        // sig verifies over the reconstructed ctx...
        verify_commit_signature(&ctx, &commit, &pub_key).expect("sig over ctx must verify");
        // ...and the signed message is the ctx, not the hash: an independent
        // signature over ctx equals the commit's sig (ECDSA is deterministic here).
        let direct = identity_sign(&priv_key, &encode_ctx(&ctx, &commit.ikm)).unwrap();
        assert_eq!(direct, commit.sig);
    }

    #[test]
    fn ikm_uniqueness_across_two_commits() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let h = fresh_set_hash();
        let c1 = create_commit(&h, &ctx, &priv_key).unwrap();
        let c2 = create_commit(&h, &ctx, &priv_key).unwrap();
        assert_ne!(c1.ikm, c2.ikm, "IKM must be fresh per commit");
        assert_ne!(c1.mac, c2.mac, "mac should change with IKM");
        assert_eq!(c1.hash, c2.hash, "hash is stable for the same set");
    }

    /// Domain separation — a commit bound to one space must fail verification
    /// under a different space, because `space` is part of the `ctx`.
    #[test]
    fn domain_separation_by_space() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let other = SpaceContext {
            space: "at://did:plc:owner/space/app.bsky.group/other".to_string(),
            ..ctx.clone()
        };
        let h = fresh_set_hash();
        let commit = create_commit(&h, &ctx, &priv_key).unwrap();
        assert!(matches!(
            verify_commit(&other, &commit),
            Err(SpaceError::CommitTagMismatch)
        ));
    }

    #[test]
    fn tampered_mac_rejected() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let mut commit = create_commit(&fresh_set_hash(), &ctx, &priv_key).unwrap();
        commit.mac[0] ^= 0xff;
        assert!(matches!(
            verify_commit(&ctx, &commit),
            Err(SpaceError::CommitTagMismatch)
        ));
    }

    #[test]
    fn tampered_hash_rejected() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let mut commit = create_commit(&fresh_set_hash(), &ctx, &priv_key).unwrap();
        commit.hash[0] ^= 0xff;
        // mac was over the original hash → mismatch.
        assert!(matches!(
            verify_commit(&ctx, &commit),
            Err(SpaceError::CommitTagMismatch)
        ));
    }

    #[test]
    fn wrong_rev_context_rejected() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let commit = create_commit(&fresh_set_hash(), &ctx, &priv_key).unwrap();
        let wrong = SpaceContext {
            rev: "3zzzzzzzzzzzz".to_string(),
            ..ctx
        };
        assert!(matches!(
            verify_commit(&wrong, &commit),
            Err(SpaceError::CommitTagMismatch)
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context();
        let mut commit = create_commit(&fresh_set_hash(), &ctx, &priv_key).unwrap();
        commit.sig[0] ^= 0xff;
        assert!(matches!(
            verify_commit_signature(&ctx, &commit, &pub_key),
            Err(SpaceError::CommitSignatureInvalid)
        ));
    }

    /// The `ctx` byte layout: tag, then uint16be-length-prefixed fields in the
    /// fixed order `[space, author, rev, ikm]`.
    ///
    /// Written as literal bytes rather than by re-running the encoder, because
    /// a test that rebuilds the value the same way agrees with any field order
    /// the implementation happens to use — which is exactly how the author DID
    /// went missing.
    #[test]
    fn commit_ctx_layout_is_a_known_answer() {
        let ctx = SpaceContext {
            space: "sp".to_string(),
            author: "au".to_string(),
            rev: "r".to_string(),
        };
        let ikm = [0xABu8; 4];
        let encoded = encode_ctx(&ctx, &ikm);

        let expected: Vec<u8> = [
            b"atproto-space-v1".as_slice(),
            &[0x00, 0x02],
            b"sp",
            &[0x00, 0x02],
            b"au",
            &[0x00, 0x01],
            b"r",
            &[0x00, 0x04],
            &[0xAB, 0xAB, 0xAB, 0xAB],
        ]
        .concat();
        assert_eq!(encoded, expected);
    }

    /// The author DID is what separates two authors' commits within one space.
    /// Without it in the `ctx`, a signature over one author's commit is a
    /// signature over any author's commit at the same rev.
    #[test]
    fn domain_separation_by_author() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let other = SpaceContext {
            author: "did:plc:someoneelse".to_string(),
            ..ctx.clone()
        };
        let h = fresh_set_hash();
        let commit = create_commit(&h, &ctx, &priv_key).unwrap();
        assert!(matches!(
            verify_commit(&other, &commit),
            Err(SpaceError::CommitTagMismatch)
        ));
    }

    #[test]
    fn a_commit_carries_version_one() {
        let (priv_key, _) = test_keypair();
        let commit = create_commit(&fresh_set_hash(), &test_context(), &priv_key).unwrap();
        assert_eq!(commit.ver, COMMIT_VERSION);
        assert_eq!(commit.ver, 1, "the lexicon says currently 1");
    }

    #[test]
    fn an_unknown_version_is_refused_before_the_mac_is_checked() {
        // Reporting a version mismatch as a MAC failure would send an
        // implementor looking for a crypto bug that is not there.
        let (priv_key, _) = test_keypair();
        let ctx = test_context();
        let mut commit = create_commit(&fresh_set_hash(), &ctx, &priv_key).unwrap();
        commit.ver = 2;
        assert!(matches!(
            verify_commit(&ctx, &commit),
            Err(SpaceError::UnsupportedCommitVersion { ver: 2 })
        ));
    }

    #[test]
    fn every_lexicon_required_field_is_present() {
        // `required: ["ver","hash","mac","ikm","sig","rev"]`. Asserting the
        // set, not the order: JSON objects are unordered and canonical
        // DAG-CBOR sorts its own keys, so an order assertion here would be
        // testing serde_json rather than this struct.
        let (priv_key, _) = test_keypair();
        let commit = create_commit(&fresh_set_hash(), &test_context(), &priv_key).unwrap();
        let json = serde_json::to_value(&commit).unwrap();
        let obj = json.as_object().unwrap();
        for field in ["ver", "hash", "mac", "ikm", "sig", "rev"] {
            assert!(
                obj.contains_key(field),
                "{field} missing from the wire form"
            );
        }
        assert_eq!(obj.len(), 6, "no extra fields: {json}");
    }
}
