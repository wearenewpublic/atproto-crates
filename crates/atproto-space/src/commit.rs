//! Permissioned-data commit construction.
//!
//!
//!
//! ```text
//! ikm        := random(32 bytes)                              // per-commit, fresh
//! hkdf_info  := DAG-CBOR(SpaceContext)
//! hmac_key   := HKDF-Extract-then-Expand(SHA256, ikm, info=hkdf_info, len=32)
//! tag        := HMAC-SHA-256(hmac_key, set_hash || rev)
//! sig_bytes  := tag || rev.as_bytes()
//! sig        := ECDSA-low-S(user_signing_key, SHA256(sig_bytes))
//! commit     := { set_hash, rev, ikm, tag, sig }
//! ```
//!
//! The IKM is included in the commit so a verifier with the relevant
//! `SpaceContext` can recompute and check; outside that context, the IKM is
//! meaningless. This is the deniability mechanism per the spec.
//!
//! `SpaceContext.scope` (Records vs Members) provides domain separation: a
//! commit signed in one scope must fail verification in the other.

use crate::errors::{SpaceError, SpaceResult};
use crate::set_hash::SetHash;
use atproto_identity::key::{KeyData, sign as identity_sign, validate as identity_validate};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Scope discriminator for `SpaceContext` — provides domain separation between
/// record-set commits and member-list commits.
///
/// **Critical security property**: a commit signed with `Records` scope must
/// fail verification under `Members` scope and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitScope {
    /// Records-set commit (per-user, per-space).
    Records,
    /// Member-list commit (owner-only).
    Members,
}

impl CommitScope {
    /// Spec-defined string value used in the HKDF info bytes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CommitScope::Records => "records",
            CommitScope::Members => "members",
        }
    }
}

/// Context for HKDF derivation of the commit's HMAC key.
///
/// Encoded as DAG-CBOR and used as the HKDF `info` parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceContext {
    /// Owner DID of the space.
    #[serde(rename = "spaceDid")]
    pub space_did: String,
    /// Space type (NSID).
    #[serde(rename = "spaceType")]
    pub space_type: String,
    /// Space key.
    #[serde(rename = "spaceKey")]
    pub space_key: String,
    /// Committer DID — the user who wrote this commit.
    #[serde(rename = "userDid")]
    pub user_did: String,
    /// Scope discriminator (Records or Members).
    pub scope: CommitScope,
    /// Rev (TID) for this commit.
    pub rev: String,
}

impl SpaceContext {
    /// Encode as DAG-CBOR for use as the HKDF `info` parameter.
    fn to_cbor(&self) -> SpaceResult<Vec<u8>> {
        atproto_dasl::to_vec(self).map_err(|e| SpaceError::ContextEncoding {
            reason: e.to_string(),
        })
    }
}

/// A signed permissioned-data commit.
///
/// Includes the IKM in the clear so verifiers with `SpaceContext` can
/// recompute the HMAC; the IKM-randomness gives deniability outside context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// SetHash digest at this commit.
    #[serde(rename = "setHash", with = "serde_bytes")]
    pub set_hash: Vec<u8>,
    /// Rev (TID).
    pub rev: String,
    /// Per-commit fresh IKM (32 bytes).
    #[serde(with = "serde_bytes")]
    pub ikm: Vec<u8>,
    /// HMAC-SHA-256 tag over `set_hash || rev` keyed by HKDF(ikm, SpaceContext).
    #[serde(with = "serde_bytes")]
    pub tag: Vec<u8>,
    /// ECDSA signature over SHA256(tag || rev), low-S normalized.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Construct a signed commit from a SetHash digest and SpaceContext.
///
/// Uses a fresh per-commit IKM drawn from the OS RNG (`rand::rng()`).
///
/// # Errors
///
/// - [`SpaceError::Hkdf`] — HKDF derivation failure.
/// - [`SpaceError::Signature`] — signing failure (key/curve mismatch, etc.).
/// - [`SpaceError::ContextEncoding`] — CBOR encoding of `SpaceContext` failed.
pub fn create_commit<H: SetHash>(
    set_hash: &H,
    context: &SpaceContext,
    signing_key: &KeyData,
) -> SpaceResult<Commit> {
    let mut ikm = [0u8; 32];
    rand::rng().fill(&mut ikm);
    create_commit_with_ikm(&set_hash.digest(), context, signing_key, &ikm)
}

/// Like [`create_commit`] but takes an explicit IKM. For deterministic tests
/// or for re-creating commits with caller-controlled randomness.
#[doc(hidden)]
pub fn create_commit_with_ikm(
    set_hash: &[u8],
    context: &SpaceContext,
    signing_key: &KeyData,
    ikm: &[u8; 32],
) -> SpaceResult<Commit> {
    if context.rev != context.rev.trim() || context.rev.is_empty() {
        return Err(SpaceError::ContextEncoding {
            reason: "rev must be non-empty and untrimmed".to_string(),
        });
    }

    // 2. HKDF-derive HMAC key with DAG-CBOR(SpaceContext) as info.
    let info = context.to_cbor()?;
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut hmac_key = [0u8; 32];
    hkdf.expand(&info, &mut hmac_key)
        .map_err(|e| SpaceError::Hkdf {
            reason: e.to_string(),
        })?;

    // 3. HMAC-SHA-256 over set_hash || rev.
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).map_err(|e| SpaceError::Hkdf {
            reason: format!("hmac key length: {}", e),
        })?;
    mac.update(set_hash);
    mac.update(context.rev.as_bytes());
    let tag = mac.finalize().into_bytes();

    // 4. ECDSA sign SHA256(tag || rev) with the user's signing key.
    let mut sig_input = Vec::with_capacity(tag.len() + context.rev.len());
    sig_input.extend_from_slice(&tag);
    sig_input.extend_from_slice(context.rev.as_bytes());
    let sig_hash = Sha256::digest(&sig_input);

    let sig = identity_sign(signing_key, &sig_hash).map_err(|e| SpaceError::Signature {
        reason: e.to_string(),
    })?;

    Ok(Commit {
        set_hash: set_hash.to_vec(),
        rev: context.rev.clone(),
        ikm: ikm.to_vec(),
        tag: tag.to_vec(),
        sig,
    })
}

/// Verify a commit against the supplied `SpaceContext` and verifying key.
///
/// Returns `Ok(())` on success. The verifying key must be the public half of
/// the signing key used during `create_commit`.
///
/// # Errors
///
/// - [`SpaceError::CommitTagMismatch`] — HMAC tag does not match (commit
///   tampered or wrong context).
/// - [`SpaceError::CommitSignatureInvalid`] — ECDSA signature does not verify.
/// - [`SpaceError::ContextEncoding`] / [`SpaceError::Hkdf`] — internal failure.
///
/// # Domain separation
///
/// A commit signed with `scope: Records` will fail verification when the
/// supplied `context.scope` is `Members` (and vice versa) because the HKDF
/// info bytes differ — this is the load-bearing security property.
pub fn verify_commit(
    context: &SpaceContext,
    commit: &Commit,
    verifying_key: &KeyData,
) -> SpaceResult<()> {
    // Cheap structural checks first.
    if commit.rev != context.rev {
        return Err(SpaceError::JwtClaimMismatch {
            field: "rev".to_string(),
            expected: context.rev.clone(),
            actual: commit.rev.clone(),
        });
    }
    if commit.ikm.len() != 32 {
        return Err(SpaceError::Hkdf {
            reason: format!("ikm must be 32 bytes, got {}", commit.ikm.len()),
        });
    }

    // Recompute HMAC.
    let info = context.to_cbor()?;
    let hkdf = Hkdf::<Sha256>::new(None, &commit.ikm);
    let mut hmac_key = [0u8; 32];
    hkdf.expand(&info, &mut hmac_key)
        .map_err(|e| SpaceError::Hkdf {
            reason: e.to_string(),
        })?;

    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).map_err(|e| SpaceError::Hkdf {
            reason: format!("hmac key length: {}", e),
        })?;
    mac.update(&commit.set_hash);
    mac.update(commit.rev.as_bytes());
    mac.verify_slice(&commit.tag)
        .map_err(|_| SpaceError::CommitTagMismatch)?;

    // Verify ECDSA over SHA256(tag || rev).
    let mut sig_input = Vec::with_capacity(commit.tag.len() + commit.rev.len());
    sig_input.extend_from_slice(&commit.tag);
    sig_input.extend_from_slice(commit.rev.as_bytes());
    let sig_hash = Sha256::digest(&sig_input);

    identity_validate(verifying_key, &commit.sig, &sig_hash)
        .map_err(|_| SpaceError::CommitSignatureInvalid)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_hash::XorSha256SetHash;
    use atproto_identity::key::{KeyType, generate_key, to_public};

    fn test_context(scope: CommitScope) -> SpaceContext {
        SpaceContext {
            space_did: "did:plc:owner".to_string(),
            space_type: "app.bsky.group".to_string(),
            space_key: "default".to_string(),
            user_did: "did:plc:alice".to_string(),
            scope,
            rev: "3jui7kd2z2y2e".to_string(),
        }
    }

    fn test_keypair() -> (KeyData, KeyData) {
        let private = generate_key(KeyType::P256Private).unwrap();
        let public = to_public(&private).unwrap();
        (private, public)
    }

    fn fresh_set_hash() -> XorSha256SetHash {
        let mut h = XorSha256SetHash::empty();
        h.add(b"app.bsky.feed.post/3jui:bafy123");
        h
    }

    #[test]
    fn round_trip_create_and_verify() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();

        let commit = create_commit(&h, &ctx, &priv_key).unwrap();
        verify_commit(&ctx, &commit, &pub_key).expect("commit must verify");
    }

    #[test]
    fn ikm_uniqueness_across_two_commits() {
        let (priv_key, _) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();
        let c1 = create_commit(&h, &ctx, &priv_key).unwrap();
        let c2 = create_commit(&h, &ctx, &priv_key).unwrap();
        assert_ne!(c1.ikm, c2.ikm, "IKM must be fresh per commit");
        assert_ne!(c1.tag, c2.tag, "tag should change with IKM");
        assert_ne!(c1.sig, c2.sig, "signature should change with tag");
    }

    /// **Domain separation** — the load-bearing security property.
    ///
    /// A commit signed with `scope: Records` MUST fail verification when the
    /// verifier presents `scope: Members`.
    #[test]
    fn domain_separation_records_vs_members() {
        let (priv_key, pub_key) = test_keypair();
        let records_ctx = test_context(CommitScope::Records);
        let members_ctx = SpaceContext {
            scope: CommitScope::Members,
            ..records_ctx.clone()
        };
        let h = fresh_set_hash();

        let commit = create_commit(&h, &records_ctx, &priv_key).unwrap();
        let result = verify_commit(&members_ctx, &commit, &pub_key);
        assert!(matches!(result, Err(SpaceError::CommitTagMismatch)));
    }

    #[test]
    fn tampered_tag_rejected() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();
        let mut commit = create_commit(&h, &ctx, &priv_key).unwrap();
        commit.tag[0] ^= 0xff;
        let result = verify_commit(&ctx, &commit, &pub_key);
        assert!(matches!(result, Err(SpaceError::CommitTagMismatch)));
    }

    #[test]
    fn tampered_rev_rejected_via_mismatch() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();
        let mut commit = create_commit(&h, &ctx, &priv_key).unwrap();
        commit.rev = "different".to_string();
        // Field-level mismatch happens first.
        let result = verify_commit(&ctx, &commit, &pub_key);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }

    #[test]
    fn tampered_set_hash_rejected() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();
        let mut commit = create_commit(&h, &ctx, &priv_key).unwrap();
        commit.set_hash[0] ^= 0xff;
        // The HMAC was over the original set_hash; mutated set_hash → tag mismatch.
        let result = verify_commit(&ctx, &commit, &pub_key);
        assert!(matches!(result, Err(SpaceError::CommitTagMismatch)));
    }

    #[test]
    fn wrong_user_context_rejected() {
        let (priv_key, pub_key) = test_keypair();
        let ctx = test_context(CommitScope::Records);
        let h = fresh_set_hash();
        let commit = create_commit(&h, &ctx, &priv_key).unwrap();

        let wrong_ctx = SpaceContext {
            user_did: "did:plc:eve".to_string(),
            ..ctx
        };
        let result = verify_commit(&wrong_ctx, &commit, &pub_key);
        assert!(matches!(result, Err(SpaceError::CommitTagMismatch)));
    }
}
