//! Signed commit object for AT Protocol repositories.
//!
//! The commit is the root object of a repository, containing:
//! - DID of the repository owner
//! - Version number (must be 3)
//! - CID of the MST root
//! - Revision string (TID format)
//! - Optional previous commit CID
//! - Signature

use crate::errors::RepoError;
use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

/// A signed commit object representing a repository state.
///
/// # DAG-CBOR Format
///
/// ```json
/// {
///   "did": "did:plc:...",
///   "version": 3,
///   "data": CID,         // MST root
///   "rev": "3jui7kd2z2y2e",
///   "prev": CID | null,  // prior commit CID, deprecated by Sync 1.1
///   "sig": bytes         // signature
/// }
/// ```
///
/// The commit carries exactly these keys. Adding one — even an optional one —
/// changes the encoded bytes, and so changes both the signature and the commit
/// CID, which is why the set is fixed rather than extensible.
///
/// # Sync 1.1
///
/// Inductive verification uses `prevData`, the **prior MST root CID** (not the
/// prior commit CID), which lets a verifier holding the previous `data` check a
/// new commit's MST against the operations in the event without retaining full
/// repo state. That field belongs to the `com.atproto.sync.subscribeRepos`
/// `#commit` event, **not** to the commit object: it is per-delivery
/// information, not repository state, and it is not part of what the repository
/// owner signs. See [`crate::repo::verify_inductive`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// DID of the repository owner.
    pub did: String,

    /// Commit format version (must be 3).
    pub version: u64,

    /// CID of the MST root node.
    pub data: Cid,

    /// Revision string (TID format).
    pub rev: String,

    /// CID of previous commit (`None` for the initial commit).
    ///
    /// Serialized as an explicit `null` when absent, never omitted: the
    /// commit schema types this as nullable-and-required, so dropping the
    /// key changes the signed bytes and the commit CID.
    pub prev: Option<Cid>,

    /// Signature bytes (raw ECDSA signature).
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Unsigned commit for signing.
///
/// This is the commit without the signature field, used for
/// computing the bytes to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedCommit {
    /// DID of the repository owner.
    pub did: String,

    /// Commit format version (must be 3).
    pub version: u64,

    /// CID of the MST root node.
    pub data: Cid,

    /// Revision string (TID format).
    pub rev: String,

    /// CID of previous commit (`None` for the initial commit).
    ///
    /// Serialized as an explicit `null` when absent, never omitted: the
    /// commit schema types this as nullable-and-required, so dropping the
    /// key changes the signed bytes and the commit CID.
    pub prev: Option<Cid>,
}

impl Commit {
    /// Create an unsigned commit.
    #[must_use]
    pub fn new_unsigned(did: String, data: Cid, rev: String, prev: Option<Cid>) -> UnsignedCommit {
        UnsignedCommit {
            did,
            version: 3,
            data,
            rev,
            prev,
        }
    }

    /// Serialize for signing (excludes sig field).
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if serialization fails.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, RepoError> {
        let unsigned = UnsignedCommit {
            did: self.did.clone(),
            version: self.version,
            data: self.data.clone(),
            rev: self.rev.clone(),
            prev: self.prev.clone(),
        };

        atproto_dasl::to_vec(&unsigned).map_err(|e| RepoError::InvalidCommit {
            reason: format!("failed to encode unsigned commit: {}", e),
        })
    }

    /// Serialize to DAG-CBOR.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RepoError> {
        atproto_dasl::to_vec(self).map_err(|e| RepoError::InvalidCommit {
            reason: format!("failed to encode commit: {}", e),
        })
    }

    /// Deserialize from DAG-CBOR.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RepoError> {
        atproto_dasl::from_slice(bytes).map_err(|e| RepoError::InvalidCommit {
            reason: format!("failed to decode commit: {}", e),
        })
    }

    /// Compute CID for this commit.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if serialization fails.
    pub fn cid(&self) -> Result<cid::Cid, RepoError> {
        let bytes = self.to_bytes()?;
        Ok(crate::compute_cid(&bytes))
    }

    /// Validate the commit structure.
    ///
    /// Checks:
    /// - Version is 3
    /// - DID is not empty
    /// - Rev is not empty
    /// - Signature is not empty
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if validation fails.
    pub fn validate(&self) -> Result<(), RepoError> {
        if self.version != 3 {
            return Err(RepoError::UnsupportedCommitVersion {
                version: self.version,
            });
        }

        if self.did.is_empty() {
            return Err(RepoError::MissingCommitField {
                field: "did".to_string(),
            });
        }

        if !self.did.starts_with("did:") {
            return Err(RepoError::InvalidDid {
                did: self.did.clone(),
            });
        }

        if self.rev.is_empty() {
            return Err(RepoError::MissingCommitField {
                field: "rev".to_string(),
            });
        }

        if self.sig.is_empty() {
            return Err(RepoError::MissingCommitField {
                field: "sig".to_string(),
            });
        }

        Ok(())
    }
}

impl UnsignedCommit {
    /// Create a new unsigned commit.
    #[must_use]
    pub fn new(did: String, data: Cid, rev: String, prev: Option<Cid>) -> Self {
        Self {
            did,
            version: 3,
            data,
            rev,
            prev,
        }
    }

    /// Serialize to DAG-CBOR for signing.
    ///
    /// # Errors
    ///
    /// Returns error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RepoError> {
        atproto_dasl::to_vec(self).map_err(|e| RepoError::InvalidCommit {
            reason: format!("failed to encode unsigned commit: {}", e),
        })
    }

    /// Convert to signed commit by adding a signature.
    #[must_use]
    pub fn sign(self, sig: Vec<u8>) -> Commit {
        Commit {
            did: self.did,
            version: self.version,
            data: self.data,
            rev: self.rev,
            prev: self.prev,
            sig,
        }
    }
}

/// Result of signature verification.
#[derive(Debug, Clone)]
pub struct SignatureVerification {
    /// Whether the signature is valid.
    pub valid: bool,
    /// The DID that signed the commit.
    pub signer_did: String,
    /// The key ID used for signing (from DID document).
    pub key_id: Option<String>,
}

impl SignatureVerification {
    /// Create a successful verification result.
    #[must_use]
    pub fn valid(signer_did: String, key_id: Option<String>) -> Self {
        Self {
            valid: true,
            signer_did,
            key_id,
        }
    }

    /// Create a failed verification result.
    #[must_use]
    pub fn invalid(signer_did: String) -> Self {
        Self {
            valid: false,
            signer_did,
            key_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_cid;

    fn test_cid() -> Cid {
        compute_cid(b"test").into()
    }

    #[test]
    fn test_unsigned_commit() {
        let unsigned = UnsignedCommit::new(
            "did:plc:test".to_string(),
            test_cid(),
            "3jui7kd2z2y2e".to_string(),
            None,
        );

        assert_eq!(unsigned.version, 3);
        assert_eq!(unsigned.did, "did:plc:test");
    }

    #[test]
    fn test_sign_commit() {
        let unsigned = UnsignedCommit::new(
            "did:plc:test".to_string(),
            test_cid(),
            "3jui7kd2z2y2e".to_string(),
            None,
        );

        let sig = vec![1, 2, 3, 4];
        let signed = unsigned.sign(sig.clone());

        assert_eq!(signed.sig, sig);
        assert_eq!(signed.version, 3);
    }

    #[test]
    fn test_commit_roundtrip() {
        let commit = Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };

        let bytes = commit.to_bytes().unwrap();
        let decoded = Commit::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.did, commit.did);
        assert_eq!(decoded.version, commit.version);
        assert_eq!(decoded.rev, commit.rev);
        assert_eq!(decoded.sig, commit.sig);
    }

    #[test]
    fn test_commit_with_prev() {
        let prev_cid = compute_cid(b"prev").into();
        let commit = Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: Some(prev_cid),
            sig: vec![1, 2, 3, 4],
        };

        let bytes = commit.to_bytes().unwrap();
        let decoded = Commit::from_bytes(&bytes).unwrap();

        assert!(decoded.prev.is_some());
    }

    #[test]
    fn test_validate_commit() {
        let valid_commit = Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };

        assert!(valid_commit.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_version() {
        let commit = Commit {
            did: "did:plc:test".to_string(),
            version: 2,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };

        assert!(matches!(
            commit.validate(),
            Err(RepoError::UnsupportedCommitVersion { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_did() {
        let commit = Commit {
            did: "invalid".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };

        assert!(matches!(
            commit.validate(),
            Err(RepoError::InvalidDid { .. })
        ));
    }

    #[test]
    fn test_validate_empty_sig() {
        let commit = Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![],
        };

        assert!(matches!(
            commit.validate(),
            Err(RepoError::MissingCommitField { .. })
        ));
    }

    /// A commit as this crate used to write it, carrying `prevData` in the
    /// body. Used to prove such a commit still decodes.
    #[derive(Serialize)]
    struct LegacyCommitWithPrevData {
        did: String,
        version: u64,
        data: Cid,
        rev: String,
        prev: Option<Cid>,
        #[serde(rename = "prevData")]
        prev_data: Option<Cid>,
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
    }

    /// A commit encoded with a `prevData` key still decodes; the key is ignored.
    ///
    /// `prevData` moved to the `subscribeRepos` `#commit` event, so it is no
    /// longer a field of [`Commit`]. Repositories written before that change
    /// have it in the body, and reading them must not break. (Their signatures
    /// no longer verify, because the signed bytes included the extra key — but
    /// that is a property of those commits, not of the decoder.)
    #[test]
    fn test_commit_with_legacy_prev_data_key_still_decodes() {
        let legacy = LegacyCommitWithPrevData {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: Some(compute_cid(b"prev").into()),
            prev_data: Some(compute_cid(b"prev_data").into()),
            sig: vec![1, 2, 3, 4],
        };
        let bytes = atproto_dasl::to_vec(&legacy).unwrap();

        let decoded = Commit::from_bytes(&bytes).expect("legacy commit should still decode");
        assert_eq!(decoded.did, "did:plc:test");
        assert_eq!(decoded.rev, "3jui7kd2z2y2e");
        assert_eq!(decoded.sig, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_signing_bytes() {
        let commit = Commit {
            did: "did:plc:test".to_string(),
            version: 3,
            data: test_cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            prev: None,
            sig: vec![1, 2, 3, 4],
        };

        let signing_bytes = commit.signing_bytes().unwrap();

        // Signing bytes should not contain the signature
        let unsigned: UnsignedCommit = atproto_dasl::from_slice(&signing_bytes).unwrap();
        assert_eq!(unsigned.did, commit.did);
    }
}
