//! PLC operation types (genesis, update, tombstone) with signing and verification.
//!
//! Operations are the fundamental building blocks of the did:plc audit log.
//! Each operation is signed, DAG-CBOR encoded, and forms a chain linked by CID references.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::errors::PLCDIDError;
use crate::key::{self, KeyData};

use super::encoding::{MAX_OPERATION_SIZE, base64url_decode, base64url_encode};
use super::state::ServiceEndpoint;

/// A signed PLC operation (genesis, update, or tombstone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Operation {
    /// Standard PLC operation (genesis or update).
    #[serde(rename = "plc_operation")]
    PlcOperation {
        /// Rotation keys (1-5 did:key strings).
        #[serde(rename = "rotationKeys")]
        rotation_keys: Vec<String>,

        /// Verification methods (max 10 entries).
        #[serde(rename = "verificationMethods")]
        verification_methods: HashMap<String, String>,

        /// Also-known-as URIs.
        #[serde(rename = "alsoKnownAs")]
        also_known_as: Vec<String>,

        /// Service endpoints.
        services: HashMap<String, ServiceEndpoint>,

        /// Previous operation CID, `null` for a genesis operation.
        ///
        /// Always serialized, including when `None`. did:plc defines `prev` as
        /// a required nullable field, and the reference directory validates
        /// with a strict schema that rejects the key being absent. Omitting it
        /// also changes the DAG-CBOR that is hashed for the DID and covered by
        /// the signature, so a skipped `prev` is not a JSON cosmetic.
        prev: Option<String>,

        /// Base64url-encoded signature.
        sig: String,
    },

    /// Tombstone operation (marks DID as deleted).
    #[serde(rename = "plc_tombstone")]
    PlcTombstone {
        /// Previous operation CID (never null for tombstone).
        prev: String,

        /// Base64url-encoded signature.
        sig: String,
    },

    /// Legacy create operation (for backwards compatibility).
    #[serde(rename = "create")]
    LegacyCreate {
        /// Signing key (did:key format).
        #[serde(rename = "signingKey")]
        signing_key: String,

        /// Recovery key (did:key format).
        #[serde(rename = "recoveryKey")]
        recovery_key: String,

        /// Handle (e.g., "alice.bsky.social").
        handle: String,

        /// Service endpoint URL.
        service: String,

        /// Previous operation CID.
        #[serde(skip_serializing_if = "Option::is_none")]
        prev: Option<String>,

        /// Base64url-encoded signature.
        sig: String,
    },
}

impl Operation {
    /// Create a new unsigned genesis operation.
    pub fn new_genesis(
        rotation_keys: Vec<String>,
        verification_methods: HashMap<String, String>,
        also_known_as: Vec<String>,
        services: HashMap<String, ServiceEndpoint>,
    ) -> UnsignedOperation {
        UnsignedOperation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            prev: None,
        }
    }

    /// Create a new unsigned update operation.
    pub fn new_update(
        rotation_keys: Vec<String>,
        verification_methods: HashMap<String, String>,
        also_known_as: Vec<String>,
        services: HashMap<String, ServiceEndpoint>,
        prev: String,
    ) -> UnsignedOperation {
        UnsignedOperation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            prev: Some(prev),
        }
    }

    /// Create a new unsigned tombstone operation.
    pub fn new_tombstone(prev: String) -> UnsignedOperation {
        UnsignedOperation::PlcTombstone { prev }
    }

    /// Get the previous operation CID, if any.
    pub fn prev(&self) -> Option<&str> {
        match self {
            Operation::PlcOperation { prev, .. } => prev.as_deref(),
            Operation::PlcTombstone { prev, .. } => Some(prev),
            Operation::LegacyCreate { prev, .. } => prev.as_deref(),
        }
    }

    /// Get the signature as a base64url string.
    pub fn signature(&self) -> &str {
        match self {
            Operation::PlcOperation { sig, .. } => sig,
            Operation::PlcTombstone { sig, .. } => sig,
            Operation::LegacyCreate { sig, .. } => sig,
        }
    }

    /// Check if this is a genesis operation (prev is None).
    pub fn is_genesis(&self) -> bool {
        self.prev().is_none()
    }

    /// Compute the CID of this operation.
    ///
    /// Uses DAG-CBOR encoding via `atproto_dasl` and returns the CID
    /// as a base32-lower string (CIDv1 with dag-cbor codec and SHA-256).
    pub fn cid(&self) -> Result<String, PLCDIDError> {
        let cid_core =
            atproto_dasl::compute_cid_for(self).map_err(|e| PLCDIDError::DagCborEncodeFailed {
                details: e.to_string(),
            })?;
        Ok(cid_core.to_string())
    }

    /// Verify the signature on this operation using the provided rotation keys.
    ///
    /// Tries each rotation key in order. Returns `Ok(())` if any key verifies
    /// the signature, or `PLCDIDError::SignatureVerificationFailed` if none do.
    pub fn verify(&self, rotation_keys: &[KeyData]) -> Result<(), PLCDIDError> {
        if rotation_keys.is_empty() {
            return Err(PLCDIDError::InvalidRotationKeys {
                details: "At least one rotation key is required for verification".to_string(),
            });
        }

        let unsigned_data = self.unsigned_bytes()?;
        let signature = base64url_decode(self.signature())?;

        for public_key_data in rotation_keys {
            if key::validate(public_key_data, &signature, &unsigned_data).is_ok() {
                return Ok(());
            }
        }

        Err(PLCDIDError::SignatureVerificationFailed)
    }

    /// Get the unsigned DAG-CBOR bytes that were signed.
    fn unsigned_bytes(&self) -> Result<Vec<u8>, PLCDIDError> {
        let unsigned = match self {
            Operation::PlcOperation {
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
                prev,
                ..
            } => UnsignedOperation::PlcOperation {
                rotation_keys: rotation_keys.clone(),
                verification_methods: verification_methods.clone(),
                also_known_as: also_known_as.clone(),
                services: services.clone(),
                prev: prev.clone(),
            },
            Operation::PlcTombstone { prev, .. } => {
                UnsignedOperation::PlcTombstone { prev: prev.clone() }
            }
            Operation::LegacyCreate {
                signing_key,
                recovery_key,
                handle,
                service,
                prev,
                ..
            } => UnsignedOperation::LegacyCreate {
                signing_key: signing_key.clone(),
                recovery_key: recovery_key.clone(),
                handle: handle.clone(),
                service: service.clone(),
                prev: prev.clone(),
            },
        };

        atproto_dasl::to_vec(&unsigned).map_err(|e| PLCDIDError::DagCborEncodeFailed {
            details: e.to_string(),
        })
    }

    /// Get the rotation keys from this operation, if any.
    pub fn rotation_keys(&self) -> Option<&[String]> {
        match self {
            Operation::PlcOperation { rotation_keys, .. } => Some(rotation_keys),
            _ => None,
        }
    }
}

/// An unsigned operation that needs to be signed before submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UnsignedOperation {
    /// Standard PLC operation (genesis or update).
    #[serde(rename = "plc_operation")]
    PlcOperation {
        /// Rotation keys for signing future operations.
        #[serde(rename = "rotationKeys")]
        rotation_keys: Vec<String>,

        /// Verification methods for authentication.
        #[serde(rename = "verificationMethods")]
        verification_methods: HashMap<String, String>,

        /// Also-known-as URIs (aliases).
        #[serde(rename = "alsoKnownAs")]
        also_known_as: Vec<String>,

        /// Service endpoints.
        services: HashMap<String, ServiceEndpoint>,

        /// CID of previous operation, `null` for a genesis operation.
        ///
        /// Always serialized — see the note on [`Operation::PlcOperation`].
        /// This is the form that is DAG-CBOR encoded and signed, so the two
        /// must agree or the signature covers different bytes than the
        /// directory verifies.
        prev: Option<String>,
    },

    /// Tombstone operation.
    #[serde(rename = "plc_tombstone")]
    PlcTombstone {
        /// CID of previous operation.
        prev: String,
    },

    /// Legacy create operation.
    #[serde(rename = "create")]
    LegacyCreate {
        /// Signing key for the DID.
        #[serde(rename = "signingKey")]
        signing_key: String,

        /// Recovery key for the DID.
        #[serde(rename = "recoveryKey")]
        recovery_key: String,

        /// Handle for the DID.
        handle: String,

        /// Service endpoint.
        service: String,

        /// CID of previous operation (None for genesis).
        #[serde(skip_serializing_if = "Option::is_none")]
        prev: Option<String>,
    },
}

impl UnsignedOperation {
    /// Sign this operation with the provided private key.
    ///
    /// Encodes the unsigned operation as DAG-CBOR, signs the bytes,
    /// and produces a signed `Operation` with the base64url-encoded signature.
    pub fn sign(self, private_key_data: &KeyData) -> Result<Operation, PLCDIDError> {
        let data = atproto_dasl::to_vec(&self).map_err(|e| PLCDIDError::DagCborEncodeFailed {
            details: e.to_string(),
        })?;

        if data.len() > MAX_OPERATION_SIZE {
            return Err(PLCDIDError::OperationTooLarge {
                size: data.len(),
                max: MAX_OPERATION_SIZE,
            });
        }

        let signature_bytes =
            key::sign(private_key_data, &data).map_err(|e| PLCDIDError::DagCborEncodeFailed {
                details: format!("Signing failed: {}", e),
            })?;

        let sig = base64url_encode(&signature_bytes);

        let operation = match self {
            UnsignedOperation::PlcOperation {
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
                prev,
            } => Operation::PlcOperation {
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
                prev,
                sig,
            },
            UnsignedOperation::PlcTombstone { prev } => Operation::PlcTombstone { prev, sig },
            UnsignedOperation::LegacyCreate {
                signing_key,
                recovery_key,
                handle,
                service,
                prev,
            } => Operation::LegacyCreate {
                signing_key,
                recovery_key,
                handle,
                service,
                prev,
                sig,
            },
        };

        Ok(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyType, generate_key, to_public};

    #[test]
    fn test_genesis_operation() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned =
            Operation::new_genesis(vec![did_key], HashMap::new(), vec![], HashMap::new());

        let signed = unsigned.sign(&private_key_data).unwrap();
        assert!(signed.is_genesis());
        assert_eq!(signed.prev(), None);
    }

    /// did:plc declares `prev` required and nullable, so a genesis operation
    /// carries `prev: null` rather than omitting the key. The reference
    /// directory validates with a strict schema and rejects the operation
    /// outright when it is absent — and because the same shape is DAG-CBOR
    /// encoded for signing and for the DID hash, omitting it changes the
    /// identifier as well as the JSON.
    #[test]
    fn genesis_serializes_prev_as_null() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned =
            Operation::new_genesis(vec![did_key], HashMap::new(), vec![], HashMap::new());
        let unsigned_json = serde_json::to_value(&unsigned).unwrap();
        assert_eq!(
            unsigned_json.get("prev"),
            Some(&serde_json::Value::Null),
            "unsigned genesis op must carry prev: null, got {unsigned_json}"
        );

        let signed = unsigned.sign(&private_key_data).unwrap();
        let signed_json = serde_json::to_value(&signed).unwrap();
        assert_eq!(
            signed_json.get("prev"),
            Some(&serde_json::Value::Null),
            "signed genesis op must carry prev: null, got {signed_json}"
        );
    }

    #[test]
    fn test_update_operation() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned = Operation::new_update(
            vec![did_key],
            HashMap::new(),
            vec![],
            HashMap::new(),
            "bafyreib2rxk3rybk3aobmv5msrxhgt7h4b4kfzxx4wxltyqu7e7vgq".to_string(),
        );

        let signed = unsigned.sign(&private_key_data).unwrap();
        assert!(!signed.is_genesis());
        assert!(signed.prev().is_some());
    }

    #[test]
    fn test_tombstone_operation() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();

        let unsigned = Operation::new_tombstone(
            "bafyreib2rxk3rybk3aobmv5msrxhgt7h4b4kfzxx4wxltyqu7e7vgq".to_string(),
        );

        let signed = unsigned.sign(&private_key_data).unwrap();
        assert!(!signed.is_genesis());
        assert!(signed.prev().is_some());
    }

    #[test]
    fn test_sign_and_verify() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let public_key_data = to_public(&private_key_data).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned =
            Operation::new_genesis(vec![did_key], HashMap::new(), vec![], HashMap::new());

        let signed = unsigned.sign(&private_key_data).unwrap();

        // Verify should succeed with the public key
        assert!(signed.verify(&[public_key_data]).is_ok());

        // Verify with wrong key should fail
        let wrong_key = generate_key(KeyType::P256Private).unwrap();
        let wrong_public = to_public(&wrong_key).unwrap();
        assert!(signed.verify(&[wrong_public]).is_err());
    }

    #[test]
    fn test_operation_cid() {
        let private_key_data = generate_key(KeyType::P256Private).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned =
            Operation::new_genesis(vec![did_key], HashMap::new(), vec![], HashMap::new());

        let signed = unsigned.sign(&private_key_data).unwrap();
        let cid = signed.cid().unwrap();

        // CIDv1 in base32 starts with 'b'
        assert!(cid.starts_with('b'));
    }

    #[test]
    fn test_sign_and_verify_k256() {
        let private_key_data = generate_key(KeyType::K256Private).unwrap();
        let public_key_data = to_public(&private_key_data).unwrap();
        let did_key = format!("{}", private_key_data);

        let unsigned =
            Operation::new_genesis(vec![did_key], HashMap::new(), vec![], HashMap::new());

        let signed = unsigned.sign(&private_key_data).unwrap();
        assert!(signed.verify(&[public_key_data]).is_ok());
    }
}
