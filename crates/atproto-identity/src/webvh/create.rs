//! Creation utilities for did:webvh genesis documents and update entries.
//!
//! Provides functions to create new did:webvh identities and append update
//! entries to existing DID logs. Genesis entries are signed with Ed25519
//! Data Integrity proofs using the `eddsa-jcs-2022` cryptosuite.

use chrono::Utc;
use serde_json::json;

use crate::errors::WebVHDIDError;
use crate::key::{self, KeyData, KeyType};

use super::jcs;
use super::model::{DataIntegrityProof, LogEntry};
use super::scid::{compute_entry_hash, compute_multihash_base58btc};

/// Result of creating a new did:webvh genesis document.
pub struct GenesisResult {
    /// The derived DID string (e.g., `did:webvh:{scid}:example.com`).
    pub did: String,
    /// The computed Self-Certifying Identifier.
    pub scid: String,
    /// The complete did.jsonl content (single line).
    pub jsonl: String,
    /// The genesis log entry as a JSON value.
    pub entry: serde_json::Value,
    /// The Ed25519 public key (multibase-encoded did:key string).
    pub update_key: String,
}

/// Creates a new did:webvh genesis log entry.
///
/// Generates an Ed25519 signing key (or uses the provided one), constructs
/// the genesis entry with a Data Integrity proof, computes the SCID, and
/// returns the complete did.jsonl content and derived DID.
///
/// The `signing_key` must be an Ed25519 private key. If not provided, a new
/// key pair is generated.
pub fn create_genesis(
    hostname: &str,
    path: Option<&str>,
    signing_key: Option<&KeyData>,
) -> Result<GenesisResult, WebVHDIDError> {
    // Generate or use provided Ed25519 key
    let (private_key, public_key) = match signing_key {
        Some(key) => {
            let public = key::to_public(key).map_err(|e| WebVHDIDError::SigningFailed {
                details: format!("failed to derive public key: {}", e),
            })?;
            (key.clone(), public)
        }
        None => {
            let private = key::generate_key(KeyType::Ed25519Private).map_err(|e| {
                WebVHDIDError::GenesisCreationFailed {
                    details: format!("failed to generate Ed25519 key: {}", e),
                }
            })?;
            let public =
                key::to_public(&private).map_err(|e| WebVHDIDError::GenesisCreationFailed {
                    details: format!("failed to derive public key: {}", e),
                })?;
            (private, public)
        }
    };

    let multikey = format!("{}", public_key)
        .strip_prefix("did:key:")
        .ok_or_else(|| WebVHDIDError::GenesisCreationFailed {
            details: "failed to extract multikey from public key".to_string(),
        })?
        .to_string();

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Build the DID path suffix
    let did_suffix = match path {
        Some(p) => format!("{}:{}", hostname, p.replace('/', ":")),
        None => hostname.to_string(),
    };

    // Step 1: Build preliminary entry with {SCID} placeholders
    let preliminary = json!({
        "versionId": "{SCID}",
        "versionTime": now,
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "{SCID}",
            "updateKeys": [multikey],
        },
        "state": {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1"
            ],
            "id": format!("did:webvh:{{SCID}}:{}", did_suffix),
            "authentication": [{
                "id": format!("did:webvh:{{SCID}}:{}#{}", did_suffix, multikey),
                "type": "Multikey",
                "controller": format!("did:webvh:{{SCID}}:{}", did_suffix),
                "publicKeyMultibase": multikey,
            }],
        }
    });

    // Step 2: Compute SCID from JCS-canonicalized preliminary entry
    let canonical = jcs::canonicalize(&preliminary);
    let scid = compute_multihash_base58btc(canonical.as_bytes());

    // Step 3: Replace {SCID} with actual value
    let json_str =
        serde_json::to_string(&preliminary).map_err(|e| WebVHDIDError::GenesisCreationFailed {
            details: format!("failed to serialize preliminary entry: {}", e),
        })?;
    let replaced = json_str.replace("{SCID}", &scid);
    let mut entry: serde_json::Value =
        serde_json::from_str(&replaced).map_err(|e| WebVHDIDError::GenesisCreationFailed {
            details: format!("failed to parse replaced entry: {}", e),
        })?;

    // Step 4: Recompute versionId with actual entry hash
    let entry_hash = compute_entry_hash(&entry)?;
    entry["versionId"] = json!(format!("1-{}", entry_hash));

    // Step 5: Sign the entry (without proof field) using Ed25519
    let entry_without_proof = {
        let mut e = entry.clone();
        if let Some(obj) = e.as_object_mut() {
            obj.remove("proof");
        }
        e
    };
    let canonical_for_signing = jcs::canonicalize(&entry_without_proof);
    let signature = key::sign(&private_key, canonical_for_signing.as_bytes()).map_err(|e| {
        WebVHDIDError::SigningFailed {
            details: format!("Ed25519 signing failed: {}", e),
        }
    })?;
    let proof_value = multibase::encode(multibase::Base::Base58Btc, &signature);

    // Step 6: Construct Data Integrity proof
    let verification_method = format!("did:key:{}#{}", multikey, multikey);
    let proof = DataIntegrityProof {
        r#type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-jcs-2022".to_string(),
        verification_method,
        created: now.clone(),
        proof_purpose: "assertionMethod".to_string(),
        proof_value,
    };

    entry["proof"] =
        serde_json::to_value([&proof]).map_err(|e| WebVHDIDError::GenesisCreationFailed {
            details: format!("failed to serialize proof: {}", e),
        })?;

    let did = format!("did:webvh:{}:{}", scid, did_suffix);
    let jsonl =
        serde_json::to_string(&entry).map_err(|e| WebVHDIDError::GenesisCreationFailed {
            details: format!("failed to serialize entry: {}", e),
        })?;

    Ok(GenesisResult {
        did,
        scid,
        jsonl,
        entry,
        update_key: format!("did:key:{}", multikey),
    })
}

/// Creates a new update log entry for an existing did:webvh DID.
///
/// Parses the current log, creates a new entry with the updated DID document
/// state, signs it with the provided Ed25519 key, and returns the new JSONL
/// line to append.
pub fn create_update_entry(
    did: &str,
    current_log: &str,
    new_state: serde_json::Value,
    signing_key: &KeyData,
    new_update_keys: Option<Vec<String>>,
) -> Result<String, WebVHDIDError> {
    // Parse current log to get last entry
    let lines: Vec<&str> = current_log
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err(WebVHDIDError::UpdateCreationFailed {
            details: "current log is empty".to_string(),
        });
    }

    let last_entry: LogEntry = serde_json::from_str(lines.last().unwrap()).map_err(|e| {
        WebVHDIDError::UpdateCreationFailed {
            details: format!("failed to parse last log entry: {}", e),
        }
    })?;

    // Parse version number from last entry
    let version_num: u64 = last_entry
        .version_id
        .split('-')
        .next()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| WebVHDIDError::UpdateCreationFailed {
            details: "failed to parse version number from last entry".to_string(),
        })?;

    let new_version = version_num + 1;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Build parameters (only include changed parameters)
    let parameters = match new_update_keys {
        Some(keys) => json!({ "updateKeys": keys }),
        None => json!({}),
    };

    // Build the new entry (without proof, with placeholder versionId)
    let mut entry = json!({
        "versionId": format!("{}-placeholder", new_version),
        "versionTime": now,
        "parameters": parameters,
        "state": new_state,
    });

    // Compute entry hash and set proper versionId
    let entry_hash = compute_entry_hash(&entry)?;
    entry["versionId"] = json!(format!("{}-{}", new_version, entry_hash));

    // Get public key for verification method
    let public_key = key::to_public(signing_key).map_err(|e| WebVHDIDError::SigningFailed {
        details: format!("failed to derive public key: {}", e),
    })?;
    let multikey = format!("{}", public_key)
        .strip_prefix("did:key:")
        .ok_or_else(|| WebVHDIDError::SigningFailed {
            details: "failed to extract multikey from public key".to_string(),
        })?
        .to_string();

    // Sign the entry
    let entry_without_proof = {
        let mut e = entry.clone();
        if let Some(obj) = e.as_object_mut() {
            obj.remove("proof");
        }
        e
    };
    let canonical = jcs::canonicalize(&entry_without_proof);
    let signature =
        key::sign(signing_key, canonical.as_bytes()).map_err(|e| WebVHDIDError::SigningFailed {
            details: format!("Ed25519 signing failed: {}", e),
        })?;
    let proof_value = multibase::encode(multibase::Base::Base58Btc, &signature);

    let proof = DataIntegrityProof {
        r#type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-jcs-2022".to_string(),
        verification_method: format!("did:key:{}#{}", multikey, multikey),
        created: now,
        proof_purpose: "assertionMethod".to_string(),
        proof_value,
    };

    entry["proof"] =
        serde_json::to_value([&proof]).map_err(|e| WebVHDIDError::UpdateCreationFailed {
            details: format!("failed to serialize proof: {}", e),
        })?;

    let _ = did; // Used for context validation in future enhancements

    serde_json::to_string(&entry).map_err(|e| WebVHDIDError::UpdateCreationFailed {
        details: format!("failed to serialize update entry: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_genesis_basic() {
        let result = create_genesis("example.com", None, None).unwrap();
        assert!(result.did.starts_with("did:webvh:"));
        assert!(result.did.contains("example.com"));
        assert!(result.scid.starts_with('z'));
        assert!(!result.jsonl.is_empty());
        assert!(result.update_key.starts_with("did:key:"));
    }

    #[test]
    fn test_create_genesis_with_path() {
        let result = create_genesis("example.com", Some("dids/issuer"), None).unwrap();
        assert!(result.did.contains("example.com:dids:issuer"));
    }

    #[test]
    fn test_create_genesis_with_provided_key() {
        let key = key::generate_key(KeyType::Ed25519Private).unwrap();
        let result = create_genesis("example.com", None, Some(&key)).unwrap();
        assert!(result.did.starts_with("did:webvh:"));
    }

    #[test]
    fn test_create_genesis_entry_has_proof() {
        let result = create_genesis("example.com", None, None).unwrap();
        let entry: serde_json::Value = serde_json::from_str(&result.jsonl).unwrap();
        assert!(entry.get("proof").is_some());
        let proofs = entry["proof"].as_array().unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0]["type"], "DataIntegrityProof");
        assert_eq!(proofs[0]["cryptosuite"], "eddsa-jcs-2022");
    }

    #[test]
    fn test_create_update_entry() {
        let key = key::generate_key(KeyType::Ed25519Private).unwrap();
        let genesis = create_genesis("example.com", None, Some(&key)).unwrap();

        let new_state = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": &genesis.did,
            "service": [{
                "id": format!("{}#pds", genesis.did),
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        });

        let update_line =
            create_update_entry(&genesis.did, &genesis.jsonl, new_state, &key, None).unwrap();
        assert!(!update_line.is_empty());

        let update_entry: serde_json::Value = serde_json::from_str(&update_line).unwrap();
        assert!(
            update_entry["versionId"]
                .as_str()
                .unwrap()
                .starts_with("2-")
        );
    }
}
