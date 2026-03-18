//! Data Integrity proof verification for did:webvh log entries.
//!
//! Verifies `eddsa-jcs-2022` cryptosuite proofs using Ed25519 signatures
//! over JCS-canonicalized log entry content. Supports both controller proofs
//! and witness proofs.

use crate::errors::WebVHDIDError;

use super::jcs;
use super::model::DataIntegrityProof;
use super::scid::compute_multihash_base58btc;

/// Ed25519 multicodec prefix bytes.
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Verifies a Data Integrity proof against a log entry.
///
/// Validates that:
/// 1. The proof type is "DataIntegrityProof"
/// 2. The cryptosuite is "eddsa-jcs-2022"
/// 3. The signing key is in the authorized `update_keys` list
/// 4. The Ed25519 signature over the JCS-canonicalized entry is valid
pub fn verify_proof(
    entry: &serde_json::Value,
    proof: &DataIntegrityProof,
    update_keys: &[String],
    entry_index: usize,
) -> Result<(), WebVHDIDError> {
    // Validate proof type
    if proof.r#type != "DataIntegrityProof" {
        return Err(WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: format!("unexpected proof type: {}", proof.r#type),
        });
    }

    // Validate cryptosuite
    if proof.cryptosuite != "eddsa-jcs-2022" {
        return Err(WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: format!("unsupported cryptosuite: {}", proof.cryptosuite),
        });
    }

    // Extract multikey from verification method
    // Format: "did:key:{multikey}#{multikey}" or "did:key:{multikey}"
    let multikey = extract_multikey(&proof.verification_method).ok_or_else(|| {
        WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: format!(
                "cannot extract multikey from verification method: {}",
                proof.verification_method
            ),
        }
    })?;

    // Verify the key is in the authorized update keys
    if !update_keys.iter().any(|k| k == &multikey) {
        return Err(WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: format!("signing key {} not in update keys", multikey),
        });
    }

    // Decode the multikey to get Ed25519 public key bytes
    let public_key_bytes = decode_ed25519_multikey(&multikey).map_err(|details| {
        WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details,
        }
    })?;

    // Remove proof from entry and canonicalize
    let mut entry_without_proof = entry.clone();
    if let Some(obj) = entry_without_proof.as_object_mut() {
        obj.remove("proof");
    }
    let canonical = jcs::canonicalize(&entry_without_proof);

    // Decode the proof value (multibase base58btc encoded signature)
    let signature_bytes = decode_proof_value(&proof.proof_value).map_err(|details| {
        WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details,
        }
    })?;

    // Verify the Ed25519 signature
    verify_ed25519_signature(&public_key_bytes, canonical.as_bytes(), &signature_bytes).map_err(
        |details| WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details,
        },
    )
}

/// Verifies that at least one proof in the entry is valid.
///
/// Returns Ok if at least one proof verifies successfully against the update keys.
pub fn verify_any_proof(
    entry: &serde_json::Value,
    proofs: &[DataIntegrityProof],
    update_keys: &[String],
    entry_index: usize,
) -> Result<(), WebVHDIDError> {
    if proofs.is_empty() {
        return Err(WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: "no proofs present".to_string(),
        });
    }

    let mut last_error = None;
    for proof in proofs {
        match verify_proof(entry, proof, update_keys, entry_index) {
            Ok(()) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }

    Err(
        last_error.unwrap_or_else(|| WebVHDIDError::ProofVerificationFailed {
            entry: entry_index,
            details: "no valid proof found".to_string(),
        }),
    )
}

/// Extracts the multikey string from a DID key verification method.
///
/// Supports formats:
/// - `did:key:{multikey}#{multikey}` → `{multikey}`
/// - `did:key:{multikey}` → `{multikey}`
/// - `{multikey}` (bare) → `{multikey}`
fn extract_multikey(verification_method: &str) -> Option<String> {
    let key_part = if let Some(stripped) = verification_method.strip_prefix("did:key:") {
        // Take the part before the fragment (#) if present
        stripped.split('#').next()?
    } else {
        verification_method
    };

    if key_part.is_empty() {
        return None;
    }

    Some(key_part.to_string())
}

/// Decodes an Ed25519 multikey string to raw public key bytes.
///
/// Multikey format: `z` + base58btc(multicodec_prefix + raw_key_bytes)
/// Ed25519 multicodec prefix: `[0xed, 0x01]`
fn decode_ed25519_multikey(multikey: &str) -> Result<[u8; 32], String> {
    let (_, decoded) = multibase::decode(multikey)
        .map_err(|e| format!("failed to decode multibase key: {}", e))?;

    if decoded.len() < 2 {
        return Err("multikey too short".to_string());
    }

    if decoded[..2] != ED25519_PUB_MULTICODEC {
        return Err(format!(
            "unexpected multicodec prefix: [{:#04x}, {:#04x}], expected Ed25519 [{:#04x}, {:#04x}]",
            decoded[0], decoded[1], ED25519_PUB_MULTICODEC[0], ED25519_PUB_MULTICODEC[1]
        ));
    }

    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(format!(
            "invalid Ed25519 public key length: expected 32, got {}",
            key_bytes.len()
        ));
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(key_bytes);
    Ok(result)
}

/// Decodes a multibase-encoded proof value to raw signature bytes.
///
/// Proof values use base58btc encoding with `z` prefix.
fn decode_proof_value(proof_value: &str) -> Result<Vec<u8>, String> {
    let (_, decoded) = multibase::decode(proof_value)
        .map_err(|e| format!("failed to decode proof value: {}", e))?;
    Ok(decoded)
}

/// Verifies an Ed25519 signature.
fn verify_ed25519_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| format!("invalid Ed25519 public key: {}", e))?;

    let sig_bytes: &[u8; 64] = signature.try_into().map_err(|_| {
        format!(
            "invalid signature length: expected 64, got {}",
            signature.len()
        )
    })?;

    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);

    ed25519_dalek::Verifier::verify(&verifying_key, message, &sig)
        .map_err(|e| format!("Ed25519 signature verification failed: {}", e))
}

/// Verifies witness proofs for a log entry meet the configured threshold.
///
/// For each witness proof:
/// 1. Verifies the proof is a valid Data Integrity proof
/// 2. Checks the signing key belongs to a configured witness
/// 3. Accumulates the witness weight
/// 4. Returns Ok once the threshold is met
///
/// The witness proofs sign the same content as controller proofs — the
/// JCS-canonicalized entry without the `proof` field.
pub fn verify_witness_proofs(
    entry: &serde_json::Value,
    witness_proofs: &[DataIntegrityProof],
    witness_config: &super::model::WitnessConfig,
    entry_index: usize,
) -> Result<(), WebVHDIDError> {
    if witness_proofs.is_empty() {
        return Err(WebVHDIDError::WitnessVerificationFailed {
            entry: entry_index,
            details: "no witness proofs provided".to_string(),
        });
    }

    let mut accumulated_weight: usize = 0;

    for proof in witness_proofs {
        // Validate proof type and cryptosuite
        if proof.r#type != "DataIntegrityProof" || proof.cryptosuite != "eddsa-jcs-2022" {
            continue;
        }

        // Extract multikey from verification method
        let multikey = match extract_multikey(&proof.verification_method) {
            Some(k) => k,
            None => continue,
        };

        // Find matching witness and get its weight
        let did_key = format!("did:key:{}", multikey);
        let witness_weight = witness_config
            .witnesses
            .iter()
            .find(|w| w.id == did_key || w.id == multikey)
            .map(|w| w.weight);

        let weight = match witness_weight {
            Some(w) => w,
            None => continue, // Not a configured witness, skip
        };

        // Decode the Ed25519 public key
        let public_key_bytes = match decode_ed25519_multikey(&multikey) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        // Remove proof from entry and canonicalize
        let mut entry_without_proof = entry.clone();
        if let Some(obj) = entry_without_proof.as_object_mut() {
            obj.remove("proof");
        }
        let canonical = jcs::canonicalize(&entry_without_proof);

        // Decode and verify the signature
        let signature_bytes = match decode_proof_value(&proof.proof_value) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        if verify_ed25519_signature(&public_key_bytes, canonical.as_bytes(), &signature_bytes)
            .is_ok()
        {
            accumulated_weight += weight;
            if accumulated_weight >= witness_config.threshold {
                return Ok(());
            }
        }
    }

    Err(WebVHDIDError::WitnessVerificationFailed {
        entry: entry_index,
        details: format!(
            "witness threshold not met: accumulated weight {} < required threshold {}",
            accumulated_weight, witness_config.threshold
        ),
    })
}

/// Verifies pre-rotation key hashes.
///
/// When pre-rotation is active (previous entry's `nextKeyHashes` is non-empty),
/// at least one key in the current `updateKeys` must have a hash matching
/// one of the previous `nextKeyHashes`.
pub fn verify_prerotation(
    current_update_keys: &[String],
    prev_next_key_hashes: &[String],
    entry_index: usize,
) -> Result<(), WebVHDIDError> {
    if prev_next_key_hashes.is_empty() {
        return Ok(());
    }

    for key in current_update_keys {
        let key_hash = compute_multihash_base58btc(key.as_bytes());
        if prev_next_key_hashes.contains(&key_hash) {
            return Ok(());
        }
    }

    Err(WebVHDIDError::PreRotationKeyMismatch { entry: entry_index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyType, generate_key, sign as key_sign, to_public};
    use serde_json::json;

    fn make_ed25519_keypair() -> (ed25519_dalek::SigningKey, String) {
        let private_key = generate_key(KeyType::Ed25519Private).unwrap();
        let public_key = to_public(&private_key).unwrap();
        // Display formats as did:key:z...
        let did_key = format!("{}", &public_key);
        let multikey = did_key.strip_prefix("did:key:").unwrap().to_string();

        let signing_key =
            ed25519_dalek::SigningKey::from_bytes(private_key.bytes().try_into().unwrap());

        (signing_key, multikey)
    }

    fn sign_entry(signing_key: &ed25519_dalek::SigningKey, entry: &serde_json::Value) -> String {
        let mut entry_without_proof = entry.clone();
        if let Some(obj) = entry_without_proof.as_object_mut() {
            obj.remove("proof");
        }
        let canonical = jcs::canonicalize(&entry_without_proof);
        let signature = ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
        multibase::encode(multibase::Base::Base58Btc, signature.to_bytes())
    }

    #[test]
    fn test_extract_multikey_did_key_with_fragment() {
        let result = extract_multikey("did:key:z6MkTest#z6MkTest");
        assert_eq!(result, Some("z6MkTest".to_string()));
    }

    #[test]
    fn test_extract_multikey_did_key_without_fragment() {
        let result = extract_multikey("did:key:z6MkTest");
        assert_eq!(result, Some("z6MkTest".to_string()));
    }

    #[test]
    fn test_extract_multikey_bare() {
        let result = extract_multikey("z6MkTest");
        assert_eq!(result, Some("z6MkTest".to_string()));
    }

    #[test]
    fn test_extract_multikey_empty() {
        assert_eq!(extract_multikey("did:key:"), None);
    }

    #[test]
    fn test_decode_ed25519_multikey_valid() {
        let (_, multikey) = make_ed25519_keypair();
        let result = decode_ed25519_multikey(&multikey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_decode_ed25519_multikey_wrong_prefix() {
        // P-256 public key multicodec prefix
        let mut bytes = vec![0x80, 0x24];
        bytes.extend_from_slice(&[0x00; 32]);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &bytes);
        let result = decode_ed25519_multikey(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unexpected multicodec prefix"));
    }

    #[test]
    fn test_verify_proof_valid() {
        let (signing_key, multikey) = make_ed25519_keypair();

        let mut entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "did:webvh:test:example.com"}
        });

        let proof_value = sign_entry(&signing_key, &entry);
        let verification_method = format!("did:key:{}#{}", multikey, multikey);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method,
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        entry["proof"] = serde_json::to_value(&[&proof]).unwrap();

        let update_keys = vec![multikey];
        let result = verify_proof(&entry, &proof, &update_keys, 1);
        assert!(result.is_ok(), "proof verification failed: {:?}", result);
    }

    #[test]
    fn test_verify_proof_tampered_entry() {
        let (signing_key, multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "did:webvh:test:example.com"}
        });

        let proof_value = sign_entry(&signing_key, &entry);
        let verification_method = format!("did:key:{}#{}", multikey, multikey);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method,
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        // Tamper with the entry
        let mut tampered = entry;
        tampered["state"]["id"] = json!("did:webvh:test:evil.com");
        tampered["proof"] = serde_json::to_value(&[&proof]).unwrap();

        let update_keys = vec![multikey];
        let result = verify_proof(&tampered, &proof, &update_keys, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_proof_wrong_key() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (_, other_multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        let proof_value = sign_entry(&signing_key, &entry);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey, multikey),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        // Update keys only contains the other key
        let update_keys = vec![other_multikey];
        let result = verify_proof(&entry, &proof, &update_keys, 1);
        assert!(result.is_err());
        if let Err(WebVHDIDError::ProofVerificationFailed { details, .. }) = result {
            assert!(details.contains("not in update keys"));
        }
    }

    #[test]
    fn test_verify_proof_wrong_cryptosuite() {
        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "wrong-suite".to_string(),
            verification_method: "did:key:z6MkTest#z6MkTest".to_string(),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "zSig".to_string(),
        };

        let entry = json!({"proof": []});
        let result = verify_proof(&entry, &proof, &["z6MkTest".to_string()], 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_any_proof_empty() {
        let entry = json!({"versionId": "1-test"});
        let result = verify_any_proof(&entry, &[], &[], 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::ProofVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_prerotation_no_hashes() {
        // Empty prev hashes means pre-rotation is not active
        let result = verify_prerotation(&["z6MkTest".to_string()], &[], 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_prerotation_matching() {
        let key = "z6MkTestKey";
        let key_hash = compute_multihash_base58btc(key.as_bytes());

        let result = verify_prerotation(&[key.to_string()], &[key_hash], 2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_prerotation_no_match() {
        let result =
            verify_prerotation(&["z6MkNewKey".to_string()], &["zWrongHash".to_string()], 2);
        assert!(matches!(
            result,
            Err(WebVHDIDError::PreRotationKeyMismatch { entry: 2 })
        ));
    }

    #[test]
    fn test_verify_witness_proofs_threshold_met() {
        let (signing_key, multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "did:webvh:test:example.com"}
        });

        let proof_value = sign_entry(&signing_key, &entry);
        let verification_method = format!("did:key:{}#{}", multikey, multikey);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method,
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        let witness_config = super::super::model::WitnessConfig {
            threshold: 1,
            witnesses: vec![super::super::model::WitnessEntry {
                id: format!("did:key:{}", multikey),
                weight: 1,
            }],
        };

        let result = verify_witness_proofs(&entry, &[proof], &witness_config, 1);
        assert!(result.is_ok(), "witness verification failed: {:?}", result);
    }

    #[test]
    fn test_verify_witness_proofs_threshold_not_met() {
        let (signing_key, multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        let proof_value = sign_entry(&signing_key, &entry);
        let verification_method = format!("did:key:{}#{}", multikey, multikey);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method,
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        let witness_config = super::super::model::WitnessConfig {
            threshold: 3, // Requires weight of 3, but only 1 witness with weight 1
            witnesses: vec![super::super::model::WitnessEntry {
                id: format!("did:key:{}", multikey),
                weight: 1,
            }],
        };

        let result = verify_witness_proofs(&entry, &[proof], &witness_config, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::WitnessVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_witness_proofs_multiple_witnesses_weighted() {
        let (signing_key1, multikey1) = make_ed25519_keypair();
        let (signing_key2, multikey2) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        let proof1 = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey1, multikey1),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: sign_entry(&signing_key1, &entry),
        };

        let proof2 = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey2, multikey2),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: sign_entry(&signing_key2, &entry),
        };

        let witness_config = super::super::model::WitnessConfig {
            threshold: 3,
            witnesses: vec![
                super::super::model::WitnessEntry {
                    id: format!("did:key:{}", multikey1),
                    weight: 1,
                },
                super::super::model::WitnessEntry {
                    id: format!("did:key:{}", multikey2),
                    weight: 2,
                },
            ],
        };

        // Both witnesses together have weight 3, meeting threshold
        let result = verify_witness_proofs(&entry, &[proof1, proof2], &witness_config, 1);
        assert!(
            result.is_ok(),
            "weighted witness verification failed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_witness_proofs_empty() {
        let witness_config = super::super::model::WitnessConfig {
            threshold: 1,
            witnesses: vec![],
        };

        let entry = json!({"versionId": "1-test"});
        let result = verify_witness_proofs(&entry, &[], &witness_config, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::WitnessVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_witness_proofs_unknown_witness_skipped() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (_, unknown_multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey, multikey),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: sign_entry(&signing_key, &entry),
        };

        // Witness config only knows about a different key
        let witness_config = super::super::model::WitnessConfig {
            threshold: 1,
            witnesses: vec![super::super::model::WitnessEntry {
                id: format!("did:key:{}", unknown_multikey),
                weight: 1,
            }],
        };

        let result = verify_witness_proofs(&entry, &[proof], &witness_config, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::WitnessVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_witness_proofs_invalid_signature_skipped() {
        let (_, multikey) = make_ed25519_keypair();
        let (other_signing_key, _) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        // Sign with wrong key
        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey, multikey),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: sign_entry(&other_signing_key, &entry),
        };

        let witness_config = super::super::model::WitnessConfig {
            threshold: 1,
            witnesses: vec![super::super::model::WitnessEntry {
                id: format!("did:key:{}", multikey),
                weight: 1,
            }],
        };

        let result = verify_witness_proofs(&entry, &[proof], &witness_config, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::WitnessVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_proof_with_key_module() {
        // Test using the key module's Ed25519 support
        let private_key = generate_key(KeyType::Ed25519Private).unwrap();
        let public_key = to_public(&private_key).unwrap();
        let multikey = format!("{}", &public_key)
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "test"}
        });

        // Sign using key module
        let mut entry_without_proof = entry.clone();
        entry_without_proof.as_object_mut().unwrap().remove("proof");
        let canonical = jcs::canonicalize(&entry_without_proof);
        let signature = key_sign(&private_key, canonical.as_bytes()).unwrap();
        let proof_value = multibase::encode(multibase::Base::Base58Btc, &signature);

        let proof = DataIntegrityProof {
            r#type: "DataIntegrityProof".to_string(),
            cryptosuite: "eddsa-jcs-2022".to_string(),
            verification_method: format!("did:key:{}#{}", multikey, multikey),
            created: "2025-04-29T17:15:59Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        let update_keys = vec![multikey];
        let result = verify_proof(&entry, &proof, &update_keys, 1);
        assert!(result.is_ok(), "proof verification failed: {:?}", result);
    }
}
