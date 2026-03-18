//! SCID computation, verification, and entry hash operations for did:webvh.
//!
//! Implements the Self-Certifying Identifier (SCID) algorithm and entry hash
//! computation used to create verifiable chains of DID document updates.
//! All hashing uses SHA-256 with multihash encoding and base58btc multibase output.

use sha2::{Digest, Sha256};

use crate::errors::WebVHDIDError;

use super::jcs;

/// SHA-256 multihash header: algorithm identifier (0x12) + digest length (0x20 = 32 bytes).
const MULTIHASH_SHA256_HEADER: [u8; 2] = [0x12, 0x20];

/// Valid base58btc alphabet characters.
const BASE58BTC_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Minimum expected SCID length in base58btc characters (includes 'z' prefix).
const SCID_MIN_LENGTH: usize = 45;

/// Maximum expected SCID length in base58btc characters (includes 'z' prefix).
const SCID_MAX_LENGTH: usize = 48;

/// Hash algorithms supported by did:webvh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (multihash code 0x12, digest length 0x20).
    Sha256,
}

/// Detects the hash algorithm from a base58btc-encoded multihash SCID.
///
/// Decodes the multibase string, reads the multihash header, and returns
/// the identified algorithm.
pub fn detect_hash_algorithm(scid: &str) -> Result<HashAlgorithm, WebVHDIDError> {
    let (_, decoded) = multibase::decode(scid).map_err(|e| WebVHDIDError::InvalidSCIDFormat {
        details: format!("failed to decode SCID multibase: {}", e),
    })?;

    if decoded.len() < 2 {
        return Err(WebVHDIDError::InvalidSCIDFormat {
            details: "SCID multihash too short".to_string(),
        });
    }

    match (decoded[0], decoded[1]) {
        (0x12, 0x20) => Ok(HashAlgorithm::Sha256),
        (code, length) => Err(WebVHDIDError::UnsupportedHashAlgorithm {
            details: format!(
                "multihash code {:#04x} with length {:#04x} is not supported",
                code, length
            ),
        }),
    }
}

/// Validates the hash algorithm in a SCID matches the permitted algorithms
/// for the given method version.
///
/// For "did:webvh:1.0" and "did:webvh:0.5", only SHA-256 is permitted.
pub fn validate_hash_algorithm(
    scid: &str,
    method_version: &str,
) -> Result<HashAlgorithm, WebVHDIDError> {
    let algorithm = detect_hash_algorithm(scid)?;

    match method_version {
        "did:webvh:1.0" | "did:webvh:0.5" => match algorithm {
            HashAlgorithm::Sha256 => Ok(algorithm),
        },
        _ => Err(WebVHDIDError::UnsupportedHashAlgorithm {
            details: format!("unknown method version: {}", method_version),
        }),
    }
}

/// Validates the format of a SCID string.
///
/// Checks that the SCID:
/// - Is exactly 46 characters long
/// - Contains only valid base58btc characters
/// - Starts with 'z' (base58btc multibase prefix)
pub fn validate_scid_format(scid: &str) -> Result<(), WebVHDIDError> {
    if !scid.starts_with('z') {
        return Err(WebVHDIDError::InvalidSCIDFormat {
            details: format!(
                "SCID must start with 'z' (base58btc prefix), got '{}'",
                scid.chars().next().unwrap_or(' ')
            ),
        });
    }

    if scid.len() < SCID_MIN_LENGTH || scid.len() > SCID_MAX_LENGTH {
        return Err(WebVHDIDError::InvalidSCIDFormat {
            details: format!(
                "SCID must be {}-{} characters, got {}",
                SCID_MIN_LENGTH,
                SCID_MAX_LENGTH,
                scid.len()
            ),
        });
    }

    // Check all characters after the 'z' prefix are valid base58btc
    for ch in scid[1..].chars() {
        if !BASE58BTC_ALPHABET.contains(ch) {
            return Err(WebVHDIDError::InvalidSCIDFormat {
                details: format!("invalid base58btc character in SCID: '{}'", ch),
            });
        }
    }

    Ok(())
}

/// Computes a SHA-256 multihash of the input data.
///
/// Returns bytes in the format: `[0x12, 0x20, ...32 hash bytes...]`
pub fn compute_multihash_sha256(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(data);
    let mut result = Vec::with_capacity(2 + hash.len());
    result.extend_from_slice(&MULTIHASH_SHA256_HEADER);
    result.extend_from_slice(&hash);
    result
}

/// Computes the base58btc-encoded multihash of the input data.
///
/// Returns the multibase-encoded string with the `z` prefix (base58btc).
pub fn compute_multihash_base58btc(data: &[u8]) -> String {
    let multihash = compute_multihash_sha256(data);
    multibase::encode(multibase::Base::Base58Btc, &multihash)
}

/// Computes the entry hash for a log entry.
///
/// Algorithm:
/// 1. Remove the `proof` and `versionId` fields from the entry
/// 2. JCS-canonicalize the result
/// 3. SHA-256 multihash the canonical bytes
/// 4. Base58btc multibase encode
///
/// The `versionId` is excluded because it contains the hash itself
/// (format: `{N}-{hash}`), making its inclusion circular.
pub fn compute_entry_hash(entry: &serde_json::Value) -> Result<String, WebVHDIDError> {
    let mut hashable = entry.clone();
    if let Some(obj) = hashable.as_object_mut() {
        obj.remove("proof");
        obj.remove("versionId");
    } else {
        return Err(WebVHDIDError::InvalidVersionId {
            entry: 0,
            details: "log entry is not a JSON object".to_string(),
        });
    }

    let canonical = jcs::canonicalize(&hashable);
    Ok(compute_multihash_base58btc(canonical.as_bytes()))
}

/// Parses a version ID into its number and hash components.
///
/// Version IDs have the format `{number}-{hash}`, e.g., `1-QmV8pidQB1...`.
pub fn parse_version_id(version_id: &str) -> Result<(u64, &str), WebVHDIDError> {
    let dash_pos = version_id
        .find('-')
        .ok_or_else(|| WebVHDIDError::InvalidVersionId {
            entry: 0,
            details: format!("missing dash separator in version ID: {}", version_id),
        })?;

    let number_str = &version_id[..dash_pos];
    let hash = &version_id[dash_pos + 1..];

    let number: u64 = number_str
        .parse()
        .map_err(|_| WebVHDIDError::InvalidVersionId {
            entry: 0,
            details: format!("invalid version number: {}", number_str),
        })?;

    if hash.is_empty() {
        return Err(WebVHDIDError::InvalidVersionId {
            entry: 0,
            details: "empty hash in version ID".to_string(),
        });
    }

    Ok((number, hash))
}

/// Verifies the entry hash matches the hash component of the version ID.
///
/// Returns the parsed version number on success.
pub fn verify_version_id(
    entry: &serde_json::Value,
    expected_number: u64,
    entry_index: usize,
) -> Result<u64, WebVHDIDError> {
    let version_id = entry
        .get("versionId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WebVHDIDError::InvalidVersionId {
            entry: entry_index,
            details: "missing or non-string versionId".to_string(),
        })?;

    let (number, expected_hash) = parse_version_id(version_id).map_err(|e| {
        if let WebVHDIDError::InvalidVersionId { details, .. } = e {
            WebVHDIDError::InvalidVersionId {
                entry: entry_index,
                details,
            }
        } else {
            e
        }
    })?;

    if number != expected_number {
        return Err(WebVHDIDError::InvalidVersionId {
            entry: entry_index,
            details: format!("expected version {}, got {}", expected_number, number),
        });
    }

    let computed_hash = compute_entry_hash(entry)?;

    if computed_hash != expected_hash {
        return Err(WebVHDIDError::EntryHashVerificationFailed { entry: entry_index });
    }

    Ok(number)
}

/// Verifies the SCID of a genesis log entry.
///
/// Algorithm:
/// 1. Clone the genesis entry and remove `proof`
/// 2. Replace `versionId` with the literal string `"{SCID}"`
/// 3. Text-replace all occurrences of the actual SCID with `{SCID}`
/// 4. JCS-canonicalize and compute multihash
/// 5. Compare with the provided SCID
pub fn verify_scid(scid: &str, genesis_entry: &serde_json::Value) -> Result<(), WebVHDIDError> {
    let mut entry = genesis_entry.clone();

    // Remove proof
    if let Some(obj) = entry.as_object_mut() {
        obj.remove("proof");
    }

    // Set versionId to "{SCID}"
    if let Some(obj) = entry.as_object_mut() {
        obj.insert(
            "versionId".to_string(),
            serde_json::Value::String("{SCID}".to_string()),
        );
    }

    // Serialize to JSON string
    let json_str = serde_json::to_string(&entry).map_err(|e| WebVHDIDError::InvalidSCIDFormat {
        details: format!("failed to serialize genesis entry: {}", e),
    })?;

    // Replace all SCID occurrences with placeholder
    let replaced = json_str.replace(scid, "{SCID}");

    // Parse back to Value for JCS canonicalization
    let replaced_value: serde_json::Value =
        serde_json::from_str(&replaced).map_err(|e| WebVHDIDError::InvalidSCIDFormat {
            details: format!("failed to parse replaced entry: {}", e),
        })?;

    let canonical = jcs::canonicalize(&replaced_value);
    let computed_scid = compute_multihash_base58btc(canonical.as_bytes());

    if computed_scid != scid {
        return Err(WebVHDIDError::SCIDVerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_multihash_sha256() {
        let data = b"hello";
        let result = compute_multihash_sha256(data);
        // Should start with SHA-256 multihash header
        assert_eq!(result[0], 0x12); // SHA-256 identifier
        assert_eq!(result[1], 0x20); // 32 bytes length
        assert_eq!(result.len(), 34); // 2 header + 32 hash

        // Verify deterministic
        let result2 = compute_multihash_sha256(data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_compute_multihash_base58btc() {
        let data = b"hello";
        let result = compute_multihash_base58btc(data);
        // Should start with 'z' (base58btc multibase prefix)
        assert!(result.starts_with('z'));

        // Verify deterministic
        let result2 = compute_multihash_base58btc(data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_compute_entry_hash() {
        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "did:webvh:test:example.com"},
            "proof": [{"type": "DataIntegrityProof"}]
        });

        let hash = compute_entry_hash(&entry).unwrap();
        assert!(hash.starts_with('z'));

        // Proof should not affect hash
        let mut entry2 = entry.clone();
        entry2["proof"] = json!([{"type": "DataIntegrityProof", "extra": "data"}]);
        let hash2 = compute_entry_hash(&entry2).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_entry_hash_not_object() {
        let entry = json!("not an object");
        assert!(compute_entry_hash(&entry).is_err());
    }

    #[test]
    fn test_parse_version_id() {
        let (num, hash) = parse_version_id("1-QmTest").unwrap();
        assert_eq!(num, 1);
        assert_eq!(hash, "QmTest");

        let (num, hash) = parse_version_id("42-zAbcdef").unwrap();
        assert_eq!(num, 42);
        assert_eq!(hash, "zAbcdef");
    }

    #[test]
    fn test_parse_version_id_invalid() {
        // No dash
        assert!(parse_version_id("1QmTest").is_err());
        // Empty hash
        assert!(parse_version_id("1-").is_err());
        // Non-numeric version
        assert!(parse_version_id("abc-QmTest").is_err());
    }

    #[test]
    fn test_verify_version_id_valid() {
        // Create an entry, compute its hash, then set the versionId
        let mut entry = json!({
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "did:webvh:test:example.com"}
        });

        // Compute the actual hash (versionId is excluded from hash)
        let hash = compute_entry_hash(&entry).unwrap();
        entry["versionId"] = serde_json::Value::String(format!("1-{}", hash));

        // Should verify successfully
        let result = verify_version_id(&entry, 1, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_verify_version_id_wrong_number() {
        let entry = json!({
            "versionId": "2-zSomeHash",
            "parameters": {},
            "state": {}
        });

        let result = verify_version_id(&entry, 1, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::InvalidVersionId { .. })
        ));
    }

    #[test]
    fn test_verify_version_id_hash_mismatch() {
        let entry = json!({
            "versionId": "1-zWrongHash",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {},
            "state": {}
        });

        let result = verify_version_id(&entry, 1, 1);
        assert!(matches!(
            result,
            Err(WebVHDIDError::EntryHashVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_scid_roundtrip() {
        // Build a preliminary entry with {SCID} placeholders
        let preliminary = json!({
            "versionId": "{SCID}",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "{SCID}",
                "updateKeys": ["z6MkTestKey"]
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:{SCID}:example.com"
            }
        });

        // Compute SCID
        let canonical = jcs::canonicalize(&preliminary);
        let scid = compute_multihash_base58btc(canonical.as_bytes());

        // Replace {SCID} with actual value
        let json_str = serde_json::to_string(&preliminary).unwrap();
        let replaced = json_str.replace("{SCID}", &scid);
        let genesis: serde_json::Value = serde_json::from_str(&replaced).unwrap();

        // Verification should succeed
        assert!(verify_scid(&scid, &genesis).is_ok());
    }

    #[test]
    fn test_verify_scid_mismatch() {
        let entry = json!({
            "versionId": "zWrongSCID",
            "versionTime": "2025-04-29T17:15:59Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "zWrongSCID",
                "updateKeys": ["z6MkTestKey"]
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:zWrongSCID:example.com"
            }
        });

        assert!(matches!(
            verify_scid("zWrongSCID", &entry),
            Err(WebVHDIDError::SCIDVerificationFailed)
        ));
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {"method": "did:webvh:1.0"},
            "state": {"id": "test"}
        });

        let hash1 = compute_entry_hash(&entry).unwrap();
        let hash2 = compute_entry_hash(&entry).unwrap();
        assert_eq!(hash1, hash2);
    }
}
