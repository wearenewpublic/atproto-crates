//! Data types for did:webvh log entries, parameters, and proofs.
//!
//! Defines the structures used to parse and process did:webvh DID log files
//! (did.jsonl), including log entries, Data Integrity proofs, witness
//! configuration, and the accumulated parameter state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Document;

/// A single entry in a did:webvh log file (did.jsonl).
///
/// Each line in the JSONL file represents one version of the DID document
/// with its associated metadata, parameters, and cryptographic proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Version identifier in the format "{N}-{hash}".
    pub version_id: String,
    /// ISO 8601 UTC timestamp of this version.
    pub version_time: String,
    /// Parameters for this entry (only changed parameters are included).
    pub parameters: serde_json::Value,
    /// The DID Document state at this version.
    pub state: serde_json::Value,
    /// Array of Data Integrity proofs.
    #[serde(default)]
    pub proof: Vec<DataIntegrityProof>,
}

/// A W3C Data Integrity proof for a log entry.
///
/// Uses the `eddsa-jcs-2022` cryptosuite for Ed25519 signatures
/// over JCS-canonicalized content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataIntegrityProof {
    /// Proof type, must be "DataIntegrityProof".
    pub r#type: String,
    /// Cryptographic suite, must be "eddsa-jcs-2022" for v1.0.
    pub cryptosuite: String,
    /// DID URL of the signing key (e.g., "did:key:z6Mk...#z6Mk...").
    pub verification_method: String,
    /// ISO 8601 timestamp when the proof was created.
    pub created: String,
    /// Purpose of the proof, typically "assertionMethod".
    pub proof_purpose: String,
    /// Multibase-encoded (base58btc) Ed25519 signature.
    pub proof_value: String,
}

/// Accumulated parameter state across all processed log entries.
///
/// Parameters carry forward from previous entries — only changed parameters
/// appear in subsequent entries. This struct tracks the fully merged state.
#[derive(Debug, Clone)]
pub struct MergedParameters {
    /// Method version string (e.g., "did:webvh:1.0").
    pub method: String,
    /// Self-Certifying Identifier from the genesis entry.
    pub scid: String,
    /// Public keys authorized to sign log entries.
    pub update_keys: Vec<String>,
    /// Hashes of pre-rotated future keys.
    pub next_key_hashes: Vec<String>,
    /// Whether the DID is portable (can be relocated).
    pub portable: bool,
    /// Whether the DID has been deactivated.
    pub deactivated: bool,
    /// Cache TTL in seconds (default 3600).
    pub ttl: u64,
    /// Witness configuration, if any.
    pub witness: Option<WitnessConfig>,
    /// Watcher notification URLs.
    pub watchers: Vec<String>,
}

impl Default for MergedParameters {
    fn default() -> Self {
        Self {
            method: String::new(),
            scid: String::new(),
            update_keys: Vec::new(),
            next_key_hashes: Vec::new(),
            portable: false,
            deactivated: false,
            ttl: 3600,
            witness: None,
            watchers: Vec::new(),
        }
    }
}

/// Witness configuration for multi-signature approval of DID updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    /// Minimum number of weighted witness approvals required.
    pub threshold: usize,
    /// List of configured witnesses.
    pub witnesses: Vec<WitnessEntry>,
}

/// A single witness in the witness configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEntry {
    /// DID key identifier of the witness (e.g., "did:key:z6Mk...").
    pub id: String,
    /// Weight of this witness's approval toward the threshold.
    #[serde(default = "default_weight")]
    pub weight: usize,
}

fn default_weight() -> usize {
    1
}

/// A witness proof entry from the did-witnesses.json file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessProofEntry {
    /// Version ID this witness proof applies to.
    pub version_id: String,
    /// Array of witness Data Integrity proofs.
    pub proof: Vec<DataIntegrityProof>,
}

/// Query parameters for historical version resolution.
///
/// When resolving a did:webvh DID, these parameters select which version
/// of the DID document to return. Only one should be set at a time.
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    /// Resolve a specific version by its full versionId (e.g., "2-zHash").
    pub version_id: Option<String>,
    /// Resolve the DIDDoc active at this ISO 8601 UTC timestamp.
    pub version_time: Option<String>,
    /// Resolve by integer version number (1-indexed).
    pub version_number: Option<u64>,
}

/// Result of processing a complete did:webvh log.
#[derive(Debug, Clone)]
pub struct ResolvedLog {
    /// The resolved DID Document from the final log entry.
    pub document: Document,
    /// Version ID of the final entry.
    pub version_id: String,
    /// Version number (1-indexed) of the final entry.
    pub version_number: u64,
    /// ISO 8601 timestamp of the final entry.
    pub version_time: String,
    /// Fully merged parameters across all entries.
    pub parameters: MergedParameters,
    /// Total number of entries in the log.
    pub entry_count: usize,
    /// Resolution metadata.
    pub metadata: ResolutionMetadata,
}

/// Resolution metadata returned alongside the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    /// Version ID of the resolved entry.
    pub version_id: String,
    /// Timestamp of the resolved entry.
    pub version_time: String,
    /// Timestamp of the first entry (creation time).
    pub created: String,
    /// Timestamp of the last entry (update time).
    pub updated: String,
    /// Self-Certifying Identifier.
    pub scid: String,
    /// Whether the DID is portable.
    pub portable: bool,
    /// Whether the DID is deactivated.
    pub deactivated: bool,
    /// Cache TTL in seconds.
    pub ttl: u64,
    /// Witness configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessConfig>,
    /// Watcher URLs.
    #[serde(default)]
    pub watchers: Vec<String>,
    /// Additional metadata fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_deserialize() {
        let json = r#"{"versionId":"1-QmTest","versionTime":"2025-04-29T17:15:59Z","parameters":{"method":"did:webvh:1.0","scid":"QmTest","updateKeys":["z6MkTest"]},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmTest:example.com"},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkTest#z6MkTest","created":"2025-04-29T17:15:59Z","proofPurpose":"assertionMethod","proofValue":"zSigTest"}]}"#;
        let entry: LogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.version_id, "1-QmTest");
        assert_eq!(entry.version_time, "2025-04-29T17:15:59Z");
        assert_eq!(entry.proof.len(), 1);
        assert_eq!(entry.proof[0].cryptosuite, "eddsa-jcs-2022");
    }

    #[test]
    fn test_log_entry_roundtrip() {
        let json = r#"{"versionId":"1-QmTest","versionTime":"2025-04-29T17:15:59Z","parameters":{},"state":{"id":"did:webvh:QmTest:example.com"},"proof":[]}"#;
        let entry: LogEntry = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&entry).unwrap();
        let reparsed: LogEntry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(entry.version_id, reparsed.version_id);
    }

    #[test]
    fn test_data_integrity_proof_deserialize() {
        let json = r#"{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkTest#z6MkTest","created":"2025-04-29T17:15:59Z","proofPurpose":"assertionMethod","proofValue":"zSigValue"}"#;
        let proof: DataIntegrityProof = serde_json::from_str(json).unwrap();
        assert_eq!(proof.r#type, "DataIntegrityProof");
        assert_eq!(proof.cryptosuite, "eddsa-jcs-2022");
        assert_eq!(proof.proof_value, "zSigValue");
    }

    #[test]
    fn test_merged_parameters_default() {
        let params = MergedParameters::default();
        assert_eq!(params.ttl, 3600);
        assert!(!params.portable);
        assert!(!params.deactivated);
        assert!(params.update_keys.is_empty());
        assert!(params.next_key_hashes.is_empty());
        assert!(params.witness.is_none());
    }

    #[test]
    fn test_witness_config_deserialize() {
        let json = r#"{"threshold":2,"witnesses":[{"id":"did:key:z6MkA","weight":1},{"id":"did:key:z6MkB","weight":2}]}"#;
        let config: WitnessConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.witnesses.len(), 2);
        assert_eq!(config.witnesses[1].weight, 2);
    }

    #[test]
    fn test_witness_entry_default_weight() {
        let json = r#"{"id":"did:key:z6MkA"}"#;
        let entry: WitnessEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.weight, 1);
    }

    #[test]
    fn test_witness_proof_entry_deserialize() {
        let json = r#"{"versionId":"2-QmHash","proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:key:z6MkW#z6MkW","created":"2025-04-29T17:15:59Z","proofPurpose":"assertionMethod","proofValue":"zWitnessSig"}]}"#;
        let entry: WitnessProofEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.version_id, "2-QmHash");
        assert_eq!(entry.proof.len(), 1);
    }
}
