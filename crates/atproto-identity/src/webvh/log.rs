//! JSONL log parsing and sequential entry validation for did:webvh.
//!
//! Processes the did.jsonl log file by parsing each line as a JSON log entry,
//! merging parameters across entries, and verifying hash chains, SCID integrity,
//! cryptographic proofs, pre-rotation constraints, and timestamp ordering.

use std::collections::HashMap;

use crate::errors::WebVHDIDError;
use crate::model::Document;

use super::model::{
    LogEntry, MergedParameters, QueryParams, ResolutionMetadata, ResolvedLog, WitnessConfig,
    WitnessProofEntry,
};
use super::proof::{verify_any_proof, verify_prerotation, verify_witness_proofs};
use super::scid::{validate_hash_algorithm, validate_scid_format, verify_scid, verify_version_id};

/// Known parameter keys recognized by did:webvh v1.0.
const KNOWN_PARAMETERS: &[&str] = &[
    "method",
    "scid",
    "updateKeys",
    "nextKeyHashes",
    "portable",
    "deactivated",
    "ttl",
    "witness",
    "watchers",
];

/// Processes a complete did:webvh log and returns the resolved DID document.
///
/// Parses the JSONL body, validates each entry sequentially, and returns
/// the final resolved state including the DID document and merged parameters.
///
/// This is the simple entry point that does not verify witness proofs.
/// Use [`process_log_with_witnesses`] when witness verification is required.
pub fn process_log(did: &str, scid: &str, body: &str) -> Result<ResolvedLog, WebVHDIDError> {
    process_log_with_witnesses(did, scid, body, None)
}

/// Processes a complete did:webvh log with optional witness proof verification.
///
/// When `witness_proofs` is `Some`, entries whose active parameters include a
/// witness configuration will be verified against the provided witness proofs.
/// Each witness proof entry is matched to a log entry by `versionId`.
///
/// When `witness_proofs` is `None`, witness verification is skipped entirely.
pub fn process_log_with_witnesses(
    did: &str,
    scid: &str,
    body: &str,
    witness_proofs: Option<&[WitnessProofEntry]>,
) -> Result<ResolvedLog, WebVHDIDError> {
    process_log_full(did, scid, body, witness_proofs, None)
}

/// Processes a complete did:webvh log with query parameters for historical resolution.
///
/// Validates ALL entries in the chain, but returns the document and metadata
/// from the entry matching the query parameters instead of the last entry.
pub fn process_log_with_params(
    did: &str,
    scid: &str,
    body: &str,
    witness_proofs: Option<&[WitnessProofEntry]>,
    query_params: &QueryParams,
) -> Result<ResolvedLog, WebVHDIDError> {
    process_log_full(did, scid, body, witness_proofs, Some(query_params))
}

/// Core log processing with all verification, witness support, and query params.
///
/// Implements partial log validity: if later entries fail verification, earlier
/// valid entries can still be returned via query parameters. The genesis entry
/// must always be valid; failures there abort entirely.
fn process_log_full(
    did: &str,
    scid: &str,
    body: &str,
    witness_proofs: Option<&[WitnessProofEntry]>,
    query_params: Option<&QueryParams>,
) -> Result<ResolvedLog, WebVHDIDError> {
    let entries = parse_log_entries(body)?;

    if entries.is_empty() {
        return Err(WebVHDIDError::EmptyLog);
    }

    let mut params = MergedParameters::default();
    let mut prev_version_time: Option<&str> = None;
    let mut prev_next_key_hashes: Vec<String> = Vec::new();
    let entry_count = entries.len();
    let mut did_id_matched = false;
    // Track the last successfully validated entry index (0-based)
    let mut last_valid_index: Option<usize> = None;
    // Track the first validation error for entries after genesis
    let mut first_error: Option<WebVHDIDError> = None;
    // Track params snapshot at each valid entry for partial validity
    let mut last_valid_params: Option<MergedParameters> = None;

    for (i, entry) in entries.iter().enumerate() {
        let entry_number = i + 1;

        // Normalize null parameter values to defaults (spec: deprecated but SHOULD accept)
        let raw_entry = parse_raw_entry(body, i)?;
        let normalized_entry = normalize_null_parameters(entry);
        let active_entry = normalized_entry.as_ref().unwrap_or(entry);

        // Validate unknown parameters
        validate_known_parameters(&active_entry.parameters, entry_number)?;

        // Save witness config BEFORE merging this entry's params
        let witness_before_merge = params.witness.clone();

        let entry_result: Result<(), WebVHDIDError> = (|| {
            if i == 0 {
                process_genesis_entry(did, scid, active_entry, &raw_entry, &mut params)?;
                did_id_matched = true; // genesis already verifies state.id == did
            } else {
                process_subsequent_entry(
                    did,
                    active_entry,
                    &raw_entry,
                    entry_number,
                    &mut params,
                    &prev_next_key_hashes,
                )?;

                // DIDDoc id match across versions
                let state_id = active_entry.state.get("id").and_then(|v| v.as_str());
                if let Some(id) = state_id {
                    if id == did {
                        did_id_matched = true;
                    } else if !params.portable {
                        return Err(WebVHDIDError::DIDDocIdMismatch {
                            entry: entry_number,
                            expected: did.to_string(),
                            found: id.to_string(),
                        });
                    }
                }
            }

            // Verify witness proofs using the config that was active BEFORE this entry
            let effective_witness = if i == 0 {
                &params.witness
            } else {
                &witness_before_merge
            };

            if let Some(witness_config) = effective_witness
                && let Some(wp) = witness_proofs
            {
                let matching_wp = wp.iter().find(|w| w.version_id == entry.version_id);
                match matching_wp {
                    Some(wp_entry) => {
                        verify_witness_proofs(
                            &raw_entry,
                            &wp_entry.proof,
                            witness_config,
                            entry_number,
                        )?;
                    }
                    None => {
                        return Err(WebVHDIDError::WitnessVerificationFailed {
                            entry: entry_number,
                            details: format!(
                                "no witness proof found for version {}",
                                entry.version_id
                            ),
                        });
                    }
                }
            }

            // Verify version time ordering
            if let Some(prev_time) = prev_version_time
                && entry.version_time.as_str() <= prev_time
            {
                return Err(WebVHDIDError::VersionTimeNotMonotonic {
                    entry: entry_number,
                });
            }

            Ok(())
        })();

        match entry_result {
            Ok(()) => {
                last_valid_index = Some(i);
                last_valid_params = Some(params.clone());
                prev_version_time = Some(&entry.version_time);
                prev_next_key_hashes = params.next_key_hashes.clone();
            }
            Err(e) => {
                if i == 0 {
                    // Genesis entry MUST be valid — abort entirely
                    return Err(e);
                }
                // For non-genesis entries, record the error and stop processing
                first_error = Some(e);
                break;
            }
        }
    }

    let last_valid_idx = last_valid_index.ok_or(WebVHDIDError::EmptyLog)?;
    let valid_params = last_valid_params.unwrap_or(params);

    // Verify version time bounds — last valid entry must not be in the future
    let last_valid_entry = &entries[last_valid_idx];
    if let Ok(last_time) = chrono::DateTime::parse_from_rfc3339(&last_valid_entry.version_time)
        && last_time > chrono::Utc::now()
    {
        return Err(WebVHDIDError::VersionTimeInFuture {
            entry: last_valid_idx + 1,
            version_time: last_valid_entry.version_time.clone(),
        });
    }

    // For portable DIDs, verify at least one entry had matching id
    if valid_params.portable && !did_id_matched {
        return Err(WebVHDIDError::DIDDocIdMismatch {
            entry: 0,
            expected: did.to_string(),
            found: "no matching DIDDoc id found in any entry".to_string(),
        });
    }

    // Determine effective deactivation: explicit flag OR empty updateKeys
    let is_deactivated = valid_params.deactivated || valid_params.update_keys.is_empty();

    // Build metadata from full chain
    let first_entry = &entries[0];
    let created_time = first_entry.version_time.clone();
    let updated_time = last_valid_entry.version_time.clone();

    // Determine which entry to return based on query params
    // With partial validity, only entries up to last_valid_idx are selectable
    let valid_entries = &entries[..=last_valid_idx];

    let (resolved_entry, resolved_number) = if let Some(qp) = query_params {
        select_entry_by_query(valid_entries, qp)?
    } else {
        // Default: return last valid entry, check deactivation
        if is_deactivated {
            return Err(WebVHDIDError::DeactivatedDID {
                did: did.to_string(),
            });
        }
        // If there were invalid entries after the last valid one, return error
        if let Some(err) = first_error {
            return Err(err);
        }
        (last_valid_entry, (last_valid_idx + 1) as u64)
    };

    let document: Document = serde_json::from_value(resolved_entry.state.clone()).map_err(|e| {
        WebVHDIDError::DocumentExtractionFailed {
            details: format!("failed to deserialize DID document: {}", e),
        }
    })?;

    let metadata = ResolutionMetadata {
        version_id: resolved_entry.version_id.clone(),
        version_time: resolved_entry.version_time.clone(),
        created: created_time,
        updated: updated_time,
        scid: valid_params.scid.clone(),
        portable: valid_params.portable,
        // Metadata MUST include deactivated: true when the DID is deactivated,
        // even when resolving a historical version via query params
        deactivated: is_deactivated,
        ttl: valid_params.ttl,
        witness: valid_params.witness.clone(),
        watchers: valid_params.watchers.clone(),
        extra: HashMap::new(),
    };

    Ok(ResolvedLog {
        document,
        version_id: resolved_entry.version_id.clone(),
        version_number: resolved_number,
        version_time: resolved_entry.version_time.clone(),
        parameters: valid_params,
        entry_count,
        metadata,
    })
}

/// Selects an entry from the log based on query parameters.
///
/// Returns the matching entry and its version number (1-indexed).
/// Only entries within the provided slice are selectable (supports partial validity).
fn select_entry_by_query<'a>(
    entries: &'a [LogEntry],
    query_params: &QueryParams,
) -> Result<(&'a LogEntry, u64), WebVHDIDError> {
    if let Some(ref vid) = query_params.version_id {
        let pos = entries
            .iter()
            .position(|e| e.version_id == *vid)
            .ok_or_else(|| WebVHDIDError::VersionNotFound {
                details: format!("no entry with versionId '{}'", vid),
            })?;
        Ok((&entries[pos], pos as u64 + 1))
    } else if let Some(ref vtime) = query_params.version_time {
        // Find latest entry with versionTime <= specified time
        let entry = entries
            .iter()
            .rev()
            .find(|e| e.version_time.as_str() <= vtime.as_str())
            .ok_or_else(|| WebVHDIDError::VersionNotFound {
                details: format!("no entry active at time '{}'", vtime),
            })?;
        let number = entries
            .iter()
            .position(|e| e.version_id == entry.version_id)
            .unwrap() as u64
            + 1;
        Ok((entry, number))
    } else if let Some(vnum) = query_params.version_number {
        if vnum == 0 || vnum as usize > entries.len() {
            return Err(WebVHDIDError::VersionNotFound {
                details: format!(
                    "version number {} out of range (1..{})",
                    vnum,
                    entries.len()
                ),
            });
        }
        let entry = &entries[vnum as usize - 1];
        Ok((entry, vnum))
    } else {
        // No query params — return last entry
        let last = entries.last().unwrap();
        Ok((last, entries.len() as u64))
    }
}

/// Normalizes JSON `null` parameter values to their spec defaults.
///
/// The spec forbids `null` but says deprecated implementations SHOULD accept
/// `null` and convert to the equivalent default. Returns `Some(normalized)`
/// if any nulls were found and converted, or `None` if no changes needed.
fn normalize_null_parameters(entry: &LogEntry) -> Option<LogEntry> {
    let params = entry.parameters.as_object()?;

    let has_nulls = params.values().any(|v| v.is_null());
    if !has_nulls {
        return None;
    }

    let mut normalized = entry.clone();
    let obj = normalized.parameters.as_object_mut().unwrap();

    for (key, value) in obj.iter_mut() {
        if !value.is_null() {
            continue;
        }
        // Convert null to spec default for each known parameter
        *value = match key.as_str() {
            "portable" | "deactivated" => serde_json::Value::Bool(false),
            "ttl" => serde_json::json!(3600),
            "updateKeys" | "nextKeyHashes" | "watchers" => serde_json::json!([]),
            "witness" => serde_json::json!({}),
            // Unknown or string params: remove null by setting to empty object
            // (will be caught by unknown parameter validation if truly unknown)
            _ => serde_json::json!({}),
        };
    }

    Some(normalized)
}

/// Validates that all parameter keys in an entry are recognized.
fn validate_known_parameters(
    entry_params: &serde_json::Value,
    entry_number: usize,
) -> Result<(), WebVHDIDError> {
    if let Some(obj) = entry_params.as_object() {
        for key in obj.keys() {
            if !KNOWN_PARAMETERS.contains(&key.as_str()) {
                return Err(WebVHDIDError::UnknownParameter {
                    entry: entry_number,
                    parameter: key.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Parses the JSONL body into a vector of LogEntry structs.
fn parse_log_entries(body: &str) -> Result<Vec<LogEntry>, WebVHDIDError> {
    let mut entries = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: LogEntry =
            serde_json::from_str(trimmed).map_err(|e| WebVHDIDError::LogEntryParseFailed {
                line: i + 1,
                details: e.to_string(),
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Parses a specific line from the JSONL body as a raw serde_json::Value.
fn parse_raw_entry(body: &str, index: usize) -> Result<serde_json::Value, WebVHDIDError> {
    let line = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .nth(index)
        .ok_or(WebVHDIDError::EmptyLog)?;

    serde_json::from_str(line.trim()).map_err(|e| WebVHDIDError::LogEntryParseFailed {
        line: index + 1,
        details: e.to_string(),
    })
}

/// Processes and validates the genesis (first) log entry.
fn process_genesis_entry(
    did: &str,
    scid: &str,
    entry: &LogEntry,
    raw_entry: &serde_json::Value,
    params: &mut MergedParameters,
) -> Result<(), WebVHDIDError> {
    let entry_params = &entry.parameters;

    // Validate required genesis parameters
    let method = entry_params.get("method").and_then(|v| v.as_str()).ok_or(
        WebVHDIDError::InvalidParameters {
            entry: 1,
            details: "missing required 'method' parameter in genesis entry".to_string(),
        },
    )?;

    // Accept both 1.0 and 0.5 method versions
    if !method.starts_with("did:webvh:") {
        return Err(WebVHDIDError::InvalidParameters {
            entry: 1,
            details: format!("invalid method format: {}", method),
        });
    }

    let entry_scid = entry_params.get("scid").and_then(|v| v.as_str()).ok_or(
        WebVHDIDError::InvalidParameters {
            entry: 1,
            details: "missing required 'scid' parameter in genesis entry".to_string(),
        },
    )?;

    if entry_scid != scid {
        return Err(WebVHDIDError::InvalidParameters {
            entry: 1,
            details: format!(
                "SCID mismatch: DID contains '{}', entry has '{}'",
                scid, entry_scid
            ),
        });
    }

    let update_keys = entry_params
        .get("updateKeys")
        .and_then(|v| v.as_array())
        .ok_or(WebVHDIDError::InvalidParameters {
            entry: 1,
            details: "missing required 'updateKeys' parameter in genesis entry".to_string(),
        })?;

    if update_keys.is_empty() {
        return Err(WebVHDIDError::InvalidParameters {
            entry: 1,
            details: "updateKeys must not be empty in genesis entry".to_string(),
        });
    }

    // Initialize merged parameters
    params.method = method.to_string();
    params.scid = scid.to_string();
    params.update_keys = update_keys
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Optional genesis parameters
    merge_optional_params(params, entry_params, true)?;

    // Validate SCID format (item 7)
    validate_scid_format(scid)?;

    // Verify SCID
    verify_scid(scid, raw_entry)?;

    // Validate hash algorithm matches method version (item 8)
    validate_hash_algorithm(scid, method)?;

    // Verify version ID (must be version 1)
    verify_version_id(raw_entry, 1, 1)?;

    // Verify proof
    verify_any_proof(raw_entry, &entry.proof, &params.update_keys, 1)?;

    // Verify state.id matches DID
    let state_id = entry.state.get("id").and_then(|v| v.as_str());
    if state_id != Some(did) {
        return Err(WebVHDIDError::InvalidParameters {
            entry: 1,
            details: format!(
                "state.id '{}' does not match DID '{}'",
                state_id.unwrap_or("<missing>"),
                did
            ),
        });
    }

    Ok(())
}

/// Processes and validates a subsequent (non-genesis) log entry.
fn process_subsequent_entry(
    _did: &str,
    entry: &LogEntry,
    raw_entry: &serde_json::Value,
    entry_number: usize,
    params: &mut MergedParameters,
    prev_next_key_hashes: &[String],
) -> Result<(), WebVHDIDError> {
    let entry_params = &entry.parameters;

    // SCID must NOT appear after genesis
    if entry_params.get("scid").is_some() {
        return Err(WebVHDIDError::InvalidParameters {
            entry: entry_number,
            details: "scid parameter must not appear after genesis entry".to_string(),
        });
    }

    // Save previous update keys for proof verification
    let prev_update_keys = params.update_keys.clone();

    // Merge parameters
    merge_entry_params(params, entry_params, entry_number)?;

    // Verify version ID
    verify_version_id(raw_entry, entry_number as u64, entry_number)?;

    // Verify pre-rotation if active
    if !prev_next_key_hashes.is_empty() {
        verify_prerotation(&params.update_keys, prev_next_key_hashes, entry_number)?;
    }

    // Verify proof
    // With pre-rotation: verify against current update keys (validated above)
    // Without pre-rotation: verify against previous update keys
    let verification_keys = if !prev_next_key_hashes.is_empty() {
        &params.update_keys
    } else {
        &prev_update_keys
    };
    verify_any_proof(raw_entry, &entry.proof, verification_keys, entry_number)?;

    Ok(())
}

/// Merges optional parameters from a genesis entry into the accumulated state.
fn merge_optional_params(
    params: &mut MergedParameters,
    entry_params: &serde_json::Value,
    is_genesis: bool,
) -> Result<(), WebVHDIDError> {
    if let Some(next_key_hashes) = entry_params.get("nextKeyHashes").and_then(|v| v.as_array()) {
        params.next_key_hashes = next_key_hashes
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    if let Some(portable) = entry_params.get("portable").and_then(|v| v.as_bool()) {
        if portable && !is_genesis {
            return Err(WebVHDIDError::InvalidParameters {
                entry: 1,
                details: "portable can only be set to true in genesis entry".to_string(),
            });
        }
        params.portable = portable;
    }

    if let Some(deactivated) = entry_params.get("deactivated").and_then(|v| v.as_bool()) {
        params.deactivated = deactivated;
    }

    if let Some(ttl) = entry_params.get("ttl").and_then(|v| v.as_u64()) {
        params.ttl = ttl;
    }

    if let Some(witness) = entry_params.get("witness") {
        if witness.is_object() && !witness.as_object().unwrap().is_empty() {
            let config: WitnessConfig = serde_json::from_value(witness.clone()).map_err(|e| {
                WebVHDIDError::InvalidParameters {
                    entry: 1,
                    details: format!("invalid witness configuration: {}", e),
                }
            })?;
            params.witness = Some(config);
        } else {
            params.witness = None;
        }
    }

    if let Some(watchers) = entry_params.get("watchers").and_then(|v| v.as_array()) {
        params.watchers = watchers
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    Ok(())
}

/// Merges parameters from a subsequent entry into the accumulated state.
fn merge_entry_params(
    params: &mut MergedParameters,
    entry_params: &serde_json::Value,
    entry_number: usize,
) -> Result<(), WebVHDIDError> {
    if let Some(method) = entry_params.get("method").and_then(|v| v.as_str()) {
        params.method = method.to_string();
    }

    if let Some(update_keys) = entry_params.get("updateKeys").and_then(|v| v.as_array()) {
        params.update_keys = update_keys
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    if let Some(next_key_hashes) = entry_params.get("nextKeyHashes").and_then(|v| v.as_array()) {
        params.next_key_hashes = next_key_hashes
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    if let Some(portable) = entry_params.get("portable").and_then(|v| v.as_bool()) {
        if portable && !params.portable {
            return Err(WebVHDIDError::InvalidParameters {
                entry: entry_number,
                details: "portable cannot be changed from false to true after genesis".to_string(),
            });
        }
        params.portable = portable;
    }

    if let Some(deactivated) = entry_params.get("deactivated").and_then(|v| v.as_bool()) {
        params.deactivated = deactivated;
    }

    if let Some(ttl) = entry_params.get("ttl").and_then(|v| v.as_u64()) {
        params.ttl = ttl;
    }

    if let Some(witness) = entry_params.get("witness") {
        if witness.is_object() && !witness.as_object().unwrap().is_empty() {
            let config: WitnessConfig = serde_json::from_value(witness.clone()).map_err(|e| {
                WebVHDIDError::InvalidParameters {
                    entry: entry_number,
                    details: format!("invalid witness configuration: {}", e),
                }
            })?;
            params.witness = Some(config);
        } else {
            params.witness = None;
        }
    }

    if let Some(watchers) = entry_params.get("watchers").and_then(|v| v.as_array()) {
        params.watchers = watchers
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::jcs;
    use super::super::scid::compute_multihash_base58btc;
    use super::*;
    use crate::key::{KeyType, generate_key, to_public};
    use serde_json::json;

    /// Helper: creates an Ed25519 keypair and returns (signing_key, multikey_string).
    fn make_ed25519_keypair() -> (ed25519_dalek::SigningKey, String) {
        let private_key = generate_key(KeyType::Ed25519Private).unwrap();
        let public_key = to_public(&private_key).unwrap();
        let did_key = format!("{}", &public_key);
        let multikey = did_key.strip_prefix("did:key:").unwrap().to_string();
        let signing_key =
            ed25519_dalek::SigningKey::from_bytes(private_key.bytes().try_into().unwrap());
        (signing_key, multikey)
    }

    /// Helper: signs a log entry and returns a DataIntegrityProof JSON value.
    fn sign_entry(
        signing_key: &ed25519_dalek::SigningKey,
        multikey: &str,
        entry: &serde_json::Value,
    ) -> serde_json::Value {
        let mut without_proof = entry.clone();
        without_proof.as_object_mut().unwrap().remove("proof");
        let canonical = jcs::canonicalize(&without_proof);
        let signature = ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
        let proof_value = multibase::encode(multibase::Base::Base58Btc, signature.to_bytes());

        json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("did:key:{}#{}", multikey, multikey),
            "created": "2025-04-29T17:15:59Z",
            "proofPurpose": "assertionMethod",
            "proofValue": proof_value
        })
    }

    /// Helper: builds and signs a valid genesis entry.
    fn build_genesis_entry(
        signing_key: &ed25519_dalek::SigningKey,
        multikey: &str,
    ) -> (String, serde_json::Value) {
        // Step 1: create preliminary entry with {SCID} placeholder
        let preliminary = json!({
            "versionId": "{SCID}",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "{SCID}",
                "updateKeys": [multikey]
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:{SCID}:example.com"
            }
        });

        // Step 2: compute SCID
        let canonical = jcs::canonicalize(&preliminary);
        let scid = compute_multihash_base58btc(canonical.as_bytes());

        // Step 3: replace {SCID} with actual value
        let json_str = serde_json::to_string(&preliminary).unwrap();
        let replaced = json_str.replace("{SCID}", &scid);
        let mut entry: serde_json::Value = serde_json::from_str(&replaced).unwrap();

        // Step 4: compute entry hash (versionId is excluded from hash)
        let entry_hash = super::super::scid::compute_entry_hash(&entry).unwrap();
        entry["versionId"] = json!(format!("1-{}", entry_hash));

        // Step 5: sign (proof is computed over entry without proof, without versionId)
        let proof = sign_entry(signing_key, multikey, &entry);
        entry["proof"] = json!([proof]);

        (scid, entry)
    }

    #[test]
    fn test_parse_log_entries_single() {
        let body = r#"{"versionId":"1-test","versionTime":"2025-01-01T00:00:00Z","parameters":{},"state":{},"proof":[]}"#;
        let entries = parse_log_entries(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version_id, "1-test");
    }

    #[test]
    fn test_parse_log_entries_multiple() {
        let body = concat!(
            r#"{"versionId":"1-a","versionTime":"2025-01-01T00:00:00Z","parameters":{},"state":{},"proof":[]}"#,
            "\n",
            r#"{"versionId":"2-b","versionTime":"2025-01-02T00:00:00Z","parameters":{},"state":{},"proof":[]}"#,
        );
        let entries = parse_log_entries(body).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_log_entries_empty() {
        let entries = parse_log_entries("").unwrap();
        assert!(entries.is_empty());

        let entries = parse_log_entries("\n\n").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_log_entries_invalid_json() {
        let body = "not json";
        let result = parse_log_entries(body);
        assert!(matches!(
            result,
            Err(WebVHDIDError::LogEntryParseFailed { .. })
        ));
    }

    #[test]
    fn test_process_log_empty() {
        let result = process_log("did:webvh:test:example.com", "test", "");
        assert!(matches!(result, Err(WebVHDIDError::EmptyLog)));
    }

    #[test]
    fn test_process_log_valid_genesis() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, entry) = build_genesis_entry(&signing_key, &multikey);

        let did = format!("did:webvh:{}:example.com", scid);
        let body = serde_json::to_string(&entry).unwrap();

        let result = process_log(&did, &scid, &body);
        assert!(result.is_ok(), "process_log failed: {:?}", result);

        let resolved = result.unwrap();
        assert_eq!(resolved.version_number, 1);
        assert_eq!(resolved.entry_count, 1);
        assert_eq!(resolved.parameters.scid, scid);
        assert_eq!(resolved.parameters.method, "did:webvh:1.0");
    }

    #[test]
    fn test_process_log_non_monotonic_time() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry with earlier timestamp
        let mut entry2 = json!({
            "versionTime": "2024-01-01T00:00:00Z",  // Earlier than genesis
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });

        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));

        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log(&did, &scid, &body);
        assert!(matches!(
            result,
            Err(WebVHDIDError::VersionTimeNotMonotonic { .. })
        ));
    }

    #[test]
    fn test_process_log_deactivated() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry that deactivates
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"deactivated": true},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });

        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));

        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log(&did, &scid, &body);
        assert!(matches!(result, Err(WebVHDIDError::DeactivatedDID { .. })));
    }

    #[test]
    fn test_process_log_missing_method() {
        let (_signing_key, multikey) = make_ed25519_keypair();

        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {
                "scid": "test",
                "updateKeys": [&multikey]
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:test:example.com"
            },
            "proof": []
        });

        let body = serde_json::to_string(&entry).unwrap();
        let result = process_log("did:webvh:test:example.com", "test", &body);
        assert!(matches!(
            result,
            Err(WebVHDIDError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn test_process_log_missing_update_keys() {
        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "test"
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:test:example.com"
            },
            "proof": []
        });

        let body = serde_json::to_string(&entry).unwrap();
        let result = process_log("did:webvh:test:example.com", "test", &body);
        assert!(matches!(
            result,
            Err(WebVHDIDError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn test_merge_entry_params_carry_forward() {
        let mut params = MergedParameters {
            method: "did:webvh:1.0".to_string(),
            scid: "test".to_string(),
            update_keys: vec!["key1".to_string()],
            ttl: 3600,
            ..Default::default()
        };

        // Empty parameters should not change anything
        let empty = json!({});
        merge_entry_params(&mut params, &empty, 2).unwrap();
        assert_eq!(params.method, "did:webvh:1.0");
        assert_eq!(params.update_keys, vec!["key1"]);
        assert_eq!(params.ttl, 3600);

        // Update only TTL
        let update = json!({"ttl": 7200});
        merge_entry_params(&mut params, &update, 3).unwrap();
        assert_eq!(params.ttl, 7200);
        assert_eq!(params.update_keys, vec!["key1"]); // unchanged
    }

    #[test]
    fn test_merge_entry_params_portable_constraint() {
        let mut params = MergedParameters {
            portable: false,
            ..MergedParameters::default()
        };

        let update = json!({"portable": true});
        let result = merge_entry_params(&mut params, &update, 2);
        assert!(matches!(
            result,
            Err(WebVHDIDError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn test_process_log_scid_in_subsequent_entry() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Second entry with SCID (invalid)
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"scid": "should-not-be-here"},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });

        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));

        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log(&did, &scid, &body);
        assert!(matches!(
            result,
            Err(WebVHDIDError::InvalidParameters { entry: 2, .. })
        ));
    }

    /// Helper: builds and signs a genesis entry with witness configuration.
    fn build_genesis_entry_with_witnesses(
        signing_key: &ed25519_dalek::SigningKey,
        multikey: &str,
        witness_config: &serde_json::Value,
    ) -> (String, serde_json::Value) {
        let preliminary = json!({
            "versionId": "{SCID}",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "{SCID}",
                "updateKeys": [multikey],
                "witness": witness_config
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:{SCID}:example.com"
            }
        });

        let canonical = jcs::canonicalize(&preliminary);
        let scid = compute_multihash_base58btc(canonical.as_bytes());

        let json_str = serde_json::to_string(&preliminary).unwrap();
        let replaced = json_str.replace("{SCID}", &scid);
        let mut entry: serde_json::Value = serde_json::from_str(&replaced).unwrap();

        let entry_hash = super::super::scid::compute_entry_hash(&entry).unwrap();
        entry["versionId"] = json!(format!("1-{}", entry_hash));

        let proof = sign_entry(signing_key, multikey, &entry);
        entry["proof"] = json!([proof]);

        (scid, entry)
    }

    /// Helper: signs a witness proof for a log entry.
    fn sign_witness_proof(
        signing_key: &ed25519_dalek::SigningKey,
        multikey: &str,
        entry: &serde_json::Value,
    ) -> serde_json::Value {
        let mut without_proof = entry.clone();
        without_proof.as_object_mut().unwrap().remove("proof");
        let canonical = jcs::canonicalize(&without_proof);
        let signature = ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
        let proof_value = multibase::encode(multibase::Base::Base58Btc, signature.to_bytes());

        json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("did:key:{}#{}", multikey, multikey),
            "created": "2025-04-29T17:15:59Z",
            "proofPurpose": "assertionMethod",
            "proofValue": proof_value
        })
    }

    #[test]
    fn test_process_log_with_witnesses_valid() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (witness_key, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 1,
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        // Create witness proof for genesis
        let witness_proof = sign_witness_proof(&witness_key, &witness_multikey, &genesis);
        let version_id = genesis["versionId"].as_str().unwrap().to_string();

        let witness_proofs = vec![super::super::model::WitnessProofEntry {
            version_id,
            proof: vec![serde_json::from_value(witness_proof).unwrap()],
        }];

        let body = serde_json::to_string(&genesis).unwrap();
        let result = process_log_with_witnesses(&did, &scid, &body, Some(&witness_proofs));
        assert!(
            result.is_ok(),
            "witness log processing failed: {:?}",
            result
        );
    }

    #[test]
    fn test_process_log_with_witnesses_missing_proof() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (_, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 1,
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        // Provide empty witness proofs
        let witness_proofs: Vec<super::super::model::WitnessProofEntry> = vec![];

        let body = serde_json::to_string(&genesis).unwrap();
        let result = process_log_with_witnesses(&did, &scid, &body, Some(&witness_proofs));
        assert!(
            matches!(result, Err(WebVHDIDError::WitnessVerificationFailed { .. })),
            "expected WitnessVerificationFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn test_process_log_with_witnesses_threshold_not_met() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (witness_key, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 5,  // Requires weight 5, but witness only has weight 1
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        let witness_proof = sign_witness_proof(&witness_key, &witness_multikey, &genesis);
        let version_id = genesis["versionId"].as_str().unwrap().to_string();

        let witness_proofs = vec![super::super::model::WitnessProofEntry {
            version_id,
            proof: vec![serde_json::from_value(witness_proof).unwrap()],
        }];

        let body = serde_json::to_string(&genesis).unwrap();
        let result = process_log_with_witnesses(&did, &scid, &body, Some(&witness_proofs));
        assert!(
            matches!(result, Err(WebVHDIDError::WitnessVerificationFailed { .. })),
            "expected WitnessVerificationFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn test_process_log_with_witnesses_no_witness_data_skips_verification() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (_, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 1,
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        // Pass None for witness_proofs — verification should be skipped
        let body = serde_json::to_string(&genesis).unwrap();
        let result = process_log_with_witnesses(&did, &scid, &body, None);
        assert!(
            result.is_ok(),
            "should skip witness verification when no data: {:?}",
            result
        );
    }

    #[test]
    fn test_process_log_with_witnesses_multi_entry() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (witness_key, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 1,
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        // Create witness proofs for both entries
        let wp1 = sign_witness_proof(&witness_key, &witness_multikey, &genesis);
        let wp2 = sign_witness_proof(&witness_key, &witness_multikey, &entry2);

        let witness_proofs = vec![
            super::super::model::WitnessProofEntry {
                version_id: genesis["versionId"].as_str().unwrap().to_string(),
                proof: vec![serde_json::from_value(wp1).unwrap()],
            },
            super::super::model::WitnessProofEntry {
                version_id: entry2["versionId"].as_str().unwrap().to_string(),
                proof: vec![serde_json::from_value(wp2).unwrap()],
            },
        ];

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log_with_witnesses(&did, &scid, &body, Some(&witness_proofs));
        assert!(
            result.is_ok(),
            "multi-entry witness verification failed: {:?}",
            result
        );
        assert_eq!(result.unwrap().version_number, 2);
    }

    #[test]
    fn test_process_log_with_witnesses_second_entry_missing_proof() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (witness_key, witness_multikey) = make_ed25519_keypair();

        let witness_config = json!({
            "threshold": 1,
            "witnesses": [{"id": format!("did:key:{}", witness_multikey), "weight": 1}]
        });

        let (scid, genesis) =
            build_genesis_entry_with_witnesses(&signing_key, &multikey, &witness_config);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        // Only provide witness proof for genesis, not entry 2
        let wp1 = sign_witness_proof(&witness_key, &witness_multikey, &genesis);
        let witness_proofs = vec![super::super::model::WitnessProofEntry {
            version_id: genesis["versionId"].as_str().unwrap().to_string(),
            proof: vec![serde_json::from_value(wp1).unwrap()],
        }];

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log_with_witnesses(&did, &scid, &body, Some(&witness_proofs));
        assert!(
            matches!(
                result,
                Err(WebVHDIDError::WitnessVerificationFailed { entry: 2, .. })
            ),
            "expected WitnessVerificationFailed for entry 2, got: {:?}",
            result
        );
    }

    #[test]
    fn test_process_log_two_entries() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build valid second entry
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did,
                "service": [{
                    "id": format!("{}#domain", &did),
                    "type": "LinkedDomains",
                    "serviceEndpoint": "https://example.com"
                }]
            }
        });

        // Compute correct versionId
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));

        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        let result = process_log(&did, &scid, &body);
        assert!(result.is_ok(), "process_log failed: {:?}", result);

        let resolved = result.unwrap();
        assert_eq!(resolved.version_number, 2);
        assert_eq!(resolved.entry_count, 2);
        assert!(!resolved.document.service.is_empty());
    }

    // ========================================================================
    // Gap 1: JSON null parameter handling
    // ========================================================================

    #[test]
    fn test_null_parameter_normalization() {
        let entry = LogEntry {
            version_id: "1-test".to_string(),
            version_time: "2025-01-01T00:00:00Z".to_string(),
            parameters: json!({
                "method": "did:webvh:1.0",
                "scid": "test",
                "updateKeys": ["key1"],
                "deactivated": null,
                "ttl": null,
                "portable": null
            }),
            state: json!({}),
            proof: vec![],
        };

        let normalized = normalize_null_parameters(&entry).unwrap();
        let params = normalized.parameters.as_object().unwrap();

        assert_eq!(params["deactivated"], json!(false));
        assert_eq!(params["ttl"], json!(3600));
        assert_eq!(params["portable"], json!(false));
    }

    #[test]
    fn test_null_parameter_array_defaults() {
        let entry = LogEntry {
            version_id: "1-test".to_string(),
            version_time: "2025-01-01T00:00:00Z".to_string(),
            parameters: json!({
                "updateKeys": null,
                "nextKeyHashes": null,
                "watchers": null
            }),
            state: json!({}),
            proof: vec![],
        };

        let normalized = normalize_null_parameters(&entry).unwrap();
        let params = normalized.parameters.as_object().unwrap();

        assert_eq!(params["updateKeys"], json!([]));
        assert_eq!(params["nextKeyHashes"], json!([]));
        assert_eq!(params["watchers"], json!([]));
    }

    #[test]
    fn test_null_witness_defaults_to_empty_object() {
        let entry = LogEntry {
            version_id: "1-test".to_string(),
            version_time: "2025-01-01T00:00:00Z".to_string(),
            parameters: json!({ "witness": null }),
            state: json!({}),
            proof: vec![],
        };

        let normalized = normalize_null_parameters(&entry).unwrap();
        let params = normalized.parameters.as_object().unwrap();
        assert_eq!(params["witness"], json!({}));
    }

    #[test]
    fn test_no_normalization_when_no_nulls() {
        let entry = LogEntry {
            version_id: "1-test".to_string(),
            version_time: "2025-01-01T00:00:00Z".to_string(),
            parameters: json!({ "ttl": 7200 }),
            state: json!({}),
            proof: vec![],
        };

        assert!(normalize_null_parameters(&entry).is_none());
    }

    // ========================================================================
    // Gap 2: Partial log validity
    // ========================================================================

    #[test]
    fn test_partial_validity_query_returns_valid_entry() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry with non-monotonic time (invalid)
        let mut entry2 = json!({
            "versionTime": "2024-01-01T00:00:00Z",  // Earlier than genesis = invalid
            "parameters": {},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        // Without query params, should fail because the invalid entry is the last
        let result = process_log(&did, &scid, &body);
        assert!(result.is_err());

        // With query params pointing to version 1, should succeed (partial validity)
        let qp = QueryParams {
            version_number: Some(1),
            ..Default::default()
        };
        let result = process_log_with_params(&did, &scid, &body, None, &qp);
        assert!(
            result.is_ok(),
            "partial validity should return version 1: {:?}",
            result
        );
        assert_eq!(result.unwrap().version_number, 1);
    }

    #[test]
    fn test_partial_validity_genesis_failure_aborts() {
        // If genesis entry is invalid, partial validity doesn't help
        let entry = json!({
            "versionId": "1-test",
            "versionTime": "2025-01-01T00:00:00Z",
            "parameters": {
                "scid": "test"
                // missing method and updateKeys
            },
            "state": { "id": "did:webvh:test:example.com" },
            "proof": []
        });

        let body = serde_json::to_string(&entry).unwrap();
        let qp = QueryParams {
            version_number: Some(1),
            ..Default::default()
        };
        let result =
            process_log_with_params("did:webvh:test:example.com", "test", &body, None, &qp);
        assert!(result.is_err(), "genesis failure should always abort");
    }

    // ========================================================================
    // Gap 3: Deactivated DID metadata on historical queries
    // ========================================================================

    #[test]
    fn test_deactivated_metadata_on_historical_query() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry that deactivates
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"deactivated": true},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        // Query for version 1 (before deactivation) — should succeed
        // but metadata MUST include deactivated: true
        let qp = QueryParams {
            version_number: Some(1),
            ..Default::default()
        };
        let result = process_log_with_params(&did, &scid, &body, None, &qp);
        assert!(
            result.is_ok(),
            "historical query should succeed: {:?}",
            result
        );

        let resolved = result.unwrap();
        assert_eq!(resolved.version_number, 1);
        assert!(
            resolved.metadata.deactivated,
            "metadata must include deactivated: true even for historical versions"
        );
    }

    #[test]
    fn test_deactivated_default_resolution_fails() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry that deactivates
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"deactivated": true},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        // Default resolution (no query params) should fail for deactivated DID
        let result = process_log(&did, &scid, &body);
        assert!(matches!(result, Err(WebVHDIDError::DeactivatedDID { .. })));
    }

    // ========================================================================
    // Gap 4: Alternative deactivation via empty updateKeys
    // ========================================================================

    #[test]
    fn test_empty_update_keys_deactivation() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry with empty updateKeys (alternative deactivation)
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"updateKeys": []},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));

        // Sign with current keys (before they become empty)
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        // Default resolution should fail — empty updateKeys is effectively deactivated
        let result = process_log(&did, &scid, &body);
        assert!(
            matches!(result, Err(WebVHDIDError::DeactivatedDID { .. })),
            "empty updateKeys should be treated as deactivation, got: {:?}",
            result
        );
    }

    #[test]
    fn test_empty_update_keys_historical_query_shows_deactivated() {
        let (signing_key, multikey) = make_ed25519_keypair();
        let (scid, genesis) = build_genesis_entry(&signing_key, &multikey);
        let did = format!("did:webvh:{}:example.com", scid);

        // Build second entry with empty updateKeys
        let mut entry2 = json!({
            "versionTime": "2025-06-01T00:00:00Z",
            "parameters": {"updateKeys": []},
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": &did
            }
        });
        let entry_hash = super::super::scid::compute_entry_hash(&entry2).unwrap();
        entry2["versionId"] = json!(format!("2-{}", entry_hash));
        let proof = sign_entry(&signing_key, &multikey, &entry2);
        entry2["proof"] = json!([proof]);

        let body = format!(
            "{}\n{}",
            serde_json::to_string(&genesis).unwrap(),
            serde_json::to_string(&entry2).unwrap()
        );

        // Historical query for version 1 should succeed but show deactivated in metadata
        let qp = QueryParams {
            version_number: Some(1),
            ..Default::default()
        };
        let result = process_log_with_params(&did, &scid, &body, None, &qp);
        assert!(result.is_ok(), "historical query should work: {:?}", result);

        let resolved = result.unwrap();
        assert!(
            resolved.metadata.deactivated,
            "metadata must show deactivated even for historical query when updateKeys is empty"
        );
    }
}
