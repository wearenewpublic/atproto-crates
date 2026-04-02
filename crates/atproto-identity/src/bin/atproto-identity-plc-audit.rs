//! PLC Directory Audit Log Validator.
//!
//! Fetches DID audit logs from plc.directory and validates each operation
//! cryptographically to ensure the chain is valid.

use atproto_identity::key::{self, KeyData};
use atproto_identity::plc::{Did, Operation, OperationChainValidator, PlcState};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::process;

/// Validate DID audit logs from plc.directory.
#[derive(Parser, Debug)]
#[command(
    name = "atproto-identity-plc-audit",
    version,
    about = "Validate DID audit logs from plc.directory",
    long_about = "Fetches and validates the complete audit log for a did:plc identifier from plc.directory.\n\nEXAMPLES:\n  atproto-identity-plc-audit did:plc:ewvi7nxzyoun6zhxrhs64oiz\n  atproto-identity-plc-audit --verbose did:plc:ewvi7nxzyoun6zhxrhs64oiz\n  atproto-identity-plc-audit --quiet did:plc:ewvi7nxzyoun6zhxrhs64oiz"
)]
struct Args {
    /// The DID to audit (e.g., did:plc:ewvi7nxzyoun6zhxrhs64oiz).
    #[arg(value_name = "DID")]
    did: String,

    /// Show verbose output including all operations.
    #[arg(short, long)]
    verbose: bool,

    /// Only show summary (no operation details).
    #[arg(short, long)]
    quiet: bool,

    /// Custom PLC directory URL.
    #[arg(long, default_value = "https://plc.directory")]
    plc_url: String,
}

/// Audit log response from plc.directory.
#[derive(Debug, Deserialize)]
struct AuditLogEntry {
    /// The DID this operation is for.
    #[allow(dead_code)]
    did: String,

    /// The operation itself.
    operation: Operation,

    /// CID of this operation.
    cid: String,

    /// Timestamp when this operation was created.
    #[serde(rename = "createdAt")]
    created_at: String,

    /// Nullified flag (if this operation was invalidated).
    #[serde(default)]
    nullified: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let did = match Did::parse(&args.did) {
        Ok(did) => did,
        Err(e) => {
            eprintln!("Error: Invalid DID format: {}", e);
            eprintln!("  Expected format: did:plc:<24 lowercase base32 characters>");
            process::exit(1);
        }
    };

    if !args.quiet {
        println!("Fetching audit log for: {}", did);
        println!("  Source: {}", args.plc_url);
        println!();
    }

    let audit_log = match fetch_audit_log(&args.plc_url, &did).await {
        Ok(log) => log,
        Err(e) => {
            eprintln!("Error: Failed to fetch audit log: {}", e);
            process::exit(1);
        }
    };

    if audit_log.is_empty() {
        eprintln!("Error: No operations found in audit log");
        process::exit(1);
    }

    if !args.quiet {
        println!("Audit Log Summary:");
        println!("  Total operations: {}", audit_log.len());
        println!("  Genesis operation: {}", audit_log[0].cid);
        println!("  Latest operation: {}", audit_log.last().unwrap().cid);
        println!();
    }

    if args.verbose {
        println!("Operations:");
        for (i, entry) in audit_log.iter().enumerate() {
            let status = if entry.nullified { "NULLIFIED" } else { "OK" };
            println!("  [{}] {} {} - {}", i, status, entry.cid, entry.created_at);
            if entry.operation.is_genesis() {
                println!("      Type: Genesis (creates the DID)");
            } else {
                println!("      Type: Update");
            }
            if let Some(prev) = entry.operation.prev() {
                println!("      Previous: {}", prev);
            }
        }
        println!();
    }

    if !args.quiet {
        println!("Analyzing operation chain...");
        println!();
    }

    let has_forks = detect_forks(&audit_log);
    let has_nullified = audit_log.iter().any(|e| e.nullified);

    if has_forks || has_nullified {
        if !args.quiet {
            if has_forks {
                println!("Fork detected - multiple operations reference the same prev CID");
            }
            if has_nullified {
                println!("Nullified operations detected - will validate canonical chain only");
            }
            println!();
        }

        if args.verbose {
            println!("Step 1: Fork Resolution & Canonical Chain Building");
            println!("===================================================");
        }

        let operations: Vec<_> = audit_log.iter().map(|e| e.operation.clone()).collect();
        let timestamps: Vec<_> = audit_log
            .iter()
            .map(|e| {
                e.created_at
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap_or_else(|_| chrono::Utc::now())
            })
            .collect();

        match OperationChainValidator::validate_chain_with_forks(&operations, &timestamps) {
            Ok(final_state) => {
                if args.verbose {
                    println!("  Fork resolution complete");
                    println!("  Canonical chain validated successfully");
                    println!();

                    println!("Canonical Chain Operations:");
                    println!("===========================");

                    let canonical_indices = build_canonical_chain_indices(&audit_log);

                    for idx in &canonical_indices {
                        let entry = &audit_log[*idx];
                        println!("  [{}] {} - {}", idx, entry.cid, entry.created_at);
                    }
                    println!();

                    if has_nullified {
                        println!("Nullified/Rejected Operations:");
                        println!("==============================");
                        for (i, entry) in audit_log.iter().enumerate() {
                            if entry.nullified && !canonical_indices.contains(&i) {
                                println!(
                                    "  [{}] {} - {} (nullified)",
                                    i, entry.cid, entry.created_at
                                );
                                if let Some(prev) = entry.operation.prev() {
                                    println!("      Referenced: {}", prev);
                                }
                            }
                        }
                        println!();
                    }
                }

                display_final_state(&final_state, args.quiet);
                return;
            }
            Err(e) => {
                eprintln!();
                eprintln!("Validation failed: {}", e);
                process::exit(1);
            }
        }
    }

    // Simple linear chain validation (no forks or nullified operations)
    if args.verbose {
        println!("Step 1: Linear Chain Validation");
        println!("================================");
    }

    for i in 1..audit_log.len() {
        let prev_cid = audit_log[i - 1].cid.clone();
        let expected_prev = audit_log[i].operation.prev();

        if args.verbose {
            println!("  [{}] Checking prev reference...", i);
            println!("      Expected: {}", prev_cid);
        }

        if let Some(actual_prev) = expected_prev {
            if args.verbose {
                println!("      Actual:   {}", actual_prev);
            }

            if actual_prev != prev_cid {
                eprintln!();
                eprintln!("Validation failed: Chain linkage broken at operation {}", i);
                eprintln!("  Expected prev: {}", prev_cid);
                eprintln!("  Actual prev: {}", actual_prev);
                process::exit(1);
            }

            if args.verbose {
                println!("      Match - chain link valid");
            }
        } else {
            eprintln!();
            eprintln!(
                "Validation failed: Non-genesis operation {} missing prev field",
                i
            );
            process::exit(1);
        }
    }

    if args.verbose {
        println!();
        println!("Chain linkage validation complete");
        println!();
    }

    // Step 2: Validate cryptographic signatures
    if args.verbose {
        println!("Step 2: Cryptographic Signature Validation");
        println!("==========================================");
    }

    let mut current_rotation_keys: Vec<String> = Vec::new();

    for (i, entry) in audit_log.iter().enumerate() {
        if entry.nullified {
            if args.verbose {
                println!("  [{}] Skipped (nullified)", i);
            }
            continue;
        }

        if i == 0 {
            if args.verbose {
                println!("  [{}] Genesis operation - extracting rotation keys", i);
            }

            if let Some(rotation_keys) = entry.operation.rotation_keys() {
                current_rotation_keys = rotation_keys.to_vec();

                if args.verbose {
                    println!("      Rotation keys: {}", rotation_keys.len());
                    for (j, rk) in rotation_keys.iter().enumerate() {
                        println!("        [{}] {}", j, rk);
                    }
                    println!("      Genesis signature cannot be verified (bootstrapping trust)");
                }
            }
            continue;
        }

        if args.verbose {
            println!("  [{}] Validating signature...", i);
            println!("      CID: {}", entry.cid);
            println!("      Signature: {}", entry.operation.signature());
        }

        if !current_rotation_keys.is_empty() {
            if args.verbose {
                println!(
                    "      Available rotation keys: {}",
                    current_rotation_keys.len()
                );
                for (j, rk) in current_rotation_keys.iter().enumerate() {
                    println!("        [{}] {}", j, rk);
                }
            }

            let verifying_keys: Vec<KeyData> = current_rotation_keys
                .iter()
                .filter_map(|k| {
                    let key_data = key::identify_key(k).ok()?;
                    key::to_public(&key_data).ok()
                })
                .collect();

            if args.verbose {
                println!(
                    "      Parsed verifying keys: {}/{}",
                    verifying_keys.len(),
                    current_rotation_keys.len()
                );
            }

            let mut verified = false;
            let mut verification_key_index = None;

            for (j, vk) in verifying_keys.iter().enumerate() {
                if entry.operation.verify(std::slice::from_ref(vk)).is_ok() {
                    verified = true;
                    verification_key_index = Some(j);
                    break;
                }
            }

            if !verified && let Err(e) = entry.operation.verify(&verifying_keys) {
                eprintln!();
                eprintln!("Validation failed: Invalid signature at operation {}", i);
                eprintln!("  Error: {}", e);
                eprintln!("  CID: {}", entry.cid);
                eprintln!(
                    "  Tried {} rotation keys, none verified the signature",
                    verifying_keys.len()
                );
                process::exit(1);
            }

            if args.verbose {
                if let Some(key_idx) = verification_key_index {
                    println!("      Signature verified with rotation key [{}]", key_idx);
                    println!("        {}", current_rotation_keys[key_idx]);
                } else {
                    println!("      Signature verified");
                }
            }
        }

        if let Some(new_rotation_keys) = entry.operation.rotation_keys()
            && new_rotation_keys != current_rotation_keys
        {
            if args.verbose {
                println!("      Rotation keys updated by this operation");
                println!("        Old keys: {}", current_rotation_keys.len());
                println!("        New keys: {}", new_rotation_keys.len());
                for (j, rk) in new_rotation_keys.iter().enumerate() {
                    println!("          [{}] {}", j, rk);
                }
            }
            current_rotation_keys = new_rotation_keys.to_vec();
        }
    }

    if args.verbose {
        println!();
        println!("Cryptographic signature validation complete");
        println!();
    }

    // Build final state
    let final_entry = audit_log.last().unwrap();
    if final_entry.operation.rotation_keys().is_some() {
        let final_state = match &final_entry.operation {
            Operation::PlcOperation {
                rotation_keys,
                verification_methods,
                also_known_as,
                services,
                ..
            } => PlcState {
                rotation_keys: rotation_keys.clone(),
                verification_methods: verification_methods.clone(),
                also_known_as: also_known_as.clone(),
                services: services.clone(),
            },
            _ => PlcState::new(),
        };

        display_final_state(&final_state, args.quiet);
    } else {
        eprintln!("Error: Could not extract final state");
        process::exit(1);
    }
}

/// Detect if there are fork points in the audit log.
fn detect_forks(audit_log: &[AuditLogEntry]) -> bool {
    let mut prev_counts: HashMap<String, usize> = HashMap::new();

    for entry in audit_log {
        if let Some(prev) = entry.operation.prev() {
            *prev_counts.entry(prev.to_string()).or_insert(0) += 1;
        }
    }

    prev_counts.values().any(|&count| count > 1)
}

/// Build a list of indices that form the canonical chain.
fn build_canonical_chain_indices(audit_log: &[AuditLogEntry]) -> Vec<usize> {
    let mut prev_to_indices: HashMap<String, Vec<usize>> = HashMap::new();

    for (i, entry) in audit_log.iter().enumerate() {
        if let Some(prev) = entry.operation.prev() {
            prev_to_indices.entry(prev.to_string()).or_default().push(i);
        }
    }

    let mut canonical = Vec::new();

    let genesis = match audit_log.first() {
        Some(g) => g,
        None => return canonical,
    };

    canonical.push(0);
    let mut current_cid = genesis.cid.clone();

    while let Some(indices) = prev_to_indices.get(&current_cid) {
        if let Some(&next_idx) = indices.iter().find(|&&idx| !audit_log[idx].nullified) {
            canonical.push(next_idx);
            current_cid = audit_log[next_idx].cid.clone();
        } else if let Some(&next_idx) = indices.first() {
            canonical.push(next_idx);
            current_cid = audit_log[next_idx].cid.clone();
        } else {
            break;
        }
    }

    canonical
}

/// Display the final state after validation.
fn display_final_state(final_state: &PlcState, quiet: bool) {
    if quiet {
        println!("VALID");
    } else {
        println!("Validation successful!");
        println!();
        println!("Final DID State:");
        println!("  Rotation keys: {}", final_state.rotation_keys.len());
        for (i, rk) in final_state.rotation_keys.iter().enumerate() {
            println!("    [{}] {}", i, rk);
        }
        println!();
        println!(
            "  Verification methods: {}",
            final_state.verification_methods.len()
        );
        for (name, vm_key) in &final_state.verification_methods {
            println!("    {}: {}", name, vm_key);
        }
        println!();
        if !final_state.also_known_as.is_empty() {
            println!("  Also known as: {}", final_state.also_known_as.len());
            for uri in &final_state.also_known_as {
                println!("    - {}", uri);
            }
            println!();
        }
        if !final_state.services.is_empty() {
            println!("  Services: {}", final_state.services.len());
            for (name, service) in &final_state.services {
                println!(
                    "    {}: {} ({})",
                    name, service.endpoint, service.service_type
                );
            }
        }
    }
}

/// Fetch the audit log for a DID from plc.directory.
async fn fetch_audit_log(
    plc_url: &str,
    did: &Did,
) -> Result<Vec<AuditLogEntry>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/log/audit", plc_url, did);

    let client = reqwest::Client::builder()
        .user_agent("atproto-identity-plc-audit/0.14.4")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(format!(
            "HTTP error: {} - {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )
        .into());
    }

    let audit_log: Vec<AuditLogEntry> = response.json().await?;
    Ok(audit_log)
}
