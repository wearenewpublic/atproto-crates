//! PLC Fork Visualizer.
//!
//! Fetches DID audit logs and visualizes any forks in the operation chain,
//! showing which operations won/lost and why based on rotation key priority
//! and the 72-hour recovery window.

use atproto_identity::key;
use atproto_identity::plc::{Did, Operation, PlcState};
use chrono::{DateTime, Utc};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::process;

/// Visualize forks in PLC audit logs.
#[derive(Parser, Debug)]
#[command(
    name = "atproto-identity-plc-fork-viz",
    version,
    about = "Visualize forks in PLC audit logs",
    long_about = "Fetches and visualizes fork points in DID operation chains from plc.directory,\nshowing which operations won/lost based on rotation key priority and recovery window rules.\n\nEXAMPLES:\n  atproto-identity-plc-fork-viz did:plc:ewvi7nxzyoun6zhxrhs64oiz\n  atproto-identity-plc-fork-viz --verbose --timing did:plc:ewvi7nxzyoun6zhxrhs64oiz\n  atproto-identity-plc-fork-viz --format json did:plc:ewvi7nxzyoun6zhxrhs64oiz"
)]
struct Args {
    /// The DID to analyze (e.g., did:plc:ewvi7nxzyoun6zhxrhs64oiz).
    #[arg(value_name = "DID")]
    did: String,

    /// Custom PLC directory URL.
    #[arg(long, default_value = "https://plc.directory")]
    plc_url: String,

    /// Show detailed information for each operation.
    #[arg(short, long)]
    verbose: bool,

    /// Show timing information (timestamps and recovery window calculations).
    #[arg(short, long)]
    timing: bool,

    /// Show full DIDs and CIDs instead of truncated versions.
    #[arg(long)]
    full_ids: bool,

    /// Output format.
    #[arg(short, long, default_value = "tree")]
    format: OutputFormat,
}

/// Output format for fork visualization.
#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    /// ASCII tree visualization.
    Tree,
    /// Structured JSON output.
    Json,
    /// Markdown report format.
    Markdown,
}

/// Audit log response from plc.directory.
#[derive(Debug, Deserialize, Clone)]
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

    /// Nullified flag (if this operation was invalidated by fork resolution).
    #[allow(dead_code)]
    #[serde(default)]
    nullified: bool,
}

/// A fork point in the operation chain.
#[derive(Debug, Clone)]
struct ForkPoint {
    /// The prev CID that all operations in this fork reference.
    prev_cid: String,

    /// Competing operations at this fork.
    operations: Vec<ForkOperation>,

    /// The winning operation CID (after fork resolution).
    winner_cid: String,
}

/// An operation that is part of a fork.
#[derive(Debug, Clone)]
struct ForkOperation {
    cid: String,
    operation: Operation,
    timestamp: DateTime<Utc>,
    signing_key_index: Option<usize>,
    signing_key: Option<String>,
    is_winner: bool,
    rejection_reason: Option<String>,
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

    println!("Analyzing forks in: {}", did);
    println!("  Source: {}", args.plc_url);
    println!();

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

    println!("Audit log contains {} operations", audit_log.len());

    let forks = detect_forks(&audit_log, &args);

    if forks.is_empty() {
        println!();
        println!("No forks detected - this is a linear operation chain");
        println!("  All operations form a single canonical path from genesis to tip.");

        if args.verbose {
            println!();
            println!("Linear chain visualization:");
            visualize_linear_chain(&audit_log, &args);
        }

        return;
    }

    println!("Detected {} fork point(s)", forks.len());
    println!();

    match args.format {
        OutputFormat::Tree => visualize_tree(&audit_log, &forks, &args),
        OutputFormat::Json => visualize_json(&forks),
        OutputFormat::Markdown => visualize_markdown(&audit_log, &forks, &args),
    }
}

/// Detect fork points in the audit log.
fn detect_forks(audit_log: &[AuditLogEntry], args: &Args) -> Vec<ForkPoint> {
    let mut prev_to_operations: HashMap<String, Vec<AuditLogEntry>> = HashMap::new();

    for entry in audit_log {
        if let Some(prev) = entry.operation.prev() {
            prev_to_operations
                .entry(prev.to_string())
                .or_default()
                .push(entry.clone());
        }
    }

    let operation_map: HashMap<String, AuditLogEntry> = audit_log
        .iter()
        .map(|e| (e.cid.clone(), e.clone()))
        .collect();

    let mut forks = Vec::new();

    for (prev_cid, operations) in prev_to_operations {
        if operations.len() > 1 {
            if args.verbose {
                println!("Fork detected at {}", truncate(&prev_cid, args));
                println!("  {} competing operations", operations.len());
            }

            let state = if let Some(prev_entry) = operation_map.get(&prev_cid) {
                get_state_from_operation(&prev_entry.operation)
            } else {
                continue;
            };

            let mut fork_ops = Vec::new();
            for entry in &operations {
                let timestamp = parse_timestamp(&entry.created_at);

                let (signing_key_index, signing_key) = if !state.rotation_keys.is_empty() {
                    find_signing_key(&entry.operation, &state.rotation_keys)
                } else {
                    (None, None)
                };

                fork_ops.push(ForkOperation {
                    cid: entry.cid.clone(),
                    operation: entry.operation.clone(),
                    timestamp,
                    signing_key_index,
                    signing_key,
                    is_winner: false,
                    rejection_reason: None,
                });
            }

            let winner_cid = resolve_fork(&mut fork_ops);

            forks.push(ForkPoint {
                prev_cid,
                operations: fork_ops,
                winner_cid,
            });
        }
    }

    forks.sort_by_key(|f| {
        f.operations
            .iter()
            .map(|op| op.timestamp)
            .min()
            .unwrap_or_else(Utc::now)
    });

    forks
}

/// Resolve a fork point and mark the winner.
fn resolve_fork(fork_ops: &mut [ForkOperation]) -> String {
    fork_ops.sort_by_key(|op| op.timestamp);

    let mut winner_idx = 0;
    fork_ops[0].is_winner = true;

    for i in 1..fork_ops.len() {
        let competing_key_idx = fork_ops[i].signing_key_index;
        let winner_key_idx = fork_ops[winner_idx].signing_key_index;

        match (competing_key_idx, winner_key_idx) {
            (Some(competing_idx), Some(winner_idx_val)) => {
                if competing_idx < winner_idx_val {
                    let time_diff = fork_ops[i].timestamp - fork_ops[winner_idx].timestamp;

                    if time_diff <= chrono::Duration::hours(72) {
                        fork_ops[winner_idx].is_winner = false;
                        fork_ops[winner_idx].rejection_reason = Some(format!(
                            "Invalidated by higher-priority key[{}] within recovery window",
                            competing_idx
                        ));

                        fork_ops[i].is_winner = true;
                        winner_idx = i;
                    } else {
                        fork_ops[i].rejection_reason = Some(format!(
                            "Higher-priority key[{}] but outside 72-hour recovery window ({:.1}h late)",
                            competing_idx,
                            time_diff.num_hours() as f64
                        ));
                    }
                } else {
                    fork_ops[i].rejection_reason = Some(format!(
                        "Lower-priority key[{}] (current winner has key[{}])",
                        competing_idx, winner_idx_val
                    ));
                }
            }
            _ => {
                fork_ops[i].rejection_reason = Some("Could not determine signing key".to_string());
            }
        }
    }

    fork_ops[winner_idx].cid.clone()
}

/// Find which rotation key signed an operation.
fn find_signing_key(
    operation: &Operation,
    rotation_keys: &[String],
) -> (Option<usize>, Option<String>) {
    for (index, key_did) in rotation_keys.iter().enumerate() {
        if let Ok(key_data) = key::identify_key(key_did)
            && let Ok(public_key) = key::to_public(&key_data)
            && operation.verify(&[public_key]).is_ok()
        {
            return (Some(index), Some(key_did.clone()));
        }
    }
    (None, None)
}

/// Get PLC state from an operation.
fn get_state_from_operation(operation: &Operation) -> PlcState {
    match operation {
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
    }
}

/// Parse ISO 8601 timestamp.
fn parse_timestamp(timestamp: &str) -> DateTime<Utc> {
    timestamp
        .parse::<DateTime<Utc>>()
        .unwrap_or_else(|_| Utc::now())
}

/// Visualize forks as a tree.
fn visualize_tree(audit_log: &[AuditLogEntry], forks: &[ForkPoint], args: &Args) {
    println!("Fork Visualization (Tree Format)");
    println!("================================================================");
    println!();

    let mut fork_map: HashMap<String, &ForkPoint> = HashMap::new();
    for fork in forks {
        for op in &fork.operations {
            fork_map.insert(op.cid.clone(), fork);
        }
    }

    let mut processed_forks: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in audit_log.iter() {
        let is_genesis = entry.operation.is_genesis();
        let prev = entry.operation.prev();

        if prev.is_some()
            && let Some(fork) = fork_map.get(&entry.cid)
        {
            if !processed_forks.contains(&fork.prev_cid) {
                processed_forks.insert(fork.prev_cid.clone());

                println!(
                    "Fork at operation referencing {}",
                    truncate(&fork.prev_cid, args)
                );

                for (j, fork_op) in fork.operations.iter().enumerate() {
                    let symbol = if fork_op.is_winner { "+" } else { "x" };
                    let status = if fork_op.is_winner {
                        "WINNER"
                    } else {
                        "REJECTED"
                    };
                    let prefix = if j == fork.operations.len() - 1 {
                        "\\-"
                    } else {
                        "|-"
                    };

                    println!(
                        "  {} [{}] {} CID: {}",
                        prefix,
                        symbol,
                        status,
                        truncate(&fork_op.cid, args)
                    );

                    if let Some(key_idx) = fork_op.signing_key_index {
                        println!("     |  Signed by: rotation_key[{}]", key_idx);
                        if args.verbose
                            && let Some(fk) = &fork_op.signing_key
                        {
                            println!("     |  Key: {}", truncate(fk, args));
                        }
                    }

                    if args.timing {
                        println!(
                            "     |  Timestamp: {}",
                            fork_op.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }

                    if !fork_op.is_winner {
                        if let Some(reason) = &fork_op.rejection_reason {
                            println!("     |  Reason: {}", reason);
                        }
                    } else {
                        println!("     |  Status: CANONICAL (winner)");
                    }

                    if args.verbose
                        && let Operation::PlcOperation { services, .. } = &fork_op.operation
                        && !services.is_empty()
                    {
                        println!("     |  Services: {} configured", services.len());
                    }

                    if j < fork.operations.len() - 1 {
                        println!("     |");
                    }
                }
                println!();
            }
            continue;
        }

        if is_genesis {
            println!("Genesis");
            println!("  CID: {}", truncate(&entry.cid, args));
            if args.timing {
                println!("  Timestamp: {}", entry.created_at);
            }
            if args.verbose
                && let Operation::PlcOperation { rotation_keys, .. } = &entry.operation
            {
                println!("  Rotation keys: {}", rotation_keys.len());
            }
            println!();
        }
    }

    println!("================================================================");
    println!("Summary:");
    println!("  Total operations: {}", audit_log.len());
    println!("  Fork points: {}", forks.len());

    let total_competing_ops: usize = forks.iter().map(|f| f.operations.len()).sum();
    let rejected_ops = total_competing_ops - forks.len();
    println!("  Rejected operations: {}", rejected_ops);

    if !forks.is_empty() {
        println!();
        println!("Fork Resolution Details:");
        for (i, fork) in forks.iter().enumerate() {
            let winner = fork.operations.iter().find(|op| op.is_winner).unwrap();
            println!(
                "  Fork {}: Winner is {} (signed by key[{}])",
                i + 1,
                truncate(&winner.cid, args),
                winner.signing_key_index.unwrap_or(999)
            );
        }
    }
}

/// Visualize linear chain (no forks).
fn visualize_linear_chain(audit_log: &[AuditLogEntry], args: &Args) {
    for (i, entry) in audit_log.iter().enumerate() {
        let symbol = if i == 0 { "[genesis]" } else { "  ->" };
        println!("{} Operation {}: {}", symbol, i, truncate(&entry.cid, args));

        if args.timing {
            println!("     Timestamp: {}", entry.created_at);
        }

        if args.verbose
            && let Some(prev) = entry.operation.prev()
        {
            println!("     Previous: {}", truncate(prev, args));
        }
    }
}

/// Visualize forks as JSON.
fn visualize_json(forks: &[ForkPoint]) {
    #[derive(serde::Serialize)]
    struct JsonFork {
        prev_cid: String,
        winner_cid: String,
        operations: Vec<JsonForkOp>,
    }

    #[derive(serde::Serialize)]
    struct JsonForkOp {
        cid: String,
        timestamp: String,
        signing_key_index: Option<usize>,
        is_winner: bool,
        rejection_reason: Option<String>,
    }

    let json_forks: Vec<JsonFork> = forks
        .iter()
        .map(|f| JsonFork {
            prev_cid: f.prev_cid.clone(),
            winner_cid: f.winner_cid.clone(),
            operations: f
                .operations
                .iter()
                .map(|op| JsonForkOp {
                    cid: op.cid.clone(),
                    timestamp: op.timestamp.to_rfc3339(),
                    signing_key_index: op.signing_key_index,
                    is_winner: op.is_winner,
                    rejection_reason: op.rejection_reason.clone(),
                })
                .collect(),
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_forks).unwrap());
}

/// Visualize forks as Markdown.
fn visualize_markdown(audit_log: &[AuditLogEntry], forks: &[ForkPoint], args: &Args) {
    println!("# PLC Fork Analysis Report\n");
    println!("**DID**: {}\n", args.did);
    println!("**Total Operations**: {}", audit_log.len());
    println!("**Fork Points**: {}\n", forks.len());

    if forks.is_empty() {
        println!("No forks detected - linear operation chain\n");
        return;
    }

    println!("## Fork Details\n");

    for (i, fork) in forks.iter().enumerate() {
        println!(
            "### Fork {} (at {})\n",
            i + 1,
            truncate(&fork.prev_cid, args)
        );
        println!("| Status | CID | Key Index | Timestamp | Reason |");
        println!("|--------|-----|-----------|-----------|--------|");

        for op in &fork.operations {
            let status = if op.is_winner { "Winner" } else { "Rejected" };
            let key_idx = op
                .signing_key_index
                .map(|i| i.to_string())
                .unwrap_or_else(|| "?".to_string());
            let timestamp = op.timestamp.format("%Y-%m-%d %H:%M:%S");
            let reason = op
                .rejection_reason
                .as_deref()
                .unwrap_or("Canonical operation");

            println!(
                "| {} | {} | {} | {} | {} |",
                status,
                truncate(&op.cid, args),
                key_idx,
                timestamp,
                reason
            );
        }

        println!();
    }

    println!("## Summary\n");
    println!(
        "- Total competing operations: {}",
        forks.iter().map(|f| f.operations.len()).sum::<usize>()
    );
    println!(
        "- Rejected operations: {}",
        forks.iter().map(|f| f.operations.len() - 1).sum::<usize>()
    );
}

/// Truncate a string for display.
fn truncate(s: &str, args: &Args) -> String {
    if args.full_ids {
        s.to_string()
    } else if s.len() > 20 {
        format!("{}...{}", &s[..8], &s[s.len() - 8..])
    } else {
        s.to_string()
    }
}

/// Fetch the audit log for a DID from plc.directory.
async fn fetch_audit_log(
    plc_url: &str,
    did: &Did,
) -> Result<Vec<AuditLogEntry>, Box<dyn std::error::Error>> {
    let url = format!("{}/{}/log/audit", plc_url, did);

    let client = reqwest::Client::builder()
        .user_agent("atproto-identity-plc-fork-viz/0.14.4")
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
