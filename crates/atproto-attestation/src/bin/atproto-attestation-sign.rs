//! Command-line tool for signing AT Protocol records with inline or remote attestations.
//!
//! This tool creates cryptographic signatures for AT Protocol records using the CID-first
//! attestation specification. It supports both inline attestations (embedding signatures
//! directly in records) and remote attestations (creating separate proof records).
//!
//! ## Usage Patterns
//!
//! ### Remote Attestation
//! ```bash
//! atproto-attestation-sign remote <source_repository_did> <source_record> <attestation_repository_did> <metadata_record>
//! ```
//!
//! ### Inline Attestation
//! ```bash
//! atproto-attestation-sign inline <source_record> <repository_did> <signing_key> <metadata_record>
//! ```
//!
//! ## Arguments
//!
//! - `source_repository_did`: (Remote mode) DID of the repository housing the source record (prevents replay attacks)
//! - `source_record`: JSON string or path to JSON file containing the record being attested
//! - `attestation_repository_did`: (Remote mode) DID of the repository where the attestation proof will be stored
//! - `repository_did`: (Inline mode) DID of the repository that will house the record (prevents replay attacks)
//! - `signing_key`: (Inline mode) Private key string (did:key format) used to sign the attestation
//! - `metadata_record`: JSON string or path to JSON file with attestation metadata used during CID creation
//!
//! ## Examples
//!
//! ```bash
//! # Remote attestation - creates proof record and strongRef
//! atproto-attestation-sign remote \
//!   did:plc:sourceRepo.. \
//!   record.json \
//!   did:plc:attestationRepo.. \
//!   metadata.json
//!
//! # Inline attestation - embeds signature in record
//! atproto-attestation-sign inline \
//!   record.json \
//!   did:plc:xyz123.. \
//!   did:key:z42tv1pb3.. \
//!   '{"$type":"com.example.attestation","purpose":"demo"}'
//!
//! # Read from stdin
//! cat record.json | atproto-attestation-sign remote \
//!   did:plc:sourceRepo.. \
//!   - \
//!   did:plc:attestationRepo.. \
//!   metadata.json
//! ```

use anyhow::{Context, Result, anyhow};
use atproto_attestation::{create_inline_attestation, create_remote_attestation, input::AnyInput};
use atproto_identity::key::identify_key;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

/// Command-line tool for signing AT Protocol records with cryptographic attestations.
///
/// Creates inline or remote attestations following the CID-first specification.
/// Inline attestations embed signatures directly in records, while remote attestations
/// generate separate proof records with strongRef references.
#[derive(Parser)]
#[command(
    name = "atproto-attestation-sign",
    version,
    about = "Sign AT Protocol records with cryptographic attestations",
    long_about = "
A command-line tool for signing AT Protocol records using the CID-first attestation
specification. Supports both inline attestations (signatures embedded in the record)
and remote attestations (separate proof records with CID references).

MODES:
  remote    Creates a separate proof record with strongRef reference
            Syntax: remote <source_repository_did> <source_record> <attestation_repository_did> <metadata_record>

  inline    Embeds signature bytes directly in the record
            Syntax: inline <source_record> <repository_did> <signing_key> <metadata_record>

ARGUMENTS:
  source_repository_did      (Remote) DID of repository housing the source record (for replay prevention)
  source_record              JSON string or file path to the record being attested
  attestation_repository_did (Remote) DID of repository where attestation proof will be stored
  repository_did             (Inline) DID of repository that will house the record (for replay prevention)
  signing_key                (Inline) Private key in did:key format for signing
  metadata_record            JSON string or file path with attestation metadata

EXAMPLES:
  # Remote attestation (creates proof record + strongRef):
  atproto-attestation-sign remote \\
    did:plc:sourceRepo... \\
    record.json \\
    did:plc:attestationRepo... \\
    metadata.json

  # Inline attestation (embeds signature):
  atproto-attestation-sign inline \\
    record.json \\
    did:plc:xyz123abc... \\
    did:key:z42tv1pb3Dzog28Q1udyieg1YJP3x1Un5vraE1bttXeCDSpW \\
    '{\"$type\":\"com.example.attestation\",\"purpose\":\"demo\"}'

  # Read source record from stdin:
  cat record.json | atproto-attestation-sign remote \\
    did:plc:sourceRepo... \\
    - \\
    did:plc:attestationRepo... \\
    metadata.json

OUTPUT:
  Remote mode outputs TWO JSON objects:
    1. The proof record (to be stored in the repository)
    2. The source record with strongRef attestation appended

  Inline mode outputs ONE JSON object:
    - The source record with inline attestation embedded
"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a remote attestation with separate proof record
    ///
    /// Generates a proof record containing the CID and returns both the proof
    /// record (to be stored in the attestation repository) and the source record
    /// with a strongRef attestation reference.
    #[command(visible_alias = "r")]
    Remote {
        /// DID of the repository housing the source record (for replay attack prevention)
        source_repository_did: String,

        /// Source record JSON string or file path (use '-' for stdin)
        source_record: String,

        /// DID of the repository where the attestation proof will be stored
        attestation_repository_did: String,

        /// Attestation metadata JSON string or file path
        metadata_record: String,
    },

    /// Create an inline attestation with embedded signature
    ///
    /// Signs the record with the provided private key and embeds the signature
    /// directly in the record's attestation structure.
    #[command(visible_alias = "i")]
    Inline {
        /// Source record JSON string or file path (use '-' for stdin)
        source_record: String,

        /// Repository DID that will house the record (for replay attack prevention)
        repository_did: String,

        /// Private signing key in did:key format (e.g., did:key:z...)
        signing_key: String,

        /// Attestation metadata JSON string or file path
        metadata_record: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Remote {
            source_repository_did,
            source_record,
            attestation_repository_did,
            metadata_record,
        } => handle_remote_attestation(
            &source_record,
            &source_repository_did,
            &metadata_record,
            &attestation_repository_did,
        )?,

        Commands::Inline {
            source_record,
            repository_did,
            signing_key,
            metadata_record,
        } => handle_inline_attestation(
            &source_record,
            &repository_did,
            &signing_key,
            &metadata_record,
        )?,
    }

    Ok(())
}

/// Handle remote attestation mode.
///
/// Creates a proof record and appends a strongRef to the source record.
/// Outputs both the proof record and the updated source record.
///
/// - `source_repository_did`: Used for signature binding (prevents replay attacks)
/// - `attestation_repository_did`: Where the attestation proof record will be stored
fn handle_remote_attestation(
    source_record: &str,
    source_repository_did: &str,
    metadata_record: &str,
    attestation_repository_did: &str,
) -> Result<()> {
    // Load source record and metadata
    let record_json = load_json_input(source_record)?;
    let metadata_json = load_json_input(metadata_record)?;

    // Validate inputs
    if !record_json.is_object() {
        return Err(anyhow!("Source record must be a JSON object"));
    }

    if !metadata_json.is_object() {
        return Err(anyhow!("Metadata record must be a JSON object"));
    }

    // Validate repository DIDs
    if !source_repository_did.starts_with("did:") {
        return Err(anyhow!(
            "Source repository DID must start with 'did:' prefix, got: {}",
            source_repository_did
        ));
    }

    if !attestation_repository_did.starts_with("did:") {
        return Err(anyhow!(
            "Attestation repository DID must start with 'did:' prefix, got: {}",
            attestation_repository_did
        ));
    }

    // Create the remote attestation using v2 API
    // This creates both the attested record with strongRef and the proof record in one call
    let (attested_record, proof_record) = create_remote_attestation(
        AnyInput::Serialize(record_json),
        AnyInput::Serialize(metadata_json),
        source_repository_did,
        attestation_repository_did,
    )
    .context("Failed to create remote attestation")?;

    // Output both records
    println!("=== Proof Record (store in repository) ===");
    println!("{}", serde_json::to_string_pretty(&proof_record)?);
    println!();
    println!("=== Attested Record (with strongRef) ===");
    println!("{}", serde_json::to_string_pretty(&attested_record)?);

    Ok(())
}

/// Handle inline attestation mode.
///
/// Signs the record with the provided key and embeds the signature.
/// Outputs the record with inline attestation.
fn handle_inline_attestation(
    source_record: &str,
    repository_did: &str,
    signing_key: &str,
    metadata_record: &str,
) -> Result<()> {
    // Load source record and metadata
    let record_json = load_json_input(source_record)?;
    let metadata_json = load_json_input(metadata_record)?;

    // Validate inputs
    if !record_json.is_object() {
        return Err(anyhow!("Source record must be a JSON object"));
    }

    if !metadata_json.is_object() {
        return Err(anyhow!("Metadata record must be a JSON object"));
    }

    // Validate repository DID
    if !repository_did.starts_with("did:") {
        return Err(anyhow!(
            "Repository DID must start with 'did:' prefix, got: {}",
            repository_did
        ));
    }

    // Parse the signing key
    let key_data = identify_key(signing_key)
        .with_context(|| format!("Failed to parse signing key: {}", signing_key))?;

    // Create inline attestation with repository binding using v2 API
    let signed_record = create_inline_attestation(
        AnyInput::Serialize(record_json),
        AnyInput::Serialize(metadata_json),
        repository_did,
        &key_data,
    )
    .context("Failed to create inline attestation")?;

    // Output the signed record
    println!("{}", serde_json::to_string_pretty(&signed_record)?);

    Ok(())
}

/// Load JSON input from various sources.
///
/// Accepts:
/// - "-" for stdin
/// - File paths (if the file exists)
/// - Direct JSON strings
///
/// Returns the parsed JSON value or an error.
fn load_json_input(argument: &str) -> Result<Value> {
    // Handle stdin input
    if argument == "-" {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .context("Failed to read from stdin")?;
        return serde_json::from_str(&input).context("Failed to parse JSON from stdin");
    }

    // Try as file path first
    let path = Path::new(argument);
    if path.is_file() {
        let file_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", argument))?;
        return serde_json::from_str(&file_content)
            .with_context(|| format!("Failed to parse JSON from file: {}", argument));
    }

    // Try as direct JSON string
    serde_json::from_str(argument).with_context(|| {
        format!(
            "Argument is neither valid JSON nor a readable file: {}",
            argument
        )
    })
}
