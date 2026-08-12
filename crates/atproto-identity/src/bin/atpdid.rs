//! AT Protocol DID resolution, verification, and management tool.
//!
//! A unified CLI for DID operations including key management, identity resolution,
//! PLC directory operations, and did:webvh document management.

use std::collections::HashMap;
use std::io::Read as _;
use std::process;

use anyhow::Result;
use atproto_identity::{
    config::{CertificateBundles, DnsNameservers, default_env, optional_env, version},
    key::{self, KeyData, KeyType},
    plc::{
        self, AuditLogEntry, Did, DidBuilder, Operation, OperationChainValidator, PlcState,
        ServiceEndpoint, UnsignedOperation,
    },
    resolve::{HickoryDnsResolver, InputType, parse_input, resolve_subject},
    web::query as web_query,
    webvh,
};
use clap::{Parser, Subcommand};

/// AT Protocol DID Management Tool
#[derive(Parser)]
#[command(
    name = "atpdid",
    version,
    about = "AT Protocol DID resolution, verification, and management",
    long_about = "
A unified command-line tool for AT Protocol DID operations. Supports key
management, identity resolution, PLC directory operations (verify, create,
update, submit), and did:webvh document management.

ENVIRONMENT VARIABLES:
  PLC_HOSTNAME         PLC directory hostname (default: \"plc.directory\")
  USER_AGENT           HTTP user agent string (default: auto-generated)
  CERTIFICATE_BUNDLES  Colon-separated paths to additional CA certificates
  DNS_NAMESERVERS      Comma-separated DNS nameserver addresses

EXAMPLES:
  # Generate a P-256 key pair:
  atpdid key generate p256

  # Inspect a did:key:
  atpdid key inspect did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2

  # Resolve a handle:
  atpdid resolve ngerakines.me

  # Verify a PLC audit log:
  atpdid plc verify did:plc:ewvi7nxzyoun6zhxrhs64oiz

  # Verify a did:webvh:
  atpdid webvh verify did:webvh:QmTest:example.com
"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cryptographic key operations
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Resolve AT Protocol handles and DIDs
    Resolve {
        /// One or more AT Protocol handles or DIDs to resolve
        subjects: Vec<String>,

        /// Fetch and display the full DID document
        #[arg(long)]
        document: bool,
    },
    /// PLC directory operations
    Plc {
        #[command(subcommand)]
        command: PlcCommands,
    },
    /// WebVH (did:webvh) operations
    Webvh {
        #[command(subcommand)]
        command: WebvhCommands,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new key pair
    Generate {
        /// Key type to generate
        #[arg(value_enum)]
        key_type: KeyTypeArg,

        /// Output JWK representation instead of multibase (P-256, P-384, K-256 only)
        #[arg(long)]
        jwk: bool,
    },
    /// Inspect a key (did:key multibase string)
    Inspect {
        /// The key to inspect (did:key or multibase string)
        key: String,

        /// Output JWK representation (P-256 and P-384 only)
        #[arg(long)]
        jwk: bool,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum KeyTypeArg {
    /// P-256 (secp256r1/ES256)
    P256,
    /// P-384 (secp384r1/ES384)
    P384,
    /// K-256 (secp256k1/ES256K)
    K256,
    /// Ed25519 (EdDSA)
    Ed25519,
}

#[derive(Subcommand)]
enum PlcCommands {
    /// Verify a PLC audit log
    Verify {
        /// The DID or handle to verify
        #[arg(value_name = "DID_OR_HANDLE")]
        subject: String,

        /// Show verbose output including all operations
        #[arg(short, long)]
        verbose: bool,

        /// Only show summary
        #[arg(short, long)]
        quiet: bool,

        /// Custom PLC directory hostname
        #[arg(long)]
        plc_hostname: Option<String>,
    },
    /// Create a new did:plc identity
    Create {
        /// Rotation key (multibase private key string, repeatable)
        #[arg(long = "rotation-key", required = true)]
        rotation_keys: Vec<String>,

        /// Verification method as name=key (repeatable)
        #[arg(long = "verification-method")]
        verification_methods: Vec<String>,

        /// Also-known-as URI (repeatable)
        #[arg(long = "also-known-as")]
        also_known_as: Vec<String>,

        /// Service as name=type,endpoint (repeatable)
        #[arg(long = "service")]
        services: Vec<String>,
    },
    /// Create a PLC update operation
    Update {
        /// The DID to update
        did: String,

        /// Private key to sign the operation (multibase)
        #[arg(long = "signing-key")]
        signing_key: String,

        /// New rotation key (multibase, repeatable)
        #[arg(long = "rotation-key")]
        rotation_keys: Vec<String>,

        /// New verification method as name=key (repeatable)
        #[arg(long = "verification-method")]
        verification_methods: Vec<String>,

        /// New also-known-as URI (repeatable)
        #[arg(long = "also-known-as")]
        also_known_as: Vec<String>,

        /// New service as name=type,endpoint (repeatable)
        #[arg(long = "service")]
        services: Vec<String>,

        /// Custom PLC directory hostname
        #[arg(long)]
        plc_hostname: Option<String>,
    },
    /// Sign an unsigned PLC operation (reads JSON from stdin)
    Sign {
        /// Private key to sign the operation (multibase)
        #[arg(long = "signing-key")]
        signing_key: String,
    },
    /// Submit a signed PLC operation
    Submit {
        /// Signed operation JSON (use - for stdin)
        operation: String,

        /// The DID to submit the operation for
        #[arg(long)]
        did: String,

        /// Custom PLC directory hostname
        #[arg(long)]
        plc_hostname: Option<String>,
    },
}

#[derive(Subcommand)]
enum WebvhCommands {
    /// Verify a did:webvh log
    Verify {
        /// The did:webvh DID to verify
        did: String,

        /// Show verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Create a new did:webvh genesis document
    Create {
        /// Hostname for the DID
        #[arg(long)]
        hostname: String,

        /// Optional path component
        #[arg(long)]
        path: Option<String>,

        /// Ed25519 private key (multibase); generates one if not provided
        #[arg(long = "signing-key")]
        signing_key: Option<String>,

        /// Also generate a did:web did.json document
        #[arg(long = "did-web")]
        did_web: bool,
    },
    /// Create an update entry for an existing did:webvh
    Update {
        /// The did:webvh DID to update
        did: String,

        /// Ed25519 private key (multibase) for signing
        #[arg(long = "signing-key")]
        signing_key: String,

        /// Path to the current did.jsonl file (use - for stdin)
        #[arg(long = "log-file")]
        log_file: String,

        /// New DID document state as JSON string
        #[arg(long = "state")]
        state: String,

        /// New update keys (multibase, repeatable)
        #[arg(long = "update-key")]
        update_keys: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Key { command } => handle_key(command),
        Commands::Resolve { subjects, document } => handle_resolve(subjects, document).await,
        Commands::Plc { command } => handle_plc(command).await,
        Commands::Webvh { command } => handle_webvh(command).await,
    }
}

// ---------------------------------------------------------------------------
// Key commands
// ---------------------------------------------------------------------------

fn handle_key(command: KeyCommands) -> Result<()> {
    match command {
        KeyCommands::Generate { key_type, jwk } => {
            let (kt, label) = match key_type {
                KeyTypeArg::P256 => (KeyType::P256Private, "p256"),
                KeyTypeArg::P384 => (KeyType::P384Private, "p384"),
                KeyTypeArg::K256 => (KeyType::K256Private, "k256"),
                KeyTypeArg::Ed25519 => (KeyType::Ed25519Private, "ed25519"),
            };

            let private_key = key::generate_key(kt)?;
            let public_key = key::to_public(&private_key)?;

            if jwk {
                let jwk_result: Result<atproto_identity::jwk::Jwk, _> = (&private_key).try_into();
                match jwk_result {
                    Ok(jwk_key) => {
                        println!("{}", serde_json::to_string_pretty(&jwk_key)?);
                    }
                    Err(e) => {
                        eprintln!("JWK output not available for {}: {}", label, e);
                        process::exit(1);
                    }
                }
            } else {
                println!("{} private: {}", label, private_key);
                println!("{} public: {}", label, public_key);
            }

            Ok(())
        }
        KeyCommands::Inspect { key, jwk } => {
            let key_data = if key.trim_start().starts_with('{') {
                parse_jwk_to_key_data(&key)?
            } else {
                key::identify_key(&key)?
            };
            println!("Key type: {}", key_data.key_type());

            // Derive public key if this is a private key
            match key::to_public(&key_data) {
                Ok(public) => {
                    println!("Public key: {}", public);
                }
                Err(_) => {
                    // Already a public key
                    println!("Public key: {}", key_data);
                }
            }

            if jwk {
                let jwk_result: Result<atproto_identity::jwk::Jwk, _> = (&key_data).try_into();
                match jwk_result {
                    Ok(jwk_key) => {
                        println!("JWK: {}", serde_json::to_string_pretty(&jwk_key)?);
                    }
                    Err(e) => {
                        eprintln!("JWK conversion not available: {}", e);
                    }
                }
            }

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Resolve commands
// ---------------------------------------------------------------------------

async fn handle_resolve(subjects: Vec<String>, document: bool) -> Result<()> {
    let (http_client, dns_resolver, plc_hostname) = build_http_context()?;

    for subject in subjects {
        let resolved_did = match resolve_subject(&http_client, &dns_resolver, &subject).await {
            Ok(value) => value,
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        if !document {
            println!("{resolved_did}");
            continue;
        }

        let did_document: Result<_, anyhow::Error> = match parse_input(&resolved_did) {
            Ok(InputType::Plc(did)) => plc::query(&http_client, &plc_hostname, &did)
                .await
                .map_err(Into::into),
            Ok(InputType::Web(did)) => web_query(&http_client, &did).await.map_err(Into::into),
            Ok(InputType::WebVH(did)) => webvh::query(&http_client, &did).await.map_err(Into::into),
            Ok(InputType::Handle(_)) => {
                eprintln!("error: subject resolved to handle");
                continue;
            }
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        match did_document {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PLC commands
// ---------------------------------------------------------------------------

async fn handle_plc(command: PlcCommands) -> Result<()> {
    match command {
        PlcCommands::Verify {
            subject,
            verbose,
            quiet,
            plc_hostname: plc_hostname_override,
        } => {
            let (http_client, dns_resolver, default_plc_hostname) = build_http_context()?;
            let plc_hostname = plc_hostname_override.unwrap_or(default_plc_hostname);

            // Resolve subject to DID if it's a handle
            let did = match parse_input(&subject) {
                Ok(InputType::Plc(did)) => did,
                Ok(InputType::Handle(_)) => {
                    resolve_subject(&http_client, &dns_resolver, &subject).await?
                }
                _ => {
                    eprintln!("error: subject must be a did:plc or handle");
                    process::exit(1);
                }
            };

            let parsed_did = Did::parse(&did)
                .map_err(|e| {
                    eprintln!("Error: Invalid DID format: {}", e);
                    process::exit(1);
                })
                .unwrap();

            if !quiet {
                println!("Fetching audit log for: {}", parsed_did);
                println!("  Source: {}", plc_hostname);
                println!();
            }

            let audit_log =
                plc::fetch_audit_log(&http_client, &plc_hostname, parsed_did.as_str()).await?;

            if audit_log.is_empty() {
                eprintln!("Error: No operations found in audit log");
                process::exit(1);
            }

            if !quiet {
                println!("Audit Log Summary:");
                println!("  Total operations: {}", audit_log.len());
                println!("  Genesis operation: {}", audit_log[0].cid);
                println!("  Latest operation: {}", audit_log.last().unwrap().cid);
                println!();
            }

            if verbose {
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

            // Check for forks and nullified operations
            let has_forks = detect_forks(&audit_log);
            let has_nullified = audit_log.iter().any(|e| e.nullified);

            if has_forks || has_nullified {
                if !quiet {
                    if has_forks {
                        println!("Fork detected - multiple operations reference the same prev CID");
                    }
                    if has_nullified {
                        println!(
                            "Nullified operations detected - will validate canonical chain only"
                        );
                    }
                    println!();
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
                        display_final_state(&final_state, quiet);
                    }
                    Err(e) => {
                        eprintln!("Validation failed: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                // Linear chain validation
                validate_linear_chain(&audit_log, verbose)?;

                // Validate signatures
                validate_signatures(&audit_log, verbose);

                // Display final state
                let final_entry = audit_log.last().unwrap();
                if let Some(final_state) = extract_state(&final_entry.operation) {
                    display_final_state(&final_state, quiet);
                } else {
                    eprintln!("Error: Could not extract final state");
                    process::exit(1);
                }
            }

            Ok(())
        }
        PlcCommands::Create {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
        } => {
            let mut builder = DidBuilder::new();

            for rk_str in &rotation_keys {
                let key_data = key::identify_key(rk_str)?;
                builder = builder.add_rotation_key(key_data);
            }

            for vm_str in &verification_methods {
                let (name, key_str) = parse_key_value_pair(vm_str, "verification-method")?;
                let key_data = key::identify_key(&key_str)?;
                builder = builder.add_verification_method(name, key_data);
            }

            for uri in also_known_as {
                builder = builder.add_also_known_as(uri);
            }

            for svc_str in &services {
                let (name, rest) = parse_key_value_pair(svc_str, "service")?;
                let (svc_type, endpoint) = parse_service_value(&rest)?;
                builder = builder.add_service(name, ServiceEndpoint::new(svc_type, endpoint));
            }

            let (did, operation, _keys) = builder.build()?;
            println!("{}", did);
            println!();
            println!("{}", serde_json::to_string_pretty(&operation)?);

            Ok(())
        }
        PlcCommands::Update {
            did,
            signing_key,
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            plc_hostname: plc_hostname_override,
        } => {
            let (http_client, _dns_resolver, default_plc_hostname) = build_http_context()?;
            let plc_hostname = plc_hostname_override.unwrap_or(default_plc_hostname);

            // Fetch current audit log to get the latest CID
            let audit_log = plc::fetch_audit_log(&http_client, &plc_hostname, &did).await?;
            if audit_log.is_empty() {
                eprintln!("Error: No operations found for DID");
                process::exit(1);
            }

            let latest = audit_log.last().unwrap();
            let prev_cid = latest.operation.cid()?;

            // Parse signing key
            let signing_key_data = key::identify_key(&signing_key)?;

            // Build rotation keys
            let rk_strings: Vec<String> = if rotation_keys.is_empty() {
                latest
                    .operation
                    .rotation_keys()
                    .map(|rks| rks.to_vec())
                    .unwrap_or_default()
            } else {
                rotation_keys
            };

            // Build verification methods
            let mut vm_map: HashMap<String, String> = HashMap::new();
            for vm_str in &verification_methods {
                let (name, key_str) = parse_key_value_pair(vm_str, "verification-method")?;
                vm_map.insert(name, key_str);
            }

            // Build services
            let mut svc_map: HashMap<String, ServiceEndpoint> = HashMap::new();
            for svc_str in &services {
                let (name, rest) = parse_key_value_pair(svc_str, "service")?;
                let (svc_type, endpoint) = parse_service_value(&rest)?;
                svc_map.insert(name, ServiceEndpoint::new(svc_type, endpoint));
            }

            let unsigned =
                Operation::new_update(rk_strings, vm_map, also_known_as, svc_map, prev_cid);

            let signed = unsigned.sign(&signing_key_data)?;
            println!("{}", serde_json::to_string_pretty(&signed)?);

            Ok(())
        }
        PlcCommands::Sign { signing_key } => {
            let signing_key_data = key::identify_key(&signing_key)?;

            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;

            let unsigned: UnsignedOperation = serde_json::from_str(&buf)?;
            let signed = unsigned.sign(&signing_key_data)?;

            println!("{}", serde_json::to_string_pretty(&signed)?);

            Ok(())
        }
        PlcCommands::Submit {
            operation,
            did,
            plc_hostname: plc_hostname_override,
        } => {
            let (http_client, _dns_resolver, default_plc_hostname) = build_http_context()?;
            let plc_hostname = plc_hostname_override.unwrap_or(default_plc_hostname);

            let op_json = if operation == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                operation
            };

            let op: Operation = serde_json::from_str(&op_json)?;
            plc::submit(&http_client, &plc_hostname, &did, &op).await?;
            println!("Operation submitted successfully");

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// WebVH commands
// ---------------------------------------------------------------------------

async fn handle_webvh(command: WebvhCommands) -> Result<()> {
    match command {
        WebvhCommands::Verify { did, verbose } => {
            let (http_client, _dns_resolver, _plc_hostname) = build_http_context()?;

            let scid = webvh::extract_scid(&did)?;
            let url = webvh::did_webvh_to_url(&did)?;

            if verbose {
                println!("Resolving: {}", did);
                println!("  SCID: {}", scid);
                println!("  URL: {}", url);
                println!();
            }

            let body = http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?
                .text()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;

            let resolved = webvh::log::process_log(&did, &scid, &body)?;

            if verbose {
                println!("Log entries: {}", resolved.entry_count);
                println!("Version: {}", resolved.version_id);
                println!("Version time: {}", resolved.version_time);
                println!("Method: {}", resolved.parameters.method);
                println!("SCID: {}", resolved.parameters.scid);
                println!("Portable: {}", resolved.parameters.portable);
                println!("Deactivated: {}", resolved.parameters.deactivated);
                println!("TTL: {}s", resolved.parameters.ttl);
                if !resolved.parameters.update_keys.is_empty() {
                    println!("Update keys:");
                    for uk in &resolved.parameters.update_keys {
                        println!("  {}", uk);
                    }
                }
                println!();
            }

            // Check for witness configuration and re-verify with witnesses if present
            if resolved.parameters.witness.is_some() {
                let witness_url = webvh::did_webvh_to_witness_url(&did)?;
                if verbose {
                    println!("Witness configuration detected, fetching: {}", witness_url);
                }
                let witness_body = http_client
                    .get(&witness_url)
                    .send()
                    .await
                    .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?
                    .text()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to read response: {}", e))?;

                let witness_proofs: Vec<webvh::WitnessProofEntry> =
                    serde_json::from_str(&witness_body)?;

                let resolved = webvh::log::process_log_with_witnesses(
                    &did,
                    &scid,
                    &body,
                    Some(&witness_proofs),
                )?;

                println!("{}", serde_json::to_string_pretty(&resolved.document)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&resolved.document)?);
            }

            if verbose {
                println!();
                println!("Verification successful!");
            }

            Ok(())
        }
        WebvhCommands::Create {
            hostname,
            path,
            signing_key,
            did_web,
        } => {
            let key_data = match signing_key {
                Some(k) => Some(key::identify_key(&k)?),
                None => None,
            };

            let result =
                webvh::create::create_genesis(&hostname, path.as_deref(), key_data.as_ref())?;

            println!("DID: {}", result.did);
            println!("SCID: {}", result.scid);
            println!("Update key: {}", result.update_key);
            println!();
            println!("did.jsonl:");
            println!("{}", result.jsonl);

            if did_web {
                let did_web_suffix = match &path {
                    Some(p) => format!("{}:{}", hostname, p.replace('/', ":")),
                    None => hostname.clone(),
                };
                let did_web_id = format!("did:web:{}", did_web_suffix);

                let multikey = result
                    .update_key
                    .strip_prefix("did:key:")
                    .unwrap_or(&result.update_key);

                let did_doc = serde_json::json!({
                    "@context": [
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/multikey/v1"
                    ],
                    "id": did_web_id,
                    "alsoKnownAs": [result.did],
                    "authentication": [{
                        "id": format!("{}#{}", did_web_id, multikey),
                        "type": "Multikey",
                        "controller": &did_web_id,
                        "publicKeyMultibase": multikey,
                    }],
                });

                println!();
                println!("did:web DID: {}", did_web_id);
                println!();
                println!("did.json:");
                println!("{}", serde_json::to_string_pretty(&did_doc)?);
            }

            Ok(())
        }
        WebvhCommands::Update {
            did,
            signing_key,
            log_file,
            state,
            update_keys,
        } => {
            let signing_key_data = key::identify_key(&signing_key)?;

            let current_log = if log_file == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&log_file)?
            };

            let new_state: serde_json::Value = serde_json::from_str(&state)?;
            let new_keys = if update_keys.is_empty() {
                None
            } else {
                Some(update_keys)
            };

            let update_line = webvh::create::create_update_entry(
                &did,
                &current_log,
                new_state,
                &signing_key_data,
                new_keys,
            )?;

            println!("{}", update_line);

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the HTTP client, DNS resolver, and PLC hostname from environment.
fn build_http_context() -> Result<(reqwest::Client, HickoryDnsResolver, String)> {
    let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");
    let certificate_bundles: CertificateBundles = optional_env("CERTIFICATE_BUNDLES").try_into()?;
    let default_user_agent = format!(
        "atpdid ({}; +https://tangled.org/ngerakines.me/atproto-crates)",
        version()?
    );
    let user_agent = default_env("USER_AGENT", &default_user_agent);
    let dns_nameservers: DnsNameservers = optional_env("DNS_NAMESERVERS").try_into()?;

    let mut client_builder = reqwest::Client::builder();
    for ca_certificate in certificate_bundles.as_ref() {
        let cert = std::fs::read(ca_certificate)?;
        let cert = reqwest::Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
    }
    client_builder = client_builder.user_agent(user_agent);
    let http_client = client_builder.build()?;

    let dns_resolver = HickoryDnsResolver::create_resolver(dns_nameservers.as_ref());

    Ok((http_client, dns_resolver, plc_hostname))
}

/// Parse a JWK JSON string into a KeyData.
///
/// Supports P-256, P-384, and K-256 EC keys. Detects private vs public
/// based on the presence of the `d` parameter.
fn parse_jwk_to_key_data(jwk_json: &str) -> Result<KeyData> {
    let jwk: atproto_identity::jwk::Jwk =
        serde_json::from_str(jwk_json).map_err(|e| anyhow::anyhow!("invalid JWK: {}", e))?;
    // Curve dispatch, `d`-presence and on-curve validation all live in the
    // conversion in the library, so this tool accepts exactly what the server
    // does.
    KeyData::try_from(&jwk).map_err(|e| anyhow::anyhow!("invalid JWK: {}", e))
}

/// Parse a `name=value` pair from a CLI argument.
fn parse_key_value_pair(s: &str, arg_name: &str) -> Result<(String, String)> {
    let (name, value) = s
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid --{} format, expected name=value", arg_name))?;
    Ok((name.to_string(), value.to_string()))
}

/// Parse a service value in the format `type,endpoint`.
fn parse_service_value(s: &str) -> Result<(String, String)> {
    let (svc_type, endpoint) = s
        .split_once(',')
        .ok_or_else(|| anyhow::anyhow!("invalid --service value format, expected type,endpoint"))?;
    Ok((svc_type.to_string(), endpoint.to_string()))
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

/// Validate a linear chain (no forks).
fn validate_linear_chain(audit_log: &[AuditLogEntry], verbose: bool) -> Result<()> {
    if verbose {
        println!("Chain Validation:");
    }

    for i in 1..audit_log.len() {
        let prev_cid = &audit_log[i - 1].cid;
        let expected_prev = audit_log[i].operation.prev();

        if let Some(actual_prev) = expected_prev {
            if actual_prev != prev_cid {
                eprintln!("Validation failed: Chain linkage broken at operation {}", i);
                eprintln!("  Expected prev: {}", prev_cid);
                eprintln!("  Actual prev: {}", actual_prev);
                process::exit(1);
            }
            if verbose {
                println!("  [{}] Chain link valid", i);
            }
        } else {
            eprintln!(
                "Validation failed: Non-genesis operation {} missing prev field",
                i
            );
            process::exit(1);
        }
    }

    if verbose {
        println!();
    }

    Ok(())
}

/// Validate cryptographic signatures on audit log entries.
fn validate_signatures(audit_log: &[AuditLogEntry], verbose: bool) {
    if verbose {
        println!("Signature Validation:");
    }

    let mut current_rotation_keys: Vec<String> = Vec::new();

    for (i, entry) in audit_log.iter().enumerate() {
        if entry.nullified {
            continue;
        }

        if i == 0 {
            if let Some(rotation_keys) = entry.operation.rotation_keys() {
                current_rotation_keys = rotation_keys.to_vec();
                if verbose {
                    println!("  [{}] Genesis - {} rotation keys", i, rotation_keys.len());
                }
            }
            continue;
        }

        if !current_rotation_keys.is_empty() {
            let verifying_keys: Vec<KeyData> = current_rotation_keys
                .iter()
                .filter_map(|k| {
                    let key_data = key::identify_key(k).ok()?;
                    key::to_public(&key_data).ok()
                })
                .collect();

            if let Err(e) = entry.operation.verify(&verifying_keys) {
                eprintln!("Validation failed: Invalid signature at operation {}", i);
                eprintln!("  Error: {}", e);
                process::exit(1);
            }

            if verbose {
                println!("  [{}] Signature verified", i);
            }
        }

        if let Some(new_rotation_keys) = entry.operation.rotation_keys()
            && new_rotation_keys != current_rotation_keys
        {
            current_rotation_keys = new_rotation_keys.to_vec();
        }
    }

    if verbose {
        println!();
    }
}

/// Extract PLC state from an operation.
fn extract_state(operation: &Operation) -> Option<PlcState> {
    match operation {
        Operation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            ..
        } => Some(PlcState {
            rotation_keys: rotation_keys.clone(),
            verification_methods: verification_methods.clone(),
            also_known_as: also_known_as.clone(),
            services: services.clone(),
        }),
        _ => None,
    }
}

/// Display the final PLC state.
fn display_final_state(final_state: &PlcState, quiet: bool) {
    if quiet {
        println!("VALID");
        return;
    }

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
