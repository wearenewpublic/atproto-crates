//! AT Protocol inter-service authentication token generator.
//!
//! Generate JWT tokens for inter-service authentication with AT Protocol services.
//! Supports customizable issuer, audience, and additional claims via key=value pairs.

use anyhow::Result;
use atproto_identity::key::{KeyType, identify_key};
use atproto_identity::validation::{
    is_valid_did_method_plc, is_valid_did_method_web, is_valid_did_method_webvh,
};
use atproto_oauth::jwt::{Claims, Header, JoseClaims, mint};
use chrono::Utc;
use clap::Parser;
use serde_json::json;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

/// Helper function to validate if a string is a valid DID
fn is_valid_did(did: &str) -> bool {
    is_valid_did_method_plc(did)
        || is_valid_did_method_web(did, false)
        || is_valid_did_method_webvh(did, false)
        || did.starts_with("did:key:")
}

#[derive(Parser)]
#[command(
    name = "atproto-oauth-service-token",
    version,
    about = "Generate AT Protocol inter-service authentication tokens",
    long_about = "Generate JWT tokens for inter-service authentication with AT Protocol services.

USAGE:
  atproto-oauth-service-token <ISSUER_DID> <SIGNING_KEY> <AUDIENCE_DID> [KEY=VALUE...]

ARGUMENTS:
  <ISSUER_DID>     DID-formatted identity the token is for (e.g., did:plc:cbkjy5n7bk3ax2wplmtjofq2)
  <SIGNING_KEY>    Private signing key in did:key format OR name of environment variable containing the key
  <AUDIENCE_DID>   DID-formatted identity the token is for (e.g., did:web:example.com)
  [KEY=VALUE...]   Additional claims to include in the JWT (e.g., lxm=lexicon.method exp=3600)

SUPPORTED CLAIM KEYS:
  exp=<seconds>    Expiration time in seconds since epoch (use exp=+<secs> for relative time, default: now + 60)
  iat=<seconds>    Issued at time in seconds since epoch (use iat= or iat=now for current time, default: now)
  jti=<id>         JWT ID (use jti= for random ULID, default: randomly generated ULID)
  lxm=<method>     XRPC method to bind the token to
  <any>=<value>    Any other key=value will be added as a private claim

EXAMPLES:
  # Basic token with 60 second expiration:
  atproto-oauth-service-token did:plc:issuer did:key:private did:web:audience

  # Token with signing key from environment variable:
  SIGNING_KEY=did:key:z3vLYrthScXDXC1AUPvRperPn5T7nWxpJkkQVhCzdgfCxxhg
  atproto-oauth-service-token did:plc:issuer SIGNING_KEY did:web:audience

  # Token with custom expiration and XRPC method:
  atproto-oauth-service-token did:plc:issuer did:key:private did:web:audience \\
    exp=+3600 lxm=com.atproto.repo.createRecord

  # Token with multiple custom claims and generated JTI:
  atproto-oauth-service-token did:plc:issuer did:key:private did:web:audience \\
    lxm=garden.lexicon.helloworld.Hello scope=read:repo jti= custom_claim=value

  # Token with current timestamp and generated JTI:
  atproto-oauth-service-token did:plc:issuer did:key:private did:web:audience \\
    iat=now jti= exp=+3600

  # Token with relative expiration time (1 hour from now):
  atproto-oauth-service-token did:plc:issuer did:key:private did:web:audience \\
    exp=+3600 jti=

OUTPUT:
  eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NDg5ODg0OTcsImlzcyI6ImRpZDpwbGM6Y2Jrank1bjdiazNheDJ3cGxtdGpvZnEyIiwiYXVkIjoiZGlkOndlYjpuZ2VyYWtpbmVzLnR1bm4uZGV2IiwiZXhwIjoxNzQ4OTg4NTU3LCJseG0iOiJnYXJkZW4ubGV4aWNvbi5uZ2VyYWtpbmVzLmhlbGxvd29ybGQuSGVsbG8iLCJqdGkiOiI0ODQ2YjQ1OWMyMDFiMDNjZjBlZGMzYmE3NjQxNTk0MiJ9.sj74PPS97z81LSay6EyDOu3IQcF-bd4xGqK5u6qruhhWWiQR2IW89YMJ1s0H-P25xaTM1Zacp-pa4RlVsrH2uA"
)]
struct Args {
    /// Issuer DID (identity the token is for)
    issuer: String,

    /// Signing key (did:key format with private key) or environment variable name
    signing_key: String,

    /// Audience DID (who the token is for)
    audience: String,

    /// Additional key=value pairs for JWT claims
    additional_claims: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate issuer DID format
    if !is_valid_did(&args.issuer) {
        anyhow::bail!("Invalid issuer DID format: {}", args.issuer);
    }

    // Validate audience DID format
    if !is_valid_did(&args.audience) {
        anyhow::bail!("Invalid audience DID format: {}", args.audience);
    }

    // Get signing key - either directly or from environment variable
    let signing_key = if args.signing_key.starts_with("did:key:") {
        // Direct key value provided
        args.signing_key.clone()
    } else {
        // Treat as environment variable name
        env::var(&args.signing_key).map_err(|_| {
            anyhow::anyhow!(
                "Environment variable '{}' not found or empty",
                args.signing_key
            )
        })?
    };

    // Parse and validate the signing key
    let key_data = identify_key(&signing_key)?;

    // Verify it's a private key
    match key_data.key_type() {
        KeyType::P256Private | KeyType::P384Private | KeyType::K256Private => {
            // Valid private key
        }
        _ => {
            anyhow::bail!(
                "Signing key must be a private key, got: {}",
                key_data.key_type()
            );
        }
    }

    // Parse additional claims
    let mut duration: Option<u64> = None;
    let mut exp: Option<u64> = None;
    let mut iat: Option<u64> = None;
    let mut jti: Option<String> = None;
    let mut private_claims = std::collections::BTreeMap::new();

    // Get current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time error")
        .as_secs();

    for claim in &args.additional_claims {
        if let Some((key, value)) = claim.split_once('=') {
            match key {
                "exp" => {
                    // If value starts with "+", set duration instead of exp
                    if let Some(offset_str) = value.strip_prefix('+') {
                        duration = Some(offset_str.parse().map_err(|_| {
                            anyhow::anyhow!("Invalid exp offset value: {}", offset_str)
                        })?);
                    } else {
                        exp = Some(
                            value
                                .parse()
                                .map_err(|_| anyhow::anyhow!("Invalid exp value: {}", value))?,
                        );
                    }
                }
                "iat" => {
                    // If value is empty or "now", use current time
                    iat = if value.is_empty() || value == "now" {
                        Some(Utc::now().timestamp().cast_unsigned())
                    } else {
                        Some(
                            value
                                .parse()
                                .map_err(|_| anyhow::anyhow!("Invalid iat value: {}", value))?,
                        )
                    };
                }
                "jti" => {
                    // If value is empty, generate a random ULID
                    jti = if value.is_empty() {
                        Some(Ulid::generate().to_string().to_lowercase())
                    } else {
                        Some(value.to_string())
                    };
                }
                _ => {
                    // Add as private claim
                    // Try to parse as number first, then as boolean, then as string
                    let json_value = if let Ok(n) = value.parse::<i64>() {
                        json!(n)
                    } else if let Ok(f) = value.parse::<f64>() {
                        json!(f)
                    } else if let Ok(b) = value.parse::<bool>() {
                        json!(b)
                    } else {
                        json!(value)
                    };
                    private_claims.insert(key.to_string(), json_value);
                }
            }
        } else {
            eprintln!(
                "Warning: Ignoring invalid claim format: {} (expected key=value)",
                claim
            );
        }
    }

    // Create header from the key
    let mut header: Header = key_data.clone().try_into()?;

    // Always set typ field to "JWT"
    header.type_ = Some("JWT".to_string());

    // Determine issued_at time
    let issued_at = iat.unwrap_or(now);

    // Determine expiration time
    let expiration = if let Some(exp_value) = exp {
        Some(exp_value)
    } else if let Some(duration_value) = duration {
        Some(issued_at + duration_value)
    } else {
        // Default to 60 seconds from issued_at
        Some(issued_at + 60)
    };

    // Generate JWT ID if not provided
    let jwt_id = jti.unwrap_or_else(|| Ulid::generate().to_string().to_lowercase());

    // Create standard JOSE claims
    let jose = JoseClaims {
        issuer: Some(args.issuer),
        subject: None,
        audience: Some(args.audience),
        expiration,
        not_before: None,
        issued_at: Some(issued_at),
        json_web_token_id: Some(jwt_id),
        http_method: None,
        http_uri: None,
        nonce: None,
        auth: None,
    };

    // Create claims with private claims
    let mut claims = Claims::new(jose);
    claims.private = private_claims;

    // Mint the JWT token
    let token = mint(&key_data, &header, &claims)?;

    // Output the token
    println!("{}", token);

    Ok(())
}
