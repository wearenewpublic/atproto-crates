//! Mint the client-attestation JWS (`typ: atproto-client-attestation+jwt`).
//!
//! Presented at `getSpaceCredential`. `iss == sub == client_id`,
//! `aud == <spaceDid>#atproto_space_host`, lifetime <= 300s, fresh `jti`.

use std::time::{SystemTime, UNIX_EPOCH};

use atproto_identity::key::{KeyData, to_public};
use atproto_oauth::jwt::{Claims, Header, JoseClaims, mint};
use atproto_space::credential::space_host_audience;
use rand::RngExt;

use crate::error::{AppError, AppResult};

/// `typ` header value for a client attestation (spec §3.7).
const TYP_CLIENT_ATTESTATION: &str = "atproto-client-attestation+jwt";

/// Lifetime of the minted attestation in seconds (spec allows <=300; we use 120).
const ATTESTATION_TTL_SECS: u64 = 120;

/// Mint a client attestation JWT for the given space host audience.
///
/// Builds an ES256 (or matching ECDSA) JWS over `signing_key` (the AppView OAuth
/// private key) with header `typ=atproto-client-attestation+jwt` and `kid` set
/// to the corresponding public key DID, and claims `iss == sub == client_id`,
/// `aud == <space_did>#atproto_space_host`, `iat`, `exp = iat + 120`, fresh
/// `jti`.
pub fn mint_client_attestation(
    signing_key: &KeyData,
    client_id: &str,
    space_did: &str,
) -> AppResult<String> {
    // Derive header (alg from key type, kid = public key DID) and override typ.
    let mut header: Header = Header::try_from(signing_key.clone())
        .map_err(|e| AppError::Space(format!("attestation header: {e}")))?;
    // Ensure kid is the public key DID even if the supplied key was already public.
    let public_key =
        to_public(signing_key).map_err(|e| AppError::Space(format!("attestation kid: {e}")))?;
    header.key_id = Some(public_key.to_string());
    header.type_ = Some(TYP_CLIENT_ATTESTATION.to_string());

    let iat = now_secs();
    let claims = Claims::new(JoseClaims {
        issuer: Some(client_id.to_string()),
        subject: Some(client_id.to_string()),
        audience: Some(space_host_audience(space_did)),
        issued_at: Some(iat),
        expiration: Some(iat + ATTESTATION_TTL_SECS),
        json_web_token_id: Some(random_jti()),
        ..JoseClaims::default()
    });

    mint(signing_key, &header, &claims)
        .map_err(|e| AppError::Space(format!("attestation mint: {e}")))
}

/// Current time as seconds since the Unix epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a random UUIDv4-shaped nonce for the `jti` claim.
fn random_jti() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
