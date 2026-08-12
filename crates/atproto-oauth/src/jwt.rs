//! JSON Web Token (JWT) minting and verification.
//!
//! Create and verify JWTs with JOSE standard claims supporting
//! ES256, ES384, and ES256K signature algorithms.
//!
//! [`crate::jwt::verify`] is strict by default: a token without an `exp` claim is
//! rejected, because such a token would otherwise be valid forever. Issuers that bound
//! token lifetime by some other mechanism can opt out with
//! [`crate::jwt::verify_with_config`] and
//! [`crate::jwt::JwtValidationConfig::allow_missing_expiration`].

use anyhow::Result;
use atproto_identity::jwk::Jwk;
use atproto_identity::key::{
    KeyData, KeyType, SignaturePolicy, sign, to_public, validate_with_policy,
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::encoding::ToBase64;
use crate::errors::JWTError;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// JWT header containing algorithm and key metadata.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Header {
    /// Algorithm used for signing (e.g., "ES256", "ES384", "ES256K").
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// Key identifier for the signing key.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Token type, typically "JWT".
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,

    /// Embedded JSON Web Key.
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub json_web_key: Option<Jwk>,
}

impl TryFrom<KeyData> for Header {
    type Error = anyhow::Error;

    fn try_from(value: KeyData) -> std::result::Result<Self, Self::Error> {
        let algorithm = match value.key_type() {
            KeyType::P256Public => Some("ES256".to_string()),
            KeyType::P256Private => Some("ES256".to_string()),
            KeyType::P384Public => Some("ES384".to_string()),
            KeyType::P384Private => Some("ES384".to_string()),
            KeyType::K256Public => Some("ES256K".to_string()),
            KeyType::K256Private => Some("ES256K".to_string()),
            KeyType::Ed25519Public | KeyType::Ed25519Private => Some("EdDSA".to_string()),
        };

        let public_key = to_public(&value)?;
        let key_id = Some(public_key.to_string());

        Ok(Self {
            algorithm,
            key_id,
            type_: None,
            json_web_key: None,
        })
    }
}

/// JWT claims combining standard JOSE claims with custom private claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    /// Standard JOSE claims.
    #[serde(flatten)]
    pub jose: JoseClaims,
    /// Custom private claims.
    #[serde(flatten)]
    pub private: BTreeMap<String, serde_json::Value>,
}

impl Claims {
    /// Create new Claims with the given JOSE claims.
    pub fn new(jose: JoseClaims) -> Self {
        Claims {
            jose,
            private: BTreeMap::new(),
        }
    }
}

/// Type alias for timestamp values representing seconds since Unix epoch.
pub type SecondsSinceEpoch = u64;

/// Standard JOSE claims for JWT tokens.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JoseClaims {
    /// Issuer of the token.
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Subject of the token.
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    /// Intended audience for the token.
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    /// Expiration time after which the token is invalid.
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<SecondsSinceEpoch>,

    /// Time before which the token is not valid.
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<SecondsSinceEpoch>,

    /// Time at which the token was issued.
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<SecondsSinceEpoch>,

    /// Unique identifier for the token.
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub json_web_token_id: Option<String>,

    /// HTTP method for request binding.
    #[serde(rename = "htm", skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,

    /// HTTP URI for request binding.
    #[serde(rename = "htu", skip_serializing_if = "Option::is_none")]
    pub http_uri: Option<String>,

    /// Nonce value for replay protection.
    #[serde(rename = "nonce", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Authorization token hash.
    #[serde(rename = "ath", skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

/// Policy applied by [`verify_with_config`] when validating JWT time claims.
///
/// [`JwtValidationConfig::default`] is the safe-by-default policy used by
/// [`verify`]: an `exp` claim is required, no clock skew is tolerated on `exp`
/// or `nbf`, and an `iat` more than 60 seconds in the future is rejected.
#[derive(Debug, Clone)]
pub struct JwtValidationConfig {
    /// Reject tokens with no `exp` claim. Defaults to `true`.
    pub require_expiration: bool,

    /// Reject tokens with no `iat` claim. Defaults to `false`.
    pub require_issued_at: bool,

    /// Skew allowance in seconds applied to `exp` and `nbf`. Defaults to `0`.
    pub clock_skew_tolerance_seconds: SecondsSinceEpoch,

    /// Skew allowance in seconds for an `iat` in the future. Defaults to `60`.
    pub future_issued_at_tolerance_seconds: SecondsSinceEpoch,

    /// Reject tokens whose `iat` is further ahead than the future tolerance.
    /// Defaults to `true`.
    pub reject_future_issued_at: bool,

    /// Maximum age in seconds computed from `iat`. `None` disables the check.
    /// Defaults to `None`.
    pub max_age_seconds: Option<SecondsSinceEpoch>,

    /// Current time in seconds since the Unix epoch. `None` uses the system
    /// clock. Intended for deterministic tests.
    pub now: Option<SecondsSinceEpoch>,
}

impl Default for JwtValidationConfig {
    fn default() -> Self {
        Self {
            require_expiration: true,
            require_issued_at: false,
            clock_skew_tolerance_seconds: 0,
            future_issued_at_tolerance_seconds: 60,
            reject_future_issued_at: true,
            max_age_seconds: None,
            now: None,
        }
    }
}

impl JwtValidationConfig {
    /// Policy that permits tokens with no `exp` claim.
    ///
    /// Only appropriate for issuers whose tokens are bounded by some other
    /// mechanism; a token with no expiration is otherwise valid forever.
    pub fn allow_missing_expiration() -> Self {
        Self {
            require_expiration: false,
            ..Default::default()
        }
    }
}

/// Create and sign a new JWT token.
pub fn mint(key_data: &KeyData, header: &Header, claims: &Claims) -> Result<String> {
    let header = header.to_base64()?;
    let claims = claims.to_base64()?;
    let content = format!("{}.{}", header, claims);

    let signature = sign(key_data, content.as_bytes())?;

    Ok(format!(
        "{}.{}",
        content,
        general_purpose::URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Verify a JWT token and extract its claims.
///
/// Applies [`JwtValidationConfig::default`], which requires an `exp` claim: a
/// token that omits `exp` is rejected with
/// [`crate::errors::JWTError::MissingClaim`] rather than treated as never expiring.
pub fn verify(token: &str, key_data: &KeyData) -> Result<Claims> {
    verify_with_config(token, key_data, &JwtValidationConfig::default())
}

/// Verify a JWT token against an explicit validation policy.
///
/// The signature is always checked before any time claim, so an invalid
/// signature can never be reported as a mere timestamp problem.
///
/// # Arguments
/// * `token` - The encoded JWT to verify
/// * `key_data` - The key to verify the signature against
/// * `config` - The time-claim policy to apply
///
/// # Errors
/// Returns a [`JWTError`] for malformed input, a failed signature check, or any
/// time claim that violates `config`.
pub fn verify_with_config(
    token: &str,
    key_data: &KeyData,
    config: &JwtValidationConfig,
) -> Result<Claims> {
    // Split token into its parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JWTError::InvalidFormat.into());
    }

    let encoded_header = parts[0];
    let encoded_claims = parts[1];
    let encoded_signature = parts[2];

    // Decode header
    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| JWTError::InvalidHeader)?;

    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| JWTError::InvalidHeader)?;

    match (header.algorithm.as_deref(), key_data.key_type()) {
        (Some("ES256K"), KeyType::K256Private) | (Some("ES256K"), KeyType::K256Public) => {}
        (Some("ES256"), KeyType::P256Private) | (Some("ES256"), KeyType::P256Public) => {}
        (Some("ES384"), KeyType::P384Private) | (Some("ES384"), KeyType::P384Public) => {}
        _ => {
            return Err(JWTError::UnsupportedAlgorithm {
                algorithm: header
                    .algorithm
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                key_type: format!("{}", key_data.key_type()),
            }
            .into());
        }
    }

    // Decode claims
    let claims_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_claims)
        .map_err(|_| JWTError::InvalidClaims)?;

    let claims: Claims =
        serde_json::from_slice(&claims_bytes).map_err(|_| JWTError::InvalidClaims)?;

    // Decode signature
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| JWTError::InvalidSignature)?;

    let content = format!("{}.{}", encoded_header, encoded_claims);

    // JWS, not an AT Protocol signature: RFC 7515 defines ES256 as the raw
    // `r || s` pair with no low-S constraint, and WebCrypto does not normalise
    // `s`. Enforcing low-S here rejected roughly half of all proofs from
    // conforming clients, at random.
    validate_with_policy(
        key_data,
        &signature_bytes,
        content.as_bytes(),
        SignaturePolicy::AnyS,
    )
    .map_err(|_| JWTError::SignatureVerificationFailed)?;

    // Get current timestamp for validation
    let now = match config.now {
        Some(value) => value,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JWTError::SystemTimeError)?
            .as_secs(),
    };

    // Validate expiration time. A token with no `exp` never expires, so it is
    // rejected unless the caller explicitly opted out.
    match claims.jose.expiration {
        Some(exp) if now >= exp.saturating_add(config.clock_skew_tolerance_seconds) => {
            return Err(JWTError::TokenExpired.into());
        }
        None if config.require_expiration => {
            return Err(JWTError::MissingClaim {
                claim: "exp".to_string(),
            }
            .into());
        }
        _ => {}
    }

    // Validate not-before time if present
    if let Some(nbf) = claims.jose.not_before
        && now.saturating_add(config.clock_skew_tolerance_seconds) < nbf
    {
        return Err(JWTError::TokenNotValidYet.into());
    }

    // Validate issued-at. All arithmetic saturates because these claims are
    // attacker-controlled and would otherwise overflow near u64::MAX.
    match claims.jose.issued_at {
        Some(issued_at) => {
            if config.reject_future_issued_at
                && issued_at > now.saturating_add(config.future_issued_at_tolerance_seconds)
            {
                return Err(JWTError::InvalidTimestamp {
                    reason: format!(
                        "issued at {issued_at} is in the future; current time is {now}"
                    ),
                }
                .into());
            }

            if let Some(max_age) = config.max_age_seconds
                && now
                    > issued_at
                        .saturating_add(max_age)
                        .saturating_add(config.clock_skew_tolerance_seconds)
            {
                return Err(JWTError::InvalidTimestamp {
                    reason: format!(
                        "token too old: issued at {issued_at}, max age is {max_age} seconds"
                    ),
                }
                .into());
            }
        }
        None if config.require_issued_at => {
            return Err(JWTError::MissingClaim {
                claim: "iat".to_string(),
            }
            .into());
        }
        None => {}
    }

    // Return validated claims
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::{KeyType, generate_key, identify_key, to_public};

    #[test]
    fn test_header_from_p256_private_key() -> Result<()> {
        let key_data = generate_key(KeyType::P256Private)?;
        let header: Header = key_data.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES256".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let public_key = to_public(&key_data)?;
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    #[test]
    fn test_header_from_p256_public_key() -> Result<()> {
        let private_key = generate_key(KeyType::P256Private)?;
        let public_key = to_public(&private_key)?;
        let header: Header = public_key.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES256".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    #[test]
    fn test_header_from_k256_private_key() -> Result<()> {
        let key_data = generate_key(KeyType::K256Private)?;
        let header: Header = key_data.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES256K".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let public_key = to_public(&key_data)?;
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    #[test]
    fn test_header_from_k256_public_key() -> Result<()> {
        let private_key = generate_key(KeyType::K256Private)?;
        let public_key = to_public(&private_key)?;
        let header: Header = public_key.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES256K".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    #[test]
    fn test_header_consistency_private_vs_public_key() -> Result<()> {
        // Test that private key and its derived public key produce headers with same key_id
        let p256_private = generate_key(KeyType::P256Private)?;
        let p256_public = to_public(&p256_private)?;

        let header_from_private: Header = p256_private.try_into()?;
        let header_from_public: Header = p256_public.try_into()?;

        assert_eq!(header_from_private.algorithm, header_from_public.algorithm);
        assert_eq!(header_from_private.key_id, header_from_public.key_id);
        assert_eq!(header_from_private.type_, header_from_public.type_);
        assert_eq!(
            header_from_private.json_web_key,
            header_from_public.json_web_key
        );

        // Test with K256 as well
        let k256_private = generate_key(KeyType::K256Private)?;
        let k256_public = to_public(&k256_private)?;

        let k256_header_from_private: Header = k256_private.try_into()?;
        let k256_header_from_public: Header = k256_public.try_into()?;

        assert_eq!(
            k256_header_from_private.algorithm,
            k256_header_from_public.algorithm
        );
        assert_eq!(
            k256_header_from_private.key_id,
            k256_header_from_public.key_id
        );
        assert_eq!(
            k256_header_from_private.type_,
            k256_header_from_public.type_
        );
        assert_eq!(
            k256_header_from_private.json_web_key,
            k256_header_from_public.json_web_key
        );

        Ok(())
    }

    #[test]
    fn test_header_from_existing_test_keys() -> Result<()> {
        // Test with known keys from the identity crate test suite
        let p256_private_key = "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o";
        let p256_public_key = "did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2";
        let k256_private_key = "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt";
        let k256_public_key = "did:key:zQ3shNzMp4oaaQ1gQRzCxMGXFrSW3NEM1M9T6KCY9eA7HhyEA";

        // Parse the keys
        let parsed_p256_private = identify_key(p256_private_key)?;
        let parsed_p256_public = identify_key(p256_public_key)?;
        let parsed_k256_private = identify_key(k256_private_key)?;
        let parsed_k256_public = identify_key(k256_public_key)?;

        // Derive the actual public keys from the private keys for comparison
        let derived_p256_public = to_public(&parsed_p256_private)?;
        let derived_k256_public = to_public(&parsed_k256_private)?;

        // Test P256 private key
        let p256_private_header: Header = parsed_p256_private.try_into()?;
        assert_eq!(p256_private_header.algorithm, Some("ES256".to_string()));
        let expected_p256_key_id = format!("{}", derived_p256_public);
        assert_eq!(p256_private_header.key_id, Some(expected_p256_key_id));

        // Test P256 public key (standalone)
        let p256_public_header: Header = parsed_p256_public.try_into()?;
        assert_eq!(p256_public_header.algorithm, Some("ES256".to_string()));
        assert_eq!(p256_public_header.key_id, Some(p256_public_key.to_string()));

        // Test K256 private key
        let k256_private_header: Header = parsed_k256_private.try_into()?;
        assert_eq!(k256_private_header.algorithm, Some("ES256K".to_string()));
        let expected_k256_key_id = format!("{}", derived_k256_public);
        assert_eq!(k256_private_header.key_id, Some(expected_k256_key_id));

        // Test K256 public key (standalone)
        let k256_public_header: Header = parsed_k256_public.try_into()?;
        assert_eq!(k256_public_header.algorithm, Some("ES256K".to_string()));
        assert_eq!(k256_public_header.key_id, Some(k256_public_key.to_string()));

        // Test that derived public keys produce consistent headers
        let derived_p256_public_header: Header = derived_p256_public.try_into()?;
        let derived_k256_public_header: Header = derived_k256_public.try_into()?;

        assert_eq!(p256_private_header, derived_p256_public_header);
        assert_eq!(k256_private_header, derived_k256_public_header);

        Ok(())
    }

    #[test]
    fn test_header_multiple_conversions_same_key() -> Result<()> {
        // Test that multiple conversions of the same key produce identical headers
        let key_data = generate_key(KeyType::P256Private)?;

        let header1: Header = key_data.clone().try_into()?;
        let header2: Header = key_data.try_into()?;

        assert_eq!(header1, header2);

        Ok(())
    }

    #[test]
    fn test_header_different_keys_different_headers() -> Result<()> {
        // Test that different keys produce different headers
        let p256_key = generate_key(KeyType::P256Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        let p256_header: Header = p256_key.try_into()?;
        let k256_header: Header = k256_key.try_into()?;

        // Algorithm should be different
        assert_ne!(p256_header.algorithm, k256_header.algorithm);
        assert_eq!(p256_header.algorithm, Some("ES256".to_string()));
        assert_eq!(k256_header.algorithm, Some("ES256K".to_string()));

        // Key IDs should be different (different public keys)
        assert_ne!(p256_header.key_id, k256_header.key_id);

        Ok(())
    }

    #[test]
    fn test_header_from_invalid_key_data() {
        // Test with invalid key data that would cause to_public() to fail
        let invalid_key_data = KeyData::new(KeyType::P256Private, vec![0u8; 10]); // Too short

        let result: Result<Header> = invalid_key_data.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_header_serialization_deserialization() -> Result<()> {
        // Test that Header can be serialized and deserialized correctly
        let key_data = generate_key(KeyType::P256Private)?;
        let header: Header = key_data.try_into()?;

        // Serialize to JSON
        let json = serde_json::to_string(&header)?;

        // Deserialize back
        let deserialized_header: Header = serde_json::from_str(&json)?;

        assert_eq!(header, deserialized_header);

        Ok(())
    }

    #[test]
    fn test_header_json_field_names() -> Result<()> {
        // Test that Header uses correct JSON field names (alg, kid, typ, jwk)
        let key_data = generate_key(KeyType::P256Private)?;
        let header: Header = key_data.try_into()?;

        let json = serde_json::to_string(&header)?;
        let json_value: serde_json::Value = serde_json::from_str(&json)?;

        // Check that the correct field names are used
        assert!(json_value.get("alg").is_some());
        assert!(json_value.get("kid").is_some());
        assert!(json_value.get("typ").is_none()); // Should be None and thus omitted
        assert!(json_value.get("jwk").is_none()); // Should be None and thus omitted

        // Verify values
        assert_eq!(json_value["alg"], "ES256");
        assert!(json_value["kid"].is_string());

        Ok(())
    }

    #[test]
    fn test_header_complete_workflow() -> Result<()> {
        println!("\n=== Header TryFrom<KeyData> Test Workflow ===");

        // Generate keys for all curves
        println!("1. Generating test keys...");
        let p256_private = generate_key(KeyType::P256Private)?;
        let p384_private = generate_key(KeyType::P384Private)?;
        let k256_private = generate_key(KeyType::K256Private)?;
        let p256_public = to_public(&p256_private)?;
        let p384_public = to_public(&p384_private)?;
        let k256_public = to_public(&k256_private)?;

        // Convert to headers
        println!("2. Converting KeyData to Headers...");
        let p256_private_header: Header = p256_private.try_into()?;
        let p256_public_header: Header = p256_public.try_into()?;
        let p384_private_header: Header = p384_private.try_into()?;
        let p384_public_header: Header = p384_public.try_into()?;
        let k256_private_header: Header = k256_private.try_into()?;
        let k256_public_header: Header = k256_public.try_into()?;

        // Verify algorithms
        println!("3. Verifying algorithms...");
        assert_eq!(p256_private_header.algorithm, Some("ES256".to_string()));
        assert_eq!(p256_public_header.algorithm, Some("ES256".to_string()));
        assert_eq!(p384_private_header.algorithm, Some("ES384".to_string()));
        assert_eq!(p384_public_header.algorithm, Some("ES384".to_string()));
        assert_eq!(k256_private_header.algorithm, Some("ES256K".to_string()));
        assert_eq!(k256_public_header.algorithm, Some("ES256K".to_string()));
        println!("   ✓ P-256 keys → ES256");
        println!("   ✓ P-384 keys → ES384");
        println!("   ✓ K-256 keys → ES256K");

        // Verify key IDs match between private and public
        println!("4. Verifying key ID consistency...");
        assert_eq!(p256_private_header.key_id, p256_public_header.key_id);
        assert_eq!(p384_private_header.key_id, p384_public_header.key_id);
        assert_eq!(k256_private_header.key_id, k256_public_header.key_id);
        println!("   ✓ Private and public keys produce same key_id");

        // Verify other fields are None
        println!("5. Verifying optional fields are None...");
        for header in [
            &p256_private_header,
            &p256_public_header,
            &p384_private_header,
            &p384_public_header,
            &k256_private_header,
            &k256_public_header,
        ] {
            assert_eq!(header.type_, None);
            assert_eq!(header.json_web_key, None);
        }
        println!("   ✓ type_ and json_web_key fields are None");

        // Test JSON serialization
        println!("6. Testing JSON serialization...");
        let json = serde_json::to_string(&p384_private_header)?;
        let parsed: Header = serde_json::from_str(&json)?;
        assert_eq!(p384_private_header, parsed);
        println!("   ✓ Headers serialize/deserialize correctly");

        println!("=== All Header conversion tests passed! ===\n");

        Ok(())
    }

    #[test]
    fn test_header_from_p384_private_key() -> Result<()> {
        let key_data = generate_key(KeyType::P384Private)?;
        let header: Header = key_data.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES384".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let public_key = to_public(&key_data)?;
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    #[test]
    fn test_header_from_p384_public_key() -> Result<()> {
        let private_key = generate_key(KeyType::P384Private)?;
        let public_key = to_public(&private_key)?;
        let header: Header = public_key.clone().try_into()?;

        assert_eq!(header.algorithm, Some("ES384".to_string()));
        assert!(header.key_id.is_some());
        assert_eq!(header.type_, None);
        assert_eq!(header.json_web_key, None);

        // Verify key_id contains the public key DID
        let expected_key_id = format!("{}", public_key);
        assert_eq!(header.key_id, Some(expected_key_id));

        Ok(())
    }

    /// Fixed instant used so the time-claim tests never depend on the wall clock.
    const FIXED_NOW: SecondsSinceEpoch = 1_700_000_000;

    fn signing_key() -> KeyData {
        generate_key(KeyType::P256Private).expect("P-256 key generation succeeds")
    }

    fn mint_with(key_data: &KeyData, jose: JoseClaims) -> String {
        let header: Header = key_data.clone().try_into().expect("header from key");
        mint(key_data, &header, &Claims::new(jose)).expect("token mints")
    }

    fn fixed_now_config() -> JwtValidationConfig {
        JwtValidationConfig {
            now: Some(FIXED_NOW),
            ..Default::default()
        }
    }

    #[test]
    fn test_verify_rejects_token_without_expiration() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issuer: Some("did:plc:attacker".to_string()),
                issued_at: Some(FIXED_NOW),
                expiration: None,
                ..Default::default()
            },
        );

        let err = verify_with_config(&token, &key_data, &fixed_now_config())
            .expect_err("a token with no exp never expires and must be rejected");

        let message = err.to_string();
        assert!(message.contains("error-atproto-oauth-jwt-12"), "{message}");
        assert!(message.contains("exp"), "{message}");
    }

    #[test]
    fn test_verify_accepts_token_with_future_expiration() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issuer: Some("did:plc:legitimate".to_string()),
                issued_at: Some(FIXED_NOW),
                expiration: Some(FIXED_NOW + 300),
                ..Default::default()
            },
        );

        let claims = verify_with_config(&token, &key_data, &fixed_now_config())
            .expect("an unexpired token verifies");

        assert_eq!(claims.jose.issuer.as_deref(), Some("did:plc:legitimate"));
        assert_eq!(claims.jose.expiration, Some(FIXED_NOW + 300));
    }

    #[test]
    fn test_verify_rejects_expired_token() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(FIXED_NOW - 600),
                expiration: Some(FIXED_NOW - 1),
                ..Default::default()
            },
        );

        let err = verify_with_config(&token, &key_data, &fixed_now_config())
            .expect_err("an expired token is rejected");

        assert!(
            err.to_string().contains("error-atproto-oauth-jwt-7"),
            "{err}"
        );
    }

    #[test]
    fn test_verify_with_config_allows_missing_expiration_when_opted_out() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issuer: Some("did:plc:bounded-elsewhere".to_string()),
                issued_at: Some(FIXED_NOW),
                expiration: None,
                ..Default::default()
            },
        );

        let config = JwtValidationConfig {
            now: Some(FIXED_NOW),
            ..JwtValidationConfig::allow_missing_expiration()
        };

        let claims =
            verify_with_config(&token, &key_data, &config).expect("the opt-out permits no exp");
        assert_eq!(
            claims.jose.issuer.as_deref(),
            Some("did:plc:bounded-elsewhere")
        );
    }

    #[test]
    fn test_verify_rejects_future_issued_at() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(FIXED_NOW + 3600),
                expiration: Some(FIXED_NOW + 7200),
                ..Default::default()
            },
        );

        let err = verify_with_config(&token, &key_data, &fixed_now_config())
            .expect_err("an iat far in the future is rejected");

        let message = err.to_string();
        assert!(message.contains("error-atproto-oauth-jwt-18"), "{message}");
        assert!(message.contains("in the future"), "{message}");
    }

    #[test]
    fn test_verify_with_config_max_age() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(FIXED_NOW - 3600),
                expiration: Some(FIXED_NOW + 3600),
                ..Default::default()
            },
        );

        let err = verify_with_config(
            &token,
            &key_data,
            &JwtValidationConfig {
                max_age_seconds: Some(60),
                ..fixed_now_config()
            },
        )
        .expect_err("a token older than max_age is rejected");

        let message = err.to_string();
        assert!(message.contains("error-atproto-oauth-jwt-18"), "{message}");
        assert!(message.contains("too old"), "{message}");

        verify_with_config(&token, &key_data, &fixed_now_config())
            .expect("the same token passes when max_age is disabled");
    }

    #[test]
    fn test_verify_rejects_not_yet_valid_token() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(FIXED_NOW),
                not_before: Some(FIXED_NOW + 300),
                expiration: Some(FIXED_NOW + 600),
                ..Default::default()
            },
        );

        let err = verify_with_config(&token, &key_data, &fixed_now_config())
            .expect_err("a not-yet-valid token is rejected");

        assert!(
            err.to_string().contains("error-atproto-oauth-jwt-8"),
            "{err}"
        );
    }

    #[test]
    fn test_verify_saturating_timestamp_arithmetic() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(SecondsSinceEpoch::MAX),
                not_before: Some(SecondsSinceEpoch::MAX),
                expiration: Some(SecondsSinceEpoch::MAX),
                ..Default::default()
            },
        );

        let config = JwtValidationConfig {
            clock_skew_tolerance_seconds: 30,
            max_age_seconds: Some(60),
            ..fixed_now_config()
        };

        // Must return a typed error rather than overflow-panic in a debug build.
        let err = verify_with_config(&token, &key_data, &config)
            .expect_err("u64::MAX timestamps are rejected, not panicked on");
        assert!(
            err.to_string().contains("error-atproto-oauth-jwt-8"),
            "{err}"
        );
    }

    #[test]
    fn test_verify_with_config_deterministic_now() {
        let key_data = signing_key();
        let token = mint_with(
            &key_data,
            JoseClaims {
                issued_at: Some(FIXED_NOW),
                expiration: Some(FIXED_NOW + 100),
                ..Default::default()
            },
        );

        verify_with_config(&token, &key_data, &fixed_now_config())
            .expect("valid at the fixed instant");

        let err = verify_with_config(
            &token,
            &key_data,
            &JwtValidationConfig {
                now: Some(FIXED_NOW + 101),
                ..Default::default()
            },
        )
        .expect_err("expired once the fixed instant moves past exp");
        assert!(
            err.to_string().contains("error-atproto-oauth-jwt-7"),
            "{err}"
        );
    }
}
