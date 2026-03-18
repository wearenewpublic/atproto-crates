//! JSON Web Token (JWT) minting and verification.
//!
//! Create and verify JWTs with JOSE standard claims supporting
//! ES256, ES384, and ES256K signature algorithms.

use anyhow::Result;
use atproto_identity::key::{KeyData, KeyType, sign, to_public, validate};
use base64::{Engine as _, engine::general_purpose};
use elliptic_curve::JwkEcKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::encoding::ToBase64;
use crate::errors::JWTError;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// JWT header containing algorithm and key metadata.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
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
    pub json_web_key: Option<JwkEcKey>,
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
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
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
pub fn verify(token: &str, key_data: &KeyData) -> Result<Claims> {
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

    validate(key_data, &signature_bytes, content.as_bytes())
        .map_err(|_| JWTError::SignatureVerificationFailed)?;

    // Get current timestamp for validation
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JWTError::SystemTimeError)?
        .as_secs();

    // Validate expiration time if present
    if let Some(exp) = claims.jose.expiration
        && now >= exp
    {
        return Err(JWTError::TokenExpired.into());
    }

    // Validate not-before time if present
    if let Some(nbf) = claims.jose.not_before
        && now < nbf
    {
        return Err(JWTError::TokenNotValidYet.into());
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
}
