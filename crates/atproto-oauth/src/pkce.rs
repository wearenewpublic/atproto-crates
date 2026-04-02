//! PKCE (Proof Key for Code Exchange) implementation.
//!
//! RFC 7636 compliant PKCE for OAuth 2.0 authorization code flow
//! security with SHA256 challenge generation.
//! 2. **Authorize**: Send the code challenge with the authorization request
//! 3. **Exchange**: Send the original code verifier when exchanging the authorization code for tokens
//!
//! ## Example
//!
//! ```rust
//! use atproto_oauth::pkce;
//!
//! // Generate PKCE parameters
//! let (code_verifier, code_challenge) = pkce::generate();
//!
//! // Use code_challenge in authorization URL
//! println!("Authorization URL: https://auth.example.com/oauth/authorize?code_challenge={}", code_challenge);
//!
//! // Later, use code_verifier when exchanging authorization code for tokens
//! println!("Token exchange: code_verifier={}", code_verifier);
//! ```
//!
//! ## Security
//!
//! - Code verifiers are generated using cryptographically secure random number generation
//! - Challenges use SHA256 hashing with base64url encoding (without padding)
//! - Implements the S256 code challenge method as specified in RFC 7636

use base64::{Engine as _, engine::general_purpose};
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};

/// Generates a PKCE code verifier and code challenge pair.
///
/// Creates a cryptographically random code verifier (100 characters) and computes
/// its corresponding SHA256 code challenge. This follows the PKCE specification
/// in RFC 7636 using the S256 code challenge method.
///
/// # Returns
///
/// A tuple containing:
/// - `String`: The code verifier (random alphanumeric string)
/// - `String`: The code challenge (base64url-encoded SHA256 hash of verifier)
///
/// # Example
///
/// ```rust
/// use atproto_oauth::pkce;
///
/// let (verifier, challenge) = pkce::generate();
/// assert_eq!(verifier.len(), 100);
/// assert!(!challenge.is_empty());
/// ```
pub fn generate() -> (String, String) {
    let token: String = Alphanumeric.sample_string(&mut rand::rng(), 100);
    (token.clone(), challenge(&token))
}

/// Creates a PKCE code challenge from a code verifier.
///
/// Computes the SHA256 hash of the provided code verifier and encodes it using
/// base64url encoding without padding. This implements the S256 code challenge
/// method as specified in RFC 7636 section 4.2.
///
/// # Arguments
///
/// * `token` - The code verifier string to hash
///
/// # Returns
///
/// The base64url-encoded SHA256 hash of the code verifier
///
/// # Example
///
/// ```rust
/// use atproto_oauth::pkce;
///
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let challenge = pkce::challenge(verifier);
/// assert!(!challenge.is_empty());
/// assert!(!challenge.contains('='));  // No padding in base64url
/// ```
pub fn challenge(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_returns_correct_verifier_length() {
        let (verifier, _) = generate();
        assert_eq!(
            verifier.len(),
            100,
            "Code verifier should be exactly 100 characters"
        );
    }

    #[test]
    fn test_generate_verifier_is_alphanumeric() {
        let (verifier, _) = generate();
        assert!(
            verifier.chars().all(|c| c.is_alphanumeric()),
            "Code verifier should contain only alphanumeric characters"
        );
    }

    #[test]
    fn test_generate_challenge_is_not_empty() {
        let (_, challenge) = generate();
        assert!(!challenge.is_empty(), "Code challenge should not be empty");
    }

    #[test]
    fn test_generate_challenge_is_base64url_without_padding() {
        let (_, challenge) = generate();

        // Should not contain padding characters
        assert!(
            !challenge.contains('='),
            "Code challenge should not contain padding (=) characters"
        );

        // Should only contain valid base64url characters
        assert!(
            challenge
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Code challenge should only contain base64url characters (A-Z, a-z, 0-9, -, _)"
        );
    }

    #[test]
    fn test_generate_produces_unique_values() {
        let mut verifiers = HashSet::new();
        let mut challenges = HashSet::new();

        // Generate multiple PKCE pairs and ensure they're all unique
        for _ in 0..10 {
            let (verifier, challenge) = generate();
            assert!(
                verifiers.insert(verifier.clone()),
                "Code verifiers should be unique"
            );
            assert!(
                challenges.insert(challenge.clone()),
                "Code challenges should be unique"
            );
        }
    }

    #[test]
    fn test_generate_verifier_and_challenge_are_related() {
        let (verifier, challenge_result) = generate();
        let computed_challenge = challenge(&verifier);
        assert_eq!(
            challenge_result, computed_challenge,
            "Generated challenge should match computed challenge from verifier"
        );
    }

    #[test]
    fn test_challenge_with_known_input() {
        // Test vector from RFC 7636 example
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let actual_challenge = challenge(verifier);
        assert_eq!(
            actual_challenge, expected_challenge,
            "Challenge should match RFC 7636 test vector"
        );
    }

    #[test]
    fn test_challenge_deterministic() {
        let verifier = "test_verifier_123";
        let challenge1 = challenge(verifier);
        let challenge2 = challenge(verifier);

        assert_eq!(
            challenge1, challenge2,
            "Challenge function should be deterministic"
        );
    }

    #[test]
    fn test_challenge_different_inputs_produce_different_outputs() {
        let challenge1 = challenge("verifier1");
        let challenge2 = challenge("verifier2");

        assert_ne!(
            challenge1, challenge2,
            "Different verifiers should produce different challenges"
        );
    }

    #[test]
    fn test_challenge_empty_string() {
        let result = challenge("");
        assert!(
            !result.is_empty(),
            "Challenge of empty string should not be empty"
        );
        assert!(
            !result.contains('='),
            "Challenge should not contain padding"
        );
    }

    #[test]
    fn test_challenge_unicode_input() {
        let verifier = "test_émojis_🔐_unicode";
        let result = challenge(verifier);

        assert!(
            !result.is_empty(),
            "Challenge should work with unicode input"
        );
        assert!(
            !result.contains('='),
            "Challenge should not contain padding"
        );
    }

    #[test]
    fn test_challenge_very_long_input() {
        let verifier = "a".repeat(1000);
        let result = challenge(&verifier);

        assert!(
            !result.is_empty(),
            "Challenge should work with very long input"
        );
        assert!(
            !result.contains('='),
            "Challenge should not contain padding"
        );
    }

    #[test]
    fn test_challenge_output_length_consistency() {
        // SHA256 produces 32 bytes, base64url encoding should produce consistent length
        let expected_length = 43; // 32 bytes -> 43 characters in base64url without padding

        let long_string = "a".repeat(100);
        let test_inputs = vec![
            "",
            "short",
            &long_string,
            "unicode_🔐_test",
            "special!@#$%^&*()characters",
        ];

        for input in test_inputs {
            let result = challenge(input);
            assert_eq!(
                result.len(),
                expected_length,
                "Challenge output length should be consistent for input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_rfc7636_compliance() {
        // Test that our implementation follows RFC 7636 requirements
        let (verifier, challenge_result) = generate();

        // RFC 7636 Section 4.1: code_verifier should be 43-128 characters
        // Our implementation uses 100 characters
        assert!(
            verifier.len() >= 43 && verifier.len() <= 128,
            "Code verifier length should comply with RFC 7636 (43-128 characters)"
        );

        // RFC 7636 Section 4.1: code_verifier should use [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        // Our implementation uses only alphanumeric (subset of allowed characters)
        assert!(
            verifier.chars().all(|c| {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".contains(c)
            }),
            "Code verifier should use RFC 7636 compliant character set"
        );

        // RFC 7636 Section 4.2: code_challenge should be base64url-encoded SHA256
        // Should be 43 characters (32 bytes SHA256 -> 43 chars base64url without padding)
        assert_eq!(
            challenge_result.len(),
            43,
            "Code challenge should be 43 characters (SHA256 base64url encoded)"
        );
    }

    #[test]
    fn test_pkce_flow_simulation() {
        // Simulate a complete PKCE flow

        // Step 1: Client generates PKCE parameters
        let (code_verifier, code_challenge) = generate();

        // Step 2: Client sends code_challenge to authorization server
        // (In real implementation, this would be in authorization URL)
        assert!(!code_challenge.is_empty());

        // Step 3: Authorization server validates challenge format
        assert!(
            !code_challenge.contains('='),
            "Challenge should not have padding"
        );
        assert_eq!(
            code_challenge.len(),
            43,
            "Challenge should be correct length"
        );

        // Step 4: Client later sends code_verifier to token endpoint
        // Server verifies that SHA256(code_verifier) == code_challenge
        let server_computed_challenge = challenge(&code_verifier);
        assert_eq!(
            code_challenge, server_computed_challenge,
            "Server should be able to verify PKCE parameters"
        );
    }
}
