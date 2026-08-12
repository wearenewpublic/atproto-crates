//! ECDSA signature normalization.
//!
//! This module handles signature normalization to the low-S form required by
//! the AT Protocol attestation specification, preventing signature malleability attacks.

use crate::errors::AttestationError;
use atproto_identity::key::KeyType;
use k256::ecdsa::Signature as K256Signature;
use p256::ecdsa::Signature as P256Signature;

/// Normalize raw signature bytes to the required low-S form.
///
/// This helper ensures signatures produced by signing APIs comply with the
/// specification requirements before embedding them in attestation objects.
///
/// # Arguments
///
/// * `signature` - The raw signature bytes to normalize
/// * `key_type` - The type of key used to create the signature
///
/// # Returns
///
/// The normalized signature bytes in low-S form
///
/// # Errors
///
/// Returns an error if:
/// - The signature length is invalid for the key type
/// - The key type is not supported
pub fn normalize_signature(
    signature: Vec<u8>,
    key_type: &KeyType,
) -> Result<Vec<u8>, AttestationError> {
    match key_type {
        KeyType::P256Private | KeyType::P256Public => normalize_p256(signature),
        KeyType::K256Private | KeyType::K256Public => normalize_k256(signature),
        other => Err(AttestationError::UnsupportedKeyType {
            key_type: (*other).clone(),
        }),
    }
}

/// Normalize a P-256 signature to low-S form.
fn normalize_p256(signature: Vec<u8>) -> Result<Vec<u8>, AttestationError> {
    if signature.len() != 64 {
        return Err(AttestationError::SignatureLengthInvalid {
            expected: 64,
            actual: signature.len(),
        });
    }

    let parsed = P256Signature::from_slice(&signature).map_err(|_| {
        AttestationError::SignatureLengthInvalid {
            expected: 64,
            actual: signature.len(),
        }
    })?;

    let normalized = parsed.normalize_s();

    Ok(normalized.to_vec())
}

/// Normalize a K-256 signature to low-S form.
fn normalize_k256(signature: Vec<u8>) -> Result<Vec<u8>, AttestationError> {
    if signature.len() != 64 {
        return Err(AttestationError::SignatureLengthInvalid {
            expected: 64,
            actual: signature.len(),
        });
    }

    let parsed = K256Signature::from_slice(&signature).map_err(|_| {
        AttestationError::SignatureLengthInvalid {
            expected: 64,
            actual: signature.len(),
        }
    })?;

    let normalized = parsed.normalize_s();

    Ok(normalized.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_invalid_signature_length() {
        let short_signature = vec![0u8; 32];
        let result = normalize_p256(short_signature);
        assert!(matches!(
            result,
            Err(AttestationError::SignatureLengthInvalid { expected: 64, .. })
        ));
    }
}
