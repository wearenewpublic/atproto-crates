//! Cryptographic key operations for AT Protocol identity.
//!
//! Elliptic curve cryptography for P-256, P-384, and K-256 curves including
//! key identification, signature validation, and content signing.
//! - **P-384** (secp384r1/ES384): NIST standard curve, providing higher security than P-256
//! - **K-256** (secp256k1/ES256K): Bitcoin curve, widely used in blockchain applications
//!
//! # Key Operations
//!
//! - Key type identification from multibase-encoded DID key strings
//! - ECDSA signature validation for both public and private keys
//! - Content signing with private keys
//! - Cryptographic key generation for private keys
//! - Public key derivation from private keys
//! - DID key method prefix handling
//!
//! # Example
//!
//! ```rust
//! use atproto_identity::key::{identify_key, generate_key, to_public, validate, sign, KeyType, KeyData};
//! use atproto_identity::jwk::Jwk;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!   // Identify existing keys
//!   let key_data = identify_key("did:key:zQ3shNzMp4oaaQ1gQRzCxMGXFrSW3NEM1M9T6KCY9eA7HhyEA")?;
//!   assert_eq!(*key_data.key_type(), KeyType::K256Public);
//!
//!   // Generate new private keys (P-256, P-384, or K-256)
//!   let p256_key = generate_key(KeyType::P256Private)?;
//!   let p384_key = generate_key(KeyType::P384Private)?;
//!   let k256_key = generate_key(KeyType::K256Private)?;
//!
//!   // Derive public key from private key
//!   let p384_public = to_public(&p384_key)?;
//!   assert_eq!(*p384_public.key_type(), KeyType::P384Public);
//!
//!   // Sign and verify with derived keys
//!   let message = b"Hello AT Protocol!";
//!   let signature = sign(&p384_key, message)?;
//!   validate(&p384_public, &signature, message)?;
//!
//!   // Convert to JWK format (P-256 and P-384 support JWK)
//!   let p256_key_data = identify_key("did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2")?;
//!   let p256_jwk: Jwk = (&p256_key_data).try_into()?;
//!   let p384_jwk: Jwk = (&p384_key).try_into()?;
//!   Ok(())
//! }
//! ```

use anyhow::{Context, Result, anyhow};
use ecdsa::signature::Signer;
use elliptic_curve::sec1::ToSec1Point;

use crate::model::VerificationMethod;
use crate::traits::IdentityResolver;

pub use crate::traits::KeyResolver;
use std::sync::Arc;

use crate::errors::KeyError;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cryptographic key types supported for AT Protocol identity.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub enum KeyType {
    /// A p256 (P-256 / secp256r1 / ES256) public key.
    /// The multibase / multicodec prefix is 8024.
    P256Public,

    /// A p256 (P-256 / secp256r1 / ES256) private key.
    /// The multibase / multicodec prefix is 8626.
    P256Private,

    /// A p384 (P-384 / secp384r1 / ES384) public key.
    /// The multibase / multicodec prefix is 1200.
    P384Public,

    /// A p384 (P-384 / secp384r1 / ES384) private key.
    /// The multibase / multicodec prefix is 1301.
    P384Private,

    /// A k256 (K-256 / secp256k1 / ES256K) public key.
    /// The multibase / multicodec prefix is e701.
    K256Public,

    /// A k256 (K-256 / secp256k1 / ES256K) private key.
    /// The multibase / multicodec prefix is 8126.
    K256Private,

    /// An Ed25519 public key.
    /// The multibase / multicodec prefix is ed01.
    Ed25519Public,

    /// An Ed25519 private key.
    /// The multibase / multicodec prefix is 8026.
    Ed25519Private,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::P256Public => write!(f, "P256Public"),
            KeyType::P256Private => write!(f, "P256Private"),
            KeyType::P384Public => write!(f, "P384Public"),
            KeyType::P384Private => write!(f, "P384Private"),
            KeyType::K256Public => write!(f, "K256Public"),
            KeyType::K256Private => write!(f, "K256Private"),
            KeyType::Ed25519Public => write!(f, "Ed25519Public"),
            KeyType::Ed25519Private => write!(f, "Ed25519Private"),
        }
    }
}

/// A wrapper for cryptographic key data containing the key type and raw bytes.
///
/// This struct encapsulates the result of key identification and provides methods
/// for accessing the key type and bytes, as well as conversion to JWK format.
///
/// When creating variables for instances of this type, they should have the
/// suffix `key_data`. Additionally the should have the prefix `public_` or
/// `private_` to indiciate how they are used. Examples include:
/// * `public_signing_key_data`
/// * `private_dpop_key_data`
///
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct KeyData(pub KeyType, pub Vec<u8>);

impl KeyData {
    /// Creates a new KeyData instance.
    pub fn new(key_type: KeyType, bytes: Vec<u8>) -> Self {
        KeyData(key_type, bytes)
    }

    /// Returns the key type.
    pub fn key_type(&self) -> &KeyType {
        &self.0
    }

    /// Returns the raw key bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.1
    }

    /// Consumes self and returns the key type and bytes as a tuple.
    pub fn into_parts(self) -> (KeyType, Vec<u8>) {
        (self.0.clone(), self.1.clone())
    }
}

impl std::fmt::Display for KeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Get the multicodec prefix based on key type
        let prefix = match self.key_type() {
            KeyType::P256Private => [0x86, 0x26],
            KeyType::P256Public => [0x80, 0x24],
            KeyType::P384Private => [0x13, 0x01],
            KeyType::P384Public => [0x12, 0x00],
            KeyType::K256Private => [0x81, 0x26],
            KeyType::K256Public => [0xe7, 0x01],
            KeyType::Ed25519Private => [0x80, 0x26],
            KeyType::Ed25519Public => [0xed, 0x01],
        };

        // Combine prefix and key bytes
        let mut multicodec_bytes = Vec::with_capacity(2 + self.bytes().len());
        multicodec_bytes.extend_from_slice(&prefix);
        multicodec_bytes.extend_from_slice(self.bytes());

        // Encode using multibase (base58btc)
        let multibase_encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec_bytes);

        // Add DID key prefix
        write!(f, "did:key:{}", multibase_encoded)
    }
}

/// DID key method prefix.
const DID_METHOD_KEY_PREFIX: &str = "did:key:";

/// Extracts the value portion from a DID key string.
///
/// Removes the "did:key:" prefix if present, otherwise returns the original string.
pub fn did_method_key_value(key: &str) -> &str {
    match key.strip_prefix(DID_METHOD_KEY_PREFIX) {
        Some(value) => value,
        None => key,
    }
}

/// JWS `alg` header value for a [`KeyData`].
///
/// Maps each [`KeyType`] to the canonical JWS algorithm string
/// [RFC 7518 §3.4](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4)
/// the SECP256K1 ext (`ES256K`) and the EdDSA RFC 8037 (`EdDSA`).
///
/// Centralized here so JWT minters across the workspace agree on alg
/// strings without each module re-implementing the same match arm
/// (`atproto-pds::oauth::jwks`, `atproto-pds::http::service_auth_handlers`,
/// `atproto-space::credential` were all carrying a copy).
#[must_use]
pub fn jws_alg(key: &KeyData) -> &'static str {
    match key.key_type() {
        KeyType::P256Private | KeyType::P256Public => "ES256",
        KeyType::P384Private | KeyType::P384Public => "ES384",
        KeyType::K256Private | KeyType::K256Public => "ES256K",
        KeyType::Ed25519Private | KeyType::Ed25519Public => "EdDSA",
    }
}

/// Identifies the key type and extracts the key data from a multibase-encoded key.
///
/// Returns a KeyData instance containing the key type and the raw key bytes.
pub fn identify_key(key: &str) -> Result<KeyData, KeyError> {
    let stripped_key = did_method_key_value(key);
    let (_, decoded_multibase_key) =
        multibase::decode(stripped_key).map_err(|error| KeyError::DecodeError { error })?;

    if decoded_multibase_key.len() < 3 {
        return Err(KeyError::UnidentifiedKeyType);
    }

    // These values were verified using the following method:
    //
    // 1. Use goat to generate p256 and k256 keys to sample.
    //    `goat key generate -t k256`
    //
    // 2. Use `multibase` and `xxd` to view the hex output
    //    `multibase decode zQ3shj41kYrAKpgMvWFZ8L4uFhQ6P57zpiQEuvL1LWWa8sZqN | xxd`
    //
    // See also: https://github.com/bluesky-social/indigo/tree/main/cmd/goat
    // See also: https://github.com/docknetwork/multibase-cli

    match &decoded_multibase_key[..2] {
        // P-256 / secp256r1 / ES256 private key
        [0x86, 0x26] => Ok(KeyData::new(
            KeyType::P256Private,
            decoded_multibase_key[2..].to_vec(),
        )),

        // P-256 / secp256r1 / ES256 public key
        [0x80, 0x24] => Ok(KeyData::new(
            KeyType::P256Public,
            decoded_multibase_key[2..].to_vec(),
        )),

        // P-384 / secp384r1 / ES384 private key
        [0x13, 0x01] => Ok(KeyData::new(
            KeyType::P384Private,
            decoded_multibase_key[2..].to_vec(),
        )),

        // P-384 / secp384r1 / ES384 public key
        [0x12, 0x00] => Ok(KeyData::new(
            KeyType::P384Public,
            decoded_multibase_key[2..].to_vec(),
        )),

        // K-256 / secp256k1 / ES256K private key
        [0x81, 0x26] => Ok(KeyData::new(
            KeyType::K256Private,
            decoded_multibase_key[2..].to_vec(),
        )),

        // K-256 / secp256k1 / ES256K public key
        [0xe7, 0x01] => Ok(KeyData::new(
            KeyType::K256Public,
            decoded_multibase_key[2..].to_vec(),
        )),

        // Ed25519 public key
        [0xed, 0x01] => Ok(KeyData::new(
            KeyType::Ed25519Public,
            decoded_multibase_key[2..].to_vec(),
        )),

        // Ed25519 private key
        [0x80, 0x26] => Ok(KeyData::new(
            KeyType::Ed25519Private,
            decoded_multibase_key[2..].to_vec(),
        )),

        _ => Err(KeyError::InvalidMultibaseKeyType {
            prefix: decoded_multibase_key[..2].to_vec(),
        }),
    }
}

/// Refuse a signature in the non-canonical high-S form.
///
/// ECDSA signatures are malleable: for every valid `(r, s)` the pair `(r, -s)`
/// verifies just as well. AT Protocol requires the low-S form, so accepting
/// both means anyone holding a valid signature can derive a second, different
/// byte string that also verifies — and "the signature over this commit" stops
/// being a unique value, which is the property anything content-addressing or
/// deduplicating a signature depends on.
// `SignatureSize<C>: ArrayLength<u8>` is the bound `Signature::s` requires. The
// only path to `ArrayLength` from here is `elliptic_curve`'s re-export, which is
// deprecated in favour of generic-array 1.x — a migration that belongs to the
// `ecdsa` crate, not to this bound. Suppressed rather than worked around,
// because dropping the bound does not compile and duplicating the check per
// curve would be three copies of one line.
#[allow(deprecated)]
fn reject_high_s<C>(signature: &ecdsa::Signature<C>) -> Result<(), KeyError>
where
    C: ecdsa::EcdsaCurve + ecdsa::elliptic_curve::CurveArithmetic,
{
    use ecdsa::elliptic_curve::scalar::IsHigh;

    if signature.s().is_high().into() {
        return Err(KeyError::SignatureMalleable);
    }
    Ok(())
}

/// Which ECDSA signature forms a verifier will accept.
///
/// The two callers of [`validate_with_policy`] want opposite things, and
/// collapsing them is why a conforming OAuth client could not authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Reject the high-S form. AT Protocol signatures — repository commits,
    /// service auth, PLC operations — are specified as low-S, and accepting the
    /// malleable twin would let a third party alter a signature's bytes without
    /// invalidating it.
    LowSOnly,

    /// Accept either form, as JWS requires.
    ///
    /// A DPoP proof is an ordinary ES256 JWS produced by whatever client is
    /// talking to us. RFC 7515 defines the signature as the raw `r || s` pair
    /// and imposes no low-S constraint, and WebCrypto — every browser, and
    /// Node's `crypto.subtle` — does not normalise `s`. Roughly half of all
    /// proofs from a conforming client therefore carry high-S. Rejecting those
    /// does not make the protocol stricter, it makes authentication fail at
    /// random for clients doing nothing wrong.
    AnyS,
}

/// Validates a signature against content using the provided key.
///
/// Applies [`SignaturePolicy::LowSOnly`]: this is the AT Protocol signature
/// path. Use [`validate_with_policy`] for JWS, where the high-S form is legal.
///
/// # Errors
///
/// Returns [`KeyError::SignatureMalleable`] for an ECDSA signature in the
/// high-S form, which AT Protocol does not accept, before checking whether it
/// verifies at all.
pub fn validate(key_data: &KeyData, signature: &[u8], content: &[u8]) -> Result<(), KeyError> {
    validate_with_policy(key_data, signature, content, SignaturePolicy::LowSOnly)
}

/// Validates a signature under an explicit malleability policy.
///
/// # Errors
///
/// Returns [`KeyError::SignatureMalleable`] only under
/// [`SignaturePolicy::LowSOnly`]; otherwise the same errors as [`validate`].
pub fn validate_with_policy(
    key_data: &KeyData,
    signature: &[u8],
    content: &[u8],
    policy: SignaturePolicy,
) -> Result<(), KeyError> {
    match *key_data.key_type() {
        KeyType::P256Public => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_data.bytes())
                .map_err(|error| KeyError::P256Error { error })?;
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::P384Public => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_data.bytes())
                .map_err(|error| KeyError::P384Error { error })?;
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::K256Public => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(key_data.bytes())
                .map_err(|error| KeyError::K256Error { error })?;
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::P256Private => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let secret_key: p256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::P384Private => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let secret_key: p384::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::K256Private => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|error| KeyError::SignatureError { error })?;
            if policy == SignaturePolicy::LowSOnly {
                reject_high_s(&signature)?;
            }
            let secret_key: k256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
            ecdsa::signature::Verifier::verify(&verifying_key, content, &signature)
                .map_err(|error| KeyError::ECDSAError { error })
        }
        KeyType::Ed25519Public => {
            let key_bytes: &[u8; 32] =
                key_data
                    .bytes()
                    .try_into()
                    .map_err(|_| KeyError::Ed25519Error {
                        error: format!(
                            "invalid public key length: expected 32, got {}",
                            key_data.bytes().len()
                        ),
                    })?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|error| {
                    KeyError::Ed25519Error {
                        error: format!("invalid public key: {}", error),
                    }
                })?;
            let sig_bytes: &[u8; 64] =
                signature.try_into().map_err(|_| KeyError::Ed25519Error {
                    error: format!(
                        "invalid signature length: expected 64, got {}",
                        signature.len()
                    ),
                })?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            ed25519_dalek::Verifier::verify(&verifying_key, content, &sig).map_err(|error| {
                KeyError::Ed25519Error {
                    error: format!("signature verification failed: {}", error),
                }
            })
        }
        KeyType::Ed25519Private => {
            let key_bytes: &[u8; 32] =
                key_data
                    .bytes()
                    .try_into()
                    .map_err(|_| KeyError::Ed25519Error {
                        error: format!(
                            "invalid private key length: expected 32, got {}",
                            key_data.bytes().len()
                        ),
                    })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(key_bytes);
            let verifying_key = signing_key.verifying_key();
            let sig_bytes: &[u8; 64] =
                signature.try_into().map_err(|_| KeyError::Ed25519Error {
                    error: format!(
                        "invalid signature length: expected 64, got {}",
                        signature.len()
                    ),
                })?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            ed25519_dalek::Verifier::verify(&verifying_key, content, &sig).map_err(|error| {
                KeyError::Ed25519Error {
                    error: format!("signature verification failed: {}", error),
                }
            })
        }
    }
}

/// Multicodec prefix for ES256 (P-256/secp256r1) signatures (0xd0a1 varint-encoded).
const ES256_SIGNATURE_MULTICODEC: [u8; 3] = [0xa1, 0xa1, 0x03];

/// Multicodec prefix for ES384 (P-384/secp384r1) signatures (0xd0a2 varint-encoded).
const ES384_SIGNATURE_MULTICODEC: [u8; 3] = [0xa2, 0xa2, 0x03];

/// Multicodec prefix for ES256K (K-256/secp256k1) signatures (0xd0e1 varint-encoded).
const ES256K_SIGNATURE_MULTICODEC: [u8; 3] = [0xe1, 0xa1, 0x03];

/// Signs content using a private key.
///
/// Returns an error if a public key is provided instead of a private key.
pub fn sign(key_data: &KeyData, content: &[u8]) -> Result<Vec<u8>, KeyError> {
    match *key_data.key_type() {
        KeyType::K256Public
        | KeyType::P256Public
        | KeyType::P384Public
        | KeyType::Ed25519Public => Err(KeyError::PrivateKeyRequiredForSignature),
        KeyType::P256Private => {
            let secret_key: p256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let signing_key: p256::ecdsa::SigningKey = p256::ecdsa::SigningKey::from(secret_key);
            let signature: p256::ecdsa::Signature = signing_key
                .try_sign(content)
                .map_err(|error| KeyError::ECDSAError { error })?;
            // `p256` ships an empty `SignPrimitive` impl, so unlike `k256` it
            // does not normalize for us. Without this the crate emits the
            // high-S form roughly half the time, and a peer enforcing low-S
            // rejects exactly those.
            Ok(signature.normalize_s().to_vec())
        }
        KeyType::P384Private => {
            let secret_key: p384::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let signing_key: p384::ecdsa::SigningKey = p384::ecdsa::SigningKey::from(secret_key);
            let signature: p384::ecdsa::Signature = signing_key
                .try_sign(content)
                .map_err(|error| KeyError::ECDSAError { error })?;
            // As for P-256: `p384` does not normalize on signing either.
            Ok(signature.normalize_s().to_vec())
        }
        KeyType::K256Private => {
            let secret_key: k256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let signing_key: k256::ecdsa::SigningKey = k256::ecdsa::SigningKey::from(secret_key);
            let signature: k256::ecdsa::Signature = signing_key
                .try_sign(content)
                .map_err(|error| KeyError::ECDSAError { error })?;
            // `k256` normalizes inside its own `SignPrimitive`, which is why
            // K-256 account keys were never affected. Stated rather than
            // relied on silently.
            Ok(signature.normalize_s().to_vec())
        }
        KeyType::Ed25519Private => {
            let key_bytes: &[u8; 32] =
                key_data
                    .bytes()
                    .try_into()
                    .map_err(|_| KeyError::Ed25519Error {
                        error: format!(
                            "invalid private key length: expected 32, got {}",
                            key_data.bytes().len()
                        ),
                    })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(key_bytes);
            let signature = ed25519_dalek::Signer::sign(&signing_key, content);
            Ok(signature.to_bytes().to_vec())
        }
    }
}

/// Encodes signature bytes using multiformat encoding (multibase + multicodec).
///
/// Creates a self-describing signature string by prepending the appropriate
/// multicodec identifier for the signature algorithm and encoding the result
/// using base58btc multibase encoding.
///
/// # Arguments
/// * `key_type` - The type of key used to create the signature (determines the algorithm prefix)
/// * `signature` - The raw ECDSA signature bytes to encode
///
/// # Returns
/// A multiformat-encoded string with the `z` prefix (base58btc) containing the
/// multicodec identifier and signature bytes.
///
/// # Supported Key Types
/// * `P256Private` / `P256Public` - Uses ES256 multicodec (0xd0a1)
/// * `P384Private` / `P384Public` - Uses ES384 multicodec (0xd0a2)
/// * `K256Private` / `K256Public` - Uses ES256K multicodec (0xd0e1)
///
/// # Example
/// ```rust
/// use atproto_identity::key::{generate_key, sign, multiformat_encode, KeyType};
///
/// let key = generate_key(KeyType::P256Private)?;
/// let message = b"Hello AT Protocol!";
/// let signature = sign(&key, message)?;
/// let encoded = multiformat_encode(key.key_type(), &signature);
/// assert!(encoded.starts_with("z")); // base58btc prefix
/// # Ok::<(), atproto_identity::errors::KeyError>(())
/// ```
/// Multicodec prefix for EdDSA (Ed25519) signatures (0xd002 varint-encoded).
const EDDSA_SIGNATURE_MULTICODEC: [u8; 3] = [0x02, 0xa0, 0x03];

/// Encodes a signature with its multicodec prefix and returns a multibase base58btc string.
pub fn multiformat_encode(key_type: &KeyType, signature: &[u8]) -> String {
    let prefix: &[u8] = match key_type {
        KeyType::P256Private | KeyType::P256Public => &ES256_SIGNATURE_MULTICODEC,
        KeyType::P384Private | KeyType::P384Public => &ES384_SIGNATURE_MULTICODEC,
        KeyType::K256Private | KeyType::K256Public => &ES256K_SIGNATURE_MULTICODEC,
        KeyType::Ed25519Private | KeyType::Ed25519Public => &EDDSA_SIGNATURE_MULTICODEC,
    };

    // Combine prefix and signature bytes
    let mut multicodec_bytes = Vec::with_capacity(prefix.len() + signature.len());
    multicodec_bytes.extend_from_slice(prefix);
    multicodec_bytes.extend_from_slice(signature);

    // Encode using multibase (base58btc with 'z' prefix)
    multibase::encode(multibase::Base::Base58Btc, &multicodec_bytes)
}

/// Key resolver implementation that fetches DID documents using an [`IdentityResolver`].
#[derive(Clone)]
pub struct IdentityDocumentKeyResolver {
    identity_resolver: Arc<dyn IdentityResolver>,
}

impl IdentityDocumentKeyResolver {
    /// Creates a new key resolver backed by an [`IdentityResolver`].
    pub fn new(identity_resolver: Arc<dyn IdentityResolver>) -> Self {
        Self { identity_resolver }
    }
}

#[async_trait::async_trait]
impl KeyResolver for IdentityDocumentKeyResolver {
    async fn resolve(&self, key: &str) -> Result<KeyData> {
        if let Some(did_key) = key.split('#').next()
            && let Ok(key_data) = identify_key(did_key)
        {
            return Ok(key_data);
        } else if let Ok(key_data) = identify_key(key) {
            return Ok(key_data);
        }

        let (did, fragment) = key
            .split_once('#')
            .context("Key reference must contain a DID fragment (e.g., did:example#key)")?;

        if did.is_empty() || fragment.is_empty() {
            return Err(anyhow!(
                "Key reference must include both DID and fragment (received `{key}`)"
            ));
        }

        let document = self.identity_resolver.resolve(did).await?;
        let fragment_with_hash = format!("#{fragment}");

        let public_key_multibase = document
            .verification_method
            .iter()
            .find_map(|method| match method {
                VerificationMethod::Multikey {
                    id,
                    public_key_multibase,
                    ..
                } if id == key || *id == fragment_with_hash => Some(public_key_multibase.clone()),
                _ => None,
            })
            .context(format!(
                "Verification method `{key}` not found in DID document `{did}`"
            ))?;

        let full_key = if public_key_multibase.starts_with("did:key:") {
            public_key_multibase
        } else {
            format!("did:key:{}", public_key_multibase)
        };

        identify_key(&full_key).context("Failed to parse key data from verification method")
    }
}

/// Recover a key from its JWK form.
///
/// The coordinates are re-derived through the curve type rather than trusted:
/// that is what rejects a point which is not actually on the curve, or a
/// private scalar outside the field order. A JWK carrying `d` yields the
/// private key type; otherwise the public one, stored compressed to match how
/// `KeyData` holds public keys everywhere else.
impl TryFrom<&crate::jwk::Jwk> for KeyData {
    type Error = KeyError;

    fn try_from(jwk: &crate::jwk::Jwk) -> Result<Self, Self::Error> {
        use crate::jwk::{CRV_K256, CRV_P256, CRV_P384};
        use elliptic_curve::sec1::ToSec1Point;

        fn err(what: &str, e: impl std::fmt::Display) -> KeyError {
            KeyError::JWKConversionFailed {
                error: format!("{what}: {e}"),
            }
        }

        let scalar = jwk.private_scalar()?;
        let point = jwk.to_sec1_uncompressed()?;
        match (jwk.crv(), scalar) {
            (CRV_P256, Some(d)) => {
                let sk = p256::SecretKey::from_slice(&d).map_err(|e| err("P-256 private", e))?;
                Ok(KeyData::new(KeyType::P256Private, sk.to_bytes().to_vec()))
            }
            (CRV_P256, None) => {
                let pk =
                    p256::PublicKey::from_sec1_bytes(&point).map_err(|e| err("P-256 public", e))?;
                Ok(KeyData::new(
                    KeyType::P256Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                ))
            }
            (CRV_P384, Some(d)) => {
                let sk = p384::SecretKey::from_slice(&d).map_err(|e| err("P-384 private", e))?;
                Ok(KeyData::new(KeyType::P384Private, sk.to_bytes().to_vec()))
            }
            (CRV_P384, None) => {
                let pk =
                    p384::PublicKey::from_sec1_bytes(&point).map_err(|e| err("P-384 public", e))?;
                Ok(KeyData::new(
                    KeyType::P384Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                ))
            }
            (CRV_K256, Some(d)) => {
                let sk =
                    k256::SecretKey::from_slice(&d).map_err(|e| err("secp256k1 private", e))?;
                Ok(KeyData::new(KeyType::K256Private, sk.to_bytes().to_vec()))
            }
            (CRV_K256, None) => {
                let pk = k256::PublicKey::from_sec1_bytes(&point)
                    .map_err(|e| err("secp256k1 public", e))?;
                Ok(KeyData::new(
                    KeyType::K256Public,
                    pk.to_sec1_point(true).as_bytes().to_vec(),
                ))
            }
            (other, _) => Err(KeyError::JWKConversionFailed {
                error: format!("unsupported jwk crv {other}"),
            }),
        }
    }
}

impl TryInto<crate::jwk::Jwk> for &KeyData {
    type Error = KeyError;

    fn try_into(self) -> Result<crate::jwk::Jwk, Self::Error> {
        use crate::jwk::{CRV_K256, CRV_P256, CRV_P384, Jwk};
        use elliptic_curve::sec1::ToSec1Point;

        // `KeyData` holds the compressed SEC1 form for public keys, and a JWK
        // needs both affine coordinates, so each arm parses the point and
        // re-encodes it uncompressed rather than splitting the stored bytes.
        fn err(curve: &str, e: impl std::fmt::Display) -> KeyError {
            KeyError::JWKConversionFailed {
                error: format!("Failed to parse {curve} key: {e}"),
            }
        }

        match *self.key_type() {
            KeyType::P256Public => {
                let pk = p256::PublicKey::from_sec1_bytes(self.bytes())
                    .map_err(|e| err("P256 public", e))?;
                Jwk::from_sec1_uncompressed(CRV_P256, pk.to_sec1_point(false).as_bytes())
            }
            KeyType::P256Private => {
                let sk = p256::SecretKey::from_slice(self.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
                Jwk::from_sec1_uncompressed(
                    CRV_P256,
                    sk.public_key().to_sec1_point(false).as_bytes(),
                )?
                .with_private_scalar(&sk.to_bytes())
            }
            KeyType::P384Public => {
                let pk = p384::PublicKey::from_sec1_bytes(self.bytes())
                    .map_err(|e| err("P384 public", e))?;
                Jwk::from_sec1_uncompressed(CRV_P384, pk.to_sec1_point(false).as_bytes())
            }
            KeyType::P384Private => {
                let sk = p384::SecretKey::from_slice(self.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
                Jwk::from_sec1_uncompressed(
                    CRV_P384,
                    sk.public_key().to_sec1_point(false).as_bytes(),
                )?
                .with_private_scalar(&sk.to_bytes())
            }
            KeyType::K256Public => {
                let pk = k256::PublicKey::from_sec1_bytes(self.bytes())
                    .map_err(|e| err("k256 public", e))?;
                Jwk::from_sec1_uncompressed(CRV_K256, pk.to_sec1_point(false).as_bytes())
            }
            KeyType::K256Private => {
                let sk = k256::SecretKey::from_slice(self.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
                Jwk::from_sec1_uncompressed(
                    CRV_K256,
                    sk.public_key().to_sec1_point(false).as_bytes(),
                )?
                .with_private_scalar(&sk.to_bytes())
            }
            KeyType::Ed25519Public | KeyType::Ed25519Private => {
                Err(KeyError::JWKConversionFailed {
                    error: "Ed25519 keys use JWK OKP key type, not EC".to_string(),
                })
            }
        }
    }
}
/// The OS RNG failing is not something a caller can act on differently from
/// any other key-generation failure, so it folds into the existing variant.
fn rng_failure(error: elliptic_curve::common::getrandom::Error) -> KeyError {
    KeyError::JWKConversionFailed {
        error: format!("system RNG unavailable for key generation: {error}"),
    }
}

/// Generates a new cryptographic key of the specified type.
///
/// # Arguments
/// * `key_type` - The type of key to generate
///
/// # Returns
/// A `KeyData` containing the generated key material
///
/// # Errors
/// * Returns `KeyError::PublicKeyGenerationNotSupported` for public key types
/// * Returns `KeyError::SecretKeyError` if key generation fails
///
/// # Example
/// ```rust
/// use atproto_identity::key::{generate_key, KeyType};
///
/// let private_key = generate_key(KeyType::P256Private)?;
/// assert_eq!(*private_key.key_type(), KeyType::P256Private);
/// # Ok::<(), atproto_identity::errors::KeyError>(())
/// ```
pub fn generate_key(key_type: KeyType) -> Result<KeyData, KeyError> {
    use elliptic_curve::common::Generate;

    match key_type {
        KeyType::P256Private => {
            let secret_key = p256::SecretKey::try_generate().map_err(rng_failure)?;
            Ok(KeyData::new(
                KeyType::P256Private,
                secret_key.to_bytes().to_vec(),
            ))
        }
        KeyType::P384Private => {
            let secret_key = p384::SecretKey::try_generate().map_err(rng_failure)?;
            Ok(KeyData::new(
                KeyType::P384Private,
                secret_key.to_bytes().to_vec(),
            ))
        }
        KeyType::K256Private => {
            let secret_key = k256::SecretKey::try_generate().map_err(rng_failure)?;
            Ok(KeyData::new(
                KeyType::K256Private,
                secret_key.to_bytes().to_vec(),
            ))
        }
        KeyType::Ed25519Private => {
            let signing_key = ed25519_dalek::SigningKey::try_generate().map_err(rng_failure)?;
            Ok(KeyData::new(
                KeyType::Ed25519Private,
                signing_key.to_bytes().to_vec(),
            ))
        }
        KeyType::P256Public
        | KeyType::P384Public
        | KeyType::K256Public
        | KeyType::Ed25519Public => Err(KeyError::PublicKeyGenerationNotSupported),
    }
}

/// Derives a public key from a private key, or returns the key if it's already public.
///
/// # Arguments
/// * `key_data` - The key data to convert to public key format
///
/// # Returns
/// A `KeyData` containing the corresponding public key
///
/// # Errors
/// * Returns `KeyError::SecretKeyError` if private key parsing fails
///
/// # Example
/// ```rust
/// use atproto_identity::key::{generate_key, to_public, KeyType};
///
/// let private_key = generate_key(KeyType::P256Private)?;
/// let public_key = to_public(&private_key)?;
/// assert_eq!(*public_key.key_type(), KeyType::P256Public);
///
/// // Works with public keys too
/// let same_public_key = to_public(&public_key)?;
/// assert_eq!(public_key.bytes(), same_public_key.bytes());
/// # Ok::<(), atproto_identity::errors::KeyError>(())
/// ```
pub fn to_public(key_data: &KeyData) -> Result<KeyData, KeyError> {
    match key_data.key_type() {
        KeyType::P256Private => {
            let secret_key: p256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let compressed = public_key.to_sec1_point(true);
            let public_key_bytes = compressed.to_bytes();
            Ok(KeyData::new(KeyType::P256Public, public_key_bytes.to_vec()))
        }
        KeyType::P384Private => {
            let secret_key: p384::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let compressed = public_key.to_sec1_point(true);
            let public_key_bytes = compressed.to_bytes();
            Ok(KeyData::new(KeyType::P384Public, public_key_bytes.to_vec()))
        }
        KeyType::K256Private => {
            let secret_key: k256::SecretKey =
                ecdsa::elliptic_curve::SecretKey::from_slice(key_data.bytes())
                    .map_err(|error| KeyError::SecretKeyError { error })?;
            let public_key = secret_key.public_key();
            let public_key_bytes = public_key.to_sec1_bytes();
            Ok(KeyData::new(KeyType::K256Public, public_key_bytes.to_vec()))
        }
        KeyType::Ed25519Private => {
            let key_bytes: &[u8; 32] =
                key_data
                    .bytes()
                    .try_into()
                    .map_err(|_| KeyError::Ed25519Error {
                        error: format!(
                            "invalid private key length: expected 32, got {}",
                            key_data.bytes().len()
                        ),
                    })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(key_bytes);
            let verifying_key = signing_key.verifying_key();
            Ok(KeyData::new(
                KeyType::Ed25519Public,
                verifying_key.to_bytes().to_vec(),
            ))
        }
        KeyType::P256Public
        | KeyType::P384Public
        | KeyType::K256Public
        | KeyType::Ed25519Public => {
            // Return a clone of the existing public key
            Ok(key_data.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::Jwk;

    /// A signature in the high-S form must verify under
    /// [`SignaturePolicy::AnyS`] and be refused under
    /// [`SignaturePolicy::LowSOnly`].
    ///
    /// This is not hypothetical. WebCrypto — every browser, and Node's
    /// `crypto.subtle` — emits `s` unnormalised, so about half of the DPoP
    /// proofs a conforming OAuth client sends carry high-S. While the JWS path
    /// enforced low-S, those clients failed authentication at random and the
    /// error said only "invalid signature".
    ///
    /// The high-S twin is constructed rather than hunted for: for any valid
    /// `(r, s)`, `(r, n - s)` is the other valid signature over the same
    /// message, so negating `s` flips the form deterministically.
    #[test]
    fn high_s_signatures_are_accepted_only_under_any_s() {
        use ecdsa::elliptic_curve::scalar::IsHigh;

        let content = b"atpint high-S regression";

        for _ in 0..16 {
            let private_key_data = generate_key(KeyType::P256Private).unwrap();
            let public_key_data = to_public(&private_key_data).unwrap();
            let signed = sign(&private_key_data, content).unwrap();

            let signature = ecdsa::Signature::<p256::NistP256>::from_slice(&signed).unwrap();
            // `sign` normalises, so flip it to get the malleable twin.
            assert!(
                !bool::from(signature.s().is_high()),
                "sign() should emit low-S"
            );
            let high = ecdsa::Signature::<p256::NistP256>::from_scalars(
                signature.r().to_owned(),
                -signature.s().to_owned(),
            )
            .unwrap();
            assert!(
                bool::from(high.s().is_high()),
                "negating s must yield high-S"
            );
            let high_bytes = high.to_vec();

            // Both forms are cryptographically valid over the same message.
            validate_with_policy(&public_key_data, &signed, content, SignaturePolicy::AnyS)
                .expect("low-S must verify under AnyS");
            validate_with_policy(
                &public_key_data,
                &high_bytes,
                content,
                SignaturePolicy::AnyS,
            )
            .expect("high-S must verify under AnyS — this is what JWS requires");

            // The AT Protocol path still refuses the malleable twin.
            assert!(matches!(
                validate(&public_key_data, &high_bytes, content),
                Err(KeyError::SignatureMalleable)
            ));
            validate(&public_key_data, &signed, content).expect("low-S must verify by default");
        }
    }

    #[test]
    fn test_identify_key() {
        // Test valid K256 private key (repeat 4 times as in original test)
        for _ in 0..4 {
            let result = identify_key("z3vLVqpQveB3w8G6MQsLVseJ1Z2E1JyQzUj6WgRYNNwB9jdE");
            assert!(result.is_ok());
            let key_data = result.unwrap();
            assert_eq!(*key_data.key_type(), KeyType::K256Private);
        }

        // Test invalid multibase encoding
        assert!(matches!(
            identify_key("asdasdasd"),
            Err(KeyError::DecodeError { .. })
        ));

        // Test invalid key type prefix
        assert!(matches!(
            identify_key("z4vLVqpQveB3w8G6MQsLVseJ1Z2E1JyQzUj6WgRYNNwB9jdE"),
            Err(KeyError::InvalidMultibaseKeyType { .. })
        ));
    }

    #[test]
    fn test_sign_p256() -> Result<()> {
        let private_key = "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o";
        let public_key = "did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2";

        let private_key_data = identify_key(private_key);
        assert!(private_key_data.is_ok());
        let private_key_data = private_key_data.unwrap();
        assert_eq!(*private_key_data.key_type(), KeyType::P256Private);

        let public_key_data = identify_key(public_key);
        assert!(public_key_data.is_ok());
        let public_key_data = public_key_data.unwrap();
        assert_eq!(*public_key_data.key_type(), KeyType::P256Public);

        let content = "hello world".as_bytes();

        let signature = sign(&private_key_data, content);
        assert!(signature.is_ok());
        let signature = signature.unwrap();

        {
            let validation = validate(&public_key_data, &signature, content);
            assert!(validation.is_ok());
        }
        {
            let validation = validate(&private_key_data, &signature, content);
            assert!(validation.is_ok());
        }
        Ok(())
    }

    #[test]
    fn test_sign_k256() -> Result<()> {
        let private_key = "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt";
        let public_key = "did:key:zQ3shNzMp4oaaQ1gQRzCxMGXFrSW3NEM1M9T6KCY9eA7HhyEA";

        let private_key_data = identify_key(private_key);
        assert!(private_key_data.is_ok());
        let private_key_data = private_key_data.unwrap();
        assert_eq!(*private_key_data.key_type(), KeyType::K256Private);

        let public_key_data = identify_key(public_key);
        assert!(public_key_data.is_ok());
        let public_key_data = public_key_data.unwrap();
        assert_eq!(*public_key_data.key_type(), KeyType::K256Public);

        let content = "hello world".as_bytes();

        let signature = sign(&private_key_data, content);
        assert!(signature.is_ok());
        let signature = signature.unwrap();

        {
            let validation = validate(&public_key_data, &signature, content);
            assert!(validation.is_ok());
        }
        {
            let validation = validate(&private_key_data, &signature, content);
            assert!(validation.is_ok());
        }
        Ok(())
    }

    #[test]
    fn test_to_jwk_p256() -> Result<()> {
        let private_key = "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o";
        let public_key = "did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2";

        let private_key_data = identify_key(private_key);
        assert!(private_key_data.is_ok());
        let private_key_data = private_key_data.unwrap();
        assert_eq!(*private_key_data.key_type(), KeyType::P256Private);

        let public_key_data = identify_key(public_key);
        assert!(public_key_data.is_ok());
        let public_key_data = public_key_data.unwrap();
        assert_eq!(*public_key_data.key_type(), KeyType::P256Public);

        // Test private key to JWK conversion
        let private_jwk: Result<crate::jwk::Jwk, _> = (&private_key_data).try_into();
        assert!(private_jwk.is_ok());

        // Test public key to JWK conversion
        let public_jwk: Result<crate::jwk::Jwk, _> = (&public_key_data).try_into();
        assert!(public_jwk.is_ok());

        Ok(())
    }

    #[test]
    fn test_to_jwk_k256_supported() -> Result<()> {
        let private_key = "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt";
        let public_key = "did:key:zQ3shNzMp4oaaQ1gQRzCxMGXFrSW3NEM1M9T6KCY9eA7HhyEA";

        let private_key_data = identify_key(private_key);
        assert!(private_key_data.is_ok());
        let private_key_data = private_key_data.unwrap();
        assert_eq!(*private_key_data.key_type(), KeyType::K256Private);

        let public_key_data = identify_key(public_key);
        assert!(public_key_data.is_ok());
        let public_key_data = public_key_data.unwrap();
        assert_eq!(*public_key_data.key_type(), KeyType::K256Public);

        // Test that K256 keys successfully convert to JWK format
        let private_jwk: Result<crate::jwk::Jwk, _> = (&private_key_data).try_into();
        assert!(private_jwk.is_ok());
        let private_jwk = private_jwk.unwrap();
        assert_eq!(private_jwk.crv(), "secp256k1");

        let public_jwk: Result<crate::jwk::Jwk, _> = (&public_key_data).try_into();
        assert!(public_jwk.is_ok());
        let public_jwk = public_jwk.unwrap();
        assert_eq!(public_jwk.crv(), "secp256k1");

        Ok(())
    }

    #[test]
    fn test_try_into_jwk_keydata() -> Result<()> {
        let private_key = "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o";
        let public_key = "did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2";

        let private_key_data = identify_key(private_key);
        assert!(private_key_data.is_ok());
        let private_key_data = private_key_data.unwrap();
        assert_eq!(*private_key_data.key_type(), KeyType::P256Private);

        let public_key_data = identify_key(public_key);
        assert!(public_key_data.is_ok());
        let public_key_data = public_key_data.unwrap();
        assert_eq!(*public_key_data.key_type(), KeyType::P256Public);

        // Test TryInto with KeyData directly
        let private_jwk: Result<Jwk, KeyError> = (&private_key_data).try_into();
        assert!(private_jwk.is_ok());

        let public_jwk: Result<Jwk, KeyError> = (&public_key_data).try_into();
        assert!(public_jwk.is_ok());

        Ok(())
    }

    #[test]
    fn test_generate_key_p256_private() -> Result<()> {
        let key_data = generate_key(KeyType::P256Private)?;
        assert_eq!(*key_data.key_type(), KeyType::P256Private);
        assert_eq!(key_data.bytes().len(), 32); // P-256 private keys are 32 bytes

        // Test that we can sign with the generated key
        let content = "test content".as_bytes();
        let signature = sign(&key_data, content)?;
        let validation = validate(&key_data, &signature, content);
        assert!(validation.is_ok());

        Ok(())
    }

    #[test]
    fn test_generate_key_k256_private() -> Result<()> {
        let key_data = generate_key(KeyType::K256Private)?;
        assert_eq!(*key_data.key_type(), KeyType::K256Private);
        assert_eq!(key_data.bytes().len(), 32); // K-256 private keys are 32 bytes

        // Test that we can sign with the generated key
        let content = "test content".as_bytes();
        let signature = sign(&key_data, content)?;
        let validation = validate(&key_data, &signature, content);
        assert!(validation.is_ok());

        Ok(())
    }

    #[test]
    fn test_generate_key_public_not_supported() {
        let result = generate_key(KeyType::P256Public);
        assert!(matches!(
            result,
            Err(KeyError::PublicKeyGenerationNotSupported)
        ));

        let result = generate_key(KeyType::K256Public);
        assert!(matches!(
            result,
            Err(KeyError::PublicKeyGenerationNotSupported)
        ));
    }

    #[test]
    fn test_generate_key_uniqueness() -> Result<()> {
        // Generate multiple keys and ensure they're different
        let key1 = generate_key(KeyType::P256Private)?;
        let key2 = generate_key(KeyType::P256Private)?;
        assert_ne!(key1.bytes(), key2.bytes());

        let key3 = generate_key(KeyType::K256Private)?;
        let key4 = generate_key(KeyType::K256Private)?;
        assert_ne!(key3.bytes(), key4.bytes());

        Ok(())
    }

    #[test]
    fn test_keydata_display_p256_private() -> Result<()> {
        // Generate a P-256 private key
        let original_key = generate_key(KeyType::P256Private)?;

        // Convert to string using Display trait
        let key_string = format!("{}", original_key);

        // Verify it has the correct prefix
        assert!(key_string.starts_with("did:key:"));

        // Parse it back using identify_key
        let parsed_key = identify_key(&key_string)?;

        // Verify round-trip: key type should match
        assert_eq!(original_key.key_type(), parsed_key.key_type());

        // Verify round-trip: bytes should match
        assert_eq!(original_key.bytes(), parsed_key.bytes());

        // Test signing and verification with both keys
        let content = "test message for p256".as_bytes();

        // Sign with original key
        let signature = sign(&original_key, content)?;

        // Verify with original key
        validate(&original_key, &signature, content)?;

        // Verify with parsed key
        validate(&parsed_key, &signature, content)?;

        // Sign with parsed key
        let signature2 = sign(&parsed_key, content)?;

        // Verify both signatures are the same (deterministic signing)
        // Note: ECDSA signatures may not be deterministic, so we just verify both work
        validate(&original_key, &signature2, content)?;
        validate(&parsed_key, &signature2, content)?;

        Ok(())
    }

    #[test]
    fn test_keydata_display_k256_private() -> Result<()> {
        // Generate a K-256 private key
        let original_key = generate_key(KeyType::K256Private)?;

        // Convert to string using Display trait
        let key_string = format!("{}", original_key);

        // Verify it has the correct prefix
        assert!(key_string.starts_with("did:key:"));

        // Parse it back using identify_key
        let parsed_key = identify_key(&key_string)?;

        // Verify round-trip: key type should match
        assert_eq!(original_key.key_type(), parsed_key.key_type());

        // Verify round-trip: bytes should match
        assert_eq!(original_key.bytes(), parsed_key.bytes());

        // Test signing and verification with both keys
        let content = "test message for k256".as_bytes();

        // Sign with original key
        let signature = sign(&original_key, content)?;

        // Verify with original key
        validate(&original_key, &signature, content)?;

        // Verify with parsed key
        validate(&parsed_key, &signature, content)?;

        // Sign with parsed key
        let signature2 = sign(&parsed_key, content)?;

        // Verify both signatures work
        validate(&original_key, &signature2, content)?;
        validate(&parsed_key, &signature2, content)?;

        Ok(())
    }

    #[test]
    fn test_keydata_display_existing_keys() -> Result<()> {
        // Test with known existing keys from other tests
        let p256_private_key = "did:key:z42tnbHmmnhF11nwSnp5kQJbcZQw2Vbw5WF3ABDSxPtDgU2o";
        let k256_private_key = "did:key:z3vLY4nbXy2rV4Qr65gUtfnSF3A8Be7gmYzUiCX6eo2PR1Rt";

        // Parse and re-serialize P-256 key
        let parsed_p256 = identify_key(p256_private_key)?;
        let reserialized_p256 = format!("{}", parsed_p256);
        assert_eq!(p256_private_key, reserialized_p256);

        // Parse and re-serialize K-256 key
        let parsed_k256 = identify_key(k256_private_key)?;
        let reserialized_k256 = format!("{}", parsed_k256);
        assert_eq!(k256_private_key, reserialized_k256);

        Ok(())
    }

    #[test]
    fn test_keydata_display_cross_verification() -> Result<()> {
        // Generate keys and test cross-verification scenarios
        let p256_key = generate_key(KeyType::P256Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        // Serialize both keys
        let p256_string = format!("{}", p256_key);
        let k256_string = format!("{}", k256_key);

        // Verify they produce different strings
        assert_ne!(p256_string, k256_string);

        // Parse them back
        let parsed_p256 = identify_key(&p256_string)?;
        let parsed_k256 = identify_key(&k256_string)?;

        // Verify types are preserved
        assert_eq!(*parsed_p256.key_type(), KeyType::P256Private);
        assert_eq!(*parsed_k256.key_type(), KeyType::K256Private);

        // Test that keys from different curves can't be used interchangeably
        let content = "cross verification test".as_bytes();

        // Sign with P-256
        let p256_signature = sign(&p256_key, content)?;

        // Sign with K-256
        let k256_signature = sign(&k256_key, content)?;

        // Verify P-256 signature with P-256 key (should work)
        assert!(validate(&p256_key, &p256_signature, content).is_ok());
        assert!(validate(&parsed_p256, &p256_signature, content).is_ok());

        // Verify K-256 signature with K-256 key (should work)
        assert!(validate(&k256_key, &k256_signature, content).is_ok());
        assert!(validate(&parsed_k256, &k256_signature, content).is_ok());

        // Cross-verification should fail
        assert!(validate(&p256_key, &k256_signature, content).is_err());
        assert!(validate(&k256_key, &p256_signature, content).is_err());

        Ok(())
    }

    #[test]
    fn test_keydata_display_format_consistency() -> Result<()> {
        // Test that the Display format matches expected patterns
        let p256_key = generate_key(KeyType::P256Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        let p256_string = format!("{}", p256_key);
        let k256_string = format!("{}", k256_key);

        // Verify format structure
        assert!(p256_string.starts_with("did:key:z"));
        assert!(k256_string.starts_with("did:key:z"));

        // Verify they can be parsed
        let _parsed_p256 = identify_key(&p256_string)?;
        let _parsed_k256 = identify_key(&k256_string)?;

        // Verify string lengths are reasonable (multibase encoded keys should be consistent length)
        // P-256 private keys: 2 bytes prefix + 32 bytes key = 34 bytes -> ~46 chars base58 + "did:key:z" prefix
        assert!(p256_string.len() > 50 && p256_string.len() < 60);

        // K-256 private keys: 2 bytes prefix + 32 bytes key = 34 bytes -> ~46 chars base58 + "did:key:z" prefix
        assert!(k256_string.len() > 50 && k256_string.len() < 60);

        Ok(())
    }

    #[test]
    fn test_complete_workflow_demonstration() -> Result<()> {
        println!("\n=== KeyData Display Implementation Test ===");

        // Step 1: Generate keys
        println!("1. Generating keys...");
        let p256_key = generate_key(KeyType::P256Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        // Step 2: Display keys (serialize)
        println!("2. Serializing keys to DID format...");
        let p256_did = format!("{}", p256_key);
        let k256_did = format!("{}", k256_key);
        println!("   P-256 DID: {}", p256_did);
        println!("   K-256 DID: {}", k256_did);

        // Step 3: Parse keys back (identify)
        println!("3. Parsing DIDs back to KeyData...");
        let parsed_p256 = identify_key(&p256_did)?;
        let parsed_k256 = identify_key(&k256_did)?;
        println!("   P-256 parsed successfully: {:?}", parsed_p256.key_type());
        println!("   K-256 parsed successfully: {:?}", parsed_k256.key_type());

        // Step 4: Verify round-trip
        println!("4. Verifying round-trip integrity...");
        assert_eq!(p256_key.bytes(), parsed_p256.bytes());
        assert_eq!(k256_key.bytes(), parsed_k256.bytes());
        println!("   Round-trip successful for both keys!");

        // Step 5: Sign and verify
        println!("5. Testing signing and verification...");
        let test_data = "Hello AT Protocol!".as_bytes();

        // Sign with original keys
        let p256_signature = sign(&p256_key, test_data)?;
        let k256_signature = sign(&k256_key, test_data)?;

        // Verify with parsed keys
        validate(&parsed_p256, &p256_signature, test_data)?;
        validate(&parsed_k256, &k256_signature, test_data)?;
        println!("   Signatures verified successfully with parsed keys!");

        // Step 6: Cross-verification should fail
        println!("6. Testing cross-curve verification (should fail)...");
        assert!(validate(&parsed_p256, &k256_signature, test_data).is_err());
        assert!(validate(&parsed_k256, &p256_signature, test_data).is_err());
        println!("   Cross-curve verification correctly failed!");

        println!("=== All tests completed successfully! ===\n");

        Ok(())
    }

    #[test]
    fn test_to_public_p256() -> Result<()> {
        // Generate a P-256 private key
        let private_key = generate_key(KeyType::P256Private)?;

        // Convert to public key
        let public_key = to_public(&private_key)?;

        // Verify the key type is correct
        assert_eq!(*public_key.key_type(), KeyType::P256Public);

        // Test that the derived public key can verify signatures from the private key
        let content = "test message for p256 public key derivation".as_bytes();
        let signature = sign(&private_key, content)?;

        // Public key should be able to verify the signature
        validate(&public_key, &signature, content)?;

        // Test that the public key produces a valid DID string
        let public_key_did = format!("{}", public_key);
        assert!(public_key_did.starts_with("did:key:"));

        // Parse the DID back and verify it's the same
        let parsed_public_key = identify_key(&public_key_did)?;
        assert_eq!(*parsed_public_key.key_type(), KeyType::P256Public);
        assert_eq!(public_key.bytes(), parsed_public_key.bytes());

        Ok(())
    }

    #[test]
    fn test_to_public_k256() -> Result<()> {
        // Generate a K-256 private key
        let private_key = generate_key(KeyType::K256Private)?;

        // Convert to public key
        let public_key = to_public(&private_key)?;

        // Verify the key type is correct
        assert_eq!(*public_key.key_type(), KeyType::K256Public);

        // Test that the derived public key can verify signatures from the private key
        let content = "test message for k256 public key derivation".as_bytes();
        let signature = sign(&private_key, content)?;

        // Public key should be able to verify the signature
        validate(&public_key, &signature, content)?;

        // Test that the public key produces a valid DID string
        let public_key_did = format!("{}", public_key);
        assert!(public_key_did.starts_with("did:key:"));

        // Parse the DID back and verify it's the same
        let parsed_public_key = identify_key(&public_key_did)?;
        assert_eq!(*parsed_public_key.key_type(), KeyType::K256Public);
        assert_eq!(public_key.bytes(), parsed_public_key.bytes());

        Ok(())
    }

    #[test]
    fn test_to_public_with_public_keys() -> Result<()> {
        // Test that passing a public key returns the same key
        let p256_private = generate_key(KeyType::P256Private)?;
        let p256_public = to_public(&p256_private)?;

        // Calling to_public on a public key should return the same key
        let result = to_public(&p256_public)?;
        assert_eq!(*result.key_type(), KeyType::P256Public);
        assert_eq!(p256_public.bytes(), result.bytes());

        let k256_private = generate_key(KeyType::K256Private)?;
        let k256_public = to_public(&k256_private)?;

        let result = to_public(&k256_public)?;
        assert_eq!(*result.key_type(), KeyType::K256Public);
        assert_eq!(k256_public.bytes(), result.bytes());

        Ok(())
    }

    #[test]
    fn test_to_public_existing_keys() -> Result<()> {
        // Test with known private keys to ensure consistent behavior
        let p256_private_key = "did:key:z42tj8ZrAza9WkewDELwWMN37TS3coEbGdZh8bp1URfMVnpx";
        let k256_private_key = "did:key:z3vLW46Z1UHwnr7vN33MoFt2sBQDQagn9HTvWnsQDHegUixP";

        // Parse the private keys
        let parsed_p256_private = identify_key(p256_private_key)?;
        let parsed_k256_private = identify_key(k256_private_key)?;

        // Convert to public keys
        let p256_public = to_public(&parsed_p256_private)?;
        let k256_public = to_public(&parsed_k256_private)?;

        // Verify types
        assert_eq!(*p256_public.key_type(), KeyType::P256Public);
        assert_eq!(*k256_public.key_type(), KeyType::K256Public);

        // Test signing and verification
        let content = "test with existing keys".as_bytes();

        let p256_signature = sign(&parsed_p256_private, content)?;
        let k256_signature = sign(&parsed_k256_private, content)?;

        // Verify with derived public keys
        validate(&p256_public, &p256_signature, content)?;
        validate(&k256_public, &k256_signature, content)?;

        Ok(())
    }

    #[test]
    fn test_to_public_comprehensive_workflow() -> Result<()> {
        println!("\n=== Public Key Derivation Test ===");

        // Generate private keys
        println!("1. Generating private keys...");
        let p256_private = generate_key(KeyType::P256Private)?;
        let k256_private = generate_key(KeyType::K256Private)?;

        // Derive public keys
        println!("2. Deriving public keys...");
        let p256_public = to_public(&p256_private)?;
        let k256_public = to_public(&k256_private)?;

        // Serialize all keys
        println!("3. Serializing keys to DID format...");
        let p256_private_did = format!("{}", p256_private);
        let p256_public_did = format!("{}", p256_public);
        let k256_private_did = format!("{}", k256_private);
        let k256_public_did = format!("{}", k256_public);

        println!("   P-256 Private: {}", p256_private_did);
        println!("   P-256 Public:  {}", p256_public_did);
        println!("   K-256 Private: {}", k256_private_did);
        println!("   K-256 Public:  {}", k256_public_did);

        // Verify different DID patterns
        assert_ne!(p256_private_did, p256_public_did);
        assert_ne!(k256_private_did, k256_public_did);
        assert_ne!(p256_public_did, k256_public_did);

        // Test signing and verification
        println!("4. Testing signature verification...");
        let test_data = "Public key derivation test data".as_bytes();

        let p256_signature = sign(&p256_private, test_data)?;
        let k256_signature = sign(&k256_private, test_data)?;

        // Verify with derived public keys
        validate(&p256_public, &p256_signature, test_data)?;
        validate(&k256_public, &k256_signature, test_data)?;
        println!("   Signatures verified successfully with derived public keys!");

        // Parse public key DIDs and re-verify
        println!("5. Testing DID round-trip with public keys...");
        let parsed_p256_public = identify_key(&p256_public_did)?;
        let parsed_k256_public = identify_key(&k256_public_did)?;

        validate(&parsed_p256_public, &p256_signature, test_data)?;
        validate(&parsed_k256_public, &k256_signature, test_data)?;
        println!("   Parsed public keys also verify signatures correctly!");

        println!("=== Public key derivation workflow completed successfully! ===\n");

        Ok(())
    }

    #[test]
    fn test_to_public_key_properties() -> Result<()> {
        // Test that derived public keys have expected properties
        let p256_private = generate_key(KeyType::P256Private)?;
        let k256_private = generate_key(KeyType::K256Private)?;

        let p256_public = to_public(&p256_private)?;
        let k256_public = to_public(&k256_private)?;

        // P-256 public keys should be 65 bytes (uncompressed) or 33 bytes (compressed)
        // SEC1 format is typically uncompressed for public keys: 0x04 + 32 bytes x + 32 bytes y
        assert!(p256_public.bytes().len() == 65 || p256_public.bytes().len() == 33);

        // K-256 public keys should also be 65 bytes (uncompressed) or 33 bytes (compressed)
        assert!(k256_public.bytes().len() == 65 || k256_public.bytes().len() == 33);

        // Test that multiple derivations from the same private key produce the same public key
        let p256_public2 = to_public(&p256_private)?;
        let k256_public2 = to_public(&k256_private)?;

        assert_eq!(p256_public.bytes(), p256_public2.bytes());
        assert_eq!(k256_public.bytes(), k256_public2.bytes());

        Ok(())
    }

    #[test]
    fn test_to_public_with_existing_public_keys() -> Result<()> {
        // Test with known public keys from the test suite
        let p256_public_key = "did:key:zDnaeXduWbJ1b1Kgjf3uCdCpMDF1LEDizUiyxAxGwerou3Nh2";
        let k256_public_key = "did:key:zQ3shNzMp4oaaQ1gQRzCxMGXFrSW3NEM1M9T6KCY9eA7HhyEA";

        // Parse the public keys
        let parsed_p256_public = identify_key(p256_public_key)?;
        let parsed_k256_public = identify_key(k256_public_key)?;

        // Verify they are public keys
        assert_eq!(*parsed_p256_public.key_type(), KeyType::P256Public);
        assert_eq!(*parsed_k256_public.key_type(), KeyType::K256Public);

        // Calling to_public should return the same keys
        let same_p256_public = to_public(&parsed_p256_public)?;
        let same_k256_public = to_public(&parsed_k256_public)?;

        // Verify they are identical
        assert_eq!(*same_p256_public.key_type(), KeyType::P256Public);
        assert_eq!(*same_k256_public.key_type(), KeyType::K256Public);
        assert_eq!(parsed_p256_public.bytes(), same_p256_public.bytes());
        assert_eq!(parsed_k256_public.bytes(), same_k256_public.bytes());

        // Verify they serialize to the same DID strings
        assert_eq!(format!("{}", same_p256_public), p256_public_key);
        assert_eq!(format!("{}", same_k256_public), k256_public_key);

        Ok(())
    }

    // ===== P-384 SPECIFIC TESTS =====

    #[test]
    fn test_generate_key_p384_private() -> Result<()> {
        let key_data = generate_key(KeyType::P384Private)?;
        assert_eq!(*key_data.key_type(), KeyType::P384Private);
        assert_eq!(key_data.bytes().len(), 48); // P-384 private keys are 48 bytes

        // Test that we can sign with the generated key
        let content = "test content for p384".as_bytes();
        let signature = sign(&key_data, content)?;
        let validation = validate(&key_data, &signature, content);
        assert!(validation.is_ok());

        Ok(())
    }

    #[test]
    fn test_generate_key_p384_public_not_supported() {
        let result = generate_key(KeyType::P384Public);
        assert!(matches!(
            result,
            Err(KeyError::PublicKeyGenerationNotSupported)
        ));
    }

    #[test]
    fn test_generate_key_p384_uniqueness() -> Result<()> {
        // Generate multiple P-384 keys and ensure they're different
        let key1 = generate_key(KeyType::P384Private)?;
        let key2 = generate_key(KeyType::P384Private)?;
        assert_ne!(key1.bytes(), key2.bytes());

        Ok(())
    }

    #[test]
    fn test_sign_and_validate_p384() -> Result<()> {
        // Generate a P-384 private key
        let private_key = generate_key(KeyType::P384Private)?;

        // Derive the corresponding public key
        let public_key = to_public(&private_key)?;
        assert_eq!(*public_key.key_type(), KeyType::P384Public);

        let content = "hello world p384 test".as_bytes();

        // Sign with private key
        let signature = sign(&private_key, content)?;
        assert!(!signature.is_empty());

        // Verify with public key
        validate(&public_key, &signature, content)?;

        // Verify with private key (should also work)
        validate(&private_key, &signature, content)?;

        // Test signature verification fails with wrong content
        let wrong_content = "wrong content".as_bytes();
        assert!(validate(&public_key, &signature, wrong_content).is_err());

        Ok(())
    }

    #[test]
    fn test_p384_keydata_display_round_trip() -> Result<()> {
        // Generate a P-384 private key
        let original_key = generate_key(KeyType::P384Private)?;

        // Convert to string using Display trait
        let key_string = format!("{}", original_key);

        // Verify it has the correct prefix
        assert!(key_string.starts_with("did:key:"));

        // Parse it back using identify_key
        let parsed_key = identify_key(&key_string)?;

        // Verify round-trip: key type should match
        assert_eq!(original_key.key_type(), parsed_key.key_type());

        // Verify round-trip: bytes should match
        assert_eq!(original_key.bytes(), parsed_key.bytes());

        // Test signing and verification with both keys
        let content = "test message for p384 round trip".as_bytes();

        // Sign with original key
        let signature = sign(&original_key, content)?;

        // Verify with original key
        validate(&original_key, &signature, content)?;

        // Verify with parsed key
        validate(&parsed_key, &signature, content)?;

        // Sign with parsed key
        let signature2 = sign(&parsed_key, content)?;

        // Verify both signatures work
        validate(&original_key, &signature2, content)?;
        validate(&parsed_key, &signature2, content)?;

        Ok(())
    }

    #[test]
    fn test_p384_to_public_key_derivation() -> Result<()> {
        // Generate a P-384 private key
        let private_key = generate_key(KeyType::P384Private)?;

        // Convert to public key
        let public_key = to_public(&private_key)?;

        // Verify the key type is correct
        assert_eq!(*public_key.key_type(), KeyType::P384Public);

        // Test that the derived public key can verify signatures from the private key
        let content = "test message for p384 public key derivation".as_bytes();
        let signature = sign(&private_key, content)?;

        // Public key should be able to verify the signature
        validate(&public_key, &signature, content)?;

        // Test that the public key produces a valid DID string
        let public_key_did = format!("{}", public_key);
        assert!(public_key_did.starts_with("did:key:"));

        // Parse the DID back and verify it's the same
        let parsed_public_key = identify_key(&public_key_did)?;
        assert_eq!(*parsed_public_key.key_type(), KeyType::P384Public);
        assert_eq!(public_key.bytes(), parsed_public_key.bytes());

        // Calling to_public on a public key should return the same key
        let result = to_public(&public_key)?;
        assert_eq!(*result.key_type(), KeyType::P384Public);
        assert_eq!(public_key.bytes(), result.bytes());

        Ok(())
    }

    #[test]
    fn test_p384_jwk_conversion() -> Result<()> {
        // Generate P-384 keys
        let private_key = generate_key(KeyType::P384Private)?;
        let public_key = to_public(&private_key)?;

        // Test private key to JWK conversion
        let private_jwk: Result<crate::jwk::Jwk, _> = (&private_key).try_into();
        assert!(private_jwk.is_ok());

        // Test public key to JWK conversion
        let public_jwk: Result<crate::jwk::Jwk, _> = (&public_key).try_into();
        assert!(public_jwk.is_ok());

        Ok(())
    }

    #[test]
    fn test_p384_key_properties() -> Result<()> {
        // Test that P-384 keys have expected properties
        let private_key = generate_key(KeyType::P384Private)?;
        let public_key = to_public(&private_key)?;

        // P-384 private keys should be 48 bytes
        assert_eq!(private_key.bytes().len(), 48);

        // P-384 public keys should be 97 bytes (uncompressed) or 49 bytes (compressed)
        // SEC1 format: 0x04 + 48 bytes x + 48 bytes y = 97 bytes uncompressed
        // or 0x02/0x03 + 48 bytes x = 49 bytes compressed
        assert!(public_key.bytes().len() == 97 || public_key.bytes().len() == 49);

        // Test that multiple derivations from the same private key produce the same public key
        let public_key2 = to_public(&private_key)?;
        assert_eq!(public_key.bytes(), public_key2.bytes());

        Ok(())
    }

    #[test]
    fn test_p384_cross_curve_verification_fails() -> Result<()> {
        // Generate keys from different curves
        let p256_key = generate_key(KeyType::P256Private)?;
        let p384_key = generate_key(KeyType::P384Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        // Get their public keys
        let p256_public = to_public(&p256_key)?;
        let p384_public = to_public(&p384_key)?;
        let k256_public = to_public(&k256_key)?;

        let content = "cross curve verification test".as_bytes();

        // Sign with each private key
        let p256_signature = sign(&p256_key, content)?;
        let p384_signature = sign(&p384_key, content)?;
        let k256_signature = sign(&k256_key, content)?;

        // Verify each signature works with its corresponding key
        validate(&p256_public, &p256_signature, content)?;
        validate(&p384_public, &p384_signature, content)?;
        validate(&k256_public, &k256_signature, content)?;

        // Cross-verification should fail - P-384 vs others
        assert!(validate(&p256_public, &p384_signature, content).is_err());
        assert!(validate(&p384_public, &p256_signature, content).is_err());
        assert!(validate(&k256_public, &p384_signature, content).is_err());
        assert!(validate(&p384_public, &k256_signature, content).is_err());

        Ok(())
    }

    #[test]
    fn test_p384_sign_with_public_key_fails() {
        let private_key = generate_key(KeyType::P384Private).unwrap();
        let public_key = to_public(&private_key).unwrap();

        let content = "test content".as_bytes();

        // Signing with public key should fail
        let result = sign(&public_key, content);
        assert!(matches!(
            result,
            Err(KeyError::PrivateKeyRequiredForSignature)
        ));
    }

    #[test]
    fn test_p384_comprehensive_workflow() -> Result<()> {
        println!("\n=== P-384 Comprehensive Workflow Test ===");

        // Step 1: Generate P-384 private key
        println!("1. Generating P-384 private key...");
        let private_key = generate_key(KeyType::P384Private)?;
        assert_eq!(*private_key.key_type(), KeyType::P384Private);
        assert_eq!(private_key.bytes().len(), 48);

        // Step 2: Derive public key
        println!("2. Deriving P-384 public key...");
        let public_key = to_public(&private_key)?;
        assert_eq!(*public_key.key_type(), KeyType::P384Public);

        // Step 3: Serialize keys to DID format
        println!("3. Serializing keys to DID format...");
        let private_did = format!("{}", private_key);
        let public_did = format!("{}", public_key);
        println!("   P-384 Private: {}", private_did);
        println!("   P-384 Public:  {}", public_did);

        assert!(private_did.starts_with("did:key:"));
        assert!(public_did.starts_with("did:key:"));
        assert_ne!(private_did, public_did);

        // Step 4: Parse DIDs back to KeyData
        println!("4. Parsing DIDs back to KeyData...");
        let parsed_private = identify_key(&private_did)?;
        let parsed_public = identify_key(&public_did)?;

        assert_eq!(*parsed_private.key_type(), KeyType::P384Private);
        assert_eq!(*parsed_public.key_type(), KeyType::P384Public);

        // Step 5: Verify round-trip integrity
        println!("5. Verifying round-trip integrity...");
        assert_eq!(private_key.bytes(), parsed_private.bytes());
        assert_eq!(public_key.bytes(), parsed_public.bytes());

        // Step 6: Test signing and verification
        println!("6. Testing signing and verification...");
        let test_data = "P-384 comprehensive test data".as_bytes();

        // Sign with original private key
        let signature = sign(&private_key, test_data)?;

        // Verify with all key variants
        validate(&private_key, &signature, test_data)?;
        validate(&public_key, &signature, test_data)?;
        validate(&parsed_private, &signature, test_data)?;
        validate(&parsed_public, &signature, test_data)?;

        // Step 7: Test JWK conversion
        println!("7. Testing JWK conversion...");
        let private_jwk: crate::jwk::Jwk = (&private_key).try_into()?;
        let public_jwk: crate::jwk::Jwk = (&public_key).try_into()?;

        assert_eq!(private_jwk.crv(), "P-384");
        assert_eq!(public_jwk.crv(), "P-384");

        println!("=== P-384 comprehensive workflow completed successfully! ===\n");

        Ok(())
    }

    #[test]
    fn test_p384_multicodec_prefix_identification() -> Result<()> {
        // Test that we can identify P-384 keys by their multicodec prefixes
        let private_key = generate_key(KeyType::P384Private)?;
        let public_key = to_public(&private_key)?;

        // Convert to DID strings
        let private_did = format!("{}", private_key);
        let public_did = format!("{}", public_key);

        // Parse back and verify the multicodec prefixes were correctly identified
        let parsed_private = identify_key(&private_did)?;
        let parsed_public = identify_key(&public_did)?;

        assert_eq!(*parsed_private.key_type(), KeyType::P384Private);
        assert_eq!(*parsed_public.key_type(), KeyType::P384Public);

        // Verify the actual multicodec prefixes in the DID strings
        let private_value = did_method_key_value(&private_did);
        let public_value = did_method_key_value(&public_did);

        let (_, private_decoded) = multibase::decode(private_value)?;
        let (_, public_decoded) = multibase::decode(public_value)?;

        // Check the multicodec prefixes
        assert_eq!(&private_decoded[..2], &[0x13, 0x01]); // P-384 private key prefix
        assert_eq!(&public_decoded[..2], &[0x12, 0x00]); // P-384 public key prefix

        Ok(())
    }

    // ===== MULTIFORMAT_ENCODE TESTS =====

    #[test]
    fn test_multiformat_encode_p256() -> Result<()> {
        let key = generate_key(KeyType::P256Private)?;
        let message = b"test message for p256 multiformat";
        let signature = sign(&key, message)?;

        let encoded = multiformat_encode(key.key_type(), &signature);

        // Verify base58btc prefix
        assert!(encoded.starts_with('z'));

        // Decode and verify multicodec prefix
        let (_, decoded) = multibase::decode(&encoded)?;
        assert_eq!(&decoded[..3], &[0xa1, 0xa1, 0x03]); // ES256 multicodec prefix

        // Verify signature bytes are preserved
        assert_eq!(&decoded[3..], &signature[..]);

        Ok(())
    }

    #[test]
    fn test_multiformat_encode_p384() -> Result<()> {
        let key = generate_key(KeyType::P384Private)?;
        let message = b"test message for p384 multiformat";
        let signature = sign(&key, message)?;

        let encoded = multiformat_encode(key.key_type(), &signature);

        // Verify base58btc prefix
        assert!(encoded.starts_with('z'));

        // Decode and verify multicodec prefix
        let (_, decoded) = multibase::decode(&encoded)?;
        assert_eq!(&decoded[..3], &[0xa2, 0xa2, 0x03]); // ES384 multicodec prefix

        // Verify signature bytes are preserved
        assert_eq!(&decoded[3..], &signature[..]);

        Ok(())
    }

    #[test]
    fn test_multiformat_encode_k256() -> Result<()> {
        let key = generate_key(KeyType::K256Private)?;
        let message = b"test message for k256 multiformat";
        let signature = sign(&key, message)?;

        let encoded = multiformat_encode(key.key_type(), &signature);

        // Verify base58btc prefix
        assert!(encoded.starts_with('z'));

        // Decode and verify multicodec prefix
        let (_, decoded) = multibase::decode(&encoded)?;
        assert_eq!(&decoded[..3], &[0xe1, 0xa1, 0x03]); // ES256K multicodec prefix

        // Verify signature bytes are preserved
        assert_eq!(&decoded[3..], &signature[..]);

        Ok(())
    }

    #[test]
    fn test_multiformat_encode_public_key_type() -> Result<()> {
        // Test that public key types produce the same encoding as their private counterparts
        let p256_key = generate_key(KeyType::P256Private)?;
        let p256_public = to_public(&p256_key)?;
        let message = b"test message";
        let signature = sign(&p256_key, message)?;

        let encoded_private = multiformat_encode(p256_key.key_type(), &signature);
        let encoded_public = multiformat_encode(p256_public.key_type(), &signature);

        // Both should produce the same encoding since they use the same algorithm
        assert_eq!(encoded_private, encoded_public);

        Ok(())
    }

    #[test]
    fn test_multiformat_encode_different_curves_different_output() -> Result<()> {
        // Same signature bytes should produce different encodings for different curves
        let fake_signature = vec![0u8; 64]; // Dummy signature bytes

        let p256_encoded = multiformat_encode(&KeyType::P256Private, &fake_signature);
        let p384_encoded = multiformat_encode(&KeyType::P384Private, &fake_signature);
        let k256_encoded = multiformat_encode(&KeyType::K256Private, &fake_signature);

        // All three should be different due to different multicodec prefixes
        assert_ne!(p256_encoded, p384_encoded);
        assert_ne!(p256_encoded, k256_encoded);
        assert_ne!(p384_encoded, k256_encoded);

        Ok(())
    }

    // ===== ED25519 SPECIFIC TESTS =====

    #[test]
    fn test_generate_key_ed25519_private() -> Result<()> {
        let key_data = generate_key(KeyType::Ed25519Private)?;
        assert_eq!(*key_data.key_type(), KeyType::Ed25519Private);
        assert_eq!(key_data.bytes().len(), 32);

        let content = "test content for ed25519".as_bytes();
        let signature = sign(&key_data, content)?;
        assert_eq!(signature.len(), 64);
        validate(&key_data, &signature, content)?;

        Ok(())
    }

    #[test]
    fn test_generate_key_ed25519_public_not_supported() {
        let result = generate_key(KeyType::Ed25519Public);
        assert!(matches!(
            result,
            Err(KeyError::PublicKeyGenerationNotSupported)
        ));
    }

    #[test]
    fn test_generate_key_ed25519_uniqueness() -> Result<()> {
        let key1 = generate_key(KeyType::Ed25519Private)?;
        let key2 = generate_key(KeyType::Ed25519Private)?;
        assert_ne!(key1.bytes(), key2.bytes());

        Ok(())
    }

    #[test]
    fn test_sign_and_validate_ed25519() -> Result<()> {
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let public_key = to_public(&private_key)?;
        assert_eq!(*public_key.key_type(), KeyType::Ed25519Public);
        assert_eq!(public_key.bytes().len(), 32);

        let content = "hello world ed25519 test".as_bytes();

        let signature = sign(&private_key, content)?;
        assert_eq!(signature.len(), 64);

        // Verify with public key
        validate(&public_key, &signature, content)?;

        // Verify with private key
        validate(&private_key, &signature, content)?;

        // Wrong content should fail
        assert!(validate(&public_key, &signature, b"wrong content").is_err());

        Ok(())
    }

    #[test]
    fn test_ed25519_tampered_signature() -> Result<()> {
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let public_key = to_public(&private_key)?;
        let content = b"test content";

        let mut signature = sign(&private_key, content)?;
        // Tamper with the signature
        signature[0] ^= 0xff;

        assert!(validate(&public_key, &signature, content).is_err());

        Ok(())
    }

    #[test]
    fn test_ed25519_keydata_display_round_trip() -> Result<()> {
        let original_key = generate_key(KeyType::Ed25519Private)?;

        let key_string = format!("{}", original_key);
        assert!(key_string.starts_with("did:key:z"));

        let parsed_key = identify_key(&key_string)?;
        assert_eq!(original_key.key_type(), parsed_key.key_type());
        assert_eq!(original_key.bytes(), parsed_key.bytes());

        // Sign with original, verify with parsed
        let content = b"ed25519 round trip test";
        let signature = sign(&original_key, content)?;
        validate(&parsed_key, &signature, content)?;

        // Sign with parsed, verify with original
        let signature2 = sign(&parsed_key, content)?;
        validate(&original_key, &signature2, content)?;

        Ok(())
    }

    #[test]
    fn test_ed25519_to_public_key_derivation() -> Result<()> {
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let public_key = to_public(&private_key)?;

        assert_eq!(*public_key.key_type(), KeyType::Ed25519Public);
        assert_eq!(public_key.bytes().len(), 32);

        let public_key_did = format!("{}", public_key);
        assert!(public_key_did.starts_with("did:key:"));

        let parsed_public_key = identify_key(&public_key_did)?;
        assert_eq!(*parsed_public_key.key_type(), KeyType::Ed25519Public);
        assert_eq!(public_key.bytes(), parsed_public_key.bytes());

        // Calling to_public on a public key should return the same key
        let result = to_public(&public_key)?;
        assert_eq!(*result.key_type(), KeyType::Ed25519Public);
        assert_eq!(public_key.bytes(), result.bytes());

        Ok(())
    }

    #[test]
    fn test_ed25519_multicodec_prefix_identification() -> Result<()> {
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let public_key = to_public(&private_key)?;

        let private_did = format!("{}", private_key);
        let public_did = format!("{}", public_key);

        let private_value = did_method_key_value(&private_did);
        let public_value = did_method_key_value(&public_did);

        let (_, private_decoded) = multibase::decode(private_value)?;
        let (_, public_decoded) = multibase::decode(public_value)?;

        assert_eq!(&private_decoded[..2], &[0x80, 0x26]);
        assert_eq!(&public_decoded[..2], &[0xed, 0x01]);

        Ok(())
    }

    #[test]
    fn test_ed25519_sign_with_public_key_fails() {
        let private_key = generate_key(KeyType::Ed25519Private).unwrap();
        let public_key = to_public(&private_key).unwrap();

        let result = sign(&public_key, b"test content");
        assert!(matches!(
            result,
            Err(KeyError::PrivateKeyRequiredForSignature)
        ));
    }

    #[test]
    fn test_ed25519_jwk_conversion_fails() -> Result<()> {
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let public_key = to_public(&private_key)?;

        let private_jwk: Result<crate::jwk::Jwk, _> = (&private_key).try_into();
        assert!(matches!(
            private_jwk,
            Err(KeyError::JWKConversionFailed { .. })
        ));

        let public_jwk: Result<crate::jwk::Jwk, _> = (&public_key).try_into();
        assert!(matches!(
            public_jwk,
            Err(KeyError::JWKConversionFailed { .. })
        ));

        Ok(())
    }

    #[test]
    fn test_ed25519_cross_curve_verification_fails() -> Result<()> {
        let ed25519_key = generate_key(KeyType::Ed25519Private)?;
        let p256_key = generate_key(KeyType::P256Private)?;
        let k256_key = generate_key(KeyType::K256Private)?;

        let ed25519_public = to_public(&ed25519_key)?;
        let p256_public = to_public(&p256_key)?;
        let k256_public = to_public(&k256_key)?;

        let content = b"cross curve ed25519 test";

        let ed25519_sig = sign(&ed25519_key, content)?;
        let p256_sig = sign(&p256_key, content)?;
        let k256_sig = sign(&k256_key, content)?;

        // Each signature verifies with its own key
        validate(&ed25519_public, &ed25519_sig, content)?;
        validate(&p256_public, &p256_sig, content)?;
        validate(&k256_public, &k256_sig, content)?;

        // Cross-verification should fail
        assert!(validate(&ed25519_public, &p256_sig, content).is_err());
        assert!(validate(&ed25519_public, &k256_sig, content).is_err());
        assert!(validate(&p256_public, &ed25519_sig, content).is_err());
        assert!(validate(&k256_public, &ed25519_sig, content).is_err());

        Ok(())
    }

    #[test]
    fn test_ed25519_deterministic_signatures() -> Result<()> {
        // Ed25519 signatures are deterministic (unlike ECDSA)
        let private_key = generate_key(KeyType::Ed25519Private)?;
        let content = b"deterministic signature test";

        let sig1 = sign(&private_key, content)?;
        let sig2 = sign(&private_key, content)?;
        assert_eq!(sig1, sig2);

        Ok(())
    }

    #[test]
    fn test_multiformat_encode_ed25519() -> Result<()> {
        let key = generate_key(KeyType::Ed25519Private)?;
        let message = b"test message for ed25519 multiformat";
        let signature = sign(&key, message)?;

        let encoded = multiformat_encode(key.key_type(), &signature);

        // Verify base58btc prefix
        assert!(encoded.starts_with('z'));

        // Decode and verify EdDSA multicodec prefix
        let (_, decoded) = multibase::decode(&encoded)?;
        assert_eq!(&decoded[..3], &EDDSA_SIGNATURE_MULTICODEC);

        // Verify signature bytes are preserved
        assert_eq!(&decoded[3..], &signature[..]);

        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Low-S normalization (F-REPO-06).
    // -----------------------------------------------------------------------

    /// Report the S-half of a 64-byte P-256/P-384/K-256 signature.
    fn s_is_high(signature: &[u8], key_type: &KeyType) -> bool {
        use ecdsa::elliptic_curve::scalar::IsHigh;

        match key_type {
            KeyType::P256Private | KeyType::P256Public => {
                p256::ecdsa::Signature::from_slice(signature)
                    .map(|sig| sig.s().is_high().into())
                    .unwrap_or(false)
            }
            KeyType::P384Private | KeyType::P384Public => {
                p384::ecdsa::Signature::from_slice(signature)
                    .map(|sig| sig.s().is_high().into())
                    .unwrap_or(false)
            }
            KeyType::K256Private | KeyType::K256Public => {
                k256::ecdsa::Signature::from_slice(signature)
                    .map(|sig| sig.s().is_high().into())
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Every signature this crate produces must be low-S.
    ///
    /// ECDSA signatures are malleable: for every valid `(r, s)` the pair
    /// `(r, -s)` verifies just as well, so a signature has two forms and only
    /// one of them is canonical. AT Protocol requires the low-S form, and a
    /// peer that enforces it rejects the other — roughly half of all
    /// signatures, at random, for the life of the key.
    ///
    /// `k256` normalizes inside its own signing primitive, which is why K-256
    /// account keys were never affected. `p256` and `p384` ship an empty
    /// `SignPrimitive` impl, so nothing normalized theirs.
    ///
    /// 64 iterations: a single sign has a ~50% chance of being low-S by luck,
    /// so one round would pass against unfixed code half the time. The odds of
    /// 64 consecutive coincidences are about 1 in 2^64.
    #[test]
    fn every_signature_is_low_s() {
        for key_type in [
            KeyType::P256Private,
            KeyType::P384Private,
            KeyType::K256Private,
        ] {
            let key = generate_key(key_type.clone()).expect("key generation should succeed");
            let mut high = 0;
            for round in 0..64u32 {
                let content = format!("message {round}");
                let signature = sign(&key, content.as_bytes()).expect("signing should succeed");
                if s_is_high(&signature, &key_type) {
                    high += 1;
                }
            }
            assert_eq!(
                high, 0,
                "{key_type:?} produced {high}/64 high-S signatures; a peer enforcing \
                 low-S rejects each of them"
            );
        }
    }

    /// A high-S signature must be refused on verify.
    ///
    /// Producing low-S is half the contract. Accepting high-S leaves the
    /// signature malleable in the other direction: anyone holding a valid
    /// signature can derive a second, different byte string that also verifies,
    /// so "the signature over this commit" stops being a unique value.
    #[test]
    fn a_high_s_signature_is_refused() {
        for key_type in [
            KeyType::P256Private,
            KeyType::P384Private,
            KeyType::K256Private,
        ] {
            let key = generate_key(key_type.clone()).expect("key generation should succeed");
            let content = b"content to sign";
            let low = sign(&key, content).expect("signing should succeed");
            assert!(
                validate(&key, &low, content).is_ok(),
                "{key_type:?}: a freshly-signed signature must verify"
            );

            // Take the high-S form of the same signature: still mathematically
            // valid over the same content, just the non-canonical one of the
            // two. Before this fix `sign` returned either form at random, so
            // the flip is conditional rather than unconditional.
            let high = if s_is_high(&low, &key_type) {
                low.clone()
            } else {
                flip_s(&low, &key_type)
            };
            assert!(
                s_is_high(&high, &key_type),
                "{key_type:?}: test setup failed to produce a high-S signature"
            );
            assert!(
                validate(&key, &high, content).is_err(),
                "{key_type:?} accepted a high-S signature, so a signature is not a unique value"
            );
        }
    }

    /// Negate the S component, yielding the other valid form of a signature.
    fn flip_s(signature: &[u8], key_type: &KeyType) -> Vec<u8> {
        match key_type {
            KeyType::P256Private | KeyType::P256Public => {
                let sig = p256::ecdsa::Signature::from_slice(signature).unwrap();
                p256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-sig.s()).to_bytes())
                    .unwrap()
                    .to_vec()
            }
            KeyType::P384Private | KeyType::P384Public => {
                let sig = p384::ecdsa::Signature::from_slice(signature).unwrap();
                p384::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-sig.s()).to_bytes())
                    .unwrap()
                    .to_vec()
            }
            KeyType::K256Private | KeyType::K256Public => {
                let sig = k256::ecdsa::Signature::from_slice(signature).unwrap();
                k256::ecdsa::Signature::from_scalars(sig.r().to_bytes(), (-sig.s()).to_bytes())
                    .unwrap()
                    .to_vec()
            }
            other => panic!("{other:?} is not an ECDSA key type"),
        }
    }
}
