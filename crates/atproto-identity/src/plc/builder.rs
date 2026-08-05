//! Fluent API for creating new did:plc identities.
//!
//! The `DidBuilder` provides a builder pattern for creating did:plc identifiers
//! with rotation keys, verification methods, also-known-as URIs, and service endpoints.
//! It generates the genesis operation, signs it, and derives the DID.

use std::collections::HashMap;

use crate::errors::PLCDIDError;
use crate::key::{self, KeyData};

use super::did::Did;
use super::encoding::{base32_encode, sha256};
use super::operations::{Operation, UnsignedOperation};
use super::state::ServiceEndpoint;

/// Builder for creating new did:plc identifiers.
///
/// Use this to create a new DID by specifying rotation keys, verification methods,
/// also-known-as URIs, and service endpoints. The builder validates all inputs,
/// creates a signed genesis operation, and derives the DID from its hash.
pub struct DidBuilder {
    rotation_keys: Vec<KeyData>,
    verification_methods: HashMap<String, KeyData>,
    also_known_as: Vec<String>,
    services: HashMap<String, ServiceEndpoint>,
    /// Which rotation key signs the genesis op. `None` means the first.
    signing_rotation_key: Option<KeyData>,
}

impl DidBuilder {
    /// Create a new DID builder.
    pub fn new() -> Self {
        Self {
            rotation_keys: Vec::new(),
            verification_methods: HashMap::new(),
            also_known_as: Vec::new(),
            services: HashMap::new(),
            signing_rotation_key: None,
        }
    }

    /// Add a rotation key (1-5 required, no duplicates).
    ///
    /// Rotation keys are used to sign operations and can be used to recover
    /// control of the DID within a 72-hour window. Must be private keys.
    pub fn add_rotation_key(mut self, key_data: KeyData) -> Self {
        self.rotation_keys.push(key_data);
        self
    }

    /// Nominate which key signs the genesis operation.
    ///
    /// Without this, `build` signs with `rotation_keys[0]`, which forces the
    /// highest-authority rotation key to be one the builder holds privately.
    /// That is the wrong constraint when a caller wants to list *someone
    /// else's* key first: PLC gives earlier rotation keys authority over later
    /// ones, so a server issuing an account on a holder's behalf should be able
    /// to put the holder's key above its own -- and it cannot do that if being
    /// first means surrendering the private half.
    ///
    /// PLC requires only that the signature come from *a* listed rotation key,
    /// not the first, so signing with a lower-authority key is valid.
    ///
    /// The nominated key must appear in `rotation_keys` by its public form;
    /// `build` refuses otherwise rather than producing an operation the
    /// directory will reject.
    pub fn sign_with(mut self, key_data: KeyData) -> Self {
        self.signing_rotation_key = Some(key_data);
        self
    }

    /// Add a verification method (max 10).
    ///
    /// Verification methods are cryptographic keys used for authentication
    /// and signing application data (e.g., signing AT Protocol records).
    pub fn add_verification_method(mut self, name: String, key_data: KeyData) -> Self {
        self.verification_methods.insert(name, key_data);
        self
    }

    /// Add an also-known-as URI.
    ///
    /// In ATProto, this is typically the user's handle (e.g., "at://alice.bsky.social").
    pub fn add_also_known_as(mut self, uri: String) -> Self {
        self.also_known_as.push(uri);
        self
    }

    /// Add a service endpoint.
    ///
    /// In ATProto, this is typically the Personal Data Server (PDS).
    pub fn add_service(mut self, name: String, endpoint: ServiceEndpoint) -> Self {
        self.services.insert(name, endpoint);
        self
    }

    /// Build and sign the genesis operation, returning the DID, operation, and keys.
    ///
    /// This method validates all inputs, creates an unsigned genesis operation,
    /// signs it with the first rotation key, and derives the DID from the
    /// signed operation's SHA-256 hash (base32-encoded, first 24 characters).
    pub fn build(self) -> Result<(Did, Operation, BuilderKeys), PLCDIDError> {
        if self.rotation_keys.is_empty() {
            return Err(PLCDIDError::InvalidRotationKeys {
                details: "At least one rotation key is required".to_string(),
            });
        }

        if self.rotation_keys.len() > 5 {
            return Err(PLCDIDError::TooManyEntries {
                field: "rotation_keys".to_string(),
                max: 5,
                actual: self.rotation_keys.len(),
            });
        }

        // Convert keys to did:key format strings.
        //
        // Rotation keys are held privately here because `build` signs the
        // genesis operation with `rotation_keys[0]`, but the operation itself
        // must publish only the PUBLIC form. Formatting the `KeyData` directly
        // emitted the private multicodec (`P256Private` -> 0x1306) followed by
        // the raw 32-byte scalar, so the genesis op carried the account's
        // rotation private key into the PLC directory — a public, permanent,
        // append-only log.
        //
        // A failed conversion is fatal rather than a fallback to `k`: falling
        // back is precisely how the private key would reach the wire.
        let rotation_key_strings: Vec<String> = self
            .rotation_keys
            .iter()
            .map(|k| {
                key::to_public(k)
                    .map(|public_key_data| format!("{}", public_key_data))
                    .map_err(|e| PLCDIDError::InvalidRotationKeys {
                        details: format!("cannot derive the public form of a rotation key: {e}"),
                    })
            })
            .collect::<Result<Vec<String>, PLCDIDError>>()?;

        let verification_method_strings: HashMap<String, String> = self
            .verification_methods
            .iter()
            .map(|(name, key_data)| {
                let public_key_data = key::to_public(key_data).unwrap_or_else(|_| key_data.clone());
                (name.clone(), format!("{}", public_key_data))
            })
            .collect();

        // Validate rotation keys are not duplicated
        let mut seen = std::collections::HashSet::new();
        for key_str in &rotation_key_strings {
            if !seen.insert(key_str) {
                return Err(PLCDIDError::DuplicateEntry {
                    field: "rotation_keys".to_string(),
                    value: key_str.clone(),
                });
            }
        }

        // Validate also-known-as URIs
        for uri in &self.also_known_as {
            if uri.is_empty() {
                return Err(PLCDIDError::InvalidAlsoKnownAs {
                    details: "URI cannot be empty".to_string(),
                });
            }
            if !uri.contains(':') {
                return Err(PLCDIDError::InvalidAlsoKnownAs {
                    details: format!("URI must contain a scheme: {}", uri),
                });
            }
        }

        // Validate services
        for (name, service) in &self.services {
            if name.is_empty() {
                return Err(PLCDIDError::InvalidService {
                    details: "Service name cannot be empty".to_string(),
                });
            }
            service.validate()?;
        }

        // Create unsigned genesis operation
        let unsigned = UnsignedOperation::PlcOperation {
            rotation_keys: rotation_key_strings.clone(),
            verification_methods: verification_method_strings,
            also_known_as: self.also_known_as,
            services: self.services,
            prev: None,
        };

        // Sign with the nominated rotation key, or the first when none was
        // named. The nominee must be listed -- PLC checks the signature against
        // the operation's own `rotationKeys`, so signing with a key that is not
        // there produces an operation the directory refuses.
        let signing_key = match self.signing_rotation_key.as_ref() {
            Some(key) => {
                let nominee = key::to_public(key).map(|k| format!("{k}")).map_err(|e| {
                    PLCDIDError::InvalidRotationKeys {
                        details: format!("cannot derive the public form of the signing key: {e}"),
                    }
                })?;
                if !rotation_key_strings.contains(&nominee) {
                    return Err(PLCDIDError::InvalidRotationKeys {
                        details: "the nominated signing key is not among the rotation keys"
                            .to_string(),
                    });
                }
                key
            }
            None => &self.rotation_keys[0],
        };
        let signed = unsigned.sign(signing_key)?;

        // Derive DID from the signed operation
        let did = Self::derive_did(&signed)?;

        let keys = BuilderKeys {
            rotation_keys: self.rotation_keys,
            verification_methods: self.verification_methods,
        };

        Ok((did, signed, keys))
    }

    /// Derive a DID from a signed genesis operation.
    ///
    /// Per did:plc the identifier is the first 24 characters of the lowercase
    /// base32 encoding of SHA-256 over the **DAG-CBOR** serialization of the
    /// signed genesis operation. JSON and DAG-CBOR are different byte strings,
    /// so hashing the wrong one yields an identifier that no other
    /// implementation derives from the same operation.
    fn derive_did(operation: &Operation) -> Result<Did, PLCDIDError> {
        let serialized =
            atproto_dasl::to_vec(operation).map_err(|e| PLCDIDError::DagCborEncodeFailed {
                details: format!("DAG-CBOR serialization failed: {}", e),
            })?;

        let hash = sha256(&serialized);
        let encoded = base32_encode(&hash);

        let identifier = &encoded[..24.min(encoded.len())];

        Did::from_identifier(identifier)
    }
}

impl Default for DidBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Keys returned from the builder.
///
/// These should be stored securely by the application.
/// Rotation keys can be used to update or recover the DID.
/// Verification methods are used for signing application data.
pub struct BuilderKeys {
    /// Rotation keys (private keys).
    pub rotation_keys: Vec<KeyData>,

    /// Verification method keys (private keys).
    pub verification_methods: HashMap<String, KeyData>,
}

impl BuilderKeys {
    /// Get a rotation key by index.
    pub fn rotation_key(&self, index: usize) -> Option<&KeyData> {
        self.rotation_keys.get(index)
    }

    /// Get a verification method key by name.
    pub fn verification_method(&self, name: &str) -> Option<&KeyData> {
        self.verification_methods.get(name)
    }

    /// Get the primary rotation key (first one).
    pub fn primary_rotation_key(&self) -> Option<&KeyData> {
        self.rotation_key(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{KeyType, generate_key};

    /// A genesis operation must never carry private key material. The operation
    /// is submitted to a PLC directory, which is a public, permanent,
    /// append-only log: a rotation key published in private form hands anyone
    /// who reads the audit log the ability to rotate the DID away from its
    /// owner. `add_rotation_key` takes the private key because `build` signs
    /// with it, so the public conversion has to happen on the way out.
    #[test]
    fn rotation_keys_are_published_in_public_form() {
        for key_type in [KeyType::P256Private, KeyType::K256Private] {
            let rotation_key = generate_key(key_type.clone()).unwrap();
            let expected_public = format!("{}", key::to_public(&rotation_key).unwrap());
            let private_form = format!("{}", rotation_key);

            let (_did, operation, _keys) = DidBuilder::new()
                .add_rotation_key(rotation_key)
                .build()
                .unwrap();

            let Operation::PlcOperation { rotation_keys, .. } = operation else {
                panic!("expected a plc_operation");
            };
            assert_eq!(
                rotation_keys,
                vec![expected_public],
                "{key_type} rotation key was not published in public form"
            );
            assert!(
                !rotation_keys.contains(&private_form),
                "{key_type} private key leaked into the genesis operation"
            );
        }
    }

    /// The identifier must come from the DAG-CBOR encoding of the signed
    /// genesis operation, which is what every other did:plc implementation
    /// hashes. Asserting only "it equals the DAG-CBOR hash" would restate the
    /// implementation, so this also pins the negative: the JSON encoding of the
    /// same operation is a different byte string and must not be what produced
    /// the DID.
    #[test]
    fn did_is_derived_from_dag_cbor_not_json() {
        let rotation_key = generate_key(KeyType::P256Private).unwrap();
        let (did, operation, _keys) = DidBuilder::new()
            .add_rotation_key(rotation_key)
            .add_also_known_as("at://alice.example.com".to_string())
            .build()
            .unwrap();

        let from_cbor = {
            let bytes = atproto_dasl::to_vec(&operation).unwrap();
            let encoded = base32_encode(&sha256(&bytes));
            encoded[..24].to_string()
        };
        let from_json = {
            let bytes = serde_json::to_vec(&operation).unwrap();
            let encoded = base32_encode(&sha256(&bytes));
            encoded[..24].to_string()
        };

        assert_ne!(
            from_cbor, from_json,
            "test is meaningless if the two encodings hash alike"
        );
        assert_eq!(
            did.identifier(),
            from_cbor,
            "DID must hash the DAG-CBOR form"
        );
        assert_ne!(
            did.identifier(),
            from_json,
            "DID was derived from the JSON encoding"
        );
    }

    #[test]
    fn test_builder_basic() {
        let rotation_key = generate_key(KeyType::P256Private).unwrap();

        let (did, operation, keys) = DidBuilder::new()
            .add_rotation_key(rotation_key)
            .build()
            .unwrap();

        assert!(did.as_str().starts_with("did:plc:"));
        assert!(operation.is_genesis());
        assert_eq!(keys.rotation_keys.len(), 1);
    }

    #[test]
    fn test_builder_with_verification_methods() {
        let rotation_key = generate_key(KeyType::P256Private).unwrap();
        let signing_key = generate_key(KeyType::K256Private).unwrap();

        let (did, _, keys) = DidBuilder::new()
            .add_rotation_key(rotation_key)
            .add_verification_method("atproto".into(), signing_key)
            .build()
            .unwrap();

        assert!(did.as_str().starts_with("did:plc:"));
        assert_eq!(keys.verification_methods.len(), 1);
        assert!(keys.verification_method("atproto").is_some());
    }

    #[test]
    fn test_builder_with_services() {
        let rotation_key = generate_key(KeyType::P256Private).unwrap();

        let (did, _, _) = DidBuilder::new()
            .add_rotation_key(rotation_key)
            .add_service(
                "atproto_pds".into(),
                ServiceEndpoint::new(
                    "AtprotoPersonalDataServer".into(),
                    "https://pds.example.com".into(),
                ),
            )
            .build()
            .unwrap();

        assert!(did.as_str().starts_with("did:plc:"));
    }

    #[test]
    fn test_builder_no_rotation_keys() {
        let result = DidBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_too_many_rotation_keys() {
        let mut builder = DidBuilder::new();

        for _ in 0..6 {
            builder = builder.add_rotation_key(generate_key(KeyType::P256Private).unwrap());
        }

        assert!(builder.build().is_err());
    }

    #[test]
    fn test_builder_keys_access() {
        let rotation_key = generate_key(KeyType::P256Private).unwrap();
        let signing_key = generate_key(KeyType::K256Private).unwrap();

        let (_, _, keys) = DidBuilder::new()
            .add_rotation_key(rotation_key)
            .add_verification_method("atproto".into(), signing_key)
            .build()
            .unwrap();

        assert!(keys.primary_rotation_key().is_some());
        assert!(keys.verification_method("atproto").is_some());
        assert!(keys.verification_method("nonexistent").is_none());
    }

    /// A key the builder does not hold privately can still be listed first.
    ///
    /// This is the whole point of `sign_with`: PLC gives earlier rotation keys
    /// authority over later ones, so a server issuing an account for someone
    /// else should be able to put that person's key above its own. Without a
    /// nominated signer, being first would mean surrendering the private half.
    #[test]
    fn the_holders_key_can_rank_above_the_signers() {
        let holder = crate::key::generate_key(crate::key::KeyType::P256Private).unwrap();
        let holder_public = crate::key::to_public(&holder).unwrap();
        let server = crate::key::generate_key(crate::key::KeyType::P256Private).unwrap();
        let signing = crate::key::generate_key(crate::key::KeyType::P256Private).unwrap();

        let (_did, op, _keys) = DidBuilder::new()
            // Only the public form of the holder's key is given to the builder.
            .add_rotation_key(holder_public.clone())
            .add_rotation_key(server.clone())
            .sign_with(server.clone())
            .add_verification_method(
                "atproto".to_string(),
                crate::key::to_public(&signing).unwrap(),
            )
            .add_also_known_as("at://alice.example.com".to_string())
            .build()
            .expect("a genesis op signed by the second rotation key");

        let Operation::PlcOperation { rotation_keys, .. } = &op else {
            panic!("expected a PLC operation")
        };
        assert_eq!(
            rotation_keys[0],
            format!("{holder_public}"),
            "the holder's key must rank first"
        );
        assert_eq!(
            rotation_keys[1],
            format!("{}", crate::key::to_public(&server).unwrap()),
            "the server's key ranks below it"
        );
        // And no private key reached the operation.
        for k in rotation_keys {
            assert!(k.starts_with("did:key:zDna"), "not a P-256 public key: {k}");
        }
    }

    /// Signing with a key that is not listed produces an operation the
    /// directory would refuse, so the builder refuses first.
    #[test]
    fn the_nominated_signer_must_be_a_listed_rotation_key() {
        let listed = crate::key::generate_key(crate::key::KeyType::P256Private).unwrap();
        let stranger = crate::key::generate_key(crate::key::KeyType::P256Private).unwrap();
        let err = DidBuilder::new()
            .add_rotation_key(listed)
            .sign_with(stranger)
            .add_also_known_as("at://alice.example.com".to_string())
            .build()
            .map(|_| ())
            .expect_err("a stranger's signature is not acceptable");
        assert!(
            format!("{err}").contains("not among the rotation keys"),
            "{err}"
        );
    }
}
