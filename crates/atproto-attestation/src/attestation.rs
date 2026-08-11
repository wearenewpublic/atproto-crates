//! Core attestation creation functions.
//!
//! This module provides functions for creating inline and remote attestations
//! and attaching attestation references.

use crate::cid::{create_attestation_cid, create_dagbor_cid};
use crate::errors::AttestationError;
pub use crate::input::AnyInput;
use crate::signature::normalize_signature;
use crate::utils::BASE64;
use atproto_identity::key::{KeyData, KeyResolver, sign, validate};
use atproto_record::lexicon::com::atproto::repo::STRONG_REF_NSID;
use atproto_record::tid::Tid;
use base64::Engine;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::convert::TryInto;

/// Helper function to extract and validate signatures array from a record
fn extract_signatures(record_obj: &Map<String, Value>) -> Result<Vec<Value>, AttestationError> {
    match record_obj.get("signatures") {
        Some(value) => value
            .as_array()
            .ok_or(AttestationError::SignaturesFieldInvalid)
            .cloned(),
        None => Ok(vec![]),
    }
}

/// Helper function to append a signature to a record and return the modified record
fn append_signature_to_record(
    mut record_obj: Map<String, Value>,
    signature: Value,
) -> Result<Value, AttestationError> {
    let mut signatures = extract_signatures(&record_obj)?;
    signatures.push(signature);

    record_obj.insert("signatures".to_string(), Value::Array(signatures));

    Ok(Value::Object(record_obj))
}

/// Creates a cryptographic signature for a record with attestation metadata.
///
/// This is a low-level function that generates just the signature bytes without
/// embedding them in a record structure. It's useful when you need to create
/// signatures independently or for custom attestation workflows.
///
/// The signature is created over a content CID that binds together:
/// - The record content
/// - The attestation metadata
/// - The repository DID (to prevent replay attacks)
///
/// # Arguments
///
/// * `record_input` - The record to sign (as AnyInput: String, Json, or TypedLexicon)
/// * `attestation_input` - The attestation metadata (as AnyInput)
/// * `repository` - The repository DID where this record will be stored
/// * `private_key_data` - The private key to use for signing
///
/// # Returns
///
/// A byte vector containing the normalized ECDSA signature that can be verified
/// against the same content CID.
///
/// # Errors
///
/// Returns an error if:
/// - CID generation fails
/// - Signature creation fails
/// - Signature normalization fails
///
/// # Example
///
/// ```rust
/// use atproto_attestation::{create_signature, input::AnyInput};
/// use atproto_identity::key::{KeyType, generate_key};
/// use serde_json::json;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let private_key = generate_key(KeyType::K256Private)?;
///
/// let record = json!({"$type": "app.bsky.feed.post", "text": "Hello!"});
/// let metadata = json!({"$type": "com.example.signature"});
///
/// let signature_bytes = create_signature(
///     AnyInput::Serialize(record),
///     AnyInput::Serialize(metadata),
///     "did:plc:repo123",
///     &private_key
/// )?;
///
/// // signature_bytes can now be base64-encoded or used as needed
/// # Ok(())
/// # }
/// ```
pub fn create_signature<R, M>(
    record_input: AnyInput<R>,
    attestation_input: AnyInput<M>,
    repository: &str,
    private_key_data: &KeyData,
) -> Result<Vec<u8>, AttestationError>
where
    R: Serialize + Clone,
    M: Serialize + Clone,
{
    // Step 1: Create a content CID from record + attestation + repository
    let content_cid = create_attestation_cid(record_input, attestation_input, repository)?;

    // Step 2: Sign the CID bytes
    let raw_signature = sign(private_key_data, &content_cid.to_bytes())
        .map_err(|error| AttestationError::SignatureCreationFailed { error })?;

    // Step 3: Normalize the signature to ensure consistent format
    normalize_signature(raw_signature, private_key_data.key_type())
}

/// Creates a remote attestation with both the attested record and proof record.
///
/// This is the recommended way to create remote attestations. It generates both:
/// 1. The attested record with a strongRef in the signatures array
/// 2. The proof record containing the CID to be stored in the attestation repository
///
/// The CID is generated with the repository DID included in the `$sig` metadata
/// to bind the attestation to a specific repository and prevent replay attacks.
///
/// # Arguments
///
/// * `record_input` - The record to attest (as AnyInput: String, Json, or TypedLexicon)
/// * `metadata_input` - The attestation metadata (must include `$type`)
/// * `repository` - The DID of the repository housing the original record
/// * `attestation_repository` - The DID of the repository that will store the proof record
///
/// # Returns
///
/// A tuple containing:
/// * `(attested_record, proof_record)` - Both records needed for remote attestation
///
/// # Errors
///
/// Returns an error if:
/// - The record or metadata are not valid JSON objects
/// - The metadata is missing the required `$type` field
/// - CID generation fails
///
/// # Example
///
/// ```rust
/// use atproto_attestation::{create_remote_attestation, input::AnyInput};
/// use serde_json::json;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let record = json!({"$type": "app.bsky.feed.post", "text": "Hello!"});
/// let metadata = json!({"$type": "com.example.attestation"});
///
/// let (attested_record, proof_record) = create_remote_attestation(
///     AnyInput::Serialize(record),
///     AnyInput::Serialize(metadata),
///     "did:plc:repo123",      // Source repository
///     "did:plc:attestor456"   // Attestation repository
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn create_remote_attestation<R: Serialize + Clone, M: Serialize + Clone>(
    record_input: AnyInput<R>,
    metadata_input: AnyInput<M>,
    repository: &str,
    attestation_repository: &str,
) -> Result<(Value, Value), AttestationError> {
    // Step 1: Create a content CID
    let content_cid =
        create_attestation_cid(record_input.clone(), metadata_input.clone(), repository)?;

    let record_obj: Map<String, Value> = record_input
        .try_into()
        .map_err(|_| AttestationError::RecordMustBeObject)?;

    // Step 2: Create the remote attestation record
    let (remote_attestation_record, remote_attestation_type) = {
        let mut metadata_obj: Map<String, Value> = metadata_input
            .try_into()
            .map_err(|_| AttestationError::MetadataMustBeObject)?;

        // Extract the type from metadata before modifying it
        let remote_type = metadata_obj
            .get("$type")
            .and_then(Value::as_str)
            .ok_or(AttestationError::MetadataMissingType)?
            .to_string();

        metadata_obj.insert("cid".to_string(), Value::String(content_cid.to_string()));
        (serde_json::Value::Object(metadata_obj), remote_type)
    };

    // Step 3: Create the remote attestation reference (type, AT-URI, and CID)
    let remote_attestation_record_key = Tid::new();
    let remote_attestation_cid = create_dagbor_cid(&remote_attestation_record)?;

    let attestation_reference = json!({
        "$type": STRONG_REF_NSID,
        "uri": format!("at://{attestation_repository}/{remote_attestation_type}/{remote_attestation_record_key}"),
        "cid": remote_attestation_cid.to_string()
    });

    // Step 4: Append the attestation reference to the record "signatures" array
    let attested_record = append_signature_to_record(record_obj, attestation_reference)?;

    Ok((attested_record, remote_attestation_record))
}

/// Creates an inline attestation with signature embedded in the record.
///
/// This is the v2 API that supports flexible input types (String, Json, TypedLexicon)
/// and provides a more streamlined interface for creating inline attestations.
///
/// The CID is generated with the repository DID included in the `$sig` metadata
/// to bind the attestation to a specific repository and prevent replay attacks.
///
/// # Arguments
///
/// * `record_input` - The record to sign (as AnyInput: String, Json, or TypedLexicon)
/// * `metadata_input` - The attestation metadata (must include `$type` and `key`)
/// * `repository` - The DID of the repository that will house this record
/// * `private_key_data` - The private key to use for signing
///
/// # Returns
///
/// The record with an inline attestation embedded in the signatures array
///
/// # Errors
///
/// Returns an error if:
/// - The record or metadata are not valid JSON objects
/// - The metadata is missing required fields
/// - Signature creation fails
/// - CID generation fails
///
/// # Example
///
/// ```rust
/// use atproto_attestation::{create_inline_attestation, input::AnyInput};
/// use atproto_identity::key::{KeyType, generate_key, to_public};
/// use serde_json::json;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let private_key = generate_key(KeyType::K256Private)?;
/// let public_key = to_public(&private_key)?;
///
/// let record = json!({"$type": "app.bsky.feed.post", "text": "Hello!"});
/// let metadata = json!({
///     "$type": "com.example.signature",
///     "key": format!("{}", public_key)
/// });
///
/// let signed_record = create_inline_attestation(
///     AnyInput::Serialize(record),
///     AnyInput::Serialize(metadata),
///     "did:plc:repo123",
///     &private_key
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn create_inline_attestation<R: Serialize + Clone, M: Serialize + Clone>(
    record_input: AnyInput<R>,
    metadata_input: AnyInput<M>,
    repository: &str,
    private_key_data: &KeyData,
) -> Result<Value, AttestationError> {
    // Step 1: Create a content CID
    let content_cid =
        create_attestation_cid(record_input.clone(), metadata_input.clone(), repository)?;

    let record_obj: Map<String, Value> = record_input
        .try_into()
        .map_err(|_| AttestationError::RecordMustBeObject)?;

    // Step 2: Create the inline attestation record
    let inline_attestation_record = {
        let mut metadata_obj: Map<String, Value> = metadata_input
            .try_into()
            .map_err(|_| AttestationError::MetadataMustBeObject)?;

        metadata_obj.insert("cid".to_string(), Value::String(content_cid.to_string()));

        let raw_signature = sign(private_key_data, &content_cid.to_bytes())
            .map_err(|error| AttestationError::SignatureCreationFailed { error })?;
        let signature_bytes = normalize_signature(raw_signature, private_key_data.key_type())?;

        metadata_obj.insert(
            "signature".to_string(),
            json!({"$bytes": BASE64.encode(signature_bytes)}),
        );

        serde_json::Value::Object(metadata_obj)
    };

    // Step 4: Append the attestation reference to the record "signatures" array
    append_signature_to_record(record_obj, inline_attestation_record)
}

/// Validates an existing proof record and appends a strongRef to it in the record's signatures array.
///
/// This function validates that an existing proof record (attestation metadata with CID)
/// is valid for the given record and repository, then creates and appends a strongRef to it.
///
/// Unlike `create_remote_attestation` which creates a new proof record, this function validates
/// an existing proof record that was already created and stored in an attestor's repository.
///
/// # Security
///
/// - **Repository binding validation**: Ensures the attestation was created for the specified repository DID
/// - **CID verification**: Validates the proof record's CID matches the computed CID
/// - **Content validation**: Ensures the proof record content matches what should be attested
///
/// # Workflow
///
/// 1. Compute the content CID from record + metadata + repository (same as attestation creation)
/// 2. Extract the claimed CID from the proof record metadata
/// 3. Verify the claimed CID matches the computed CID
/// 4. Extract the proof record's storage CID (DAG-CBOR CID of the full proof record)
/// 5. Create a strongRef with the AT-URI and proof record CID
/// 6. Append the strongRef to the record's signatures array
///
/// # Arguments
///
/// * `record_input` - The record to append the attestation to (as AnyInput)
/// * `metadata_input` - The proof record metadata (must include `$type`, `cid`, and attestation fields)
/// * `repository` - The repository DID where the source record is stored (for replay attack prevention)
/// * `attestation_uri` - The AT-URI where the proof record is stored (e.g., "at://did:plc:attestor/com.example.attestation/abc123")
///
/// # Returns
///
/// The modified record with the strongRef appended to its `signatures` array
///
/// # Errors
///
/// Returns an error if:
/// - The record or metadata are not valid JSON objects
/// - The metadata is missing the `cid` field
/// - The computed CID doesn't match the claimed CID in the metadata
/// - The metadata is missing required attestation fields
///
/// # Type Parameters
///
/// * `R` - The record type (must implement Serialize + LexiconType + PartialEq + Clone)
/// * `A` - The attestation type (must implement Serialize + LexiconType + PartialEq + Clone)
///
/// # Example
///
/// ```ignore
/// use atproto_attestation::{append_remote_attestation, input::AnyInput};
/// use serde_json::json;
///
/// let record = json!({
///     "$type": "app.bsky.feed.post",
///     "text": "Hello world!"
/// });
///
/// // This is the proof record that was previously created and stored
/// let proof_metadata = json!({
///     "$type": "com.example.attestation",
///     "issuer": "did:plc:issuer",
///     "cid": "bafyrei...",  // Content CID computed from record+metadata+repository
///     // .. other attestation fields
/// });
///
/// let repository_did = "did:plc:repo123";
/// let attestation_uri = "at://did:plc:attestor456/com.example.attestation/abc123";
///
/// let signed_record = append_remote_attestation(
///     AnyInput::Serialize(record),
///     AnyInput::Serialize(proof_metadata),
///     repository_did,
///     attestation_uri
/// )?;
/// ```
pub fn append_remote_attestation<R, A>(
    record_input: AnyInput<R>,
    metadata_input: AnyInput<A>,
    repository: &str,
    attestation_uri: &str,
) -> Result<Value, AttestationError>
where
    R: Serialize + Clone,
    A: Serialize + Clone,
{
    // Step 1: Compute the content CID (same as create_remote_attestation)
    let content_cid =
        create_attestation_cid(record_input.clone(), metadata_input.clone(), repository)?;

    // Step 2: Convert metadata to JSON and extract the claimed CID
    let metadata_obj: Map<String, Value> = metadata_input
        .try_into()
        .map_err(|_| AttestationError::MetadataMustBeObject)?;

    let claimed_cid = metadata_obj
        .get("cid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AttestationError::SignatureMissingField {
            field: "cid".to_string(),
        })?;

    // Step 3: Verify the claimed CID matches the computed content CID
    if content_cid.to_string() != claimed_cid {
        return Err(AttestationError::RemoteAttestationCidMismatch {
            expected: claimed_cid.to_string(),
            actual: content_cid.to_string(),
        });
    }

    // Step 4: Compute the proof record's DAG-CBOR CID
    let proof_record_cid = create_dagbor_cid(&metadata_obj)?;

    // Step 5: Create the strongRef
    let strongref = json!({
        "$type": STRONG_REF_NSID,
        "uri": attestation_uri,
        "cid": proof_record_cid.to_string()
    });

    // Step 6: Convert record to JSON object and append the strongRef
    let record_obj: Map<String, Value> = record_input
        .try_into()
        .map_err(|_| AttestationError::RecordMustBeObject)?;

    append_signature_to_record(record_obj, strongref)
}

/// Validates an inline attestation and appends it to a record's signatures array.
///
/// Inline attestations contain cryptographic signatures embedded directly in the record.
/// This function validates the attestation signature against the record and repository,
/// then appends it if validation succeeds.
///
/// # Security
///
/// - **Repository binding validation**: Ensures the attestation was created for the specified repository DID
/// - **CID verification**: Validates the CID in the attestation matches the computed CID
/// - **Signature verification**: Cryptographically verifies the ECDSA signature
/// - **Key resolution**: Resolves and validates the verification key
///
/// # Arguments
///
/// * `record_input` - The record to append the attestation to (as AnyInput)
/// * `attestation_input` - The inline attestation to validate and append (as AnyInput)
/// * `repository` - The repository DID where this record is stored (for replay attack prevention)
/// * `key_resolver` - Resolver for looking up verification keys from DIDs
///
/// # Returns
///
/// The modified record with the validated attestation appended to its `signatures` array
///
/// # Errors
///
/// Returns an error if:
/// - The record or attestation are not valid JSON objects
/// - The attestation is missing required fields (`$type`, `key`, `cid`, `signature`)
/// - The attestation CID doesn't match the computed CID for the record
/// - The signature bytes are invalid or not base64-encoded
/// - Signature verification fails
/// - Key resolution fails
///
/// # Type Parameters
///
/// * `R` - The record type (must implement Serialize + LexiconType + PartialEq + Clone)
/// * `A` - The attestation type (must implement Serialize + LexiconType + PartialEq + Clone)
/// * `KR` - The key resolver type (must implement KeyResolver)
///
/// # Example
///
/// ```ignore
/// use atproto_attestation::{append_inline_attestation, input::AnyInput};
/// use serde_json::json;
///
/// let record = json!({
///     "$type": "app.bsky.feed.post",
///     "text": "Hello world!"
/// });
///
/// let attestation = json!({
///     "$type": "com.example.inlineSignature",
///     "key": "did:key:zQ3sh...",
///     "cid": "bafyrei...",
///     "signature": {"$bytes": "base64-signature-bytes"}
/// });
///
/// let repository_did = "did:plc:repo123";
/// let key_resolver = /* your KeyResolver implementation */;
///
/// let signed_record = append_inline_attestation(
///     AnyInput::Serialize(record),
///     AnyInput::Serialize(attestation),
///     repository_did,
///     key_resolver
/// ).await?;
/// ```
pub async fn append_inline_attestation<R, A, KR>(
    record_input: AnyInput<R>,
    attestation_input: AnyInput<A>,
    repository: &str,
    key_resolver: KR,
) -> Result<Value, AttestationError>
where
    R: Serialize + Clone,
    A: Serialize + Clone,
    KR: KeyResolver,
{
    // Step 1: Create a content CID
    let content_cid =
        create_attestation_cid(record_input.clone(), attestation_input.clone(), repository)?;

    let record_obj: Map<String, Value> = record_input
        .try_into()
        .map_err(|_| AttestationError::RecordMustBeObject)?;

    let attestation_obj: Map<String, Value> = attestation_input
        .try_into()
        .map_err(|_| AttestationError::MetadataMustBeObject)?;

    let key = attestation_obj
        .get("key")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AttestationError::SignatureMissingField {
            field: "key".to_string(),
        })?;
    let key_data =
        key_resolver
            .resolve(key)
            .await
            .map_err(|error| AttestationError::KeyResolutionFailed {
                key: key.to_string(),
                error,
            })?;

    let signature_bytes = attestation_obj
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|object| object.get("$bytes"))
        .and_then(Value::as_str)
        .ok_or(AttestationError::SignatureBytesFormatInvalid)?;

    let signature_bytes = BASE64
        .decode(signature_bytes)
        .map_err(|error| AttestationError::SignatureDecodingFailed { error })?;

    let computed_cid_bytes = content_cid.to_bytes();

    validate(&key_data, &signature_bytes, &computed_cid_bytes)
        .map_err(|error| AttestationError::SignatureValidationFailed { error })?;

    // Step 6: Append the validated attestation to the signatures array
    append_signature_to_record(record_obj, json!(attestation_obj))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::{KeyType, generate_key, to_public};
    use serde_json::json;

    #[test]
    fn create_remote_attestation_produces_both_records() -> Result<(), Box<dyn std::error::Error>> {
        let record = json!({
            "$type": "app.example.record",
            "body": "remote attestation"
        });

        let metadata = json!({
            "$type": "com.example.attestation"
        });

        let source_repository = "did:plc:test";
        let attestation_repository = "did:plc:attestor";

        let (attested_record, proof_record) = create_remote_attestation(
            AnyInput::Serialize(record.clone()),
            AnyInput::Serialize(metadata),
            source_repository,
            attestation_repository,
        )?;

        // Verify proof record structure
        let proof_object = proof_record.as_object().expect("proof should be an object");
        assert_eq!(
            proof_object.get("$type").and_then(Value::as_str),
            Some("com.example.attestation")
        );
        assert!(
            proof_object.get("cid").and_then(Value::as_str).is_some(),
            "proof must contain a cid"
        );
        assert!(
            proof_object.get("repository").is_none(),
            "repository should not be in final proof record"
        );

        // Verify attested record has strongRef
        let attested_object = attested_record
            .as_object()
            .expect("attested record should be an object");
        let signatures = attested_object
            .get("signatures")
            .and_then(Value::as_array)
            .expect("attested record should have signatures array");
        assert_eq!(signatures.len(), 1, "should have one signature");

        let signature = &signatures[0];
        assert_eq!(
            signature.get("$type").and_then(Value::as_str),
            Some("com.atproto.repo.strongRef"),
            "signature should be a strongRef"
        );
        assert!(
            signature.get("uri").and_then(Value::as_str).is_some(),
            "strongRef must contain a uri"
        );
        assert!(
            signature.get("cid").and_then(Value::as_str).is_some(),
            "strongRef must contain a cid"
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_inline_attestation_full_workflow() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = generate_key(KeyType::K256Private)?;
        let public_key = to_public(&private_key)?;
        let key_reference = format!("{}", public_key);
        let repository_did = "did:plc:testrepository123";

        let base_record = json!({
            "$type": "app.example.record",
            "body": "Sign me"
        });

        let sig_metadata = json!({
            "$type": "com.example.inlineSignature",
            "key": key_reference,
            "purpose": "unit-test"
        });

        let signed = create_inline_attestation(
            AnyInput::Serialize(base_record),
            AnyInput::Serialize(sig_metadata),
            repository_did,
            &private_key,
        )?;

        // Verify structure
        let signatures = signed
            .get("signatures")
            .and_then(Value::as_array)
            .expect("should have signatures array");
        assert_eq!(signatures.len(), 1);

        let sig = &signatures[0];
        assert_eq!(
            sig.get("$type").and_then(Value::as_str),
            Some("com.example.inlineSignature")
        );
        assert!(sig.get("signature").is_some());
        assert!(sig.get("key").is_some());
        assert!(sig.get("repository").is_none()); // Should not be in final signature

        Ok(())
    }

    #[test]
    fn create_signature_returns_valid_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = generate_key(KeyType::K256Private)?;
        let public_key = to_public(&private_key)?;

        let record = json!({
            "$type": "app.example.record",
            "body": "Test signature creation"
        });

        let metadata = json!({
            "$type": "com.example.signature",
            "key": format!("{}", public_key)
        });

        let repository = "did:plc:test123";

        // Create signature
        let signature_bytes = create_signature(
            AnyInput::Serialize(record.clone()),
            AnyInput::Serialize(metadata.clone()),
            repository,
            &private_key,
        )?;

        // Verify signature is not empty
        assert!(
            !signature_bytes.is_empty(),
            "Signature bytes should not be empty"
        );

        // Verify signature length is reasonable for ECDSA (typically 64-72 bytes for secp256k1)
        assert!(
            signature_bytes.len() >= 64 && signature_bytes.len() <= 73,
            "Signature length should be between 64 and 73 bytes, got {}",
            signature_bytes.len()
        );

        // Verify we can validate the signature
        let content_cid = create_attestation_cid(
            AnyInput::Serialize(record),
            AnyInput::Serialize(metadata),
            repository,
        )?;

        validate(&public_key, &signature_bytes, &content_cid.to_bytes())?;

        Ok(())
    }

    #[test]
    fn create_signature_different_inputs_produce_different_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let private_key = generate_key(KeyType::K256Private)?;

        let record1 = json!({"$type": "app.example.record", "body": "First message"});
        let record2 = json!({"$type": "app.example.record", "body": "Second message"});
        let metadata = json!({"$type": "com.example.signature"});
        let repository = "did:plc:test123";

        let sig1 = create_signature(
            AnyInput::Serialize(record1),
            AnyInput::Serialize(metadata.clone()),
            repository,
            &private_key,
        )?;

        let sig2 = create_signature(
            AnyInput::Serialize(record2),
            AnyInput::Serialize(metadata),
            repository,
            &private_key,
        )?;

        assert_ne!(
            sig1, sig2,
            "Different records should produce different signatures"
        );

        Ok(())
    }

    #[test]
    fn create_signature_different_repositories_produce_different_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let private_key = generate_key(KeyType::K256Private)?;

        let record = json!({"$type": "app.example.record", "body": "Message"});
        let metadata = json!({"$type": "com.example.signature"});

        let sig1 = create_signature(
            AnyInput::Serialize(record.clone()),
            AnyInput::Serialize(metadata.clone()),
            "did:plc:repo1",
            &private_key,
        )?;

        let sig2 = create_signature(
            AnyInput::Serialize(record),
            AnyInput::Serialize(metadata),
            "did:plc:repo2",
            &private_key,
        )?;

        assert_ne!(
            sig1, sig2,
            "Different repository DIDs should produce different signatures"
        );

        Ok(())
    }
}
