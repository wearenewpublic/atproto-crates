//! Data structures for DID documents and AT Protocol entities.
//!
//! Core data models for AT Protocol identity including DID documents, services,
//! and verification methods with full JSON serialization support.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// AT Protocol service configuration from a DID document.
/// Represents services like Personal Data Servers (PDS).
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Unique identifier for the service.
    pub id: String,
    /// Service type (e.g., "AtprotoPersonalDataServer").
    pub r#type: String,
    /// URL endpoint where the service can be reached.
    pub service_endpoint: String,

    /// Additional service properties not explicitly defined.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Cryptographic verification method from a DID document.
/// Used to verify signatures and authenticate identity operations.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum VerificationMethod {
    /// Multikey verification method with multibase-encoded public key.
    Multikey {
        /// Unique identifier for this verification method.
        id: String,
        /// DID that controls this verification method.
        controller: String,

        /// Public key encoded in multibase format.
        #[serde(rename = "publicKeyMultibase")]
        public_key_multibase: String,

        /// Additional verification method properties.
        #[serde(flatten)]
        extra: HashMap<String, Value>,
    },

    /// Other verification method types not explicitly supported.
    #[serde(untagged)]
    Other {
        /// All properties of the unsupported verification method.
        #[serde(flatten)]
        extra: HashMap<String, Value>,
    },
}

/// Complete DID document containing identity information.
/// Contains services, verification methods, and aliases for a DID.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// JSON-LD context URLs defining the semantics of the DID document.
    /// Typically includes "<https://www.w3.org/ns/did/v1>" and method-specific contexts.
    #[serde(rename = "@context", default)]
    pub context: Vec<String>,

    /// The DID identifier (e.g., "did:plc:abc123").
    pub id: String,
    /// Alternative identifiers like handles and domains.
    #[serde(default)]
    pub also_known_as: Vec<String>,
    /// Available services for this identity.
    #[serde(default)]
    pub service: Vec<Service>,

    /// Cryptographic verification methods.
    #[serde(alias = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,

    /// Additional document properties not explicitly defined.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Builder for constructing DID documents with a fluent API.
/// Provides controlled construction with validation capabilities.
#[derive(Default)]
pub struct DocumentBuilder {
    context: Option<Vec<String>>,
    id: Option<String>,
    also_known_as: Vec<String>,
    service: Vec<Service>,
    verification_method: Vec<VerificationMethod>,
    extra: HashMap<String, Value>,
}

impl DocumentBuilder {
    /// Creates a new DocumentBuilder with empty fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the JSON-LD context URLs for the document.
    pub fn context(mut self, context: Vec<String>) -> Self {
        self.context = Some(context);
        self
    }

    /// Adds a single context URL to the document.
    pub fn add_context(mut self, context_url: impl Into<String>) -> Self {
        self.context
            .get_or_insert_with(|| vec!["https://www.w3.org/ns/did/v1".to_string()])
            .push(context_url.into());
        self
    }

    /// Sets the DID identifier for the document.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets all alternative identifiers at once.
    pub fn also_known_as(mut self, aliases: Vec<String>) -> Self {
        self.also_known_as = aliases;
        self
    }

    /// Adds a single alternative identifier.
    pub fn add_also_known_as(mut self, alias: impl Into<String>) -> Self {
        self.also_known_as.push(alias.into());
        self
    }

    /// Sets all services at once.
    pub fn services(mut self, services: Vec<Service>) -> Self {
        self.service = services;
        self
    }

    /// Adds a single service to the document.
    pub fn add_service(mut self, service: Service) -> Self {
        self.service.push(service);
        self
    }

    /// Convenience method to add a PDS service.
    pub fn add_pds_service(mut self, endpoint: impl Into<String>) -> Self {
        self.service.push(Service {
            id: "#atproto_pds".to_string(),
            r#type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: endpoint.into(),
            extra: HashMap::new(),
        });
        self
    }

    /// Sets all verification methods at once.
    pub fn verification_methods(mut self, methods: Vec<VerificationMethod>) -> Self {
        self.verification_method = methods;
        self
    }

    /// Adds a single verification method.
    pub fn add_verification_method(mut self, method: VerificationMethod) -> Self {
        self.verification_method.push(method);
        self
    }

    /// Convenience method to add a Multikey verification method.
    pub fn add_multikey(
        mut self,
        id: impl Into<String>,
        controller: impl Into<String>,
        public_key_multibase: impl Into<String>,
    ) -> Self {
        let key_multibase = public_key_multibase.into();
        let key_multibase = key_multibase
            .strip_prefix("did:key:")
            .unwrap_or(&key_multibase)
            .to_string();

        self.verification_method.push(VerificationMethod::Multikey {
            id: id.into(),
            controller: controller.into(),
            public_key_multibase: key_multibase,
            extra: HashMap::new(),
        });
        self
    }

    /// Adds an extra property to the document.
    pub fn add_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Builds the Document, returning an error if required fields are missing.
    pub fn build(self) -> Result<Document, &'static str> {
        let id = self.id.ok_or("Document ID is required")?;

        // Use default context if not provided
        let context = self
            .context
            .unwrap_or_else(|| vec!["https://www.w3.org/ns/did/v1".to_string()]);

        Ok(Document {
            context,
            id,
            also_known_as: self.also_known_as,
            service: self.service,
            verification_method: self.verification_method,
            extra: self.extra,
        })
    }
}

impl Document {
    /// Creates a new DocumentBuilder for constructing a Document.
    pub fn builder() -> DocumentBuilder {
        DocumentBuilder::new()
    }

    /// Extracts Personal Data Server endpoints from services.
    /// Returns URLs of all AtprotoPersonalDataServer services.
    pub fn pds_endpoints(&self) -> Vec<&str> {
        self.service
            .iter()
            .filter_map(|service| {
                if service.r#type == "AtprotoPersonalDataServer" {
                    Some(service.service_endpoint.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Gets the primary handle from alsoKnownAs aliases.
    /// Returns the first alias with "at://" prefix stripped if present.
    pub fn handles(&self) -> Option<&str> {
        self.also_known_as.first().map(|handle| {
            if let Some(trimmed) = handle.strip_prefix("at://") {
                trimmed
            } else {
                handle.as_str()
            }
        })
    }

    /// Extracts multibase public keys from verification methods.
    /// Returns public keys from Multikey verification methods only.
    pub fn did_keys(&self) -> Vec<&str> {
        self.verification_method
            .iter()
            .filter_map(|verification_method| match verification_method {
                VerificationMethod::Multikey {
                    public_key_multibase,
                    ..
                } => Some(public_key_multibase.as_str()),
                VerificationMethod::Other { extra: _ } => None,
            })
            .collect()
    }
}

/// Resolved handle information linking DID to human-readable identifier.
/// Contains the complete identity resolution result.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Deserialize, Serialize)]
pub struct Handle {
    /// The resolved DID identifier.
    pub did: String,
    /// Human-readable handle (e.g., "alice.bsky.social").
    pub handle: String,
    /// Personal Data Server URL hosting the identity.
    pub pds: String,
    /// Available cryptographic verification methods.
    pub verification_methods: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::model::{Document, Service};
    use std::collections::HashMap;

    #[test]
    fn test_deserialize() {
        let document = serde_json::from_str::<Document>(
            r##"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1","https://w3id.org/security/suites/secp256k1-2019/v1"],"id":"did:plc:cbkjy5n7bk3ax2wplmtjofq2","alsoKnownAs":["at://ngerakines.me","at://nick.gerakines.net","at://nick.thegem.city","https://github.com/ngerakines","https://ngerakines.me/","dns:ngerakines.me"],"verificationMethod":[{"id":"did:plc:cbkjy5n7bk3ax2wplmtjofq2#atproto","type":"Multikey","controller":"did:plc:cbkjy5n7bk3ax2wplmtjofq2","publicKeyMultibase":"zQ3shXvCK2RyPrSLYQjBEw5CExZkUhJH3n1K2Mb9sC7JbvRMF"}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.cauda.cloud"}]}"##,
        );
        assert!(document.is_ok());

        let document = document.unwrap();
        assert_eq!(document.id, "did:plc:cbkjy5n7bk3ax2wplmtjofq2");
    }

    #[test]
    fn test_document_builder() {
        // Test basic builder
        let doc = Document::builder()
            .id("did:plc:test123")
            .build()
            .expect("Should build with just ID");

        assert_eq!(doc.id, "did:plc:test123");
        assert_eq!(doc.context, vec!["https://www.w3.org/ns/did/v1"]);
        assert!(doc.also_known_as.is_empty());
        assert!(doc.service.is_empty());
        assert!(doc.verification_method.is_empty());
    }

    #[test]
    fn test_document_builder_full() {
        let doc = Document::builder()
            .id("did:plc:test123")
            .add_context("https://w3id.org/security/multikey/v1")
            .add_also_known_as("at://test.bsky.social")
            .add_also_known_as("https://test.example.com")
            .add_pds_service("https://pds.example.com")
            .add_multikey(
                "did:plc:test123#atproto",
                "did:plc:test123",
                "zQ3shXvCK2RyPrSLYQjBEw5CExZkUhJH3n1K2Mb9sC7JbvRMF",
            )
            .build()
            .expect("Should build complete document");

        assert_eq!(doc.id, "did:plc:test123");
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.also_known_as.len(), 2);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].r#type, "AtprotoPersonalDataServer");
        assert_eq!(doc.verification_method.len(), 1);

        // Test PDS endpoint extraction
        let pds_endpoints = doc.pds_endpoints();
        assert_eq!(pds_endpoints.len(), 1);
        assert_eq!(pds_endpoints[0], "https://pds.example.com");
    }

    #[test]
    fn test_document_builder_with_service() {
        let service = Service {
            id: "#custom".to_string(),
            r#type: "CustomService".to_string(),
            service_endpoint: "https://custom.example.com".to_string(),
            extra: HashMap::new(),
        };

        let doc = Document::builder()
            .id("did:web:example.com")
            .add_service(service)
            .build()
            .expect("Should build with custom service");

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].r#type, "CustomService");
    }

    #[test]
    fn test_document_builder_missing_id() {
        let result = Document::builder()
            .add_also_known_as("at://test.bsky.social")
            .build();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Document ID is required");
    }

    #[test]
    fn test_document_builder_with_extra() {
        let doc = Document::builder()
            .id("did:plc:test123")
            .add_extra("customField", serde_json::json!("customValue"))
            .add_extra("numberField", serde_json::json!(42))
            .build()
            .expect("Should build with extra fields");

        assert_eq!(doc.extra.len(), 2);
        assert_eq!(
            doc.extra.get("customField").unwrap(),
            &serde_json::json!("customValue")
        );
        assert_eq!(
            doc.extra.get("numberField").unwrap(),
            &serde_json::json!(42)
        );
    }

    #[test]
    fn test_deserialize_unsupported_verification_method() {
        let documents = vec![
            r##"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1","https://w3id.org/security/suites/secp256k1-2019/v1"],"id":"did:plc:cbkjy5n7bk3ax2wplmtjofq2","alsoKnownAs":["at://ngerakines.me","at://nick.gerakines.net","at://nick.thegem.city","https://github.com/ngerakines","https://ngerakines.me/","dns:ngerakines.me"],"verificationMethod":[{"id":"did:plc:cbkjy5n7bk3ax2wplmtjofq2#atproto","type":"Ed25519VerificationKey2020","controller":"did:plc:cbkjy5n7bk3ax2wplmtjofq2","publicKeyMultibase":"zQ3shXvCK2RyPrSLYQjBEw5CExZkUhJH3n1K2Mb9sC7JbvRMF"}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.cauda.cloud"}]}"##,
            r##"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1","https://w3id.org/security/suites/secp256k1-2019/v1"],"id":"did:plc:cbkjy5n7bk3ax2wplmtjofq2","alsoKnownAs":["at://ngerakines.me","at://nick.gerakines.net","at://nick.thegem.city","https://github.com/ngerakines","https://ngerakines.me/","dns:ngerakines.me"],"verificationMethod":[{"id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A","type": "JsonWebKey2020","controller": "did:example:123","publicKeyJwk": {"crv": "Ed25519","x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ","kty": "OKP","kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"}}],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.cauda.cloud"}]}"##,
        ];
        for document in documents {
            let document = serde_json::from_str::<Document>(document);
            assert!(document.is_ok());

            let document = document.unwrap();
            assert_eq!(document.id, "did:plc:cbkjy5n7bk3ax2wplmtjofq2");
        }
    }

    #[test]
    fn test_deserialize_service_did_document() {
        // DID document from api.bsky.app - a service DID without alsoKnownAs
        let document = serde_json::from_str::<Document>(
            r##"{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:web:api.bsky.app","verificationMethod":[{"id":"did:web:api.bsky.app#atproto","type":"Multikey","controller":"did:web:api.bsky.app","publicKeyMultibase":"zQ3shpRzb2NDriwCSSsce6EqGxG23kVktHZc57C3NEcuNy1jg"}],"service":[{"id":"#bsky_notif","type":"BskyNotificationService","serviceEndpoint":"https://api.bsky.app"},{"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://api.bsky.app"}]}"##,
        );
        assert!(document.is_ok(), "Failed to parse: {:?}", document.err());

        let document = document.unwrap();
        assert_eq!(document.id, "did:web:api.bsky.app");
        assert!(document.also_known_as.is_empty());
        assert_eq!(document.service.len(), 2);
        assert_eq!(document.service[0].id, "#bsky_notif");
        assert_eq!(document.service[1].id, "#bsky_appview");
    }
}
