//! Schema type definitions for ATProtocol lexicons
//!
//! This module defines all the schema types used in ATProtocol lexicons.
//! See: <https://atproto.com/specs/lexicon>

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// A schema definition - the main entry point for lexicon types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SchemaDef {
    /// Record schema (main type for stored records)
    Record(RecordSchema),
    /// Query schema (HTTP GET endpoint)
    Query(QuerySchema),
    /// Procedure schema (HTTP POST endpoint)
    Procedure(ProcedureSchema),
    /// Subscription schema (WebSocket stream)
    Subscription(SubscriptionSchema),
    /// Permission set
    #[serde(rename = "permission-set")]
    PermissionSet(PermissionSetSchema),
    /// Space (permissioned-data space type definition)
    Space(SpaceSchema),
    /// Boolean type
    Boolean(BooleanSchema),
    /// Integer type
    Integer(IntegerSchema),
    /// String type
    String(StringSchema),
    /// Bytes type (base64 encoded)
    Bytes(BytesSchema),
    /// CID link type
    #[serde(rename = "cid-link")]
    CidLink(CidLinkSchema),
    /// Array type
    Array(ArraySchema),
    /// Object type
    Object(ObjectSchema),
    /// Blob type (file reference)
    Blob(BlobSchema),
    /// Params type (query parameters)
    Params(ParamsSchema),
    /// Reference to another type
    Ref(RefSchema),
    /// Union of types
    Union(UnionSchema),
    /// Unknown type (accepts any value)
    Unknown(UnknownSchema),
    /// Token type (constant string)
    Token(TokenSchema),
}

impl SchemaDef {
    /// Get the type name
    pub fn type_name(&self) -> &'static str {
        match self {
            SchemaDef::Record(_) => "record",
            SchemaDef::Query(_) => "query",
            SchemaDef::Procedure(_) => "procedure",
            SchemaDef::Subscription(_) => "subscription",
            SchemaDef::PermissionSet(_) => "permission-set",
            SchemaDef::Space(_) => "space",
            SchemaDef::Boolean(_) => "boolean",
            SchemaDef::Integer(_) => "integer",
            SchemaDef::String(_) => "string",
            SchemaDef::Bytes(_) => "bytes",
            SchemaDef::CidLink(_) => "cid-link",
            SchemaDef::Array(_) => "array",
            SchemaDef::Object(_) => "object",
            SchemaDef::Blob(_) => "blob",
            SchemaDef::Params(_) => "params",
            SchemaDef::Ref(_) => "ref",
            SchemaDef::Union(_) => "union",
            SchemaDef::Unknown(_) => "unknown",
            SchemaDef::Token(_) => "token",
        }
    }

    /// Check if this is a primary type (record, query, procedure,
    /// subscription, permission-set, space)
    pub fn is_primary(&self) -> bool {
        matches!(
            self,
            SchemaDef::Record(_)
                | SchemaDef::Query(_)
                | SchemaDef::Procedure(_)
                | SchemaDef::Subscription(_)
                | SchemaDef::PermissionSet(_)
                | SchemaDef::Space(_)
        )
    }

    /// Expand local refs (like `#link`) to full refs (like `nsid#link`)
    ///
    /// This is used when retrieving schemas from the catalog to ensure
    /// local refs can be resolved in any context.
    pub fn expand_local_refs(&mut self, nsid: &str) {
        match self {
            SchemaDef::Record(r) => {
                r.record.expand_local_refs(nsid);
            }
            SchemaDef::Query(q) => {
                if let Some(params) = &mut q.parameters {
                    params.expand_local_refs(nsid);
                }
                if let Some(output) = &mut q.output
                    && let Some(schema) = &mut output.schema
                {
                    schema.expand_local_refs(nsid);
                }
            }
            SchemaDef::Procedure(p) => {
                if let Some(params) = &mut p.parameters {
                    params.expand_local_refs(nsid);
                }
                if let Some(input) = &mut p.input
                    && let Some(schema) = &mut input.schema
                {
                    schema.expand_local_refs(nsid);
                }
                if let Some(output) = &mut p.output
                    && let Some(schema) = &mut output.schema
                {
                    schema.expand_local_refs(nsid);
                }
            }
            SchemaDef::Subscription(s) => {
                if let Some(params) = &mut s.parameters {
                    params.expand_local_refs(nsid);
                }
                if let Some(message) = &mut s.message {
                    message.schema.expand_local_refs(nsid);
                }
            }
            SchemaDef::Array(a) => {
                a.items.expand_local_refs(nsid);
            }
            SchemaDef::Object(o) => {
                for prop in o.properties.values_mut() {
                    prop.expand_local_refs(nsid);
                }
            }
            SchemaDef::Params(p) => {
                for prop in p.properties.values_mut() {
                    prop.expand_local_refs(nsid);
                }
            }
            SchemaDef::Ref(r) => {
                if r.ref_path.starts_with('#') {
                    r.ref_path = format!("{}{}", nsid, r.ref_path);
                }
            }
            SchemaDef::Union(u) => {
                for ref_path in &mut u.refs {
                    if ref_path.starts_with('#') {
                        *ref_path = format!("{}{}", nsid, ref_path);
                    }
                }
            }
            // These types don't contain refs
            SchemaDef::PermissionSet(_)
            | SchemaDef::Space(_)
            | SchemaDef::Boolean(_)
            | SchemaDef::Integer(_)
            | SchemaDef::String(_)
            | SchemaDef::Bytes(_)
            | SchemaDef::CidLink(_)
            | SchemaDef::Blob(_)
            | SchemaDef::Unknown(_)
            | SchemaDef::Token(_) => {}
        }
    }
}

/// Record schema - stored data type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordSchema {
    /// Description of the record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Key for the record (e.g., "tid", "any", "literal:self")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// The record structure
    pub record: Box<SchemaDef>,
}

/// Query schema - HTTP GET endpoint
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct QuerySchema {
    /// Description of the query
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Query parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Box<SchemaDef>>,

    /// Output type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputSchema>,

    /// Possible errors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ErrorSchema>,
}

/// Procedure schema - HTTP POST endpoint
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProcedureSchema {
    /// Description of the procedure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Query parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Box<SchemaDef>>,

    /// Input body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<InputSchema>,

    /// Output type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputSchema>,

    /// Possible errors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ErrorSchema>,
}

/// Subscription schema - WebSocket stream
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SubscriptionSchema {
    /// Description of the subscription
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Query parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Box<SchemaDef>>,

    /// Message types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageSchema>,

    /// Possible errors
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ErrorSchema>,
}

/// Permission set schema - defines OAuth permission groupings
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PermissionSetSchema {
    /// Human-readable title for the permission grouping (required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Descriptive text shown during OAuth flow (spec field name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Descriptive text (alternative to detail, for compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Localization map for title (language code -> translated title)
    #[serde(
        rename = "title:lang",
        default,
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub title_lang: IndexMap<String, String>,

    /// Localization map for detail (language code -> translated detail)
    #[serde(
        rename = "detail:lang",
        default,
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub detail_lang: IndexMap<String, String>,

    /// Array of permission objects
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Permission>,
}

impl PermissionSetSchema {
    /// Get the detail/description text (prefers detail over description)
    pub fn get_detail(&self) -> Option<&str> {
        self.detail.as_deref().or(self.description.as_deref())
    }
}

/// A single permission entry in a permission set
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Permission {
    /// Type field - must be "permission"
    #[serde(rename = "type")]
    pub type_field: String,

    /// Resource type: "repo", "rpc", "blob", "identity", or "account"
    pub resource: String,

    /// Actions for repo resources (e.g., ["create", "update", "delete"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Vec<String>>,

    /// Collection NSIDs for repo resources
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<Vec<String>>,

    /// Lexicon method NSIDs for rpc resources
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<Vec<String>>,

    /// Whether to inherit audience for rpc resources
    #[serde(rename = "inheritAud", skip_serializing_if = "Option::is_none")]
    pub inherit_aud: Option<bool>,

    /// Space type NSID for `space` resources (the `spaceType` field).
    ///
    /// Identifies the concrete space type a permission applies to. Inside a
    /// permission set this must be a concrete NSID and not the `*` wildcard.
    #[serde(rename = "spaceType", skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,

    /// Owner DID for `space` resources.
    ///
    /// Scopes the permission to spaces owned by a specific DID. May be the
    /// `*` wildcard to match any owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,

    /// Record key for `space` resources.
    ///
    /// Scopes the permission to a specific space instance. May be the `*`
    /// wildcard to match any space key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skey: Option<String>,
}

/// Valid resource types for permissions
pub const PERMISSION_RESOURCES: &[&str] = &["repo", "rpc", "blob", "identity", "account", "space"];

/// Valid actions for repo permissions
pub const REPO_ACTIONS: &[&str] = &["create", "update", "delete"];

/// Space schema - declares a permissioned-data space type.
///
/// A space definition must be the `main` definition of its lexicon. The
/// `name` is shown on OAuth consent screens when an application requests
/// access to a space of this type, and `collections` lists the recommended
/// record collections for clients.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SpaceSchema {
    /// Description of the space type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Recommended space key (`skey`) type for spaces of this type.
    ///
    /// Required. Mirrors the [record key
    /// types](https://atproto.com/specs/record-key#record-key-type-tid) — e.g.
    /// `"tid"`, `"literal:self"`, or `"any"`. A declaration missing `key` fails
    /// deserialization (spec line 125).
    pub key: String,

    /// Human-readable name for the space type (length 1..=64).
    pub name: String,

    /// Localization map for name (language code -> translated name).
    #[serde(
        rename = "name:lang",
        default,
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub name_lang: IndexMap<String, String>,

    /// Recommended record collection NSIDs for clients of this space type.
    ///
    /// Required (the field must be present), but may be an empty array.
    pub collections: Vec<String>,
}

/// Input schema for procedures
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputSchema {
    /// Content encoding (e.g., "application/json")
    pub encoding: String,

    /// The schema for the input
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<Box<SchemaDef>>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Output schema for queries and procedures
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputSchema {
    /// Content encoding (e.g., "application/json")
    pub encoding: String,

    /// The schema for the output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<Box<SchemaDef>>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Message schema for subscriptions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageSchema {
    /// Content encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,

    /// The schema for the message
    pub schema: Box<SchemaDef>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Error schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorSchema {
    /// Error name
    pub name: String,

    /// Error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Boolean schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BooleanSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,

    /// Constant value
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<bool>,
}

/// Integer schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct IntegerSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<i64>,

    /// Constant value
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<i64>,

    /// Minimum value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,

    /// Maximum value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,

    /// Enumerated values
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<i64>>,
}

/// String schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StringSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// Constant value
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<String>,

    /// Format (e.g., "datetime", "uri", "did")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Minimum length
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,

    /// Minimum grapheme length
    #[serde(rename = "minGraphemes", skip_serializing_if = "Option::is_none")]
    pub min_graphemes: Option<usize>,

    /// Maximum grapheme length
    #[serde(rename = "maxGraphemes", skip_serializing_if = "Option::is_none")]
    pub max_graphemes: Option<usize>,

    /// Enumerated values
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,

    /// Known values (non-exhaustive enum)
    #[serde(rename = "knownValues", skip_serializing_if = "Option::is_none")]
    pub known_values: Option<Vec<String>>,
}

/// Bytes schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BytesSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Minimum length in bytes
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length in bytes
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

/// CID link schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CidLinkSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Array schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArraySchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Item type
    pub items: Box<SchemaDef>,

    /// Minimum length
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

/// Object schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ObjectSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required property names
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,

    /// Nullable property names
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nullable: Vec<String>,

    /// Property definitions
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, SchemaDef>,
}

/// Blob schema
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BlobSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Accepted MIME types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,

    /// Maximum size in bytes
    #[serde(rename = "maxSize", skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

/// Params schema (query parameters)
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ParamsSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required parameter names
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,

    /// Parameter definitions
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, SchemaDef>,
}

/// Reference schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Reference path (e.g., "#defs/myType" or "com.example.lexicon#type")
    #[serde(rename = "ref")]
    pub ref_path: String,
}

/// Union schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnionSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// References to types in the union
    pub refs: Vec<String>,

    /// Whether the union is closed (default) or open
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub closed: bool,
}

/// Unknown schema (accepts any value)
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct UnknownSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Token schema (constant string type)
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct TokenSchema {
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_def_type_names() {
        assert_eq!(
            SchemaDef::Boolean(BooleanSchema::default()).type_name(),
            "boolean"
        );
        assert_eq!(
            SchemaDef::Integer(IntegerSchema::default()).type_name(),
            "integer"
        );
        assert_eq!(
            SchemaDef::String(StringSchema::default()).type_name(),
            "string"
        );
    }

    #[test]
    fn test_schema_def_is_primary() {
        let record = SchemaDef::Record(RecordSchema {
            description: None,
            key: None,
            record: Box::new(SchemaDef::Object(ObjectSchema::default())),
        });
        assert!(record.is_primary());

        let boolean = SchemaDef::Boolean(BooleanSchema::default());
        assert!(!boolean.is_primary());
    }

    #[test]
    fn test_deserialize_boolean_schema() {
        let json = r#"{"type": "boolean", "default": true}"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Boolean(b) = schema {
            assert_eq!(b.default, Some(true));
        } else {
            panic!("Expected Boolean schema");
        }
    }

    #[test]
    fn test_deserialize_string_schema() {
        let json = r#"{"type": "string", "format": "datetime", "minLength": 1, "maxLength": 100}"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::String(s) = schema {
            assert_eq!(s.format, Some("datetime".to_string()));
            assert_eq!(s.min_length, Some(1));
            assert_eq!(s.max_length, Some(100));
        } else {
            panic!("Expected String schema");
        }
    }

    #[test]
    fn test_deserialize_object_schema() {
        let json = r#"{
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"}
            }
        }"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Object(o) = schema {
            assert_eq!(o.required, vec!["name"]);
            assert!(o.properties.contains_key("name"));
            assert!(o.properties.contains_key("count"));
        } else {
            panic!("Expected Object schema");
        }
    }

    #[test]
    fn test_deserialize_array_schema() {
        let json = r#"{
            "type": "array",
            "items": {"type": "string"},
            "minLength": 1,
            "maxLength": 10
        }"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Array(a) = schema {
            assert_eq!(a.min_length, Some(1));
            assert_eq!(a.max_length, Some(10));
            assert!(matches!(*a.items, SchemaDef::String(_)));
        } else {
            panic!("Expected Array schema");
        }
    }

    #[test]
    fn test_deserialize_ref_schema() {
        let json = r##"{"type": "ref", "ref": "#defs/myType"}"##;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Ref(r) = schema {
            assert_eq!(r.ref_path, "#defs/myType");
        } else {
            panic!("Expected Ref schema");
        }
    }

    #[test]
    fn test_deserialize_union_schema() {
        let json = r##"{
            "type": "union",
            "refs": ["#defs/typeA", "#defs/typeB"],
            "closed": true
        }"##;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Union(u) = schema {
            assert_eq!(u.refs.len(), 2);
            assert!(u.closed);
        } else {
            panic!("Expected Union schema");
        }
    }

    #[test]
    fn test_deserialize_blob_schema() {
        let json = r#"{
            "type": "blob",
            "accept": ["image/png", "image/jpeg"],
            "maxSize": 1000000
        }"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Blob(b) = schema {
            assert_eq!(b.accept, vec!["image/png", "image/jpeg"]);
            assert_eq!(b.max_size, Some(1000000));
        } else {
            panic!("Expected Blob schema");
        }
    }

    #[test]
    fn test_deserialize_cid_link_schema() {
        let json = r#"{"type": "cid-link"}"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        assert!(matches!(schema, SchemaDef::CidLink(_)));
    }

    #[test]
    fn test_space_schema_type_name_and_primary() {
        let space = SchemaDef::Space(SpaceSchema {
            name: "Example".to_string(),
            ..Default::default()
        });
        assert_eq!(space.type_name(), "space");
        assert!(space.is_primary());
    }

    #[test]
    fn test_deserialize_space_schema() {
        let json = r#"{
            "type": "space",
            "key": "tid",
            "name": "AtmoBoards Forum",
            "description": "A discussion forum",
            "name:lang": {"es": "Foro AtmoBoards"},
            "collections": ["com.atmoboards.thread", "com.atmoboards.reply"]
        }"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Space(s) = schema {
            assert_eq!(s.key, "tid");
            assert_eq!(s.name, "AtmoBoards Forum");
            assert_eq!(s.description, Some("A discussion forum".to_string()));
            assert_eq!(s.name_lang.get("es"), Some(&"Foro AtmoBoards".to_string()));
            assert_eq!(s.collections.len(), 2);
        } else {
            panic!("Expected Space schema");
        }
    }

    #[test]
    fn test_space_schema_round_trip() {
        let json = r#"{"type":"space","key":"tid","name":"Example Space","collections":["com.example.thing"]}"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&schema).unwrap();
        let reparsed: SchemaDef = serde_json::from_str(&serialized).unwrap();
        assert_eq!(schema, reparsed);
    }

    #[test]
    fn test_space_schema_missing_name_fails() {
        let json = r#"{"type": "space", "key": "tid", "collections": []}"#;
        assert!(serde_json::from_str::<SchemaDef>(json).is_err());
    }

    #[test]
    fn test_space_schema_missing_collections_fails() {
        let json = r#"{"type": "space", "key": "tid", "name": "Example Space"}"#;
        assert!(serde_json::from_str::<SchemaDef>(json).is_err());
    }

    #[test]
    fn test_space_schema_missing_key_fails() {
        let json = r#"{"type": "space", "name": "Example Space", "collections": []}"#;
        assert!(serde_json::from_str::<SchemaDef>(json).is_err());
    }

    #[test]
    fn test_space_schema_key_round_trips() {
        let json = r#"{"type":"space","key":"literal:self","name":"Profile","collections":[]}"#;
        let schema: SchemaDef = serde_json::from_str(json).unwrap();
        if let SchemaDef::Space(s) = &schema {
            assert_eq!(s.key, "literal:self");
        } else {
            panic!("Expected Space schema");
        }
        let serialized = serde_json::to_string(&schema).unwrap();
        assert!(serialized.contains("\"key\":\"literal:self\""));
    }
}
