//! Data validation error types for AT Protocol lexicon validation
//!
//! This module defines the [`DataValidationError`] enum which represents all possible
//! errors that can occur when validating data against lexicon schemas. Each variant
//! carries structured context about the validation failure.
//!
//! All errors follow the format: `error-atproto-lexicon-data-validation-N <message>: <details>`

/// Errors that can occur when validating data against lexicon schemas.
///
/// Each variant is numbered sequentially and carries sufficient context to produce
/// a human-readable error message describing the validation failure, including the
/// JSON path where the error occurred when applicable.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DataValidationError {
    /// Failed to parse a lexicon schema document.
    #[error("error-atproto-lexicon-data-validation-1 Failed to parse schema: {message}")]
    SchemaParseError {
        /// Description of the parse failure.
        message: String,
    },

    /// The lexicon version field contains an unsupported value.
    #[error(
        "error-atproto-lexicon-data-validation-2 Unsupported lexicon version: {version}, expected 1"
    )]
    UnsupportedLexiconVersion {
        /// The unsupported version number encountered.
        version: i32,
    },

    /// The schema document has an invalid internal structure.
    #[error("error-atproto-lexicon-data-validation-3 Invalid schema structure: {message}")]
    SchemaStructureInvalid {
        /// Description of the structural problem.
        message: String,
    },

    /// A referenced schema NSID could not be found in the catalog.
    #[error("error-atproto-lexicon-data-validation-4 Schema not found: {nsid}")]
    SchemaNotFound {
        /// The NSID that was not found.
        nsid: String,
    },

    /// A record schema was expected but a different schema type was found.
    #[error("error-atproto-lexicon-data-validation-5 Expected record schema, got {got}")]
    ExpectedRecordSchema {
        /// The schema type that was found instead.
        got: String,
    },

    /// The record `$type` field does not match the expected schema NSID.
    #[error(
        "error-atproto-lexicon-data-validation-6 Record $type mismatch: expected '{expected}', got '{actual}'"
    )]
    RecordTypeMismatch {
        /// The expected `$type` value.
        expected: String,
        /// The actual `$type` value found in the record.
        actual: String,
    },

    /// The record is missing the required `$type` field.
    #[error(
        "error-atproto-lexicon-data-validation-7 Record missing required $type field (expected '{expected}')"
    )]
    RecordMissingType {
        /// The expected `$type` value.
        expected: String,
    },

    /// The data type at a given path does not match the schema expectation.
    #[error(
        "error-atproto-lexicon-data-validation-8 Type mismatch at {path}: expected {expected}, got {actual}"
    )]
    TypeMismatch {
        /// The JSON path where the mismatch occurred.
        path: String,
        /// The type expected by the schema.
        expected: String,
        /// The actual type found in the data.
        actual: String,
    },

    /// A const value does not match the schema-defined constant.
    #[error(
        "error-atproto-lexicon-data-validation-9 Const mismatch at {path}: expected {expected}, got {actual}"
    )]
    ConstMismatch {
        /// The JSON path where the mismatch occurred.
        path: String,
        /// The expected constant value.
        expected: String,
        /// The actual value found in the data.
        actual: String,
    },

    /// An integer value is below the schema-defined minimum.
    #[error(
        "error-atproto-lexicon-data-validation-10 Integer too small at {path}: minimum {minimum}, got {actual}"
    )]
    IntegerTooSmall {
        /// The JSON path where the violation occurred.
        path: String,
        /// The minimum allowed value.
        minimum: i64,
        /// The actual value found in the data.
        actual: i64,
    },

    /// An integer value exceeds the schema-defined maximum.
    #[error(
        "error-atproto-lexicon-data-validation-11 Integer too large at {path}: maximum {maximum}, got {actual}"
    )]
    IntegerTooLarge {
        /// The JSON path where the violation occurred.
        path: String,
        /// The maximum allowed value.
        maximum: i64,
        /// The actual value found in the data.
        actual: i64,
    },

    /// An integer value is not in the schema-defined enum set.
    #[error(
        "error-atproto-lexicon-data-validation-12 Integer {value} not in enum at {path}: allowed {allowed:?}"
    )]
    IntegerNotInEnum {
        /// The JSON path where the violation occurred.
        path: String,
        /// The integer value that was not allowed.
        value: i64,
        /// The set of allowed integer values.
        allowed: Vec<i64>,
    },

    /// A string value is shorter than the schema-defined minimum byte length.
    #[error(
        "error-atproto-lexicon-data-validation-13 String too short at {path}: minimum {min_length} bytes, got {actual}"
    )]
    StringTooShort {
        /// The JSON path where the violation occurred.
        path: String,
        /// The minimum allowed byte length.
        min_length: usize,
        /// The actual byte length of the string.
        actual: usize,
    },

    /// A string value exceeds the schema-defined maximum byte length.
    #[error(
        "error-atproto-lexicon-data-validation-14 String too long at {path}: maximum {max_length} bytes, got {actual}"
    )]
    StringTooLong {
        /// The JSON path where the violation occurred.
        path: String,
        /// The maximum allowed byte length.
        max_length: usize,
        /// The actual byte length of the string.
        actual: usize,
    },

    /// A string value has fewer grapheme clusters than the schema-defined minimum.
    #[error(
        "error-atproto-lexicon-data-validation-15 String too few graphemes at {path}: minimum {min_graphemes}, got {actual}"
    )]
    StringTooFewGraphemes {
        /// The JSON path where the violation occurred.
        path: String,
        /// The minimum allowed grapheme count.
        min_graphemes: usize,
        /// The actual grapheme count of the string.
        actual: usize,
    },

    /// A string value has more grapheme clusters than the schema-defined maximum.
    #[error(
        "error-atproto-lexicon-data-validation-16 String too many graphemes at {path}: maximum {max_graphemes}, got {actual}"
    )]
    StringTooManyGraphemes {
        /// The JSON path where the violation occurred.
        path: String,
        /// The maximum allowed grapheme count.
        max_graphemes: usize,
        /// The actual grapheme count of the string.
        actual: usize,
    },

    /// A string value is not in the schema-defined enum set.
    #[error(
        "error-atproto-lexicon-data-validation-17 String '{value}' not in enum at {path}: allowed {allowed:?}"
    )]
    StringNotInEnum {
        /// The JSON path where the violation occurred.
        path: String,
        /// The string value that was not allowed.
        value: String,
        /// The set of allowed string values.
        allowed: Vec<String>,
    },

    /// A string value does not match the expected format constraint.
    #[error(
        "error-atproto-lexicon-data-validation-18 Invalid {format} format for '{value}': {reason}"
    )]
    StringFormatInvalid {
        /// The format name that was expected (e.g. "at-uri", "did", "datetime").
        format: String,
        /// The value that failed format validation.
        value: String,
        /// Description of why the value is invalid.
        reason: String,
    },

    /// A bytes value is shorter than the schema-defined minimum length.
    #[error(
        "error-atproto-lexicon-data-validation-19 Bytes too short at {path}: minimum {min_length}, got {actual}"
    )]
    BytesTooShort {
        /// The JSON path where the violation occurred.
        path: String,
        /// The minimum allowed byte length.
        min_length: usize,
        /// The actual byte length.
        actual: usize,
    },

    /// A bytes value exceeds the schema-defined maximum length.
    #[error(
        "error-atproto-lexicon-data-validation-20 Bytes too long at {path}: maximum {max_length}, got {actual}"
    )]
    BytesTooLong {
        /// The JSON path where the violation occurred.
        path: String,
        /// The maximum allowed byte length.
        max_length: usize,
        /// The actual byte length.
        actual: usize,
    },

    /// A bytes value has invalid base64 encoding.
    #[error("error-atproto-lexicon-data-validation-21 Invalid bytes encoding at {path}")]
    InvalidBytesEncoding {
        /// The JSON path where the encoding error occurred.
        path: String,
    },

    /// An array has fewer elements than the schema-defined minimum.
    #[error(
        "error-atproto-lexicon-data-validation-22 Array too short at {path}: minimum {min_length}, got {actual}"
    )]
    ArrayTooShort {
        /// The JSON path where the violation occurred.
        path: String,
        /// The minimum allowed array length.
        min_length: usize,
        /// The actual array length.
        actual: usize,
    },

    /// An array has more elements than the schema-defined maximum.
    #[error(
        "error-atproto-lexicon-data-validation-23 Array too long at {path}: maximum {max_length}, got {actual}"
    )]
    ArrayTooLong {
        /// The JSON path where the violation occurred.
        path: String,
        /// The maximum allowed array length.
        max_length: usize,
        /// The actual array length.
        actual: usize,
    },

    /// A required property is missing from an object.
    #[error(
        "error-atproto-lexicon-data-validation-24 Missing required property '{property}' at {path}"
    )]
    MissingRequiredProperty {
        /// The JSON path of the parent object.
        path: String,
        /// The name of the missing property.
        property: String,
    },

    /// A non-nullable property has a null value.
    #[error(
        "error-atproto-lexicon-data-validation-25 Unexpected null for non-nullable property '{property}' at {path}"
    )]
    UnexpectedNull {
        /// The JSON path of the parent object.
        path: String,
        /// The name of the property with a null value.
        property: String,
    },

    /// A blob's MIME type is not in the schema-defined accepted list.
    #[error(
        "error-atproto-lexicon-data-validation-26 Blob MIME type '{mime_type}' not accepted at {path}: allowed {accepted:?}"
    )]
    BlobMimeTypeNotAccepted {
        /// The JSON path where the blob was found.
        path: String,
        /// The MIME type of the blob.
        mime_type: String,
        /// The set of accepted MIME types.
        accepted: Vec<String>,
    },

    /// A blob exceeds the schema-defined maximum size.
    #[error(
        "error-atproto-lexicon-data-validation-27 Blob too large at {path}: maximum {max_size}, got {actual}"
    )]
    BlobTooLarge {
        /// The JSON path where the blob was found.
        path: String,
        /// The maximum allowed blob size in bytes.
        max_size: u64,
        /// The actual blob size in bytes.
        actual: u64,
    },

    /// A legacy blob format was encountered but is not allowed.
    #[error("error-atproto-lexicon-data-validation-28 Legacy blob format not allowed")]
    LegacyBlobNotAllowed,

    /// A schema `$ref` could not be resolved to a definition.
    #[error("error-atproto-lexicon-data-validation-29 Unresolved reference: {ref_path}")]
    UnresolvedReference {
        /// The unresolved reference path.
        ref_path: String,
    },

    /// A circular reference was detected in schema definitions.
    #[error("error-atproto-lexicon-data-validation-30 Recursive reference detected: {ref_path}")]
    RecursiveReference {
        /// The reference path where the cycle was detected.
        ref_path: String,
    },

    /// A union discriminator `$type` is not in the allowed refs.
    #[error(
        "error-atproto-lexicon-data-validation-31 Union type '{type_marker}' not in refs at {path}: allowed {allowed:?}"
    )]
    UnionTypeNotInRefs {
        /// The JSON path where the union was found.
        path: String,
        /// The `$type` discriminator value.
        type_marker: String,
        /// The set of allowed union refs.
        allowed: Vec<String>,
    },

    /// No union ref matched the data at the given path.
    #[error(
        "error-atproto-lexicon-data-validation-32 No matching union type at {path}: refs {refs:?}"
    )]
    UnionNoMatchingType {
        /// The JSON path where the union was found.
        path: String,
        /// The set of union refs that were tried.
        refs: Vec<String>,
    },

    /// A union value carries no `$type` discriminator.
    ///
    /// A union is discriminated: the member says which variant it is. Without
    /// `$type` the value is not a union member at all, whatever its shape.
    #[error(
        "error-atproto-lexicon-data-validation-94 Union value at {path} must be an object with a \"$type\" property naming one of: {refs:?}"
    )]
    UnionMissingType {
        /// The JSON path where the union was found.
        path: String,
        /// The set of union refs declared by the schema.
        refs: Vec<String>,
    },

    /// A CID value is invalid.
    #[error("error-atproto-lexicon-data-validation-33 Invalid CID: {value}")]
    InvalidCid {
        /// The invalid CID string.
        value: String,
    },

    /// The data violates the AT Protocol data model constraints.
    #[error("error-atproto-lexicon-data-validation-34 Invalid data model: {reason}")]
    DataModelInvalid {
        /// Description of the data model violation.
        reason: String,
    },

    /// An NSID value is invalid.
    #[error("error-atproto-lexicon-data-validation-35 Invalid NSID '{nsid}': {reason}")]
    InvalidNsid {
        /// The invalid NSID string.
        nsid: String,
        /// Description of why the NSID is invalid.
        reason: String,
    },

    /// A record key value is invalid.
    #[error("error-atproto-lexicon-data-validation-36 Invalid record key: {key}")]
    InvalidRecordKey {
        /// The invalid record key string.
        key: String,
    },

    /// An unknown string format was referenced in the schema.
    #[error("error-atproto-lexicon-data-validation-37 Unknown string format: {format}")]
    InvalidStringFormat {
        /// The unknown format name.
        format: String,
    },

    /// A query schema was expected but a different schema type was found.
    #[error("error-atproto-lexicon-data-validation-38 Expected query schema, got {got}")]
    ExpectedQuerySchema {
        /// The schema type that was found instead.
        got: String,
    },

    /// A procedure schema was expected but a different schema type was found.
    #[error("error-atproto-lexicon-data-validation-39 Expected procedure schema, got {got}")]
    ExpectedProcedureSchema {
        /// The schema type that was found instead.
        got: String,
    },

    /// A procedure schema has no input defined.
    #[error("error-atproto-lexicon-data-validation-40 Procedure has no input defined")]
    NoInputDefined,

    /// A procedure input uses an unsupported encoding.
    #[error(
        "error-atproto-lexicon-data-validation-41 Unsupported input encoding '{encoding}', only 'application/json' is supported"
    )]
    UnsupportedInputEncoding {
        /// The unsupported encoding value.
        encoding: String,
    },

    /// A permission-set definition is missing the required `title` field.
    #[error(
        "error-atproto-lexicon-data-validation-42 Permission-set missing required 'title' field"
    )]
    PermissionSetMissingTitle,

    /// A permission-set definition is missing the required `detail` or `description` field.
    #[error(
        "error-atproto-lexicon-data-validation-43 Permission-set missing required 'detail' or 'description' field"
    )]
    PermissionSetMissingDetail,

    /// A permission-set has an empty `permissions` array.
    #[error(
        "error-atproto-lexicon-data-validation-44 Permission-set 'permissions' array cannot be empty"
    )]
    PermissionSetEmptyPermissions,

    /// A permission has an invalid type value.
    #[error("error-atproto-lexicon-data-validation-45 Permission has invalid type: {got}")]
    PermissionInvalidType {
        /// The invalid permission type value.
        got: String,
    },

    /// A permission has an invalid resource value.
    #[error("error-atproto-lexicon-data-validation-46 Permission has invalid resource: {resource}")]
    PermissionInvalidResource {
        /// The invalid resource value.
        resource: String,
    },

    /// A permission has an invalid action value.
    #[error("error-atproto-lexicon-data-validation-47 Permission has invalid action: {action}")]
    PermissionInvalidAction {
        /// The invalid action value.
        action: String,
    },

    /// A permission is missing the required `collection` field.
    #[error(
        "error-atproto-lexicon-data-validation-48 Permission missing required 'collection' field"
    )]
    PermissionMissingCollection,

    /// A permission is missing the required `lxm` field.
    #[error("error-atproto-lexicon-data-validation-49 Permission missing required 'lxm' field")]
    PermissionMissingLxm,

    /// A permission has an empty `collection` field.
    #[error(
        "error-atproto-lexicon-data-validation-50 Permission 'collection' field cannot be empty"
    )]
    PermissionEmptyCollection,

    /// A permission has an empty `lxm` field.
    #[error("error-atproto-lexicon-data-validation-51 Permission 'lxm' field cannot be empty")]
    PermissionEmptyLxm,

    /// A permission has an empty `action` field.
    #[error("error-atproto-lexicon-data-validation-52 Permission 'action' field cannot be empty")]
    PermissionEmptyAction,

    /// A permission's collection NSID is invalid.
    #[error(
        "error-atproto-lexicon-data-validation-53 Permission has invalid collection NSID '{nsid}': {reason}"
    )]
    PermissionInvalidCollectionNsid {
        /// The invalid NSID string.
        nsid: String,
        /// Description of why the NSID is invalid.
        reason: String,
    },

    /// A permission's LXM NSID is invalid.
    #[error(
        "error-atproto-lexicon-data-validation-54 Permission has invalid LXM NSID '{nsid}': {reason}"
    )]
    PermissionInvalidLxmNsid {
        /// The invalid NSID string.
        nsid: String,
        /// Description of why the NSID is invalid.
        reason: String,
    },

    /// A permission NSID falls outside the lexicon's namespace.
    #[error(
        "error-atproto-lexicon-data-validation-55 Permission NSID '{nsid}' is outside namespace '{namespace}'"
    )]
    PermissionNsidOutsideNamespace {
        /// The NSID that is outside the namespace.
        nsid: String,
        /// The expected namespace.
        namespace: String,
    },

    /// A permission set uses a wildcard where a concrete NSID is required.
    ///
    /// Wildcards are legal in an OAuth scope *string*, where the user is
    /// granting them directly. Inside a permission set they are not: the set
    /// is published under one authority and read by everyone, so a wildcard
    /// would let it grant what its namespace does not cover.
    #[error(
        "error-atproto-lexicon-data-validation-91 Wildcard '{value}' is not allowed in a permission set ({resource} permission); name a concrete NSID"
    )]
    PermissionWildcardInSet {
        /// The resource type the wildcard appeared under.
        resource: String,
        /// The wildcard value as written.
        value: String,
    },

    /// An `include` permission is missing its `nsid` parameter.
    #[error(
        "error-atproto-lexicon-data-validation-92 Permission with resource 'include' requires an 'nsid' naming the permission set to include"
    )]
    PermissionMissingNsid,

    /// An `include` permission names an NSID that is not syntactically valid.
    #[error(
        "error-atproto-lexicon-data-validation-93 Permission include NSID '{nsid}' is not a valid NSID: {reason}"
    )]
    PermissionInvalidIncludeNsid {
        /// The offending NSID.
        nsid: String,
        /// Description of why the NSID is invalid.
        reason: String,
    },

    /// A space definition has a `name` whose length is outside the 1..=64 range.
    #[error(
        "error-atproto-lexicon-data-validation-56 Space name length out of range: expected 1..=64, got {length}"
    )]
    SpaceNameLengthInvalid {
        /// The actual length of the name.
        length: usize,
    },

    /// A space definition's collection NSID is invalid.
    #[error(
        "error-atproto-lexicon-data-validation-57 Space has invalid collection NSID '{nsid}': {reason}"
    )]
    SpaceInvalidCollectionNsid {
        /// The invalid NSID string.
        nsid: String,
        /// Description of why the NSID is invalid.
        reason: String,
    },

    /// A space permission is missing the required `spaceType` field.
    #[error(
        "error-atproto-lexicon-data-validation-58 Space permission missing required 'spaceType' field"
    )]
    SpacePermissionMissingSpaceType,

    /// A space permission uses the `*` wildcard for `spaceType`, which is not
    /// allowed inside a permission set.
    #[error(
        "error-atproto-lexicon-data-validation-59 Space permission 'spaceType' must not be the '*' wildcard"
    )]
    SpacePermissionWildcardSpaceType,

    /// A space permission's `manage` list names a verb that is not one of
    /// `create`, `update`, `delete`.
    #[error(
        "error-atproto-lexicon-data-validation-95 Space permission 'manage' verb is not one of create/update/delete: {verb}"
    )]
    SpacePermissionInvalidManageVerb {
        /// The unrecognised verb.
        verb: String,
    },

    /// A space permission carries `manage` as an empty array.
    ///
    /// Omitting `manage` grants no management capability, and an empty array
    /// says the same thing in a way that reads like an oversight.
    #[error(
        "error-atproto-lexicon-data-validation-96 Space permission 'manage' must not be an empty array; omit it instead"
    )]
    SpacePermissionEmptyManage,

    /// The `ref`/`union` indirection depth exceeded the configured limit.
    ///
    /// Raised before the native stack can overflow. See
    /// [`ValidationLimits::max_ref_depth`](crate::validation::limits::ValidationLimits::max_ref_depth).
    #[error(
        "error-atproto-lexicon-data-validation-60 Reference depth limit exceeded at {path}: maximum {max_depth} ref/union hops, at '{ref_path}'"
    )]
    RefDepthExceeded {
        /// The JSON path at which the limit was reached.
        path: String,
        /// The configured maximum depth.
        max_depth: usize,
        /// The reference that would have exceeded the limit.
        ref_path: String,
    },

    /// The total `ref`/`union` traversal budget for one validation was exhausted.
    ///
    /// Bounds the cost of unions that try every candidate against the same
    /// value. The budget is the fixed
    /// [`ValidationLimits::max_ref_steps`](crate::validation::limits::ValidationLimits::max_ref_steps)
    /// allowance plus
    /// [`ValidationLimits::max_ref_steps_per_node`](crate::validation::limits::ValidationLimits::max_ref_steps_per_node)
    /// for every value in the input.
    #[error(
        "error-atproto-lexicon-data-validation-61 Reference traversal budget exhausted at {path}: maximum {max_steps} ref/union resolutions"
    )]
    RefStepBudgetExhausted {
        /// The JSON path at which the budget ran out.
        path: String,
        /// The budget for this input: the fixed allowance plus the per-node
        /// allowance for the document being validated.
        max_steps: usize,
    },
}
