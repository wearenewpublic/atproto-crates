//! Core validation logic for ATProtocol lexicons
//!
//! This module provides the main validation functions and the Catalog trait
//! for resolving schema references.

use std::collections::{HashMap, HashSet};

use crate::validation::data_errors::DataValidationError;
use crate::validation::data_types::DataValue;
use crate::validation::flags::ValidateFlags;
use crate::validation::mimetype::mime_type_matches_any;
use crate::validation::parse::parse_json;
use crate::validation::schema::{
    ArraySchema, BlobSchema, BooleanSchema, BytesSchema, CidLinkSchema, IntegerSchema,
    ObjectSchema, ParamsSchema, RefSchema, SchemaDef, StringSchema, UnionSchema, UnknownSchema,
};
use crate::validation::schema_file::{SchemaFile, parse_ref};
use crate::validation::syntax::{validate_cid, validate_string_format};

/// A resolved schema with its full reference path
#[derive(Debug, Clone)]
pub struct Schema {
    /// The schema definition
    pub def: SchemaDef,
    /// The full reference path (e.g., "com.example.test#myType")
    pub id: String,
}

/// Trait for resolving schema references
pub trait Catalog: Send + Sync {
    /// Resolve a schema reference to a schema definition
    /// Returns None if the schema is not found
    fn resolve(&self, ref_path: &str) -> Option<Schema>;

    /// Get the schema file by NSID
    /// Used for local reference resolution
    fn get_schema_file(&self, _nsid: &str) -> Option<&SchemaFile> {
        None
    }
}

/// A basic catalog implementation using an in-memory HashMap
pub struct BaseCatalog {
    schemas: HashMap<String, SchemaFile>,
}

impl BaseCatalog {
    /// Create a new empty catalog
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
        }
    }

    /// Add a schema file to the catalog
    pub fn add_schema(&mut self, schema: SchemaFile) {
        self.schemas.insert(schema.id.clone(), schema);
    }

    /// Add a schema from JSON string
    pub fn add_schema_json(&mut self, json: &str) -> Result<(), DataValidationError> {
        let schema = SchemaFile::parse(json)?;
        self.add_schema(schema);
        Ok(())
    }

    /// Get a schema file by ID
    pub fn get_schema(&self, id: &str) -> Option<&SchemaFile> {
        self.schemas.get(id)
    }

    /// Get all schema IDs
    pub fn schema_ids(&self) -> impl Iterator<Item = &str> {
        self.schemas.keys().map(|s| s.as_str())
    }
}

impl Default for BaseCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl Catalog for BaseCatalog {
    fn resolve(&self, ref_path: &str) -> Option<Schema> {
        let (nsid, def_name) = parse_ref(ref_path);

        match nsid {
            Some(id) => {
                // External reference
                let schema_file = self.schemas.get(id)?;
                let def = schema_file.get_def(def_name)?;
                // Clone and expand local refs so they can be resolved in any context
                let mut expanded_def = def.clone();
                expanded_def.expand_local_refs(id);
                Some(Schema {
                    def: expanded_def,
                    id: schema_file.full_ref(def_name),
                })
            }
            None => {
                // This shouldn't happen - local refs need a base schema
                // The validator should handle local refs directly
                None
            }
        }
    }

    fn get_schema_file(&self, nsid: &str) -> Option<&SchemaFile> {
        self.schemas.get(nsid)
    }
}

/// Validation context for tracking path and visited refs
struct ValidationContext<'a> {
    catalog: &'a dyn Catalog,
    flags: ValidateFlags,
    path: Vec<String>,
    visited_refs: HashSet<String>,
    base_schema: Option<&'a SchemaFile>,
}

impl<'a> ValidationContext<'a> {
    fn new(catalog: &'a dyn Catalog, flags: ValidateFlags) -> Self {
        Self {
            catalog,
            flags,
            path: Vec::new(),
            visited_refs: HashSet::new(),
            base_schema: None,
        }
    }

    fn with_base_schema(mut self, schema: &'a SchemaFile) -> Self {
        self.base_schema = Some(schema);
        self
    }

    fn push_path(&mut self, segment: &str) {
        self.path.push(segment.to_string());
    }

    fn pop_path(&mut self) {
        self.path.pop();
    }

    fn current_path(&self) -> String {
        if self.path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.path.join("/"))
        }
    }

    fn resolve_ref(&self, ref_path: &str) -> Option<Schema> {
        let (nsid, def_name) = parse_ref(ref_path);

        // Check if this is a reference to the current schema (same NSID or no NSID)
        let is_local = match (nsid, self.base_schema) {
            (None, _) => true,                               // #fragment style is always local
            (Some(id), Some(base)) if id == base.id => true, // Same NSID means local
            _ => false,
        };

        if is_local {
            // Local reference - use base schema
            if let Some(base) = self.base_schema {
                base.get_def(def_name).map(|def| Schema {
                    def: def.clone(),
                    id: base.full_ref(def_name),
                })
            } else {
                self.catalog.resolve(ref_path)
            }
        } else {
            // External reference - use catalog
            self.catalog.resolve(ref_path)
        }
    }
}

/// Validate a record against a schema
pub fn validate_record(
    nsid: &str,
    data: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Try to get the schema file for local ref resolution
    let schema_file = catalog.get_schema_file(nsid);

    // Resolve the schema
    let schema = catalog
        .resolve(nsid)
        .ok_or_else(|| DataValidationError::SchemaNotFound {
            nsid: nsid.to_string(),
        })?;

    // Parse the JSON data
    let data_value = parse_json(data, flags)?;

    // The schema must be a record type
    let record_schema = match &schema.def {
        SchemaDef::Record(r) => r,
        other => {
            return Err(DataValidationError::ExpectedRecordSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Validate $type field matches the expected NSID
    // AT Protocol requires records to have a $type that matches the lexicon
    match data_value.get_type() {
        Some(actual_type) if actual_type == nsid => {
            // $type matches, continue validation
        }
        Some(actual_type) => {
            return Err(DataValidationError::RecordTypeMismatch {
                expected: nsid.to_string(),
                actual: actual_type.to_string(),
            });
        }
        None => {
            return Err(DataValidationError::RecordMissingType {
                expected: nsid.to_string(),
            });
        }
    }

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate the data against the record's inner schema
    validate_value(&data_value, &record_schema.record, &mut ctx)
}

/// Validate a record with a schema file directly
pub fn validate_record_with_schema(
    data: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Get the main definition
    let main_def =
        schema_file
            .main()
            .ok_or_else(|| DataValidationError::SchemaStructureInvalid {
                message: "schema has no main definition".to_string(),
            })?;

    // The main must be a record type
    let record_schema = match main_def {
        SchemaDef::Record(r) => r,
        other => {
            return Err(DataValidationError::ExpectedRecordSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Parse the JSON data
    let data_value = parse_json(data, flags)?;

    // Validate $type field matches the schema NSID
    // AT Protocol requires records to have a $type that matches the lexicon
    let expected_type = &schema_file.id;
    match data_value.get_type() {
        Some(actual_type) if actual_type == expected_type => {
            // $type matches, continue validation
        }
        Some(actual_type) => {
            return Err(DataValidationError::RecordTypeMismatch {
                expected: expected_type.clone(),
                actual: actual_type.to_string(),
            });
        }
        None => {
            return Err(DataValidationError::RecordMissingType {
                expected: expected_type.clone(),
            });
        }
    }

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags).with_base_schema(schema_file);

    // Validate the data against the record's inner schema
    validate_value(&data_value, &record_schema.record, &mut ctx)
}

/// Validate query parameters against a Query schema.
///
/// Unlike record validation, parameters do NOT require a $type field.
/// The parameters schema is typically a "params" type with properties.
/// Unknown parameters are allowed (consistent with ATProtocol's open data model).
pub fn validate_query_params(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Try to get the schema file for local ref resolution
    let schema_file = catalog.get_schema_file(nsid);

    // Resolve the schema
    let schema = catalog
        .resolve(nsid)
        .ok_or_else(|| DataValidationError::SchemaNotFound {
            nsid: nsid.to_string(),
        })?;

    // The schema must be a query type
    let query_schema = match &schema.def {
        SchemaDef::Query(q) => q,
        other => {
            return Err(DataValidationError::ExpectedQuerySchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate parameters
    validate_params_internal(params, query_schema.parameters.as_deref(), &mut ctx, flags)
}

/// Validate query parameters with a schema file directly
pub fn validate_query_params_with_schema(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Get the main definition
    let main_def =
        schema_file
            .main()
            .ok_or_else(|| DataValidationError::SchemaStructureInvalid {
                message: "schema has no main definition".to_string(),
            })?;

    // The main must be a query type
    let query_schema = match main_def {
        SchemaDef::Query(q) => q,
        other => {
            return Err(DataValidationError::ExpectedQuerySchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags).with_base_schema(schema_file);

    // Validate parameters
    validate_params_internal(params, query_schema.parameters.as_deref(), &mut ctx, flags)
}

/// Validate procedure parameters against a Procedure schema.
///
/// Parameters are URL query params, similar to query validation.
/// Unlike record validation, parameters do NOT require a $type field.
pub fn validate_procedure_params(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Try to get the schema file for local ref resolution
    let schema_file = catalog.get_schema_file(nsid);

    // Resolve the schema
    let schema = catalog
        .resolve(nsid)
        .ok_or_else(|| DataValidationError::SchemaNotFound {
            nsid: nsid.to_string(),
        })?;

    // The schema must be a procedure type
    let procedure_schema = match &schema.def {
        SchemaDef::Procedure(p) => p,
        other => {
            return Err(DataValidationError::ExpectedProcedureSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate parameters
    validate_params_internal(
        params,
        procedure_schema.parameters.as_deref(),
        &mut ctx,
        flags,
    )
}

/// Validate procedure parameters with a schema file directly
pub fn validate_procedure_params_with_schema(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Get the main definition
    let main_def =
        schema_file
            .main()
            .ok_or_else(|| DataValidationError::SchemaStructureInvalid {
                message: "schema has no main definition".to_string(),
            })?;

    // The main must be a procedure type
    let procedure_schema = match main_def {
        SchemaDef::Procedure(p) => p,
        other => {
            return Err(DataValidationError::ExpectedProcedureSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags).with_base_schema(schema_file);

    // Validate parameters
    validate_params_internal(
        params,
        procedure_schema.parameters.as_deref(),
        &mut ctx,
        flags,
    )
}

/// Validate procedure input body against a Procedure schema.
///
/// Input bodies may or may not require $type depending on schema.
/// Only supports "application/json" encoding.
pub fn validate_procedure_input(
    nsid: &str,
    input: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Try to get the schema file for local ref resolution
    let schema_file = catalog.get_schema_file(nsid);

    // Resolve the schema
    let schema = catalog
        .resolve(nsid)
        .ok_or_else(|| DataValidationError::SchemaNotFound {
            nsid: nsid.to_string(),
        })?;

    // The schema must be a procedure type
    let procedure_schema = match &schema.def {
        SchemaDef::Procedure(p) => p,
        other => {
            return Err(DataValidationError::ExpectedProcedureSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate input
    validate_input_internal(input, procedure_schema.input.as_ref(), &mut ctx, flags)
}

/// Validate procedure input body with a schema file directly
pub fn validate_procedure_input_with_schema(
    input: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Get the main definition
    let main_def =
        schema_file
            .main()
            .ok_or_else(|| DataValidationError::SchemaStructureInvalid {
                message: "schema has no main definition".to_string(),
            })?;

    // The main must be a procedure type
    let procedure_schema = match main_def {
        SchemaDef::Procedure(p) => p,
        other => {
            return Err(DataValidationError::ExpectedProcedureSchema {
                got: other.type_name().to_string(),
            });
        }
    };

    // Create validation context with base schema for local refs
    let mut ctx = ValidationContext::new(catalog, flags).with_base_schema(schema_file);

    // Validate input
    validate_input_internal(input, procedure_schema.input.as_ref(), &mut ctx, flags)
}

/// Internal helper to validate parameters against an optional parameters schema.
fn validate_params_internal(
    params: &serde_json::Value,
    params_schema: Option<&SchemaDef>,
    ctx: &mut ValidationContext,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    // Parse the JSON data
    let data_value = parse_json(params, flags)?;

    match params_schema {
        Some(schema) => {
            // Validate against the parameters schema
            // The schema could be Params, Object, or Ref
            validate_value(&data_value, schema, ctx)
        }
        None => {
            // No parameters schema defined - accept empty objects only
            if let Some(obj) = data_value.as_object() {
                if obj.is_empty() {
                    Ok(())
                } else {
                    Err(DataValidationError::SchemaStructureInvalid {
                        message: "no parameters defined but non-empty params provided".to_string(),
                    })
                }
            } else {
                Err(DataValidationError::TypeMismatch {
                    path: "/".to_string(),
                    expected: "object".to_string(),
                    actual: data_value.type_name().to_string(),
                })
            }
        }
    }
}

/// Internal helper to validate input body against an optional input schema.
fn validate_input_internal(
    input: &serde_json::Value,
    input_schema: Option<&crate::validation::schema::InputSchema>,
    ctx: &mut ValidationContext,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    let Some(input_def) = input_schema else {
        // No input schema defined
        return Err(DataValidationError::NoInputDefined);
    };

    // Check encoding - only support application/json
    if input_def.encoding != "application/json" {
        return Err(DataValidationError::UnsupportedInputEncoding {
            encoding: input_def.encoding.clone(),
        });
    }

    // Parse the JSON data
    let data_value = parse_json(input, flags)?;

    // If there's a schema, validate against it
    if let Some(schema) = &input_def.schema {
        validate_value(&data_value, schema, ctx)
    } else {
        // No schema defined but encoding is JSON - accept any valid JSON
        Ok(())
    }
}

/// Validate a value against a schema definition
fn validate_value(
    value: &DataValue,
    schema: &SchemaDef,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    match schema {
        SchemaDef::Boolean(s) => validate_boolean(value, s, ctx),
        SchemaDef::Integer(s) => validate_integer(value, s, ctx),
        SchemaDef::String(s) => validate_string(value, s, ctx),
        SchemaDef::Bytes(s) => validate_bytes(value, s, ctx),
        SchemaDef::CidLink(s) => validate_cid_link(value, s, ctx),
        SchemaDef::Array(s) => validate_array(value, s, ctx),
        SchemaDef::Object(s) => validate_object(value, s, ctx),
        SchemaDef::Blob(s) => validate_blob(value, s, ctx),
        SchemaDef::Ref(s) => validate_ref(value, s, ctx),
        SchemaDef::Union(s) => validate_union(value, s, ctx),
        SchemaDef::Unknown(s) => validate_unknown(value, s, ctx),
        SchemaDef::Token(_) => {
            // Tokens are just type markers, they accept string values
            if value.is_string() {
                Ok(())
            } else {
                Err(DataValidationError::TypeMismatch {
                    path: ctx.current_path(),
                    expected: "string (token)".to_string(),
                    actual: value.type_name().to_string(),
                })
            }
        }
        SchemaDef::Params(s) => validate_params(value, s, ctx),
        // Primary types shouldn't appear as nested schemas
        SchemaDef::Record(_)
        | SchemaDef::Query(_)
        | SchemaDef::Procedure(_)
        | SchemaDef::Subscription(_)
        | SchemaDef::PermissionSet(_)
        | SchemaDef::Space(_) => Err(DataValidationError::SchemaStructureInvalid {
            message: format!(
                "primary type '{}' cannot be used as a nested schema",
                schema.type_name()
            ),
        }),
    }
}

fn validate_boolean(
    value: &DataValue,
    schema: &BooleanSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let bool_val = value
        .as_boolean()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "boolean".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check const constraint
    if let Some(const_val) = schema.const_value
        && bool_val != const_val
    {
        return Err(DataValidationError::ConstMismatch {
            path: ctx.current_path(),
            expected: const_val.to_string(),
            actual: bool_val.to_string(),
        });
    }

    Ok(())
}

fn validate_integer(
    value: &DataValue,
    schema: &IntegerSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let int_val = value
        .as_integer()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "integer".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check const constraint
    if let Some(const_val) = schema.const_value
        && int_val != const_val
    {
        return Err(DataValidationError::ConstMismatch {
            path: ctx.current_path(),
            expected: const_val.to_string(),
            actual: int_val.to_string(),
        });
    }

    // Check minimum
    if let Some(min) = schema.minimum
        && int_val < min
    {
        return Err(DataValidationError::IntegerTooSmall {
            path: ctx.current_path(),
            minimum: min,
            actual: int_val,
        });
    }

    // Check maximum
    if let Some(max) = schema.maximum
        && int_val > max
    {
        return Err(DataValidationError::IntegerTooLarge {
            path: ctx.current_path(),
            maximum: max,
            actual: int_val,
        });
    }

    // Check enum values
    if let Some(ref enum_vals) = schema.enum_values
        && !enum_vals.contains(&int_val)
    {
        return Err(DataValidationError::IntegerNotInEnum {
            path: ctx.current_path(),
            value: int_val,
            allowed: enum_vals.clone(),
        });
    }

    Ok(())
}

fn validate_string(
    value: &DataValue,
    schema: &StringSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let str_val = value
        .as_string()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "string".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check const constraint
    if let Some(ref const_val) = schema.const_value
        && str_val != const_val
    {
        return Err(DataValidationError::ConstMismatch {
            path: ctx.current_path(),
            expected: const_val.clone(),
            actual: str_val.to_string(),
        });
    }

    // Check byte length constraints
    let byte_len = str_val.len();

    if let Some(min) = schema.min_length
        && byte_len < min
    {
        return Err(DataValidationError::StringTooShort {
            path: ctx.current_path(),
            min_length: min,
            actual: byte_len,
        });
    }

    if let Some(max) = schema.max_length
        && byte_len > max
    {
        return Err(DataValidationError::StringTooLong {
            path: ctx.current_path(),
            max_length: max,
            actual: byte_len,
        });
    }

    // Check grapheme length constraints
    if schema.min_graphemes.is_some() || schema.max_graphemes.is_some() {
        use unicode_segmentation::UnicodeSegmentation;
        let grapheme_count = str_val.graphemes(true).count();

        if let Some(min) = schema.min_graphemes
            && grapheme_count < min
        {
            return Err(DataValidationError::StringTooFewGraphemes {
                path: ctx.current_path(),
                min_graphemes: min,
                actual: grapheme_count,
            });
        }

        if let Some(max) = schema.max_graphemes
            && grapheme_count > max
        {
            return Err(DataValidationError::StringTooManyGraphemes {
                path: ctx.current_path(),
                max_graphemes: max,
                actual: grapheme_count,
            });
        }
    }

    // Check enum values
    if let Some(ref enum_vals) = schema.enum_values
        && !enum_vals.iter().any(|v| v == str_val)
    {
        return Err(DataValidationError::StringNotInEnum {
            path: ctx.current_path(),
            value: str_val.to_string(),
            allowed: enum_vals.clone(),
        });
    }

    // Check format
    if let Some(ref format) = schema.format {
        validate_string_format(format, str_val, ctx.flags)?;
    }

    Ok(())
}

fn validate_bytes(
    value: &DataValue,
    schema: &BytesSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let bytes = value
        .as_bytes()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "bytes".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Decode to check length
    let decoded_len =
        bytes
            .decoded_len()
            .ok_or_else(|| DataValidationError::InvalidBytesEncoding {
                path: ctx.current_path(),
            })?;

    if let Some(min) = schema.min_length
        && decoded_len < min
    {
        return Err(DataValidationError::BytesTooShort {
            path: ctx.current_path(),
            min_length: min,
            actual: decoded_len,
        });
    }

    if let Some(max) = schema.max_length
        && decoded_len > max
    {
        return Err(DataValidationError::BytesTooLong {
            path: ctx.current_path(),
            max_length: max,
            actual: decoded_len,
        });
    }

    Ok(())
}

fn validate_cid_link(
    value: &DataValue,
    _schema: &CidLinkSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let link = value
        .as_link()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "cid-link".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Validate the CID format
    validate_cid(&link.link)?;

    Ok(())
}

fn validate_array(
    value: &DataValue,
    schema: &ArraySchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    let array = value
        .as_array()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "array".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check length constraints
    if let Some(min) = schema.min_length
        && array.len() < min
    {
        return Err(DataValidationError::ArrayTooShort {
            path: ctx.current_path(),
            min_length: min,
            actual: array.len(),
        });
    }

    if let Some(max) = schema.max_length
        && array.len() > max
    {
        return Err(DataValidationError::ArrayTooLong {
            path: ctx.current_path(),
            max_length: max,
            actual: array.len(),
        });
    }

    // Validate each item
    for (i, item) in array.iter().enumerate() {
        ctx.push_path(&i.to_string());
        validate_value(item, &schema.items, ctx)?;
        ctx.pop_path();
    }

    Ok(())
}

fn validate_object(
    value: &DataValue,
    schema: &ObjectSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "object".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check required properties
    for req in &schema.required {
        if !obj.contains_key(req) {
            return Err(DataValidationError::MissingRequiredProperty {
                path: ctx.current_path(),
                property: req.clone(),
            });
        }
    }

    // Validate each property
    for (key, prop_value) in obj {
        // Skip $type field
        if key == "$type" {
            continue;
        }

        if let Some(prop_schema) = schema.properties.get(key) {
            ctx.push_path(key);

            // Handle nullable properties
            if prop_value.is_null() {
                if schema.nullable.contains(key) {
                    ctx.pop_path();
                    continue;
                } else {
                    ctx.pop_path();
                    return Err(DataValidationError::UnexpectedNull {
                        path: ctx.current_path(),
                        property: key.clone(),
                    });
                }
            }

            validate_value(prop_value, prop_schema, ctx)?;
            ctx.pop_path();
        } else {
            // Unknown property - this is allowed in ATProtocol (open objects)
        }
    }

    Ok(())
}

fn validate_blob(
    value: &DataValue,
    schema: &BlobSchema,
    ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    let blob = value
        .as_blob()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "blob".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check MIME type if accept list is specified
    if !schema.accept.is_empty() && !mime_type_matches_any(&blob.mime_type, &schema.accept) {
        return Err(DataValidationError::BlobMimeTypeNotAccepted {
            path: ctx.current_path(),
            mime_type: blob.mime_type.clone(),
            accepted: schema.accept.clone(),
        });
    }

    // Check size constraint
    if let Some(max_size) = schema.max_size
        && blob.size > max_size
    {
        return Err(DataValidationError::BlobTooLarge {
            path: ctx.current_path(),
            max_size,
            actual: blob.size,
        });
    }

    // Validate the CID if present
    if let Some(cid) = blob.get_cid() {
        validate_cid(cid)?;
    }

    Ok(())
}

fn validate_ref(
    value: &DataValue,
    schema: &RefSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    // Resolve the reference
    let resolved = match ctx.resolve_ref(&schema.ref_path) {
        Some(r) => r,
        None => {
            // If SKIP_EXTERNAL_REFS is set, treat unresolved external refs as valid
            if ctx.flags.contains(ValidateFlags::SKIP_EXTERNAL_REFS) {
                tracing::debug!(
                    ref_path = %schema.ref_path,
                    "Skipping unresolved external reference (SKIP_EXTERNAL_REFS)"
                );
                return Ok(());
            }
            return Err(DataValidationError::UnresolvedReference {
                ref_path: schema.ref_path.clone(),
            });
        }
    };

    // Prevent infinite recursion
    if ctx.visited_refs.contains(&resolved.id) {
        if ctx
            .flags
            .contains(ValidateFlags::STRICT_RECURSIVE_VALIDATION)
        {
            return Err(DataValidationError::RecursiveReference {
                ref_path: schema.ref_path.clone(),
            });
        }
        // Non-strict mode: skip validation for recursive refs
        return Ok(());
    }

    ctx.visited_refs.insert(resolved.id.clone());
    let result = validate_value(value, &resolved.def, ctx);
    ctx.visited_refs.remove(&resolved.id);

    result
}

fn validate_union(
    value: &DataValue,
    schema: &UnionSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    // Get the $type from the value if it's an object
    let type_marker = value.get_type();

    if let Some(type_str) = type_marker {
        // Check if the type is in the union refs
        let matching_ref = schema.refs.iter().find(|r| {
            // The type marker should match the full reference or just the def name
            let (nsid, def_name) = parse_ref(r);
            match nsid {
                Some(id) => {
                    // Full reference like "com.example.type#def"
                    let full_ref = if def_name == "main" {
                        id.to_string()
                    } else {
                        format!("{}#{}", id, def_name)
                    };
                    type_str == full_ref || type_str == *r
                }
                None => {
                    // Local reference
                    type_str.ends_with(&format!("#{}", def_name)) || type_str == def_name
                }
            }
        });

        if let Some(ref_path) = matching_ref {
            // Validate against the matched type
            match ctx.resolve_ref(ref_path) {
                Some(resolved) => {
                    return validate_value(value, &resolved.def, ctx);
                }
                None => {
                    // If SKIP_EXTERNAL_REFS is set, treat unresolved external refs as valid
                    if ctx.flags.contains(ValidateFlags::SKIP_EXTERNAL_REFS) {
                        tracing::debug!(
                            ref_path = %ref_path,
                            "Skipping unresolved union reference (SKIP_EXTERNAL_REFS)"
                        );
                        return Ok(());
                    }
                    return Err(DataValidationError::UnresolvedReference {
                        ref_path: ref_path.clone(),
                    });
                }
            }
        }

        // Type not in union
        if schema.closed {
            return Err(DataValidationError::UnionTypeNotInRefs {
                path: ctx.current_path(),
                type_marker: type_str.to_string(),
                allowed: schema.refs.clone(),
            });
        }

        // Open union - accept unknown types
        return Ok(());
    }

    // No $type field - try each type in order
    let mut last_error = None;
    let mut any_resolved = false;
    for ref_path in &schema.refs {
        if let Some(resolved) = ctx.resolve_ref(ref_path) {
            any_resolved = true;
            match validate_value(value, &resolved.def, ctx) {
                Ok(()) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
    }

    // If SKIP_EXTERNAL_REFS is set and no refs could be resolved, accept the value
    if !any_resolved && ctx.flags.contains(ValidateFlags::SKIP_EXTERNAL_REFS) {
        tracing::debug!(
            refs = ?schema.refs,
            "Skipping union with no resolvable refs (SKIP_EXTERNAL_REFS)"
        );
        return Ok(());
    }

    Err(
        last_error.unwrap_or_else(|| DataValidationError::UnionNoMatchingType {
            path: ctx.current_path(),
            refs: schema.refs.clone(),
        }),
    )
}

fn validate_unknown(
    _value: &DataValue,
    _schema: &UnknownSchema,
    _ctx: &ValidationContext,
) -> Result<(), DataValidationError> {
    // Unknown accepts any value
    Ok(())
}

fn validate_params(
    value: &DataValue,
    schema: &ParamsSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    let obj = value
        .as_object()
        .ok_or_else(|| DataValidationError::TypeMismatch {
            path: ctx.current_path(),
            expected: "object (params)".to_string(),
            actual: value.type_name().to_string(),
        })?;

    // Check required parameters
    for req in &schema.required {
        if !obj.contains_key(req) {
            return Err(DataValidationError::MissingRequiredProperty {
                path: ctx.current_path(),
                property: req.clone(),
            });
        }
    }

    // Validate each parameter
    for (key, param_value) in obj {
        if let Some(param_schema) = schema.properties.get(key) {
            ctx.push_path(key);
            validate_value(param_value, param_schema, ctx)?;
            ctx.pop_path();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_catalog_with_schema(json: &str) -> BaseCatalog {
        let mut catalog = BaseCatalog::new();
        catalog.add_schema_json(json).unwrap();
        catalog
    }

    #[test]
    fn test_validate_boolean() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "flag": {"type": "boolean"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "flag": true});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid type
        let data = serde_json::json!({"$type": "com.example.test", "flag": "not a bool"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_integer_constraints() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "count": {"type": "integer", "minimum": 0, "maximum": 100}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "count": 50});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Too small
        let data = serde_json::json!({"$type": "com.example.test", "count": -1});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );

        // Too large
        let data = serde_json::json!({"$type": "com.example.test", "count": 101});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_string_length() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 10}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "name": "hello"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Too short
        let data = serde_json::json!({"$type": "com.example.test", "name": ""});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );

        // Too long
        let data = serde_json::json!({"$type": "com.example.test", "name": "this is way too long"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_string_format() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "did": {"type": "string", "format": "did"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid DID
        let data = serde_json::json!({"$type": "com.example.test", "did": "did:plc:z72i7hdynmk6r22z27h6tvur"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid DID
        let data = serde_json::json!({"$type": "com.example.test", "did": "not-a-did"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_required_properties() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid - has required property
        let data = serde_json::json!({"$type": "com.example.test", "name": "test"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid - missing required property (but has $type)
        let data = serde_json::json!({"$type": "com.example.test"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_array() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minLength": 1,
                                "maxLength": 3
                            }
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "items": ["a", "b"]});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Too short
        let data = serde_json::json!({"$type": "com.example.test", "items": []});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );

        // Too long
        let data = serde_json::json!({"$type": "com.example.test", "items": ["a", "b", "c", "d"]});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );

        // Wrong item type
        let data = serde_json::json!({"$type": "com.example.test", "items": [1, 2, 3]});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_ref() {
        let schema = r##"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "item": {"type": "ref", "ref": "#item"}
                        }
                    }
                },
                "item": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string"}
                    }
                }
            }
        }"##;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "item": {"name": "test"}});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid - missing required field in ref
        let data = serde_json::json!({"$type": "com.example.test", "item": {}});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_ref_with_full_nsid() {
        // Test that references using the full NSID (e.g., "com.example.test#item")
        // resolve correctly when they point to the same schema being validated
        let schema = r##"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "mode": {"type": "ref", "ref": "com.example.test#mode"},
                            "status": {"type": "ref", "ref": "com.example.test#status"}
                        }
                    }
                },
                "mode": {
                    "type": "string",
                    "knownValues": ["com.example.test#online", "com.example.test#offline"]
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "inactive"]
                },
                "online": {"type": "token"},
                "offline": {"type": "token"}
            }
        }"##;

        let schema_file = SchemaFile::parse(schema).unwrap();
        let catalog = BaseCatalog::new();

        // Valid - using full NSID refs
        let data = serde_json::json!({
            "$type": "com.example.test",
            "mode": "com.example.test#online",
            "status": "active"
        });
        assert!(
            validate_record_with_schema(&data, &schema_file, &catalog, ValidateFlags::empty())
                .is_ok()
        );

        // Valid - different values
        let data = serde_json::json!({
            "$type": "com.example.test",
            "mode": "com.example.test#offline",
            "status": "inactive"
        });
        assert!(
            validate_record_with_schema(&data, &schema_file, &catalog, ValidateFlags::empty())
                .is_ok()
        );
    }

    #[test]
    fn test_skip_external_refs_flag() {
        // Schema that references an external type
        let schema = r##"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "facets": {
                                "type": "array",
                                "items": {"type": "ref", "ref": "app.bsky.richtext.facet"}
                            }
                        }
                    }
                }
            }
        }"##;

        let schema_file = SchemaFile::parse(schema).unwrap();
        let catalog = BaseCatalog::new(); // Empty catalog - no external schemas

        let data = serde_json::json!({
            "$type": "com.example.test",
            "facets": [{"index": {"byteStart": 0, "byteEnd": 10}, "features": []}]
        });

        // Without SKIP_EXTERNAL_REFS - should fail with unresolved reference
        let result =
            validate_record_with_schema(&data, &schema_file, &catalog, ValidateFlags::empty());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::UnresolvedReference { .. }),
            "Expected UnresolvedReference, got: {:?}",
            err
        );

        // With SKIP_EXTERNAL_REFS - should succeed
        assert!(
            validate_record_with_schema(
                &data,
                &schema_file,
                &catalog,
                ValidateFlags::SKIP_EXTERNAL_REFS
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_enum() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string", "enum": ["active", "inactive", "pending"]}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let data = serde_json::json!({"$type": "com.example.test", "status": "active"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid - not in enum
        let data = serde_json::json!({"$type": "com.example.test", "status": "unknown"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_err()
        );
    }

    #[test]
    fn test_validate_type_mismatch() {
        // Test that validation fails when $type doesn't match the expected NSID
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid - correct $type
        let data = serde_json::json!({"$type": "com.example.test", "name": "test"});
        assert!(
            validate_record("com.example.test", &data, &catalog, ValidateFlags::empty()).is_ok()
        );

        // Invalid - wrong $type
        let data = serde_json::json!({"$type": "com.other.type", "name": "test"});
        let result = validate_record("com.example.test", &data, &catalog, ValidateFlags::empty());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::RecordTypeMismatch { .. }),
            "Expected RecordTypeMismatch, got: {:?}",
            err
        );

        // Invalid - missing $type
        let data = serde_json::json!({"name": "test"});
        let result = validate_record("com.example.test", &data, &catalog, ValidateFlags::empty());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::RecordMissingType { .. }),
            "Expected RecordMissingType, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_type_mismatch_with_schema_file() {
        // Test validate_record_with_schema also checks $type (used by XRPC endpoint)
        let schema_json = r#"{
            "lexicon": 1,
            "id": "garden.lexicon.example",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": {"type": "string"}
                        }
                    }
                }
            }
        }"#;

        let schema_file = SchemaFile::parse(schema_json).unwrap();
        let catalog = BaseCatalog::new();

        // Valid - correct $type
        let data = serde_json::json!({"$type": "garden.lexicon.example", "message": "hello"});
        assert!(
            validate_record_with_schema(
                &data,
                &schema_file,
                &catalog,
                ValidateFlags::SKIP_EXTERNAL_REFS
            )
            .is_ok()
        );

        // Invalid - wrong $type (prefixed with "not.")
        let data = serde_json::json!({"$type": "not.garden.lexicon.example", "message": "hello"});
        let result = validate_record_with_schema(
            &data,
            &schema_file,
            &catalog,
            ValidateFlags::SKIP_EXTERNAL_REFS,
        );
        assert!(
            result.is_err(),
            "Should fail when $type doesn't match schema ID"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::RecordTypeMismatch { .. }),
            "Expected RecordTypeMismatch, got: {:?}",
            err
        );

        // Invalid - missing $type
        let data = serde_json::json!({"message": "hello"});
        let result = validate_record_with_schema(
            &data,
            &schema_file,
            &catalog,
            ValidateFlags::SKIP_EXTERNAL_REFS,
        );
        assert!(result.is_err(), "Should fail when $type is missing");
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::RecordMissingType { .. }),
            "Expected RecordMissingType, got: {:?}",
            err
        );
    }

    #[test]
    fn test_catalog() {
        let mut catalog = BaseCatalog::new();

        let schema1 = r#"{
            "lexicon": 1,
            "id": "com.example.one",
            "defs": {
                "main": {"type": "token"}
            }
        }"#;

        let schema2 = r#"{
            "lexicon": 1,
            "id": "com.example.two",
            "defs": {
                "main": {"type": "token"},
                "other": {"type": "boolean"}
            }
        }"#;

        catalog.add_schema_json(schema1).unwrap();
        catalog.add_schema_json(schema2).unwrap();

        // Resolve main
        assert!(catalog.resolve("com.example.one").is_some());
        assert!(catalog.resolve("com.example.two").is_some());

        // Resolve def
        assert!(catalog.resolve("com.example.two#other").is_some());

        // Not found
        assert!(catalog.resolve("com.example.three").is_none());
    }

    // =========================================================================
    // Query Parameter Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_query_params_valid() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "required": ["handle"],
                        "properties": {
                            "handle": {"type": "string", "format": "handle"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid params
        let params = serde_json::json!({"handle": "alice.bsky.social"});
        assert!(
            validate_query_params(
                "com.example.query",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_query_params_missing_required() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "required": ["handle"],
                        "properties": {
                            "handle": {"type": "string"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Missing required param
        let params = serde_json::json!({});
        let result = validate_query_params(
            "com.example.query",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::MissingRequiredProperty { .. }),
            "Expected MissingRequiredProperty, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_query_params_invalid_type() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "properties": {
                            "count": {"type": "integer"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Wrong type for param
        let params = serde_json::json!({"count": "not an integer"});
        let result = validate_query_params(
            "com.example.query",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::TypeMismatch { .. }),
            "Expected TypeMismatch, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_query_params_unknown_allowed() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "properties": {
                            "known": {"type": "string"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Unknown params should be allowed (open model)
        let params = serde_json::json!({"known": "value", "unknown": "extra"});
        assert!(
            validate_query_params(
                "com.example.query",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_query_params_no_params_defined() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query"
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Empty params should be valid when no schema defined
        let params = serde_json::json!({});
        assert!(
            validate_query_params(
                "com.example.query",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );

        // Non-empty params should fail when no schema defined
        let params = serde_json::json!({"extra": "value"});
        assert!(
            validate_query_params(
                "com.example.query",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_query_params_with_schema_file() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "required": ["q"],
                        "properties": {
                            "q": {"type": "string"},
                            "limit": {"type": "integer", "minimum": 1, "maximum": 100}
                        }
                    }
                }
            }
        }"#;

        let schema_file = SchemaFile::parse(schema_json).unwrap();
        let catalog = BaseCatalog::new();

        // Valid
        let params = serde_json::json!({"q": "search term", "limit": 50});
        assert!(
            validate_query_params_with_schema(
                &params,
                &schema_file,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );

        // Invalid - limit too large
        let params = serde_json::json!({"q": "search term", "limit": 200});
        let result = validate_query_params_with_schema(
            &params,
            &schema_file,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_query_params_wrong_schema_type() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.record",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {"type": "object"}
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Should fail when schema is not a query
        let params = serde_json::json!({});
        let result = validate_query_params(
            "com.example.record",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::ExpectedQuerySchema { .. }),
            "Expected ExpectedQuerySchema, got: {:?}",
            err
        );
    }

    // =========================================================================
    // Procedure Parameter Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_procedure_params_valid() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.procedure",
            "defs": {
                "main": {
                    "type": "procedure",
                    "parameters": {
                        "type": "params",
                        "properties": {
                            "validate": {"type": "boolean"}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid params
        let params = serde_json::json!({"validate": true});
        assert!(
            validate_procedure_params(
                "com.example.procedure",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_procedure_params_wrong_schema_type() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.query",
            "defs": {
                "main": {
                    "type": "query"
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Should fail when schema is not a procedure
        let params = serde_json::json!({});
        let result = validate_procedure_params(
            "com.example.query",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::ExpectedProcedureSchema { .. }),
            "Expected ExpectedProcedureSchema, got: {:?}",
            err
        );
    }

    // =========================================================================
    // Procedure Input Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_procedure_input_valid() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.createPost",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": {"type": "string", "maxLength": 300}
                            }
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid input
        let input = serde_json::json!({"text": "Hello, world!"});
        assert!(
            validate_procedure_input(
                "com.example.createPost",
                &input,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_procedure_input_missing_required() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.createPost",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Missing required field
        let input = serde_json::json!({});
        let result = validate_procedure_input(
            "com.example.createPost",
            &input,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::MissingRequiredProperty { .. }),
            "Expected MissingRequiredProperty, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_procedure_input_no_input_defined() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.procedure",
            "defs": {
                "main": {
                    "type": "procedure"
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Should fail when no input is defined
        let input = serde_json::json!({"data": "value"});
        let result = validate_procedure_input(
            "com.example.procedure",
            &input,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::NoInputDefined),
            "Expected NoInputDefined, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_procedure_input_unsupported_encoding() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.upload",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "*/*"
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Should fail for non-JSON encoding
        let input = serde_json::json!({});
        let result = validate_procedure_input(
            "com.example.upload",
            &input,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::UnsupportedInputEncoding { .. }),
            "Expected UnsupportedInputEncoding, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_procedure_input_with_schema_file() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.createRecord",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "required": ["repo", "collection", "record"],
                            "properties": {
                                "repo": {"type": "string", "format": "at-identifier"},
                                "collection": {"type": "string", "format": "nsid"},
                                "record": {"type": "unknown"}
                            }
                        }
                    }
                }
            }
        }"#;

        let schema_file = SchemaFile::parse(schema_json).unwrap();
        let catalog = BaseCatalog::new();

        // Valid input
        let input = serde_json::json!({
            "repo": "did:plc:xyz123",
            "collection": "app.bsky.feed.post",
            "record": {"$type": "app.bsky.feed.post", "text": "Hello"}
        });
        assert!(
            validate_procedure_input_with_schema(
                &input,
                &schema_file,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_procedure_input_json_no_schema() {
        // When input has encoding but no schema, any valid JSON should pass
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.flexible",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json"
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Any JSON should be valid
        let input = serde_json::json!({"anything": "goes", "numbers": [1, 2, 3]});
        assert!(
            validate_procedure_input(
                "com.example.flexible",
                &input,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_procedure_input_with_ref() {
        let schema = r##"{
            "lexicon": 1,
            "id": "com.example.withRef",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json",
                        "schema": {"type": "ref", "ref": "#inputData"}
                    }
                },
                "inputData": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string"}
                    }
                }
            }
        }"##;

        let schema_file = SchemaFile::parse(schema).unwrap();
        let catalog = BaseCatalog::new();

        // Valid - matches ref schema
        let input = serde_json::json!({"name": "test"});
        assert!(
            validate_procedure_input_with_schema(
                &input,
                &schema_file,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );

        // Invalid - missing required field from ref
        let input = serde_json::json!({});
        assert!(
            validate_procedure_input_with_schema(
                &input,
                &schema_file,
                &catalog,
                ValidateFlags::empty()
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_query_params_with_integer_constraints() {
        let schema = r#"{
            "lexicon": 1,
            "id": "com.example.search",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "properties": {
                            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                            "offset": {"type": "integer", "minimum": 0}
                        }
                    }
                }
            }
        }"#;

        let catalog = make_catalog_with_schema(schema);

        // Valid
        let params = serde_json::json!({"limit": 50, "offset": 0});
        assert!(
            validate_query_params(
                "com.example.search",
                &params,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );

        // Invalid - limit too high
        let params = serde_json::json!({"limit": 150});
        let result = validate_query_params(
            "com.example.search",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::IntegerTooLarge { .. }),
            "Expected IntegerTooLarge, got: {:?}",
            err
        );

        // Invalid - offset negative
        let params = serde_json::json!({"offset": -1});
        let result = validate_query_params(
            "com.example.search",
            &params,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DataValidationError::IntegerTooSmall { .. }),
            "Expected IntegerTooSmall, got: {:?}",
            err
        );
    }
}
