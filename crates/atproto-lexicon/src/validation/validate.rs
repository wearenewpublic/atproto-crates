//! Core validation logic for ATProtocol lexicons
//!
//! This module provides the main validation functions and the Catalog trait
//! for resolving schema references.
//!
//! ## Resource limits
//!
//! `ref` and `union` schemas are indirections: following one does not consume
//! any of the input document, so the lexicon alone controls how far validation
//! recurses. Every entry point therefore enforces a [`ValidationLimits`] budget
//! covering both the live indirection depth (stack safety) and the total number
//! of indirections followed (CPU safety, bounding the combinatorial search a
//! union without a `$type` discriminator performs). The `*_with_limits` and
//! `*_with_schema_and_limits` entry points accept an explicit budget; the
//! others use [`ValidationLimits::default`].

use std::collections::{HashMap, HashSet};

use crate::validation::data_errors::DataValidationError;
use crate::validation::data_types::DataValue;
use crate::validation::flags::ValidateFlags;
use crate::validation::limits::ValidationLimits;
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

/// Validation context for tracking path, visited refs, and resource budgets
struct ValidationContext<'a> {
    catalog: &'a dyn Catalog,
    flags: ValidateFlags,
    path: Vec<String>,
    visited_refs: HashSet<String>,
    base_schema: Option<&'a SchemaFile>,
    /// Configured budget for ref/union traversal.
    limits: ValidationLimits,
    /// Number of ref/union hops currently active on the stack.
    ref_depth: usize,
    /// Number of ref/union hops charged so far; never decremented.
    ref_steps: usize,
    /// Total hops this validation may charge. Starts at `limits.max_ref_steps`
    /// and grows by the per-node allowance once the input size is known.
    step_budget: usize,
    /// Union targets active at a given value-nesting level, keyed by
    /// `(value level, resolved def id)`. Re-entering one of these means the
    /// recursion cannot consume any input.
    active_union_frames: HashSet<(usize, String)>,
    /// Reference counts of the union def ids currently on the stack, at any
    /// value level. Used only by `STRICT_RECURSIVE_VALIDATION`.
    active_union_defs: HashMap<String, u32>,
}

impl<'a> ValidationContext<'a> {
    fn new(catalog: &'a dyn Catalog, flags: ValidateFlags, limits: ValidationLimits) -> Self {
        Self {
            catalog,
            flags,
            path: Vec::new(),
            visited_refs: HashSet::new(),
            base_schema: None,
            ref_depth: 0,
            ref_steps: 0,
            step_budget: limits.max_ref_steps,
            limits,
            active_union_frames: HashSet::new(),
            active_union_defs: HashMap::new(),
        }
    }

    fn with_base_schema(mut self, schema: &'a SchemaFile) -> Self {
        self.base_schema = Some(schema);
        self
    }

    /// Widen the step budget by the per-node allowance for `value`.
    ///
    /// Called once per parsed document, before it is walked. Legitimate
    /// traversal work is proportional to the number of values in the input, so
    /// the budget has to be too; an absolute cap rejects ordinary large records
    /// (100,000 integers behind a `ref` cost 100,000 hops) while still handing a
    /// tiny hostile body the whole allowance.
    fn grant_input_allowance(&mut self, value: &DataValue) {
        let granted = self.limits.step_allowance_for(count_value_nodes(value));
        self.step_budget = self.step_budget.saturating_add(granted);
    }

    /// Charge one unit of ref/union traversal work against the step budget.
    fn charge_step(&mut self) -> Result<(), DataValidationError> {
        if self.ref_steps >= self.step_budget {
            return Err(DataValidationError::RefStepBudgetExhausted {
                path: self.current_path(),
                max_steps: self.step_budget,
            });
        }
        self.ref_steps += 1;
        Ok(())
    }

    /// Enter a ref/union indirection: charge a step and push one depth level.
    ///
    /// On error the depth counter is left untouched, so a caller that uses `?`
    /// must not call [`ValidationContext::exit_hop`].
    fn enter_hop(&mut self, ref_path: &str) -> Result<(), DataValidationError> {
        self.charge_step()?;
        if self.ref_depth >= self.limits.max_ref_depth {
            return Err(DataValidationError::RefDepthExceeded {
                path: self.current_path(),
                max_depth: self.limits.max_ref_depth,
                ref_path: ref_path.to_string(),
            });
        }
        self.ref_depth += 1;
        Ok(())
    }

    /// Leave a ref/union indirection entered with [`ValidationContext::enter_hop`].
    fn exit_hop(&mut self) {
        debug_assert!(self.ref_depth > 0, "ref depth underflow");
        self.ref_depth = self.ref_depth.saturating_sub(1);
    }

    /// Mark a union target as active at the current value-nesting level.
    ///
    /// Returns the level that was recorded. That level must be handed back to
    /// [`ValidationContext::exit_union_target`] rather than re-read from
    /// `self.path` at exit: the frame key would otherwise depend on mutable
    /// state that the nested validation owns, and any imbalance would leave a
    /// stale frame behind that falsely rejects later values.
    fn enter_union_target(&mut self, id: &str) -> usize {
        let level = self.path.len();
        self.active_union_frames.insert((level, id.to_string()));
        *self.active_union_defs.entry(id.to_string()).or_insert(0) += 1;
        level
    }

    /// Clear a union target marked by [`ValidationContext::enter_union_target`].
    ///
    /// `level` must be the value returned by the matching `enter_union_target`.
    fn exit_union_target(&mut self, level: usize, id: &str) {
        self.active_union_frames.remove(&(level, id.to_string()));
        if let Some(count) = self.active_union_defs.get_mut(id) {
            *count -= 1;
            if *count == 0 {
                self.active_union_defs.remove(id);
            }
        }
    }

    /// True when re-entering `id` cannot consume input: the same def is already
    /// being validated against a value at this same nesting level.
    fn is_nonproductive_union(&self, id: &str) -> bool {
        self.active_union_frames
            .contains(&(self.path.len(), id.to_string()))
    }

    /// True when `id` is anywhere on the union stack, including at shallower
    /// value levels (that is, productive recursion).
    fn is_recursive_union(&self, id: &str) -> bool {
        self.active_union_defs.contains_key(id)
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

/// Count every value in `root`, including `root` itself and all nested values.
///
/// Walks an explicit stack rather than recursing: the count is taken before
/// validation begins, so it must not be able to overflow the native stack on a
/// deeply nested document.
fn count_value_nodes(root: &DataValue) -> usize {
    let mut count = 0usize;
    let mut stack = vec![root];

    while let Some(value) = stack.pop() {
        count = count.saturating_add(1);
        match value {
            DataValue::Array(items) => stack.extend(items.iter()),
            DataValue::Object(entries) => stack.extend(entries.values()),
            _ => {}
        }
    }

    count
}

/// Validate a record against a schema, using the default [`ValidationLimits`].
///
/// See [`validate_record_with_limits`] to supply an explicit budget.
pub fn validate_record(
    nsid: &str,
    data: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_record_with_limits(nsid, data, catalog, flags, ValidationLimits::default())
}

/// Validate a record against a schema with explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_record_with_limits(
    nsid: &str,
    data: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }
    ctx.grant_input_allowance(&data_value);

    // Validate the data against the record's inner schema
    validate_value(&data_value, &record_schema.record, &mut ctx)
}

/// Validate a record with a schema file directly, using the default [`ValidationLimits`].
///
/// See [`validate_record_with_schema_and_limits`] to supply an explicit budget.
pub fn validate_record_with_schema(
    data: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_record_with_schema_and_limits(
        data,
        schema_file,
        catalog,
        flags,
        ValidationLimits::default(),
    )
}

/// Validate a record with a schema file directly and explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_record_with_schema_and_limits(
    data: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits).with_base_schema(schema_file);
    ctx.grant_input_allowance(&data_value);

    // Validate the data against the record's inner schema
    validate_value(&data_value, &record_schema.record, &mut ctx)
}

/// Validate query parameters against a Query schema.
///
/// Unlike record validation, parameters do NOT require a $type field.
/// The parameters schema is typically a "params" type with properties.
/// Unknown parameters are allowed (consistent with ATProtocol's open data model).
///
/// Uses the default [`ValidationLimits`]; see [`validate_query_params_with_limits`].
pub fn validate_query_params(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_query_params_with_limits(nsid, params, catalog, flags, ValidationLimits::default())
}

/// Validate query parameters against a Query schema with explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_query_params_with_limits(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate parameters
    validate_params_internal(params, query_schema.parameters.as_deref(), &mut ctx, flags)
}

/// Validate query parameters with a schema file directly, using the default
/// [`ValidationLimits`].
///
/// See [`validate_query_params_with_schema_and_limits`] to supply an explicit budget.
pub fn validate_query_params_with_schema(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_query_params_with_schema_and_limits(
        params,
        schema_file,
        catalog,
        flags,
        ValidationLimits::default(),
    )
}

/// Validate query parameters with a schema file directly and explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_query_params_with_schema_and_limits(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits).with_base_schema(schema_file);

    // Validate parameters
    validate_params_internal(params, query_schema.parameters.as_deref(), &mut ctx, flags)
}

/// Validate procedure parameters against a Procedure schema.
///
/// Parameters are URL query params, similar to query validation.
/// Unlike record validation, parameters do NOT require a $type field.
///
/// Uses the default [`ValidationLimits`]; see [`validate_procedure_params_with_limits`].
pub fn validate_procedure_params(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_procedure_params_with_limits(nsid, params, catalog, flags, ValidationLimits::default())
}

/// Validate procedure parameters against a Procedure schema with explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_procedure_params_with_limits(
    nsid: &str,
    params: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits);
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

/// Validate procedure parameters with a schema file directly, using the default
/// [`ValidationLimits`].
///
/// See [`validate_procedure_params_with_schema_and_limits`] to supply an explicit budget.
pub fn validate_procedure_params_with_schema(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_procedure_params_with_schema_and_limits(
        params,
        schema_file,
        catalog,
        flags,
        ValidationLimits::default(),
    )
}

/// Validate procedure parameters with a schema file directly and explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_procedure_params_with_schema_and_limits(
    params: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits).with_base_schema(schema_file);

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
///
/// Uses the default [`ValidationLimits`]; see [`validate_procedure_input_with_limits`].
pub fn validate_procedure_input(
    nsid: &str,
    input: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_procedure_input_with_limits(nsid, input, catalog, flags, ValidationLimits::default())
}

/// Validate procedure input body against a Procedure schema with explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_procedure_input_with_limits(
    nsid: &str,
    input: &serde_json::Value,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits);
    if let Some(sf) = schema_file {
        ctx = ctx.with_base_schema(sf);
    }

    // Validate input
    validate_input_internal(input, procedure_schema.input.as_ref(), &mut ctx, flags)
}

/// Validate procedure input body with a schema file directly, using the default
/// [`ValidationLimits`].
///
/// See [`validate_procedure_input_with_schema_and_limits`] to supply an explicit budget.
pub fn validate_procedure_input_with_schema(
    input: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
) -> Result<(), DataValidationError> {
    validate_procedure_input_with_schema_and_limits(
        input,
        schema_file,
        catalog,
        flags,
        ValidationLimits::default(),
    )
}

/// Validate procedure input body with a schema file directly and explicit resource limits.
///
/// See [`ValidationLimits`] for what the budget bounds and why.
pub fn validate_procedure_input_with_schema_and_limits(
    input: &serde_json::Value,
    schema_file: &SchemaFile,
    catalog: &dyn Catalog,
    flags: ValidateFlags,
    limits: ValidationLimits,
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
    let mut ctx = ValidationContext::new(catalog, flags, limits).with_base_schema(schema_file);

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
    ctx.grant_input_allowance(&data_value);

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
    ctx.grant_input_allowance(&data_value);

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

    // Validate each item. The path segment is popped before propagating a
    // failure so that a caller which recovers from the error (the union
    // candidate loop) observes the same nesting level it started at.
    for (i, item) in array.iter().enumerate() {
        ctx.push_path(&i.to_string());
        let result = validate_value(item, &schema.items, ctx);
        ctx.pop_path();
        result?;
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

            // Pop before propagating so an error path leaves the context's
            // nesting level unchanged (see `validate_array`).
            let result = validate_value(prop_value, prop_schema, ctx);
            ctx.pop_path();
            result?;
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

/// Validate a value against a `ref` schema, charging the ref/union budget.
///
/// The budget is charged here rather than inside `validate_ref_inner` so that
/// the depth counter is decremented on every exit path, including the `?`
/// early returns in the inner function.
fn validate_ref(
    value: &DataValue,
    schema: &RefSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    ctx.enter_hop(&schema.ref_path)?;
    let result = validate_ref_inner(value, schema, ctx);
    ctx.exit_hop();
    result
}

fn validate_ref_inner(
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

/// Validate a value against a `union` schema, charging the ref/union budget.
///
/// Like [`validate_ref`], the hop is charged in a wrapper so the depth counter
/// cannot leak through any of the inner function's early returns.
fn validate_union(
    value: &DataValue,
    schema: &UnionSchema,
    ctx: &mut ValidationContext,
) -> Result<(), DataValidationError> {
    let hop_label = schema.refs.first().map(String::as_str).unwrap_or("<union>");
    ctx.enter_hop(hop_label)?;
    let result = validate_union_inner(value, schema, ctx);
    ctx.exit_hop();
    result
}

fn validate_union_inner(
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
                    // A union target that is already being validated against a
                    // value at this same nesting level cannot consume input, so
                    // re-entering it would recurse forever.
                    if ctx.is_nonproductive_union(&resolved.id)
                        || (ctx
                            .flags
                            .contains(ValidateFlags::STRICT_RECURSIVE_VALIDATION)
                            && ctx.is_recursive_union(&resolved.id))
                    {
                        return Err(DataValidationError::RecursiveReference {
                            ref_path: ref_path.clone(),
                        });
                    }

                    let level = ctx.enter_union_target(&resolved.id);
                    let result = validate_value(value, &resolved.def, ctx);
                    ctx.exit_union_target(level, &resolved.id);
                    return result;
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

            // Charge every candidate attempt, not just the ones that recurse
            // into another ref/union: a union listing thousands of plain object
            // refs would otherwise do unbounded work for a single hop.
            ctx.charge_step()?;

            if ctx.is_nonproductive_union(&resolved.id)
                || (ctx
                    .flags
                    .contains(ValidateFlags::STRICT_RECURSIVE_VALIDATION)
                    && ctx.is_recursive_union(&resolved.id))
            {
                // Skip the candidate rather than accepting it; a non-productive
                // cycle proves nothing about the value.
                last_error = Some(DataValidationError::RecursiveReference {
                    ref_path: ref_path.clone(),
                });
                continue;
            }

            let level = ctx.enter_union_target(&resolved.id);
            let attempt = validate_value(value, &resolved.def, ctx);
            ctx.exit_union_target(level, &resolved.id);

            match attempt {
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
            // Pop before propagating so an error path leaves the context's
            // nesting level unchanged (see `validate_array`).
            let result = validate_value(param_value, param_schema, ctx);
            ctx.pop_path();
            result?;
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

#[cfg(test)]
mod recursion_limit_tests {
    use super::*;
    use crate::validation::limits::{DEFAULT_MAX_REF_STEPS, ValidationLimits};

    /// Lexicon whose `loop` def is a union that references only itself.
    ///
    /// This is the exact payload from the security report: before the fix it
    /// drove `validate_union` into unbounded recursion and aborted the process.
    const LOOP_LEXICON: &str = r##"{
        "lexicon": 1,
        "id": "com.example.loop",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "properties": {"x": {"type": "union", "refs": ["#loop"]}}
                }
            },
            "loop": {"type": "union", "refs": ["#loop"]}
        }
    }"##;

    /// Thread-style lexicon with a legitimately self-referencing union.
    const THREAD_LEXICON: &str = r##"{
        "lexicon": 1,
        "id": "com.example.thread",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["node"],
                    "properties": {"node": {"type": "union", "refs": ["#node"]}}
                }
            },
            "node": {
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": {"type": "string"},
                    "child": {"type": "union", "refs": ["#node"]}
                }
            }
        }
    }"##;

    /// Run a validation closure on a 2 MiB stack, matching a Tokio worker.
    ///
    /// A Rust stack overflow is a process abort, so if the guard fails to hold
    /// the test binary dies rather than reporting a failure. Running on an
    /// explicitly sized thread makes the bound meaningful.
    fn on_worker_stack<F, T>(f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(f)
            .expect("spawn validation thread")
            .join()
            .expect("validation thread panicked")
    }

    fn catalog_from(json: &str) -> BaseCatalog {
        let mut catalog = BaseCatalog::new();
        catalog.add_schema_json(json).unwrap();
        catalog
    }

    /// Build a chain lexicon `a0 -> a1 -> ... -> a{n-1}` terminating in an
    /// object, where each link uses `link_json` with `{next}` substituted.
    fn chain_lexicon(n: usize, main_prop: &str, link_template: &str) -> String {
        let mut defs = String::new();
        for i in 0..n - 1 {
            defs.push_str(&format!(
                "\"a{}\": {},",
                i,
                link_template.replace("{next}", &format!("#a{}", i + 1))
            ));
        }
        defs.push_str(&format!(
            "\"a{}\": {{\"type\": \"object\", \"properties\": {{}}}}",
            n - 1
        ));
        format!(
            r##"{{"lexicon": 1, "id": "com.example.chain", "defs": {{
                "main": {{"type": "record", "key": "tid", "record": {{
                    "type": "object", "properties": {{"x": {}}}
                }}}},
                {}
            }}}}"##,
            main_prop, defs
        )
    }

    /// Build a nested thread record with `levels` child links.
    ///
    /// When `drop_text_at` is set, that node omits its required `text` field.
    fn build_thread(levels: usize, drop_text_at: Option<usize>) -> serde_json::Value {
        let make = |idx: usize, child: Option<serde_json::Value>| {
            let mut obj = serde_json::Map::new();
            obj.insert(
                "$type".to_string(),
                serde_json::json!("com.example.thread#node"),
            );
            if drop_text_at != Some(idx) {
                obj.insert("text".to_string(), serde_json::json!(format!("n{}", idx)));
            }
            if let Some(child) = child {
                obj.insert("child".to_string(), child);
            }
            serde_json::Value::Object(obj)
        };

        let mut node = make(levels, None);
        for idx in (0..levels).rev() {
            node = make(idx, Some(node));
        }
        serde_json::json!({"$type": "com.example.thread", "node": node})
    }

    #[test]
    fn test_union_self_reference_via_type_marker_is_bounded() {
        let err = on_worker_stack(|| {
            let catalog = catalog_from(LOOP_LEXICON);
            // The $type must be the fully normalized ref: schema parsing rewrites
            // ["#loop"] to ["com.example.loop#loop"], and the bare "#loop" form
            // would be treated as an unknown type by the open union.
            let record = serde_json::json!({
                "$type": "com.example.loop",
                "x": {"$type": "com.example.loop#loop"}
            });
            validate_record(
                "com.example.loop",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });

        assert!(
            matches!(err, DataValidationError::RecursiveReference { .. }),
            "expected RecursiveReference, got {err:?}"
        );
    }

    #[test]
    fn test_union_self_reference_without_type_marker_is_bounded() {
        let err = on_worker_stack(|| {
            let catalog = catalog_from(LOOP_LEXICON);
            let record = serde_json::json!({"$type": "com.example.loop", "x": {}});
            validate_record(
                "com.example.loop",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });

        assert!(
            matches!(err, DataValidationError::RecursiveReference { .. }),
            "expected RecursiveReference, got {err:?}"
        );
    }

    #[test]
    fn test_acyclic_union_chain_hits_depth_limit() {
        // No cycle anywhere: cycle detection alone cannot stop this, only a
        // depth bound can.
        let err = on_worker_stack(|| {
            let lexicon = chain_lexicon(
                5000,
                r##"{"type": "union", "refs": ["#a0"]}"##,
                r##"{"type": "union", "refs": ["{next}"]}"##,
            );
            let catalog = catalog_from(&lexicon);
            let record = serde_json::json!({"$type": "com.example.chain", "x": {}});
            validate_record(
                "com.example.chain",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });

        assert!(
            matches!(
                err,
                DataValidationError::RefDepthExceeded {
                    max_depth: crate::validation::limits::DEFAULT_MAX_REF_DEPTH,
                    ..
                }
            ),
            "expected RefDepthExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_acyclic_plain_ref_chain_hits_depth_limit() {
        // Same shape with no unions at all. `visited_refs` only detects cycles,
        // so an acyclic ref chain was an abort vector too.
        let err = on_worker_stack(|| {
            let lexicon = chain_lexicon(
                5000,
                r##"{"type": "ref", "ref": "#a0"}"##,
                r##"{"type": "ref", "ref": "{next}"}"##,
            );
            let catalog = catalog_from(&lexicon);
            let record = serde_json::json!({"$type": "com.example.chain", "x": {}});
            validate_record(
                "com.example.chain",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });

        assert!(
            matches!(err, DataValidationError::RefDepthExceeded { .. }),
            "expected RefDepthExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_union_fanout_hits_step_budget() {
        // Depth 13, width 4: 4^13 combinations from a 34-byte body and a
        // sub-1 KiB lexicon. Took ~25 s before the fix.
        let mut defs = String::new();
        for i in 0..13 {
            defs.push_str(&format!(
                "\"u{0}\": {{\"type\": \"union\", \"refs\": [\"#u{1}\", \"#u{1}\", \"#u{1}\", \"#u{1}\"]}},",
                i,
                i + 1
            ));
        }
        defs.push_str(
            r##""u13": {"type": "object", "required": ["zzz"], "properties": {"zzz": {"type": "string"}}}"##,
        );
        let lexicon = format!(
            r##"{{"lexicon": 1, "id": "com.example.fan", "defs": {{
                "main": {{"type": "record", "key": "tid", "record": {{
                    "type": "object", "properties": {{"x": {{"type": "union", "refs": ["#u0"]}}}}
                }}}},
                {}
            }}}}"##,
            defs
        );

        let started = std::time::Instant::now();
        let err = on_worker_stack(move || {
            let catalog = catalog_from(&lexicon);
            let record = serde_json::json!({"$type": "com.example.fan", "x": {}});
            validate_record("com.example.fan", &record, &catalog, ValidateFlags::empty())
                .unwrap_err()
        });
        let elapsed = started.elapsed();

        match err {
            DataValidationError::RefStepBudgetExhausted { max_steps, .. } => {
                // A three-node body must not buy meaningful extra budget: the
                // per-node allowance is proportional, so amplification from a
                // tiny request stays bounded by the fixed allowance.
                assert!(
                    max_steps < DEFAULT_MAX_REF_STEPS + 1_000,
                    "tiny body granted {max_steps} steps, expected ~{DEFAULT_MAX_REF_STEPS}"
                );
            }
            other => panic!("expected RefStepBudgetExhausted, got {other:?}"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "fan-out validation took {elapsed:?}, expected well under 2s"
        );
    }

    #[test]
    fn test_mixed_union_ref_cycle_is_bounded() {
        // union -> ref -> union: the union frame set and validate_ref's
        // visited_refs must interlock rather than each hiding the other's cycle.
        let lexicon = r##"{
            "lexicon": 1,
            "id": "com.example.mixed",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {"x": {"type": "union", "refs": ["#u"]}}
                    }
                },
                "u": {"type": "union", "refs": ["#r"]},
                "r": {"type": "ref", "ref": "#u"}
            }
        }"##;

        let err = on_worker_stack(|| {
            let catalog = catalog_from(lexicon);
            let record = serde_json::json!({"$type": "com.example.mixed", "x": {}});
            validate_record(
                "com.example.mixed",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });

        assert!(
            matches!(
                err,
                DataValidationError::RecursiveReference { .. }
                    | DataValidationError::RefDepthExceeded { .. }
                    | DataValidationError::RefStepBudgetExhausted { .. }
            ),
            "expected a bounded recursion error, got {err:?}"
        );
    }

    #[test]
    fn test_legitimate_recursive_union_still_validates() {
        let catalog = catalog_from(THREAD_LEXICON);

        let record = build_thread(50, None);
        let result = validate_record(
            "com.example.thread",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "50-level recursive union must still validate, got {result:?}"
        );

        // The fix must not "solve" recursion by skipping nested levels: a
        // violation buried 40 levels down still has to be reported.
        let broken = build_thread(50, Some(40));
        let err = validate_record(
            "com.example.thread",
            &broken,
            &catalog,
            ValidateFlags::empty(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DataValidationError::MissingRequiredProperty { ref property, .. } if property == "text"
            ),
            "expected MissingRequiredProperty for 'text', got {err:?}"
        );
    }

    #[test]
    fn test_strict_recursive_validation_applies_to_unions() {
        // Regression test: STRICT_RECURSIVE_VALIDATION was consulted only in
        // validate_ref, so recursive unions silently ignored it.
        let catalog = catalog_from(THREAD_LEXICON);
        let record = build_thread(3, None);

        let err = validate_record(
            "com.example.thread",
            &record,
            &catalog,
            ValidateFlags::STRICT_RECURSIVE_VALIDATION,
        )
        .unwrap_err();

        assert!(
            matches!(err, DataValidationError::RecursiveReference { .. }),
            "expected RecursiveReference under STRICT_RECURSIVE_VALIDATION, got {err:?}"
        );
    }

    #[test]
    fn test_large_record_stays_within_step_budget() {
        let lexicon = r##"{
            "lexicon": 1,
            "id": "com.example.bulk",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["items"],
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {"type": "ref", "ref": "#item"}
                            }
                        }
                    }
                },
                "item": {
                    "type": "object",
                    "required": ["v"],
                    "properties": {"v": {"type": "string"}}
                }
            }
        }"##;

        let catalog = catalog_from(lexicon);
        let items: Vec<serde_json::Value> = (0..10_000)
            .map(|i| serde_json::json!({"v": i.to_string()}))
            .collect();
        let record = serde_json::json!({"$type": "com.example.bulk", "items": items});

        let result = validate_record(
            "com.example.bulk",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "10k ref'd items must fit the default step budget, got {result:?}"
        );
    }

    /// Lexicon whose array elements sit behind a plain `ref` to an integer.
    const INT_ARRAY_LEXICON: &str = r##"{
        "lexicon": 1,
        "id": "com.example.ints",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["xs"],
                    "properties": {
                        "xs": {"type": "array", "items": {"type": "ref", "ref": "#n"}}
                    }
                }
            },
            "n": {"type": "integer"}
        }
    }"##;

    /// Lexicon whose array elements sit behind a four-branch open union, the
    /// shape a Bluesky embed union has. Elements carry no `$type`, so every
    /// branch is tried in order and only the last one matches.
    const OPEN_UNION_ARRAY_LEXICON: &str = r##"{
        "lexicon": 1,
        "id": "com.example.fanarray",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["items"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}
                        }
                    }
                }
            },
            "a": {"type": "object", "required": ["aa"], "properties": {"aa": {"type": "string"}}},
            "b": {"type": "object", "required": ["bb"], "properties": {"bb": {"type": "string"}}},
            "c": {"type": "object", "required": ["cc"], "properties": {"cc": {"type": "string"}}},
            "d": {"type": "object", "required": ["v"], "properties": {"v": {"type": "string"}}}
        }
    }"##;

    /// Build the `com.example.fanarray` record with `n` union elements.
    fn build_open_union_record(n: usize) -> serde_json::Value {
        let items: Vec<serde_json::Value> = (0..n).map(|_| serde_json::json!({"v": "x"})).collect();
        serde_json::json!({"$type": "com.example.fanarray", "items": items})
    }

    #[test]
    fn test_plain_ref_array_beyond_old_absolute_budget_is_accepted() {
        // Regression: with a flat 100,000-step budget this 300 KB record was
        // rejected at /xs/100000 even though nothing about it is hostile.
        let catalog = catalog_from(INT_ARRAY_LEXICON);
        let xs: Vec<serde_json::Value> = (0..150_000).map(serde_json::Value::from).collect();
        let record = serde_json::json!({"$type": "com.example.ints", "xs": xs});

        let result = validate_record(
            "com.example.ints",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "150k integers behind a ref must validate, got {result:?}"
        );
    }

    #[test]
    fn test_megabyte_record_with_open_union_per_element_is_accepted() {
        // Regression: a four-branch open union at every element costs about five
        // traversals per element, so a flat 100,000-step budget rejected this
        // record at roughly 20,000 elements. ~105k elements is about 1 MB of
        // JSON, the practical AT Protocol record ceiling.
        let catalog = catalog_from(OPEN_UNION_ARRAY_LEXICON);
        let record = build_open_union_record(105_000);
        assert!(
            serde_json::to_string(&record).unwrap().len() > 1_000_000,
            "test payload should be at least 1 MB"
        );

        let result = validate_record(
            "com.example.fanarray",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "1 MB record with an open union per element must validate, got {result:?}"
        );
    }

    #[test]
    fn test_nested_backtracking_fanout_is_bounded() {
        // The proportional allowance must not become an escape hatch. Here every
        // union candidate *descends* into a child value, so the hops are not
        // same-value re-entries, yet the search still explores 4^depth branches
        // because the innermost value fails. A 700-byte body must not buy that.
        let lexicon = r##"{
            "lexicon": 1,
            "id": "com.example.nestfan",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {"x": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}}
                    }
                },
                "a": {"type": "object", "required": ["x"], "properties": {"x": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}}},
                "b": {"type": "object", "required": ["x"], "properties": {"x": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}}},
                "c": {"type": "object", "required": ["x"], "properties": {"x": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}}},
                "d": {"type": "object", "required": ["x"], "properties": {"x": {"type": "union", "refs": ["#a", "#b", "#c", "#d"]}}}
            }
        }"##;

        // 60 levels of {"x": {...}} ending in {}: ~700 bytes, ~120 value nodes.
        let mut node = serde_json::json!({});
        for _ in 0..60 {
            node = serde_json::json!({"x": node});
        }
        let record = serde_json::json!({"$type": "com.example.nestfan", "x": node});
        assert!(serde_json::to_string(&record).unwrap().len() < 1_024);

        let started = std::time::Instant::now();
        let err = on_worker_stack(move || {
            let catalog = catalog_from(lexicon);
            validate_record(
                "com.example.nestfan",
                &record,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err()
        });
        let elapsed = started.elapsed();

        match err {
            DataValidationError::RefStepBudgetExhausted { max_steps, .. } => {
                assert!(
                    max_steps < DEFAULT_MAX_REF_STEPS + 10_000,
                    "small nested body granted {max_steps} steps"
                );
            }
            other => panic!("expected RefStepBudgetExhausted, got {other:?}"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "nested fan-out took {elapsed:?}"
        );
    }

    #[test]
    fn test_absolute_step_cap_still_available_to_callers() {
        // The proportional allowance is what fixes the false rejection: turning
        // it off reproduces the old cliff, so callers who want a hard ceiling
        // can still have one.
        let catalog = catalog_from(OPEN_UNION_ARRAY_LEXICON);
        let record = build_open_union_record(60_000);

        let err = validate_record_with_limits(
            "com.example.fanarray",
            &record,
            &catalog,
            ValidateFlags::empty(),
            ValidationLimits::default()
                .with_max_ref_steps(DEFAULT_MAX_REF_STEPS)
                .with_max_ref_steps_per_node(0),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DataValidationError::RefStepBudgetExhausted {
                    max_steps: DEFAULT_MAX_REF_STEPS,
                    ..
                }
            ),
            "expected the absolute cap to bite, got {err:?}"
        );

        // Same record, default (proportional) limits: accepted.
        assert!(
            validate_record(
                "com.example.fanarray",
                &record,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok(),
            "default limits must accept the same record"
        );
    }

    #[test]
    fn test_validation_limits_are_configurable() {
        let catalog = catalog_from(THREAD_LEXICON);
        let deep = build_thread(50, None);

        let err = validate_record_with_limits(
            "com.example.thread",
            &deep,
            &catalog,
            ValidateFlags::empty(),
            ValidationLimits::default().with_max_ref_depth(8),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DataValidationError::RefDepthExceeded { max_depth: 8, .. }
            ),
            "expected RefDepthExceeded with max_depth 8, got {err:?}"
        );

        // A zero per-node allowance makes max_ref_steps an absolute cap.
        let err = validate_record_with_limits(
            "com.example.thread",
            &deep,
            &catalog,
            ValidateFlags::empty(),
            ValidationLimits::default()
                .with_max_ref_steps(4)
                .with_max_ref_steps_per_node(0),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                DataValidationError::RefStepBudgetExhausted { max_steps: 4, .. }
            ),
            "expected RefStepBudgetExhausted with max_steps 4, got {err:?}"
        );

        // Default limits are unchanged for ordinary data.
        let shallow = build_thread(3, None);
        assert!(
            validate_record(
                "com.example.thread",
                &shallow,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_step_budget_applies_to_procedure_and_query_entry_points() {
        let procedure = r##"{
            "lexicon": 1,
            "id": "com.example.ploop",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "properties": {"x": {"type": "union", "refs": ["#loop"]}}
                        }
                    }
                },
                "loop": {"type": "union", "refs": ["#loop"]}
            }
        }"##;
        let query = r##"{
            "lexicon": 1,
            "id": "com.example.qloop",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "properties": {"x": {"type": "union", "refs": ["#loop"]}}
                    }
                },
                "loop": {"type": "union", "refs": ["#loop"]}
            }
        }"##;

        on_worker_stack(move || {
            let body = serde_json::json!({"x": {}});

            let catalog = catalog_from(procedure);
            let err = validate_procedure_input(
                "com.example.ploop",
                &body,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err();
            assert!(
                matches!(err, DataValidationError::RecursiveReference { .. }),
                "validate_procedure_input: expected RecursiveReference, got {err:?}"
            );

            let schema_file = SchemaFile::parse(procedure).unwrap();
            let err = validate_procedure_input_with_schema(
                &body,
                &schema_file,
                &catalog,
                ValidateFlags::empty(),
            )
            .unwrap_err();
            assert!(
                matches!(err, DataValidationError::RecursiveReference { .. }),
                "validate_procedure_input_with_schema: expected RecursiveReference, got {err:?}"
            );

            let catalog = catalog_from(query);
            let err =
                validate_query_params("com.example.qloop", &body, &catalog, ValidateFlags::empty())
                    .unwrap_err();
            assert!(
                matches!(err, DataValidationError::RecursiveReference { .. }),
                "validate_query_params: expected RecursiveReference, got {err:?}"
            );
        });
    }

    #[test]
    fn test_depth_counter_does_not_leak_across_siblings() {
        // Each array item tries a ref chain that trips the depth limit, then
        // falls back to a matching def. If exit_hop were skipped on the error
        // path the counter would ratchet up and later items would be rejected.
        let mut defs = String::new();
        for i in 0..39 {
            defs.push_str(&format!(
                "\"d{}\": {{\"type\": \"ref\", \"ref\": \"#d{}\"}},",
                i,
                i + 1
            ));
        }
        defs.push_str(r##""d39": {"type": "object", "required": ["nope"], "properties": {"nope": {"type": "string"}}},"##);
        defs.push_str(
            r##""ok": {"type": "object", "required": ["v"], "properties": {"v": {"type": "string"}}}"##,
        );
        let lexicon = format!(
            r##"{{"lexicon": 1, "id": "com.example.siblings", "defs": {{
                "main": {{"type": "record", "key": "tid", "record": {{
                    "type": "object",
                    "required": ["items"],
                    "properties": {{"items": {{"type": "array", "items": {{
                        "type": "union", "refs": ["#d0", "#ok"]
                    }}}}}}
                }}}},
                {}
            }}}}"##,
            defs
        );

        let catalog = catalog_from(&lexicon);
        let items: Vec<serde_json::Value> = (0..300)
            .map(|i| serde_json::json!({"v": i.to_string()}))
            .collect();
        let record = serde_json::json!({"$type": "com.example.siblings", "items": items});

        let result = validate_record_with_limits(
            "com.example.siblings",
            &record,
            &catalog,
            ValidateFlags::empty(),
            ValidationLimits::default().with_max_ref_depth(16),
        );
        assert!(
            result.is_ok(),
            "300 siblings must all validate after recovered depth errors, got {result:?}"
        );
    }

    /// Two sibling properties whose unions share candidate defs. Validating
    /// `a.u` tries `#alpha` first, which fails one level deeper (at `q`).
    const LEAK_LEXICON: &str = r##"{
        "lexicon": 1,
        "id": "com.example.leak",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["a", "b"],
                    "properties": {
                        "a": {"type": "ref", "ref": "#wrapper"},
                        "b": {"type": "union", "refs": ["#alpha", "#beta"]}
                    }
                }
            },
            "wrapper": {
                "type": "object",
                "required": ["u"],
                "properties": {"u": {"type": "union", "refs": ["#alpha", "#beta"]}}
            },
            "alpha": {
                "type": "object",
                "required": ["q"],
                "properties": {"q": {"type": "integer"}}
            },
            "beta": {
                "type": "object",
                "required": ["q"],
                "properties": {"q": {"type": "string"}}
            }
        }
    }"##;

    #[test]
    fn test_union_frame_does_not_leak_across_siblings() {
        // Regression test: the union frame key was read from the live
        // `ctx.path` at exit, while validate_object left a path segment pushed
        // when a candidate failed. The mismatched key left a stale frame
        // behind, and the later sibling's matching candidate was skipped as a
        // non-productive cycle.
        let catalog = catalog_from(LEAK_LEXICON);

        // Control: `#alpha` succeeds under "a", so nothing is left behind.
        let control =
            serde_json::json!({"$type": "com.example.leak", "a": {"u": {"q": 1}}, "b": {"q": 5}});
        assert!(
            validate_record(
                "com.example.leak",
                &control,
                &catalog,
                ValidateFlags::empty()
            )
            .is_ok(),
            "control record must validate"
        );

        // "a.u" matches #beta only after #alpha fails; "b" matches #alpha.
        let record = serde_json::json!({
            "$type": "com.example.leak",
            "a": {"u": {"q": "text"}},
            "b": {"q": 5}
        });
        let result = validate_record(
            "com.example.leak",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "valid record was falsely rejected: {result:?}"
        );
    }

    #[test]
    fn test_union_frame_does_not_leak_across_array_items() {
        // Same leak reached through validate_array: the first item's leading
        // candidate fails deep, and the second item must still be able to use
        // that candidate.
        let lexicon = r##"{
            "lexicon": 1,
            "id": "com.example.leakarr",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["items"],
                        "properties": {
                            "items": {
                                "type": "array",
                                "items": {"type": "union", "refs": ["#alpha", "#beta"]}
                            }
                        }
                    }
                },
                "alpha": {
                    "type": "object",
                    "required": ["q"],
                    "properties": {"q": {"type": "integer"}}
                },
                "beta": {
                    "type": "object",
                    "required": ["q"],
                    "properties": {"q": {"type": "string"}}
                }
            }
        }"##;

        let catalog = catalog_from(lexicon);
        let record = serde_json::json!({
            "$type": "com.example.leakarr",
            "items": [{"q": "text"}, {"q": 5}, {"q": "more"}, {"q": 7}]
        });
        let result = validate_record(
            "com.example.leakarr",
            &record,
            &catalog,
            ValidateFlags::empty(),
        );
        assert!(
            result.is_ok(),
            "array of mixed union members was falsely rejected: {result:?}"
        );

        // A genuinely invalid item must be reported at its own path, not at a
        // path inherited from an earlier item's failed candidate.
        let broken = serde_json::json!({
            "$type": "com.example.leakarr",
            "items": [{"q": "text"}, {"q": 5}, {"q": true}]
        });
        let err = validate_record(
            "com.example.leakarr",
            &broken,
            &catalog,
            ValidateFlags::empty(),
        )
        .unwrap_err();
        match err {
            DataValidationError::TypeMismatch { ref path, .. } => {
                assert_eq!(path, "/items/2/q", "error path was polluted: {err:?}");
            }
            other => panic!("expected TypeMismatch at /items/2/q, got {other:?}"),
        }
    }

    #[test]
    fn test_error_path_is_not_polluted_by_failed_union_candidates() {
        // The unbalanced push/pop also corrupted reported error paths: the
        // failure below is at "/b/q", not "/a/b/q".
        let catalog = catalog_from(LEAK_LEXICON);
        let record = serde_json::json!({
            "$type": "com.example.leak",
            "a": {"u": {"q": "text"}},
            "b": {"q": true}
        });
        let err = validate_record(
            "com.example.leak",
            &record,
            &catalog,
            ValidateFlags::empty(),
        )
        .unwrap_err();
        match err {
            DataValidationError::TypeMismatch { ref path, .. } => {
                assert_eq!(path, "/b/q", "error path was polluted: {err:?}");
            }
            other => panic!("expected TypeMismatch at /b/q, got {other:?}"),
        }
    }

    #[test]
    fn test_params_path_is_not_polluted_by_failed_union_candidates() {
        // validate_params had the same unbalanced push/pop.
        let lexicon = r##"{
            "lexicon": 1,
            "id": "com.example.leakparams",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "required": ["one", "two"],
                        "properties": {
                            "one": {"type": "string"},
                            "two": {"type": "integer"}
                        }
                    }
                }
            }
        }"##;

        let catalog = catalog_from(lexicon);
        let params = serde_json::json!({"one": 1, "two": 2});
        let err = validate_query_params(
            "com.example.leakparams",
            &params,
            &catalog,
            ValidateFlags::empty(),
        )
        .unwrap_err();
        match err {
            DataValidationError::TypeMismatch { ref path, .. } => {
                assert_eq!(path, "/one", "error path was polluted: {err:?}");
            }
            other => panic!("expected TypeMismatch at /one, got {other:?}"),
        }
    }
}
