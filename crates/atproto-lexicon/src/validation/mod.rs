//! Lexicon validation functionality for AT Protocol.
//!
//! This module provides validation of lexicon NSIDs, references, schemas,
//! and data values against lexicon schema definitions.
//!
//! ## Submodules
//!
//! - `nsid`: NSID parsing, validation, and DNS name conversion
//! - [`data_types`]: AT Protocol data model types for validation
//! - [`data_errors`]: Error types for data validation operations
//! - [`flags`]: Configuration flags for validation behavior
//! - [`limits`]: Resource limits bounding validation recursion and CPU
//! - [`mimetype`]: MIME type matching utilities
//! - [`parse`]: JSON to DataValue parsing
//! - [`schema`]: Lexicon schema type definitions
//! - [`schema_file`]: Lexicon schema file parsing and validation
//! - [`syntax`]: String format validators for AT Protocol types
//! - [`validate`]: Core validation logic and catalog trait

mod nsid;

pub mod data_errors;
pub mod data_types;
pub mod flags;
pub mod limits;
pub mod mimetype;
pub mod parse;
pub mod schema;
pub mod schema_file;
pub mod syntax;
pub mod validate;

// Re-export all existing symbols from nsid for backwards compatibility
pub use nsid::{
    NsidParts, absolute, extract_nsid_from_ref_object, extract_nsid_from_reference,
    extract_nsids_from_union_object, is_reference_object, is_union_object, is_valid_nsid,
    is_valid_reference, nsid_to_dns_name, parse_nsid, validate_lexicon_schema,
};

// Re-export key types from new validation modules
pub use data_errors::DataValidationError;
pub use data_types::{Blob, Bytes, CIDLink, DataValue};
pub use flags::ValidateFlags;
pub use limits::{
    DEFAULT_MAX_REF_DEPTH, DEFAULT_MAX_REF_STEPS, DEFAULT_MAX_REF_STEPS_PER_NODE, ValidationLimits,
};
pub use schema::SchemaDef;
pub use schema_file::SchemaFile;
pub use validate::{
    BaseCatalog, Catalog, Schema, validate_procedure_input, validate_procedure_input_with_limits,
    validate_procedure_input_with_schema, validate_procedure_input_with_schema_and_limits,
    validate_procedure_params, validate_procedure_params_with_limits,
    validate_procedure_params_with_schema, validate_procedure_params_with_schema_and_limits,
    validate_query_params, validate_query_params_with_limits, validate_query_params_with_schema,
    validate_query_params_with_schema_and_limits, validate_record, validate_record_with_limits,
    validate_record_with_schema, validate_record_with_schema_and_limits,
};
