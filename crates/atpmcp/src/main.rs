//! AT Protocol MCP server for identity, record, and lexicon operations.
//!
//! This binary implements a Model Context Protocol (MCP) server that
//! communicates over stdio using JSON-RPC 2.0. It provides tools for
//! CID computation, lexicon validation, identity resolution, facet
//! parsing, and record retrieval.
//!
//! # MCP Protocol
//!
//! The server uses the MCP stdio transport:
//! - stdin: receives newline-delimited JSON-RPC 2.0 messages
//! - stdout: sends newline-delimited JSON-RPC 2.0 responses
//! - stderr: used for tracing/logging output
//!
//! # Tools
//!
//! - `create_record_cid` — Compute the DAG-CBOR CID for a JSON record
//! - `validate_lexicon_schema` — Validate a lexicon schema object
//! - `resolve_handle_to_did` — Resolve an AT Protocol handle to a DID
//! - `resolve_identity` — Resolve a DID to its full DID document
//! - `parse_facets` — Parse rich text facets from plain text
//! - `get_record` — Retrieve an AT Protocol record by AT-URI
//! - `get_lexicon` — Fetch a lexicon schema record by NSID
//! - `validate_xrpc` — Validate XRPC parameters against a lexicon schema
//! - `invoke_xrpc` — Make an XRPC request to an AT Protocol service

mod errors;

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

use atproto_client::client::{
    AppPasswordAuth, get_apppassword_json_with_headers, get_json_with_headers,
    post_apppassword_json_with_headers, post_json_with_headers,
};
use atproto_client::com::atproto::server::{create_session, refresh_session};
use atproto_identity::resolve::{HickoryDnsResolver, InnerIdentityResolver};
use atproto_identity::url::build_url;
use errors::ToolError;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_subscriber::EnvFilter;

/// MCP protocol version supported by this server.
const PROTOCOL_VERSION: &str = "2025-11-25";

/// JSON-RPC error code for parse errors.
const PARSE_ERROR: i64 = -32700;

/// JSON-RPC error code for invalid requests.
const INVALID_REQUEST: i64 = -32600;

/// JSON-RPC error code for method not found.
const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC error code for invalid params.
const INVALID_PARAMS: i64 = -32602;

// -- JSON-RPC types --

/// An incoming JSON-RPC 2.0 request or notification.
#[derive(Debug, Deserialize)]
struct JsonRpcMessage {
    /// Must be "2.0".
    #[allow(dead_code)]
    jsonrpc: String,
    /// Request ID. Absent for notifications.
    id: Option<Value>,
    /// Method name.
    method: String,
    /// Optional parameters.
    params: Option<Value>,
}

/// An outgoing JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl JsonRpcResponse {
    /// Create a success response.
    fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// -- MCP handlers --

/// Handle the `initialize` request.
fn handle_initialize() -> Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "atpmcp",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

/// Handle the `tools/list` request.
fn handle_tools_list() -> Value {
    serde_json::json!({
        "tools": [
            {
                "name": "create_record_cid",
                "description": "Compute the DAG-CBOR CID for a JSON record. Accepts a JSON object, serializes it to DAG-CBOR, hashes with SHA-256, and returns the CIDv1 string.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "record": {
                            "type": "object",
                            "description": "The JSON record object to compute a CID for."
                        }
                    },
                    "required": ["record"],
                    "additionalProperties": false
                }
            },
            {
                "name": "validate_lexicon_schema",
                "description": "Validate a lexicon schema object. Accepts a JSON object representing a lexicon schema and validates its structure, version, NSID, and definitions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "schema": {
                            "type": "object",
                            "description": "The lexicon schema to validate."
                        }
                    },
                    "required": ["schema"],
                    "additionalProperties": false
                }
            },
            {
                "name": "resolve_handle_to_did",
                "description": "Resolve an AT Protocol handle to its DID. Accepts a handle string (e.g. 'alice.bsky.social') and returns the resolved DID (e.g. 'did:plc:abc123').",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "handle": {
                            "type": "string",
                            "description": "The AT Protocol handle to resolve."
                        }
                    },
                    "required": ["handle"],
                    "additionalProperties": false
                }
            },
            {
                "name": "resolve_identity",
                "description": "Resolve a DID to its full DID document. Accepts a DID string and returns the complete DID document as JSON.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "did": {
                            "type": "string",
                            "description": "The DID to resolve."
                        },
                        "plc_directory_hostname": {
                            "type": "string",
                            "description": "PLC directory hostname override, defaults to 'plc.directory'."
                        }
                    },
                    "required": ["did"],
                    "additionalProperties": false
                }
            },
            {
                "name": "parse_facets",
                "description": "Parse rich text facets (mentions, URLs, and hashtags) from plain text. Returns AT Protocol facets with correct UTF-8 byte offsets. Mentions are resolved to DIDs when possible.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The plain text to parse for facets."
                        }
                    },
                    "required": ["text"],
                    "additionalProperties": false
                }
            },
            {
                "name": "get_record",
                "description": "Retrieve an AT Protocol record by AT-URI. Resolves the identity, finds the PDS endpoint, and retrieves the record using com.atproto.repo.getRecord with unauthenticated access.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "uri": {
                            "type": "string",
                            "description": "The AT-URI of the record to retrieve (e.g. 'at://did:plc:abc123/app.bsky.feed.post/rkey')."
                        },
                        "cid": {
                            "type": "string",
                            "description": "Specific version CID to retrieve."
                        },
                        "plc_directory_hostname": {
                            "type": "string",
                            "description": "PLC directory hostname override, defaults to 'plc.directory'."
                        }
                    },
                    "required": ["uri"],
                    "additionalProperties": false
                }
            },
            {
                "name": "get_lexicon",
                "description": "Fetch a lexicon schema record by NSID. Resolves the authority from the NSID via DNS if no repository is provided, then retrieves the lexicon from the repository's PDS.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "nsid": {
                            "type": "string",
                            "description": "The NSID of the lexicon to fetch (e.g. 'app.bsky.feed.post')."
                        },
                        "repo": {
                            "type": "string",
                            "description": "Optional repository DID or handle. If omitted, the authority is resolved from the NSID via DNS."
                        }
                    },
                    "required": ["nsid"],
                    "additionalProperties": false
                }
            },
            {
                "name": "validate_xrpc",
                "description": "Validate XRPC parameters and input body against a lexicon schema. Fetches the lexicon for the given NSID, determines whether it defines a query or procedure, and validates the provided params and/or body accordingly.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "nsid": {
                            "type": "string",
                            "description": "The XRPC method NSID (e.g. 'com.atproto.repo.describeRepo')."
                        },
                        "params": {
                            "type": "object",
                            "description": "Query or procedure parameters to validate."
                        },
                        "body": {
                            "type": "object",
                            "description": "Procedure input body to validate."
                        },
                        "repo": {
                            "type": "string",
                            "description": "Optional repository DID or handle for lexicon resolution. If omitted, the authority is resolved from the NSID via DNS."
                        }
                    },
                    "required": ["nsid"],
                    "additionalProperties": false
                }
            },
            {
                "name": "invoke_xrpc",
                "description": "Make an XRPC request to an AT Protocol service. Supports queries (GET) and procedures (POST). If a JSON body is provided, a POST is made; otherwise GET. Supports unauthenticated, authenticated (via stored atpxrpc credentials), and proxied requests (via the atproto-proxy header through the authenticated user's PDS).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "nsid": {
                            "type": "string",
                            "description": "The XRPC method NSID (e.g. 'com.atproto.repo.describeRepo')."
                        },
                        "params": {
                            "type": "object",
                            "description": "Query parameters as key-value string pairs for GET requests.",
                            "additionalProperties": { "type": "string" }
                        },
                        "body": {
                            "type": "object",
                            "description": "JSON body for POST (procedure) requests. If present, the request is a POST."
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "Explicit service endpoint URL (e.g. 'https://bsky.network'). Either endpoint, identity, or auth_handle is required."
                        },
                        "identity": {
                            "type": "string",
                            "description": "Handle or DID to resolve for PDS endpoint discovery. Either endpoint, identity, or auth_handle is required."
                        },
                        "auth_handle": {
                            "type": "string",
                            "description": "Handle of a stored atpxrpc account for authenticated requests. If omitted, the request is unauthenticated."
                        },
                        "proxy": {
                            "type": "string",
                            "description": "Service audience for proxied requests in DID#serviceId format (e.g. 'did:web:api.bsky.app#bsky_fg'). Requires auth_handle. The request is sent to the authenticated user's PDS with the atproto-proxy header set to this value."
                        }
                    },
                    "required": ["nsid"],
                    "additionalProperties": false
                }
            },
            {
                "name": "generate_tid",
                "description": "Generate AT Protocol Timestamp Identifiers (TIDs). TIDs are 13-character base32-sortable strings used as record keys. Optionally generate multiple TIDs or generate from a specific microsecond timestamp.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "count": {
                            "type": "integer",
                            "description": "Number of TIDs to generate (default 1, max 100)."
                        },
                        "timestamp_micros": {
                            "type": "integer",
                            "description": "Specific microsecond UNIX timestamp to generate from. If omitted, uses current time."
                        }
                    },
                    "additionalProperties": false
                }
            }
        ]
    })
}

/// Handle the `tools/call` request.
async fn handle_tools_call(
    id: Value,
    params: Option<Value>,
    resolver: &InnerIdentityResolver,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing params");
    };

    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing tool name");
    };

    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    match name {
        "create_record_cid" => JsonRpcResponse::success(id, handle_create_record_cid(arguments)),
        "validate_lexicon_schema" => {
            JsonRpcResponse::success(id, handle_validate_lexicon_schema(arguments))
        }
        "resolve_handle_to_did" => {
            JsonRpcResponse::success(id, handle_resolve_handle_to_did(arguments, resolver).await)
        }
        "resolve_identity" => {
            JsonRpcResponse::success(id, handle_resolve_identity(arguments, resolver).await)
        }
        "parse_facets" => {
            JsonRpcResponse::success(id, handle_parse_facets(arguments, resolver).await)
        }
        "get_record" => JsonRpcResponse::success(id, handle_get_record(arguments, resolver).await),
        "get_lexicon" => {
            JsonRpcResponse::success(id, handle_get_lexicon(arguments, resolver).await)
        }
        "validate_xrpc" => {
            JsonRpcResponse::success(id, handle_validate_xrpc(arguments, resolver).await)
        }
        "invoke_xrpc" => {
            JsonRpcResponse::success(id, handle_invoke_xrpc(arguments, resolver).await)
        }
        "generate_tid" => JsonRpcResponse::success(id, handle_generate_tid(arguments)),
        _ => JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("Unknown tool: {name}")),
    }
}

/// Execute the `create_record_cid` tool.
fn handle_create_record_cid(arguments: Value) -> Value {
    let record = arguments.get("record").cloned().unwrap_or(Value::Null);

    if !record.is_object() {
        return tool_error("The 'record' argument must be a JSON object.");
    }

    match atproto_dasl::compute_cid_for(&record) {
        Ok(cid) => tool_success(&cid.to_string()),
        Err(error) => {
            let tool_err = ToolError::SerializationFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, "DAG-CBOR serialization failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `validate_lexicon_schema` tool.
fn handle_validate_lexicon_schema(arguments: Value) -> Value {
    let schema = arguments.get("schema").cloned().unwrap_or(Value::Null);

    if !schema.is_object() {
        return tool_error("The 'schema' argument must be a JSON object.");
    }

    match atproto_lexicon::validation::schema_file::SchemaFile::from_value(schema) {
        Ok(schema_file) => tool_success(&format!("Lexicon schema '{}' is valid.", schema_file.id)),
        Err(error) => {
            let tool_err = ToolError::ValidationFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, "Lexicon schema validation failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `resolve_handle_to_did` tool.
async fn handle_resolve_handle_to_did(arguments: Value, resolver: &InnerIdentityResolver) -> Value {
    let Some(handle) = arguments.get("handle").and_then(Value::as_str) else {
        return tool_error("The 'handle' argument must be a string.");
    };

    match resolver.resolve(handle).await {
        Ok(document) => tool_success(&document.id),
        Err(error) => {
            let tool_err = ToolError::HandleResolutionFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, handle = %handle, "Handle resolution failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `resolve_identity` tool.
async fn handle_resolve_identity(
    arguments: Value,
    default_resolver: &InnerIdentityResolver,
) -> Value {
    let Some(did) = arguments.get("did").and_then(Value::as_str) else {
        return tool_error("The 'did' argument must be a string.");
    };

    let plc_hostname = arguments
        .get("plc_directory_hostname")
        .and_then(Value::as_str)
        .unwrap_or("plc.directory");

    let resolver = if plc_hostname == "plc.directory" {
        default_resolver
    } else {
        &InnerIdentityResolver {
            dns_resolver: default_resolver.dns_resolver.clone(),
            http_client: default_resolver.http_client.clone(),
            plc_hostname: plc_hostname.to_string(),
        }
    };

    match resolver.resolve(did).await {
        Ok(document) => match serde_json::to_string(&document) {
            Ok(json) => tool_success(&json),
            Err(error) => {
                let tool_err = ToolError::IdentityResolutionFailed {
                    reason: error.to_string(),
                };
                tracing::error!(error = ?error, "Failed to serialize DID document.");
                tool_error(&tool_err.to_string())
            }
        },
        Err(error) => {
            let tool_err = ToolError::IdentityResolutionFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, did = %did, "Identity resolution failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `parse_facets` tool.
async fn handle_parse_facets(arguments: Value, resolver: &InnerIdentityResolver) -> Value {
    let Some(text) = arguments.get("text").and_then(Value::as_str) else {
        return tool_error("The 'text' argument must be a string.");
    };

    let limits = atproto_extras::FacetLimits::default();

    match atproto_extras::parse_facets_from_text(text, resolver, &limits).await {
        Some(facets) => match serde_json::to_string(&facets) {
            Ok(json) => tool_success(&json),
            Err(error) => {
                let tool_err = ToolError::FacetParsingFailed {
                    reason: error.to_string(),
                };
                tracing::error!(error = ?error, "Failed to serialize facets.");
                tool_error(&tool_err.to_string())
            }
        },
        None => tool_success("[]"),
    }
}

/// Execute the `get_record` tool.
async fn handle_get_record(arguments: Value, default_resolver: &InnerIdentityResolver) -> Value {
    let Some(uri) = arguments.get("uri").and_then(Value::as_str) else {
        return tool_error("The 'uri' argument must be a string.");
    };

    let cid = arguments.get("cid").and_then(Value::as_str);

    let plc_hostname = arguments
        .get("plc_directory_hostname")
        .and_then(Value::as_str)
        .unwrap_or("plc.directory");

    let aturi = match uri.parse::<atproto_record::aturi::ATURI>() {
        Ok(aturi) => aturi,
        Err(error) => {
            let tool_err = ToolError::RecordRetrievalFailed {
                reason: format!("Invalid AT-URI: {error}"),
            };
            tracing::error!(error = ?error, uri = %uri, "Failed to parse AT-URI.");
            return tool_error(&tool_err.to_string());
        }
    };

    let resolver = if plc_hostname == "plc.directory" {
        default_resolver
    } else {
        &InnerIdentityResolver {
            dns_resolver: default_resolver.dns_resolver.clone(),
            http_client: default_resolver.http_client.clone(),
            plc_hostname: plc_hostname.to_string(),
        }
    };

    let document = match resolver.resolve(&aturi.authority).await {
        Ok(doc) => doc,
        Err(error) => {
            let tool_err = ToolError::RecordRetrievalFailed {
                reason: format!("Failed to resolve identity: {error}"),
            };
            tracing::error!(error = ?error, authority = %aturi.authority, "Identity resolution failed.");
            return tool_error(&tool_err.to_string());
        }
    };

    let pds_endpoints = document.pds_endpoints();
    let Some(pds_url) = pds_endpoints.first() else {
        let tool_err = ToolError::RecordRetrievalFailed {
            reason: "No PDS endpoint found in DID document".to_string(),
        };
        tracing::error!(did = %aturi.authority, "No PDS endpoint found.");
        return tool_error(&tool_err.to_string());
    };

    match atproto_client::com::atproto::repo::get_record(
        &default_resolver.http_client,
        &atproto_client::client::Auth::None,
        pds_url,
        &aturi.authority,
        &aturi.collection,
        &aturi.record_key,
        cid,
    )
    .await
    {
        Ok(atproto_client::com::atproto::repo::GetRecordResponse::Record { value, .. }) => {
            match serde_json::to_string(&value) {
                Ok(json) => tool_success(&json),
                Err(error) => {
                    let tool_err = ToolError::RecordRetrievalFailed {
                        reason: error.to_string(),
                    };
                    tracing::error!(error = ?error, "Failed to serialize record.");
                    tool_error(&tool_err.to_string())
                }
            }
        }
        Ok(atproto_client::com::atproto::repo::GetRecordResponse::Error(err)) => {
            let error_str = err.error.as_deref().unwrap_or("unknown");
            let message_str = err.message.as_deref().unwrap_or("unknown");
            let tool_err = ToolError::RecordRetrievalFailed {
                reason: format!("{error_str}: {message_str}"),
            };
            tracing::error!(error = %error_str, message = %message_str, "Record retrieval returned error.");
            tool_error(&tool_err.to_string())
        }
        Err(error) => {
            let tool_err = ToolError::RecordRetrievalFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, uri = %uri, "Record retrieval failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `validate_xrpc` tool.
async fn handle_validate_xrpc(arguments: Value, resolver: &InnerIdentityResolver) -> Value {
    let Some(nsid) = arguments.get("nsid").and_then(Value::as_str) else {
        return tool_error("The 'nsid' argument must be a string.");
    };

    let params = arguments.get("params").cloned();
    let body = arguments.get("body").cloned();
    let repo = arguments.get("repo").and_then(Value::as_str);

    // Fetch the lexicon schema.
    let lexicon_value = match atproto_lexicon::resolve::get_lexicon(
        &resolver.http_client,
        resolver.dns_resolver.as_ref(),
        nsid,
        repo,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let tool_err = ToolError::XrpcValidationFailed {
                reason: format!("Failed to fetch lexicon for {nsid}: {error}"),
            };
            tracing::error!(error = ?error, nsid = %nsid, "Lexicon retrieval failed for validation.");
            return tool_error(&tool_err.to_string());
        }
    };

    // Parse into a SchemaFile.
    let schema_file =
        match atproto_lexicon::validation::schema_file::SchemaFile::from_value(lexicon_value) {
            Ok(sf) => sf,
            Err(error) => {
                let tool_err = ToolError::XrpcValidationFailed {
                    reason: format!("Invalid lexicon schema for {nsid}: {error}"),
                };
                tracing::error!(error = ?error, nsid = %nsid, "Lexicon schema parse failed.");
                return tool_error(&tool_err.to_string());
            }
        };

    // Determine method type from the main definition.
    let main_def = match schema_file.defs.get("main") {
        Some(def) => def,
        None => {
            let tool_err = ToolError::XrpcValidationFailed {
                reason: format!("Lexicon {nsid} has no main definition"),
            };
            return tool_error(&tool_err.to_string());
        }
    };

    let is_query = matches!(main_def, atproto_lexicon::validation::SchemaDef::Query(_));
    let is_procedure = matches!(
        main_def,
        atproto_lexicon::validation::SchemaDef::Procedure(_)
    );

    if !is_query && !is_procedure {
        let tool_err = ToolError::XrpcValidationFailed {
            reason: format!("Lexicon {nsid} main definition is not a query or procedure"),
        };
        return tool_error(&tool_err.to_string());
    }

    // Build a catalog with this schema.
    let mut catalog = atproto_lexicon::validation::BaseCatalog::new();
    catalog.add_schema(schema_file);
    let flags = atproto_lexicon::validation::ValidateFlags::empty();

    let mut validated = Vec::new();
    let mut errors = Vec::new();

    // Validate params if provided.
    if let Some(ref params_value) = params {
        let result = if is_query {
            atproto_lexicon::validation::validate_query_params(nsid, params_value, &catalog, flags)
        } else {
            atproto_lexicon::validation::validate_procedure_params(
                nsid,
                params_value,
                &catalog,
                flags,
            )
        };
        match result {
            Ok(()) => validated.push("params"),
            Err(error) => errors.push(format!("params: {error}")),
        }
    }

    // Validate body if provided (only for procedures).
    if let Some(ref body_value) = body {
        if is_query {
            errors.push("body: queries do not accept an input body".to_string());
        } else {
            match atproto_lexicon::validation::validate_procedure_input(
                nsid, body_value, &catalog, flags,
            ) {
                Ok(()) => validated.push("body"),
                Err(error) => errors.push(format!("body: {error}")),
            }
        }
    }

    if !errors.is_empty() {
        let tool_err = ToolError::XrpcValidationFailed {
            reason: errors.join("; "),
        };
        tracing::error!(nsid = %nsid, "XRPC validation failed.");
        return tool_error(&tool_err.to_string());
    }

    let method_type = if is_query { "query" } else { "procedure" };
    if validated.is_empty() {
        tool_success(&format!(
            "Lexicon {nsid} is a valid {method_type}. No params or body were provided to validate."
        ))
    } else {
        tool_success(&format!(
            "Validation passed for {method_type} {nsid}: {} validated successfully.",
            validated.join(" and ")
        ))
    }
}

/// Execute the `get_lexicon` tool.
async fn handle_get_lexicon(arguments: Value, resolver: &InnerIdentityResolver) -> Value {
    let Some(nsid) = arguments.get("nsid").and_then(Value::as_str) else {
        return tool_error("The 'nsid' argument must be a string.");
    };

    let repo = arguments.get("repo").and_then(Value::as_str);

    match atproto_lexicon::resolve::get_lexicon(
        &resolver.http_client,
        resolver.dns_resolver.as_ref(),
        nsid,
        repo,
    )
    .await
    {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => tool_success(&json),
            Err(error) => {
                let tool_err = ToolError::LexiconRetrievalFailed {
                    reason: error.to_string(),
                };
                tracing::error!(error = ?error, "Failed to serialize lexicon.");
                tool_error(&tool_err.to_string())
            }
        },
        Err(error) => {
            let tool_err = ToolError::LexiconRetrievalFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, nsid = %nsid, "Lexicon retrieval failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// A stored atpxrpc account with session credentials.
#[derive(Clone, Serialize, Deserialize)]
struct XrpcAccount {
    /// The account handle.
    handle: String,
    /// The resolved DID.
    did: String,
    /// The PDS endpoint URL.
    pds_endpoint: String,
    /// The app password used for re-authentication.
    app_password: String,
    /// The current JWT access token.
    access_jwt: String,
    /// The current JWT refresh token.
    refresh_jwt: String,
}

/// Persistent atpxrpc configuration.
#[derive(Serialize, Deserialize)]
struct XrpcConfig {
    /// List of authenticated accounts.
    accounts: Vec<XrpcAccount>,
}

/// Returns the path to the atpxrpc config file.
fn xrpc_config_path() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("ATPXRPC_CONFIG") {
        return Ok(std::path::PathBuf::from(path));
    }
    let config_dir = dirs::config_dir().ok_or_else(|| {
        anyhow::anyhow!(
            "error-atpmcp-tool-8 XRPC request failed: could not determine config directory"
        )
    })?;
    Ok(config_dir.join("atpxrpc").join("config.json"))
}

/// Loads the atpxrpc config from disk.
fn load_xrpc_config() -> anyhow::Result<XrpcConfig> {
    let path = xrpc_config_path()?;

    let content = std::fs::read_to_string(&path).map_err(|error| {
        anyhow::anyhow!(
            "error-atpmcp-tool-8 XRPC request failed: could not read config file {}: {error}",
            path.display()
        )
    })?;

    let config: XrpcConfig = serde_json::from_str(&content).map_err(|error| {
        anyhow::anyhow!(
            "error-atpmcp-tool-8 XRPC request failed: could not parse config file {}: {error}",
            path.display()
        )
    })?;

    Ok(config)
}

/// Saves the atpxrpc config to disk.
fn save_xrpc_config(config: &XrpcConfig) -> anyhow::Result<()> {
    let path = xrpc_config_path()?;
    let content = serde_json::to_string_pretty(config).map_err(|error| {
        anyhow::anyhow!(
            "error-atpmcp-tool-8 XRPC request failed: could not serialize config: {error}"
        )
    })?;
    std::fs::write(&path, content).map_err(|error| {
        anyhow::anyhow!(
            "error-atpmcp-tool-8 XRPC request failed: could not write config file {}: {error}",
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Updates a single account in the config file by matching on DID.
fn update_xrpc_account(account: &XrpcAccount) -> anyhow::Result<()> {
    let mut config = load_xrpc_config()?;
    if let Some(existing) = config.accounts.iter_mut().find(|a| a.did == account.did) {
        *existing = account.clone();
    }
    save_xrpc_config(&config)?;
    Ok(())
}

/// Loads an atpxrpc account by handle, returning the account or a tool error.
fn load_xrpc_account(handle: &str) -> Result<XrpcAccount, Value> {
    let config = load_xrpc_config().map_err(|error| {
        let tool_err = ToolError::XrpcRequestFailed {
            reason: error.to_string(),
        };
        tracing::error!(error = ?error, "Failed to load atpxrpc config.");
        tool_error(&tool_err.to_string())
    })?;

    let account = config
        .accounts
        .into_iter()
        .find(|a| a.handle == handle)
        .ok_or_else(|| {
            let tool_err = ToolError::XrpcRequestFailed {
                reason: format!("No account found for handle '{handle}'"),
            };
            tool_error(&tool_err.to_string())
        })?;

    Ok(account)
}

/// Checks if an XRPC JSON response indicates an expired token.
fn is_expired_token_error(response: &serde_json::Value) -> bool {
    response
        .get("error")
        .and_then(|v| v.as_str())
        .is_some_and(|e| e == "ExpiredToken")
}

/// Execute the `invoke_xrpc` tool.
async fn handle_invoke_xrpc(arguments: Value, default_resolver: &InnerIdentityResolver) -> Value {
    let Some(nsid) = arguments.get("nsid").and_then(Value::as_str) else {
        return tool_error("The 'nsid' argument must be a string.");
    };

    let endpoint = arguments.get("endpoint").and_then(Value::as_str);
    let identity = arguments.get("identity").and_then(Value::as_str);
    let auth_handle = arguments.get("auth_handle").and_then(Value::as_str);
    let proxy = arguments.get("proxy").and_then(Value::as_str);
    let body = arguments.get("body").cloned();
    let params = arguments.get("params").and_then(Value::as_object);

    // Proxy requires auth_handle.
    if proxy.is_some() && auth_handle.is_none() {
        return tool_error("The 'proxy' parameter requires 'auth_handle' to be set.");
    }

    // Determine the service endpoint.
    let service_endpoint = if let Some(ep) = endpoint {
        ep.to_string()
    } else if let Some(id) = identity {
        match default_resolver.resolve(id).await {
            Ok(document) => {
                let pds_endpoints = document.pds_endpoints();
                match pds_endpoints.first() {
                    Some(ep) => ep.to_string(),
                    None => {
                        let tool_err = ToolError::XrpcRequestFailed {
                            reason: "No PDS endpoint found in DID document".to_string(),
                        };
                        tracing::error!(identity = %id, "No PDS endpoint found.");
                        return tool_error(&tool_err.to_string());
                    }
                }
            }
            Err(error) => {
                let tool_err = ToolError::XrpcRequestFailed {
                    reason: format!("Failed to resolve identity: {error}"),
                };
                tracing::error!(error = ?error, identity = %id, "Identity resolution failed.");
                return tool_error(&tool_err.to_string());
            }
        }
    } else if let Some(handle) = auth_handle {
        // Fall back to the PDS endpoint from the auth account.
        match load_xrpc_account(handle) {
            Ok(account) => account.pds_endpoint,
            Err(err) => return err,
        }
    } else {
        return tool_error("Either 'endpoint', 'identity', or 'auth_handle' must be provided.");
    };

    // Build query parameters from the params object.
    let query_pairs: Vec<(String, String)> = params
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let is_procedure = body.is_some();

    // Build the URL.
    let url = if is_procedure {
        match build_url(
            &service_endpoint,
            &format!("/xrpc/{nsid}"),
            std::iter::empty::<(&str, &str)>(),
        ) {
            Ok(u) => u.to_string(),
            Err(error) => {
                let tool_err = ToolError::XrpcRequestFailed {
                    reason: format!("Failed to build URL: {error}"),
                };
                return tool_error(&tool_err.to_string());
            }
        }
    } else {
        match build_url(
            &service_endpoint,
            &format!("/xrpc/{nsid}"),
            query_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        ) {
            Ok(u) => u.to_string(),
            Err(error) => {
                let tool_err = ToolError::XrpcRequestFailed {
                    reason: format!("Failed to build URL: {error}"),
                };
                return tool_error(&tool_err.to_string());
            }
        }
    };

    // Build headers, including the atproto-proxy header for proxied requests.
    let mut headers = HeaderMap::new();
    if let Some(audience) = proxy {
        match reqwest::header::HeaderValue::from_str(audience) {
            Ok(value) => {
                headers.insert(
                    reqwest::header::HeaderName::from_static("atproto-proxy"),
                    value,
                );
            }
            Err(error) => {
                let tool_err = ToolError::XrpcRequestFailed {
                    reason: format!("Invalid proxy audience header value: {error}"),
                };
                return tool_error(&tool_err.to_string());
            }
        }
    }

    // Make the request.
    let result = if let Some(handle) = auth_handle {
        let mut account = match load_xrpc_account(handle) {
            Ok(a) => a,
            Err(err) => return err,
        };

        let app_auth = AppPasswordAuth {
            access_token: account.access_jwt.clone(),
        };

        let first_result = if is_procedure {
            let data = body.clone().unwrap_or(Value::Null);
            post_apppassword_json_with_headers(
                &default_resolver.http_client,
                &app_auth,
                &url,
                data,
                &headers,
            )
            .await
        } else {
            get_apppassword_json_with_headers(
                &default_resolver.http_client,
                &app_auth,
                &url,
                &headers,
            )
            .await
        };

        // Check for expired token and attempt refresh.
        match &first_result {
            Ok(response) if is_expired_token_error(response) => {
                tracing::info!(handle = %handle, "Session expired, attempting refresh.");

                let refreshed = match refresh_session(
                    &default_resolver.http_client,
                    &account.pds_endpoint,
                    &account.refresh_jwt,
                )
                .await
                {
                    Ok(r) => {
                        account.access_jwt = r.access_jwt;
                        account.refresh_jwt = r.refresh_jwt;
                        true
                    }
                    Err(refresh_err) => {
                        tracing::warn!(error = ?refresh_err, "Refresh failed, re-authenticating.");
                        match create_session(
                            &default_resolver.http_client,
                            &account.pds_endpoint,
                            &account.handle,
                            &account.app_password,
                            None,
                        )
                        .await
                        {
                            Ok(session) => {
                                account.access_jwt = session.access_jwt;
                                account.refresh_jwt = session.refresh_jwt;
                                true
                            }
                            Err(auth_err) => {
                                tracing::error!(error = ?auth_err, "Re-authentication failed.");
                                false
                            }
                        }
                    }
                };

                if refreshed {
                    if let Err(error) = update_xrpc_account(&account) {
                        tracing::warn!(error = ?error, "Failed to persist refreshed tokens.");
                    }

                    let new_auth = AppPasswordAuth {
                        access_token: account.access_jwt.clone(),
                    };

                    if is_procedure {
                        let data = body.unwrap_or(Value::Null);
                        post_apppassword_json_with_headers(
                            &default_resolver.http_client,
                            &new_auth,
                            &url,
                            data,
                            &headers,
                        )
                        .await
                    } else {
                        get_apppassword_json_with_headers(
                            &default_resolver.http_client,
                            &new_auth,
                            &url,
                            &headers,
                        )
                        .await
                    }
                } else {
                    first_result
                }
            }
            _ => first_result,
        }
    } else if is_procedure {
        let data = body.unwrap_or(Value::Null);
        post_json_with_headers(&default_resolver.http_client, &url, data, &headers).await
    } else {
        get_json_with_headers(&default_resolver.http_client, &url, &headers).await
    };

    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => tool_success(&json),
            Err(error) => {
                let tool_err = ToolError::XrpcRequestFailed {
                    reason: error.to_string(),
                };
                tracing::error!(error = ?error, "Failed to serialize XRPC response.");
                tool_error(&tool_err.to_string())
            }
        },
        Err(error) => {
            let tool_err = ToolError::XrpcRequestFailed {
                reason: error.to_string(),
            };
            tracing::error!(error = ?error, nsid = %nsid, "XRPC request failed.");
            tool_error(&tool_err.to_string())
        }
    }
}

/// Execute the `generate_tid` tool.
fn handle_generate_tid(arguments: Value) -> Value {
    let count = arguments.get("count").and_then(Value::as_u64).unwrap_or(1);

    if count == 0 || count > 100 {
        return tool_error("The 'count' argument must be between 1 and 100.");
    }

    let timestamp_micros = arguments.get("timestamp_micros").and_then(Value::as_u64);

    let tids: Vec<String> = (0..count)
        .map(|_| {
            let tid = match timestamp_micros {
                Some(ts) => atproto_record::tid::Tid::new_with_time(ts),
                None => atproto_record::tid::Tid::new(),
            };
            tid.to_string()
        })
        .collect();

    if tids.len() == 1 {
        tool_success(&tids[0])
    } else {
        tool_success(&tids.join("\n"))
    }
}

/// Build a successful tool call result.
fn tool_success(text: &str) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    })
}

/// Build an error tool call result.
fn tool_error(text: &str) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true
    })
}

/// Route an incoming JSON-RPC message and return an optional response.
///
/// Returns `None` for notifications (messages without an `id`).
async fn route_message(
    msg: JsonRpcMessage,
    resolver: &InnerIdentityResolver,
) -> Option<JsonRpcResponse> {
    let id = match msg.id {
        Some(id) => id,
        None => {
            // Notification - no response.
            tracing::debug!(method = %msg.method, "Received notification.");
            return None;
        }
    };

    let response = match msg.method.as_str() {
        "initialize" => JsonRpcResponse::success(id, handle_initialize()),
        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
        "tools/list" => JsonRpcResponse::success(id, handle_tools_list()),
        "tools/call" => handle_tools_call(id, msg.params, resolver).await,
        _ => JsonRpcResponse::error(
            id,
            METHOD_NOT_FOUND,
            format!("Method not found: {}", msg.method),
        ),
    };

    Some(response)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("atpmcp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting atpmcp MCP server");

    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let http_client = reqwest::Client::new();
    let resolver = InnerIdentityResolver {
        dns_resolver: Arc::new(dns_resolver),
        http_client,
        plc_hostname: "plc.directory".to_string(),
    };

    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout().lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(error) => {
                tracing::error!(error = ?error, "Failed to read from stdin.");
                break;
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let msg: JsonRpcMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(error) => {
                tracing::warn!(error = ?error, "Failed to parse JSON-RPC message.");
                let response = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Parse error");
                let out = serde_json::to_string(&response)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
                continue;
            }
        };

        if msg.jsonrpc != "2.0" {
            let id = msg.id.unwrap_or(Value::Null);
            let response = JsonRpcResponse::error(id, INVALID_REQUEST, "Invalid JSON-RPC version");
            let out = serde_json::to_string(&response)?;
            writeln!(stdout, "{out}")?;
            stdout.flush()?;
            continue;
        }

        if let Some(response) = route_message(msg, &resolver).await {
            let out = serde_json::to_string(&response)?;
            writeln!(stdout, "{out}")?;
            stdout.flush()?;
        }
    }

    tracing::info!("atpmcp MCP server shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_resolver() -> InnerIdentityResolver {
        let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
        InnerIdentityResolver {
            dns_resolver: Arc::new(dns_resolver),
            http_client: reqwest::Client::new(),
            plc_hostname: "plc.directory".to_string(),
        }
    }

    #[test]
    fn test_handle_initialize() {
        let result = handle_initialize();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], "atpmcp");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn test_handle_tools_list() {
        let result = handle_tools_list();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
        assert_eq!(tools[0]["name"], "create_record_cid");
        assert_eq!(tools[1]["name"], "validate_lexicon_schema");
        assert_eq!(tools[2]["name"], "resolve_handle_to_did");
        assert_eq!(tools[3]["name"], "resolve_identity");
        assert_eq!(tools[4]["name"], "parse_facets");
        assert_eq!(tools[5]["name"], "get_record");
        assert_eq!(tools[6]["name"], "get_lexicon");
        assert_eq!(tools[7]["name"], "validate_xrpc");
        assert_eq!(tools[8]["name"], "invoke_xrpc");
        assert_eq!(tools[9]["name"], "generate_tid");
        for tool in tools {
            assert!(tool["inputSchema"].is_object());
        }
    }

    // -- create_record_cid tests --

    #[test]
    fn test_create_record_cid_success() {
        let args = serde_json::json!({
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Hello world",
                "createdAt": "2025-01-19T10:00:00.000Z"
            }
        });
        let result = handle_create_record_cid(args);
        assert_eq!(result["isError"], false);

        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");

        let cid_str = content[0]["text"].as_str().unwrap();
        assert!(!cid_str.is_empty());
    }

    #[test]
    fn test_create_record_cid_deterministic() {
        let args = serde_json::json!({
            "record": { "text": "deterministic test" }
        });

        let r1 = handle_create_record_cid(args.clone());
        let r2 = handle_create_record_cid(args);

        let cid1 = r1["content"][0]["text"].as_str().unwrap();
        let cid2 = r2["content"][0]["text"].as_str().unwrap();
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_create_record_cid_different_inputs() {
        let args1 = serde_json::json!({ "record": { "text": "hello" } });
        let args2 = serde_json::json!({ "record": { "text": "world" } });

        let r1 = handle_create_record_cid(args1);
        let r2 = handle_create_record_cid(args2);

        let cid1 = r1["content"][0]["text"].as_str().unwrap();
        let cid2 = r2["content"][0]["text"].as_str().unwrap();
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_create_record_cid_non_object() {
        let args = serde_json::json!({ "record": "not an object" });
        let result = handle_create_record_cid(args);
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_create_record_cid_missing_record() {
        let args = serde_json::json!({});
        let result = handle_create_record_cid(args);
        assert_eq!(result["isError"], true);
    }

    // -- validate_lexicon_schema tests --

    #[test]
    fn test_validate_lexicon_schema_success() {
        let args = serde_json::json!({
            "schema": {
                "lexicon": 1,
                "id": "com.example.test",
                "defs": {
                    "main": {
                        "type": "record",
                        "key": "tid",
                        "record": {
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let result = handle_validate_lexicon_schema(args);
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("com.example.test"));
        assert!(text.contains("valid"));
    }

    #[test]
    fn test_validate_lexicon_schema_invalid_version() {
        let args = serde_json::json!({
            "schema": {
                "lexicon": 99,
                "id": "com.example.test",
                "defs": {
                    "main": {
                        "type": "record",
                        "key": "tid",
                        "record": {
                            "type": "object",
                            "required": ["text"],
                            "properties": {
                                "text": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let result = handle_validate_lexicon_schema(args);
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_validate_lexicon_schema_non_object() {
        let args = serde_json::json!({ "schema": "not an object" });
        let result = handle_validate_lexicon_schema(args);
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_validate_lexicon_schema_missing_schema() {
        let args = serde_json::json!({});
        let result = handle_validate_lexicon_schema(args);
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_validate_lexicon_schema_missing_main_def() {
        let args = serde_json::json!({
            "schema": {
                "lexicon": 1,
                "id": "com.example.test",
                "defs": {}
            }
        });
        let result = handle_validate_lexicon_schema(args);
        assert_eq!(result["isError"], true);
    }

    // -- resolve_handle_to_did tests --

    #[tokio::test]
    async fn test_resolve_handle_to_did_missing_handle() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_resolve_handle_to_did(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_resolve_handle_to_did_non_string_handle() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "handle": 123 });
        let result = handle_resolve_handle_to_did(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    // -- resolve_identity tests --

    #[tokio::test]
    async fn test_resolve_identity_missing_did() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_resolve_identity(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_resolve_identity_non_string_did() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "did": 123 });
        let result = handle_resolve_identity(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    // -- parse_facets tests --

    #[tokio::test]
    async fn test_parse_facets_missing_text() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_parse_facets(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_parse_facets_non_string_text() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "text": 123 });
        let result = handle_parse_facets(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_parse_facets_empty_text() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "text": "no facets here" });
        let result = handle_parse_facets(args, &resolver).await;
        assert_eq!(result["isError"], false);
        assert_eq!(result["content"][0]["text"], "[]");
    }

    #[tokio::test]
    async fn test_parse_facets_with_url() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "text": "Check out https://example.com" });
        let result = handle_parse_facets(args, &resolver).await;
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("https://example.com"));
    }

    #[tokio::test]
    async fn test_parse_facets_with_hashtag() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "text": "Hello #rust" });
        let result = handle_parse_facets(args, &resolver).await;
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("rust"));
    }

    // -- get_record tests --

    #[tokio::test]
    async fn test_get_record_missing_uri() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_get_record(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_record_non_string_uri() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "uri": 123 });
        let result = handle_get_record(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_record_invalid_aturi() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "uri": "not-a-valid-aturi" });
        let result = handle_get_record(args, &resolver).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Invalid AT-URI"));
    }

    // -- get_lexicon tests --

    #[tokio::test]
    async fn test_get_lexicon_missing_nsid() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_get_lexicon(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_lexicon_non_string_nsid() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "nsid": 123 });
        let result = handle_get_lexicon(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_get_lexicon_invalid_nsid() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "nsid": "invalid" });
        let result = handle_get_lexicon(args, &resolver).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Invalid NSID"));
    }

    // -- message routing tests --

    #[tokio::test]
    async fn test_route_notification_returns_none() {
        let resolver = create_test_resolver();
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };
        assert!(route_message(msg, &resolver).await.is_none());
    }

    #[tokio::test]
    async fn test_route_unknown_method() {
        let resolver = create_test_resolver();
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(1.into())),
            method: "unknown/method".to_string(),
            params: None,
        };
        let resp = route_message(msg, &resolver).await.unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_route_tools_call() {
        let resolver = create_test_resolver();
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(1.into())),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "create_record_cid",
                "arguments": {
                    "record": { "text": "test" }
                }
            })),
        };
        let resp = route_message(msg, &resolver).await.unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_route_tools_call_unknown_tool() {
        let resolver = create_test_resolver();
        let msg = JsonRpcMessage {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(1.into())),
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({
                "name": "nonexistent_tool",
                "arguments": {}
            })),
        };
        let resp = route_message(msg, &resolver).await.unwrap();
        assert!(resp.error.is_some());
    }

    // -- invoke_xrpc tests --

    #[tokio::test]
    async fn test_invoke_xrpc_missing_nsid() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({});
        let result = handle_invoke_xrpc(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_invoke_xrpc_non_string_nsid() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "nsid": 123 });
        let result = handle_invoke_xrpc(args, &resolver).await;
        assert_eq!(result["isError"], true);
    }

    #[tokio::test]
    async fn test_invoke_xrpc_missing_endpoint_and_identity() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({ "nsid": "com.atproto.repo.describeRepo" });
        let result = handle_invoke_xrpc(args, &resolver).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("endpoint"));
    }

    #[tokio::test]
    async fn test_invoke_xrpc_proxy_requires_auth_handle() {
        let resolver = create_test_resolver();
        let args = serde_json::json!({
            "nsid": "app.bsky.feed.getAuthorFeed",
            "endpoint": "https://bsky.network",
            "proxy": "did:web:api.bsky.app#bsky_fg"
        });
        let result = handle_invoke_xrpc(args, &resolver).await;
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("proxy"));
        assert!(text.contains("auth_handle"));
    }

    // -- validate_xrpc tests --

    #[test]
    fn test_validate_xrpc_missing_nsid() {
        let args = serde_json::json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resolver = create_test_resolver();
        let result = rt.block_on(handle_validate_xrpc(args, &resolver));
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("nsid"));
    }

    #[test]
    fn test_validate_xrpc_non_string_nsid() {
        let args = serde_json::json!({"nsid": 123});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resolver = create_test_resolver();
        let result = rt.block_on(handle_validate_xrpc(args, &resolver));
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("nsid"));
    }

    // -- generate_tid tests --

    #[test]
    fn test_generate_tid_default() {
        let args = serde_json::json!({});
        let result = handle_generate_tid(args);
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text.len(), 13);
    }

    #[test]
    fn test_generate_tid_with_count() {
        let args = serde_json::json!({ "count": 3 });
        let result = handle_generate_tid(args);
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        let tids: Vec<&str> = text.lines().collect();
        assert_eq!(tids.len(), 3);
        for tid in &tids {
            assert_eq!(tid.len(), 13);
        }
    }

    #[test]
    fn test_generate_tid_with_timestamp() {
        let args = serde_json::json!({ "timestamp_micros": 1773067572000000_u64 });
        let result = handle_generate_tid(args);
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text.len(), 13);
    }

    #[test]
    fn test_generate_tid_count_zero() {
        let args = serde_json::json!({ "count": 0 });
        let result = handle_generate_tid(args);
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_generate_tid_count_over_max() {
        let args = serde_json::json!({ "count": 101 });
        let result = handle_generate_tid(args);
        assert_eq!(result["isError"], true);
    }
}
