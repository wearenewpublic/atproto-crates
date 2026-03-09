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

mod errors;

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

use atproto_identity::resolve::{HickoryDnsResolver, InnerIdentityResolver};
use errors::ToolError;
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
        assert_eq!(tools.len(), 6);
        assert_eq!(tools[0]["name"], "create_record_cid");
        assert_eq!(tools[1]["name"], "validate_lexicon_schema");
        assert_eq!(tools[2]["name"], "resolve_handle_to_did");
        assert_eq!(tools[3]["name"], "resolve_identity");
        assert_eq!(tools[4]["name"], "parse_facets");
        assert_eq!(tools[5]["name"], "get_record");
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
}
