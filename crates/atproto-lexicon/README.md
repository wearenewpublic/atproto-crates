# atproto-lexicon

AT Protocol lexicon resolution and validation library for Rust.

## Overview

This library provides functionality for resolving and validating AT Protocol lexicons, which define the schema and structure of AT Protocol data. It implements the full lexicon resolution chain as specified by the AT Protocol:

1. Convert NSID to DNS name with `_lexicon` prefix
2. Perform DNS TXT lookup to get the authoritative DID
3. Resolve the DID to get the DID document
4. Extract PDS endpoint from the DID document
5. Make XRPC call to fetch the lexicon schema

## Features

- **Lexicon Resolution**: Resolve NSIDs to their schema definitions via DNS and XRPC
- **Recursive Resolution**: Automatically resolve referenced lexicons with configurable depth limits
- **NSID Validation**: Comprehensive validation of Namespace Identifiers
- **Reference Extraction**: Extract and resolve lexicon references including fragment-only references
- **Context-Aware Resolution**: Handle fragment-only references using lexicon ID as context
- **CLI Tool**: Command-line interface for lexicon resolution

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
atproto-lexicon = "0.14.4"
```

## Usage

### Basic Lexicon Resolution

```rust
use atproto_lexicon::resolve::{DefaultLexiconResolver, LexiconResolver};
use atproto_identity::resolve::HickoryDnsResolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);

    let resolver = DefaultLexiconResolver::new(http_client, dns_resolver);

    // Resolve a single lexicon
    let lexicon = resolver.resolve("app.bsky.feed.post").await?;
    println!("Resolved lexicon: {}", serde_json::to_string_pretty(&lexicon)?);

    Ok(())
}
```

### Recursive Resolution

```rust
use atproto_lexicon::resolve_recursive::{RecursiveLexiconResolver, RecursiveResolverConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let resolver = DefaultLexiconResolver::new(http_client, dns_resolver);

    let config = RecursiveResolverConfig {
        max_depth: 5,  // Maximum recursion depth
        include_entry: true,  // Include the entry lexicon in results
    };

    let recursive_resolver = RecursiveLexiconResolver::with_config(resolver, config);

    // Resolve a lexicon and all its dependencies
    let lexicons = recursive_resolver.resolve_recursive("app.bsky.feed.post").await?;

    for (nsid, schema) in lexicons {
        println!("Resolved {}: {} bytes", nsid,
                 serde_json::to_string(&schema)?.len());
    }

    Ok(())
}
```

### NSID Validation

```rust
use atproto_lexicon::validation::{
    is_valid_nsid, parse_nsid, nsid_to_dns_name, absolute
};

// Validate NSIDs
assert!(is_valid_nsid("app.bsky.feed.post"));
assert!(!is_valid_nsid("invalid"));

// Parse NSID components
let parts = parse_nsid("app.bsky.feed.post#reply", None)?;
assert_eq!(parts.parts, vec!["app", "bsky", "feed", "post"]);
assert_eq!(parts.fragment, Some("reply".to_string()));

// Convert parsed NSID back to string using Display trait
println!("Parsed NSID: {}", parts); // Outputs: app.bsky.feed.post#reply

// Convert NSID to DNS name for resolution
let dns_name = nsid_to_dns_name("app.bsky.feed.post")?;
assert_eq!(dns_name, "_lexicon.feed.bsky.app");

// Make fragment-only references absolute
assert_eq!(absolute("app.bsky.feed.post", "#reply"), "app.bsky.feed.post#reply");
assert_eq!(absolute("app.bsky.feed.post", "com.example.other"), "com.example.other");
```

### Extract Lexicon References

```rust
use atproto_lexicon::resolve_recursive::extract_lexicon_references;
use serde_json::json;

let schema = json!({
    "lexicon": 1,
    "id": "app.bsky.feed.post",
    "defs": {
        "main": {
            "type": "record",
            "record": {
                "type": "object",
                "properties": {
                    "embed": {
                        "type": "union",
                        "refs": [
                            { "type": "ref", "ref": "app.bsky.embed.images" },
                            { "type": "ref", "ref": "#localref" }  // Fragment reference
                        ]
                    }
                }
            }
        }
    }
});

let references = extract_lexicon_references(&schema);
// References will include:
// - "app.bsky.embed.images" (external reference)
// - "app.bsky.feed.post" (from #localref using the lexicon's id as context)
```

## CLI Tool

The crate includes a command-line tool for lexicon resolution:

```bash
# Build with CLI support
cargo build --features clap --bin atproto-lexicon-resolve

# Resolve a single lexicon
cargo run --features clap --bin atproto-lexicon-resolve -- app.bsky.feed.post

# Pretty print the output
cargo run --features clap --bin atproto-lexicon-resolve -- --pretty app.bsky.feed.post

# Recursively resolve all referenced lexicons
cargo run --features clap --bin atproto-lexicon-resolve -- --recursive app.bsky.feed.post

# Limit recursion depth
cargo run --features clap --bin atproto-lexicon-resolve -- --recursive --max-depth 3 app.bsky.feed.post

# Show dependency graph
cargo run --features clap --bin atproto-lexicon-resolve -- --recursive --show-deps app.bsky.feed.post

# List only direct references
cargo run --features clap --bin atproto-lexicon-resolve -- --list-refs app.bsky.feed.post
```

## Module Structure

- **`errors`**: Structured error types for all lexicon operations
- **`resolve`**: Core lexicon resolution implementation following AT Protocol specification
- **`resolve_recursive`**: Recursive resolution with dependency tracking and cycle detection
- **`validation`**: NSID validation, parsing, and helper functions

## Key Types

### `NsidParts`
Represents a parsed NSID with its component parts and optional fragment:
- `parts`: Vector of NSID components (e.g., `["app", "bsky", "feed", "post"]`)
- `fragment`: Optional fragment identifier (e.g., `"reply"` for `#reply`)

Implements `Display` trait for converting back to string format.

### `RecursiveResolverConfig`
Configuration for recursive resolution:
- `max_depth`: Maximum recursion depth (default: 10)
- `include_entry`: Whether to include the entry lexicon in results (default: true)

### `RecursiveResolutionResult`
Detailed results from recursive resolution:
- `lexicons`: HashMap of resolved lexicons by NSID
- `failed`: Set of NSIDs that couldn't be resolved
- `dependencies`: Dependency graph showing which lexicons reference which

## Features

- **Fragment-Only Reference Resolution**: Automatically resolves fragment-only references (e.g., `#localref`) using the lexicon's `id` field as context
- **Union Type Support**: Extracts references from both `ref` objects and `union` types with `refs` arrays
- **DNS-based Discovery**: Implements the AT Protocol DNS-based lexicon discovery mechanism
- **Cycle Detection**: Prevents infinite recursion when resolving circular dependencies
- **Validation**: Comprehensive NSID validation following AT Protocol specifications

## Error Handling

The library uses structured error types following the project convention `error-atproto-lexicon-<domain>-<number>`:

- **`LexiconResolveError`**: Resolution errors (no DIDs found, invalid DID format, PDS errors)
- **`LexiconValidationError`**: NSID format and validation errors
- **`LexiconSchemaError`**: Schema structure and parsing errors
- **`LexiconRecursiveError`**: Errors specific to recursive resolution

All errors implement the `Error` trait and provide detailed context about failures.

## Dependencies

- `atproto-identity`: For DID resolution and DNS operations
- `atproto-client`: For XRPC communication
- `serde_json`: For JSON schema handling
- `async-trait`: For async trait definitions
- `tracing`: For structured logging

## License

This project is part of the atproto-identity-rs workspace. See the root LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.