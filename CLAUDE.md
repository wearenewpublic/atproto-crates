# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `atproto-identity`, a comprehensive Rust library for AT Protocol identity management. The project provides full functionality for DID resolution, handle resolution, and identity document management across multiple DID methods.

## Common Commands

- **Build**: `cargo build`
- **Build with CLI tools**: `cargo build --features clap,hickory-dns --bins`
- **Run tests**: `cargo test`
- **Run specific test**: `cargo test test_name`
- **Check code**: `cargo check`
- **Format code**: `cargo fmt`
- **Lint**: `cargo clippy`

### CLI Tools (require --features clap)

All CLI tools now use clap for consistent command-line argument processing. Use `--help` with any tool for detailed usage information.

#### Identity Management
- **Resolve identities**: `cargo run --features clap,hickory-dns --bin atproto-identity-resolve -- <handle_or_did>`
- **Resolve with DID document**: `cargo run --features clap,hickory-dns --bin atproto-identity-resolve -- --did-document <handle_or_did>`
- **Generate keys**: `cargo run --features clap --bin atproto-identity-key -- generate p256` (supports p256, p384, k256)
- **Sign data**: `cargo run --features clap --bin atproto-identity-sign -- <did_key> <json_file>`
- **Validate signatures**: `cargo run --features clap --bin atproto-identity-validate -- <did_key> <json_file> <signature>`

#### Attestation Operations
- **Sign records (inline)**: `cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-sign -- inline <source_record> <signing_key> <metadata_record>`
- **Sign records (remote)**: `cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-sign -- remote <source_record> <repository_did> <metadata_record>`
- **Verify records**: `cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-verify -- <record>` (verifies all signatures)
- **Verify attestation**: `cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-verify -- <record> <attestation>` (verifies specific attestation)

#### DASL Operations
- **Compute CID**: `cargo run --features clap --bin atpcid -- '<json_or_data>'` (auto-detects record vs raw CID; use `-` for stdin, `--raw` to force RAW CID, `--record` to force DAG-CBOR record CID)

#### Record Operations
- **Generate CID**: `cat record.json | cargo run --features clap --bin atproto-record-cid` (reads JSON from stdin, outputs CID)

#### Client Tools
- **App password auth**: `cargo run --features clap --bin atproto-client-app-password -- <subject> <access_token> <xrpc_path>`
- **Session auth**: `cargo run --features clap --bin atproto-client-auth -- login <identifier> <password>`
- **DPoP client**: `cargo run --features clap --bin atproto-client-dpop -- <subject> <private_dpop_key> <access_token> <xrpc_path>`

#### Streaming and OAuth
- **Jetstream consumer**: `cargo run --features clap --bin atproto-jetstream-consumer -- <hostname> <zstd_dictionary>`
- **OAuth tool**: `cargo run --features clap --bin atproto-oauth-tool -- login <private_signing_key> <subject>`
- **XRPCS service**: `cargo run --features clap --bin atproto-xrpcs-helloworld`

## Architecture

A comprehensive Rust workspace with multiple crates:
- **atproto-dasl**: Data-Addressed Structures & Links (DASL) framework with modules for CIDs, DRISL (DAG-CBOR serialization), CAR v1 archives, block storage, and varint encoding
- **atproto-identity**: Core identity management with 11 modules (resolve, plc, web, model, validation, config, errors, key, storage_lru, traits, url)
- **atproto-attestation**: CID-first attestation utilities for creating and verifying record signatures
- **atproto-record**: Record utilities including TID generation, AT-URI parsing, and CID generation
- **atproto-repo**: AT Protocol repository operations including MST trees, commits, and record access (re-exports CAR/storage from atproto-dasl)
- **atproto-client**: HTTP client with OAuth and identity integration
- **atproto-jetstream**: WebSocket event streaming with compression
- **atproto-oauth**: OAuth workflow implementation with DPoP, PKCE, JWT, and storage abstractions
- **atproto-oauth-aip**: AT Protocol OAuth AIP (Identity Provider) implementation with PAR support
- **atproto-oauth-axum**: Axum web framework integration for OAuth
- **atproto-xrpcs**: XRPC service framework
- **atproto-xrpcs-helloworld**: Complete example XRPC service

Features:
- **13 CLI tools** with consistent clap-based command-line interfaces (optional via `clap` feature)
- **Rust edition 2024** with modern async/await patterns
- **Comprehensive error handling** with structured error types
- **Full test coverage** with unit tests across all modules
- **Modern dependencies** for HTTP, DNS, JSON, cryptographic operations, and WebSocket streaming
- **Storage abstractions** with LRU caching support (enabled by default via `lru` feature)
- **DNS resolution** with Hickory DNS support (enabled by default via `hickory-dns` feature)
- **Secure memory handling** (optional via `zeroize` feature)

## Error Handling

All error strings must use this format:

    error-atproto-identity-<domain>-<number> <message>: <details>

Example errors:

* error-atproto-identity-resolve-1 Multiple DIDs resolved for method
* error-atproto-identity-plc-1 HTTP request failed: https://google.com/ Not Found
* error-atproto-identity-key-1 Error decoding key: invalid

Errors should be represented as enums using the `thiserror` library when possible using `src/errors.rs` as a reference and example.

Avoid creating new errors with the `anyhow!(...)` macro.

When a function call would return `anyhow::Error`, use the following pattern to log the error in addition to any code specific handling that must occur:

```
If let Err(err) = result {
    tracing::error!(error = ?error, "Helpful contextual log line.");
}
```

## Result

Functions that return a `Result` type should use `anyhow::Result` where second Error component of is one of the error types defined in `src/errors.rs`.

## Logging

Use tracing for structured logging.

All calls to `tracing::error`, `tracing::warn`, `tracing::info`, `tracing::debug`, and `tracing::trace` should be fully qualified.

Do not use the `println!` macro in library code.

Async calls should be instrumented using the `.instrument()` that references the `use tracing::Instrument;` trait.

## Command-Line Interface Pattern

All CLI tools use the clap library with derive macros for consistent command-line argument processing:

- **Optional dependency**: clap is an optional dependency in each crate via `clap = { workspace = true, optional = true }`
- **Feature-gated**: All binaries require the `clap` feature via `required-features = ["clap"]`
- **Derive pattern**: Use `#[derive(Parser)]` and `#[derive(Subcommand)]` for command structures
- **Comprehensive help**: Include detailed help documentation in clap attributes
- **Consistent structure**: Use structured arguments with proper types rather than manual parsing

Example command structure:
```rust
#[derive(Parser)]
#[command(
    name = "tool-name",
    version,
    about = "Brief description",
    long_about = "Detailed description with examples"
)]
struct Args {
    /// Argument description
    positional_arg: String,
    
    /// Optional flag description
    #[arg(long)]
    optional_flag: bool,
}
```

## Module Structure

### Core Library Modules (atproto-identity)
- **`src/lib.rs`**: Main library exports
- **`src/resolve.rs`**: Core resolution logic for handles and DIDs, DNS/HTTP resolution
- **`src/plc.rs`**: PLC directory client for did:plc resolution
- **`src/web.rs`**: Web DID client for did:web resolution and URL conversion
- **`src/model.rs`**: Data structures for DID documents and AT Protocol entities
- **`src/validation.rs`**: Input validation for handles and DIDs
- **`src/config.rs`**: Configuration management and environment variable handling
- **`src/errors.rs`**: Structured error types following project conventions
- **`src/key.rs`**: Cryptographic key operations including signature validation and key identification for P-256, P-384, and K-256 curves
- **`src/storage_lru.rs`**: LRU-based storage implementation (requires `lru` feature)
- **`src/traits.rs`**: Core trait definitions for identity resolution and key resolution
- **`src/url.rs`**: URL utilities for AT Protocol services

### CLI Tools (require --features clap)

#### DASL Operations (atproto-dasl)
- **`crates/atproto-dasl/src/bin/atpcid.rs`**: Compute CIDs from input data (auto-detects DAG-CBOR record vs RAW CID)

#### Identity Management (atproto-identity)
- **`src/bin/atproto-identity-resolve.rs`**: Resolve AT Protocol handles and DIDs to canonical identifiers
- **`src/bin/atproto-identity-key.rs`**: Generate and manage cryptographic keys (P-256, P-384, K-256)
- **`src/bin/atproto-identity-sign.rs`**: Create cryptographic signatures of JSON data
- **`src/bin/atproto-identity-validate.rs`**: Validate cryptographic signatures

#### Attestation Operations (atproto-attestation)
- **`src/bin/atproto-attestation-sign.rs`**: Sign AT Protocol records with inline or remote attestations using CID-first specification
- **`src/bin/atproto-attestation-verify.rs`**: Verify cryptographic signatures on AT Protocol records with attestation validation

#### Record Operations (atproto-record)
- **`src/bin/atproto-record-cid.rs`**: Generate CID (Content Identifier) for AT Protocol records using DAG-CBOR serialization

#### Client Tools (atproto-client)
- **`src/bin/atproto-client-app-password.rs`**: Make XRPC calls using app password authentication
- **`src/bin/atproto-client-auth.rs`**: Create and refresh authentication sessions
- **`src/bin/atproto-client-dpop.rs`**: Make XRPC calls using DPoP (Demonstration of Proof-of-Possession) authentication

#### Streaming and Services
- **`crates/atproto-jetstream/src/bin/atproto-jetstream-consumer.rs`**: Consume AT Protocol events via WebSocket streaming
- **`crates/atproto-oauth/src/bin/atproto-oauth-service-token.rs`**: OAuth service token management tool for AT Protocol authentication workflows
- **`crates/atproto-oauth-axum/src/bin/atproto-oauth-tool.rs`**: OAuth authentication workflow management
- **`crates/atproto-xrpcs-helloworld/src/main.rs`**: Complete example XRPC service with DID web functionality

## Documentation

All public and exported types, methods, and variables must be documented.

All source files must have high level module documentation.

Documentation must be brief and specific.
