# AT Protocol Rust Crates

A Rust workspace of crates for building AT Protocol applications. This collection provides building blocks for content-addressed data, identity management, repository operations, record signing, OAuth 2.0 authentication flows, HTTP client operations, XRPC services, real-time event streaming, and developer tooling.

**Origin**: Parts of this project were extracted from the open-source [smokesignal.events](https://tangled.sh/@smokesignal.events/smokesignal) project, an AT Protocol event and RSVP management application. This library is released under the MIT license to enable broader AT Protocol ecosystem development.

## Components

This workspace contains 16 crates that work together to provide complete AT Protocol application development capabilities:

### Data Foundations

- **[`atproto-dasl`](crates/atproto-dasl/)** - DASL (Data-Addressed Structures & Links) framework implementing CID computation, DRISL (deterministic DAG-CBOR encoding), CAR v1 archives, block storage backends, RASL retrieval, BDASL large file hashing, and Web Tiles. *Includes 1 CLI tool.*

### Identity & Cryptography

- **[`atproto-identity`](crates/atproto-identity/)** - Core identity management with multi-method DID resolution (plc, web, key), DNS/HTTP handle resolution, PLC directory operations, and P-256/P-384/K-256 cryptographic operations. *Includes 6 CLI tools.*
- **[`atproto-attestation`](crates/atproto-attestation/)** - CID-first attestation utilities for creating and verifying cryptographic signatures on AT Protocol records, supporting both inline and remote attestation workflows. *Includes 2 CLI tools.*
- **[`atproto-record`](crates/atproto-record/)** - Record utilities including TID generation, AT-URI parsing, datetime formatting, and CID generation using IPLD DAG-CBOR serialization. *Includes 2 CLI tools.*
- **[`atproto-lexicon`](crates/atproto-lexicon/)** - Lexicon schema resolution and validation for AT Protocol, supporting recursive resolution, NSID validation, and DNS-based lexicon discovery. *Includes 1 CLI tool.*

### Repository

- **[`atproto-repo`](crates/atproto-repo/)** - AT Protocol repository handling with Merkle Search Tree (MST) encoding/decoding, commit structures, tree diffing for sync, and configurable verification. Builds on `atproto-dasl` for CAR and storage. *Includes 2 CLI tools.*

### Authentication & Authorization

- **[`atproto-oauth`](crates/atproto-oauth/)** - Complete OAuth 2.0 implementation with AT Protocol security extensions including DPoP (RFC 9449), PKCE (RFC 7636), JWT operations, and secure storage abstractions. *Includes 1 CLI tool.*
- **[`atproto-oauth-axum`](crates/atproto-oauth-axum/)** - Production-ready Axum web handlers for OAuth endpoints including authorization callbacks, JWKS endpoints, and client metadata. *Includes 1 CLI tool.*
- **[`atproto-oauth-dioxus`](crates/atproto-oauth-dioxus/)** - Dioxus fullstack integration for AT Protocol OAuth authentication flow components, hooks, and server functions.

### Client & Service Development

- **[`atproto-client`](crates/atproto-client/)** - HTTP client library supporting multiple authentication methods (DPoP, Bearer tokens, sessions) with native XRPC protocol operations and repository management. *Includes 4 CLI tools.*
- **[`atproto-xrpcs`](crates/atproto-xrpcs/)** - XRPC service framework providing JWT authorization extractors, DID resolution integration, and Axum middleware for building AT Protocol services.
- **[`atpxrpc`](crates/atpxrpc/)** - XRPC CLI client with persistent session management for making authenticated AT Protocol API calls. *Includes 1 CLI tool.*

### Real-time Event Processing

- **[`atproto-jetstream`](crates/atproto-jetstream/)** - WebSocket consumer for AT Protocol Jetstream events with Zstandard compression, automatic reconnection, and configurable event filtering. *Includes 1 CLI tool.*
- **[`atproto-tap`](crates/atproto-tap/)** - TAP (Trusted Attestation Protocol) service consumer for filtered, verified AT Protocol repository events with MST integrity checks, automatic backfill, and acknowledgment-based delivery. *Includes 2 CLI tools.*

### Developer Tools

- **[`atpmcp`](crates/atpmcp/)** - MCP (Model Context Protocol) server for AT Protocol DAG-CBOR CID generation, enabling AI assistants to compute content identifiers for records. *Includes 1 server binary.*

### Utilities

- **[`atproto-extras`](crates/atproto-extras/)** - Facet parsing and rich text utilities for AT Protocol, extracting mentions, URLs, and hashtags from plain text with correct UTF-8 byte offset calculation. *Includes 1 CLI tool.*

## Quick Start

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
atproto-dasl = "0.15.0-rc.3"
atproto-identity = "0.15.0-rc.3"
atproto-attestation = "0.15.0-rc.3"
atproto-record = "0.15.0-rc.3"
atproto-repo = "0.15.0-rc.3"
atproto-lexicon = "0.15.0-rc.3"
atproto-oauth = "0.15.0-rc.3"
atproto-client = "0.15.0-rc.3"
atproto-extras = "0.15.0-rc.3"
atproto-tap = "0.15.0-rc.3"
# Add others as needed
```

### Basic Identity Resolution

```rust
use atproto_identity::resolve::{resolve_subject, create_resolver};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let dns_resolver = create_resolver(&[]);

    let did = resolve_subject(&http_client, &dns_resolver, "alice.bsky.social").await?;
    println!("Resolved DID: {}", did);

    Ok(())
}
```

### Lexicon Resolution

```rust
use atproto_lexicon::resolve::{DefaultLexiconResolver, LexiconResolver};
use atproto_identity::resolve::HickoryDnsResolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let resolver = DefaultLexiconResolver::new(http_client, dns_resolver);

    // Resolve a lexicon schema
    let lexicon = resolver.resolve("app.bsky.feed.post").await?;
    println!("Lexicon schema: {}", serde_json::to_string_pretty(&lexicon)?);

    Ok(())
}
```

### Record Signing

```rust
use atproto_attestation::{create_inline_attestation, AnyInput};
use atproto_identity::key::{generate_key, KeyType};
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let key = generate_key(KeyType::P256Private)?;

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello AT Protocol!",
        "createdAt": "2024-01-01T00:00:00.000Z"
    });

    let metadata = json!({
        "$type": "com.example.inlineSignature",
        "key": "did:key:...",
        "issuer": "did:plc:issuer123",
        "issuedAt": "2024-01-01T00:00:00.000Z"
    });

    let signed_record = create_inline_attestation(
        AnyInput::Serialize(record),
        AnyInput::Serialize(metadata),
        "did:plc:repo123",
        &key
    )?;

    println!("Signed record: {}", serde_json::to_string_pretty(&signed_record)?);
    Ok(())
}
```

### XRPC Service

```rust
use atproto_xrpcs::authorization::Authorization;
use axum::{Json, Router, extract::Query, routing::get};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct HelloParams {
    subject: Option<String>,
}

async fn handle_hello(
    params: Query<HelloParams>,
    authorization: Option<Authorization>,
) -> Json<serde_json::Value> {
    let subject = params.subject.as_deref().unwrap_or("World");

    let message = if let Some(auth) = authorization {
        format!("Hello, authenticated {}! (caller: {})", subject, auth.subject())
    } else {
        format!("Hello, {}!", subject)
    };

    Json(json!({ "message": message }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/xrpc/com.example.hello", get(handle_hello))
        .with_state(your_web_context);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

### OAuth Client Flow

```rust
use atproto_oauth_aip::workflow::{oauth_init, oauth_complete, session_exchange, OAuthClient};
use atproto_oauth::workflow::OAuthRequestState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();

    let oauth_client = OAuthClient {
        redirect_uri: "https://your-app.com/callback".to_string(),
        client_id: "your-client-id".to_string(),
        client_secret: "your-client-secret".to_string(),
    };

    let oauth_request_state = OAuthRequestState {
        state: "random-state".to_string(),
        nonce: "random-nonce".to_string(),
        code_challenge: "code-challenge".to_string(),
        scope: "atproto transition:generic".to_string(),
    };

    // 1. Start OAuth flow with Pushed Authorization Request
    let par_response = oauth_init(
        &http_client,
        &oauth_client,
        Some("alice.bsky.social"),
        "https://auth-server.example.com/par",
        &oauth_request_state,
    ).await?;

    println!("PAR request URI: {}", par_response.request_uri);

    // 2. After user authorizes and returns with a code, exchange it for tokens
    let token_response = oauth_complete(
        &http_client,
        &oauth_client,
        "https://auth-server.example.com/token",
        "received-auth-code",
        &oauth_request,  // OAuthRequest from your stored state
    ).await?;

    // 3. Exchange token for AT Protocol session
    let session = session_exchange(
        &http_client,
        "https://pds.example.com",
        &token_response.access_token,
    ).await?;

    println!("Authenticated as: {} ({})", session.handle, session.did);

    Ok(())
}
```

## Command Line Tools

The workspace includes command-line tools and server binaries across the crates, providing ready-to-use utilities for AT Protocol development and testing. Most CLI tools require the `clap` feature:

```bash
# Build with CLI support
cargo build --features clap --bins

# DASL operations (atproto-dasl crate)
cargo run --package atproto-dasl --features clap --bin atpcid -- '{"text":"hello"}'

# Identity operations (atproto-identity crate)
cargo run --features clap,hickory-dns --bin atproto-identity-resolve -- alice.bsky.social
cargo run --features clap --bin atproto-identity-key -- generate p256
cargo run --features clap --bin atproto-identity-sign -- did:key:... data.json
cargo run --features clap --bin atproto-identity-validate -- did:key:... data.json signature
cargo run --features clap,hickory-dns --bin atproto-identity-plc-audit -- did:plc:...
cargo run --features clap,hickory-dns --bin atproto-identity-plc-fork-viz -- did:plc:...

# Attestation operations (atproto-attestation crate)
cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-sign -- inline record.json did:key:... metadata.json
cargo run --package atproto-attestation --features clap,tokio --bin atproto-attestation-verify -- signed_record.json

# Record operations (atproto-record crate)
cat record.json | cargo run --features clap --bin atproto-record-cid
cargo run --package atproto-record --features clap --bin atptid
cargo run --package atproto-record --features clap --bin atptid -- -n 5

# Repository operations (atproto-repo crate)
cargo run --package atproto-repo --features clap --bin atproto-repo-car -- ls repo.car
cargo run --package atproto-repo --features clap --bin atproto-repo-mst -- ls repo.car

# Lexicon operations (atproto-lexicon crate)
cargo run --features clap,hickory-dns --bin atproto-lexicon-resolve -- app.bsky.feed.post

# Client operations (atproto-client crate)
cargo run --features clap --bin atproto-client-auth -- login alice.bsky.social password123
cargo run --features clap --bin atproto-client-app-password -- alice.bsky.social access_token /xrpc/com.atproto.repo.listRecords
cargo run --features clap --bin atproto-client-dpop -- alice.bsky.social did:key:... access_token /xrpc/com.atproto.repo.listRecords
cargo run --features clap --bin atproto-client-put-record -- --help

# OAuth operations (atproto-oauth crate)
cargo run --package atproto-oauth --features clap --bin atproto-oauth-service-token -- --help

# OAuth operations (atproto-oauth-axum crate)
cargo run --package atproto-oauth-axum --features clap --bin atproto-oauth-tool -- login did:key:... alice.bsky.social

# Event streaming (atproto-jetstream crate)
cargo run --features clap --bin atproto-jetstream-consumer -- jetstream1.us-east.bsky.network dictionary.zstd

# TAP service consumer (atproto-tap crate)
cargo run --package atproto-tap --features clap --bin atproto-tap-client -- --help
cargo run --package atproto-tap --features clap --bin atproto-tap-extras -- --help

# Rich text utilities (atproto-extras crate)
cargo run --package atproto-extras --features clap,cli,hickory-dns --bin atproto-extras-parse-facets -- "Hello @alice.bsky.social"

# XRPC CLI client (atpxrpc crate)
cargo run --package atpxrpc --bin atpxrpc -- --help

# MCP server (atpmcp crate)
cargo build -p atpmcp
```

## Development

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Format and lint
cargo fmt && cargo clippy

# Generate documentation
cargo doc --workspace --open
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Architecture

These components are designed to work together as building blocks for AT Protocol applications:

- **Data Foundation Layer**: `atproto-dasl` provides CID computation, deterministic DAG-CBOR encoding, CAR v1 archives, and pluggable block storage
- **Identity Layer**: `atproto-identity` provides the foundation for DID resolution and cryptographic operations
- **Repository Layer**: `atproto-repo` provides Merkle Search Tree operations, commit structures, and repository handling
- **Data Layer**: `atproto-record` and `atproto-attestation` handle record operations, CID generation, and cryptographic attestations
- **Schema Layer**: `atproto-lexicon` provides lexicon resolution and validation for AT Protocol schemas
- **Authentication Layer**: `atproto-oauth*` crates handle complete OAuth 2.0 flows with AT Protocol security extensions
- **Application Layer**: `atproto-client` and `atproto-xrpcs*` enable client applications and service development
- **Event Layer**: `atproto-jetstream` and `atproto-tap` provide real-time event processing capabilities
- **Utilities Layer**: `atproto-extras` provides rich text facet parsing for AT Protocol applications

## Use Cases

This workspace enables development of:

- **AT Protocol Identity Providers (AIPs)** - Complete OAuth servers with DID-based authentication
- **Personal Data Servers (PDS)** - XRPC services with JWT authorization and repository management
- **AT Protocol Clients** - Applications that authenticate and interact with AT Protocol services
- **Event Processing Systems** - Real-time processors for AT Protocol repository events via Jetstream or TAP
- **Repository Tools** - CAR file inspection, MST analysis, and repository verification utilities
- **Development Tools** - CLI utilities for testing, debugging, and managing AT Protocol identities

## Contributing

Contributions are welcome! This project follows standard Rust development practices:

1. Fork this repository
2. Create a feature branch
3. Run tests: `cargo test`
4. Run linting: `cargo fmt && cargo clippy`
5. Submit a pull request

## Acknowledgments

Parts of this project were extracted from the [smokesignal.events](https://tangled.sh/@smokesignal.events/smokesignal) project, an open-source AT Protocol event and RSVP management application. This extraction enables broader community use and contribution to AT Protocol tooling in Rust.
