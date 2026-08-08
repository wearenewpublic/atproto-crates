# atproto-xrpcs

XRPC service framework for AT Protocol applications.

## Overview

Build AT Protocol services with JWT authorization, DID resolution, and cryptographic identity verification middleware.

## Features

- **JWT authorization**: Comprehensive JWT token validation with DID-based issuer verification
- **DID resolution integration**: Automatic DID document resolution and key verification for authorization
- **Identity verification**: Cryptographic verification of JWT signatures using DID documents
- **Axum extractors**: Ready-to-use authorization extractors for Axum web handlers
- **Structured errors**: Specialized error types for authorization and XRPC operations

## CLI Tools

This crate does not provide standalone CLI tools. It serves as a foundational library for building XRPC services.

## Usage

### Basic XRPC Service

```rust
use atproto_xrpcs::authorization::Authorization;
use axum::{Json, Router, extract::Query, routing::get};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct HelloParams {
    name: Option<String>,
}

async fn handle_hello(
    params: Query<HelloParams>,
    authorization: Option<Authorization>,
) -> Json<serde_json::Value> {
    let name = params.name.as_deref().unwrap_or("World");

    let message = if authorization.is_some() {
        format!("Hello, authenticated {}!", name)
    } else {
        format!("Hello, {}!", name)
    };

    Json(json!({ "message": message }))
}

let app = Router::new()
    .route("/xrpc/com.example.hello", get(handle_hello))
    .with_state(your_web_context);
```

### JWT Authorization

```rust
use atproto_xrpcs::authorization::Authorization;

async fn handle_secure_endpoint(
    authorization: Authorization, // Required authorization
) -> Json<serde_json::Value> {
    // The Authorization extractor automatically:
    // 1. Validates the JWT token
    // 2. Resolves the caller's DID document
    // 3. Verifies the signature against the DID document
    // 4. Provides access to caller identity information

    let caller_did = authorization.subject();
    Json(json!({"caller": caller_did, "status": "authenticated"}))
}
```

### Error Handling

```rust
use atproto_xrpcs::errors::AuthorizationError;
use axum::{response::IntoResponse, http::StatusCode};

async fn protected_handler(
    authorization: Result<Authorization, AuthorizationError>,
) -> impl IntoResponse {
    match authorization {
        Ok(auth) => (StatusCode::OK, "Access granted").into_response(),
        Err(AuthorizationError::InvalidJWTFormat) => {
            (StatusCode::UNAUTHORIZED, "Invalid token").into_response()
        }
        Err(AuthorizationError::SubjectResolutionFailed { .. }) => {
            (StatusCode::FORBIDDEN, "Identity verification failed").into_response()
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Authorization error").into_response()
        }
    }
}
```

## Authorization Flow

The `Authorization` extractor implements:

1. JWT extraction from HTTP Authorization headers
2. Token validation (signature and claims structure)
3. DID resolution for the token issuer
4. Signature verification against DID document public keys
5. Identity confirmation and authorization scope validation

## License

MIT License