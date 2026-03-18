//! AT Protocol server authentication operations.
//!
//! Client functions for com.atproto.server XRPC methods including
//! session creation, refresh, and deletion with app password authentication.
//! - **`create_app_password()`**: Create a new app password for authenticated account
//! - **`delete_session()`**: Delete the current authentication session
//!
//! ## Request/Response Types
//!
//! - **`CreateSessionRequest`**: Parameters for creating a new session
//! - **`AppPasswordSession`**: Response containing session data and tokens
//! - **`RefreshSessionResponse`**: Response from session refresh operation
//! - **`AppPasswordResponse`**: Response containing created app password details
//!
//! ## Authentication
//!
//! Session creation uses app password authentication, while session refresh requires
//! the refresh JWT token from a previous session. App password creation requires
//! an access JWT token from an authenticated session.

use anyhow::Result;
use atproto_identity::url::build_url;
use serde::{Deserialize, Serialize};
use std::iter;

use crate::{
    client::{Auth, post_json},
    errors::ClientError,
};

/// Request to create a new authentication session.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone)]
pub struct CreateSessionRequest {
    /// Handle or other identifier supported by the server for the authenticating user
    pub identifier: String,
    /// User password or app password
    pub password: String,
    /// Optional two-factor authentication token
    #[serde(skip_serializing_if = "Option::is_none", rename = "authFactorToken")]
    pub auth_factor_token: Option<String>,
}

/// App password session data returned from successful authentication.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
pub struct AppPasswordSession {
    /// Distributed identifier for the authenticated account
    pub did: String,
    /// Handle for the authenticated account
    pub handle: String,
    /// Email address for the authenticated account
    pub email: String,
    /// JWT access token for authenticated requests
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// JWT refresh token for obtaining new access tokens
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
}

/// Response from refreshing an authentication session.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
pub struct RefreshSessionResponse {
    /// Distributed identifier for the authenticated account
    pub did: String,
    /// Handle for the authenticated account
    pub handle: String,
    /// JWT access token for authenticated requests
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// JWT refresh token for obtaining new access tokens
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
    /// Whether the account is active
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Account status (e.g., "takendown", "suspended", "deactivated")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Response from creating a new app password.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
pub struct AppPasswordResponse {
    /// Name of the app password
    pub name: String,
    /// Generated app password string
    pub password: String,
    /// Creation timestamp in ISO 8601 format
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Creates a new authentication session using app password credentials.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `base_url` - Base URL of the AT Protocol server
/// * `identifier` - Handle or other identifier for the user
/// * `password` - User password or app password
/// * `auth_factor_token` - Optional two-factor authentication token
///
/// # Returns
///
/// The created session data including access and refresh tokens
///
/// # Errors
///
/// Returns errors for HTTP request failures, authentication failures,
/// or JSON parsing failures.
pub async fn create_session(
    http_client: &reqwest::Client,
    base_url: &str,
    identifier: &str,
    password: &str,
    auth_factor_token: Option<&str>,
) -> Result<AppPasswordSession> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.server.createSession",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let request = CreateSessionRequest {
        identifier: identifier.to_string(),
        password: password.to_string(),
        auth_factor_token: auth_factor_token.map(|s| s.to_string()),
    };

    let value = serde_json::to_value(request)?;

    post_json(http_client, &url, value)
        .await
        .and_then(|value| serde_json::from_value(value).map_err(|err| err.into()))
}

/// Refreshes an existing authentication session using a refresh token.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `base_url` - Base URL of the AT Protocol server
/// * `refresh_token` - JWT refresh token from a previous session
///
/// # Returns
///
/// The refreshed session data with new access and refresh tokens
///
/// # Errors
///
/// Returns errors for HTTP request failures, authentication failures,
/// or JSON parsing failures.
pub async fn refresh_session(
    http_client: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> Result<RefreshSessionResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.server.refreshSession",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    // Create a new client with the refresh token in Authorization header
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", refresh_token))?,
    );

    let response = http_client.post(&url).headers(headers).send().await?;

    let value = response.json::<serde_json::Value>().await?;

    serde_json::from_value(value).map_err(|err| err.into())
}

/// Creates a new app password for the authenticated account.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `base_url` - Base URL of the AT Protocol server
/// * `access_token` - JWT access token for authentication
/// * `name` - Name for the app password
///
/// # Returns
///
/// The created app password details including the generated password
///
/// # Errors
///
/// Returns errors for HTTP request failures, authentication failures,
/// or JSON parsing failures.
pub async fn create_app_password(
    http_client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
    name: &str,
) -> Result<AppPasswordResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.server.createAppPassword",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let request_body = serde_json::json!({
        "name": name
    });

    // Create a new client with the access token in Authorization header
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", access_token))?,
    );

    let response = http_client
        .post(&url)
        .headers(headers)
        .json(&request_body)
        .send()
        .await?;

    let value = response.json::<serde_json::Value>().await?;

    serde_json::from_value(value).map_err(|err| err.into())
}

/// Deletes the current authentication session.
///
/// Terminates the authenticated session, invalidating the current access token.
/// This operation requires app password authentication and will fail with
/// other authentication methods.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (must be AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
///
/// # Returns
///
/// Returns `Ok(())` on successful session deletion (HTTP 200 response)
///
/// # Errors
///
/// Returns `ClientError::InvalidAuthMethod` if authentication is not AppPassword,
/// or other errors for HTTP request failures.
pub async fn delete_session(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
) -> Result<()> {
    // Ensure we have AppPassword authentication
    let app_auth = match auth {
        Auth::AppPassword(app_auth) => app_auth,
        _ => {
            return Err(ClientError::InvalidAuthMethod {
                method: "deleteSession requires AppPassword authentication".to_string(),
            }
            .into());
        }
    };

    let url = build_url(
        base_url,
        "/xrpc/com.atproto.server.deleteSession",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    // Create headers with the Bearer token
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", app_auth.access_token))?,
    );

    // Send POST request with no body
    let response = http_client
        .post(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?;

    // Check for successful response (200 OK)
    if response.status() == reqwest::StatusCode::OK {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "deleteSession failed: expected 200 OK, got {}",
            response.status()
        ))
    }
}
