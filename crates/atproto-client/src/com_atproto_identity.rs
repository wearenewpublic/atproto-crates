//! AT Protocol identity XRPC methods implementation.
//!
//! This module provides client implementations for com.atproto.identity namespace methods,
//! including handle resolution functionality.

use std::collections::HashMap;

use anyhow::Result;
use atproto_identity::url::build_url;
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    client::{Auth, get_apppassword_json, get_dpop_json, get_json},
    errors::SimpleError,
};

/// Response from the com.atproto.identity.resolveHandle XRPC method.
///
/// This enum represents either a successful handle resolution containing a DID,
/// or an error response from the server.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum ResolveHandleResponse {
    /// Successful handle resolution response.
    Response {
        /// The DID that the handle resolves to.
        did: String,

        /// Additional fields not part of the standard response
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },

    /// Error response from the server
    Error(SimpleError),
}

/// Resolves an AT Protocol handle to its associated DID.
///
/// Makes an XRPC call to com.atproto.identity.resolveHandle to resolve
/// a handle (e.g., "user.bsky.social") to its corresponding DID.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - The base URL of the AT Protocol service
/// * `handle` - The handle to resolve
///
/// # Returns
///
/// Returns a `ResolveHandleResponse` containing either the resolved DID
/// or an error response from the server.
pub async fn resolve_handle<T: DeserializeOwned>(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    handle: String,
) -> Result<ResolveHandleResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.identity.resolveHandle",
        [("handle", handle.as_str())],
    )?
    .to_string();

    match auth {
        Auth::None => get_json(http_client, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => get_dpop_json(http_client, dpop_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => get_apppassword_json(http_client, app_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}
