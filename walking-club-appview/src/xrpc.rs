//! Thin XRPC client helpers over `atproto-client`.
//!
//! Builds `DPoPAuth` from a stored session and wraps the `com.atproto.space.*`
//! methods the AppView calls. Writes and delegation present the member's
//! DPoP/OAuth session; the authority-host credential exchange presents the
//! delegation token as a Bearer header. The read-side helpers here mirror the
//! XRPC method shapes; the live read path in `space::reader` performs its own
//! credential-bearer reads (reads require `Authorization: Bearer <CRED>`).

use atproto_client::client::{DPoPAuth, get_dpop_json, post_dpop_json};
use atproto_identity::key::identify_key;
use atproto_space::types::SpaceUri;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::error::{AppError, AppResult};
use crate::oauth::session::SessionCookie;

/// Build a `DPoPAuth` from a session cookie (access token + DPoP key).
pub fn dpop_auth_from_session(session: &SessionCookie) -> AppResult<DPoPAuth> {
    let key = identify_key(&session.dpop_private_key)
        .map_err(|e| anyhow::anyhow!("invalid dpop key: {e}"))?;
    Ok(DPoPAuth {
        dpop_private_key_data: key,
        oauth_access_token: session.access_token.clone(),
    })
}

/// Build a fully-qualified XRPC URL for the given host + NSID + query params.
pub fn xrpc_url(host: &str, nsid: &str, params: &[(&str, &str)]) -> AppResult<String> {
    let mut url = format!("{}/xrpc/{}", host.trim_end_matches('/'), nsid);
    if !params.is_empty() {
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect();
        url.push('?');
        url.push_str(&query.join("&"));
    }
    Ok(url)
}

/// Build a `HeaderMap` carrying `Authorization: Bearer <token>`.
fn bearer_headers(token: &str) -> AppResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| AppError::Space(format!("invalid bearer token: {e}")))?;
    headers.insert(AUTHORIZATION, value);
    Ok(headers)
}

/// `com.atproto.space.createRecord` — create a record in the space.
///
/// POSTed to the member's own PDS with their DPoP/OAuth session. The body
/// matches `CreateRecordInput{space, repo, collection, rkey?, validate?, record}`;
/// `repo` is the member DID and MUST equal the OAuth subject (the host enforces
/// `require_repo_matches_subject`). The response is `{uri, cid, validationStatus?}`
/// only.
// The argument list mirrors the `CreateRecordInput` body fields (space, repo,
// collection, rkey, record) plus the transport (http, auth, host); collapsing
// them into a struct would only obscure the 1:1 wire mapping.
#[allow(clippy::too_many_arguments)]
pub async fn create_record(
    http: &reqwest::Client,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    collection: &str,
    rkey: Option<&str>,
    record: Value,
) -> AppResult<Value> {
    let url = xrpc_url(host, "com.atproto.space.createRecord", &[])?;
    let mut input = json!({
        "space": space.to_string(),
        "repo": repo,
        "collection": collection,
        "validate": true,
        "record": record,
    });
    if let Some(rkey) = rkey
        && let Some(obj) = input.as_object_mut()
    {
        obj.insert("rkey".to_string(), Value::String(rkey.to_string()));
    }
    post_dpop_json(http, auth, &url, input)
        .await
        .map_err(|e| AppError::Space(format!("createRecord failed: {e}")))
}

/// `com.atproto.space.getDelegationToken` — mint a member delegation token.
///
/// GET on the member's own PDS with their DPoP/OAuth session. Returns the raw
/// delegation token string from the `{token}` response.
pub async fn get_delegation_token(
    http: &reqwest::Client,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
) -> AppResult<String> {
    let url = xrpc_url(
        host,
        "com.atproto.space.getDelegationToken",
        &[("space", &space.to_string())],
    )?;
    let value = get_dpop_json(http, auth, &url)
        .await
        .map_err(|e| AppError::Space(format!("getDelegationToken failed: {e}")))?;
    value
        .get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::Space("getDelegationToken: missing token".to_string()))
}

/// `com.atproto.space.getSpaceCredential` — exchange delegation + attestation
/// for a space credential. Uses Bearer (delegation token), NOT DPoP.
///
/// POSTed to the authority host with `Authorization: Bearer <delegation_token>`
/// and body `{space, clientAttestation?}`. Returns the credential string from
/// the `{credential}` response.
pub async fn get_space_credential(
    http: &reqwest::Client,
    host: &str,
    space: &SpaceUri,
    delegation_token: &str,
    client_attestation: Option<&str>,
) -> AppResult<String> {
    let url = xrpc_url(host, "com.atproto.space.getSpaceCredential", &[])?;
    let mut body = json!({ "space": space.to_string() });
    if let Some(att) = client_attestation
        && let Some(obj) = body.as_object_mut()
    {
        obj.insert(
            "clientAttestation".to_string(),
            Value::String(att.to_string()),
        );
    }
    let headers = bearer_headers(delegation_token)?;
    let response = http
        .post(&url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Space(format!("getSpaceCredential request failed: {e}")))?;
    let value: Value = response
        .json()
        .await
        .map_err(|e| AppError::Space(format!("getSpaceCredential parse failed: {e}")))?;
    value
        .get("credential")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AppError::Space("getSpaceCredential: missing credential".to_string()))
}

// NOTE: The credential-gated read methods (`listRepos`, `getRepoState`,
// `listRepoOps`, `getRecord`) and `registerNotify` are NOT exposed here. Per the
// protocol canon those calls authenticate with `Authorization: Bearer <space
// credential>` (a no-`aud` JWT), never DPoP/OAuth. They live in `space::reader`
// and `space::notify`, which own the credential-bearer raw-HTTP reads.
