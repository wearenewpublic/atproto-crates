//! HTTP client operations with DPoP authentication support.
//!
//! Authenticated and unauthenticated HTTP requests for JSON APIs
//! with DPoP (Demonstration of Proof-of-Possession) support.

use crate::errors::{ClientError, DPoPError, XrpcError};
use anyhow::Result;
use atproto_identity::key::KeyData;
use atproto_oauth::dpop::{dpop_with_nonce, request_dpop};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use tracing::Instrument;

/// DPoP authentication credentials for authenticated HTTP requests.
///
/// Contains the private key for DPoP proof generation and OAuth access token
/// for Authorization header.
#[derive(Clone)]
pub struct DPoPAuth {
    /// Private key data for generating DPoP proof tokens
    pub dpop_private_key_data: KeyData,
    /// OAuth access token for the Authorization header
    pub oauth_access_token: String,
}

/// App password authentication credentials for authenticated HTTP requests.
///
/// Contains the JWT access token for Bearer token authentication.
#[derive(Clone)]
pub struct AppPasswordAuth {
    /// JWT access token for the Authorization header
    pub access_token: String,
}

/// Authentication method for AT Protocol XRPC requests.
///
/// Supports multiple authentication schemes including unauthenticated requests,
/// DPoP (Demonstration of Proof-of-Possession) tokens, and app password bearer tokens.
#[derive(Clone)]
pub enum Auth {
    /// No authentication - for public endpoints that don't require authentication
    None,
    /// DPoP authentication with proof-of-possession tokens and OAuth access token
    DPoP(DPoPAuth),
    /// App password authentication using JWT bearer tokens
    AppPassword(AppPasswordAuth),
}

/// The body of a DPoP-authenticated request.
///
/// `Bytes` exists because `com.atproto.repo.uploadBlob` is not JSON: it sends
/// raw bytes and the server records the `Content-Type` it was given on the
/// blob. A JSON-only transport is why an uploader ends up as a second copy of
/// the nonce dance rather than a caller of it.
#[derive(Debug, Clone)]
pub enum DpopBody<'a> {
    /// A JSON document, sent as `application/json`.
    Json(&'a serde_json::Value),
    /// Raw bytes with a caller-chosen content type.
    Bytes {
        /// The `Content-Type` to send.
        ///
        /// For `uploadBlob` this is recorded on the blob, so it must be the
        /// type determined from the bytes and never the one a browser
        /// declared.
        content_type: &'a str,
        /// The bytes to send.
        data: Vec<u8>,
    },
}

/// An XRPC response with the status line intact.
///
/// [`post_dpop_json`] and its siblings parse the body regardless of status and
/// return it, which makes a `429` indistinguishable from a `200` except by
/// guessing at the body shape, and puts `Retry-After` and `DPoP-Nonce` out of
/// reach. This carries all three.
#[derive(Debug)]
pub struct XrpcResponse {
    /// The HTTP status the server answered with.
    pub status: StatusCode,
    /// Every response header, including `Retry-After` and `DPoP-Nonce`.
    pub headers: HeaderMap,
    /// The parsed body.
    ///
    /// `None` when the body was absent, empty, or not JSON -- never an error.
    /// Some deployments front their errors with a proxy that answers HTML, and
    /// a classifier that unwrapped here would turn a bad gateway into a panic.
    pub body: Option<serde_json::Value>,
    /// The body as it arrived.
    ///
    /// Kept alongside the parsed form because several XRPC methods do not
    /// answer JSON at all: the `com.atproto.sync` exports return CAR files on
    /// success and an XRPC JSON error otherwise, so the status has to be read
    /// before the body can be interpreted as either, and a transport that only
    /// handed back the parse would make those methods need a second one.
    pub bytes: Bytes,
}

impl XrpcResponse {
    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// The `error` and `message` fields of an XRPC error body.
    ///
    /// Both are empty when absent. Both are optional in practice -- a proxy
    /// that answers a 502 sends neither -- so this reports their absence
    /// rather than failing on it.
    pub fn xrpc_error_fields(&self) -> (String, String) {
        let field = |name: &str| {
            self.body
                .as_ref()
                .and_then(|value| value.get(name))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        (field("error"), field("message"))
    }

    /// The `Retry-After` header in seconds.
    ///
    /// RFC 9110 §10.2.3 allows an HTTP-date as well as delta-seconds. Only the
    /// delta-seconds form is read here; a date returns `None`, which a caller
    /// handles the same way it handles a server that sent no header at all.
    pub fn retry_after_secs(&self) -> Option<u64> {
        self.headers
            .get(reqwest::header::RETRY_AFTER)?
            .to_str()
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// The value of the `DPoP-Nonce` header, when the server sent one.
    pub fn dpop_nonce(&self) -> Option<&str> {
        self.headers.get("DPoP-Nonce")?.to_str().ok()
    }

    /// Classify this response as an XRPC error, or `None` if it succeeded.
    pub fn error(&self) -> Option<XrpcError> {
        XrpcError::from_response(self)
    }
}

/// The name [`XrpcResponse`] had when it only served [`dpop_call`].
pub type DpopResponse = XrpcResponse;

/// Whether a 400 or 401 is a DPoP nonce challenge.
///
/// Three signals, because one server is not the network:
///
/// * the XRPC error code, which is what a token endpoint sends;
/// * the `WWW-Authenticate` challenge, which is what RFC 9449 §7.1 specifies
///   and what a resource server sends;
/// * a `DPoP-Nonce` header with no error code at all, which is the bare shape
///   some servers answer with.
///
/// The third arm is the loosest and is still safe: it is only reached on a 400
/// or 401, only on the first attempt, and only when a nonce header was
/// present. The worst case is one retry that fails identically.
pub fn is_nonce_challenge(code: &str, www_authenticate: &str, has_nonce: bool) -> bool {
    if code == "use_dpop_nonce" || code == "invalid_dpop_proof" {
        return true;
    }
    // `DPoP error="use_dpop_nonce"`, case-insensitively: the scheme and the
    // parameter names are case-insensitive per RFC 9110 §11.1, and quoting is
    // at the server's discretion, so this looks for the token rather than
    // parsing the whole header.
    let header = www_authenticate.to_ascii_lowercase();
    if header.contains("use_dpop_nonce") || header.contains("invalid_dpop_proof") {
        return true;
    }
    has_nonce && code.is_empty()
}

/// A DPoP-authenticated XRPC call with the status line intact.
///
/// Unlike [`post_dpop_json`], this returns the status and the response headers
/// alongside the body, so a caller can distinguish a `429` from a `200`, read
/// `Retry-After`, and classify an XRPC error code with
/// [`XrpcError::from_response`].
///
/// The nonce dance is handled here rather than by middleware: exactly one
/// retry, because a server that demands a nonce from a proof already carrying
/// the one it just issued is misbehaving, and looping on it turns one bad peer
/// into an outbound request flood. The retry proof is minted fresh rather than
/// re-signed, so it carries a new `jti` and `iat` -- a server that tracks
/// `jti` for replay protection would refuse a re-send of the proof it just
/// challenged.
///
/// A challenge the server sent no `DPoP-Nonce` with is returned as-is rather
/// than retried or turned into an error: there is nothing to retry with, and
/// the caller is better placed to say what a nonce-less challenge means.
///
/// # Errors
///
/// Returns [`DPoPError::ProofGenerationFailed`] if the proof cannot be minted,
/// [`DPoPError::BodySerializationFailed`] if a JSON body cannot be encoded,
/// [`DPoPError::RequestFailed`] if the request cannot be sent, and
/// [`DPoPError::BodyReadFailed`] if the response body cannot be read off the
/// socket. A non-2xx status is **not** an error -- that is the point.
pub async fn dpop_call(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    method: Method,
    url: &str,
    body: Option<DpopBody<'_>>,
    additional_headers: &HeaderMap,
) -> Result<XrpcResponse, DPoPError> {
    dpop_call_with_timeout(
        http_client,
        dpop_auth,
        method,
        url,
        body,
        additional_headers,
        None,
    )
    .await
}

/// [`dpop_call`] with a deadline that applies to this call alone.
///
/// A timeout set on the shared `reqwest::Client` applies to every other thing
/// that client does -- a firehose socket, a blob fetch -- so a per-call
/// deadline has to be passed per call. The deadline covers each attempt
/// separately, so a nonce challenge followed by a retry can take up to twice
/// `timeout`.
///
/// # Errors
///
/// As [`dpop_call`]; a deadline overrun arrives as
/// [`DPoPError::RequestFailed`].
pub async fn dpop_call_with_timeout(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    method: Method,
    url: &str,
    body: Option<DpopBody<'_>>,
    additional_headers: &HeaderMap,
    timeout: Option<std::time::Duration>,
) -> Result<XrpcResponse, DPoPError> {
    // Serialized once: the retry sends the same bytes, and re-encoding them
    // would be the second place a body could differ from the one the first
    // proof was minted over.
    let payload = encode_body(body)?;

    let (proof, ..) = request_dpop(
        &dpop_auth.dpop_private_key_data,
        method.as_str(),
        url,
        &dpop_auth.oauth_access_token,
    )
    .map_err(|error| DPoPError::ProofGenerationFailed { error })?;

    let first = send_dpop_request(
        http_client,
        dpop_auth,
        &method,
        url,
        payload.as_ref(),
        additional_headers,
        &proof,
        timeout,
    )
    .await?;

    let challenged = (first.status == StatusCode::BAD_REQUEST
        || first.status == StatusCode::UNAUTHORIZED)
        && is_nonce_challenge(
            &first.xrpc_error_fields().0,
            first
                .headers
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default(),
            first.dpop_nonce().is_some(),
        );

    if !challenged {
        return Ok(first);
    }

    let Some(nonce) = first.dpop_nonce().map(str::to_string) else {
        return Ok(first);
    };

    let (retry_proof, ..) = dpop_with_nonce(
        &dpop_auth.dpop_private_key_data,
        method.as_str(),
        url,
        Some(&dpop_auth.oauth_access_token),
        &nonce,
    )
    .map_err(|error| DPoPError::ProofGenerationFailed { error })?;

    send_dpop_request(
        http_client,
        dpop_auth,
        &method,
        url,
        payload.as_ref(),
        additional_headers,
        &retry_proof,
        timeout,
    )
    .await
}

/// Turn a request body into a content type and the bytes to send.
///
/// An empty content type means "send none", which is what the raw-byte helper
/// did before this transport existed.
fn encode_body(body: Option<DpopBody<'_>>) -> Result<Option<(String, Bytes)>, DPoPError> {
    Ok(match body {
        None => None,
        Some(DpopBody::Json(value)) => {
            let data = serde_json::to_vec(value)
                .map_err(|error| DPoPError::BodySerializationFailed { error })?;
            Some(("application/json".to_string(), Bytes::from(data)))
        }
        Some(DpopBody::Bytes { content_type, data }) => {
            Some((content_type.to_string(), Bytes::from(data)))
        }
    })
}

/// An XRPC call under whichever authentication the caller holds, with the
/// status line intact.
///
/// [`dpop_call`] for [`Auth::DPoP`], including its one-retry nonce dance; a
/// plain request otherwise. Prefer this over [`get_json`] and friends anywhere
/// the answer to "what went wrong" is a status code or a header: a `404` and a
/// `503` are the difference between "this repository is gone" and "this PDS is
/// having a bad minute", and a caller that only sees the body cannot tell them
/// apart.
///
/// # Errors
///
/// As [`dpop_call`]. A non-2xx status is not an error.
pub async fn xrpc_call(
    http_client: &reqwest::Client,
    auth: &Auth,
    method: Method,
    url: &str,
    body: Option<DpopBody<'_>>,
    additional_headers: &HeaderMap,
) -> Result<XrpcResponse> {
    match auth {
        Auth::DPoP(dpop_auth) => Ok(dpop_call(
            http_client,
            dpop_auth,
            method,
            url,
            body,
            additional_headers,
        )
        .await?),
        Auth::None => {
            let payload = encode_body(body)?;
            Ok(send_request(
                http_client,
                &method,
                url,
                payload.as_ref(),
                additional_headers.clone(),
                None,
            )
            .await?)
        }
        Auth::AppPassword(app_auth) => {
            let payload = encode_body(body)?;
            let mut headers = additional_headers.clone();
            set_header(
                &mut headers,
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", app_auth.access_token),
            )?;
            Ok(send_request(http_client, &method, url, payload.as_ref(), headers, None).await?)
        }
    }
}

/// Issue one request and read the whole response.
///
/// `headers` carries whatever authentication the caller settled on; nothing
/// here adds any.
async fn send_request(
    http_client: &reqwest::Client,
    method: &Method,
    url: &str,
    payload: Option<&(String, Bytes)>,
    mut headers: HeaderMap,
    timeout: Option<std::time::Duration>,
) -> Result<XrpcResponse, DPoPError> {
    if let Some((content_type, _)) = payload {
        // An empty content type means "send none". The body's own type wins
        // over anything in the caller's headers: it is the argument the API is
        // built around, and for `uploadBlob` it is the value the server
        // records on the blob.
        if !content_type.is_empty() {
            set_header(&mut headers, reqwest::header::CONTENT_TYPE, content_type)?;
        }
    }

    let mut builder = http_client.request(method.clone(), url).headers(headers);

    if let Some((_, data)) = payload {
        builder = builder.body(data.clone());
    }

    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }

    let response = builder
        .send()
        .instrument(tracing::debug_span!("xrpc_call", method = %method, url = %url))
        .await
        .map_err(|error| DPoPError::RequestFailed {
            url: url.to_string(),
            error,
        })?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| DPoPError::BodyReadFailed {
            url: url.to_string(),
            error,
        })?;

    Ok(XrpcResponse {
        status,
        headers,
        body: serde_json::from_slice(&bytes).ok(),
        bytes,
    })
}

/// Issue one DPoP attempt and read the whole response.
#[allow(clippy::too_many_arguments)]
async fn send_dpop_request(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    method: &Method,
    url: &str,
    payload: Option<&(String, Bytes)>,
    additional_headers: &HeaderMap,
    proof: &str,
    timeout: Option<std::time::Duration>,
) -> Result<XrpcResponse, DPoPError> {
    // Built with `insert` rather than `RequestBuilder::header`, which appends:
    // a caller that passed its own `Authorization` or `Content-Type` in
    // `additional_headers` would otherwise get two of them on the wire, and
    // which one the server honours is its business rather than ours.
    let mut headers = additional_headers.clone();
    set_header(
        &mut headers,
        reqwest::header::AUTHORIZATION,
        &format!("DPoP {}", dpop_auth.oauth_access_token),
    )?;
    set_header(&mut headers, HeaderName::from_static("dpop"), proof)?;

    send_request(http_client, method, url, payload, headers, timeout).await
}

/// Set one header, replacing any the caller already supplied.
fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) -> Result<(), DPoPError> {
    let value = HeaderValue::from_str(value).map_err(|_| DPoPError::InvalidHeaderValue {
        name: name.as_str().to_string(),
    })?;
    headers.insert(name, value);
    Ok(())
}

/// Decode a successful XRPC response, or report why it was not one.
///
/// The status decides. A body is only parsed when the server said the call
/// succeeded, so an error body that happens to have the shape of a success --
/// which `#[serde(untagged)]` response enums make easy to fall into -- cannot
/// be mistaken for one.
///
/// # Errors
///
/// Returns [`XrpcError`] on a non-2xx, classified from the status and the
/// error code together; [`ClientError::ResponseNotJson`] when a success
/// carried no JSON body; and a `serde_json` error when the body did not fit
/// `T`.
pub fn decode_xrpc<T: serde::de::DeserializeOwned>(response: XrpcResponse) -> Result<T> {
    if let Some(error) = XrpcError::from_response(&response) {
        return Err(error.into());
    }
    let body = response.body.ok_or(ClientError::ResponseNotJson {
        url: String::new(),
        status: response.status.as_u16(),
    })?;
    Ok(serde_json::from_value(body)?)
}

/// Read an [`XrpcResponse`] body the way the pre-existing helpers do.
///
/// The body regardless of status, and a parse failure if it was not JSON.
/// Callers that need the status line should use [`dpop_call`] directly.
fn body_or_parse_error(url: &str, response: XrpcResponse) -> Result<serde_json::Value> {
    response.body.ok_or_else(|| {
        ClientError::ResponseNotJson {
            url: url.to_string(),
            status: response.status.as_u16(),
        }
        .into()
    })
}

/// Performs an unauthenticated HTTP GET request and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn get_json(http_client: &reqwest::Client, url: &str) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    get_json_with_headers(http_client, url, &empty).await
}

/// Performs an unauthenticated HTTP GET request with additional headers and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn get_json_with_headers(
    http_client: &reqwest::Client,
    url: &str,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let http_response = http_client
        .get(url)
        .headers(additional_headers.clone())
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;

    let value = http_response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| ClientError::JsonParseFailed {
            url: url.to_string(),
            error,
        })?;

    Ok(value)
}

/// Performs an unauthenticated HTTP GET request and returns the response as bytes.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
///
/// # Returns
///
/// The response body as bytes
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or an error if streaming the response bytes fails.
pub async fn get_bytes(http_client: &reqwest::Client, url: &str) -> Result<Bytes> {
    let empty = HeaderMap::default();
    get_bytes_with_headers(http_client, url, &empty).await
}

/// Performs an unauthenticated HTTP GET request with additional headers and returns the response as bytes.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The response body as bytes
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or an error if streaming the response bytes fails.
pub async fn get_bytes_with_headers(
    http_client: &reqwest::Client,
    url: &str,
    additional_headers: &HeaderMap,
) -> Result<Bytes> {
    let http_response = http_client
        .get(url)
        .headers(additional_headers.clone())
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;
    Ok(http_response
        .bytes()
        .await
        .map_err(|error| ClientError::ByteStreamFailed {
            url: url.to_string(),
            error,
        })?)
}

/// Performs a DPoP-authenticated HTTP GET request and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `dpop_auth` - DPoP authentication credentials
/// * `url` - The URL to request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `DPoPError::ProofGenerationFailed` if DPoP proof generation fails,
/// `DPoPError::HttpRequestFailed` if the HTTP request fails,
/// or `DPoPError::JsonParseFailed` if JSON parsing fails.
pub async fn get_dpop_json(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    url: &str,
) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    get_dpop_json_with_headers(http_client, dpop_auth, url, &empty).await
}

/// Performs a DPoP-authenticated HTTP GET request with additional headers and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `dpop_auth` - DPoP authentication credentials
/// * `url` - The URL to request
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `DPoPError::ProofGenerationFailed` if DPoP proof generation fails,
/// `DPoPError::HttpRequestFailed` if the HTTP request fails,
/// or `DPoPError::JsonParseFailed` if JSON parsing fails.
pub async fn get_dpop_json_with_headers(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    url: &str,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let response = dpop_call(
        http_client,
        dpop_auth,
        Method::GET,
        url,
        None,
        additional_headers,
    )
    .await?;

    body_or_parse_error(url, response)
}

/// Performs a DPoP-authenticated HTTP POST request with JSON body and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `dpop_auth` - DPoP authentication credentials
/// * `url` - The URL to request
/// * `record` - The JSON data to send in the request body
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `DPoPError::ProofGenerationFailed` if DPoP proof generation fails,
/// `DPoPError::HttpRequestFailed` if the HTTP request fails,
/// or `DPoPError::JsonParseFailed` if JSON parsing fails.
pub async fn post_dpop_json(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    url: &str,
    record: serde_json::Value,
) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    post_dpop_json_with_headers(http_client, dpop_auth, url, record, &empty).await
}

/// Performs a DPoP-authenticated HTTP POST request with JSON body and additional headers, and parses the response as JSON.
///
/// This function extends `post_dpop_json` by allowing custom headers to be included
/// in the request. Useful for adding custom content types, user agents, or other
/// protocol-specific headers while maintaining DPoP authentication.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `dpop_auth` - DPoP authentication credentials
/// * `url` - The URL to request
/// * `record` - The JSON data to send in the request body
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `DPoPError::ProofGenerationFailed` if DPoP proof generation fails,
/// `DPoPError::HttpRequestFailed` if the HTTP request fails,
/// or `DPoPError::JsonParseFailed` if JSON parsing fails.
///
/// # Example
///
/// ```no_run
/// use atproto_client::client::{DPoPAuth, post_dpop_json_with_headers};
/// use atproto_identity::key::identify_key;
/// use reqwest::{Client, header::{HeaderMap, USER_AGENT}};
/// use serde_json::json;
///
/// # async fn example() -> anyhow::Result<()> {
/// let client = Client::new();
/// let dpop_auth = DPoPAuth {
///     dpop_private_key_data: identify_key("did:key:zQ3sh...")?,
///     oauth_access_token: "access_token".to_string(),
/// };
///
/// let mut headers = HeaderMap::new();
/// headers.insert(USER_AGENT, "my-app/1.0".parse()?);
///
/// let response = post_dpop_json_with_headers(
///     &client,
///     &dpop_auth,
///     "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
///     json!({"$type": "app.bsky.feed.post", "text": "Hello!"}),
///     &headers
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn post_dpop_json_with_headers(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    url: &str,
    record: serde_json::Value,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let response = dpop_call(
        http_client,
        dpop_auth,
        Method::POST,
        url,
        Some(DpopBody::Json(&record)),
        additional_headers,
    )
    .await?;

    body_or_parse_error(url, response)
}

/// Performs a DPoP-authenticated HTTP POST request with raw bytes body and additional headers, and parses the response as JSON.
///
/// This function is similar to `post_dpop_json_with_headers` but accepts a raw bytes payload
/// instead of JSON. Useful for sending pre-serialized data or binary payloads while maintaining
/// DPoP authentication and custom headers.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `dpop_auth` - DPoP authentication credentials
/// * `url` - The URL to request
/// * `payload` - The raw bytes to send in the request body
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `DPoPError::ProofGenerationFailed` if DPoP proof generation fails,
/// `DPoPError::HttpRequestFailed` if the HTTP request fails,
/// or `DPoPError::JsonParseFailed` if JSON parsing fails.
///
/// # Example
///
/// ```no_run
/// use atproto_client::client::{DPoPAuth, post_dpop_bytes_with_headers};
/// use atproto_identity::key::identify_key;
/// use reqwest::{Client, header::{HeaderMap, CONTENT_TYPE}};
/// use bytes::Bytes;
///
/// # async fn example() -> anyhow::Result<()> {
/// let client = Client::new();
/// let dpop_auth = DPoPAuth {
///     dpop_private_key_data: identify_key("did:key:zQ3sh...")?,
///     oauth_access_token: "access_token".to_string(),
/// };
///
/// let mut headers = HeaderMap::new();
/// headers.insert(CONTENT_TYPE, "application/json".parse()?);
///
/// let payload = Bytes::from(r#"{"text": "Hello!"}"#);
/// let response = post_dpop_bytes_with_headers(
///     &client,
///     &dpop_auth,
///     "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
///     payload,
///     &headers
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn post_dpop_bytes_with_headers(
    http_client: &reqwest::Client,
    dpop_auth: &DPoPAuth,
    url: &str,
    payload: Bytes,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    // The content type comes from `additional_headers` on this path, as it
    // always has. Empty when the caller named none, which sends no
    // `Content-Type` at all rather than inventing one.
    let content_type = additional_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let response = dpop_call(
        http_client,
        dpop_auth,
        Method::POST,
        url,
        Some(DpopBody::Bytes {
            content_type: &content_type,
            data: payload.to_vec(),
        }),
        additional_headers,
    )
    .await?;

    body_or_parse_error(url, response)
}

/// Performs an unauthenticated HTTP POST request with JSON body and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
/// * `data` - The JSON data to send in the request body
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn post_json(
    http_client: &reqwest::Client,
    url: &str,
    data: serde_json::Value,
) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    post_json_with_headers(http_client, url, data, &empty).await
}

/// Performs an unauthenticated HTTP POST request with JSON body and additional headers, and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `url` - The URL to request
/// * `data` - The JSON data to send in the request body
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn post_json_with_headers(
    http_client: &reqwest::Client,
    url: &str,
    data: serde_json::Value,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let http_response = http_client
        .post(url)
        .headers(additional_headers.clone())
        .json(&data)
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;

    let value = http_response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| ClientError::JsonParseFailed {
            url: url.to_string(),
            error,
        })?;

    Ok(value)
}

/// Performs an app password-authenticated HTTP GET request and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn get_apppassword_json(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    get_apppassword_json_with_headers(http_client, app_auth, url, &empty).await
}

/// Performs an app password-authenticated HTTP GET request with additional headers and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn get_apppassword_json_with_headers(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let mut headers = additional_headers.clone();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", app_auth.access_token))?,
    );

    let http_response = http_client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;

    let value = http_response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| ClientError::JsonParseFailed {
            url: url.to_string(),
            error,
        })?;

    Ok(value)
}

/// Performs an app password-authenticated HTTP POST request with JSON body and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
/// * `data` - The JSON data to send in the request body
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn post_apppassword_json(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
    data: serde_json::Value,
) -> Result<serde_json::Value> {
    let empty = HeaderMap::default();
    post_apppassword_json_with_headers(http_client, app_auth, url, data, &empty).await
}

/// Performs an app password-authenticated HTTP POST request with JSON body and additional headers, and parses the response as JSON.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
/// * `data` - The JSON data to send in the request body
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The parsed JSON response as a `serde_json::Value`
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or `ClientError::JsonParseFailed` if JSON parsing fails.
pub async fn post_apppassword_json_with_headers(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
    data: serde_json::Value,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let mut headers = additional_headers.clone();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", app_auth.access_token))?,
    );

    let http_response = http_client
        .post(url)
        .headers(headers)
        .json(&data)
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;

    let value = http_response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| ClientError::JsonParseFailed {
            url: url.to_string(),
            error,
        })?;

    Ok(value)
}

/// Performs an app password-authenticated HTTP GET request and returns the response as bytes.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The response body as bytes
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or an error if streaming the response bytes fails.
pub async fn get_apppassword_bytes_with_headers(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
    additional_headers: &HeaderMap,
) -> Result<Bytes> {
    let mut headers = additional_headers.clone();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", app_auth.access_token))?,
    );
    let http_response = http_client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;
    Ok(http_response
        .bytes()
        .await
        .map_err(|error| ClientError::ByteStreamFailed {
            url: url.to_string(),
            error,
        })?)
}

/// Performs an app password-authenticated HTTP POST request with JSON body and returns the response as bytes.
///
/// This is useful when the server returns binary data such as images, CAR files,
/// or other non-JSON content in response to authenticated POST requests.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for the request
/// * `app_auth` - App password authentication credentials
/// * `url` - The URL to request
/// * `record` - The JSON data to send in the request body
/// * `additional_headers` - Additional HTTP headers to include in the request
///
/// # Returns
///
/// The response body as bytes
///
/// # Errors
///
/// Returns `ClientError::HttpRequestFailed` if the HTTP request fails,
/// or an error if streaming the response bytes fails.
pub async fn post_apppassword_bytes_with_headers(
    http_client: &reqwest::Client,
    app_auth: &AppPasswordAuth,
    url: &str,
    payload: Bytes,
    additional_headers: &HeaderMap,
) -> Result<Bytes> {
    let mut headers = additional_headers.clone();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", app_auth.access_token))?,
    );
    let http_response = http_client
        .post(url)
        .headers(headers)
        .body(payload)
        .send()
        .instrument(tracing::info_span!("post_apppassword_bytes_with_headers", url = %url))
        .await
        .map_err(|error| ClientError::HttpRequestFailed {
            url: url.to_string(),
            error,
        })?;
    Ok(http_response
        .bytes()
        .await
        .map_err(|error| ClientError::ByteStreamFailed {
            url: url.to_string(),
            error,
        })?)
}
