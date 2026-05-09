//! DPoP (Demonstration of Proof-of-Possession) implementation.
//!
//! RFC 9449 compliant DPoP token generation with automatic retry middleware
//! for nonce challenges and ES256 signature support.

use crate::errors::{JWKError, JWTError};
use anyhow::Result;
use atproto_identity::key::{KeyData, to_public, validate};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use elliptic_curve::JwkEcKey;
use reqwest::header::HeaderValue;
use reqwest_chain::Chainer;
use ulid::Ulid;

use crate::{
    errors::DpopError,
    jwk::{WrappedJsonWebKey, thumbprint, to_key_data},
    jwt::{Claims, Header, JoseClaims, mint},
    pkce::challenge,
};

/// Retry middleware for handling DPoP nonce challenges in HTTP requests.
///
/// This struct implements the `Chainer` trait to automatically retry requests
/// when the server responds with a "use_dpop_nonce" error, adding the required
/// nonce to the DPoP proof before retrying.
#[derive(Clone)]
pub struct DpopRetry {
    /// The JWT header for the DPoP proof.
    pub header: Header,
    /// The JWT claims for the DPoP proof.
    pub claims: Claims,
    /// The cryptographic key data used to sign the DPoP proof.
    pub key_data: KeyData,

    /// Whether to check the response body for DPoP errors in addition to headers.
    pub check_response_body: bool,
}

impl DpopRetry {
    /// Creates a new DpopRetry instance with the provided header, claims, and key data.
    ///
    /// # Arguments
    /// * `header` - The JWT header for the DPoP proof
    /// * `claims` - The JWT claims for the DPoP proof
    /// * `key_data` - The cryptographic key data for signing
    pub fn new(
        header: Header,
        claims: Claims,
        key_data: KeyData,
        check_response_body: bool,
    ) -> Self {
        DpopRetry {
            header,
            claims,
            key_data,
            check_response_body,
        }
    }
}

/// Implementation of the `Chainer` trait for handling DPoP nonce challenges.
///
/// This middleware intercepts HTTP responses with 400/401 status codes and
/// "use_dpop_nonce" errors, extracts the DPoP-Nonce header, and retries
/// the request with an updated DPoP proof containing the nonce.
///
/// This does not evaluate the response body to determine if a DPoP error was
/// returned. Only the returned "WWW-Authenticate" header is evaluated. This
/// is the expected and defined behavior per RFC7235 sections 3.1 and 4.1.
#[async_trait::async_trait]
impl Chainer for DpopRetry {
    type State = ();

    /// Handles the retry logic for DPoP nonce challenges.
    ///
    /// # Arguments
    /// * `result` - The result of the HTTP request
    /// * `_state` - Unused state (unit type)
    /// * `request` - The mutable request to potentially retry
    ///
    /// # Returns
    /// * `Ok(Some(response))` - Original response if no retry needed
    /// * `Ok(None)` - Retry the request with updated DPoP proof
    /// * `Err(error)` - Error if retry logic fails
    async fn chain(
        &self,
        result: Result<reqwest::Response, reqwest_middleware::Error>,
        _state: &mut Self::State,
        request: &mut reqwest::Request,
    ) -> Result<Option<reqwest::Response>, reqwest_middleware::Error> {
        let response = result?;

        let status_code = response.status();

        let dpop_status_code = status_code == 400 || status_code == 401;
        if !dpop_status_code {
            return Ok(Some(response));
        };

        let headers = response.headers().clone();
        let www_authenticate_header = headers.get("WWW-Authenticate");
        let www_authenticate_value = www_authenticate_header.and_then(|value| value.to_str().ok());
        let dpop_header_error = www_authenticate_value.is_some_and(is_dpop_error);

        if !dpop_header_error && !self.check_response_body {
            return Ok(Some(response));
        };

        if self.check_response_body {
            let response_body = match response.json::<serde_json::Value>().await {
                Err(err) => {
                    return Err(reqwest_middleware::Error::Middleware(
                        DpopError::ResponseBodyParsingFailed(err).into(),
                    ));
                }
                Ok(value) => value,
            };
            if let Some(response_body_obj) = response_body.as_object() {
                let error_value = response_body_obj
                    .get("error")
                    .and_then(|value| value.as_str())
                    .unwrap_or("placeholder_unknown_error");

                if error_value != "invalid_dpop_proof" && error_value != "use_dpop_nonce" {
                    return Err(reqwest_middleware::Error::Middleware(
                        DpopError::UnexpectedOAuthError {
                            error: error_value.to_string(),
                        }
                        .into(),
                    ));
                }
            } else {
                return Err(reqwest_middleware::Error::Middleware(
                    DpopError::ResponseBodyObjectParsingFailed.into(),
                ));
            }
        };

        let dpop_header = headers
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok());

        if dpop_header.is_none() {
            return Err(reqwest_middleware::Error::Middleware(
                DpopError::MissingDpopNonceHeader.into(),
            ));
        }
        let dpop_header = dpop_header.unwrap();

        let dpop_proof_header = self.header.clone();
        let mut dpop_proof_claim = self.claims.clone();
        dpop_proof_claim
            .private
            .insert("nonce".to_string(), dpop_header.to_string().into());

        let dpop_proof_token = mint(&self.key_data, &dpop_proof_header, &dpop_proof_claim)
            .map_err(|err| {
                reqwest_middleware::Error::Middleware(DpopError::TokenMintingFailed(err).into())
            })?;

        request.headers_mut().insert(
            "DPoP",
            HeaderValue::from_str(&dpop_proof_token).map_err(|err| {
                reqwest_middleware::Error::Middleware(DpopError::HeaderCreationFailed(err).into())
            })?,
        );

        Ok(None)
    }
}

/// Parses the value of the "WWW-Authenticate" header and returns true if the inner "error" field is either "invalid_dpop_proof" or "use_dpop_nonce".
///
/// This function parses DPoP challenge headers to determine if the server is requesting
/// a DPoP proof or indicating that the provided proof is invalid.
///
/// # Arguments
/// * `value` - The WWW-Authenticate header value to parse
///
/// # Returns
/// * `true` if the error field indicates a DPoP-related error
/// * `false` if no DPoP error is found or the header format is invalid
///
/// # Examples
/// ```no_run
/// use atproto_oauth::dpop::is_dpop_error;
///
/// // Valid DPoP error: invalid_dpop_proof
/// let header1 = r#"DPoP algs="ES256", error="invalid_dpop_proof", error_description="DPoP proof required""#;
/// assert!(is_dpop_error(header1));
///
/// // Valid DPoP error: use_dpop_nonce
/// let header2 = r#"DPoP algs="ES256", error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof""#;
/// assert!(is_dpop_error(header2));
///
/// // Non-DPoP error
/// let header3 = r#"DPoP algs="ES256", error="invalid_token", error_description="Token is invalid""#;
/// assert!(!is_dpop_error(header3));
///
/// // Non-DPoP authentication scheme
/// let header4 = r#"Bearer error="invalid_token""#;
/// assert!(!is_dpop_error(header4));
/// ```
pub fn is_dpop_error(value: &str) -> bool {
    // Check if the header starts with "DPoP"
    if !value.trim_start().starts_with("DPoP") {
        return false;
    }

    // Remove the "DPoP" scheme prefix and parse the parameters
    let params_part = value.trim_start().strip_prefix("DPoP").unwrap_or("").trim();

    // Split by commas and look for error field
    for part in params_part.split(',') {
        let trimmed = part.trim();

        // Look for error="value" pattern
        if let Some(equals_pos) = trimmed.find('=') {
            let (key, value_part) = trimmed.split_at(equals_pos);
            let key = key.trim();

            if key == "error" {
                // Extract the quoted value
                let value_part = &value_part[1..]; // Skip the '='
                let value_part = value_part.trim();

                // Remove surrounding quotes if present (handle malformed quotes too)
                let error_value = if let Some(stripped) = value_part.strip_prefix('"') {
                    if value_part.ends_with('"') && value_part.len() >= 2 {
                        &value_part[1..value_part.len() - 1]
                    } else {
                        stripped // Remove leading quote even if no closing quote
                    }
                } else if let Some(stripped) = value_part.strip_suffix('"') {
                    stripped // Remove trailing quote if no leading quote
                } else {
                    value_part
                };

                return error_value == "invalid_dpop_proof" || error_value == "use_dpop_nonce";
            }
        }
    }

    false
}

/// Creates a DPoP proof token for OAuth authorization requests.
///
/// Generates a JWT with the required DPoP claims for proving possession
/// of the private key during OAuth authorization flows.
///
/// # Arguments
/// * `key_data` - The cryptographic key data for signing the proof
/// * `http_method` - The HTTP method of the request (e.g., "POST")
/// * `http_uri` - The full URI of the authorization endpoint
///
/// # Returns
/// A tuple containing:
/// * The signed JWT token as a string
/// * The JWT header used for signing
/// * The JWT claims used in the token
///
/// # Errors
/// Returns an error if key conversion or token minting fails.
pub fn auth_dpop(
    key_data: &KeyData,
    http_method: &str,
    http_uri: &str,
) -> anyhow::Result<(String, Header, Claims)> {
    build_dpop(key_data, http_method, http_uri, None)
}

/// Creates a DPoP proof token for OAuth resource requests.
///
/// Generates a JWT with the required DPoP claims for proving possession
/// of the private key when making requests to protected resources using
/// an OAuth access token.
///
/// # Arguments
/// * `key_data` - The cryptographic key data for signing the proof
/// * `http_method` - The HTTP method of the request (e.g., "GET")
/// * `http_uri` - The full URI of the resource endpoint
/// * `oauth_access_token` - The OAuth access token being used
///
/// # Returns
/// A tuple containing:
/// * The signed JWT token as a string
/// * The JWT header used for signing
/// * The JWT claims used in the token
///
/// # Errors
/// Returns an error if key conversion or token minting fails.
pub fn request_dpop(
    key_data: &KeyData,
    http_method: &str,
    http_uri: &str,
    oauth_access_token: &str,
) -> anyhow::Result<(String, Header, Claims)> {
    build_dpop(key_data, http_method, http_uri, Some(oauth_access_token))
}

fn build_dpop(
    key_data: &KeyData,
    http_method: &str,
    http_uri: &str,
    access_token: Option<&str>,
) -> anyhow::Result<(String, Header, Claims)> {
    let now = chrono::Utc::now();

    let public_key_data = to_public(key_data)?;
    let dpop_jwk: JwkEcKey = (&public_key_data).try_into()?;

    let header = Header {
        type_: Some("dpop+jwt".to_string()),
        algorithm: Some("ES256".to_string()),
        json_web_key: Some(dpop_jwk),
        key_id: None,
    };

    let auth = access_token.map(challenge);
    let issued_at = Some(now.timestamp().cast_unsigned());
    let expiration = Some(
        (now + chrono::Duration::seconds(30))
            .timestamp()
            .cast_unsigned(),
    );

    let claims = Claims::new(JoseClaims {
        auth,
        expiration,
        http_method: Some(http_method.to_string()),
        http_uri: Some(http_uri.to_string()),
        issued_at,
        json_web_token_id: Some(Ulid::new().to_string()),
        ..Default::default()
    });

    let token = mint(key_data, &header, &claims)?;

    Ok((token, header, claims))
}

/// Extracts the JWK thumbprint from a DPoP JWT.
///
/// This function parses a DPoP JWT, extracts the JWK from the JWT header,
/// and computes the RFC 7638 thumbprint of that JWK. The thumbprint can
/// be used to uniquely identify the key used in the DPoP proof.
///
/// # Arguments
/// * `dpop_jwt` - The DPoP JWT token as a string
///
/// # Returns
/// * `Ok(String)` - The base64url-encoded SHA-256 thumbprint of the JWK
/// * `Err(anyhow::Error)` - If JWT parsing, JWK extraction, or thumbprint calculation fails
///
/// # Errors
/// This function will return an error if:
/// - The JWT format is invalid (not 3 parts separated by dots)
/// - The JWT header cannot be base64 decoded or parsed as JSON
/// - The header does not contain a "jwk" field
/// - The JWK cannot be converted to the required format
/// - Thumbprint calculation fails
///
/// # Examples
/// ```
/// use atproto_oauth::dpop::extract_jwk_thumbprint;
///
/// let dpop_jwt = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVpVeEFhZDJUbkRYTjFaZWprcFV4TWVvMW9mNzF6NGVackxLRFRtaEQzOEQ3Iiwia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJ4IjoiaG56dDlSSGppUDBvMFJJTEZacEdjX0phenJUb1pHUzF1d0d5R3JleUNNbyIsInkiOiJzaXJhU2FGU09md3FrYTZRdnR3aUJhM0FKUi14eEhQaWVWZkFhZEhQQ0JRIn0sInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiI2NDM0ZmFlNC00ZTYxLTQ1NDEtOTNlZC1kMzQ5ZjRiMTQ1NjEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9haXBkZXYudHVubi5kZXYvb2F1dGgvdG9rZW4iLCJpYXQiOjE3NDk3NjQ1MTl9.GkoB00Y-68djRHLhO5-PayNV8PWcQI1pwZaAUL3Hzppj-ga6SKMyGpPwY4kcGdHM7lvvisNkzvd7RjEmdDtnjQ";
/// let thumbprint = extract_jwk_thumbprint(dpop_jwt)?;
/// assert_eq!(thumbprint.len(), 43); // SHA-256 base64url is 43 characters
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn extract_jwk_thumbprint(dpop_jwt: &str) -> Result<String> {
    // Split the JWT into its three parts
    let parts: Vec<&str> = dpop_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JWTError::InvalidFormat.into());
    }

    let encoded_header = parts[0];

    // Decode the header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| JWTError::InvalidHeader)?;

    // Parse the header as JSON
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JWTError::InvalidHeader)?;

    // Extract the JWK from the header
    let jwk_value = header_json
        .get("jwk")
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "jwk".to_string(),
        })?;

    // Filter the JWK to only include core fields that JwkEcKey expects
    let jwk_object = jwk_value
        .as_object()
        .ok_or_else(|| JWKError::MissingField {
            field: "jwk object".to_string(),
        })?;

    // Extract only the core JWK fields that JwkEcKey supports
    let mut filtered_jwk = serde_json::Map::new();
    for field in ["kty", "crv", "x", "y", "d"] {
        if let Some(value) = jwk_object.get(field) {
            filtered_jwk.insert(field.to_string(), value.clone());
        }
    }

    // Convert the filtered JWK JSON to a JwkEcKey
    let jwk_ec_key: JwkEcKey = serde_json::from_value(serde_json::Value::Object(filtered_jwk))
        .map_err(|e| JWKError::SerializationError {
            message: e.to_string(),
        })?;

    // Create a WrappedJsonWebKey to use with the thumbprint function
    let wrapped_jwk = WrappedJsonWebKey {
        kid: None,  // We don't need the kid for thumbprint calculation
        alg: None,  // We don't need the alg for thumbprint calculation
        _use: None, // We don't need the use for thumbprint calculation
        jwk: jwk_ec_key,
    };

    // Calculate and return the thumbprint
    thumbprint(&wrapped_jwk).map_err(|e| e.into())
}

/// Configuration for DPoP JWT validation.
///
/// This struct allows callers to specify what aspects of the DPoP JWT should be validated.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone)]
pub struct DpopValidationConfig {
    /// Expected HTTP method (e.g., "POST", "GET"). If None, method validation is skipped.
    pub expected_http_method: Option<String>,
    /// Expected HTTP URI. If None, URI validation is skipped.
    pub expected_http_uri: Option<String>,
    /// Expected access token hash. If Some, the `ath` claim must match this value.
    pub expected_access_token_hash: Option<String>,
    /// Maximum age of the token in seconds. Default is 60 seconds.
    pub max_age_seconds: u64,
    /// Whether to allow tokens with future `iat` times (for clock skew tolerance).
    pub allow_future_iat: bool,
    /// Clock skew tolerance in seconds (default 30 seconds).
    pub clock_skew_tolerance_seconds: u64,
    /// Array of valid nonce values. If not empty, the `nonce` claim must be present and match one of these values.
    pub expected_nonce_values: Vec<String>,
    /// Current timestamp for validation purposes.
    pub now: i64,
}

impl Default for DpopValidationConfig {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            expected_http_method: None,
            expected_http_uri: None,
            expected_access_token_hash: None,
            max_age_seconds: 60,
            allow_future_iat: false,
            clock_skew_tolerance_seconds: 30,
            expected_nonce_values: Vec::new(),
            now,
        }
    }
}

impl DpopValidationConfig {
    /// Create a new validation config for authorization requests (no access token hash required).
    pub fn for_authorization(http_method: &str, http_uri: &str) -> Self {
        Self {
            expected_http_method: Some(http_method.to_string()),
            expected_http_uri: Some(http_uri.to_string()),
            expected_access_token_hash: None,
            ..Default::default()
        }
    }

    /// Create a new validation config for resource requests (access token hash required).
    pub fn for_resource_request(http_method: &str, http_uri: &str, access_token: &str) -> Self {
        Self {
            expected_http_method: Some(http_method.to_string()),
            expected_http_uri: Some(http_uri.to_string()),
            expected_access_token_hash: Some(challenge(access_token)),
            ..Default::default()
        }
    }
}

/// Validates a DPoP JWT and returns the JWK thumbprint if validation succeeds.
///
/// This function performs comprehensive validation of a DPoP JWT including:
/// - JWT structure and format validation
/// - Header validation (typ, alg, jwk fields)
/// - Claims validation (jti, htm, htu, iat, and optionally ath and nonce)
/// - Cryptographic signature verification using the embedded JWK
/// - Timestamp validation with configurable tolerances
/// - Nonce validation against expected values (if configured)
///
/// # Arguments
/// * `dpop_jwt` - The DPoP JWT token as a string
/// * `config` - Validation configuration specifying what to validate
///
/// # Returns
/// * `Ok(String)` - The base64url-encoded SHA-256 thumbprint of the validated JWK
/// * `Err(anyhow::Error)` - If any validation step fails
///
/// # Errors
/// This function will return an error if:
/// - The JWT format is invalid
/// - Required header fields are missing or invalid
/// - Required claims are missing or invalid
/// - The signature verification fails
/// - Timestamp validation fails
/// - HTTP method or URI don't match expected values
///
/// # Examples
/// ```no_run
/// use atproto_oauth::dpop::{validate_dpop_jwt, DpopValidationConfig};
///
/// let dpop_jwt = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVpVeEFhZDJUbkRYTjFaZWprcFV4TWVvMW9mNzF6NGVackxLRFRtaEQzOEQ3Iiwia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJ4IjoiaG56dDlSSGppUDBvMFJJTEZacEdjX0phenJUb1pHUzF1d0d5R3JleUNNbyIsInkiOiJzaXJhU2FGU09md3FrYTZRdnR3aUJhM0FKUi14eEhQaWVWZkFhZEhQQ0JRIn0sInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiI2NDM0ZmFlNC00ZTYxLTQ1NDEtOTNlZC1kMzQ5ZjRiMTQ1NjEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9haXBkZXYudHVubi5kZXYvb2F1dGgvdG9rZW4iLCJpYXQiOjE3NDk3NjQ1MTl9.GkoB00Y-68djRHLhO5-PayNV8PWcQI1pwZaAUL3Hzppj-ga6SKMyGpPwY4kcGdHM7lvvisNkzvd7RjEmdDtnjQ";
/// let mut config = DpopValidationConfig::for_authorization("POST", "https://aipdev.tunn.dev/oauth/token");
/// config.max_age_seconds = 9000000;
/// let thumbprint = validate_dpop_jwt(dpop_jwt, &config)?;
/// assert_eq!(thumbprint.len(), 43); // SHA-256 base64url is 43 characters
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_dpop_jwt(dpop_jwt: &str, config: &DpopValidationConfig) -> Result<String> {
    // Split the JWT into its three parts
    let parts: Vec<&str> = dpop_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JWTError::InvalidFormat.into());
    }

    let (encoded_header, encoded_payload, encoded_signature) = (parts[0], parts[1], parts[2]);

    // 1. DECODE AND VALIDATE HEADER
    let header_bytes = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| JWTError::InvalidHeader)?;

    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| JWTError::InvalidHeader)?;

    // Validate typ field
    let typ = header_json
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "typ".to_string(),
        })?;

    if typ != "dpop+jwt" {
        return Err(JWTError::InvalidTokenType {
            expected: "dpop+jwt".to_string(),
            actual: typ.to_string(),
        }
        .into());
    }

    // Validate alg field
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "alg".to_string(),
        })?;

    if !matches!(alg, "ES256" | "ES384" | "ES256K") {
        return Err(JWTError::UnsupportedAlgorithm {
            algorithm: alg.to_string(),
            key_type: "EC".to_string(),
        }
        .into());
    }

    // Extract and validate JWK
    let jwk_value = header_json
        .get("jwk")
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "jwk".to_string(),
        })?;

    let jwk_object = jwk_value
        .as_object()
        .ok_or_else(|| JWKError::MissingField {
            field: "jwk object".to_string(),
        })?;

    // Filter the JWK to only include core fields that JwkEcKey expects
    let mut filtered_jwk = serde_json::Map::new();
    for field in ["kty", "crv", "x", "y", "d"] {
        if let Some(value) = jwk_object.get(field) {
            filtered_jwk.insert(field.to_string(), value.clone());
        }
    }

    let jwk_ec_key: JwkEcKey = serde_json::from_value(serde_json::Value::Object(filtered_jwk))
        .map_err(|e| JWKError::SerializationError {
            message: e.to_string(),
        })?;

    // Create WrappedJsonWebKey for further operations
    let wrapped_jwk = WrappedJsonWebKey {
        kid: None,
        alg: Some(alg.to_string()),
        _use: Some("sig".to_string()),
        jwk: jwk_ec_key,
    };

    // Convert JWK to KeyData for signature verification
    let key_data = to_key_data(&wrapped_jwk)?;

    // 2. DECODE AND VALIDATE PAYLOAD/CLAIMS
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| JWTError::InvalidPayload)?;

    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| JWTError::InvalidPayloadJson)?;

    // Validate required claims
    // jti (JWT ID) - required for replay protection
    claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "jti".to_string(),
        })?;

    if let Some(expected_method) = &config.expected_http_method {
        // htm (HTTP method) - validate if expected method is specified
        let htm =
            claims
                .get("htm")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JWTError::MissingClaim {
                    claim: "htm".to_string(),
                })?;

        if htm != expected_method {
            return Err(JWTError::HttpMethodMismatch {
                expected: expected_method.clone(),
                actual: htm.to_string(),
            }
            .into());
        }
    }

    if let Some(expected_uri) = &config.expected_http_uri {
        // htu (HTTP URI) - validate if expected URI is specified
        let htu =
            claims
                .get("htu")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JWTError::MissingClaim {
                    claim: "htu".to_string(),
                })?;

        if htu != expected_uri {
            return Err(JWTError::HttpUriMismatch {
                expected: expected_uri.clone(),
                actual: htu.to_string(),
            }
            .into());
        }
    }

    // iat (issued at) - validate timestamp
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| JWTError::MissingClaim {
            claim: "iat".to_string(),
        })?;

    // Check if token is too old
    if config.now.cast_unsigned()
        > iat + config.max_age_seconds + config.clock_skew_tolerance_seconds
    {
        return Err(JWTError::InvalidTimestamp {
            reason: format!(
                "Token too old: issued at {} but max age is {} seconds",
                iat, config.max_age_seconds
            ),
        }
        .into());
    }

    // Check if token is from the future (unless allowed)
    if !config.allow_future_iat
        && iat > config.now.cast_unsigned() + config.clock_skew_tolerance_seconds
    {
        return Err(JWTError::InvalidTimestamp {
            reason: format!(
                "Token from future: issued at {} but current time is {}",
                iat, config.now
            ),
        }
        .into());
    }

    // ath (access token hash) - validate if required
    if let Some(expected_ath) = &config.expected_access_token_hash {
        let ath =
            claims
                .get("ath")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JWTError::MissingClaim {
                    claim: "ath".to_string(),
                })?;

        if ath != expected_ath {
            return Err(JWTError::AccessTokenHashMismatch.into());
        }
    }

    // nonce - validate if required
    if !config.expected_nonce_values.is_empty() {
        let nonce = claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JWTError::MissingClaim {
                claim: "nonce".to_string(),
            })?;

        if !config.expected_nonce_values.contains(&nonce.to_string()) {
            return Err(JWTError::InvalidNonce {
                nonce: nonce.to_string(),
            }
            .into());
        }
    }

    // exp (expiration) - validate if present
    if let Some(exp_value) = claims.get("exp")
        && let Some(exp) = exp_value.as_u64()
        && config.now.cast_unsigned() >= exp
    {
        return Err(JWTError::TokenExpired.into());
    }

    // 3. VERIFY SIGNATURE
    let content = format!("{}.{}", encoded_header, encoded_payload);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| JWTError::InvalidSignature)?;

    validate(&key_data, &signature_bytes, content.as_bytes())
        .map_err(|_| JWTError::SignatureVerificationFailed)?;

    // 4. CALCULATE AND RETURN JWK THUMBPRINT
    thumbprint(&wrapped_jwk).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_dpop_error_invalid_dpop_proof() {
        let header = r#"DPoP algs="RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES256K ES384 ES512", error="invalid_dpop_proof", error_description="DPoP proof required""#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_use_dpop_nonce() {
        let header = r#"DPoP algs="RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES256K ES384 ES512", error="use_dpop_nonce", error_description="Authorization server requires nonce in DPoP proof""#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_other_error() {
        let header =
            r#"DPoP algs="ES256", error="invalid_token", error_description="Token is invalid""#;
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_no_error_field() {
        let header = r#"DPoP algs="ES256", error_description="Some description""#;
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_not_dpop_header() {
        let header = r#"Bearer error="invalid_token""#;
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_empty_string() {
        assert!(!is_dpop_error(""));
    }

    #[test]
    fn test_is_dpop_error_minimal_valid() {
        let header = r#"DPoP error="invalid_dpop_proof""#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_unquoted_value() {
        let header = r#"DPoP error=invalid_dpop_proof"#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_whitespace_handling() {
        let header =
            r#"  DPoP  algs="ES256"  ,  error="use_dpop_nonce"  ,  error_description="test"  "#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_case_sensitive_scheme() {
        let header = r#"dpop error="invalid_dpop_proof""#;
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_case_sensitive_error_value() {
        let header = r#"DPoP error="INVALID_DPOP_PROOF""#;
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_malformed_quotes() {
        let header = r#"DPoP error="invalid_dpop_proof"#;
        assert!(is_dpop_error(header));
    }

    #[test]
    fn test_is_dpop_error_multiple_error_fields() {
        let header = r#"DPoP error="invalid_token", algs="ES256", error="invalid_dpop_proof""#;
        // Should match the first error field found
        assert!(!is_dpop_error(header));
    }

    #[test]
    fn test_extract_jwk_thumbprint_with_known_jwt() -> anyhow::Result<()> {
        // Test with the provided DPoP JWT
        let dpop_jwt = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVpVeEFhZDJUbkRYTjFaZWprcFV4TWVvMW9mNzF6NGVackxLRFRtaEQzOEQ3Iiwia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJ4IjoiaG56dDlSSGppUDBvMFJJTEZacEdjX0phenJUb1pHUzF1d0d5R3JleUNNbyIsInkiOiJzaXJhU2FGU09md3FrYTZRdnR3aUJhM0FKUi14eEhQaWVWZkFhZEhQQ0JRIn0sInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiI2NDM0ZmFlNC00ZTYxLTQ1NDEtOTNlZC1kMzQ5ZjRiMTQ1NjEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9haXBkZXYudHVubi5kZXYvb2F1dGgvdG9rZW4iLCJpYXQiOjE3NDk3NjQ1MTl9.GkoB00Y-68djRHLhO5-PayNV8PWcQI1pwZaAUL3Hzppj-ga6SKMyGpPwY4kcGdHM7lvvisNkzvd7RjEmdDtnjQ";

        let thumbprint = extract_jwk_thumbprint(dpop_jwt)?;

        // Verify the thumbprint is a valid base64url string
        assert_eq!(thumbprint.len(), 43); // SHA-256 base64url encoded is 43 characters
        assert!(!thumbprint.contains('=')); // No padding in base64url
        assert!(!thumbprint.contains('+')); // No + in base64url
        assert!(!thumbprint.contains('/')); // No / in base64url

        // Verify that the thumbprint is deterministic (same result every time)
        let thumbprint2 = extract_jwk_thumbprint(dpop_jwt)?;
        assert_eq!(thumbprint, thumbprint2);

        assert_eq!(thumbprint, "lkqoPsebYpatLxSM4WCfAvOHqxU7X5RKlg-0_cobwSU");

        Ok(())
    }

    #[test]
    fn test_extract_jwk_thumbprint_invalid_jwt_format() {
        // Test with invalid JWT format (not 3 parts)
        let invalid_jwt = "invalid.jwt";
        let result = extract_jwk_thumbprint(invalid_jwt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 3 parts"));
    }

    #[test]
    fn test_extract_jwk_thumbprint_invalid_header() {
        // Test with invalid base64 in header
        let invalid_jwt = "invalid-base64.eyJqdGkiOiJ0ZXN0In0.signature";
        let result = extract_jwk_thumbprint(invalid_jwt);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid JWT header")
        );
    }

    #[test]
    fn test_extract_jwk_thumbprint_missing_jwk() -> anyhow::Result<()> {
        // Create a valid JWT header without a JWK field
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "dpop+jwt"
        });
        let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&header)?.as_bytes());

        let jwt_without_jwk = format!("{}.eyJqdGkiOiJ0ZXN0In0.signature", encoded_header);
        let result = extract_jwk_thumbprint(&jwt_without_jwk);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: jwk")
        );

        Ok(())
    }

    #[test]
    fn test_extract_jwk_thumbprint_with_generated_dpop() -> anyhow::Result<()> {
        // Test with a DPoP JWT generated by our own functions
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        let thumbprint = extract_jwk_thumbprint(&dpop_token)?;

        // Verify the thumbprint properties
        assert_eq!(thumbprint.len(), 43);
        assert!(!thumbprint.contains('='));
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));

        // Verify deterministic behavior
        let thumbprint2 = extract_jwk_thumbprint(&dpop_token)?;
        assert_eq!(thumbprint, thumbprint2);

        Ok(())
    }

    #[test]
    fn test_extract_jwk_thumbprint_different_keys_different_thumbprints() -> anyhow::Result<()> {
        // Test that different keys produce different thumbprints
        use atproto_identity::key::{KeyType, generate_key};

        let key1 = generate_key(KeyType::P256Private)?;
        let key2 = generate_key(KeyType::P256Private)?;

        let (dpop_token1, _, _) = auth_dpop(&key1, "POST", "https://example.com/token")?;
        let (dpop_token2, _, _) = auth_dpop(&key2, "POST", "https://example.com/token")?;

        let thumbprint1 = extract_jwk_thumbprint(&dpop_token1)?;
        let thumbprint2 = extract_jwk_thumbprint(&dpop_token2)?;

        assert_ne!(thumbprint1, thumbprint2);

        Ok(())
    }

    // === DPOP VALIDATION TESTS ===

    #[test]
    fn test_validate_dpop_jwt_with_known_jwt() -> anyhow::Result<()> {
        // Test with the provided DPoP JWT - but this will fail timestamp validation
        // since the iat is from 2024. We'll use a permissive config.
        let dpop_jwt = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiZGlkOmtleTp6RG5hZVpVeEFhZDJUbkRYTjFaZWprcFV4TWVvMW9mNzF6NGVackxLRFRtaEQzOEQ3Iiwia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJ4IjoiaG56dDlSSGppUDBvMFJJTEZacEdjX0phenJUb1pHUzF1d0d5R3JleUNNbyIsInkiOiJzaXJhU2FGU09md3FrYTZRdnR3aUJhM0FKUi14eEhQaWVWZkFhZEhQQ0JRIn0sInR5cCI6ImRwb3Arand0In0.eyJqdGkiOiI2NDM0ZmFlNC00ZTYxLTQ1NDEtOTNlZC1kMzQ5ZjRiMTQ1NjEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9haXBkZXYudHVubi5kZXYvb2F1dGgvdG9rZW4iLCJpYXQiOjE3NDk3NjQ1MTl9.GkoB00Y-68djRHLhO5-PayNV8PWcQI1pwZaAUL3Hzppj-ga6SKMyGpPwY4kcGdHM7lvvisNkzvd7RjEmdDtnjQ";

        // Use a very permissive config to account for old timestamp
        let config = DpopValidationConfig {
            expected_http_method: Some("POST".to_string()),
            expected_http_uri: Some("https://aipdev.tunn.dev/oauth/token".to_string()),
            expected_access_token_hash: None,
            max_age_seconds: 365 * 24 * 60 * 60, // 1 year
            allow_future_iat: true,
            clock_skew_tolerance_seconds: 365 * 24 * 60 * 60, // 1 year
            expected_nonce_values: Vec::new(),
            now: 1,
        };

        let thumbprint = validate_dpop_jwt(dpop_jwt, &config)?;

        // Verify the thumbprint matches what we expect
        assert_eq!(thumbprint, "lkqoPsebYpatLxSM4WCfAvOHqxU7X5RKlg-0_cobwSU");
        assert_eq!(thumbprint.len(), 43);

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_with_generated_jwt() -> anyhow::Result<()> {
        // Test with a freshly generated DPoP JWT
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        let config = DpopValidationConfig::for_authorization("POST", "https://example.com/token");
        let thumbprint = validate_dpop_jwt(&dpop_token, &config)?;

        // Verify the thumbprint properties
        assert_eq!(thumbprint.len(), 43);
        assert!(!thumbprint.contains('='));
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_invalid_format() {
        let config = DpopValidationConfig::default();

        // Test invalid JWT format
        let result = validate_dpop_jwt("invalid.jwt", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 3 parts"));
    }

    #[test]
    fn test_validate_dpop_jwt_invalid_typ() -> anyhow::Result<()> {
        // Create a JWT with wrong typ field
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT", // Wrong type, should be "dpop+jwt"
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "test",
                "y": "test"
            }
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let jwt = format!("{}.eyJqdGkiOiJ0ZXN0In0.signature", encoded_header);

        let config = DpopValidationConfig::default();
        let result = validate_dpop_jwt(&jwt, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid token type")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_unsupported_algorithm() -> anyhow::Result<()> {
        // Create a JWT with unsupported algorithm
        let header = serde_json::json!({
            "alg": "HS256", // Unsupported algorithm
            "typ": "dpop+jwt",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "test",
                "y": "test"
            }
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let jwt = format!("{}.eyJqdGkiOiJ0ZXN0In0.signature", encoded_header);

        let config = DpopValidationConfig::default();
        let result = validate_dpop_jwt(&jwt, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported JWT algorithm")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_missing_jwk() -> anyhow::Result<()> {
        // Create a JWT without JWK field
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "dpop+jwt"
            // Missing jwk field
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let jwt = format!("{}.eyJqdGkiOiJ0ZXN0In0.signature", encoded_header);

        let config = DpopValidationConfig::default();
        let result = validate_dpop_jwt(&jwt, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: jwk")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_missing_claims() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Modify the token to remove jti claim
        let parts: Vec<&str> = dpop_token.split('.').collect();
        let payload = serde_json::json!({
            // Missing jti
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": chrono::Utc::now().timestamp()
        });
        let encoded_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());
        let modified_jwt = format!("{}.{}.{}", parts[0], encoded_payload, parts[2]);

        let config = DpopValidationConfig::default();
        let result = validate_dpop_jwt(&modified_jwt, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: jti")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_http_method_mismatch() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Config expects GET but token has POST
        let config = DpopValidationConfig::for_authorization("GET", "https://example.com/token");
        let result = validate_dpop_jwt(&dpop_token, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HTTP method mismatch")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_http_uri_mismatch() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Config expects different URI
        let config = DpopValidationConfig::for_authorization("POST", "https://different.com/token");
        let result = validate_dpop_jwt(&dpop_token, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("HTTP URI mismatch")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_require_access_token_hash() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Config requires ath but auth_dpop doesn't include it
        let config = DpopValidationConfig::for_resource_request(
            "POST",
            "https://example.com/token",
            "access_token",
        );
        let result = validate_dpop_jwt(&dpop_token, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: ath")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_with_resource_request() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let access_token = "test_access_token";
        let (dpop_token, _, _) = request_dpop(
            &key_data,
            "GET",
            "https://example.com/resource",
            access_token,
        )?;

        // Config for resource request (requires ath)
        let config = DpopValidationConfig::for_resource_request(
            "GET",
            "https://example.com/resource",
            access_token,
        );
        let thumbprint = validate_dpop_jwt(&dpop_token, &config)?;

        assert_eq!(thumbprint.len(), 43);

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_timestamp_validation() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;

        // Create a token with old timestamp
        let old_time = chrono::Utc::now().timestamp().cast_unsigned() - 3600; // 1 hour ago

        let public_key_data = to_public(&key_data)?;
        let dpop_jwk: JwkEcKey = (&public_key_data).try_into()?;

        let header = Header {
            type_: Some("dpop+jwt".to_string()),
            algorithm: Some("ES256".to_string()),
            json_web_key: Some(dpop_jwk),
            key_id: None,
        };

        let claims = Claims::new(JoseClaims {
            json_web_token_id: Some(Ulid::new().to_string()),
            http_method: Some("POST".to_string()),
            http_uri: Some("https://example.com/token".to_string()),
            issued_at: Some(old_time),
            ..Default::default()
        });

        let old_token = mint(&key_data, &header, &claims)?;

        // Use strict config with short max_age
        let config = DpopValidationConfig {
            expected_http_method: Some("POST".to_string()),
            expected_http_uri: Some("https://example.com/token".to_string()),
            max_age_seconds: 60, // 1 minute
            ..Default::default()
        };

        let result = validate_dpop_jwt(&old_token, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Token too old"));

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_different_keys_different_thumbprints() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key1 = generate_key(KeyType::P256Private)?;
        let key2 = generate_key(KeyType::P256Private)?;

        let (dpop_token1, _, _) = auth_dpop(&key1, "POST", "https://example.com/token")?;
        let (dpop_token2, _, _) = auth_dpop(&key2, "POST", "https://example.com/token")?;

        let config = DpopValidationConfig::for_authorization("POST", "https://example.com/token");

        let thumbprint1 = validate_dpop_jwt(&dpop_token1, &config)?;
        let thumbprint2 = validate_dpop_jwt(&dpop_token2, &config)?;

        assert_ne!(thumbprint1, thumbprint2);

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_config_for_authorization() {
        let config = DpopValidationConfig::for_authorization("POST", "https://example.com/auth");

        assert_eq!(config.expected_http_method, Some("POST".to_string()));
        assert_eq!(
            config.expected_http_uri,
            Some("https://example.com/auth".to_string())
        );
        assert_eq!(config.max_age_seconds, 60);
        assert!(!config.allow_future_iat);
        assert_eq!(config.clock_skew_tolerance_seconds, 30);
    }

    #[test]
    fn test_validate_dpop_jwt_config_for_resource_request() {
        let config = DpopValidationConfig::for_resource_request(
            "GET",
            "https://example.com/resource",
            "access_token",
        );

        assert_eq!(config.expected_http_method, Some("GET".to_string()));
        assert_eq!(
            config.expected_http_uri,
            Some("https://example.com/resource".to_string())
        );
        assert_eq!(config.max_age_seconds, 60);
        assert!(!config.allow_future_iat);
        assert_eq!(config.clock_skew_tolerance_seconds, 30);
    }

    #[test]
    fn test_validate_dpop_jwt_permissive_config() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        let now = chrono::Utc::now().timestamp();

        // Very permissive config - doesn't validate method/URI
        let config = DpopValidationConfig {
            expected_http_method: None,
            expected_http_uri: None,
            expected_access_token_hash: None,
            max_age_seconds: 3600,
            allow_future_iat: true,
            clock_skew_tolerance_seconds: 300,
            expected_nonce_values: Vec::new(),
            now,
        };

        let thumbprint = validate_dpop_jwt(&dpop_token, &config)?;
        assert_eq!(thumbprint.len(), 43);

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_nonce_validation_success() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;

        // Create a DPoP token with a nonce by manually building it
        let (_, header, mut claims) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Add nonce to claims
        let test_nonce = "test_nonce_12345";
        claims
            .private
            .insert("nonce".to_string(), test_nonce.into());

        // Create the token with nonce
        let dpop_token = mint(&key_data, &header, &claims)?;

        // Create config with expected nonce values
        let mut config =
            DpopValidationConfig::for_authorization("POST", "https://example.com/token");
        config.expected_nonce_values = vec![test_nonce.to_string(), "other_nonce".to_string()];

        let thumbprint = validate_dpop_jwt(&dpop_token, &config)?;
        assert_eq!(thumbprint.len(), 43);

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_nonce_validation_failure() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;

        // Create a DPoP token with a specific nonce
        let (_, header, mut claims) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Add a nonce that won't match the expected values
        let token_nonce = "token_nonce_that_wont_match";
        claims
            .private
            .insert("nonce".to_string(), token_nonce.into());

        // Create the token with nonce
        let dpop_token = mint(&key_data, &header, &claims)?;

        // Create config with different nonce values (not matching the token)
        let mut config =
            DpopValidationConfig::for_authorization("POST", "https://example.com/token");
        config.expected_nonce_values = vec![
            "expected_nonce_1".to_string(),
            "expected_nonce_2".to_string(),
        ];

        let result = validate_dpop_jwt(&dpop_token, &config);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid nonce"));

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_nonce_missing_when_required() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Modify the token to remove the nonce claim
        let parts: Vec<&str> = dpop_token.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

        // Remove the nonce field
        payload.as_object_mut().unwrap().remove("nonce");

        let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());
        let modified_jwt = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);

        // Create config that requires nonce validation
        let mut config =
            DpopValidationConfig::for_authorization("POST", "https://example.com/token");
        config.expected_nonce_values = vec!["required_nonce".to_string()];

        let result = validate_dpop_jwt(&modified_jwt, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing required claim: nonce")
        );

        Ok(())
    }

    #[test]
    fn test_validate_dpop_jwt_nonce_empty_array_skips_validation() -> anyhow::Result<()> {
        use atproto_identity::key::{KeyType, generate_key};

        let key_data = generate_key(KeyType::P256Private)?;
        let (dpop_token, _, _) = auth_dpop(&key_data, "POST", "https://example.com/token")?;

        // Create config with empty nonce values (should skip nonce validation)
        let config = DpopValidationConfig::for_authorization("POST", "https://example.com/token");
        assert!(config.expected_nonce_values.is_empty());

        let thumbprint = validate_dpop_jwt(&dpop_token, &config)?;
        assert_eq!(thumbprint.len(), 43);

        Ok(())
    }
}
