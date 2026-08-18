//! # Structured Error Types for OAuth Operations
//!
//! Comprehensive error handling for AT Protocol OAuth operations using structured error types
//! with the `thiserror` library. All errors follow the project convention of prefixed error codes
//! with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`JWTError`** (jwt-1 to jwt-18): JSON Web Token validation, parsing, and verification errors
//! - **`JWKError`** (jwk-1 to jwk-7): JSON Web Key conversion, processing, and thumbprint errors
//! - **`OAuthClientError`** (client-1 to client-17): OAuth client operations and server communication errors
//! - **`ResourceValidationError`** (resource-1 to resource-2): OAuth protected resource configuration validation errors
//! - **`AuthServerValidationError`** (auth-server-1 to auth-server-12): OAuth authorization server configuration validation errors
//! - **`DpopError`** (dpop-1 to dpop-6): DPoP (Demonstration of Proof-of-Possession) operation errors
//! - **`OAuthStorageError`** (storage-1 to storage-4): OAuth request storage operations including cache lock failures and data access errors
//!
//! ## Error Format
//!
//! All errors use the standardized format: `error-atproto-oauth-{domain}-{number} {message}: {details}`

use thiserror::Error;

/// Error types that can occur when working with JSON Web Tokens
#[derive(Debug, Error)]
pub enum JWTError {
    /// Occurs when JWT does not have the expected 3-part format (header.payload.signature)
    #[error("error-atproto-oauth-jwt-1 Invalid JWT format: expected 3 parts separated by dots")]
    InvalidFormat,

    /// Occurs when JWT header cannot be base64 decoded or parsed as JSON
    #[error("error-atproto-oauth-jwt-2 Invalid JWT header: failed to decode or parse")]
    InvalidHeader,

    /// Occurs when JWT algorithm does not match the provided key type
    #[error(
        "error-atproto-oauth-jwt-3 Unsupported JWT algorithm: algorithm {algorithm} incompatible with key type {key_type}"
    )]
    UnsupportedAlgorithm {
        /// The algorithm specified in the JWT header
        algorithm: String,
        /// The type of key provided for verification
        key_type: String,
    },

    /// Occurs when JWT claims cannot be base64 decoded or parsed as JSON
    #[error("error-atproto-oauth-jwt-4 Invalid JWT claims: failed to decode or parse")]
    InvalidClaims,

    /// Occurs when JWT signature cannot be base64 decoded
    #[error("error-atproto-oauth-jwt-5 Invalid JWT signature: failed to decode signature")]
    InvalidSignature,

    /// Occurs when system time cannot be obtained for timestamp validation
    #[error("error-atproto-oauth-jwt-6 System time error: unable to get current timestamp")]
    SystemTimeError,

    /// Occurs when JWT has passed its expiration time
    #[error("error-atproto-oauth-jwt-7 JWT expired: token is past expiration time")]
    TokenExpired,

    /// Occurs when JWT is used before its not-before time
    #[error("error-atproto-oauth-jwt-8 JWT not valid yet: token is before not-before time")]
    TokenNotValidYet,

    /// Occurs when signature verification fails
    #[error("error-atproto-oauth-jwt-9 Signature verification failed: invalid signature")]
    SignatureVerificationFailed,

    /// Occurs when JWT payload cannot be base64 decoded
    #[error("error-atproto-oauth-jwt-10 Invalid JWT payload: failed to decode payload")]
    InvalidPayload,

    /// Occurs when JWT payload cannot be parsed as JSON
    #[error("error-atproto-oauth-jwt-11 Invalid JWT payload JSON: failed to parse payload as JSON")]
    InvalidPayloadJson,

    /// Occurs when a required JWT claim is missing
    #[error("error-atproto-oauth-jwt-12 Missing required claim: {claim}")]
    MissingClaim {
        /// The name of the missing claim
        claim: String,
    },

    /// Occurs when JWT type field has wrong value
    #[error("error-atproto-oauth-jwt-13 Invalid token type: expected '{expected}', got '{actual}'")]
    InvalidTokenType {
        /// The expected token type
        expected: String,
        /// The actual token type found
        actual: String,
    },

    /// Occurs when HTTP method in JWT doesn't match expected value
    #[error(
        "error-atproto-oauth-jwt-14 HTTP method mismatch: expected '{expected}', got '{actual}'"
    )]
    HttpMethodMismatch {
        /// The expected HTTP method
        expected: String,
        /// The actual HTTP method in the JWT
        actual: String,
    },

    /// Occurs when HTTP URI in JWT doesn't match expected value
    #[error("error-atproto-oauth-jwt-15 HTTP URI mismatch: expected '{expected}', got '{actual}'")]
    HttpUriMismatch {
        /// The expected HTTP URI
        expected: String,
        /// The actual HTTP URI in the JWT
        actual: String,
    },

    /// Occurs when access token hash validation fails
    #[error("error-atproto-oauth-jwt-16 Access token hash mismatch: invalid 'ath' claim")]
    AccessTokenHashMismatch,

    /// Occurs when nonce value is not in the expected values list
    #[error("error-atproto-oauth-jwt-17 Invalid nonce: value '{nonce}' not in expected values")]
    InvalidNonce {
        /// The nonce value that was not found in expected values
        nonce: String,
    },

    /// Occurs when JWT has invalid timestamp claim
    #[error("error-atproto-oauth-jwt-18 Invalid timestamp: {reason}")]
    InvalidTimestamp {
        /// The reason for the timestamp validation failure
        reason: String,
    },
}

/// Error types that can occur when working with JSON Web Keys
#[derive(Debug, Error)]
pub enum JWKError {
    /// Occurs when P-256 JWK conversion to KeyData fails
    #[error("error-atproto-oauth-jwk-1 P-256 JWK conversion failed: unable to convert to KeyData")]
    P256ConversionFailed,

    /// Occurs when P-384 JWK conversion to KeyData fails
    #[error("error-atproto-oauth-jwk-2 P-384 JWK conversion failed: unable to convert to KeyData")]
    P384ConversionFailed,

    /// Occurs when K-256 JWK conversion to KeyData fails
    #[error("error-atproto-oauth-jwk-3 K-256 JWK conversion failed: unable to convert to KeyData")]
    K256ConversionFailed,

    /// Occurs when an unsupported elliptic curve is encountered
    #[error("error-atproto-oauth-jwk-4 Unsupported curve: {curve}")]
    UnsupportedCurve {
        /// The unsupported curve name
        curve: String,
    },

    /// Occurs when an unsupported key type is encountered
    #[error("error-atproto-oauth-jwk-5 Unsupported key type: {kty}")]
    UnsupportedKeyType {
        /// The unsupported key type
        kty: String,
    },

    /// Occurs when a required field is missing from the JWK
    #[error("error-atproto-oauth-jwk-6 Missing required field: {field}")]
    MissingField {
        /// The missing field name
        field: String,
    },

    /// Occurs when JWK serialization fails
    #[error("error-atproto-oauth-jwk-7 JWK serialization failed: {message}")]
    SerializationError {
        /// The serialization error message
        message: String,
    },
}

/// Represents errors that can occur during OAuth client operations.
///
/// These errors are related to the OAuth client functionality, including
/// interacting with authorization servers, protected resources, and token management.
#[derive(Debug, Error)]
pub enum OAuthClientError {
    /// Error when a request to the authorization server fails.
    ///
    /// This error occurs when the OAuth client fails to establish a connection
    /// or complete a request to the authorization server.
    #[error("error-atproto-oauth-client-1 Authorization Server Request Failed: {0:?}")]
    AuthorizationServerRequestFailed(reqwest::Error),

    /// Error when the authorization server response is malformed.
    ///
    /// This error occurs when the response from the authorization server
    /// cannot be properly parsed or processed.
    #[error("error-atproto-oauth-client-2 Malformed Authorization Server Response: {0:?}")]
    MalformedAuthorizationServerResponse(reqwest::Error),

    /// Error when the authorization server response is invalid.
    ///
    /// This error occurs when the response from the authorization server
    /// is well-formed but contains invalid or unexpected data.
    #[error("error-atproto-oauth-client-3 Invalid Authorization Server Response: {0:?}")]
    InvalidAuthorizationServerResponse(anyhow::Error),

    /// Error when an OAuth protected resource is invalid.
    ///
    /// This error occurs when trying to access a protected resource that
    /// is not properly configured for OAuth access.
    #[error("error-atproto-oauth-client-4 Invalid OAuth Protected Resource")]
    InvalidOAuthProtectedResource,

    /// Error when a request to an OAuth protected resource fails.
    ///
    /// This error occurs when the OAuth client fails to establish a connection
    /// or complete a request to a protected resource.
    #[error("error-atproto-oauth-client-5 OAuth Protected Resource Request Failed: {0:?}")]
    OAuthProtectedResourceRequestFailed(reqwest::Error),

    /// Error when a protected resource response is malformed.
    ///
    /// This error occurs when the response from a protected resource
    /// cannot be properly parsed or processed.
    #[error("error-atproto-oauth-client-6 Malformed OAuth Protected Resource Response: {0:?}")]
    MalformedOAuthProtectedResourceResponse(reqwest::Error),

    /// Error when a protected resource response is invalid.
    ///
    /// This error occurs when the response from a protected resource
    /// is well-formed but contains invalid or unexpected data.
    #[error("error-atproto-oauth-client-7 Invalid OAuth Protected Resource Response: {0:?}")]
    InvalidOAuthProtectedResourceResponse(anyhow::Error),

    /// Error when token minting fails.
    ///
    /// This error occurs when the system fails to mint (create) a new
    /// OAuth token, typically due to cryptographic or validation issues.
    #[error("error-atproto-oauth-client-8 Token minting failed: {0:?}")]
    MintTokenFailed(anyhow::Error),

    /// Error when JWT header creation from key data fails.
    ///
    /// This error occurs when attempting to create a JWT header from
    /// cryptographic key data during OAuth workflow operations.
    #[error("error-atproto-oauth-client-9 JWT header creation from key failed: {0:?}")]
    JWTHeaderCreationFailed(anyhow::Error),

    /// Error when DPoP token creation fails.
    ///
    /// This error occurs when attempting to create a DPoP proof token
    /// during OAuth workflow operations.
    #[error("error-atproto-oauth-client-10 DPoP token creation failed: {0:?}")]
    DpopTokenCreationFailed(anyhow::Error),

    /// Error when PAR (Pushed Authorization Request) HTTP request fails.
    ///
    /// This error occurs when the HTTP request to the pushed authorization
    /// request endpoint fails during OAuth workflow operations.
    #[error("error-atproto-oauth-client-11 PAR HTTP request failed: {0:?}")]
    PARHttpRequestFailed(reqwest_middleware::Error),

    /// Error when PAR response JSON parsing fails.
    ///
    /// This error occurs when the response from the pushed authorization
    /// request endpoint cannot be parsed as JSON.
    #[error("error-atproto-oauth-client-12 PAR response JSON parsing failed: {0:?}")]
    PARResponseJsonParsingFailed(reqwest::Error),

    /// Error when token endpoint HTTP request fails.
    ///
    /// This error occurs when the HTTP request to the token endpoint
    /// fails during OAuth token exchange operations.
    #[error("error-atproto-oauth-client-13 Token endpoint HTTP request failed: {0:?}")]
    TokenHttpRequestFailed(reqwest_middleware::Error),

    /// Error when token response JSON parsing fails.
    ///
    /// This error occurs when the response from the token endpoint
    /// cannot be parsed as JSON.
    #[error("error-atproto-oauth-client-14 Token response JSON parsing failed: {0:?}")]
    TokenResponseJsonParsingFailed(reqwest::Error),

    /// Error when the token endpoint response omits the `sub` claim.
    ///
    /// AT Protocol OAuth requires the token response to identify the account
    /// DID. A missing subject cannot be bound to the DID the authorization flow
    /// was initiated for, so the response is rejected rather than trusted.
    #[error(
        "error-atproto-oauth-client-15 Token response missing subject: authorization server returned no 'sub' claim"
    )]
    TokenResponseMissingSubject,

    /// Error when the token endpoint returns a subject other than the DID the
    /// authorization flow was initiated for.
    ///
    /// A mismatch means the authorization server is attempting to authenticate
    /// the client as a different account than the one the flow began for.
    #[error(
        "error-atproto-oauth-client-16 Token subject mismatch: expected {expected}, got {actual}"
    )]
    TokenSubjectMismatch {
        /// The DID the authorization flow was initiated for.
        expected: String,
        /// The subject returned by the authorization server.
        actual: String,
    },

    /// Error when the caller supplies an empty expected subject.
    ///
    /// An empty expected subject would disable subject binding entirely, so it
    /// is rejected rather than silently accepted.
    #[error(
        "error-atproto-oauth-client-17 Expected subject required: caller supplied an empty expected subject"
    )]
    MissingExpectedSubject,

    /// Occurs when an authorization response carried no `iss` parameter.
    ///
    /// AT Protocol requires it (RFC 9207), so an absent one is a refusal
    /// rather than a tolerated omission: without it a response from one
    /// authorization server can be replayed into a flow started with another.
    #[error("error-atproto-oauth-client-21 Authorization response carried no iss parameter")]
    AuthorizationResponseMissingIssuer,

    /// Occurs when an authorization response came from a different issuer than
    /// the flow was started with.
    #[error(
        "error-atproto-oauth-client-22 Authorization response issuer mismatch: expected {expected}, got {actual}"
    )]
    AuthorizationResponseIssuerMismatch {
        /// The issuer the flow was started with.
        expected: String,
        /// The issuer the callback named.
        actual: String,
    },

    /// Error when a discovery document exceeds the size a metadata document
    /// may plausibly be.
    ///
    /// Both well-known documents are fetched from a server the caller has not
    /// yet established anything about — that is what discovery is — so the
    /// response is attacker-controlled by construction. Deserializing it
    /// buffers the whole body, and nothing bounded that body, so a peer could
    /// answer a request for a few hundred bytes of JSON with as many gigabytes
    /// as it liked and the caller would hold all of them.
    #[error(
        "error-atproto-oauth-client-18 Discovery document too large: {url} exceeded {limit} bytes"
    )]
    DiscoveryDocumentTooLarge {
        /// The document that was being fetched.
        url: String,
        /// The ceiling it went past.
        limit: usize,
    },

    /// Error when a discovery document could not be read from the network.
    #[error("error-atproto-oauth-client-19 Discovery document read failed: {0:?}")]
    DiscoveryReadFailed(reqwest::Error),

    /// Error when a discovery document is not the JSON it claims to be.
    #[error("error-atproto-oauth-client-20 Discovery document parse failed: {0:?}")]
    DiscoveryParseFailed(serde_json::Error),
}

/// Represents errors that can occur during OAuth resource validation.
///
/// These errors occur when validating the configuration of an OAuth resource server
/// against the requirements of the AT Protocol.
#[derive(Debug, Error)]
pub enum ResourceValidationError {
    /// Error when the resource server URI doesn't match the PDS URI.
    ///
    /// This error occurs when the resource server URI in the OAuth configuration
    /// does not match the expected Personal Data Server (PDS) URI, which is required
    /// for proper AT Protocol OAuth integration.
    #[error("error-atproto-oauth-resource-1 Resource must match PDS")]
    ResourceMustMatchPds,

    /// Error when the authorization servers list doesn't contain exactly one server.
    ///
    /// This error occurs when the OAuth resource configuration doesn't specify
    /// exactly one authorization server as required by AT Protocol specification.
    #[error("error-atproto-oauth-resource-2 Authorization servers must contain exactly one server")]
    AuthorizationServersMustContainExactlyOne,
}

/// Represents errors that can occur during OAuth authorization server validation.
///
/// These errors occur when validating the configuration of an OAuth authorization server
/// against the requirements specified by the AT Protocol.
#[derive(Debug, Error)]
pub enum AuthServerValidationError {
    /// Error when the authorization server issuer doesn't match the PDS.
    ///
    /// This error occurs when the issuer URI in the OAuth authorization server metadata
    /// does not match the expected Personal Data Server (PDS) URI.
    #[error("error-atproto-oauth-auth-server-1 Issuer must match PDS")]
    IssuerMustMatchPds,

    /// Error when the 'code' response type is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'code' response type,
    /// which is required for the authorization code grant flow in AT Protocol.
    #[error("error-atproto-oauth-auth-server-2 Response types supported must include 'code'")]
    ResponseTypesSupportMustIncludeCode,

    /// Error when the 'authorization_code' grant type is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'authorization_code'
    /// grant type, which is required for the AT Protocol OAuth flow.
    #[error(
        "error-atproto-oauth-auth-server-3 Grant types supported must include 'authorization_code'"
    )]
    GrantTypesSupportMustIncludeAuthorizationCode,

    /// Error when the 'refresh_token' grant type is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'refresh_token'
    /// grant type, which is required for maintaining long-term access in AT Protocol.
    #[error("error-atproto-oauth-auth-server-4 Grant types supported must include 'refresh_token'")]
    GrantTypesSupportMustIncludeRefreshToken,

    /// Error when the 'S256' code challenge method is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'S256' code
    /// challenge method for PKCE, which is required for secure authorization code flow.
    #[error(
        "error-atproto-oauth-auth-server-5 Code challenge methods supported must include 'S256'"
    )]
    CodeChallengeMethodsSupportedMustIncludeS256,

    /// Error when the 'none' token endpoint auth method is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'none'
    /// token endpoint authentication method, which is used for public clients.
    #[error(
        "error-atproto-oauth-auth-server-6 Token endpoint auth methods supported must include 'none'"
    )]
    TokenEndpointAuthMethodsSupportedMustIncludeNone,

    /// Error when the 'private_key_jwt' token endpoint auth method is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'private_key_jwt'
    /// token endpoint authentication method, which is required for AT Protocol clients.
    #[error(
        "error-atproto-oauth-auth-server-7 Token endpoint auth methods supported must include 'private_key_jwt'"
    )]
    TokenEndpointAuthMethodsSupportedMustIncludePrivateKeyJwt,

    /// Error when the 'ES256' signing algorithm is not supported for token endpoint auth.
    ///
    /// This error occurs when the authorization server doesn't support the 'ES256' signing
    /// algorithm for token endpoint authentication, which is required for AT Protocol.
    #[error(
        "error-atproto-oauth-auth-server-8 Token endpoint auth signing algorithm values must include 'ES256'"
    )]
    TokenEndpointAuthSigningAlgValuesMustIncludeES256,

    /// Error when the 'atproto' scope is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'atproto'
    /// scope, which is required for accessing AT Protocol resources.
    #[error("error-atproto-oauth-auth-server-9 Scopes supported must include 'atproto'")]
    ScopesSupportedMustIncludeAtProto,

    /// Error when the 'transition:generic' scope is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'transition:generic'
    /// scope, which is required for transitional functionality in AT Protocol.
    #[error(
        "error-atproto-oauth-auth-server-10 Scopes supported must include 'transition:generic'"
    )]
    ScopesSupportedMustIncludeTransitionGeneric,

    /// Error when the 'ES256' DPoP signing algorithm is not supported.
    ///
    /// This error occurs when the authorization server doesn't support the 'ES256'
    /// signing algorithm for DPoP proofs, which is required for AT Protocol security.
    #[error(
        "error-atproto-oauth-auth-server-11 DPoP signing algorithm values supported must include 'ES256'"
    )]
    DpopSigningAlgValuesSupportedMustIncludeES256,

    /// Error when required server features are not supported.
    ///
    /// This error occurs when the authorization server doesn't support required features
    /// such as pushed authorization requests, client ID metadata, or authorization response parameters.
    #[error(
        "error-atproto-oauth-auth-server-12 Authorization response parameters, pushed requests, client ID metadata must be supported"
    )]
    RequiredServerFeaturesMustBeSupported,
}

/// Represents errors that can occur during DPoP (Demonstration of Proof-of-Possession) operations.
///
/// These errors occur when creating, validating, or using DPoP proofs for OAuth security.
#[derive(Debug, Error)]
pub enum DpopError {
    /// Error when server returns an unexpected OAuth error.
    ///
    /// No longer produced. [`crate::dpop::DpopRetry`] used to raise this for
    /// any 400 or 401 whose body named something other than a DPoP error,
    /// which meant an ordinary `InvalidSwap` or `ScopeMissingError` reached
    /// the caller as a middleware error rather than as its response. Such a
    /// response is now returned intact. Kept so existing matches compile.
    #[error("error-atproto-oauth-dpop-1 Unexpected OAuth error: {error}")]
    UnexpectedOAuthError {
        /// The unexpected error returned by the server
        error: String,
    },

    /// Error when DPoP-Nonce header is missing from server response.
    ///
    /// No longer produced. A challenge with no nonce leaves nothing to retry
    /// with, and the response says more about why than this error did, so it
    /// is returned to the caller instead. Kept so existing matches compile.
    #[error("error-atproto-oauth-dpop-2 Missing DPoP-Nonce response header")]
    MissingDpopNonceHeader,

    /// Error when DPoP token minting fails.
    ///
    /// This error occurs when the system fails to create (mint) a DPoP proof token,
    /// typically due to cryptographic key issues or claim validation problems.
    #[error("error-atproto-oauth-dpop-3 DPoP token minting failed: {0:?}")]
    TokenMintingFailed(anyhow::Error),

    /// Error when HTTP header creation fails.
    ///
    /// This error occurs when the DPoP proof token cannot be converted into
    /// a valid HTTP header value, typically due to invalid characters.
    #[error("error-atproto-oauth-dpop-4 HTTP header creation failed: {0:?}")]
    HeaderCreationFailed(reqwest::header::InvalidHeaderValue),

    /// Error when response body JSON parsing fails.
    ///
    /// No longer produced. RFC 9449 section 7.1 specifies the nonce challenge
    /// as headers and says nothing about a body, so a challenge that carries
    /// none is conformant -- and treating that as a malformed response was
    /// what silently dropped writes against servers that send the bare shape.
    /// Kept so existing matches compile.
    #[error("error-atproto-oauth-dpop-5 Response body JSON parsing failed: {0:?}")]
    ResponseBodyParsingFailed(reqwest::Error),

    /// Error when response body is not a valid JSON object.
    ///
    /// No longer produced, for the same reason as
    /// [`DpopError::ResponseBodyParsingFailed`]. Kept so existing matches
    /// compile.
    #[error("error-atproto-oauth-dpop-6 Response body is not a valid JSON object")]
    ResponseBodyObjectParsingFailed,
}

/// Error returned when a required OAuth permission scope is missing.
///
/// Mirrors the reference `ScopeMissingError` from `@atproto/oauth-scopes`. The
/// embedded scope string is the minimal scope that would have satisfied the
/// attempted operation, as produced by the relevant `scope_needed_for` helper.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("error-atproto-oauth-scope-1 Missing required scope: {scope}")]
pub struct ScopeMissingError {
    /// The minimal scope string that would satisfy the attempted operation.
    pub scope: String,
}

impl ScopeMissingError {
    /// Create a new [`ScopeMissingError`] for the given required scope string.
    pub fn new(scope: impl Into<String>) -> Self {
        ScopeMissingError {
            scope: scope.into(),
        }
    }
}

/// Error types that can occur when working with OAuth request storage operations
#[derive(Debug, Error)]
pub enum OAuthStorageError {
    /// Occurs when cache lock acquisition fails during OAuth request retrieval operations
    #[error(
        "error-atproto-oauth-storage-1 Cache lock acquisition failed for get operation: {details}"
    )]
    CacheLockFailedGet {
        /// Details about the lock failure
        details: String,
    },

    /// Occurs when cache lock acquisition fails during OAuth request insertion operations
    #[error(
        "error-atproto-oauth-storage-2 Cache lock acquisition failed for insert operation: {details}"
    )]
    CacheLockFailedInsert {
        /// Details about the lock failure
        details: String,
    },

    /// Occurs when cache lock acquisition fails during OAuth request deletion operations
    #[error(
        "error-atproto-oauth-storage-3 Cache lock acquisition failed for delete operation: {details}"
    )]
    CacheLockFailedDelete {
        /// Details about the lock failure
        details: String,
    },

    /// Occurs when cache lock acquisition fails during expired OAuth request cleanup operations
    #[error(
        "error-atproto-oauth-storage-4 Cache lock acquisition failed for cleanup operation: {details}"
    )]
    CacheLockFailedCleanup {
        /// Details about the lock failure
        details: String,
    },
}
