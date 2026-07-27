//! Session + identity cookie types and the AES-256-GCM cookie codec.
//!
//! The session cookie (encrypted, HttpOnly) carries the OAuth tokens and the
//! per-session DPoP key; the identity cookie (base64 JSON, JS-readable) carries
//! navbar display info. Mirrors the reference appview's cookie module.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, SameSite};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::WebError;

/// Name of the encrypted session cookie.
pub const SESSION_COOKIE_NAME: &str = "session";
/// Name of the readable identity cookie.
pub const IDENTITY_COOKIE_NAME: &str = "identity";

/// Encrypted session state (OAuth tokens + DPoP key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookie {
    /// The user's DID.
    pub did: String,
    /// The DPoP-bound OAuth access token.
    pub access_token: String,
    /// The OAuth refresh token, if any.
    pub refresh_token: Option<String>,
    /// Access-token expiry.
    pub expires_at: DateTime<Utc>,
    /// The per-session DPoP private key (`did:key:...`).
    pub dpop_private_key: String,
}

impl SessionCookie {
    /// Whether the access token has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Whether the access token expires within `duration`.
    pub fn expires_within(&self, duration: Duration) -> bool {
        Utc::now() + duration >= self.expires_at
    }
}

/// Readable identity info for the navbar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCookie {
    /// The user's DID.
    pub did: String,
    /// The user's handle, if resolved.
    pub handle: Option<String>,
    /// The user's PDS URL, if resolved.
    pub pds_url: Option<String>,
}

/// Cookie codec/transport errors.
#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    /// Cipher initialization failed.
    #[error("error-walking-club-cookie-1 Failed to initialize cipher")]
    CipherInit,
    /// Encryption failed.
    #[error("error-walking-club-cookie-2 Encryption failed")]
    Encryption,
    /// Decryption failed.
    #[error("error-walking-club-cookie-3 Decryption failed")]
    Decryption,
    /// Base64 decoding failed.
    #[error("error-walking-club-cookie-4 Invalid base64 encoding")]
    InvalidBase64,
    /// The ciphertext was malformed.
    #[error("error-walking-club-cookie-5 Invalid cookie format")]
    InvalidFormat,
    /// (De)serialization failed.
    #[error("error-walking-club-cookie-6 Serialization failed")]
    Serialization,
    /// The cookie value was not a valid header value.
    #[error("error-walking-club-cookie-7 Invalid cookie value")]
    InvalidCookieValue,
}

/// Encrypt `data` with AES-256-GCM, returning base64url(nonce || ciphertext).
#[allow(deprecated)]
pub fn encrypt_cookie(secret: &[u8; 32], data: &[u8]) -> Result<String, CookieError> {
    let cipher = Aes256Gcm::new_from_slice(secret).map_err(|_| CookieError::CipherInit)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| CookieError::Encryption)?;
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(&combined))
}

/// Decrypt a value produced by `encrypt_cookie`.
#[allow(deprecated)]
pub fn decrypt_cookie(secret: &[u8; 32], encrypted: &str) -> Result<Vec<u8>, CookieError> {
    let combined = BASE64
        .decode(encrypted)
        .map_err(|_| CookieError::InvalidBase64)?;
    if combined.len() < 12 {
        return Err(CookieError::InvalidFormat);
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(secret).map_err(|_| CookieError::CipherInit)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CookieError::Decryption)
}

/// Serialize + encrypt a session cookie.
pub fn encode_session_cookie(
    secret: &[u8; 32],
    session: &SessionCookie,
) -> Result<String, CookieError> {
    let json = serde_json::to_vec(session).map_err(|_| CookieError::Serialization)?;
    encrypt_cookie(secret, &json)
}

/// Decrypt + deserialize a session cookie.
pub fn decode_session_cookie(
    secret: &[u8; 32],
    encrypted: &str,
) -> Result<SessionCookie, CookieError> {
    let decrypted = decrypt_cookie(secret, encrypted)?;
    serde_json::from_slice(&decrypted).map_err(|_| CookieError::Serialization)
}

/// Encode an identity cookie (base64 JSON, readable by JS).
pub fn encode_identity_cookie(identity: &IdentityCookie) -> Result<String, CookieError> {
    let json = serde_json::to_vec(identity).map_err(|_| CookieError::Serialization)?;
    Ok(BASE64.encode(&json))
}

/// Decode an identity cookie.
pub fn decode_identity_cookie(encoded: &str) -> Result<IdentityCookie, CookieError> {
    let json = BASE64
        .decode(encoded)
        .map_err(|_| CookieError::InvalidBase64)?;
    serde_json::from_slice(&json).map_err(|_| CookieError::Serialization)
}

/// Build a `Set-Cookie` header for the session cookie.
pub fn build_session_cookie_header(
    domain: &str,
    value: &str,
    max_age_secs: i64,
) -> Result<HeaderValue, CookieError> {
    let cookie = Cookie::build((SESSION_COOKIE_NAME, value))
        .domain(domain.to_string())
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(max_age_secs))
        .build();
    HeaderValue::from_str(&cookie.to_string()).map_err(|_| CookieError::InvalidCookieValue)
}

/// Build a `Set-Cookie` header for the identity cookie (JS-readable).
pub fn build_identity_cookie_header(
    domain: &str,
    value: &str,
    max_age_secs: i64,
) -> Result<HeaderValue, CookieError> {
    let cookie = Cookie::build((IDENTITY_COOKIE_NAME, value))
        .domain(domain.to_string())
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(max_age_secs))
        .build();
    HeaderValue::from_str(&cookie.to_string()).map_err(|_| CookieError::InvalidCookieValue)
}

/// Build a `Set-Cookie` header that clears a cookie.
pub fn build_clear_cookie_header(
    name: &str,
    domain: &str,
    http_only: bool,
) -> Result<HeaderValue, CookieError> {
    let cookie = Cookie::build((name.to_string(), String::new()))
        .domain(domain.to_string())
        .path("/")
        .secure(true)
        .http_only(http_only)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0))
        .build();
    HeaderValue::from_str(&cookie.to_string()).map_err(|_| CookieError::InvalidCookieValue)
}

/// Extract a named cookie value from a `Cookie` header.
pub fn extract_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for cookie_str in cookie_header.split(';') {
        let cookie_str = cookie_str.trim();
        if let Some(value) = cookie_str.strip_prefix(name)
            && let Some(value) = value.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

/// Extract and decrypt the session cookie from request headers.
pub fn get_session_from_headers(config: &Config, headers: &HeaderMap) -> Option<SessionCookie> {
    let cookie_secret = config.cookie_secret.as_ref()?;
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let session_value = extract_cookie_value(cookie_header, SESSION_COOKIE_NAME)?;
    decode_session_cookie(cookie_secret, session_value).ok()
}

/// Require an authenticated session or return `WebError::Unauthorized`.
pub fn get_authenticated_session(
    config: &Config,
    headers: &HeaderMap,
) -> Result<SessionCookie, WebError> {
    get_session_from_headers(config, headers).ok_or(WebError::Unauthorized)
}

/// Whether a valid session belongs to `resource_did`.
pub fn is_session_owner(config: &Config, headers: &HeaderMap, resource_did: &str) -> bool {
    get_session_from_headers(config, headers)
        .map(|s| s.did == resource_did)
        .unwrap_or(false)
}
