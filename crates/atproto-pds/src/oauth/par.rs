//! Pushed Authorization Request (PAR) endpoint — RFC 9126.
//!
//! Two intake shapes per RFC 9126 §2.1:
//!
//! - **Inline parameters** — the client posts each PAR field as a top-level
//!   form/JSON value (`client_id`, `redirect_uri`, `scope`, etc.).
//! - **Signed request object** — the client posts a single `request` JWT
//!   whose payload carries the same fields, signed with one of the keys
//!   in the client's published `jwks_uri`. When
//!   `request` is present, inline parameters are ignored; the JWS is
//!   verified and its embedded payload is used instead.

use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::oauth::client_metadata::{assert_redirect_uri_registered, resolve_client_metadata};
use crate::oauth::extract::JsonOrForm;
use crate::oauth::state::{OAuthRequest, OAuthState, PAR_TTL_SECS};
use atproto_identity::key::{KeyData, KeyType, validate as validate_signature};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Inputs for `POST /oauth/par`.
///
/// All inline fields are optional in struct form because the spec accepts
/// either inline parameters OR a single `request` JWT. The handler validates required fields after merging the two
/// shapes — when `request` is present, the JWT payload's fields take
/// precedence; otherwise the inline fields must satisfy the same
/// validations.
#[derive(Debug, Deserialize)]
pub struct ParInput {
    /// Optional signed request object (RFC 9126 §2.1, JAR per RFC 9101).
    /// When present, all other fields here are ignored — the embedded
    /// payload is used instead.
    pub request: Option<String>,
    /// `client_id` (URL of the client metadata document).
    #[serde(default)]
    pub client_id: Option<String>,
    /// `response_type` — must be `code`.
    #[serde(default)]
    pub response_type: Option<String>,
    /// Redirect URI (must match a `redirect_uris` entry in client metadata).
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Requested scope (space-separated; must include `atproto`).
    #[serde(default)]
    pub scope: Option<String>,
    /// Opaque client state.
    #[serde(default)]
    pub state: Option<String>,
    /// PKCE `code_challenge`.
    #[serde(default)]
    pub code_challenge: Option<String>,
    /// PKCE method — must be `S256`.
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// Optional DPoP key thumbprint.
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    /// Optional handle/DID hint for prefilling consent.
    #[serde(default)]
    pub login_hint: Option<String>,
}

/// Resolved + validated PAR fields after merging inline + request-object
/// shapes. The handler builds this internally from `ParInput` and then
/// applies the spec-required validations.
#[derive(Debug, Clone)]
struct ResolvedFields {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    dpop_jkt: Option<String>,
    login_hint: Option<String>,
}

/// Decoded payload of a JAR-style request object (RFC 9101 §2.1).
#[derive(Debug, Clone, Deserialize)]
struct RequestObjectClaims {
    /// `iss` claim — must equal `client_id`.
    iss: Option<String>,
    /// `aud` claim — must equal the PDS issuer URL.
    aud: Option<serde_json::Value>,
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    dpop_jkt: Option<String>,
    #[serde(default)]
    login_hint: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    iat: Option<i64>,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
}

/// Response shape — `request_uri` + `expires_in`.
#[derive(Debug, Serialize)]
pub struct ParResponse {
    /// PAR-style `urn:ietf:params:oauth:request_uri:<token>` URI.
    pub request_uri: String,
    /// Seconds until the request URI expires.
    pub expires_in: u64,
}

/// Handler for `POST /oauth/par`.
pub async fn par_handler(
    State(state): State<HttpState>,
    headers: axum::http::HeaderMap,
    JsonOrForm(input): JsonOrForm<ParInput>,
) -> Result<Json<ParResponse>, XrpcError> {
    // §10.2 — when `request` is present, JWS-verify against the client
    // metadata's `jwks_uri` and use the embedded payload. Otherwise fall
    // through to the inline-parameters path.
    let resolved = if let Some(jws) = input.request.as_deref() {
        let claims = verify_request_object(&state, jws, input.client_id.as_deref()).await?;
        merge_request_object_into_resolved(claims)?
    } else {
        merge_inline_into_resolved(&input)?
    };

    // RFC 9449 §10.1: on PAR the key may be bound by the DPoP header or by the
    // `dpop_jkt` parameter. Either alone is fine — the proof is optional here,
    // and a bare request is not an error. But when both are present and
    // disagree, the request must be refused: `dpop_jkt` is an assertion by
    // whoever sent the request, and honouring it over a signed proof would let
    // a caller bind the eventual token to a key it does not hold. The reference
    // provider raises InvalidDpopKeyBindingError for exactly this.
    let par_url = format!(
        "{}/oauth/par",
        crate::oauth::metadata::issuer_url(&state.service_did)
    );
    if let Some(proof_jkt) = crate::oauth::dpop::par_dpop_thumbprint(&headers, &par_url)?
        && let Some(claimed) = resolved.dpop_jkt.as_deref()
        && claimed != proof_jkt
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "dpop_jkt does not match the thumbprint of the DPoP proof",
        ));
    }

    // Spec-required validations (apply to whichever shape we resolved).
    if resolved.response_type != "code" {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be 'code'",
        ));
    }
    if resolved.code_challenge_method != "S256" {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be 'S256'",
        ));
    }
    if !resolved.scope.split_whitespace().any(|s| s == "atproto") {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must include 'atproto'",
        ));
    }
    if resolved.code_challenge.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge required",
        ));
    }

    // Resolve the client's metadata and confirm the requested redirect is one
    // it published. Without this the authorization code for a legitimate,
    // user-trusted `client_id` can be delivered to any destination the caller
    // names — the consent screen shows the genuine client, and the code goes
    // somewhere else. RFC 6749 §3.1.2.3.
    let metadata = resolve_client_metadata(&resolved.client_id, &crate::user_agent())
        .await
        .map_err(|err| {
            tracing::warn!(
                client_id = %resolved.client_id,
                error = %err,
                "PAR rejected: could not resolve client metadata"
            );
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("client metadata could not be resolved: {err}"),
            )
        })?;
    assert_redirect_uri_registered(&resolved.client_id, &metadata, &resolved.redirect_uri)
        .map_err(|err| {
            tracing::warn!(
                client_id = %resolved.client_id,
                redirect_uri = %resolved.redirect_uri,
                "PAR rejected: redirect_uri is not registered for this client"
            );
            XrpcError::new(StatusCode::BAD_REQUEST, "invalid_request", err.to_string())
        })?;

    // Generate the request_uri token.
    let token = random_token();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{token}");
    let request = OAuthRequest {
        client_id: resolved.client_id,
        redirect_uri: resolved.redirect_uri,
        scope: resolved.scope,
        state: resolved.state,
        code_challenge: resolved.code_challenge,
        code_challenge_method: resolved.code_challenge_method,
        dpop_jkt: resolved.dpop_jkt,
        login_hint: resolved.login_hint,
        created_at: Utc::now(),
    };
    state
        .oauth_state()
        .store_par(request_uri.clone(), request)
        .await
        .map_err(XrpcError::from)?;

    Ok(Json(ParResponse {
        request_uri,
        expires_in: PAR_TTL_SECS,
    }))
}

fn merge_inline_into_resolved(input: &ParInput) -> Result<ResolvedFields, XrpcError> {
    fn req<T: Clone>(field: &Option<T>, name: &str) -> Result<T, XrpcError> {
        field.clone().ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("{name} required"),
            )
        })
    }
    Ok(ResolvedFields {
        client_id: req(&input.client_id, "client_id")?,
        response_type: req(&input.response_type, "response_type")?,
        redirect_uri: req(&input.redirect_uri, "redirect_uri")?,
        scope: req(&input.scope, "scope")?,
        state: req(&input.state, "state")?,
        code_challenge: req(&input.code_challenge, "code_challenge")?,
        code_challenge_method: req(&input.code_challenge_method, "code_challenge_method")?,
        dpop_jkt: input.dpop_jkt.clone(),
        login_hint: input.login_hint.clone(),
    })
}

fn merge_request_object_into_resolved(
    claims: RequestObjectClaims,
) -> Result<ResolvedFields, XrpcError> {
    Ok(ResolvedFields {
        client_id: claims.client_id,
        response_type: claims.response_type,
        redirect_uri: claims.redirect_uri,
        scope: claims.scope,
        state: claims.state,
        code_challenge: claims.code_challenge,
        code_challenge_method: claims.code_challenge_method,
        dpop_jkt: claims.dpop_jkt,
        login_hint: claims.login_hint,
    })
}

/// Verify a JAR-style signed request object (RFC 9101) against the client
/// metadata's published `jwks_uri`. Returns the decoded payload claims on
/// success.
///
/// Steps:
///
/// 1. Parse JWS header + payload (no signature check yet).
/// 2. Cross-check header `alg` is one of the EC algorithms we accept.
/// 3. Cross-check claims.iss == claims.client_id (RFC 9101 §2.1) and
///    cross-check the inline `client_id` (when supplied) against the
///    payload value.
/// 4. Fetch `<client_id>` (the URL of the client metadata document)
///    to discover `jwks` (inline) or `jwks_uri`.
/// 5. Resolve the matching JWK by `kid` (or fall back to first
///    EC-compatible key when `kid` absent), build a `KeyData` from it,
///    and `validate(signing_input, signature, key)`.
/// 6. Reject expired (`exp < now`) and not-yet-valid (`nbf > now`) claims.
async fn verify_request_object(
    state: &HttpState,
    jws: &str,
    inline_client_id: Option<&str>,
) -> Result<RequestObjectClaims, XrpcError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request must be a compact-form JWS",
        ));
    }
    let header_bytes = B64URL.decode(parts[0]).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("decode header: {e}"),
        )
    })?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("parse header: {e}"),
        )
    })?;
    if !matches!(header.alg.as_str(), "ES256" | "ES256K" | "ES384") {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!(
                "unsupported alg {}; want ES256 / ES256K / ES384",
                header.alg
            ),
        ));
    }
    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("decode payload: {e}"),
        )
    })?;
    let claims: RequestObjectClaims = serde_json::from_slice(&payload_bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("parse payload: {e}"),
        )
    })?;

    // RFC 9101 §2.1: iss must match client_id.
    if let Some(iss) = claims.iss.as_deref()
        && iss != claims.client_id
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "iss != client_id",
        ));
    }
    // When the wrapper also passes inline client_id, it must match.
    if let Some(inline) = inline_client_id
        && inline != claims.client_id
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "inline client_id != request-object client_id",
        ));
    }

    // Time bounds.
    let now = Utc::now().timestamp();
    if let Some(exp) = claims.exp
        && exp <= now
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request expired",
        ));
    }
    if let Some(nbf) = claims.nbf
        && nbf > now
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request not yet valid",
        ));
    }

    // Fetch the client's keyset.
    let signing_key = resolve_client_signing_key(&claims.client_id, header.kid.as_deref())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request_object",
                format!("resolve client key: {e}"),
            )
        })?;

    // Verify the JWS signature.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = B64URL.decode(parts[2]).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("decode sig: {e}"),
        )
    })?;
    validate_signature(&signing_key, signing_input.as_bytes(), &sig_bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            format!("signature verify: {e}"),
        )
    })?;

    // Audience: when claims.aud is set, it should include this PDS's
    // issuer/host. We don't strictly enforce — the spec recommends but
    // doesn't require — but log mismatches.
    if let Some(aud) = claims.aud.as_ref() {
        let expected = state.service_did.as_str();
        let matches = match aud {
            serde_json::Value::String(s) => s == expected,
            serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected)),
            _ => false,
        };
        if !matches {
            tracing::debug!(
                aud = ?aud,
                expected,
                "PAR request_object aud mismatch (advisory)"
            );
        }
    }

    Ok(claims)
}

/// Fetch the client's metadata document at `client_id`, extract `jwks` or
/// `jwks_uri`, and resolve a matching `KeyData` by `kid`. Falls back to the
/// first EC key when `kid` is absent.
async fn resolve_client_signing_key(
    client_id: &str,
    kid: Option<&str>,
) -> Result<KeyData, KeyResolveError> {
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| KeyResolveError(format!("build http client: {e}")))?;
    let metadata: serde_json::Value = http
        .get(client_id)
        .send()
        .await
        .map_err(|e| KeyResolveError(format!("fetch client metadata: {e}")))?
        .json()
        .await
        .map_err(|e| KeyResolveError(format!("parse client metadata json: {e}")))?;

    // Inline keyset wins when present.
    let keyset_value: serde_json::Value = if let Some(jwks) = metadata.get("jwks").cloned() {
        jwks
    } else if let Some(uri) = metadata.get("jwks_uri").and_then(|v| v.as_str()) {
        http.get(uri)
            .send()
            .await
            .map_err(|e| KeyResolveError(format!("fetch jwks_uri {uri}: {e}")))?
            .json()
            .await
            .map_err(|e| KeyResolveError(format!("parse jwks_uri json: {e}")))?
    } else {
        return Err(KeyResolveError(
            "client metadata has neither `jwks` nor `jwks_uri`".to_string(),
        ));
    };

    let keys = keyset_value
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KeyResolveError("jwks missing `keys` array".to_string()))?;

    let chosen = match kid {
        Some(k) => keys
            .iter()
            .find(|jwk| jwk.get("kid").and_then(|v| v.as_str()) == Some(k))
            .ok_or_else(|| KeyResolveError(format!("no key with kid={k} in jwks")))?,
        None => keys
            .iter()
            .find(|jwk| jwk.get("kty").and_then(|v| v.as_str()) == Some("EC"))
            .ok_or_else(|| KeyResolveError("jwks has no EC key".to_string()))?,
    };

    jwk_to_key_data(chosen).map_err(|e| KeyResolveError(format!("decode jwk → KeyData: {e}")))
}

#[derive(Debug)]
struct KeyResolveError(String);

impl std::fmt::Display for KeyResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for KeyResolveError {}

/// Convert a JWK JSON object into an `atproto_identity::key::KeyData`
/// (public form). Used to materialize the client's signing key from the
/// JWKS published at its `client_id` metadata document.
///
/// Mirrors the `parse_jwk_to_key_data` helper in
/// `atproto-identity/src/bin/atpdid.rs` — bypasses `identify_key` because
/// we already have the raw SEC1 bytes from the JWK.
fn jwk_to_key_data(jwk: &serde_json::Value) -> Result<KeyData, String> {
    use elliptic_curve::JwkEcKey;
    use elliptic_curve::sec1::ToEncodedPoint;

    let parsed: JwkEcKey =
        serde_json::from_value(jwk.clone()).map_err(|e| format!("parse JwkEcKey: {e}"))?;
    match parsed.crv() {
        "P-256" => {
            let pk: p256::PublicKey =
                p256::PublicKey::from_jwk(&parsed).map_err(|e| format!("p256 from jwk: {e}"))?;
            Ok(KeyData::new(
                KeyType::P256Public,
                pk.to_encoded_point(true).as_bytes().to_vec(),
            ))
        }
        "P-384" => {
            let pk: p384::PublicKey =
                p384::PublicKey::from_jwk(&parsed).map_err(|e| format!("p384 from jwk: {e}"))?;
            Ok(KeyData::new(
                KeyType::P384Public,
                pk.to_encoded_point(true).as_bytes().to_vec(),
            ))
        }
        "secp256k1" => {
            let pk: k256::PublicKey =
                k256::PublicKey::from_jwk(&parsed).map_err(|e| format!("k256 from jwk: {e}"))?;
            Ok(KeyData::new(
                KeyType::K256Public,
                pk.to_encoded_point(true).as_bytes().to_vec(),
            ))
        }
        other => Err(format!("unsupported jwk crv {other}")),
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

// ---- HttpState extension ----

impl HttpState {
    /// Get the OAuth state, lazily initialized via [`OAuthState::default`].
    pub fn oauth_state(&self) -> &OAuthState {
        // The OAuthState is stored on HttpState; see state.rs for the field.
        &self.oauth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_input() -> ParInput {
        ParInput {
            request: None,
            client_id: Some("https://app.example/cm.json".to_string()),
            response_type: Some("code".to_string()),
            redirect_uri: Some("https://app.example/cb".to_string()),
            scope: Some("atproto transition:generic".to_string()),
            state: Some("abc".to_string()),
            code_challenge: Some("ZGVhZGJlZWY".to_string()),
            code_challenge_method: Some("S256".to_string()),
            dpop_jkt: None,
            login_hint: None,
        }
    }

    #[test]
    fn random_token_is_64_hex_chars() {
        let t = random_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn par_input_round_trip() {
        let input = fresh_input();
        assert_eq!(input.response_type.as_deref(), Some("code"));
        assert_eq!(input.code_challenge_method.as_deref(), Some("S256"));
    }

    #[test]
    fn merge_inline_rejects_missing_required_fields() {
        let mut input = fresh_input();
        input.client_id = None;
        let err = merge_inline_into_resolved(&input).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "invalid_request");
    }

    #[test]
    fn merge_inline_round_trips_full_input() {
        let resolved = merge_inline_into_resolved(&fresh_input()).unwrap();
        assert_eq!(resolved.client_id, "https://app.example/cm.json");
        assert_eq!(resolved.response_type, "code");
    }

    #[test]
    fn jwk_to_key_data_round_trip_p256() {
        // Round-trip a freshly-generated P-256 key through the JWK encoder
        // → our jwk_to_key_data decoder, and verify the decoded public
        // bytes match the source key's public form.
        use atproto_identity::key::{KeyType, generate_key, to_public};
        use elliptic_curve::JwkEcKey;
        let priv_key = generate_key(KeyType::P256Private).unwrap();
        let pub_key = to_public(&priv_key).unwrap();
        let jwk: JwkEcKey = (&pub_key).try_into().unwrap();
        let jwk_value = serde_json::to_value(&jwk).unwrap();
        let recovered = jwk_to_key_data(&jwk_value).unwrap();
        assert_eq!(recovered.bytes(), pub_key.bytes());
    }

    #[test]
    fn jwk_to_key_data_round_trip_k256() {
        use atproto_identity::key::{KeyType, generate_key, to_public};
        use elliptic_curve::JwkEcKey;
        let priv_key = generate_key(KeyType::K256Private).unwrap();
        let pub_key = to_public(&priv_key).unwrap();
        let jwk: JwkEcKey = (&pub_key).try_into().unwrap();
        let jwk_value = serde_json::to_value(&jwk).unwrap();
        let recovered = jwk_to_key_data(&jwk_value).unwrap();
        assert_eq!(recovered.bytes(), pub_key.bytes());
    }

    #[test]
    fn jwk_to_key_data_rejects_unknown_curve() {
        let weird = serde_json::json!({"kty": "EC", "crv": "Ed25519", "x": "", "y": ""});
        assert!(jwk_to_key_data(&weird).is_err());
    }
}
