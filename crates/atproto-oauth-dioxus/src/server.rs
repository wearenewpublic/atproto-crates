use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use atproto_identity::key::{KeyData, KeyType, generate_key, to_public};
use atproto_identity::resolve::{HickoryDnsResolver, InnerIdentityResolver};
use atproto_oauth::resources::{AuthorizationServer, pds_resources};
use atproto_oauth::workflow::{
    OAuthClient, OAuthRequest, OAuthRequestState, oauth_complete, oauth_init,
};
use p256::SecretKey;

use crate::errors::DioxusOAuthError;
use crate::types::SessionData;

static OAUTH_STATES: LazyLock<tokio::sync::Mutex<HashMap<String, StoredOAuthState>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

pub(crate) static ACTIVE_SESSIONS: LazyLock<tokio::sync::Mutex<HashMap<String, ActiveSession>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

static SIGNING_KEY: LazyLock<KeyData> = LazyLock::new(|| {
    get_or_generate_signing_key()
        .expect("Failed to initialize OAuth signing key; set a valid OAUTH_KEY_SEED or ensure key generation works")
});

#[derive(Clone)]
struct StoredOAuthState {
    oauth_request: OAuthRequest,
    auth_server: AuthorizationServer,
    pds_url: String,
    client_id: String,
    redirect_uri: String,
    signing_key: KeyData,
    dpop_key: KeyData,
    handle: String,
}

/// An authenticated AT Protocol OAuth session.
///
/// Stored server-side after successful token exchange. Other server functions
/// can retrieve this session to make DPoP-authenticated API calls to the
/// user's PDS on their behalf.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ActiveSession {
    /// The user's decentralized identifier (DID).
    pub did: String,
    /// The user's AT Protocol handle.
    pub handle: String,
    /// The endpoint URL of the user's Personal Data Server.
    pub pds_endpoint: String,
    /// The OAuth access token for authenticated API calls.
    pub access_token: String,
    /// The DPoP private key for signing proof-of-possession tokens.
    pub dpop_key: KeyData,
}

/// Retrieves an active session by DID from the session store.
///
/// Returns `None` if no active session exists for the given DID.
#[allow(dead_code)]
pub async fn get_active_session(did: &str) -> Option<ActiveSession> {
    ACTIVE_SESSIONS.lock().await.get(did).cloned()
}

/// Returns a reference to the static OAuth signing key.
pub fn get_signing_key() -> &'static KeyData {
    &SIGNING_KEY
}

fn get_or_generate_signing_key() -> Result<KeyData, DioxusOAuthError> {
    if let Ok(seed_hex) = std::env::var("OAUTH_KEY_SEED") {
        let trimmed = seed_hex.trim();
        if !trimmed.is_empty() {
            let seed = hex::decode(trimmed)
                .map_err(|e| DioxusOAuthError::InvalidKeySeed(format!("Invalid hex: {}", e)))?;
            let seed: [u8; 32] = seed.try_into().map_err(|_| {
                DioxusOAuthError::InvalidKeySeed(
                    "OAUTH_KEY_SEED must be exactly 32 bytes (64 hex chars)".to_string(),
                )
            })?;
            let sk = SecretKey::from_slice(&seed).map_err(|_| {
                DioxusOAuthError::InvalidKeySeed(
                    "OAUTH_KEY_SEED is not a valid P-256 private key".to_string(),
                )
            })?;
            return Ok(KeyData::new(KeyType::P256Private, sk.to_bytes().to_vec()));
        }
    }
    generate_key(KeyType::P256Private)
        .map_err(|e| DioxusOAuthError::KeyInitializationFailed(e.to_string()))
}

/// Derives the public key JWKS for the signing key.
pub fn signing_key_jwks() -> Result<serde_json::Value, DioxusOAuthError> {
    let public_key = to_public(&SIGNING_KEY)
        .map_err(|e| DioxusOAuthError::PublicKeyDerivationFailed(e.to_string()))?;
    let jwk = atproto_oauth::jwk::generate(&public_key)
        .map_err(|e| DioxusOAuthError::JwkGenerationFailed(e.to_string()))?;
    let jwks = atproto_oauth::jwk::WrappedJsonWebKeySet { keys: vec![jwk] };
    serde_json::to_value(jwks).map_err(|e| DioxusOAuthError::JwkGenerationFailed(e.to_string()))
}

fn generate_random_hex(len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Returns the base URL of the deployment.
pub fn base_url() -> String {
    let domain = std::env::var("HOST_DOMAIN")
        .or_else(|_| std::env::var("RAILWAY_PUBLIC_DOMAIN"))
        .unwrap_or_default();
    if domain.is_empty() {
        "http://127.0.0.1:8080".to_string()
    } else {
        format!("https://{}", domain)
    }
}

/// Initiates the AT Protocol OAuth authorization flow.
///
/// Resolves the user's handle to a DID, discovers their PDS OAuth endpoints,
/// and pushes an authorization request via PAR. Returns the URL the user
/// should be redirected to for authentication.
pub async fn init_oauth(handle: String) -> Result<String, DioxusOAuthError> {
    let http_client = reqwest::Client::new();

    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);
    let identity_resolver = InnerIdentityResolver {
        dns_resolver: Arc::new(dns_resolver),
        http_client: http_client.clone(),
        plc_hostname: "https://plc.directory".to_string(),
    };

    let doc = identity_resolver
        .resolve(&handle)
        .await
        .map_err(|e| DioxusOAuthError::HandleResolutionFailed(e.to_string()))?;

    let pds_url = doc
        .pds_endpoints()
        .first()
        .ok_or_else(|| {
            DioxusOAuthError::PdsResolutionFailed("No PDS endpoints in DID document".to_string())
        })?
        .to_string();

    let (_protected, auth_server) = pds_resources(&http_client, &pds_url)
        .await
        .map_err(|e| DioxusOAuthError::PdsResourceDiscoveryFailed(e.to_string()))?;

    let base = base_url();
    let redirect_uri = format!("{}/oauth/callback", base);
    let client_id = if base.starts_with("https://") {
        format!("{}/oauth/client-metadata.json", base)
    } else {
        format!(
            "http://localhost?redirect_uri={}&scope={}",
            urlencode(&redirect_uri),
            urlencode("atproto transition:generic"),
        )
    };

    let (code_verifier, code_challenge) = atproto_oauth::pkce::generate();

    let state = generate_random_hex(16);
    let nonce = generate_random_hex(16);

    let signing_key = get_signing_key().clone();
    let dpop_key = generate_key(KeyType::P256Private)
        .map_err(|e| DioxusOAuthError::KeyInitializationFailed(e.to_string()))?;

    let oauth_client = OAuthClient {
        redirect_uri: redirect_uri.clone(),
        client_id: client_id.clone(),
        private_signing_key_data: signing_key.clone(),
    };

    let oauth_request_state = OAuthRequestState {
        state: state.clone(),
        nonce: nonce.clone(),
        code_challenge,
        scope: "atproto transition:generic".to_string(),
    };

    let par_response = oauth_init(
        &http_client,
        &oauth_client,
        &dpop_key,
        Some(&handle),
        &auth_server,
        &oauth_request_state,
    )
    .await
    .map_err(|e| DioxusOAuthError::OAuthInitFailed(e.to_string()))?;

    let oauth_request = OAuthRequest {
        oauth_state: state.clone(),
        issuer: auth_server.issuer.clone(),
        authorization_server: auth_server.pushed_authorization_request_endpoint.clone(),
        nonce,
        pkce_verifier: code_verifier,
        signing_public_key: hex::encode(&signing_key.1),
        dpop_private_key: hex::encode(&dpop_key.1),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::TimeDelta::seconds(par_response.expires_in as i64),
    };

    OAUTH_STATES.lock().await.insert(
        state.clone(),
        StoredOAuthState {
            oauth_request,
            auth_server: auth_server.clone(),
            pds_url,
            client_id: client_id.clone(),
            redirect_uri,
            signing_key,
            dpop_key,
            handle: handle.clone(),
        },
    );

    let authorization_url = format!(
        "{}?client_id={}&request_uri={}&state={}",
        auth_server.authorization_endpoint,
        urlencode(&client_id),
        urlencode(&par_response.request_uri),
        urlencode(&state),
    );

    Ok(authorization_url)
}

/// Completes the OAuth flow by exchanging the authorization code for tokens.
///
/// Verifies the state parameter, performs the token exchange with DPoP,
/// and stores the active session for subsequent authenticated API calls.
pub async fn complete_oauth(code: String, state: String) -> Result<SessionData, DioxusOAuthError> {
    let stored = {
        let mut states = OAUTH_STATES.lock().await;
        states
            .remove(&state)
            .ok_or(DioxusOAuthError::InvalidOAuthState)?
    };

    let http_client = reqwest::Client::new();

    let oauth_client = OAuthClient {
        redirect_uri: stored.redirect_uri.clone(),
        client_id: stored.client_id.clone(),
        private_signing_key_data: stored.signing_key.clone(),
    };

    let token_response = oauth_complete(
        &http_client,
        &oauth_client,
        &stored.dpop_key,
        &code,
        &stored.oauth_request,
        &stored.auth_server,
    )
    .await
    .map_err(|e| DioxusOAuthError::TokenExchangeFailed(e.to_string()))?;

    let did = token_response
        .sub
        .ok_or(DioxusOAuthError::MissingSubField)?;

    ACTIVE_SESSIONS.lock().await.insert(
        did.clone(),
        ActiveSession {
            did: did.clone(),
            handle: stored.handle.clone(),
            pds_endpoint: stored.pds_url.clone(),
            access_token: token_response.access_token.clone(),
            dpop_key: stored.dpop_key.clone(),
        },
    );

    Ok(SessionData {
        did,
        handle: stored.handle,
        pds_endpoint: stored.pds_url,
        access_token: token_response.access_token,
    })
}
