use dioxus::prelude::*;

use crate::types::{ClientMetadata, OAuthInitResponse, SessionData};

/// Server function: initiates the AT Protocol OAuth authorization flow.
///
/// Resolves the user's handle, discovers their PDS, and returns
/// an authorization URL for the user to visit.
///
/// Call this from the client when the user clicks "Log in".
#[server]
pub async fn init_atproto_oauth(handle: String) -> Result<OAuthInitResponse, ServerFnError> {
    let authorization_url = crate::server::init_oauth(handle)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(OAuthInitResponse { authorization_url })
}

/// Server function: completes the OAuth flow by exchanging the
/// authorization code for tokens.
///
/// Called automatically by the [`AtprotoOAuthCallback`] component
/// when the user is redirected back from their PDS.
#[server]
pub async fn complete_atproto_oauth(
    code: String,
    state: String,
) -> Result<SessionData, ServerFnError> {
    crate::server::complete_oauth(code, state)
        .await
        .map(|s| SessionData {
            did: s.did,
            handle: s.handle,
            pds_endpoint: s.pds_endpoint,
            access_token: s.access_token,
        })
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Serves the OAuth client metadata at `GET /oauth/client-metadata.json`.
///
/// This endpoint is used by AT Protocol authorization servers to verify
/// the client's identity and discover supported grant types, redirect URIs,
/// and the client's public signing key (JWKS).
#[get("/oauth/client-metadata.json")]
pub async fn client_metadata() -> Result<ClientMetadata, ServerFnError> {
    let base = crate::server::base_url();
    let jwks = crate::server::signing_key_jwks().map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(ClientMetadata {
        client_id: format!("{}/oauth/client-metadata.json", base),
        dpop_bound_access_tokens: true,
        application_type: "web".to_string(),
        redirect_uris: vec![format!("{}/oauth/callback", base)],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        scope: "atproto transition:generic".to_string(),
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        subject_type: "public".to_string(),
        token_endpoint_auth_signing_alg: "ES256".to_string(),
        jwks,
    })
}
