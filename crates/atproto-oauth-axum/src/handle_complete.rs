//! OAuth authorization callback handler.
//!
//! Exchange authorization codes for tokens with state validation
//! and comprehensive error handling for OAuth completion.

use std::sync::Arc;

use anyhow::Result;
use atproto_identity::{
    key::{KeyResolver, identify_key},
    traits::DidDocumentStorage,
};
use atproto_oauth::{
    resources::pds_resources,
    storage::OAuthRequestStorage,
    workflow::{OAuthClient, oauth_complete},
};
use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    errors::OAuthCallbackError,
    state::{HttpClient, OAuthClientConfig},
};

/// OAuth authorization callback form data.
///
/// Contains the parameters sent by the authorization server during the OAuth callback.
#[derive(Deserialize, Serialize)]
pub struct OAuthCallbackForm {
    /// OAuth state parameter for CSRF protection
    pub state: String,
    /// Authorization server issuer identifier
    pub iss: String,
    /// Authorization code from the authorization server
    pub code: String,
}

impl IntoResponse for OAuthCallbackError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "OAuth callback error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("OAuth callback failed: {}", self),
        )
            .into_response()
    }
}

/// Handles OAuth authorization callback requests.
///
/// Processes the authorization callback by validating the OAuth state, exchanging
/// the authorization code for tokens, and returning the complete OAuth response.
pub async fn handle_oauth_callback(
    oauth_client_config: OAuthClientConfig,
    client: HttpClient,
    oauth_request_storage: State<Arc<dyn OAuthRequestStorage>>,
    did_document_storage: State<Arc<dyn DidDocumentStorage>>,
    key_resolver: State<Arc<dyn KeyResolver>>,
    Form(callback_form): Form<OAuthCallbackForm>,
) -> Result<impl IntoResponse, OAuthCallbackError> {
    let oauth_request = oauth_request_storage
        .get_oauth_request_by_state(&callback_form.state)
        .await?;

    let oauth_request = oauth_request.ok_or(OAuthCallbackError::NoOAuthRequestFound)?;

    if oauth_request.issuer != callback_form.iss {
        return Err(OAuthCallbackError::InvalidIssuer {
            expected: oauth_request.issuer.clone(),
            actual: callback_form.iss.clone(),
        });
    }

    let private_signing_key_data = key_resolver
        .resolve(&oauth_request.signing_public_key)
        .await
        .map_err(|_| OAuthCallbackError::NoSigningKeyFound)?;

    let private_dpop_key_data = identify_key(&oauth_request.dpop_private_key)?;

    let oauth_client = OAuthClient {
        redirect_uri: oauth_client_config.redirect_uris.clone(),
        client_id: oauth_client_config.client_id.clone(),
        private_signing_key_data,
    };

    // We need to get the DID from the token response after OAuth completion
    // First, get authorization server from the issuer to complete OAuth
    let (_, authorization_server) =
        pds_resources(&client, &oauth_request.authorization_server).await?;

    let token_response = oauth_complete(
        &client,
        &oauth_client,
        &private_dpop_key_data,
        &callback_form.code,
        &oauth_request.subject,
        &oauth_request,
        &authorization_server,
    )
    .await?;

    // `oauth_complete` has already bound the token response's `sub` claim to
    // the DID the flow began for, so the stored subject is authoritative.
    let did = oauth_request.subject.clone();

    let document = did_document_storage.get_document_by_did(&did).await?;

    let document = document.ok_or(OAuthCallbackError::NoDIDDocumentFound)?;

    // Format the response with OAuth tokens and DPoP key information
    let response_body = format!(
        "OAuth Callback Completed Successfully\n\
            =====================================\n\
            DID: {}\n\
            Issuer: {}\n\
            Access Token: {}\n\
            Refresh Token: {}\n\
            Token Type: {}\n\
            Expires In: {} seconds\n\
            Scope: {}\n\
            Subject: {}\n\
            Private DPoP Key: {}\n",
        document.id,
        oauth_request.issuer,
        token_response.access_token,
        token_response
            .refresh_token
            .clone()
            .unwrap_or_else(|| "N/A".to_string()),
        token_response.token_type,
        token_response.expires_in,
        token_response.scope,
        token_response.sub.clone().unwrap_or("unknown".to_string()),
        private_dpop_key_data
    );

    Ok((
        StatusCode::OK,
        [("Content-Type", "text/plain")],
        response_body,
    )
        .into_response())
}
