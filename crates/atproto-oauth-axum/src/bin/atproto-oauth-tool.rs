//! # AT Protocol OAuth CLI Tool
//!
//! Command-line tool for managing AT Protocol OAuth authentication flows.
//! Provides functionality to initiate OAuth login flows and refresh access tokens
//! for AT Protocol services.
//!
//! ## Commands
//!
//! - `login <private_signing_key> <subject>`: Start OAuth login flow
//! - `refresh <private_signing_key> <subject> <private_dpop_key> <refresh_token>`: Refresh OAuth tokens
//!
//! ## Features
//!
//! - Complete OAuth 2.0 authorization code flow with PKCE
//! - DPoP (Demonstration of Proof-of-Possession) token support
//! - AT Protocol identity resolution and DID document management
//! - OAuth server endpoints for client metadata and callback handling
//! - Support for both `did:plc` and `did:web` identity methods
//!
//! ## Environment Variables
//!
//! - `EXTERNAL_BASE`: External hostname for OAuth endpoints (required)
//! - `PORT`: HTTP server port (default: 8080)
//! - `PLC_HOSTNAME`: PLC directory hostname (default: plc.directory)
//! - `USER_AGENT`: HTTP User-Agent header (auto-generated)
//! - `DNS_NAMESERVERS`: Custom DNS nameservers (optional)
//! - `CERTIFICATE_BUNDLES`: Additional CA certificates (optional)

use anyhow::Result;
use async_trait::async_trait;
use atproto_identity::{
    config::{CertificateBundles, DnsNameservers, default_env, optional_env, require_env, version},
    key::{KeyData, KeyResolver, KeyType, generate_key, identify_key, to_public},
    storage_lru::LruDidDocumentStorage,
    traits::DidDocumentStorage,
};

#[cfg(feature = "hickory-dns")]
use atproto_identity::resolve::HickoryDnsResolver;
use atproto_identity::resolve::IdentityResolver;
use atproto_identity::resolve::InnerIdentityResolver;
use atproto_identity::resolve::SharedIdentityResolver;
use atproto_oauth::{
    pkce,
    resources::pds_resources,
    storage::OAuthRequestStorage,
    storage_lru::LruOAuthRequestStorage,
    workflow::{OAuthClient, OAuthRequest, OAuthRequestState, oauth_init, oauth_refresh},
};
use atproto_oauth_axum::errors::OAuthLoginError;
use atproto_oauth_axum::{handle_complete::handle_oauth_callback, handle_jwks::handle_oauth_jwks};
use atproto_oauth_axum::{handler_metadata::handle_oauth_metadata, state::OAuthClientConfig};
use axum::{Router, extract::FromRef, routing::get};
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rand::distr::{Alphanumeric, SampleString};
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    num::NonZeroUsize,
    ops::Deref,
    sync::Arc,
};

#[derive(Clone)]
pub struct SimpleKeyResolver {
    keys: HashMap<String, KeyData>,
}

impl Default for SimpleKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleKeyResolver {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

#[async_trait]
impl KeyResolver for SimpleKeyResolver {
    async fn resolve(&self, key_id: &str) -> anyhow::Result<KeyData> {
        self.keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Key not found: {}", key_id))
    }
}

pub struct InnerWebContext {
    pub http_client: reqwest::Client,
    pub identity_resolver: Arc<dyn IdentityResolver>,
    pub oauth_client_config: OAuthClientConfig,
    pub oauth_storage: Arc<dyn OAuthRequestStorage + Send + Sync>,
    pub document_storage: Arc<dyn DidDocumentStorage + Send + Sync>,
    pub key_resolver: Arc<dyn KeyResolver + Send + Sync>,
}

#[derive(Clone, FromRef)]
pub struct WebContext(pub Arc<InnerWebContext>);

impl Deref for WebContext {
    type Target = InnerWebContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRef<WebContext> for OAuthClientConfig {
    fn from_ref(context: &WebContext) -> Self {
        context.0.oauth_client_config.clone()
    }
}

impl FromRef<WebContext> for reqwest::Client {
    fn from_ref(context: &WebContext) -> Self {
        context.0.http_client.clone()
    }
}

impl FromRef<WebContext> for Arc<dyn OAuthRequestStorage> {
    fn from_ref(context: &WebContext) -> Self {
        context.0.oauth_storage.clone()
    }
}

impl FromRef<WebContext> for Arc<dyn DidDocumentStorage> {
    fn from_ref(context: &WebContext) -> Self {
        context.0.document_storage.clone()
    }
}

impl FromRef<WebContext> for Arc<dyn KeyResolver> {
    fn from_ref(context: &WebContext) -> Self {
        context.0.key_resolver.clone()
    }
}

impl FromRef<WebContext> for Arc<dyn IdentityResolver> {
    fn from_ref(context: &WebContext) -> Self {
        context.0.identity_resolver.clone()
    }
}

/// AT Protocol OAuth Tool
#[derive(Parser)]
#[command(
    name = "atproto-oauth-tool",
    version,
    about = "Manage AT Protocol OAuth authentication flows",
    long_about = "
A command-line tool for managing AT Protocol OAuth authentication flows.
Provides functionality to initiate OAuth login flows and refresh access tokens
for AT Protocol services.

FEATURES:
  - Complete OAuth 2.0 authorization code flow with PKCE
  - DPoP (Demonstration of Proof-of-Possession) token support
  - AT Protocol identity resolution and DID document management
  - OAuth server endpoints for client metadata and callback handling
  - Support for both did:plc and did:web identity methods

ENVIRONMENT VARIABLES:
  EXTERNAL_BASE        External hostname for OAuth endpoints (required)
  PORT                HTTP server port (default: 8080)
  PLC_HOSTNAME        PLC directory hostname (default: plc.directory)
  USER_AGENT          HTTP User-Agent header (auto-generated)
  DNS_NAMESERVERS     Custom DNS nameservers (optional)
  CERTIFICATE_BUNDLES Additional CA certificates (optional)
"
)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start OAuth login flow
    Login {
        /// OAuth subject identifier
        subject: String,
    },
    /// Refresh OAuth tokens
    Refresh {
        /// OAuth subject identifier
        subject: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle secure credential loading based on command
    let (subcommand, private_signing_key, subject, private_dpop_key, refresh_token) = match &args
        .command
    {
        Commands::Login { subject } => {
            let signing_key = load_secret_from_env_or_prompt("ATPROTO_SIGNING_KEY", "signing key")?;
            ("login", signing_key, subject.clone(), None, None)
        }
        Commands::Refresh { subject } => {
            let signing_key = load_secret_from_env_or_prompt("ATPROTO_SIGNING_KEY", "signing key")?;
            let dpop_key = load_secret_from_env_or_prompt("ATPROTO_DPOP_KEY", "DPoP key")?;
            let token =
                load_secret_string_from_env_or_prompt("ATPROTO_REFRESH_TOKEN", "refresh token")?;
            (
                "refresh",
                signing_key,
                subject.clone(),
                Some(dpop_key),
                Some(token),
            )
        }
    };

    // Log the selected command (without sensitive data)
    println!(
        "Starting OAuth {} flow for subject: {}",
        subcommand, subject
    );
    if private_dpop_key.is_some() {
        println!("DPoP key loaded from secure source");
    }
    if refresh_token.is_some() {
        println!("Refresh token loaded from secure source");
    }

    let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");
    let certificate_bundles: CertificateBundles = optional_env("CERTIFICATE_BUNDLES").try_into()?;
    let default_user_agent = format!(
        "atproto-identity-rs ({}; +https://tangled.org/ngerakines.me/atproto-crates)",
        version()?
    );
    let user_agent = default_env("USER_AGENT", &default_user_agent);
    let dns_nameservers: DnsNameservers = optional_env("DNS_NAMESERVERS").try_into()?;

    let mut client_builder = reqwest::Client::builder();
    for ca_certificate in certificate_bundles.as_ref() {
        let cert = std::fs::read(ca_certificate)?;
        let cert = reqwest::Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder = client_builder.user_agent(user_agent);
    let http_client = client_builder.build()?;

    let dns_resolver = HickoryDnsResolver::create_resolver(dns_nameservers.as_ref());

    let external_base = require_env("EXTERNAL_BASE")?;
    let port = default_env("PORT", "8080");

    // Load signing keys for JWK generation
    let mut signing_keys = Vec::new();
    if subcommand == "login" {
        // For login command, include the provided signing key in the JWKS
        match identify_key(&private_signing_key) {
            Ok(key_data) => {
                signing_keys.push(key_data);
            }
            Err(e) => tracing::warn!(error = ?e, "Failed to parse signing key for JWKS"),
        }
    }

    let oauth_client_config = OAuthClientConfig {
        jwks_uri: Some(format!("https://{}/.well-known/jwks.json", &external_base)),
        redirect_uris: format!("https://{}/oauth/callback", &external_base),
        client_id: format!("https://{}/oauth/client-metadata.json", &external_base),
        signing_keys: signing_keys
            .iter()
            .filter_map(|value| to_public(value).ok())
            .collect(),
        scope: None,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        tos_uri: None,
        policy_uri: None,
    };

    let mut signing_key_storage = HashMap::new();

    for signing_key in &signing_keys {
        let public_signing_key_data = to_public(signing_key)?;

        let public_signing_key = public_signing_key_data.to_string();
        signing_key_storage.insert(public_signing_key, signing_key.clone());
    }

    let identity_resolver = Arc::new(SharedIdentityResolver(Arc::new(InnerIdentityResolver {
        dns_resolver: Arc::new(dns_resolver),
        http_client: http_client.clone(),
        plc_hostname: plc_hostname.clone(),
    })));

    let web_context = WebContext(Arc::new(InnerWebContext {
        http_client: http_client.clone(),
        identity_resolver: identity_resolver.clone(),
        oauth_client_config: oauth_client_config.clone(),
        oauth_storage: Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap())),
        document_storage: Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(255).unwrap())),
        key_resolver: Arc::new(SimpleKeyResolver {
            keys: signing_key_storage,
        }),
    }));

    let router = Router::new()
        .route("/oauth/client-metadata.json", get(handle_oauth_metadata))
        .route("/.well-known/jwks.json", get(handle_oauth_jwks))
        .route("/oauth/callback", get(handle_oauth_callback))
        .with_state(web_context.clone());

    let bind_address = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;

    // Start the web server in the background
    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("Server error: {}", e);
        }
    });

    println!("OAuth server started on http://0.0.0.0:{}", port);

    // Handle the login command
    if subcommand == "login" {
        handle_login_command(
            &http_client,
            identity_resolver.clone(),
            &private_signing_key,
            &subject,
            &external_base,
            &web_context.document_storage,
            &web_context.oauth_storage,
        )
        .await?;

        println!("\nServer is running to handle the OAuth callback...");
        println!("Press Ctrl+C to stop the server when done.");
    } else if subcommand == "refresh" {
        handle_refresh_command(
            &http_client,
            identity_resolver.clone(),
            &private_signing_key,
            &subject,
            &external_base,
            private_dpop_key.as_ref().unwrap(),
            refresh_token.as_ref().unwrap(),
            &web_context.document_storage,
        )
        .await?;

        println!("\nOAuth token refresh completed.");
    }

    // Keep the server running
    server_handle.await.unwrap();

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_login_command(
    http_client: &reqwest::Client,
    identity_resolver: Arc<dyn IdentityResolver>,
    private_signing_key: &str,
    subject: &str,
    external_base: &str,
    did_document_storage: &Arc<dyn DidDocumentStorage + Send + Sync>,
    oauth_request_storage: &Arc<dyn OAuthRequestStorage + Send + Sync>,
) -> Result<()> {
    println!("Resolving subject: {}", subject);

    let document = identity_resolver.resolve(subject).await?;

    did_document_storage
        .store_document(document.clone())
        .await?;

    println!("Retrieved DID document for: {}", document.id);

    // Get PDS endpoint from the DID document
    let pds_endpoints = document.pds_endpoints();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or(OAuthLoginError::NoPDSEndpointFound)?;

    println!("Using PDS endpoint: {}", pds_endpoint);

    // Get authorization server configuration
    let (_, authorization_server) = pds_resources(http_client, pds_endpoint)
        .await
        .map_err(|e| OAuthLoginError::PDSResourcesFailed { error: e.into() })?;

    println!("Authorization server: {}", authorization_server.issuer);

    // Generate OAuth security parameters
    let (pkce_verifier, code_challenge) = pkce::generate();
    let state = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let nonce = Alphanumeric.sample_string(&mut rand::rng(), 32);

    // Generate DPoP key
    let dpop_key = generate_key(KeyType::P256Private)
        .map_err(|e| OAuthLoginError::DPoPKeyGenerationFailed { error: e.into() })?;

    // Parse the private signing key
    let signing_key = identify_key(private_signing_key)
        .map_err(|e| OAuthLoginError::InvalidPrivateSigningKey { error: e.into() })?;

    // Create OAuth client configuration
    let oauth_client = OAuthClient {
        redirect_uri: format!("https://{}/oauth/callback", external_base),
        client_id: format!("https://{}/oauth/client-metadata.json", external_base),
        private_signing_key_data: signing_key.clone(),
    };

    // Create OAuth request state
    let oauth_request_state = OAuthRequestState {
        state: state.clone(),
        nonce: nonce.clone(),
        code_challenge,
        scope: "atproto transition:generic".to_string(),
    };

    println!("Initiating OAuth flow...");

    // Initiate OAuth flow
    let par_response = oauth_init(
        http_client,
        &oauth_client,
        &dpop_key,
        Some(subject),
        &authorization_server,
        &oauth_request_state,
    )
    .await
    .map_err(|e| OAuthLoginError::OAuthInitFailed { error: e.into() })?;

    // Store OAuth request state for callback handling
    let public_signing_key = to_public(&signing_key)
        .map_err(|e| OAuthLoginError::PublicKeyDerivationFailed { error: e.into() })?;

    let now = Utc::now();
    let oauth_request = OAuthRequest {
        oauth_state: state.clone(),
        issuer: authorization_server.issuer.clone(),
        authorization_server: authorization_server.issuer.clone(),
        nonce: nonce.clone(),
        pkce_verifier,
        signing_public_key: public_signing_key.to_string(),
        dpop_private_key: dpop_key.to_string(),
        created_at: now,
        expires_at: now + Duration::hours(1),
    };

    oauth_request_storage
        .insert_oauth_request(oauth_request)
        .await
        .map_err(|e| OAuthLoginError::OAuthRequestStorageFailed { error: e })?;

    // Compose the authorization URL
    let auth_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_server.authorization_endpoint,
        oauth_client.client_id,
        par_response.request_uri
    );

    println!("\nOAuth Authorization URL:");
    println!("{}\n", auth_url);
    println!("Please visit this URL in your browser to complete the OAuth flow.");
    println!(
        "The callback will be handled at: https://{}/oauth/callback",
        external_base
    );
    println!("OAuth state: {}", state);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_refresh_command(
    http_client: &reqwest::Client,
    identity_resolver: Arc<dyn IdentityResolver>,
    private_signing_key: &str,
    subject: &str,
    external_base: &str,
    private_dpop_key: &str,
    refresh_token: &SecretString,
    did_document_storage: &Arc<dyn DidDocumentStorage + Send + Sync>,
) -> Result<()> {
    println!("Resolving subject: {}", subject);

    let document = identity_resolver.resolve(subject).await?;

    did_document_storage
        .store_document(document.clone())
        .await?;

    println!("Retrieved DID document for: {}", document.id);

    // Get PDS endpoint from the DID document
    let pds_endpoints = document.pds_endpoints();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or(OAuthLoginError::NoPDSEndpointFound)?;

    println!("Using PDS endpoint: {}", pds_endpoint);

    // Parse the private signing key
    let signing_key = identify_key(private_signing_key)
        .map_err(|e| OAuthLoginError::InvalidPrivateSigningKey { error: e.into() })?;

    // Parse the DPoP private key
    let dpop_key = identify_key(private_dpop_key)
        .map_err(|e| OAuthLoginError::DPoPKeyGenerationFailed { error: e.into() })?;

    // Create OAuth client configuration
    let oauth_client = OAuthClient {
        redirect_uri: format!("https://{}/oauth/callback", external_base),
        client_id: format!("https://{}/oauth/client-metadata.json", external_base),
        private_signing_key_data: signing_key.clone(),
    };

    println!("Refreshing OAuth tokens...");

    // Refresh the tokens
    let token_response = oauth_refresh(
        http_client,
        &oauth_client,
        &dpop_key,
        refresh_token.expose_secret(),
        &document,
    )
    .await
    .map_err(|e| OAuthLoginError::OAuthInitFailed { error: e.into() })?;

    // Display the token response
    println!("\nOAuth Token Refresh Response:");
    println!("Access Token: {}", token_response.access_token);
    println!("Token Type: {}", token_response.token_type);
    println!(
        "Refresh Token: {}",
        token_response.refresh_token.as_deref().unwrap_or("N/A")
    );
    println!("Scope: {}", token_response.scope);
    println!("Expires In: {} seconds", token_response.expires_in);
    println!(
        "Subject: {}",
        token_response.sub.as_deref().unwrap_or("N/A")
    );
    println!("DPoP Key: {}", dpop_key);

    Ok(())
}

/// Load secret from environment variable or secure prompt
fn load_secret_from_env_or_prompt(env_var: &str, secret_type: &str) -> Result<String> {
    if let Ok(secret) = env::var(env_var) {
        Ok(secret)
    } else {
        print!("Enter {} content: ", secret_type);
        io::stdout().flush()?;
        let secret = read_password()?;
        if secret.is_empty() {
            anyhow::bail!("{} cannot be empty", secret_type);
        }
        Ok(secret)
    }
}

/// Load secret string from environment variable or secure prompt
fn load_secret_string_from_env_or_prompt(env_var: &str, secret_type: &str) -> Result<SecretString> {
    if let Ok(secret) = env::var(env_var) {
        Ok(SecretString::new(secret.into()))
    } else {
        print!("Enter {} content: ", secret_type);
        io::stdout().flush()?;
        let secret = read_password()?;
        if secret.is_empty() {
            anyhow::bail!("{} cannot be empty", secret_type);
        }
        Ok(SecretString::new(secret.into()))
    }
}
