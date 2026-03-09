//! AT Protocol XRPC client with persistent session management.
//!
//! Provides a streamlined CLI for making XRPC calls using stored
//! app password sessions with automatic token refresh.

mod config;
mod errors;

use anyhow::Result;
use atproto_client::client::{
    AppPasswordAuth, get_apppassword_json_with_headers, post_apppassword_bytes_with_headers,
    post_apppassword_json_with_headers,
};
use atproto_client::com::atproto::server::{create_session, refresh_session};
use atproto_identity::{
    config::{CertificateBundles, DnsNameservers, default_env, optional_env, version},
    plc,
    resolve::{HickoryDnsResolver, resolve_subject},
    url::build_url,
    web,
};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use config::{Account, load_config, save_config};
use errors::XrpcCliError;
use reqwest::header::{CONTENT_TYPE, HeaderMap};
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

/// AT Protocol XRPC client with persistent session management.
#[derive(Parser)]
#[command(
    name = "atpxrpc",
    version,
    about = "Make AT Protocol XRPC calls with persistent session management",
    args_conflicts_with_subcommands = true,
    long_about = "
A command-line tool for making XRPC calls to AT Protocol services.
Manages authentication sessions in a local config file, automatically
refreshing expired tokens as needed.

SUBCOMMANDS:
  login                Log in with a handle and app password
  logout               Remove a stored account
  accounts             List all stored accounts

XRPC CALLS (default when no subcommand matches):
  atpxrpc [--handle <handle>] <nsid> [key=value ...]

  Query (GET):   Pass key=value pairs as positional arguments.
  Procedure (POST): Pipe JSON to stdin.
  Bytes (POST):  Use --bytes to send raw bytes from stdin.

EXAMPLES:
  atpxrpc login alice.bsky.social xxxx-xxxx-xxxx-xxxx
  atpxrpc com.atproto.repo.describeRepo repo=alice.bsky.social
  atpxrpc com.atproto.repo.getRecord repo=did:plc:... collection=app.bsky.feed.post rkey=abc
  jo repo=did:plc:... collection=app.bsky.feed.post record[text]=Hello | atpxrpc com.atproto.repo.createRecord
  atpxrpc --handle bob.bsky.social com.atproto.repo.listRecords repo=did:plc:...
  cat image.png | atpxrpc --bytes --content-type image/png com.atproto.repo.uploadBlob

ENVIRONMENT VARIABLES:
  ATPXRPC_CONFIG       Override config file path
  PLC_HOSTNAME         PLC directory hostname (default: plc.directory)
  USER_AGENT           HTTP user agent string
  CERTIFICATE_BUNDLES  Additional CA certificate bundles
  DNS_NAMESERVERS      Custom DNS nameserver addresses
"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Handle of the account to use for the request
    #[arg(long, global = true)]
    handle: Option<String>,

    /// XRPC method NSID (e.g., com.atproto.repo.getRecord)
    nsid: Option<String>,

    /// Write response body to a file instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,

    /// Send raw bytes from stdin instead of JSON (forces POST)
    #[arg(long)]
    bytes: bool,

    /// Content-Type header for --bytes mode
    #[arg(long, default_value = "application/octet-stream")]
    content_type: String,

    /// Query parameters as key=value pairs
    params: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Log in with a handle and app password, storing the session
    Login {
        /// Handle or DID to authenticate as
        identifier: String,
        /// App password (prompted securely if not provided)
        #[arg(env = "ATPROTO_PASSWORD")]
        password: Option<String>,
        /// Print session details as JSON to stdout after login
        #[arg(long)]
        show: bool,
    },
    /// Remove a stored account from the config
    Logout {
        /// Handle of the account to remove
        handle: String,
    },
    /// List all stored accounts
    Accounts,
    /// Refresh the access token for an account if expired
    CheckAuth {
        /// Handle of the account to check (optional if only one account)
        handle: Option<String>,
    },
    /// Send a proxied XRPC request through the PDS using the atproto-proxy header
    Proxy {
        /// Service audience in DID#serviceId format (e.g., did:web:api.bsky.app#bsky_fg)
        audience: String,
        /// XRPC method NSID (e.g., app.bsky.feed.getAuthorFeed)
        nsid: String,
        /// Write response body to a file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Send raw bytes from stdin instead of JSON (forces POST)
        #[arg(long)]
        bytes: bool,
        /// Content-Type header for --bytes mode
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
        /// Use manual service auth instead of the atproto-proxy header.
        /// Gets a service auth token via getServiceAuth, resolves the
        /// audience DID, and sends the request directly to the target service.
        #[arg(long)]
        manual: bool,
        /// Query parameters as key=value pairs (for GET), or pipe JSON to stdin (for POST)
        params: Vec<String>,
    },
}

/// Builds the shared HTTP client from environment configuration.
fn build_http_client() -> Result<reqwest::Client> {
    let certificate_bundles: CertificateBundles = optional_env("CERTIFICATE_BUNDLES").try_into()?;
    let default_user_agent = format!(
        "atpxrpc ({}; +https://tangled.org/ngerakines.me/atproto-crates)",
        version()?
    );
    let user_agent = default_env("USER_AGENT", &default_user_agent);

    let mut client_builder = reqwest::Client::builder();
    for ca_certificate in certificate_bundles.as_ref() {
        let cert = std::fs::read(ca_certificate)?;
        let cert = reqwest::Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
    }
    client_builder = client_builder.user_agent(user_agent);
    Ok(client_builder.build()?)
}

/// Resolves an identifier to a DID and PDS endpoint.
async fn resolve_pds(
    http_client: &reqwest::Client,
    identifier: &str,
) -> Result<(String, String, String)> {
    let dns_nameservers: DnsNameservers = optional_env("DNS_NAMESERVERS").try_into()?;
    let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");
    let dns_resolver = HickoryDnsResolver::create_resolver(dns_nameservers.as_ref());

    let did = resolve_subject(http_client, &dns_resolver, identifier).await?;

    let document = if did.starts_with("did:plc:") {
        plc::query(http_client, &plc_hostname, &did).await?
    } else if did.starts_with("did:web:") {
        web::query(http_client, &did).await?
    } else {
        anyhow::bail!("Unsupported DID method: {}", did);
    };

    let pds_endpoints = document.pds_endpoints();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or_else(|| XrpcCliError::NoPdsEndpointFound { did: did.clone() })?
        .to_string();

    let handle = document
        .handles()
        .map(|h| h.to_string())
        .unwrap_or_else(|| identifier.to_string());

    Ok((did, pds_endpoint, handle))
}

/// Checks if an XRPC response indicates an expired token.
fn is_expired_token_error(response: &serde_json::Value) -> bool {
    response
        .get("error")
        .and_then(|v| v.as_str())
        .is_some_and(|e| e == "ExpiredToken")
}

/// Makes a single XRPC request using the given account credentials.
async fn make_request(
    http_client: &reqwest::Client,
    account: &Account,
    nsid: &str,
    is_procedure: bool,
    query_params: &[(String, String)],
    json_body: &Option<serde_json::Value>,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let app_auth = AppPasswordAuth {
        access_token: account.access_jwt.clone(),
    };

    if is_procedure {
        let body = json_body.clone().unwrap_or(serde_json::Value::Null);
        let url = build_url(
            &account.pds_endpoint,
            &format!("/xrpc/{}", nsid),
            std::iter::empty::<(&str, &str)>(),
        )?
        .to_string();
        post_apppassword_json_with_headers(http_client, &app_auth, &url, body, additional_headers)
            .await
    } else {
        let url = build_url(
            &account.pds_endpoint,
            &format!("/xrpc/{}", nsid),
            query_params.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )?
        .to_string();
        get_apppassword_json_with_headers(http_client, &app_auth, &url, additional_headers).await
    }
}

/// Makes a single XRPC bytes request using the given account credentials.
async fn make_bytes_request(
    http_client: &reqwest::Client,
    account: &Account,
    nsid: &str,
    payload: Bytes,
    additional_headers: &HeaderMap,
) -> Result<Bytes> {
    let app_auth = AppPasswordAuth {
        access_token: account.access_jwt.clone(),
    };
    let url = build_url(
        &account.pds_endpoint,
        &format!("/xrpc/{}", nsid),
        std::iter::empty::<(&str, &str)>(),
    )?
    .to_string();
    post_apppassword_bytes_with_headers(http_client, &app_auth, &url, payload, additional_headers)
        .await
}

/// Executes an XRPC bytes request with automatic session refresh.
///
/// Detects `ExpiredToken` errors by attempting to parse the raw response
/// bytes as JSON. AT Protocol errors are always JSON, so a non-JSON
/// response is treated as a successful result.
async fn execute_bytes_with_refresh(
    http_client: &reqwest::Client,
    account: &mut Account,
    nsid: &str,
    payload: Bytes,
    additional_headers: &HeaderMap,
) -> Result<Bytes> {
    let response = make_bytes_request(
        http_client,
        account,
        nsid,
        payload.clone(),
        additional_headers,
    )
    .await?;

    if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&response)
        && is_expired_token_error(&json_value)
    {
        eprintln!("Session expired, refreshing...");

        match refresh_session(http_client, &account.pds_endpoint, &account.refresh_jwt).await {
            Ok(refreshed) => {
                account.access_jwt = refreshed.access_jwt;
                account.refresh_jwt = refreshed.refresh_jwt;
                update_account_in_config(account)?;
                eprintln!("Session refreshed.");
            }
            Err(_) => {
                eprintln!("Refresh failed, re-authenticating...");
                let session = create_session(
                    http_client,
                    &account.pds_endpoint,
                    &account.handle,
                    &account.app_password,
                    None,
                )
                .await
                .map_err(|e| XrpcCliError::ReAuthFailed {
                    error: e.to_string(),
                })?;

                account.access_jwt = session.access_jwt;
                account.refresh_jwt = session.refresh_jwt;
                update_account_in_config(account)?;
                eprintln!("Re-authenticated.");
            }
        }

        return make_bytes_request(http_client, account, nsid, payload, additional_headers).await;
    }

    Ok(response)
}

/// Executes an XRPC request with automatic session refresh.
///
/// Strategy:
/// 1. Try with current access_jwt.
/// 2. On ExpiredToken, refresh using refresh_jwt.
/// 3. If refresh fails, re-authenticate with stored app_password.
/// 4. On any successful refresh/re-auth, update the config file.
/// 5. Retry the original request with new tokens.
async fn execute_with_refresh(
    http_client: &reqwest::Client,
    account: &mut Account,
    nsid: &str,
    is_procedure: bool,
    query_params: &[(String, String)],
    json_body: &Option<serde_json::Value>,
    additional_headers: &HeaderMap,
) -> Result<serde_json::Value> {
    let response = make_request(
        http_client,
        account,
        nsid,
        is_procedure,
        query_params,
        json_body,
        additional_headers,
    )
    .await?;

    if !is_expired_token_error(&response) {
        return Ok(response);
    }

    eprintln!("Session expired, refreshing...");

    match refresh_session(http_client, &account.pds_endpoint, &account.refresh_jwt).await {
        Ok(refreshed) => {
            account.access_jwt = refreshed.access_jwt;
            account.refresh_jwt = refreshed.refresh_jwt;
            update_account_in_config(account)?;
            eprintln!("Session refreshed.");
        }
        Err(_) => {
            eprintln!("Refresh failed, re-authenticating...");
            let session = create_session(
                http_client,
                &account.pds_endpoint,
                &account.handle,
                &account.app_password,
                None,
            )
            .await
            .map_err(|e| XrpcCliError::ReAuthFailed {
                error: e.to_string(),
            })?;

            account.access_jwt = session.access_jwt;
            account.refresh_jwt = session.refresh_jwt;
            update_account_in_config(account)?;
            eprintln!("Re-authenticated.");
        }
    }

    make_request(
        http_client,
        account,
        nsid,
        is_procedure,
        query_params,
        json_body,
        additional_headers,
    )
    .await
}

/// Updates a single account in the config file by matching on DID.
fn update_account_in_config(account: &Account) -> Result<()> {
    let mut config = load_config()?;
    if let Some(existing) = config.accounts.iter_mut().find(|a| a.did == account.did) {
        *existing = account.clone();
    }
    save_config(&config)?;
    Ok(())
}

/// Writes the JSON response to a file or stdout.
fn write_response(response: &serde_json::Value, out: &Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(response)?;
    if let Some(path) = out {
        std::fs::write(path, json.as_bytes())?;
    } else {
        println!("{json}");
    }
    Ok(())
}

/// Writes a bytes response to a file or stdout.
///
/// Attempts to parse the response as JSON for pretty-printed display.
/// Falls back to writing raw bytes if the response is not valid JSON.
fn write_bytes_response(response: &Bytes, out: &Option<PathBuf>) -> Result<()> {
    if let Some(path) = out {
        std::fs::write(path, response)?;
    } else if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(response) {
        println!("{}", serde_json::to_string_pretty(&json_value)?);
    } else {
        io::stdout().write_all(response)?;
    }
    Ok(())
}

/// Selects the account to use for an XRPC call.
fn select_account<'a>(
    config: &'a mut config::Config,
    handle: &Option<String>,
) -> Result<&'a mut Account> {
    if config.accounts.is_empty() {
        return Err(XrpcCliError::NoAccountsConfigured.into());
    }

    if let Some(handle) = handle {
        let idx = config
            .accounts
            .iter()
            .position(|a| a.handle == *handle)
            .ok_or_else(|| XrpcCliError::AccountNotFound {
                handle: handle.clone(),
            })?;
        Ok(&mut config.accounts[idx])
    } else if config.accounts.len() == 1 {
        Ok(&mut config.accounts[0])
    } else {
        Err(XrpcCliError::AmbiguousAccount.into())
    }
}

/// Handles the `login` subcommand.
async fn handle_login(identifier: &str, password: Option<String>, show: bool) -> Result<()> {
    let password = if let Some(p) = password {
        SecretString::new(p.into())
    } else {
        eprint!("Enter app password: ");
        io::stderr().flush()?;
        let p = read_password()?;
        if p.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        SecretString::new(p.into())
    };

    let http_client = build_http_client()?;

    eprintln!("Resolving {}...", identifier);
    let (did, pds_endpoint, handle) = resolve_pds(&http_client, identifier).await?;
    eprintln!("Resolved to {} ({})", did, pds_endpoint);

    eprintln!("Creating session...");
    let session = create_session(
        &http_client,
        &pds_endpoint,
        identifier,
        password.expose_secret(),
        None,
    )
    .await?;

    let account = Account {
        handle: handle.clone(),
        did: session.did.clone(),
        pds_endpoint: pds_endpoint.clone(),
        app_password: password.expose_secret().to_string(),
        access_jwt: session.access_jwt.clone(),
        refresh_jwt: session.refresh_jwt.clone(),
    };

    let mut config = load_config()?;
    if let Some(existing) = config.accounts.iter_mut().find(|a| a.did == account.did) {
        *existing = account;
    } else {
        config.accounts.push(account);
    }
    save_config(&config)?;

    eprintln!("Logged in as {} ({})", handle, session.did);

    if show {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "did": session.did,
                "pds": pds_endpoint,
                "accessJwt": session.access_jwt,
                "refreshJwt": session.refresh_jwt,
            }))?
        );
    }

    Ok(())
}

/// Handles the `logout` subcommand.
fn handle_logout(handle: &str) -> Result<()> {
    let mut config = load_config()?;
    let before = config.accounts.len();
    config.accounts.retain(|a| a.handle != handle);
    if config.accounts.len() == before {
        return Err(XrpcCliError::AccountNotFound {
            handle: handle.to_string(),
        }
        .into());
    }
    save_config(&config)?;
    eprintln!("Logged out {}", handle);
    Ok(())
}

/// Handles the `accounts` subcommand.
fn handle_accounts() -> Result<()> {
    let config = load_config()?;
    if config.accounts.is_empty() {
        eprintln!("No accounts configured.");
        return Ok(());
    }
    for account in &config.accounts {
        println!(
            "{}\t{}\t{}",
            account.handle, account.did, account.pds_endpoint
        );
    }
    Ok(())
}

/// Handles the `check-auth` subcommand.
///
/// Calls `com.atproto.server.getSession` to test the current access token.
/// If expired, refreshes via refresh token or re-authenticates with the
/// stored app password, then persists the updated tokens.
async fn handle_check_auth(handle: &Option<String>) -> Result<()> {
    let mut config = load_config()?;
    let account = select_account(&mut config, handle)?;

    let http_client = build_http_client()?;

    let response = make_request(
        &http_client,
        account,
        "com.atproto.server.getSession",
        false,
        &[],
        &None,
        &HeaderMap::default(),
    )
    .await?;

    if is_expired_token_error(&response) {
        eprintln!("Session expired, refreshing...");

        match refresh_session(&http_client, &account.pds_endpoint, &account.refresh_jwt).await {
            Ok(refreshed) => {
                account.access_jwt = refreshed.access_jwt;
                account.refresh_jwt = refreshed.refresh_jwt;
                update_account_in_config(account)?;
                eprintln!("Session refreshed.");
            }
            Err(_) => {
                eprintln!("Refresh failed, re-authenticating...");
                let session = create_session(
                    &http_client,
                    &account.pds_endpoint,
                    &account.handle,
                    &account.app_password,
                    None,
                )
                .await
                .map_err(|e| XrpcCliError::ReAuthFailed {
                    error: e.to_string(),
                })?;

                account.access_jwt = session.access_jwt;
                account.refresh_jwt = session.refresh_jwt;
                update_account_in_config(account)?;
                eprintln!("Re-authenticated.");
            }
        }
    } else {
        eprintln!("Session is valid.");
    }

    Ok(())
}

/// Handles an XRPC call (no subcommand).
async fn handle_xrpc_call(
    handle: &Option<String>,
    nsid: &str,
    params: &[String],
    out: &Option<PathBuf>,
    bytes_mode: bool,
    content_type: &str,
) -> Result<()> {
    let mut config = load_config()?;
    let account = select_account(&mut config, handle)?;

    if bytes_mode {
        let mut raw_input = Vec::new();
        io::stdin().read_to_end(&mut raw_input).map_err(|e| {
            XrpcCliError::StdinBytesReadFailed {
                error: e.to_string(),
            }
        })?;
        let payload = Bytes::from(raw_input);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, content_type.parse()?);

        let http_client = build_http_client()?;
        let response =
            execute_bytes_with_refresh(&http_client, account, nsid, payload, &headers).await?;

        return write_bytes_response(&response, out);
    }

    let stdin_is_pipe = !io::stdin().is_terminal();

    let (is_procedure, json_body) = if stdin_is_pipe {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        let value: serde_json::Value =
            serde_json::from_str(&input).map_err(|e| XrpcCliError::StdinJsonParseFailed {
                error: e.to_string(),
            })?;
        (true, Some(value))
    } else {
        (false, None)
    };

    let query_params: Vec<(String, String)> = if !is_procedure {
        params
            .iter()
            .filter_map(|arg| {
                let (key, value) = arg.split_once('=')?;
                Some((key.to_string(), value.to_string()))
            })
            .collect()
    } else {
        vec![]
    };

    let http_client = build_http_client()?;
    let response = execute_with_refresh(
        &http_client,
        account,
        nsid,
        is_procedure,
        &query_params,
        &json_body,
        &HeaderMap::default(),
    )
    .await?;

    write_response(&response, out)?;
    Ok(())
}

/// Resolves the target service endpoint from an audience string.
///
/// Parses the audience as `DID#serviceId`, resolves the DID document,
/// and returns the service endpoint URL matching the service ID fragment.
/// If no fragment is provided, returns the first PDS endpoint.
async fn resolve_service_endpoint(
    http_client: &reqwest::Client,
    audience: &str,
) -> Result<(String, String)> {
    let (did, service_id) = if let Some((did, fragment)) = audience.split_once('#') {
        (did.to_string(), Some(format!("#{}", fragment)))
    } else {
        (audience.to_string(), None)
    };

    let dns_nameservers: DnsNameservers = optional_env("DNS_NAMESERVERS").try_into()?;
    let plc_hostname = default_env("PLC_HOSTNAME", "plc.directory");
    let dns_resolver = HickoryDnsResolver::create_resolver(dns_nameservers.as_ref());
    let resolved_did = resolve_subject(http_client, &dns_resolver, &did).await?;

    let document = if resolved_did.starts_with("did:plc:") {
        plc::query(http_client, &plc_hostname, &resolved_did).await?
    } else if resolved_did.starts_with("did:web:") {
        web::query(http_client, &resolved_did).await?
    } else {
        anyhow::bail!("Unsupported DID method: {}", resolved_did);
    };

    if let Some(ref sid) = service_id {
        for service in &document.service {
            if service.id == *sid {
                return Ok((did, service.service_endpoint.clone()));
            }
        }
        Err(XrpcCliError::NoServiceEndpointFound {
            did,
            service_id: sid.clone(),
        }
        .into())
    } else {
        let pds_endpoints = document.pds_endpoints();
        let endpoint = pds_endpoints
            .first()
            .ok_or_else(|| XrpcCliError::NoPdsEndpointFound { did: did.clone() })?
            .to_string();
        Ok((did, endpoint))
    }
}

/// Gets a service auth token from the user's PDS.
///
/// Calls `com.atproto.server.getServiceAuth` with the audience DID
/// and XRPC method, returning the signed JWT token.
async fn get_service_auth_token(
    http_client: &reqwest::Client,
    account: &mut Account,
    aud: &str,
    lxm: &str,
) -> Result<String> {
    let query_params = vec![
        ("aud".to_string(), aud.to_string()),
        ("lxm".to_string(), lxm.to_string()),
    ];
    let response = execute_with_refresh(
        http_client,
        account,
        "com.atproto.server.getServiceAuth",
        false,
        &query_params,
        &None,
        &HeaderMap::default(),
    )
    .await?;

    response
        .get("token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            XrpcCliError::ServiceAuthFailed {
                error: format!("Unexpected response: {}", response),
            }
            .into()
        })
}

/// Handles the `proxy` subcommand.
///
/// Sends an XRPC request through the user's PDS with the `atproto-proxy`
/// header set, enabling inter-service authentication. The PDS forwards the
/// request to the target service identified by the audience parameter.
///
/// With `--manual`, bypasses the PDS proxy mechanism and instead gets a
/// service auth token via `getServiceAuth`, resolves the audience DID to
/// find the target service endpoint, and sends the request directly.
#[allow(clippy::too_many_arguments)]
async fn handle_proxy(
    handle: &Option<String>,
    audience: &str,
    nsid: &str,
    params: &[String],
    out: &Option<PathBuf>,
    bytes_mode: bool,
    content_type: &str,
    manual: bool,
) -> Result<()> {
    let mut config = load_config()?;
    let account = select_account(&mut config, handle)?;
    let http_client = build_http_client()?;

    if manual {
        // Extract the DID portion (before #fragment) for the service auth audience
        let aud_did = audience.split_once('#').map_or(audience, |(did, _)| did);

        // Step 1: Get a service auth token from the user's PDS
        eprintln!("Getting service auth token for {}...", aud_did);
        let token = get_service_auth_token(&http_client, account, aud_did, nsid).await?;

        // Step 2: Resolve the audience DID to find the target service endpoint
        eprintln!("Resolving service endpoint for {}...", audience);
        let (_did, service_endpoint) = resolve_service_endpoint(&http_client, audience).await?;
        eprintln!("Target endpoint: {}", service_endpoint);

        // Step 3: Make the request directly to the target service
        let target_auth = AppPasswordAuth {
            access_token: token,
        };

        if bytes_mode {
            let mut raw_input = Vec::new();
            io::stdin().read_to_end(&mut raw_input).map_err(|e| {
                XrpcCliError::StdinBytesReadFailed {
                    error: e.to_string(),
                }
            })?;
            let payload = Bytes::from(raw_input);

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, content_type.parse()?);

            let url = build_url(
                &service_endpoint,
                &format!("/xrpc/{}", nsid),
                std::iter::empty::<(&str, &str)>(),
            )?
            .to_string();
            let response = post_apppassword_bytes_with_headers(
                &http_client,
                &target_auth,
                &url,
                payload,
                &headers,
            )
            .await?;

            return write_bytes_response(&response, out);
        }

        let stdin_is_pipe = !io::stdin().is_terminal();

        let (is_procedure, json_body) = if stdin_is_pipe {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let value: serde_json::Value =
                serde_json::from_str(&input).map_err(|e| XrpcCliError::StdinJsonParseFailed {
                    error: e.to_string(),
                })?;
            (true, Some(value))
        } else {
            (false, None)
        };

        let response = if is_procedure {
            let body = json_body.unwrap_or(serde_json::Value::Null);
            let url = build_url(
                &service_endpoint,
                &format!("/xrpc/{}", nsid),
                std::iter::empty::<(&str, &str)>(),
            )?
            .to_string();
            post_apppassword_json_with_headers(
                &http_client,
                &target_auth,
                &url,
                body,
                &HeaderMap::default(),
            )
            .await?
        } else {
            let query_params: Vec<(String, String)> = params
                .iter()
                .filter_map(|arg| {
                    let (key, value) = arg.split_once('=')?;
                    Some((key.to_string(), value.to_string()))
                })
                .collect();
            let url = build_url(
                &service_endpoint,
                &format!("/xrpc/{}", nsid),
                query_params.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            )?
            .to_string();
            get_apppassword_json_with_headers(
                &http_client,
                &target_auth,
                &url,
                &HeaderMap::default(),
            )
            .await?
        };

        write_response(&response, out)?;
        return Ok(());
    }

    if bytes_mode {
        let mut raw_input = Vec::new();
        io::stdin().read_to_end(&mut raw_input).map_err(|e| {
            XrpcCliError::StdinBytesReadFailed {
                error: e.to_string(),
            }
        })?;
        let payload = Bytes::from(raw_input);

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("atproto-proxy"),
            reqwest::header::HeaderValue::from_str(audience)?,
        );
        headers.insert(CONTENT_TYPE, content_type.parse()?);

        let response =
            execute_bytes_with_refresh(&http_client, account, nsid, payload, &headers).await?;

        return write_bytes_response(&response, out);
    }

    let stdin_is_pipe = !io::stdin().is_terminal();

    let (is_procedure, json_body) = if stdin_is_pipe {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        let value: serde_json::Value =
            serde_json::from_str(&input).map_err(|e| XrpcCliError::StdinJsonParseFailed {
                error: e.to_string(),
            })?;
        (true, Some(value))
    } else {
        (false, None)
    };

    let query_params: Vec<(String, String)> = if !is_procedure {
        params
            .iter()
            .filter_map(|arg| {
                let (key, value) = arg.split_once('=')?;
                Some((key.to_string(), value.to_string()))
            })
            .collect()
    } else {
        vec![]
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("atproto-proxy"),
        reqwest::header::HeaderValue::from_str(audience)?,
    );

    let response = execute_with_refresh(
        &http_client,
        account,
        nsid,
        is_procedure,
        &query_params,
        &json_body,
        &headers,
    )
    .await?;

    write_response(&response, out)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Commands::Login {
            identifier,
            password,
            show,
        }) => handle_login(&identifier, password, show).await,
        Some(Commands::Logout { handle }) => handle_logout(&handle),
        Some(Commands::Accounts) => handle_accounts(),
        Some(Commands::CheckAuth { handle }) => handle_check_auth(&handle).await,
        Some(Commands::Proxy {
            audience,
            nsid,
            out,
            bytes: bytes_mode,
            content_type,
            manual,
            params,
        }) => {
            handle_proxy(
                &args.handle,
                &audience,
                &nsid,
                &params,
                &out,
                bytes_mode,
                &content_type,
                manual,
            )
            .await
        }
        None => match args.nsid {
            Some(nsid) => {
                handle_xrpc_call(
                    &args.handle,
                    &nsid,
                    &args.params,
                    &args.out,
                    args.bytes,
                    &args.content_type,
                )
                .await
            }
            None => {
                eprintln!("Error: an XRPC method NSID or subcommand is required.");
                eprintln!("Run 'atpxrpc --help' for usage information.");
                std::process::exit(1);
            }
        },
    }
}
