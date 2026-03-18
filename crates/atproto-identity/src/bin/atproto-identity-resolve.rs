//! CLI tool for resolving AT Protocol identities.
//!
//! This tool can resolve both handles and DIDs to their identity documents.

use anyhow::Result;
use atproto_identity::{
    config::{CertificateBundles, DnsNameservers, default_env, optional_env, version},
    plc::query as plc_query,
    resolve::{HickoryDnsResolver, InputType, parse_input, resolve_subject},
    web::query as web_query,
};
use clap::Parser;

/// AT Protocol Identity Resolution CLI
#[derive(Parser)]
#[command(
    name = "atproto-identity-resolve",
    version,
    about = "Resolve AT Protocol handles and DIDs to their canonical DID identifiers",
    long_about = "
A command-line tool for resolving AT Protocol handles and DIDs to their canonical
DID identifiers and optionally retrieving their full DID documents. Supports
both did:plc and did:web methods with configurable DNS and HTTP settings.

ENVIRONMENT VARIABLES:
  PLC_HOSTNAME         PLC directory hostname (default: \"plc.directory\")
  USER_AGENT           HTTP user agent string (default: auto-generated)
  CERTIFICATE_BUNDLES  Colon-separated paths to additional CA certificates
  DNS_NAMESERVERS      Comma-separated DNS nameserver addresses

EXAMPLES:
  # Basic handle resolution:
  atproto-identity-resolve alice.bsky.social

  # Resolve multiple subjects:
  atproto-identity-resolve alice.bsky.social bob.example.com

  # Get DID document:
  atproto-identity-resolve --did-document alice.bsky.social
"
)]
struct Args {
    /// One or more AT Protocol handles or DIDs to resolve
    subjects: Vec<String>,

    /// Additionally fetch and display the full DID document
    #[arg(long)]
    did_document: bool,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    for subject in args.subjects {
        let resolved_did = resolve_subject(&http_client, &dns_resolver, &subject).await;
        let resolved_did = match resolved_did {
            Ok(value) => value,
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        if !args.did_document {
            println!("{resolved_did}");
            continue;
        }

        let did_document: Result<_, anyhow::Error> = match parse_input(&resolved_did) {
            Ok(InputType::Plc(did)) => plc_query(&http_client, &plc_hostname, &did)
                .await
                .map_err(Into::into),
            Ok(InputType::Web(did)) => web_query(&http_client, &did).await.map_err(Into::into),
            Ok(InputType::WebVH(did)) => atproto_identity::webvh::query(&http_client, &did)
                .await
                .map_err(Into::into),
            Ok(InputType::Handle(_)) => {
                eprintln!("error: subject resolved to handle");
                continue;
            }
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        };

        match did_document {
            Ok(value) => {
                println!("{}", serde_json::to_string_pretty(&value)?)
            }
            Err(err) => {
                eprintln!("{err}");
                continue;
            }
        }
    }

    Ok(())
}
