//! `atproto-pds-admin` — operational CLI for a running `atproto-pds`
//! deployment.
//!
//! Wraps the JSON `com.atproto.admin.*` and `com.atproto.server.*` XRPC
//! endpoints with Basic-auth-bearing HTTP calls. Configure with
//! `--base-url` (default `http://127.0.0.1:4800`) and `--admin-password`
//! (or `PDS_ADMIN_PASSWORD`).
//!
//! Modeled on `bluesky-social/pds`'s `pdsadmin.sh` script.

use anyhow::{Context, Result};
use atproto_pds::{BUILD_REV, CRATE_VERSION, user_agent};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64STD};
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "atproto-pds-admin",
    version,
    about = "Admin CLI for atproto-pds"
)]
struct Args {
    /// Base URL of the running PDS (default `http://127.0.0.1:4800`).
    #[arg(
        long,
        env = "PDS_ADMIN_BASE_URL",
        default_value = "http://127.0.0.1:4800"
    )]
    base_url: String,

    /// Admin password (Basic-auth secret). Required for every command except
    /// `version`.
    #[arg(long, env = "PDS_ADMIN_PASSWORD")]
    admin_password: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the running CLI's version + build rev.
    Version,

    /// Invite-code subcommands.
    #[command(subcommand)]
    Invite(InviteCmd),

    /// Account-management subcommands.
    #[command(subcommand)]
    Account(AccountCmd),

    /// Takedown subcommands.
    #[command(subcommand)]
    Takedown(TakedownCmd),
}

#[derive(Subcommand, Debug)]
enum InviteCmd {
    /// List all invite codes (optionally filter by issuer DID).
    List {
        /// Filter to codes created by this DID.
        #[arg(long)]
        created_by: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AccountCmd {
    /// Show a single account's row by DID or handle.
    Info {
        /// DID or handle.
        target: String,
    },
    /// Search accounts by handle/email substring.
    Search {
        /// Substring to match against handle/email (case-insensitive).
        query: String,
        /// Page size (default 25).
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
    /// Hard-delete an account (state → `deleted`). Irreversible.
    Delete {
        /// DID to delete.
        did: String,
        /// Skip the y/N prompt.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TakedownCmd {
    /// Apply a takedown to an account (state → `takendown`).
    Apply {
        /// DID to take down.
        did: String,
    },
    /// Lift a takedown (state → `active`).
    Lift {
        /// DID to lift.
        did: String,
    },
    /// Show current takedown status of a DID.
    Status {
        /// DID to inspect.
        did: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Command::Version = &args.command {
        println!("atproto-pds-admin {CRATE_VERSION} (build {BUILD_REV})");
        println!("user-agent: {}", user_agent());
        return Ok(());
    }

    let password = args
        .admin_password
        .as_deref()
        .context("--admin-password (or PDS_ADMIN_PASSWORD) is required")?;
    let client = AdminClient::new(args.base_url.clone(), password.to_string());

    match args.command {
        Command::Version => unreachable!("handled above"),
        Command::Invite(InviteCmd::List { created_by }) => {
            let path = match created_by {
                Some(did) => format!(
                    "/xrpc/com.atproto.admin.getInviteCodes?createdBy={}",
                    urlencode(&did)
                ),
                None => "/xrpc/com.atproto.admin.getInviteCodes".to_string(),
            };
            let body = client.get(&path).await?;
            print_pretty(&body);
        }
        Command::Account(AccountCmd::Info { target }) => {
            let path = format!(
                "/xrpc/com.atproto.admin.getAccountInfo?did={}",
                urlencode(&target)
            );
            let body = client.get(&path).await?;
            print_pretty(&body);
        }
        Command::Account(AccountCmd::Search { query, limit }) => {
            let path = format!(
                "/xrpc/com.atproto.admin.searchAccounts?email={}&limit={}",
                urlencode(&query),
                limit
            );
            let body = client.get(&path).await?;
            print_pretty(&body);
        }
        Command::Account(AccountCmd::Delete { did, force }) => {
            if !force {
                eprintln!("This will hard-delete account `{did}`. Continue? [y/N]");
                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf)?;
                if !buf.trim().eq_ignore_ascii_case("y") {
                    eprintln!("aborted");
                    std::process::exit(1);
                }
            }
            let body = client
                .post(
                    "/xrpc/com.atproto.admin.deleteAccount",
                    &serde_json::json!({"did": did}),
                )
                .await?;
            print_pretty(&body);
        }
        Command::Takedown(TakedownCmd::Apply { did }) => {
            let body = client
                .post(
                    "/xrpc/com.atproto.admin.updateSubjectStatus",
                    &serde_json::json!({"did": did, "state": "takendown"}),
                )
                .await?;
            print_pretty(&body);
        }
        Command::Takedown(TakedownCmd::Lift { did }) => {
            let body = client
                .post(
                    "/xrpc/com.atproto.admin.updateSubjectStatus",
                    &serde_json::json!({"did": did, "state": "active"}),
                )
                .await?;
            print_pretty(&body);
        }
        Command::Takedown(TakedownCmd::Status { did }) => {
            let path = format!(
                "/xrpc/com.atproto.admin.getSubjectStatus?did={}",
                urlencode(&did)
            );
            let body = client.get(&path).await?;
            print_pretty(&body);
        }
    }
    Ok(())
}

struct AdminClient {
    base: String,
    auth: String,
    client: reqwest::Client,
}

impl AdminClient {
    fn new(base: String, password: String) -> Self {
        let auth = format!("Basic {}", B64STD.encode(format!("admin:{password}")));
        Self {
            base,
            auth,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        check_response(resp).await
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body)?)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        check_response(resp).await
    }
}

async fn check_response(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("server returned {status}: {text}");
    }
    if text.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

fn print_pretty(body: &Value) {
    match serde_json::to_string_pretty(body) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{body}"),
    }
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
