//! Configuration file management for atpxrpc.
//!
//! Handles reading and writing the persistent config file that stores
//! authenticated account sessions at `~/.config/atpxrpc/config.json`.

use crate::errors::XrpcCliError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent configuration containing authenticated accounts.
#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    /// List of authenticated accounts.
    pub accounts: Vec<Account>,
}

/// A stored account with session credentials.
#[derive(Serialize, Deserialize, Clone)]
pub struct Account {
    /// The account handle (e.g., "alice.bsky.social").
    pub handle: String,
    /// The resolved DID for the account.
    pub did: String,
    /// The PDS endpoint URL.
    pub pds_endpoint: String,
    /// The app password used for re-authentication.
    pub app_password: String,
    /// The current JWT access token.
    pub access_jwt: String,
    /// The current JWT refresh token.
    pub refresh_jwt: String,
}

/// Returns the path to the config file.
///
/// Checks `ATPXRPC_CONFIG` env var first, then falls back to
/// `~/.config/atpxrpc/config.json` via `dirs::config_dir()`.
pub fn config_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("ATPXRPC_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    let config_dir = dirs::config_dir().ok_or(XrpcCliError::ConfigDirNotFound)?;
    Ok(config_dir.join("atpxrpc").join("config.json"))
}

/// Loads the config from disk.
///
/// Returns a default empty config if the file doesn't exist.
pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = std::fs::read_to_string(&path).map_err(|_| XrpcCliError::ConfigReadFailed {
        path: path.display().to_string(),
    })?;
    let config: Config =
        serde_json::from_str(&content).map_err(|_| XrpcCliError::ConfigReadFailed {
            path: path.display().to_string(),
        })?;
    Ok(config)
}

/// Saves the config to disk, creating parent directories as needed.
///
/// Sets file permissions to 0600 on Unix to protect stored credentials.
pub fn save_config(config: &Config) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| XrpcCliError::ConfigWriteFailed {
            path: path.display().to_string(),
        })?;
    }
    let content =
        serde_json::to_string_pretty(config).map_err(|_| XrpcCliError::ConfigWriteFailed {
            path: path.display().to_string(),
        })?;
    std::fs::write(&path, content).map_err(|_| XrpcCliError::ConfigWriteFailed {
        path: path.display().to_string(),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|_| {
            XrpcCliError::ConfigWriteFailed {
                path: path.display().to_string(),
            }
        })?;
    }

    Ok(())
}
