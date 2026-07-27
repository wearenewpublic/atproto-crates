//! Minijinja template engine setup.
//!
//! Provides `reload_env` (filesystem auto-reload, dev) and `embed_env`
//! (compiled-in templates, release) builders plus a small set of filters. Space
//! records use `ats://` so the `ats://`-aware extractors use `atproto_space`
//! types, while the public plane keeps `at://` via `atproto_record`.

use std::str::FromStr;

use atproto_record::aturi::ATURI;
use atproto_space::types::RecordUri;
use chrono::DateTime;
use minijinja::Value;

/// Format an RFC3339 datetime string for display.
pub fn format_datetime(value: Value) -> Result<String, minijinja::Error> {
    if let Some(s) = value.as_str()
        && let Ok(dt) = DateTime::parse_from_rfc3339(s)
    {
        return Ok(dt.format("%Y-%m-%d %H:%M UTC").to_string());
    }
    Ok(value.to_string())
}

/// Extract the authority DID from an `at://` AT-URI.
pub fn extract_did(value: Value) -> Result<String, minijinja::Error> {
    if let Some(s) = value.as_str()
        && let Ok(parsed) = ATURI::from_str(s)
    {
        return Ok(parsed.authority);
    }
    Ok(String::new())
}

/// Extract the record key from an `at://` AT-URI.
pub fn extract_rkey(value: Value) -> Result<String, minijinja::Error> {
    if let Some(s) = value.as_str()
        && let Ok(parsed) = ATURI::from_str(s)
    {
        return Ok(parsed.record_key);
    }
    Ok(String::new())
}

/// Extract the author DID from an `ats://` space record URI.
pub fn extract_space_author(value: Value) -> Result<String, minijinja::Error> {
    if let Some(s) = value.as_str()
        && let Ok(parsed) = RecordUri::parse(s)
    {
        return Ok(parsed.author_did);
    }
    Ok(String::new())
}

/// Whether a string starts with a prefix.
pub fn starts_with(value: Value, prefix: String) -> bool {
    value
        .as_str()
        .map(|s| s.starts_with(&prefix))
        .unwrap_or(false)
}

/// Truncate a string to a maximum length with an ellipsis.
pub fn truncate(
    value: Value,
    kwargs: minijinja::value::Kwargs,
) -> Result<String, minijinja::Error> {
    let max_len: usize = kwargs.get::<Option<usize>>("length")?.unwrap_or(255);
    let s = value.as_str().unwrap_or_default();
    if s.len() <= max_len {
        Ok(s.to_string())
    } else {
        Ok(format!("{}…", &s[..max_len.saturating_sub(1)]))
    }
}

#[cfg(all(feature = "reload", not(feature = "embed")))]
pub mod reload_env {
    //! Filesystem auto-reloading environment (development).
    use std::path::PathBuf;

    use minijinja::{Environment, path_loader};
    use minijinja_autoreload::AutoReloader;

    /// Build an auto-reloading minijinja environment.
    pub fn build_env(http_external: &str) -> AutoReloader {
        let http_external = http_external.to_string();
        AutoReloader::new(move |notifier| {
            let template_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
            let mut env = Environment::new();
            env.set_trim_blocks(true);
            env.set_lstrip_blocks(true);
            env.add_global("base", format!("https://{}", http_external));
            env.add_global("build_rev", env!("BUILD_REV"));
            env.add_filter("format_datetime", super::format_datetime);
            env.add_filter("extract_did", super::extract_did);
            env.add_filter("extract_rkey", super::extract_rkey);
            env.add_filter("extract_space_author", super::extract_space_author);
            env.add_filter("starts_with", super::starts_with);
            env.add_filter("truncate", super::truncate);
            env.set_loader(path_loader(&template_path));
            notifier.set_fast_reload(true);
            notifier.watch_path(&template_path, true);
            Ok(env)
        })
    }
}

#[cfg(feature = "embed")]
pub mod embed_env {
    //! Compiled-in environment (release).
    use minijinja::Environment;

    /// Build an embedded minijinja environment from compiled templates.
    pub fn build_env(http_external: String) -> Environment<'static> {
        let mut env = Environment::new();
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.add_global("base", format!("https://{}", http_external));
        env.add_global("build_rev", env!("BUILD_REV"));
        env.add_filter("format_datetime", super::format_datetime);
        env.add_filter("extract_did", super::extract_did);
        env.add_filter("extract_rkey", super::extract_rkey);
        env.add_filter("extract_space_author", super::extract_space_author);
        env.add_filter("starts_with", super::starts_with);
        env.add_filter("truncate", super::truncate);
        minijinja_embed::load_templates!(&mut env);
        env
    }
}
