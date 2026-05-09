//! Build script: exposes `BUILD_REV` to the binary so we can stamp it into
//! User-Agent headers, `/xrpc/_health`, OAuth metadata ETag seeds, and asset
//! cache busting (per).
//!
//! Strategy: try `git rev-parse --short=10 HEAD` first; on any failure (no
//! git repo, no git binary, etc.) fall back to a build timestamp.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let rev = git_rev().unwrap_or_else(build_timestamp);
    println!("cargo:rustc-env=BUILD_REV={}", rev);
}

fn git_rev() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=10", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn build_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("ts{}", secs)
}
