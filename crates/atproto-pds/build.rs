//! Build script: exposes `BUILD_REV` to the binary so we can stamp it into
//! User-Agent headers, `/xrpc/_health`, OAuth metadata ETag seeds, and asset
//! cache busting (per).
//!
//! Strategy: try `git rev-parse --short=10 HEAD` first; on any failure (no
//! git repo, no git binary, etc.) fall back to a build timestamp.
//!
//! Also embeds the vendored lexicon corpus. `lexicons/` is walked and a table
//! of `(nsid, json)` pairs generated, backed by `include_str!` so the schemas
//! live in the binary rather than being read from a filesystem layout the
//! server does not control. The NSID comes from the path --
//! `app/bsky/feed/post.json` is `app.bsky.feed.post` -- which matches the `id`
//! field in every one of the vendored documents; reading the JSON here would
//! mean a serde dependency in the build graph to learn what the layout already
//! states.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let rev = git_rev().unwrap_or_else(build_timestamp);
    println!("cargo:rustc-env=BUILD_REV={}", rev);

    generate_lexicon_table();
    strip_portal_stylesheet();
}

/// Write `src/http/portal.css` into `OUT_DIR` with its comments removed.
///
/// The portal inlines its stylesheet into every response and there is no
/// cross-page CSS cache, so every byte is paid on every page view. Roughly half
/// of `portal.css` is commentary explaining why the values are what they are --
/// worth keeping in the source, not worth sending to a browser. Stripping here
/// rather than by hand means the explanation and the shipped bytes cannot drift.
fn strip_portal_stylesheet() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let source = manifest.join("src/http/portal.css");
    println!("cargo:rerun-if-changed=src/http/portal.css");

    let css = std::fs::read_to_string(&source).expect("read the portal stylesheet");
    let stripped = strip_css_comments(&css);

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set")).join("portal.css");
    std::fs::write(&out, stripped).expect("write the stripped portal stylesheet");
}

/// Remove `/* ... */` comments and per-line padding from a stylesheet.
///
/// Verified by the unit tests on `STYLESHEET` in `src/http/portal.rs`, which
/// assert against the file this actually produces. Tests written here would
/// not run: `cargo test` does not execute a build script's test module.
///
/// String-aware, so a `/*` inside a `url("...")` or `content: "..."` is left
/// alone. Line structure is kept -- this is a comment stripper, not a minifier,
/// and the remaining newlines cost little against the clarity of a stylesheet
/// that can still be read in a browser's devtools.
///
/// Every delimiter it looks for is ASCII, but the text between them need not be
/// (`content: "\u{2191}"` is legal CSS), so this copies string slices rather
/// than bytes and never splits a character.
fn strip_css_comments(css: &str) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len());
    let mut i = 0;
    // Start of the run of retained text not yet copied into `out`.
    let mut run = 0;
    let mut quote: Option<u8> = None;

    while i < bytes.len() {
        match quote {
            // Inside a string: skip escapes so a `\"` does not close it, and
            // close on the matching quote. Nothing here is ever dropped.
            Some(q) => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    quote = None;
                }
                i += 1;
            }
            None => {
                if bytes[i] == b'"' || bytes[i] == b'\'' {
                    quote = Some(bytes[i]);
                    i += 1;
                } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    // Flush what preceded the comment, then skip to the closing
                    // delimiter -- or to the end, if it is unterminated.
                    out.push_str(&css[run..i]);
                    match css[i + 2..].find("*/") {
                        Some(end) => i += 2 + end + 2,
                        None => i = bytes.len(),
                    }
                    run = i;
                } else {
                    i += 1;
                }
            }
        }
    }
    out.push_str(&css[run..]);

    // Drop the indentation the comments were aligned to, and the blank lines
    // they leave behind.
    let mut result = String::with_capacity(out.len());
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        result.push_str(trimmed);
        result.push('\n');
    }
    result
}

/// Walk `lexicons/` and write the `BUNDLED_LEXICONS` table into `OUT_DIR`.
fn generate_lexicon_table() {
    let manifest =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let root = manifest.join("lexicons");
    println!("cargo:rerun-if-changed=lexicons");

    let mut found = BTreeMap::new();
    collect_lexicons(&root, &root, &mut found);

    let mut generated = String::from(
        "// Generated by build.rs from the vendored `lexicons/` corpus. Do not edit.\n\
         /// Every bundled lexicon, as `(nsid, document json)`, sorted by NSID.\n\
         pub static BUNDLED_LEXICONS: &[(&str, &str)] = &[\n",
    );
    for (nsid, path) in &found {
        generated.push_str(&format!(
            "    ({nsid:?}, include_str!({:?})),\n",
            path.to_string_lossy()
        ));
    }
    generated.push_str("];\n");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set"))
        .join("bundled_lexicons.rs");
    std::fs::write(&out, generated).expect("write the generated lexicon table");
}

fn collect_lexicons(dir: &Path, root: &Path, out: &mut BTreeMap<String, PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_lexicons(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let nsid = rel
                .with_extension("")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(".");
            out.insert(nsid, path.clone());
        }
    }
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
