//! The no-network build stays no-network.
//!
//! `atproto-record` exists partly so a consumer can import the AT Protocol
//! wire types. A consumer with a no-I/O rule -- a crate that wants to
//! property-test ordering and structure without a socket or a database --
//! could not, because importing a four-field struct pulled an HTTP client, an
//! async runtime and a DNS resolver in behind it. The answer downstream was to
//! redeclare the types, and a wire format maintained in two places is one that
//! will diverge.
//!
//! Features are additive, so nothing about the default build changes and
//! nothing here can be checked by compiling. The guarantee is a property of
//! the dependency graph, so the graph is what this asks about. Shelling out to
//! `cargo tree` is ugly and is the only thing that actually holds.

use std::process::Command;

/// The normal (non-dev, non-build) dependency graph of one package.
fn tree(package: &str, default_features: bool) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

    let mut command = Command::new(cargo);
    command.args([
        "tree",
        "--manifest-path",
        manifest,
        "--package",
        package,
        // Dev-dependencies are irrelevant: they are not in a consumer's graph.
        // Build-dependencies likewise.
        "--edges",
        "normal",
        // No network and no lockfile churn: this is an assertion about a
        // resolution that has already happened.
        "--offline",
        "--locked",
    ]);
    if !default_features {
        command.arg("--no-default-features");
    }

    let output = command.output().expect("cargo tree should run");

    assert!(
        output.status.success(),
        "cargo tree failed for {package}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("cargo tree output is utf-8")
}

/// Every crate whose presence means an I/O stack came along.
const NETWORK_CRATES: [&str; 3] = ["reqwest", "tokio", "hickory-resolver"];

/// Which of [`NETWORK_CRATES`] appear in a package's tree.
fn network_crates_in(package: &str, default_features: bool) -> Vec<&'static str> {
    let tree = tree(package, default_features);
    NETWORK_CRATES
        .into_iter()
        // `cargo tree` draws box-drawing characters before each name, so match
        // on the name followed by its version rather than on the whole line.
        .filter(|name| tree.contains(&format!("{name} v")))
        .collect()
}

fn assert_lean(package: &str) {
    let tree = tree(package, false);
    for crate_name in NETWORK_CRATES {
        // `cargo tree` draws box-drawing characters before each name, so match
        // on the name followed by its version rather than on the whole line.
        let found: Vec<&str> = tree
            .lines()
            .filter(|line| line.contains(&format!("{crate_name} v")))
            .collect();
        assert!(
            found.is_empty(),
            "{package} --no-default-features pulls in {crate_name}:\n{}",
            found.join("\n")
        );
    }
}

#[test]
fn the_lexicon_types_cost_no_network_stack() {
    assert_lean("atproto-record");
}

/// The same for the crate underneath it.
///
/// `atproto-record` can only be lean if `atproto-identity` is, since it
/// depends on it in every configuration: the AT-URI parser and several error
/// variants need it, and none of them needs its network half.
#[test]
fn the_identity_types_cost_no_network_stack() {
    assert_lean("atproto-identity");
}

/// The matcher can see what it is looking for.
///
/// Without this the two tests above pass just as well against a typo in a
/// crate name, a `cargo tree` invocation that silently returns nothing, or a
/// day when the whole workspace has no network dependencies left. The default
/// build has all three, so finding all three is the control.
#[test]
fn the_default_build_carries_all_three() {
    assert_eq!(
        network_crates_in("atproto-record", true),
        NETWORK_CRATES.to_vec(),
    );
}
