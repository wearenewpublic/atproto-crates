# Useful Prompts

## Find unecessary project dependencies

Analyze all of the project dependencies and identify any that are not necessary or could be reduced. Think very very hard.

## Review and ensure error correctness

Review all of the errors in the `atproto-jetstream` crate and ensure their names, messages, documentation, and usage are correct. Each error must have a globally unique identifier and error numbers must be ordered consistently. Think very very hard.

Review all of the errors and identify any that are unused. Think very very hard.

## Add missing documentation

Using `cargo check`, add documentation to things that are missing documentation to satisfy compiler warnings.

Document the `crates/atproto-oauth/src/pkce.rs` source file. Think very hard.

## Review and ensure README correctness

In the `atproto-record` crate, update project documentation and README files to ensure they are accurate and reflect current source code. Think very very hard.

## Module documentation

Write high level module documentation in the `path/to/file.rs` source file. Documentation should brief and specific. Think very hard about how to do this.

Write high level crate documentation in the `crates/atproto-oauth-axum/src/lib.rs` and `crates/atproto-oauth-dioxus/src/lib.rs` source files. Documentation should brief and specific. Think very hard about how to do this.

Update the high level module documentation in each of the source files in the `atproto-xrpcs` crates. Documentation should brief and specific. Think very hard about how to do this.

Update the `README.md` files in the `atproto-identity`, `atproto-record`, `atproto-oauth`, `atproto-oauth-axum`, `atproto-oauth-dioxus`, and `atproto-client` crates. Each `README.md` file should include a high level overview of what the crate provides and include a summary of each binary produced by the crate. Think very hard.

Write a project `README.md` file that describes the project as a library that supports ATProtocol identity record signing and verifying. Note that parts of this was extracted from the open sourced https://tangled.sh/@smokesignal.events/smokesignal project. This project is open source under the MIT license.

The `README.md` file should provide a high level overview of all of the project crates. It should also concisely reference the available binaries and provide a minimal example of how to use them.

Write a `README.md` file for the `atproto-oauth` crate. Use `crates/atproto-identity/README.md` and `crates/atproto-record/README.md` as references. Think really hard.

## Check and clippy

Using `cargo clippy`, satisfy warnings. Think very hard about how to do this.

Using `cargo build`, `cargo fmt`, `cargo check`, `cargo clippy`, and `cargo test` identity and resolve and warnings or errors. Work iteratively and think very hard.

## Cleanup and Check

Cleanup and prepare the project for release.

1. Review all of the errors in the project crates and ensure their names, messages, documentation, and usage are correct. Each error must have a globally unique identifier and error numbers must be ordered consistently.

2. Using `cargo build`, `cargo fmt`, `cargo check`, `cargo clippy`, and `cargo test` identity and resolve and warnings or errors.

3. Update the high level module documentation in each of the source files in the project crates. Documentation should brief and specific.

4. Update the `README.md` files in each of the project crates. Each `README.md` file should include a high level overview of what the crate provides and include a summary of each binary produced by the crate.

5. Update the `README.md` file in the root of the project that describes the project as collection of components used to create ATProtocol applications. Note that parts of this was extracted from the open sourced https://tangled.sh/@smokesignal.events/smokesignal project. This project is open source under the MIT license.

6. Ensure the Dockerfile is accurate and correct.

Avoid introducing new dependencies. Think very very hard.

## Release

Ensure all crates can be packaged and published.
