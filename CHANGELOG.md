# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed
- `Cargo.lock` was corrupt and no crate in the workspace built from a clean checkout. A bad merge
  concatenated two resolutions of the AWS SDK dependency subtree, leaving 35 duplicate `[[package]]`
  entries and an inconsistent `data-encoding` selection, so `cargo` refused to parse the file at all
  (`package 'aws-config' is specified twice in the lockfile`). Regenerated; 716 package entries
  down to 577. This shipped in `0.15.0-rc.1` because nothing ran a build.
- Removed `crates/atproto-space/benches/set_hash.rs`, which had not compiled since the set-hash
  rewrite: it declares no `[[bench]]` target, has no `criterion` dev-dependency, and imports
  `XorSha256SetHash` (renamed to `LtHash`) from `set_hash_ecmh` (never declared as a module). Its
  presence made `cargo clippy --workspace --all-targets` fail.

### Added
- Continuous integration at `.tangled/workflows/ci.yml`, running `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on every push
  to `main` and every pull request, with a recursive submodule checkout so the DASL CBOR compliance
  fixtures are actually present. Previously no workflow ran the test suite, and 13 `atproto-dasl`
  compliance cases failed on a missing fixture from a fresh clone.
- Known-answer conformance vectors from `bluesky-social/atproto-interop-tests` (CC-0, pinned at
  `056e574`), vendored at `tests/interop/`, with three harnesses:
  `crates/atproto-repo/tests/interop_mst.rs` (MST key heights, common prefixes, and commit root
  CIDs), `crates/atproto-dasl/tests/interop_data_model.rs` (canonical DAG-CBOR bytes and CIDs), and
  `crates/atproto-pds/tests/interop_firehose.rs` (frame headers against hand-decoded CBOR, the
  `#commit` body against the `subscribeRepos` lexicon, and the first end-to-end WebSocket test of
  the firehose). Every prior encoding test in the workspace was a round trip, which passes just as
  happily against a wrong encoding; these are the first that compare against an external oracle.
  Vectors that do not pass yet are enumerated in each harness's `KNOWN_FAILURES` table with the
  defect that explains them, and are required to keep failing until it is fixed.
- `atproto_repo::mst::common_prefix_len` is now re-exported alongside `compare_keys` and
  `key_height`.

## [0.15.0-rc.1] - 2026-07-27
### Security
- `atproto-lexicon`: bounded `ref`/`union` traversal during data validation. A `union` def that
  referenced itself, or an acyclic chain of ~2500 `union` defs (~105 KB of lexicon JSON), drove
  unbounded recursion on the same `DataValue` and overflowed the stack. A stack overflow aborts the
  whole process with `SIGABRT`, so a single unauthenticated request killed every in-flight request on
  the server; `catch_unwind` cannot catch it. `validate_union` now honours `visited_refs` and
  `ValidateFlags::STRICT_RECURSIVE_VALIDATION` the same way `validate_ref` always did, and
  `ValidationLimits` adds a recursion depth cap (`max_ref_depth`, default 256) plus a total traversal
  step budget (`max_ref_steps` + `max_ref_steps_per_node`). Reported by Lexicon Garden.
- `atproto-lexicon`: bounded the `union` fan-out search. When a value carried no `$type`, every ref
  was tried against the same value and each nested union retried all of its own refs, so a 978-byte
  lexicon plus a 34-byte request body consumed ~25 s of CPU. The step budget above bounds it; the
  same payload now fails in ~39 ms.
- `atproto-dasl`: DRISL decoding no longer panics on a hostile collection header. A 9-byte input
  declaring an array of 2^63 elements reached `Vec::reserve` with the wire-declared count and panicked
  with `capacity overflow` under both `DecodeConfig::default()` and `non_strict()`. Pre-allocation is
  now clamped, a declared count exceeding the remaining input is rejected
  (`DecodeError::CollectionLengthExceedsInput`), and `max_array_elements` / `max_map_entries` default
  to 2^24 instead of `0` (unlimited).
- `atproto-dasl`: CAR block reads no longer allocate from an unvalidated wire length. A 10-byte input
  declaring a 2^63-byte block panicked with `capacity overflow`. `CarBlock::read_from` /
  `from_bytes` and the async block reader now enforce `LimitsConfig::max_block_size` *before*
  allocating and read incrementally via `Vec::try_reserve`. `CarReader::next_block` was affected too:
  it checked `max_block_size` only *after* `read_block` had already allocated, so the documented
  limit provided no protection.
- `atproto-identity`: hardened the SSRF surface around DID and handle hosts. `is_valid_hostname`
  accepted integer, hexadecimal and octal IP forms (`2852039166`, `0xA9FEA9FE`,
  `0250.0376.0250.0376`, and empty-hex labels such as `0x7f.0x.0x.0x1`), all of which resolvers and
  `reqwest` normalize back into addresses like `169.254.169.254` and `127.0.0.1`. Neither
  `did_web_to_url` nor `did_webvh_to_url` validated the host at all before building a URL. Hosts are
  now rejected syntactically and cross-checked against the `url` parser, a shared method-aware
  `did_host()` helper avoids consumers re-deriving host extraction (`did:webvh` places the SCID
  first), and `Document::pds_endpoints()` documents that `serviceEndpoint` is attacker-controlled
  alongside a new validating accessor.
- `atproto-oauth`: `oauth_complete` now requires an expected subject and rejects a `TokenResponse`
  whose `sub` does not match it. Previously `sub` was never bound to the DID the flow began for, so
  an attacker running their own authorization server could return any victim's DID and have the
  relying app mint a session as that victim. JWT verification now requires an `exp` claim, since a
  token omitting it never expired.

### Changed
- **Breaking** `atproto-oauth`: `oauth_complete` takes an additional expected-subject argument.
  Callers must pass the DID the authorization flow started for.
- **Breaking** `atproto-oauth`: `oauth_refresh` keeps its signature, but now binds the returned `sub`
  to the `document` it was called with and rejects a mismatch. A refresh whose authorization server
  returns a different subject now fails where it previously succeeded. Because the signature is
  unchanged, this one does not surface as a compile error.
- **Breaking** `atproto-lexicon`: data validation now bounds `ref`/`union` traversal, so a document
  needing more than `DEFAULT_MAX_REF_DEPTH` (256) nested ref/union hops — or more traversal steps
  than `DEFAULT_MAX_REF_STEPS` (100,000) plus `DEFAULT_MAX_REF_STEPS_PER_NODE` (16) per value node
  allows — is now rejected where it previously validated. Ordinary records, including legitimately
  self-referential ones such as threaded replies, are unaffected. Tune the bounds with
  `ValidationLimits` through the new `validate_record_with_limits` and matching
  `validate_query_params_with_limits` / `validate_procedure_params_with_limits` /
  `validate_procedure_input_with_limits` entry points (and their `_with_schema_and_limits` variants).
- **Breaking** `atproto-identity`: `did_web_to_url` and `did_webvh_to_url` now return an error for
  hosts that are address literals or fall under the reserved suffixes `.local`, `.internal`,
  `.localhost` and `.arpa`. This blocks `metadata.google.internal`, but also rejects
  cluster-internal names such as `pds.svc.cluster.local` and `host.docker.internal` that previously
  produced a URL — deployments publishing a PDS under a cluster-internal name need a routable
  hostname. Bare `localhost` (with or without a port) is unaffected. `did:web` path segments are
  also restricted to `[A-Za-z0-9._-]`, which rejects the percent-encoded segments the DID Core
  `idchar` grammar permits.
- **Breaking** `atproto-dasl`: `CarBlock::read_from` and `CarBlock::from_bytes` are now bounded by
  `LimitsConfig::default()` (1 MB) instead of being unlimited. Use `read_from_with_limits` /
  `from_bytes_with_limits` to widen. Callers going through `CarReader` are unaffected.
- **Breaking** `atproto-dasl`: `DecodeConfig::max_array_elements` and `max_map_entries` default to
  2^24 rather than `0` (unlimited). Because `serde` encodes a plain `Vec<u8>` as a CBOR array, a
  `Vec<u8>` larger than 16 MiB no longer round-trips under the defaults; use `serde_bytes` /
  `Ipld::Bytes`, or `with_unlimited_array_elements()`.

## [0.15.0-alpha.2] - 2026-06-26
### Changed
- Re-aligned permissioned-data Spaces (`atproto-space`, `atproto-pds`) to the published [0016 "Permissioned Data"](https://github.com/bluesky-social/proposals/blob/06d439e6be9004a086f392008e41acddd1a444ff/0016-permissioned-data/README.md) draft, taking the spec as the source of truth over the reference implementation: LtHash set-hash commits, the delegation-token / space-credential JWT shapes, the OAuth `space:` scope grammar, and the `com.atproto.simplespace` mint-policy / `appAccess` / `managingApp` configuration.
- Unified space-declaration resolution across the OAuth consent screen and the `space:` scope gate behind a shared resolver.

### Removed
- Permissioned-data member-sync machinery (`getMemberState` / `getMemberOplog` / `notifyMembership`); member-list management (`addMember` / `removeMember` / `listMembers`) is retained.

## [0.15.0-alpha.1] - 2026-05-09
### Added
- AT Protocol PDS + permissioned-data Spaces (alpha-ready) — new `atproto-pds` and `atproto-space` crates introducing a Personal Data Server implementation and permissioned-data Space primitives (commits, credentials, recon, set hashing, members, repo, storage).
- `atproto-repo`: inductive verification (`src/repo/inductive.rs`) and MST diffing (`src/mst/diff.rs`).

## [0.14.6] - 2026-04-22
### Added
- `atpmcp login <identifier> [password]` subcommand mirroring the atpxrpc login UX. Resolves the identifier, creates a session via `com.atproto.server.createSession`, and upserts the account into the shared `~/.config/atpxrpc/config.json` so credentials are usable by both binaries.

## [0.14.5] - 2026-04-02
### Fixed
- Fixed panproto strategies bypassing `$type` rewriting for nested union types

### Changed
- Updated dependency versions: criterion 0.8, compact_str 0.9, data-encoding 2.10, sha2 0.11, tokio 1.50, unicode-segmentation 1.13, proptest 1.11

## [0.14.4] - 2026-04-02
### Added
- `transmogrify_record` tool to atpmcp MCP server
- `transmogrify_record` function in atproto-lexicon library
- Scenario triggers, parameter examples, and error guidance to atpmcp tool descriptions
- `lenient_optional_format` datetime module and malformed `createdAt` test
- Default values to `alt` and `role` fields in Media type
- Unified `atpdid` CLI tool for DID management (key generate/inspect, resolve, PLC audit/create/update/submit, did:webvh verify/create/update)
- did:webvh v1.0 resolution with full spec compliance
- DiskRepository with `from_car` support

### Changed
- Made lexicon main definition optional per AT Protocol spec
- Moved transmogrify and compatibility into atproto-lexicon library
- Replaced deprecated `plugin-types` CSP directive with `media-src`

## [0.14.3] - 2026-03-12
### Added
- Unknown variant to LocationOrRef and EventLocation enums for calendar events
- `--version` flag to atpmcp CLI

## [0.14.2] - 2026-03-09
### Added
- `atptid` CLI tool for generating and parsing AT Protocol Timestamp Identifiers
- `get_lexicon` tool to atpmcp MCP server for fetching lexicon schema records
- `invoke_xrpc` tool to atpmcp MCP server
- `generate_tid` tool to atpmcp MCP server
- `validate_xrpc` tool to atpmcp MCP server

### Changed
- Updated release workflow and README to include atptid and atpcid binaries

## [0.14.1] - 2026-03-08
### Added
- `atpxrpc` CLI tool for persistent XRPC session management with proxy support
- `--out` argument for atpxrpc proxy and base commands for output control
- `--bytes` and `--manual` proxy flags to atpxrpc CLI
- 5 new tools to atpmcp MCP server

### Changed
- Updated GitHub Actions workflow to build atpxrpc and atpmcp release binaries
- Updated README to reflect full Rust crates workspace

## [0.14.0] - 2026-02-21

## [0.13.0] - 2025-09-21
### Added
- New `atproto-lexicon` crate for AT Protocol lexicon resolution and validation
- `atproto-lexicon-resolve` CLI tool for resolving lexicons via DNS and XRPC
- Comprehensive lexicon reference extraction and recursive resolution capabilities
- Full support for NSID validation and DNS-based lexicon discovery

### Changed
- Updated Rust minimum version requirement to 1.90
- Enhanced error management across atproto-lexicon crate
- Improved project documentation with atproto-lexicon integration

### Improved
- Code formatting and linting across all crates
- Updated README documentation to include atproto-lexicon references

## [0.12.0] - 2025-09-17
### Added
- Unified `Auth` enum for authentication methods in `atproto-client` supporting None, DPoP, and AppPassword authentication
- `com.atproto.server.deleteSession` support in `atproto-client` with AppPassword authentication requirement
- `com.atproto.identity.resolveHandle` support in `atproto-client` for handle resolution
- OAuth client credentials token flow in `atproto-oauth-aip` for service-to-service authentication
- `session_exchange_with_options` function with optional `access_token_type` and `subject` parameters
- Documentation for all Auth enum variants and authentication methods

### Changed
- Updated all XRPC client methods to use the unified `Auth` enum pattern instead of optional DPoP parameters
- Made `refresh_token` field optional in `TokenResponse` structure as not all token responses include refresh tokens
- Refactored `session_exchange` to use `session_exchange_with_options` internally with backward compatibility
- Enhanced error handling with new `InvalidAuthMethod` error variant in client errors

### Fixed
- Removed unused imports and cleaned up code after Auth enum refactoring
- Fixed doctest failures from outdated function signatures
- Resolved compilation errors from type mismatches in error handling

## [0.11.3] - 2025-09-03
### Added
- OAuth scope types, parsing, and utilities for the `atproto-oauth` crate
- Comprehensive support for AT Protocol OAuth 2.0 scope handling

## [0.11.2] - 2025-08-20
### Fixed
- Fixed `atproto-jetstream` consumer to correctly send multiple query parameters for `wantedCollections` and `wantedDids` instead of joining them with commas

## [0.11.1] - 2025-08-20
### Fixed
- Base64 decoding in `atproto-record` now accepts both padded and unpadded base64 strings for better compatibility with various AT Protocol implementations
- Updated `signature::verify` function to only accept `{"$bytes": "..."}` format for signatures

### Added
- Comprehensive unit tests for record signature creation and verification across P-256, P-384, and K-256 curves
- Unit test for deserializing real-world RSVP records with signatures

### Changed
- Made `create` and `verify` functions in the signature module synchronous (removed `async`) as they don't perform async operations

## [0.11.0] - 2025-08-18
### Added
- Document builder functionality for AT Protocol documents
- New `atproto-oauth-service-token` CLI tool for OAuth service token management
- Community lexicon support for extended AT Protocol functionality

### Changed
- Updated record signature and verification to align with current AT Protocol proposal
- Removed `issuedAt` field as required signature field
- Streamlined Debug derive implementations across crates

### Improved
- Removed unused dependencies for smaller build size
- Release preparation and project maintenance

## [0.10.0] - 2025-07-28
### Changed
- Version release 0.10.0 with updated dependencies and stability improvements

## [0.9.7] - 2025-07-13
### Changed
- Updated `list_records` method to support optional DPoP authentication for enhanced security

## [0.9.6] - 2025-07-11
### Improved
- Enhanced DID method validation for did-method-plc and did-method-web
- Updated validation examples and documentation for better clarity

## [0.9.5] - 2025-07-09
### Changed
- Refactored OAuth components to support blind OAuth workflows for enhanced security and privacy

## [0.9.4] - 2025-07-09
### Fixed
- Fixed issue where login_hint was always sent in OAuth initialization

## [0.9.3] - 2025-07-06
### Added
- `delete_record` method to atproto-client for removing AT Protocol records

## [0.9.2] - 2025-06-30
### Added
- Optional `zeroize` feature for secure memory handling of sensitive cryptographic data

## [0.9.1] - 2025-06-29
### Changed
- Updated dependency versions for improved compatibility

## [0.9.0] - 2025-06-29
### Security
- Explicitly forbid unsafe code usage across all crates for enhanced security

### Changed
- Reduced debug information exposure in production builds
- Improved sensitive data handling and reduced exposure
- Cleaned up tracing instrumentation for better performance

### Improved
- Enhanced documentation across all crates and modules

## [0.8.1] - 2025-06-21
### Improved
- Enhanced module documentation across all crates with comprehensive usage examples
- Standardized error handling with consistent naming and unique identifiers
- Updated OAuth AIP crate with detailed API documentation and security considerations
- Improved project documentation and README files across all crates

### Fixed
- Code formatting compliance with rustfmt standards
- Consistent error message formatting and numbering

## [0.8.0] - 2025-06-18
### Added
- OAuth Authorization Initiation Protocol (AIP) crate for AT Protocol OAuth workflows

## [0.7.0] - 2025-06-16
### Added
- DPoP validation support for enhanced security
- Embedded JWKS in OAuth metadata
- P-384 cryptographic curve support and JWK conversion
- App password creation method to atproto-client
- Client authentication binaries for app password and session management

### Changed
- Standardized CLI tools with clap for consistent command-line interfaces
- Enhanced security measures across client tools
- Streamlined documentation structure

### Fixed
- Error cleanup and improved error handling throughout codebase
- Removed unused issuer field from DPoP implementation

## [0.6.0] - 2025-06-08
### Added
- AT Protocol event streaming via atproto-jetstream crate with WebSocket support

## [0.5.0] - 2025-06-05
### Added
- XRPC service helpers and framework crate
- PORT environment variable support for service configuration
- Enhanced DPoP client support for query and procedure methods

### Changed
- Improved tracing and logging throughout the codebase
- Updated Docker configuration to include additional binaries

### Fixed
- Removed hardcoded OAuth metadata field values
- Added missing crate metadata fields

## [0.4.0] - 2025-06-03
### Added
- Initial OAuth client implementation
- Basic AT Protocol identity resolution
- Core DID document handling
- Cryptographic key operations for P-256 curves

[0.15.0-rc.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-rc.1
[0.15.0-alpha.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.2
[0.15.0-alpha.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.1
[0.14.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.6
[0.14.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.5
[0.14.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.4
[0.14.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.3
[0.14.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.2
[0.14.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.1
[0.14.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.0
[0.13.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.13.0
[0.12.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.12.0
[0.11.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.3
[0.11.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.2
[0.11.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.1
[0.11.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.0
[0.10.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.10.0
[0.9.7]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.7
[0.9.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.6
[0.9.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.5
[0.9.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.4
[0.9.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.3
[0.9.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.2
[0.9.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.1
[0.9.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.0
[0.8.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.1
[0.8.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.0
[0.7.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.7.0
[0.6.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.6.0
[0.5.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.5.0
[0.4.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.4.0