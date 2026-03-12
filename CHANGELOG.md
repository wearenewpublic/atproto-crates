# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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