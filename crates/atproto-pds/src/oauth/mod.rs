//! OAuth 2.1 Authorization Server: PAR + PKCE + DPoP + refresh-token rotation. Built atop `atproto-oauth` primitives.
//!
//! Surface:
//! - PAR endpoint (`/oauth/par`) — stores authorization-request state and
//!   returns a `request_uri` token (RFC 9126). Accepts inline parameters
//!   AND signed-request-object form per RFC 9101.
//! - Authorize endpoint (`/oauth/authorize`) — server-rendered consent page
//!   that the user POSTs through to issue an authorization code.
//! - Token endpoint (`/oauth/token`) — exchanges `authorization_code` or
//!   `refresh_token` for access+refresh JWT pair, DPoP-bound.
//! - Revoke endpoint (`/oauth/revoke`) — RFC 7009.
//! - JWKS endpoint (`/oauth/jwks`) — exposes the PDS's public signing key.
//! - Metadata endpoints — `/.well-known/oauth-authorization-server`,
//!   `/.well-known/oauth-protected-resource`.
//!
//! Friendly per-scope rendering on the consent page is closed; the
//! Askama-template refactor is documented in D-7.

pub mod authorize;
pub mod client_metadata;
pub mod consent;
pub mod dpop;
pub mod extract;
pub mod jwks;
pub mod metadata;
pub mod par;
pub mod permission_set;
pub mod revoke;
pub mod state;
pub mod token;

pub use authorize::{AuthorizeInput, AuthorizeResponse, authorize_handler};
pub use client_metadata::{
    ClientMetadata, ClientMetadataError, assert_redirect_uri_registered, resolve_client_metadata,
};
pub use consent::consent_page;
pub use dpop::{DPOP_HEADER, verify_dpop_proof};
pub use extract::JsonOrForm;
pub use jwks::jwks_handler;
pub use metadata::{
    AuthorizationServerMetadata, ProtectedResourceMetadata, oauth_authorization_server,
    oauth_protected_resource,
};
pub use par::{ParInput, ParResponse, par_handler};
pub use revoke::{RevokeForm, revoke_handler};
pub use state::{AuthorizationCode, OAuthRequest, OAuthState};
pub use token::{TokenInput, TokenResponse, token_handler};
