//! OAuth confidential-client (BFF) flow: client metadata + JWKS, PKCE/PAR
//! login init, code-exchange callback, stateless cookie refresh, logout, and
//! session extraction helpers.

pub mod callback;
pub mod login;
pub mod logout;
pub mod metadata;
pub mod refresh;
pub mod session;
