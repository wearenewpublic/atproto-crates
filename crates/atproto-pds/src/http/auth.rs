//! Unified access-token authentication for XRPC handlers.
//!
//! every authenticated XRPC must:
//!
//! 1. Verify the `Authorization: <scheme> <jwt>` header, where `<scheme>` is
//!    `Bearer` (RFC 6750) or `DPoP` (RFC 9449 §7.1). The scheme is not
//!    cosmetic: it declares whether the token is proof-of-possession bound,
//!    and it must agree with the token's own `cnf.jkt` claim.
//! 2. Accept either an app-password session (`typ=at-pp-access`) or an OAuth
//!    access token (`typ=at-oauth-access`). The two flavors are HS256-signed
//!    with the same shared secret; the `typ` distinguishes them.
//! 3. When the token is OAuth-flavored AND carries a `cnf.jkt` thumbprint,
//!    enforce the DPoP proof (RFC 9449) and check its `jti` against the
//!    replay guard.
//!
//! The previous codebase had a dozen handlers each open-coding the bearer
//! extraction + `session::verify_access` call. They all rejected OAuth
//! tokens (different `typ`) and never enforced DPoP. This module
//! centralizes the flow:
//!
//! - [`require_authn`] does the full check and returns an [`AuthSubject`].
//! - Handlers can call `subject.sub()` for the bare DID, or pattern-match
//!   on [`AuthSubject`] for OAuth-specific concerns (scope, client_id).

use crate::account::session::{self, SessionClaims};
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::oauth::dpop::verify_dpop_proof;
use crate::oauth::token::{OAuthClaims, TYP_ACCESS as OAUTH_TYP_ACCESS, verify_oauth_jwt};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

/// Result of a successful bearer-token verification.
///
/// Carries the underlying claim shape so callers can branch on
/// app-password-vs-OAuth concerns (e.g. scope checks). For most handlers
/// only [`Self::sub`] (the subject DID) is interesting.
#[derive(Debug, Clone)]
pub enum AuthSubject {
    /// App-password session JWT (`typ=at-pp-access`).
    AppPassword(SessionClaims),
    /// OAuth access JWT (`typ=at-oauth-access`).
    OAuth(OAuthClaims),
}

impl AuthSubject {
    /// Subject DID (the account the token authorizes).
    #[must_use]
    pub fn sub(&self) -> &str {
        match self {
            AuthSubject::AppPassword(c) => &c.sub,
            AuthSubject::OAuth(c) => &c.sub,
        }
    }

    /// JWT-id of the bearer token (for revocation/audit).
    #[must_use]
    pub fn jti(&self) -> &str {
        match self {
            AuthSubject::AppPassword(c) => &c.jti,
            AuthSubject::OAuth(c) => &c.jti,
        }
    }

    /// OAuth `client_id` of the requesting app, when the token is an OAuth
    /// access token. `None` for app-password sessions (which have no
    /// associated OAuth client).
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        match self {
            AuthSubject::AppPassword(_) => None,
            AuthSubject::OAuth(c) => Some(&c.client_id),
        }
    }

    /// `true` when this is an OAuth token bound to a DPoP key (the
    /// `cnf.jkt` claim is present).
    #[must_use]
    pub fn is_dpop_bound(&self) -> bool {
        matches!(self, AuthSubject::OAuth(c) if c.cnf.is_some())
    }

    /// `true` when this is an OAuth access token (as opposed to an
    /// app-password session). Space scope gating only applies to OAuth
    /// tokens — app-password sessions carry no `space:` grants and so can
    /// never satisfy [`assert_space`](atproto_oauth::scopes::ScopesSet::assert_space).
    #[must_use]
    pub fn is_oauth(&self) -> bool {
        matches!(self, AuthSubject::OAuth(_))
    }

    /// The granted OAuth scope set, parsed from the access token's `scope`
    /// claim. Returns an empty set for app-password sessions (which have no
    /// OAuth scope string), so callers can uniformly run
    /// [`assert_space`](atproto_oauth::scopes::ScopesSet::assert_space)
    /// against it — an empty set simply satisfies nothing.
    #[must_use]
    pub fn scopes(&self) -> atproto_oauth::scopes::ScopesSet {
        match self {
            AuthSubject::AppPassword(_) => atproto_oauth::scopes::ScopesSet::new(),
            AuthSubject::OAuth(c) => {
                // Bound to the token's subject so a `space:` grant that omits
                // `authority` resolves to the account it was issued for, which
                // is what `authority=self` means and what the default is.
                atproto_oauth::scopes::ScopesSet::from_scope_string_for(&c.scope, &c.sub)
            }
        }
    }

    /// `true` when the caller authenticated with the account password itself,
    /// rather than with an app password or an OAuth grant.
    ///
    /// This is a stricter question than [`privileged`](Self::privileged), and
    /// the two are not interchangeable. `privileged` asks whether an app
    /// password was marked privileged when it was created; this asks whether
    /// there is an app password involved at all.
    ///
    /// It gates the operations that can take over or destroy an identity —
    /// minting further app passwords, signing PLC operations, starting an
    /// account deletion or an email change. App passwords are handed to
    /// third-party tools, so a tool holding one must not be able to reach
    /// them. The reference draws the same line, reserving these to
    /// `AuthScope.Access` and refusing both `AppPass` and
    /// `AppPassPrivileged`.
    ///
    /// OAuth tokens are not full sessions. An OAuth client is a third party
    /// in the same sense an app-password holder is, and `transition:generic`
    /// exists to mean "whatever an app password can do" — not more.
    #[must_use]
    pub fn is_full_session(&self) -> bool {
        match self {
            AuthSubject::AppPassword(c) => c.full,
            AuthSubject::OAuth(_) => false,
        }
    }

    /// `true` if the token is allowed to perform privileged operations
    /// (those gated to sensitive paths like `importRepo`,
    /// `getServiceAuth`, account migration). For app-password sessions
    /// this maps to the `privileged` claim. For OAuth tokens we look for
    /// the `transition:generic` scope, which is the AT Protocol convention
    /// for "anything app-password can do".
    #[must_use]
    pub fn privileged(&self) -> bool {
        match self {
            AuthSubject::AppPassword(c) => c.privileged,
            AuthSubject::OAuth(c) => c
                .scope
                .split_whitespace()
                .any(|s| s == "transition:generic"),
        }
    }
}

/// The scheme a request presented its access token under.
///
/// RFC 9449 §7.1 makes this load-bearing rather than decorative: a
/// DPoP-bound token is presented as `DPoP`, an unbound one as `Bearer`, and
/// the two are not interchangeable. Presenting a bound token as `Bearer`
/// asks the server to accept it without proof of possession, which is
/// exactly the downgrade the binding exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// RFC 6750 — an unbound token.
    Bearer,
    /// RFC 9449 §7.1 — a token bound to a proof-of-possession key.
    Dpop,
}

impl AuthScheme {
    /// The scheme name as it appears in the `Authorization` header.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthScheme::Bearer => "Bearer",
            AuthScheme::Dpop => "DPoP",
        }
    }
}

/// Read an `Authorization: Bearer <token>` **or** `Authorization: DPoP
/// <token>` header, returning the scheme and the raw token.
///
/// This is the extractor for *access tokens*, whose scheme varies. Tokens
/// that are Bearer by definition — service auth, space credentials,
/// delegation grants — use [`bearer_token`] instead.
///
/// The scheme is matched case-sensitively against the names RFC 6750 and
/// RFC 9449 register. Failure is a 401 `AuthenticationRequired`.
pub fn authorization_token(parts: &Parts) -> Result<(AuthScheme, &str), XrpcError> {
    let raw = authorization_header(parts)?;

    if let Some(token) = raw.strip_prefix("Bearer ") {
        return Ok((AuthScheme::Bearer, token));
    }
    if let Some(token) = raw.strip_prefix("DPoP ") {
        return Ok((AuthScheme::Dpop, token));
    }

    Err(XrpcError::new(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        "expected Bearer or DPoP scheme",
    ))
}

/// Shared header read: present, and valid UTF-8.
fn authorization_header(parts: &Parts) -> Result<&str, XrpcError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "no Authorization header",
        )
    })?;
    header.to_str().map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not valid UTF-8",
        )
    })
}

/// Read the `Authorization: Bearer <token>` header. Returns the raw token
/// (no `Bearer ` prefix). Failure is a 401 `AuthenticationRequired`.
///
/// For credentials that are Bearer by definition. Access tokens go through
/// [`authorization_token`], which also accepts `DPoP`.
pub fn bearer_token(parts: &Parts) -> Result<&str, XrpcError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "no Authorization header",
        )
    })?;
    let raw = header.to_str().map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not valid UTF-8",
        )
    })?;
    raw.strip_prefix("Bearer ").ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "expected Bearer scheme",
        )
    })
}

/// The full XRPC authentication path: bearer extraction → session-or-OAuth
/// verification → DPoP proof check (when bound).
///
/// `htm` and `htu` are the canonical HTTP method + URL the DPoP proof must
/// pin to. Caller must derive these from the live request — see
/// [`request_htm_htu`] for an axum-friendly helper. They are unused for
/// non-DPoP-bound tokens.
pub async fn require_authn(
    parts: &Parts,
    state: &HttpState,
    htm: &str,
    htu: &str,
) -> Result<AuthSubject, XrpcError> {
    let (scheme, raw) = authorization_token(parts)?;

    // Try app-password first — that's the dominant path today. A session
    // token is never proof-of-possession bound, so it is a Bearer token and
    // presenting it as `DPoP` is a category error rather than a stricter
    // request.
    if let Ok(claims) = session::verify_access(raw, &state.jwt_secret) {
        require_scheme(
            scheme,
            AuthScheme::Bearer,
            "an app-password session token is not bound",
        )?;
        return Ok(AuthSubject::AppPassword(claims));
    }

    // Fall back to OAuth. If the token isn't OAuth-flavored either, we
    // surface a generic 401 (don't disclose which JWT shape was tried).
    let claims = verify_oauth_jwt(raw, OAUTH_TYP_ACCESS, &state.jwt_secret).map_err(|e| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            format!("bearer token rejected: {e}"),
        )
    })?;

    // DPoP enforcement: when `cnf.jkt` is bound, the request MUST be made
    // under the `DPoP` scheme and MUST carry a valid proof keyed to the same
    // thumbprint. The scheme is checked first because it is the client's
    // declaration of what it thinks it holds — a bound token offered as
    // `Bearer` is a downgrade attempt whether or not a proof happens to
    // accompany it.
    if claims.cnf.is_some() {
        require_scheme(
            scheme,
            AuthScheme::Dpop,
            "this access token is bound to a DPoP key",
        )?;
        verify_dpop_proof(&parts.headers, &claims, htm, htu, raw, &state.jti_guard).await?;
    } else {
        require_scheme(
            scheme,
            AuthScheme::Bearer,
            "this access token is not bound to a DPoP key",
        )?;
    }

    Ok(AuthSubject::OAuth(claims))
}

/// Require that the presented scheme matches the one the token's binding
/// implies, with `why` naming the property that decided it.
///
/// Split out so both directions read the same way: a bound token under
/// `Bearer` and an unbound token under `DPoP` are both mismatches, and
/// neither is more acceptable than the other.
fn require_scheme(got: AuthScheme, want: AuthScheme, why: &str) -> Result<(), XrpcError> {
    if got == want {
        return Ok(());
    }
    Err(XrpcError::new(
        StatusCode::UNAUTHORIZED,
        "AuthenticationRequired",
        format!(
            "{why}, so it must be presented with the {} scheme, not {}",
            want.as_str(),
            got.as_str()
        ),
    ))
}

/// Convenience wrapper: same as [`require_authn`] but discards the full
/// claims shape and returns just the subject DID. Suitable for the dozens
/// of handlers that only care about *which account* is calling.
pub async fn require_authn_sub(
    parts: &Parts,
    state: &HttpState,
    htm: &str,
    htu: &str,
) -> Result<String, XrpcError> {
    require_authn(parts, state, htm, htu)
        .await
        .map(|s| s.sub().to_string())
}

/// Derive the canonical `htm` + `htu` for a DPoP proof from the request.
///
/// `htu` is `scheme://authority/path` per RFC 9449 §4.2 — query and
/// fragment are stripped because the proof spec normalizes them away. The
/// scheme + authority are reconstructed from the `Host` (or
/// `X-Forwarded-Host` / `X-Forwarded-Proto`) headers when proxied; falls
/// back to the request's URI authority + scheme.
pub fn request_htm_htu(parts: &Parts) -> (String, String) {
    let htm = parts.method.as_str().to_string();

    let path = parts.uri.path();
    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.scheme_str().map(str::to_string))
        .unwrap_or_else(|| "http".to_string());
    let authority = parts
        .headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .unwrap_or_else(|| "localhost".to_string());

    let htu = format!("{scheme}://{authority}{path}");
    (htm, htu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    fn parts_with(method: Method, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut req = axum::http::Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req.body(()).unwrap();
        req.into_parts().0
    }

    #[test]
    fn request_htm_htu_strips_query() {
        let parts = parts_with(
            Method::POST,
            "/xrpc/com.atproto.foo?since=abc",
            &[("host", "pds.example")],
        );
        let (htm, htu) = request_htm_htu(&parts);
        assert_eq!(htm, "POST");
        // Default scheme is http when no x-forwarded-proto is set.
        assert_eq!(htu, "http://pds.example/xrpc/com.atproto.foo");
    }

    #[test]
    fn request_htm_htu_honors_forwarded_proto() {
        let parts = parts_with(
            Method::GET,
            "/xrpc/com.atproto.bar",
            &[
                ("host", "pds.example"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "public.example"),
            ],
        );
        let (htm, htu) = request_htm_htu(&parts);
        assert_eq!(htm, "GET");
        assert_eq!(htu, "https://public.example/xrpc/com.atproto.bar");
    }

    #[test]
    fn bearer_token_strips_prefix() {
        let parts = parts_with(
            Method::POST,
            "/x",
            &[("authorization", "Bearer abc.def.ghi")],
        );
        assert_eq!(bearer_token(&parts).unwrap(), "abc.def.ghi");
    }

    #[test]
    fn bearer_token_rejects_missing_header() {
        let parts = parts_with(Method::POST, "/x", &[]);
        let err = bearer_token(&parts).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn bearer_token_rejects_non_bearer_scheme() {
        let parts = parts_with(Method::POST, "/x", &[("authorization", "Basic xyz")]);
        let err = bearer_token(&parts).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
}
