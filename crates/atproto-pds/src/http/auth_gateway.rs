//! Sessions minted from an auth-gateway token
//! (`town.roundabout.server.createSessionFromToken`).
//!
//! The gateway (`services/auth-gateway` in the xoxo repo) signs a short-lived
//! RS256 JWT after Google OAuth or a magic link: `iss` is the literal
//! `auth-gateway`, `aud` is this PDS's public URL, `sub`/`email` is the
//! address it proved, and `provider` / `environment` say how and for which
//! deployment. This module verifies such a token against the gateway's JWKS
//! and hands back the claims the handler needs. It never creates accounts.

use std::time::Duration;

/// How long a fetched JWKS is trusted before it is fetched again.
pub const JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Floor on how often an unknown `kid` may force a re-fetch. Without it a
/// stream of tokens bearing random `kid`s would drive one outbound request
/// per token at the gateway — an amplifier pointed at our own sign-in path.
pub const JWKS_MIN_FORCED_REFETCH: Duration = Duration::from_secs(30);

/// The issuer every gateway token must carry. Not configurable: the TS PDS
/// hardcodes the same literal (`AUTH_GATEWAY_ISSUER`), and the gateway's
/// `AUTH_GATEWAY_JWT_ISSUER` is set to it in every environment.
pub const AUTH_GATEWAY_ISSUER: &str = "auth-gateway";

/// Operator configuration for the gateway trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthGatewayConfig {
    /// Origin of the gateway, without a trailing slash; the JWKS lives at
    /// `<url>/.well-known/jwks.json`.
    pub url: String,
    /// The exact `aud` a token must carry — this PDS's public URL as the
    /// gateway knows it (`AUTH_GATEWAY_PDS_URL_MAP` in the xoxo repo).
    pub audience: String,
}

/// Why an [`AuthGatewayConfig`] was refused at startup.
#[derive(Debug, thiserror::Error)]
pub enum AuthGatewayConfigError {
    /// `PDS_AUTH_GATEWAY_URL` is not an absolute http(s) URL.
    #[error(
        "error-atproto-pds-auth-gateway-1 PDS_AUTH_GATEWAY_URL is not an absolute http(s) URL: {url}"
    )]
    InvalidUrl {
        /// The rejected value.
        url: String,
    },
    /// `PDS_AUTH_GATEWAY_AUDIENCE` is empty.
    #[error("error-atproto-pds-auth-gateway-2 PDS_AUTH_GATEWAY_AUDIENCE must not be empty")]
    EmptyAudience,
}

impl AuthGatewayConfig {
    /// Validate operator input. Trailing slashes on the URL are stripped so
    /// the JWKS path joins cleanly; the audience is kept byte-for-byte
    /// because the gateway compares it byte-for-byte.
    pub fn new(url: &str, audience: &str) -> Result<Self, AuthGatewayConfigError> {
        let parsed = url::Url::parse(url).map_err(|_| AuthGatewayConfigError::InvalidUrl {
            url: url.to_string(),
        })?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(AuthGatewayConfigError::InvalidUrl {
                url: url.to_string(),
            });
        }
        if audience.is_empty() {
            return Err(AuthGatewayConfigError::EmptyAudience);
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            audience: audience.to_string(),
        })
    }

    /// Where the gateway publishes its signing keys.
    #[must_use]
    pub fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.url)
    }
}

/// Verifier for gateway tokens. Holds the operator config and the JWKS cache.
#[derive(Debug)]
pub struct AuthGateway {
    config: AuthGatewayConfig,
}

impl AuthGateway {
    /// Build a verifier from validated config.
    #[must_use]
    pub fn new(config: AuthGatewayConfig) -> Self {
        Self { config }
    }

    /// The operator config this verifier enforces.
    #[must_use]
    pub fn config(&self) -> &AuthGatewayConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trailing slash on the operator's URL must not produce
    /// `//.well-known/jwks.json` — some servers 404 that.
    #[test]
    fn jwks_url_joins_cleanly_with_or_without_trailing_slash() {
        let a = AuthGatewayConfig::new("https://auth.example/", "https://pds.example").unwrap();
        let b = AuthGatewayConfig::new("https://auth.example", "https://pds.example").unwrap();
        assert_eq!(a.jwks_url(), "https://auth.example/.well-known/jwks.json");
        assert_eq!(a, b);
    }

    /// A misconfigured URL must fail at startup, not at the first sign-in.
    #[test]
    fn refuses_a_relative_url_and_an_empty_audience() {
        assert!(matches!(
            AuthGatewayConfig::new("auth.example", "x"),
            Err(AuthGatewayConfigError::InvalidUrl { .. })
        ));
        assert!(matches!(
            AuthGatewayConfig::new("https://auth.example", ""),
            Err(AuthGatewayConfigError::EmptyAudience)
        ));
    }
}
