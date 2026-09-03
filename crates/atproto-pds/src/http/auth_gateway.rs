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

/// How much of a JWKS document to read before giving up. It is a handful of
/// RSA keys; without a ceiling the reply is buffered to whatever length the
/// far end chooses to send, which turns operator configuration the gateway
/// itself controls into an unbounded allocation on every cold fetch.
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// Operator configuration for the gateway trust.
///
/// Plain `http` is accepted, because the dev docker stack points this at
/// `http://auth-gateway:3004` inside a private network. It is a real caveat
/// rather than a convenience: the JWKS fetched from [`url`](Self::url) is the
/// entire root of trust for the `Full`-authority sessions
/// `town.roundabout.server.createSessionFromToken` mints, so over plain http
/// to a remote host anyone on the path can serve a key set of their own
/// choosing and mint sessions for any account on this PDS. The binary warns
/// about exactly that shape at startup — see [`Self::is_plaintext_remote`].
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

    /// Whether this gateway is reached over plain `http` at a host that is
    /// not loopback — the shape the startup warning exists for.
    ///
    /// `http://auth-gateway:3004` (the dev docker stack) and
    /// `https://auth.example` are both fine in their place; `http://` to a
    /// host reachable across a network is the one that hands the root of
    /// trust for token sessions to whoever is on the path. Pure, so the
    /// decision is testable without booting the binary.
    #[must_use]
    pub fn is_plaintext_remote(&self) -> bool {
        let Ok(parsed) = url::Url::parse(&self.url) else {
            return false;
        };
        if parsed.scheme() != "http" {
            return false;
        }
        match parsed.host() {
            Some(url::Host::Domain(host)) => host != "localhost",
            Some(url::Host::Ipv4(ip)) => !ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
            None => false,
        }
    }
}

use std::sync::Mutex;
use std::time::Instant;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::ttl_cache::TtlCache;

/// What a verified gateway token tells us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayClaims {
    /// The address the gateway proved, exactly as it appears in the token.
    pub email: String,
    /// `google` / `allegro` / `email` — how it was proved.
    pub provider: String,
    /// The deployment the client signed in for (its login hostname).
    pub environment: String,
}

/// Why a token was refused. The handler collapses every variant to the
/// lexicon's `InvalidToken`; the distinction exists for logs and for the
/// unknown-`kid` re-fetch decision.
#[derive(Debug, thiserror::Error)]
pub enum GatewayTokenError {
    /// Not a JWT at all.
    #[error("error-atproto-pds-auth-gateway-10 malformed token: {0}")]
    Malformed(String),
    /// The JWKS could not be fetched or parsed.
    #[error("error-atproto-pds-auth-gateway-11 jwks unavailable: {0}")]
    Jwks(String),
    /// The token's `kid` is not in the (current) key set.
    #[error("error-atproto-pds-auth-gateway-12 unknown kid: {0}")]
    UnknownKid(String),
    /// Wrong algorithm or a signature that does not verify.
    #[error("error-atproto-pds-auth-gateway-13 signature refused: {0}")]
    Signature(String),
    /// Signature fine, claims not: issuer, audience, expiry, or a missing
    /// gateway claim.
    #[error("error-atproto-pds-auth-gateway-14 claims refused: {0}")]
    Claims(String),
}

/// The raw claim set. Everything the gateway signs is a string except the
/// timestamps, which `jsonwebtoken` validates before we see them.
#[derive(Debug, serde::Deserialize)]
struct RawClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default, rename = "googleId")]
    google_id: Option<String>,
    #[serde(default, rename = "allegroId")]
    allegro_id: Option<String>,
    #[serde(default, rename = "emailId")]
    email_id: Option<String>,
}

/// Verifier for gateway tokens. Holds the operator config and the JWKS cache.
#[derive(Debug)]
pub struct AuthGateway {
    config: AuthGatewayConfig,
    /// Keyed by JWKS URL so a future second issuer cannot evict this one.
    jwks: TtlCache<JwkSet>,
    /// When an unknown `kid` last forced a re-fetch (see
    /// [`JWKS_MIN_FORCED_REFETCH`]).
    last_forced: Mutex<Option<Instant>>,
    /// When a cold or expired-cache JWKS fetch last failed (see
    /// [`JWKS_MIN_FORCED_REFETCH`]). Without this floor, every sign-in
    /// attempt on this unauthenticated endpoint drives one outbound GET —
    /// with a 10 s timeout — for as long as the gateway is down or slow, the
    /// same amplifier the unknown-`kid` floor exists to prevent on the other
    /// re-fetch path. Cleared on a successful fetch.
    last_fetch_failed_at: Mutex<Option<Instant>>,
}

impl AuthGateway {
    /// Build a verifier from validated config.
    #[must_use]
    pub fn new(config: AuthGatewayConfig) -> Self {
        Self {
            config,
            jwks: TtlCache::new(JWKS_CACHE_TTL, 4),
            last_forced: Mutex::new(None),
            last_fetch_failed_at: Mutex::new(None),
        }
    }

    /// The operator config this verifier enforces.
    #[must_use]
    pub fn config(&self) -> &AuthGatewayConfig {
        &self.config
    }

    /// Verify `token` against the gateway's published keys, re-fetching once
    /// if the token names a `kid` the cached set lacks (a rotation we have not
    /// seen yet) and the forced-refetch floor allows it.
    pub async fn verify(&self, token: &str) -> Result<GatewayClaims, GatewayTokenError> {
        let jwks = self.jwks_cached().await?;
        match self.verify_with_jwks(token, &jwks) {
            Err(GatewayTokenError::UnknownKid(kid)) => {
                if !self.may_force_refetch() {
                    return Err(GatewayTokenError::UnknownKid(kid));
                }
                let fresh = self.fetch_jwks().await?;
                self.jwks.put(&self.config.jwks_url(), fresh.clone());
                self.verify_with_jwks(token, &fresh)
            }
            other => other,
        }
    }

    /// Pure verification against a caller-supplied key set. Signature first,
    /// claims after — nothing in the payload is read until the signature
    /// stands (the same rule `oauth::client_auth::verify_assertion` follows).
    pub fn verify_with_jwks(
        &self,
        token: &str,
        jwks: &JwkSet,
    ) -> Result<GatewayClaims, GatewayTokenError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| GatewayTokenError::Malformed(e.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(GatewayTokenError::Signature(format!(
                "alg {:?} is not RS256",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| GatewayTokenError::Signature("token has no kid".into()))?;
        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| GatewayTokenError::UnknownKid(kid.clone()))?;
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|e| GatewayTokenError::Jwks(format!("kid {kid}: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[AUTH_GATEWAY_ISSUER]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = jsonwebtoken::decode::<RawClaims>(token, &key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => {
                    GatewayTokenError::Signature(e.to_string())
                }
                _ => GatewayTokenError::Claims(e.to_string()),
            }
        })?;
        let raw = data.claims;

        let email = match raw.email.as_deref() {
            Some(e) if !e.is_empty() => e.to_string(),
            _ => return Err(GatewayTokenError::Claims("no email claim".into())),
        };
        let provider = raw
            .provider
            .ok_or_else(|| GatewayTokenError::Claims("no provider claim".into()))?;
        let environment = raw
            .environment
            .ok_or_else(|| GatewayTokenError::Claims("no environment claim".into()))?;
        let id_present = match provider.as_str() {
            "google" => raw.google_id.is_some(),
            "allegro" => raw.allegro_id.is_some(),
            "email" => raw.email_id.is_some(),
            _ => true,
        };
        if !id_present {
            return Err(GatewayTokenError::Claims(format!(
                "provider {provider} requires its id claim"
            )));
        }
        Ok(GatewayClaims {
            email,
            provider,
            environment,
        })
    }

    /// The cached key set, or a fresh fetch on a miss — floored the same way
    /// `may_force_refetch` floors the unknown-`kid` path: a fetch that failed
    /// inside [`JWKS_MIN_FORCED_REFETCH`] is not retried, so a down or slow
    /// gateway cannot be turned into one live request per unauthenticated
    /// sign-in attempt.
    async fn jwks_cached(&self) -> Result<JwkSet, GatewayTokenError> {
        let url = self.config.jwks_url();
        if let Some(set) = self.jwks.get(&url) {
            return Ok(set);
        }
        let failed_at = *self
            .last_fetch_failed_at
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if failed_at.is_some_and(|t| t.elapsed() < JWKS_MIN_FORCED_REFETCH) {
            return Err(GatewayTokenError::Jwks(
                "jwks fetch recently failed; retry later".into(),
            ));
        }
        match self.fetch_jwks().await {
            Ok(fresh) => {
                self.jwks.put(&url, fresh.clone());
                *self
                    .last_fetch_failed_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
                Ok(fresh)
            }
            Err(err) => {
                *self
                    .last_fetch_failed_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
                Err(err)
            }
        }
    }

    fn may_force_refetch(&self) -> bool {
        let mut last = self.last_forced.lock().unwrap_or_else(|p| p.into_inner());
        let allowed = last.is_none_or(|t| t.elapsed() >= JWKS_MIN_FORCED_REFETCH);
        if allowed {
            *last = Some(Instant::now());
        }
        allowed
    }

    /// One bounded, redirect-free GET of the JWKS. The URL is operator
    /// configuration, not caller input, so the SSRF guard used for OAuth
    /// client metadata does not apply — the dev stack points this at a
    /// docker hostname over plain http.
    async fn fetch_jwks(&self) -> Result<JwkSet, GatewayTokenError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(crate::user_agent())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| GatewayTokenError::Jwks(e.to_string()))?;
        let mut response = client
            .get(self.config.jwks_url())
            .send()
            .await
            .map_err(|e| GatewayTokenError::Jwks(e.to_string()))?;
        if !response.status().is_success() {
            return Err(GatewayTokenError::Jwks(format!(
                "jwks fetch returned {}",
                response.status()
            )));
        }
        // A declared Content-Length over the cap is rejected up front as a
        // cheap fast path, but is not trusted instead of the running-total
        // check below: it is the sender's own claim about a body they also
        // control, and may be absent or wrong.
        if response
            .content_length()
            .is_some_and(|len| len > MAX_JWKS_BYTES as u64)
        {
            return Err(GatewayTokenError::Jwks(format!(
                "jwks exceeds {MAX_JWKS_BYTES} bytes"
            )));
        }
        // Chunk by chunk rather than `.bytes()`, which buffers the whole
        // reply before the length check ever runs — the same shape as
        // `oauth::client_metadata::read_json_bounded`.
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| GatewayTokenError::Jwks(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_JWKS_BYTES {
                return Err(GatewayTokenError::Jwks(format!(
                    "jwks exceeds {MAX_JWKS_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let set: JwkSet =
            serde_json::from_slice(&body).map_err(|e| GatewayTokenError::Jwks(e.to_string()))?;
        if set.keys.is_empty() {
            return Err(GatewayTokenError::Jwks("jwks has no keys".into()));
        }
        Ok(set)
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

    /// The dev stack's `http://auth-gateway:3004` must not be refused, but it
    /// must be the case that the operator hears about it: the JWKS behind that
    /// URL is the root of trust for every `Full` session this endpoint mints,
    /// and over plain http to a routable host anyone on the path can serve
    /// their own keys. Loopback is exempt (nothing is on that path) and https
    /// is the intended shape.
    #[test]
    fn flags_plain_http_to_a_non_loopback_host() {
        let plaintext_remote = |url: &str| {
            AuthGatewayConfig::new(url, "https://pds.example")
                .unwrap()
                .is_plaintext_remote()
        };
        assert!(plaintext_remote("http://auth-gateway:3004"));
        assert!(plaintext_remote("http://auth.example"));
        assert!(plaintext_remote("http://10.0.0.4:3004"));
        assert!(!plaintext_remote("http://localhost:3004"));
        assert!(!plaintext_remote("http://127.0.0.1:3004"));
        assert!(!plaintext_remote("http://[::1]:3004"));
        assert!(!plaintext_remote("https://auth.example"));
        assert!(!plaintext_remote("https://localhost:3004"));
    }

    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    const PRIVATE_PEM: &str = include_str!("../../tests/fixtures/auth_gateway/private.pem");
    const JWKS_JSON: &str = include_str!("../../tests/fixtures/auth_gateway/jwks.json");

    fn jwks() -> jsonwebtoken::jwk::JwkSet {
        serde_json::from_str(JWKS_JSON).unwrap()
    }

    fn gateway() -> AuthGateway {
        AuthGateway::new(
            AuthGatewayConfig::new("https://auth.example", "https://pds.example").unwrap(),
        )
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A token shaped exactly like `services/auth-gateway`'s `sign()`:
    /// `iss`, `aud`, `sub` = email, `iat`, `exp`, plus the gateway claims.
    fn sign(kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn good_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": AUTH_GATEWAY_ISSUER,
            "aud": "https://pds.example",
            "sub": "Admin@Example.com",
            "email": "Admin@Example.com",
            "provider": "email",
            "emailId": "ml_123",
            "environment": "roundabout-grove.fly.dev",
            "iat": now(),
            "exp": now() + 300,
        })
    }

    /// The happy path: a gateway-signed token yields its email verbatim
    /// (lower-casing is the handler's job, at lookup time) and the two
    /// gateway claims the TS contract requires.
    #[test]
    fn verifies_a_gateway_token_and_returns_its_claims() {
        let claims = gateway()
            .verify_with_jwks(&sign("test-key-1", good_claims()), &jwks())
            .unwrap();
        assert_eq!(claims.email, "Admin@Example.com");
        assert_eq!(claims.provider, "email");
        assert_eq!(claims.environment, "roundabout-grove.fly.dev");
    }

    /// `aud` is what stops a token minted for a community PDS from opening a
    /// session here. It must match the configured audience byte-for-byte.
    #[test]
    fn refuses_a_token_for_another_audience() {
        let mut c = good_claims();
        c["aud"] = "https://pds.other".into();
        assert!(matches!(
            gateway().verify_with_jwks(&sign("test-key-1", c), &jwks()),
            Err(GatewayTokenError::Claims(_))
        ));
    }

    /// Only the gateway issues these tokens.
    #[test]
    fn refuses_a_token_from_another_issuer() {
        let mut c = good_claims();
        c["iss"] = "someone-else".into();
        assert!(matches!(
            gateway().verify_with_jwks(&sign("test-key-1", c), &jwks()),
            Err(GatewayTokenError::Claims(_))
        ));
    }

    /// Gateway tokens live 300 s; an expired one must not mint a session.
    #[test]
    fn refuses_an_expired_token() {
        let mut c = good_claims();
        c["exp"] = (now() - 3600).into();
        c["iat"] = (now() - 3900).into();
        assert!(
            gateway()
                .verify_with_jwks(&sign("test-key-1", c), &jwks())
                .is_err()
        );
    }

    /// The TS contract requires `provider` and `environment`, and a
    /// per-provider id (`emailId` / `googleId` / `allegroId`). A service token
    /// the gateway mints for account lookup carries none of these and must
    /// never open a session.
    #[test]
    fn refuses_a_token_missing_the_gateway_claims() {
        let mut no_provider = good_claims();
        no_provider.as_object_mut().unwrap().remove("provider");
        assert!(matches!(
            gateway().verify_with_jwks(&sign("test-key-1", no_provider), &jwks()),
            Err(GatewayTokenError::Claims(_))
        ));

        let mut google_without_id = good_claims();
        google_without_id["provider"] = "google".into();
        google_without_id.as_object_mut().unwrap().remove("emailId");
        assert!(matches!(
            gateway().verify_with_jwks(&sign("test-key-1", google_without_id), &jwks()),
            Err(GatewayTokenError::Claims(_))
        ));

        let mut no_email = good_claims();
        no_email.as_object_mut().unwrap().remove("email");
        assert!(matches!(
            gateway().verify_with_jwks(&sign("test-key-1", no_email), &jwks()),
            Err(GatewayTokenError::Claims(_))
        ));
    }

    /// `alg: none` and HS256 (signed with a guessable secret) must be refused
    /// before any key lookup — a JWKS lookup keyed off an attacker's header
    /// is itself a vector.
    #[test]
    fn refuses_non_rs256_tokens() {
        let hs = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &good_claims(),
            &EncodingKey::from_secret(b"guess"),
        )
        .unwrap();
        assert!(matches!(
            gateway().verify_with_jwks(&hs, &jwks()),
            Err(GatewayTokenError::Signature(_))
        ));
        assert!(matches!(
            gateway().verify_with_jwks("not.a.jwt", &jwks()),
            Err(GatewayTokenError::Malformed(_))
        ));
    }

    /// A `kid` the JWKS does not list is a distinct error: the handler uses it
    /// to decide whether a forced re-fetch is worth trying.
    #[test]
    fn reports_an_unknown_kid_distinctly() {
        assert!(matches!(
            gateway().verify_with_jwks(&sign("rotated-key", good_claims()), &jwks()),
            Err(GatewayTokenError::UnknownKid(_))
        ));
    }

    const OTHER_PRIVATE_PEM: &str =
        include_str!("../../tests/fixtures/auth_gateway/other-private.pem");

    /// A token naming a real `kid` but signed by a *different* key must be
    /// refused as a bad signature. Every other `Signature` assertion in this
    /// file is satisfied by the alg-mismatch pre-check before any crypto
    /// runs; this is the one that actually exercises RSA verification.
    #[test]
    fn refuses_a_token_signed_by_the_wrong_key() {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &good_claims(),
            &EncodingKey::from_rsa_pem(OTHER_PRIVATE_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            gateway().verify_with_jwks(&token, &jwks()),
            Err(GatewayTokenError::Signature(_))
        ));
    }

    /// A cold or failed JWKS fetch must not turn every sign-in attempt on
    /// this unauthenticated endpoint into a fresh outbound request while the
    /// gateway is down: a second call inside the floor must fail fast, from
    /// the stamp alone, with no network attempt.
    #[tokio::test]
    async fn floors_retries_after_a_failed_jwks_fetch() {
        // Port 1 on loopback: nothing listens there, so the connection is
        // refused immediately rather than hanging out to the 10 s timeout —
        // that fast failure is what lets the second call's near-zero elapsed
        // time distinguish "floored" from "attempted and also failed fast".
        let gateway = AuthGateway::new(
            AuthGatewayConfig::new("http://127.0.0.1:1", "https://pds.example").unwrap(),
        );
        assert!(gateway.jwks_cached().await.is_err());

        let start = std::time::Instant::now();
        let err = gateway.jwks_cached().await.unwrap_err();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "the floor should short-circuit without a network attempt"
        );
        assert!(
            matches!(&err, GatewayTokenError::Jwks(msg) if msg.contains("recently failed")),
            "expected the floor's own message, got {err}"
        );
    }
}
