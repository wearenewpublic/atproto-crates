//! Server-provided DPoP nonces.
//!
//! The AT Protocol OAuth specification is verbatim: *"Server-provided DPoP
//! nonces are mandatory."* Without them a captured proof is replayable for its
//! whole freshness window, defended only by the JTI guard -- which is one
//! process's memory of what it has seen, and the wrong thing to have as a sole
//! defence.
//!
//! A nonce here is derived, not stored. It is an HMAC of the current time
//! window under a server secret, so:
//!
//! - nothing has to be written down, and a flood of challenges costs no
//!   storage;
//! - it survives a restart, because the secret does;
//! - every instance of a deployment issues and accepts the same values,
//!   because they share the secret.
//!
//! The alternative -- recording every nonce handed out -- buys single-use
//! semantics that RFC 9449 does not ask for, at the cost of a write per
//! challenge on a path an unauthenticated caller can drive.
//!
//! The secret is derived from `PDS_JWT_SECRET` under a domain separator rather
//! than configured separately. It is already required, already at least 32
//! bytes, already stable across restarts and already shared by every instance,
//! which is the entire list of properties this needs.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// How long a nonce stays current.
///
/// The previous window is accepted too, so the effective lifetime is between
/// one and two of these. Short enough that a captured proof is worth little,
/// long enough that a client is not challenged on every request.
const WINDOW_SECS: u64 = 300;

/// Which endpoint family a nonce belongs to.
///
/// RFC 9449 §8.1 keeps the authorization server's nonces and the resource
/// server's separate, and this server is both. Distinct domain separators mean
/// a nonce issued for one cannot be presented at the other, without having to
/// track which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceSpace {
    /// `/oauth/token`, `/oauth/par` — the authorization server.
    Authorization,
    /// XRPC methods — the resource server.
    Resource,
}

impl NonceSpace {
    const fn separator(self) -> &'static [u8] {
        match self {
            Self::Authorization => b"atproto-pds-dpop-nonce-as",
            Self::Resource => b"atproto-pds-dpop-nonce-rs",
        }
    }
}

/// Issues and checks DPoP nonces.
#[derive(Clone)]
pub struct NonceIssuer {
    secret: std::sync::Arc<Vec<u8>>,
}

impl std::fmt::Debug for NonceIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NonceIssuer(<secret>)")
    }
}

impl NonceIssuer {
    /// Build an issuer over the server's JWT secret.
    #[must_use]
    pub fn new(secret: std::sync::Arc<Vec<u8>>) -> Self {
        Self { secret }
    }

    /// The nonce to hand out right now.
    #[must_use]
    pub fn current(&self, space: NonceSpace) -> String {
        self.at(space, Self::window(now_secs()))
    }

    /// Every nonce this server will accept right now.
    ///
    /// Two: the current window and the one before it. A client that fetched a
    /// nonce moments before a rotation must not be refused for using it, and a
    /// refusal here is indistinguishable to the client from a stolen proof.
    #[must_use]
    pub fn accepted(&self, space: NonceSpace) -> Vec<String> {
        let window = Self::window(now_secs());
        vec![
            self.at(space, window),
            self.at(space, window.saturating_sub(1)),
        ]
    }

    fn window(secs: u64) -> u64 {
        secs / WINDOW_SECS
    }

    fn at(&self, space: NonceSpace, window: u64) -> String {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.secret)
            .expect("HMAC accepts a key of any length");
        mac.update(space.separator());
        mac.update(&window.to_be_bytes());
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            mac.finalize().into_bytes(),
        )
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn issuer() -> NonceIssuer {
        NonceIssuer::new(Arc::new(b"a-32-byte-test-only-jwt-secret!!".to_vec()))
    }

    #[test]
    fn the_current_nonce_is_accepted() {
        let issuer = issuer();
        let current = issuer.current(NonceSpace::Resource);
        assert!(issuer.accepted(NonceSpace::Resource).contains(&current));
    }

    /// A client that fetched a nonce just before a rotation must not be
    /// refused for using it, so the previous window is accepted too.
    #[test]
    fn the_previous_window_is_still_accepted() {
        let issuer = issuer();
        let window = NonceIssuer::window(now_secs());
        let previous = issuer.at(NonceSpace::Resource, window - 1);
        assert!(issuer.accepted(NonceSpace::Resource).contains(&previous));
    }

    /// But not one from before that, or the rotation would mean nothing.
    #[test]
    fn an_older_window_is_refused() {
        let issuer = issuer();
        let window = NonceIssuer::window(now_secs());
        let stale = issuer.at(NonceSpace::Resource, window - 2);
        assert!(!issuer.accepted(NonceSpace::Resource).contains(&stale));
    }

    /// A nonce issued by the authorization server is not valid at the resource
    /// server, and the reverse.
    #[test]
    fn the_two_spaces_do_not_share_nonces() {
        let issuer = issuer();
        let authorization = issuer.current(NonceSpace::Authorization);
        assert!(
            !issuer
                .accepted(NonceSpace::Resource)
                .contains(&authorization),
            "an authorization-server nonce must not be accepted at the resource server"
        );
    }

    /// A different server does not accept this server's nonces.
    #[test]
    fn a_nonce_does_not_travel_between_servers() {
        let mine = issuer().current(NonceSpace::Resource);
        let theirs = NonceIssuer::new(Arc::new(b"a-different-32-byte-jwt-secret!!".to_vec()));
        assert!(!theirs.accepted(NonceSpace::Resource).contains(&mine));
    }

    /// Two calls inside one window agree, which is what makes the value
    /// usable without storing it.
    #[test]
    fn the_nonce_is_stable_within_a_window() {
        let issuer = issuer();
        assert_eq!(
            issuer.current(NonceSpace::Resource),
            issuer.current(NonceSpace::Resource)
        );
    }
}
