//! Which account a completed flow is allowed to be for.
//!
//! Section 4.6 of the AT Protocol OAuth specification allows three login-hint
//! shapes. A handle and a DID both name an account, so the flow knows its
//! subject before the redirect and pins it. The third names a *server*, and
//! there is no account in it to pin -- so a client that can only pin cannot
//! support that shape at all, and refusing at the callback instead means the
//! user types a URL, is redirected, signs in, comes back, and only then learns
//! it was never going to work.

use atproto_oauth::errors::OAuthClientError;
use atproto_oauth::workflow::{SubjectBinding, TokenResponse, bind_response_issuer, bind_subject};

const HOLDER: &str = "did:plc:holder";

fn response(sub: Option<&str>) -> TokenResponse {
    TokenResponse {
        access_token: "an-access-token".to_string(),
        token_type: "DPoP".to_string(),
        refresh_token: None,
        scope: "atproto".to_string(),
        expires_in: 3600,
        sub: sub.map(str::to_string),
        extra: Default::default(),
    }
}

/// The existing guarantee, made explicit: a pinned subject must match.
#[test]
fn a_pinned_subject_must_match() {
    assert_eq!(
        bind_subject(SubjectBinding::Pinned(HOLDER), &response(Some(HOLDER))).expect("bind"),
        HOLDER
    );

    let error = bind_subject(
        SubjectBinding::Pinned(HOLDER),
        &response(Some("did:plc:someone-else")),
    )
    .expect_err("a different account");
    assert!(
        matches!(error, OAuthClientError::TokenSubjectMismatch { .. }),
        "{error}"
    );
}

/// An empty pin is a caller that meant to pin and had nothing to pin with,
/// which is a different thing from choosing not to.
#[test]
fn an_empty_pin_is_still_refused() {
    let error = bind_subject(SubjectBinding::Pinned(""), &response(Some(HOLDER)))
        .expect_err("nothing to pin with");
    assert!(
        matches!(error, OAuthClientError::MissingExpectedSubject),
        "{error}"
    );
}

/// `Discovered` returns whatever the authorization server proved, and compares
/// it to nothing.
#[test]
fn a_discovered_subject_is_returned_and_not_compared() {
    assert_eq!(
        bind_subject(
            SubjectBinding::Discovered,
            &response(Some("did:plc:whoever"))
        )
        .expect("bind"),
        "did:plc:whoever"
    );
}

/// It is narrower, not absent: a response naming no subject at all is still
/// refused, because the token has to say who it is for.
#[test]
fn a_discovered_binding_still_requires_a_subject() {
    let error = bind_subject(SubjectBinding::Discovered, &response(None)).expect_err("no subject");
    assert!(
        matches!(error, OAuthClientError::TokenResponseMissingSubject),
        "{error}"
    );
}

/// And `iss` still binds the response to this flow.
///
/// This is what makes `Discovered` narrower rather than unbound: with no prior
/// expectation about the account, RFC 9207's `iss` and the PKCE verifier are
/// what is left.
#[test]
fn the_response_issuer_still_binds() {
    bind_response_issuer("https://pds.example", Some("https://pds.example")).expect("same issuer");

    let error = bind_response_issuer("https://pds.example", Some("https://attacker.example"))
        .expect_err("a different issuer");
    assert!(
        matches!(
            error,
            OAuthClientError::AuthorizationResponseIssuerMismatch { .. }
        ),
        "{error}"
    );
}

/// AT Protocol requires the parameter, so an absent one is a refusal rather
/// than a tolerated omission -- without it a response from one authorization
/// server can be replayed into a flow started with another.
#[test]
fn an_absent_response_issuer_is_refused() {
    let error = bind_response_issuer("https://pds.example", None).expect_err("no iss");
    assert!(
        matches!(error, OAuthClientError::AuthorizationResponseMissingIssuer),
        "{error}"
    );
}

/// The pre-existing entry point keeps its behaviour.
#[test]
fn bind_token_subject_still_pins() {
    atproto_oauth::workflow::bind_token_subject(HOLDER, &response(Some(HOLDER))).expect("bind");
    atproto_oauth::workflow::bind_token_subject(HOLDER, &response(Some("did:plc:other")))
        .expect_err("a different account");
    atproto_oauth::workflow::bind_token_subject("", &response(Some(HOLDER)))
        .expect_err("nothing to pin with");
}
