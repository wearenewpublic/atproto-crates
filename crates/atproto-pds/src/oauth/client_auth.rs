//! Authenticating a confidential client at the token endpoint.
//!
//! A client's metadata declares how it authenticates, in
//! `token_endpoint_auth_method`. This server parsed that field and then ignored
//! it, so a client declaring `private_key_jwt` was authenticated exactly as
//! weakly as one declaring `none`: not at all.
//!
//! That is worse than an unimplemented feature. Private-key client
//! authentication exists so that a stolen authorization code is useless without
//! the key — a code is a bearer value that travels through a redirect, a
//! browser, and often a log. Ignoring the declaration handed that protection
//! back: anyone holding a confidential client's code could redeem it here with
//! no assertion at all.
//!
//! The advertised list could not simply drop the method, either. The AT
//! Protocol client library refuses an authorization server whose metadata omits
//! `private_key_jwt` — for every client, including the public ones that use
//! `none` — so removing it would have broken every login rather than narrowing
//! anything.
//!
//! # Failing closed
//!
//! A client that declares `private_key_jwt` and whose keys cannot be fetched is
//! refused. Falling back to unauthenticated on the error path would rebuild the
//! hole out of the recovery code, which is how a permissive default usually
//! gets back in.

use crate::http::errors::XrpcError;
use crate::oauth::client_metadata::ClientMetadata;
use axum::http::StatusCode;

/// The only assertion type RFC 7523 defines for this.
pub const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How a client said it authenticates.
///
/// Absent means `none`, per RFC 7591 — a client that says nothing is public.
#[derive(Debug, PartialEq, Eq)]
pub enum Method {
    /// Public client. The authorization code and PKCE verifier are the whole
    /// of what it presents.
    None,
    /// Confidential client. Must present a signed assertion.
    PrivateKeyJwt,
}

impl Method {
    /// Read the method a client declared.
    #[must_use]
    pub fn declared(metadata: &ClientMetadata) -> Self {
        match metadata.token_endpoint_auth_method.as_deref() {
            Some("private_key_jwt") => Method::PrivateKeyJwt,
            _ => Method::None,
        }
    }
}

/// Require the client to authenticate the way its own metadata says it does.
///
/// The check is on the *declaration*, not on what the request happens to
/// carry: a confidential client that presents nothing must be refused rather
/// than quietly downgraded, which is the whole point of declaring a method.
///
/// # Errors
///
/// `invalid_client` when a confidential client presents no assertion, presents
/// one this server cannot verify, or has keys this server cannot reach.
pub async fn authenticate(
    metadata: &ClientMetadata,
    client_id: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    jti_guard: &crate::security::JtiReplayGuard,
    expected_audience: &[String],
) -> Result<Option<String>, XrpcError> {
    let refused = |detail: &str| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            detail.to_string(),
        )
    };

    if Method::declared(metadata) == Method::None {
        // A public client presenting an assertion is confused rather than
        // hostile, and nothing here can verify one for a client that published
        // no keys. Refusing it is clearer than ignoring it.
        if assertion.is_some() {
            return Err(refused(
                "this client is registered as public and cannot present a client assertion",
            ));
        }
        return Ok(None);
    }

    // From here the client declared `private_key_jwt`, so every path that is
    // not a verified assertion is a refusal.
    match assertion_type {
        Some(JWT_BEARER_ASSERTION) => {}
        Some(other) => {
            return Err(refused(&format!(
                "unsupported client_assertion_type {other}; want {JWT_BEARER_ASSERTION}"
            )));
        }
        // Named separately from a missing assertion: a client sending one
        // without the other has a bug this should point at.
        None if assertion.is_some() => {
            return Err(refused(
                "client_assertion was supplied without client_assertion_type",
            ));
        }
        None => {
            tracing::warn!(
                client_id = %client_id,
                "refused a confidential client that presented no assertion"
            );
            return Err(refused(
                "this client is registered as confidential and must present a client assertion",
            ));
        }
    }

    let Some(assertion) = assertion else {
        return Err(refused(
            "this client is registered as confidential and must present a client assertion",
        ));
    };

    // Fail closed. A client that cannot be authenticated is not a client that
    // may skip authentication -- key resolution failures surface as refusals
    // from inside verify_assertion.
    verify_assertion(assertion, client_id, jti_guard, expected_audience)
        .await
        .map_err(|detail| {
            tracing::warn!(client_id = %client_id, detail = %detail, "client assertion refused");
            refused(&detail)
        })
}

/// Verify a client assertion: signature first, then claims.
///
/// RFC 7523 §3. The signature is checked against the key the client publishes
/// at its own `client_id`, resolved by `kid` — the same path a PAR request
/// object takes, so a client that can sign one can sign the other.
///
/// Claims are checked after the signature, deliberately: reading claims out of
/// a JWT nobody has authenticated is how an unsigned token gets treated as
/// evidence of anything.
async fn verify_assertion(
    assertion: &str,
    client_id: &str,
    jti_guard: &crate::security::JtiReplayGuard,
    expected_audience: &[String],
) -> Result<Option<String>, String> {
    let parts: Vec<&str> = assertion.split('.').collect();
    if parts.len() != 3 {
        return Err("client assertion is not a compact JWS".to_string());
    }

    let header: serde_json::Value = decode_part(parts[0], "header")?;
    let alg = header["alg"].as_str().unwrap_or_default();
    if !crate::oauth::par::SUPPORTED_JWS_ALGS.contains(&alg) {
        return Err(format!(
            "unsupported client assertion alg {alg}; want one of {:?}",
            crate::oauth::par::SUPPORTED_JWS_ALGS
        ));
    }

    let key = crate::oauth::par::resolve_client_signing_key(client_id, header["kid"].as_str())
        .await
        .map_err(|e| format!("resolve client key: {e}"))?;

    let signature =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
            .map_err(|e| format!("decode signature: {e}"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verify_jws_signature(&key, &signature, signing_input.as_bytes())?;

    let claims: serde_json::Value = decode_part(parts[1], "payload")?;

    // `iss` and `sub` are both the client, which is what distinguishes a client
    // assertion from every other JWT this server accepts. A mismatch means the
    // assertion was minted for something else and is being replayed here.
    for field in ["iss", "sub"] {
        match claims[field].as_str() {
            Some(v) if v == client_id => {}
            Some(other) => {
                return Err(format!(
                    "client assertion {field} is {other}, not {client_id}"
                ));
            }
            None => return Err(format!("client assertion has no {field}")),
        }
    }

    // Audience must name this server, or an assertion minted for a different
    // authorization server would be accepted here -- the mix-up this claim
    // exists to prevent.
    if !names_this_server(&claims["aud"], expected_audience) {
        return Err("client assertion aud does not name this server".to_string());
    }

    let exp = claims["exp"]
        .as_i64()
        .ok_or_else(|| "client assertion has no exp".to_string())?;
    let now = chrono::Utc::now().timestamp();
    if exp <= now {
        return Err("client assertion has expired".to_string());
    }

    // Single use, per RFC 7523 §3. An assertion is not bound to the code it
    // accompanies -- nothing in it names one -- so without this a captured
    // assertion authenticates this client for *any* code an attacker holds,
    // for as long as `exp` allows. Spending the `jti` makes one capture worth
    // one redemption rather than a credential reusable for the window.
    //
    // Held until the assertion expires and no longer: past `exp` the check
    // above refuses it anyway, so a longer entry only spends memory to
    // re-refuse something already refused.
    let jti = claims["jti"]
        .as_str()
        .ok_or_else(|| "client assertion has no jti".to_string())?;
    let remaining = u64::try_from(exp - now).unwrap_or(0).saturating_add(1);
    jti_guard
        .check_and_insert(jti, std::time::Duration::from_secs(remaining))
        .await
        .map_err(|e| format!("client assertion replay: {e}"))?;

    Ok(header["kid"].as_str().map(str::to_string))
}

/// Decode one base64url JWS segment as JSON.
fn decode_part(part: &str, what: &str) -> Result<serde_json::Value, String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, part)
        .map_err(|e| format!("decode {what}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {what}: {e}"))
}

/// Whether an assertion's `aud` names this server.
///
/// Passed in rather than held in a thread-local, which is what this was and
/// why it failed intermittently. `verify_assertion` awaits a key fetch, tokio
/// may move the task to a different worker across that await, and a value set
/// before it is not there afterwards -- so a correctly-signed assertion was
/// refused for naming an audience the server had, on that thread, no record of
/// accepting. The client saw a refusal it could not reproduce, and retrying
/// sometimes worked, which is the worst shape a failure can take.
///
/// A thread-local is never the right carrier for request state in async code:
/// the task, not the thread, is the thing the state belongs to.
///
/// RFC 7519 allows `aud` to be a string or an array; one matching entry is
/// enough.
fn names_this_server(aud: &serde_json::Value, expected: &[String]) -> bool {
    match aud {
        serde_json::Value::String(a) => expected.iter().any(|e| e == a),
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str())
            .any(|a| expected.iter().any(|e| e == a)),
        _ => false,
    }
}

/// Verify the signature over a client assertion's signing input.
///
/// `AnyS`, not the AT Protocol default, and that is the whole point of this
/// function existing separately.
///
/// A client assertion is an ordinary ES256 JWS produced by whatever client is
/// talking to us. RFC 7515 defines its signature as the raw `r || s` pair and
/// imposes no low-S constraint, and WebCrypto -- every browser, and Node's
/// `crypto.subtle` -- does not normalise `s`. About half of all assertions from
/// a conforming client therefore carry the high-S form. Refusing them does not
/// make anything stricter; it fails authentication at random for clients doing
/// nothing wrong, and reports it as signature malleability, which sends whoever
/// reads the error looking for an attack rather than a coin flip.
///
/// Low-S belongs to the signatures AT Protocol itself specifies -- repository
/// commits, service auth, PLC operations -- where a unique byte string per
/// signature is a property something depends on. Nothing here depends on it.
///
/// `dpop.rs` and `jwt.rs` make the same call for the same reason. This site was
/// missed when those were fixed, so it is a named function now: the policy is
/// the thing worth asserting, and it cannot be asserted inline.
fn verify_jws_signature(
    key: &atproto_identity::key::KeyData,
    signature: &[u8],
    signing_input: &[u8],
) -> Result<(), String> {
    atproto_identity::key::validate_with_policy(
        key,
        signature,
        signing_input,
        atproto_identity::key::SignaturePolicy::AnyS,
    )
    .map_err(|e| format!("signature verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audiences() -> Vec<String> {
        vec!["https://pds.example".to_string()]
    }

    fn guard() -> crate::security::JtiReplayGuard {
        crate::security::JtiReplayGuard::new(64)
    }

    fn metadata(method: Option<&str>) -> ClientMetadata {
        let mut m = crate::oauth::client_metadata::loopback_client_metadata("http://localhost")
            .expect("loopback metadata");
        m.token_endpoint_auth_method = method.map(str::to_string);
        m
    }

    /// A public client authenticates with no key, and says so.
    ///
    /// `None` here is what a refresh compares against later, so it has to mean
    /// "no key" rather than "did not look".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_public_client_reports_no_key() {
        let kid = authenticate(
            &metadata(None),
            "http://localhost",
            None,
            None,
            &guard(),
            &audiences(),
        )
        .await
        .expect("a public client authenticates by presenting nothing");
        assert_eq!(kid, None);
    }

    /// A confidential client presenting nothing is refused, rather than
    /// falling through as public.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_confidential_client_must_present_an_assertion() {
        let err = authenticate(
            &metadata(Some("private_key_jwt")),
            "http://localhost",
            None,
            None,
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("a confidential client must authenticate");
        assert_eq!(err.name, "invalid_client");
    }

    /// The `kid` reported is the one from the assertion header.
    ///
    /// Read from the header before the signature is checked, but only
    /// *returned* from the path where the signature verified -- so what a
    /// refresh pins against is a key that actually signed something.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_reported_kid_comes_from_the_verified_assertion() {
        // An assertion naming a kid the client does not publish cannot verify,
        // so nothing is reported and the refresh has nothing to match.
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"ES256","kid":"not-a-published-key"}"#,
        );
        let err = verify_assertion(
            &format!("{header}.e30.c2ln"),
            "https://app.example/client-metadata.json",
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("an unresolvable kid cannot verify");
        assert!(
            err.contains("resolve client key") || err.contains("client_id"),
            "expected a key-resolution refusal, got {err}"
        );
    }

    /// A malformed assertion is refused before anything is read from it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_assertion_that_is_not_a_jws_is_refused() {
        let err = verify_assertion("not-a-jws", "https://app.example/x", &guard(), &audiences())
            .await
            .expect_err("three segments or nothing");
        assert!(err.contains("compact JWS"), "{err}");
    }

    /// An algorithm this server cannot verify is refused by name.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unverifiable_alg_is_refused() {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"none"}"#,
        );
        let err = verify_assertion(
            &format!("{header}.e30.sig"),
            "https://app.example/x",
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("`none` must never verify");
        assert!(err.contains("unsupported client assertion alg"), "{err}");
    }

    /// The audience gate, and the shapes RFC 7519 allows.
    #[test]
    fn only_an_audience_naming_this_server_passes() {
        let expected = audiences();

        assert!(names_this_server(
            &serde_json::json!("https://pds.example"),
            &expected
        ));
        assert!(
            !names_this_server(
                &serde_json::json!("https://someone-else.example"),
                &expected
            ),
            "an assertion minted for another authorization server must not verify here"
        );
        // `aud` may be an array; one matching entry is enough.
        assert!(names_this_server(
            &serde_json::json!(["https://other.example", "https://pds.example"]),
            &expected
        ));
        assert!(!names_this_server(
            &serde_json::json!(["https://other.example"]),
            &expected
        ));
        // Absent, or any other shape, is not a match.
        assert!(!names_this_server(&serde_json::Value::Null, &expected));
    }

    /// A client that publishes no keys cannot be authenticated, so it is
    /// refused rather than allowed through.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_with_unreachable_keys_is_refused() {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            br#"{"alg":"ES256"}"#,
        );
        let err = verify_assertion(
            &format!("{header}.e30.sig"),
            "https://nonexistent.invalid/client-metadata.json",
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("unreachable keys must fail closed");
        assert!(err.contains("resolve client key"), "{err}");
    }

    /// The guard spends a `jti` once, so a captured assertion is worth one
    /// redemption rather than every code an attacker later steals.
    ///
    /// Exercised against the guard directly: reaching it through
    /// `verify_assertion` needs a real signature from a reachable client, and
    /// the property worth pinning is that the second presentation is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_jti_is_spent_once() {
        let g = guard();
        let ttl = std::time::Duration::from_secs(60);

        g.check_and_insert("assertion-jti", ttl)
            .await
            .expect("first use is the legitimate one");

        assert!(
            g.check_and_insert("assertion-jti", ttl).await.is_err(),
            "a replayed client assertion was accepted"
        );
    }

    /// Distinct assertions are unaffected by each other.
    #[tokio::test(flavor = "multi_thread")]
    async fn distinct_assertions_do_not_collide() {
        let g = guard();
        let ttl = std::time::Duration::from_secs(60);

        g.check_and_insert("one", ttl).await.unwrap();
        g.check_and_insert("two", ttl)
            .await
            .expect("a different assertion must not be refused as a replay");
    }

    /// A client that declared nothing is public, per RFC 7591.
    #[test]
    fn an_undeclared_method_is_public() {
        assert_eq!(Method::declared(&metadata(None)), Method::None);
        assert_eq!(Method::declared(&metadata(Some("none"))), Method::None);
        assert_eq!(
            Method::declared(&metadata(Some("private_key_jwt"))),
            Method::PrivateKeyJwt
        );
    }

    /// The hole this closes: a confidential client presenting nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_confidential_client_cannot_skip_its_assertion() {
        let err = authenticate(
            &metadata(Some("private_key_jwt")),
            "https://app.example/client-metadata.json",
            None,
            None,
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("a declared method must be enforced");

        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.name, "invalid_client");
    }

    /// A public client is unaffected, which is every client today.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_public_client_is_unchanged() {
        authenticate(
            &metadata(None),
            "https://app.example/x",
            None,
            None,
            &guard(),
            &audiences(),
        )
        .await
        .expect("public clients must keep working");
    }

    /// An unknown assertion type is refused rather than read as absent.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_assertion_type_is_refused() {
        let err = authenticate(
            &metadata(Some("private_key_jwt")),
            "https://app.example/x",
            Some("urn:example:something-else"),
            Some("ey.."),
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("an unrecognised assertion type must not pass");

        assert!(
            err.message.contains("unsupported client_assertion_type"),
            "{}",
            err.message
        );
    }

    /// A public client presenting an assertion is refused, not ignored.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_public_client_may_not_present_an_assertion() {
        let err = authenticate(
            &metadata(None),
            "https://app.example/x",
            Some(JWT_BEARER_ASSERTION),
            Some("ey.."),
            &guard(),
            &audiences(),
        )
        .await
        .expect_err("nothing can verify an assertion for a client with no keys");

        assert_eq!(err.name, "invalid_client");
    }

    /// A high-S client assertion verifies.
    ///
    /// The regression: this path called the bare `validate`, which is
    /// `LowSOnly`, so a conforming client whose signature happened to land in
    /// the upper half of the curve order was refused with
    /// "Signature is malleable" -- for roughly half of its attempts, at random,
    /// having done nothing wrong. The DPoP and JWT paths were fixed for this in
    /// 7977b26; this one was missed.
    ///
    /// The high-S twin is constructed rather than hunted for: for any valid
    /// `(r, s)`, `(r, n - s)` verifies over the same message, so negating `s`
    /// flips the form deterministically.
    #[test]
    fn a_high_s_client_assertion_is_accepted() {
        use atproto_identity::key::{KeyType, generate_key, sign, to_public};
        use p256::elliptic_curve::scalar::IsHigh;

        let signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcC5leGFtcGxlIn0";

        // Repeated because `sign` normalises: the flip below is what
        // guarantees a high-S case rather than waiting for one to occur.
        for _ in 0..8 {
            let private_key = generate_key(KeyType::P256Private).unwrap();
            let public_key = to_public(&private_key).unwrap();
            let low_s = sign(&private_key, signing_input).unwrap();

            let parsed = p256::ecdsa::Signature::from_slice(&low_s).unwrap();
            let high_s =
                p256::ecdsa::Signature::from_scalars(parsed.r().to_owned(), -parsed.s().to_owned())
                    .unwrap();
            assert!(
                bool::from(high_s.s().is_high()),
                "negating s must yield the high-S twin"
            );

            verify_jws_signature(&public_key, &low_s, signing_input)
                .expect("a low-S assertion must verify");
            verify_jws_signature(&public_key, &high_s.to_vec(), signing_input)
                .expect("a high-S assertion must verify -- JWS imposes no low-S constraint");
        }
    }

    /// A signature that is simply wrong is still refused.
    ///
    /// Accepting high-S widens which encodings verify, not which keys do.
    #[test]
    fn a_signature_from_another_key_is_still_refused() {
        use atproto_identity::key::{KeyType, generate_key, sign, to_public};

        let signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwcC5leGFtcGxlIn0";
        let signer = generate_key(KeyType::P256Private).unwrap();
        let impostor = to_public(&generate_key(KeyType::P256Private).unwrap()).unwrap();
        let signature = sign(&signer, signing_input).unwrap();

        assert!(verify_jws_signature(&impostor, &signature, signing_input).is_err());
        assert!(verify_jws_signature(&impostor, b"not a signature", signing_input).is_err());
    }
}
