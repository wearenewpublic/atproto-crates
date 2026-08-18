//! What a service-auth verifier accepts, and what it must not.
//!
//! Every token here is minted with a real key and signed over its real signing
//! input. A hand-built string would be refused for the wrong reason -- "not a
//! JWT" rather than "scoped to no method" -- and the test would stay green
//! while the check it names was absent. That mistake has been made and fixed
//! once already in a downstream reimplementation of this verifier.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use atproto_identity::key::{KeyData, KeyType, generate_key, jws_alg, sign, to_public};
use atproto_identity::model::{Document, VerificationMethod};
use atproto_identity::traits::IdentityResolver;
use atproto_xrpcs::errors::ServiceAuthError;
use atproto_xrpcs::service_auth::{
    RevocationCheck, ServiceAuthClaims, ServiceAuthHeader, ServiceAuthPolicy, TYP_SERVICE_AUTH,
    mint_service_auth, verify_service_auth,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const ISSUER: &str = "did:web:issuer.example";
const AUDIENCE: &str = "did:web:receiver.example";
const METHOD: &str = "com.atproto.space.notifyWrite";

/// A resolver that answers with one document and counts how often it is asked.
struct Directory {
    document: Document,
    resolutions: AtomicUsize,
}

#[async_trait]
impl IdentityResolver for Directory {
    async fn resolve(&self, subject: &str) -> Result<Document> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        if subject == self.document.id {
            Ok(self.document.clone())
        } else {
            Err(anyhow::anyhow!("no such DID: {subject}"))
        }
    }
}

/// A document for `did`, publishing `key` as its own `#atproto` method.
fn document_for(did: &str, key: &KeyData) -> Document {
    document_with_method(did, &format!("{did}#atproto"), key)
}

/// A document for `did` publishing an `#atproto` method under `method_id`.
fn document_with_method(did: &str, method_id: &str, key: &KeyData) -> Document {
    let public = to_public(key).expect("public key");
    Document {
        context: vec![],
        id: did.to_string(),
        also_known_as: vec![],
        service: vec![],
        verification_method: vec![VerificationMethod::Multikey {
            id: method_id.to_string(),
            controller: did.to_string(),
            public_key_multibase: format!("{public}"),
            extra: HashMap::new(),
        }],
        extra: HashMap::new(),
    }
}

fn directory(document: Document) -> Directory {
    Directory {
        document,
        resolutions: AtomicUsize::new(0),
    }
}

/// Mint a token with fields the ordinary minter does not let a caller choose.
///
/// Signed for real, so every refusal below is a refusal of the claim under
/// test rather than of a malformed token.
fn mint_raw(key: &KeyData, header: &ServiceAuthHeader, claims: &ServiceAuthClaims) -> String {
    let header_bytes = serde_json::to_vec(header).expect("header");
    let claims_bytes = serde_json::to_vec(claims).expect("claims");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header_bytes),
        URL_SAFE_NO_PAD.encode(&claims_bytes)
    );
    let signature = sign(key, signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&signature))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn header(kid: Option<&str>, key: &KeyData) -> ServiceAuthHeader {
    ServiceAuthHeader {
        alg: jws_alg(key).to_string(),
        typ: TYP_SERVICE_AUTH.to_string(),
        kid: kid.map(str::to_string),
    }
}

fn claims(lxm: Option<&str>) -> ServiceAuthClaims {
    let iat = now();
    ServiceAuthClaims {
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        lxm: lxm.map(str::to_string),
        iat,
        exp: iat + 60,
        jti: "a-nonce".to_string(),
    }
}

// ---------------------------------------------------------------------------

/// An ordinary token verifies.
#[tokio::test]
async fn a_well_formed_token_verifies() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token =
        mint_service_auth(&key, ISSUER, AUDIENCE, METHOD, Duration::from_secs(60)).expect("mint");

    let verified = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect("verify");

    assert_eq!(verified.iss, ISSUER);
    assert_eq!(verified.lxm.as_deref(), Some(METHOD));
}

/// A token scoped to no method is refused.
///
/// It satisfies every method that gates on one, so accepting it makes any
/// service-auth token in existence a wildcard credential here.
#[tokio::test]
async fn a_token_scoped_to_no_method_is_refused() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(&key, &header(None, &key), &claims(None));

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("a token scoped to nothing");

    assert!(
        matches!(error, ServiceAuthError::Unscoped { .. }),
        "{error}"
    );
}

/// A token scoped to another method is refused, and named differently.
#[tokio::test]
async fn a_token_for_another_method_is_refused() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(
        &key,
        &header(None, &key),
        &claims(Some("com.atproto.space.notifySpaceDeleted")),
    );

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("the wrong method");

    assert!(matches!(error, ServiceAuthError::Method { .. }), "{error}");
}

/// A `kid` naming another DID's `#atproto` is refused.
///
/// This is the vulnerability. A `did:web` document is served by whoever
/// controls the domain, so a hostile one can list a verification method
/// belonging to a DID it controls; a verifier matching the fragment alone then
/// checks the signature against the attacker's key and it verifies.
#[tokio::test]
async fn a_kid_naming_another_dids_key_is_refused() {
    let attacker = generate_key(KeyType::P256Private).expect("key");

    // The issuer's document lists a method belonging to somebody else, which
    // is a document a hostile host is free to publish.
    let resolver = directory(document_with_method(
        ISSUER,
        "did:web:attacker.example#atproto",
        &attacker,
    ));

    let mut header = header(Some("did:web:attacker.example#atproto"), &attacker);
    header.typ = TYP_SERVICE_AUTH.to_string();
    let token = mint_raw(&attacker, &header, &claims(Some(METHOD)));

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("a kid belonging to another DID");

    assert!(
        matches!(error, ServiceAuthError::KeyIdentifier { .. }),
        "{error}"
    );
}

/// An absent `kid` is accepted: it is the specified default (proposal 0014).
#[tokio::test]
async fn an_absent_kid_is_accepted() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(&key, &header(None, &key), &claims(Some(METHOD)));

    verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect("an absent kid means #atproto");
}

/// A relative `#atproto` is this issuer's key, and so is the absolute form.
#[tokio::test]
async fn both_renderings_of_the_issuers_kid_are_accepted() {
    let key = generate_key(KeyType::P256Private).expect("key");
    for kid in ["#atproto", "did:web:issuer.example#atproto"] {
        let resolver = directory(document_for(ISSUER, &key));
        let token = mint_raw(&key, &header(Some(kid), &key), &claims(Some(METHOD)));

        verify_service_auth(
            &token,
            &resolver,
            &ServiceAuthPolicy::new(METHOD, AUDIENCE),
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{kid} should verify: {error}"));
    }
}

/// An `iat` in the future is refused, and one inside the skew is accepted.
///
/// The lifetime ceiling is measured from `iat`, so an `iat` the issuer can
/// place anywhere makes the ceiling free too.
#[tokio::test]
async fn an_iat_in_the_future_is_refused_beyond_the_skew() {
    let key = generate_key(KeyType::P256Private).expect("key");

    let mut inside = claims(Some(METHOD));
    inside.iat = now() + 30;
    inside.exp = inside.iat + 60;
    let resolver = directory(document_for(ISSUER, &key));
    verify_service_auth(
        &mint_raw(&key, &header(None, &key), &inside),
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect("30s of drift is inside the 60s tolerance");

    let mut outside = claims(Some(METHOD));
    outside.iat = now() + 3_600;
    outside.exp = outside.iat + 60;
    let resolver = directory(document_for(ISSUER, &key));
    let error = verify_service_auth(
        &mint_raw(&key, &header(None, &key), &outside),
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("an hour of drift is not drift");

    assert!(
        matches!(error, ServiceAuthError::IssuedInTheFuture { .. }),
        "{error}"
    );
}

/// A lifetime past the ceiling is refused even though `exp` is in the future.
///
/// Without this a peer mints a token good for a decade and it stays good until
/// somebody notices it leaked.
#[tokio::test]
async fn a_lifetime_past_the_ceiling_is_refused() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));

    let mut long = claims(Some(METHOD));
    long.exp = long.iat + 60 * 60 * 24 * 365;

    let error = verify_service_auth(
        &mint_raw(&key, &header(None, &key), &long),
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("a year-long credential");

    assert!(
        matches!(error, ServiceAuthError::LifetimeTooLong { .. }),
        "{error}"
    );
    // And `exp` really was in the future, so this is the ceiling talking.
    assert!(long.exp > now());
}

/// The claim checks run before the resolution.
///
/// A token addressed elsewhere or scoped to another method should not buy a
/// network round trip; a verifier that resolves first turns every malformed
/// token into load on somebody else's host.
#[tokio::test]
async fn the_claim_checks_run_before_any_resolution() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(&key, &header(None, &key), &claims(None));

    let _ = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("scoped to nothing");

    assert_eq!(resolver.resolutions.load(Ordering::Relaxed), 0);
}

/// An unaudienced policy verifies and hands back the claims, so the caller can
/// inspect an audience it could not have predicted.
#[tokio::test]
async fn an_unaudienced_policy_returns_the_claims() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));

    let mut fragmented = claims(Some(METHOD));
    fragmented.aud = "did:web:receiver.example#atproto_space_syncer".to_string();
    let token = mint_raw(&key, &header(None, &key), &fragmented);

    let verified = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::unaudienced(METHOD),
        None,
    )
    .await
    .expect("verify");

    assert_eq!(
        verified.aud,
        "did:web:receiver.example#atproto_space_syncer"
    );
}

/// A token naming a service fragment satisfies an expectation of the bare DID,
/// and never a different DID.
#[tokio::test]
async fn a_service_fragment_satisfies_the_bare_did() {
    let key = generate_key(KeyType::P256Private).expect("key");

    let mut fragmented = claims(Some(METHOD));
    fragmented.aud = "did:web:receiver.example#atproto_space_syncer".to_string();
    let token = mint_raw(&key, &header(None, &key), &fragmented);

    let resolver = directory(document_for(ISSUER, &key));
    verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect("a fragment selects an entry of the same receiver");

    let resolver = directory(document_for(ISSUER, &key));
    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, "did:web:somewhere-else.example"),
        None,
    )
    .await
    .expect_err("a different receiver entirely");
    assert!(
        matches!(error, ServiceAuthError::Audience { .. }),
        "{error}"
    );
}

struct Revocations(Vec<String>);

#[async_trait]
impl RevocationCheck for Revocations {
    async fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        Ok(self.0.iter().any(|revoked| revoked == jti))
    }
}

struct BrokenRevocations;

#[async_trait]
impl RevocationCheck for BrokenRevocations {
    async fn is_revoked(&self, _jti: &str) -> Result<bool, String> {
        Err("the revocation store is down".to_string())
    }
}

#[tokio::test]
async fn a_revoked_token_is_refused() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(&key, &header(None, &key), &claims(Some(METHOD)));
    let revocations = Revocations(vec!["a-nonce".to_string()]);

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        Some(&revocations),
    )
    .await
    .expect_err("revoked");

    assert!(matches!(error, ServiceAuthError::Revoked { .. }), "{error}");
}

/// A revocation list that cannot be read refuses the token.
///
/// "I could not check" is not "no".
#[tokio::test]
async fn an_unreadable_revocation_list_refuses() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));
    let token = mint_raw(&key, &header(None, &key), &claims(Some(METHOD)));

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        Some(&BrokenRevocations),
    )
    .await
    .expect_err("an unreadable list");

    assert!(
        matches!(error, ServiceAuthError::RevocationUnavailable { .. }),
        "{error}"
    );
}

/// A signature from a key the issuer does not publish is refused as a
/// signature failure, not as an unresolvable issuer.
#[tokio::test]
async fn a_foreign_signature_is_refused() {
    let published = generate_key(KeyType::P256Private).expect("key");
    let other = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &published));
    let token = mint_raw(&other, &header(None, &other), &claims(Some(METHOD)));

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("signed by somebody else");

    assert!(
        matches!(error, ServiceAuthError::Signature { .. }),
        "{error}"
    );
}

/// An issuer whose host cannot be reached is not a peer lying about itself.
#[tokio::test]
async fn an_unreachable_issuer_is_named_as_such() {
    let key = generate_key(KeyType::P256Private).expect("key");
    // The directory only knows some other DID, so resolving ISSUER fails.
    let resolver = directory(document_for("did:web:somebody.else", &key));
    let token = mint_raw(&key, &header(None, &key), &claims(Some(METHOD)));

    let error = verify_service_auth(
        &token,
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("unresolvable");

    assert!(
        matches!(error, ServiceAuthError::IssuerUnresolved { .. }),
        "{error}"
    );
}

/// An expired token is refused.
#[tokio::test]
async fn an_expired_token_is_refused() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let resolver = directory(document_for(ISSUER, &key));

    let mut expired = claims(Some(METHOD));
    expired.iat = now() - 300;
    expired.exp = now() - 240;

    let error = verify_service_auth(
        &mint_raw(&key, &header(None, &key), &expired),
        &resolver,
        &ServiceAuthPolicy::new(METHOD, AUDIENCE),
        None,
    )
    .await
    .expect_err("expired");

    assert!(matches!(error, ServiceAuthError::Expired { .. }), "{error}");
}

/// A minted token round-trips through the verifier that will see it.
#[tokio::test]
async fn a_minted_token_carries_the_kid_it_will_be_checked_against() {
    let key = generate_key(KeyType::P256Private).expect("key");
    let token =
        mint_service_auth(&key, ISSUER, AUDIENCE, METHOD, Duration::from_secs(60)).expect("mint");

    let header_b64 = token.split('.').next().expect("a header");
    let header: ServiceAuthHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).expect("base64"))
            .expect("header");

    assert_eq!(header.kid.as_deref(), Some("#atproto"));
    assert_eq!(header.typ, TYP_SERVICE_AUTH);
}
