//! The three-hop credential chain, and where each hop goes.
//!
//! Two scripted servers here rather than one, because the thing most worth
//! pinning is *which* server received *which* call. A single host standing in
//! for both is the bug `SpaceHosts` exists to prevent, and it is invisible for
//! as long as every space is the account's own -- there the member is the
//! authority and the two strings are equal.

use atproto_identity::key::{KeyType, generate_key};
use atproto_space::types::{SpaceKey, SpaceType};
use atproto_space::{SpaceUri, credential::create_space_credential};
use atproto_space_client::{Delivery, SpaceHosts, space_read_credential, subscribe_to_space};

mod support;
use support::{Reply, Scripted};

const AUTHORITY: &str = "did:plc:authority";

fn space() -> SpaceUri {
    SpaceUri::new(
        AUTHORITY.to_string(),
        SpaceType::new("app.bsky.group").expect("type"),
        SpaceKey::new("default").expect("key"),
    )
}

/// A real space credential, so the client's decode is exercised rather than
/// stubbed.
fn a_credential(space: &SpaceUri) -> String {
    let authority_key = generate_key(KeyType::P256Private).expect("key");
    // A real thumbprint shape: 43 unpadded base64url characters, which is
    // what a SHA-256 JWK thumbprint is and what the credential type checks.
    let jkt = "0000000000000000000000000000000000000000000";
    create_space_credential(AUTHORITY, space, jkt, None, &authority_key, 3_600).expect("credential")
}

/// Hop 1 goes to the member's PDS; hops 2 and 3 go to the authority.
///
/// The regression test for `SpaceHosts`, and it fails two ways if the fields
/// are swapped: the recorded method lists come out the wrong way round, and
/// the flow itself breaks, because each server is scripted only with answers
/// to the calls it is supposed to receive.
#[tokio::test]
async fn each_hop_goes_to_the_host_that_owns_it() {
    let space = space();
    let credential = a_credential(&space);

    let member_pds =
        Scripted::start(vec![Reply::new(200, r#"{"token":"a.delegation.token"}"#)]).await;
    let authority = Scripted::start(vec![
        Reply::new(200, &format!(r#"{{"credential":"{credential}"}}"#)),
        Reply::new(200, r#"{"expiresAt":"2026-10-17T00:00:00Z"}"#),
    ])
    .await;

    let key = generate_key(KeyType::P256Private).expect("key");
    let subscription = subscribe_to_space(
        &reqwest::Client::new(),
        SpaceHosts {
            member_pds: &member_pds.base_url,
            authority: &authority.base_url,
        },
        &key,
        "an-access-token",
        &space,
        Delivery::Service("did:web:syncer.example#atproto_space_syncer"),
        None,
    )
    .await
    .expect("subscribe");

    let at_member: Vec<String> = member_pds
        .requests()
        .await
        .iter()
        .map(|request| request.xrpc_method().to_string())
        .collect();
    let at_authority: Vec<String> = authority
        .requests()
        .await
        .iter()
        .map(|request| request.xrpc_method().to_string())
        .collect();

    assert_eq!(at_member, vec!["com.atproto.space.getDelegationToken"]);
    assert_eq!(
        at_authority,
        vec![
            "com.atproto.space.getSpaceCredential",
            "com.atproto.space.registerNotify",
        ]
    );

    // Read from the answer, never assumed: `atproto-pds` takes this from a
    // setting clamped to 60s..365d, so a client that assumed 24 hours would
    // silently stop receiving deliveries on most of that range.
    assert_eq!(subscription.expires_at, "2026-10-17T00:00:00Z");
    assert_eq!(subscription.credential.claims.sub, space.to_string());
}

/// Hop 2 offers a grant, and hops 1 and 3 offer bound tokens.
///
/// The grant's proof carries no `ath`: there is no bound token to hash, and
/// the proof is there to demonstrate possession of the key the *answer* will
/// be bound to. Getting this backwards produces `401 missing DPoP header` from
/// a server that was never asked about membership.
#[tokio::test]
async fn the_grant_hop_is_a_bearer_with_an_athless_proof() {
    let space = space();
    let credential = a_credential(&space);

    let member_pds =
        Scripted::start(vec![Reply::new(200, r#"{"token":"a.delegation.token"}"#)]).await;
    let authority = Scripted::start(vec![
        Reply::new(200, &format!(r#"{{"credential":"{credential}"}}"#)),
        Reply::new(200, r#"{"expiresAt":"2026-10-17T00:00:00Z"}"#),
    ])
    .await;

    let key = generate_key(KeyType::P256Private).expect("key");
    subscribe_to_space(
        &reqwest::Client::new(),
        SpaceHosts {
            member_pds: &member_pds.base_url,
            authority: &authority.base_url,
        },
        &key,
        "an-access-token",
        &space,
        Delivery::Service("did:web:syncer.example#atproto_space_syncer"),
        None,
    )
    .await
    .expect("subscribe");

    // Hop 1: a bound OAuth access token.
    let hop1 = &member_pds.requests().await[0];
    assert_eq!(hop1.header("authorization"), Some("DPoP an-access-token"));
    assert!(
        hop1.proof_claims().get("ath").is_some(),
        "a bound token's proof hashes it"
    );

    let at_authority = authority.requests().await;

    // Hop 2: a grant.
    let hop2 = &at_authority[0];
    assert_eq!(
        hop2.header("authorization"),
        Some("Bearer a.delegation.token")
    );
    assert!(
        hop2.proof_claims().get("ath").is_none(),
        "a grant has no bound token to hash: {}",
        hop2.proof_claims()
    );

    // And the thumbprint is demonstrated by the proof, not asserted in the
    // body. `dpopJkt` was removed from the input for exactly that reason: it
    // is a claim anyone holding a delegation token can make about a key
    // somebody else controls.
    let hop2_body: serde_json::Value = serde_json::from_str(&hop2.body).expect("json");
    assert!(hop2_body.get("dpopJkt").is_none(), "{hop2_body}");
    assert_eq!(hop2_body["space"], space.to_string());

    // Hop 3: the credential, bound.
    let hop3 = &at_authority[1];
    assert_eq!(
        hop3.header("authorization"),
        Some(format!("DPoP {credential}").as_str())
    );
    assert!(hop3.proof_claims().get("ath").is_some());
}

/// An unregistrable delivery target fails before any hop runs.
///
/// Hops 1 and 2 spend a single-use grant, so discovering at hop 3 that the
/// target was never registrable means the grant was burnt to learn a fact
/// known before hop 1.
#[tokio::test]
async fn an_unregistrable_target_costs_no_requests() {
    let member_pds = Scripted::start(vec![Reply::new(200, r#"{"token":"t"}"#)]).await;
    let authority = Scripted::start(vec![Reply::new(200, "{}")]).await;
    let key = generate_key(KeyType::P256Private).expect("key");

    for target in [
        Delivery::Service("syncer.example"),
        Delivery::Service("did:web"),
        Delivery::Endpoint("http://syncer.example/notify"),
        Delivery::Endpoint("not a url at all"),
    ] {
        let error = subscribe_to_space(
            &reqwest::Client::new(),
            SpaceHosts {
                member_pds: &member_pds.base_url,
                authority: &authority.base_url,
            },
            &key,
            "an-access-token",
            &space(),
            target,
            None,
        )
        .await
        .expect_err("an unregistrable target");

        assert!(
            error
                .to_string()
                .contains("error-atproto-space-client-client-2"),
            "{error}"
        );
    }

    assert!(member_pds.requests().await.is_empty());
    assert!(authority.requests().await.is_empty());
}

/// A registrable target is accepted in both shapes.
#[tokio::test]
async fn a_registrable_target_is_accepted_in_both_shapes() {
    let space = space();
    let credential = a_credential(&space);
    let key = generate_key(KeyType::P256Private).expect("key");

    for (target, field) in [
        (
            Delivery::Service("did:web:syncer.example#atproto_space_syncer"),
            "service",
        ),
        (
            Delivery::Endpoint("https://syncer.example/notify"),
            "endpoint",
        ),
    ] {
        let member_pds =
            Scripted::start(vec![Reply::new(200, r#"{"token":"a.delegation.token"}"#)]).await;
        let authority = Scripted::start(vec![
            Reply::new(200, &format!(r#"{{"credential":"{credential}"}}"#)),
            Reply::new(200, r#"{"expiresAt":"2026-10-17T00:00:00Z"}"#),
        ])
        .await;

        subscribe_to_space(
            &reqwest::Client::new(),
            SpaceHosts {
                member_pds: &member_pds.base_url,
                authority: &authority.base_url,
            },
            &key,
            "an-access-token",
            &space,
            target,
            None,
        )
        .await
        .expect("subscribe");

        let hop3 = &authority.requests().await[1];
        let body: serde_json::Value = serde_json::from_str(&hop3.body).expect("json");
        assert!(body.get(field).is_some(), "{field} missing from {body}");
    }
}

/// A refusal at hop 1 is a typed error naming the method and the host, and
/// nothing downstream is attempted.
#[tokio::test]
async fn a_refusal_at_hop_one_stops_the_chain() {
    let member_pds = Scripted::start(vec![Reply::new(
        403,
        r#"{"error":"InvalidRequest","message":"app passwords cannot delegate"}"#,
    )])
    .await;
    let authority = Scripted::start(vec![Reply::new(200, "{}")]).await;

    let key = generate_key(KeyType::P256Private).expect("key");
    let error = space_read_credential(
        &reqwest::Client::new(),
        SpaceHosts {
            member_pds: &member_pds.base_url,
            authority: &authority.base_url,
        },
        &key,
        "an-app-password-session",
        &space(),
    )
    .await
    .expect_err("refused");

    assert!(
        error
            .to_string()
            .contains("com.atproto.space.getDelegationToken"),
        "{error}"
    );
    assert!(
        authority.requests().await.is_empty(),
        "hop 2 must not run after hop 1 refuses"
    );
}
