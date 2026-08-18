//! Space management: what goes on the wire, and what the types make
//! impossible to omit.

use atproto_identity::key::{KeyType, generate_key};
use atproto_space::SpaceUri;
use atproto_space::types::{SpaceKey, SpaceType};
use atproto_space_client::{
    CreateSpace, ListSpaces, SpaceSession, create_space, delete_space, get_space, list_spaces,
};

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

/// `policy` and `appAccess` are not optional on the type, so they cannot be
/// omitted from the wire.
///
/// The lexicon marks both required. A host that accepted their absence and
/// applied its documented defaults answered `200` with a silently defaulted
/// space, and a shipped client ran that way for months -- invalid against the
/// schema, accepted, and configured exactly as its owner intended. Making them
/// mandatory fields is what keeps that from being reachable by omission rather
/// than by decision.
#[tokio::test]
async fn create_space_always_sends_both_policies() {
    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"uri":"at://did:plc:authority/space/app.bsky.group/default"}"#,
    )])
    .await;

    let key = generate_key(KeyType::P256Private).expect("key");
    let http = reqwest::Client::new();
    let created = create_space(
        SpaceSession {
            http: &http,
            host: &server.base_url,
            dpop_key: &key,
            access_token: "an-access-token",
        },
        &CreateSpace {
            did: None,
            space_type: "app.bsky.group",
            skey: Some("default"),
            policy: serde_json::json!({"$type": "com.atproto.simplespace.defs#memberListPolicy"}),
            app_access: serde_json::json!({"$type": "com.atproto.simplespace.defs#open"}),
        },
    )
    .await
    .expect("create");

    assert_eq!(created, space());

    let request = &server.requests().await[0];
    assert_eq!(request.xrpc_method(), "com.atproto.simplespace.createSpace");
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("json");
    assert!(body.get("policy").is_some(), "{body}");
    assert!(body.get("appAccess").is_some(), "{body}");
    assert_eq!(body["type"], "app.bsky.group");
    assert_eq!(body["skey"], "default");
    // Absent rather than null: the lexicon defaults `did` to the caller.
    assert!(body.get("did").is_none(), "{body}");
}

/// `listSpaces` is `com.atproto.space`; the management calls are
/// `com.atproto.simplespace`. Mixing them up is a 404 from a working server.
#[tokio::test]
async fn each_call_uses_the_lexicon_that_owns_it() {
    let key = generate_key(KeyType::P256Private).expect("key");

    let http = reqwest::Client::new();
    let session = |host: &'static str| SpaceSession {
        http: &http,
        host,
        dpop_key: &key,
        access_token: "token",
    };

    let server = Scripted::start(vec![Reply::new(200, r#"{"spaces":[]}"#)]).await;
    let host: &'static str = Box::leak(server.base_url.clone().into_boxed_str());
    list_spaces(session(host), &ListSpaces::default())
        .await
        .expect("list");
    assert_eq!(
        server.requests().await[0].xrpc_method(),
        "com.atproto.space.listSpaces"
    );

    let server = Scripted::start(vec![Reply::new(200, "")]).await;
    let host: &'static str = Box::leak(server.base_url.clone().into_boxed_str());
    delete_space(session(host), &space()).await.expect("delete");
    assert_eq!(
        server.requests().await[0].xrpc_method(),
        "com.atproto.simplespace.deleteSpace"
    );

    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"uri":"at://did:plc:authority/space/app.bsky.group/default","policy":{},"appAccess":{}}"#,
    )])
    .await;
    let host: &'static str = Box::leak(server.base_url.clone().into_boxed_str());
    get_space(session(host), &space()).await.expect("get");
    assert_eq!(
        server.requests().await[0].xrpc_method(),
        "com.atproto.simplespace.getSpace"
    );
}

/// A policy variant this build does not know is a server ahead of it, not a
/// malformed answer.
///
/// The lexicon declares both policy fields as **open** unions, so decoding
/// them into a closed enum would turn "newer server" into "broken server".
#[tokio::test]
async fn an_unknown_policy_variant_still_decodes() {
    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"uri":"at://did:plc:authority/space/app.bsky.group/default",
            "policy":{"$type":"com.atproto.simplespace.defs#somethingLater","extra":7},
            "appAccess":{"$type":"com.atproto.simplespace.defs#open"}}"#,
    )])
    .await;

    let key = generate_key(KeyType::P256Private).expect("key");
    let http = reqwest::Client::new();
    let config = get_space(
        SpaceSession {
            http: &http,
            host: &server.base_url,
            dpop_key: &key,
            access_token: "token",
        },
        &space(),
    )
    .await
    .expect("an open union tolerates a variant this build predates");

    assert_eq!(
        config.policy["$type"],
        "com.atproto.simplespace.defs#somethingLater"
    );
}

/// A page carries its cursor through, and a last page carries none.
#[tokio::test]
async fn a_space_page_carries_its_cursor() {
    let key = generate_key(KeyType::P256Private).expect("key");

    let server = Scripted::start(vec![Reply::new(
        200,
        r#"{"spaces":[{"uri":"at://did:plc:a/space/app.bsky.group/x","isOwner":true,"isMember":true,
                      "createdAt":"2026-01-01T00:00:00Z"}],
            "cursor":"next"}"#,
    )])
    .await;
    let http = reqwest::Client::new();
    let page = list_spaces(
        SpaceSession {
            http: &http,
            host: &server.base_url,
            dpop_key: &key,
            access_token: "token",
        },
        &ListSpaces {
            space_type: Some("app.bsky.group"),
            limit: Some(25),
            ..ListSpaces::default()
        },
    )
    .await
    .expect("list");

    assert_eq!(page.cursor.as_deref(), Some("next"));
    assert!(page.spaces[0].is_owner);

    let request = &server.requests().await[0];
    assert!(
        request.request_line.contains("type=app.bsky.group"),
        "{}",
        request.request_line
    );
    assert!(
        request.request_line.contains("limit=25"),
        "{}",
        request.request_line
    );

    let server = Scripted::start(vec![Reply::new(200, r#"{"spaces":[]}"#)]).await;
    let page = list_spaces(
        SpaceSession {
            http: &http,
            host: &server.base_url,
            dpop_key: &key,
            access_token: "token",
        },
        &ListSpaces::default(),
    )
    .await
    .expect("list");
    assert_eq!(page.cursor, None);
}

/// A refusal names the method and the host, and classifies the status.
#[tokio::test]
async fn a_refusal_is_typed() {
    let server = Scripted::start(vec![Reply::new(
        403,
        r#"{"error":"NotAuthorized","message":"not a member"}"#,
    )])
    .await;

    let key = generate_key(KeyType::P256Private).expect("key");
    let http = reqwest::Client::new();
    let error = get_space(
        SpaceSession {
            http: &http,
            host: &server.base_url,
            dpop_key: &key,
            access_token: "token",
        },
        &space(),
    )
    .await
    .expect_err("refused");

    let message = error.to_string();
    assert!(
        message.contains("com.atproto.simplespace.getSpace"),
        "{message}"
    );
    assert!(
        message.contains("error-atproto-space-client-client-4"),
        "{message}"
    );
}
