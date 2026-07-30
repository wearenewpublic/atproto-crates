//! Phase 7 HTTP integration tests — the `com.atproto.space.*` and
//! `com.atproto.simplespace.*` surface, aligned to the published 0016
//! Permissioned Data spec.
//!
//! This suite exercises the spec-aligned wire shapes:
//! - `com.atproto.simplespace.createSpace` (`{did?, type, skey?, config?}` ->
//!   `{uri}`), `updateSpace`, `deleteSpace`, `addMember`, `removeMember`,
//!   `listMembers`.
//! - `com.atproto.space.getSpace` (`{uri, config}`), `listSpaces`.
//! - `applyWrites` + single-op `createRecord` / `putRecord` / `deleteRecord`.
//! - `getRecord` (`{uri, cid, value}`) / `listRecords` (keys-only
//!   `{collection, rkey, cid}`).
//! - `getRepoState` / `listRepoOps` — signed-commit (`{commit:#signedCommit}`)
//!   sync surface (sig over `ctx` + `mac`-bound `hash`, spec lines 285-316).
//! - `getDelegationToken` (GET -> `{token}`; spec lines 147-176) exchanged at
//!   `getSpaceCredential` (delegation token in the `Authorization` header +
//!   body `{space, clientAttestation?}` -> `{credential}`; spec lines 200-251)
//!   with mint authorization (member-list allow, non-member deny, `#allowList`
//!   app deny).
//! - `getBlob` permissioned gating, `listRepos` (`{did, rev}`),
//!   `registerNotify`, `notifyWrite` (contentless `{space, repo, rev}`),
//!   `notifySpaceDeleted`.
//!
//! Management endpoints authenticate with an app-password session token (the
//! `space:` scope gate is a no-op for non-OAuth subjects). `getDelegationToken`
//! requires an OAuth token carrying a `client_id`, so those flows mint an
//! HS256 OAuth access token directly (mirroring `tests/dpop_enforcement.rs`).

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::Sha256;
use sha2::digest::KeyInit;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

const JWT_SECRET: &[u8] = b"test-secret-do-not-use-in-prod-32!";
const CLIENT_ID: &str = "https://app.example/client-metadata.json";

/// Build a fresh PDS app with the full Spaces wiring (service + writer +
/// reader + sync). Returns the router and the owning `TempDir`.
async fn build_app() -> (axum::Router, Arc<AccountManager>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));

    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        JWT_SECRET.to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);

    (build_router(state), manager, tmp)
}

/// Create an account and return its app-password session access token.
async fn create_account_and_token(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("fixture account needs a session password");
    session_token(app, handle).await
}

/// Mint an OAuth access JWT (`typ=at-oauth-access`, HS256 over `JWT_SECRET`)
/// with the supplied `scope`, no `cnf` (so no DPoP proof is required). Carries
/// a `client_id`, which `getDelegationToken` needs.
fn mint_oauth_access(sub: &str, scope: &str) -> String {
    let header = json!({"alg": "HS256", "typ": "at-oauth-access"});
    let now = chrono::Utc::now().timestamp() as u64;
    let payload = json!({
        "sub": sub,
        "iss": "did:web:test.example",
        "aud": "did:web:test.example",
        "client_id": CLIENT_ID,
        "scope": scope,
        "iat": now,
        "exp": now + 3600,
        "jti": format!("oauth-jti-{sub}-{now}"),
    });
    let h = B64URL.encode(serde_json::to_vec(&header).unwrap());
    let p = B64URL.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(JWT_SECRET).unwrap();
    mac.update(signing_input.as_bytes());
    format!(
        "{}.{}",
        signing_input,
        B64URL.encode(mac.finalize().into_bytes())
    )
}

/// Mint a *real*, authority-signed space credential for `member_did` over
/// `space_uri` by running the full `getDelegationToken` -> `getSpaceCredential`
/// flow. `member_did` must already be authorized to mint (a member under the
/// default member-list policy). Returns the compact credential JWT.
async fn mint_space_credential(app: &axum::Router, member_did: &str, space_uri: &str) -> String {
    let oauth = mint_oauth_access(member_did, &read_scope());
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(space_uri)
        ),
        Some(&oauth),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getDelegationToken: {body}");
    let grant = body["token"].as_str().unwrap().to_string();
    let (status, body) = exchange_credential(app, &grant, space_uri, None).await;
    assert_eq!(status, StatusCode::OK, "getSpaceCredential: {body}");
    body["credential"].as_str().unwrap().to_string()
}

/// Forge a JWT that merely *classifies* as a space credential — correct
/// `typ`/`kid` header so [`classify`] tags it `SpaceCredential`, plausible
/// `iss`/`sub`/`exp` claims, but a bogus (non-cryptographic) signature. The
/// host/sync read methods must reject this: it is never signed by the space
/// authority's `#atproto_space` key.
fn forge_space_credential(authority_did: &str, space_uri: &str) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "atproto-space-credential+jwt",
        "kid": "#atproto_space"
    });
    let now = chrono::Utc::now().timestamp() as u64;
    let payload = json!({
        "iss": authority_did,
        "sub": space_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let h = B64URL.encode(serde_json::to_vec(&header).unwrap());
    let p = B64URL.encode(serde_json::to_vec(&payload).unwrap());
    // 64-byte all-zero "signature" — structurally a P-256 sig, cryptographically
    // invalid.
    let sig = B64URL.encode([0u8; 64]);
    format!("{h}.{p}.{sig}")
}

async fn post_json(
    app: axum::Router,
    path: &str,
    body: Value,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .header("host", "test.example");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get_json(app: axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(path).header("host", "test.example");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req.body(Body::empty()).unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Split a compact JWT into its decoded `(header, payload)` JSON objects,
/// without verifying the signature (the handlers verify; tests assert shape).
fn decode_jwt(jwt: &str) -> (Value, Value) {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().expect("jwt header segment");
    let payload_b64 = parts.next().expect("jwt payload segment");
    assert!(parts.next().is_some(), "jwt must carry a signature segment");
    let header: Value =
        serde_json::from_slice(&B64URL.decode(header_b64).expect("decode jwt header"))
            .expect("parse jwt header");
    let payload: Value =
        serde_json::from_slice(&B64URL.decode(payload_b64).expect("decode jwt payload"))
            .expect("parse jwt payload");
    (header, payload)
}

/// Percent-encode a string for use in a query parameter.
fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Create a space via `simplespace.createSpace` and return its URI.
async fn create_space(app: &axum::Router, owner_token: &str, skey: &str) -> String {
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group", "skey": skey}),
        Some(owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSpace failed: {body}");
    body["uri"].as_str().unwrap().to_string()
}

/// Exchange a delegation token for a space credential at
/// `com.atproto.space.getSpaceCredential`.
///
/// Per the 0016 spec (lines 200-251) the delegation token is presented in the
/// `Authorization: Bearer` header and the body carries the target `space` plus
/// an optional `clientAttestation`. The response is `{credential}`.
async fn exchange_credential(
    app: &axum::Router,
    delegation_token: &str,
    space: &str,
    client_attestation: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({ "space": space });
    if let Some(att) = client_attestation {
        body["clientAttestation"] = json!(att);
    }
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.getSpaceCredential",
        body,
        Some(delegation_token),
    )
    .await
}

// ---------------------------------------------------------------------------
//  simplespace management
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn create_space_round_trip() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group", "skey": "default"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let uri = body["uri"].as_str().unwrap();
    assert_eq!(uri, "at://did:plc:owner/space/app.bsky.group/default");

    // getSpace returns {uri, config}; config carries the default mint policy.
    let (status, info) = get_json(
        app,
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(uri)),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {info}");
    assert_eq!(info["uri"], uri);
    assert_eq!(info["config"]["policy"], "member-list");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_space_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group", "skey": "default"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_space_auto_generates_skey() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"type": "app.bsky.group"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let uri = body["uri"].as_str().unwrap();
    assert!(uri.starts_with("at://did:plc:owner/space/app.bsky.group/"));
    // The auto-generated skey is a non-empty TID.
    assert!(uri.rsplit('/').next().unwrap().len() >= 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_space_did_must_match_caller() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({"did": "did:plc:someoneelse", "type": "app.bsky.group", "skey": "x"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_space_reflects_in_get_space() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &token, "default").await;

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.updateSpace",
        json!({"space": uri, "policy": "public"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, info) = get_json(
        app,
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(&uri)),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {info}");
    assert_eq!(info["config"]["policy"], "public");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_space_then_get_space_fails() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &token, "default").await;

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.deleteSpace",
        json!({"space": uri}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // getSpace on a tombstoned space reads as SpaceNotFound.
    let (status, body) = get_json(
        app.clone(),
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(&uri)),
        Some(&token),
    )
    .await;
    assert!(
        status.is_client_error(),
        "expected 4xx after delete: {body}"
    );
    assert_eq!(
        body["error"], "SpaceNotFound",
        "deleted space must read as SpaceNotFound: {body}"
    );

    // The tombstone gate also blocks writes: applyWrites to a deleted space
    // must fail with SpaceNotFound (the owner is a member, so this is the
    // tombstone gate firing, not a membership rejection).
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{
                "action": "create",
                "collection": "app.bsky.group.message",
                "rkey": "x",
                "value": {"text": "hi"}
            }]
        }),
        Some(&token),
    )
    .await;
    assert!(
        status.is_client_error(),
        "expected 4xx writing to deleted space: {body}"
    );
    assert_eq!(
        body["error"], "SpaceNotFound",
        "writing to a deleted space must fail with SpaceNotFound: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_space_seeds_owner_in_member_list() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &token, "default").await;

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.simplespace.listMembers?space={}",
            urlencode(&uri)
        ),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["did"], "did:plc:owner");
}

#[tokio::test(flavor = "multi_thread")]
async fn add_remove_then_list_members() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.simplespace.listMembers?space={}",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let dids: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["did"].as_str().unwrap())
        .collect();
    assert!(dids.contains(&"did:plc:owner"));
    assert!(dids.contains(&"did:plc:alice"));

    // Remove alice.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.removeMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.simplespace.listMembers?space={}",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let dids: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["did"].as_str().unwrap())
        .collect();
    assert!(!dids.contains(&"did:plc:alice"));
}

#[tokio::test(flavor = "multi_thread")]
async fn add_member_by_non_owner_rejected() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let eve_token = create_account_and_token(&app, &manager, "did:plc:eve", "eve.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&eve_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
//  applyWrites + single-op record writes + reads
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_then_read_back() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let alice_token =
        create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "space": uri,
            "writes": [{
                "action": "create",
                "collection": "app.bsky.group.message",
                "rkey": "first",
                "value": {"text": "hi"}
            }]
        }),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let results = body["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]["$type"], "com.atproto.space.applyWrites#createResult",
        "body: {body}"
    );
    assert!(results[0]["uri"].as_str().is_some());
    assert!(results[0]["cid"].as_str().is_some());

    // getRecord returns {uri, cid, value}.
    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&repo=did:plc:alice&collection=app.bsky.group.message&rkey=first",
            urlencode(&uri)
        ),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["value"]["text"], "hi");
    assert!(body["cid"].as_str().is_some());
    assert!(
        body["uri"]
            .as_str()
            .unwrap()
            .contains("app.bsky.group.message/first")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_empty_batch_rejected() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.applyWrites",
        json!({"space": uri, "repo": "did:plc:owner", "writes": []}),
        Some(&owner_token),
    )
    .await;
    assert!(status.is_client_error());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_put_delete_record_single_ops() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    // createRecord (owner writes to its own repo).
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.createRecord",
        json!({
            "space": uri,
            "repo": "did:plc:owner",
            "collection": "app.bsky.group.message",
            "rkey": "r1",
            "record": {"$type": "app.bsky.group.message", "text": "v1"}
        }),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createRecord: {body}");
    assert!(body["cid"].as_str().is_some());
    assert!(
        body["uri"]
            .as_str()
            .unwrap()
            .contains("app.bsky.group.message/r1")
    );

    // putRecord updates the same record.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.putRecord",
        json!({
            "space": uri,
            "repo": "did:plc:owner",
            "collection": "app.bsky.group.message",
            "rkey": "r1",
            "record": {"$type": "app.bsky.group.message", "text": "v2"}
        }),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "putRecord: {body}");

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&repo=did:plc:owner&collection=app.bsky.group.message&rkey=r1",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getRecord: {body}");
    assert_eq!(body["value"]["text"], "v2");

    // deleteRecord removes it.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.deleteRecord",
        json!({
            "space": uri,
            "repo": "did:plc:owner",
            "collection": "app.bsky.group.message",
            "rkey": "r1"
        }),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&repo=did:plc:owner&collection=app.bsky.group.message&rkey=r1",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_record_repo_must_match_subject() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.createRecord",
        json!({
            "space": uri,
            "repo": "did:plc:someoneelse",
            "collection": "c",
            "record": {"$type": "c", "v": 1}
        }),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_keys_only_paginated() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    for r in ["a", "b", "c"] {
        post_json(
            app.clone(),
            "/xrpc/com.atproto.space.applyWrites",
            json!({
            "repo": "did:plc:owner",
                "space": uri,
                "writes": [{"action": "create", "collection": "c", "rkey": r, "value": {"k": r}}]
            }),
            Some(&owner_token),
        )
        .await;
    }

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRecords?space={}&collection=c&limit=2&excludeValues=true",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    // Keys-only shape: {collection, rkey, cid} and NO value.
    //
    // This test used to omit `excludeValues` and assert the same thing, which
    // pinned the divergence: the lexicon inlines values by default and only
    // `excludeValues` reduces an entry to its keys.
    assert_eq!(records[0]["collection"], "c");
    assert!(records[0]["rkey"].as_str().is_some());
    assert!(records[0]["cid"].as_str().is_some());
    assert!(records[0].get("value").is_none());
    assert!(body["cursor"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_across_all_collections() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    for (collection, rkey) in [
        ("app.bsky.group.message", "m1"),
        ("app.bsky.group.message", "m2"),
        ("app.bsky.group.like", "l1"),
    ] {
        post_json(
            app.clone(),
            "/xrpc/com.atproto.space.applyWrites",
            json!({
            "repo": "did:plc:owner",
                "space": uri,
                "writes": [{"action": "create", "collection": collection, "rkey": rkey, "value": {}}]
            }),
            Some(&owner_token),
        )
        .await;
    }

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRecords?space={}",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["records"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_record_oauth_with_repo_override() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let alice_token =
        create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    // Alice writes to her own per-actor store.
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "space": uri,
            "writes": [{"action": "create", "collection": "c", "rkey": "alice-1", "value": {"who": "alice"}}]
        }),
        Some(&alice_token),
    )
    .await;

    // Owner reads with repo=alice and pulls from Alice's store.
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=alice-1&repo=did:plc:alice",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["value"]["who"], "alice");

    // `repo` is required by the lexicon, so omitting it is a bad request
    // rather than a lookup against the caller's own store.
    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=alice-1",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  Sync: getRepoState / listRepoOps (signed commit)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_state_signed_commit() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    // Empty repo: no commit yet.
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.get("commit").is_none() || body["commit"].is_null());

    // Write, then a signed commit is present.
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{"action": "create", "collection": "c", "rkey": "k", "value": {"v": 1}}]
        }),
        Some(&owner_token),
    )
    .await;

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let commit = &body["commit"];
    assert!(commit["rev"].as_str().is_some());
    // Signed-commit byte fields are lex-data {"$bytes": <base64>}.
    assert!(commit["hash"]["$bytes"].as_str().is_some());
    assert!(commit["mac"]["$bytes"].as_str().is_some());
    assert!(commit["ikm"]["$bytes"].as_str().is_some());
    assert!(commit["sig"]["$bytes"].as_str().is_some());

    // listRepoOps: the single create op + a caught-up signed commit.
    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRepoOps?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["collection"], "c");
    assert_eq!(ops[0]["rkey"], "k");
    assert!(ops[0]["cid"].as_str().is_some());
    assert!(body["commit"]["sig"]["$bytes"].as_str().is_some());
}

// ---------------------------------------------------------------------------
//  Credential flow: getDelegationToken -> getSpaceCredential, mint authz
// ---------------------------------------------------------------------------

/// Read scope string covering the default space
/// (`at://did:plc:owner/space/app.bsky.group/default`).
fn read_scope() -> String {
    "atproto space:app.bsky.group?did=did:plc:owner&skey=default&action=read".to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn delegation_token_then_space_credential_member_allowed() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    // Alice mints a delegation token via OAuth (needs a client_id).
    let alice_oauth = mint_oauth_access("did:plc:alice", &read_scope());
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(&uri)
        ),
        Some(&alice_oauth),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getDelegationToken: {body}");
    let grant = body["token"].as_str().unwrap().to_string();
    // Output is exactly {token} (spec lines 147-176; no expiresAt field).
    assert!(body.get("expiresAt").is_none());
    assert!(body.get("credential").is_none());

    // Delegation-token shape (spec lines 152-171): typ
    // atproto-space-delegation+jwt, kid #atproto, sub == the space URI,
    // aud == <spaceDid>#atproto_space_host, no lxm, exp == iat + 60.
    let (dt_header, dt_payload) = decode_jwt(&grant);
    assert_eq!(dt_header["typ"], "atproto-space-delegation+jwt");
    assert_eq!(dt_header["kid"], "#atproto");
    assert_eq!(dt_payload["iss"], "did:plc:alice");
    assert_eq!(dt_payload["sub"], uri);
    assert_eq!(dt_payload["aud"], "did:plc:owner#atproto_space_host");
    assert!(
        dt_payload.get("lxm").is_none(),
        "delegation token has no lxm"
    );
    let dt_iat = dt_payload["iat"].as_u64().unwrap();
    let dt_exp = dt_payload["exp"].as_u64().unwrap();
    assert_eq!(dt_exp, dt_iat + 60, "delegation token exp is iat + 60");

    // Exchange the grant for a space credential (member-list + #open => allow).
    // The delegation token rides in the Authorization header; the body carries
    // only the target space. The response is {credential} (spec lines 200-251).
    let (status, body) = exchange_credential(&app, &grant, &uri, None).await;
    assert_eq!(status, StatusCode::OK, "getSpaceCredential: {body}");
    let credential = body["credential"].as_str().unwrap();
    // No legacy {token, expiresAt} shape.
    assert!(body.get("token").is_none());
    assert!(body.get("expiresAt").is_none());

    // Space-credential shape (spec lines 206-225): typ
    // atproto-space-credential+jwt, kid #atproto_space, iss == the authority,
    // sub == the space URI, NO aud. No attestation was presented, so client_id
    // is omitted (spec lines 221, 228).
    let (sc_header, sc_payload) = decode_jwt(credential);
    assert_eq!(sc_header["typ"], "atproto-space-credential+jwt");
    assert_eq!(sc_header["kid"], "#atproto_space");
    assert_eq!(sc_payload["iss"], "did:plc:owner");
    assert_eq!(sc_payload["sub"], uri);
    assert!(
        sc_payload.get("aud").is_none(),
        "space credential has no aud"
    );
    assert!(sc_payload.get("client_id").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn delegation_token_requires_oauth_client_id() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // App-password session token carries no client_id -> 403.
    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn space_credential_non_member_denied() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:eve", "eve.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // Eve is NOT a member. She can still mint a delegation token (it's just a
    // signed assertion), but the owner's getSpaceCredential mint authz must
    // deny her under the default member-list policy.
    let eve_oauth = mint_oauth_access("did:plc:eve", &read_scope());
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(&uri)
        ),
        Some(&eve_oauth),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getDelegationToken: {body}");
    let grant = body["token"].as_str().unwrap().to_string();

    let (status, _) = exchange_credential(&app, &grant, &uri, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-member must be denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn space_credential_app_allowlist_denies_unattested() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    // Tighten appAccess to an allow-list that excludes alice's client.
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.updateSpace",
        json!({
            "space": uri,
            "appAccess": {
                "$type": "com.atproto.simplespace.defs#allowList",
                "allowed": ["https://other.example/cm.json"]
            }
        }),
        Some(&owner_token),
    )
    .await;

    let alice_oauth = mint_oauth_access("did:plc:alice", &read_scope());
    let (_, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(&uri)
        ),
        Some(&alice_oauth),
    )
    .await;
    let grant = body["token"].as_str().unwrap().to_string();

    // No client attestation -> the #allowList app axis denies (spec lines
    // 533-535: only the apps named in `allowed` may access the space).
    let (status, _) = exchange_credential(&app, &grant, &uri, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn space_credential_registers_recipient_idempotently() {
    // build_app hides the data dir, so this test constructs the app inline
    // with a TempDir it can inspect afterwards.
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&data_dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        data_dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), data_dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, data_dir.clone()));
    let svc = Arc::new(SpaceService::with_accounts(
        data_dir.clone(),
        manager.clone(),
    ));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), data_dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), data_dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(data_dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        JWT_SECRET.to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, space_writer, space_reader, space_sync);
    let app = build_router(state);

    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let _ = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;

    for i in 0..2 {
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let alice_oauth = mint_oauth_access("did:plc:alice", &read_scope());
        let (_, body) = get_json(
            app.clone(),
            &format!(
                "/xrpc/com.atproto.space.getDelegationToken?space={}",
                urlencode(&uri)
            ),
            Some(&alice_oauth),
        )
        .await;
        let grant = body["token"].as_str().unwrap().to_string();
        let (status, body) = exchange_credential(&app, &grant, &uri, None).await;
        assert_eq!(status, StatusCode::OK, "getSpaceCredential: {body}");
    }

    let owner_store =
        atproto_pds::actor_store::sql::SqlActorStore::open(&data_dir, "did:plc:owner")
            .await
            .unwrap();
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT space, service_did FROM space_credential_recipient")
            .fetch_all(owner_store.pool())
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "expected one recipient row, got: {rows:?}");
    assert_eq!(rows[0].0, uri);
}

// ---------------------------------------------------------------------------
//  listRepos
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_wrong_space_credential_rejected() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // A credential minted for `default` does not authorize a different space
    // URI: the `sub` claim must match the requested space, so the verify gate
    // rejects it (401) before any SpaceNotFound lookup.
    let credential = mint_space_credential(&app, "did:plc:owner", &uri).await;
    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode("at://did:plc:owner/space/app.bsky.group/missing")
        ),
        Some(&credential),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_empty_writer_set() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // listRepos is space-credential-only: mint a real, authority-signed
    // credential for the owner (an implicit member of their own space).
    let credential = mint_space_credential(&app, "did:plc:owner", &uri).await;
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&credential),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // No inbound write receipts yet -> empty writer set.
    assert_eq!(body["repos"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_rejects_oauth_token() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // listRepos accepts a space credential ONLY (spec XRPC table). An OAuth /
    // session bearer — even the owner's — must be rejected with 401.
    let oauth = mint_oauth_access("did:plc:owner", &read_scope());
    let (status, _) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&oauth),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "oauth must be rejected");
    // The owner's app-password session token is likewise rejected.
    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "session must be rejected");
}

// ---------------------------------------------------------------------------
//  Forged-credential rejection on the host/sync read methods (F1 security fix)
// ---------------------------------------------------------------------------

/// A bearer that merely *classifies* as a space credential (correct `typ`) but
/// carries an invalid signature must be rejected — not admitted on its `typ`
/// string alone — on every host/sync read method.
#[tokio::test(flavor = "multi_thread")]
async fn forged_space_credential_rejected_on_read_methods() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    let forged = forge_space_credential("did:plc:owner", &uri);

    // getSpace
    let (status, _) = get_json(
        app.clone(),
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(&uri)),
        Some(&forged),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "getSpace forged");

    // getRepoState
    let (status, _) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&forged),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "getRepoState forged");

    // listRepoOps
    let (status, _) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepoOps?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&forged),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "listRepoOps forged");

    // listRepos
    let (status, _) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&forged),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "listRepos forged");
}

// ---------------------------------------------------------------------------
//  getBlob gating
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn get_blob_requires_repo_and_gates_auth() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;

    // Missing bearer -> unauthorized.
    let (status, _) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getBlob?space={}&repo=did:plc:owner&cid=bafkreigh2akiscaildc",
            urlencode(&uri)
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authed but no such blob -> BlobNotFound (404). This proves the auth
    // gate passed and the reader was reached.
    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getBlob?space={}&repo=did:plc:owner&cid=bafkreigh2akiscaildc",
            urlencode(&uri)
        ),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["error"], "BlobNotFound");
}

// ---------------------------------------------------------------------------
//  registerNotify
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn register_notify_requires_space_credential() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // A plain session token is not a space credential -> 401.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.registerNotify",
        json!({"space": uri, "endpoint": "https://consumer.example"}),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
//  Inbound notify endpoints (service auth required)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn notify_write_requires_service_auth() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    // Contentless payload, but no bearer -> unauthorized.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.notifyWrite",
        json!({"space": uri, "repo": "did:plc:writer", "rev": "3kabc"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A session token is not service auth -> rejected (4xx).
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.notifyWrite",
        json!({"space": uri, "repo": "did:plc:writer", "rev": "3kabc"}),
        Some(&owner_token),
    )
    .await;
    assert!(
        status.is_client_error(),
        "session token must not pass service auth"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn notify_space_deleted_requires_service_auth() {
    let (app, manager, _tmp) = build_app().await;
    let owner_token =
        create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner_token, "default").await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.space.notifySpaceDeleted",
        json!({"space": uri}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Log in as a fixture account and return its access token.
async fn session_token(app: &axum::Router, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "identifier": handle, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"]
        .as_str()
        .expect("createSession should return an access token")
        .to_string()
}

// ---------------------------------------------------------------------------
//  F-SPACE-07 — read-time membership enforcement.
//
//  `resolve_record_auth` adopted the caller-supplied `repo` verbatim, with no
//  comparison against the subject and no membership lookup. So any
//  authenticated local account could read any other local account's
//  permissioned records by naming them — the confidentiality property the
//  whole feature exists to provide did not hold against anyone on the same PDS.
//
//  The report scopes this honestly: all three links are shared with the
//  reference on the `permissioned-data` branch, so it is a hole in 0016 as
//  implemented by everyone following it, not an authoring error here.
// ---------------------------------------------------------------------------

/// A space owned by `owner`, containing one record written by member `alice`.
async fn space_with_alices_record(
    app: &axum::Router,
    manager: &Arc<AccountManager>,
) -> (String, String, String) {
    let owner_token =
        create_account_and_token(app, manager, "did:plc:owner", "owner.example").await;
    let alice_token =
        create_account_and_token(app, manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(app, &owner_token, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner_token),
    )
    .await;
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "space": uri,
            "writes": [{"action": "create", "collection": "c", "rkey": "alice-1", "value": {"who": "alice"}}]
        }),
        Some(&alice_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed write: {body}");
    (uri, owner_token, alice_token)
}

async fn read_alices_record(app: &axum::Router, uri: &str, token: &str) -> (StatusCode, Value) {
    get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=alice-1&repo=did:plc:alice",
            urlencode(uri)
        ),
        Some(token),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_member_cannot_read_another_accounts_records() {
    // The exploit, as a test. An ordinary app-password session for an account
    // that was never added to the space, naming the victim as `repo`.
    let (app, manager, _tmp) = build_app().await;
    let (uri, _owner, _alice) = space_with_alices_record(&app, &manager).await;
    let mallory =
        create_account_and_token(&app, &manager, "did:plc:mallory", "mallory.example").await;

    let (status, body) = read_alices_record(&app, &uri, &mallory).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a non-member read Alice's permissioned record: {body}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"], "SpaceNotFound",
        "whether a space holds an account's records is itself confidential"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_member_cannot_list_another_accounts_records() {
    // Same override reaches listRecords, which returns the whole repo.
    let (app, manager, _tmp) = build_app().await;
    let (uri, _owner, _alice) = space_with_alices_record(&app, &manager).await;
    let mallory =
        create_account_and_token(&app, &manager, "did:plc:mallory", "mallory.example").await;

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRecords?space={}&repo=did:plc:alice",
            urlencode(&uri)
        ),
        Some(&mallory),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "body: {body}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_member_cannot_read_another_accounts_blobs() {
    let (app, manager, _tmp) = build_app().await;
    let (uri, _owner, _alice) = space_with_alices_record(&app, &manager).await;
    let mallory =
        create_account_and_token(&app, &manager, "did:plc:mallory", "mallory.example").await;

    // The blob need not exist: the membership gate runs before any lookup, so a
    // refusal here is the gate and not a not-found.
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getBlob?space={}&repo=did:plc:alice&cid=bafkreiabc",
            urlencode(&uri)
        ),
        Some(&mallory),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "SpaceNotFound", "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_naming_a_non_member_target_is_refused() {
    // A space is not a lens onto arbitrary accounts. Alice is a member; Mallory
    // is not, so Alice may not read Mallory through this space.
    let (app, manager, _tmp) = build_app().await;
    let (uri, _owner, alice) = space_with_alices_record(&app, &manager).await;
    let _mallory =
        create_account_and_token(&app, &manager, "did:plc:mallory", "mallory.example").await;

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=x&repo=did:plc:mallory",
            urlencode(&uri)
        ),
        Some(&alice),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "SpaceNotFound", "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn members_can_still_read_each_other() {
    // The control, and the point of a shared space. Every test above asserts a
    // refusal; a gate that refused everything would pass all of them.
    let (app, manager, _tmp) = build_app().await;
    let (uri, owner, alice) = space_with_alices_record(&app, &manager).await;

    // Owner (implicitly a member) reads Alice.
    let (status, body) = read_alices_record(&app, &uri, &owner).await;
    assert_eq!(status, StatusCode::OK, "owner → alice: {body}");
    assert_eq!(body["value"]["who"], "alice");

    // Alice reads her own repo, both with and without an explicit `repo`.
    let (status, body) = read_alices_record(&app, &uri, &alice).await;
    assert_eq!(status, StatusCode::OK, "alice → alice explicit: {body}");
    assert_eq!(body["value"]["who"], "alice");

    // There is no implicit form: `repo` names the record's author and the
    // lexicon requires it, even when that author is the caller.
    let (status, _) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&collection=c&rkey=alice-1",
            urlencode(&uri)
        ),
        Some(&alice),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "alice → alice implicit");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_member_loses_read_access() {
    // Membership is checked per read, not captured at session creation, so
    // removal takes effect on the next request.
    let (app, manager, _tmp) = build_app().await;
    let (uri, owner, alice) = space_with_alices_record(&app, &manager).await;

    let (status, _) = read_alices_record(&app, &uri, &alice).await;
    assert_eq!(status, StatusCode::OK, "member reads before removal");

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.removeMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "removeMember: {body}");

    let (status, body) = read_alices_record(&app, &uri, &alice).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a removed member kept read access: {body}"
    );
}

// ---------------------------------------------------------------------------
//  F-BLOB-03 + F-SPACE-12 — permissioned blobs.
//
//  There is no `com.atproto.space.uploadBlob`: permissioned blobs are uploaded
//  through the ordinary `com.atproto.repo.uploadBlob` and land in the same
//  `repo_blob` table as public ones. Two defects followed.
//
//  F-BLOB-03: `com.atproto.sync.getBlob` served those bytes to anyone holding
//  the CID, with no credential at all — a longer reach than F-SPACE-07, which
//  at least needs an account here. CIDs are high-entropy but not secret: they
//  appear in oplog entries, in `listRepoOps`, in indexing AppViews, in logs,
//  and to every member including one since removed.
//
//  F-SPACE-12: `com.atproto.space.getBlob` gated on `space` and then fetched by
//  `(repo, cid)` alone, so the parameter never reached the lookup.
// ---------------------------------------------------------------------------

/// Upload a blob as `token`'s account, returning its CID.
async fn upload_blob(app: &axum::Router, token: &str, bytes: &'static [u8]) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.repo.uploadBlob")
                .method("POST")
                .header("content-type", "image/png")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["blob"]["ref"]["$link"]
        .as_str()
        .expect("uploadBlob returns a blob ref")
        .to_string()
}

fn blob_embed(cid: &str) -> Value {
    json!({
        "$type": "blob",
        "ref": {"$link": cid},
        "mimeType": "image/png",
        "size": 16,
    })
}

async fn sync_get_blob(app: &axum::Router, did: &str, cid: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn space_get_blob(
    app: &axum::Router,
    space: &str,
    repo: &str,
    cid: &str,
    token: &str,
) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.space.getBlob?space={}&repo={repo}&cid={cid}",
                    urlencode(space)
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_permissioned_blob_is_not_served_by_the_public_endpoint() {
    // The exploit: no credential, just the CID.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let cid = upload_blob(&app, &owner, b"secret image!!!!").await;
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{
                "action": "create", "collection": "c", "rkey": "r1",
                "value": {"embed": blob_embed(&cid)}
            }]
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "permissioned write: {body}");

    assert_eq!(
        sync_get_blob(&app, "did:plc:owner", &cid).await,
        StatusCode::NOT_FOUND,
        "a blob referenced only from a permissioned record must not be served \
         by the unauthenticated public endpoint"
    );

    // And it is not enumerated, either — listing the CIDs is most of the attack.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.sync.listBlobs?did=did:plc:owner",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let listed: Vec<&str> = body["cids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(
        !listed.contains(&cid.as_str()),
        "listBlobs enumerated a permissioned CID: {listed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_blob_is_served_to_a_member_through_the_space_endpoint() {
    // The complement, and the control: the gate must withhold the blob from the
    // public route without breaking the route that is supposed to serve it.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let cid = upload_blob(&app, &owner, b"secret image!!!!").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{
                "action": "create", "collection": "c", "rkey": "r1",
                "value": {"embed": blob_embed(&cid)}
            }]
        }),
        Some(&owner),
    )
    .await;

    assert_eq!(
        space_get_blob(&app, &uri, "did:plc:owner", &cid, &owner).await,
        StatusCode::OK,
        "a member must still be able to fetch the blob through space.getBlob"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_public_blob_is_still_served_publicly() {
    // The other control. A gate that refused everything would pass the two
    // tests above.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;

    let cid = upload_blob(&app, &owner, b"public image!!!!").await;
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:owner",
            "collection": "app.bsky.feed.post",
            "rkey": "pub",
            "record": {"$type": "app.bsky.feed.post", "text": "hi", "embed": blob_embed(&cid)}
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "public write: {body}");

    assert_eq!(
        sync_get_blob(&app, "did:plc:owner", &cid).await,
        StatusCode::OK,
        "a blob a public record references is public"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreferenced_blob_is_not_publicly_fetchable() {
    // Stated explicitly rather than left implied, because it is a behaviour
    // change: uploading no longer makes bytes publicly readable. Nothing should
    // be fetching them before a record names them, and the uploader has them.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let cid = upload_blob(&app, &owner, b"orphan image!!!!").await;

    assert_eq!(
        sync_get_blob(&app, "did:plc:owner", &cid).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_space_parameter_reaches_the_blob_lookup() {
    // F-SPACE-12. The same account owns two spaces; a blob referenced only from
    // the first must not be fetchable through the second.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let space_a = create_space(&app, &owner, "aaa").await;
    let space_b = create_space(&app, &owner, "bbb").await;

    let cid = upload_blob(&app, &owner, b"space a image!!!").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": space_a,
            "writes": [{
                "action": "create", "collection": "c", "rkey": "r1",
                "value": {"embed": blob_embed(&cid)}
            }]
        }),
        Some(&owner),
    )
    .await;

    assert_eq!(
        space_get_blob(&app, &space_a, "did:plc:owner", &cid, &owner).await,
        StatusCode::OK,
        "readable in the space that references it"
    );
    assert_eq!(
        space_get_blob(&app, &space_b, "did:plc:owner", &cid, &owner).await,
        StatusCode::NOT_FOUND,
        "the `space` parameter must reach the lookup, not merely gate the request"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_last_referencing_record_revokes_the_blob() {
    // The revocation half. Adding refs without dropping them would leave a blob
    // readable in a space after the only record naming it stopped naming it,
    // and nothing would visibly break.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let cid = upload_blob(&app, &owner, b"transient image!").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{
                "action": "create", "collection": "c", "rkey": "r1",
                "value": {"embed": blob_embed(&cid)}
            }]
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(
        space_get_blob(&app, &uri, "did:plc:owner", &cid, &owner).await,
        StatusCode::OK
    );

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:owner",
            "space": uri,
            "writes": [{"action": "delete", "collection": "c", "rkey": "r1"}]
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete: {body}");

    assert_eq!(
        space_get_blob(&app, &uri, "did:plc:owner", &cid, &owner).await,
        StatusCode::NOT_FOUND,
        "with no record referencing it, the blob is no longer readable in the space"
    );
}

// ---------------------------------------------------------------------------
//  F-SPACE-11 — `getSpace` describes the authority's space, not the caller's.
//
//  It used to open the *caller's* per-actor store. Two failures followed:
//  `ensure_space_row` gives a member's store a space row with column defaults
//  the moment they write, so a client asking about an `allowList` space was
//  told `open`; and a member who had never written had no row at all and got
//  `SpaceNotFound` for a space they belong to.
//
//  Every pre-existing unit test passed the authority as the viewer, so
//  caller-store and authority-store were the same store and none of them could
//  see this.
// ---------------------------------------------------------------------------

async fn get_space(app: &axum::Router, space: &str, token: &str) -> (StatusCode, Value) {
    get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getSpace?space={}",
            urlencode(space)
        ),
        Some(token),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_never_wrote_can_describe_the_space() {
    // Previously `SpaceNotFound`: no write meant no row in the member's store.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let alice = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let uri = create_space(&app, &owner, "default").await;
    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner),
    )
    .await;

    let (status, body) = get_space(&app, &uri, &alice).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a member must be able to describe a space they never wrote to: {body}"
    );
    assert_eq!(body["uri"], uri);
    assert_eq!(
        body["config"]["$type"],
        "com.atproto.simplespace.defs#spaceConfig"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_authoritys_config_is_reported_not_the_callers_defaults() {
    // The test the existing four could not have been. The member writes first,
    // which is what plants a defaulted space row in *their* store — so a pass
    // here means the defaulted row is being ignored, not merely absent.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let alice = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

    // A space whose config is *not* the column defaults.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({
            "type": "app.bsky.group",
            "skey": "restricted",
            "config": {
                "policy": "public",
                "appAccess": {
                    "$type": "com.atproto.simplespace.defs#allowList",
                    "allowed": ["did:web:trusted.example"]
                }
            }
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSpace: {body}");
    let uri = body["uri"].as_str().unwrap().to_string();

    post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.addMember",
        json!({"space": uri, "did": "did:plc:alice"}),
        Some(&owner),
    )
    .await;

    // Alice writes. This is what plants the defaulted row in her store.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "space": uri,
            "writes": [{"action": "create", "collection": "c", "rkey": "r1", "value": {"v": 1}}]
        }),
        Some(&alice),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member write: {body}");

    // Alice asks. She must get the owner's config, not her own defaults.
    let (status, body) = get_space(&app, &uri, &alice).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["config"]["policy"], "public",
        "the caller's defaulted row must not be the answer: {body}"
    );
    assert_eq!(
        body["config"]["appAccess"]["$type"], "com.atproto.simplespace.defs#allowList",
        "a client told `open` for an allowList space cannot make a correct \
         minting decision: {body}"
    );

    // And the authority gets the identical answer — the endpoint does not
    // depend on who asked.
    let (status, owner_body) = get_space(&app, &uri, &owner).await;
    assert_eq!(status, StatusCode::OK, "body: {owner_body}");
    assert_eq!(owner_body["config"], body["config"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_space_is_still_not_found() {
    // Reading the authority's store must not resurrect a tombstoned space.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "doomed").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.deleteSpace",
        json!({"space": uri}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deleteSpace: {body}");

    let (status, body) = get_space(&app, &uri, &owner).await;
    assert_ne!(status, StatusCode::OK, "body: {body}");
}

// ---------------------------------------------------------------------------
//  F-SPACE-03 — inlined record values on the sync path.
//
//  `listRecords` and `listRepoOps` returned keys only, so a syncer had to
//  issue one `getRecord` per record with no bulk path: initial backfill was
//  unusable and the pull design became quadratic. Both lexicons inline the
//  value **by default** and offer `excludeValues` as the opt-out; the in-code
//  comment claiming keys-only "per the lexicon" contradicted the lexicon it
//  named.
// ---------------------------------------------------------------------------

async fn list_space_records(
    app: &axum::Router,
    uri: &str,
    token: &str,
    extra: &str,
) -> (StatusCode, Value) {
    get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRecords?space={}&collection=c{extra}",
            urlencode(uri)
        ),
        Some(token),
    )
    .await
}

async fn list_ops(app: &axum::Router, uri: &str, repo: &str, token: &str, extra: &str) -> Value {
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepoOps?space={}&repo={repo}{extra}",
            urlencode(uri)
        ),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listRepoOps: {body}");
    body
}

async fn space_write(app: &axum::Router, uri: &str, repo: &str, token: &str, writes: Value) {
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({"space": uri, "repo": repo, "writes": writes}),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "applyWrites: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_inlines_values_by_default() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    // A value containing a `$link`, so the decode path is exercised rather than
    // just the plumbing: a raw CBOR tag 42 would come back as a map, not a link.
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{
            "action": "create", "collection": "c", "rkey": "r1",
            "value": {"text": "hi", "ref": {"$link": "bafyreiabc"}}
        }]),
    )
    .await;

    let (status, body) = list_space_records(&app, &uri, &owner, "").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let rec = &body["records"][0];
    assert_eq!(rec["rkey"], "r1");
    assert_eq!(
        rec["value"]["text"], "hi",
        "the value must be inlined by default, or sync needs one getRecord per record: {body}"
    );
    assert_eq!(
        rec["value"]["ref"]["$link"], "bafyreiabc",
        "a stored CBOR link must come back as $link, not a raw map: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_records_honours_reverse() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    for r in ["a", "b", "c"] {
        space_write(
            &app,
            &uri,
            "did:plc:owner",
            &owner,
            json!([{"action": "create", "collection": "c", "rkey": r, "value": {"k": r}}]),
        )
        .await;
    }

    let (_, fwd) = list_space_records(&app, &uri, &owner, "").await;
    let fwd_keys: Vec<&str> = fwd["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rkey"].as_str().unwrap())
        .collect();
    assert_eq!(fwd_keys, vec!["a", "b", "c"]);

    let (_, rev) = list_space_records(&app, &uri, &owner, "&reverse=true").await;
    let rev_keys: Vec<&str> = rev["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rkey"].as_str().unwrap())
        .collect();
    assert_eq!(rev_keys, vec!["c", "b", "a"]);

    // And reverse paginates: the cursor must move backwards, not restart.
    let (_, page1) = list_space_records(&app, &uri, &owner, "&reverse=true&limit=2").await;
    let cursor = page1["cursor"].as_str().unwrap().to_string();
    let (_, page2) = list_space_records(
        &app,
        &uri,
        &owner,
        &format!("&reverse=true&limit=2&cursor={cursor}"),
    )
    .await;
    let p2: Vec<&str> = page2["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rkey"].as_str().unwrap())
        .collect();
    assert_eq!(
        p2,
        vec!["a"],
        "reverse pagination must continue, not restart"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repo_ops_inlines_values_and_omits_superseded_ones() {
    // The subtle half. The lexicon: value is "omitted when excludeValues is
    // set, for deletes, or when the value has been superseded by a later
    // operation". A join on (collection, rkey) alone would attach the *new*
    // value to the *old* op, which is worse than omitting it.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c", "rkey": "r1", "value": {"v": "first"}}]),
    )
    .await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "update", "collection": "c", "rkey": "r1", "value": {"v": "second"}}]),
    )
    .await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c", "rkey": "r2", "value": {"v": "kept"}}]),
    )
    .await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "delete", "collection": "c", "rkey": "r2"}]),
    )
    .await;

    let body = list_ops(&app, &uri, "did:plc:owner", &owner, "").await;
    let ops = body["ops"].as_array().unwrap();
    assert_eq!(
        ops.len(),
        4,
        "four ops: create, update, create, delete: {body}"
    );

    // op 0 — the superseded create.
    assert_eq!(ops[0]["rkey"], "r1");
    assert!(
        ops[0].get("value").is_none(),
        "a superseded op must not inline a value, least of all the newer one: {body}"
    );
    // op 1 — the current update.
    assert_eq!(ops[1]["value"]["v"], "second");
    // op 2 — a create whose record was later deleted, so no current row matches.
    assert!(ops[2].get("value").is_none());
    // op 3 — the delete itself has no cid and so no value.
    assert_eq!(ops[3]["cid"], Value::Null);
    assert!(ops[3].get("value").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repo_ops_exclude_values_omits_every_value() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c", "rkey": "r1", "value": {"v": 1}}]),
    )
    .await;

    let inlined = list_ops(&app, &uri, "did:plc:owner", &owner, "").await;
    assert!(
        inlined["ops"][0]["value"].is_object(),
        "control: inlined by default: {inlined}"
    );

    let excluded = list_ops(&app, &uri, "did:plc:owner", &owner, "&excludeValues=true").await;
    assert!(
        excluded["ops"][0].get("value").is_none(),
        "excludeValues must omit it: {excluded}"
    );
    // The metadata is still there.
    assert_eq!(excluded["ops"][0]["rkey"], "r1");
    assert!(excluded["ops"][0]["cid"].as_str().is_some());
}

// ---------------------------------------------------------------------------
//  F-SPACE-01 / F-SPACE-02 / F-SPACE-20 — the sync recovery path.
//
//  `com.atproto.space.getRepo` and `getLatestCommit` were both absent from the
//  route table, so there was no conformant path to repo state at all: a syncer
//  past its oplog retention had nowhere to go, and a client asking for the
//  commit by its canonical name got a 404. `getRepoState` served the same
//  envelope under a name the draft does not define.
// ---------------------------------------------------------------------------

async fn get_car(
    app: &axum::Router,
    space: &str,
    repo: &str,
    token: &str,
) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.space.getRepo?space={}&repo={repo}",
                    urlencode(space)
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

/// Read a CAR back into `(roots, blocks)`.
async fn parse_car(car: &[u8]) -> (Vec<String>, Vec<(String, Vec<u8>)>) {
    let mut reader = atproto_dasl::car::CarReader::new(std::io::Cursor::new(car.to_vec()))
        .await
        .expect("the response must be a readable CAR");
    let roots = reader
        .header()
        .roots
        .iter()
        .map(|c| c.to_string())
        .collect();
    let mut blocks = Vec::new();
    while let Some(b) = reader.next_block().await.unwrap() {
        blocks.push((b.cid.to_string(), b.data));
    }
    (roots, blocks)
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_exports_a_two_root_car_a_syncer_can_verify() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([
            {"action": "create", "collection": "c.d.e", "rkey": "one", "value": {"v": 1}},
            {"action": "create", "collection": "c.d.e", "rkey": "two", "value": {"v": 2}}
        ]),
    )
    .await;

    let (status, car) = get_car(&app, &uri, "did:plc:owner", &owner).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "getRepo must be routed and serve a CAR"
    );

    let (roots, blocks) = parse_car(&car).await;
    assert_eq!(roots.len(), 2, "commit root then index root");
    // Commit, index, two records.
    assert_eq!(blocks.len(), 4, "commit + index + 2 records");

    // Every block must hash to the CID the CAR claims, or the export is not
    // verifiable — which is the whole purpose of shipping a CAR.
    for (cid, data) in &blocks {
        assert_eq!(
            atproto_dasl::cid::compute_cid(data).to_string(),
            *cid,
            "block bytes must hash to their CID"
        );
    }

    // The index (root 1) maps `{collection}/{rkey}` to the record CIDs, and
    // those CIDs must be blocks in this CAR.
    let index_bytes = blocks
        .iter()
        .find(|(c, _)| *c == roots[1])
        .map(|(_, d)| d.clone())
        .expect("the index root must have a block");
    let index: Value = atproto_dasl::atproto_json::from_slice(&index_bytes).unwrap();
    let obj = index.as_object().unwrap();
    assert_eq!(obj.len(), 2, "one index entry per record: {index}");
    for key in ["c.d.e/one", "c.d.e/two"] {
        let link = obj[key]["$link"].as_str().expect("index entry is a link");
        assert!(
            blocks.iter().any(|(c, _)| c == link),
            "{key} points at {link}, which is not in the CAR"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_car_root_is_the_commit_get_latest_commit_reports() {
    // A CAR whose first root disagreed with `getLatestCommit` would send a
    // syncer chasing a mismatch it cannot resolve.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c.d.e", "rkey": "one", "value": {"v": 1}}]),
    )
    .await;

    let (_, car) = get_car(&app, &uri, "did:plc:owner", &owner).await;
    let (roots, blocks) = parse_car(&car).await;
    let commit_block = blocks
        .iter()
        .find(|(c, _)| *c == roots[0])
        .map(|(_, d)| d.clone())
        .expect("commit root block");
    let from_car: Value = atproto_dasl::atproto_json::from_slice(&commit_block).unwrap();

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getLatestCommit?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // `ikm` is fresh per commit by design, so the two differ there. What must
    // agree is the state being attested: version, rev, and the repo hash.
    assert_eq!(from_car["ver"], body["commit"]["ver"]);
    assert_eq!(from_car["rev"], body["commit"]["rev"]);
    assert_eq!(from_car["hash"], body["commit"]["hash"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_latest_commit_and_get_repo_state_are_the_same_endpoint() {
    // F-SPACE-20: the canonical name is `getLatestCommit`; `getRepoState` is the
    // name this server shipped and is kept as an alias rather than removed.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c.d.e", "rkey": "one", "value": {"v": 1}}]),
    )
    .await;

    let (s1, canonical) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getLatestCommit?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner),
    )
    .await;
    let (s2, alias) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepoState?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(
        s1,
        StatusCode::OK,
        "canonical name must be routed: {canonical}"
    );
    assert_eq!(s2, StatusCode::OK, "the alias must keep working: {alias}");
    // `ikm` and therefore `sig`/`mac` are per-call, so compare the attested state.
    assert_eq!(canonical["commit"]["ver"], alias["commit"]["ver"]);
    assert_eq!(canonical["commit"]["rev"], alias["commit"]["rev"]);
    assert_eq!(canonical["commit"]["hash"], alias["commit"]["hash"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_exports_every_record_across_the_page_boundary() {
    // `list_records` clamps to 100 per page, so an export of more than 100
    // records is where a missing paging loop would silently truncate — and a
    // truncated recovery CAR is worse than none, because it looks complete.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let writes: Vec<Value> = (0..105)
        .map(|i| {
            json!({
                "action": "create",
                "collection": "c.d.e",
                "rkey": format!("r{i:03}"),
                "value": {"i": i}
            })
        })
        .collect();
    space_write(&app, &uri, "did:plc:owner", &owner, json!(writes)).await;

    let (status, car) = get_car(&app, &uri, "did:plc:owner", &owner).await;
    assert_eq!(status, StatusCode::OK);
    let (roots, blocks) = parse_car(&car).await;
    let index_bytes = blocks
        .iter()
        .find(|(c, _)| *c == roots[1])
        .map(|(_, d)| d.clone())
        .unwrap();
    let index: Value = atproto_dasl::atproto_json::from_slice(&index_bytes).unwrap();
    assert_eq!(
        index.as_object().unwrap().len(),
        105,
        "every record must be exported, not just the first page"
    );
    assert_eq!(blocks.len(), 107, "commit + index + 105 records");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_refuses_a_non_member() {
    // Auth goes through the same resolver as every other record read, so the
    // membership check applies — an export is the largest possible read.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let mallory =
        create_account_and_token(&app, &manager, "did:plc:mallory", "mallory.example").await;
    let uri = create_space(&app, &owner, "default").await;
    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c.d.e", "rkey": "one", "value": {"v": 1}}]),
    )
    .await;

    let (status, _) = get_car(&app, &uri, "did:plc:owner", &mallory).await;
    // The specific status matters: an unrouted endpoint also fails, so
    // `!= OK` would pass against a server that never served getRepo at all.
    // 400 `SpaceNotFound` is the membership refusal.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-member must be refused by the membership gate, not by a missing route"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_repo_reports_repo_not_found_for_an_empty_repo() {
    // `RepoNotFound` is declared on getRepo and on no sibling — a repo with no
    // commits has no state to export, and that is a different answer from an
    // empty CAR.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getRepo?space={}&repo=did:plc:owner",
            urlencode(&uri)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "RepoNotFound");
}

// ---------------------------------------------------------------------------
//  F-SPACE-05 — the hash-propagation loop from repo host to space host.
//
//  `notifyWrite` carried `{space, repo, rev}` with no `hash`, though the
//  lexicon marks it required and says why: *"Lets the space host maintain each
//  repo's hash for listRepos."* `listRepos#repo` had no `hash` either, so a
//  syncer could not tell which repos had actually changed without fetching
//  every one.
//
//  Everything needed was already present and unused: `space_received_op` has a
//  `set_hash` column that `receive_write` filled with an empty blob, and the
//  writer built the signed commit and discarded it.
// ---------------------------------------------------------------------------

/// Drive the inbound half directly.
///
/// The writer's `notifyWrite` hop resolves the owner's `#atproto_pds` endpoint
/// from their DID document, which this harness cannot provide — so the send and
/// receive halves are exercised separately rather than through a hop that never
/// fires. `build_notify_payload` covers what is sent; this covers what a space
/// host does with it.
async fn deliver_notify_write(manager: &Arc<AccountManager>, owner_did: &str, payload: &Value) {
    let http = reqwest::Client::new();
    atproto_pds::space::inbound::receive_write(
        &http,
        None,
        manager.data_dir(),
        owner_did,
        serde_json::to_vec(payload).unwrap().as_ref(),
    )
    .await
    .expect("receive_write");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_payload_a_writer_sends_carries_the_commit_hash() {
    // The send half. Previously `{space, repo, rev}` with no hash, though the
    // lexicon marks it required.
    let space: atproto_space::SpaceUri = "at://did:plc:owner/space/app.bsky.group/default"
        .parse()
        .unwrap();
    let hash = vec![0xABu8; 32];
    let payload =
        atproto_pds::space::writer::build_notify_payload(&space, "did:plc:alice", "3jui", &hash);

    let wire = serde_json::to_value(&payload).unwrap();
    assert_eq!(wire["space"], space.to_string());
    assert_eq!(wire["repo"], "did:plc:alice");
    assert_eq!(wire["rev"], "3jui");
    assert_eq!(
        wire["hash"]["$bytes"],
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(&hash),
        "hash must travel in the lexicon's `bytes` wire form"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_inbound_hash_is_stored_on_the_receipt() {
    // The receive half. `space_received_op` has always had a `set_hash` column;
    // `receive_write` filled it with an empty blob.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let hash = vec![0x11u8; 32];
    deliver_notify_write(
        &manager,
        "did:plc:owner",
        &json!({
            "space": uri,
            "repo": "did:plc:alice",
            "rev": "3aaa",
            "hash": {"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(&hash)},
        }),
    )
    .await;

    let store =
        atproto_pds::actor_store::sql::SqlActorStore::open(manager.data_dir(), "did:plc:owner")
            .await
            .unwrap();
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT set_hash FROM space_received_op WHERE space = ? AND issuer_did = ?",
    )
    .bind(&uri)
    .bind("did:plc:alice")
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stored, hash, "the receipt must carry the reported hash");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_reports_the_hash_belonging_to_the_latest_rev() {
    // The report half, and the aggregate-correctness case. Pairing `MAX(rev)`
    // with another row's hash is a wrong answer rather than a missing one, and
    // a syncer acting on it would skip a repo that had in fact changed.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    let older = vec![0x11u8; 32];
    let newer = vec![0x22u8; 32];
    for (rev, hash) in [("3aaa", &older), ("3bbb", &newer)] {
        deliver_notify_write(
            &manager,
            "did:plc:owner",
            &json!({
                "space": uri,
                "repo": "did:plc:alice",
                "rev": rev,
                "hash": {"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash)},
            }),
        )
        .await;
    }

    let credential = mint_space_credential(&app, "did:plc:owner", &uri).await;
    let (status, listed) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&credential),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listRepos: {listed}");
    let repo = &listed["repos"][0];
    assert_eq!(repo["did"], "did:plc:alice");
    assert_eq!(repo["rev"], "3bbb");
    assert_eq!(
        repo["hash"]["$bytes"],
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(&newer),
        "the hash must belong to the latest rev, not another row: {listed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_notify_write_without_a_hash_is_accepted_and_reports_none() {
    // `notifyWrite` is declared best-effort and this is the only implementation
    // that emits a hash at all, so rejecting a payload without one would drop
    // write notifications from every peer running older code. It must also not
    // report `{"$bytes": ""}`, which would claim a hash that is not one.
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    deliver_notify_write(
        &manager,
        "did:plc:owner",
        &json!({"space": uri, "repo": "did:plc:alice", "rev": "3aaa"}),
    )
    .await;

    let credential = mint_space_credential(&app, "did:plc:owner", &uri).await;
    let (status, listed) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&uri)
        ),
        Some(&credential),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listRepos: {listed}");
    assert_eq!(listed["repos"][0]["did"], "did:plc:alice");
    assert!(
        listed["repos"][0].get("hash").is_none(),
        "no hash reported is better than an empty one: {listed}"
    );
}

// ---------------------------------------------------------------------------
//  Wire-shape conformance (F-SPACE-16/17/22/23/24/26).
// ---------------------------------------------------------------------------

/// The lexicon names the user-authorization policy `policy`. This server used
/// to read and write `mintPolicy`, so a conformant client's `policy` was
/// silently dropped and the default applied in its place.
#[tokio::test(flavor = "multi_thread")]
async fn create_space_honours_the_lexicon_policy_field() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.createSpace",
        json!({
            "type": "app.bsky.group",
            "skey": "policied",
            "config": {
                "$type": "com.atproto.simplespace.defs#spaceConfig",
                "policy": "public",
                "appAccess": {"$type": "com.atproto.simplespace.defs#open"}
            }
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createSpace: {body}");
    let uri = body["uri"].as_str().unwrap().to_string();

    let (status, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(&uri)),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getSpace: {body}");
    assert_eq!(
        body["config"]["policy"], "public",
        "the lexicon's `policy` must round-trip: {body}"
    );
    assert!(
        body["config"].get("mintPolicy").is_none(),
        "the non-lexicon name must not be emitted: {body}"
    );
}

/// `updateSpace` takes the same field name.
#[tokio::test(flavor = "multi_thread")]
async fn update_space_honours_the_lexicon_policy_field() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "updatable").await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.updateSpace",
        json!({"space": uri, "policy": "public"}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "updateSpace: {body}");

    let (status, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.space.getSpace?space={}", urlencode(&uri)),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["config"]["policy"], "public", "{body}");
}

/// `applyWrites` returns a `results` array of `$type`-tagged union members,
/// one per write, in request order.
#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_returns_one_typed_result_per_write() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "results").await;

    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "app.t.rec", "rkey": "keep", "value": {"v": 1}}]),
    )
    .await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({
            "space": uri,
            "repo": "did:plc:owner",
            "writes": [
                {"action": "create", "collection": "app.t.rec", "rkey": "fresh", "value": {"v": 2}},
                {"action": "update", "collection": "app.t.rec", "rkey": "keep", "value": {"v": 3}},
                {"action": "delete", "collection": "app.t.rec", "rkey": "keep"}
            ]
        }),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "applyWrites: {body}");

    let results = body["results"].as_array().expect("results array");
    assert_eq!(results.len(), 3, "{body}");
    assert_eq!(
        results[0]["$type"],
        "com.atproto.space.applyWrites#createResult"
    );
    assert!(results[0]["cid"].as_str().is_some());
    assert_eq!(
        results[1]["$type"],
        "com.atproto.space.applyWrites#updateResult"
    );
    assert!(results[1]["cid"].as_str().is_some());
    // A delete result declares no properties at all.
    assert_eq!(
        results[2],
        json!({"$type": "com.atproto.space.applyWrites#deleteResult"})
    );
}

/// `repo` is required on `applyWrites` and, as on the single-record writes,
/// must name the authenticated subject.
#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_requires_a_repo_naming_the_caller() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "repogate").await;

    let write =
        json!([{"action": "create", "collection": "app.t.rec", "rkey": "x", "value": {"v": 1}}]);

    // Omitted entirely.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({"space": uri, "writes": write}),
        Some(&owner),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "a missing repo must be refused");

    // Present but naming someone else.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.space.applyWrites",
        json!({"space": uri, "repo": "did:plc:someone-else", "writes": write}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The URI `getRecord` reports must parse as a space record URI — it names the
/// author. Built with a format string it dropped that segment, so the URI this
/// server returned did not parse with this workspace's own parser.
#[tokio::test(flavor = "multi_thread")]
async fn get_record_reports_a_uri_that_parses_back() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "uris").await;

    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "app.t.rec", "rkey": "r1", "value": {"v": 1}}]),
    )
    .await;

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.getRecord?space={}&repo=did:plc:owner&collection=app.t.rec&rkey=r1",
            urlencode(&uri)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getRecord: {body}");

    let reported = body["uri"].as_str().expect("uri");
    let parsed = atproto_space::RecordUri::parse(reported).expect("reported uri must parse");
    assert_eq!(parsed.author_did, "did:plc:owner");
    assert_eq!(parsed.collection, "app.t.rec");
    assert_eq!(parsed.rkey, "r1");
    assert_eq!(parsed.space.to_string(), uri);
}

/// `listSpaces` takes the lexicon's `type` and `did` filters and returns a
/// cursor when the page is full.
#[tokio::test(flavor = "multi_thread")]
async fn list_spaces_filters_by_type_and_did_and_pages() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;

    for skey in ["a", "b", "c"] {
        create_space(&app, &owner, skey).await;
    }

    // Unfiltered.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.space.listSpaces",
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listSpaces: {body}");
    assert_eq!(body["spaces"].as_array().unwrap().len(), 3, "{body}");
    assert!(
        body.get("cursor").is_none(),
        "a short page must not carry a cursor: {body}"
    );

    // `type` matches.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.space.listSpaces?type=app.bsky.group",
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["spaces"].as_array().unwrap().len(), 3, "{body}");

    // `type` does not match.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.space.listSpaces?type=app.other.kind",
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["spaces"].as_array().unwrap().is_empty(), "{body}");

    // `did` does not match.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.space.listSpaces?did=did:plc:someone-else",
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["spaces"].as_array().unwrap().is_empty(), "{body}");

    // A full page carries a cursor that resumes where it left off.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.space.listSpaces?limit=2",
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = body["spaces"].as_array().unwrap().clone();
    assert_eq!(first.len(), 2, "{body}");
    let cursor = body["cursor"].as_str().expect("cursor on a full page");

    let (status, body) = get_json(
        app,
        &format!(
            "/xrpc/com.atproto.space.listSpaces?limit=2&cursor={}",
            urlencode(cursor)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = body["spaces"].as_array().unwrap();
    assert_eq!(second.len(), 1, "{body}");
    assert!(
        !first.iter().any(|s| s["uri"] == second[0]["uri"]),
        "the cursor must not re-serve a space: {body}"
    );
}

/// `SpaceNotFound` is declared with one status. Three handlers answered 404
/// while every sibling answered 400, so a client switching on the status saw
/// the same condition two different ways.
#[tokio::test(flavor = "multi_thread")]
async fn space_not_found_uses_one_status_everywhere() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let real = create_space(&app, &owner, "default").await;
    let missing = "at://did:plc:owner/space/app.bsky.group/nope";

    // A sibling handler, for the baseline every other one already used.
    let (baseline, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getSpace?space={}",
            urlencode(missing)
        ),
        Some(&owner),
    )
    .await;
    assert_eq!(baseline, StatusCode::BAD_REQUEST, "getSpace: {body}");
    assert_eq!(body["error"], "SpaceNotFound", "{body}");

    // getSpaceCredential — reached with a valid delegation token whose `sub`
    // names a space that does not exist.
    let oauth = mint_oauth_access(
        "did:plc:owner",
        "atproto space:app.bsky.group?did=did:plc:owner&skey=nope&action=read",
    );
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.getDelegationToken?space={}",
            urlencode(missing)
        ),
        Some(&oauth),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getDelegationToken: {body}");
    let grant = body["token"].as_str().unwrap().to_string();
    let (status, body) = exchange_credential(&app, &grant, missing, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "getSpaceCredential must match its siblings: {body}"
    );
    assert_eq!(body["error"], "SpaceNotFound", "{body}");

    // listRepos and registerNotify are space-credential-only, so reaching
    // their lookup needs a credential minted while the space still existed.
    let credential = mint_space_credential(&app, "did:plc:owner", &real).await;
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.simplespace.deleteSpace",
        json!({"space": real}),
        Some(&owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deleteSpace: {body}");

    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.space.listRepos?space={}",
            urlencode(&real)
        ),
        Some(&credential),
    )
    .await;
    assert_ne!(status, StatusCode::NOT_FOUND, "listRepos: {body}");

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.space.registerNotify",
        json!({"space": real}),
        Some(&credential),
    )
    .await;
    assert_ne!(status, StatusCode::NOT_FOUND, "registerNotify: {body}");
}

// ---------------------------------------------------------------------------
//  `listRepoOps.since` accepts a bare rev (F-SPACE-21).
// ---------------------------------------------------------------------------

/// The lexicon calls `since` "operations after this revision" and declares no
/// separate `cursor` **input** — so the `cursor` the response carries has
/// nowhere to go except back into `since`, and a client written against the
/// lexicon alone sends a bare rev. This server required its composite
/// `"<rev>__<idx>"` token and 400'd on anything else, which made the endpoint
/// unreachable from such a client.
#[tokio::test(flavor = "multi_thread")]
async fn list_repo_ops_accepts_a_bare_rev_as_since() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    space_write(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        json!([{"action": "create", "collection": "c.d.e", "rkey": "one", "value": {"v": 1}}]),
    )
    .await;

    let body = list_ops(&app, &uri, "did:plc:owner", &owner, "").await;
    let rev = body["ops"][0]["rev"].as_str().expect("rev").to_string();
    // A TID carries no underscore, so a bare rev can never be mistaken for the
    // composite form.
    assert!(
        !rev.contains("__"),
        "rev must not contain the separator: {rev}"
    );

    let body = list_ops(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        &format!("&since={}", urlencode(&rev)),
    )
    .await;
    // `(rev, 0)` is exclusive of index 0, so the single-op batch is caught up.
    assert!(body["ops"].as_array().unwrap().is_empty(), "{body}");
}

/// The reason a bare rev resolves to `(rev, 0)` rather than to "everything
/// strictly after `rev`": an atomic batch larger than one page. Resuming from
/// a bare rev re-delivers the whole batch, which a syncer applies idempotently
/// — where the stricter reading would silently drop everything after the page
/// boundary. That is the batch-tail-drop bug latent in the draft.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_rev_recovers_a_batch_tail_rather_than_skipping_it() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    // One atomic batch of five ops: all five share a single rev.
    let writes: Vec<Value> = (0..5)
        .map(|i| json!({"action": "create", "collection": "c.d.e", "rkey": format!("k{i}"), "value": {"v": i}}))
        .collect();
    space_write(&app, &uri, "did:plc:owner", &owner, json!(writes)).await;

    // Page one stops inside the batch.
    let body = list_ops(&app, &uri, "did:plc:owner", &owner, "&limit=2").await;
    let first = body["ops"].as_array().unwrap().clone();
    assert_eq!(first.len(), 2, "{body}");
    let rev = first[0]["rev"].as_str().unwrap().to_string();
    assert!(
        first.iter().all(|o| o["rev"] == rev.as_str()),
        "the whole batch must share one rev: {body}"
    );

    // Resuming from the bare rev returns the batch's remaining ops. Under the
    // "strictly after this revision" reading this would come back empty and
    // three writes would be lost with nothing to indicate it.
    let body = list_ops(
        &app,
        &uri,
        "did:plc:owner",
        &owner,
        &format!("&since={}&limit=10", urlencode(&rev)),
    )
    .await;
    let rest = body["ops"].as_array().unwrap();
    assert_eq!(rest.len(), 4, "the batch tail must survive: {body}");
    let rkeys: Vec<&str> = rest.iter().map(|o| o["rkey"].as_str().unwrap()).collect();
    assert_eq!(rkeys, vec!["k1", "k2", "k3", "k4"], "{body}");
}

/// Widening `since` must not widen it to anything: a genuinely malformed token
/// is still a bad request rather than a silently-ignored resume point.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_since_is_still_refused() {
    let (app, manager, _tmp) = build_app().await;
    let owner = create_account_and_token(&app, &manager, "did:plc:owner", "owner.example").await;
    let uri = create_space(&app, &owner, "default").await;

    for token in ["3kabc__x", "__3"] {
        let (status, body) = get_json(
            app.clone(),
            &format!(
                "/xrpc/com.atproto.space.listRepoOps?space={}&repo=did:plc:owner&since={}",
                urlencode(&uri),
                urlencode(token)
            ),
            Some(&owner),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{token}: {body}");
    }
}
