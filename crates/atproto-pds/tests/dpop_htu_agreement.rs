//! The client and the server must compute the same `htu`.
//!
//! `atproto-oauth` mints DPoP proofs; `atproto-pds` recomputes `htu` from the
//! request it received and compares. Nothing made the two agree, and they did
//! not: the client signed the full URL and the server stripped the query, so
//! every authenticated GET carrying parameters was rejected as
//! `InvalidDpopProof` — an error naming the proof, not the URI, and pointing at
//! the token, the key and the clock, all of which were fine.
//!
//! POST procedures were unaffected because their URLs carry no query, which is
//! why this survived: the write path is the one exercised first.
//!
//! Lives here because `atproto-pds` already depends on `atproto-oauth`; the
//! reverse dependency would be the wrong direction for a test.

use atproto_identity::key::{KeyType, generate_key};
use axum::http::Request;
use base64::Engine as _;

/// The `htu` a minted proof actually carries.
fn signed_htu(url: &str) -> String {
    let key = generate_key(KeyType::P256Private).expect("key");
    let (token, _, _) =
        atproto_oauth::dpop::request_dpop(&key, "GET", url, "access-token").expect("proof");
    let payload = token.split('.').nth(1).expect("compact JWS");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("claims");
    claims["htu"].as_str().expect("htu claim").to_string()
}

/// The `htu` this server derives from the corresponding request.
fn derived_htu(path_and_query: &str, host: &str) -> String {
    let parts = Request::builder()
        .uri(path_and_query)
        .header("host", host)
        .header("x-forwarded-proto", "https")
        .body(())
        .expect("request")
        .into_parts()
        .0;
    let (_, htu) = atproto_pds::http::auth::request_htm_htu(&parts);
    htu
}

/// A query-bearing request: the case that failed in production.
#[test]
fn the_two_crates_agree_on_a_query_bearing_url() {
    let host = "pds.example";
    let path = "/xrpc/com.atproto.space.listSpaces?type=app.bulleted.space&limit=100";

    assert_eq!(
        signed_htu(&format!("https://{host}{path}")),
        derived_htu(path, host),
        "the client signs one htu and the server recomputes another, so every \
         authenticated GET with parameters is rejected"
    );
}

/// And on the shapes around it, so agreement is not a coincidence of one URL.
#[test]
fn the_two_crates_agree_across_url_shapes() {
    let host = "pds.example";
    for path in [
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:x&collection=a.b.c&rkey=k",
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x&lxm=a.b.c",
        // No query at all — the POST-shaped case that always worked.
        "/xrpc/com.atproto.repo.createRecord",
        // A trailing slash is path, not decoration.
        "/xrpc/",
        // An encoded delimiter inside the path is not a delimiter.
        "/xrpc/a.b.c/weird%3Fkey?q=1",
    ] {
        assert_eq!(
            signed_htu(&format!("https://{host}{path}")),
            derived_htu(path, host),
            "disagreement on {path}"
        );
    }
}
