//! The DPoP transport: status preservation, the nonce dance, and the failure
//! table.
//!
//! These run against a scripted socket rather than a mocked client. What is
//! under test is what goes on the wire and how many times it goes there --
//! whether a challenge is retried, whether the retry carries the nonce the
//! server issued, whether two challenges in a row loop -- and none of that is
//! observable from a faked response.

use atproto_client::client::{
    DPoPAuth, DpopBody, dpop_call, is_nonce_challenge, post_dpop_json_with_headers,
};
use atproto_client::errors::{UpstreamReason, XrpcError};
use atproto_identity::key::{KeyType, generate_key};
use reqwest::Method;
use reqwest::header::HeaderMap;

mod support;
use support::{Reply, Scripted};

fn auth() -> DPoPAuth {
    DPoPAuth {
        dpop_private_key_data: generate_key(KeyType::P256Private).expect("generate"),
        oauth_access_token: "access-token".to_string(),
    }
}

/// The `nonce` claim of a DPoP proof, without verifying its signature.
fn proof_nonce(proof: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = proof.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

#[tokio::test]
async fn a_rate_limited_response_keeps_its_status_and_retry_after() {
    let server = Scripted::start(vec![
        Reply::new(429, r#"{"error":"RateLimitExceeded"}"#).header("Retry-After", "30"),
    ])
    .await;

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", server.base_url),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 429);
    assert_eq!(response.retry_after_secs(), Some(30));
    assert_eq!(
        response.error(),
        Some(XrpcError::RateLimited {
            retry_after_secs: Some(30)
        })
    );
}

#[tokio::test]
async fn an_invalid_swap_survives_as_a_response() {
    // The regression test for the middleware that turned every non-DPoP 400
    // into `UnexpectedOAuthError`. `InvalidSwap` is the compare-and-swap
    // failure every correct writer has to handle, and it has to arrive as a
    // response for that to be possible.
    let script = || {
        vec![Reply::new(
            400,
            r#"{"error":"InvalidSwap","message":"Record was changed"}"#,
        )]
    };

    let server = Scripted::start(script()).await;
    let url = format!("{}/xrpc/com.atproto.repo.putRecord", server.base_url);
    let record = serde_json::json!({"repo": "did:plc:x"});

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::POST,
        &url,
        Some(DpopBody::Json(&record)),
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 400);
    assert_eq!(
        response.error(),
        Some(XrpcError::InvalidSwap {
            message: "Record was changed".to_string()
        })
    );

    // And the body-only helper, which used to fail here, now returns the body.
    let server = Scripted::start(script()).await;
    let url = format!("{}/xrpc/com.atproto.repo.putRecord", server.base_url);
    let value = post_dpop_json_with_headers(
        &reqwest::Client::new(),
        &auth(),
        &url,
        record,
        &HeaderMap::new(),
    )
    .await
    .expect("post_dpop_json_with_headers");
    assert_eq!(value["error"], "InvalidSwap");
}

#[tokio::test]
async fn a_header_only_nonce_challenge_is_retried_once_with_the_nonce() {
    // RFC 9449 section 7.1 specifies the challenge as headers and says nothing
    // about a body. Against a server that sends the bare shape, the old
    // middleware raised a parse failure and the write was dropped.
    let server = Scripted::start(vec![
        Reply::new(401, "")
            .header("DPoP-Nonce", "abc")
            .header("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#),
        Reply::new(200, r#"{"cid":"bafy"}"#),
    ])
    .await;

    let url = format!("{}/xrpc/com.atproto.repo.createRecord", server.base_url);
    let record = serde_json::json!({"repo": "did:plc:x"});
    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::POST,
        &url,
        Some(DpopBody::Json(&record)),
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 200);

    let requests = server.requests().await;
    assert_eq!(requests.len(), 2, "expected exactly one retry");
    assert_eq!(proof_nonce(requests[0].header("dpop").expect("dpop")), None);
    assert_eq!(
        proof_nonce(requests[1].header("dpop").expect("dpop")),
        Some("abc".to_string())
    );
    // The retry sends the same body, and mints a fresh proof rather than
    // re-signing the challenged one.
    assert_eq!(requests[0].body, requests[1].body);
    assert_ne!(requests[0].header("dpop"), requests[1].header("dpop"));
}

#[tokio::test]
async fn a_bare_nonce_with_no_body_is_retried() {
    let server = Scripted::start(vec![
        Reply::new(400, "").header("DPoP-Nonce", "xyz"),
        Reply::new(200, r#"{"ok":true}"#),
    ])
    .await;

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", server.base_url),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 200);
    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(
        proof_nonce(requests[1].header("dpop").expect("dpop")),
        Some("xyz".to_string())
    );
}

#[tokio::test]
async fn two_nonce_demands_in_a_row_do_not_loop() {
    let challenge = || {
        Reply::new(401, r#"{"error":"use_dpop_nonce"}"#)
            .header("DPoP-Nonce", "abc")
            .header("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#)
    };
    let server = Scripted::start(vec![challenge(), challenge(), Reply::new(200, "{}")]).await;

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", server.base_url),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 401);
    assert_eq!(server.requests().await.len(), 2, "exactly one retry");
}

#[tokio::test]
async fn a_challenge_without_a_nonce_is_returned_rather_than_retried() {
    let server = Scripted::start(vec![
        Reply::new(401, r#"{"error":"use_dpop_nonce"}"#)
            .header("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#),
    ])
    .await;

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", server.base_url),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 401);
    assert_eq!(server.requests().await.len(), 1);
}

#[tokio::test]
async fn a_byte_body_sends_the_given_content_type_and_the_exact_bytes() {
    let server = Scripted::start(vec![Reply::new(200, r#"{"blob":{}}"#)]).await;

    dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::POST,
        &format!("{}/xrpc/com.atproto.repo.uploadBlob", server.base_url),
        Some(DpopBody::Bytes {
            content_type: "image/png",
            data: b"not-really-a-png".to_vec(),
        }),
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    let requests = server.requests().await;
    assert!(
        requests[0]
            .request_line
            .starts_with("POST /xrpc/com.atproto.repo.uploadBlob "),
        "{}",
        requests[0].request_line
    );
    assert_eq!(requests[0].header("content-type"), Some("image/png"));
    assert_eq!(requests[0].body, "not-really-a-png");
}

#[tokio::test]
async fn a_five_hundred_with_an_html_body_does_not_panic() {
    let server = Scripted::start(vec![Reply::new(502, "<html>bad gateway</html>")]).await;

    let response = dpop_call(
        &reqwest::Client::new(),
        &auth(),
        Method::GET,
        &format!("{}/xrpc/com.atproto.repo.getRecord", server.base_url),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("call");

    assert_eq!(response.status.as_u16(), 502);
    assert!(response.body.is_none());
    assert_eq!(response.xrpc_error_fields(), (String::new(), String::new()));
    assert_eq!(
        response.error(),
        Some(XrpcError::Upstream {
            status: 502,
            reason: UpstreamReason::ServerError,
            detail: String::new(),
        })
    );
}

#[test]
fn the_failure_table_classifies_every_shape_it_models() {
    let cases: Vec<(u16, &str, &str, Option<u64>, XrpcError)> = vec![
        (
            429,
            "",
            "",
            None,
            XrpcError::RateLimited {
                retry_after_secs: None,
            },
        ),
        (
            400,
            "InvalidSwap",
            "moved",
            None,
            XrpcError::InvalidSwap {
                message: "moved".to_string(),
            },
        ),
        (
            400,
            "ExpiredToken",
            "",
            None,
            XrpcError::Unauthorized {
                code: "ExpiredToken".to_string(),
                message: String::new(),
            },
        ),
        (
            400,
            "SomeLexiconThing",
            "no",
            None,
            XrpcError::Lexicon {
                status: 400,
                code: "SomeLexiconThing".to_string(),
                message: "no".to_string(),
            },
        ),
        (
            403,
            "ScopeMissingError",
            "",
            None,
            XrpcError::Unauthorized {
                code: "ScopeMissingError".to_string(),
                message: String::new(),
            },
        ),
        (
            503,
            "RateLimitExceeded",
            "",
            Some(5),
            XrpcError::RateLimited {
                retry_after_secs: Some(5),
            },
        ),
        (
            418,
            "",
            "",
            None,
            XrpcError::Upstream {
                status: 418,
                reason: UpstreamReason::UnexpectedStatus,
                detail: String::new(),
            },
        ),
        (
            404,
            "RecordNotFound",
            "gone",
            None,
            XrpcError::Lexicon {
                status: 404,
                code: "RecordNotFound".to_string(),
                message: "gone".to_string(),
            },
        ),
    ];

    for (status, code, message, retry_after, expected) in cases {
        assert_eq!(
            XrpcError::classify(status, code, message, retry_after),
            expected,
            "status {status} code {code}"
        );
    }
}

#[test]
fn the_nonce_challenge_test_reads_all_three_signals() {
    assert!(is_nonce_challenge("use_dpop_nonce", "", false));
    assert!(is_nonce_challenge("invalid_dpop_proof", "", false));
    assert!(is_nonce_challenge(
        "",
        r#"dpop error="use_dpop_nonce""#,
        false
    ));
    assert!(is_nonce_challenge(
        "",
        r#"Bearer realm="pds", DPoP error="use_dpop_nonce""#,
        false
    ));
    assert!(is_nonce_challenge("", "", true));

    // A nonce header alongside a real error code is not a challenge: some
    // servers stamp the current nonce on every response.
    assert!(!is_nonce_challenge("InvalidSwap", "", true));
    assert!(!is_nonce_challenge("", "", false));
}
