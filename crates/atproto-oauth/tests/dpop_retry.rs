//! What [`DpopRetry`] does with a 400 or a 401.
//!
//! Three behaviours, each of which was wrong in a way that only shows up
//! against a real server:
//!
//! * a nonce challenge carrying no body is retried rather than reported as a
//!   parse failure;
//! * an ordinary XRPC error reaches the caller as a response rather than as a
//!   middleware error;
//! * a `WWW-Authenticate` that names something other than DPoP settles the
//!   question without the body being read at all.

use std::sync::Arc;

use atproto_identity::key::{KeyType, generate_key};
use atproto_oauth::dpop::{DpopRetry, request_dpop};
use reqwest_chain::ChainMiddleware;
use reqwest_middleware::ClientBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

struct Reply {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

/// A server that answers a fixed script and records the DPoP proof it was sent.
///
/// Every reply closes the connection, so the number of recorded proofs is the
/// number of requests the client issued.
async fn scripted(script: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let count: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let counter = count.clone();
    tokio::spawn(async move {
        for reply in script {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut raw = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let Ok(read) = socket.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let head = String::from_utf8_lossy(&raw).to_string();
            let proof = head
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("dpop"))
                .map(|(_, value)| value.trim().to_string())
                .unwrap_or_default();
            counter.lock().await.push(proof);

            let mut response = format!("HTTP/1.1 {} X\r\n", reply.status);
            for (name, value) in &reply.headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
            response.push_str("Connection: close\r\n\r\n");
            response.push_str(reply.body);

            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    (format!("http://{addr}"), count)
}

/// A client whose middleware is the one under test.
async fn send(url: &str) -> Result<reqwest::Response, reqwest_middleware::Error> {
    let key = generate_key(KeyType::P256Private).expect("generate");
    let (proof, header, claims) = request_dpop(&key, "POST", url, "access-token").expect("proof");

    let client = ClientBuilder::new(reqwest::Client::new())
        .with(ChainMiddleware::new(DpopRetry::new(
            header, claims, key, true,
        )))
        .build();

    client
        .post(url)
        .header("Authorization", "DPoP access-token")
        .header("DPoP", proof)
        .json(&serde_json::json!({"repo": "did:plc:x"}))
        .send()
        .await
}

#[tokio::test]
async fn a_challenge_with_no_body_is_retried() {
    // RFC 9449 section 7.1 specifies the challenge as a `DPoP-Nonce` header
    // and a `WWW-Authenticate`, and says nothing about a body. Reading the
    // body first turned a conformant challenge into
    // `ResponseBodyParsingFailed`, and the write was dropped.
    let (base, count) = scripted(vec![
        Reply {
            status: 401,
            headers: vec![
                ("DPoP-Nonce", "abc"),
                ("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#),
            ],
            body: "",
        },
        Reply {
            status: 200,
            headers: vec![],
            body: r#"{"cid":"bafy"}"#,
        },
    ])
    .await;

    let response = send(&format!("{base}/xrpc/com.atproto.repo.createRecord"))
        .await
        .expect("the challenge should be retried, not raised");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(count.lock().await.len(), 2);
}

#[tokio::test]
async fn an_ordinary_xrpc_error_reaches_the_caller_as_a_response() {
    // `InvalidSwap` is the compare-and-swap failure every correct writer has
    // to handle. The middleware used to raise it as `UnexpectedOAuthError`,
    // so the status, the message, and the chance to retry were all gone.
    let (base, count) = scripted(vec![Reply {
        status: 400,
        headers: vec![],
        body: r#"{"error":"InvalidSwap","message":"Record was changed"}"#,
    }])
    .await;

    let response = send(&format!("{base}/xrpc/com.atproto.repo.putRecord"))
        .await
        .expect("a non-DPoP 400 is a response, not a middleware error");

    assert_eq!(response.status().as_u16(), 400);
    let body: serde_json::Value = response.json().await.expect("body survives");
    assert_eq!(body["error"], "InvalidSwap");
    assert_eq!(body["message"], "Record was changed");
    assert_eq!(count.lock().await.len(), 1);
}

#[tokio::test]
async fn a_non_dpop_challenge_header_settles_it_without_the_body() {
    let (base, count) = scripted(vec![Reply {
        status: 401,
        headers: vec![("WWW-Authenticate", r#"Bearer error="invalid_token""#)],
        body: r#"{"error":"ExpiredToken"}"#,
    }])
    .await;

    let response = send(&format!("{base}/xrpc/com.atproto.repo.putRecord"))
        .await
        .expect("a Bearer challenge is not ours to retry");

    assert_eq!(response.status().as_u16(), 401);
    let body: serde_json::Value = response.json().await.expect("body survives");
    assert_eq!(body["error"], "ExpiredToken");
    assert_eq!(count.lock().await.len(), 1);
}

#[tokio::test]
async fn a_challenge_offered_beside_a_bearer_one_is_still_a_challenge() {
    // RFC 9110 section 11.6.1 lets one header carry several challenges, and a
    // scheme-prefix test refuses the combined form.
    let (base, count) = scripted(vec![
        Reply {
            status: 401,
            headers: vec![
                ("DPoP-Nonce", "abc"),
                (
                    "WWW-Authenticate",
                    r#"Bearer realm="pds", DPoP error="use_dpop_nonce""#,
                ),
            ],
            body: "",
        },
        Reply {
            status: 200,
            headers: vec![],
            body: "{}",
        },
    ])
    .await;

    let response = send(&format!("{base}/xrpc/com.atproto.repo.putRecord"))
        .await
        .expect("retried");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(count.lock().await.len(), 2);
}

#[tokio::test]
async fn a_bare_nonce_with_no_error_code_is_a_challenge() {
    let (base, count) = scripted(vec![
        Reply {
            status: 400,
            headers: vec![("DPoP-Nonce", "xyz")],
            body: "",
        },
        Reply {
            status: 200,
            headers: vec![],
            body: "{}",
        },
    ])
    .await;

    let response = send(&format!("{base}/xrpc/com.atproto.repo.putRecord"))
        .await
        .expect("retried");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(count.lock().await.len(), 2);
}

/// The `jti` and `iat` claims of a proof, without verifying its signature.
fn claims_of(proof: &str) -> serde_json::Value {
    use base64::Engine as _;
    let payload = proof.split('.').nth(1).expect("a compact JWS");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims json")
}

#[tokio::test]
async fn the_retry_proof_is_minted_fresh_and_carries_the_nonce() {
    let (base, proofs) = scripted(vec![
        Reply {
            status: 401,
            headers: vec![
                ("DPoP-Nonce", "abc"),
                ("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#),
            ],
            body: "",
        },
        Reply {
            status: 200,
            headers: vec![],
            body: "{}",
        },
    ])
    .await;

    send(&format!("{base}/xrpc/com.atproto.repo.putRecord"))
        .await
        .expect("retried");

    let proofs = proofs.lock().await.clone();
    assert_eq!(proofs.len(), 2);

    let first = claims_of(&proofs[0]);
    let second = claims_of(&proofs[1]);

    assert!(first.get("nonce").is_none());
    assert_eq!(second["nonce"], "abc");

    // `jti` is single-use (RFC 9449 section 11.1) and servers record it, so a
    // retry re-signing the challenged proof invites being refused as a replay.
    assert_ne!(first["jti"], second["jti"]);
    // And the original `exp` is 30 seconds from a request that has already
    // been out and back.
    assert!(second["exp"].as_u64().expect("exp") >= first["exp"].as_u64().expect("exp"));
}
