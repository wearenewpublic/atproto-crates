//! A scripted HTTP server for the space-client tests.
//!
//! What is under test here is largely which server received which call and
//! what the request looked like -- the `SpaceHosts` split, the `Bearer` versus
//! `DPoP` scheme, whether a proof carries `ath`. None of that is observable
//! from a faked return value, so the tests drive real sockets.

#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// One scripted response.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    /// Owned, because a space credential is minted per test rather than
    /// written out as a literal.
    pub body: String,
}

impl Reply {
    pub fn new(status: u16, body: &str) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: body.to_string(),
        }
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

/// What one request looked like on the wire.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A server that answers a fixed script and records what it was asked.
///
/// Every reply closes the connection. Keeping the socket alive would let
/// reqwest reuse it for the retry, and then "how many connections did the
/// server accept" would stop being the same question as "how many requests
/// did the client issue".
pub struct Scripted {
    pub base_url: String,
    pub seen: Arc<Mutex<Vec<Recorded>>>,
}

impl Scripted {
    pub async fn start(script: Vec<Reply>) -> Scripted {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let seen = Arc::new(Mutex::new(Vec::new()));

        let recorder = seen.clone();
        tokio::spawn(async move {
            for reply in script {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };

                let mut raw = Vec::new();
                let mut buffer = [0u8; 4096];
                let head_end = loop {
                    let Ok(read) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        break raw.len();
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(position) = find_head_end(&raw) {
                        break position;
                    }
                };

                let head = String::from_utf8_lossy(&raw[..head_end.min(raw.len())]).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_string();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(key, value)| (key.to_string(), value.trim().to_string()))
                    .collect();

                let content_length: usize = headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);

                let mut body = raw[head_end.min(raw.len())..].to_vec();
                while body.len() < content_length {
                    let Ok(read) = socket.read(&mut buffer).await else {
                        break;
                    };
                    if read == 0 {
                        break;
                    }
                    body.extend_from_slice(&buffer[..read]);
                }

                recorder.lock().await.push(Recorded {
                    request_line,
                    headers,
                    body: String::from_utf8_lossy(&body).to_string(),
                });

                let mut response = format!("HTTP/1.1 {} X\r\n", reply.status);
                for (name, value) in &reply.headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
                response.push_str("Connection: close\r\n\r\n");
                response.push_str(&reply.body);

                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });

        Scripted {
            base_url: format!("http://{addr}"),
            seen,
        }
    }

    pub async fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().await.clone()
    }
}

fn find_head_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

impl Recorded {
    /// The XRPC method this request called.
    pub fn xrpc_method(&self) -> &str {
        self.request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .trim_start_matches("/xrpc/")
            .split('?')
            .next()
            .unwrap_or_default()
    }

    /// The claims of the `DPoP` proof, without verifying its signature.
    pub fn proof_claims(&self) -> serde_json::Value {
        use base64::Engine as _;
        let proof = self.header("dpop").expect("a DPoP proof");
        let payload = proof.split('.').nth(1).expect("a compact JWS");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("claims json")
    }
}
