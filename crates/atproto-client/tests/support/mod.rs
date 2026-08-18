//! A scripted HTTP server for the transport tests.
//!
//! What is under test in this crate is largely what goes on the wire and how
//! many times it goes there -- whether a challenge is retried, whether a
//! content type survives, whether a status is read before a body. None of that
//! is observable from a faked response, so the tests drive a real socket. A
//! hand-rolled listener keeps that from costing a test-server dependency.

#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// One scripted response.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: &'static str,
}

impl Reply {
    pub fn new(status: u16, body: &'static str) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body,
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
                response.push_str(reply.body);

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
