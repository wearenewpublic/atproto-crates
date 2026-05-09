//! `com.atproto.sync.subscribeRepos` WebSocket handler.
//!
//! Live-tail firehose. Subscribers receive a stream of `#commit`, `#sync`,
//! `#identity`, `#account`, and `#info` events; the durable per-actor
//! outbox is the source of truth, with an in-process broadcast channel as
//! a wakeup-on-write optimization.
//!
//! # Wire framing
//!
//! Sync 1.1 mandates a binary frame: each WS message is a single binary
//! blob containing two consecutive DAG-CBOR objects (header || body),
//! the `com.atproto.sync.subscribeRepos` lexicon. The encoder lives in
//! [`crate::sequencer::frame`].
//!
//! Browser-dev consumers can opt-in to JSON frames via `?encoding=json` or
//! the `Accept: application/json` header. CBOR is the production default.

use crate::actor_store::sql::SqlActorStore;
use crate::http::state::HttpState;
use crate::sequencer::OutboxReader;
use crate::sequencer::frame::{Encoding, encode_event, encode_info};

/// Open the per-DID outbox reader. Routes through the trait dispatch
/// when `state.public_realm_backend` is wired; otherwise falls back to the legacy SQLite-direct path so
/// tests that build `HttpState` without a backend keep working.
async fn open_outbox(state: &HttpState, did: &str) -> crate::errors::PdsResult<OutboxReader> {
    if let Some(backend) = state.public_realm_backend.as_ref() {
        Ok(OutboxReader::dispatch(backend.outbox.clone(), did))
    } else {
        let store = SqlActorStore::open(state.reader.data_dir(), did).await?;
        Ok(OutboxReader::new(store.pool().clone()))
    }
}
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::sleep;

/// Query parameters for `com.atproto.sync.subscribeRepos`.
#[derive(Debug, Deserialize)]
pub struct SubscribeReposParams {
    /// Resume cursor (`seq` to read after).
    pub cursor: Option<i64>,
    /// Restrict to one DID (PDS-local helper; the spec firehose is
    /// global).
    pub did: Option<String>,
    /// Override the wire encoding. `cbor` (default, spec) or `json`
    /// (browser-dev). Also negotiable via the `Accept` header.
    pub encoding: Option<String>,
}

/// WebSocket upgrade handler.
pub async fn subscribe_repos(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<SubscribeReposParams>,
) -> axum::response::Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let encoding = Encoding::negotiate(params.encoding.as_deref(), accept.as_deref());
    ws.on_upgrade(move |socket| run_subscriber(socket, state, params, encoding))
}

/// Send a single frame to a subscriber, returning `false` if the socket
/// closed (caller should exit the loop).
async fn send_frame(socket: &mut WebSocket, bytes: Vec<u8>, is_text: bool) -> bool {
    let message = if is_text {
        Message::Text(String::from_utf8_lossy(&bytes).into_owned().into())
    } else {
        Message::Binary(bytes.into())
    };
    socket.send(message).await.is_ok()
}

async fn run_subscriber(
    mut socket: WebSocket,
    state: HttpState,
    params: SubscribeReposParams,
    encoding: Encoding,
) {
    // Resolve which DIDs to tail.
    let dids = match params.did.as_deref() {
        Some(did) => vec![did.to_string()],
        None => match list_account_dids(&state).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "subscribeRepos: account listing failed");
                let (bytes, is_text) = encode_info(encoding, "InternalError", &e.to_string());
                let _ = send_frame(&mut socket, bytes, is_text).await;
                return;
            }
        },
    };

    // Per-DID cursor map. All start from the requested global cursor.
    let mut cursors: std::collections::BTreeMap<String, Option<i64>> =
        dids.into_iter().map(|did| (did, params.cursor)).collect();

    // Poll fallback now runs at a longer interval since the broadcast covers
    // most wakeups; we still poll occasionally to backfill any events we
    // missed due to broadcast lag.
    let poll_interval = Duration::from_secs(5);

    // Subscribe to live events *before* the initial backfill so we don't lose
    // any commit that lands while we're draining outboxes.
    let mut live_rx = state.event_bus.subscribe();

    loop {
        // Drain all outboxes once.
        for (did, cursor) in cursors.iter_mut() {
            let outbox = match open_outbox(&state, did).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(did, error = %e, "subscribeRepos: open outbox failed");
                    continue;
                }
            };
            let rows = match outbox.read_after(*cursor, 100).await {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(did, error = %e, "subscribeRepos: read_after failed");
                    continue;
                }
            };
            for row in rows {
                let Some((bytes, is_text)) = encode_event(
                    encoding,
                    row.event_type.as_str(),
                    row.seq,
                    did,
                    &row.payload,
                    &row.created_at,
                ) else {
                    tracing::warn!(
                        did,
                        seq = row.seq,
                        "subscribeRepos: failed to encode frame; dropping event"
                    );
                    continue;
                };
                if !send_frame(&mut socket, bytes, is_text).await {
                    tracing::debug!("subscribeRepos: client closed");
                    return;
                }
                *cursor = Some(row.seq);
            }
        }

        // Wait for either a live broadcast event, the poll-interval timer,
        // or the client closing the socket.
        tokio::select! {
            ev = live_rx.recv() => {
                match ev {
                    Ok(event) => {
                        // Only forward events for DIDs we're tailing.
                        if let Some(cursor) = cursors.get_mut(&event.did) {
                            // Skip if we already saw this seq in the poll path.
                            if cursor.map(|c| event.seq <= c).unwrap_or(false) {
                                continue;
                            }
                            let Some((bytes, is_text)) = encode_event(
                                encoding,
                                &event.event_type,
                                event.seq,
                                &event.did,
                                &event.payload,
                                &event.created_at,
                            ) else {
                                tracing::warn!(
                                    did = %event.did,
                                    seq = event.seq,
                                    "subscribeRepos: failed to encode broadcast frame; dropping"
                                );
                                continue;
                            };
                            if !send_frame(&mut socket, bytes, is_text).await {
                                return;
                            }
                            *cursor = Some(event.seq);
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        // Subscriber fell behind by `n` events; skip the
                        // broadcast slot and let the next poll-cycle backfill
                        // from the durable outbox.
                        tracing::warn!(lagged = n, "subscribeRepos: broadcast lag, falling back to poll");
                    }
                    Err(RecvError::Closed) => {
                        // Bus dropped (PDS shutting down).
                        return;
                    }
                }
            }
            _ = sleep(poll_interval) => {}
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Err(_)) => return,
                    _ => {} // ignore other inbound frames
                }
            }
        }
    }
}

async fn list_account_dids(state: &HttpState) -> crate::errors::PdsResult<Vec<String>> {
    let directory = state.reader.accounts();
    let rows = directory.list_accounts(None, 1000).await?;
    Ok(rows.into_iter().map(|r| r.did).collect())
}
