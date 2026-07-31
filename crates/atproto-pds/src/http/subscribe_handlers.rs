//! `com.atproto.sync.subscribeRepos` WebSocket handler.
//!
//! Live-tail firehose. Subscribers receive a stream of `#commit`, `#sync`,
//! `#identity`, `#account`, and `#info` events. The durable source of truth is
//! [`crate::sequencer::Sequencer`] — one ordered log for the whole server —
//! with an in-process broadcast channel as a wakeup-on-write optimization.
//!
//! One log means one cursor. `seq` numbers the stream, so a subscriber holds a
//! single position in it and resumes from that number; there is no per-account
//! bookkeeping, no ceiling on how many accounts a connection covers, and an
//! account created after a subscriber connects appears without reconnecting.
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

use crate::http::state::HttpState;
use crate::sequencer::frame::{Encoding, encode_event, encode_info};
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
    crate::http::extract::XrpcQuery(params): crate::http::extract::XrpcQuery<SubscribeReposParams>,
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
    // One log, one cursor. `did` is a filter over that log, not a separate
    // stream — the `seq` values a filtered subscriber sees are still the
    // stream's, so its cursor stays valid against the unfiltered stream.
    let did_filter = params.did.clone();
    let sequencer = state.reader.sequencer();

    // A cursor past the head is a client error, not something to wait out. The
    // lexicon declares `FutureCursor` for it and the reference PDS raises it
    // (packages/pds/src/api/com/atproto/sync/subscribeRepos.ts:29-30); holding
    // the socket open instead leaves a consumer that mangled its cursor
    // believing it is caught up and idle forever.
    let head = match sequencer.latest_seq().await {
        Ok(seq) => seq,
        Err(e) => {
            tracing::warn!(error = %e, "subscribeRepos: could not read the stream head");
            None
        }
    };
    if let Some(requested) = params.cursor
        && requested > head.unwrap_or(0)
    {
        let (bytes, is_text) = encode_info(
            encoding,
            "FutureCursor",
            "cursor is ahead of the stream head",
        );
        let _ = send_frame(&mut socket, bytes, is_text).await;
        return;
    }

    // No cursor means "from here on", not "from the beginning". `read_after`
    // treats `None` as the start of the log, so a cursor-less subscriber was
    // served the whole retained history — every reconnect re-read everything,
    // and a new consumer inherited a backlog it had no way to ask not to
    // receive. The reference leaves its outbox cursor unset in this case and
    // streams live events only (subscribeRepos.ts:23-24).
    let mut cursor = params.cursor.or(head);

    // Poll fallback runs at a longer interval since the broadcast covers most
    // wakeups; we still poll occasionally to backfill anything the broadcast
    // dropped.
    let poll_interval = Duration::from_secs(5);

    // Subscribe to live events *before* the initial backfill so we don't lose
    // any commit that lands while we're draining the log.
    let mut live_rx = state.event_bus.subscribe();

    loop {
        // Drain the log up to its current head. `read_after` caps each read, so
        // a subscriber resuming from far behind catches up over several passes
        // rather than buffering the whole backlog.
        loop {
            let rows = match sequencer
                .read_after(cursor, did_filter.as_deref(), 100)
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(error = %e, "subscribeRepos: stream read failed");
                    break;
                }
            };
            let drained = rows.len();
            for row in rows {
                let Some((bytes, is_text)) = encode_event(
                    encoding,
                    row.event_type.as_str(),
                    row.seq,
                    &row.did,
                    &row.payload,
                    &row.created_at,
                ) else {
                    tracing::warn!(
                        did = %row.did,
                        seq = row.seq,
                        "subscribeRepos: failed to encode frame; dropping event"
                    );
                    cursor = Some(row.seq);
                    continue;
                };
                if !send_frame(&mut socket, bytes, is_text).await {
                    tracing::debug!("subscribeRepos: client closed");
                    return;
                }
                cursor = Some(row.seq);
            }
            if drained < 100 {
                break;
            }
        }

        // Wait for either a live broadcast event, the poll-interval timer,
        // or the client closing the socket.
        tokio::select! {
            ev = live_rx.recv() => {
                match ev {
                    Ok(event) => {
                        if did_filter.as_deref().is_some_and(|did| did != event.did) {
                            continue;
                        }
                        // Skip if the poll path already sent this one.
                        if cursor.is_some_and(|c| event.seq <= c) {
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
                        cursor = Some(event.seq);
                    }
                    Err(RecvError::Lagged(n)) => {
                        // Subscriber fell behind by `n` events; skip the
                        // broadcast slot and let the next poll cycle backfill
                        // from the durable log.
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
