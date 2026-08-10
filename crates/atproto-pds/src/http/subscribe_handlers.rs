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
use crate::sequencer::frame::{Encoding, encode_error, encode_event};
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
async fn send_frame(
    socket: &mut WebSocket,
    bytes: Vec<u8>,
    is_text: bool,
    timeout_secs: u64,
) -> SendOutcome {
    let message = if is_text {
        Message::Text(String::from_utf8_lossy(&bytes).into_owned().into())
    } else {
        Message::Binary(bytes.into())
    };
    if timeout_secs == 0 {
        return match socket.send(message).await {
            Ok(()) => SendOutcome::Sent,
            Err(_) => SendOutcome::Closed,
        };
    }
    // A send that never completes is the whole failure. Once the consumer
    // stops reading, TCP backpressure reaches this await and it parks -- the
    // task, the socket and the connection slot are held for as long as the
    // peer leaves the connection open, which can be forever, and nothing
    // distinguishes it from a subscriber idling on a quiet stream.
    match tokio::time::timeout(Duration::from_secs(timeout_secs), socket.send(message)).await {
        Ok(Ok(())) => SendOutcome::Sent,
        Ok(Err(_)) => SendOutcome::Closed,
        Err(_) => SendOutcome::TooSlow,
    }
}

/// What became of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    /// The consumer took it.
    Sent,
    /// The socket is gone; nothing more can be delivered.
    Closed,
    /// The consumer did not take it within the bound.
    TooSlow,
}

/// Resolve when `token` is cancelled, or never if there is no token.
///
/// `select!` needs a future in every arm; this supplies one for the case where
/// the state carries no shutdown token.
async fn cancelled_or_pending(token: Option<&tokio_util::sync::CancellationToken>) {
    match token {
        Some(token) => token.cancelled().await,
        None => std::future::pending().await,
    }
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
    let shutdown = state.shutdown.clone();
    let send_timeout = state.firehose_send_timeout_secs;

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
        // An error frame, not an #info message: the subscription ends here.
        let (bytes, is_text) = encode_error(
            encoding,
            "FutureCursor",
            "cursor is ahead of the stream head",
        );
        let _ = send_frame(&mut socket, bytes, is_text, send_timeout).await;
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

    // A wakeup for a DID this subscriber filters out is the one case where
    // there is nothing to go and look for, so it waits again instead of
    // querying. Every other path through the select drains.
    let mut drain = true;

    loop {
        // Drain the log up to its current head. `read_after` caps each read, so
        // a subscriber resuming from far behind catches up over several passes
        // rather than buffering the whole backlog.
        //
        // This is the only place frames are sent. Everything below decides
        // when to come back here, never what to deliver, so what a subscriber
        // receives is the log's contents in the log's order by construction.
        while drain {
            let rows = match sequencer
                .read_after(cursor, did_filter.as_deref(), 100)
                .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    // Stop and wait rather than re-entering the read
                    // immediately: `drain` is the loop condition now, so
                    // leaving it set would spin against a failing database.
                    tracing::warn!(error = %e, "subscribeRepos: stream read failed");
                    drain = false;
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
                    // Ending the subscription is the honest response. Skipping
                    // the row and advancing past it removes an event from this
                    // consumer's stream permanently while the socket stays up
                    // and healthy-looking, which is the same silent gap the
                    // broadcast path used to produce. A closed connection is
                    // something a consumer reconnects from and an operator can
                    // see.
                    tracing::error!(
                        did = %row.did,
                        seq = row.seq,
                        "subscribeRepos: failed to encode frame; closing the subscription"
                    );
                    let (bytes, is_text) = encode_error(
                        encoding,
                        "InternalServerError",
                        "an event in the stream could not be encoded",
                    );
                    let _ = send_frame(&mut socket, bytes, is_text, send_timeout).await;
                    return;
                };
                match send_frame(&mut socket, bytes, is_text, send_timeout).await {
                    SendOutcome::Sent => {}
                    SendOutcome::Closed => {
                        tracing::debug!("subscribeRepos: client closed");
                        return;
                    }
                    SendOutcome::TooSlow => {
                        // Say so before dropping the socket. A consumer that
                        // reads `ConsumerTooSlow` knows to reconnect from its
                        // cursor and that it is the one falling behind; one
                        // whose connection simply ends has to guess.
                        //
                        // The error frame gets its own bound rather than the
                        // full one: the socket is already congested, so
                        // waiting the same minute again to announce the
                        // problem would double the time the connection is
                        // held for no further benefit.
                        tracing::info!(
                            seq = row.seq,
                            timeout_secs = send_timeout,
                            "subscribeRepos: consumer could not take a frame; closing as too slow"
                        );
                        let (bytes, is_text) = encode_error(
                            encoding,
                            "ConsumerTooSlow",
                            "the stream moved faster than this connection could take it",
                        );
                        let _ = send_frame(&mut socket, bytes, is_text, 1).await;
                        return;
                    }
                }
                cursor = Some(row.seq);
            }
            if drained < 100 {
                drain = false;
                break;
            }
        }

        // `drain` is false on every path out of the loop above, so each arm
        // below states its own answer to "is this a reason to read the log
        // again". An inbound frame that is not a close says nothing, and
        // therefore leaves it false.
        //
        // Wait for either a live wakeup, the poll-interval timer, or the
        // client closing the socket.
        tokio::select! {
            ev = live_rx.recv() => {
                match ev {
                    Ok(event) => {
                        // The signal says the stream moved, not what it moved
                        // to; the drain above decides that. All this arm can
                        // do is skip the query when the write cannot concern
                        // a DID-filtered subscriber.
                        drain = did_filter.as_deref().is_none_or(|did| did == event.did);
                    }
                    Err(RecvError::Lagged(n)) => {
                        // Missed signals are not missed events. The drain reads
                        // from the cursor, so however many wakeups were dropped
                        // it still reads everything after what it last sent.
                        tracing::debug!(lagged = n, "subscribeRepos: missed wakeups; draining from the cursor");
                        drain = true;
                    }
                    Err(RecvError::Closed) => {
                        // Bus dropped (PDS shutting down).
                        return;
                    }
                }
            }
            _ = sleep(poll_interval) => { drain = true; }
            () = cancelled_or_pending(shutdown.as_ref()) => {
                // Close deliberately rather than letting the process drop the
                // socket. A consumer that sees a close frame reconnects; one
                // whose connection is reset mid-frame has to decide whether it
                // lost anything first.
                tracing::debug!("subscribeRepos: shutting down; closing the subscription");
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
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
