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
//! Proposal 0015 adds a versioned wire subprotocol, negotiated through
//! `Sec-WebSocket-Protocol`: `xrpc.v1.json` and `xrpc.v1.cbor` carry one
//! self-describing object per frame, where `xrpc.v0.cbor` splits each message
//! into a header and a body. `xrpc.v0.cbor` stays the default for anything
//! that does not negotiate, which is every consumer in the network today.
//!
//! Browser-dev consumers can also opt-in to JSON frames via `?encoding=json`
//! or the `Accept: application/json` header. That is a private shape from
//! before the proposal and is not the same thing as `xrpc.v1.json`; it stays
//! for the consoles already using it, and a negotiated subprotocol wins.

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
    /// (browser-dev). Also negotiable via the `Accept` header. A private
    /// extension predating proposal 0015; a negotiated subprotocol wins.
    pub encoding: Option<String>,
}

/// WebSocket upgrade handler.
///
/// The wire subprotocol is negotiated the standard way, through
/// `Sec-WebSocket-Protocol` (proposal 0015). A client that offers nothing this
/// server speaks -- or no header at all, which is every consumer written
/// before the proposal -- gets `xrpc.v0.cbor`, which is what the lexicon
/// declares by omission and what the existing firehose has always been.
pub async fn subscribe_repos(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
    headers: HeaderMap,
    crate::http::extract::XrpcQuery(params): crate::http::extract::XrpcQuery<SubscribeReposParams>,
) -> axum::response::Response {
    let offered = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok());

    if let Some((encoding, selected)) = Encoding::negotiate_subprotocol(offered) {
        // Handed back as a one-element list so the token the server echoes is
        // the one this connection will actually speak. axum picks the first
        // *server*-listed protocol the client also offered, so passing the
        // full set would let its order overrule the client's.
        return ws
            .protocols([selected])
            .on_upgrade(move |socket| run_subscriber(socket, state, params, encoding));
    }

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

/// How soon after a quiet period the backstop poll first fires.
const POLL_BASE: Duration = Duration::from_secs(5);

/// The longest the backstop poll will wait.
///
/// This is the worst-case delay for an event the broadcast failed to signal,
/// which is a bug rather than a routine occurrence -- the bus covers the
/// normal path and a lagged receiver already forces a drain. A minute is the
/// point past which a backstop stops being one.
const POLL_MAX: Duration = Duration::from_secs(60);

/// The next backstop interval after a poll that found nothing.
///
/// Doubling rather than a fixed step so an idle connection reaches the ceiling
/// in a handful of polls instead of grinding towards it.
fn backed_off(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > POLL_MAX {
        POLL_MAX
    } else {
        doubled
    }
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

    // The poll is a backstop, not the delivery path: the broadcast wakes a
    // subscriber the moment the stream moves, and this exists only to catch
    // anything the broadcast did not signal. Held at a fixed five seconds it
    // was the dominant cost of an idle server -- every subscriber querying the
    // shared accounts database twelve times a minute whether or not anything
    // had happened, so a thousand idle subscribers cost 200 queries a second
    // to learn that nothing had changed.
    //
    // So it backs off while nothing is arriving and snaps back to the base
    // interval the moment something does. An idle subscriber walks 5s, 10s,
    // 20s, 40s, 60s and stays there; the same thousand cost about 17 queries
    // a second. Live delivery is untouched, because it does not come from
    // here.
    let mut poll_interval = POLL_BASE;

    // Subscribe to live events *before* the initial backfill so we don't lose
    // any commit that lands while we're draining the log.
    let mut live_rx = state.event_bus.subscribe();

    // A wakeup for a DID this subscriber filters out is the one case where
    // there is nothing to go and look for, so it waits again instead of
    // querying. Every other path through the select drains.
    let mut drain = true;

    loop {
        // Reset on delivery rather than on the wakeup that caused it: a
        // broadcast for a DID this subscriber filters out is not traffic as
        // far as this connection is concerned, and treating it as such would
        // hold a filtered subscriber at the base interval forever.
        let mut delivered = false;
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
                delivered = true;
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
        if delivered {
            poll_interval = POLL_BASE;
        }

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
            _ = sleep(poll_interval) => {
                drain = true;
                poll_interval = backed_off(poll_interval);
            }
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

#[cfg(test)]
mod poll_backoff_tests {
    use super::*;

    /// The backstop doubles and then stops.
    ///
    /// The ceiling is what makes this safe to reason about: it is the
    /// worst-case delay for an event the broadcast never signalled, and an
    /// unbounded backoff would turn a missed wakeup into a subscriber that
    /// looks alive and is hours behind.
    #[test]
    fn the_backstop_doubles_up_to_a_ceiling() {
        assert_eq!(backed_off(POLL_BASE), Duration::from_secs(10));
        assert_eq!(backed_off(Duration::from_secs(10)), Duration::from_secs(20));
        assert_eq!(backed_off(Duration::from_secs(20)), Duration::from_secs(40));
        assert_eq!(backed_off(Duration::from_secs(40)), POLL_MAX);
        assert_eq!(backed_off(POLL_MAX), POLL_MAX, "the ceiling holds");
    }

    /// An idle connection reaches the ceiling in a handful of polls.
    ///
    /// Four, from the base -- which is the difference between an idle
    /// subscriber costing twelve queries a minute and costing one.
    #[test]
    fn an_idle_subscriber_reaches_the_ceiling_quickly() {
        let mut interval = POLL_BASE;
        let mut polls = 0;
        while interval < POLL_MAX {
            interval = backed_off(interval);
            polls += 1;
            assert!(polls < 10, "backoff is not converging");
        }
        assert_eq!(polls, 4, "took {polls} polls to reach the ceiling");
    }
}
