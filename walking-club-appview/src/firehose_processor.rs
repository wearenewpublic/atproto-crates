//! Direct per-PDS `com.atproto.sync.subscribeRepos` consumer.
//!
//! Opens a WebSocket to each PDS, replays from the stored cursor, decodes each
//! binary frame (DAG-CBOR header + `#commit` body carrying a CAR slice + ops),
//! loads tracked record blocks by CID, and upserts/deletes them into
//! `public_records`. Persists the firehose `seq` per source as the resume
//! cursor.

use std::collections::HashMap;
use std::io::Cursor as IoCursor;
use std::time::Duration;

use atproto_dasl::Ipld;
use atproto_dasl::cid::CidCore;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokio_util::sync::CancellationToken;
use tokio_websockets::ClientBuilder;

use crate::error::{AppError, AppResult};
use crate::state::WebContext;

/// Decoded firehose frame header (first DAG-CBOR object).
#[derive(Debug, Deserialize)]
pub struct FrameHeader {
    /// Frame op code.
    pub op: i64,
    /// Frame type, e.g. `#commit`.
    pub t: Option<String>,
}

/// A single repo op from a `#commit` frame.
#[derive(Debug, Deserialize)]
pub struct FrameOp {
    /// `create` | `update` | `delete`.
    pub action: String,
    /// `<collection>/<rkey>`.
    pub path: String,
    /// New record CID (absent for delete).
    pub cid: Option<atproto_dasl::Cid>,
}

/// The `#commit` frame body.
#[derive(Debug, Deserialize)]
pub struct CommitPayload {
    /// Sequence number (resume cursor).
    pub seq: i64,
    /// Repo DID.
    pub repo: String,
    /// Commit rev (TID).
    pub rev: String,
    /// CARv1 of changed blocks.
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    /// Ops in this commit.
    pub ops: Vec<FrameOp>,
}

/// Maximum backoff between reconnect attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Initial backoff between reconnect attempts.
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// Run the firehose consumer for a single source until cancelled.
///
/// Connects to `{ws_url}/xrpc/com.atproto.sync.subscribeRepos?cursor=<seq>`,
/// replaying from the cursor stored in `firehose_cursors` (if any), then
/// processes frames live. Reconnects with exponential backoff on transport
/// errors, honouring the cancellation token at every wait point.
pub async fn run_source(
    ctx: WebContext,
    source_name: String,
    ws_url: String,
    cancel: CancellationToken,
) {
    tracing::info!(source = %source_name, url = %ws_url, "firehose consumer starting");

    let mut backoff = INITIAL_BACKOFF;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        match run_source_once(&ctx, &source_name, &ws_url, &cancel).await {
            Ok(()) => {
                // Clean shutdown (cancelled) — exit the loop.
                break;
            }
            Err(err) => {
                tracing::warn!(
                    source = %source_name,
                    error = %err,
                    backoff_ms = backoff.as_millis(),
                    "firehose source errored; reconnecting after backoff"
                );
            }
        }

        // Wait out the backoff, but wake early on cancellation.
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    tracing::info!(source = %source_name, "firehose consumer stopped");
}

/// Connect once and stream frames until the socket closes, errors, or the
/// consumer is cancelled. Returns `Ok(())` only when cancelled.
async fn run_source_once(
    ctx: &WebContext,
    source_name: &str,
    ws_url: &str,
    cancel: &CancellationToken,
) -> AppResult<()> {
    let cursor = load_cursor(ctx, source_name).await?;
    let connect_uri = subscribe_uri(ws_url, cursor);

    tracing::info!(source = %source_name, uri = %connect_uri, "connecting to firehose");

    let (mut stream, _resp) = ClientBuilder::new()
        .uri(&connect_uri)
        .map_err(|e| AppError::Firehose(format!("invalid subscribe uri: {e}")))?
        .connect()
        .await
        .map_err(|e| AppError::Firehose(format!("websocket connect failed: {e}")))?;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                return Ok(());
            }
            message = stream.next() => {
                let message = match message {
                    Some(Ok(message)) => message,
                    Some(Err(e)) => {
                        return Err(AppError::Firehose(format!("websocket read error: {e}")));
                    }
                    None => {
                        return Err(AppError::Firehose("websocket stream ended".to_string()));
                    }
                };

                if message.is_close() {
                    return Err(AppError::Firehose("websocket closed by peer".to_string()));
                }
                if !message.is_binary() {
                    // Ping/pong/text are not firehose frames; ignore.
                    continue;
                }

                let payload = message.into_payload();
                if let Err(e) = process_frame(ctx, &payload).await {
                    // A single bad frame should not tear down the whole
                    // connection; log and continue.
                    tracing::warn!(
                        source = %source_name,
                        error = %e,
                        "failed to process firehose frame"
                    );
                    continue;
                }

                // Persist the resume cursor from the frame's seq (commit frames
                // only). Decoding only the header + seq is cheap.
                match frame_commit_seq(&payload) {
                    Ok(Some(seq)) => {
                        if let Err(e) = store_cursor(ctx, source_name, seq).await {
                            tracing::error!(
                                source = %source_name,
                                error = ?e,
                                "failed to persist firehose cursor"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(source = %source_name, error = %e, "no cursor seq in frame");
                    }
                }
            }
        }
    }
}

/// Build the subscribe URL, appending the xrpc path and optional cursor.
fn subscribe_uri(ws_url: &str, cursor: Option<i64>) -> String {
    let base = ws_url.trim_end_matches('/');
    let mut uri = format!("{base}/xrpc/com.atproto.sync.subscribeRepos");
    if let Some(seq) = cursor {
        uri.push_str(&format!("?cursor={seq}"));
    }
    uri
}

/// Read the stored resume cursor for a source, if present.
async fn load_cursor(ctx: &WebContext, source_name: &str) -> AppResult<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT seq FROM firehose_cursors WHERE source = ?")
        .bind(source_name)
        .fetch_optional(&ctx.pool)
        .await?;
    Ok(row.map(|(seq,)| seq))
}

/// Persist the resume cursor for a source (upsert).
async fn store_cursor(ctx: &WebContext, source_name: &str, seq: i64) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO firehose_cursors (source, seq) VALUES (?, ?) \
         ON CONFLICT(source) DO UPDATE SET seq = excluded.seq",
    )
    .bind(source_name)
    .bind(seq)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Decode one binary frame and project tracked record ops.
///
/// Decodes the DAG-CBOR header; for a `#commit` frame it decodes the
/// [`CommitPayload`] body, reads the CAR slice, and upserts/deletes tracked
/// records into `public_records`. Non-`#commit` and error frames are ignored.
pub async fn process_frame(ctx: &WebContext, frame: &[u8]) -> AppResult<()> {
    ctx.metrics.firehose_frames_total.inc();

    let Some(body_bytes) = commit_body(frame)? else {
        // Non-message or non-commit frame: nothing to project.
        return Ok(());
    };

    let commit: CommitPayload = atproto_dasl::from_slice(body_bytes)
        .map_err(|e| AppError::Firehose(format!("commit payload decode failed: {e}")))?;

    project_commit(ctx, &commit).await
}

/// Decode the frame header and, for a `#commit` message frame, return the body
/// byte slice (the second concatenated DAG-CBOR object). Returns `Ok(None)` for
/// non-message or non-commit frames.
fn commit_body(frame: &[u8]) -> AppResult<Option<&[u8]>> {
    // A frame is two concatenated DAG-CBOR objects: a header then a body.
    // Read the header non-strict (it ignores the trailing body bytes) and
    // capture the cursor position so the body starts at the remainder.
    let mut reader = IoCursor::new(frame);
    let header: FrameHeader = atproto_dasl::from_reader_non_strict(&mut reader)
        .map_err(|e| AppError::Firehose(format!("frame header decode failed: {e}")))?;

    // op == -1 signals an error frame; op == 1 is a normal message frame.
    if header.op != 1 {
        tracing::debug!(op = header.op, "skipping non-message firehose frame");
        return Ok(None);
    }

    if header.t.as_deref() != Some("#commit") {
        // Other frame types (#identity, #account, #sync, #info, …) carry no
        // tracked record blocks for the public plane.
        return Ok(None);
    }

    let body_offset = reader.position() as usize;
    Ok(Some(&frame[body_offset..]))
}

/// Extract the resume `seq` from a `#commit` frame for cursor persistence,
/// decoding only the header and the body's `seq` field. Returns `Ok(None)` for
/// non-commit frames.
fn frame_commit_seq(frame: &[u8]) -> AppResult<Option<i64>> {
    /// Minimal projection of the commit body: just the resume cursor.
    #[derive(Deserialize)]
    struct SeqOnly {
        seq: i64,
    }

    let Some(body_bytes) = commit_body(frame)? else {
        return Ok(None);
    };
    let SeqOnly { seq } = atproto_dasl::from_slice_non_strict(body_bytes)
        .map_err(|e| AppError::Firehose(format!("commit seq decode failed: {e}")))?;
    Ok(Some(seq))
}

/// Apply a `#commit`'s tracked ops to `public_records`.
async fn project_commit(ctx: &WebContext, commit: &CommitPayload) -> AppResult<()> {
    let tracked = &ctx.config.tracked_collections;

    // Fast path: nothing to index if no op touches a tracked collection.
    let has_tracked = commit
        .ops
        .iter()
        .any(|op| collection_of(&op.path).is_some_and(|c| tracked.iter().any(|t| t == c)));
    if !has_tracked {
        return Ok(());
    }

    // Load the CAR slice of changed blocks once, indexed by CID.
    let blocks = read_car_blocks(&commit.blocks).await?;

    for op in &commit.ops {
        let Some((collection, rkey)) = split_path(&op.path) else {
            tracing::debug!(path = %op.path, "skipping op with malformed path");
            continue;
        };
        if !tracked.iter().any(|t| t == collection) {
            continue;
        }

        match op.action.as_str() {
            "create" | "update" => {
                let Some(cid) = &op.cid else {
                    tracing::warn!(
                        repo = %commit.repo,
                        path = %op.path,
                        "create/update op missing cid"
                    );
                    continue;
                };
                let Some(block) = blocks.get(cid.inner()) else {
                    tracing::warn!(
                        repo = %commit.repo,
                        path = %op.path,
                        cid = %cid,
                        "record block not present in commit CAR"
                    );
                    continue;
                };

                let record = decode_record_json(block).map_err(|e| {
                    AppError::Firehose(format!("record decode failed for {}: {e}", op.path))
                })?;
                let record_text = serde_json::to_string(&record)
                    .map_err(|e| AppError::Firehose(format!("record re-encode failed: {e}")))?;

                upsert_record(
                    ctx,
                    &commit.repo,
                    collection,
                    rkey,
                    &cid.to_string(),
                    &record_text,
                )
                .await?;
            }
            "delete" => {
                delete_record(ctx, &commit.repo, collection, rkey).await?;
            }
            other => {
                tracing::debug!(action = %other, path = %op.path, "ignoring unknown op action");
            }
        }
    }

    Ok(())
}

/// Read a CARv1 byte slice into a `CID -> block bytes` map.
async fn read_car_blocks(car: &[u8]) -> AppResult<HashMap<CidCore, Vec<u8>>> {
    let cursor = IoCursor::new(car);
    let mut reader = atproto_repo::CarReader::new(cursor)
        .await
        .map_err(|e| AppError::Firehose(format!("CAR header decode failed: {e}")))?;

    let mut blocks = HashMap::new();
    while let Some(block) = reader
        .next_block()
        .await
        .map_err(|e| AppError::Firehose(format!("CAR block decode failed: {e}")))?
    {
        blocks.insert(block.cid, block.data);
    }
    Ok(blocks)
}

/// Decode a DAG-CBOR record block into atproto-canonical JSON.
fn decode_record_json(block: &[u8]) -> Result<JsonValue, String> {
    let ipld: Ipld =
        atproto_dasl::from_slice(block).map_err(|e| format!("dag-cbor decode: {e}"))?;
    Ok(ipld_to_json(&ipld))
}

/// Convert an `Ipld` value to a `serde_json::Value`, rendering CID links as
/// `{"$link": "<cid>"}` and raw bytes as `{"$bytes": "<base64>"}` per the
/// AT Protocol JSON encoding.
fn ipld_to_json(ipld: &Ipld) -> JsonValue {
    match ipld {
        Ipld::Null => JsonValue::Null,
        Ipld::Bool(b) => JsonValue::Bool(*b),
        Ipld::Integer(i) => {
            // serde_json numbers are i64/u64/f64; clamp to i64 where possible.
            if let Ok(n) = i64::try_from(*i) {
                JsonValue::from(n)
            } else if let Ok(n) = u64::try_from(*i) {
                JsonValue::from(n)
            } else {
                JsonValue::String(i.to_string())
            }
        }
        Ipld::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Ipld::String(s) => JsonValue::String(s.clone()),
        Ipld::Bytes(b) => {
            let mut map = JsonMap::new();
            map.insert(
                "$bytes".to_string(),
                JsonValue::String(BASE64_STANDARD_NO_PAD.encode(b)),
            );
            JsonValue::Object(map)
        }
        Ipld::List(items) => JsonValue::Array(items.iter().map(ipld_to_json).collect()),
        Ipld::Map(entries) => {
            let mut map = JsonMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), ipld_to_json(v));
            }
            JsonValue::Object(map)
        }
        Ipld::Link(cid) => {
            let mut map = JsonMap::new();
            map.insert("$link".to_string(), JsonValue::String(cid.to_string()));
            JsonValue::Object(map)
        }
    }
}

/// Split an op `path` (`<collection>/<rkey>`) into its parts.
fn split_path(path: &str) -> Option<(&str, &str)> {
    let (collection, rkey) = path.split_once('/')?;
    if collection.is_empty() || rkey.is_empty() {
        return None;
    }
    Some((collection, rkey))
}

/// Extract just the collection (NSID) from an op `path`.
fn collection_of(path: &str) -> Option<&str> {
    split_path(path).map(|(collection, _)| collection)
}

/// Upsert a record into `public_records` keyed by `(did, collection, rkey)`.
async fn upsert_record(
    ctx: &WebContext,
    did: &str,
    collection: &str,
    rkey: &str,
    cid: &str,
    record: &str,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO public_records (did, collection, rkey, cid, record, indexed_at) \
         VALUES (?, ?, ?, ?, ?, datetime('now')) \
         ON CONFLICT(did, collection, rkey) DO UPDATE SET \
           cid = excluded.cid, record = excluded.record, indexed_at = excluded.indexed_at",
    )
    .bind(did)
    .bind(collection)
    .bind(rkey)
    .bind(cid)
    .bind(record)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Delete a record from `public_records` keyed by `(did, collection, rkey)`.
async fn delete_record(ctx: &WebContext, did: &str, collection: &str, rkey: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM public_records WHERE did = ? AND collection = ? AND rkey = ?")
        .bind(did)
        .bind(collection)
        .bind(rkey)
        .execute(&ctx.pool)
        .await?;
    Ok(())
}
