//! Space write path: create event/post records in the member's space repo.
//!
//! Called by the compose handlers. The caller passes the record fields; this
//! module stamps `$type`/`createdAt` and POSTs `com.atproto.space.createRecord`
//! on the member's own space host (== their `#atproto_pds` endpoint), authorized
//! by the member's OAuth+DPoP access token (writes are author-attributed; the
//! space credential is never used for writes).

use atproto_client::client::DPoPAuth;
use atproto_space::types::SpaceUri;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::xrpc;

/// The calendar-event collection NSID.
const EVENT_COLLECTION: &str = "community.lexicon.calendar.event";
/// The feed-post collection NSID.
const POST_COLLECTION: &str = "app.bsky.feed.post";

/// Stamp `$type` and `createdAt` into a record if absent, then return it.
fn finalize_record(mut record: Value, collection: &str) -> AppResult<Value> {
    let obj = record
        .as_object_mut()
        .ok_or_else(|| AppError::Space("record must be a JSON object".to_string()))?;
    obj.entry("$type".to_string())
        .or_insert_with(|| Value::String(collection.to_string()));
    obj.entry("createdAt".to_string())
        .or_insert_with(|| Value::String(now_iso()));
    Ok(record)
}

/// Current time as an RFC3339 / ISO-8601 timestamp (UTC, second precision).
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Create a `community.lexicon.calendar.event` record in the space.
///
/// The `record` value carries the event fields; `$type` and `createdAt` are
/// stamped if missing. `repo` is the member DID (MUST equal the OAuth subject).
/// POSTs `com.atproto.space.createRecord` on `host` (the member's own PDS) with
/// DPoP auth and returns `{ uri, cid, validationStatus? }`.
pub async fn create_event(
    http: &reqwest::Client,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    record: Value,
) -> AppResult<Value> {
    let record = finalize_record(record, EVENT_COLLECTION)?;
    xrpc::create_record(
        http,
        auth,
        host,
        space,
        repo,
        EVENT_COLLECTION,
        None,
        record,
    )
    .await
}

/// Create an `app.bsky.feed.post` record in the space.
///
/// The `record` value carries the post fields; `$type` and `createdAt` are
/// stamped if missing. `repo` is the member DID (MUST equal the OAuth subject).
/// POSTs `com.atproto.space.createRecord` on `host` (the member's own PDS) with
/// DPoP auth and returns `{ uri, cid, validationStatus? }`.
pub async fn create_post(
    http: &reqwest::Client,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    record: Value,
) -> AppResult<Value> {
    let record = finalize_record(record, POST_COLLECTION)?;
    xrpc::create_record(http, auth, host, space, repo, POST_COLLECTION, None, record).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finalize_stamps_type_and_created_at() {
        let out = finalize_record(json!({"name": "Walk"}), EVENT_COLLECTION).unwrap();
        assert_eq!(out["$type"], json!(EVENT_COLLECTION));
        assert_eq!(out["name"], json!("Walk"));
        assert!(out["createdAt"].is_string());
    }

    #[test]
    fn finalize_preserves_existing_type() {
        let out = finalize_record(
            json!({"$type": "custom", "createdAt": "x"}),
            POST_COLLECTION,
        )
        .unwrap();
        assert_eq!(out["$type"], json!("custom"));
        assert_eq!(out["createdAt"], json!("x"));
    }

    #[test]
    fn finalize_rejects_non_object() {
        assert!(finalize_record(json!("nope"), EVENT_COLLECTION).is_err());
    }
}
