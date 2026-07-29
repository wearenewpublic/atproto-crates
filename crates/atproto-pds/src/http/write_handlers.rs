//! XRPC HTTP handlers for `com.atproto.repo.{create,put,delete}Record` and
//! `applyWrites`. All require an authenticated app-password session JWT.

use crate::actor_store::sql::SqlActorStore;
use crate::http::auth::{AuthSubject, request_htm_htu, require_authn};
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::repo::{RepoWriter, WriteAction, WriteOp};
use crate::sequencer::SubscribeEvent;
use atproto_record::tid::Tid;
use atproto_repo::mst::RepoOpAction;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

/// Wake live subscribers with the event this write just recorded.
///
/// The stream is the durable record; the bus only saves a subscriber from
/// waiting out the poll interval. Best-effort in consequence — a failure to
/// read the stream or send to the bus is logged and the write still succeeds,
/// because the poll path delivers the same event moments later.
async fn publish_recent_stream_event(state: &HttpState, did: &str) {
    let sequencer = state.reader.sequencer();
    let latest = match sequencer.latest_seq().await {
        Ok(Some(seq)) => seq,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(did, error = %error, "firehose: stream high-water read failed");
            return;
        }
    };
    // Read the single newest row so the broadcast carries the payload itself.
    let rows = match sequencer.read_after(Some(latest - 1), Some(did), 1).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(did, error = %error, "firehose: stream tail read failed");
            return;
        }
    };
    for row in rows {
        let _ = state.event_bus.publish(SubscribeEvent {
            did: row.did,
            seq: row.seq,
            event_type: row.event_type,
            payload: row.payload,
            created_at: row.created_at,
        });
    }
}

fn writer(state: &HttpState) -> Result<&RepoWriter, XrpcError> {
    state.writer.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "WriteUnavailable",
            "the write subsystem is not configured on this PDS",
        )
    })
}

/// Wrapper around the unified [`require_authn`] that derives `htm`/`htu`
/// from the live request (DPoP proofs are pinned to those values when the
/// caller's OAuth token carries a `cnf.jkt` binding).
async fn require_session(parts: &Parts, state: &HttpState) -> Result<AuthSubject, XrpcError> {
    require_writable_session(parts, state, false).await
}

/// Like [`require_session`], but permits a `deactivated` account.
///
/// Inbound migration is prescribed as create → deactivate → `importRepo` →
/// upload the blobs `listMissingBlobs` reports → `activateAccount`, so every
/// step between the first and the last necessarily runs while the account is
/// deactivated. Refusing them would make the ordinary migration path
/// impossible.
///
/// Moderated states are refused here exactly as elsewhere: a taken-down
/// account must not be able to import a repository either.
async fn require_migration_session(
    parts: &Parts,
    state: &HttpState,
) -> Result<AuthSubject, XrpcError> {
    require_writable_session(parts, state, true).await
}

/// Authenticate, then refuse accounts whose state disallows the write.
///
/// A valid token is not the same as an account permitted to write.
/// `AccountState::allows_writes` existed with no caller at all, so a taken-down
/// account kept writing records and publishing firehose commits until its
/// refresh token expired — up to 90 days after the moderation action.
async fn require_writable_session(
    parts: &Parts,
    state: &HttpState,
    allow_deactivated: bool,
) -> Result<AuthSubject, XrpcError> {
    use crate::account::AccountState;

    let (htm, htu) = request_htm_htu(parts);
    let subject = require_authn(parts, state, &htm, &htu).await?;

    let account = state
        .reader
        .accounts()
        .lookup_did(subject.sub())
        .await
        .map_err(XrpcError::from)?;
    if let Some(account) = account {
        let permitted = account.state.allows_writes()
            || (allow_deactivated && account.state == AccountState::Deactivated);
        if !permitted {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "AccountTakedown",
                format!(
                    "account {} is {}, writes disallowed",
                    account.did, account.state
                ),
            ));
        }
    }
    Ok(subject)
}

/// Refuse a write the granted OAuth scopes do not cover.
///
/// The authorization server parsed and stored what it granted and the resource
/// server never consulted it, so every OAuth token behaved as a wildcard:
/// `scope=atproto` alone could write every collection. App-password sessions
/// carry no scopes by construction and are full-authority, so they are not
/// checked — the same rule `assert_space_scope` already applies to spaces.
fn assert_repo_scope(
    subject: &AuthSubject,
    collection: &str,
    action: atproto_oauth::scopes::RepoAction,
) -> Result<(), XrpcError> {
    if !subject.is_oauth() {
        return Ok(());
    }
    subject
        .scopes()
        .assert_repo(collection, &action)
        .map_err(|missing| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InsufficientScope",
                format!("this token does not grant {}", missing.scope),
            )
        })
}

/// Refuse a blob upload the granted OAuth scopes do not cover.
fn assert_blob_scope(subject: &AuthSubject, mime: &str) -> Result<(), XrpcError> {
    if !subject.is_oauth() {
        return Ok(());
    }
    subject.scopes().assert_blob(mime).map_err(|missing| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InsufficientScope",
            format!("this token does not grant {}", missing.scope),
        )
    })
}

/// Inputs for `com.atproto.repo.createRecord`.
#[derive(Debug, Deserialize)]
pub struct CreateRecordInput {
    /// DID or handle of the repo (must match the session subject).
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Optional record key. If absent, a TID is generated.
    pub rkey: Option<String>,
    /// Record value (DAG-CBOR-encodable JSON).
    pub record: serde_json::Value,
    /// Lexicon schema validation: `false` skips it, `true` requires it, unset
    /// validates against known lexicons only. Declared on all four write
    /// methods and previously accepted by none.
    pub validate: Option<bool>,
    /// Compare-and-swap on the repo's current commit. The write is refused
    /// with `InvalidSwap` if the repository has moved on since the caller read
    /// it. Declared before and never read.
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

/// Output for record-mutation endpoints.
#[derive(Debug, Serialize)]
pub struct WriteRecordResponse {
    /// AT-URI of the affected record.
    pub uri: String,
    /// Record CID (None for delete).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// New commit metadata.
    pub commit: WriteCommitInfo,
    /// What validation this server performed. `unknown` while no schema
    /// engine is wired — reporting `valid` would claim a check that did not
    /// happen. Omitted when the caller asked for validation to be skipped.
    #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<&'static str>,
}

/// Commit metadata returned with a write.
#[derive(Debug, Serialize)]
pub struct WriteCommitInfo {
    /// Commit CID.
    pub cid: String,
    /// Commit rev.
    pub rev: String,
}

fn assert_subject(claims: &AuthSubject, repo_did: &str) -> Result<(), XrpcError> {
    if claims.sub() != repo_did {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "AuthRequired",
            format!(
                "session subject {} cannot write to {}",
                claims.sub(),
                repo_did
            ),
        ));
    }
    Ok(())
}

async fn resolve_repo_did(state: &HttpState, repo: &str) -> Result<String, XrpcError> {
    if repo.starts_with("did:") {
        return Ok(repo.to_string());
    }
    let directory = state.reader.accounts();
    let account = directory.lookup_handle(repo).await?.ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "RepoNotFound",
            format!("handle {repo} not found"),
        )
    })?;
    Ok(account.did)
}

/// Handler for `com.atproto.repo.createRecord`.
pub async fn create_record(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateRecordInput>,
) -> Result<Json<WriteRecordResponse>, XrpcError> {
    let claims = require_session(&parts, &state).await?;
    let writer = writer(&state)?;
    let repo_did = resolve_repo_did(&state, &input.repo).await?;
    assert_subject(&claims, &repo_did)?;
    assert_repo_scope(
        &claims,
        &input.collection,
        atproto_oauth::scopes::RepoAction::Create,
    )?;

    // `validate: true` means "refuse this write unless you validated it".
    // Accepting it while validating nothing would be a control that reads as
    // working and is not, so it is refused by name until the schema engine is
    // wired.
    let validate = crate::repo::prepare::ValidateMode::from_flag(input.validate);
    validate.ensure_supported().map_err(XrpcError::from)?;

    let rkey = input.rkey.unwrap_or_else(|| Tid::new().to_string());
    let result = writer
        .apply_writes_with_swap(
            &repo_did,
            vec![WriteOp {
                action: WriteAction::Create,
                collection: input.collection,
                rkey,
                value: Some(input.record),
                swap_record: None,
            }],
            input.swap_commit.as_deref(),
        )
        .await
        .map_err(XrpcError::from)?;
    publish_recent_stream_event(&state, &repo_did).await;
    let entry = &result.writes[0];
    Ok(Json(WriteRecordResponse {
        uri: entry.uri.clone(),
        cid: entry.cid.clone(),
        commit: WriteCommitInfo {
            cid: result.commit_cid,
            rev: result.rev,
        },
        validation_status: validate.status(),
    }))
}

/// Inputs for `com.atproto.repo.putRecord`.
#[derive(Debug, Deserialize)]
pub struct PutRecordInput {
    /// DID or handle of the repo.
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Record value.
    pub record: serde_json::Value,
    /// Optional swap-record guard.
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
    /// Lexicon schema validation: `false` skips it, `true` requires it, unset
    /// validates against known lexicons only. Declared and previously not
    /// accepted. (`deleteRecord` does not take it — the lexicon has no such
    /// field, since a delete has no record to validate.)
    pub validate: Option<bool>,
    /// Compare-and-swap on the repo's current commit.
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

/// Handler for `com.atproto.repo.putRecord` (idempotent upsert).
pub async fn put_record(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<PutRecordInput>,
) -> Result<Json<WriteRecordResponse>, XrpcError> {
    let claims = require_session(&parts, &state).await?;
    let writer = writer(&state)?;
    let repo_did = resolve_repo_did(&state, &input.repo).await?;
    assert_subject(&claims, &repo_did)?;
    assert_repo_scope(
        &claims,
        &input.collection,
        atproto_oauth::scopes::RepoAction::Update,
    )?;

    let validate = crate::repo::prepare::ValidateMode::from_flag(input.validate);
    validate.ensure_supported().map_err(XrpcError::from)?;

    let result = writer
        .apply_writes_with_swap(
            &repo_did,
            vec![WriteOp {
                action: WriteAction::Update,
                collection: input.collection,
                rkey: input.rkey,
                value: Some(input.record),
                swap_record: input.swap_record,
            }],
            input.swap_commit.as_deref(),
        )
        .await
        .map_err(XrpcError::from)?;
    publish_recent_stream_event(&state, &repo_did).await;
    let entry = &result.writes[0];
    Ok(Json(WriteRecordResponse {
        uri: entry.uri.clone(),
        cid: entry.cid.clone(),
        commit: WriteCommitInfo {
            cid: result.commit_cid,
            rev: result.rev,
        },
        validation_status: validate.status(),
    }))
}

/// Inputs for `com.atproto.repo.deleteRecord`.
#[derive(Debug, Deserialize)]
pub struct DeleteRecordInput {
    /// DID or handle of the repo.
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Optional swap-record guard.
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
    /// Compare-and-swap on the repo's current commit.
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

/// Handler for `com.atproto.repo.deleteRecord`.
pub async fn delete_record(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DeleteRecordInput>,
) -> Result<Json<WriteRecordResponse>, XrpcError> {
    let claims = require_session(&parts, &state).await?;
    let writer = writer(&state)?;
    let repo_did = resolve_repo_did(&state, &input.repo).await?;
    assert_subject(&claims, &repo_did)?;
    assert_repo_scope(
        &claims,
        &input.collection,
        atproto_oauth::scopes::RepoAction::Delete,
    )?;

    let result = writer
        .apply_writes_with_swap(
            &repo_did,
            vec![WriteOp {
                action: WriteAction::Delete,
                collection: input.collection,
                rkey: input.rkey,
                value: None,
                swap_record: input.swap_record,
            }],
            input.swap_commit.as_deref(),
        )
        .await
        .map_err(XrpcError::from)?;
    publish_recent_stream_event(&state, &repo_did).await;
    let entry = &result.writes[0];
    Ok(Json(WriteRecordResponse {
        uri: entry.uri.clone(),
        cid: None,
        // `deleteRecord` declares no `validate` field and no
        // `validationStatus`: there is no record to validate.
        commit: WriteCommitInfo {
            cid: result.commit_cid,
            rev: result.rev,
        },
        validation_status: None,
    }))
}

/// Inputs for `com.atproto.repo.applyWrites`.
#[derive(Debug, Deserialize)]
pub struct ApplyWritesInput {
    /// DID or handle of the repo.
    pub repo: String,
    /// Writes batch.
    pub writes: Vec<ApplyWritesEntry>,
    /// Lexicon schema validation: `false` skips it, `true` requires it, unset
    /// validates against known lexicons only. Declared and previously not
    /// accepted. (`deleteRecord` does not take it — the lexicon has no such
    /// field, since a delete has no record to validate.)
    pub validate: Option<bool>,
    /// Compare-and-swap on the repo's current commit. Guards the whole batch:
    /// the lexicon says "the entire operation will fail".
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

/// One entry in an `applyWrites` batch.
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub enum ApplyWritesEntry {
    /// Create variant.
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        /// NSID collection.
        collection: String,
        /// Optional record key.
        rkey: Option<String>,
        /// Record value.
        value: serde_json::Value,
    },
    /// Update variant.
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        /// NSID collection.
        collection: String,
        /// Record key.
        rkey: String,
        /// Record value.
        value: serde_json::Value,
    },
    /// Delete variant.
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete {
        /// NSID collection.
        collection: String,
        /// Record key.
        rkey: String,
    },
}

/// One entry of the `applyWrites` result union.
///
/// The lexicon types `results` as a **closed** union of `#createResult`,
/// `#updateResult` and `#deleteResult`, so each entry must carry a `$type`
/// naming which one it is. Emitting an undiscriminated object makes batched
/// writes unusable from any validating client.
///
/// Note what these do *not* carry. Neither create nor update results include
/// `commit` — that appears once, at the top level of the response — and
/// `#deleteResult` is an empty object, with no `uri` and no `cid`.
#[derive(Debug, Serialize)]
#[serde(tag = "$type")]
pub enum ApplyWritesResult {
    /// A record was created.
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    Create {
        /// AT-URI of the new record.
        uri: String,
        /// CID of the record value.
        cid: String,
        /// What validation this server performed.
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<&'static str>,
    },
    /// A record was updated.
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    Update {
        /// AT-URI of the record.
        uri: String,
        /// CID of the new record value.
        cid: String,
        /// What validation this server performed.
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<&'static str>,
    },
    /// A record was deleted. Carries nothing else.
    #[serde(rename = "com.atproto.repo.applyWrites#deleteResult")]
    Delete {},
}

/// Output for `com.atproto.repo.applyWrites`.
#[derive(Debug, Serialize)]
pub struct ApplyWritesResponse {
    /// New commit metadata.
    pub commit: WriteCommitInfo,
    /// Per-op results, in input order.
    pub results: Vec<ApplyWritesResult>,
}

/// Handler for `com.atproto.repo.applyWrites`.
pub async fn apply_writes(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Json<ApplyWritesResponse>, XrpcError> {
    let claims = require_session(&parts, &state).await?;
    let writer = writer(&state)?;
    let repo_did = resolve_repo_did(&state, &input.repo).await?;
    assert_subject(&claims, &repo_did)?;

    if input.writes.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "writes must be non-empty",
        ));
    }

    // Captured before `input.writes` is consumed below.
    let swap_commit = input.swap_commit.clone();

    // Asserted per operation, not once for the batch: one `applyWrites` can
    // touch several collections with different verbs, and a token scoped to
    // create in one collection must not delete in another by riding along.
    for entry in &input.writes {
        let (collection, action) = match entry {
            ApplyWritesEntry::Create { collection, .. } => {
                (collection, atproto_oauth::scopes::RepoAction::Create)
            }
            ApplyWritesEntry::Update { collection, .. } => {
                (collection, atproto_oauth::scopes::RepoAction::Update)
            }
            ApplyWritesEntry::Delete { collection, .. } => {
                (collection, atproto_oauth::scopes::RepoAction::Delete)
            }
        };
        assert_repo_scope(&claims, collection, action)?;
    }

    let validate = crate::repo::prepare::ValidateMode::from_flag(input.validate);
    validate.ensure_supported().map_err(XrpcError::from)?;

    let ops: Vec<WriteOp> = input
        .writes
        .into_iter()
        .map(|entry| match entry {
            ApplyWritesEntry::Create {
                collection,
                rkey,
                value,
            } => WriteOp {
                action: WriteAction::Create,
                collection,
                rkey: rkey.unwrap_or_else(|| Tid::new().to_string()),
                value: Some(value),
                swap_record: None,
            },
            ApplyWritesEntry::Update {
                collection,
                rkey,
                value,
            } => WriteOp {
                action: WriteAction::Update,
                collection,
                rkey,
                value: Some(value),
                swap_record: None,
            },
            ApplyWritesEntry::Delete { collection, rkey } => WriteOp {
                action: WriteAction::Delete,
                collection,
                rkey,
                value: None,
                swap_record: None,
            },
        })
        .collect();

    let result = writer
        .apply_writes_with_swap(&repo_did, ops, swap_commit.as_deref())
        .await
        .map_err(XrpcError::from)?;
    publish_recent_stream_event(&state, &repo_did).await;
    let commit = WriteCommitInfo {
        cid: result.commit_cid.clone(),
        rev: result.rev.clone(),
    };
    let results = result
        .writes
        .into_iter()
        .map(|w| match w.op.action {
            RepoOpAction::Create => ApplyWritesResult::Create {
                uri: w.uri,
                cid: w.cid.unwrap_or_default(),
                validation_status: validate.status(),
            },
            RepoOpAction::Update => ApplyWritesResult::Update {
                uri: w.uri,
                cid: w.cid.unwrap_or_default(),
                validation_status: validate.status(),
            },
            RepoOpAction::Delete => ApplyWritesResult::Delete {},
        })
        .collect();
    Ok(Json(ApplyWritesResponse { commit, results }))
}

// ---------------------------------------------------------------------------
//  Account migration scaffolds.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.repo.listMissingBlobs`.
#[derive(Debug, Deserialize)]
pub struct ListMissingBlobsQuery {
    /// Cursor (last `cid`).
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// One entry in the missing-blobs response.
#[derive(Debug, Serialize)]
pub struct MissingBlob {
    /// Blob CID.
    pub cid: String,
    /// AT-URI of a record that references this blob.
    #[serde(rename = "recordUri")]
    pub record_uri: String,
}

/// Response shape for `com.atproto.repo.listMissingBlobs`.
#[derive(Debug, Serialize)]
pub struct ListMissingBlobsResponse {
    /// Page of missing blobs.
    pub blobs: Vec<MissingBlob>,
    /// Cursor for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Handler for `GET /xrpc/com.atproto.repo.listMissingBlobs`.
///
/// Walks `repo_blob_ref ⨝ repo_blob` per the per-actor SQLite store; emits
/// every CID that has at least one record reference but no bytes uploaded.
pub async fn list_missing_blobs(
    State(state): State<HttpState>,
    parts: Parts,
    axum::extract::Query(q): axum::extract::Query<ListMissingBlobsQuery>,
) -> Result<Json<ListMissingBlobsResponse>, XrpcError> {
    let claims = require_migration_session(&parts, &state).await?;
    let limit = q.limit.unwrap_or(500);
    let did = claims.sub();
    if let Some(backend) = state.public_realm_backend.as_ref() {
        // Trait-dispatched path.
        let rows = backend
            .blob
            .list_missing_refs(did, q.cursor.as_deref(), limit)
            .await
            .map_err(XrpcError::from)?;
        let cursor = rows.last().map(|r| r.blob_cid.clone());
        return Ok(Json(ListMissingBlobsResponse {
            blobs: rows
                .into_iter()
                .map(|r| MissingBlob {
                    cid: r.blob_cid,
                    record_uri: r.record_uri,
                })
                .collect(),
            cursor,
        }));
    }
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    let store = SqlActorStore::open(manager.data_dir(), did)
        .await
        .map_err(XrpcError::from)?;
    let rows = crate::blob::list_missing(&store, q.cursor.as_deref(), limit)
        .await
        .map_err(XrpcError::from)?;
    let cursor = rows.last().map(|r| r.cid.clone());
    Ok(Json(ListMissingBlobsResponse {
        blobs: rows
            .into_iter()
            .map(|r| MissingBlob {
                cid: r.cid,
                record_uri: r.record_uri,
            })
            .collect(),
        cursor,
    }))
}

/// Output of `com.atproto.repo.uploadBlob`.
#[derive(Debug, Serialize)]
pub struct UploadBlobResponse {
    /// The canonical blob ref envelope for embedding into a record value.
    pub blob: crate::blob::BlobRef,
}

/// The XRPC refusal for an over-sized upload.
///
/// axum's own rejection is `text/plain` — `Failed to buffer the request body:
/// length limit exceeded` — which is not the error shape every other failure on
/// this surface uses, so a client's error handling never sees it. Reading the
/// body ourselves keeps the refusal in the shape clients already parse.
fn blob_too_large(actual: usize, limit: usize) -> XrpcError {
    XrpcError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "BlobTooLarge",
        format!("blob is {actual} bytes; this server accepts at most {limit}"),
    )
}

/// The XRPC refusal for an over-sized CAR.
fn car_too_large(limit: usize) -> XrpcError {
    XrpcError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "RepoTooLarge",
        format!("repository CAR exceeds this server's {limit}-byte import ceiling"),
    )
}

/// Buffer a request body under an explicit ceiling.
///
/// The handlers take `Body` rather than `Bytes` so the limit is ours. Extracting
/// `Bytes` applies axum's `DEFAULT_LIMIT` of 2 MiB unless a `DefaultBodyLimit`
/// layer overrides it, which is what made the 16 MiB blob ceiling dead code —
/// the real limit was eight times smaller and rejected a typical phone photo.
async fn buffer_body(
    body: axum::body::Body,
    limit: usize,
    too_large: impl FnOnce() -> XrpcError,
) -> Result<axum::body::Bytes, XrpcError> {
    axum::body::to_bytes(body, limit).await.map_err(|_| {
        // `to_bytes` fails on an over-long body or a broken stream. Both are
        // refusals the caller can only act on as "send less".
        too_large()
    })
}

/// Handler for `POST /xrpc/com.atproto.repo.uploadBlob`.
///
/// Reads raw bytes from the request body (axum buffers); content-addresses
/// them; persists into the per-actor `repo_blob` table. The MIME type is
/// taken from the `Content-Type` header (default `application/octet-stream`
/// when absent).
pub async fn upload_blob(
    State(state): State<HttpState>,
    parts: Parts,
    body: axum::body::Body,
) -> Result<Json<UploadBlobResponse>, XrpcError> {
    let claims = require_migration_session(&parts, &state).await?;
    let limit = state.blob_upload_limit_bytes;
    let body = buffer_body(body, limit, || blob_too_large(limit + 1, limit)).await?;
    let mime = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    assert_blob_scope(&claims, &mime)?;
    let did = claims.sub();
    if let Some(backend) = state.public_realm_backend.as_ref() {
        // Trait-dispatched path.
        if body.len() > state.blob_upload_limit_bytes {
            return Err(blob_too_large(body.len(), state.blob_upload_limit_bytes));
        }
        let cid = atproto_dasl::cid::compute_raw_cid(&body).to_string();
        let row = crate::actor_store::BlobRow {
            cid: cid.clone(),
            mime_type: mime.clone(),
            size: body.len() as u64,
            data: body.to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        backend.blob.put(did, &row).await.map_err(XrpcError::from)?;
        return Ok(Json(UploadBlobResponse {
            blob: crate::blob::blob_ref(cid, mime, body.len() as u64),
        }));
    }
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    let store = SqlActorStore::open(manager.data_dir(), did)
        .await
        .map_err(XrpcError::from)?;
    let blob = crate::blob::put_blob(&store, &body, &mime, state.blob_upload_limit_bytes)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(UploadBlobResponse { blob }))
}

/// Output of `com.atproto.repo.importRepo`.
#[derive(Debug, Serialize)]
pub struct ImportRepoResponse {
    /// Latest commit CID after import.
    #[serde(rename = "headCid")]
    pub head_cid: String,
    /// Latest rev (TID).
    #[serde(rename = "headRev")]
    pub head_rev: String,
    /// Number of CAR blocks ingested.
    #[serde(rename = "blocksIngested")]
    pub blocks_ingested: usize,
    /// Number of distinct commits in the imported chain.
    #[serde(rename = "commitsIndexed")]
    pub commits_indexed: usize,
}

/// Handler for `POST /xrpc/com.atproto.repo.importRepo`.
///
/// consumes a CARv1
/// stream into the per-actor block store + commit chain, verifying inductive
/// proofs at each commit. The bearer must own the target repo.
pub async fn import_repo(
    State(state): State<HttpState>,
    parts: Parts,
    body: axum::body::Body,
) -> Result<Json<ImportRepoResponse>, XrpcError> {
    let claims = require_migration_session(&parts, &state).await?;
    let limit = state.import_limit_bytes;
    let body = buffer_body(body, limit, || car_too_large(limit)).await?;
    if !claims.privileged() {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "importRepo requires a privileged session (account password)",
        ));
    }
    let data_dir = match state.account_manager.as_deref() {
        Some(m) => m.data_dir().to_path_buf(),
        None => {
            return Err(XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            ));
        }
    };
    let sequencer = state.reader.sequencer();
    let mut importer = crate::repo::RepoImporter::new(&data_dir).with_sequencer(&sequencer);
    if let Some(backend) = state.public_realm_backend.as_ref() {
        importer = importer.with_backend(backend);
    }
    let outcome = importer
        .import_from_stream(claims.sub(), std::io::Cursor::new(body.to_vec()))
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(ImportRepoResponse {
        head_cid: outcome.head_cid,
        head_rev: outcome.head_rev,
        blocks_ingested: outcome.blocks_ingested,
        commits_indexed: outcome.commits_indexed,
    }))
}
