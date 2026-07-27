//! Space read pipeline: credential -> direct per-writer pull -> verify -> project.
//!
//! Reads are a **direct, partitioned pull** (plan §2.4, §3.5 D-H). The writer
//! set comes from `listRepos` on the authority host (the space owner's
//! `#atproto_space_host`); each writer's records are then pulled from *that
//! writer's own* `#atproto_pds` with the no-`aud` space credential — never
//! proxied through the authority host. Each writer's signed commit is verified
//! and its LtHash reconciled (`verify::verify_repo_state`) before any op is
//! projected, and a writer's `cursor` is only advanced on a successful verify.
//!
//! Background syncs (notify-triggered) carry no member session, so they cannot
//! mint a fresh credential; they rely on a cached, unexpired space credential in
//! `space_credential_cache`. On a cache miss the sync logs and no-ops — the
//! session-driven feed path mints the credential.

use atproto_space::set_hash::record_element_bytes;
use atproto_space::types::SpaceUri;
use atproto_space::{Commit, LtHash, SetHash, SpaceContext};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NOPAD;
use chrono::Utc;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::space::verify;
use crate::state::WebContext;
use crate::xrpc::xrpc_url;

/// Pull and project the entire space (all member repos).
///
/// Resolves the authority host, ensures a (cached) space credential, fetches the
/// writer set via `listRepos`, resolves each writer's `#atproto_pds`, persists
/// the writer row, and syncs each repo. Failure to sync one writer never aborts
/// the others.
pub async fn sync_space(ctx: &WebContext, space: &SpaceUri) -> AppResult<()> {
    let authority_host = authority_host(ctx, space).await?;
    let credential = match cached_space_credential(ctx, space).await? {
        Some(cred) => cred,
        None => {
            tracing::warn!(
                space = %space,
                "no cached space credential; skipping background space sync"
            );
            return Ok(());
        }
    };

    let repos = list_repos(ctx, &authority_host, space, &credential).await?;
    // Member perimeter (Step G): the rendered set is exactly the listRepos
    // writer set. Each writer is persisted, then pulled directly from its host.
    for (writer_did, rev) in &repos {
        let pds_host = match resolve_pds_host(ctx, writer_did).await {
            Ok(host) => host,
            Err(error) => {
                tracing::warn!(
                    writer = %writer_did,
                    error = ?error,
                    "could not resolve writer #atproto_pds; skipping"
                );
                continue;
            }
        };
        if let Err(error) = upsert_writer(ctx, space, writer_did, rev, &pds_host).await {
            tracing::warn!(writer = %writer_did, error = ?error, "writer upsert failed");
            continue;
        }
        if let Err(error) = sync_repo(ctx, space, writer_did).await {
            tracing::warn!(writer = %writer_did, error = ?error, "writer sync failed");
        }
    }
    Ok(())
}

/// Pull, verify, and project a single member repo.
///
/// Reads the writer's host (from `writers.pds_host`, resolving on demand),
/// pulls `getRepoState` + `listRepoOps` with the cached space credential,
/// verifies the deniable commit and reconciles the LtHash over the live ops,
/// recomputes each op CID, fetches each record, and upserts the projection. The
/// writer cursor advances only after the verify succeeds.
pub async fn sync_repo(ctx: &WebContext, space: &SpaceUri, repo_did: &str) -> AppResult<()> {
    let credential = match cached_space_credential(ctx, space).await? {
        Some(cred) => cred,
        None => {
            tracing::warn!(
                space = %space,
                repo = %repo_did,
                "no cached space credential; skipping repo sync"
            );
            return Ok(());
        }
    };

    let pds_host = writer_pds_host(ctx, space, repo_did).await?;

    // 1. getRepoState -> the current signed commit (or empty repo: nothing to do).
    let state = get_repo_state(ctx, &pds_host, space, repo_did, &credential).await?;
    let Some(commit_value) = state.get("commit").filter(|v| !v.is_null()) else {
        tracing::debug!(repo = %repo_did, "repo has no commit yet; nothing to project");
        return Ok(());
    };
    let commit = decode_commit(commit_value)?;

    // 2. listRepoOps (paged) -> the full live op set for reconciliation, plus the
    //    record fetches that feed the projection.
    let ops = list_all_repo_ops(ctx, &pds_host, space, repo_did, &credential).await?;

    // 3. Reconcile: rebuild an LtHash from the live (collection, rkey, cid) ops
    //    and confirm sha256(state) == commit.hash. Also recompute every op CID.
    let mut lt = LtHash::empty();
    for op in &ops {
        let Some(cid) = op.cid.as_deref() else {
            continue; // deletes carry no cid and no live element.
        };
        lt.add(&record_element_bytes(&op.collection, &op.rkey, cid));
    }
    // The PDS does not return `setHash` on getRepoState; the reconcile target is
    // the LtHash rebuilt from the live ops. Drive the fixed verify_repo_state
    // signature with the hex of that rebuilt state.
    let set_hash_hex = hex::encode(lt.state_bytes());

    let author_key = resolve_author_key(ctx, repo_did).await?;
    let context = SpaceContext {
        space: space.to_string(),
        rev: commit.rev.clone(),
    };
    if let Err(error) = verify::verify_repo_state(&context, &commit, &author_key, &set_hash_hex) {
        // error-walking-club-appview-verify-1: reject this writer's batch and do
        // NOT advance its cursor.
        tracing::error!(
            repo = %repo_did,
            error = ?error,
            "error-walking-club-appview-verify-1 commit verify/reconcile failed"
        );
        return Err(error);
    }

    // 4. Fetch + project each live record. Recompute the CID independently and
    //    confirm it matches the op's advertised CID before projecting.
    let mut last_rev = commit.rev.clone();
    for op in &ops {
        let Some(op_cid) = op.cid.as_deref() else {
            // delete: drop any projected row for this (writer, rkey).
            delete_projection(ctx, space, repo_did, &op.collection, &op.rkey).await?;
            if op.rev.as_str() > last_rev.as_str() {
                last_rev = op.rev.clone();
            }
            continue;
        };
        let fetched = match get_record(
            ctx,
            &pds_host,
            space,
            repo_did,
            &op.collection,
            &op.rkey,
            &credential,
        )
        .await
        {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    repo = %repo_did,
                    collection = %op.collection,
                    rkey = %op.rkey,
                    error = ?error,
                    "getRecord failed; skipping op"
                );
                continue;
            }
        };

        // Independently recompute the record CID (CIDv1/dag-cbor/sha2-256) and
        // compare against the op CID.
        let encoded = atproto_dasl::to_vec(&fetched)
            .map_err(|e| AppError::Space(format!("dag-cbor encode record: {e}")))?;
        let computed = atproto_dasl::cid::compute_cid(&encoded).to_string();
        if computed != op_cid {
            tracing::error!(
                repo = %repo_did,
                collection = %op.collection,
                rkey = %op.rkey,
                op_cid = %op_cid,
                computed = %computed,
                "error-walking-club-appview-verify-1 record CID mismatch"
            );
            return Err(AppError::Space("record CID mismatch".into()));
        }

        project_record(
            ctx,
            space,
            repo_did,
            op_cid,
            &op.collection,
            &op.rkey,
            &fetched,
        )
        .await?;
        if op.rev.as_str() > last_rev.as_str() {
            last_rev = op.rev.clone();
        }
    }

    // 5. Advance the writer cursor + verified marker only after a clean verify.
    advance_writer(ctx, space, repo_did, &last_rev, &commit.hash).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
//  Host / credential resolution.
// ---------------------------------------------------------------------------

/// Resolve the authority host (the space owner's `#atproto_space_host`).
async fn authority_host(ctx: &WebContext, space: &SpaceUri) -> AppResult<String> {
    let owner_did = ctx
        .config
        .space_owner_did
        .clone()
        .unwrap_or_else(|| space.space_did.clone());
    let document = ctx
        .identity_resolver
        .resolve(&owner_did)
        .await
        .map_err(|e| AppError::Space(format!("resolve space owner {owner_did}: {e}")))?;
    document
        .service_endpoint("atproto_space_host")
        .or_else(|| document.service_endpoint("atproto_pds"))
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Space(format!("owner {owner_did} has no #atproto_space_host")))
}

/// Resolve a DID's `#atproto_pds` service endpoint.
async fn resolve_pds_host(ctx: &WebContext, did: &str) -> AppResult<String> {
    let document = ctx
        .identity_resolver
        .resolve(did)
        .await
        .map_err(|e| AppError::Space(format!("resolve {did}: {e}")))?;
    document
        .service_endpoint("atproto_pds")
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Space(format!("{did} has no #atproto_pds")))
}

/// Resolve a DID's `#atproto` verification key into a [`KeyData`].
async fn resolve_author_key(
    ctx: &WebContext,
    did: &str,
) -> AppResult<atproto_identity::key::KeyData> {
    let document = ctx
        .identity_resolver
        .resolve(did)
        .await
        .map_err(|e| AppError::Space(format!("resolve {did}: {e}")))?;
    let multibase = document
        .verification_method_multibase("atproto")
        .ok_or_else(|| AppError::Space(format!("{did} has no #atproto key")))?;
    atproto_identity::key::identify_key(multibase)
        .map_err(|e| AppError::Space(format!("parse {did} #atproto key: {e}")))
}

/// Read the writer's host from `writers.pds_host`, resolving + persisting it on
/// a miss.
async fn writer_pds_host(ctx: &WebContext, space: &SpaceUri, repo_did: &str) -> AppResult<String> {
    let space_str = space.to_string();
    let row: Option<(String,)> =
        sqlx::query_as("SELECT pds_host FROM writers WHERE space = ? AND writer_did = ?")
            .bind(&space_str)
            .bind(repo_did)
            .fetch_optional(&ctx.pool)
            .await?;
    match row {
        Some((host,)) if !host.is_empty() => Ok(host),
        _ => resolve_pds_host(ctx, repo_did).await,
    }
}

/// Look up any cached, unexpired space credential for this space.
///
/// The credential is bound to the space (`sub`, no `aud`), not to a member, so
/// any unexpired row for the space is reusable across writers (plan R6).
async fn cached_space_credential(ctx: &WebContext, space: &SpaceUri) -> AppResult<Option<String>> {
    let space_str = space.to_string();
    let now = Utc::now().to_rfc3339();
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT credential FROM space_credential_cache \
         WHERE space = ? AND expires_at > ? \
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(&space_str)
    .bind(&now)
    .fetch_optional(&ctx.pool)
    .await?;
    Ok(row.map(|(c,)| c))
}

// ---------------------------------------------------------------------------
//  Credential-bearer XRPC reads (raw HTTP — reads use Bearer <CRED>, not DPoP).
// ---------------------------------------------------------------------------

/// `GET com.atproto.space.listRepos` on the authority host (Bearer credential).
async fn list_repos(
    ctx: &WebContext,
    host: &str,
    space: &SpaceUri,
    credential: &str,
) -> AppResult<Vec<(String, String)>> {
    let space_str = space.to_string();
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut params: Vec<(&str, &str)> = vec![("space", space_str.as_str())];
        if let Some(c) = cursor.as_deref() {
            params.push(("cursor", c));
        }
        let url = xrpc_url(host, "com.atproto.space.listRepos", &params)?;
        let body = bearer_get(ctx, &url, credential).await?;
        if let Some(repos) = body.get("repos").and_then(Value::as_array) {
            for repo in repos {
                let did = repo.get("did").and_then(Value::as_str);
                let rev = repo.get("rev").and_then(Value::as_str);
                if let (Some(did), Some(rev)) = (did, rev) {
                    out.push((did.to_string(), rev.to_string()));
                }
            }
        }
        match body.get("cursor").and_then(Value::as_str) {
            Some(next) if !next.is_empty() => cursor = Some(next.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

/// `GET com.atproto.space.getRepoState` (Bearer credential, explicit `repo`).
async fn get_repo_state(
    ctx: &WebContext,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    credential: &str,
) -> AppResult<Value> {
    let space_str = space.to_string();
    let url = xrpc_url(
        host,
        "com.atproto.space.getRepoState",
        &[("space", space_str.as_str()), ("repo", repo)],
    )?;
    bearer_get(ctx, &url, credential).await
}

/// A single records-oplog entry (`com.atproto.space.listRepoOps#opEntry`).
struct OpEntry {
    rev: String,
    collection: String,
    rkey: String,
    cid: Option<String>,
}

/// Page through `com.atproto.space.listRepoOps` to the head of the oplog.
async fn list_all_repo_ops(
    ctx: &WebContext,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    credential: &str,
) -> AppResult<Vec<OpEntry>> {
    let space_str = space.to_string();
    let mut out = Vec::new();
    let mut since: Option<String> = None;
    loop {
        let mut params: Vec<(&str, &str)> = vec![("space", space_str.as_str()), ("repo", repo)];
        if let Some(s) = since.as_deref() {
            params.push(("since", s));
        }
        let url = xrpc_url(host, "com.atproto.space.listRepoOps", &params)?;
        let body = bearer_get(ctx, &url, credential).await?;
        if let Some(ops) = body.get("ops").and_then(Value::as_array) {
            for op in ops {
                let rev = op.get("rev").and_then(Value::as_str).unwrap_or_default();
                let collection = op
                    .get("collection")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let rkey = op.get("rkey").and_then(Value::as_str).unwrap_or_default();
                let cid = op.get("cid").and_then(Value::as_str).map(|s| s.to_string());
                out.push(OpEntry {
                    rev: rev.to_string(),
                    collection: collection.to_string(),
                    rkey: rkey.to_string(),
                    cid,
                });
            }
        }
        match body.get("cursor").and_then(Value::as_str) {
            Some(next) if !next.is_empty() => since = Some(next.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

/// `GET com.atproto.space.getRecord` (Bearer credential, explicit `repo`).
async fn get_record(
    ctx: &WebContext,
    host: &str,
    space: &SpaceUri,
    repo: &str,
    collection: &str,
    rkey: &str,
    credential: &str,
) -> AppResult<Option<Value>> {
    let space_str = space.to_string();
    let url = xrpc_url(
        host,
        "com.atproto.space.getRecord",
        &[
            ("space", space_str.as_str()),
            ("repo", repo),
            ("collection", collection),
            ("rkey", rkey),
        ],
    )?;
    let resp = ctx
        .http_client
        .get(&url)
        .header("Authorization", format!("Bearer {credential}"))
        .send()
        .await
        .map_err(|e| AppError::Space(format!("getRecord request: {e}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(AppError::Space(format!("getRecord {status}")));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| AppError::Space(format!("getRecord decode: {e}")))?;
    Ok(body.get("value").cloned())
}

/// Issue an authenticated GET with a space-credential bearer and decode JSON.
async fn bearer_get(ctx: &WebContext, url: &str, credential: &str) -> AppResult<Value> {
    let resp = ctx
        .http_client
        .get(url)
        .header("Authorization", format!("Bearer {credential}"))
        .send()
        .await
        .map_err(|e| AppError::Space(format!("request {url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(AppError::Space(format!("{url} returned {status}")));
    }
    resp.json()
        .await
        .map_err(|e| AppError::Space(format!("decode {url}: {e}")))
}

// ---------------------------------------------------------------------------
//  Commit decoding ($bytes -> Commit).
// ---------------------------------------------------------------------------

/// Decode a `getRepoState`/`listRepoOps` `#signedCommit` JSON object (whose
/// `hash`/`mac`/`ikm`/`sig` are atproto lex-bytes `{"$bytes":"<base64,unpadded>"}`)
/// into an [`atproto_space::Commit`].
fn decode_commit(value: &Value) -> AppResult<Commit> {
    let hash = decode_bytes_field(value, "hash")?;
    let mac = decode_bytes_field(value, "mac")?;
    let ikm = decode_bytes_field(value, "ikm")?;
    let sig = decode_bytes_field(value, "sig")?;
    let rev = value
        .get("rev")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Space("commit missing rev".into()))?
        .to_string();
    Ok(Commit {
        hash,
        mac,
        ikm,
        sig,
        rev,
    })
}

/// Pull a lex-bytes field (`{"$bytes":"<base64>"}`) and base64-decode it
/// (STANDARD_NO_PAD), delegating the raw decode to `verify::decode_commit_bytes`.
fn decode_bytes_field(value: &Value, field: &str) -> AppResult<Vec<u8>> {
    let node = value
        .get(field)
        .ok_or_else(|| AppError::Space(format!("commit missing {field}")))?;
    // Accept either {"$bytes":"..."} (canonical wire form) or a bare base64
    // string, for robustness against minor wire variations.
    let b64 = if let Some(s) = node.get("$bytes").and_then(Value::as_str) {
        s
    } else if let Some(s) = node.as_str() {
        s
    } else {
        return Err(AppError::Space(format!("commit {field} is not lex-bytes")));
    };
    // Reuse the shared base64 decoder; tolerate padded input defensively.
    verify::decode_commit_bytes(b64.trim_end_matches('=')).or_else(|_| {
        BASE64_NOPAD
            .decode(b64.trim_end_matches('='))
            .map_err(|e| AppError::Space(format!("commit {field} base64: {e}")))
    })
}

// ---------------------------------------------------------------------------
//  Projection (SQLite upserts).
// ---------------------------------------------------------------------------

/// Upsert a writer row (set/refresh its rev + host) before pulling.
async fn upsert_writer(
    ctx: &WebContext,
    space: &SpaceUri,
    writer_did: &str,
    rev: &str,
    pds_host: &str,
) -> AppResult<()> {
    let space_str = space.to_string();
    sqlx::query(
        "INSERT INTO writers (space, writer_did, rev, pds_host) VALUES (?, ?, ?, ?) \
         ON CONFLICT(space, writer_did) DO UPDATE SET rev = excluded.rev, pds_host = excluded.pds_host",
    )
    .bind(&space_str)
    .bind(writer_did)
    .bind(rev)
    .bind(pds_host)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Advance the writer cursor + verified marker after a clean verify.
async fn advance_writer(
    ctx: &WebContext,
    space: &SpaceUri,
    writer_did: &str,
    rev: &str,
    commit_hash: &[u8],
) -> AppResult<()> {
    let space_str = space.to_string();
    let now = Utc::now().to_rfc3339();
    let hash_b64 = BASE64_NOPAD.encode(commit_hash);
    sqlx::query(
        "UPDATE writers SET cursor = ?, rev = ?, last_commit_hash = ?, verified_at = ? \
         WHERE space = ? AND writer_did = ?",
    )
    .bind(rev)
    .bind(rev)
    .bind(&hash_b64)
    .bind(&now)
    .bind(&space_str)
    .bind(writer_did)
    .execute(&ctx.pool)
    .await?;
    Ok(())
}

/// Project a single record into `events`/`posts` based on collection.
async fn project_record(
    ctx: &WebContext,
    space: &SpaceUri,
    writer_did: &str,
    cid: &str,
    collection: &str,
    rkey: &str,
    value: &Value,
) -> AppResult<()> {
    let space_str = space.to_string();
    let raw = serde_json::to_string(value)
        .map_err(|e| AppError::Space(format!("serialize record: {e}")))?;

    if is_event_collection(collection) {
        let name = value.get("name").and_then(Value::as_str);
        let starts_at = value
            .get("startsAt")
            .or_else(|| value.get("starts_at"))
            .and_then(Value::as_str);
        let ends_at = value
            .get("endsAt")
            .or_else(|| value.get("ends_at"))
            .and_then(Value::as_str);
        sqlx::query(
            "INSERT INTO events (space, writer_did, rkey, cid, name, starts_at, ends_at, value) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(space, writer_did, rkey) DO UPDATE SET \
             cid = excluded.cid, name = excluded.name, starts_at = excluded.starts_at, \
             ends_at = excluded.ends_at, value = excluded.value",
        )
        .bind(&space_str)
        .bind(writer_did)
        .bind(rkey)
        .bind(cid)
        .bind(name)
        .bind(starts_at)
        .bind(ends_at)
        .bind(&raw)
        .execute(&ctx.pool)
        .await?;
    } else if is_post_collection(collection) {
        let text_body = value.get("text").and_then(Value::as_str);
        let created_at = value.get("createdAt").and_then(Value::as_str);
        sqlx::query(
            "INSERT INTO posts (space, writer_did, rkey, cid, text_body, created_at, value) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(space, writer_did, rkey) DO UPDATE SET \
             cid = excluded.cid, text_body = excluded.text_body, \
             created_at = excluded.created_at, value = excluded.value",
        )
        .bind(&space_str)
        .bind(writer_did)
        .bind(rkey)
        .bind(cid)
        .bind(text_body)
        .bind(created_at)
        .bind(&raw)
        .execute(&ctx.pool)
        .await?;
    } else {
        tracing::debug!(collection = %collection, "untracked collection; not projected");
    }
    Ok(())
}

/// Remove a projected row for a delete op.
async fn delete_projection(
    ctx: &WebContext,
    space: &SpaceUri,
    writer_did: &str,
    collection: &str,
    rkey: &str,
) -> AppResult<()> {
    let space_str = space.to_string();
    if is_event_collection(collection) {
        sqlx::query("DELETE FROM events WHERE space = ? AND writer_did = ? AND rkey = ?")
            .bind(&space_str)
            .bind(writer_did)
            .bind(rkey)
            .execute(&ctx.pool)
            .await?;
    } else if is_post_collection(collection) {
        sqlx::query("DELETE FROM posts WHERE space = ? AND writer_did = ? AND rkey = ?")
            .bind(&space_str)
            .bind(writer_did)
            .bind(rkey)
            .execute(&ctx.pool)
            .await?;
    }
    Ok(())
}

/// Whether a collection NSID is projected into `events`.
fn is_event_collection(collection: &str) -> bool {
    collection == "community.lexicon.calendar.event"
}

/// Whether a collection NSID is projected into `posts`.
fn is_post_collection(collection: &str) -> bool {
    collection == "app.bsky.feed.post"
}
