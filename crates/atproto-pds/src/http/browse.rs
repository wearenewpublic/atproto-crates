//! A repository browser for the account portal.
//!
//! The portal could manage the *account* — email, password, handle, app
//! passwords — but showed nothing of what the account actually holds. An
//! account holder with only a browser could not see their own records, let
//! alone correct one, and the data is theirs.
//!
//! # Two realms, one shape
//!
//! Public records and permissioned-space records are stored and authorised
//! differently, but they browse identically: collections, then records, then
//! one record. The URL says which realm, and the rendering is shared.
//!
//! # Reading `[collection]` and `[cid]` from the same position
//!
//! `/browse/public/{x}` is a collection listing when `x` is an NSID and a blob
//! when `x` is a CID. Nothing needs to be guessed to tell them apart: an NSID
//! is reverse-DNS and always contains a dot, and a base32 CIDv1 is a single
//! run of `[a-z2-7]` with no dot in it. [`looks_like_cid`] is that rule, and
//! it is the only place the ambiguity is resolved.
//!
//! # Deleting from a browser
//!
//! HTML forms submit `GET` and `POST` and nothing else, so a delete button
//! cannot issue `DELETE`. Both are wired: the `DELETE` method works for
//! anything driving these routes programmatically, and a `POST` carrying
//! `_method=delete` is what the button in the page sends. The alternative was
//! a delete that only worked from `curl`.

use crate::http::errors::XrpcError;
use crate::http::portal::{current_account, esc, notice, page, redirect, require_same_origin};
use crate::http::state::HttpState;
use atproto_space::types::SpaceUri;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// Records listed per page.
const PAGE_SIZE: u32 = 50;

/// Collections listed per page.
const COLLECTIONS_PER_PAGE: usize = 50;

/// Query for a listing — a records cursor, a collections page, and a message.
#[derive(Debug, Deserialize, Default)]
pub struct BrowseQuery {
    /// Opaque records cursor, carried straight through to the reader.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Zero-based page for the in-memory collection listings.
    #[serde(default)]
    pub page: Option<usize>,
    /// Status word set by whatever redirected here.
    #[serde(default)]
    pub msg: Option<String>,
}

/// Body of a record edit, create, or delete.
#[derive(Debug, Deserialize)]
pub struct RecordForm {
    /// The record as JSON.
    #[serde(default)]
    pub value: Option<String>,
    /// Collection, when creating.
    #[serde(default)]
    pub collection: Option<String>,
    /// Record key, when creating. Empty means "assign a TID".
    #[serde(default)]
    pub rkey: Option<String>,
    /// `delete` turns a form POST into a delete. See the module note.
    #[serde(default)]
    pub _method: Option<String>,
}

/// Whether a path segment is a CID rather than an NSID.
///
/// An NSID is reverse-DNS and always carries a dot; a base32 CIDv1 never
/// does. That is the whole distinction, and it is decidable without asking
/// storage.
#[must_use]
pub fn looks_like_cid(segment: &str) -> bool {
    !segment.contains('.') && segment.len() > 8
}

/// Render a banner from a `?msg=` word, matching the portal's convention.
fn banner(msg: Option<&str>) -> String {
    match msg {
        Some("saved") => notice("ok", "Record saved."),
        Some("created") => notice("ok", "Record created."),
        Some("deleted") => notice("ok", "Record deleted."),
        Some(e) if e.starts_with("err-") => notice("err", &e[4..].replace('-', " ")),
        _ => String::new(),
    }
}

/// Shared page chrome for the browser.
fn browse_page(title: &str, crumbs: &str, body: &str) -> Response {
    page(
        title,
        &format!(
            r#"<nav><a href="/account">&larr; Account</a> &middot; {crumbs}</nav>
<h1>{title}</h1>
{body}"#
        ),
    )
    .into_response()
}

/// `GET /browse/` — the two realms this account can browse.
pub async fn index(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };

    // Spaces this account is a member of *and* holds records in, read from its
    // own per-actor store. A space with no records of theirs is not something
    // they can browse, so listing it would be an empty promise.
    let spaces = spaces_with_records(&state, &account.did)
        .await
        .unwrap_or_default();
    let space_rows = if spaces.is_empty() {
        r#"<tr><td class="muted">No spaces with records.</td></tr>"#.to_string()
    } else {
        spaces
            .iter()
            .filter_map(|uri| SpaceUri::parse(uri).ok().map(|s| (uri, s)))
            .map(|(raw, s)| {
                format!(
                    r#"<tr><td><a href="/browse/space/{}/{}/{}">{}</a></td></tr>"#,
                    esc(&urlenc(&s.space_did)),
                    esc(&urlenc(s.space_type.as_str())),
                    esc(&urlenc(s.space_key.as_str())),
                    esc(raw)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let body = format!(
        r#"{banner}
<section>
<h2 style="margin-top:0">Public repository</h2>
<p class="muted">Records anyone can read, published to the network.</p>
<p><a href="/browse/public/">Browse public records</a></p>
</section>

<section>
<h2 style="margin-top:0">Spaces</h2>
<p class="muted">Permissioned records, readable only by the members of each space.</p>
<table>{space_rows}</table>
</section>"#,
        banner = banner(q.msg.as_deref()),
    );
    Ok(browse_page("Repository", "Repository", &body))
}

/// Distinct spaces this account holds records in.
async fn spaces_with_records(state: &HttpState, did: &str) -> Result<Vec<String>, XrpcError> {
    let store = crate::actor_store::sql::SqlActorStore::open(state.reader.data_dir(), did)
        .await
        .map_err(XrpcError::from)?;
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT space FROM space_record ORDER BY space ASC")
            .fetch_all(store.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("list spaces: {e}"),
                )
            })?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Render a paginated collection listing for either realm.
#[allow(clippy::too_many_arguments)]
fn collections_view(
    title: &str,
    crumbs: &str,
    self_url: &str,
    child_base: &str,
    collections: &[String],
    page_no: usize,
    msg: Option<&str>,
    create_form: &str,
) -> Response {
    let start = page_no.saturating_mul(COLLECTIONS_PER_PAGE);
    let slice: Vec<_> = collections
        .iter()
        .skip(start)
        .take(COLLECTIONS_PER_PAGE)
        .collect();

    let rows = if slice.is_empty() {
        r#"<tr><td class="muted">No collections.</td></tr>"#.to_string()
    } else {
        slice
            .iter()
            .map(|c| {
                format!(
                    r#"<tr><td><a href="{child_base}{}">{}</a></td></tr>"#,
                    esc(&urlenc(c)),
                    esc(c)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let mut nav = String::new();
    if page_no > 0 {
        nav.push_str(&format!(
            r#"<a href="{self_url}?page={}">&larr; Previous</a> "#,
            page_no - 1
        ));
    }
    if start + COLLECTIONS_PER_PAGE < collections.len() {
        nav.push_str(&format!(
            r#"<a href="{self_url}?page={}">Next &rarr;</a>"#,
            page_no + 1
        ));
    }

    browse_page(
        title,
        crumbs,
        &format!(
            r#"{}<section><table>{rows}</table><p>{nav}</p></section>{create_form}"#,
            banner(msg)
        ),
    )
}

/// Render a paginated record listing for either realm.
fn records_view(
    title: &str,
    crumbs: &str,
    self_url: &str,
    child_base: &str,
    records: &[(String, String)],
    cursor: Option<&str>,
    msg: Option<&str>,
) -> Response {
    let rows = if records.is_empty() {
        r#"<tr><td class="muted">No records.</td></tr>"#.to_string()
    } else {
        records
            .iter()
            .map(|(rkey, cid)| {
                format!(
                    r#"<tr><td><a href="{child_base}{}">{}</a></td><td class="muted"><code>{}</code></td></tr>"#,
                    esc(&urlenc(rkey)),
                    esc(rkey),
                    esc(cid)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let nav = match cursor {
        Some(c) => format!(
            r#"<a href="{self_url}?cursor={}">Next &rarr;</a>"#,
            esc(&urlenc(c))
        ),
        None => String::new(),
    };
    browse_page(
        title,
        crumbs,
        &format!(
            r#"{}<section><table>{rows}</table><p>{nav}</p></section>"#,
            banner(msg)
        ),
    )
}

/// Render one record, with its JSON in an editable form.
fn record_view(
    title: &str,
    crumbs: &str,
    action: &str,
    uri: &str,
    cid: &str,
    value: &serde_json::Value,
    msg: Option<&str>,
) -> Response {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    browse_page(
        title,
        crumbs,
        &format!(
            r#"{banner}
<section>
<p><code>{uri}</code></p>
<p class="muted">CID <code>{cid}</code></p>
<form method="POST" action="{action}">
  <label for="value">Record JSON</label>
  <textarea id="value" name="value" rows="20" spellcheck="false"
            style="width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
                   font-size:0.85em;padding:0.55em;border:1px solid #c8c8c8;
                   border-radius:5px;box-sizing:border-box">{json}</textarea>
  <p class="muted">Saving replaces the record. Its <code>$type</code> must match
  the collection, and the server validates it the same way it validates a write
  from any client.</p>
  <button type="submit">Save record</button>
</form>
<form method="POST" action="{action}" style="margin-top:0.8em">
  <input type="hidden" name="_method" value="delete">
  <button class="danger" type="submit">Delete record</button>
  <p class="muted">Deleting is published to the network and cannot be undone here.</p>
</form>
</section>"#,
            banner = banner(msg),
            uri = esc(uri),
            cid = esc(cid),
            json = esc(&pretty),
        ),
    )
}

/// Percent-encode a path segment.
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
//  Public realm
// ---------------------------------------------------------------------------

/// `GET /browse/public/` — collections holding public records.
pub async fn public_collections(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let described = state
        .reader
        .describe_repo(&account.did)
        .await
        .map_err(XrpcError::from)?;

    let create = r#"<section>
<h2 style="margin-top:0">Create a record</h2>
<form method="POST" action="/browse/public/">
  <label for="collection">Collection</label>
  <input id="collection" name="collection" type="text" spellcheck="false"
         placeholder="app.bsky.feed.post" required>
  <label for="rkey">Record key</label>
  <input id="rkey" name="rkey" type="text" spellcheck="false" placeholder="leave blank for a TID">
  <label for="value">Record JSON</label>
  <textarea id="value" name="value" rows="10" spellcheck="false"
            style="width:100%;font-family:ui-monospace,monospace;font-size:0.85em;
                   padding:0.55em;border:1px solid #c8c8c8;border-radius:5px;
                   box-sizing:border-box">{}</textarea>
  <button type="submit">Create record</button>
</form>
</section>"#;

    Ok(collections_view(
        "Public records",
        r#"<a href="/browse/">Repository</a> &middot; Public"#,
        "/browse/public/",
        "/browse/public/",
        &described.collections,
        q.page.unwrap_or(0),
        q.msg.as_deref(),
        create,
    ))
}

/// `GET /browse/public/{segment}` — records in a collection, or a blob.
pub async fn public_collection_or_blob(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(segment): Path<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };

    if looks_like_cid(&segment) {
        // The blob bytes already have an endpoint that streams them with the
        // right content type. Duplicating that here would be a second code
        // path for the same job, and a second place to get the type wrong.
        return Ok(redirect(&format!(
            "/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            urlenc(&account.did),
            urlenc(&segment)
        )));
    }

    let listed = state
        .reader
        .list_records(
            &account.did,
            &segment,
            PAGE_SIZE,
            q.cursor.as_deref(),
            false,
        )
        .await
        .map_err(XrpcError::from)?;

    let rows: Vec<(String, String)> = listed
        .records
        .iter()
        .map(|r| {
            (
                r.uri.rsplit('/').next().unwrap_or_default().to_string(),
                r.cid.clone(),
            )
        })
        .collect();

    Ok(records_view(
        &segment,
        &format!(
            r#"<a href="/browse/">Repository</a> &middot; <a href="/browse/public/">Public</a> &middot; {}"#,
            esc(&segment)
        ),
        &format!("/browse/public/{}", urlenc(&segment)),
        &format!("/browse/public/{}/", urlenc(&segment)),
        &rows,
        listed.cursor.as_deref(),
        q.msg.as_deref(),
    ))
}

/// `GET /browse/public/{collection}/{rkey}` — one record.
pub async fn public_record(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let record = state
        .reader
        .get_record(&account.did, &collection, &rkey, None)
        .await
        .map_err(XrpcError::from)?;

    Ok(record_view(
        &rkey,
        &format!(
            r#"<a href="/browse/">Repository</a> &middot; <a href="/browse/public/">Public</a> &middot; <a href="/browse/public/{}">{}</a>"#,
            urlenc(&collection),
            esc(&collection)
        ),
        &format!("/browse/public/{}/{}", urlenc(&collection), urlenc(&rkey)),
        &record.uri,
        &record.cid,
        &record.value,
        q.msg.as_deref(),
    ))
}

/// `POST /browse/public/` — create a record.
pub async fn public_create(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let Some(collection) = form
        .collection
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return Ok(redirect("/browse/public/?msg=err-name-a-collection"));
    };
    let value = match parse_value(form.value.as_deref()) {
        Ok(v) => v,
        Err(m) => return Ok(redirect(&format!("/browse/public/?msg={m}"))),
    };

    let op = crate::repo::WriteOp {
        action: crate::repo::WriteAction::Create,
        collection: collection.to_string(),
        rkey: form
            .rkey
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_string(),
        value: Some(value),
        swap_record: None,
    };
    match apply(&state, &account.did, op).await {
        Ok(()) => Ok(redirect(&format!(
            "/browse/public/{}?msg=created",
            urlenc(collection)
        ))),
        Err(m) => Ok(redirect(&format!("/browse/public/?msg={m}"))),
    }
}

/// `POST /browse/public/{collection}/{rkey}` — edit, or delete via `_method`.
pub async fn public_record_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };

    if form._method.as_deref() == Some("delete") {
        return Ok(delete_public(&state, &account.did, &collection, &rkey).await);
    }

    let value = match parse_value(form.value.as_deref()) {
        Ok(v) => v,
        Err(m) => {
            return Ok(redirect(&format!(
                "/browse/public/{}/{}?msg={m}",
                urlenc(&collection),
                urlenc(&rkey)
            )));
        }
    };
    let op = crate::repo::WriteOp {
        action: crate::repo::WriteAction::Update,
        collection: collection.clone(),
        rkey: rkey.clone(),
        value: Some(value),
        swap_record: None,
    };
    let msg = match apply(&state, &account.did, op).await {
        Ok(()) => "saved".to_string(),
        Err(m) => m,
    };
    Ok(redirect(&format!(
        "/browse/public/{}/{}?msg={msg}",
        urlenc(&collection),
        urlenc(&rkey)
    )))
}

/// `DELETE /browse/public/{collection}/{rkey}`.
pub async fn public_record_delete(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    Ok(delete_public(&state, &account.did, &collection, &rkey).await)
}

async fn delete_public(state: &HttpState, did: &str, collection: &str, rkey: &str) -> Response {
    let op = crate::repo::WriteOp {
        action: crate::repo::WriteAction::Delete,
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        value: None,
        swap_record: None,
    };
    match apply(state, did, op).await {
        Ok(()) => redirect(&format!(
            "/browse/public/{}?msg=deleted",
            urlenc(collection)
        )),
        Err(m) => redirect(&format!(
            "/browse/public/{}/{}?msg={m}",
            urlenc(collection),
            urlenc(rkey)
        )),
    }
}

/// Parse the JSON out of a textarea, or a `err-` word saying why not.
fn parse_value(raw: Option<&str>) -> Result<serde_json::Value, String> {
    let raw = raw.unwrap_or_default().trim();
    if raw.is_empty() {
        return Err("err-the-record-cannot-be-empty".to_string());
    }
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) if v.is_object() => Ok(v),
        // A record is always a map. Anything else parses but cannot be stored,
        // and saying so here is clearer than the validator's later complaint.
        Ok(_) => Err("err-a-record-must-be-a-json-object".to_string()),
        Err(_) => Err("err-that-is-not-valid-json".to_string()),
    }
}

/// Apply one write to the public repo, reporting failure as a `err-` word.
async fn apply(state: &HttpState, did: &str, op: crate::repo::WriteOp) -> Result<(), String> {
    let Some(writer) = state.writer.as_ref() else {
        return Err("err-this-server-is-read-only".to_string());
    };
    match writer.apply_writes(did, vec![op]).await {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!(did = %did, error = ?e, "portal repo write failed");
            Err("err-the-write-was-refused-check-the-server-logs".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
//  Spaces
// ---------------------------------------------------------------------------

/// Rebuild a `SpaceUri` from its three path segments.
fn space_from_path(host: &str, ty: &str, key: &str) -> Result<SpaceUri, XrpcError> {
    SpaceUri::parse(&format!("at://{host}/space/{ty}/{key}")).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "that is not a valid space",
        )
    })
}

/// Base URL for a space's browse routes.
fn space_base(host: &str, ty: &str, key: &str) -> String {
    format!(
        "/browse/space/{}/{}/{}/",
        urlenc(host),
        urlenc(ty),
        urlenc(key)
    )
}

/// `GET /browse/space/{host}/{type}/{key}` — collections in the space.
pub async fn space_collections(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key)): Path<(String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;
    let reader = space_reader(&state)?;
    let collections = reader
        .list_collections(&space, &account.did)
        .await
        .map_err(XrpcError::from)?;

    let base = space_base(&host, &ty, &key);
    Ok(collections_view(
        &format!("{ty}/{key}"),
        &format!(
            r#"<a href="/browse/">Repository</a> &middot; {}"#,
            esc(&space.to_string())
        ),
        base.trim_end_matches('/'),
        &base,
        &collections,
        q.page.unwrap_or(0),
        q.msg.as_deref(),
        "",
    ))
}

/// `GET /browse/space/{host}/{type}/{key}/{segment}` — records, or a blob.
pub async fn space_collection_or_blob(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, segment)): Path<(String, String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;

    if looks_like_cid(&segment) {
        return Ok(redirect(&format!(
            "/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            urlenc(&account.did),
            urlenc(&segment)
        )));
    }

    let reader = space_reader(&state)?;
    let page_of = reader
        .list_records(
            &space,
            crate::space::reader::SpaceReadAuth::OwnPds {
                account_did: account.did.clone(),
            },
            &account.did,
            crate::space::reader::RecordListing {
                collection: Some(&segment),
                cursor: q.cursor.as_deref(),
                limit: PAGE_SIZE,
                reverse: false,
            },
        )
        .await
        .map_err(XrpcError::from)?;

    let rows: Vec<(String, String)> = page_of
        .records
        .iter()
        .map(|r| (r.rkey.clone(), r.cid.clone()))
        .collect();

    let base = space_base(&host, &ty, &key);
    Ok(records_view(
        &segment,
        &format!(
            r#"<a href="/browse/">Repository</a> &middot; <a href="{}">{}</a> &middot; {}"#,
            base.trim_end_matches('/'),
            esc(&space.to_string()),
            esc(&segment)
        ),
        &format!("{base}{}", urlenc(&segment)),
        &format!("{base}{}/", urlenc(&segment)),
        &rows,
        page_of.cursor.as_deref(),
        q.msg.as_deref(),
    ))
}

/// `GET /browse/space/{host}/{type}/{key}/{collection}/{rkey}`.
pub async fn space_record(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;
    let reader = space_reader(&state)?;
    let found = reader
        .get_record(
            &space,
            crate::space::reader::SpaceReadAuth::OwnPds {
                account_did: account.did.clone(),
            },
            &account.did,
            &collection,
            &rkey,
        )
        .await
        .map_err(XrpcError::from)?;
    let Some(record) = found else {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "RecordNotFound",
            "no such record in this space",
        ));
    };

    let base = space_base(&host, &ty, &key);
    Ok(record_view(
        &rkey,
        &format!(
            r#"<a href="/browse/">Repository</a> &middot; <a href="{}">{}</a> &middot; <a href="{base}{}">{}</a>"#,
            base.trim_end_matches('/'),
            esc(&space.to_string()),
            urlenc(&collection),
            esc(&collection)
        ),
        &format!("{base}{}/{}", urlenc(&collection), urlenc(&rkey)),
        &format!("{space}/{collection}/{rkey}"),
        &record.cid,
        &decode_record(&record.value)?,
        q.msg.as_deref(),
    ))
}

/// `POST /browse/space/.../{collection}/{rkey}` — edit, or delete.
pub async fn space_record_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;
    let base = space_base(&host, &ty, &key);

    if form._method.as_deref() == Some("delete") {
        return Ok(delete_space(&state, &account.did, &space, &collection, &rkey, &base).await);
    }

    let value = match parse_value(form.value.as_deref()) {
        Ok(v) => v,
        Err(m) => {
            return Ok(redirect(&format!(
                "{base}{}/{}?msg={m}",
                urlenc(&collection),
                urlenc(&rkey)
            )));
        }
    };
    let writer = space_writer(&state)?;
    let msg = match writer
        .put_record(
            &account.did,
            &space,
            collection.clone(),
            rkey.clone(),
            value,
        )
        .await
    {
        Ok(_) => "saved".to_string(),
        Err(e) => {
            tracing::warn!(did = %account.did, error = ?e, "portal space write failed");
            "err-the-write-was-refused-check-the-server-logs".to_string()
        }
    };
    Ok(redirect(&format!(
        "{base}{}/{}?msg={msg}",
        urlenc(&collection),
        urlenc(&rkey)
    )))
}

/// `DELETE /browse/space/.../{collection}/{rkey}`.
pub async fn space_record_delete(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;
    let base = space_base(&host, &ty, &key);
    Ok(delete_space(&state, &account.did, &space, &collection, &rkey, &base).await)
}

async fn delete_space(
    state: &HttpState,
    did: &str,
    space: &SpaceUri,
    collection: &str,
    rkey: &str,
    base: &str,
) -> Response {
    let Ok(writer) = space_writer(state) else {
        return redirect(&format!("{base}?msg=err-spaces-are-not-configured"));
    };
    match writer
        .delete_record(did, space, collection.to_string(), rkey.to_string())
        .await
    {
        Ok(_) => redirect(&format!("{base}{}?msg=deleted", urlenc(collection))),
        Err(e) => {
            tracing::warn!(did = %did, error = ?e, "portal space delete failed");
            redirect(&format!(
                "{base}{}/{}?msg=err-the-delete-was-refused-check-the-server-logs",
                urlenc(collection),
                urlenc(rkey)
            ))
        }
    }
}

/// Decode a stored record body into JSON for display.
///
/// Space records are held as DAG-CBOR, which is what goes over the wire and
/// into the MST. The browser shows and accepts JSON, so this is the boundary.
fn decode_record(bytes: &[u8]) -> Result<serde_json::Value, XrpcError> {
    atproto_dasl::from_slice(bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("decode record: {e}"),
        )
    })
}

/// Refuse a space this account is not a member of.
///
/// The XRPC path authorises space writes with OAuth scopes, which a portal
/// session does not carry: it is a full-authority browser session, so
/// `assert_space_scope` has nothing to assert against and the writer itself
/// checks only that the space is not deleted -- and `ensure_space_live`
/// returns `Ok` when the authority's store is not even local.
///
/// Nothing above this therefore stopped a crafted URL from writing records
/// into the caller's own store scoped to a space they do not belong to, or to
/// one that does not exist. The records would be real, would be theirs, and
/// would sync nowhere. Membership is the check that belongs here.
async fn require_member(state: &HttpState, space: &SpaceUri, did: &str) -> Result<(), XrpcError> {
    let service = state.space_service.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            "spaces are not configured on this server",
        )
    })?;
    if service
        .is_member(space, did)
        .await
        .map_err(XrpcError::from)?
    {
        return Ok(());
    }
    tracing::warn!(
        did = %did,
        space = %space,
        "refused a portal space request from a non-member"
    );
    Err(XrpcError::new(
        StatusCode::FORBIDDEN,
        "Forbidden",
        "you are not a member of that space",
    ))
}

fn space_reader(state: &HttpState) -> Result<&crate::space::reader::SpaceReader, XrpcError> {
    state.space_reader.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            "spaces are not configured on this server",
        )
    })
}

fn space_writer(state: &HttpState) -> Result<&crate::space::writer::SpaceWriter, XrpcError> {
    state.space_writer.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            "spaces are not configured on this server",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one ambiguity in the URL scheme, decided without asking storage.
    #[test]
    fn an_nsid_is_not_mistaken_for_a_cid() {
        assert!(!looks_like_cid("app.bsky.feed.post"));
        assert!(!looks_like_cid("com.atproto-crates.pds.policyAcceptance"));
    }

    #[test]
    fn a_cid_is_not_mistaken_for_an_nsid() {
        assert!(looks_like_cid(
            "bafyreiddvxxawd6apfgk757vltzxmnra5t5a4bmj5s3d6353vzjefw3ijq"
        ));
        assert!(looks_like_cid(
            "bafkreigcsk44torjvfr6rvmixv23vsmp2ey4c6z2yftuqecmqgvsyk4uye"
        ));
    }

    /// A record is a map. Anything else parses as JSON and cannot be stored.
    #[test]
    fn only_a_json_object_is_a_record() {
        assert!(parse_value(Some(r#"{"$type":"a.b.c"}"#)).is_ok());
        assert_eq!(
            parse_value(Some("[1,2]")).unwrap_err(),
            "err-a-record-must-be-a-json-object"
        );
        assert_eq!(
            parse_value(Some("not json")).unwrap_err(),
            "err-that-is-not-valid-json"
        );
        assert_eq!(
            parse_value(Some("   ")).unwrap_err(),
            "err-the-record-cannot-be-empty"
        );
    }

    /// Path segments carry NSIDs, DIDs and rkeys, which contain characters
    /// that would otherwise change what the URL means.
    #[test]
    fn path_segments_are_encoded() {
        assert_eq!(urlenc("did:plc:abc"), "did%3Aplc%3Aabc");
        assert_eq!(urlenc("app.bsky.feed.post"), "app.bsky.feed.post");
        assert_eq!(urlenc("a/b"), "a%2Fb");
    }
}
