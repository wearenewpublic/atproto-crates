//! The Repository section of the account portal: a repository browser.
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
//! `/account/repository/public/{x}` is a collection listing when `x` is an NSID
//! and a blob when `x` is a CID. Nothing needs to be guessed to tell them
//! apart: an NSID is reverse-DNS and always contains a dot, and a base32 CIDv1
//! is a single run of `[a-z2-7]` with no dot in it. [`looks_like_cid`] is that
//! rule, and it is the only place the ambiguity is resolved.
//!
//! # Deleting from a browser
//!
//! HTML forms submit `GET` and `POST` and nothing else, so a delete button
//! cannot issue `DELETE`. Both are wired: the `DELETE` method works for
//! anything driving these routes programmatically, and a `POST` carrying
//! `_method=delete` is what the button in the page sends. The alternative was
//! a delete that only worked from `curl`.
//!
//! # One place the paths are written
//!
//! Every URL this module emits hangs off [`ROOT`]. The browser previously lived
//! at `/browse/`, spelled out in a dozen `format!` strings and three breadcrumb
//! trails; moving it meant editing all of them, and the link-crawl test is what
//! caught the ones that were missed. It is a constant now, so the next move is
//! one line.

use crate::http::errors::XrpcError;
use crate::http::portal::{
    Section, esc, nav, notice, page, redirect, require_same_origin, section_account,
};
use crate::http::state::HttpState;
use atproto_space::types::SpaceUri;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// Where the browser is mounted. Every URL it generates starts here.
pub const ROOT: &str = "/account/repository";

/// Records listed per page.
const PAGE_SIZE: u32 = 50;

/// How many authority domains one page of a collection listing shows.
///
/// Counted in groups rather than collections because the listing is paged by
/// group; a publisher with thirty collections is one entry here.
const GROUPS_PER_PAGE: usize = 25;

/// Blob CIDs listed per page on the index.
const BLOBS_PER_PAGE: u32 = 50;

/// Query for a listing — a records cursor, a collections page, and a message.
#[derive(Debug, Deserialize, Default)]
pub struct BrowseQuery {
    /// Opaque records cursor, carried straight through to the reader.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Zero-based page for the in-memory collection listings.
    #[serde(default)]
    pub page: Option<usize>,
    /// Blob-listing cursor on the index — the last CID of the previous page.
    ///
    /// Separate from `cursor` because the index paginates blobs while the
    /// listings below it paginate records, and a single parameter would make
    /// "next page of blobs" and "next page of records" the same link.
    #[serde(default)]
    pub blobs: Option<String>,
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
///
/// The portal nav rather than a bare "back to account" link: this is one of
/// four sections, and a page that offers only the way it came makes the other
/// three reachable only by typing their URLs.
fn browse_page(
    account: &crate::account::AccountRow,
    title: &str,
    crumbs: &str,
    body: &str,
) -> Response {
    page(
        title,
        &format!(
            r#"{}
<h1>{title}</h1>
{body}"#,
            nav(Section::Repository, account, crumbs)
        ),
    )
    .into_response()
}

/// `GET /account/repository` — the realms this account holds, and its blobs.
pub async fn index(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };

    // Every space this account holds, not only the ones it has written to. An
    // empty space is a real thing -- newly created, or emptied -- and omitting
    // it made a space the holder had just made themselves look like it had
    // never existed. "What do I have" is the question this list answers, and a
    // filter on record count answers a different one.
    let spaces = all_spaces(&state, &account.did).await.unwrap_or_default();
    let space_rows = if spaces.is_empty() {
        r#"<tr><td class="muted">No spaces.</td></tr>"#.to_string()
    } else {
        spaces
            .iter()
            .filter_map(|uri| SpaceUri::parse(uri).ok().map(|s| (uri, s)))
            .map(|(raw, s)| {
                format!(
                    r#"<tr><td><a href="{ROOT}/space/{}/{}/{}">{}</a></td></tr>"#,
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
<p><a href="{ROOT}/public/">Browse public records</a></p>
</section>

<section>
<h2 style="margin-top:0">Spaces</h2>
<p class="muted">Permissioned records, readable only by the members of each space.</p>
<table>{space_rows}</table>
</section>

{blobs}"#,
        banner = banner(q.msg.as_deref()),
        blobs = blob_section(&state, &account.did, q.blobs.as_deref()).await?,
    );
    Ok(browse_page(&account, "Repository", "", &body))
}

/// The index's blob listing.
///
/// Public blobs only, through the same enumeration
/// `com.atproto.sync.listBlobs` serves -- [`crate::blob::list_public`] -- so
/// what the holder sees here is what the network can fetch, and the two cannot
/// drift. A blob referenced only from a permissioned record is deliberately
/// absent: it is not public, and listing it here under a heading that says
/// "anyone holding the CID can fetch these" would be false.
///
/// Each row links to `getBlob` rather than to a page of its own. That endpoint
/// already streams the bytes under the stored MIME type with the headers that
/// keep a blob from rendering as a document on this origin; a second path to
/// the same bytes would be a second place to get those headers wrong.
async fn blob_section(
    state: &HttpState,
    did: &str,
    cursor: Option<&str>,
) -> Result<String, XrpcError> {
    // Said rather than omitted. A section that vanishes reads as "this account
    // has no blobs", which is a different claim from "this server cannot answer
    // the question".
    let Some(manager) = state.account_manager.as_deref() else {
        return Ok(r#"<section>
<h2 style="margin-top:0">Blobs</h2>
<p class="muted">This server has no account manager configured, so blob storage
cannot be read from here.</p>
</section>"#
            .to_string());
    };
    let store = crate::actor_store::sql::SqlActorStore::open(manager.data_dir(), did)
        .await
        .map_err(XrpcError::from)?;
    let listed = crate::blob::list_public(
        &store,
        state.public_realm_backend.as_ref().map(|b| b.blob.as_ref()),
        did,
        cursor,
        BLOBS_PER_PAGE,
    )
    .await
    .map_err(XrpcError::from)?;

    let rows = if listed.cids.is_empty() {
        r#"<tr><td class="muted">No public blobs.</td></tr>"#.to_string()
    } else {
        listed
            .cids
            .iter()
            .map(|cid| {
                format!(
                    r#"<tr><td><a href="/xrpc/com.atproto.sync.getBlob?did={}&amp;cid={}"><code>{}</code></a></td></tr>"#,
                    esc(&urlenc(did)),
                    esc(&urlenc(cid)),
                    esc(cid)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    // On `scanned`, not on `cids`. The cursor advances over CIDs *scanned*
    // rather than CIDs *kept*, so a full page whose blobs were all permissioned
    // comes back with no rows and more behind it -- and a short scan is the end
    // of the list even when every CID in it was kept. Keying the link on the
    // rows shown would hide the rest in the first case and offer an empty page
    // forever in the second.
    let next = match listed.cursor.as_deref() {
        Some(c) if listed.scanned == BLOBS_PER_PAGE as usize => format!(
            r#"<p><a href="{ROOT}?blobs={}">Next &rarr;</a></p>"#,
            esc(&urlenc(c))
        ),
        _ => String::new(),
    };

    Ok(format!(
        r#"<section>
<h2 style="margin-top:0">Blobs</h2>
<p class="muted">Images and other binaries referenced by a public record. Anyone
holding the CID can fetch these; a blob referenced only from a space is not
listed and is not public.</p>
<table>{rows}</table>
{next}
</section>"#
    ))
}

/// Every space this account owns or belongs to.
///
/// Reads the `space` table through the same service `listSpaces` uses, rather
/// than the distinct values in `space_record`: a space exists once it is
/// created, and not having written to it yet is not the same as not having it.
/// Tombstoned spaces stay excluded -- that is the one exclusion which belongs
/// here, and the service already makes it.
///
/// Paginates to exhaustion. The portal renders one list, and a holder with more
/// spaces than a page should see all of them rather than the first hundred.
async fn all_spaces(state: &HttpState, did: &str) -> Result<Vec<String>, XrpcError> {
    let Some(service) = state.space_service.as_deref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = service
            .list_spaces(did, None, None, cursor.as_deref(), 100)
            .await
            .map_err(XrpcError::from)?;
        out.extend(page.spaces.into_iter().map(|s| s.uri));
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The registrable domain an NSID's authority lives under.
///
/// `app.bsky.feed.post` → `bsky.app`. The first two segments reversed, not the
/// whole authority: `app.bsky.feed.post` and `app.bsky.graph.follow` are
/// published by one party and belong together in a list, which is what a person
/// reading their own repository is looking for. An NSID with fewer than the two
/// segments a domain needs is its own group, since there is nothing to derive.
pub(crate) fn nsid_domain(nsid: &str) -> String {
    let mut parts = nsid.split('.');
    match (parts.next(), parts.next()) {
        (Some(tld), Some(name)) if !tld.is_empty() && !name.is_empty() => {
            format!("{name}.{tld}")
        }
        _ => nsid.to_string(),
    }
}

/// Group collections by their authority domain, keeping both the groups and
/// the collections inside them in the order they arrived (already sorted).
fn group_by_domain(collections: &[String]) -> Vec<(String, Vec<&String>)> {
    let mut groups: Vec<(String, Vec<&String>)> = Vec::new();
    for collection in collections {
        let domain = nsid_domain(collection);
        match groups.last_mut() {
            Some((current, members)) if *current == domain => members.push(collection),
            _ => groups.push((domain, vec![collection])),
        }
    }
    groups
}

/// The group's icon: this server's cached copy of the authority's favicon.
///
/// Same-origin by construction — see [`crate::http::icons`] for why the bytes
/// are proxied rather than hot-linked, and what is served when an authority has
/// no favicon to fetch. The `alt` is empty because the domain is written out on
/// the row beside it, and announcing it twice is noise to a screen reader.
fn domain_badge(nsid: &str, domain: &str) -> String {
    format!(
        r#"<span class="badge"><img src="{ROOT}/icon/{}" alt="" loading="lazy" width="16" height="16" title="{}"></span>"#,
        esc(&urlenc(nsid)),
        esc(domain)
    )
}

/// Render a paginated collection listing for either realm.
#[allow(clippy::too_many_arguments)]
fn collections_view(
    account: &crate::account::AccountRow,
    title: &str,
    crumbs: &str,
    self_url: &str,
    child_base: &str,
    collections: &[String],
    page_no: usize,
    msg: Option<&str>,
    create_form: &str,
) -> Response {
    // Paged by group rather than by collection: a page boundary that lands in
    // the middle of one publisher's collections splits the thing the grouping
    // exists to show.
    let groups = group_by_domain(collections);
    let start = page_no.saturating_mul(GROUPS_PER_PAGE);
    let slice: Vec<_> = groups.iter().skip(start).take(GROUPS_PER_PAGE).collect();

    let rows = if slice.is_empty() {
        r#"<tr><td class="muted">No collections.</td></tr>"#.to_string()
    } else {
        slice
            .iter()
            .flat_map(|(domain, members)| {
                members.iter().enumerate().map(move |(i, c)| {
                    // The badge marks where a group starts; the rows under it
                    // are indented instead of repeating it.
                    let mark = if i == 0 {
                        domain_badge(c, domain)
                    } else {
                        r#"<span class="badge-gap"></span>"#.to_string()
                    };
                    let row_class = if i == 0 { r#" class="group""# } else { "" };
                    // The authority is the same for every row in the group, so
                    // it is dimmed and the part that differs is left to read.
                    let prefix_len = c.len() - c.rsplit('.').next().unwrap_or(c).len();
                    let (prefix, tail) = c.split_at(prefix_len);
                    format!(
                        r#"<tr{row_class}><td>{mark}<a href="{child_base}{}"><span class="dim">{}</span>{}</a></td></tr>"#,
                        esc(&urlenc(c)),
                        esc(prefix),
                        esc(tail)
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let mut pager = String::new();
    if page_no > 0 {
        pager.push_str(&format!(
            r#"<a href="{self_url}?page={}">&larr; Previous</a> "#,
            page_no - 1
        ));
    }
    if start + GROUPS_PER_PAGE < groups.len() {
        pager.push_str(&format!(
            r#"<a href="{self_url}?page={}">Next &rarr;</a>"#,
            page_no + 1
        ));
    }

    browse_page(
        account,
        title,
        crumbs,
        &format!(
            r#"{}<section><table class="groups">{rows}</table><p>{pager}</p></section>{create_form}"#,
            banner(msg)
        ),
    )
}

/// Render a paginated record listing for either realm.
#[allow(clippy::too_many_arguments)]
fn records_view(
    account: &crate::account::AccountRow,
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
    let pager = match cursor {
        Some(c) => format!(
            r#"<a href="{self_url}?cursor={}">Next &rarr;</a>"#,
            esc(&urlenc(c))
        ),
        None => String::new(),
    };
    browse_page(
        account,
        title,
        crumbs,
        &format!(
            r#"{}<section><table>{rows}</table><p>{pager}</p></section>"#,
            banner(msg)
        ),
    )
}

/// Every CID a record links to, in document order and without repeats.
///
/// A blob reference is `{"$type":"blob","ref":{"$link":"bafkrei…"}}`, but
/// `$link` is the general cid-link form and appears outside blobs too, so the
/// walk keys on `$link` rather than on the blob shape -- a record referencing a
/// CID some other way is still referencing it.
///
/// Nested because records nest: a blob three levels inside an array is as much
/// a reference as one at the top.
fn linked_cids(value: &serde_json::Value) -> Vec<String> {
    fn walk(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, v) in map {
                    if key == "$link"
                        && let Some(cid) = v.as_str()
                        && !out.iter().any(|c| c == cid)
                    {
                        out.push(cid.to_string());
                    }
                    walk(v, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// Render one record, with its JSON in an editable form.
#[allow(clippy::too_many_arguments)]
fn record_view(
    account: &crate::account::AccountRow,
    title: &str,
    crumbs: &str,
    action: &str,
    blob_base: &str,
    uri: &str,
    cid: &str,
    value: &serde_json::Value,
    msg: Option<&str>,
) -> Response {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());

    // The CIDs this record points at, as links. Reading one out of the JSON and
    // pasting it into a URL is work the page can do.
    let cids = linked_cids(value);
    let linked = if cids.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="muted" style="margin-top:0.8em">Linked content</p><table>{}</table>"#,
            cids.iter()
                .map(|cid| format!(
                    r#"<tr><td><a href="{}{}"><code>{}</code></a></td></tr>"#,
                    blob_base,
                    esc(&urlenc(cid)),
                    esc(cid)
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    browse_page(
        account,
        title,
        crumbs,
        &format!(
            r#"{banner}
<section>
<p><code>{uri}</code></p>
<p class="muted">CID <code>{cid}</code></p>
{linked}
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
            linked = linked,
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

/// `GET /account/repository/public/` — collections holding public records.
pub async fn public_collections(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let described = state
        .reader
        .describe_repo(&account.did)
        .await
        .map_err(XrpcError::from)?;

    // `{{}}` is a literal pair of braces: the empty JSON object the textarea
    // starts from, not a placeholder.
    let create = format!(
        r#"<section>
<h2 style="margin-top:0">Create a record</h2>
<form method="POST" action="{ROOT}/public/">
  <label for="collection">Collection</label>
  <input id="collection" name="collection" type="text" spellcheck="false"
         placeholder="app.bsky.feed.post" required>
  <label for="rkey">Record key</label>
  <input id="rkey" name="rkey" type="text" spellcheck="false" placeholder="leave blank for a TID">
  <label for="value">Record JSON</label>
  <textarea id="value" name="value" rows="10" spellcheck="false"
            style="width:100%;font-family:ui-monospace,monospace;font-size:0.85em;
                   padding:0.55em;border:1px solid #c8c8c8;border-radius:5px;
                   box-sizing:border-box">{{}}</textarea>
  <button type="submit">Create record</button>
</form>
</section>"#
    );

    Ok(collections_view(
        &account,
        "Public records",
        &format!(r#"<a href="{ROOT}">Repository</a> &middot; Public"#),
        &format!("{ROOT}/public/"),
        &format!("{ROOT}/public/"),
        &described.collections,
        q.page.unwrap_or(0),
        q.msg.as_deref(),
        &create,
    ))
}

/// `GET /account/repository/public/{segment}` — records in a collection, or a blob.
pub async fn public_collection_or_blob(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(segment): Path<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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
        &account,
        &segment,
        &format!(
            r#"<a href="{ROOT}">Repository</a> &middot; <a href="{ROOT}/public/">Public</a> &middot; {}"#,
            esc(&segment)
        ),
        &format!("{ROOT}/public/{}", urlenc(&segment)),
        &format!("{ROOT}/public/{}/", urlenc(&segment)),
        &rows,
        listed.cursor.as_deref(),
        q.msg.as_deref(),
    ))
}

/// `GET /account/repository/public/{collection}/{rkey}` — one record.
pub async fn public_record(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let record = state
        .reader
        .get_record(&account.did, &collection, &rkey, None)
        .await
        .map_err(XrpcError::from)?;

    Ok(record_view(
        &account,
        &rkey,
        &format!(
            r#"<a href="{ROOT}">Repository</a> &middot; <a href="{ROOT}/public/">Public</a> &middot; <a href="{ROOT}/public/{}">{}</a>"#,
            urlenc(&collection),
            esc(&collection)
        ),
        &format!("{ROOT}/public/{}/{}", urlenc(&collection), urlenc(&rkey)),
        &format!("{ROOT}/public/"),
        &record.uri,
        &record.cid,
        &record.value,
        q.msg.as_deref(),
    ))
}

/// `POST /account/repository/public/` — create a record.
pub async fn public_create(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let Some(collection) = form
        .collection
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return Ok(redirect(&format!(
            "{ROOT}/public/?msg=err-name-a-collection"
        )));
    };
    let value = match parse_value(form.value.as_deref()) {
        Ok(v) => v,
        Err(m) => return Ok(redirect(&format!("{ROOT}/public/?msg={m}"))),
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
            "{ROOT}/public/{}?msg=created",
            urlenc(collection)
        ))),
        Err(m) => Ok(redirect(&format!("{ROOT}/public/?msg={m}"))),
    }
}

/// `POST /account/repository/public/{collection}/{rkey}` — edit, or delete via `_method`.
pub async fn public_record_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };

    if form._method.as_deref() == Some("delete") {
        return Ok(delete_public(&state, &account.did, &collection, &rkey).await);
    }

    let value = match parse_value(form.value.as_deref()) {
        Ok(v) => v,
        Err(m) => {
            return Ok(redirect(&format!(
                "{ROOT}/public/{}/{}?msg={m}",
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
        "{ROOT}/public/{}/{}?msg={msg}",
        urlenc(&collection),
        urlenc(&rkey)
    )))
}

/// `DELETE /account/repository/public/{collection}/{rkey}`.
pub async fn public_record_delete(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((collection, rkey)): Path<(String, String)>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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
        Ok(()) => redirect(&format!("{ROOT}/public/{}?msg=deleted", urlenc(collection))),
        Err(m) => redirect(&format!(
            "{ROOT}/public/{}/{}?msg={m}",
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
        "{ROOT}/space/{}/{}/{}/",
        urlenc(host),
        urlenc(ty),
        urlenc(key)
    )
}

/// `GET /account/repository/space/{host}/{type}/{key}` — collections in the space.
pub async fn space_collections(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key)): Path<(String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let space = space_from_path(&host, &ty, &key)?;
    require_member(&state, &space, &account.did).await?;
    let reader = space_reader(&state)?;
    let collections = reader
        .list_collections(
            &space,
            &crate::space::reader::SpaceReadAuth::OwnPds {
                account_did: account.did.clone(),
            },
            &account.did,
        )
        .await
        .map_err(XrpcError::from)?;

    let base = space_base(&host, &ty, &key);
    Ok(collections_view(
        &account,
        &format!("{ty}/{key}"),
        &format!(
            r#"<a href="{ROOT}">Repository</a> &middot; {}"#,
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

/// `GET /account/repository/space/{host}/{type}/{key}/{segment}` — records, or a blob.
pub async fn space_collection_or_blob(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, segment)): Path<(String, String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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
        &account,
        &segment,
        &format!(
            r#"<a href="{ROOT}">Repository</a> &middot; <a href="{}">{}</a> &middot; {}"#,
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

/// `GET /account/repository/space/{host}/{type}/{key}/{collection}/{rkey}`.
pub async fn space_record(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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
        &account,
        &rkey,
        &format!(
            r#"<a href="{ROOT}">Repository</a> &middot; <a href="{}">{}</a> &middot; <a href="{base}{}">{}</a>"#,
            base.trim_end_matches('/'),
            esc(&space.to_string()),
            urlenc(&collection),
            esc(&collection)
        ),
        &format!("{base}{}/{}", urlenc(&collection), urlenc(&rkey)),
        &base,
        &format!("{space}/{collection}/{rkey}"),
        &record.cid,
        &decode_record(&record.value)?,
        q.msg.as_deref(),
    ))
}

/// `POST /account/repository/space/.../{collection}/{rkey}` — edit, or delete.
pub async fn space_record_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
    Form(form): Form<RecordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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

/// `DELETE /account/repository/space/.../{collection}/{rkey}`.
pub async fn space_record_delete(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((host, ty, key, collection, rkey)): Path<(String, String, String, String, String)>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
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
///
/// Positive local evidence, deliberately: only [`crate::space::Membership::Member`]
/// passes here, so a space whose authority this server does not host is refused
/// along with one the caller simply is not in.
///
/// That is stricter than the XRPC guard, which defers to a remote authority
/// rather than lock out cross-PDS members. The difference is what the caller
/// brought. An XRPC client presents a credential the authority signed, or is
/// syncing a space it can name for a reason; a browser session presents a
/// guessable URL and nothing else, and the space DID in that URL is a path
/// segment the user typed. With no list to check it against there is nothing
/// between "a space I am in on another host" and "a DID I made up", so the
/// portal declines to guess — a cross-PDS member reaches the space over XRPC
/// instead of through this UI.
async fn require_member(state: &HttpState, space: &SpaceUri, did: &str) -> Result<(), XrpcError> {
    let service = state.space_service.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            "spaces are not configured on this server",
        )
    })?;
    if service
        .membership(space, did)
        .await
        .map_err(XrpcError::from)?
        == crate::space::Membership::Member
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

    /// The grouping key, on the shapes a repository actually holds.
    #[test]
    fn a_domain_is_the_first_two_segments_reversed() {
        for (nsid, want) in [
            ("app.bsky.feed.post", "bsky.app"),
            ("app.bsky.graph.follow", "bsky.app"),
            ("blue.badge.collection", "badge.blue"),
            ("actor.rpg.stats", "rpg.actor"),
            ("at.youandme.connection", "youandme.at"),
            ("app.beaconbits.bookmark.folder", "beaconbits.app"),
        ] {
            assert_eq!(nsid_domain(nsid), want, "{nsid}");
        }
        // Nothing to derive a domain from is its own group rather than a panic
        // or a silent lump with everything else short.
        assert_eq!(nsid_domain("weird"), "weird");
    }

    /// Groups follow the sorted order they arrive in, and a publisher's
    /// collections stay together.
    #[test]
    fn collections_group_by_publisher() {
        let collections: Vec<String> = [
            "app.bsky.feed.post",
            "app.bsky.graph.follow",
            "blue.badge.collection",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let groups = group_by_domain(&collections);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, "bsky.app");
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].0, "badge.blue");
        assert_eq!(groups[1].1.len(), 1);
    }

    /// The mark points at this server's own icon route, never at the authority
    /// it depicts — the whole reason the bytes are proxied.
    #[test]
    fn a_group_mark_is_served_from_this_origin() {
        let mark = domain_badge("app.bsky.feed.post", "bsky.app");
        assert!(
            mark.contains(r#"src="/account/repository/icon/app.bsky.feed.post""#),
            "{mark}"
        );
        assert!(
            !mark.contains("https://"),
            "the page must not reach out to the authority: {mark}"
        );
    }

    /// A blob reference, as records actually carry one.
    #[test]
    fn a_blob_reference_is_found() {
        let record = serde_json::json!({
            "$type": "app.bulleted.outline",
            "image": {
                "$type": "blob",
                "mimeType": "image/jpeg",
                "ref": {"$link": "bafkreicfngbcd3osqxa7oaufocet2j7jytwv526xwtrgruvphxsacrfrk4"},
                "size": 123037,
            },
        });

        assert_eq!(
            linked_cids(&record),
            vec!["bafkreicfngbcd3osqxa7oaufocet2j7jytwv526xwtrgruvphxsacrfrk4".to_string()]
        );
    }

    /// Nested and repeated references: records nest, and the same blob can be
    /// referenced twice without earning two rows.
    #[test]
    fn nested_references_are_found_once_each() {
        let record = serde_json::json!({
            "items": [
                {"ref": {"$link": "bafkone"}},
                {"deep": {"deeper": {"ref": {"$link": "bafktwo"}}}},
                {"again": {"$link": "bafkone"}},
            ],
        });

        assert_eq!(
            linked_cids(&record),
            vec!["bafkone".to_string(), "bafktwo".to_string()],
            "document order, no repeats"
        );
    }

    /// A record with no references contributes no list.
    #[test]
    fn a_record_without_references_links_nothing() {
        let record = serde_json::json!({"$type": "app.bsky.feed.post", "text": "hi"});
        assert!(linked_cids(&record).is_empty());
    }

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
