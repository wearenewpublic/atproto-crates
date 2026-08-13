//! Portal pages for administering the spaces this account owns.
//!
//! The repository browser at `/account/repository/space/…` treats a space as a
//! read surface: what records are in it, and what one of them says. This
//! section answers the other question an owner has — who is in the space and
//! what may reach it — and the two are deliberately separate pages. Browsing is
//! something every member does; configuring is something only the authority
//! can do, and a control nobody present is allowed to use does not belong
//! beside the records.
//!
//! Everything here is a thin portal over [`crate::space::SpaceService`]. The
//! service already refuses a non-owner with `NotSpaceOwner`, so these handlers
//! do not re-implement the check: they hide the controls a non-owner cannot
//! use, and let the service refuse anything that arrives anyway.

use crate::http::errors::XrpcError;
use crate::http::portal::{
    Section, esc, nav, page, redirect, require_same_origin, section_account,
};
use crate::http::state::HttpState;
use crate::space::config::{AppAccess, MintPolicy, SpaceConfigPatch};
use atproto_space::types::SpaceUri;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// How many members one page of the membership table holds.
const MEMBER_PAGE: u32 = 100;

/// Query for the space pages — carries a status word after a redirect.
#[derive(Debug, Deserialize, Default)]
pub struct SpaceQuery {
    /// Status word set by whichever POST redirected here.
    #[serde(default)]
    pub msg: Option<String>,
    /// Cursor into the membership listing.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The three path segments that address a space in this section's URLs.
#[derive(Debug, Deserialize)]
pub struct SpacePath {
    /// Space authority DID.
    pub host: String,
    /// Space type NSID.
    pub space_type: String,
    /// Space key.
    pub space_key: String,
}

impl SpacePath {
    /// Rebuild the space URI, refusing anything that is not one.
    fn uri(&self) -> Result<SpaceUri, XrpcError> {
        let raw = format!(
            "at://{}/space/{}/{}",
            self.host, self.space_type, self.space_key
        );
        SpaceUri::parse(&raw).map_err(|_| {
            XrpcError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("not a space uri: {raw}"),
            )
        })
    }

    /// The path prefix every control on these pages posts back to.
    fn base(&self) -> String {
        format!(
            "/account/spaces/{}/{}/{}",
            urlenc(&self.host),
            urlenc(&self.space_type),
            urlenc(&self.space_key)
        )
    }
}

/// Percent-encode a path segment. A DID carries `:` and a space key may carry
/// anything, so segments are encoded rather than interpolated raw.
fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn service(state: &HttpState) -> Result<&crate::space::SpaceService, XrpcError> {
    state.space_service.as_deref().ok_or_else(|| {
        XrpcError::new(
            axum::http::StatusCode::NOT_FOUND,
            "NotFound",
            "spaces are not configured on this server",
        )
    })
}

/// Status words this section sets on itself, rendered as a banner.
fn banner(msg: Option<&str>) -> String {
    let (kind, text) = match msg {
        Some("config-saved") => ("ok", "Space settings saved."),
        Some("member-added") => ("ok", "Member added."),
        Some("member-removed") => ("ok", "Member removed."),
        Some("err-not-owner") => ("err", "Only the space's authority can change this."),
        Some("err-unknown-space") => (
            "err",
            "You do not hold records in that space, and do not host it.",
        ),
        Some("err-enter-a-did") => ("err", "Enter the DID of the account to add."),
        Some("err-already-a-member") => ("err", "That account is already a member."),
        Some("err-not-a-member") => ("err", "That account is not a member of this space."),
        Some("err-allow-list-needs-an-entry") => (
            "err",
            "An allow list with no clients would lock every app out. Name at least one, or choose Open.",
        ),
        Some("err-save-failed") => ("err", "The space could not be updated."),
        _ => return String::new(),
    };
    format!(r#"<div class="notice {kind}">{}</div>"#, esc(text))
}

// ---------------------------------------------------------------------------
//  Index
// ---------------------------------------------------------------------------

/// `GET /account/spaces` — the spaces this account is in, owned ones first.
pub async fn index(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(q): Query<SpaceQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };

    // The nav offers this section on every page, so it has to answer on a
    // server with spaces switched off rather than 404 a link the portal itself
    // drew. Saying so is also the useful answer: an operator wondering where
    // their spaces went learns that this server does not serve them.
    let Some(svc) = state.space_service.as_deref() else {
        let body = format!(
            r#"{nav}
<h1>Spaces</h1>
<p class="sub">Permissioned data you share with a named set of people.</p>
<section>
<div class="notice warn"><b>Not enabled.</b> This server does not serve spaces,
so there is nothing to administer here.</div>
</section>"#,
            nav = nav(Section::Spaces, &account, ""),
        );
        return Ok(page("Spaces", &body).into_response());
    };

    let page_of = svc
        .list_spaces(&account.did, None, None, None, 100)
        .await
        .map_err(XrpcError::from)?;

    // Owned first: this section exists for the spaces the account can act on,
    // and a member-only space is here for context rather than as a control.
    let (owned, joined): (Vec<_>, Vec<_>) = page_of.spaces.iter().partition(|s| s.is_owner);

    let row = |s: &crate::space::SpaceInfo, linked: bool| {
        let uri = SpaceUri::parse(&s.uri).ok();
        let label = esc(&s.uri);
        let cell = match (linked, uri) {
            (true, Some(u)) => format!(
                r#"<a href="/account/spaces/{}/{}/{}">{label}</a>"#,
                urlenc(&u.space_did),
                urlenc(u.space_type.as_str()),
                urlenc(u.space_key.as_str())
            ),
            _ => label,
        };
        format!(
            r#"<tr><td>{cell}</td><td class="muted">{}</td></tr>"#,
            esc(&s.created_at)
        )
    };

    let owned_rows = if owned.is_empty() {
        r#"<tr><td colspan="2" class="muted">You are not the authority for any space.</td></tr>"#
            .to_string()
    } else {
        owned
            .iter()
            .map(|s| row(s, true))
            .collect::<Vec<_>>()
            .join("")
    };
    let joined_rows = if joined.is_empty() {
        r#"<tr><td colspan="2" class="muted">No spaces hosted by anyone else.</td></tr>"#
            .to_string()
    } else {
        joined
            .iter()
            .map(|s| row(s, true))
            .collect::<Vec<_>>()
            .join("")
    };

    let body = format!(
        r#"{nav}
{banner}
<h1>Spaces</h1>
<p class="sub">Permissioned data you share with a named set of people.</p>

<section>
<h2 style="margin-top:0">Spaces you host</h2>
<p class="muted">You are the authority for these, so you set who may join and
which applications may reach them.</p>
<table><thead><tr><th>Space</th><th>Created</th></tr></thead>
<tbody>{owned_rows}</tbody></table>
</section>

<section>
<h2 style="margin-top:0">Spaces you are in</h2>
<p class="muted">Hosted by another account, which decides their membership and
access. Your records in them are yours and live in your repository, and each one
shows what has been reading them.</p>
<table><thead><tr><th>Space</th><th>Joined</th></tr></thead>
<tbody>{joined_rows}</tbody></table>
</section>"#,
        nav = nav(Section::Spaces, &account, ""),
        banner = banner(q.msg.as_deref()),
    );
    Ok(page("Spaces", &body).into_response())
}

// ---------------------------------------------------------------------------
//  One space
// ---------------------------------------------------------------------------

/// The "who has read your records here" table.
///
/// Reads its rows from the viewer's own per-actor store, because that is where
/// the reads happened: a space credential is minted by the authority, so this
/// server only ever sees one arrive at a repo it hosts.
async fn access_log_section(
    state: &HttpState,
    viewer_did: &str,
    uri: &SpaceUri,
) -> Result<String, XrpcError> {
    let store =
        crate::actor_store::sql::SqlActorStore::open_if_exists(state.reader.data_dir(), viewer_did)
            .await
            .map_err(XrpcError::from)?;
    let entries = match &store {
        Some(store) => crate::space::access_log::list(store.pool(), uri)
            .await
            .map_err(XrpcError::from)?,
        None => Vec::new(),
    };

    let rows = if entries.is_empty() {
        r#"<tr><td colspan="4" class="muted">Nothing has read your records in this space.</td></tr>"#
            .to_string()
    } else {
        entries
            .iter()
            .map(|e| {
                // An application that proved its identity is named. One that
                // did not is called what it is: the only thing identifying it
                // is a key the specification says to replace with each
                // credential, so it is a stranger every couple of hours and
                // naming it after that key would imply otherwise.
                let who = match &e.client_id {
                    Some(client_id) => format!("<code>{}</code>", esc(client_id)),
                    None => r#"<span class="muted">Unidentified application</span>"#.to_string(),
                };
                format!(
                    r#"<tr><td>{who}</td><td class="muted">{}</td><td class="muted">{}</td>
<td class="muted" style="text-align:right">{}</td></tr>"#,
                    esc(&e.first_seen),
                    esc(&e.last_seen),
                    e.reads
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let anonymous = entries.iter().any(|e| e.client_id.is_none());
    let caveat = if anonymous {
        r#"<p class="muted">An application only appears by name when it proved
its identity to the space's authority. One that did not cannot be told apart
from any other, or from itself an hour later, so it is listed as unidentified
each time its credential is renewed.</p>"#
    } else {
        ""
    };

    Ok(format!(
        r#"<section>
<h2 style="margin-top:0">Who has read your records</h2>
<p class="muted">Applications that presented a credential from this space's
authority to read your records on this server. Reads of other members' records,
on their own servers, are not visible here.</p>
<table><thead><tr><th>Application</th><th>First seen</th><th>Last seen</th><th>Reads</th></tr></thead>
<tbody>{rows}</tbody></table>
{caveat}
</section>"#
    ))
}

/// `GET /account/spaces/{host}/{space_type}/{space_key}` — settings and members.
pub async fn detail(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(path): Path<SpacePath>,
    Query(q): Query<SpaceQuery>,
) -> Result<Response, XrpcError> {
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let svc = service(&state)?;
    let uri = path.uri()?;
    let base = path.base();

    // Two different pages share this route, because two different questions
    // are asked of a space and they belong to different people. The authority
    // configures it; anyone holding records in it wants to know who has been
    // reading them. A space the account has no relationship with is neither.
    let holds_records = svc
        .list_spaces(&account.did, None, None, None, 100)
        .await
        .map_err(XrpcError::from)?
        .spaces
        .into_iter()
        .any(|s| s.uri == uri.to_string());
    let is_authority = uri.space_did == account.did;
    if !holds_records && !is_authority {
        return Ok(redirect("/account/spaces?msg=err-unknown-space"));
    }

    let readers = access_log_section(&state, &account.did, &uri).await?;

    if !is_authority {
        // A member's view: the records are theirs, the space is not.
        let body = format!(
            r#"{nav}
{banner}
<h1>{uri_label}</h1>
<p class="sub">Hosted by another account, which sets its membership and access.</p>
{readers}
<p class="muted"><a href="/account/repository/space/{host}/{stype}/{skey}">Browse your records in this space</a>
&middot; <a href="/account/spaces">All spaces</a></p>"#,
            nav = nav(Section::Spaces, &account, &esc(&uri.to_string())),
            banner = banner(q.msg.as_deref()),
            uri_label = esc(&uri.to_string()),
            host = urlenc(&path.host),
            stype = urlenc(&path.space_type),
            skey = urlenc(&path.space_key),
        );
        return Ok(page("Space", &body).into_response());
    }

    let inputs = svc
        .load_mint_authz_inputs(&uri, &account.did)
        .await
        .map_err(XrpcError::from)?;
    if !inputs.found || inputs.deleted {
        return Ok(redirect("/account/spaces?msg=err-unknown-space"));
    }
    let config = inputs.config;

    let members = svc
        .list_members(&uri, q.cursor.as_deref(), MEMBER_PAGE)
        .await
        .map_err(XrpcError::from)?;

    let member_rows = if members.members.is_empty() {
        r#"<tr><td colspan="3" class="muted">No members.</td></tr>"#.to_string()
    } else {
        members
            .members
            .iter()
            .map(|m| {
                // The authority is a member of its own space and cannot be
                // removed from it, so it gets no control rather than a button
                // that returns an error.
                let control = if m.did == uri.space_did {
                    r#"<span class="muted">authority</span>"#.to_string()
                } else {
                    format!(
                        r#"<form method="POST" action="{base}/members/remove" style="display:inline">
  <input type="hidden" name="did" value="{}">
  <button class="quiet" type="submit">Remove</button></form>"#,
                        esc(&m.did)
                    )
                };
                format!(
                    r#"<tr><td><code>{}</code></td><td class="muted">{}</td>
<td style="text-align:right">{control}</td></tr>"#,
                    esc(&m.did),
                    esc(&m.added_at)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let more = match members.cursor {
        Some(cursor) => format!(
            r#"<p><a href="{base}?cursor={}">Next page</a></p>"#,
            urlenc(&cursor)
        ),
        None => String::new(),
    };

    let sel = |p: MintPolicy| {
        if config.mint_policy == p {
            " selected"
        } else {
            ""
        }
    };
    let (open_checked, list_checked, allowed) = match &config.app_access {
        AppAccess::Open => (" checked", "", String::new()),
        AppAccess::AllowList { allowed } => ("", " checked", allowed.join("\n")),
    };

    let body = format!(
        r#"{nav}
{banner}
<h1>{uri_label}</h1>
<p class="sub">Who may join this space, and which applications may reach it.</p>

<section>
<h2 style="margin-top:0">Access</h2>
<form method="POST" action="{base}/config">
  <label for="policy">Who may be issued a credential</label>
  <select id="policy" name="policy">
    <option value="member-list"{ml}>Members of this space</option>
    <option value="public"{pu}>Anyone</option>
    <option value="managing-app"{ma}>Whatever the managing app decides</option>
  </select>

  <fieldset>
    <legend>Which applications may reach it</legend>
    <label><input type="radio" name="app_access" value="open"{open_checked}> Any application</label>
    <label><input type="radio" name="app_access" value="allow-list"{list_checked}> Only the applications I name</label>
    <label for="allowed">Allowed client IDs, one per line</label>
    <textarea id="allowed" name="allowed" rows="4" placeholder="https://example.app/oauth-client-metadata.json">{allowed}</textarea>
    <p class="muted">An allow list is matched against the client identity an
    application proves when it asks for a credential. An application that does
    not prove one is refused, so an allow list also excludes every app that
    cannot identify itself.</p>
  </fieldset>

  <label for="managing_app">Managing app</label>
  <input id="managing_app" name="managing_app" type="text" value="{managing}"
    placeholder="did:web:app.example#svc">
  <p class="muted">Consulted only by the "whatever the managing app decides"
  policy. Leave empty for none.</p>

  <button type="submit">Save settings</button>
</form>
</section>

{readers}

<section>
<h2 style="margin-top:0">Members</h2>
<p class="muted">Members hold their own records for this space, in their own
repositories. Removing someone stops this space issuing them new credentials;
it does not reach into their repository, and a credential already issued works
until it expires.</p>
<table><thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
<tbody>{member_rows}</tbody></table>
{more}
<form method="POST" action="{base}/members">
  <label for="did">Add a member by DID</label>
  <input id="did" name="did" type="text" placeholder="did:plc:…" required maxlength="256">
  <button type="submit">Add member</button>
</form>
</section>

<p class="muted"><a href="/account/repository/space/{host}/{stype}/{skey}">Browse this space's records</a>
&middot; <a href="/account/spaces">All spaces</a></p>"#,
        nav = nav(Section::Spaces, &account, &esc(&uri.to_string())),
        banner = banner(q.msg.as_deref()),
        uri_label = esc(&uri.to_string()),
        readers = readers,
        base = base,
        ml = sel(MintPolicy::MemberList),
        pu = sel(MintPolicy::Public),
        ma = sel(MintPolicy::ManagingApp),
        managing = esc(config.managing_app.as_deref().unwrap_or_default()),
        host = urlenc(&path.host),
        stype = urlenc(&path.space_type),
        skey = urlenc(&path.space_key),
    );
    Ok(page("Space", &body).into_response())
}

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------

/// Submitted by the access form.
#[derive(Debug, Deserialize)]
pub struct ConfigForm {
    /// `member-list` | `public` | `managing-app`.
    pub policy: String,
    /// `open` | `allow-list`.
    pub app_access: String,
    /// Newline-separated client IDs, when `app_access` is `allow-list`.
    #[serde(default)]
    pub allowed: String,
    /// Managing-app service identifier; empty clears it.
    #[serde(default)]
    pub managing_app: String,
}

/// `POST /account/spaces/{…}/config` — save the access settings.
pub async fn save_config(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(path): Path<SpacePath>,
    Form(form): Form<ConfigForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let svc = service(&state)?;
    let uri = path.uri()?;
    let base = path.base();

    let Ok(mint_policy) = MintPolicy::from_str_value(&form.policy) else {
        return Ok(redirect(&format!("{base}?msg=err-save-failed")));
    };

    let app_access = if form.app_access == "allow-list" {
        let allowed: Vec<String> = form
            .allowed
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        // An empty allow list is not "allow nobody" by accident -- it is the
        // shape a form submits when the radio was chosen and the box left
        // blank, and saving it would lock every application out of the space
        // including the one the owner is using.
        if allowed.is_empty() {
            return Ok(redirect(&format!(
                "{base}?msg=err-allow-list-needs-an-entry"
            )));
        }
        AppAccess::AllowList { allowed }
    } else {
        AppAccess::Open
    };

    let patch = SpaceConfigPatch {
        mint_policy: Some(mint_policy),
        app_access: Some(app_access),
        managing_app: Some(form.managing_app.trim().to_string()),
    };

    match svc.update_space(&account.did, &uri, patch).await {
        Ok(_) => {
            tracing::info!(did = %account.did, space = %uri, "portal space config saved");
            Ok(redirect(&format!("{base}?msg=config-saved")))
        }
        Err(crate::errors::PdsError::NotSpaceOwner { .. }) => {
            Ok(redirect("/account/spaces?msg=err-not-owner"))
        }
        Err(error) => {
            tracing::warn!(error = ?error, space = %uri, "portal space config refused");
            Ok(redirect(&format!("{base}?msg=err-save-failed")))
        }
    }
}

// ---------------------------------------------------------------------------
//  Membership
// ---------------------------------------------------------------------------

/// Submitted by both membership forms.
#[derive(Debug, Deserialize)]
pub struct MemberForm {
    /// DID of the account to add or remove.
    pub did: String,
}

/// `POST /account/spaces/{…}/members` — add a member.
pub async fn add_member(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(path): Path<SpacePath>,
    Form(form): Form<MemberForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let svc = service(&state)?;
    let uri = path.uri()?;
    let base = path.base();

    let did = form.did.trim();
    if did.is_empty() {
        return Ok(redirect(&format!("{base}?msg=err-enter-a-did")));
    }

    match svc.add_member(&account.did, &uri, did).await {
        Ok(()) => {
            tracing::info!(space = %uri, member = %did, "portal space member added");
            Ok(redirect(&format!("{base}?msg=member-added")))
        }
        Err(crate::errors::PdsError::NotSpaceOwner { .. }) => {
            Ok(redirect("/account/spaces?msg=err-not-owner"))
        }
        Err(error) => {
            // `MemberAlreadyExists` is the common one and is the owner's to
            // read, not a fault: they asked for a state the space is already in.
            let already = matches!(
                &error,
                crate::errors::PdsError::Space(
                    atproto_space::SpaceError::MemberAlreadyExists { .. }
                )
            );
            if !already {
                tracing::warn!(error = ?error, space = %uri, "portal space member add refused");
            }
            let msg = if already {
                "err-already-a-member"
            } else {
                "err-save-failed"
            };
            Ok(redirect(&format!("{base}?msg={msg}")))
        }
    }
}

/// `POST /account/spaces/{…}/members/remove` — remove a member.
pub async fn remove_member(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(path): Path<SpacePath>,
    Form(form): Form<MemberForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let (_, account) = match section_account(&state, &headers).await {
        Ok(found) => found,
        Err(response) => return Ok(response),
    };
    let svc = service(&state)?;
    let uri = path.uri()?;
    let base = path.base();

    let did = form.did.trim();
    if did.is_empty() {
        return Ok(redirect(&format!("{base}?msg=err-enter-a-did")));
    }

    match svc.remove_member(&account.did, &uri, did).await {
        Ok(()) => {
            tracing::info!(space = %uri, member = %did, "portal space member removed");
            Ok(redirect(&format!("{base}?msg=member-removed")))
        }
        Err(crate::errors::PdsError::NotSpaceOwner { .. }) => {
            Ok(redirect("/account/spaces?msg=err-not-owner"))
        }
        Err(error) => {
            let absent = matches!(
                &error,
                crate::errors::PdsError::Space(atproto_space::SpaceError::NotAMember { .. })
            );
            if !absent {
                tracing::warn!(error = ?error, space = %uri, "portal space member remove refused");
            }
            let msg = if absent {
                "err-not-a-member"
            } else {
                "err-save-failed"
            };
            Ok(redirect(&format!("{base}?msg={msg}")))
        }
    }
}
