//! Expanding `include:` scopes into the permissions they stand for.
//!
//! A client may ask for `include:app.example.appAccess` instead of listing
//! scopes one by one. The NSID names a `com.atproto.lexicon.schema` record
//! whose `main` def is a `permission-set`: a title, a description, and the
//! permissions it covers. It is what lets a consent screen say "Read and write
//! your outlines" rather than reciting seven collections.
//!
//! Nothing here expanded them. The scope parsed, consent displayed it, the
//! token carried it, and enforcement then looked for a concrete `repo:` grant,
//! found none, and refused every write — a permission set was accepted end to
//! end and honoured nowhere.
//!
//! # Expansion is pinned, not live
//!
//! This runs once, when an authorization code is exchanged, and the result is
//! what the token carries. Re-resolving on each request would be simpler and
//! wrong: the record lives in the *client's* repository, so a client could
//! widen its own grant after the fact by editing a record the account holder
//! consented to once and never sees again. A grant is what was shown at
//! consent, and it has to stop moving after that.
//!
//! It also keeps a network round trip off the write path, but that is the
//! lesser reason.
//!
//! # What is covered
//!
//! `repo`, `blob`, `rpc` and `space` permissions. A permission naming any other
//! resource is dropped with a warning rather than guessed at: the failure from
//! too few scopes is a clear `InsufficientScope`, and the failure from inventing
//! one is a grant nobody approved.
//!
//! # The consent screen expands through here too
//!
//! [`scopes_for_permission`] is the single decision about what one declared
//! permission becomes, and both callers go through it: this module, to build the
//! grant, and `oauth::consent`, to describe it. They used to be separate — the
//! screen had its own summary that predated `rpc` and `space` expansion and went
//! on calling both "not granted by this server" after the token started carrying
//! them. Describing the grant by expanding it is what stops the two drifting
//! again: a resource arm added below is described above without being told.
//!
//! A permission that expands to nothing returns why, rather than an empty list,
//! because the screen has to say which of "you are not getting this" and "add
//! `?aud=` to get this" is true.

use crate::repo::lexicon::LexiconResolver;
use atproto_oauth::scopes::Scope;
use std::sync::Arc;

/// Expand every `include:` in a space-separated scope string.
///
/// Unresolvable or malformed sets contribute nothing and leave the rest of the
/// grant intact — a client that asked for one permission set and three literal
/// scopes keeps the three.
///
/// The `include:` itself is kept alongside its expansion so the token still
/// records what was asked for.
pub async fn expand(resolver: Option<&Arc<dyn LexiconResolver>>, granted: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for raw in granted.split_whitespace() {
        out.push(raw.to_string());
        // The audience travels with the `include:`, not with the permission
        // set: a set is published once and reused by every client, so it cannot
        // know which service any particular grant is for. `inheritAud` is how a
        // permission says "take it from the scope that pulled me in".
        let (nsid, include_aud) = match Scope::parse(raw) {
            Ok(Scope::Include(inc)) => (inc.nsid.clone(), inc.aud.clone()),
            _ => continue,
        };
        let Some(resolver) = resolver else {
            tracing::warn!(
                nsid = %nsid,
                "cannot expand a permission set: no lexicon resolver is configured"
            );
            continue;
        };
        let Some(doc) = resolver.resolve(&nsid).await else {
            tracing::warn!(nsid = %nsid, "permission set did not resolve; granting nothing for it");
            continue;
        };
        let expanded = permissions_from(&doc, &nsid, include_aud.as_deref());
        if expanded.is_empty() {
            tracing::warn!(nsid = %nsid, "permission set declared nothing this server understands");
        } else {
            tracing::info!(
                nsid = %nsid,
                count = expanded.len(),
                "expanded a permission set"
            );
        }
        out.extend(expanded);
    }
    // Order-insensitive de-duplication: a client naming a scope both directly
    // and through a set should not have it counted twice.
    out.sort();
    out.dedup();
    out.join(" ")
}

/// Read the concrete scopes out of a `permission-set` record.
fn permissions_from(doc: &serde_json::Value, nsid: &str, include_aud: Option<&str>) -> Vec<String> {
    let main = &doc["defs"]["main"];
    if main["type"].as_str() != Some("permission-set") {
        tracing::warn!(
            nsid = %nsid,
            found = ?main["type"].as_str(),
            "include: named a lexicon that is not a permission-set"
        );
        return Vec::new();
    }
    // A lexicon document names itself. Resolution is by NSID, but nothing
    // required the document that came back to agree that it *is* that NSID --
    // so a resolver returning the wrong document, or a client publishing one
    // under a name it does not claim, expanded into permissions attributed to
    // an NSID the account holder was shown and the document disowns.
    //
    // Absent `id` is tolerated: the check is that a stated identity matches,
    // not that one is stated.
    if let Some(id) = doc["id"].as_str()
        && id != nsid
    {
        tracing::warn!(
            nsid = %nsid,
            id = %id,
            "permission set resolved to a document naming a different lexicon; granting nothing"
        );
        return Vec::new();
    }

    let Some(permissions) = main["permissions"].as_array() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for perm in permissions {
        match scopes_for_permission(perm, nsid, include_aud) {
            Ok(scopes) => out.extend(scopes),
            Err(reason) => tracing::warn!(
                nsid = %nsid,
                resource = ?perm["resource"].as_str(),
                reason = %reason,
                "skipping a permission this server will not grant"
            ),
        }
    }
    out
}

/// The scopes one declared permission expands into, or why it expands into
/// nothing.
///
/// This is the whole decision about what a permission becomes, and it is
/// deliberately the only copy: `oauth::consent` calls it to describe a set on
/// the consent screen, so the words the account holder reads are generated from
/// the same code that builds the grant they are approving. See the module note.
///
/// The error is a sentence for a person, not a code — it reaches the consent
/// screen verbatim.
pub(crate) fn scopes_for_permission(
    perm: &serde_json::Value,
    nsid: &str,
    include_aud: Option<&str>,
) -> Result<Vec<String>, String> {
    let scopes = match perm["resource"].as_str() {
        Some("repo") => repo_scopes(perm)?,
        Some("blob") => blob_scopes(perm),
        Some("rpc") => rpc_scopes(perm, nsid, include_aud)?,
        Some("space") => space_scopes(perm)?,
        // Deliberately not guessed at. See the module note.
        Some(other) => {
            return Err(format!("`{other}` is not a resource this server grants"));
        }
        None => return Err("the permission names no resource".to_string()),
    };

    // Every string these scopes are built from is chosen by the client. The
    // record lives in the client's own repository, so `lxm`, `collection`,
    // `action` and `accept` are all its text, and the audience arrives on the
    // `include:` scope the client wrote. A grant is space-delimited, so a value
    // carrying a space is not a value -- it is a second scope, and one that
    // never appeared on the consent screen because the screen splits on
    // whitespace too and saw a single token.
    //
    // Checking here rather than in each builder is deliberate: this is the one
    // place every expanded scope passes through, and a new resource arm added
    // later inherits the check instead of having to remember it.
    if let Some(bad) = scopes
        .iter()
        .find(|scope| !atproto_oauth::scopes::is_scope_token(scope))
    {
        return Err(format!(
            "`{bad}` is not a single scope token; a permission set may not decide how many scopes \
             it becomes"
        ));
    }
    Ok(scopes)
}

/// `space:<spaceType>[?authority=…][&skey=…][&collection=…][&action=…][&manage=…]`
/// for a space permission.
///
/// # The space type must be concrete
///
/// A permission set is published once and reused by every client that names
/// it, so `spaceType=*` inside one would let the publisher hand out access to
/// every space type a user participates in — a cross-type grant is expressible
/// only as a `space:` scope a client requests directly and a user sees on the
/// consent screen for what it is. The lexicon layer refuses to publish such a
/// set; refusing to expand one too means a set published elsewhere, or before
/// that validation existed, cannot smuggle the wildcard past this server.
///
/// # `collection` is left alone when omitted
///
/// Unlike [`repo_scopes`], an omitted `collection` is *not* expanded into the
/// actions' defaults. A space scope with no `collection` resolves against the
/// space type's declaration every time it is evaluated, so the grant follows
/// the declaration as it changes; enumerating the collections here would
/// freeze them at the moment of expansion. The spec says an app that wants
/// them frozen should list them explicitly, which a permission set can do.
fn space_scopes(perm: &serde_json::Value) -> Result<Vec<String>, String> {
    let Some(space_type) = perm["spaceType"].as_str().filter(|t| !t.is_empty()) else {
        return Err(
            "the space permission names no spaceType, and a set permission must name a concrete \
             space type"
                .to_string(),
        );
    };
    if space_type == "*" {
        return Err(
            "the space permission asks for every space type, which is only expressible as a scope \
             requested directly"
                .to_string(),
        );
    }

    let mut params: Vec<String> = Vec::new();
    // The spec spells this `authority`; `did` is the name this crate's
    // permission model used before it did, and a set written against either
    // means the same thing.
    if let Some(authority) = perm["authority"]
        .as_str()
        .or_else(|| perm["did"].as_str())
        .filter(|v| !v.is_empty())
    {
        params.push(format!("authority={authority}"));
    }
    if let Some(skey) = perm["skey"].as_str().filter(|v| !v.is_empty()) {
        params.push(format!("skey={skey}"));
    }
    for collection in string_list(&perm["collection"]) {
        params.push(format!("collection={collection}"));
    }
    // An omitted `action` means read + create + update + delete, matching how
    // a bare `space:` scope parses. Naming them keeps the emitted scope exact
    // rather than relying on that default holding.
    let actions = string_list(&perm["action"]);
    let actions = if actions.is_empty() {
        vec![
            "read".to_string(),
            "create".to_string(),
            "update".to_string(),
            "delete".to_string(),
        ]
    } else {
        actions
    };
    for action in actions {
        params.push(format!("action={action}"));
    }
    // `manage` is the other axis and has no default: omitted, it grants no
    // administrative capability at all, so there is nothing to fill in and
    // every verb here was asked for explicitly.
    //
    // An unrecognised verb is refused rather than dropped. Dropping it would
    // narrow a grant the consent screen described, and emitting it would build
    // a scope string `Scope::parse` rejects outright -- which takes the
    // record access down with the administrative grant that was malformed.
    for verb in string_list(&perm["manage"]) {
        if !matches!(verb.as_str(), "create" | "update" | "delete") {
            return Err(format!(
                "`{verb}` is not a space-management verb; a permission set may name only create, \
                 update or delete"
            ));
        }
        params.push(format!("manage={verb}"));
    }

    Ok(vec![if params.is_empty() {
        format!("space:{space_type}")
    } else {
        format!("space:{space_type}?{}", params.join("&"))
    }])
}

/// `rpc:<lxm>?aud=<audience>` for each method the permission names.
///
/// # An audience is required
///
/// A bare `rpc:<lxm>` parses with `aud=*`, which grants the method at *every*
/// service: the PDS signs each proxied call with the holder's own key, so the
/// upstream sees a request the account genuinely authorised. Emitting that from
/// a permission set would hand out a grant far wider than the consent screen
/// implied, and — unlike granting too little — nothing would ever report it.
/// Too few scopes fails loudly with `InsufficientScope`; too many fails
/// silently, forever.
///
/// So a permission that cannot be given a concrete audience is skipped, with
/// the same warning an unknown resource gets. The consequence is worth stating
/// plainly: a client writing `include:app.bsky.authCreatePosts` with no `?aud=`
/// gets that set's `repo:` grants and none of its `rpc:` ones, exactly as
/// before this function existed. It has to name the service it intends to call.
///
/// # Where the audience comes from
///
/// `inheritAud: true` takes it from the `include:<nsid>?aud=<did>` scope that
/// pulled the set in. A permission naming its own concrete `aud` is refused
/// outright, matching the reference (`oauth-scopes`, `include-scope.ts`): a set
/// is published once and reused by every client, so an audience baked into it
/// would be the publisher choosing who a holder's tokens may talk to.
fn rpc_scopes(
    perm: &serde_json::Value,
    nsid: &str,
    include_aud: Option<&str>,
) -> Result<Vec<String>, String> {
    // `aud: "*"` is the one self-named audience that is not a claim about a
    // particular service, and the reference lets it through to be treated like
    // an absent one. It still needs an inherited audience to expand.
    let own_aud = perm["aud"].as_str().filter(|a| *a != "*");
    if let Some(own) = own_aud {
        return Err(format!(
            "the permission names its own audience (`{own}`), and a permission set may not choose \
             which service a holder's token may call"
        ));
    }

    let inherits = perm["inheritAud"].as_bool().unwrap_or(false);
    let aud = match (inherits, include_aud.filter(|a| !a.is_empty())) {
        (true, Some(aud)) => aud,
        (true, None) => {
            return Err(format!(
                "the permission takes its audience from the request, which named none — ask for \
                 `include:{nsid}?aud=<did>` to grant it"
            ));
        }
        (false, _) => {
            return Err(
                "the permission names no audience, and granting it would mean every service, which \
                 is wider than this set describes"
                    .to_string(),
            );
        }
    };

    let methods = string_list(&perm["lxm"]);
    if methods.is_empty() {
        // No `lxm` means every method, which with a concrete audience is still
        // "anything at that one service" -- broader than any set here declares.
        return Err(
            "the permission names no methods, so it would grant every method at its audience"
                .to_string(),
        );
    }

    Ok(methods
        .into_iter()
        .map(|lxm| format!("rpc:{lxm}?aud={aud}"))
        .collect())
}

/// `repo:<collection>?action=…` for each collection the permission names.
fn repo_scopes(perm: &serde_json::Value) -> Result<Vec<String>, String> {
    let actions = string_list(&perm["action"]);
    let collections = string_list(&perm["collection"]);
    if collections.is_empty() {
        return Err("the permission names no collections".to_string());
    }
    let mut out = Vec::new();
    for collection in collections {
        // An omitted `action` means every action, matching how a bare `repo:`
        // scope parses. Naming them explicitly keeps the emitted scope exact
        // rather than relying on that default holding.
        let actions = if actions.is_empty() {
            vec![
                "create".to_string(),
                "update".to_string(),
                "delete".to_string(),
            ]
        } else {
            actions.clone()
        };
        let query = actions
            .iter()
            .map(|a| format!("action={a}"))
            .collect::<Vec<_>>()
            .join("&");
        out.push(format!("repo:{collection}?{query}"));
    }
    Ok(out)
}

/// `blob:<mime>` for each accepted type.
fn blob_scopes(perm: &serde_json::Value) -> Vec<String> {
    let accept = string_list(&perm["accept"]);
    if accept.is_empty() {
        return vec!["blob:*/*".to_string()];
    }
    accept.into_iter().map(|m| format!("blob:{m}")).collect()
}

/// A lexicon list field, which may be a single string or an array of them.
fn string_list(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(serde_json::Value);

    #[async_trait::async_trait]
    impl LexiconResolver for Fixed {
        async fn resolve(&self, _nsid: &str) -> Option<serde_json::Value> {
            Some(self.0.clone())
        }
    }

    struct Missing;

    #[async_trait::async_trait]
    impl LexiconResolver for Missing {
        async fn resolve(&self, _nsid: &str) -> Option<serde_json::Value> {
            None
        }
    }

    /// A resolver whose answer changes between calls, which is what a client
    /// editing its own permission-set record looks like from here.
    struct Swappable(std::sync::Mutex<Vec<serde_json::Value>>);

    #[async_trait::async_trait]
    impl LexiconResolver for Swappable {
        async fn resolve(&self, _nsid: &str) -> Option<serde_json::Value> {
            let mut answers = self.0.lock().unwrap();
            if answers.len() > 1 {
                Some(answers.remove(0))
            } else {
                answers.first().cloned()
            }
        }
    }

    /// A permission set widened after it was first read must not widen a grant
    /// that has already been expanded.
    ///
    /// This is the property the pin in `authorize` buys: expansion happens once
    /// and its result is what the code carries. Expanding a second time later
    /// -- which is what redemption used to do -- reads whatever the client has
    /// published by then.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_set_edited_after_expansion_does_not_widen_the_grant() {
        let narrow = serde_json::json!({
            "lexicon": 1,
            "id": "app.example.access",
            "defs": {"main": {
                "type": "permission-set",
                "title": "Example",
                "permissions": [
                    {"resource": "repo", "collection": ["app.example.note"], "action": ["create"]}
                ]
            }}
        });
        let wide = serde_json::json!({
            "lexicon": 1,
            "id": "app.example.access",
            "defs": {"main": {
                "type": "permission-set",
                "title": "Example",
                "permissions": [
                    {"resource": "repo", "collection": ["*"],
                     "action": ["create", "update", "delete"]}
                ]
            }}
        });
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Swappable(std::sync::Mutex::new(vec![
            narrow.clone(),
            wide.clone(),
        ])));

        // The expansion the holder approved.
        let pinned = expand(Some(&resolver), "include:app.example.access").await;
        assert!(
            pinned.contains("repo:app.example.note?action=create"),
            "the narrow set should expand to its one collection: {pinned}"
        );
        assert!(
            !pinned.contains("repo:*"),
            "the narrow set must not grant every collection: {pinned}"
        );

        // The client has since republished a wider set. Whatever the token
        // carries must still be the pinned string -- nothing re-reads it.
        let second_read = expand(Some(&resolver), "include:app.example.access").await;
        assert!(
            second_read.contains("repo:*"),
            "the fixture must actually serve the wider set second: {second_read}"
        );
        assert_ne!(
            pinned, second_read,
            "the fixture must distinguish the two reads, or this proves nothing"
        );
    }

    /// A document that names a different lexicon than the one requested grants
    /// nothing. Resolution is by NSID; nothing required the answer to agree
    /// that it *is* that NSID.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_set_whose_id_disagrees_with_the_request_grants_nothing() {
        let impostor = serde_json::json!({
            "lexicon": 1,
            "id": "app.attacker.access",
            "defs": {"main": {
                "type": "permission-set",
                "title": "Something else entirely",
                "permissions": [
                    {"resource": "repo", "collection": ["*"],
                     "action": ["create", "update", "delete"]}
                ]
            }}
        });
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(impostor));
        let expanded = expand(Some(&resolver), "include:app.example.access").await;
        assert_eq!(
            expanded, "include:app.example.access",
            "a disowned document must contribute no permissions: {expanded}"
        );
    }

    /// The record that started this: Bulleted's own permission set.
    fn bulleted() -> serde_json::Value {
        serde_json::json!({
            "lexicon": 1,
            "id": "app.bulleted.appAccess",
            "defs": {"main": {
                "type": "permission-set",
                "title": "Bulleted",
                "detail": "Read and write your outlines, bullets, and notes.",
                "permissions": [{
                    "type": "permission",
                    "resource": "repo",
                    "action": ["create", "update", "delete"],
                    "collection": ["app.bulleted.outline", "app.bulleted.note"],
                }],
            }},
        })
    }

    fn resolver(doc: serde_json::Value) -> Arc<dyn LexiconResolver> {
        Arc::new(Fixed(doc))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_permission_set_becomes_the_scopes_it_declares() {
        let r = resolver(bulleted());
        let out = expand(Some(&r), "atproto include:app.bulleted.appAccess").await;

        assert!(
            out.contains("repo:app.bulleted.outline?action=create&action=update&action=delete"),
            "the write that was refused is still not granted: {out}"
        );
        assert!(out.contains("repo:app.bulleted.note?"), "{out}");
        assert!(
            out.contains("atproto"),
            "unrelated scopes must survive: {out}"
        );
        assert!(
            out.contains("include:app.bulleted.appAccess"),
            "the token should still record what was asked for: {out}"
        );
    }

    /// The expansion has to satisfy the check that was failing.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_expansion_grants_the_action_that_was_refused() {
        let r = resolver(bulleted());
        let out = expand(Some(&r), "include:app.bulleted.appAccess").await;

        let scopes =
            atproto_oauth::scopes::ScopesSet::from_scope_string_for(&out, "did:plc:holder");
        assert!(
            scopes
                .assert_repo(
                    "app.bulleted.outline",
                    &atproto_oauth::scopes::RepoAction::Update
                )
                .is_ok(),
            "putRecord is still refused after expansion: {out}"
        );
    }

    /// A set that does not resolve grants nothing, and takes nothing with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unresolvable_set_leaves_the_rest_of_the_grant_alone() {
        let r: Arc<dyn LexiconResolver> = Arc::new(Missing);
        let out = expand(Some(&r), "atproto include:app.example.gone").await;

        assert!(out.contains("atproto"), "{out}");
        assert!(
            !out.contains("repo:"),
            "an unresolved set granted something: {out}"
        );
    }

    /// A lexicon that is not a permission set grants nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_record_that_is_not_a_permission_set_grants_nothing() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "record", "key": "tid"}}
        }));
        let out = expand(Some(&r), "include:app.example.notASet").await;

        assert!(!out.contains("repo:"), "{out}");
    }

    /// A resource this server does not understand is dropped, not guessed at.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_resource_is_not_invented() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {"type": "permission", "resource": "something-new", "action": ["*"]}
            ]}}
        }));
        let out = expand(Some(&r), "include:app.example.future").await;

        assert_eq!(
            out, "include:app.example.future",
            "an unrecognised resource must not become a grant: {out}"
        );
    }

    /// A space permission expands to the `space:` scope it describes.
    ///
    /// Until it did, a set naming a space resource granted nothing: the
    /// expander skipped it with a warning, so a client that requested the set
    /// received every `repo:` grant in it and no space access at all, with a
    /// 200 and a consent screen that had described the space.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_expands_to_a_space_scope() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {
                    "type": "permission",
                    "resource": "space",
                    "spaceType": "com.atmoboards.forum",
                    "authority": "*",
                    "collection": ["com.atmoboards.thread", "com.atmoboards.reply"],
                    "action": ["read", "create"]
                }
            ]}}
        }));
        let out = expand(Some(&r), "include:com.atmoboards.access").await;
        assert!(
            out.contains(
                "space:com.atmoboards.forum?authority=*&collection=com.atmoboards.thread&collection=com.atmoboards.reply&action=read&action=create"
            ),
            "{out}"
        );

        // And what it emits is a grant this server honours, rather than a
        // string that merely looks like one. Expansion feeding a scope the
        // enforcement layer cannot read would fail exactly as silently as the
        // skip it replaces.
        let scopes = atproto_oauth::scopes::ScopesSet::from_scope_string_for(&out, "did:plc:me");
        assert!(
            scopes
                .assert_space(&atproto_oauth::scopes::SpaceTarget::new(
                    "com.atmoboards.forum",
                    "did:plc:someone-else",
                    "any-key",
                    atproto_oauth::scopes::SpaceAction::Read,
                ))
                .is_ok(),
            "the emitted scope must grant whole-space read under any authority: {out}"
        );
    }

    /// The spec spells the authority field `authority`; this crate's own
    /// permission model called it `did` first. A set written against either
    /// means the same thing, and dropping one silently would widen the grant
    /// to every authority.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_accepts_either_authority_spelling() {
        for field in ["authority", "did"] {
            let mut perm = serde_json::json!({
                "type": "permission",
                "resource": "space",
                "spaceType": "com.example.bookmarks",
                "action": ["read"]
            });
            perm[field] = serde_json::json!("did:plc:abc123");
            let r = resolver(serde_json::json!({
                "defs": {"main": {"type": "permission-set", "permissions": [perm]}}
            }));
            let out = expand(Some(&r), "include:com.example.access").await;
            assert!(
                out.contains("space:com.example.bookmarks?authority=did:plc:abc123&action=read"),
                "{field}: {out}"
            );
        }
    }

    /// A set's `manage` verbs reach the scope it expands to.
    ///
    /// Until they did, a set asking to administer a user's spaces expanded to
    /// a scope with no `manage` at all: the consent screen described an
    /// administrative grant, the account holder approved one, and every
    /// `simplespace` call the application then made was refused for a scope it
    /// had been told it was given.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_carries_its_manage_verbs() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {
                    "type": "permission",
                    "resource": "space",
                    "spaceType": "com.atmoboards.forum",
                    "authority": "*",
                    "action": ["read_self"],
                    "manage": ["update", "delete"]
                }
            ]}}
        }));
        let out = expand(Some(&r), "include:com.atmoboards.access").await;
        assert!(
            out.contains(
                "space:com.atmoboards.forum?authority=*&action=read_self&manage=update&manage=delete"
            ),
            "{out}"
        );

        // And the emitted scope confers the verbs, rather than merely spelling
        // them: expansion feeding a string the enforcement layer reads
        // differently would fail as silently as the drop it replaces.
        let scopes = atproto_oauth::scopes::ScopesSet::from_scope_string_for(&out, "did:plc:me");
        for verb in [
            atproto_oauth::scopes::SpaceManageVerb::Update,
            atproto_oauth::scopes::SpaceManageVerb::Delete,
        ] {
            assert!(
                scopes
                    .assert_space_manage(&atproto_oauth::scopes::SpaceManageTarget::new(
                        "com.atmoboards.forum",
                        "did:plc:abc",
                        "default",
                        verb,
                    ))
                    .is_ok(),
                "the emitted scope must confer {verb:?}: {out}"
            );
        }
        assert!(
            scopes
                .assert_space_manage(&atproto_oauth::scopes::SpaceManageTarget::new(
                    "com.atmoboards.forum",
                    "did:plc:abc",
                    "default",
                    atproto_oauth::scopes::SpaceManageVerb::Create,
                ))
                .is_err(),
            "a verb the set did not name must not be conferred: {out}"
        );
    }

    /// Omitting `manage` stays the default, and the default is nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_without_manage_confers_no_administration() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {
                    "type": "permission",
                    "resource": "space",
                    "spaceType": "com.example.bookmarks",
                    "action": ["read"]
                }
            ]}}
        }));
        let out = expand(Some(&r), "include:com.example.access").await;
        assert!(out.contains("space:com.example.bookmarks"), "{out}");
        assert!(!out.contains("manage="), "got: {out}");
    }

    /// An unrecognised verb takes the permission out rather than being dropped
    /// from it.
    ///
    /// Dropping it would narrow a grant the consent screen had described.
    /// Emitting it would produce a scope string `Scope::parse` refuses whole,
    /// which loses the record access alongside the administrative grant that
    /// was actually malformed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_refuses_a_verb_that_is_not_a_verb() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {
                    "type": "permission",
                    "resource": "space",
                    "spaceType": "com.atmoboards.forum",
                    "manage": ["administer"]
                }
            ]}}
        }));
        let out = expand(Some(&r), "include:com.atmoboards.access").await;
        assert!(
            !out.contains("space:"),
            "an unknown manage verb must grant nothing: {out}"
        );
    }

    /// A wildcard space type is refused rather than expanded.
    ///
    /// A set is published once and reused by every client that names it, so a
    /// cross-type grant inside one would be the publisher handing out access
    /// to every space type a user participates in. It is expressible only as a
    /// scope a client requests directly, where the consent screen shows it for
    /// what it is.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_may_not_name_every_space_type() {
        for space_type in [serde_json::json!("*"), serde_json::Value::Null] {
            let mut perm = serde_json::json!({
                "type": "permission",
                "resource": "space",
                "action": ["read"]
            });
            if !space_type.is_null() {
                perm["spaceType"] = space_type.clone();
            }
            let r = resolver(serde_json::json!({
                "defs": {"main": {"type": "permission-set", "permissions": [perm]}}
            }));
            let out = expand(Some(&r), "include:com.example.access").await;
            assert!(
                !out.contains("space:"),
                "spaceType {space_type:?} must grant nothing: {out}"
            );
        }
    }

    /// An omitted `collection` stays omitted, so the grant keeps following the
    /// space type's declaration instead of freezing it at expansion time.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_space_permission_does_not_freeze_the_declared_collections() {
        let r = resolver(serde_json::json!({
            "defs": {"main": {"type": "permission-set", "permissions": [
                {
                    "type": "permission",
                    "resource": "space",
                    "spaceType": "com.example.bookmarks"
                }
            ]}}
        }));
        let out = expand(Some(&r), "include:com.example.access").await;
        assert!(!out.contains("collection="), "{out}");
        // The action default is enumerated, which changes nothing about what
        // is granted and keeps the emitted scope exact.
        assert!(
            out.contains(
                "space:com.example.bookmarks?action=read&action=create&action=update&action=delete"
            ),
            "{out}"
        );
    }

    /// Without a resolver nothing is granted, rather than everything.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_resolver_grants_nothing() {
        let out = expand(None, "atproto include:app.bulleted.appAccess").await;
        assert!(!out.contains("repo:"), "{out}");
        assert!(out.contains("atproto"), "{out}");
    }

    /// A permission set served from disk expands, exactly as a network one does.
    ///
    /// The regression this guards is not in the expansion at all -- it is that
    /// the resolver never answered. A PDS writing genesis operations to a local
    /// PLC directory cannot resolve a DID registered in the production one, so
    /// `app.bulleted.authFull` came back `None`, expanded to nothing, and every
    /// write was refused with `InsufficientScope` several steps later.
    /// `DirectoryLexiconResolver` is what closes that, and this asserts the two
    /// halves meet: a document read off disk yields concrete `repo:` grants.
    ///
    /// The document is the one `lexicons.bulleted.app` actually publishes,
    /// verified byte-identical against the record on 2026-08-07.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_permission_set_read_from_disk_expands() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("authFull.json"),
            r#"{
              "lexicon": 1,
              "id": "app.bulleted.authFull",
              "defs": {"main": {
                "type": "permission-set",
                "title": "Bulleted",
                "detail": "Read and write your outlines, bullets, and notes.",
                "permissions": [{
                  "type": "permission",
                  "resource": "repo",
                  "collection": [
                    "app.bulleted.node", "app.bulleted.note", "app.bulleted.outline",
                    "app.bulleted.mirror", "app.bulleted.comment", "app.bulleted.commentPolicy"
                  ]
                }]
              }}
            }"#,
        )
        .unwrap();
        let (disk, skipped) =
            crate::repo::lexicon::DirectoryLexiconResolver::load(tmp.path()).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");

        let resolver: Arc<dyn LexiconResolver> = Arc::new(disk);
        let expanded = expand(Some(&resolver), "include:app.bulleted.authFull").await;

        // The `include:` survives so the token still records what was asked for.
        assert!(
            expanded.contains("include:app.bulleted.authFull"),
            "{expanded}"
        );
        for collection in [
            "app.bulleted.node",
            "app.bulleted.note",
            "app.bulleted.outline",
            "app.bulleted.mirror",
            "app.bulleted.comment",
            "app.bulleted.commentPolicy",
        ] {
            assert!(
                expanded.contains(collection),
                "{collection} was not granted: {expanded}"
            );
        }
    }

    // --- rpc permissions ----------------------------------------------------

    /// The real `app.bsky.authCreatePosts`, which is what surfaced this.
    ///
    /// Its rpc permission covers the three video methods and carries
    /// `inheritAud: true`; its repo permission covers the three post
    /// collections. Both halves have to come out.
    fn auth_create_posts() -> serde_json::Value {
        serde_json::json!({
          "lexicon": 1,
          "id": "app.bsky.authCreatePosts",
          "defs": {"main": {
            "type": "permission-set",
            "title": "Create Bluesky Posts",
            "detail": "Can not update or delete posts.",
            "permissions": [
              {
                "type": "permission",
                "resource": "rpc",
                "inheritAud": true,
                "lxm": [
                  "app.bsky.video.uploadVideo",
                  "app.bsky.video.getJobStatus",
                  "app.bsky.video.getUploadLimits"
                ]
              },
              {
                "type": "permission",
                "resource": "repo",
                "action": ["create"],
                "collection": [
                  "app.bsky.feed.post",
                  "app.bsky.feed.postgate",
                  "app.bsky.feed.threadgate"
                ]
              }
            ]
          }}
        })
    }

    /// With an audience on the `include:`, the rpc methods expand.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_inherited_audience_expands_the_rpc_methods() {
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(auth_create_posts()));
        let expanded = expand(
            Some(&resolver),
            "include:app.bsky.authCreatePosts?aud=did:web:api.bsky.app%23bsky_appview",
        )
        .await;

        for method in [
            "app.bsky.video.uploadVideo",
            "app.bsky.video.getJobStatus",
            "app.bsky.video.getUploadLimits",
        ] {
            assert!(
                expanded.contains(&format!(
                    "rpc:{method}?aud=did:web:api.bsky.app#bsky_appview"
                )),
                "{method} did not expand: {expanded}"
            );
        }
        // The repo half is unaffected.
        assert!(
            expanded.contains("repo:app.bsky.feed.post?action=create"),
            "{expanded}"
        );
    }

    /// Without one, the rpc methods are skipped and the repo half survives.
    ///
    /// This is the deliberate cost of requiring an audience: a client that does
    /// not name a service gets the repository grants and no proxy rights. The
    /// alternative is `aud=*`, which grants the method at *every* service and
    /// would never be reported to anyone.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_an_audience_the_rpc_methods_are_skipped() {
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(auth_create_posts()));
        let expanded = expand(Some(&resolver), "include:app.bsky.authCreatePosts").await;

        assert!(
            !expanded.contains("rpc:"),
            "an rpc scope was granted with no audience: {expanded}"
        );
        assert!(
            !expanded.contains("aud=*"),
            "the wildcard audience must never be emitted: {expanded}"
        );
        assert!(
            expanded.contains("repo:app.bsky.feed.post?action=create"),
            "{expanded}"
        );
    }

    /// A set naming its own audience is refused.
    ///
    /// A set is published once and reused by every client, so an audience baked
    /// into it would be the publisher deciding which services a holder's tokens
    /// may call.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_permission_naming_its_own_audience_is_refused() {
        let doc = serde_json::json!({
          "lexicon": 1, "id": "com.example.set",
          "defs": {"main": {"type": "permission-set", "permissions": [
            {"type": "permission", "resource": "rpc",
             "aud": "did:web:elsewhere.example", "lxm": ["com.example.method"]}
          ]}}
        });
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(doc));
        let expanded = expand(
            Some(&resolver),
            "include:com.example.set?aud=did:web:api.bsky.app",
        )
        .await;

        assert!(!expanded.contains("rpc:"), "{expanded}");
        assert!(!expanded.contains("elsewhere.example"), "{expanded}");
    }

    /// An rpc permission naming no methods is skipped even with an audience.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_rpc_permission_with_no_methods_is_skipped() {
        let doc = serde_json::json!({
          "lexicon": 1, "id": "com.example.set",
          "defs": {"main": {"type": "permission-set", "permissions": [
            {"type": "permission", "resource": "rpc", "inheritAud": true}
          ]}}
        });
        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(doc));
        let expanded = expand(
            Some(&resolver),
            "include:com.example.set?aud=did:web:api.bsky.app",
        )
        .await;

        assert!(!expanded.contains("rpc:"), "{expanded}");
    }

    /// The expansion is what enforcement asks for, not merely a similar string.
    ///
    /// `assert_rpc` is the check on the proxy path; a scope that expands but
    /// does not satisfy it would be the same class of bug in a new place.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_expansion_satisfies_the_proxy_assertion() {
        use atproto_oauth::scopes::ScopesSet;

        let resolver: Arc<dyn LexiconResolver> = Arc::new(Fixed(auth_create_posts()));
        let expanded = expand(
            Some(&resolver),
            "include:app.bsky.authCreatePosts?aud=did:web:api.bsky.app",
        )
        .await;

        let granted = ScopesSet::from_scope_string(&expanded);
        granted
            .assert_rpc("app.bsky.video.uploadVideo", "did:web:api.bsky.app")
            .expect("the granted scope must satisfy the proxy check");
        // Not a method the set names, and not another audience.
        assert!(
            granted
                .assert_rpc("app.bsky.feed.getTimeline", "did:web:api.bsky.app")
                .is_err()
        );
        assert!(
            granted
                .assert_rpc("app.bsky.video.uploadVideo", "did:web:elsewhere.example")
                .is_err()
        );
    }

    // --- scope injection ----------------------------------------------------

    /// A permission set is fetched from the client's own repository, so every
    /// string in it is text the client chose -- and it needs no encoding trick,
    /// just a space.
    ///
    /// Which field carries it depends on where the builder puts the value.
    /// Only a value written *last* can append a whole token: `rpc:{lxm}?aud=`
    /// puts `aud` last, so a space in `lxm` yields `transition:generic?aud=…`,
    /// which parses as nothing and is ignored. `blob:{accept}` and the final
    /// `action=` of `repo:{collection}?{actions}` are the two record fields
    /// that do land at the end, so they are the two tested here.
    ///
    /// The assertion is on `assert_repo`, not on the string.
    /// `transition:generic` short-circuits the repo axis, so a surviving token
    /// turns a set that names one image type into write access to every
    /// collection in the repository.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_permission_sets_own_fields_cannot_append_a_second_scope() {
        use atproto_oauth::scopes::{RepoAction, ScopesSet};

        for permission in [
            serde_json::json!({
                "type": "permission", "resource": "blob",
                "accept": ["image/png transition:generic"]
            }),
            serde_json::json!({
                "type": "permission", "resource": "repo",
                "collection": ["app.evil.thing"],
                "action": ["create", "delete transition:generic"]
            }),
        ] {
            let doc = serde_json::json!({
              "lexicon": 1, "id": "app.evil.appAccess",
              "defs": {"main": {
                "type": "permission-set",
                "title": "Upload an image",
                "permissions": [permission]
              }}
            });
            let r = resolver(doc);
            let expanded = expand(Some(&r), "atproto include:app.evil.appAccess").await;

            assert!(
                !expanded
                    .split_whitespace()
                    .any(|token| token == "transition:generic"),
                "a permission set appended a grant to itself: {expanded}"
            );

            let granted = ScopesSet::from_scope_string(&expanded);
            assert!(
                granted
                    .assert_repo("app.bsky.feed.post", &RepoAction::Create)
                    .is_err(),
                "a permission set widened the grant to every collection: {expanded}"
            );
            // The rest of the grant is untouched.
            assert!(expanded.contains("atproto"), "{expanded}");
        }
    }

    /// The same defect reached through the audience instead of the record, so
    /// it needs no published lexicon of the attacker's own -- a first-party set
    /// carries it. `%20` is the whole payload.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_encoded_space_in_the_audience_grants_nothing_extra() {
        use atproto_oauth::scopes::{RepoAction, ScopesSet};

        let r = resolver(auth_create_posts());
        let expanded = expand(
            Some(&r),
            "atproto include:app.bsky.authCreatePosts\
             ?aud=did%3Aweb%3Aapi.bsky.app%20transition%3Ageneric",
        )
        .await;

        assert!(
            !expanded
                .split_whitespace()
                .any(|token| token == "transition:generic"),
            "the audience carried a second grant through expansion: {expanded}"
        );

        let granted = ScopesSet::from_scope_string(&expanded);
        assert!(
            granted
                .assert_repo("app.bsky.feed.post", &RepoAction::Create)
                .is_err(),
            "a narrow consent became a write grant on every collection: {expanded}"
        );
    }

    /// Refusing the injection must not cost a legitimate set its expansion.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_well_formed_set_still_expands_in_full() {
        use atproto_oauth::scopes::ScopesSet;

        let r = resolver(auth_create_posts());
        let expanded = expand(
            Some(&r),
            "include:app.bsky.authCreatePosts?aud=did:web:api.bsky.app%23bsky_appview",
        )
        .await;

        let granted = ScopesSet::from_scope_string(&expanded);
        granted
            .assert_rpc(
                "app.bsky.video.uploadVideo",
                "did:web:api.bsky.app#bsky_appview",
            )
            .expect("the check must still pass for an audience naming a service");
        assert!(
            expanded.contains("repo:app.bsky.feed.post?action=create"),
            "{expanded}"
        );
    }

    /// Every resource the bundled corpus declares is one this server expands.
    ///
    /// The underlying defect is structural: two lists -- what enforcement
    /// asserts and what expansion emits -- that have to agree, written in
    /// different files with nothing tying them together. It has now produced
    /// the same bug three times (space declarations, rpc, and
    /// `repo?collection=` on the parse side), and each time the only signal was
    /// a WARN in a log nobody was reading.
    ///
    /// This turns that warning into a build failure for the sets we ship. It
    /// deliberately checks only the *unknown resource* refusal: an rpc
    /// permission skipped for want of an audience is a decision, made in
    /// `rpc_scopes` and visible on the consent screen, not a gap. A new
    /// resource appearing in a vendored lexicon is the gap.
    #[test]
    fn every_bundled_permission_set_expands_completely() {
        let mut checked = 0;
        for (nsid, raw) in crate::repo::lexicon::BUNDLED_LEXICONS {
            let doc: serde_json::Value =
                serde_json::from_str(raw).expect("a bundled lexicon parses");
            let main = &doc["defs"]["main"];
            if main["type"].as_str() != Some("permission-set") {
                continue;
            }
            let Some(permissions) = main["permissions"].as_array() else {
                continue;
            };
            for perm in permissions {
                checked += 1;
                // A concrete audience, so an `inheritAud` permission is judged
                // on whether this server understands it rather than on whether
                // the caller supplied one.
                let outcome = scopes_for_permission(perm, nsid, Some("did:web:api.bsky.app"));
                if let Err(reason) = &outcome {
                    assert!(
                        !reason.contains("is not a resource this server grants"),
                        "{nsid} declares a resource expansion does not handle, so a set the \
                         holder approves grants less than the screen showed: {reason}"
                    );
                }
            }
        }
        assert!(
            checked > 0,
            "the corpus guard found no bundled permission sets, so it is asserting nothing"
        );
    }
}
