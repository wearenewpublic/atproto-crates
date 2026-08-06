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
//! `repo` and `blob` permissions. A permission naming any other resource is
//! dropped with a warning rather than guessed at: the failure from too few
//! scopes is a clear `InsufficientScope`, and the failure from inventing one
//! is a grant nobody approved.

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
        let nsid = match Scope::parse(raw) {
            Ok(Scope::Include(inc)) => inc.nsid.clone(),
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
        let expanded = permissions_from(&doc, &nsid);
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
fn permissions_from(doc: &serde_json::Value, nsid: &str) -> Vec<String> {
    let main = &doc["defs"]["main"];
    if main["type"].as_str() != Some("permission-set") {
        tracing::warn!(
            nsid = %nsid,
            found = ?main["type"].as_str(),
            "include: named a lexicon that is not a permission-set"
        );
        return Vec::new();
    }
    let Some(permissions) = main["permissions"].as_array() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for perm in permissions {
        match perm["resource"].as_str() {
            Some("repo") => out.extend(repo_scopes(perm)),
            Some("blob") => out.extend(blob_scopes(perm)),
            other => {
                // Deliberately not guessed at. See the module note.
                tracing::warn!(
                    nsid = %nsid,
                    resource = ?other,
                    "skipping a permission for a resource this server does not expand"
                );
            }
        }
    }
    out
}

/// `repo:<collection>?action=…` for each collection the permission names.
fn repo_scopes(perm: &serde_json::Value) -> Vec<String> {
    let actions = string_list(&perm["action"]);
    let collections = string_list(&perm["collection"]);
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
    out
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

    /// Without a resolver nothing is granted, rather than everything.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_resolver_grants_nothing() {
        let out = expand(None, "atproto include:app.bulleted.appAccess").await;
        assert!(!out.contains("repo:"), "{out}");
        assert!(out.contains("atproto"), "{out}");
    }
}
