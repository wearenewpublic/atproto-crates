//! AT Protocol OAuth scopes module
//!
//! This module provides comprehensive support for AT Protocol OAuth scopes,
//! including parsing, serialization, normalization, and permission checking.
//!
//! Scopes in AT Protocol follow a prefix-based format with optional query parameters:
//! - `account`: Access to account information (email, repo, status)
//! - `identity`: Access to identity information (handle)
//! - `blob`: Access to blob operations with mime type constraints
//! - `repo`: Repository operations with collection and action constraints
//! - `rpc`: RPC method access with lexicon and audience constraints
//! - `atproto`: Required scope to indicate that other AT Protocol scopes will be used
//! - `transition`: Migration operations (generic or email)
//!
//! Standard OpenID Connect scopes (no suffixes or query parameters):
//! - `openid`: Required for OpenID Connect authentication
//! - `profile`: Access to user profile information
//! - `email`: Access to user email address

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// `space:` permission scope (AT Protocol permissioned-data spaces).
pub mod space_permission;

pub use space_permission::{
    SpaceAction, SpaceCollection, SpaceCollections, SpaceDid, SpaceManageTarget, SpaceManageVerb,
    SpacePermission, SpaceSkey, SpaceTarget, SpaceType,
};

/// Represents an AT Protocol OAuth scope
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Account scope for accessing account information
    Account(AccountScope),
    /// Identity scope for accessing identity information
    Identity(IdentityScope),
    /// Blob scope for blob operations with mime type constraints
    Blob(BlobScope),
    /// Repository scope for collection operations
    Repo(RepoScope),
    /// RPC scope for method access
    Rpc(RpcScope),
    /// Space scope for permissioned-data space operations
    Space(SpacePermission),
    /// AT Protocol scope - required to indicate that other AT Protocol scopes will be used
    Atproto,
    /// Transition scope for migration operations
    Transition(TransitionScope),
    /// Include scope for referencing permission sets by NSID
    Include(IncludeScope),
    /// OpenID Connect scope - required for OpenID Connect authentication
    OpenId,
    /// Profile scope - access to user profile information
    Profile,
    /// Email scope - access to user email address
    Email,
}

/// Account scope attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountScope {
    /// The account resource type
    pub resource: AccountResource,
    /// The action permission level
    pub action: AccountAction,
}

/// Account resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountResource {
    /// Email access
    Email,
    /// Repository access
    Repo,
    /// Status access
    Status,
}

/// Account action permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountAction {
    /// Read-only access
    Read,
    /// Management access (includes read)
    Manage,
}

/// Identity scope attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityScope {
    /// Handle access
    Handle,
    /// All identity access (wildcard)
    All,
}

/// Transition scope types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransitionScope {
    /// Generic transition operations
    Generic,
    /// Email transition operations
    Email,
    /// Chat (`chat.bsky.*`) transition operations.
    ///
    /// Deliberately *not* implied by [`Generic`](Self::Generic): direct
    /// messages are carved out of the legacy blanket grant and need their own
    /// scope.
    ChatBsky,
}

/// Include scope for referencing permission sets by NSID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IncludeScope {
    /// The permission set NSID (e.g., "app.example.authFull")
    pub nsid: String,
    /// Optional audience DID for inherited RPC permissions
    pub aud: Option<String>,
}

/// Blob scope with mime type constraints
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobScope {
    /// Accepted mime types
    pub accept: BTreeSet<MimePattern>,
}

/// MIME type pattern for blob scope
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MimePattern {
    /// Match all types
    All,
    /// Match all subtypes of a type (e.g., "image/*")
    TypeWildcard(String),
    /// Exact mime type match
    Exact(String),
}

/// Repository scope with collection and action constraints
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoScope {
    /// Collections this scope covers.
    ///
    /// A set, because `collection` is multi-valued:
    /// `repo?collection=a&collection=b` names two in one scope, and
    /// `repo:a` is shorthand for `repo?collection=a`. A single field could
    /// only hold the shorthand.
    pub collections: BTreeSet<RepoCollection>,
    /// Allowed actions
    pub actions: BTreeSet<RepoAction>,
}

/// Repository collection identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RepoCollection {
    /// All collections (wildcard)
    All,
    /// Specific collection NSID
    Nsid(String),
}

/// Repository actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RepoAction {
    /// Create records
    Create,
    /// Update records
    Update,
    /// Delete records
    Delete,
}

impl RepoAction {
    /// The action's spelling in a `repo:` scope string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RepoAction::Create => "create",
            RepoAction::Update => "update",
            RepoAction::Delete => "delete",
        }
    }
}

/// RPC scope with lexicon method and audience constraints
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpcScope {
    /// Lexicon methods (NSIDs or wildcard)
    pub lxm: BTreeSet<RpcLexicon>,
    /// Audiences (DIDs or wildcard)
    pub aud: BTreeSet<RpcAudience>,
}

/// RPC lexicon identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RpcLexicon {
    /// All lexicons (wildcard)
    All,
    /// Specific lexicon NSID
    Nsid(String),
}

/// RPC audience identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RpcAudience {
    /// All audiences (wildcard)
    All,
    /// Specific DID
    Did(String),
}

impl Scope {
    /// Parse multiple space-separated scopes from a string
    ///
    /// # Examples
    /// ```
    /// # use atproto_oauth::scopes::Scope;
    /// let scopes = Scope::parse_multiple("atproto repo:*").unwrap();
    /// assert_eq!(scopes.len(), 2);
    /// ```
    pub fn parse_multiple(s: &str) -> Result<Vec<Self>, ParseError> {
        if s.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut scopes = Vec::new();
        for scope_str in s.split_whitespace() {
            scopes.push(Self::parse(scope_str)?);
        }

        Ok(scopes)
    }

    /// Parse multiple space-separated scopes and return the minimal set needed
    ///
    /// This method removes duplicate scopes and scopes that are already granted
    /// by other scopes in the list, returning only the minimal set of scopes needed.
    ///
    /// # Examples
    /// ```
    /// # use atproto_oauth::scopes::Scope;
    /// // repo:* grants repo:foo.bar, so only repo:* is kept
    /// let scopes = Scope::parse_multiple_reduced("atproto repo:foo.bar repo:*").unwrap();
    /// assert_eq!(scopes.len(), 2); // atproto and repo:*
    /// ```
    pub fn parse_multiple_reduced(s: &str) -> Result<Vec<Self>, ParseError> {
        let all_scopes = Self::parse_multiple(s)?;

        if all_scopes.is_empty() {
            return Ok(Vec::new());
        }

        let mut result: Vec<Self> = Vec::new();

        for scope in all_scopes {
            // Check if this scope is already granted by something in the result
            let mut is_granted = false;
            for existing in &result {
                if existing.grants(&scope) && existing != &scope {
                    is_granted = true;
                    break;
                }
            }

            if is_granted {
                continue; // Skip this scope, it's already covered
            }

            // Check if this scope grants any existing scopes in the result
            let mut indices_to_remove = Vec::new();
            for (i, existing) in result.iter().enumerate() {
                if scope.grants(existing) && &scope != existing {
                    indices_to_remove.push(i);
                }
            }

            // Remove scopes that are granted by the new scope (in reverse order to maintain indices)
            for i in indices_to_remove.into_iter().rev() {
                result.remove(i);
            }

            // Add the new scope if it's not a duplicate
            if !result.contains(&scope) {
                result.push(scope);
            }
        }

        Ok(result)
    }

    /// Serialize a list of scopes into a space-separated OAuth scopes string
    ///
    /// The scopes are sorted alphabetically by their string representation to ensure
    /// consistent output regardless of input order.
    ///
    /// # Examples
    /// ```
    /// # use atproto_oauth::scopes::Scope;
    /// let scopes = vec![
    ///     Scope::parse("repo:*").unwrap(),
    ///     Scope::parse("atproto").unwrap(),
    ///     Scope::parse("account:email").unwrap(),
    /// ];
    /// let result = Scope::serialize_multiple(&scopes);
    /// assert_eq!(result, "account:email atproto repo:*");
    /// ```
    pub fn serialize_multiple(scopes: &[Self]) -> String {
        if scopes.is_empty() {
            return String::new();
        }

        let mut serialized: Vec<String> = scopes.iter().map(|scope| scope.to_string()).collect();

        serialized.sort();
        serialized.join(" ")
    }

    /// Remove a scope from a list of scopes
    ///
    /// Returns a new vector with all instances of the specified scope removed.
    /// If the scope doesn't exist in the list, returns a copy of the original list.
    ///
    /// # Examples
    /// ```
    /// # use atproto_oauth::scopes::Scope;
    /// let scopes = vec![
    ///     Scope::parse("repo:*").unwrap(),
    ///     Scope::parse("atproto").unwrap(),
    ///     Scope::parse("account:email").unwrap(),
    /// ];
    /// let to_remove = Scope::parse("atproto").unwrap();
    /// let result = Scope::remove_scope(&scopes, &to_remove);
    /// assert_eq!(result.len(), 2);
    /// assert!(!result.contains(&to_remove));
    /// ```
    pub fn remove_scope(scopes: &[Self], scope_to_remove: &Self) -> Vec<Self> {
        scopes
            .iter()
            .filter(|s| *s != scope_to_remove)
            .cloned()
            .collect()
    }

    /// Parse a scope from a string
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        // Determine the prefix first by checking for known prefixes
        let prefixes = [
            "account",
            "identity",
            "blob",
            "repo",
            "rpc",
            "space",
            "atproto",
            "transition",
            "include",
            "openid",
            "profile",
            "email",
        ];
        let mut found_prefix = None;
        let mut suffix = None;

        for prefix in &prefixes {
            if let Some(remainder) = s.strip_prefix(prefix)
                && (remainder.is_empty()
                    || remainder.starts_with(':')
                    || remainder.starts_with('?'))
            {
                found_prefix = Some(*prefix);
                if let Some(stripped) = remainder.strip_prefix(':') {
                    suffix = Some(stripped);
                } else if remainder.starts_with('?') {
                    suffix = Some(remainder);
                } else {
                    suffix = None;
                }
                break;
            }
        }

        let prefix = found_prefix.ok_or_else(|| {
            // If no known prefix found, extract what looks like a prefix for error reporting
            let end = s.find(':').or_else(|| s.find('?')).unwrap_or(s.len());
            ParseError::UnknownPrefix(s[..end].to_string())
        })?;

        match prefix {
            "account" => Self::parse_account(suffix),
            "identity" => Self::parse_identity(suffix),
            "blob" => Self::parse_blob(suffix),
            "repo" => Self::parse_repo(suffix),
            "rpc" => Self::parse_rpc(suffix),
            "space" => Self::parse_space(suffix),
            "atproto" => Self::parse_atproto(suffix),
            "transition" => Self::parse_transition(suffix),
            "include" => Self::parse_include(suffix),
            "openid" => Self::parse_openid(suffix),
            "profile" => Self::parse_profile(suffix),
            "email" => Self::parse_email(suffix),
            _ => Err(ParseError::UnknownPrefix(prefix.to_string())),
        }
    }

    fn parse_account(suffix: Option<&str>) -> Result<Self, ParseError> {
        let (resource_str, params) = match suffix {
            Some(s) => {
                if let Some(pos) = s.find('?') {
                    (&s[..pos], Some(&s[pos + 1..]))
                } else {
                    (s, None)
                }
            }
            None => return Err(ParseError::MissingResource),
        };

        let resource = match resource_str {
            "email" => AccountResource::Email,
            "repo" => AccountResource::Repo,
            "status" => AccountResource::Status,
            _ => return Err(ParseError::InvalidResource(resource_str.to_string())),
        };

        let action = if let Some(params) = params {
            let parsed_params = parse_query_string(params);
            match parsed_params
                .get("action")
                .and_then(|v| v.first())
                .map(|s| s.as_str())
            {
                Some("read") => AccountAction::Read,
                Some("manage") => AccountAction::Manage,
                Some(other) => return Err(ParseError::InvalidAction(other.to_string())),
                None => AccountAction::Read,
            }
        } else {
            AccountAction::Read
        };

        Ok(Scope::Account(AccountScope { resource, action }))
    }

    fn parse_identity(suffix: Option<&str>) -> Result<Self, ParseError> {
        let scope = match suffix {
            Some("handle") => IdentityScope::Handle,
            Some("*") => IdentityScope::All,
            Some(other) => return Err(ParseError::InvalidResource(other.to_string())),
            None => return Err(ParseError::MissingResource),
        };

        Ok(Scope::Identity(scope))
    }

    fn parse_blob(suffix: Option<&str>) -> Result<Self, ParseError> {
        let mut accept = BTreeSet::new();

        match suffix {
            Some(s) if s.starts_with('?') => {
                let params = parse_query_string(&s[1..]);
                if let Some(values) = params.get("accept") {
                    for value in values {
                        accept.insert(MimePattern::from_str(value)?);
                    }
                }
            }
            Some(s) => {
                accept.insert(MimePattern::from_str(s)?);
            }
            None => {
                accept.insert(MimePattern::All);
            }
        }

        if accept.is_empty() {
            accept.insert(MimePattern::All);
        }

        Ok(Scope::Blob(BlobScope { accept }))
    }

    fn parse_repo(suffix: Option<&str>) -> Result<Self, ParseError> {
        // `collection` is the positional parameter, so `repo:foo` is shorthand
        // for `repo?collection=foo` -- and it is multi-valued, so
        // `repo?collection=a&collection=b` names both in one scope. Reading
        // only the positional form left every query-form scope granting
        // nothing: the empty string before the `?` became a collection NSID of
        // `""`, which matches no collection, and the `collection=` parameters
        // were never looked at.
        let (positional, params) = match suffix {
            // `repo?...` arrives with the `?` still attached, so the positional
            // part is empty rather than absent. Both mean "not given".
            Some(s) => match s.find('?') {
                Some(pos) => (
                    Some(&s[..pos]).filter(|p| !p.is_empty()),
                    Some(&s[pos + 1..]),
                ),
                None => (Some(s).filter(|p| !p.is_empty()), None),
            },
            None => (None, None),
        };

        let mut collections = BTreeSet::new();
        if let Some(nsid) = positional {
            collections.insert(match nsid {
                "*" => RepoCollection::All,
                other => RepoCollection::Nsid(other.to_string()),
            });
        }

        let mut actions = BTreeSet::new();
        if let Some(params) = params {
            let parsed_params = parse_query_string(params);
            if let Some(values) = parsed_params.get("collection") {
                for value in values {
                    collections.insert(match value.as_str() {
                        "*" => RepoCollection::All,
                        other => RepoCollection::Nsid(other.to_string()),
                    });
                }
            }
            if let Some(values) = parsed_params.get("action") {
                for value in values {
                    match value.as_str() {
                        "create" => {
                            actions.insert(RepoAction::Create);
                        }
                        "update" => {
                            actions.insert(RepoAction::Update);
                        }
                        "delete" => {
                            actions.insert(RepoAction::Delete);
                        }
                        "*" => {
                            actions.insert(RepoAction::Create);
                            actions.insert(RepoAction::Update);
                            actions.insert(RepoAction::Delete);
                        }
                        other => return Err(ParseError::InvalidAction(other.to_string())),
                    }
                }
            }
        }

        // Naming no collection at all means every collection, which is how a
        // bare `repo` scope has always parsed.
        if collections.is_empty() {
            collections.insert(RepoCollection::All);
        }
        if actions.is_empty() {
            actions.insert(RepoAction::Create);
            actions.insert(RepoAction::Update);
            actions.insert(RepoAction::Delete);
        }

        Ok(Scope::Repo(RepoScope {
            collections,
            actions,
        }))
    }

    fn parse_rpc(suffix: Option<&str>) -> Result<Self, ParseError> {
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();

        match suffix {
            Some("*") => {
                lxm.insert(RpcLexicon::All);
                aud.insert(RpcAudience::All);
            }
            Some(s) if s.starts_with('?') => {
                let params = parse_query_string(&s[1..]);

                if let Some(values) = params.get("lxm") {
                    for value in values {
                        if value == "*" {
                            lxm.insert(RpcLexicon::All);
                        } else {
                            lxm.insert(RpcLexicon::Nsid(value.to_string()));
                        }
                    }
                }

                if let Some(values) = params.get("aud") {
                    for value in values {
                        if value == "*" {
                            aud.insert(RpcAudience::All);
                        } else {
                            aud.insert(RpcAudience::Did(value.to_string()));
                        }
                    }
                }
            }
            Some(s) => {
                // Check if there's a query string in the suffix
                if let Some(pos) = s.find('?') {
                    let nsid = &s[..pos];
                    let params = parse_query_string(&s[pos + 1..]);

                    lxm.insert(RpcLexicon::Nsid(nsid.to_string()));

                    if let Some(values) = params.get("aud") {
                        for value in values {
                            if value == "*" {
                                aud.insert(RpcAudience::All);
                            } else {
                                aud.insert(RpcAudience::Did(value.to_string()));
                            }
                        }
                    }
                } else {
                    lxm.insert(RpcLexicon::Nsid(s.to_string()));
                }
            }
            None => {}
        }

        if lxm.is_empty() {
            lxm.insert(RpcLexicon::All);
        }
        if aud.is_empty() {
            aud.insert(RpcAudience::All);
        }

        Ok(Scope::Rpc(RpcScope { lxm, aud }))
    }

    fn parse_space(suffix: Option<&str>) -> Result<Self, ParseError> {
        Ok(Scope::Space(SpacePermission::parse_suffix(suffix)?))
    }

    fn parse_atproto(suffix: Option<&str>) -> Result<Self, ParseError> {
        if suffix.is_some() {
            return Err(ParseError::InvalidResource(
                "atproto scope does not accept suffixes".to_string(),
            ));
        }
        Ok(Scope::Atproto)
    }

    fn parse_transition(suffix: Option<&str>) -> Result<Self, ParseError> {
        let scope = match suffix {
            Some("generic") => TransitionScope::Generic,
            Some("email") => TransitionScope::Email,
            Some("chat.bsky") => TransitionScope::ChatBsky,
            Some(other) => return Err(ParseError::InvalidResource(other.to_string())),
            None => return Err(ParseError::MissingResource),
        };

        Ok(Scope::Transition(scope))
    }

    fn parse_include(suffix: Option<&str>) -> Result<Self, ParseError> {
        let (nsid, params) = match suffix {
            Some(s) => {
                if let Some(pos) = s.find('?') {
                    (&s[..pos], Some(&s[pos + 1..]))
                } else {
                    (s, None)
                }
            }
            None => return Err(ParseError::MissingResource),
        };

        if nsid.is_empty() {
            return Err(ParseError::MissingResource);
        }

        let aud = if let Some(params) = params {
            let parsed_params = parse_query_string(params);
            parsed_params
                .get("aud")
                .and_then(|v| v.first())
                .map(|s| url_decode(s))
        } else {
            None
        };

        Ok(Scope::Include(IncludeScope {
            nsid: nsid.to_string(),
            aud,
        }))
    }

    fn parse_openid(suffix: Option<&str>) -> Result<Self, ParseError> {
        if suffix.is_some() {
            return Err(ParseError::InvalidResource(
                "openid scope does not accept suffixes".to_string(),
            ));
        }
        Ok(Scope::OpenId)
    }

    fn parse_profile(suffix: Option<&str>) -> Result<Self, ParseError> {
        if suffix.is_some() {
            return Err(ParseError::InvalidResource(
                "profile scope does not accept suffixes".to_string(),
            ));
        }
        Ok(Scope::Profile)
    }

    fn parse_email(suffix: Option<&str>) -> Result<Self, ParseError> {
        if suffix.is_some() {
            return Err(ParseError::InvalidResource(
                "email scope does not accept suffixes".to_string(),
            ));
        }
        Ok(Scope::Email)
    }

    /// Convert the scope to its normalized string representation
    pub fn to_string_normalized(&self) -> String {
        match self {
            Scope::Account(scope) => {
                let resource = match scope.resource {
                    AccountResource::Email => "email",
                    AccountResource::Repo => "repo",
                    AccountResource::Status => "status",
                };

                match scope.action {
                    AccountAction::Read => format!("account:{}", resource),
                    AccountAction::Manage => format!("account:{}?action=manage", resource),
                }
            }
            Scope::Identity(scope) => match scope {
                IdentityScope::Handle => "identity:handle".to_string(),
                IdentityScope::All => "identity:*".to_string(),
            },
            Scope::Blob(scope) => {
                if scope.accept.len() == 1
                    && let Some(pattern) = scope.accept.iter().next()
                {
                    match pattern {
                        MimePattern::All => "blob:*/*".to_string(),
                        MimePattern::TypeWildcard(t) => format!("blob:{}/*", t),
                        MimePattern::Exact(mime) => format!("blob:{}", mime),
                    }
                } else {
                    let mut params = Vec::new();
                    for pattern in &scope.accept {
                        match pattern {
                            MimePattern::All => params.push("accept=*/*".to_string()),
                            MimePattern::TypeWildcard(t) => params.push(format!("accept={}/*", t)),
                            MimePattern::Exact(mime) => params.push(format!("accept={}", mime)),
                        }
                    }
                    params.sort();
                    format!("blob?{}", params.join("&"))
                }
            }
            Scope::Repo(scope) => {
                let name = |c: &RepoCollection| match c {
                    RepoCollection::All => "*".to_string(),
                    RepoCollection::Nsid(nsid) => nsid.clone(),
                };

                let mut params = Vec::new();
                // One collection keeps the positional shorthand, which is what
                // every existing scope string looks like; more than one has to
                // use the query form, since the shorthand cannot express them.
                let single = if scope.collections.len() == 1 {
                    scope.collections.iter().next().map(name)
                } else {
                    for collection in &scope.collections {
                        params.push(format!("collection={}", name(collection)));
                    }
                    None
                };

                if scope.actions.len() < 3 {
                    for action in &scope.actions {
                        params.push(
                            match action {
                                RepoAction::Create => "action=create",
                                RepoAction::Update => "action=update",
                                RepoAction::Delete => "action=delete",
                            }
                            .to_string(),
                        );
                    }
                }

                match (single, params.is_empty()) {
                    (Some(collection), true) => format!("repo:{collection}"),
                    (Some(collection), false) => format!("repo:{collection}?{}", params.join("&")),
                    (None, true) => "repo".to_string(),
                    (None, false) => format!("repo?{}", params.join("&")),
                }
            }
            Scope::Rpc(scope) => {
                if scope.lxm.len() == 1
                    && scope.lxm.contains(&RpcLexicon::All)
                    && scope.aud.len() == 1
                    && scope.aud.contains(&RpcAudience::All)
                {
                    "rpc:*".to_string()
                } else if scope.lxm.len() == 1
                    && scope.aud.len() == 1
                    && scope.aud.contains(&RpcAudience::All)
                    && let Some(lxm) = scope.lxm.iter().next()
                {
                    match lxm {
                        RpcLexicon::All => "rpc:*".to_string(),
                        RpcLexicon::Nsid(nsid) => format!("rpc:{}?aud=*", nsid),
                    }
                } else if scope.lxm.len() == 1 && scope.aud.len() == 1 {
                    // Single lxm and single aud (aud is not All, handled above)
                    if let (Some(lxm), Some(aud)) =
                        (scope.lxm.iter().next(), scope.aud.iter().next())
                    {
                        match (lxm, aud) {
                            (RpcLexicon::Nsid(nsid), RpcAudience::Did(did)) => {
                                format!("rpc:{}?aud={}", nsid, did)
                            }
                            (RpcLexicon::All, RpcAudience::Did(did)) => {
                                format!("rpc:*?aud={}", did)
                            }
                            _ => "rpc:*".to_string(),
                        }
                    } else {
                        "rpc:*".to_string()
                    }
                } else {
                    let mut params = Vec::new();

                    for lxm in &scope.lxm {
                        match lxm {
                            RpcLexicon::All => params.push("lxm=*".to_string()),
                            RpcLexicon::Nsid(nsid) => params.push(format!("lxm={}", nsid)),
                        }
                    }

                    for aud in &scope.aud {
                        match aud {
                            RpcAudience::All => params.push("aud=*".to_string()),
                            RpcAudience::Did(did) => params.push(format!("aud={}", did)),
                        }
                    }

                    params.sort();

                    if params.is_empty() {
                        "rpc:*".to_string()
                    } else {
                        format!("rpc?{}", params.join("&"))
                    }
                }
            }
            Scope::Space(scope) => scope.to_scope_string(),
            Scope::Atproto => "atproto".to_string(),
            Scope::Transition(scope) => match scope {
                TransitionScope::Generic => "transition:generic".to_string(),
                TransitionScope::Email => "transition:email".to_string(),
                TransitionScope::ChatBsky => "transition:chat.bsky".to_string(),
            },
            Scope::Include(scope) => {
                if let Some(ref aud) = scope.aud {
                    format!("include:{}?aud={}", scope.nsid, url_encode(aud))
                } else {
                    format!("include:{}", scope.nsid)
                }
            }
            Scope::OpenId => "openid".to_string(),
            Scope::Profile => "profile".to_string(),
            Scope::Email => "email".to_string(),
        }
    }

    /// Check if this scope grants the permissions of another scope
    pub fn grants(&self, other: &Scope) -> bool {
        match (self, other) {
            // Atproto only grants itself (it's a required scope, not a permission grant)
            (Scope::Atproto, Scope::Atproto) => true,
            (Scope::Atproto, _) => false,
            // Nothing else grants atproto
            (_, Scope::Atproto) => false,
            // Transition scopes only grant themselves
            (Scope::Transition(a), Scope::Transition(b)) => a == b,
            // Other scopes don't grant transition scopes
            (_, Scope::Transition(_)) => false,
            (Scope::Transition(_), _) => false,
            // Include scopes only grant themselves (exact match including aud)
            (Scope::Include(a), Scope::Include(b)) => a == b,
            // Other scopes don't grant include scopes
            (_, Scope::Include(_)) => false,
            (Scope::Include(_), _) => false,
            // OpenID Connect scopes only grant themselves
            (Scope::OpenId, Scope::OpenId) => true,
            (Scope::OpenId, _) => false,
            (_, Scope::OpenId) => false,
            (Scope::Profile, Scope::Profile) => true,
            (Scope::Profile, _) => false,
            (_, Scope::Profile) => false,
            (Scope::Email, Scope::Email) => true,
            (Scope::Email, _) => false,
            (_, Scope::Email) => false,
            (Scope::Account(a), Scope::Account(b)) => {
                a.resource == b.resource
                    && matches!(
                        (a.action, b.action),
                        (AccountAction::Manage, _) | (AccountAction::Read, AccountAction::Read)
                    )
            }
            (Scope::Identity(a), Scope::Identity(b)) => matches!(
                (a, b),
                (IdentityScope::All, _) | (IdentityScope::Handle, IdentityScope::Handle)
            ),
            (Scope::Blob(a), Scope::Blob(b)) => {
                for b_pattern in &b.accept {
                    let mut granted = false;
                    for a_pattern in &a.accept {
                        if a_pattern.grants(b_pattern) {
                            granted = true;
                            break;
                        }
                    }
                    if !granted {
                        return false;
                    }
                }
                true
            }
            (Scope::Repo(a), Scope::Repo(b)) => {
                // `a` covers `b` only if every collection `b` names is one `a`
                // already grants -- a scope naming two collections is not
                // covered by one naming a single member of that pair.
                let collection_match = a.collections.contains(&RepoCollection::All)
                    || b.collections
                        .iter()
                        .all(|wanted| a.collections.contains(wanted));

                if !collection_match {
                    return false;
                }

                b.actions.is_subset(&a.actions) || a.actions.len() == 3
            }
            (Scope::Rpc(a), Scope::Rpc(b)) => {
                let lxm_match = if a.lxm.contains(&RpcLexicon::All) {
                    true
                } else {
                    b.lxm.iter().all(|b_lxm| match b_lxm {
                        RpcLexicon::All => false,
                        RpcLexicon::Nsid(_) => a.lxm.contains(b_lxm),
                    })
                };

                let aud_match = if a.aud.contains(&RpcAudience::All) {
                    true
                } else {
                    b.aud.iter().all(|b_aud| match b_aud {
                        RpcAudience::All => false,
                        RpcAudience::Did(_) => a.aud.contains(b_aud),
                    })
                };

                lxm_match && aud_match
            }
            // Space scopes only grant themselves (exact match). Subset-based
            // reduction is intentionally not performed for spaces; this keeps
            // `parse_multiple_reduced` sound (it never drops a distinct grant).
            (Scope::Space(a), Scope::Space(b)) => a == b,
            _ => false,
        }
    }
}

impl MimePattern {
    fn grants(&self, other: &MimePattern) -> bool {
        match (self, other) {
            (MimePattern::All, _) => true,
            (MimePattern::TypeWildcard(a_type), MimePattern::TypeWildcard(b_type)) => {
                a_type == b_type
            }
            (MimePattern::TypeWildcard(a_type), MimePattern::Exact(b_mime)) => {
                b_mime.starts_with(&format!("{}/", a_type))
            }
            (MimePattern::Exact(a), MimePattern::Exact(b)) => a == b,
            _ => false,
        }
    }
}

impl FromStr for MimePattern {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*/*" {
            Ok(MimePattern::All)
        } else if let Some(stripped) = s.strip_suffix("/*") {
            Ok(MimePattern::TypeWildcard(stripped.to_string()))
        } else if s.contains('/') {
            Ok(MimePattern::Exact(s.to_string()))
        } else {
            Err(ParseError::InvalidMimeType(s.to_string()))
        }
    }
}

impl FromStr for Scope {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_normalized())
    }
}

/// Parse a query string into a map of keys to lists of values
fn parse_query_string(query: &str) -> BTreeMap<String, Vec<String>> {
    let mut params = BTreeMap::new();

    for pair in query.split('&') {
        if let Some(pos) = pair.find('=') {
            let key = &pair[..pos];
            let value = &pair[pos + 1..];
            params
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }
    }

    params
}

/// Decode a percent-encoded string
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
            {
                result.push(byte as char);
                continue;
            }
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(c);
        }
    }

    result
}

/// Encode a string for use in a URL query parameter
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);

    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | ':' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }

    result
}

/// Error type for scope parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Unknown scope prefix
    UnknownPrefix(String),
    /// Missing required resource
    MissingResource,
    /// Invalid resource type
    InvalidResource(String),
    /// Invalid action type
    InvalidAction(String),
    /// Invalid MIME type
    InvalidMimeType(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnknownPrefix(prefix) => write!(f, "Unknown scope prefix: {}", prefix),
            ParseError::MissingResource => write!(f, "Missing required resource"),
            ParseError::InvalidResource(resource) => write!(f, "Invalid resource: {}", resource),
            ParseError::InvalidAction(action) => write!(f, "Invalid action: {}", action),
            ParseError::InvalidMimeType(mime) => write!(f, "Invalid MIME type: {}", mime),
        }
    }
}

impl std::error::Error for ParseError {}

/// A set of granted OAuth scopes that can be queried for permission matches.
///
/// Mirrors the reference `ScopesSet` / `ScopePermissions`: it stores the raw
/// granted scope strings and, on demand, parses the ones relevant to a given
/// resource to evaluate whether a request is allowed.
///
/// Scope strings that fail to parse are ignored during matching (they simply
/// cannot grant anything), matching the reference where `fromString` returning
/// `null` means the scope does not contribute to a match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopesSet {
    scopes: Vec<String>,
    /// The DID these grants were issued to, used to resolve a `self`
    /// authority in a `space:` scope.
    ///
    /// The subject belongs to the token, not to each question asked of it, so
    /// it is bound once here rather than threaded through every `allows_*`
    /// call. `None` means the caller did not say, and a `self` grant then
    /// matches nothing.
    subject: Option<String>,
}

impl ScopesSet {
    /// Create an empty scope set.
    pub fn new() -> Self {
        ScopesSet::default()
    }

    /// Build a scope set from a space-separated OAuth scope string.
    ///
    /// **The result cannot resolve a `self` authority.** `space:` grants
    /// default to `authority=self`, so a set built this way matches no space
    /// at all unless the grant names its authority explicitly. Prefer
    /// [`from_scope_string_for`](Self::from_scope_string_for), which supplies
    /// the DID the token was issued to.
    ///
    /// Kept for callers that genuinely have no subject — scope-string
    /// round-trips, consent-screen rendering — where failing closed is right.
    pub fn from_scope_string(scope: &str) -> Self {
        ScopesSet {
            scopes: scope.split_whitespace().map(|s| s.to_string()).collect(),
            subject: None,
        }
    }

    /// Build a scope set from a scope string, bound to the DID it was issued
    /// to.
    ///
    /// `subject` is what `authority=self` resolves to — the default for every
    /// `space:` grant that does not name an authority.
    pub fn from_scope_string_for(scope: &str, subject: impl Into<String>) -> Self {
        ScopesSet {
            scopes: scope.split_whitespace().map(|s| s.to_string()).collect(),
            subject: Some(subject.into()),
        }
    }

    /// Bind this set to the DID its grants were issued to.
    ///
    /// Chainable form of [`from_scope_string_for`](Self::from_scope_string_for),
    /// for sets assembled from individual scopes.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// The DID `authority=self` resolves against, if the set was built with
    /// one.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Build a scope set from an iterator of individual scope strings.
    pub fn from_scopes<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ScopesSet {
            scopes: scopes.into_iter().map(Into::into).collect(),
            subject: None,
        }
    }

    /// Add a scope string to the set.
    pub fn insert(&mut self, scope: impl Into<String>) {
        self.scopes.push(scope.into());
    }

    /// The raw granted scope strings.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether a legacy `transition:generic` grant is present.
    ///
    /// `transition:generic` is the migration scope meaning "legacy full
    /// access": it predates granular scopes and is what most AT Protocol OAuth
    /// clients request today. Enforcing the granular axes without honouring it
    /// would refuse every such client, so it satisfies the repo, blob, rpc and
    /// identity assertions below.
    ///
    /// It is deliberately *not* a wildcard for `space:` — spaces post-date it,
    /// so nothing granted it expecting space access.
    /// Whether `transition:chat.bsky` was granted — the only scope that
    /// confers `chat.bsky.*` RPC access.
    fn has_legacy_chat(&self) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(
                Scope::parse(scope),
                Ok(Scope::Transition(TransitionScope::ChatBsky))
            )
        })
    }

    fn has_legacy_generic(&self) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(
                Scope::parse(scope),
                Ok(Scope::Transition(TransitionScope::Generic))
            )
        })
    }

    /// Returns `true` if some granted `repo:` scope permits `action` on
    /// `collection`.
    pub fn allows_repo(&self, collection: &str, action: &RepoAction) -> bool {
        self.has_legacy_generic()
            || self.scopes.iter().any(|scope| match Scope::parse(scope) {
                Ok(Scope::Repo(repo)) => {
                    let collection_ok = repo.collections.iter().any(|granted| match granted {
                        RepoCollection::All => true,
                        RepoCollection::Nsid(nsid) => nsid == collection,
                    });
                    collection_ok && repo.actions.contains(action)
                }
                _ => false,
            })
    }

    /// Asserts that some granted `repo:` scope permits `action` on
    /// `collection`.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// the minimal scope that would have satisfied the write, so a client can
    /// act on the refusal rather than guess.
    pub fn assert_repo(
        &self,
        collection: &str,
        action: &RepoAction,
    ) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_repo(collection, action) {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(format!(
                "repo:{collection}?action={}",
                action.as_str()
            )))
        }
    }

    /// Returns `true` if some granted `blob:` scope accepts `mime`.
    pub fn allows_blob(&self, mime: &str) -> bool {
        let Ok(requested) = MimePattern::from_str(mime) else {
            return false;
        };
        self.has_legacy_generic()
            || self.scopes.iter().any(|scope| match Scope::parse(scope) {
                Ok(Scope::Blob(blob)) => {
                    blob.accept.iter().any(|pattern| pattern.grants(&requested))
                }
                _ => false,
            })
    }

    /// Asserts that some granted `blob:` scope accepts `mime`.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// the minimal scope that would have satisfied the upload.
    pub fn assert_blob(&self, mime: &str) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_blob(mime) {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(format!(
                "blob:{mime}"
            )))
        }
    }

    /// Returns `true` if some granted `rpc:` scope permits calling `lxm` at
    /// `aud`.
    pub fn allows_rpc(&self, lxm: &str, aud: &str) -> bool {
        let is_chat = lxm.starts_with("chat.bsky.");

        // `transition:generic` is the legacy blanket grant, but chat is carved
        // out of it: direct messages need `transition:chat.bsky`. A request for
        // the `*` wildcard is still satisfied by `generic` alone — asking for
        // "whatever this token has" is not the same as asking for chat.
        if self.has_legacy_generic() && (lxm == "*" || !is_chat) {
            return true;
        }
        if is_chat && self.has_legacy_chat() {
            return true;
        }

        self.scopes.iter().any(|scope| match Scope::parse(scope) {
            Ok(Scope::Rpc(rpc)) => {
                let lxm_ok = rpc.lxm.iter().any(|granted| match granted {
                    RpcLexicon::All => true,
                    RpcLexicon::Nsid(nsid) => nsid == lxm,
                });
                let aud_ok = rpc.aud.iter().any(|granted| match granted {
                    RpcAudience::All => true,
                    RpcAudience::Did(did) => did == aud,
                });
                lxm_ok && aud_ok
            }
            _ => false,
        })
    }

    /// Asserts that some granted `rpc:` scope permits calling `lxm` at `aud`.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// the minimal scope that would have satisfied the call.
    pub fn assert_rpc(&self, lxm: &str, aud: &str) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_rpc(lxm, aud) {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(format!(
                "rpc:{lxm}?aud={aud}"
            )))
        }
    }

    /// Returns `true` if `identity:*` was granted.
    ///
    /// Distinct from [`allows_identity_handle`](Self::allows_identity_handle):
    /// signing or submitting a PLC operation can rewrite rotation keys and
    /// verification methods, not just the handle, so `identity:handle` is not
    /// enough. `transition:generic` confers nothing here — see
    /// [`allows_identity_handle`](Self::allows_identity_handle).
    pub fn allows_identity_all(&self) -> bool {
        self.scopes
            .iter()
            .any(|scope| matches!(Scope::parse(scope), Ok(Scope::Identity(IdentityScope::All))))
    }

    /// Asserts that `identity:*` was granted.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// `identity:*`.
    pub fn assert_identity_all(&self) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_identity_all() {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new("identity:*"))
        }
    }

    /// Returns `true` if some granted `account:` scope permits *managing* the
    /// email address, as opposed to reading it.
    ///
    /// `transition:email` grants read only, matching the reference — it is the
    /// legacy scope for surfacing the address, not for changing what it is or
    /// triggering mail to it.
    pub fn allows_account_email_manage(&self) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(
                Scope::parse(scope),
                Ok(Scope::Account(AccountScope {
                    resource: AccountResource::Email,
                    action: AccountAction::Manage,
                }))
            )
        })
    }

    /// Asserts that some granted `account:` scope permits managing the email
    /// address.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// `account:email?action=manage`.
    pub fn assert_account_email_manage(&self) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_account_email_manage() {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(
                "account:email?action=manage",
            ))
        }
    }

    /// Returns `true` if some granted `identity:` scope permits changing the
    /// account handle.
    /// `transition:generic` deliberately does **not** satisfy this. The legacy
    /// blanket covers repo, blob and non-chat RPC; identity is outside it, so
    /// rotating a handle needs `identity:handle` or `identity:*` explicitly.
    /// Treating the blanket as covering identity let every client holding the
    /// standard legacy scope change the account's handle in PLC.
    pub fn allows_identity_handle(&self) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(
                Scope::parse(scope),
                Ok(Scope::Identity(IdentityScope::Handle | IdentityScope::All))
            )
        })
    }

    /// Asserts that some granted `identity:` scope permits changing the handle.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeMissingError`](crate::errors::ScopeMissingError) naming
    /// the minimal scope that would have satisfied the change.
    pub fn assert_identity_handle(&self) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_identity_handle() {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new("identity:handle"))
        }
    }

    /// Returns `true` if any granted `space:` scope satisfies the given record
    /// target. An omitted-`collection` grant confers no write targets (the
    /// `spaceType=*` / no-declaration case); use
    /// [`allows_space_with`](Self::allows_space_with) to resolve the collection
    /// default against a space type declaration's collections.
    pub fn allows_space(&self, target: &SpaceTarget) -> bool {
        self.allows_space_with(target, &[])
    }

    /// Like [`allows_space`](Self::allows_space) but resolves the per-grant
    /// `collection` default against `declared` (the space type declaration's
    /// `collections`) per spec line 413.
    pub fn allows_space_with(&self, target: &SpaceTarget, declared: &[String]) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(Scope::parse(scope), Ok(Scope::Space(permission)) if permission.matches_with(target, declared, self.subject()))
        })
    }

    /// Returns `true` if any granted `space:` scope satisfies the given
    /// space-management target (spec lines 415-419).
    pub fn allows_space_manage(&self, target: &SpaceManageTarget) -> bool {
        self.scopes.iter().any(|scope| {
            matches!(Scope::parse(scope), Ok(Scope::Space(permission)) if permission.matches_manage(target, self.subject()))
        })
    }

    /// Asserts that some granted `space:` scope satisfies the given record
    /// target, returning a [`ScopeMissingError`](crate::errors::ScopeMissingError)
    /// carrying the minimal scope that would satisfy it otherwise.
    pub fn assert_space(
        &self,
        target: &SpaceTarget,
    ) -> Result<(), crate::errors::ScopeMissingError> {
        self.assert_space_with(target, &[])
    }

    /// Like [`assert_space`](Self::assert_space) but resolves the collection
    /// default against `declared` (spec line 413).
    pub fn assert_space_with(
        &self,
        target: &SpaceTarget,
        declared: &[String],
    ) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_space_with(target, declared) {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(
                SpacePermission::scope_needed_for(target),
            ))
        }
    }

    /// Asserts that some granted `space:` scope satisfies the given
    /// space-management target (spec lines 415-419).
    pub fn assert_space_manage(
        &self,
        target: &SpaceManageTarget,
    ) -> Result<(), crate::errors::ScopeMissingError> {
        if self.allows_space_manage(target) {
            Ok(())
        } else {
            Err(crate::errors::ScopeMissingError::new(
                SpacePermission::scope_needed_for_manage(target),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_scope_parsing() {
        let scope = Scope::parse("account:email").unwrap();
        assert_eq!(
            scope,
            Scope::Account(AccountScope {
                resource: AccountResource::Email,
                action: AccountAction::Read,
            })
        );

        let scope = Scope::parse("account:repo?action=manage").unwrap();
        assert_eq!(
            scope,
            Scope::Account(AccountScope {
                resource: AccountResource::Repo,
                action: AccountAction::Manage,
            })
        );

        let scope = Scope::parse("account:status?action=read").unwrap();
        assert_eq!(
            scope,
            Scope::Account(AccountScope {
                resource: AccountResource::Status,
                action: AccountAction::Read,
            })
        );
    }

    #[test]
    fn test_identity_scope_parsing() {
        let scope = Scope::parse("identity:handle").unwrap();
        assert_eq!(scope, Scope::Identity(IdentityScope::Handle));

        let scope = Scope::parse("identity:*").unwrap();
        assert_eq!(scope, Scope::Identity(IdentityScope::All));
    }

    #[test]
    fn test_blob_scope_parsing() {
        let scope = Scope::parse("blob:*/*").unwrap();
        let mut accept = BTreeSet::new();
        accept.insert(MimePattern::All);
        assert_eq!(scope, Scope::Blob(BlobScope { accept }));

        let scope = Scope::parse("blob:image/png").unwrap();
        let mut accept = BTreeSet::new();
        accept.insert(MimePattern::Exact("image/png".to_string()));
        assert_eq!(scope, Scope::Blob(BlobScope { accept }));

        let scope = Scope::parse("blob?accept=image/png&accept=image/jpeg").unwrap();
        let mut accept = BTreeSet::new();
        accept.insert(MimePattern::Exact("image/png".to_string()));
        accept.insert(MimePattern::Exact("image/jpeg".to_string()));
        assert_eq!(scope, Scope::Blob(BlobScope { accept }));

        let scope = Scope::parse("blob:image/*").unwrap();
        let mut accept = BTreeSet::new();
        accept.insert(MimePattern::TypeWildcard("image".to_string()));
        assert_eq!(scope, Scope::Blob(BlobScope { accept }));
    }

    #[test]
    fn test_repo_scope_parsing() {
        let scope = Scope::parse("repo:*?action=create").unwrap();
        let mut actions = BTreeSet::new();
        actions.insert(RepoAction::Create);
        assert_eq!(
            scope,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::All]),
                actions,
            })
        );

        let scope = Scope::parse("repo:foo.bar?action=create&action=update").unwrap();
        let mut actions = BTreeSet::new();
        actions.insert(RepoAction::Create);
        actions.insert(RepoAction::Update);
        assert_eq!(
            scope,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("foo.bar".to_string())]),
                actions,
            })
        );

        let scope = Scope::parse("repo:foo.bar").unwrap();
        let mut actions = BTreeSet::new();
        actions.insert(RepoAction::Create);
        actions.insert(RepoAction::Update);
        actions.insert(RepoAction::Delete);
        assert_eq!(
            scope,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("foo.bar".to_string())]),
                actions,
            })
        );
    }

    #[test]
    fn test_rpc_scope_parsing() {
        let scope = Scope::parse("rpc:*").unwrap();
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();
        lxm.insert(RpcLexicon::All);
        aud.insert(RpcAudience::All);
        assert_eq!(scope, Scope::Rpc(RpcScope { lxm, aud }));

        let scope = Scope::parse("rpc:com.example.service").unwrap();
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();
        lxm.insert(RpcLexicon::Nsid("com.example.service".to_string()));
        aud.insert(RpcAudience::All);
        assert_eq!(scope, Scope::Rpc(RpcScope { lxm, aud }));

        let scope = Scope::parse("rpc:com.example.service?aud=did:example:123").unwrap();
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();
        lxm.insert(RpcLexicon::Nsid("com.example.service".to_string()));
        aud.insert(RpcAudience::Did("did:example:123".to_string()));
        assert_eq!(scope, Scope::Rpc(RpcScope { lxm, aud }));

        let scope =
            Scope::parse("rpc?lxm=com.example.method1&lxm=com.example.method2&aud=did:example:123")
                .unwrap();
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();
        lxm.insert(RpcLexicon::Nsid("com.example.method1".to_string()));
        lxm.insert(RpcLexicon::Nsid("com.example.method2".to_string()));
        aud.insert(RpcAudience::Did("did:example:123".to_string()));
        assert_eq!(scope, Scope::Rpc(RpcScope { lxm, aud }));
    }

    #[test]
    fn test_scope_normalization() {
        let tests = vec![
            ("account:email", "account:email"),
            ("account:email?action=read", "account:email"),
            ("account:email?action=manage", "account:email?action=manage"),
            ("blob:image/png", "blob:image/png"),
            (
                "blob?accept=image/jpeg&accept=image/png",
                "blob?accept=image/jpeg&accept=image/png",
            ),
            ("repo:foo.bar", "repo:foo.bar"),
            ("repo:foo.bar?action=create", "repo:foo.bar?action=create"),
            ("rpc:*", "rpc:*"),
            ("rpc:com.example.service", "rpc:com.example.service?aud=*"),
            (
                "rpc:com.example.service?aud=did:example:123",
                "rpc:com.example.service?aud=did:example:123",
            ),
        ];

        for (input, expected) in tests {
            let scope = Scope::parse(input).unwrap();
            assert_eq!(scope.to_string_normalized(), expected);
        }
    }

    #[test]
    fn test_account_scope_grants() {
        let manage = Scope::parse("account:email?action=manage").unwrap();
        let read = Scope::parse("account:email?action=read").unwrap();
        let other_read = Scope::parse("account:repo?action=read").unwrap();

        assert!(manage.grants(&read));
        assert!(manage.grants(&manage));
        assert!(!read.grants(&manage));
        assert!(read.grants(&read));
        assert!(!read.grants(&other_read));
    }

    #[test]
    fn test_identity_scope_grants() {
        let all = Scope::parse("identity:*").unwrap();
        let handle = Scope::parse("identity:handle").unwrap();

        assert!(all.grants(&handle));
        assert!(all.grants(&all));
        assert!(!handle.grants(&all));
        assert!(handle.grants(&handle));
    }

    #[test]
    fn test_blob_scope_grants() {
        let all = Scope::parse("blob:*/*").unwrap();
        let image_all = Scope::parse("blob:image/*").unwrap();
        let image_png = Scope::parse("blob:image/png").unwrap();
        let text_plain = Scope::parse("blob:text/plain").unwrap();

        assert!(all.grants(&image_all));
        assert!(all.grants(&image_png));
        assert!(all.grants(&text_plain));
        assert!(image_all.grants(&image_png));
        assert!(!image_all.grants(&text_plain));
        assert!(!image_png.grants(&image_all));
    }

    #[test]
    fn test_repo_scope_grants() {
        let all_all = Scope::parse("repo:*").unwrap();
        let all_create = Scope::parse("repo:*?action=create").unwrap();
        let specific_all = Scope::parse("repo:foo.bar").unwrap();
        let specific_create = Scope::parse("repo:foo.bar?action=create").unwrap();
        let other_create = Scope::parse("repo:baz.qux?action=create").unwrap();

        assert!(all_all.grants(&all_create));
        assert!(all_all.grants(&specific_all));
        assert!(all_all.grants(&specific_create));
        assert!(all_create.grants(&all_create));
        assert!(!all_create.grants(&specific_all));
        assert!(specific_all.grants(&specific_create));
        assert!(!specific_create.grants(&specific_all));
        assert!(!specific_create.grants(&other_create));
    }

    #[test]
    fn test_rpc_scope_grants() {
        let all = Scope::parse("rpc:*").unwrap();
        let specific_lxm = Scope::parse("rpc:com.example.service").unwrap();
        let specific_both = Scope::parse("rpc:com.example.service?aud=did:example:123").unwrap();

        assert!(all.grants(&specific_lxm));
        assert!(all.grants(&specific_both));
        assert!(specific_lxm.grants(&specific_both));
        assert!(!specific_both.grants(&specific_lxm));
        assert!(!specific_both.grants(&all));
    }

    #[test]
    fn test_cross_scope_grants() {
        let account = Scope::parse("account:email").unwrap();
        let identity = Scope::parse("identity:handle").unwrap();

        assert!(!account.grants(&identity));
        assert!(!identity.grants(&account));
    }

    #[test]
    fn test_parse_errors() {
        assert!(matches!(
            Scope::parse("unknown:test"),
            Err(ParseError::UnknownPrefix(_))
        ));

        assert!(matches!(
            Scope::parse("account"),
            Err(ParseError::MissingResource)
        ));

        assert!(matches!(
            Scope::parse("account:invalid"),
            Err(ParseError::InvalidResource(_))
        ));

        assert!(matches!(
            Scope::parse("account:email?action=invalid"),
            Err(ParseError::InvalidAction(_))
        ));
    }

    #[test]
    fn test_query_parameter_sorting() {
        let scope =
            Scope::parse("blob?accept=image/png&accept=application/pdf&accept=image/jpeg").unwrap();
        let normalized = scope.to_string_normalized();
        assert!(normalized.contains("accept=application/pdf"));
        assert!(normalized.contains("accept=image/jpeg"));
        assert!(normalized.contains("accept=image/png"));
        let pdf_pos = normalized.find("accept=application/pdf").unwrap();
        let jpeg_pos = normalized.find("accept=image/jpeg").unwrap();
        let png_pos = normalized.find("accept=image/png").unwrap();
        assert!(pdf_pos < jpeg_pos);
        assert!(jpeg_pos < png_pos);
    }

    #[test]
    fn test_repo_action_wildcard() {
        let scope = Scope::parse("repo:foo.bar?action=*").unwrap();
        let mut actions = BTreeSet::new();
        actions.insert(RepoAction::Create);
        actions.insert(RepoAction::Update);
        actions.insert(RepoAction::Delete);
        assert_eq!(
            scope,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("foo.bar".to_string())]),
                actions,
            })
        );
    }

    #[test]
    fn test_multiple_blob_accepts() {
        let scope = Scope::parse("blob?accept=image/*&accept=text/plain").unwrap();
        assert!(scope.grants(&Scope::parse("blob:image/png").unwrap()));
        assert!(scope.grants(&Scope::parse("blob:text/plain").unwrap()));
        assert!(!scope.grants(&Scope::parse("blob:application/json").unwrap()));
    }

    #[test]
    fn test_rpc_default_wildcards() {
        let scope = Scope::parse("rpc").unwrap();
        let mut lxm = BTreeSet::new();
        let mut aud = BTreeSet::new();
        lxm.insert(RpcLexicon::All);
        aud.insert(RpcAudience::All);
        assert_eq!(scope, Scope::Rpc(RpcScope { lxm, aud }));
    }

    #[test]
    fn test_atproto_scope_parsing() {
        let scope = Scope::parse("atproto").unwrap();
        assert_eq!(scope, Scope::Atproto);

        // Atproto should not accept suffixes
        assert!(Scope::parse("atproto:something").is_err());
        assert!(Scope::parse("atproto?param=value").is_err());
    }

    #[test]
    fn test_transition_scope_parsing() {
        let scope = Scope::parse("transition:generic").unwrap();
        assert_eq!(scope, Scope::Transition(TransitionScope::Generic));

        let scope = Scope::parse("transition:email").unwrap();
        assert_eq!(scope, Scope::Transition(TransitionScope::Email));

        // Test invalid transition types
        assert!(matches!(
            Scope::parse("transition:invalid"),
            Err(ParseError::InvalidResource(_))
        ));

        // Test missing suffix
        assert!(matches!(
            Scope::parse("transition"),
            Err(ParseError::MissingResource)
        ));

        // Test transition doesn't accept query parameters
        assert!(matches!(
            Scope::parse("transition:generic?param=value"),
            Err(ParseError::InvalidResource(_))
        ));
    }

    #[test]
    fn test_atproto_scope_normalization() {
        let scope = Scope::parse("atproto").unwrap();
        assert_eq!(scope.to_string_normalized(), "atproto");
    }

    #[test]
    fn test_transition_scope_normalization() {
        let tests = vec![
            ("transition:generic", "transition:generic"),
            ("transition:email", "transition:email"),
        ];

        for (input, expected) in tests {
            let scope = Scope::parse(input).unwrap();
            assert_eq!(scope.to_string_normalized(), expected);
        }
    }

    #[test]
    fn test_atproto_scope_grants() {
        let atproto = Scope::parse("atproto").unwrap();
        let account = Scope::parse("account:email").unwrap();
        let identity = Scope::parse("identity:handle").unwrap();
        let blob = Scope::parse("blob:image/png").unwrap();
        let repo = Scope::parse("repo:foo.bar").unwrap();
        let rpc = Scope::parse("rpc:com.example.service").unwrap();
        let transition_generic = Scope::parse("transition:generic").unwrap();
        let transition_email = Scope::parse("transition:email").unwrap();

        // Atproto only grants itself (it's a required scope, not a permission grant)
        assert!(atproto.grants(&atproto));
        assert!(!atproto.grants(&account));
        assert!(!atproto.grants(&identity));
        assert!(!atproto.grants(&blob));
        assert!(!atproto.grants(&repo));
        assert!(!atproto.grants(&rpc));
        assert!(!atproto.grants(&transition_generic));
        assert!(!atproto.grants(&transition_email));

        // Nothing else grants atproto
        assert!(!account.grants(&atproto));
        assert!(!identity.grants(&atproto));
        assert!(!blob.grants(&atproto));
        assert!(!repo.grants(&atproto));
        assert!(!rpc.grants(&atproto));
        assert!(!transition_generic.grants(&atproto));
        assert!(!transition_email.grants(&atproto));
    }

    #[test]
    fn test_transition_scope_grants() {
        let transition_generic = Scope::parse("transition:generic").unwrap();
        let transition_email = Scope::parse("transition:email").unwrap();
        let account = Scope::parse("account:email").unwrap();

        // Transition scopes only grant themselves
        assert!(transition_generic.grants(&transition_generic));
        assert!(transition_email.grants(&transition_email));
        assert!(!transition_generic.grants(&transition_email));
        assert!(!transition_email.grants(&transition_generic));

        // Transition scopes don't grant other scope types
        assert!(!transition_generic.grants(&account));
        assert!(!transition_email.grants(&account));

        // Other scopes don't grant transition scopes
        assert!(!account.grants(&transition_generic));
        assert!(!account.grants(&transition_email));
    }

    #[test]
    fn test_parse_multiple() {
        // Test parsing multiple scopes
        let scopes = Scope::parse_multiple("atproto repo:*").unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0], Scope::Atproto);
        assert_eq!(
            scopes[1],
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::All]),
                actions: {
                    let mut actions = BTreeSet::new();
                    actions.insert(RepoAction::Create);
                    actions.insert(RepoAction::Update);
                    actions.insert(RepoAction::Delete);
                    actions
                }
            })
        );

        // Test with more scopes
        let scopes = Scope::parse_multiple("account:email identity:handle blob:image/png").unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(matches!(scopes[0], Scope::Account(_)));
        assert!(matches!(scopes[1], Scope::Identity(_)));
        assert!(matches!(scopes[2], Scope::Blob(_)));

        // Test with complex scopes
        let scopes = Scope::parse_multiple(
            "account:email?action=manage repo:foo.bar?action=create transition:email",
        )
        .unwrap();
        assert_eq!(scopes.len(), 3);

        // Test empty string
        let scopes = Scope::parse_multiple("").unwrap();
        assert_eq!(scopes.len(), 0);

        // Test whitespace only
        let scopes = Scope::parse_multiple("   ").unwrap();
        assert_eq!(scopes.len(), 0);

        // Test with extra whitespace
        let scopes = Scope::parse_multiple("  atproto   repo:*  ").unwrap();
        assert_eq!(scopes.len(), 2);

        // Test single scope
        let scopes = Scope::parse_multiple("atproto").unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], Scope::Atproto);

        // Test error propagation
        assert!(Scope::parse_multiple("atproto invalid:scope").is_err());
        assert!(Scope::parse_multiple("account:invalid repo:*").is_err());
    }

    #[test]
    fn test_parse_multiple_reduced() {
        // Test repo scope reduction - wildcard grants specific
        let scopes = Scope::parse_multiple_reduced("atproto repo:foo.bar repo:*").unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&Scope::Atproto));
        assert!(scopes.contains(&Scope::Repo(RepoScope {
            collections: BTreeSet::from([RepoCollection::All]),
            actions: {
                let mut actions = BTreeSet::new();
                actions.insert(RepoAction::Create);
                actions.insert(RepoAction::Update);
                actions.insert(RepoAction::Delete);
                actions
            }
        })));

        // Test reverse order - should get same result
        let scopes = Scope::parse_multiple_reduced("atproto repo:* repo:foo.bar").unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&Scope::Atproto));
        assert!(scopes.contains(&Scope::Repo(RepoScope {
            collections: BTreeSet::from([RepoCollection::All]),
            actions: {
                let mut actions = BTreeSet::new();
                actions.insert(RepoAction::Create);
                actions.insert(RepoAction::Update);
                actions.insert(RepoAction::Delete);
                actions
            }
        })));

        // Test account scope reduction - manage grants read
        let scopes =
            Scope::parse_multiple_reduced("account:email account:email?action=manage").unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(
            scopes[0],
            Scope::Account(AccountScope {
                resource: AccountResource::Email,
                action: AccountAction::Manage,
            })
        );

        // Test identity scope reduction - wildcard grants specific
        let scopes = Scope::parse_multiple_reduced("identity:handle identity:*").unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], Scope::Identity(IdentityScope::All));

        // Test blob scope reduction - wildcard grants specific
        let scopes = Scope::parse_multiple_reduced("blob:image/png blob:image/* blob:*/*").unwrap();
        assert_eq!(scopes.len(), 1);
        let mut accept = BTreeSet::new();
        accept.insert(MimePattern::All);
        assert_eq!(scopes[0], Scope::Blob(BlobScope { accept }));

        // Test no reduction needed - different scope types
        let scopes =
            Scope::parse_multiple_reduced("account:email identity:handle blob:image/png").unwrap();
        assert_eq!(scopes.len(), 3);

        // Test repo action reduction
        let scopes =
            Scope::parse_multiple_reduced("repo:foo.bar?action=create repo:foo.bar").unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(
            scopes[0],
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("foo.bar".to_string())]),
                actions: {
                    let mut actions = BTreeSet::new();
                    actions.insert(RepoAction::Create);
                    actions.insert(RepoAction::Update);
                    actions.insert(RepoAction::Delete);
                    actions
                }
            })
        );

        // Test RPC scope reduction
        let scopes = Scope::parse_multiple_reduced(
            "rpc:com.example.service?aud=did:example:123 rpc:com.example.service rpc:*",
        )
        .unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(
            scopes[0],
            Scope::Rpc(RpcScope {
                lxm: {
                    let mut lxm = BTreeSet::new();
                    lxm.insert(RpcLexicon::All);
                    lxm
                },
                aud: {
                    let mut aud = BTreeSet::new();
                    aud.insert(RpcAudience::All);
                    aud
                }
            })
        );

        // Test duplicate removal
        let scopes = Scope::parse_multiple_reduced("atproto atproto atproto").unwrap();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], Scope::Atproto);

        // Test transition scopes - only grant themselves
        let scopes = Scope::parse_multiple_reduced("transition:generic transition:email").unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&Scope::Transition(TransitionScope::Generic)));
        assert!(scopes.contains(&Scope::Transition(TransitionScope::Email)));

        // Test empty input
        let scopes = Scope::parse_multiple_reduced("").unwrap();
        assert_eq!(scopes.len(), 0);

        // Test complex scenario with multiple reductions
        let scopes = Scope::parse_multiple_reduced(
            "account:email?action=manage account:email account:repo account:repo?action=read identity:* identity:handle"
        ).unwrap();
        assert_eq!(scopes.len(), 3);
        // Should have: account:email?action=manage, account:repo, identity:*
        assert!(scopes.contains(&Scope::Account(AccountScope {
            resource: AccountResource::Email,
            action: AccountAction::Manage,
        })));
        assert!(scopes.contains(&Scope::Account(AccountScope {
            resource: AccountResource::Repo,
            action: AccountAction::Read,
        })));
        assert!(scopes.contains(&Scope::Identity(IdentityScope::All)));

        // Test that atproto doesn't grant other scopes (per recent change)
        let scopes = Scope::parse_multiple_reduced("atproto account:email repo:*").unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&Scope::Atproto));
        assert!(scopes.contains(&Scope::Account(AccountScope {
            resource: AccountResource::Email,
            action: AccountAction::Read,
        })));
        assert!(scopes.contains(&Scope::Repo(RepoScope {
            collections: BTreeSet::from([RepoCollection::All]),
            actions: {
                let mut actions = BTreeSet::new();
                actions.insert(RepoAction::Create);
                actions.insert(RepoAction::Update);
                actions.insert(RepoAction::Delete);
                actions
            }
        })));
    }

    #[test]
    fn test_openid_connect_scope_parsing() {
        // Test OpenID scope
        let scope = Scope::parse("openid").unwrap();
        assert_eq!(scope, Scope::OpenId);

        // Test Profile scope
        let scope = Scope::parse("profile").unwrap();
        assert_eq!(scope, Scope::Profile);

        // Test Email scope
        let scope = Scope::parse("email").unwrap();
        assert_eq!(scope, Scope::Email);

        // Test that they don't accept suffixes
        assert!(Scope::parse("openid:something").is_err());
        assert!(Scope::parse("profile:something").is_err());
        assert!(Scope::parse("email:something").is_err());

        // Test that they don't accept query parameters
        assert!(Scope::parse("openid?param=value").is_err());
        assert!(Scope::parse("profile?param=value").is_err());
        assert!(Scope::parse("email?param=value").is_err());
    }

    #[test]
    fn test_openid_connect_scope_normalization() {
        let scope = Scope::parse("openid").unwrap();
        assert_eq!(scope.to_string_normalized(), "openid");

        let scope = Scope::parse("profile").unwrap();
        assert_eq!(scope.to_string_normalized(), "profile");

        let scope = Scope::parse("email").unwrap();
        assert_eq!(scope.to_string_normalized(), "email");
    }

    #[test]
    fn test_openid_connect_scope_grants() {
        let openid = Scope::parse("openid").unwrap();
        let profile = Scope::parse("profile").unwrap();
        let email = Scope::parse("email").unwrap();
        let account = Scope::parse("account:email").unwrap();

        // OpenID Connect scopes only grant themselves
        assert!(openid.grants(&openid));
        assert!(!openid.grants(&profile));
        assert!(!openid.grants(&email));
        assert!(!openid.grants(&account));

        assert!(profile.grants(&profile));
        assert!(!profile.grants(&openid));
        assert!(!profile.grants(&email));
        assert!(!profile.grants(&account));

        assert!(email.grants(&email));
        assert!(!email.grants(&openid));
        assert!(!email.grants(&profile));
        assert!(!email.grants(&account));

        // Other scopes don't grant OpenID Connect scopes
        assert!(!account.grants(&openid));
        assert!(!account.grants(&profile));
        assert!(!account.grants(&email));
    }

    #[test]
    fn test_parse_multiple_with_openid_connect() {
        let scopes = Scope::parse_multiple("openid profile email atproto").unwrap();
        assert_eq!(scopes.len(), 4);
        assert_eq!(scopes[0], Scope::OpenId);
        assert_eq!(scopes[1], Scope::Profile);
        assert_eq!(scopes[2], Scope::Email);
        assert_eq!(scopes[3], Scope::Atproto);

        // Test with mixed scopes
        let scopes = Scope::parse_multiple("openid account:email profile repo:*").unwrap();
        assert_eq!(scopes.len(), 4);
        assert!(scopes.contains(&Scope::OpenId));
        assert!(scopes.contains(&Scope::Profile));
    }

    #[test]
    fn test_parse_multiple_reduced_with_openid_connect() {
        // OpenID Connect scopes don't grant each other, so no reduction
        let scopes = Scope::parse_multiple_reduced("openid profile email openid").unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&Scope::OpenId));
        assert!(scopes.contains(&Scope::Profile));
        assert!(scopes.contains(&Scope::Email));

        // Mixed with other scopes
        let scopes = Scope::parse_multiple_reduced(
            "openid account:email account:email?action=manage profile",
        )
        .unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&Scope::OpenId));
        assert!(scopes.contains(&Scope::Profile));
        assert!(scopes.contains(&Scope::Account(AccountScope {
            resource: AccountResource::Email,
            action: AccountAction::Manage,
        })));
    }

    #[test]
    fn test_serialize_multiple() {
        // Test empty list
        let scopes: Vec<Scope> = vec![];
        assert_eq!(Scope::serialize_multiple(&scopes), "");

        // Test single scope
        let scopes = vec![Scope::Atproto];
        assert_eq!(Scope::serialize_multiple(&scopes), "atproto");

        // Test multiple scopes - should be sorted alphabetically
        let scopes = vec![
            Scope::parse("repo:*").unwrap(),
            Scope::Atproto,
            Scope::parse("account:email").unwrap(),
        ];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "account:email atproto repo:*"
        );

        // Test that sorting is consistent regardless of input order
        let scopes = vec![
            Scope::parse("identity:handle").unwrap(),
            Scope::parse("blob:image/png").unwrap(),
            Scope::parse("account:repo?action=manage").unwrap(),
        ];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "account:repo?action=manage blob:image/png identity:handle"
        );

        // Test with OpenID Connect scopes
        let scopes = vec![Scope::Email, Scope::OpenId, Scope::Profile, Scope::Atproto];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "atproto email openid profile"
        );

        // Test with complex scopes including query parameters
        let scopes = vec![
            Scope::parse("rpc:com.example.service?aud=did:example:123").unwrap(),
            Scope::parse("repo:foo.bar?action=create&action=update").unwrap(),
            Scope::parse("blob:image/*?accept=image/png&accept=image/jpeg").unwrap(),
        ];
        let result = Scope::serialize_multiple(&scopes);
        // The result should be sorted alphabetically
        // Single lxm + single aud is serialized as "rpc:[lxm]?aud=[aud]"
        assert!(result.starts_with("blob:"));
        assert!(result.contains(" repo:"));
        assert!(result.contains("rpc:com.example.service?aud=did:example:123"));

        // Test with transition scopes
        let scopes = vec![
            Scope::Transition(TransitionScope::Email),
            Scope::Transition(TransitionScope::Generic),
            Scope::Atproto,
        ];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "atproto transition:email transition:generic"
        );

        // Test duplicates - they remain in the output (caller's responsibility to dedupe if needed)
        let scopes = vec![
            Scope::Atproto,
            Scope::Atproto,
            Scope::parse("account:email").unwrap(),
        ];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "account:email atproto atproto"
        );

        // Test normalization is preserved in serialization
        let scopes = vec![Scope::parse("blob?accept=image/png&accept=image/jpeg").unwrap()];
        // Should normalize query parameters alphabetically
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "blob?accept=image/jpeg&accept=image/png"
        );
    }

    #[test]
    fn test_serialize_multiple_roundtrip() {
        // Test that parse_multiple and serialize_multiple are inverses (when sorted)
        let original = "account:email atproto blob:image/png identity:handle repo:*";
        let scopes = Scope::parse_multiple(original).unwrap();
        let serialized = Scope::serialize_multiple(&scopes);
        assert_eq!(serialized, original);

        // Test with complex scopes
        let original = "account:repo?action=manage blob?accept=image/jpeg&accept=image/png rpc:*";
        let scopes = Scope::parse_multiple(original).unwrap();
        let serialized = Scope::serialize_multiple(&scopes);
        // Parse again to verify it's valid
        let reparsed = Scope::parse_multiple(&serialized).unwrap();
        assert_eq!(scopes, reparsed);

        // Test with OpenID Connect scopes
        let original = "email openid profile";
        let scopes = Scope::parse_multiple(original).unwrap();
        let serialized = Scope::serialize_multiple(&scopes);
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_remove_scope() {
        // Test removing a scope that exists
        let scopes = vec![
            Scope::parse("repo:*").unwrap(),
            Scope::Atproto,
            Scope::parse("account:email").unwrap(),
        ];
        let to_remove = Scope::Atproto;
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&to_remove));
        assert!(result.contains(&Scope::parse("repo:*").unwrap()));
        assert!(result.contains(&Scope::parse("account:email").unwrap()));

        // Test removing a scope that doesn't exist
        let scopes = vec![
            Scope::parse("repo:*").unwrap(),
            Scope::parse("account:email").unwrap(),
        ];
        let to_remove = Scope::parse("identity:handle").unwrap();
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert_eq!(result, scopes);

        // Test removing from empty list
        let scopes: Vec<Scope> = vec![];
        let to_remove = Scope::Atproto;
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 0);

        // Test removing all instances of a duplicate scope
        let scopes = vec![
            Scope::Atproto,
            Scope::parse("account:email").unwrap(),
            Scope::Atproto,
            Scope::parse("repo:*").unwrap(),
            Scope::Atproto,
        ];
        let to_remove = Scope::Atproto;
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&to_remove));
        assert!(result.contains(&Scope::parse("account:email").unwrap()));
        assert!(result.contains(&Scope::parse("repo:*").unwrap()));

        // Test removing complex scopes with query parameters
        let scopes = vec![
            Scope::parse("account:email?action=manage").unwrap(),
            Scope::parse("blob?accept=image/png&accept=image/jpeg").unwrap(),
            Scope::parse("rpc:com.example.service?aud=did:example:123").unwrap(),
        ];
        let to_remove = Scope::parse("blob?accept=image/jpeg&accept=image/png").unwrap(); // Note: normalized order
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&to_remove));

        // Test with OpenID Connect scopes
        let scopes = vec![Scope::OpenId, Scope::Profile, Scope::Email, Scope::Atproto];
        let to_remove = Scope::Profile;
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 3);
        assert!(!result.contains(&to_remove));
        assert!(result.contains(&Scope::OpenId));
        assert!(result.contains(&Scope::Email));
        assert!(result.contains(&Scope::Atproto));

        // Test with transition scopes
        let scopes = vec![
            Scope::Transition(TransitionScope::Generic),
            Scope::Transition(TransitionScope::Email),
            Scope::Atproto,
        ];
        let to_remove = Scope::Transition(TransitionScope::Email);
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&to_remove));
        assert!(result.contains(&Scope::Transition(TransitionScope::Generic)));
        assert!(result.contains(&Scope::Atproto));

        // Test that only exact matches are removed
        let scopes = vec![
            Scope::parse("account:email").unwrap(),
            Scope::parse("account:email?action=manage").unwrap(),
            Scope::parse("account:repo").unwrap(),
        ];
        let to_remove = Scope::parse("account:email").unwrap();
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&Scope::parse("account:email").unwrap()));
        assert!(result.contains(&Scope::parse("account:email?action=manage").unwrap()));
        assert!(result.contains(&Scope::parse("account:repo").unwrap()));
    }

    #[test]
    fn test_repo_nsid_with_wildcard_suffix() {
        // Test parsing "repo:app.bsky.feed.*" - the asterisk is treated as a literal part of the NSID,
        // not as a wildcard pattern. Only "repo:*" has special wildcard behavior for ALL collections.
        let scope = Scope::parse("repo:app.bsky.feed.*").unwrap();

        // Verify it parses as a specific NSID, not as a wildcard
        assert_eq!(
            scope,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("app.bsky.feed.*".to_string())]),
                actions: {
                    let mut actions = BTreeSet::new();
                    actions.insert(RepoAction::Create);
                    actions.insert(RepoAction::Update);
                    actions.insert(RepoAction::Delete);
                    actions
                }
            })
        );

        // Verify normalization preserves the literal NSID
        assert_eq!(scope.to_string_normalized(), "repo:app.bsky.feed.*");

        // Test that it does NOT grant access to "app.bsky.feed.post"
        // (because "app.bsky.feed.*" is a literal NSID, not a pattern)
        let specific_feed = Scope::parse("repo:app.bsky.feed.post").unwrap();
        assert!(!scope.grants(&specific_feed));

        // Test that only "repo:*" grants access to "app.bsky.feed.*"
        let repo_all = Scope::parse("repo:*").unwrap();
        assert!(repo_all.grants(&scope));

        // Test that "repo:app.bsky.feed.*" only grants itself
        assert!(scope.grants(&scope));

        // Test with actions
        let scope_with_create = Scope::parse("repo:app.bsky.feed.*?action=create").unwrap();
        assert_eq!(
            scope_with_create,
            Scope::Repo(RepoScope {
                collections: BTreeSet::from([RepoCollection::Nsid("app.bsky.feed.*".to_string())]),
                actions: {
                    let mut actions = BTreeSet::new();
                    actions.insert(RepoAction::Create);
                    actions
                }
            })
        );

        // The full scope (with all actions) grants the create-only scope
        assert!(scope.grants(&scope_with_create));
        // But the create-only scope does NOT grant the full scope
        assert!(!scope_with_create.grants(&scope));

        // Test parsing multiple scopes with NSID wildcards
        let scopes =
            Scope::parse_multiple("repo:app.bsky.feed.* repo:app.bsky.graph.* repo:*").unwrap();
        assert_eq!(scopes.len(), 3);

        // Test that parse_multiple_reduced properly reduces when "repo:*" is present
        let reduced =
            Scope::parse_multiple_reduced("repo:app.bsky.feed.* repo:app.bsky.graph.* repo:*")
                .unwrap();
        assert_eq!(reduced.len(), 1);
        assert_eq!(reduced[0], repo_all);
    }

    #[test]
    fn test_include_scope_parsing() {
        // Test basic include scope
        let scope = Scope::parse("include:app.example.authFull").unwrap();
        assert_eq!(
            scope,
            Scope::Include(IncludeScope {
                nsid: "app.example.authFull".to_string(),
                aud: None,
            })
        );

        // Test include scope with audience
        let scope =
            Scope::parse("include:app.example.authFull?aud=did:web:api.example.com").unwrap();
        assert_eq!(
            scope,
            Scope::Include(IncludeScope {
                nsid: "app.example.authFull".to_string(),
                aud: Some("did:web:api.example.com".to_string()),
            })
        );

        // Test include scope with URL-encoded audience (with fragment)
        let scope =
            Scope::parse("include:app.example.authFull?aud=did:web:api.example.com%23svc_chat")
                .unwrap();
        assert_eq!(
            scope,
            Scope::Include(IncludeScope {
                nsid: "app.example.authFull".to_string(),
                aud: Some("did:web:api.example.com#svc_chat".to_string()),
            })
        );

        // Test missing NSID
        assert!(matches!(
            Scope::parse("include"),
            Err(ParseError::MissingResource)
        ));

        // Test empty NSID with query params
        assert!(matches!(
            Scope::parse("include:?aud=did:example:123"),
            Err(ParseError::MissingResource)
        ));
    }

    #[test]
    fn test_include_scope_normalization() {
        // Test normalization without audience
        let scope = Scope::parse("include:com.example.authBasic").unwrap();
        assert_eq!(
            scope.to_string_normalized(),
            "include:com.example.authBasic"
        );

        // Test normalization with audience (no special chars)
        let scope = Scope::parse("include:com.example.authBasic?aud=did:plc:xyz123").unwrap();
        assert_eq!(
            scope.to_string_normalized(),
            "include:com.example.authBasic?aud=did:plc:xyz123"
        );

        // Test normalization with URL encoding (fragment needs encoding)
        let scope =
            Scope::parse("include:app.example.authFull?aud=did:web:api.example.com%23svc_chat")
                .unwrap();
        let normalized = scope.to_string_normalized();
        assert_eq!(
            normalized,
            "include:app.example.authFull?aud=did:web:api.example.com%23svc_chat"
        );
    }

    #[test]
    fn test_include_scope_grants() {
        let include1 = Scope::parse("include:app.example.authFull").unwrap();
        let include2 = Scope::parse("include:app.example.authBasic").unwrap();
        let include1_with_aud =
            Scope::parse("include:app.example.authFull?aud=did:plc:xyz").unwrap();
        let account = Scope::parse("account:email").unwrap();

        // Include scopes only grant themselves (exact match)
        assert!(include1.grants(&include1));
        assert!(!include1.grants(&include2));
        assert!(!include1.grants(&include1_with_aud)); // Different because aud differs
        assert!(include1_with_aud.grants(&include1_with_aud));

        // Include scopes don't grant other scope types
        assert!(!include1.grants(&account));
        assert!(!account.grants(&include1));

        // Include scopes don't grant atproto or transition
        let atproto = Scope::parse("atproto").unwrap();
        let transition = Scope::parse("transition:generic").unwrap();
        assert!(!include1.grants(&atproto));
        assert!(!include1.grants(&transition));
        assert!(!atproto.grants(&include1));
        assert!(!transition.grants(&include1));
    }

    /// `include:` grants nothing, and the day it does is the day a security
    /// check becomes mandatory.
    ///
    /// An `include:` scope names a permission set the user never reads, so the
    /// permissions it expands to must be filtered to the declaring lexicon's own
    /// namespace authority — otherwise `include:app.evil.authFull` can grant
    /// `repo:com.yourbank.records`. The reference does that filtering in
    /// `isAllowedPermission` as it resolves the scope.
    ///
    /// `atproto-lexicon` no longer enforces that rule when the permission set is
    /// *parsed*, because the reference does not either and doing so made this
    /// crate refuse documents the reference accepts. The rule now lives in
    /// `atproto_lexicon::validation::schema_file::permission_within_authority`,
    /// which has no caller because nothing here resolves `include:` yet.
    ///
    /// This test exists so that gap cannot close quietly. It asserts the current
    /// invariant — an `include:` scope expands to nothing — so implementing
    /// resolution *will* fail it. When it does, do not simply update it: wire
    /// `permission_within_authority` into the expansion first, then assert that
    /// out-of-authority permissions are dropped.
    #[test]
    fn include_scope_grants_nothing_until_authority_filtering_exists() {
        let include = Scope::parse("include:app.example.authFull").unwrap();

        // Every concrete permission an expanded set could plausibly yield.
        for granted in [
            "repo:com.example.calendar.event",
            "repo:*",
            "rpc:example.lexicon.endpoint",
            "blob:*/*",
            "account:email",
        ] {
            let scope = Scope::parse(granted)
                .unwrap_or_else(|e| panic!("{granted} should be a parsable scope: {e:?}"));
            assert!(
                !include.grants(&scope),
                "include: now grants {granted} — resolution has been implemented. Filter the \
                 expansion through permission_within_authority before relaxing this assertion; \
                 without it, a permission set can grant across namespace authorities."
            );
        }
    }

    #[test]
    fn test_parse_multiple_with_include() {
        let scopes = Scope::parse_multiple("atproto include:app.example.auth repo:*").unwrap();
        assert_eq!(scopes.len(), 3);
        assert_eq!(scopes[0], Scope::Atproto);
        assert!(matches!(scopes[1], Scope::Include(_)));
        assert!(matches!(scopes[2], Scope::Repo(_)));

        // Test with URL-encoded audience
        let scopes = Scope::parse_multiple(
            "include:app.example.auth?aud=did:web:api.example.com%23svc account:email",
        )
        .unwrap();
        assert_eq!(scopes.len(), 2);
        if let Scope::Include(inc) = &scopes[0] {
            assert_eq!(inc.nsid, "app.example.auth");
            assert_eq!(inc.aud, Some("did:web:api.example.com#svc".to_string()));
        } else {
            panic!("Expected Include scope");
        }
    }

    #[test]
    fn test_parse_multiple_reduced_with_include() {
        // Include scopes don't reduce each other (each is distinct)
        let scopes = Scope::parse_multiple_reduced(
            "include:app.example.auth include:app.example.other include:app.example.auth",
        )
        .unwrap();
        assert_eq!(scopes.len(), 2); // Duplicates are removed
        assert!(scopes.contains(&Scope::Include(IncludeScope {
            nsid: "app.example.auth".to_string(),
            aud: None,
        })));
        assert!(scopes.contains(&Scope::Include(IncludeScope {
            nsid: "app.example.other".to_string(),
            aud: None,
        })));

        // Include scopes with different audiences are not duplicates
        let scopes = Scope::parse_multiple_reduced(
            "include:app.example.auth include:app.example.auth?aud=did:plc:xyz",
        )
        .unwrap();
        assert_eq!(scopes.len(), 2);
    }

    #[test]
    fn test_serialize_multiple_with_include() {
        let scopes = vec![
            Scope::parse("repo:*").unwrap(),
            Scope::parse("include:app.example.authFull").unwrap(),
            Scope::Atproto,
        ];
        let result = Scope::serialize_multiple(&scopes);
        assert_eq!(result, "atproto include:app.example.authFull repo:*");

        // Test with URL-encoded audience
        let scopes = vec![Scope::Include(IncludeScope {
            nsid: "app.example.auth".to_string(),
            aud: Some("did:web:api.example.com#svc".to_string()),
        })];
        let result = Scope::serialize_multiple(&scopes);
        assert_eq!(
            result,
            "include:app.example.auth?aud=did:web:api.example.com%23svc"
        );
    }

    #[test]
    fn test_remove_scope_with_include() {
        let scopes = vec![
            Scope::Atproto,
            Scope::parse("include:app.example.auth").unwrap(),
            Scope::parse("account:email").unwrap(),
        ];
        let to_remove = Scope::parse("include:app.example.auth").unwrap();
        let result = Scope::remove_scope(&scopes, &to_remove);
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&to_remove));
        assert!(result.contains(&Scope::Atproto));
    }

    #[test]
    fn test_include_scope_roundtrip() {
        // Test that parse and serialize are inverses
        let original =
            "include:com.example.authBasicFeatures?aud=did:web:api.example.com%23svc_appview";
        let scope = Scope::parse(original).unwrap();
        let serialized = scope.to_string_normalized();
        let reparsed = Scope::parse(&serialized).unwrap();
        assert_eq!(scope, reparsed);
    }

    #[test]
    fn test_space_scope_parsing_dispatch() {
        // The `space` prefix is recognized and dispatched (no longer an
        // UnknownPrefix error).
        let scope = Scope::parse("space:com.example.space").unwrap();
        assert!(matches!(scope, Scope::Space(_)));

        // A bare `space` without a type is an error, not UnknownPrefix.
        assert!(matches!(
            Scope::parse("space"),
            Err(ParseError::MissingResource)
        ));
    }

    #[test]
    fn test_space_scope_normalization() {
        let tests = vec![
            ("space:com.example.space", "space:com.example.space"),
            ("space:*", "space:*"),
            // Explicit defaults stripped — but `authority=*` is no longer a
            // default, so it survives. Dropping it would silently narrow an
            // any-authority grant to the user's own on a round trip.
            ("space:com.example.space?skey=*", "space:com.example.space"),
            (
                "space:com.example.space?authority=*&skey=*",
                "space:com.example.space?authority=*",
            ),
            (
                "space:com.example.space?action=read&action=create&action=update&action=delete",
                "space:com.example.space",
            ),
            (
                "space:com.example.space?authority=did:plc:abc&action=read",
                "space:com.example.space?authority=did:plc:abc&action=read",
            ),
            // `manage` is a separate parameter, preserved on normalization.
            (
                "space:com.example.space?manage=update&manage=delete",
                "space:com.example.space?manage=update&manage=delete",
            ),
        ];

        for (input, expected) in tests {
            let scope = Scope::parse(input).unwrap();
            assert_eq!(scope.to_string_normalized(), expected, "input: {input}");
        }
    }

    #[test]
    fn test_space_scope_grants_self_only() {
        let a = Scope::parse("space:com.example.space?action=read").unwrap();
        let b = Scope::parse("space:com.example.space?action=read").unwrap();
        let c = Scope::parse("space:com.example.space?manage=update").unwrap();
        let account = Scope::parse("account:email").unwrap();

        assert!(a.grants(&b));
        assert!(!a.grants(&c));
        assert!(!a.grants(&account));
        assert!(!account.grants(&a));
    }

    #[test]
    fn test_space_scope_in_serialize_multiple() {
        let scopes = vec![
            Scope::parse("space:com.example.space?action=read").unwrap(),
            Scope::Atproto,
            Scope::parse("account:email").unwrap(),
        ];
        assert_eq!(
            Scope::serialize_multiple(&scopes),
            "account:email atproto space:com.example.space?action=read"
        );
    }

    #[test]
    fn test_scopes_set_allows_space() {
        let set = ScopesSet::from_scope_string(
            "atproto space:com.example.space?authority=did:plc:abc&skey=s1&collection=com.example.note&action=read&action=create",
        );

        // read is allowed.
        assert!(set.allows_space(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));

        // create on covered collection is allowed.
        assert!(set.allows_space(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        )));

        // delete is not granted.
        assert!(!set.allows_space(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Delete,
            "com.example.note",
        )));

        // a different space key is not granted.
        assert!(!set.allows_space(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "other",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_scopes_set_assert_space() {
        // Bound to a subject: the grant omits `authority`, which means
        // `self`, and `self` resolves against the DID the token was issued to.
        let set =
            ScopesSet::from_scope_string_for("space:com.example.space?action=read", "did:plc:abc");

        // Satisfied: Ok.
        assert!(
            set.assert_space(&SpaceTarget::new(
                "com.example.space",
                "did:plc:abc",
                "s1",
                SpaceAction::Read,
            ))
            .is_ok()
        );

        // Not satisfied: returns the minimal needed scope.
        let target = SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        );
        let err = set.assert_space(&target).unwrap_err();
        assert_eq!(err.scope, SpacePermission::scope_needed_for(&target));
        assert!(err.to_string().contains("error-atproto-oauth-scope-1"));
    }

    #[test]
    fn test_scopes_set_ignores_unparseable_scopes() {
        // A non-space and a malformed scope are simply ignored for matching.
        let set = ScopesSet::from_scopes(["account:email", "space:com.example.space?action=read"])
            .with_subject("did:plc:abc");
        assert!(set.allows_space(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));
    }

    // --- granular enforcement (F-OAUTH-12) --------------------------------

    fn set(scope: &str) -> ScopesSet {
        ScopesSet::from_scope_string(scope)
    }

    /// `atproto` alone authorises nothing beyond announcing that other AT
    /// Protocol scopes will be used. It was previously enough for everything.
    #[test]
    fn atproto_alone_grants_no_granular_access() {
        let s = set("atproto");
        assert!(!s.allows_repo("app.bsky.feed.post", &RepoAction::Create));
        assert!(!s.allows_blob("image/png"));
        assert!(!s.allows_rpc("app.bsky.feed.getTimeline", "did:web:appview.example"));
        assert!(!s.allows_identity_handle());
    }

    #[test]
    fn repo_scope_is_bounded_by_collection_and_action() {
        let s = set("atproto repo:app.bsky.feed.post?action=create");
        assert!(s.allows_repo("app.bsky.feed.post", &RepoAction::Create));
        assert!(
            !s.allows_repo("app.bsky.feed.post", &RepoAction::Delete),
            "a create grant must not confer delete"
        );
        assert!(
            !s.allows_repo("app.bsky.graph.follow", &RepoAction::Create),
            "a grant for one collection must not confer another"
        );
    }

    #[test]
    fn repo_wildcard_covers_every_collection() {
        let s = set("atproto repo:*?action=create&action=delete");
        assert!(s.allows_repo("anything.at.all", &RepoAction::Create));
        assert!(s.allows_repo("anything.at.all", &RepoAction::Delete));
        assert!(!s.allows_repo("anything.at.all", &RepoAction::Update));
    }

    #[test]
    fn blob_scope_is_bounded_by_mime() {
        let s = set("atproto blob:image/*");
        assert!(s.allows_blob("image/png"));
        assert!(
            !s.allows_blob("text/html"),
            "an image grant must not confer uploading a document"
        );
        assert!(set("atproto blob:*/*").allows_blob("text/html"));
    }

    #[test]
    fn rpc_scope_is_bounded_by_method_and_audience() {
        let s = set("atproto rpc:app.bsky.feed.getTimeline?aud=did:web:appview.example");
        assert!(s.allows_rpc("app.bsky.feed.getTimeline", "did:web:appview.example"));
        assert!(
            !s.allows_rpc("app.bsky.feed.getTimeline", "did:web:elsewhere.example"),
            "a grant for one audience must not confer another"
        );
        assert!(
            !s.allows_rpc("chat.bsky.convo.sendMessage", "did:web:appview.example"),
            "a grant for one method must not confer another"
        );
    }

    /// `transition:generic` is the legacy full-access scope most clients still
    /// request, and it covers the axes that existed when it was minted:
    /// repo, blob, and non-chat RPC.
    #[test]
    fn transition_generic_satisfies_the_axes_it_covers() {
        let s = set("atproto transition:generic");
        assert!(s.allows_repo("app.bsky.feed.post", &RepoAction::Create));
        assert!(s.allows_blob("text/html"));
        assert!(s.allows_rpc("app.bsky.feed.getTimeline", "did:web:appview.example"));
        // Asking for "whatever this token has" is satisfied by the blanket
        // itself, which is why the wildcard is not treated as a chat request.
        assert!(s.allows_rpc("*", "did:web:appview.example"));
    }

    /// It does **not** reach chat. Direct messages are carved out of the legacy
    /// blanket and need `transition:chat.bsky`, which is a separate grant a
    /// user consents to separately.
    ///
    /// This previously passed: `transition:generic` — the scope in every
    /// client's README — conferred the ability to read and send DMs.
    #[test]
    fn transition_generic_does_not_confer_chat_access() {
        let generic = set("atproto transition:generic");
        assert!(
            !generic.allows_rpc("chat.bsky.convo.sendMessage", "did:web:anywhere.example"),
            "transition:generic must not reach chat.bsky.*"
        );

        let chat = set("atproto transition:chat.bsky");
        assert!(
            chat.allows_rpc("chat.bsky.convo.sendMessage", "did:web:anywhere.example"),
            "transition:chat.bsky is what grants it"
        );
        // And chat alone does not re-open the rest.
        assert!(!chat.allows_repo("app.bsky.feed.post", &RepoAction::Create));
    }

    /// It does **not** confer identity permissions. Rotating a handle rewrites
    /// the account's PLC document, which is outside anything the legacy
    /// blanket was granted for; it needs `identity:handle` or `identity:*`.
    ///
    /// This previously passed, so any client holding the standard legacy scope
    /// could change the account's handle.
    #[test]
    fn transition_generic_does_not_confer_identity_access() {
        assert!(!set("atproto transition:generic").allows_identity_handle());
        assert!(set("atproto identity:handle").allows_identity_handle());
        assert!(set("atproto identity:*").allows_identity_handle());
    }

    /// It is not a wildcard for spaces: spaces post-date it, so nothing was
    /// granted it expecting space access.
    #[test]
    fn transition_generic_does_not_confer_space_access() {
        let s = set("atproto transition:generic");
        let target = SpaceTarget::new(
            "com.example.space",
            "did:plc:owner",
            "default",
            SpaceAction::Create,
        );
        assert!(!s.allows_space(&target));
    }

    /// A refusal names the scope that would have worked.
    #[test]
    fn a_refusal_names_the_missing_scope() {
        let s = set("atproto");
        assert_eq!(
            s.assert_repo("app.bsky.feed.post", &RepoAction::Create)
                .unwrap_err()
                .scope,
            "repo:app.bsky.feed.post?action=create"
        );
        assert_eq!(
            s.assert_blob("image/png").unwrap_err().scope,
            "blob:image/png"
        );
        assert_eq!(
            s.assert_rpc("a.b.c", "did:web:x.example")
                .unwrap_err()
                .scope,
            "rpc:a.b.c?aud=did:web:x.example"
        );
        assert_eq!(
            s.assert_identity_handle().unwrap_err().scope,
            "identity:handle"
        );
    }

    /// `collection` is the positional parameter, so the query form is the same
    /// scope written out longhand.
    #[test]
    fn a_repo_scope_reads_the_collection_parameter() {
        assert_eq!(
            Scope::parse("repo?collection=app.offprint.publication").unwrap(),
            Scope::parse("repo:app.offprint.publication").unwrap(),
        );
    }

    /// `collection` is multi-valued: one scope may name several.
    ///
    /// This is the form a real client sent, and every collection in it granted
    /// nothing. The empty string before the `?` was read as the collection
    /// NSID -- a collection literally named `""` -- and the `collection=`
    /// parameters were never looked at, so a token carrying this scope was
    /// refused on every write with `InsufficientScope`.
    #[test]
    fn every_collection_named_in_one_scope_is_granted() {
        let granted = ScopesSet::from_scope_string(
            "repo?collection=app.offprint.document.article\
&collection=app.offprint.publication\
&collection=app.offprint.actor.profile\
&collection=app.offprint.page\
&collection=app.offprint.component",
        );

        for collection in [
            "app.offprint.document.article",
            "app.offprint.publication",
            "app.offprint.actor.profile",
            "app.offprint.page",
            "app.offprint.component",
        ] {
            for action in [RepoAction::Create, RepoAction::Update, RepoAction::Delete] {
                assert!(
                    granted.allows_repo(collection, &action),
                    "{collection} {action:?} was not granted"
                );
            }
        }

        // And nothing it did not name.
        assert!(!granted.allows_repo("app.bsky.feed.post", &RepoAction::Create));
        // Least of all the empty collection the old parser invented.
        assert!(!granted.allows_repo("", &RepoAction::Create));
    }

    /// Actions still apply across every collection in the scope.
    #[test]
    fn actions_bind_all_collections_in_the_scope() {
        let granted =
            ScopesSet::from_scope_string("repo?collection=a.b.c&collection=d.e.f&action=create");
        for collection in ["a.b.c", "d.e.f"] {
            assert!(granted.allows_repo(collection, &RepoAction::Create));
            assert!(!granted.allows_repo(collection, &RepoAction::Delete));
        }
    }

    /// A bare `repo` still means every collection.
    #[test]
    fn a_bare_repo_scope_still_covers_everything() {
        let granted = ScopesSet::from_scope_string("repo");
        assert!(granted.allows_repo("anything.at.all", &RepoAction::Delete));
        assert_eq!(
            Scope::parse("repo?collection=*").unwrap(),
            Scope::parse("repo:*").unwrap()
        );
    }

    /// A multi-collection scope survives a round trip through its string form.
    ///
    /// The positional shorthand cannot express more than one collection, so
    /// rendering has to fall back to the query form -- and a scope that parsed
    /// but could not be written back would be lost the moment a token was
    /// re-read.
    #[test]
    fn a_multi_collection_scope_round_trips() {
        for original in [
            "repo:foo.bar",
            "repo:foo.bar?action=create",
            "repo?collection=a.b.c&collection=d.e.f",
            "repo?collection=a.b.c&collection=d.e.f&action=create",
            "repo:*",
        ] {
            let parsed = Scope::parse(original).unwrap();
            let rendered = parsed.to_string();
            assert_eq!(
                Scope::parse(&rendered).unwrap(),
                parsed,
                "{original} rendered as {rendered}, which parses differently"
            );
        }
    }
}
