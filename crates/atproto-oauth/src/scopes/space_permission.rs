//! AT Protocol permissioned-data `space:` OAuth permission scope.
//!
//! This module implements the `space:` scope grammar, parser, formatter, and
//! request-time matcher per the published **0016 Permissioned Data** spec
//! (OAuth scopes, lines 369-465), choosing the spec prose over the reference
//! implementation wherever they diverge.
//!
//! # Grammar
//!
//! ```text
//! space:<spaceType>[?did=<did>][&skey=<skey>][&collection=<nsid>...][&action=<action>...][&manage=<op>...]
//! ```
//!
//! - `spaceType`: positional, **required** — a space-type NSID or `*` (any
//!   type).
//! - `did`: a DID or `*` (any authority). Default `*`.
//! - `skey`: a non-empty string up to 512 chars, or `*`. Default `*`.
//! - `collection`: multi-valued NSID or `*`. Default is the space type
//!   declaration's `collections` (resolved by the consumer); empty when
//!   `spaceType=*`.
//! - `action`: multi-valued. Action values are `read_self, read, create,
//!   update, delete`. Default (when omitted) is `{read, create, update,
//!   delete}` — note **not** `read_self` alone, since `read` is inclusive of
//!   `read_self`.
//! - `manage`: multi-valued, a **separate** parameter governing operations on
//!   the spaces themselves. Verbs are `create, update, delete`. Default is
//!   none — an ordinary record-access grant confers no administrative
//!   capability.
//!
//! `did`, `spaceType`, and `skey` select **which spaces** the grant covers.
//! `action` (and `collection`) govern operations on the **records** in those
//! spaces. `manage` governs operations on the **spaces themselves**.
//!
//! # Matching
//!
//! At request time a [`SpaceTarget`] is checked against a granted
//! [`SpacePermission`] (spec lines 401-419):
//!
//! - The tuple `(spaceType, did, skey)` must overlap: each grant component is
//!   `*` or equals the target component.
//! - `read` covers every repo in the space and **ignores** `collection`. It
//!   also grants `getDelegationToken`.
//! - `read_self` covers only the holder's **own** repo, is **constrained by**
//!   `collection`, and does **not** grant `getDelegationToken`. A `read` grant
//!   also satisfies a `read_self` request (`read` implies `read_self`).
//! - `create` / `update` / `delete` act on a specific record and are
//!   constrained by `collection` (the action must be granted **and** the target
//!   collection covered).
//! - A [`SpaceManageTarget`] is checked against the grant's `manage` set: a
//!   management verb is permitted when the grant's `manage` set contains that
//!   verb. `manage` ignores `collection`.

use std::collections::BTreeSet;
use std::fmt;

use super::ParseError;

/// Maximum allowed length, in characters, of a `skey` parameter value.
const SKEY_MAX_LENGTH: usize = 512;

/// A single action that may appear in a `space:` scope's `action` list.
///
/// Per the 0016 spec param table (line 383) the action values are exactly
/// `[read_self, read, create, update, delete]`. `manage` is **not** an action;
/// it is a separate parameter (see [`SpaceManageVerb`]).
///
/// The variant order is the canonical action order used for formatting:
/// `read_self`, `read`, `create`, `update`, `delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceAction {
    /// Read the holder's **own** repo only; collection-constrained; does not
    /// grant `getDelegationToken`. A `read` grant also satisfies a `read_self`
    /// request.
    ReadSelf,
    /// Read every repo in the space; ignores `collection`; grants
    /// `getDelegationToken`. Implies [`SpaceAction::ReadSelf`].
    Read,
    /// Create records in a covered collection.
    Create,
    /// Update records in a covered collection.
    Update,
    /// Delete records in a covered collection.
    Delete,
}

impl SpaceAction {
    /// The full, canonically ordered action set: `[read_self, read, create,
    /// update, delete]`.
    pub const ALL: [SpaceAction; 5] = [
        SpaceAction::ReadSelf,
        SpaceAction::Read,
        SpaceAction::Create,
        SpaceAction::Update,
        SpaceAction::Delete,
    ];

    /// The default `action` set when the parameter is omitted: `{read, create,
    /// update, delete}` (spec line 411). `read` is inclusive of `read_self`, so
    /// `read_self` is not listed separately.
    pub const DEFAULT: [SpaceAction; 4] = [
        SpaceAction::Read,
        SpaceAction::Create,
        SpaceAction::Update,
        SpaceAction::Delete,
    ];

    /// The lowercase wire form of this action.
    pub fn as_str(self) -> &'static str {
        match self {
            SpaceAction::ReadSelf => "read_self",
            SpaceAction::Read => "read",
            SpaceAction::Create => "create",
            SpaceAction::Update => "update",
            SpaceAction::Delete => "delete",
        }
    }

    /// Parse an action from its wire form, returning [`None`] for unknown
    /// values.
    pub fn from_wire(value: &str) -> Option<SpaceAction> {
        match value {
            "read_self" => Some(SpaceAction::ReadSelf),
            "read" => Some(SpaceAction::Read),
            "create" => Some(SpaceAction::Create),
            "update" => Some(SpaceAction::Update),
            "delete" => Some(SpaceAction::Delete),
            _ => None,
        }
    }
}

/// A single verb that may appear in a `space:` scope's `manage` list.
///
/// `manage` is a separate parameter from `action` (spec line 384). Its verbs
/// `create`, `update`, `delete` apply to the **space itself** rather than to
/// the records in it, and map onto implementation-defined management
/// operations (spec lines 415-419).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceManageVerb {
    /// Create a space of the given `spaceType` under the given authority.
    Create,
    /// Update the space (e.g. `updateSpace`, `addMember`, `removeMember`).
    Update,
    /// Delete the space.
    Delete,
}

impl SpaceManageVerb {
    /// The full, canonically ordered manage-verb set: `[create, update,
    /// delete]`.
    pub const ALL: [SpaceManageVerb; 3] = [
        SpaceManageVerb::Create,
        SpaceManageVerb::Update,
        SpaceManageVerb::Delete,
    ];

    /// The lowercase wire form of this verb.
    pub fn as_str(self) -> &'static str {
        match self {
            SpaceManageVerb::Create => "create",
            SpaceManageVerb::Update => "update",
            SpaceManageVerb::Delete => "delete",
        }
    }

    /// Parse a manage verb from its wire form, returning [`None`] for unknown
    /// values.
    pub fn from_wire(value: &str) -> Option<SpaceManageVerb> {
        match value {
            "create" => Some(SpaceManageVerb::Create),
            "update" => Some(SpaceManageVerb::Update),
            "delete" => Some(SpaceManageVerb::Delete),
            _ => None,
        }
    }
}

/// The `type` component of a `space:` scope: a space-type NSID or any (`*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceType {
    /// Matches any space type (wildcard `*`).
    All,
    /// A specific space-type NSID.
    Nsid(String),
}

/// The `did` component of a `space:` scope: a specific DID or any (`*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceDid {
    /// Matches any owner DID (wildcard `*`).
    All,
    /// A specific owner DID.
    Did(String),
}

/// The `skey` component of a `space:` scope: a specific space key or any (`*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceSkey {
    /// Matches any space key (wildcard `*`).
    All,
    /// A specific space key (non-empty, up to 512 chars).
    Key(String),
}

/// A single `collection` value in a `space:` scope: an NSID or any (`*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpaceCollection {
    /// Matches any collection (wildcard `*`).
    All,
    /// A specific collection NSID.
    Nsid(String),
}

/// The resolved or unresolved `collection` set of a `space:` scope.
///
/// When `collection` is omitted, the spec (line 413) defaults it to the
/// collections declared by the space type's declaration — which the scope
/// parser cannot resolve on its own. [`SpaceCollections::Default`] preserves
/// that "use the declaration's collections" intent; the consumer resolves it
/// against the declared collections at enforcement time via
/// [`SpacePermission::collections_resolved_with`]. When `spaceType` is `*`
/// there is no declaration, so the default resolves to the empty set (no write
/// targets).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpaceCollections {
    /// `collection` was omitted; defaults to the space type declaration's
    /// `collections` (empty when `spaceType=*`).
    Default,
    /// `collection` was supplied explicitly (normalized; a `*` collapses to a
    /// single [`SpaceCollection::All`]).
    Explicit(BTreeSet<SpaceCollection>),
}

/// A parsed `space:` permission scope (0016 spec, lines 373-419).
///
/// - [`collection`](Self::collection) is [`SpaceCollections::Default`] when the
///   parameter is omitted (resolves to the declaration's collections at
///   enforcement time) or [`SpaceCollections::Explicit`] when supplied. An
///   explicit list containing `*` collapses to a single
///   [`SpaceCollection::All`]; otherwise it is a sorted, deduplicated set.
/// - [`action`](Self::action) is normalized to canonical action order and
///   defaults to [`SpaceAction::DEFAULT`] (`{read, create, update, delete}`)
///   when omitted.
/// - [`manage`](Self::manage) is empty by default; an ordinary record-access
///   grant confers no administrative capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpacePermission {
    /// The space type (NSID or `*`).
    pub space_type: SpaceType,
    /// The owner/authority DID (DID or `*`).
    pub did: SpaceDid,
    /// The space key (string or `*`).
    pub skey: SpaceSkey,
    /// The covered collections, or [`SpaceCollections::Default`] when omitted.
    pub collection: SpaceCollections,
    /// The granted record actions, always a subset of [`SpaceAction::ALL`].
    pub action: BTreeSet<SpaceAction>,
    /// The granted space-management verbs. Empty by default (no admin grant).
    pub manage: BTreeSet<SpaceManageVerb>,
}

/// A request-time **record** permission check against a granted
/// [`SpacePermission`].
///
/// The `collection` field is meaningful for the write actions
/// ([`SpaceAction::Create`], [`SpaceAction::Update`], [`SpaceAction::Delete`])
/// and for [`SpaceAction::ReadSelf`] reads; for whole-space [`SpaceAction::Read`]
/// it is ignored and may be left as [`None`].
///
/// For a read of the holder's own repo, request [`SpaceAction::ReadSelf`]
/// (collection-constrained, also satisfied by a `read` grant). For a read of
/// any repo in the space, request [`SpaceAction::Read`]. Management operations
/// use [`SpaceManageTarget`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpaceTarget {
    /// The space type being accessed (a concrete NSID; `*` is also accepted but
    /// only overlaps a grant whose type is also `*`).
    pub space_type: String,
    /// The authority DID being accessed.
    pub did: String,
    /// The space key being accessed.
    pub skey: String,
    /// The action being attempted.
    pub action: SpaceAction,
    /// The collection being acted on. Required for writes and `read_self`;
    /// ignored for whole-space `read`.
    pub collection: Option<String>,
}

impl SpaceTarget {
    /// Construct a collection-independent whole-space `read` target.
    pub fn new(
        space_type: impl Into<String>,
        did: impl Into<String>,
        skey: impl Into<String>,
        action: SpaceAction,
    ) -> Self {
        SpaceTarget {
            space_type: space_type.into(),
            did: did.into(),
            skey: skey.into(),
            action,
            collection: None,
        }
    }

    /// Construct a collection-bound target (`create`, `update`, `delete`, or a
    /// `read_self` read).
    pub fn with_collection(
        space_type: impl Into<String>,
        did: impl Into<String>,
        skey: impl Into<String>,
        action: SpaceAction,
        collection: impl Into<String>,
    ) -> Self {
        SpaceTarget {
            space_type: space_type.into(),
            did: did.into(),
            skey: skey.into(),
            action,
            collection: Some(collection.into()),
        }
    }
}

/// A request-time **space-management** permission check against a granted
/// [`SpacePermission`].
///
/// Management operations are governed by the grant's `manage` set, take a verb
/// (`create`/`update`/`delete`) applied to the space itself, and ignore
/// `collection` (spec lines 415-419).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpaceManageTarget {
    /// The space type being managed (a concrete NSID, or `*`).
    pub space_type: String,
    /// The authority DID being managed.
    pub did: String,
    /// The space key being managed.
    pub skey: String,
    /// The management verb being attempted.
    pub verb: SpaceManageVerb,
}

impl SpaceManageTarget {
    /// Construct a space-management target.
    pub fn new(
        space_type: impl Into<String>,
        did: impl Into<String>,
        skey: impl Into<String>,
        verb: SpaceManageVerb,
    ) -> Self {
        SpaceManageTarget {
            space_type: space_type.into(),
            did: did.into(),
            skey: skey.into(),
            verb,
        }
    }
}

impl SpacePermission {
    /// Parse a `space:` scope from its suffix (everything after `space`).
    ///
    /// The `suffix` is the remainder of the scope string after the `space`
    /// prefix has been stripped, beginning with either `:` (already removed by
    /// the caller, so a positional type) or `?` (a query string), matching the
    /// suffix handed to the other `Scope::parse_*` helpers.
    ///
    /// Returns a [`ParseError`] when the grammar or a parameter value is
    /// invalid (0016 spec, lines 373-384).
    pub(super) fn parse_suffix(suffix: Option<&str>) -> Result<SpacePermission, ParseError> {
        // Split the suffix into the positional `type` value and the query
        // string.
        let (positional, query) = match suffix {
            // `space?...` — query only, no positional type.
            Some(s) if s.starts_with('?') => (None, Some(&s[1..])),
            // `space:<type>` possibly followed by `?<query>`.
            Some(s) => {
                if let Some(pos) = s.find('?') {
                    let positional = &s[..pos];
                    (Some(positional), Some(&s[pos + 1..]))
                } else {
                    (Some(s), None)
                }
            }
            // Bare `space` — no type, which is invalid (type is required).
            None => (None, None),
        };

        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(query) = query
            && !query.is_empty()
        {
            for pair in query.split('&') {
                if let Some(eq) = pair.find('=') {
                    params.push((pair[..eq].to_string(), pair[eq + 1..].to_string()));
                } else {
                    // A key with no `=` is not part of the schema.
                    return Err(ParseError::InvalidResource(format!(
                        "space scope has malformed query parameter: {pair}"
                    )));
                }
            }
        }

        // Reject any query key that is not part of the schema. The five valid
        // query parameters are `did`, `skey`, `collection`, `action`, and
        // `manage` (spec lines 373-384).
        for (key, _) in &params {
            match key.as_str() {
                "did" | "skey" | "collection" | "action" | "manage" => {}
                "type" => {
                    // `type` is positional-only; it cannot be supplied as a
                    // named parameter alongside the positional value.
                    return Err(ParseError::InvalidResource(
                        "space scope 'type' must be positional, not a query parameter".to_string(),
                    ));
                }
                other => {
                    return Err(ParseError::InvalidResource(format!(
                        "space scope has unknown query parameter: {other}"
                    )));
                }
            }
        }

        // Resolve `type` (required positional).
        let space_type = match positional {
            Some(value) if !value.is_empty() => Self::parse_type(value)?,
            _ => return Err(ParseError::MissingResource),
        };

        // Resolve `did` (single, default `*`).
        let did = match Self::single_param(&params, "did")? {
            Some(value) => Self::parse_did(value)?,
            None => SpaceDid::All,
        };

        // Resolve `skey` (single, default `*`).
        let skey = match Self::single_param(&params, "skey")? {
            Some(value) => Self::parse_skey(value)?,
            None => SpaceSkey::All,
        };

        // Resolve `collection` (multi). When omitted, the default is the space
        // type declaration's `collections`, which the parser cannot resolve;
        // represent that intent as `SpaceCollections::Default`.
        let mut explicit_collection: BTreeSet<SpaceCollection> = BTreeSet::new();
        let mut saw_collection = false;
        for (key, value) in &params {
            if key == "collection" {
                saw_collection = true;
                explicit_collection.insert(Self::parse_collection(value)?);
            }
        }
        let collection = if saw_collection {
            normalize_collection(&mut explicit_collection);
            SpaceCollections::Explicit(explicit_collection)
        } else {
            SpaceCollections::Default
        };

        // Resolve `action` (multi, default = {read, create, update, delete}).
        let mut action: BTreeSet<SpaceAction> = BTreeSet::new();
        for (key, value) in &params {
            if key == "action" {
                let parsed = SpaceAction::from_wire(value)
                    .ok_or_else(|| ParseError::InvalidAction(value.clone()))?;
                action.insert(parsed);
            }
        }
        if action.is_empty() {
            action.extend(SpaceAction::DEFAULT);
        }

        // Resolve `manage` (multi, default = none).
        let mut manage: BTreeSet<SpaceManageVerb> = BTreeSet::new();
        for (key, value) in &params {
            if key == "manage" {
                let parsed = SpaceManageVerb::from_wire(value)
                    .ok_or_else(|| ParseError::InvalidAction(value.clone()))?;
                manage.insert(parsed);
            }
        }

        Ok(SpacePermission {
            space_type,
            did,
            skey,
            collection,
            action,
            manage,
        })
    }

    /// Extract a single-valued parameter, returning an error when it appears
    /// more than once (`did` and `skey` are single-valued per the spec param
    /// table, line 384).
    fn single_param<'a>(
        params: &'a [(String, String)],
        key: &str,
    ) -> Result<Option<&'a str>, ParseError> {
        let mut found: Option<&'a str> = None;
        for (k, v) in params {
            if k == key {
                if found.is_some() {
                    return Err(ParseError::InvalidResource(format!(
                        "space scope '{key}' may only appear once"
                    )));
                }
                found = Some(v.as_str());
            }
        }
        Ok(found)
    }

    fn parse_type(value: &str) -> Result<SpaceType, ParseError> {
        if value == "*" {
            Ok(SpaceType::All)
        } else {
            Ok(SpaceType::Nsid(value.to_string()))
        }
    }

    fn parse_did(value: &str) -> Result<SpaceDid, ParseError> {
        if value == "*" {
            Ok(SpaceDid::All)
        } else {
            Ok(SpaceDid::Did(value.to_string()))
        }
    }

    fn parse_skey(value: &str) -> Result<SpaceSkey, ParseError> {
        if value == "*" {
            Ok(SpaceSkey::All)
        } else if value.is_empty() || value.chars().count() > SKEY_MAX_LENGTH {
            Err(ParseError::InvalidResource(format!(
                "space scope 'skey' must be non-empty and at most {SKEY_MAX_LENGTH} characters"
            )))
        } else {
            Ok(SpaceSkey::Key(value.to_string()))
        }
    }

    fn parse_collection(value: &str) -> Result<SpaceCollection, ParseError> {
        if value == "*" {
            Ok(SpaceCollection::All)
        } else {
            Ok(SpaceCollection::Nsid(value.to_string()))
        }
    }

    /// Format this permission back into its canonical scope string.
    ///
    /// Parameters equal to their default are omitted:
    ///
    /// - `did=*`, `skey=*` are omitted.
    /// - `collection` is omitted when [`SpaceCollections::Default`].
    /// - `action` is omitted when it is exactly the default action set
    ///   (`{read, create, update, delete}`).
    /// - `manage` is omitted when empty.
    ///
    /// The result round-trips through [`SpacePermission::parse_suffix`].
    pub fn to_scope_string(&self) -> String {
        let positional = match &self.space_type {
            SpaceType::All => "*".to_string(),
            SpaceType::Nsid(nsid) => nsid.clone(),
        };

        let mut params: Vec<String> = Vec::new();

        // did (default `*`).
        if let SpaceDid::Did(did) = &self.did {
            params.push(format!("did={did}"));
        }

        // skey (default `*`).
        if let SpaceSkey::Key(skey) = &self.skey {
            params.push(format!("skey={skey}"));
        }

        // collection (omitted when Default). BTreeSet iteration is sorted.
        if let SpaceCollections::Explicit(set) = &self.collection {
            for c in set {
                match c {
                    SpaceCollection::All => params.push("collection=*".to_string()),
                    SpaceCollection::Nsid(nsid) => params.push(format!("collection={nsid}")),
                }
            }
        }

        // action (default = {read, create, update, delete}). BTreeSet iteration
        // yields canonical order (read_self, read, create, update, delete).
        if !self.is_default_action_set() {
            for a in &self.action {
                params.push(format!("action={}", a.as_str()));
            }
        }

        // manage (default = none).
        for m in &self.manage {
            params.push(format!("manage={}", m.as_str()));
        }

        if params.is_empty() {
            format!("space:{positional}")
        } else {
            format!("space:{positional}?{}", params.join("&"))
        }
    }

    /// Returns `true` when the action set is exactly the default action set
    /// (`{read, create, update, delete}`), in which case it is omitted from the
    /// formatted scope string.
    fn is_default_action_set(&self) -> bool {
        self.action.len() == SpaceAction::DEFAULT.len()
            && SpaceAction::DEFAULT.iter().all(|a| self.action.contains(a))
    }

    /// Returns `true` when `space_type`/`did`/`skey` of this grant overlap the
    /// given target components (each grant component is `*` or equal).
    fn tuple_overlaps(&self, space_type: &str, did: &str, skey: &str) -> bool {
        if let SpaceType::Nsid(t) = &self.space_type
            && t != space_type
        {
            return false;
        }
        if let SpaceDid::Did(d) = &self.did
            && d != did
        {
            return false;
        }
        if let SpaceSkey::Key(s) = &self.skey
            && s != skey
        {
            return false;
        }
        true
    }

    /// Resolve this grant's effective collection set, using `declared` as the
    /// default when `collection` was omitted (spec line 413). `declared` should
    /// be the space type declaration's `collections`; pass an empty slice when
    /// `spaceType=*` (no declaration) — the default then confers no write
    /// targets.
    pub fn collections_resolved_with(&self, declared: &[String]) -> BTreeSet<SpaceCollection> {
        match &self.collection {
            SpaceCollections::Explicit(set) => set.clone(),
            SpaceCollections::Default => declared
                .iter()
                .map(|nsid| SpaceCollection::Nsid(nsid.clone()))
                .collect(),
        }
    }

    /// Check whether this granted permission satisfies the given request-time
    /// record [`SpaceTarget`], resolving the collection default against the
    /// space type's `declared` collections (spec lines 407-413).
    ///
    /// 1. Tuple gate: `spaceType`, `did`, `skey` must each be `*` or equal the
    ///    target.
    /// 2. `read`: granted if the action set includes `read`; ignores collection.
    /// 3. `read_self`: granted if the action set includes `read_self` **or**
    ///    `read` (read implies read_self) **and** the target collection is
    ///    covered.
    /// 4. `create` / `update` / `delete`: granted if the action set includes
    ///    the action **and** the target collection is covered.
    pub fn matches_with(&self, target: &SpaceTarget, declared: &[String]) -> bool {
        if !self.tuple_overlaps(&target.space_type, &target.did, &target.skey) {
            return false;
        }

        match target.action {
            // Whole-space read ignores collection.
            SpaceAction::Read => self.action.contains(&SpaceAction::Read),
            // Own-repo read: read implies read_self; collection-constrained.
            SpaceAction::ReadSelf => {
                if !(self.action.contains(&SpaceAction::ReadSelf)
                    || self.action.contains(&SpaceAction::Read))
                {
                    return false;
                }
                // A `read` grant covers every collection for the own repo too.
                if self.action.contains(&SpaceAction::Read) {
                    return true;
                }
                self.collection_covers(target.collection.as_deref(), declared)
            }
            // Writes require the action AND collection coverage.
            SpaceAction::Create | SpaceAction::Update | SpaceAction::Delete => {
                if !self.action.contains(&target.action) {
                    return false;
                }
                self.collection_covers(target.collection.as_deref(), declared)
            }
        }
    }

    /// Check whether this granted permission satisfies the given record target,
    /// treating an omitted-`collection` grant as conferring **no** write
    /// targets (the `spaceType=*` / no-declaration case). Convenience wrapper
    /// over [`matches_with`](Self::matches_with) with an empty declared list.
    pub fn matches(&self, target: &SpaceTarget) -> bool {
        self.matches_with(target, &[])
    }

    /// Whether this grant's collection set (resolved against `declared`) covers
    /// the target collection.
    fn collection_covers(&self, target: Option<&str>, declared: &[String]) -> bool {
        let resolved = self.collections_resolved_with(declared);
        if resolved.contains(&SpaceCollection::All) {
            return true;
        }
        match target {
            Some(c) => resolved.contains(&SpaceCollection::Nsid(c.to_string())),
            None => false,
        }
    }

    /// Check whether this granted permission satisfies the given space-management
    /// [`SpaceManageTarget`] (spec lines 415-419): the tuple must overlap and the
    /// grant's `manage` set must contain the requested verb. `manage` ignores
    /// `collection`.
    pub fn matches_manage(&self, target: &SpaceManageTarget) -> bool {
        if !self.tuple_overlaps(&target.space_type, &target.did, &target.skey) {
            return false;
        }
        self.manage.contains(&target.verb)
    }

    /// Build the minimal `space:` scope string that would satisfy the given
    /// record target.
    ///
    /// For whole-space `read` the result is collection-independent; for
    /// `read_self` and write actions the target's collection is included.
    pub fn scope_needed_for(target: &SpaceTarget) -> String {
        let space_type = nsid_or_all(&target.space_type);
        let did = did_or_all(&target.did);
        let skey = skey_or_all(&target.skey);

        let collection_independent = matches!(target.action, SpaceAction::Read);

        let collection = if collection_independent {
            SpaceCollections::Explicit(BTreeSet::new())
        } else {
            let mut set: BTreeSet<SpaceCollection> = BTreeSet::new();
            if let Some(c) = &target.collection {
                set.insert(if c == "*" {
                    SpaceCollection::All
                } else {
                    SpaceCollection::Nsid(c.clone())
                });
            }
            normalize_collection(&mut set);
            SpaceCollections::Explicit(set)
        };

        let mut action: BTreeSet<SpaceAction> = BTreeSet::new();
        action.insert(target.action);

        SpacePermission {
            space_type,
            did,
            skey,
            collection,
            action,
            manage: BTreeSet::new(),
        }
        .to_scope_string()
    }

    /// Build the minimal `space:` scope string that would satisfy the given
    /// space-management target (a single `manage` verb, collection-independent).
    pub fn scope_needed_for_manage(target: &SpaceManageTarget) -> String {
        let mut manage: BTreeSet<SpaceManageVerb> = BTreeSet::new();
        manage.insert(target.verb);

        SpacePermission {
            space_type: nsid_or_all(&target.space_type),
            did: did_or_all(&target.did),
            skey: skey_or_all(&target.skey),
            // No record actions and no collection — manage only.
            collection: SpaceCollections::Explicit(BTreeSet::new()),
            action: BTreeSet::new(),
            manage,
        }
        .to_scope_string()
    }
}

/// Convert a target type string into a [`SpaceType`] (`*` → `All`).
fn nsid_or_all(value: &str) -> SpaceType {
    if value == "*" {
        SpaceType::All
    } else {
        SpaceType::Nsid(value.to_string())
    }
}

/// Convert a target DID string into a [`SpaceDid`] (`*` → `All`).
fn did_or_all(value: &str) -> SpaceDid {
    if value == "*" {
        SpaceDid::All
    } else {
        SpaceDid::Did(value.to_string())
    }
}

/// Convert a target skey string into a [`SpaceSkey`] (`*` → `All`).
fn skey_or_all(value: &str) -> SpaceSkey {
    if value == "*" {
        SpaceSkey::All
    } else {
        SpaceSkey::Key(value.to_string())
    }
}

/// Normalize a collection set: if it contains `*`, collapse to just `*`.
///
/// Deduplication and sorting are already handled by the [`BTreeSet`].
fn normalize_collection(collection: &mut BTreeSet<SpaceCollection>) {
    if collection.len() > 1 && collection.contains(&SpaceCollection::All) {
        collection.clear();
        collection.insert(SpaceCollection::All);
    }
}

impl fmt::Display for SpacePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_scope_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scopes::Scope;

    /// Parse a full `space:` scope string into a [`SpacePermission`].
    fn parse(scope: &str) -> SpacePermission {
        match Scope::parse(scope).unwrap() {
            Scope::Space(permission) => permission,
            other => panic!("expected space scope, got {other:?}"),
        }
    }

    fn collections(values: &[SpaceCollection]) -> SpaceCollections {
        SpaceCollections::Explicit(values.iter().cloned().collect())
    }

    fn actions(values: &[SpaceAction]) -> BTreeSet<SpaceAction> {
        values.iter().copied().collect()
    }

    fn manages(values: &[SpaceManageVerb]) -> BTreeSet<SpaceManageVerb> {
        values.iter().copied().collect()
    }

    #[test]
    fn test_parse_minimal_type_only() {
        let permission = parse("space:com.example.space");
        assert_eq!(
            permission.space_type,
            SpaceType::Nsid("com.example.space".to_string())
        );
        // Defaults: did=*, skey=*, collection=Default, action={read,create,
        // update,delete} (no read_self/no manage), manage empty.
        assert_eq!(permission.did, SpaceDid::All);
        assert_eq!(permission.skey, SpaceSkey::All);
        assert_eq!(permission.collection, SpaceCollections::Default);
        assert_eq!(permission.action, actions(&SpaceAction::DEFAULT));
        assert!(permission.manage.is_empty());
    }

    #[test]
    fn test_parse_type_wildcard() {
        let permission = parse("space:*");
        assert_eq!(permission.space_type, SpaceType::All);
    }

    #[test]
    fn test_parse_all_params() {
        let permission = parse(
            "space:com.example.space?did=did:plc:abc&skey=my-space&collection=com.example.note&collection=com.example.photo&action=read&action=create&manage=update",
        );
        assert_eq!(
            permission.space_type,
            SpaceType::Nsid("com.example.space".to_string())
        );
        assert_eq!(permission.did, SpaceDid::Did("did:plc:abc".to_string()));
        assert_eq!(permission.skey, SpaceSkey::Key("my-space".to_string()));
        assert_eq!(
            permission.collection,
            collections(&[
                SpaceCollection::Nsid("com.example.note".to_string()),
                SpaceCollection::Nsid("com.example.photo".to_string()),
            ])
        );
        assert_eq!(
            permission.action,
            actions(&[SpaceAction::Read, SpaceAction::Create])
        );
        assert_eq!(permission.manage, manages(&[SpaceManageVerb::Update]));
    }

    #[test]
    fn test_parse_read_self_action() {
        let permission = parse("space:com.example.space?action=read_self");
        assert_eq!(permission.action, actions(&[SpaceAction::ReadSelf]));
    }

    #[test]
    fn test_parse_manage_is_separate_param() {
        // `manage` is its own parameter, distinct from `action`.
        let permission = parse("space:com.example.space?manage=create&manage=delete");
        // action keeps its default; manage carries the verbs.
        assert_eq!(permission.action, actions(&SpaceAction::DEFAULT));
        assert_eq!(
            permission.manage,
            manages(&[SpaceManageVerb::Create, SpaceManageVerb::Delete])
        );
    }

    #[test]
    fn test_parse_manage_invalid_verb_is_error() {
        assert!(Scope::parse("space:com.example.space?manage=read").is_err());
    }

    #[test]
    fn test_parse_wildcards_in_params() {
        let permission = parse("space:*?did=*&skey=*&collection=*");
        assert_eq!(permission.space_type, SpaceType::All);
        assert_eq!(permission.did, SpaceDid::All);
        assert_eq!(permission.skey, SpaceSkey::All);
        assert_eq!(permission.collection, collections(&[SpaceCollection::All]));
    }

    #[test]
    fn test_parse_collection_wildcard_collapses() {
        // A `*` mixed with NSIDs collapses to just `*`.
        let permission = parse("space:com.example.space?collection=com.example.note&collection=*");
        assert_eq!(permission.collection, collections(&[SpaceCollection::All]));
    }

    #[test]
    fn test_parse_collection_dedup() {
        let permission = parse(
            "space:com.example.space?collection=com.example.note&collection=com.example.note",
        );
        assert_eq!(
            permission.collection,
            collections(&[SpaceCollection::Nsid("com.example.note".to_string())])
        );
    }

    #[test]
    fn test_parse_missing_type_is_error() {
        assert!(Scope::parse("space").is_err());
        assert!(Scope::parse("space:").is_err());
        assert!(Scope::parse("space?did=did:plc:abc").is_err());
    }

    #[test]
    fn test_parse_unknown_param_is_error() {
        assert!(Scope::parse("space:com.example.space?bogus=1").is_err());
    }

    #[test]
    fn test_parse_type_as_named_param_is_error() {
        assert!(Scope::parse("space:com.example.space?type=other").is_err());
    }

    #[test]
    fn test_parse_invalid_action_is_error() {
        assert!(Scope::parse("space:com.example.space?action=write").is_err());
        // `manage` is no longer a valid action value (it is its own param).
        assert!(Scope::parse("space:com.example.space?action=manage").is_err());
    }

    #[test]
    fn test_parse_duplicate_single_param_is_error() {
        assert!(Scope::parse("space:com.example.space?did=did:a&did=did:b").is_err());
        assert!(Scope::parse("space:com.example.space?skey=a&skey=b").is_err());
    }

    #[test]
    fn test_parse_skey_length_limits() {
        // Empty skey is invalid.
        assert!(Scope::parse("space:com.example.space?skey=").is_err());

        // 512 chars is allowed.
        let ok = "x".repeat(512);
        assert!(Scope::parse(&format!("space:com.example.space?skey={ok}")).is_ok());

        // 513 chars is rejected.
        let too_long = "x".repeat(513);
        assert!(Scope::parse(&format!("space:com.example.space?skey={too_long}")).is_err());
    }

    #[test]
    fn test_format_omits_defaults() {
        // Type-only round-trips to itself; defaults omitted.
        let permission = parse("space:com.example.space");
        assert_eq!(permission.to_scope_string(), "space:com.example.space");

        // Explicit defaults are stripped on format.
        let permission = parse("space:com.example.space?did=*&skey=*");
        assert_eq!(permission.to_scope_string(), "space:com.example.space");

        // The default action set ({read,create,update,delete}) is omitted.
        let permission =
            parse("space:com.example.space?action=read&action=create&action=update&action=delete");
        assert_eq!(permission.to_scope_string(), "space:com.example.space");
    }

    #[test]
    fn test_format_includes_non_defaults() {
        let permission = parse(
            "space:com.example.space?did=did:plc:abc&skey=my-space&collection=com.example.note&action=read",
        );
        assert_eq!(
            permission.to_scope_string(),
            "space:com.example.space?did=did:plc:abc&skey=my-space&collection=com.example.note&action=read"
        );
    }

    #[test]
    fn test_format_includes_manage() {
        let permission = parse("space:com.example.space?manage=update&manage=delete");
        assert_eq!(
            permission.to_scope_string(),
            "space:com.example.space?manage=update&manage=delete"
        );
    }

    #[test]
    fn test_round_trip() {
        let cases = [
            "space:com.example.space",
            "space:*",
            "space:com.example.space?did=did:plc:abc",
            "space:com.example.space?skey=my-space",
            "space:com.example.space?collection=com.example.note",
            "space:com.example.space?collection=*",
            "space:com.example.space?action=read",
            "space:com.example.space?action=read_self",
            "space:com.example.space?action=create&action=update",
            "space:com.example.space?manage=update",
            "space:com.example.space?action=read_self&manage=update&manage=delete",
            "space:com.example.space?did=did:plc:abc&skey=s&collection=a.b.c&action=read&action=create",
        ];

        for case in cases {
            let first = parse(case);
            let formatted = first.to_scope_string();
            let second = parse(&formatted);
            assert_eq!(first, second, "round-trip mismatch for {case}");
            // Formatting is idempotent.
            assert_eq!(formatted, second.to_scope_string());
        }
    }

    // --- Matching matrix ---

    #[test]
    fn test_match_tuple_gate() {
        let grant = parse("space:com.example.space?did=did:plc:abc&skey=s1");

        // Exact tuple matches for read (read is in default action set).
        assert!(grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));

        // Wrong type, did, or skey each block.
        assert!(!grant.matches(&SpaceTarget::new(
            "com.other.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));
        assert!(!grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:xyz",
            "s1",
            SpaceAction::Read,
        )));
        assert!(!grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s2",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_match_tuple_wildcards() {
        let grant = parse("space:*");
        // type/did/skey all `*` overlap any concrete tuple.
        assert!(grant.matches(&SpaceTarget::new(
            "anything",
            "did:plc:zzz",
            "whatever",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_match_read_does_not_imply_write_or_manage() {
        // A read grant does not confer create.
        let grant = parse("space:com.example.space?action=read");
        assert!(!grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        )));
        // A grant without read does not confer whole-space read.
        let grant = parse("space:com.example.space?action=create&collection=com.example.note");
        assert!(!grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_match_read_implies_read_self() {
        // A whole-space `read` grant satisfies a read_self request and is not
        // collection-constrained for the own repo.
        let grant = parse("space:com.example.space?action=read");
        assert!(grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::ReadSelf,
            "any.collection.here",
        )));
    }

    #[test]
    fn test_match_read_self_is_collection_constrained() {
        // A read_self grant covers only the listed collection on the own repo.
        let grant = parse("space:com.example.space?action=read_self&collection=com.example.note");
        assert!(grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::ReadSelf,
            "com.example.note",
        )));
        // A different collection is not covered.
        assert!(!grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::ReadSelf,
            "com.example.photo",
        )));
        // read_self does NOT confer whole-space read.
        assert!(!grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_match_manage_verbs() {
        let grant = parse("space:com.example.space?manage=update");
        // The granted verb is permitted; collection is ignored.
        assert!(grant.matches_manage(&SpaceManageTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceManageVerb::Update,
        )));
        // A different verb is not.
        assert!(!grant.matches_manage(&SpaceManageTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceManageVerb::Create,
        )));
    }

    #[test]
    fn test_match_bare_grant_confers_no_manage() {
        // An ordinary record-access grant confers no administrative capability.
        let grant = parse("space:com.example.space");
        for verb in SpaceManageVerb::ALL {
            assert!(!grant.matches_manage(&SpaceManageTarget::new(
                "com.example.space",
                "did:plc:abc",
                "s1",
                verb,
            )));
        }
    }

    #[test]
    fn test_match_write_requires_action_and_collection() {
        let grant = parse(
            "space:com.example.space?collection=com.example.note&action=create&action=update",
        );

        // create on the covered collection is granted.
        assert!(grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        )));

        // delete is not in the action list.
        assert!(!grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Delete,
            "com.example.note",
        )));

        // create on a different collection is not covered.
        assert!(!grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.photo",
        )));
    }

    #[test]
    fn test_match_write_collection_wildcard() {
        let grant = parse("space:com.example.space?collection=*&action=create");
        assert!(grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "any.collection.here",
        )));
    }

    #[test]
    fn test_match_collection_default_resolves_to_declared() {
        // A bare grant defaults `collection` to the declared collections.
        let grant = parse("space:com.example.space");
        assert!(grant.action.contains(&SpaceAction::Create));
        assert_eq!(grant.collection, SpaceCollections::Default);

        let declared = vec!["com.example.note".to_string()];

        // With no declared collections (e.g. spaceType=*), writes are blocked.
        assert!(!grant.matches(&SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        )));

        // With the declared collections resolved in, the write is permitted.
        assert!(grant.matches_with(
            &SpaceTarget::with_collection(
                "com.example.space",
                "did:plc:abc",
                "s1",
                SpaceAction::Create,
                "com.example.note",
            ),
            &declared,
        ));
        // A collection outside the declaration is still blocked.
        assert!(!grant.matches_with(
            &SpaceTarget::with_collection(
                "com.example.space",
                "did:plc:abc",
                "s1",
                SpaceAction::Create,
                "com.example.photo",
            ),
            &declared,
        ));

        // Whole-space read is allowed regardless of collection.
        assert!(grant.matches(&SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Read,
        )));
    }

    #[test]
    fn test_collections_resolved_with() {
        let bare = parse("space:com.example.space");
        let declared = vec!["a.b.c".to_string(), "d.e.f".to_string()];
        assert_eq!(
            bare.collections_resolved_with(&declared),
            [
                SpaceCollection::Nsid("a.b.c".to_string()),
                SpaceCollection::Nsid("d.e.f".to_string())
            ]
            .into_iter()
            .collect()
        );

        // An explicit list ignores the declaration.
        let explicit = parse("space:com.example.space?collection=x.y.z");
        assert_eq!(
            explicit.collections_resolved_with(&declared),
            [SpaceCollection::Nsid("x.y.z".to_string())]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn test_match_write_without_target_collection_is_false() {
        let grant = parse("space:com.example.space?collection=com.example.note&action=create");
        // A write target with no collection cannot match a non-wildcard grant.
        let target = SpaceTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
        );
        assert!(!grant.matches(&target));
    }

    // --- scope_needed_for ---

    #[test]
    fn test_scope_needed_for_read_is_collection_independent() {
        let target = SpaceTarget::new("com.example.space", "did:plc:abc", "s1", SpaceAction::Read);
        assert_eq!(
            SpacePermission::scope_needed_for(&target),
            "space:com.example.space?did=did:plc:abc&skey=s1&action=read"
        );
    }

    #[test]
    fn test_scope_needed_for_manage_is_collection_independent() {
        let target = SpaceManageTarget::new(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceManageVerb::Update,
        );
        assert_eq!(
            SpacePermission::scope_needed_for_manage(&target),
            "space:com.example.space?did=did:plc:abc&skey=s1&manage=update"
        );
    }

    #[test]
    fn test_scope_needed_for_write_includes_collection() {
        let target = SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Create,
            "com.example.note",
        );
        assert_eq!(
            SpacePermission::scope_needed_for(&target),
            "space:com.example.space?did=did:plc:abc&skey=s1&collection=com.example.note&action=create"
        );
    }

    #[test]
    fn test_scope_needed_for_round_trips_and_satisfies() {
        let target = SpaceTarget::with_collection(
            "com.example.space",
            "did:plc:abc",
            "s1",
            SpaceAction::Update,
            "com.example.note",
        );
        let scope = SpacePermission::scope_needed_for(&target);
        let permission = parse(&scope);
        assert!(permission.matches(&target));
    }
}
