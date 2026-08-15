//! Schema file parsing and structure
//!
//! A SchemaFile represents a parsed lexicon JSON file.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::validation::data_errors::DataValidationError;
use crate::validation::schema::{
    PERMISSION_RESOURCES, PERMISSION_RESOURCES_WITHOUT_NSIDS, Permission, PermissionSetSchema,
    REPO_ACTIONS, SPACE_MANAGE_VERBS, SchemaDef, SpaceSchema,
};
use crate::validation::syntax::validate_nsid;

/// The current lexicon version
pub const LEXICON_VERSION: i32 = 1;

/// A parsed lexicon schema file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaFile {
    /// Lexicon version (must be 1)
    pub lexicon: i32,
    /// The NSID for this lexicon (e.g., "app.bsky.feed.post")
    pub id: String,
    /// Revision number (optional, for versioning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<i32>,
    /// Description of the lexicon
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Type definitions
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub defs: IndexMap<String, SchemaDef>,
}

impl SchemaFile {
    /// Parse a lexicon JSON string
    pub fn parse(json: &str) -> Result<Self, DataValidationError> {
        let file: SchemaFile =
            serde_json::from_str(json).map_err(|e| DataValidationError::SchemaParseError {
                message: e.to_string(),
            })?;
        file.validate_structure()?;
        Ok(file)
    }

    /// Parse from a JSON value
    pub fn from_value(value: serde_json::Value) -> Result<Self, DataValidationError> {
        let file: SchemaFile =
            serde_json::from_value(value).map_err(|e| DataValidationError::SchemaParseError {
                message: e.to_string(),
            })?;
        file.validate_structure()?;
        Ok(file)
    }

    /// Validate the structure of the schema file
    pub fn validate_structure(&self) -> Result<(), DataValidationError> {
        if self.lexicon != LEXICON_VERSION {
            return Err(DataValidationError::UnsupportedLexiconVersion {
                version: self.lexicon,
            });
        }
        validate_nsid(&self.id)?;
        if self.defs.is_empty() {
            return Err(DataValidationError::SchemaStructureInvalid {
                message: "lexicon must have at least one definition".to_string(),
            });
        }
        let mut primary_count = 0;
        for (name, def) in &self.defs {
            if def.is_primary() {
                primary_count += 1;
                if name != "main" {
                    return Err(DataValidationError::SchemaStructureInvalid {
                        message: format!("primary type definition '{}' must be named 'main'", name),
                    });
                }
            }
        }
        if primary_count > 1 {
            return Err(DataValidationError::SchemaStructureInvalid {
                message: "lexicon must have at most one primary type definition".to_string(),
            });
        }
        for (name, _def) in &self.defs {
            validate_def_name(name)?;
        }
        for (name, def) in &self.defs {
            Self::validate_def_is_a_user_type(name, def)?;
        }
        for def in self.defs.values() {
            match def {
                SchemaDef::PermissionSet(ps) => validate_permission_set(ps, &self.id)?,
                SchemaDef::Space(space) => validate_space(space)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Reject definition types that are only meaningful *inside* another
    /// definition.
    ///
    /// `ref`, `union` and `params` describe how a field relates to something
    /// else, so they say nothing on their own: a top-level `ref` is a pointer
    /// with no one holding it, and a `params` is the query-string half of an
    /// endpoint that is not there. The reference lists the types a definition
    /// may take (`lexUserType`, `packages/lexicon/src/types.ts:372-404`) and
    /// none of the three appears in it.
    ///
    /// This matters more than an invalid record does. A record that should not
    /// validate is one bad record; a schema that should not parse is every
    /// record validated against it, and the mistake is inherited rather than
    /// repeated.
    fn validate_def_is_a_user_type(name: &str, def: &SchemaDef) -> Result<(), DataValidationError> {
        let type_name = def.type_name();
        if matches!(
            def,
            SchemaDef::Ref(_) | SchemaDef::Union(_) | SchemaDef::Params(_)
        ) {
            return Err(DataValidationError::SchemaStructureInvalid {
                message: format!(
                    "definition '{name}' has type '{type_name}', which is only valid inside another definition, not as a definition itself"
                ),
            });
        }
        Ok(())
    }

    /// Get the main definition
    pub fn main(&self) -> Option<&SchemaDef> {
        self.defs.get("main")
    }

    /// Get a definition by name
    pub fn get_def(&self, name: &str) -> Option<&SchemaDef> {
        self.defs.get(name)
    }

    /// Resolve a reference within this schema file
    pub fn resolve_local_ref(&self, ref_path: &str) -> Option<&SchemaDef> {
        if let Some(def_name) = ref_path.strip_prefix('#') {
            self.defs.get(def_name)
        } else {
            None
        }
    }

    /// Get all definition names
    pub fn def_names(&self) -> impl Iterator<Item = &str> {
        self.defs.keys().map(|s| s.as_str())
    }

    /// Get the full reference path for a definition
    pub fn full_ref(&self, def_name: &str) -> String {
        if def_name == "main" {
            self.id.clone()
        } else {
            format!("{}#{}", self.id, def_name)
        }
    }
}

fn validate_def_name(name: &str) -> Result<(), DataValidationError> {
    let Some(&first) = name.as_bytes().first() else {
        return Err(DataValidationError::SchemaStructureInvalid {
            message: "definition name cannot be empty".to_string(),
        });
    };
    if !first.is_ascii_lowercase() {
        return Err(DataValidationError::SchemaStructureInvalid {
            message: format!(
                "definition name '{}' must start with a lowercase letter",
                name
            ),
        });
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(DataValidationError::SchemaStructureInvalid {
            message: format!("definition name '{}' must be alphanumeric", name),
        });
    }
    Ok(())
}

fn validate_permission_set(
    ps: &PermissionSetSchema,
    lexicon_id: &str,
) -> Result<(), DataValidationError> {
    if ps.title.is_none() {
        return Err(DataValidationError::PermissionSetMissingTitle);
    }
    if ps.get_detail().is_none() {
        return Err(DataValidationError::PermissionSetMissingDetail);
    }
    if ps.permissions.is_empty() {
        return Err(DataValidationError::PermissionSetEmptyPermissions);
    }
    let namespace = extract_namespace(lexicon_id);
    for permission in &ps.permissions {
        validate_permission(permission, namespace)?;
    }
    Ok(())
}

fn extract_namespace(nsid: &str) -> &str {
    if let Some(last_dot) = nsid.rfind('.') {
        &nsid[..last_dot]
    } else {
        nsid
    }
}

fn nsid_in_namespace(nsid: &str, namespace: &str) -> bool {
    nsid.starts_with(namespace)
        && nsid.len() > namespace.len()
        && nsid.as_bytes()[namespace.len()] == b'.'
}

/// Whether a permission's NSID may be granted by a permission set declared in
/// `lexicon_nsid`.
///
/// **This is a security check and it has no caller yet.** It is the rule that
/// stops `app.evil.authFull` from declaring `repo:com.yourbank.records`: an
/// `include:` scope names a permission set, so the user consents to a *name*
/// rather than to a list they have read, and only this constraint keeps a
/// lexicon author inside namespaces they actually control.
///
/// It lives here, unwired, rather than in [`validate_permission_set`], because
/// the reference applies it when an `include:` scope is *resolved* — see
/// `isAllowedPermission` in `@atproto/oauth-scopes`, which drops offending
/// permissions instead of rejecting the document that carries them. Enforcing
/// it at parse time made this crate refuse whole lexicons the reference reads
/// happily, losing every unrelated definition in the same file along with them.
///
/// This workspace does not resolve `include:` scopes at all — `Scope::Include`
/// grants only itself — so there is currently no grant path for an
/// out-of-authority permission to travel down. **Whoever builds that path must
/// call this**, or the escalation it prevents becomes reachable. A guard test in
/// `atproto-oauth` fails the moment `include:` starts granting anything, so this
/// cannot be forgotten silently.
///
/// The authority is the lexicon's NSID minus its final segment, matching the
/// reference's `lastIndexOf('.')`: `example.lexicon.perms` has authority
/// `example.lexicon`, which admits `example.lexicon.endpoint` and refuses
/// `com.example.calendar.event`.
pub fn permission_within_authority(nsid: &str, lexicon_nsid: &str) -> bool {
    nsid_in_namespace(nsid, extract_namespace(lexicon_nsid))
}

fn validate_permission(
    permission: &Permission,
    namespace: &str,
) -> Result<(), DataValidationError> {
    if permission.type_field != "permission" {
        return Err(DataValidationError::PermissionInvalidType {
            got: permission.type_field.clone(),
        });
    }
    if !PERMISSION_RESOURCES.contains(&permission.resource.as_str()) {
        return Err(DataValidationError::PermissionInvalidResource {
            resource: permission.resource.clone(),
        });
    }
    match permission.resource.as_str() {
        "repo" => {
            validate_repo_permission(permission)?;
        }
        "rpc" => {
            validate_rpc_permission(permission)?;
        }
        "space" => {
            validate_space_permission(permission, namespace)?;
        }
        "include" => {
            validate_include_permission(permission, namespace)?;
        }
        // Only resources that name no NSID reach here, and they are named
        // rather than defaulted: `PERMISSION_RESOURCES_WITHOUT_NSIDS` is
        // asserted to be exactly this set, so adding a resource without
        // deciding how the Namespace Authority rule applies to it fails a
        // test instead of silently exempting it.
        other => debug_assert!(
            PERMISSION_RESOURCES_WITHOUT_NSIDS.contains(&other),
            "permission resource {other:?} names no validator and is not listed as NSID-free"
        ),
    }
    Ok(())
}

/// Refuse a wildcard where a permission set requires a concrete NSID.
///
/// `*` is legal in an OAuth scope *string* — there the user is granting it
/// directly and can see what they are granting. A permission set is published
/// under one authority and read by everyone, so a wildcard inside one would
/// grant beyond that authority, which is precisely what the Namespace
/// Authority rule exists to prevent. The spec says so outright: "Wildcards are
/// not supported in permissions within a permission set."
///
/// Checked before the NSID syntax check so `*` is reported as a wildcard
/// rather than as a malformed NSID, which is a different problem with a
/// different fix.
fn reject_wildcard(value: &str, resource: &str) -> Result<(), DataValidationError> {
    if value == "*" || value.contains('*') {
        return Err(DataValidationError::PermissionWildcardInSet {
            resource: resource.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Validate an `include` permission entry.
///
/// `include` references another permission set, and is the one resource whose
/// grant is *transitive*: whatever the referenced set contains is inherited.
/// The Namespace Authority rule therefore matters more here than anywhere
/// else. Without it, a set could name a set under an unrelated authority and
/// inherit permissions its own namespace does not cover — one hop, and the
/// rule is gone.
fn validate_include_permission(
    permission: &Permission,
    namespace: &str,
) -> Result<(), DataValidationError> {
    let nsid = permission
        .nsid
        .as_ref()
        .ok_or(DataValidationError::PermissionMissingNsid)?;

    reject_wildcard(nsid, "include")?;

    if let Err(e) = validate_nsid(nsid) {
        return Err(DataValidationError::PermissionInvalidIncludeNsid {
            nsid: nsid.clone(),
            reason: e.to_string(),
        });
    }

    if !nsid_in_namespace(nsid, namespace) {
        return Err(DataValidationError::PermissionNsidOutsideNamespace {
            nsid: nsid.clone(),
            namespace: namespace.to_string(),
        });
    }

    Ok(())
}

/// Validate a `space` permission entry.
///
/// The `collection` list may be wildcard (`*`) or list collections under a
/// different namespace authority than the space and the permission set, so
/// collection NSIDs are not constrained here (spec line 465, final sentence).
///
/// `spaceType` must be present, must not be the `*` wildcard (a permission set
/// must target a concrete space type), and must obey the permission set's
/// [Namespace Authority](https://atproto.com/specs/permission#namespace-authority)
/// requirement — it must fall under the set's `namespace` (spec line 465), the
/// same constraint enforced for repo `collection` and rpc `lxm`.
///
/// `manage` is checked against the three verbs the spec defines. It is checked
/// where `action` is not because a `manage` verb has no default: an unknown
/// one cannot be read as "the usual set", and the scope grammar it expands
/// into has a closed value set, so publishing a set naming one produces a
/// permission that describes an administrative grant and confers none.
fn validate_space_permission(
    permission: &Permission,
    namespace: &str,
) -> Result<(), DataValidationError> {
    let space_type = permission
        .space_type
        .as_ref()
        .ok_or(DataValidationError::SpacePermissionMissingSpaceType)?;
    if space_type == "*" {
        return Err(DataValidationError::SpacePermissionWildcardSpaceType);
    }
    if !nsid_in_namespace(space_type, namespace) {
        return Err(DataValidationError::PermissionNsidOutsideNamespace {
            nsid: space_type.clone(),
            namespace: namespace.to_string(),
        });
    }
    if let Some(manage) = &permission.manage {
        if manage.is_empty() {
            return Err(DataValidationError::SpacePermissionEmptyManage);
        }
        for verb in manage {
            if !SPACE_MANAGE_VERBS.contains(&verb.as_str()) {
                return Err(DataValidationError::SpacePermissionInvalidManageVerb {
                    verb: verb.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Validate a `space` definition.
///
/// Enforces that `name` has length 1..=64 and that each `collections` entry
/// is a valid NSID. The `collections` array itself may be empty.
fn validate_space(space: &SpaceSchema) -> Result<(), DataValidationError> {
    let len = space.name.len();
    if !(1..=64).contains(&len) {
        return Err(DataValidationError::SpaceNameLengthInvalid { length: len });
    }
    for nsid in &space.collections {
        if let Err(e) = validate_nsid(nsid) {
            return Err(DataValidationError::SpaceInvalidCollectionNsid {
                nsid: nsid.clone(),
                reason: e.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_repo_permission(permission: &Permission) -> Result<(), DataValidationError> {
    if let Some(action) = &permission.action {
        if action.is_empty() {
            return Err(DataValidationError::PermissionEmptyAction);
        }
        for a in action {
            if !REPO_ACTIONS.contains(&a.as_str()) {
                return Err(DataValidationError::PermissionInvalidAction { action: a.clone() });
            }
        }
    }
    let collection = permission
        .collection
        .as_ref()
        .ok_or(DataValidationError::PermissionMissingCollection)?;
    if collection.is_empty() {
        return Err(DataValidationError::PermissionEmptyCollection);
    }
    for nsid in collection {
        reject_wildcard(nsid, "repo")?;
        if let Err(e) = validate_nsid(nsid) {
            return Err(DataValidationError::PermissionInvalidCollectionNsid {
                nsid: nsid.clone(),
                reason: e.to_string(),
            });
        }
        // Namespace authority is deliberately NOT enforced here — see
        // [`permission_within_authority`] for where it belongs and why.
    }
    Ok(())
}

fn validate_rpc_permission(permission: &Permission) -> Result<(), DataValidationError> {
    let lxm = permission
        .lxm
        .as_ref()
        .ok_or(DataValidationError::PermissionMissingLxm)?;
    if lxm.is_empty() {
        return Err(DataValidationError::PermissionEmptyLxm);
    }
    for nsid in lxm {
        reject_wildcard(nsid, "rpc")?;
        if let Err(e) = validate_nsid(nsid) {
            return Err(DataValidationError::PermissionInvalidLxmNsid {
                nsid: nsid.clone(),
                reason: e.to_string(),
            });
        }
        // Namespace authority is deliberately NOT enforced here — see
        // [`permission_within_authority`] for where it belongs and why.
    }
    Ok(())
}

/// Parse a reference string into (lexicon_id, def_name)
pub fn parse_ref(ref_path: &str) -> (Option<&str>, &str) {
    if let Some(hash_pos) = ref_path.find('#') {
        if hash_pos == 0 {
            (None, &ref_path[1..])
        } else {
            (Some(&ref_path[..hash_pos]), &ref_path[hash_pos + 1..])
        }
    } else {
        (Some(ref_path), "main")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_lexicon() {
        let json = r#"{"lexicon": 1, "id": "com.example.test", "defs": {"main": {"type": "record", "record": {"type": "object", "properties": {"name": {"type": "string"}}}}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.lexicon, 1);
        assert_eq!(schema.id, "com.example.test");
        assert!(schema.main().is_some());
    }

    #[test]
    fn test_parse_lexicon_with_defs() {
        let json = r##"{"lexicon": 1, "id": "com.example.test", "defs": {"main": {"type": "record", "record": {"type": "object", "properties": {"item": {"type": "ref", "ref": "#item"}}}}, "item": {"type": "object", "properties": {"name": {"type": "string"}}}}}"##;
        let schema = SchemaFile::parse(json).unwrap();
        assert!(schema.get_def("item").is_some());
        assert!(schema.resolve_local_ref("#item").is_some());
    }

    #[test]
    fn test_invalid_lexicon_version() {
        let json =
            r#"{"lexicon": 2, "id": "com.example.test", "defs": {"main": {"type": "token"}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::UnsupportedLexiconVersion { version: 2 })
        ));
    }

    #[test]
    fn test_lexicon_without_main() {
        let json =
            r#"{"lexicon": 1, "id": "com.example.test", "defs": {"other": {"type": "token"}}}"#;
        let result = SchemaFile::parse(json);
        assert!(result.is_ok());
        assert!(result.unwrap().main().is_none());
    }

    #[test]
    fn test_defs_only_lexicon() {
        let json = r#"{"lexicon": 1, "id": "com.example.defs", "defs": {"viewBasic": {"type": "object", "properties": {"name": {"type": "string"}}}, "viewDetailed": {"type": "object", "properties": {"name": {"type": "string"}, "bio": {"type": "string"}}}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert!(schema.main().is_none());
        assert!(schema.get_def("viewBasic").is_some());
        assert!(schema.get_def("viewDetailed").is_some());
    }

    #[test]
    fn test_primary_type_must_be_named_main() {
        let json = r#"{"lexicon": 1, "id": "com.example.test", "defs": {"other": {"type": "record", "record": {"type": "object", "properties": {"name": {"type": "string"}}}}}}"#;
        let result = SchemaFile::parse(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be named 'main'")
        );
    }

    #[test]
    fn test_invalid_nsid() {
        let json = r#"{"lexicon": 1, "id": "invalid", "defs": {"main": {"type": "token"}}}"#;
        let result = SchemaFile::parse(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ref() {
        let (nsid, def) = parse_ref("#myDef");
        assert_eq!(nsid, None);
        assert_eq!(def, "myDef");
        let (nsid, def) = parse_ref("com.example.other#myDef");
        assert_eq!(nsid, Some("com.example.other"));
        assert_eq!(def, "myDef");
        let (nsid, def) = parse_ref("com.example.other");
        assert_eq!(nsid, Some("com.example.other"));
        assert_eq!(def, "main");
    }

    #[test]
    fn test_full_ref() {
        let json = r#"{"lexicon": 1, "id": "com.example.test", "defs": {"main": {"type": "token"}, "other": {"type": "token"}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.full_ref("main"), "com.example.test");
        assert_eq!(schema.full_ref("other"), "com.example.test#other");
    }

    #[test]
    fn test_validate_def_name() {
        assert!(validate_def_name("main").is_ok());
        assert!(validate_def_name("myDef").is_ok());
        assert!(validate_def_name("def123").is_ok());
        assert!(validate_def_name("").is_err());
        assert!(validate_def_name("Main").is_err());
        assert!(validate_def_name("123def").is_err());
        assert!(validate_def_name("my-def").is_err());
        assert!(validate_def_name("my_def").is_err());
    }

    #[test]
    fn test_parse_permission_set() {
        let json = r#"{"lexicon": 1, "id": "community.lexicon.calendar.authFull", "defs": {"main": {"type": "permission-set", "title": "Full Lexicon Community Calendar Permissions", "description": "Full auth permission Lexicon Community Calendar types and functions", "permissions": [{"type": "permission", "action": ["delete"], "resource": "repo", "collection": ["community.lexicon.calendar.event", "community.lexicon.calendar.rsvp"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.id, "community.lexicon.calendar.authFull");
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(
                ps.title,
                Some("Full Lexicon Community Calendar Permissions".to_string())
            );
            assert_eq!(ps.permissions.len(), 1);
            assert_eq!(ps.permissions[0].resource, "repo");
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_permission_set_with_detail() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.authBasic", "defs": {"main": {"type": "permission-set", "title": "Basic App Functionality", "detail": "Creation of posts and interactions", "permissions": [{"type": "permission", "action": ["create", "update"], "resource": "repo", "collection": ["com.example.app.post"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(
                ps.detail,
                Some("Creation of posts and interactions".to_string())
            );
            assert_eq!(ps.get_detail(), Some("Creation of posts and interactions"));
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_permission_set_rpc_resource() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.authApi", "defs": {"main": {"type": "permission-set", "title": "API Access", "description": "Access to API endpoints", "permissions": [{"type": "permission", "resource": "rpc", "lxm": ["com.example.app.getProfile", "com.example.app.updateProfile"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(ps.permissions[0].resource, "rpc");
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_permission_set_missing_title() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "description": "Some description", "permissions": [{"type": "permission", "resource": "blob"}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionSetMissingTitle)
        ));
    }

    #[test]
    fn test_permission_set_missing_detail() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "permissions": [{"type": "permission", "resource": "blob"}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionSetMissingDetail)
        ));
    }

    #[test]
    fn test_permission_set_empty_permissions() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": []}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionSetEmptyPermissions)
        ));
    }

    #[test]
    fn test_permission_invalid_type() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "invalid", "resource": "blob"}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionInvalidType { .. })
        ));
    }

    #[test]
    fn test_permission_invalid_resource() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "invalid"}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionInvalidResource { .. })
        ));
    }

    #[test]
    fn test_repo_permission_missing_action_implies_all() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "repo", "collection": ["com.example.app.post"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(
            result.is_ok(),
            "Expected success when action is missing (all actions implied)"
        );
        let schema = result.unwrap();
        if let SchemaDef::PermissionSet(ps) = schema.defs.get("main").unwrap() {
            assert!(ps.permissions[0].action.is_none());
        } else {
            panic!("Expected permission-set");
        }
    }

    #[test]
    fn test_repo_permission_missing_collection() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "repo", "action": ["create"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionMissingCollection)
        ));
    }

    #[test]
    fn test_rpc_permission_missing_lxm() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "rpc"}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionMissingLxm)
        ));
    }

    #[test]
    fn test_permission_invalid_action() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "repo", "action": ["invalid"], "collection": ["com.example.app.post"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionInvalidAction { .. })
        ));
    }

    #[test]
    fn test_permission_nsid_outside_namespace() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "repo", "action": ["create"], "collection": ["com.other.app.post"]}]}}}"#;
        // The document is readable: an out-of-authority grant is no longer a
        // parse error, matching the reference, which performs no authority
        // check on the schema at all.
        assert!(SchemaFile::parse(json).is_ok());
        // The rule that governs it still says no.
        assert!(!permission_within_authority(
            "com.other.app.post",
            "com.example.app.auth"
        ));
    }

    #[test]
    fn test_permission_blob_resource() {
        let json = r#"{"lexicon": 1, "id": "com.example.app.auth", "defs": {"main": {"type": "permission-set", "title": "Some Title", "description": "Some description", "permissions": [{"type": "permission", "resource": "blob"}, {"type": "permission", "resource": "identity"}, {"type": "permission", "resource": "account"}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(ps.permissions.len(), 3);
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_extract_namespace() {
        assert_eq!(extract_namespace("com.example.app.auth"), "com.example.app");
        assert_eq!(
            extract_namespace("community.lexicon.calendar.authFull"),
            "community.lexicon.calendar"
        );
        assert_eq!(extract_namespace("simple"), "simple");
    }

    #[test]
    fn test_nsid_in_namespace() {
        assert!(nsid_in_namespace("com.example.app.post", "com.example.app"));
        assert!(nsid_in_namespace(
            "com.example.app.nested.thing",
            "com.example.app"
        ));
        assert!(!nsid_in_namespace("com.other.app.post", "com.example.app"));
        assert!(!nsid_in_namespace("com.example.app", "com.example.app"));
        assert!(!nsid_in_namespace(
            "com.example.appextended.post",
            "com.example.app"
        ));
    }

    #[test]
    fn test_bsky_auth_view_all() {
        let json = r#"{"id": "app.bsky.authViewAll", "defs": {"main": {"type": "permission-set", "title": "Read-only access to all content", "detail": "View Bluesky network content from account perspective, and read all notifications and preferences.", "permissions": [{"lxm": ["app.bsky.actor.getProfile", "app.bsky.actor.getProfiles", "app.bsky.feed.getTimeline", "app.bsky.feed.getPostThread", "app.bsky.graph.getFollowers", "app.bsky.notification.listNotifications"], "type": "permission", "resource": "rpc", "inheritAud": true}]}}, "lexicon": 1}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.id, "app.bsky.authViewAll");
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(
                ps.title,
                Some("Read-only access to all content".to_string())
            );
            assert_eq!(ps.permissions.len(), 1);
            assert_eq!(ps.permissions[0].resource, "rpc");
            assert_eq!(ps.permissions[0].inherit_aud, Some(true));
            assert!(ps.permissions[0].lxm.as_ref().unwrap().len() >= 6);
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_bsky_auth_create_posts() {
        let json = r#"{"id": "app.bsky.authCreatePosts", "defs": {"main": {"type": "permission-set", "title": "Create Bluesky Posts", "detail": "Can not update or delete posts.", "permissions": [{"lxm": ["app.bsky.video.uploadVideo", "app.bsky.video.getJobStatus", "app.bsky.video.getUploadLimits"], "type": "permission", "resource": "rpc", "inheritAud": true}, {"type": "permission", "action": ["create"], "resource": "repo", "collection": ["app.bsky.feed.post", "app.bsky.feed.postgate", "app.bsky.feed.threadgate"]}]}}, "lexicon": 1}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.id, "app.bsky.authCreatePosts");
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(ps.title, Some("Create Bluesky Posts".to_string()));
            assert_eq!(ps.permissions.len(), 2);
            assert_eq!(ps.permissions[0].resource, "rpc");
            assert_eq!(ps.permissions[1].resource, "repo");
            assert_eq!(ps.permissions[1].action, Some(vec!["create".to_string()]));
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_deep_namespace_hierarchy() {
        assert_eq!(extract_namespace("app.bsky.authViewAll"), "app.bsky");
        assert!(nsid_in_namespace("app.bsky.actor.getProfile", "app.bsky"));
        assert!(nsid_in_namespace("app.bsky.feed.post", "app.bsky"));
        assert!(!nsid_in_namespace(
            "com.atproto.repo.createRecord",
            "app.bsky"
        ));
    }

    #[test]
    fn test_permission_set_with_localization() {
        let json = r#"{"id": "app.bsky.authViewAll", "defs": {"main": {"type": "permission-set", "title": "Read-only access", "detail": "View content", "title:lang": {"es": "Acceso de solo lectura", "fr": "Accès en lecture seule"}, "detail:lang": {"es": "Ver contenido", "fr": "Voir le contenu"}, "permissions": [{"type": "permission", "resource": "rpc", "lxm": ["app.bsky.actor.getProfile"]}]}}, "lexicon": 1}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(
                ps.title_lang.get("es"),
                Some(&"Acceso de solo lectura".to_string())
            );
            assert_eq!(
                ps.title_lang.get("fr"),
                Some(&"Accès en lecture seule".to_string())
            );
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_permission_set_with_empty_localization() {
        let json = r#"{"id": "app.bsky.authViewAll", "defs": {"main": {"type": "permission-set", "title": "Read-only access", "detail": "View content", "title:lang": {}, "detail:lang": {}, "permissions": [{"type": "permission", "resource": "rpc", "lxm": ["app.bsky.actor.getProfile"]}]}}, "lexicon": 1}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert!(ps.title_lang.is_empty());
            assert!(ps.detail_lang.is_empty());
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_validate_def_name_error_messages() {
        let err = validate_def_name("").unwrap_err();
        assert!(err.to_string().contains("empty"), "{}", err);
        let err = validate_def_name("Main").unwrap_err();
        assert!(err.to_string().contains("lowercase"), "{}", err);
        let err = validate_def_name("my-def").unwrap_err();
        assert!(err.to_string().contains("alphanumeric"), "{}", err);
        let err = validate_def_name("123def").unwrap_err();
        assert!(err.to_string().contains("lowercase"), "{}", err);
    }

    #[test]
    fn test_validate_def_name_single_char() {
        assert!(validate_def_name("a").is_ok());
        assert!(validate_def_name("z").is_ok());
        assert!(validate_def_name("A").is_err());
        assert!(validate_def_name("0").is_err());
    }

    #[test]
    fn test_extract_namespace_two_segments() {
        assert_eq!(extract_namespace("com.example"), "com");
    }

    #[test]
    fn test_extract_namespace_no_dots() {
        assert_eq!(extract_namespace("nodots"), "nodots");
    }

    #[test]
    fn test_parse_space_main() {
        let json = r#"{"lexicon": 1, "id": "com.atmoboards.forum", "defs": {"main": {"type": "space", "key": "tid", "name": "AtmoBoards Forum", "description": "A discussion forum", "name:lang": {"es": "Foro AtmoBoards", "ja": "AtmoBoards 掲示板"}, "collections": ["com.atmoboards.thread", "com.atmoboards.reply"]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        assert_eq!(schema.id, "com.atmoboards.forum");
        if let Some(SchemaDef::Space(space)) = schema.main() {
            assert_eq!(space.key, "tid");
            assert_eq!(space.name, "AtmoBoards Forum");
            assert_eq!(space.collections.len(), 2);
            assert_eq!(
                space.name_lang.get("es"),
                Some(&"Foro AtmoBoards".to_string())
            );
        } else {
            panic!("Expected Space schema");
        }
    }

    #[test]
    fn test_space_main_round_trip() {
        let json = r#"{"lexicon":1,"id":"com.atmoboards.forum","defs":{"main":{"type":"space","key":"tid","name":"AtmoBoards Forum","collections":["com.atmoboards.thread"]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        let serialized = serde_json::to_string(&schema).unwrap();
        let reparsed = SchemaFile::parse(&serialized).unwrap();
        assert_eq!(schema, reparsed);
    }

    #[test]
    fn test_space_empty_collections_allowed() {
        let json = r#"{"lexicon": 1, "id": "com.example.empty", "defs": {"main": {"type": "space", "key": "tid", "name": "Empty Space", "collections": []}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::Space(space)) = schema.main() {
            assert!(space.collections.is_empty());
        } else {
            panic!("Expected Space schema");
        }
    }

    #[test]
    fn test_space_must_be_main() {
        let json = r#"{"lexicon": 1, "id": "com.example.space", "defs": {"demo": {"type": "space", "key": "tid", "name": "Example Space", "collections": []}}}"#;
        let result = SchemaFile::parse(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must be named 'main'")
        );
    }

    #[test]
    fn test_space_name_empty_rejected() {
        let json = r#"{"lexicon": 1, "id": "com.example.space", "defs": {"main": {"type": "space", "key": "tid", "name": "", "collections": []}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::SpaceNameLengthInvalid { length: 0 })
        ));
    }

    #[test]
    fn test_space_name_too_long_rejected() {
        let name = "a".repeat(65);
        let json = format!(
            r#"{{"lexicon": 1, "id": "com.example.space", "defs": {{"main": {{"type": "space", "key": "tid", "name": "{}", "collections": []}}}}}}"#,
            name
        );
        let result = SchemaFile::parse(&json);
        assert!(matches!(
            result,
            Err(DataValidationError::SpaceNameLengthInvalid { length: 65 })
        ));
    }

    #[test]
    fn test_space_name_max_length_allowed() {
        let name = "a".repeat(64);
        let json = format!(
            r#"{{"lexicon": 1, "id": "com.example.space", "defs": {{"main": {{"type": "space", "key": "tid", "name": "{}", "collections": []}}}}}}"#,
            name
        );
        assert!(SchemaFile::parse(&json).is_ok());
    }

    #[test]
    fn test_space_invalid_collection_nsid() {
        let json = r#"{"lexicon": 1, "id": "com.example.space", "defs": {"main": {"type": "space", "key": "tid", "name": "Example Space", "collections": ["not-a-valid-nsid"]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::SpaceInvalidCollectionNsid { .. })
        ));
    }

    #[test]
    fn test_space_missing_key_rejected() {
        // `key` is a required field (spec line 125); a declaration omitting it
        // must fail to parse.
        let json = r#"{"lexicon": 1, "id": "com.example.space", "defs": {"main": {"type": "space", "name": "Example Space", "collections": []}}}"#;
        assert!(SchemaFile::parse(json).is_err());
    }

    #[test]
    fn test_space_key_round_trips_through_file() {
        let json = r#"{"lexicon":1,"id":"com.example.space","defs":{"main":{"type":"space","key":"any","name":"Example Space","collections":[]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::Space(space)) = schema.main() {
            assert_eq!(space.key, "any");
        } else {
            panic!("Expected Space schema");
        }
    }

    #[test]
    fn test_permission_set_space_resource() {
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "com.example.lexicon.group", "did": "*", "skey": "*", "collection": ["com.example.calendar.event"], "action": ["read", "create"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        if let Some(SchemaDef::PermissionSet(ps)) = schema.main() {
            assert_eq!(ps.permissions.len(), 1);
            assert_eq!(ps.permissions[0].resource, "space");
            assert_eq!(
                ps.permissions[0].space_type,
                Some("com.example.lexicon.group".to_string())
            );
            assert_eq!(ps.permissions[0].did, Some("*".to_string()));
            assert_eq!(ps.permissions[0].skey, Some("*".to_string()));
        } else {
            panic!("Expected PermissionSet schema");
        }
    }

    #[test]
    fn test_permission_set_space_resource_round_trip() {
        let json = r#"{"lexicon":1,"id":"com.example.lexicon.perms","defs":{"main":{"type":"permission-set","title":"test case","detail":"test detail","permissions":[{"type":"permission","resource":"space","spaceType":"com.example.lexicon.group","action":["read"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        let serialized = serde_json::to_string(&schema).unwrap();
        let reparsed = SchemaFile::parse(&serialized).unwrap();
        assert_eq!(schema, reparsed);
    }

    /// `manage` survives parsing and round-trips, so a set that declares an
    /// administrative grant still declares one after this crate has read it.
    #[test]
    fn test_permission_set_space_manage() {
        let json = r#"{"lexicon":1,"id":"com.example.lexicon.perms","defs":{"main":{"type":"permission-set","title":"test case","detail":"test detail","permissions":[{"type":"permission","resource":"space","spaceType":"com.example.lexicon.group","action":["read_self"],"manage":["update","delete"]}]}}}"#;
        let schema = SchemaFile::parse(json).unwrap();
        let Some(SchemaDef::PermissionSet(ps)) = schema.main() else {
            panic!("Expected PermissionSet schema");
        };
        assert_eq!(
            ps.permissions[0].manage,
            Some(vec!["update".to_string(), "delete".to_string()])
        );

        let reparsed = SchemaFile::parse(&serde_json::to_string(&schema).unwrap()).unwrap();
        assert_eq!(schema, reparsed, "manage must survive a serialize/parse");
    }

    /// A verb outside `create`/`update`/`delete` is refused at publication.
    ///
    /// The scope grammar `manage` expands into has a closed value set, so a
    /// set naming anything else describes an administrative grant on a consent
    /// screen and confers none.
    #[test]
    fn test_space_permission_unknown_manage_verb_rejected() {
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "com.example.lexicon.group", "manage": ["administer"]}]}}}"#;
        assert!(matches!(
            SchemaFile::parse(json),
            Err(DataValidationError::SpacePermissionInvalidManageVerb { ref verb }) if verb == "administer"
        ));
    }

    /// An empty `manage` is the same grant as no `manage` and reads like an
    /// oversight, so it is refused rather than silently meaning nothing.
    #[test]
    fn test_space_permission_empty_manage_rejected() {
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "com.example.lexicon.group", "manage": []}]}}}"#;
        assert!(matches!(
            SchemaFile::parse(json),
            Err(DataValidationError::SpacePermissionEmptyManage)
        ));
    }

    #[test]
    fn test_space_permission_missing_space_type() {
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "collection": ["com.example.calendar.event"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::SpacePermissionMissingSpaceType)
        ));
    }

    #[test]
    fn test_space_permission_wildcard_space_type_rejected() {
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "*", "action": ["read"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::SpacePermissionWildcardSpaceType)
        ));
    }

    #[test]
    fn test_space_permission_space_type_outside_namespace_rejected() {
        // The permission set id is `com.example.lexicon.perms` (namespace
        // `com.example.lexicon`); a `spaceType` under a different namespace
        // authority must be rejected (spec line 465, Namespace Authority).
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "com.atmoboards.forum", "action": ["read"]}]}}}"#;
        let result = SchemaFile::parse(json);
        assert!(
            matches!(
                result,
                Err(DataValidationError::PermissionNsidOutsideNamespace { .. })
            ),
            "got: {result:?}"
        );
    }

    #[test]
    fn test_space_permission_cross_namespace_collection_allowed() {
        // The collection list MAY reference NSIDs under a different namespace
        // authority than the space and the permission set (spec line 465).
        let json = r#"{"lexicon": 1, "id": "com.example.lexicon.perms", "defs": {"main": {"type": "permission-set", "title": "test case", "detail": "test detail", "permissions": [{"type": "permission", "resource": "space", "spaceType": "com.example.lexicon.group", "collection": ["org.other.note"], "action": ["read", "create"]}]}}}"#;
        assert!(SchemaFile::parse(json).is_ok());
    }
}

#[cfg(test)]
mod namespace_authority {
    use super::*;
    use crate::validation::schema::{PERMISSION_RESOURCES, PERMISSION_RESOURCES_WITHOUT_NSIDS};

    fn permission_set(id: &str, permissions: &str) -> Result<SchemaFile, DataValidationError> {
        SchemaFile::parse(&format!(
            r#"{{"lexicon":1,"id":"{id}","defs":{{"main":{{"type":"permission-set",
               "title":"t","detail":"d","permissions":[{permissions}]}}}}}}"#
        ))
    }

    fn repo(collection: &str) -> String {
        format!(r#"{{"type":"permission","resource":"repo","collection":["{collection}"]}}"#)
    }

    fn rpc(lxm: &str) -> String {
        format!(r#"{{"type":"permission","resource":"rpc","lxm":["{lxm}"]}}"#)
    }

    fn include(nsid: &str) -> String {
        format!(r#"{{"type":"permission","resource":"include","nsid":"{nsid}"}}"#)
    }

    /// The worked example from the specification, verbatim.
    ///
    /// > the set `app.example.feed.authOnlyPost` could include permissions to
    /// > `app.example.feed.post` records and making `app.example.feed.getPostThread`
    /// > API endpoint requests to remote services. But it could not grant
    /// > permissions to `app.example.actor.profile`. A permission set
    /// > `app.example.authFull`, which is a level up in the hierarchy, could
    /// > include permissions to all these resources, or even further down.
    #[test]
    fn the_specs_worked_example() {
        let post = "app.example.feed.authOnlyPost";
        let full = "app.example.authFull";

        // The rule, which now bounds what may be *granted* rather than what may
        // be written down — see `permission_within_authority`.
        assert!(permission_within_authority("app.example.feed.post", post));
        assert!(permission_within_authority(
            "app.example.feed.getPostThread",
            post
        ));
        assert!(
            !permission_within_authority("app.example.actor.profile", post),
            "a sibling group must not be reachable"
        );

        assert!(permission_within_authority("app.example.feed.post", full));
        assert!(permission_within_authority(
            "app.example.actor.profile",
            full
        ));
        assert!(permission_within_authority(
            "app.example.feed.getPostThread",
            full
        ));

        // Every one of those documents parses, including the one whose grant is
        // out of authority. Refusing to *read* it is what this crate stopped
        // doing; refusing to *honour* it is the resolver's job.
        assert!(permission_set(post, &repo("app.example.feed.post")).is_ok());
        assert!(permission_set(post, &repo("app.example.actor.profile")).is_ok());
        assert!(permission_set(full, &repo("app.example.actor.profile")).is_ok());
    }

    /// Authority runs downward only: children yes, parents and siblings no.
    #[test]
    fn parents_and_siblings_are_refused_children_are_not() {
        let set = "app.example.feed.authOnlyPost";
        // Same group.
        assert!(permission_within_authority("app.example.feed.post", set));
        // Children, recursively deep.
        assert!(permission_within_authority(
            "app.example.feed.thread.reply",
            set
        ));
        // A parent.
        assert!(!permission_within_authority("app.example.post", set));
        // An unrelated authority.
        assert!(!permission_within_authority("com.other.thing", set));
        // A name that merely shares a prefix without a segment boundary — the
        // check must not be a bare `starts_with`.
        assert!(!permission_within_authority("app.examplefeed.post", set));

        // None of them makes the document unreadable.
        assert!(permission_set(set, &repo("com.other.thing")).is_ok());
    }

    /// `include` is transitive, so the rule binds it too.
    ///
    /// This is the case the rule most needs: a set that could name a set under
    /// another authority would inherit permissions its own namespace does not
    /// cover, in one hop.
    #[test]
    fn include_is_bound_by_the_same_rule() {
        let set = "app.example.authFull";
        assert!(permission_set(set, &include("app.example.feed.authOnlyPost")).is_ok());
        assert!(
            permission_set(set, &include("com.other.authFull")).is_err(),
            "including a set under another authority would inherit its permissions"
        );
        assert!(
            permission_set(set, r#"{"type":"permission","resource":"include"}"#).is_err(),
            "include without an nsid names nothing"
        );
    }

    /// Wildcards are refused, and reported as wildcards.
    ///
    /// The refusal already happened — `*` is not a valid NSID — but it was
    /// reported as a malformed NSID, which sends a reader looking for a typo
    /// instead of at the rule.
    #[test]
    fn wildcards_are_refused_by_name() {
        let set = "app.example.feed.authOnlyPost";
        for (permission, resource) in [
            (repo("*"), "repo"),
            (rpc("*"), "rpc"),
            (include("*"), "include"),
            (repo("app.example.*"), "repo"),
        ] {
            let err = permission_set(set, &permission).unwrap_err();
            let DataValidationError::PermissionWildcardInSet { resource: got, .. } = &err else {
                panic!("expected a wildcard refusal for {resource}, got {err:?}");
            };
            assert_eq!(got, resource);
        }
    }

    /// Every resource is either checked or explicitly exempt.
    ///
    /// The exemptions are resources that name no NSID at all, not NSIDs that
    /// are allowed to escape: the spec says authority works "without
    /// 'siblings' or special namespaces", so there is no such thing as an
    /// exempt name. Adding a resource without deciding which side it falls on
    /// fails here.
    #[test]
    fn permission_resources_are_all_accounted_for() {
        let checked = ["repo", "rpc", "space", "include"];
        for resource in PERMISSION_RESOURCES {
            assert!(
                checked.contains(resource) || PERMISSION_RESOURCES_WITHOUT_NSIDS.contains(resource),
                "resource {resource:?} is neither namespace-checked nor listed as NSID-free"
            );
        }
        for resource in PERMISSION_RESOURCES_WITHOUT_NSIDS {
            assert!(
                PERMISSION_RESOURCES.contains(resource),
                "{resource:?} is listed as NSID-free but is not a valid resource"
            );
            assert!(
                !checked.contains(resource),
                "{resource:?} cannot be both checked and exempt"
            );
        }
    }
}

#[cfg(test)]
mod definition_types {
    use super::*;

    fn doc(def: &str) -> Result<SchemaFile, DataValidationError> {
        SchemaFile::parse(&format!(
            r#"{{"lexicon":1,"id":"com.example.t","defs":{{"demo":{def}}}}}"#
        ))
    }

    /// `ref`, `union` and `params` are not definition types.
    ///
    /// Each describes how a field relates to something else, so none says
    /// anything standing alone: a top-level `ref` is a pointer with nobody
    /// holding it, and a `params` is the query-string half of an endpoint that
    /// is not there. The reference lists what a definition may be
    /// (`lexUserType`) and none of the three appears; none of the 396
    /// lexicons in the reference repository defines one either.
    #[test]
    fn non_user_types_are_refused_as_definitions() {
        for def in [
            r#"{"type":"ref","ref":"com.atproto.repo.strongRef"}"#,
            r##"{"type":"union","refs":["#a"]}"##,
            r#"{"type":"params","properties":{}}"#,
        ] {
            let err = doc(def).unwrap_err();
            let DataValidationError::SchemaStructureInvalid { message } = &err else {
                panic!("expected SchemaStructureInvalid, got {err:?}");
            };
            assert!(
                message.contains("only valid inside another definition"),
                "the refusal should say why, got {message:?}"
            );
        }
    }

    /// Everything the reference does list still parses.
    ///
    /// The refusal above is a list of three, not a whitelist of what someone
    /// happened to test — narrowing it further would refuse schemas that
    /// exist.
    #[test]
    fn user_types_are_still_accepted_as_definitions() {
        for def in [
            r#"{"type":"integer"}"#,
            r#"{"type":"string"}"#,
            r#"{"type":"boolean"}"#,
            r#"{"type":"bytes"}"#,
            r#"{"type":"cid-link"}"#,
            r#"{"type":"blob"}"#,
            r#"{"type":"token"}"#,
            r#"{"type":"unknown"}"#,
            r#"{"type":"object","properties":{}}"#,
            r#"{"type":"array","items":{"type":"integer"}}"#,
        ] {
            assert!(doc(def).is_ok(), "should parse: {def}");
        }
    }

    /// `unknown` stays accepted, deliberately.
    ///
    /// The interop corpus lists a lone `{"type": "unknown"}` definition as
    /// invalid, but the reference's `lexUserType` has a case for it, so the
    /// corpus and the reference disagree and this is not this crate's call to
    /// settle. `interop_lexicon.rs` pins that vector with the same reasoning.
    #[test]
    fn unknown_is_a_definition_type_despite_the_corpus() {
        assert!(doc(r#"{"type":"unknown"}"#).is_ok());
    }
    /// The spec spells the space authority field `authority`; this crate
    /// called it `did` first. A published set may use either, and a set that
    /// scopes a permission to one authority must not be read as scoping it to
    /// none — an alias that silently dropped the field would widen the grant
    /// to every authority.
    #[test]
    fn a_space_permission_accepts_either_authority_spelling() {
        for field in ["authority", "did"] {
            let json = format!(
                r#"{{"type":"permission","resource":"space","spaceType":"com.example.bookmarks","{field}":"did:plc:abc123"}}"#
            );
            let perm: Permission = serde_json::from_str(&json).expect("permission parses");
            assert_eq!(
                perm.did.as_deref(),
                Some("did:plc:abc123"),
                "{field} must reach the model"
            );
        }

        // And a set this crate writes back out carries the spec's name.
        let perm: Permission = serde_json::from_str(
            r#"{"type":"permission","resource":"space","spaceType":"com.example.bookmarks","did":"did:plc:abc123"}"#,
        )
        .unwrap();
        let out = serde_json::to_string(&perm).unwrap();
        assert!(out.contains(r#""authority":"did:plc:abc123""#), "{out}");
    }
}
