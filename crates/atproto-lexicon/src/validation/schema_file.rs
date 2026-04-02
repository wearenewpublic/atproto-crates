//! Schema file parsing and structure
//!
//! A SchemaFile represents a parsed lexicon JSON file.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::validation::data_errors::DataValidationError;
use crate::validation::schema::{
    PERMISSION_RESOURCES, Permission, PermissionSetSchema, REPO_ACTIONS, SchemaDef,
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
        for def in self.defs.values() {
            if let SchemaDef::PermissionSet(ps) = def {
                validate_permission_set(ps, &self.id)?;
            }
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
            validate_repo_permission(permission, namespace)?;
        }
        "rpc" => {
            validate_rpc_permission(permission, namespace)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_repo_permission(
    permission: &Permission,
    namespace: &str,
) -> Result<(), DataValidationError> {
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
        if let Err(e) = validate_nsid(nsid) {
            return Err(DataValidationError::PermissionInvalidCollectionNsid {
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
    }
    Ok(())
}

fn validate_rpc_permission(
    permission: &Permission,
    namespace: &str,
) -> Result<(), DataValidationError> {
    let lxm = permission
        .lxm
        .as_ref()
        .ok_or(DataValidationError::PermissionMissingLxm)?;
    if lxm.is_empty() {
        return Err(DataValidationError::PermissionEmptyLxm);
    }
    for nsid in lxm {
        if let Err(e) = validate_nsid(nsid) {
            return Err(DataValidationError::PermissionInvalidLxmNsid {
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
        let result = SchemaFile::parse(json);
        assert!(matches!(
            result,
            Err(DataValidationError::PermissionNsidOutsideNamespace { .. })
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
}
