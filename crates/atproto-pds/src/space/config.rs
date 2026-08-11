//! Simplespace configuration model.
//!
//! Persists and surfaces the `com.atproto.simplespace.defs#spaceConfig`
//! shape: a `policy` (how the authority decides whether to authorize a
//! requesting *user*), an `appAccess` open union (how it decides whether to
//! authorize a requesting *app*), and an optional `managingApp` service
//! identifier.
//!
//! Two serializations are provided:
//! - **Storage form** — compact JSON stored in the `space.app_access` column
//!   (`{"type":"open"}` / `{"type":"allowList","allowed":[...]}`), plus the
//!   scalar `space.mint_policy` and `space.managing_app` columns.
//! - **Wire form** — the lexicon open-union shape returned by
//!   `com.atproto.space.getSpace`, with `$type` discriminators referencing
//!   `com.atproto.simplespace.defs#spaceConfig` / `#open` / `#allowList`.

use crate::actor_store::sql::{SqlActorStore, actor_db_path};
use crate::errors::PdsError;
use atproto_space::types::SpaceUri;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::Path;

/// `$type` of the space-config union variant in `getSpace` output.
pub const SPACE_CONFIG_TYPE: &str = "com.atproto.simplespace.defs#spaceConfig";
/// `$type` of the `#open` app-access union variant.
pub const APP_ACCESS_OPEN_TYPE: &str = "com.atproto.simplespace.defs#open";
/// `$type` of the `#allowList` app-access union variant.
pub const APP_ACCESS_ALLOW_LIST_TYPE: &str = "com.atproto.simplespace.defs#allowList";
/// `$type` of the `#publicPolicy` user-authorization union variant.
pub const POLICY_PUBLIC_TYPE: &str = "com.atproto.simplespace.defs#publicPolicy";
/// `$type` of the `#memberListPolicy` user-authorization union variant.
pub const POLICY_MEMBER_LIST_TYPE: &str = "com.atproto.simplespace.defs#memberListPolicy";
/// `$type` of the `#managingAppPolicy` user-authorization union variant.
pub const POLICY_MANAGING_APP_TYPE: &str = "com.atproto.simplespace.defs#managingAppPolicy";

/// How the authority decides whether to authorize a requesting user.
///
/// Serializes to the lexicon `knownValues` strings
/// (`public` | `member-list` | `managing-app`). `member-list` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum MintPolicy {
    /// Authorize anyone.
    #[serde(rename = "public")]
    Public,
    /// Consult the member list (default).
    #[default]
    #[serde(rename = "member-list")]
    MemberList,
    /// Ask the `managingApp` via `checkUserAccess`.
    #[serde(rename = "managing-app")]
    ManagingApp,
}

impl MintPolicy {
    /// The `knownValues` string form persisted in the `mint_policy` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::MemberList => "member-list",
            Self::ManagingApp => "managing-app",
        }
    }

    /// Parse the `knownValues` string form. Unknown values are rejected.
    ///
    /// A value read back from the `mint_policy` column is one this host wrote,
    /// so an unrecognised one there is corruption rather than a bad request —
    /// but the same parser also sees the legacy string form on input, where an
    /// unknown value is the caller's. [`PdsError::UnsupportedPolicy`] answers
    /// both correctly: a 400 naming the value the caller sent, and a log line
    /// naming the value the column held.
    pub fn from_str_value(value: &str) -> Result<Self, PdsError> {
        match value {
            "public" => Ok(Self::Public),
            "member-list" => Ok(Self::MemberList),
            "managing-app" => Ok(Self::ManagingApp),
            other => Err(PdsError::UnsupportedPolicy {
                value: other.to_string(),
            }),
        }
    }
}

/// Parse a `policy` open-union value into the stored `(policy, managingApp)`
/// pair.
///
/// The lexicons carry `managingApp` *inside* the `#managingAppPolicy` variant
/// rather than beside the policy, which is what makes "managing-app policy
/// with no managing app" unrepresentable — a state this server can otherwise
/// store and only discovers at mint time, when it refuses to issue a
/// credential for a space whose owner believes it configured one. Parsing the
/// union enforces it at the point the owner can still fix it.
///
/// Returns the managing app only for `#managingAppPolicy`; the other two
/// variants carry none, and selecting one clears whatever was set.
fn policy_from_wire(value: &serde_json::Value) -> Result<(MintPolicy, Option<String>), PdsError> {
    let ty = value
        .get("$type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PdsError::UnsupportedPolicy {
            value: "<missing $type>".to_string(),
        })?;
    match ty {
        POLICY_PUBLIC_TYPE => Ok((MintPolicy::Public, None)),
        POLICY_MEMBER_LIST_TYPE => Ok((MintPolicy::MemberList, None)),
        POLICY_MANAGING_APP_TYPE => {
            let managing_app = value
                .get("managingApp")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| PdsError::InvalidSubject {
                    reason: format!("{POLICY_MANAGING_APP_TYPE} requires a managingApp"),
                })?;
            Ok((MintPolicy::ManagingApp, Some(managing_app.to_string())))
        }
        other => Err(PdsError::UnsupportedPolicy {
            value: other.to_string(),
        }),
    }
}

/// Read a `policy` input field in either accepted shape.
///
/// The lexicon shape is the `$type`-tagged union. The bare `knownValues`
/// string is what this server required before the union existed, and is still
/// accepted so a deployed client keeps working; it cannot express
/// `managingApp`, so a legacy caller sets that separately as before.
///
/// `Ok(None)` means the field was absent — leave the current value alone.
fn parse_policy_input(
    value: Option<&serde_json::Value>,
) -> Result<Option<(MintPolicy, Option<String>)>, PdsError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some((MintPolicy::from_str_value(s)?, None))),
        Some(v @ serde_json::Value::Object(_)) => policy_from_wire(v).map(Some),
        Some(other) => Err(PdsError::UnsupportedPolicy {
            value: other.to_string(),
        }),
    }
}

/// How the authority decides whether to authorize a requesting app.
///
/// Mirrors the `com.atproto.simplespace.defs` open union of `#open` /
/// `#allowList`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AppAccess {
    /// `#open` — any app may access the space.
    #[default]
    Open,
    /// `#allowList` — only the named OAuth client IDs may access the space.
    AllowList {
        /// Permitted OAuth client IDs.
        allowed: Vec<String>,
    },
}

/// Internal compact storage representation of [`AppAccess`], tagged on a
/// plain `type` field (no `$type`) so the value is self-describing inside
/// the `space.app_access` JSON column.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum AppAccessStored {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "allowList")]
    AllowList { allowed: Vec<String> },
}

impl AppAccess {
    /// Serialize to the compact JSON storage form for the `app_access`
    /// column.
    pub fn to_storage_json(&self) -> Result<String, PdsError> {
        let stored = match self {
            Self::Open => AppAccessStored::Open,
            Self::AllowList { allowed } => AppAccessStored::AllowList {
                allowed: allowed.clone(),
            },
        };
        serde_json::to_string(&stored).map_err(|e| PdsError::Storage {
            reason: format!("serialize appAccess: {e}"),
        })
    }

    /// Parse the compact JSON storage form from the `app_access` column.
    pub fn from_storage_json(json: &str) -> Result<Self, PdsError> {
        let stored: AppAccessStored =
            serde_json::from_str(json).map_err(|e| PdsError::Storage {
                reason: format!("parse appAccess {json}: {e}"),
            })?;
        Ok(match stored {
            AppAccessStored::Open => Self::Open,
            AppAccessStored::AllowList { allowed } => Self::AllowList { allowed },
        })
    }

    /// Build from a `getSpace`/`updateSpace` wire-form union value (tagged on
    /// `$type` with the `#open` / `#allowList` refs).
    pub fn from_wire(value: &serde_json::Value) -> Result<Self, PdsError> {
        let ty = value
            .get("$type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| PdsError::Storage {
                reason: "appAccess union missing $type".to_string(),
            })?;
        match ty {
            APP_ACCESS_OPEN_TYPE => Ok(Self::Open),
            APP_ACCESS_ALLOW_LIST_TYPE => {
                let allowed = value
                    .get("allowed")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| PdsError::Storage {
                        reason: "appAccess #allowList missing allowed[]".to_string(),
                    })?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| PdsError::Storage {
                                reason: "appAccess #allowList allowed[] entry not a string"
                                    .to_string(),
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::AllowList { allowed })
            }
            other => Err(PdsError::UnsupportedAppAccess {
                value: other.to_string(),
            }),
        }
    }

    /// Render the lexicon wire-form union value (with `$type`).
    #[must_use]
    pub fn to_wire(&self) -> serde_json::Value {
        match self {
            Self::Open => serde_json::json!({ "$type": APP_ACCESS_OPEN_TYPE }),
            Self::AllowList { allowed } => serde_json::json!({
                "$type": APP_ACCESS_ALLOW_LIST_TYPE,
                "allowed": allowed,
            }),
        }
    }
}

/// In-memory model of a space's simplespace configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpaceConfig {
    /// User-authorization policy.
    pub mint_policy: MintPolicy,
    /// App-authorization policy.
    pub app_access: AppAccess,
    /// Optional managing-app service identifier.
    pub managing_app: Option<String>,
}

impl SpaceConfig {
    /// Reconstruct from the three persisted columns.
    pub fn from_columns(
        mint_policy: &str,
        app_access: &str,
        managing_app: Option<String>,
    ) -> Result<Self, PdsError> {
        Ok(Self {
            mint_policy: MintPolicy::from_str_value(mint_policy)?,
            app_access: AppAccess::from_storage_json(app_access)?,
            managing_app,
        })
    }

    /// Parse a `createSpace` config object. Missing fields fall back to the
    /// host defaults (`member-list` / `#open` / no managing app), which is
    /// what the spec documents as the default policy and app access.
    ///
    /// Both `policy` shapes are accepted (see [`parse_policy_input`]); a
    /// `#managingAppPolicy` supplies its own `managingApp`, and the separate
    /// top-level field is read only for the legacy string form.
    pub fn from_create_input(value: &serde_json::Value) -> Result<Self, PdsError> {
        let (mint_policy, policy_managing_app): (MintPolicy, Option<String>) =
            parse_policy_input(policy_field(value))?.unwrap_or_default();
        let app_access = match value.get("appAccess") {
            Some(v) if !v.is_null() => AppAccess::from_wire(v)?,
            _ => AppAccess::default(),
        };
        let managing_app = policy_managing_app.or_else(|| {
            value
                .get("managingApp")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        });
        Ok(Self {
            mint_policy,
            app_access,
            managing_app,
        })
    }

    /// Render the `getSpace` wire-form `config` union value (with the
    /// `#spaceConfig` `$type` discriminator).
    #[must_use]
    pub fn to_wire(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "$type": SPACE_CONFIG_TYPE,
            "policy": self.mint_policy.as_str(),
            "appAccess": self.app_access.to_wire(),
        });
        if let Some(ref app) = self.managing_app {
            obj["managingApp"] = serde_json::Value::String(app.clone());
        }
        obj
    }
}

/// Read the raw user-authorization policy field from a config or `updateSpace`
/// input object.
///
/// The lexicon names this field `policy`. This server previously read and wrote
/// `mintPolicy`, so a conformant client's `policy` was silently ignored and the
/// default applied instead. Both names are accepted on input — `policy` wins —
/// and only `policy` is emitted.
///
/// The value is returned untyped because the field carries either shape: the
/// lexicon's `$type`-tagged union object, or the legacy `knownValues` string.
/// [`parse_policy_input`] decides which it is.
fn policy_field(value: &serde_json::Value) -> Option<&serde_json::Value> {
    value
        .get("policy")
        .or_else(|| value.get("mintPolicy"))
        .filter(|v| !v.is_null())
}

/// A field-level patch applied by `updateSpace`. Each `Option::None` leaves
/// the corresponding column unchanged; `managing_app == Some("")` clears the
/// column to `NULL`.
#[derive(Debug, Default)]
pub struct SpaceConfigPatch {
    /// New mint policy, if provided.
    pub mint_policy: Option<MintPolicy>,
    /// New app-access policy, if provided (replaces wholesale).
    pub app_access: Option<AppAccess>,
    /// New managing-app identifier. `Some("")` clears to `NULL`; `Some(id)`
    /// sets; `None` leaves unchanged.
    pub managing_app: Option<String>,
}

impl SpaceConfigPatch {
    /// Parse an `updateSpace` input object into a patch. The `space` field is
    /// handled by the caller; only the config fields are read here.
    ///
    /// A `policy` union replaces the managing app as part of the same field:
    /// `#managingAppPolicy` sets it, and the other two variants clear it,
    /// because a space whose policy no longer consults a managing app should
    /// not keep pointing at one. The legacy string form cannot say either, so
    /// it leaves the column to the separate `managingApp` field as before.
    pub fn from_update_input(value: &serde_json::Value) -> Result<Self, PdsError> {
        let policy = parse_policy_input(policy_field(value))?;
        let app_access = match value.get("appAccess") {
            Some(v) if !v.is_null() => Some(AppAccess::from_wire(v)?),
            _ => None,
        };
        let managing_app = match &policy {
            // `#managingAppPolicy` — take the app the variant carries.
            Some((MintPolicy::ManagingApp, Some(app))) => Some(app.clone()),
            // A union naming a policy that consults no app clears the column;
            // `Some("")` is the patch's existing "clear to NULL" signal.
            Some((MintPolicy::Public | MintPolicy::MemberList, None))
                if policy_field(value).is_some_and(serde_json::Value::is_object) =>
            {
                Some(String::new())
            }
            _ => value
                .get("managingApp")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        };
        Ok(Self {
            mint_policy: policy.map(|(p, _)| p),
            app_access,
            managing_app,
        })
    }
}

/// Fail with `SpaceNotFound` when the space is tombstoned
/// (`deleted_at IS NOT NULL`) in the given store. A missing row is treated as
/// *not deleted* here so callers that operate on spaces seeded lazily
/// (notify-inbound, cross-PDS reads) keep working; the tombstone gate only
/// fires once a row exists and carries a `deleted_at`. The query is a no-op
/// (returns `Ok`) when the `space` row is absent.
///
/// # Errors
/// Returns [`PdsError::SpaceNotFound`] when the space is tombstoned, or
/// [`PdsError::Storage`] on a query failure.
pub async fn ensure_not_deleted(pool: &SqlitePool, uri: &SpaceUri) -> Result<(), PdsError> {
    let deleted_at: Option<Option<String>> =
        sqlx::query_scalar("SELECT deleted_at FROM space WHERE uri = ?")
            .bind(uri.to_string())
            .fetch_optional(pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("ensure_not_deleted: {e}"),
            })?;
    if matches!(deleted_at, Some(Some(_))) {
        return Err(PdsError::SpaceNotFound {
            uri: uri.to_string(),
        });
    }
    Ok(())
}

/// Fail with `SpaceNotFound` when the space identified by `space` is
/// tombstoned in the space-authority's per-actor store.
///
/// The space row (and its `deleted_at` tombstone) is owned by
/// `space.space_did`. This opens that authority's store *only when it already
/// exists locally*; for cross-PDS spaces whose authority lives elsewhere the
/// check is skipped (the remote authority enforces deletion on its side, and
/// `getSpaceCredential` minting is gated separately).
///
/// # Errors
/// Returns [`PdsError::SpaceNotFound`] when the authority's row is tombstoned,
/// or [`PdsError::Storage`] on a query failure.
pub async fn ensure_space_live(data_dir: &Path, space: &SpaceUri) -> Result<(), PdsError> {
    // Skip when the authority's store does not exist locally.
    if !actor_db_path(data_dir, &space.space_did).exists() {
        return Ok(());
    }
    let store = SqlActorStore::open(data_dir, &space.space_did).await?;
    ensure_not_deleted(store.pool(), space).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_access_storage_round_trip() {
        let open = AppAccess::Open;
        let json = open.to_storage_json().unwrap();
        assert_eq!(json, r#"{"type":"open"}"#);
        assert_eq!(AppAccess::from_storage_json(&json).unwrap(), open);

        let list = AppAccess::AllowList {
            allowed: vec!["https://app.example/client".to_string()],
        };
        let json = list.to_storage_json().unwrap();
        assert_eq!(AppAccess::from_storage_json(&json).unwrap(), list);
    }

    #[test]
    fn app_access_default_matches_migration_default() {
        assert_eq!(
            AppAccess::from_storage_json(r#"{"type":"open"}"#).unwrap(),
            AppAccess::Open
        );
    }

    #[test]
    fn app_access_wire_round_trip() {
        let list = AppAccess::AllowList {
            allowed: vec!["c1".to_string(), "c2".to_string()],
        };
        let wire = list.to_wire();
        assert_eq!(wire["$type"], APP_ACCESS_ALLOW_LIST_TYPE);
        assert_eq!(AppAccess::from_wire(&wire).unwrap(), list);

        let open = AppAccess::Open;
        assert_eq!(AppAccess::from_wire(&open.to_wire()).unwrap(), open);
    }

    #[test]
    fn mint_policy_round_trip() {
        for p in [
            MintPolicy::Public,
            MintPolicy::MemberList,
            MintPolicy::ManagingApp,
        ] {
            assert_eq!(MintPolicy::from_str_value(p.as_str()).unwrap(), p);
        }
        assert!(MintPolicy::from_str_value("bogus").is_err());
    }

    #[test]
    fn config_default_is_member_list_open() {
        let cfg = SpaceConfig::default();
        assert_eq!(cfg.mint_policy, MintPolicy::MemberList);
        assert_eq!(cfg.app_access, AppAccess::Open);
        assert!(cfg.managing_app.is_none());
    }

    #[test]
    fn config_to_wire_carries_type() {
        let cfg = SpaceConfig {
            mint_policy: MintPolicy::Public,
            app_access: AppAccess::Open,
            managing_app: Some("did:web:example.com#forum".to_string()),
        };
        let wire = cfg.to_wire();
        assert_eq!(wire["$type"], SPACE_CONFIG_TYPE);
        assert_eq!(wire["policy"], "public");
        assert_eq!(wire["managingApp"], "did:web:example.com#forum");
        assert_eq!(wire["appAccess"]["$type"], APP_ACCESS_OPEN_TYPE);
    }

    #[test]
    fn config_from_create_input_defaults() {
        let cfg = SpaceConfig::from_create_input(&serde_json::json!({})).unwrap();
        assert_eq!(cfg, SpaceConfig::default());
    }

    /// The pre-conformance spelling stays accepted so clients written against
    /// this server's older releases keep working.
    #[test]
    fn config_from_create_input_full() {
        let cfg = SpaceConfig::from_create_input(&serde_json::json!({
            "mintPolicy": "managing-app",
            "appAccess": { "$type": APP_ACCESS_ALLOW_LIST_TYPE, "allowed": ["c1"] },
            "managingApp": "did:web:m.example#svc",
        }))
        .unwrap();
        assert_eq!(cfg.mint_policy, MintPolicy::ManagingApp);
        assert_eq!(
            cfg.app_access,
            AppAccess::AllowList {
                allowed: vec!["c1".to_string()]
            }
        );
        assert_eq!(cfg.managing_app.as_deref(), Some("did:web:m.example#svc"));
    }

    #[test]
    fn create_input_empty_managing_app_is_none() {
        let cfg =
            SpaceConfig::from_create_input(&serde_json::json!({ "managingApp": "" })).unwrap();
        assert!(cfg.managing_app.is_none());
    }

    #[test]
    fn the_lexicon_policy_field_is_read_and_wins_over_the_legacy_name() {
        let cfg = SpaceConfig::from_create_input(&serde_json::json!({
            "policy": "public",
            "appAccess": { "$type": APP_ACCESS_OPEN_TYPE },
        }))
        .unwrap();
        assert_eq!(cfg.mint_policy, MintPolicy::Public);

        // Both present is a client mid-migration; the lexicon name decides.
        let cfg = SpaceConfig::from_create_input(&serde_json::json!({
            "policy": "public",
            "mintPolicy": "managing-app",
        }))
        .unwrap();
        assert_eq!(cfg.mint_policy, MintPolicy::Public);

        let patch = SpaceConfigPatch::from_update_input(&serde_json::json!({
            "space": "ignored",
            "policy": "managing-app",
        }))
        .unwrap();
        assert_eq!(patch.mint_policy, Some(MintPolicy::ManagingApp));
    }

    /// The lexicon's `$type`-tagged union is the shape a conformant client
    /// sends, and it must reach the same stored config as the legacy string.
    #[test]
    fn the_policy_union_parses_to_the_same_config_as_the_legacy_string() {
        for (union_type, legacy, expected) in [
            (POLICY_PUBLIC_TYPE, "public", MintPolicy::Public),
            (
                POLICY_MEMBER_LIST_TYPE,
                "member-list",
                MintPolicy::MemberList,
            ),
        ] {
            let from_union = SpaceConfig::from_create_input(&serde_json::json!({
                "policy": { "$type": union_type },
            }))
            .unwrap();
            let from_legacy =
                SpaceConfig::from_create_input(&serde_json::json!({ "policy": legacy })).unwrap();
            assert_eq!(from_union.mint_policy, expected);
            assert_eq!(from_union, from_legacy, "{union_type} vs {legacy}");
        }
    }

    /// `managingApp` lives *inside* `#managingAppPolicy`, so a policy that
    /// consults a managing app cannot be configured without naming one. This
    /// server can otherwise store that state and only notices at mint time,
    /// where it refuses to issue a credential — telling the owner their space
    /// is broken long after the request that broke it.
    #[test]
    fn the_managing_app_policy_carries_its_own_app_and_cannot_omit_it() {
        let cfg = SpaceConfig::from_create_input(&serde_json::json!({
            "policy": {
                "$type": POLICY_MANAGING_APP_TYPE,
                "managingApp": "did:web:forum.example#forum",
            },
        }))
        .unwrap();
        assert_eq!(cfg.mint_policy, MintPolicy::ManagingApp);
        assert_eq!(
            cfg.managing_app.as_deref(),
            Some("did:web:forum.example#forum")
        );

        for missing in [
            serde_json::json!({ "$type": POLICY_MANAGING_APP_TYPE }),
            serde_json::json!({ "$type": POLICY_MANAGING_APP_TYPE, "managingApp": "" }),
        ] {
            let result = SpaceConfig::from_create_input(&serde_json::json!({ "policy": missing }));
            assert!(
                matches!(result, Err(PdsError::InvalidSubject { .. })),
                "a managing-app policy with no app must be refused, got {result:?}"
            );
        }
    }

    /// A union is an open union: a value this host does not implement decodes
    /// perfectly well, so it has to be refused deliberately. Storing one would
    /// leave the owner believing their space is gated by a rule nothing
    /// enforces.
    #[test]
    fn a_variant_this_host_does_not_implement_is_refused_per_axis() {
        let policy = SpaceConfig::from_create_input(&serde_json::json!({
            "policy": { "$type": "com.example.custom#inviteOnly" },
        }));
        assert!(
            matches!(policy, Err(PdsError::UnsupportedPolicy { ref value }) if value == "com.example.custom#inviteOnly"),
            "got {policy:?}"
        );

        // The legacy string form answers on the same axis.
        let legacy =
            SpaceConfig::from_create_input(&serde_json::json!({ "policy": "invite-only" }));
        assert!(
            matches!(legacy, Err(PdsError::UnsupportedPolicy { .. })),
            "got {legacy:?}"
        );

        let app_access = SpaceConfig::from_create_input(&serde_json::json!({
            "appAccess": { "$type": "com.example.custom#paidOnly" },
        }));
        assert!(
            matches!(app_access, Err(PdsError::UnsupportedAppAccess { ref value }) if value == "com.example.custom#paidOnly"),
            "got {app_access:?}"
        );

        // And on update, not just create.
        let on_update = SpaceConfigPatch::from_update_input(&serde_json::json!({
            "policy": { "$type": "com.example.custom#inviteOnly" },
        }));
        assert!(
            matches!(on_update, Err(PdsError::UnsupportedPolicy { .. })),
            "got {on_update:?}"
        );
    }

    /// Switching to a policy that consults no managing app clears the one
    /// that was set: a space left pointing at a managing app it no longer
    /// asks reads as configured when it is inert.
    #[test]
    fn a_policy_union_replaces_the_managing_app_wholesale() {
        let patch = SpaceConfigPatch::from_update_input(&serde_json::json!({
            "policy": {
                "$type": POLICY_MANAGING_APP_TYPE,
                "managingApp": "did:web:forum.example#forum",
            },
        }))
        .unwrap();
        assert_eq!(patch.mint_policy, Some(MintPolicy::ManagingApp));
        assert_eq!(
            patch.managing_app.as_deref(),
            Some("did:web:forum.example#forum")
        );

        let patch = SpaceConfigPatch::from_update_input(&serde_json::json!({
            "policy": { "$type": POLICY_PUBLIC_TYPE },
        }))
        .unwrap();
        assert_eq!(patch.mint_policy, Some(MintPolicy::Public));
        assert_eq!(
            patch.managing_app.as_deref(),
            Some(""),
            "the empty string is the patch's clear-to-NULL signal"
        );

        // The legacy string cannot express a managing app either way, so it
        // leaves the column to the separate field.
        let patch = SpaceConfigPatch::from_update_input(&serde_json::json!({ "policy": "public" }))
            .unwrap();
        assert!(patch.managing_app.is_none());
    }

    #[test]
    fn update_patch_partial() {
        let patch = SpaceConfigPatch::from_update_input(&serde_json::json!({
            "space": "ignored",
            "mintPolicy": "public",
        }))
        .unwrap();
        assert_eq!(patch.mint_policy, Some(MintPolicy::Public));
        assert!(patch.app_access.is_none());
        assert!(patch.managing_app.is_none());
    }

    #[test]
    fn update_patch_clear_managing_app() {
        let patch =
            SpaceConfigPatch::from_update_input(&serde_json::json!({ "managingApp": "" })).unwrap();
        assert_eq!(patch.managing_app.as_deref(), Some(""));
    }
}
