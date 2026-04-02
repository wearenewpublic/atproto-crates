//! Schema compatibility analysis for AT Protocol lexicon schemas.
//!
//! This module provides functions for checking breaking vs non-breaking changes
//! between lexicon schema versions, generating migration guidance, and analyzing
//! cross-schema compatibility impacts. Requires the `panproto` feature.
//!
//! ## Functions
//!
//! - [`check_compatibility`]: Compare two schemas and produce a compatibility report
//! - [`generate_migration_guidance`]: Generate actionable migration guidance
//! - [`check_cross_compatibility`]: Check if breaking changes affect dependent schemas

use panproto_core::check::classify::{
    self, BreakingChange as PpBreaking, CompatReport as PpCompatReport,
    NonBreakingChange as PpNonBreaking,
};
use panproto_core::check::diff;
use panproto_core::check::report::report_json;
use panproto_core::protocols::web_document::atproto;
use serde::{Deserialize, Serialize};

use crate::errors::CompatibilityError;

/// Report describing compatibility between two schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityReport {
    /// Whether any breaking changes were detected.
    pub is_breaking: bool,
    /// List of breaking changes found.
    pub breaking_changes: Vec<Change>,
    /// List of non-breaking changes found.
    pub non_breaking_changes: Vec<Change>,
    /// Human-readable summary of the changes.
    pub summary: String,
    /// Raw JSON from panproto's report for detailed/structured output.
    pub detail_json: serde_json::Value,
}

/// A single schema change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    /// The kind of change (e.g. "RemovedVertex", "AddedEdge").
    pub kind: String,
    /// Debug description of the change.
    pub description: String,
}

/// Migration guidance between two schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationGuidance {
    /// Vertices removed from the schema.
    pub removed_vertices: Vec<String>,
    /// Vertices added to the schema.
    pub added_vertices: Vec<String>,
    /// Constraint changes (tightened, relaxed, added, removed).
    pub constraint_changes: Vec<ConstraintChange>,
    /// Additional notes about the migration.
    pub notes: Vec<String>,
}

/// A single constraint change in a schema migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintChange {
    /// The kind of constraint change.
    pub kind: String,
    /// Debug description of the constraint change.
    pub description: String,
}

/// Impact of schema changes on a dependent schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCompatibilityImpact {
    /// The NSID of the dependent schema.
    pub nsid: String,
    /// Whether the dependent is affected by the changes.
    pub is_affected: bool,
    /// The breaking changes that affect this dependent.
    pub affected_changes: Vec<Change>,
}

/// Compare two lexicon schema JSON values and produce a compatibility report.
pub fn check_compatibility(
    from_schema: &serde_json::Value,
    to_schema: &serde_json::Value,
) -> Result<CompatibilityReport, CompatibilityError> {
    let protocol = atproto::protocol();

    let old = atproto::parse_lexicon(from_schema)
        .map_err(|e| CompatibilityError::ParseFrom(e.to_string()))?;
    let new = atproto::parse_lexicon(to_schema)
        .map_err(|e| CompatibilityError::ParseTo(e.to_string()))?;

    let schema_diff = diff::diff(&old, &new);
    let compat: PpCompatReport = classify::classify(&schema_diff, &protocol);
    let detail_json = report_json(&compat);

    let breaking_changes: Vec<Change> = compat
        .breaking
        .iter()
        .map(|bc| Change {
            kind: breaking_kind_name(bc),
            description: format!("{bc:?}"),
        })
        .collect();

    let non_breaking_changes: Vec<Change> = compat
        .non_breaking
        .iter()
        .map(|nbc| Change {
            kind: non_breaking_kind_name(nbc),
            description: format!("{nbc:?}"),
        })
        .collect();

    let summary = build_summary(&breaking_changes, &non_breaking_changes, compat.compatible);

    Ok(CompatibilityReport {
        is_breaking: !compat.compatible,
        breaking_changes,
        non_breaking_changes,
        summary,
        detail_json,
    })
}

/// Generate migration guidance between two schema versions.
pub fn generate_migration_guidance(
    from_schema: &serde_json::Value,
    to_schema: &serde_json::Value,
) -> Result<MigrationGuidance, CompatibilityError> {
    let protocol = atproto::protocol();

    let old = atproto::parse_lexicon(from_schema)
        .map_err(|e| CompatibilityError::ParseFrom(e.to_string()))?;
    let new = atproto::parse_lexicon(to_schema)
        .map_err(|e| CompatibilityError::ParseTo(e.to_string()))?;

    let schema_diff = diff::diff(&old, &new);
    let compat = classify::classify(&schema_diff, &protocol);

    let mut removed_vertices = Vec::new();
    let mut added_vertices = Vec::new();
    let mut constraint_changes = Vec::new();
    let mut notes = Vec::new();

    for bc in &compat.breaking {
        match bc {
            PpBreaking::RemovedVertex { .. } => {
                removed_vertices.push(format!("{bc:?}"));
            }
            PpBreaking::ConstraintTightened { .. } | PpBreaking::ConstraintAdded { .. } => {
                constraint_changes.push(ConstraintChange {
                    kind: breaking_kind_name(bc),
                    description: format!("{bc:?}"),
                });
            }
            _ => {
                notes.push(format!("Breaking: {bc:?}"));
            }
        }
    }

    for nbc in &compat.non_breaking {
        match nbc {
            PpNonBreaking::AddedVertex { .. } => {
                added_vertices.push(format!("{nbc:?}"));
            }
            PpNonBreaking::ConstraintRelaxed { .. } | PpNonBreaking::ConstraintRemoved { .. } => {
                constraint_changes.push(ConstraintChange {
                    kind: non_breaking_kind_name(nbc),
                    description: format!("{nbc:?}"),
                });
            }
            _ => {
                notes.push(format!("Non-breaking: {nbc:?}"));
            }
        }
    }

    Ok(MigrationGuidance {
        removed_vertices,
        added_vertices,
        constraint_changes,
        notes,
    })
}

/// Check whether breaking changes in a schema affect its dependents.
pub fn check_cross_compatibility(
    from_schema: &serde_json::Value,
    to_schema: &serde_json::Value,
    changed_nsid: &str,
    dependent_schemas: &[(String, serde_json::Value)],
) -> Result<Vec<CrossCompatibilityImpact>, CompatibilityError> {
    let report = check_compatibility(from_schema, to_schema)?;

    if !report.is_breaking {
        return Ok(dependent_schemas
            .iter()
            .map(|(nsid, _)| CrossCompatibilityImpact {
                nsid: nsid.clone(),
                is_affected: false,
                affected_changes: Vec::new(),
            })
            .collect());
    }

    let mut impacts = Vec::new();

    for (dep_nsid, dep_schema) in dependent_schemas {
        let dep_json = serde_json::to_string(dep_schema).unwrap_or_default();
        let references_changed = dep_json.contains(changed_nsid);

        if references_changed {
            impacts.push(CrossCompatibilityImpact {
                nsid: dep_nsid.clone(),
                is_affected: true,
                affected_changes: report.breaking_changes.clone(),
            });
        } else {
            impacts.push(CrossCompatibilityImpact {
                nsid: dep_nsid.clone(),
                is_affected: false,
                affected_changes: Vec::new(),
            });
        }
    }

    Ok(impacts)
}

fn breaking_kind_name(bc: &PpBreaking) -> String {
    match bc {
        PpBreaking::RemovedVertex { .. } => "RemovedVertex".to_string(),
        PpBreaking::RemovedEdge { .. } => "RemovedEdge".to_string(),
        PpBreaking::RemovedVariant { .. } => "RemovedVariant".to_string(),
        PpBreaking::KindChanged { .. } => "KindChanged".to_string(),
        PpBreaking::ConstraintTightened { .. } => "ConstraintTightened".to_string(),
        PpBreaking::ConstraintAdded { .. } => "ConstraintAdded".to_string(),
        PpBreaking::OrderToUnordered { .. } => "OrderToUnordered".to_string(),
        PpBreaking::RecursionBroken { .. } => "RecursionBroken".to_string(),
        PpBreaking::LinearityTightened { .. } => "LinearityTightened".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn non_breaking_kind_name(nbc: &PpNonBreaking) -> String {
    match nbc {
        PpNonBreaking::AddedVertex { .. } => "AddedVertex".to_string(),
        PpNonBreaking::AddedEdge { .. } => "AddedEdge".to_string(),
        PpNonBreaking::ConstraintRelaxed { .. } => "ConstraintRelaxed".to_string(),
        PpNonBreaking::ConstraintRemoved { .. } => "ConstraintRemoved".to_string(),
        PpNonBreaking::RemovedEdge { .. } => "RemovedEdge".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn build_summary(breaking: &[Change], non_breaking: &[Change], compatible: bool) -> String {
    if compatible {
        if non_breaking.is_empty() {
            "No changes detected.".to_string()
        } else {
            format!(
                "Backward compatible. {} non-breaking change{}.",
                non_breaking.len(),
                if non_breaking.len() == 1 { "" } else { "s" }
            )
        }
    } else {
        format!(
            "{} breaking change{}, {} non-breaking change{}.",
            breaking.len(),
            if breaking.len() == 1 { "" } else { "s" },
            non_breaking.len(),
            if non_breaking.len() == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record_schema() -> serde_json::Value {
        serde_json::json!({
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text", "createdAt"],
                        "properties": {
                            "text": { "type": "string", "maxLength": 300 },
                            "createdAt": { "type": "string", "format": "datetime" }
                        }
                    }
                }
            }
        })
    }

    fn sample_record_schema_added_field() -> serde_json::Value {
        serde_json::json!({
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text", "createdAt"],
                        "properties": {
                            "text": { "type": "string", "maxLength": 300 },
                            "createdAt": { "type": "string", "format": "datetime" },
                            "lang": { "type": "string", "format": "language" }
                        }
                    }
                }
            }
        })
    }

    fn sample_record_schema_removed_field() -> serde_json::Value {
        serde_json::json!({
            "lexicon": 1,
            "id": "com.example.test",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text"],
                        "properties": {
                            "text": { "type": "string", "maxLength": 300 }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn test_identical_schemas_are_compatible() {
        let schema = sample_record_schema();
        let report = check_compatibility(&schema, &schema).unwrap();
        assert!(!report.is_breaking);
        assert!(report.breaking_changes.is_empty());
    }

    #[test]
    fn test_added_optional_field_is_non_breaking() {
        let from = sample_record_schema();
        let to = sample_record_schema_added_field();
        let report = check_compatibility(&from, &to).unwrap();
        assert!(!report.is_breaking);
        assert!(!report.non_breaking_changes.is_empty());
    }

    #[test]
    fn test_removed_required_field_is_breaking() {
        let from = sample_record_schema();
        let to = sample_record_schema_removed_field();
        let report = check_compatibility(&from, &to).unwrap();
        assert!(report.is_breaking);
        assert!(!report.breaking_changes.is_empty());
    }

    #[test]
    fn test_migration_guidance_for_removed_field() {
        let from = sample_record_schema();
        let to = sample_record_schema_removed_field();
        let guidance = generate_migration_guidance(&from, &to).unwrap();
        assert!(
            !guidance.removed_vertices.is_empty() || !guidance.notes.is_empty(),
            "migration guidance should note removed elements"
        );
    }
}
