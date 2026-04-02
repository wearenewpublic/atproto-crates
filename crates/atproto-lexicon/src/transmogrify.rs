//! Record transmogrification between AT Protocol lexicon schemas.
//!
//! This module provides functionality for transforming records from one lexicon
//! schema to another. It supports multiple transformation strategies:
//!
//! - **Panproto morphism discovery** (requires `panproto` feature): Uses formal
//!   category-theoretic morphisms to find optimal schema mappings.
//! - **JSON-level fallback**: Uses property-name intersection, explicit field
//!   mappings, and default values for pragmatic transformation.
//!
//! ## Example
//!
//! ```no_run
//! use serde_json::json;
//! use atproto_lexicon::transmogrify::{transmogrify, TransmogrifyMappings};
//!
//! let source_schema = json!({
//!     "lexicon": 1,
//!     "id": "com.example.source",
//!     "defs": { "main": { "type": "record", "key": "tid", "record": {
//!         "type": "object",
//!         "properties": { "text": { "type": "string" } }
//!     }}}
//! });
//! let dest_schema = json!({
//!     "lexicon": 1,
//!     "id": "com.example.dest",
//!     "defs": { "main": { "type": "record", "key": "tid", "record": {
//!         "type": "object",
//!         "properties": { "text": { "type": "string" }, "title": { "type": "string" } }
//!     }}}
//! });
//! let record = json!({ "text": "hello" });
//!
//! let result = transmogrify(&source_schema, &dest_schema, &record, None).unwrap();
//! assert_eq!(result.record["text"], "hello");
//! ```

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::TransmogrifyError;
use crate::resolve::LexiconResolver;

/// Mappings to guide transmogrification: field renames and default values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransmogrifyMappings {
    /// Field renames: source field name to destination field name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub field_mappings: HashMap<String, String>,
    /// Default values to inject into the destination record.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub defaults: HashMap<String, Value>,
}

impl TransmogrifyMappings {
    /// Returns true if both field_mappings and defaults are empty.
    pub fn is_empty(&self) -> bool {
        self.field_mappings.is_empty() && self.defaults.is_empty()
    }

    /// Returns the field_mappings as a reference, or None if empty.
    pub fn field_mappings_ref(&self) -> Option<&HashMap<String, String>> {
        if self.field_mappings.is_empty() {
            None
        } else {
            Some(&self.field_mappings)
        }
    }
}

/// Result of a transmogrification operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransmogrifyResult {
    /// The transformed record JSON.
    pub record: Value,
    /// Quality score of the transformation (0.0–1.0).
    pub quality: f64,
}

/// Transmogrify a record from one lexicon schema to another.
///
/// Convenience wrapper over [`transmogrify_with_refs`] that passes `None`
/// for `resolved_refs`. Use [`transmogrify_with_refs`] when external schema
/// references need to be resolved for nested object mapping.
pub fn transmogrify(
    from_schema_json: &Value,
    to_schema_json: &Value,
    record_value: &Value,
    mappings: Option<&TransmogrifyMappings>,
) -> Result<TransmogrifyResult, TransmogrifyError> {
    transmogrify_with_refs(
        from_schema_json,
        to_schema_json,
        record_value,
        mappings,
        None,
    )
}

/// Resolve schemas and transmogrify a record from one lexicon schema to another.
///
/// This is the high-level entry point that handles the full pipeline:
/// 1. Resolve source and destination schemas via the provided resolver
/// 2. Extract and resolve external schema references
/// 3. Enrich both schemas with resolved references
/// 4. Run transmogrification
///
/// Use this when you have NSIDs and a resolver rather than pre-fetched schemas.
pub async fn transmogrify_record(
    resolver: &dyn LexiconResolver,
    source_nsid: &str,
    destination_nsid: &str,
    record: &Value,
    mappings: Option<&TransmogrifyMappings>,
) -> Result<TransmogrifyResult, TransmogrifyError> {
    let source_schema = resolver.resolve(source_nsid).await.map_err(|e| {
        TransmogrifyError::SchemaResolveFailed {
            nsid: source_nsid.to_string(),
            details: e.to_string(),
        }
    })?;

    let dest_schema = resolver.resolve(destination_nsid).await.map_err(|e| {
        TransmogrifyError::SchemaResolveFailed {
            nsid: destination_nsid.to_string(),
            details: e.to_string(),
        }
    })?;

    let mut all_refs = extract_schema_refs(&source_schema);
    all_refs.extend(extract_schema_refs(&dest_schema));

    let mut resolved_refs = HashMap::new();
    for ref_nsid in &all_refs {
        let base_nsid = ref_nsid.split('#').next().unwrap_or(ref_nsid);
        if resolved_refs.contains_key(base_nsid) {
            continue;
        }
        match resolver.resolve(base_nsid).await {
            Ok(schema) => {
                resolved_refs.insert(base_nsid.to_string(), schema);
            }
            Err(error) => {
                tracing::debug!(error = ?error, nsid = %base_nsid, "Failed to resolve external ref schema, skipping.");
            }
        }
    }

    let enriched_source = enrich_schema_with_refs(&source_schema, &resolved_refs);
    let enriched_dest = enrich_schema_with_refs(&dest_schema, &resolved_refs);

    transmogrify_with_refs(
        &enriched_source,
        &enriched_dest,
        record,
        mappings,
        Some(&resolved_refs),
    )
}

/// Transmogrify a record, with access to resolved external schemas for
/// recursive nested-object mapping.
///
/// Uses a multi-strategy approach:
/// 1. Try strict morphism discovery (best quality, requires `panproto` feature)
/// 2. Fall back to overlap-based partial migration with left Kan extension
/// 3. Property-name intersection at the JSON level, augmented by caller-provided
///    field mappings and default values
pub fn transmogrify_with_refs(
    from_schema_json: &Value,
    to_schema_json: &Value,
    record_value: &Value,
    mappings: Option<&TransmogrifyMappings>,
    resolved_refs: Option<&HashMap<String, Value>>,
) -> Result<TransmogrifyResult, TransmogrifyError> {
    #[cfg(feature = "panproto")]
    let panproto_result: Option<TransmogrifyResult> = {
        use panproto_core::inst;
        use panproto_core::mig;
        use panproto_core::mig::hom_search::{SearchOptions, morphism_to_migration};
        use panproto_core::protocols::web_document::atproto;

        let from_schema = atproto::parse_lexicon(from_schema_json)
            .map_err(|e| TransmogrifyError::ParseFrom(e.to_string()))?;
        let to_schema = atproto::parse_lexicon(to_schema_json)
            .map_err(|e| TransmogrifyError::ParseTo(e.to_string()))?;

        // When explicit field mappings are provided, use the JSON-level strategy directly.
        if mappings.is_some_and(|m| !m.field_mappings.is_empty()) {
            return transmogrify_json(
                record_value,
                from_schema_json,
                to_schema_json,
                mappings,
                resolved_refs,
            );
        }

        let parsed_instance = find_record_body_vertex(&from_schema)
            .and_then(|from_root| inst::parse_json(&from_schema, &from_root, record_value).ok());

        if let Some(instance) = &parsed_instance {
            // Strategy 1: Strict morphism discovery
            let search_opts = SearchOptions {
                max_results: 1,
                ..SearchOptions::default()
            };
            let morphisms = mig::find_morphisms(&from_schema, &to_schema, &search_opts);
            let strategy1 = morphisms.into_iter().next().and_then(|morphism| {
                let quality = morphism.quality;
                let migration = morphism_to_migration(&morphism);
                let compiled = mig::compile(&from_schema, &to_schema, &migration).ok()?;
                let transformed =
                    mig::lift_wtype(&compiled, &from_schema, &to_schema, instance).ok()?;
                let output = inst::to_json(&to_schema, &transformed);
                Some(TransmogrifyResult {
                    record: output,
                    quality,
                })
            });

            if strategy1.is_some() {
                strategy1
            } else {
                // Strategy 2: Overlap-based partial migration with left Kan extension
                let overlap = mig::discover_overlap(&from_schema, &to_schema);
                if !overlap.vertex_pairs.is_empty() {
                    let mut migration = mig::Migration::empty();
                    migration.vertex_map = overlap
                        .vertex_pairs
                        .iter()
                        .map(|(l, r)| (l.clone(), r.clone()))
                        .collect();
                    migration.edge_map = overlap
                        .edge_pairs
                        .iter()
                        .map(|(l, r)| (l.clone(), r.clone()))
                        .collect();

                    mig::compile(&from_schema, &to_schema, &migration)
                        .ok()
                        .and_then(|compiled| {
                            mig::lift_wtype_sigma(&compiled, &to_schema, instance).ok()
                        })
                        .map(|transformed| {
                            let output = inst::to_json(&to_schema, &transformed);
                            let target_vertex_count = to_schema.vertices.len().max(1);
                            let quality =
                                overlap.vertex_pairs.len() as f64 / target_vertex_count as f64;
                            TransmogrifyResult {
                                record: output,
                                quality,
                            }
                        })
                } else {
                    None
                }
            }
        } else {
            None
        }
    };

    #[cfg(feature = "panproto")]
    if let Some(result) = panproto_result {
        // When resolved_refs are provided, the JSON-level strategy may produce
        // a better result because it handles $type rewriting for union fields.
        // Compare both and return the higher-quality result.
        if resolved_refs.is_some()
            && let Ok(json_result) = transmogrify_json(
                record_value,
                from_schema_json,
                to_schema_json,
                mappings,
                resolved_refs,
            )
            && json_result.quality >= result.quality
        {
            return Ok(json_result);
        }
        return Ok(result);
    }

    #[cfg(not(feature = "panproto"))]
    {
        // When explicit field mappings are provided, use the JSON-level strategy directly.
        if mappings.is_some_and(|m| !m.field_mappings.is_empty()) {
            return transmogrify_json(
                record_value,
                from_schema_json,
                to_schema_json,
                mappings,
                resolved_refs,
            );
        }
    }

    // Strategy 3 (or only strategy without panproto): JSON-level fallback
    transmogrify_json(
        record_value,
        from_schema_json,
        to_schema_json,
        mappings,
        resolved_refs,
    )
}

/// JSON-level transmogrification using property-name intersection, explicit
/// field mappings, and default values.
pub fn transmogrify_json(
    record_value: &Value,
    from_schema_json: &Value,
    to_schema_json: &Value,
    mappings: Option<&TransmogrifyMappings>,
    resolved_refs: Option<&HashMap<String, Value>>,
) -> Result<TransmogrifyResult, TransmogrifyError> {
    let dest_properties = extract_schema_properties(to_schema_json);
    if dest_properties.is_empty() {
        return Err(TransmogrifyError::NoMorphismFound);
    }

    let reverse_map: HashMap<&str, &str> = mappings
        .map(|m| {
            m.field_mappings
                .iter()
                .filter(|(_, dst)| !dst.contains('.'))
                .map(|(src, dst)| (dst.as_str(), src.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let defaults = mappings.map(|m| &m.defaults);

    let source_obj = record_value
        .as_object()
        .ok_or_else(|| TransmogrifyError::ParseRecord("record is not a JSON object".to_string()))?;

    let mut output = serde_json::Map::new();
    let mut matched = 0usize;

    // Phase 1: Match top-level destination properties
    for dest_prop in &dest_properties {
        if let Some(&src_field) = reverse_map.get(dest_prop.as_str())
            && let Some(value) = resolve_dotted_path(record_value, src_field)
        {
            output.insert(dest_prop.clone(), value.clone());
            matched += 1;
            continue;
        }
        if let Some(value) = source_obj.get(dest_prop) {
            output.insert(dest_prop.clone(), value.clone());
            matched += 1;
            continue;
        }
        if let Some(default_value) = defaults.and_then(|d| d.get(dest_prop))
            && !dest_prop.contains('.')
        {
            output.insert(dest_prop.clone(), default_value.clone());
            matched += 1;
        }
    }

    // Phase 2: Auto-map nested typed objects to unmatched destination union/ref fields
    if let Some(refs) = resolved_refs {
        let nested_sources: Vec<(&str, &Value)> = source_obj
            .iter()
            .filter(|(key, val)| {
                !output.contains_key(key.as_str())
                    && val.is_object()
                    && val.get("$type").and_then(|t| t.as_str()).is_some()
            })
            .map(|(k, v)| (k.as_str(), v))
            .collect();

        if !nested_sources.is_empty() {
            let unmatched_dest: Vec<&str> = dest_properties
                .iter()
                .filter(|prop| !output.contains_key(prop.as_str()))
                .map(|s| s.as_str())
                .collect();

            for dest_prop in unmatched_dest {
                let prop_def = get_property_schema_def(to_schema_json, dest_prop);
                let candidate_nsids = prop_def
                    .as_ref()
                    .map(get_union_or_ref_candidates)
                    .unwrap_or_default();

                if candidate_nsids.is_empty() {
                    continue;
                }

                let mut best: Option<(Value, f64, String)> = None;

                for (_, src_val) in &nested_sources {
                    let src_type = src_val.get("$type").unwrap().as_str().unwrap();
                    let src_nested_schema =
                        resolve_nested_type_schema(src_type, from_schema_json, refs);

                    let Some(src_schema) = src_nested_schema else {
                        continue;
                    };

                    for candidate_nsid in &candidate_nsids {
                        let dest_nested_schema =
                            resolve_nested_type_schema(candidate_nsid, to_schema_json, refs);

                        let Some(dest_schema) = dest_nested_schema else {
                            continue;
                        };

                        let panproto_result =
                            transmogrify(&src_schema, &dest_schema, src_val, None).ok();

                        let deep_result =
                            deep_match_nested(src_val, &dest_schema).and_then(|record| {
                                let dest_leaf_count = count_dest_schema_leaves(&dest_schema);
                                let matched_count =
                                    record.as_object().map(count_leaf_values).unwrap_or(0);
                                let quality = matched_count as f64 / dest_leaf_count.max(1) as f64;
                                if quality >= 0.75 {
                                    Some(TransmogrifyResult { record, quality })
                                } else {
                                    None
                                }
                            });

                        let result_opt = match (panproto_result, deep_result) {
                            (Some(a), Some(b)) => Some(if b.quality >= a.quality { b } else { a }),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b),
                            (None, None) => None,
                        };

                        if let Some(result) = result_opt
                            && best.as_ref().is_none_or(|(_, q, _)| result.quality > *q)
                        {
                            let mut nested_record = result.record;
                            if let Some(obj) = nested_record.as_object_mut() {
                                obj.insert(
                                    "$type".to_string(),
                                    Value::String(candidate_nsid.clone()),
                                );
                            }
                            best = Some((nested_record, result.quality, candidate_nsid.clone()));
                        }
                    }
                }

                if let Some((nested_record, _, _)) = best {
                    output.insert(dest_prop.to_string(), nested_record);
                    matched += 1;
                }
            }
        }
    }

    // Phase 3: Apply dotted-path field mappings
    if let Some(m) = mappings {
        for (src_path, dst_path) in &m.field_mappings {
            if !dst_path.contains('.') {
                continue;
            }
            if let Some(value) = resolve_dotted_path(record_value, src_path) {
                set_nested_path(&mut output, dst_path, value.clone());
                matched += 1;
            }
        }
    }

    // Phase 4: Apply dotted-path defaults
    if let Some(defaults_map) = defaults {
        for (path, value) in defaults_map {
            if !path.contains('.') {
                continue;
            }
            if resolve_dotted_path(&Value::Object(output.clone()), path).is_none() {
                set_nested_path(&mut output, path, value.clone());
                matched += 1;
            }
        }
    }

    if matched == 0 {
        return Err(TransmogrifyError::NoMorphismFound);
    }

    let quality = matched as f64 / dest_properties.len().max(1) as f64;
    Ok(TransmogrifyResult {
        record: Value::Object(output),
        quality,
    })
}

/// Extract all external ref NSIDs from a lexicon schema JSON.
pub fn extract_schema_refs(schema_json: &Value) -> HashSet<String> {
    let mut refs = HashSet::new();
    if let Some(defs) = schema_json.get("defs").and_then(|d| d.as_object()) {
        for (_def_name, def) in defs {
            collect_refs_from_def(def, &mut refs);
        }
    }
    refs
}

/// Enrich a schema JSON by inlining external ref definitions.
pub fn enrich_schema_with_refs(
    schema_json: &Value,
    resolved_schemas: &HashMap<String, Value>,
) -> Value {
    let mut result = schema_json.clone();
    if let Some(defs) = result.get_mut("defs").and_then(|d| d.as_object_mut()) {
        let keys: Vec<String> = defs.keys().cloned().collect();
        for key in keys {
            if let Some(def) = defs.get_mut(&key) {
                enrich_def(def, resolved_schemas);
            }
        }
    }

    // Add union variant definitions keyed by NSID with dots replaced by underscores.
    let union_refs = collect_union_refs(&result);
    if !union_refs.is_empty()
        && let Some(defs) = result.get_mut("defs").and_then(|d| d.as_object_mut())
    {
        for ref_nsid in union_refs {
            let safe_key = ref_nsid.replace('.', "_");
            if defs.contains_key(&safe_key) {
                continue;
            }
            if let Some(resolved_def) = resolve_ref_definition(&ref_nsid, resolved_schemas) {
                defs.insert(safe_key, resolved_def);
            }
        }
    }

    result
}

// -- Private helpers --

/// Extract property names from a lexicon schema's main record definition.
fn extract_schema_properties(schema_json: &Value) -> Vec<String> {
    schema_json
        .pointer("/defs/main/record/properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default()
}

/// Get the schema definition for a named property from a lexicon schema's
/// main record definition.
fn get_property_schema_def(schema_json: &Value, prop_name: &str) -> Option<Value> {
    schema_json
        .pointer(&format!("/defs/main/record/properties/{prop_name}"))
        .cloned()
}

/// Extract candidate type NSIDs from a property definition that is a union or ref.
fn get_union_or_ref_candidates(prop_def: &Value) -> Vec<String> {
    let type_str = prop_def.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match type_str {
        "union" => prop_def
            .get("refs")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        "ref" => prop_def
            .get("ref")
            .and_then(|r| r.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        _ => vec![],
    }
}

/// Resolve a dotted path through nested JSON objects.
fn resolve_dotted_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if !path.contains('.') {
        return value.as_object().and_then(|obj| obj.get(path));
    }
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object().and_then(|obj| obj.get(segment))?;
    }
    Some(current)
}

/// Set a value at a dotted path in a JSON map, creating intermediate objects as needed.
fn set_nested_path(output: &mut serde_json::Map<String, Value>, path: &str, value: Value) {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.len() == 1 {
        output.insert(segments[0].to_string(), value);
        return;
    }
    let mut current = output;
    for segment in &segments[..segments.len() - 1] {
        let key = segment.to_string();
        if !current.contains_key(&key) {
            current.insert(key.clone(), Value::Object(serde_json::Map::new()));
        }
        current = current
            .get_mut(&key)
            .unwrap()
            .as_object_mut()
            .expect("intermediate path segment is not an object");
    }
    current.insert(segments.last().unwrap().to_string(), value);
}

/// Find the record body vertex in a panproto ATProto schema.
#[cfg(feature = "panproto")]
fn find_record_body_vertex(schema: &panproto_core::schema::Schema) -> Option<String> {
    for vertex in schema.vertices.values() {
        if vertex.id.ends_with(":body") {
            return Some(vertex.id.to_string());
        }
    }
    None
}

/// Recursively collect external ref NSIDs from a schema definition.
fn collect_refs_from_def(def: &Value, refs: &mut HashSet<String>) {
    let type_str = def.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match type_str {
        "ref" => {
            if let Some(r) = def.get("ref").and_then(|v| v.as_str())
                && !r.starts_with('#')
            {
                refs.insert(r.to_string());
            }
        }
        "union" => {
            if let Some(arr) = def.get("refs").and_then(|v| v.as_array()) {
                for r in arr.iter().filter_map(|v| v.as_str()) {
                    if !r.starts_with('#') {
                        refs.insert(r.to_string());
                    }
                }
            }
        }
        "record" => {
            if let Some(record) = def.get("record") {
                collect_refs_from_def(record, refs);
            }
        }
        "object" => {
            if let Some(props) = def.get("properties").and_then(|p| p.as_object()) {
                for (_name, prop_def) in props {
                    collect_refs_from_def(prop_def, refs);
                }
            }
        }
        "array" => {
            if let Some(items) = def.get("items") {
                collect_refs_from_def(items, refs);
            }
        }
        _ => {}
    }
}

/// Collect all external union ref NSIDs from a schema's defs.
fn collect_union_refs(schema_json: &Value) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(defs) = schema_json.get("defs").and_then(|d| d.as_object()) {
        for (_def_name, def) in defs {
            collect_union_refs_from_def(def, &mut refs);
        }
    }
    refs
}

/// Recursively collect union ref NSIDs from a schema definition.
fn collect_union_refs_from_def(def: &Value, refs: &mut Vec<String>) {
    let type_str = def.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match type_str {
        "union" => {
            if let Some(arr) = def.get("refs").and_then(|v| v.as_array()) {
                for r in arr.iter().filter_map(|v| v.as_str()) {
                    if !r.starts_with('#') {
                        refs.push(r.to_string());
                    }
                }
            }
        }
        "record" => {
            if let Some(record) = def.get("record") {
                collect_union_refs_from_def(record, refs);
            }
        }
        "object" => {
            if let Some(props) = def.get("properties").and_then(|p| p.as_object()) {
                for (_name, prop_def) in props {
                    collect_union_refs_from_def(prop_def, refs);
                }
            }
        }
        "array" => {
            if let Some(items) = def.get("items") {
                collect_union_refs_from_def(items, refs);
            }
        }
        _ => {}
    }
}

/// Recursively enrich a schema definition by inlining external refs.
fn enrich_def(def: &mut Value, resolved_schemas: &HashMap<String, Value>) {
    let type_str = def
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    match type_str.as_str() {
        "ref" => {
            if let Some(ref_target) = def.get("ref").and_then(|v| v.as_str()).map(String::from)
                && let Some(resolved_def) = resolve_ref_definition(&ref_target, resolved_schemas)
            {
                *def = resolved_def;
            }
        }
        "record" => {
            if let Some(record) = def.get_mut("record") {
                enrich_def(record, resolved_schemas);
            }
        }
        "object" => {
            if let Some(props) = def.get_mut("properties").and_then(|p| p.as_object_mut()) {
                let keys: Vec<String> = props.keys().cloned().collect();
                for key in keys {
                    if let Some(prop_def) = props.get_mut(&key) {
                        enrich_def(prop_def, resolved_schemas);
                    }
                }
            }
        }
        "array" => {
            if let Some(items) = def.get_mut("items") {
                enrich_def(items, resolved_schemas);
            }
        }
        "union" => {
            // For unions, we don't inline individual variants since panproto
            // creates variant vertices from the refs array.
        }
        _ => {}
    }
}

/// Resolve a ref NSID to an inline definition from the resolved schemas map.
fn resolve_ref_definition(
    ref_target: &str,
    resolved_schemas: &HashMap<String, Value>,
) -> Option<Value> {
    let (nsid, fragment) = if let Some(idx) = ref_target.find('#') {
        (&ref_target[..idx], Some(&ref_target[idx + 1..]))
    } else {
        (ref_target, None)
    };

    let schema = resolved_schemas.get(nsid)?;

    let def = if let Some(frag) = fragment {
        schema.pointer(&format!("/defs/{frag}"))
    } else {
        schema
            .pointer("/defs/main/record")
            .or_else(|| schema.pointer("/defs/main"))
    }?;

    Some(def.clone())
}

/// Resolve a `$type` NSID to a minimal wrapping schema suitable for transmogrify.
fn resolve_nested_type_schema(
    type_nsid: &str,
    parent_schema_json: &Value,
    resolved_refs: &HashMap<String, Value>,
) -> Option<Value> {
    let (base_nsid, fragment) = if let Some(idx) = type_nsid.find('#') {
        (&type_nsid[..idx], Some(&type_nsid[idx + 1..]))
    } else {
        (type_nsid, None)
    };

    let parent_id = parent_schema_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let (object_def, containing_schema) = if let Some(frag) = fragment {
        if base_nsid == parent_id || base_nsid.is_empty() {
            let def = parent_schema_json.pointer(&format!("/defs/{frag}"))?;
            (def, parent_schema_json)
        } else {
            let schema = resolved_refs.get(base_nsid)?;
            let def = schema.pointer(&format!("/defs/{frag}"))?;
            (def, schema)
        }
    } else if let Some(schema) = resolved_refs.get(base_nsid) {
        let def = schema
            .pointer("/defs/main/record")
            .or_else(|| schema.pointer("/defs/main"))?;
        (def, schema)
    } else {
        let safe_key = base_nsid.replace('.', "_");
        let def = parent_schema_json.pointer(&format!("/defs/{safe_key}"))?;
        (def, parent_schema_json)
    };

    let record_def = if object_def.get("type").and_then(|t| t.as_str()) == Some("object") {
        object_def.clone()
    } else {
        object_def
            .get("record")
            .cloned()
            .unwrap_or_else(|| object_def.clone())
    };

    let record_def = resolve_internal_refs(&record_def, containing_schema);

    Some(serde_json::json!({
        "lexicon": 1,
        "id": type_nsid.replace('#', "."),
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": record_def
            }
        }
    }))
}

/// Recursively resolve internal fragment refs within a definition.
fn resolve_internal_refs(def: &Value, containing_schema: &Value) -> Value {
    let type_str = def
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    match type_str.as_str() {
        "ref" => {
            if let Some(ref_target) = def.get("ref").and_then(|v| v.as_str())
                && let Some(frag) = ref_target.strip_prefix('#')
                && let Some(resolved) = containing_schema.pointer(&format!("/defs/{frag}"))
            {
                return resolve_internal_refs(resolved, containing_schema);
            }
            def.clone()
        }
        "object" => {
            let mut result = def.clone();
            if let Some(props) = result.get_mut("properties").and_then(|p| p.as_object_mut()) {
                let keys: Vec<String> = props.keys().cloned().collect();
                for key in keys {
                    if let Some(prop_def) = props.get(&key).cloned() {
                        let resolved = resolve_internal_refs(&prop_def, containing_schema);
                        props.insert(key, resolved);
                    }
                }
            }
            result
        }
        "array" => {
            let mut result = def.clone();
            if let Some(items) = result.get("items").cloned() {
                let resolved = resolve_internal_refs(&items, containing_schema);
                result
                    .as_object_mut()
                    .unwrap()
                    .insert("items".to_string(), resolved);
            }
            result
        }
        _ => def.clone(),
    }
}

/// Known format-aware field name aliases.
const NAME_ALIASES: &[(&str, &str)] = &[("uri", "url"), ("url", "uri")];

/// Deep-match a source value into a destination schema structure by recursively
/// searching for field names that match destination leaf properties.
fn deep_match_nested(src_val: &Value, dest_schema_json: &Value) -> Option<Value> {
    let record_props = dest_schema_json
        .pointer("/defs/main/record/properties")
        .and_then(|p| p.as_object())?;

    build_deep_matched_object(src_val, record_props)
}

/// Recursively build an output object matching the destination property structure.
fn build_deep_matched_object(
    src_val: &Value,
    dest_props: &serde_json::Map<String, Value>,
) -> Option<Value> {
    let mut output = serde_json::Map::new();
    let mut matched = 0usize;

    for (prop_name, prop_def) in dest_props {
        let type_str = prop_def.get("type").and_then(|t| t.as_str()).unwrap_or("");

        if type_str == "object" {
            if let Some(nested_props) = prop_def.get("properties").and_then(|p| p.as_object())
                && let Some(nested_val) = build_deep_matched_object(src_val, nested_props)
            {
                output.insert(prop_name.clone(), nested_val);
                matched += 1;
            }
        } else if let Some(found) = find_value_by_name(src_val, prop_name) {
            output.insert(prop_name.clone(), found.clone());
            matched += 1;
        }
    }

    if matched > 0 {
        Some(Value::Object(output))
    } else {
        None
    }
}

/// Recursively search a JSON value for a field with the given name.
fn find_value_by_name<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let obj = value.as_object()?;

    if let Some(v) = obj.get(name)
        && (!v.is_object() || v.get("$type").is_some())
    {
        return Some(v);
    }

    for &(from, to) in NAME_ALIASES {
        if name == from
            && let Some(v) = obj.get(to)
            && (!v.is_object() || v.get("$type").is_some())
        {
            return Some(v);
        }
    }

    for (_, child) in obj {
        if child.is_object()
            && let Some(found) = find_value_by_name(child, name)
        {
            return Some(found);
        }
    }

    None
}

/// Count leaf properties in a destination schema's record definition.
fn count_dest_schema_leaves(schema_json: &Value) -> usize {
    fn count_props(props: &serde_json::Map<String, Value>) -> usize {
        let mut count = 0;
        for (_, def) in props {
            let type_str = def.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if type_str == "object" {
                if let Some(nested) = def.get("properties").and_then(|p| p.as_object()) {
                    count += count_props(nested);
                }
            } else {
                count += 1;
            }
        }
        count
    }

    schema_json
        .pointer("/defs/main/record/properties")
        .and_then(|p| p.as_object())
        .map(count_props)
        .unwrap_or(0)
}

/// Count leaf (non-object) values in a JSON map, recursing into nested objects.
fn count_leaf_values(obj: &serde_json::Map<String, Value>) -> usize {
    let mut count = 0;
    for (_, v) in obj {
        if let Some(nested) = v.as_object() {
            count += count_leaf_values(nested);
        } else {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_transmogrify_json_direct_match() {
        let source_schema = json!({
            "lexicon": 1,
            "id": "com.example.source",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "lang": { "type": "string" }
                }
            }}}
        });
        let dest_schema = json!({
            "lexicon": 1,
            "id": "com.example.dest",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "title": { "type": "string" }
                }
            }}}
        });
        let record = json!({ "text": "hello", "lang": "en" });

        let result = transmogrify_json(&record, &source_schema, &dest_schema, None, None).unwrap();
        assert_eq!(result.record["text"], "hello");
        assert!(result.record.get("lang").is_none());
        assert!(result.quality > 0.0);
    }

    #[test]
    fn test_transmogrify_json_with_mappings() {
        let source_schema = json!({
            "lexicon": 1,
            "id": "com.example.source",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": { "body": { "type": "string" } }
            }}}
        });
        let dest_schema = json!({
            "lexicon": 1,
            "id": "com.example.dest",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }}}
        });
        let record = json!({ "body": "hello" });
        let mappings = TransmogrifyMappings {
            field_mappings: [("body".to_string(), "text".to_string())]
                .into_iter()
                .collect(),
            defaults: HashMap::new(),
        };

        let result =
            transmogrify_json(&record, &source_schema, &dest_schema, Some(&mappings), None)
                .unwrap();
        assert_eq!(result.record["text"], "hello");
    }

    #[test]
    fn test_transmogrify_json_with_defaults() {
        let source_schema = json!({
            "lexicon": 1,
            "id": "com.example.source",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": { "text": { "type": "string" } }
            }}}
        });
        let dest_schema = json!({
            "lexicon": 1,
            "id": "com.example.dest",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "lang": { "type": "string" }
                }
            }}}
        });
        let record = json!({ "text": "hello" });
        let mappings = TransmogrifyMappings {
            field_mappings: HashMap::new(),
            defaults: [("lang".to_string(), json!("en"))].into_iter().collect(),
        };

        let result =
            transmogrify_json(&record, &source_schema, &dest_schema, Some(&mappings), None)
                .unwrap();
        assert_eq!(result.record["text"], "hello");
        assert_eq!(result.record["lang"], "en");
    }

    #[test]
    fn test_transmogrify_json_no_dest_properties() {
        let source_schema = json!({ "lexicon": 1, "id": "a", "defs": {} });
        let dest_schema = json!({ "lexicon": 1, "id": "b", "defs": {} });
        let record = json!({ "text": "hello" });

        let err = transmogrify_json(&record, &source_schema, &dest_schema, None, None).unwrap_err();
        assert!(matches!(err, TransmogrifyError::NoMorphismFound));
    }

    #[test]
    fn test_transmogrify_json_record_not_object() {
        let source_schema = json!({
            "lexicon": 1, "id": "a",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object", "properties": { "x": { "type": "string" } }
            }}}
        });
        let dest_schema = source_schema.clone();
        let record = json!("not an object");

        let err = transmogrify_json(&record, &source_schema, &dest_schema, None, None).unwrap_err();
        assert!(matches!(err, TransmogrifyError::ParseRecord(_)));
    }

    #[test]
    fn test_extract_schema_refs() {
        let schema = json!({
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "embed": { "type": "ref", "ref": "com.example.embed" },
                            "local": { "type": "ref", "ref": "#localDef" }
                        }
                    }
                }
            }
        });
        let refs = extract_schema_refs(&schema);
        assert!(refs.contains("com.example.embed"));
        assert!(!refs.contains("#localDef"));
    }

    #[test]
    fn test_enrich_schema_with_refs() {
        let schema = json!({
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "properties": {
                            "embed": { "type": "ref", "ref": "com.example.embed" }
                        }
                    }
                }
            }
        });
        let mut resolved = HashMap::new();
        resolved.insert(
            "com.example.embed".to_string(),
            json!({
                "defs": {
                    "main": {
                        "type": "object",
                        "properties": { "url": { "type": "string" } }
                    }
                }
            }),
        );

        let enriched = enrich_schema_with_refs(&schema, &resolved);
        let embed_def = enriched
            .pointer("/defs/main/record/properties/embed")
            .unwrap();
        assert_eq!(embed_def["type"], "object");
    }

    #[test]
    fn test_transmogrify_shared_fields() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.profileA",
            "defs": { "main": { "type": "record", "key": "literal:self", "record": {
                "type": "object",
                "properties": {
                    "displayName": { "type": "string", "maxLength": 640 },
                    "description": { "type": "string", "maxLength": 2560 },
                    "uniqueToA": { "type": "boolean" }
                }
            }}}
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.profileB",
            "defs": { "main": { "type": "record", "key": "literal:self", "record": {
                "type": "object",
                "properties": {
                    "displayName": { "type": "string", "maxLength": 640 },
                    "description": { "type": "string", "maxLength": 2560 },
                    "uniqueToB": { "type": "string" }
                }
            }}}
        });
        let record = json!({
            "$type": "com.example.profileA",
            "displayName": "Alice",
            "description": "Hello world",
            "uniqueToA": true
        });
        let result = transmogrify(&from, &to, &record, None).unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("displayName").unwrap(), "Alice");
        assert_eq!(obj.get("description").unwrap(), "Hello world");
        assert!(obj.get("uniqueToA").is_none());
        assert!(obj.get("uniqueToB").is_none());
    }

    #[test]
    fn test_transmogrify_with_explicit_mappings() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.source",
            "defs": { "main": { "type": "record", "key": "literal:self", "record": {
                "type": "object",
                "properties": {
                    "title": { "type": "string" },
                    "body": { "type": "string" }
                }
            }}}
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.dest",
            "defs": { "main": { "type": "record", "key": "literal:self", "record": {
                "type": "object",
                "properties": {
                    "displayName": { "type": "string" },
                    "description": { "type": "string" }
                }
            }}}
        });
        let record = json!({ "title": "My Title", "body": "Some content" });
        let mappings = TransmogrifyMappings {
            field_mappings: HashMap::from([
                ("title".to_string(), "displayName".to_string()),
                ("body".to_string(), "description".to_string()),
            ]),
            ..Default::default()
        };
        let result = transmogrify(&from, &to, &record, Some(&mappings)).unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("displayName").unwrap(), "My Title");
        assert_eq!(obj.get("description").unwrap(), "Some content");
        assert!((result.quality - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_transmogrify_no_shared_fields() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.schemaA",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "alpha": { "type": "string" },
                    "beta": { "type": "string" }
                }
            }}}
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.schemaB",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "gamma": { "type": "boolean" },
                    "delta": { "type": "integer" }
                }
            }}}
        });
        let record = json!({ "alpha": "val", "beta": "val2" });
        let result = transmogrify(&from, &to, &record, None);
        // Either panproto finds a structural mapping or strategy 3 fails
        if let Ok(r) = &result {
            assert!(r.quality > 0.0);
        }
    }

    #[test]
    fn test_transmogrify_dotted_path_writes() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.card",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "content": { "type": "object", "properties": {
                        "metadata": { "type": "object", "properties": {
                            "title": { "type": "string" },
                            "description": { "type": "string" }
                        }}
                    }},
                    "createdAt": { "type": "string", "format": "datetime" }
                }
            }}}
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.post",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "embed": { "type": "object", "properties": {
                        "external": { "type": "object", "properties": {
                            "uri": { "type": "string" },
                            "title": { "type": "string" },
                            "description": { "type": "string" }
                        }}
                    }},
                    "createdAt": { "type": "string", "format": "datetime" }
                }
            }}}
        });
        let record = json!({
            "url": "https://example.com",
            "content": { "metadata": { "title": "Example", "description": "An example page" } },
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let mappings = TransmogrifyMappings {
            field_mappings: HashMap::from([
                ("url".to_string(), "embed.external.uri".to_string()),
                (
                    "content.metadata.title".to_string(),
                    "embed.external.title".to_string(),
                ),
                (
                    "content.metadata.description".to_string(),
                    "embed.external.description".to_string(),
                ),
            ]),
            defaults: HashMap::from([
                ("text".to_string(), json!("")),
                ("embed.$type".to_string(), json!("app.bsky.embed.external")),
            ]),
        };
        let result = transmogrify(&from, &to, &record, Some(&mappings)).unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("text").unwrap(), "");
        assert_eq!(obj.get("createdAt").unwrap(), "2024-01-01T00:00:00.000Z");

        let embed = obj.get("embed").unwrap().as_object().unwrap();
        assert_eq!(embed.get("$type").unwrap(), "app.bsky.embed.external");

        let external = embed.get("external").unwrap().as_object().unwrap();
        assert_eq!(external.get("uri").unwrap(), "https://example.com");
        assert_eq!(external.get("title").unwrap(), "Example");
        assert_eq!(external.get("description").unwrap(), "An example page");
    }

    #[test]
    fn test_transmogrify_recursive_nested_types() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.card",
            "defs": {
                "main": { "type": "record", "key": "tid", "record": {
                    "type": "object",
                    "properties": {
                        "content": { "type": "union", "refs": ["#urlContent"] },
                        "createdAt": { "type": "string", "format": "datetime" }
                    }
                }},
                "urlContent": { "type": "object", "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }}
            }
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.post",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "embed": { "type": "union", "refs": ["com.example.embed.link"] },
                    "createdAt": { "type": "string", "format": "datetime" }
                }
            }}}
        });
        let embed_schema = json!({
            "lexicon": 1,
            "id": "com.example.embed.link",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }
            }}}
        });
        let resolved_refs = HashMap::from([("com.example.embed.link".to_string(), embed_schema)]);
        let record = json!({
            "content": {
                "$type": "com.example.card#urlContent",
                "url": "https://example.com",
                "title": "Example Site",
                "description": "An example"
            },
            "createdAt": "2024-01-01T00:00:00.000Z"
        });

        let result =
            transmogrify_with_refs(&from, &to, &record, None, Some(&resolved_refs)).unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("createdAt").unwrap(), "2024-01-01T00:00:00.000Z");

        let embed = obj.get("embed").unwrap().as_object().unwrap();
        assert_eq!(embed.get("$type").unwrap(), "com.example.embed.link");
        assert_eq!(embed.get("url").unwrap(), "https://example.com");
        assert_eq!(embed.get("title").unwrap(), "Example Site");
        assert_eq!(embed.get("description").unwrap(), "An example");
    }

    #[test]
    fn test_transmogrify_recursive_with_ref_indirection() {
        let from = json!({
            "lexicon": 1,
            "id": "network.cosmik.card",
            "defs": {
                "main": { "type": "record", "key": "tid", "record": {
                    "type": "object",
                    "properties": {
                        "type": { "type": "string" },
                        "content": { "type": "union", "refs": ["#urlContent"] },
                        "createdAt": { "type": "string", "format": "datetime" }
                    }
                }},
                "urlContent": { "type": "object", "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "metadata": { "type": "ref", "ref": "#urlMetadata" }
                }},
                "urlMetadata": { "type": "object", "properties": {
                    "title": { "type": "string" },
                    "description": { "type": "string" },
                    "imageUrl": { "type": "string" },
                    "siteName": { "type": "string" }
                }}
            }
        });
        let to = json!({
            "lexicon": 1,
            "id": "app.bsky.feed.post",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "embed": { "type": "union", "refs": ["app.bsky.embed.external"] },
                    "createdAt": { "type": "string", "format": "datetime" }
                }
            }}}
        });
        let embed_schema = json!({
            "lexicon": 1,
            "id": "app.bsky.embed.external",
            "defs": {
                "main": { "type": "object", "required": ["external"], "properties": {
                    "external": { "type": "ref", "ref": "#external" }
                }},
                "external": { "type": "object", "required": ["uri", "title", "description"], "properties": {
                    "uri": { "type": "string", "format": "uri" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }}
            }
        });
        let resolved_refs = HashMap::from([("app.bsky.embed.external".to_string(), embed_schema)]);
        let record = json!({
            "type": "URL",
            "$type": "network.cosmik.card",
            "content": {
                "$type": "network.cosmik.card#urlContent",
                "url": "https://zipcodefirst.com/",
                "metadata": {
                    "$type": "network.cosmik.card#urlMetadata",
                    "title": "Put the ZIP code first.",
                    "description": "A ZIP code is 5 characters.",
                    "imageUrl": "https://zipcodefirst.com/og.png",
                    "siteName": "zipcodefirst.com"
                }
            },
            "createdAt": "2026-03-11T18:41:46.651Z"
        });
        let mappings = TransmogrifyMappings {
            field_mappings: HashMap::from([(
                "content.metadata.description".to_string(),
                "text".to_string(),
            )]),
            ..Default::default()
        };

        let result =
            transmogrify_with_refs(&from, &to, &record, Some(&mappings), Some(&resolved_refs))
                .unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("text").unwrap(), "A ZIP code is 5 characters.");
        assert_eq!(obj.get("createdAt").unwrap(), "2026-03-11T18:41:46.651Z");

        let embed = obj.get("embed").unwrap().as_object().unwrap();
        assert_eq!(embed.get("$type").unwrap(), "app.bsky.embed.external");
        let external = embed.get("external").unwrap().as_object().unwrap();
        assert_eq!(external.get("uri").unwrap(), "https://zipcodefirst.com/");
        assert_eq!(external.get("title").unwrap(), "Put the ZIP code first.");
        assert_eq!(
            external.get("description").unwrap(),
            "A ZIP code is 5 characters."
        );
        assert!(external.get("imageUrl").is_none());
        assert!(external.get("siteName").is_none());
    }

    #[test]
    fn test_transmogrify_no_spurious_deep_match() {
        let from = json!({
            "lexicon": 1,
            "id": "com.example.card",
            "defs": {
                "main": { "type": "record", "key": "tid", "record": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string" },
                        "content": { "type": "union", "refs": ["#urlContent"] }
                    }
                }},
                "urlContent": { "type": "object", "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "title": { "type": "string" }
                }}
            }
        });
        let to = json!({
            "lexicon": 1,
            "id": "com.example.post",
            "defs": {
                "main": { "type": "record", "key": "tid", "record": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string" },
                        "reply": { "type": "ref", "ref": "#replyRef" }
                    }
                }},
                "replyRef": { "type": "object", "properties": {
                    "root": { "type": "ref", "ref": "#postRef" },
                    "parent": { "type": "ref", "ref": "#postRef" }
                }},
                "postRef": { "type": "object", "properties": {
                    "uri": { "type": "string", "format": "at-uri" },
                    "cid": { "type": "string", "format": "cid" }
                }}
            }
        });
        let resolved_refs = HashMap::new();
        let record = json!({
            "text": "Hello",
            "content": {
                "$type": "com.example.card#urlContent",
                "url": "https://example.com",
                "title": "Example"
            }
        });

        let result =
            transmogrify_with_refs(&from, &to, &record, None, Some(&resolved_refs)).unwrap();
        let obj = result.record.as_object().unwrap();
        assert_eq!(obj.get("text").unwrap(), "Hello");
        assert!(
            obj.get("reply").is_none(),
            "reply should not be spuriously populated from URL content"
        );
    }

    #[test]
    fn test_enrich_inlines_union_variants_for_nested_resolution() {
        let dest_schema = json!({
            "lexicon": 1,
            "id": "com.example.post",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "embed": { "type": "union", "refs": ["com.example.embed.link"] }
                }
            }}}
        });
        let embed_schema = json!({
            "lexicon": 1,
            "id": "com.example.embed.link",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "uri": { "type": "string", "format": "uri" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }
            }}}
        });

        let mut resolved = HashMap::new();
        resolved.insert("com.example.embed.link".to_string(), embed_schema);

        let enriched = enrich_schema_with_refs(&dest_schema, &resolved);
        assert!(
            enriched.pointer("/defs/com_example_embed_link").is_some(),
            "enriched schema should contain inlined union variant def"
        );

        let empty_refs = HashMap::new();
        let resolved = resolve_nested_type_schema("com.example.embed.link", &enriched, &empty_refs);
        assert!(resolved.is_some());

        let resolved = resolved.unwrap();
        let props = resolved.pointer("/defs/main/record/properties").unwrap();
        assert!(props.get("uri").is_some());
        assert!(props.get("title").is_some());
        assert!(props.get("description").is_some());
    }

    #[test]
    fn test_transmogrify_union_nested_via_enriched_schema() {
        let source_schema = json!({
            "lexicon": 1,
            "id": "com.example.card",
            "defs": {
                "main": { "type": "record", "key": "tid", "record": {
                    "type": "object",
                    "properties": {
                        "content": { "type": "ref", "ref": "#urlContent" },
                        "createdAt": { "type": "string", "format": "datetime" }
                    }
                }},
                "urlContent": { "type": "object", "properties": {
                    "url": { "type": "string", "format": "uri" },
                    "metadata": { "type": "ref", "ref": "#urlMetadata" }
                }},
                "urlMetadata": { "type": "object", "properties": {
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }}
            }
        });
        let dest_schema = json!({
            "lexicon": 1,
            "id": "com.example.post",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "embed": { "type": "union", "refs": ["com.example.embed.link"] },
                    "createdAt": { "type": "string", "format": "datetime" }
                }
            }}}
        });
        let embed_schema = json!({
            "lexicon": 1,
            "id": "com.example.embed.link",
            "defs": { "main": { "type": "record", "key": "tid", "record": {
                "type": "object",
                "properties": {
                    "uri": { "type": "string", "format": "uri" },
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }
            }}}
        });

        let record = json!({
            "$type": "com.example.card",
            "content": {
                "$type": "com.example.card#urlContent",
                "url": "https://example.com/",
                "metadata": {
                    "$type": "com.example.card#urlMetadata",
                    "title": "Example Title",
                    "description": "Example description text"
                }
            },
            "createdAt": "2026-01-01T00:00:00.000Z"
        });

        let mut resolved_schemas = HashMap::new();
        resolved_schemas.insert("com.example.embed.link".to_string(), embed_schema);

        let enriched_source = enrich_schema_with_refs(&source_schema, &resolved_schemas);
        let enriched_dest = enrich_schema_with_refs(&dest_schema, &resolved_schemas);

        let empty_refs = HashMap::new();
        let result = transmogrify_with_refs(
            &enriched_source,
            &enriched_dest,
            &record,
            None,
            Some(&empty_refs),
        )
        .unwrap();

        let obj = result.record.as_object().unwrap();
        assert!(obj.get("createdAt").is_some());

        let embed = obj.get("embed").expect("embed should be present");
        let embed_obj = embed.as_object().unwrap();

        let has_uri = embed_obj.get("uri").is_some()
            || embed_obj
                .values()
                .filter_map(|v| v.as_object())
                .any(|nested| nested.get("uri").is_some());
        assert!(has_uri, "embed should contain uri (from url alias)");

        let has_title = embed_obj.get("title").is_some()
            || embed_obj
                .values()
                .filter_map(|v| v.as_object())
                .any(|nested| nested.get("title").is_some());
        assert!(has_title, "embed should contain title from source metadata");
    }

    #[test]
    fn test_transmogrify_explicit_mappings_with_auto_nested() {
        let from = serde_json::json!({
            "lexicon": 1,
            "id": "network.cosmik.card",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "content": {
                                "type": "union",
                                "refs": ["#urlContent"]
                            },
                            "createdAt": { "type": "string", "format": "datetime" }
                        }
                    }
                },
                "urlContent": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "format": "uri" },
                        "metadata": { "type": "ref", "ref": "#urlMetadata" }
                    }
                },
                "urlMetadata": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" },
                        "description": { "type": "string" },
                        "imageUrl": { "type": "string" },
                        "siteName": { "type": "string" }
                    }
                }
            }
        });

        let to = serde_json::json!({
            "lexicon": 1,
            "id": "app.bsky.feed.post",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {
                            "text": { "type": "string" },
                            "embed": {
                                "type": "union",
                                "refs": ["app.bsky.embed.external"]
                            },
                            "createdAt": { "type": "string", "format": "datetime" }
                        }
                    }
                }
            }
        });

        let embed_schema = serde_json::json!({
            "lexicon": 1,
            "id": "app.bsky.embed.external",
            "defs": {
                "main": {
                    "type": "object",
                    "required": ["external"],
                    "properties": {
                        "external": { "type": "ref", "ref": "#external" }
                    }
                },
                "external": {
                    "type": "object",
                    "required": ["uri", "title", "description"],
                    "properties": {
                        "uri": { "type": "string", "format": "uri" },
                        "title": { "type": "string" },
                        "description": { "type": "string" }
                    }
                }
            }
        });

        let resolved_refs = HashMap::from([("app.bsky.embed.external".to_string(), embed_schema)]);

        let record = serde_json::json!({
            "type": "URL",
            "$type": "network.cosmik.card",
            "content": {
                "$type": "network.cosmik.card#urlContent",
                "url": "https://zipcodefirst.com/",
                "metadata": {
                    "$type": "network.cosmik.card#urlMetadata",
                    "title": "Put the ZIP code first.",
                    "description": "A ZIP code is 5 characters.",
                    "imageUrl": "https://zipcodefirst.com/og.png",
                    "siteName": "zipcodefirst.com"
                }
            },
            "createdAt": "2026-03-11T18:41:46.651Z"
        });

        let mappings = TransmogrifyMappings {
            field_mappings: HashMap::from([
                (
                    "content.metadata.description".to_string(),
                    "text".to_string(),
                ),
                ("content.url".to_string(), "embed.external.uri".to_string()),
            ]),
            ..Default::default()
        };

        let result =
            transmogrify_with_refs(&from, &to, &record, Some(&mappings), Some(&resolved_refs))
                .unwrap();
        let obj = result.record.as_object().unwrap();

        assert_eq!(obj.get("text").unwrap(), "A ZIP code is 5 characters.");
        assert_eq!(obj.get("createdAt").unwrap(), "2026-03-11T18:41:46.651Z");
        assert!(
            obj.contains_key("embed"),
            "embed field should be present from auto-mapping"
        );

        let embed = obj.get("embed").unwrap().as_object().unwrap();
        assert_eq!(embed.get("$type").unwrap(), "app.bsky.embed.external");

        let external = embed.get("external").unwrap().as_object().unwrap();
        assert_eq!(external.get("uri").unwrap(), "https://zipcodefirst.com/");
        assert_eq!(external.get("title").unwrap(), "Put the ZIP code first.");
        assert_eq!(
            external.get("description").unwrap(),
            "A ZIP code is 5 characters."
        );
        assert!(external.get("imageUrl").is_none());
        assert!(external.get("siteName").is_none());
    }

    #[test]
    fn test_mappings_is_empty() {
        let empty = TransmogrifyMappings::default();
        assert!(empty.is_empty());
        assert!(empty.field_mappings_ref().is_none());

        let with_mappings = TransmogrifyMappings {
            field_mappings: HashMap::from([("a".to_string(), "b".to_string())]),
            ..Default::default()
        };
        assert!(!with_mappings.is_empty());
        assert!(with_mappings.field_mappings_ref().is_some());
    }
}
