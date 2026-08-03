//! JSON to DataValue parsing

use indexmap::IndexMap;
use serde_json::Value as JsonValue;

use crate::validation::data_errors::DataValidationError;
use crate::validation::data_types::{Blob, Bytes, CIDLink, DataValue};
use crate::validation::flags::ValidateFlags;

/// Parse a top-level record document into a [`DataValue`].
///
/// Identical to [`parse_json`] except that the document itself must be an
/// object. The distinction is not pedantic: the data model permits any value in
/// a *field*, so `"blah"` is a well-formed data-model value — it is only
/// ill-formed as a *record*. [`parse_json`] is called recursively for every
/// nested field and so cannot make that demand; only a record-level entry point
/// can, which is why the rule lives here rather than there.
pub fn parse_record_json(
    value: &JsonValue,
    flags: ValidateFlags,
) -> Result<DataValue, DataValidationError> {
    if !value.is_object() {
        return Err(DataValidationError::DataModelInvalid {
            reason: format!(
                "a record must be an object, got {}",
                match value {
                    JsonValue::Null => "null",
                    JsonValue::Bool(_) => "boolean",
                    JsonValue::Number(_) => "number",
                    JsonValue::String(_) => "string",
                    JsonValue::Array(_) => "array",
                    JsonValue::Object(_) => unreachable!("guarded above"),
                }
            ),
        });
    }
    parse_json(value, flags)
}

/// Parse a JSON value into a DataValue
pub fn parse_json(
    value: &JsonValue,
    flags: ValidateFlags,
) -> Result<DataValue, DataValidationError> {
    match value {
        JsonValue::Null => Ok(DataValue::Null),
        JsonValue::Bool(b) => Ok(DataValue::Boolean(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(DataValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                if f.is_nan() || f.is_infinite() {
                    return Err(DataValidationError::DataModelInvalid {
                        reason: "NaN and Infinity are not valid in ATProtocol data model"
                            .to_string(),
                    });
                }
                Ok(DataValue::Float(f))
            } else {
                Err(DataValidationError::DataModelInvalid {
                    reason: "Invalid number value".to_string(),
                })
            }
        }
        JsonValue::String(s) => Ok(DataValue::String(s.clone())),
        JsonValue::Array(arr) => {
            let values: Result<Vec<DataValue>, DataValidationError> =
                arr.iter().map(|v| parse_json(v, flags)).collect();
            Ok(DataValue::Array(values?))
        }
        JsonValue::Object(obj) => parse_object(obj, flags),
    }
}

fn parse_object(
    obj: &serde_json::Map<String, JsonValue>,
    flags: ValidateFlags,
) -> Result<DataValue, DataValidationError> {
    if let Some(bytes_val) = obj.get("$bytes") {
        if obj.len() != 1 {
            return Err(DataValidationError::DataModelInvalid {
                reason: "$bytes object must only have $bytes field".to_string(),
            });
        }
        let bytes_str =
            bytes_val
                .as_str()
                .ok_or_else(|| DataValidationError::DataModelInvalid {
                    reason: "$bytes value must be a string".to_string(),
                })?;
        return Ok(DataValue::Bytes(Bytes::new(bytes_str)));
    }
    if let Some(link_val) = obj.get("$link") {
        if obj.len() != 1 {
            return Err(DataValidationError::DataModelInvalid {
                reason: "$link object must only have $link field".to_string(),
            });
        }
        let link_str = link_val
            .as_str()
            .ok_or_else(|| DataValidationError::DataModelInvalid {
                reason: "$link value must be a string".to_string(),
            })?;
        return Ok(DataValue::Link(CIDLink::new(link_str)));
    }
    if let Some(type_val) = obj.get("$type") {
        let type_str = type_val
            .as_str()
            .ok_or_else(|| DataValidationError::DataModelInvalid {
                reason: "$type value must be a string".to_string(),
            })?;
        // An empty `$type` is not merely an unknown type: `$type` names the
        // schema a consumer is meant to dispatch on, and the empty string names
        // nothing. Accepting it produced an object that claimed to be typed and
        // could never be resolved, which is worse than an absent `$type` —
        // absence is at least detectable as such.
        if type_str.is_empty() {
            return Err(DataValidationError::DataModelInvalid {
                reason: "$type value must not be empty".to_string(),
            });
        }
        if type_str == "blob" {
            return parse_blob(obj, flags);
        }
    }
    let mut result = IndexMap::new();
    for (key, value) in obj {
        if key.starts_with('$') && key != "$type" {
            return Err(DataValidationError::DataModelInvalid {
                reason: format!(
                    "Unknown $ field '{}' - only $type, $link, and $bytes are allowed",
                    key
                ),
            });
        }
        result.insert(key.clone(), parse_json(value, flags)?);
    }
    Ok(DataValue::Object(result))
}

fn parse_blob(
    obj: &serde_json::Map<String, JsonValue>,
    flags: ValidateFlags,
) -> Result<DataValue, DataValidationError> {
    let mime_type = obj
        .get("mimeType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DataValidationError::DataModelInvalid {
            reason: "blob must have mimeType field".to_string(),
        })?
        .to_string();
    let size = obj.get("size").and_then(|v| v.as_u64()).ok_or_else(|| {
        DataValidationError::DataModelInvalid {
            reason: "blob must have size field".to_string(),
        }
    })?;
    let ref_link = if let Some(ref_obj) = obj.get("ref") {
        let ref_map = ref_obj
            .as_object()
            .ok_or_else(|| DataValidationError::DataModelInvalid {
                reason: "blob ref must be an object".to_string(),
            })?;
        let link = ref_map
            .get("$link")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DataValidationError::DataModelInvalid {
                reason: "blob ref must have $link field".to_string(),
            })?;
        Some(CIDLink::new(link))
    } else {
        None
    };
    let cid = obj.get("cid").and_then(|v| v.as_str()).map(String::from);
    if ref_link.is_none() && cid.is_none() {
        return Err(DataValidationError::DataModelInvalid {
            reason: "blob must have either ref or cid field".to_string(),
        });
    }
    if cid.is_some() && ref_link.is_none() && !flags.contains(ValidateFlags::ALLOW_LEGACY_BLOB) {
        return Err(DataValidationError::LegacyBlobNotAllowed);
    }
    Ok(DataValue::Blob(Blob {
        type_marker: "blob".to_string(),
        ref_link,
        mime_type,
        size,
        cid,
    }))
}

/// Convert a DataValue back to JSON
pub fn to_json(value: &DataValue) -> JsonValue {
    match value {
        DataValue::Null => JsonValue::Null,
        DataValue::Boolean(b) => JsonValue::Bool(*b),
        DataValue::Integer(i) => JsonValue::Number((*i).into()),
        DataValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        DataValue::String(s) => JsonValue::String(s.clone()),
        DataValue::Bytes(b) => {
            let mut obj = serde_json::Map::new();
            obj.insert("$bytes".to_string(), JsonValue::String(b.bytes.clone()));
            JsonValue::Object(obj)
        }
        DataValue::Link(l) => {
            let mut obj = serde_json::Map::new();
            obj.insert("$link".to_string(), JsonValue::String(l.link.clone()));
            JsonValue::Object(obj)
        }
        DataValue::Blob(b) => {
            let mut obj = serde_json::Map::new();
            obj.insert("$type".to_string(), JsonValue::String("blob".to_string()));
            obj.insert(
                "mimeType".to_string(),
                JsonValue::String(b.mime_type.clone()),
            );
            obj.insert("size".to_string(), JsonValue::Number(b.size.into()));
            if let Some(ref link) = b.ref_link {
                let mut ref_obj = serde_json::Map::new();
                ref_obj.insert("$link".to_string(), JsonValue::String(link.link.clone()));
                obj.insert("ref".to_string(), JsonValue::Object(ref_obj));
            }
            if let Some(ref cid) = b.cid {
                obj.insert("cid".to_string(), JsonValue::String(cid.clone()));
            }
            JsonValue::Object(obj)
        }
        DataValue::Array(arr) => JsonValue::Array(arr.iter().map(to_json).collect()),
        DataValue::Object(map) => {
            let obj: serde_json::Map<String, JsonValue> =
                map.iter().map(|(k, v)| (k.clone(), to_json(v))).collect();
            JsonValue::Object(obj)
        }
    }
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitives() {
        let flags = ValidateFlags::empty();
        assert!(matches!(
            parse_json(&JsonValue::Null, flags).unwrap(),
            DataValue::Null
        ));
        assert!(matches!(
            parse_json(&JsonValue::Bool(true), flags).unwrap(),
            DataValue::Boolean(true)
        ));
        assert!(matches!(
            parse_json(&serde_json::json!(42), flags).unwrap(),
            DataValue::Integer(42)
        ));
        assert!(matches!(
            parse_json(&serde_json::json!(3.14), flags).unwrap(),
            DataValue::Float(_)
        ));
        assert!(matches!(
            parse_json(&serde_json::json!("hello"), flags).unwrap(),
            DataValue::String(_)
        ));
    }

    #[test]
    fn test_parse_array() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!([1, 2, 3]);
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_parse_object() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({"name": "test", "count": 42});
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_object());
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("name").unwrap().as_string(), Some("test"));
        assert_eq!(obj.get("count").unwrap().as_integer(), Some(42));
    }

    #[test]
    fn test_parse_bytes() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({"$bytes": "SGVsbG8="});
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_bytes());
        assert_eq!(result.as_bytes().unwrap().bytes, "SGVsbG8=");
    }

    #[test]
    fn test_parse_link() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({"$link": "bafytest"});
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_link());
        assert_eq!(result.as_link().unwrap().link, "bafytest");
    }

    #[test]
    fn test_parse_modern_blob() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({
            "$type": "blob",
            "ref": {"$link": "bafytest"},
            "mimeType": "image/png",
            "size": 1024
        });
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_blob());
        let blob = result.as_blob().unwrap();
        assert_eq!(blob.mime_type, "image/png");
        assert_eq!(blob.size, 1024);
        assert!(blob.is_modern());
    }

    #[test]
    fn test_parse_legacy_blob_allowed() {
        let flags = ValidateFlags::ALLOW_LEGACY_BLOB;
        let json = serde_json::json!({
            "$type": "blob",
            "cid": "bafytest",
            "mimeType": "image/png",
            "size": 1024
        });
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_blob());
        assert!(result.as_blob().unwrap().is_legacy());
    }

    #[test]
    fn test_parse_legacy_blob_not_allowed() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({
            "$type": "blob",
            "cid": "bafytest",
            "mimeType": "image/png",
            "size": 1024
        });
        let result = parse_json(&json, flags);
        assert!(matches!(
            result,
            Err(DataValidationError::LegacyBlobNotAllowed)
        ));
    }

    #[test]
    fn test_parse_object_with_type() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world"
        });
        let result = parse_json(&json, flags).unwrap();
        assert!(result.is_object());
        assert_eq!(result.get_type(), Some("app.bsky.feed.post"));
    }

    #[test]
    fn test_invalid_dollar_field() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({"$unknown": "value"});
        let result = parse_json(&json, flags);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        let flags = ValidateFlags::empty();
        let json = serde_json::json!({
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": true,
            "null": null,
            "array": [1, 2, 3],
            "nested": {"a": 1}
        });
        let data = parse_json(&json, flags).unwrap();
        let back = to_json(&data);
        assert_eq!(json, back);
    }
}
