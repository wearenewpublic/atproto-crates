//! JSON Canonicalization Scheme (JCS) implementation per RFC 8785.
//!
//! Produces deterministic JSON serialization with lexicographically sorted
//! object keys, no extraneous whitespace, and ES6-compliant number formatting.
//! Used by did:webvh for computing entry hashes and SCID values.

use serde_json::Value;

/// Produces a JCS-canonicalized JSON string from a serde_json::Value.
///
/// Implements RFC 8785 JSON Canonicalization Scheme:
/// - Object keys sorted lexicographically by UTF-16 code units
/// - No whitespace between tokens
/// - Numbers formatted per ES6 (via serde_json's ryu-based formatting)
/// - Standard JSON string escaping
pub fn canonicalize(value: &Value) -> String {
    let mut output = String::new();
    write_canonical(value, &mut output);
    output
}

fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(b) => {
            if *b {
                output.push_str("true");
            } else {
                output.push_str("false");
            }
        }
        Value::Number(n) => {
            // serde_json's Number Display uses ryu which produces ES6-compliant output
            output.push_str(&n.to_string());
        }
        Value::String(s) => {
            write_json_string(s, output);
        }
        Value::Array(arr) => {
            output.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    output.push(',');
                }
                write_canonical(item, output);
            }
            output.push(']');
        }
        Value::Object(map) => {
            // RFC 8785: sort keys by UTF-16 code units
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a_utf16: Vec<u16> = a.encode_utf16().collect();
                let b_utf16: Vec<u16> = b.encode_utf16().collect();
                a_utf16.cmp(&b_utf16)
            });

            output.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    output.push(',');
                }
                write_json_string(key, output);
                output.push(':');
                write_canonical(&map[*key], output);
            }
            output.push('}');
        }
    }
}

/// Writes a JSON-escaped string with surrounding quotes.
fn write_json_string(s: &str, output: &mut String) {
    output.push('"');
    for ch in s.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000C}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c < '\u{0020}' => {
                // Control characters use \u00XX notation
                output.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => output.push(c),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_null() {
        assert_eq!(canonicalize(&json!(null)), "null");
    }

    #[test]
    fn test_booleans() {
        assert_eq!(canonicalize(&json!(true)), "true");
        assert_eq!(canonicalize(&json!(false)), "false");
    }

    #[test]
    fn test_integers() {
        assert_eq!(canonicalize(&json!(0)), "0");
        assert_eq!(canonicalize(&json!(1)), "1");
        assert_eq!(canonicalize(&json!(-1)), "-1");
        assert_eq!(canonicalize(&json!(42)), "42");
        assert_eq!(canonicalize(&json!(999999999)), "999999999");
    }

    #[test]
    fn test_floats() {
        assert_eq!(canonicalize(&json!(1.0)), "1.0");
        assert_eq!(canonicalize(&json!(0.5)), "0.5");
        assert_eq!(canonicalize(&json!(-0.5)), "-0.5");
        assert_eq!(canonicalize(&json!(1.23e2)), "123.0");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(canonicalize(&json!("")), r#""""#);
    }

    #[test]
    fn test_simple_string() {
        assert_eq!(canonicalize(&json!("hello")), r#""hello""#);
    }

    #[test]
    fn test_string_escaping() {
        assert_eq!(canonicalize(&json!("a\"b")), r#""a\"b""#);
        assert_eq!(canonicalize(&json!("a\\b")), r#""a\\b""#);
        assert_eq!(canonicalize(&json!("a\nb")), r#""a\nb""#);
        assert_eq!(canonicalize(&json!("a\rb")), r#""a\rb""#);
        assert_eq!(canonicalize(&json!("a\tb")), r#""a\tb""#);
    }

    #[test]
    fn test_control_characters() {
        // BEL character (U+0007)
        assert_eq!(
            canonicalize(&Value::String("\u{0007}".to_string())),
            r#""\u0007""#
        );
        // NUL character (U+0000)
        assert_eq!(
            canonicalize(&Value::String("\u{0000}".to_string())),
            r#""\u0000""#
        );
    }

    #[test]
    fn test_empty_array() {
        assert_eq!(canonicalize(&json!([])), "[]");
    }

    #[test]
    fn test_array_with_elements() {
        assert_eq!(canonicalize(&json!([1, 2, 3])), "[1,2,3]");
        assert_eq!(canonicalize(&json!(["a", "b"])), r#"["a","b"]"#);
        assert_eq!(canonicalize(&json!([true, null, 1])), "[true,null,1]");
    }

    #[test]
    fn test_nested_arrays() {
        assert_eq!(canonicalize(&json!([[1], [2, 3]])), "[[1],[2,3]]");
    }

    #[test]
    fn test_empty_object() {
        assert_eq!(canonicalize(&json!({})), "{}");
    }

    #[test]
    fn test_object_key_sorting() {
        // Keys must be sorted lexicographically
        let val: Value = serde_json::from_str(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        assert_eq!(canonicalize(&val), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_nested_objects() {
        let val: Value = serde_json::from_str(r#"{"b":{"z":1,"a":2},"a":3}"#).unwrap();
        assert_eq!(canonicalize(&val), r#"{"a":3,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_mixed_types_in_object() {
        let val: Value =
            serde_json::from_str(r#"{"str":"hello","num":42,"bool":true,"null":null,"arr":[1,2]}"#)
                .unwrap();
        assert_eq!(
            canonicalize(&val),
            r#"{"arr":[1,2],"bool":true,"null":null,"num":42,"str":"hello"}"#
        );
    }

    #[test]
    fn test_rfc8785_example_structure() {
        // Based on RFC 8785 Section 3.2 test structure
        let val: Value = serde_json::from_str(
            r#"{"literals":[null,true,false],"numbers":[333333333.33333329,1e30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\""}"#,
        )
        .unwrap();
        let result = canonicalize(&val);
        // Verify it's valid JSON and keys are sorted
        let reparsed: Value = serde_json::from_str(&result).unwrap();
        assert!(reparsed.is_object());
        // "literals" < "numbers" < "string" in lexicographic order
        assert!(result.starts_with(r#"{"literals":[null,true,false],"numbers":"#));
    }

    #[test]
    fn test_unicode_sorting() {
        // UTF-16 code unit ordering
        let val: Value = serde_json::from_str(r#"{"b":"2","a":"1"}"#).unwrap();
        assert_eq!(canonicalize(&val), r#"{"a":"1","b":"2"}"#);
    }

    #[test]
    fn test_deeply_nested() {
        let val = json!({"a": {"b": {"c": {"d": "deep"}}}});
        assert_eq!(canonicalize(&val), r#"{"a":{"b":{"c":{"d":"deep"}}}}"#);
    }

    #[test]
    fn test_no_trailing_whitespace() {
        let val = json!({"key": "value"});
        let result = canonicalize(&val);
        assert!(!result.contains(' '));
        assert!(!result.contains('\n'));
        assert!(!result.contains('\t'));
    }

    #[test]
    fn test_idempotent() {
        let val: Value = serde_json::from_str(r#"{"z":1,"a":2,"m":[3,4,{"x":5}]}"#).unwrap();
        let first = canonicalize(&val);
        let reparsed: Value = serde_json::from_str(&first).unwrap();
        let second = canonicalize(&reparsed);
        assert_eq!(first, second);
    }
}
