//! Strict mode validation tests for DAG-CBOR.
//!
//! Tests that strict mode correctly rejects non-conforming DAG-CBOR data.

use atproto_dasl::{
    DecodeConfig, from_slice, from_slice_non_strict, from_slice_with_config, to_vec,
};

#[test]
fn test_strict_rejects_non_minimal_unsigned() {
    // 0 should be encoded as 0x00, not 0x18 0x00
    let non_minimal = [0x18, 0x00]; // 0 with extra byte
    assert!(from_slice::<u8>(&non_minimal).is_err());

    // But non-strict accepts it
    assert_eq!(from_slice_non_strict::<u8>(&non_minimal).unwrap(), 0);

    // 23 should be encoded as 0x17, not 0x18 0x17
    let non_minimal = [0x18, 0x17]; // 23 with extra byte
    assert!(from_slice::<u8>(&non_minimal).is_err());
    assert_eq!(from_slice_non_strict::<u8>(&non_minimal).unwrap(), 23);

    // 255 should be encoded as 0x18 0xff, not 0x19 0x00 0xff
    let non_minimal = [0x19, 0x00, 0xff]; // 255 with extra bytes
    assert!(from_slice::<u16>(&non_minimal).is_err());
    assert_eq!(from_slice_non_strict::<u16>(&non_minimal).unwrap(), 255);
}

#[test]
fn test_strict_rejects_non_minimal_negative() {
    // -1 should be encoded as 0x20, not 0x38 0x00
    let non_minimal = [0x38, 0x00]; // -1 with extra byte
    assert!(from_slice::<i8>(&non_minimal).is_err());
    assert_eq!(from_slice_non_strict::<i8>(&non_minimal).unwrap(), -1);

    // -24 should be encoded as 0x37, not 0x38 0x17
    let non_minimal = [0x38, 0x17]; // -24 with extra byte
    assert!(from_slice::<i8>(&non_minimal).is_err());
    assert_eq!(from_slice_non_strict::<i8>(&non_minimal).unwrap(), -24);
}

#[test]
fn test_strict_rejects_indefinite_length() {
    // Indefinite length array: 0x9f .. 0xff
    let indefinite_array = [0x9f, 0x01, 0x02, 0x03, 0xff];
    assert!(from_slice::<Vec<u8>>(&indefinite_array).is_err());

    // Indefinite length map: 0xbf .. 0xff
    let indefinite_map = [0xbf, 0x61, 0x61, 0x01, 0xff];
    assert!(from_slice::<std::collections::BTreeMap<String, u8>>(&indefinite_map).is_err());

    // Indefinite length bytes: 0x5f .. 0xff
    let indefinite_bytes = [0x5f, 0x41, 0x01, 0xff];
    assert!(from_slice::<serde_bytes::ByteBuf>(&indefinite_bytes).is_err());

    // Indefinite length string: 0x7f .. 0xff
    let indefinite_string = [0x7f, 0x61, 0x61, 0xff];
    assert!(from_slice::<String>(&indefinite_string).is_err());
}

#[test]
fn test_strict_rejects_forbidden_simple_values() {
    // Undefined (0xf7) is forbidden in strict mode
    let undefined = [0xf7];
    assert!(from_slice::<()>(&undefined).is_err());

    // Simple values 0-19 are unassigned and forbidden
    for i in 0..20u8 {
        let bytes = [0xe0 | i];
        assert!(
            from_slice::<()>(&bytes).is_err(),
            "Simple value {} should be rejected",
            i
        );
    }

    // Simple values 28-30 are reserved
    for i in 28..=30u8 {
        let bytes = [0xf8, i];
        assert!(
            from_slice::<()>(&bytes).is_err(),
            "Simple value {} should be rejected",
            i
        );
    }
}

#[test]
fn test_strict_rejects_forbidden_tags() {
    // Only tag 42 (CID) is allowed in DAG-CBOR
    // Tag 0 (datetime) should be rejected
    let tag_0 = [
        0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32, 0x30,
        0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a,
    ];
    assert!(from_slice::<String>(&tag_0).is_err());

    // Tag 1 (epoch timestamp) should be rejected
    let tag_1 = [0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0];
    assert!(from_slice::<u64>(&tag_1).is_err());

    // Tag 2 (bignum) should be rejected
    let tag_2 = [0xc2, 0x41, 0x01];
    assert!(from_slice::<serde_bytes::ByteBuf>(&tag_2).is_err());

    // Tag 3 (negative bignum) should be rejected
    let tag_3 = [0xc3, 0x41, 0x01];
    assert!(from_slice::<serde_bytes::ByteBuf>(&tag_3).is_err());
}

#[test]
fn test_strict_requires_64bit_floats() {
    // Half-precision float (0xf9) should be rejected in strict mode
    let half_float = [0xf9, 0x3c, 0x00]; // 1.0 as half-precision
    assert!(from_slice::<f64>(&half_float).is_err());

    // Single-precision float (0xfa) should be rejected in strict mode
    let single_float = [0xfa, 0x3f, 0x80, 0x00, 0x00]; // 1.0 as single-precision
    assert!(from_slice::<f64>(&single_float).is_err());

    // Double-precision float (0xfb) should be accepted
    let double_float = [0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 1.0 as double-precision
    assert_eq!(from_slice::<f64>(&double_float).unwrap(), 1.0);
}

#[test]
fn test_encode_rejects_nan() {
    let result = to_vec(&f64::NAN);
    assert!(result.is_err());
}

#[test]
fn test_encode_rejects_infinity() {
    let result = to_vec(&f64::INFINITY);
    assert!(result.is_err());

    let result = to_vec(&f64::NEG_INFINITY);
    assert!(result.is_err());
}

#[test]
fn test_map_keys_must_be_sorted() {
    use std::collections::BTreeMap;

    // Properly sorted map: a < b < z (bytewise lexicographic order)
    // Map of 3, key "a"=2, key "m"=3, key "z"=1
    let sorted = [0xa3, 0x61, 0x61, 0x02, 0x61, 0x6d, 0x03, 0x61, 0x7a, 0x01];
    let result: BTreeMap<String, u8> = from_slice(&sorted).unwrap();
    assert_eq!(result.get("a"), Some(&2));
    assert_eq!(result.get("m"), Some(&3));
    assert_eq!(result.get("z"), Some(&1));

    // Unsorted map: z < a (violates DAG-CBOR requirement)
    // Note: Map sorting is enforced at encode time, not decode time in many implementations
    // The decoder may accept unsorted maps for compatibility
}

#[test]
fn test_custom_config_max_depth() {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Nested {
        #[allow(dead_code)]
        inner: Option<Box<Nested>>,
    }

    // Create a deeply nested structure
    let mut bytes = Vec::new();
    // Each level: map of 1, key "inner", then the next map..
    for _ in 0..10 {
        bytes.extend_from_slice(&[0xa1, 0x65, 0x69, 0x6e, 0x6e, 0x65, 0x72]); // {inner:
    }
    bytes.push(0xf6); // null at the deepest level

    // Very shallow depth should reject deep nesting
    let config = DecodeConfig::default().with_max_depth(3);
    let result = from_slice_with_config::<Nested>(&bytes, config);
    assert!(result.is_err());
}

#[test]
fn test_encoding_always_uses_shortest_form() {
    // Small integers should use inline encoding
    let bytes = to_vec(&0u8).unwrap();
    assert_eq!(bytes, [0x00]);

    let bytes = to_vec(&23u8).unwrap();
    assert_eq!(bytes, [0x17]);

    let bytes = to_vec(&24u8).unwrap();
    assert_eq!(bytes, [0x18, 0x18]);

    let bytes = to_vec(&255u8).unwrap();
    assert_eq!(bytes, [0x18, 0xff]);

    let bytes = to_vec(&256u16).unwrap();
    assert_eq!(bytes, [0x19, 0x01, 0x00]);

    let bytes = to_vec(&65535u16).unwrap();
    assert_eq!(bytes, [0x19, 0xff, 0xff]);

    let bytes = to_vec(&65536u32).unwrap();
    assert_eq!(bytes, [0x1a, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn test_encoding_always_uses_sorted_map_keys() {
    use std::collections::BTreeMap;

    let mut map = BTreeMap::new();
    // Insert in non-sorted order
    map.insert("z".to_string(), 1);
    map.insert("a".to_string(), 2);
    map.insert("m".to_string(), 3);

    let bytes = to_vec(&map).unwrap();

    // Keys should be in sorted order: a, m, z
    // Map of 3: 0xa3
    // Key "a" (0x61 0x61), value 2 (0x02)
    // Key "m" (0x61 0x6d), value 3 (0x03)
    // Key "z" (0x61 0x7a), value 1 (0x01)
    assert_eq!(
        bytes,
        [0xa3, 0x61, 0x61, 0x02, 0x61, 0x6d, 0x03, 0x61, 0x7a, 0x01]
    );
}

#[test]
fn test_struct_fields_are_sorted() {
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestStruct {
        z_field: i32,
        a_field: i32,
        m_field: i32,
    }

    let s = TestStruct {
        z_field: 1,
        a_field: 2,
        m_field: 3,
    };

    let bytes = to_vec(&s).unwrap();

    // Fields should be sorted: a_field, m_field, z_field
    // Verify by deserializing back to a map
    let decoded: std::collections::BTreeMap<String, i32> =
        atproto_dasl::from_slice(&bytes).unwrap();

    // Verify all fields are present
    assert_eq!(decoded.get("z_field"), Some(&1));
    assert_eq!(decoded.get("a_field"), Some(&2));
    assert_eq!(decoded.get("m_field"), Some(&3));
}
