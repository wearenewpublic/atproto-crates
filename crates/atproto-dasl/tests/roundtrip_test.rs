//! Roundtrip tests for DAG-CBOR
//!
//! Tests that values can be serialized and deserialized without data loss.

use atproto_dasl::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[test]
fn test_roundtrip_primitives() {
    // Booleans
    let original = true;
    let bytes = to_vec(&original).unwrap();
    let decoded: bool = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);

    // Integers
    for i in [
        0i64,
        1,
        -1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        -24,
        -25,
        i64::MAX,
        i64::MIN,
    ] {
        let bytes = to_vec(&i).unwrap();
        let decoded: i64 = from_slice(&bytes).unwrap();
        assert_eq!(i, decoded, "roundtrip failed for {}", i);
    }

    // Unsigned integers
    for u in [0u64, 1, 23, 24, 255, 256, 65535, 65536, u64::MAX / 2] {
        let bytes = to_vec(&u).unwrap();
        let decoded: u64 = from_slice(&bytes).unwrap();
        assert_eq!(u, decoded, "roundtrip failed for {}", u);
    }

    // Floats
    for f in [0.0f64, 1.0, -1.0, 2.5, 1e10, 1e-10] {
        let bytes = to_vec(&f).unwrap();
        let decoded: f64 = from_slice(&bytes).unwrap();
        assert!(
            (f - decoded).abs() < f64::EPSILON,
            "roundtrip failed for {}",
            f
        );
    }

    // Strings
    for s in ["", "a", "hello", "hello world!", "unicode: 你好世界 🌍"] {
        let bytes = to_vec(&s).unwrap();
        let decoded: String = from_slice(&bytes).unwrap();
        assert_eq!(s, decoded, "roundtrip failed for {:?}", s);
    }
}

#[test]
fn test_roundtrip_option() {
    let some: Option<i32> = Some(42);
    let bytes = to_vec(&some).unwrap();
    let decoded: Option<i32> = from_slice(&bytes).unwrap();
    assert_eq!(some, decoded);

    let none: Option<i32> = None;
    let bytes = to_vec(&none).unwrap();
    let decoded: Option<i32> = from_slice(&bytes).unwrap();
    assert_eq!(none, decoded);
}

#[test]
fn test_roundtrip_vec() {
    let original: Vec<i32> = vec![];
    let bytes = to_vec(&original).unwrap();
    let decoded: Vec<i32> = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);

    let original: Vec<i32> = vec![1, 2, 3, 4, 5];
    let bytes = to_vec(&original).unwrap();
    let decoded: Vec<i32> = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);

    let original: Vec<String> = vec!["hello".into(), "world".into()];
    let bytes = to_vec(&original).unwrap();
    let decoded: Vec<String> = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_map() {
    let mut original: BTreeMap<String, i32> = BTreeMap::new();
    let bytes = to_vec(&original).unwrap();
    let decoded: BTreeMap<String, i32> = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);

    original.insert("a".into(), 1);
    original.insert("b".into(), 2);
    original.insert("c".into(), 3);
    let bytes = to_vec(&original).unwrap();
    let decoded: BTreeMap<String, i32> = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_struct() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Simple {
        a: i32,
        b: String,
    }

    let original = Simple {
        a: 42,
        b: "hello".into(),
    };
    let bytes = to_vec(&original).unwrap();
    let decoded: Simple = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_nested_struct() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Inner {
        value: i32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Outer {
        inner: Inner,
        name: String,
    }

    let original = Outer {
        inner: Inner { value: 42 },
        name: "test".into(),
    };
    let bytes = to_vec(&original).unwrap();
    let decoded: Outer = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_enum() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Color {
        Red,
        Green,
        Blue,
    }

    for color in [Color::Red, Color::Green, Color::Blue] {
        let bytes = to_vec(&color).unwrap();
        let decoded: Color = from_slice(&bytes).unwrap();
        assert_eq!(color, decoded);
    }
}

#[test]
fn test_roundtrip_complex_enum() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Message {
        Quit,
        Move { x: i32, y: i32 },
        Write(String),
        ChangeColor(i32, i32, i32),
    }

    let messages = vec![
        Message::Quit,
        Message::Move { x: 10, y: 20 },
        Message::Write("hello".into()),
        Message::ChangeColor(255, 128, 0),
    ];

    for msg in messages {
        let bytes = to_vec(&msg).unwrap();
        let decoded: Message = from_slice(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}

#[test]
fn test_roundtrip_deeply_nested() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Level3 {
        value: i32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Level2 {
        level3: Level3,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Level1 {
        level2: Level2,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Root {
        level1: Level1,
    }

    let original = Root {
        level1: Level1 {
            level2: Level2 {
                level3: Level3 { value: 42 },
            },
        },
    };
    let bytes = to_vec(&original).unwrap();
    let decoded: Root = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_tuple() {
    let original = (1i32, "hello".to_string(), true);
    let bytes = to_vec(&original).unwrap();
    let decoded: (i32, String, bool) = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_bytes() {
    use serde_bytes::ByteBuf;

    let original = ByteBuf::from(vec![0x01, 0x02, 0x03, 0x04]);
    let bytes = to_vec(&original).unwrap();
    let decoded: ByteBuf = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn test_roundtrip_at_protocol_like_record() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Post {
        #[serde(rename = "$type")]
        record_type: String,
        text: String,
        #[serde(rename = "createdAt")]
        created_at: String,
        langs: Vec<String>,
    }

    let original = Post {
        record_type: "app.bsky.feed.post".into(),
        text: "Hello, Bluesky!".into(),
        created_at: "2024-01-01T00:00:00.000Z".into(),
        langs: vec!["en".into()],
    };

    let bytes = to_vec(&original).unwrap();
    let decoded: Post = from_slice(&bytes).unwrap();
    assert_eq!(original, decoded);
}
