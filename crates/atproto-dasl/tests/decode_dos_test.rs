//! Regression tests for DRISL decode denial-of-service payloads.
//!
//! Every payload here was confirmed to panic (or to drive an unbounded
//! allocation) before the collection-limit and bounded-pre-allocation fixes.
//! Each test asserts a clean typed `Err` rather than a panic or an abort.

use atproto_dasl::{
    DecodeConfig, DecodeError, Ipld, from_reader, from_reader_with_config, from_slice,
    from_slice_non_strict, from_slice_with_config,
};
use std::io::Cursor;

/// CBOR array header declaring 2^63 elements (`0x9b` + u64 `0x8000000000000000`).
///
/// Nine bytes. The 8-byte form is genuinely required for 2^63, so strict-mode
/// minimality checking passes it through.
const ARRAY_BOMB_2_63: [u8; 9] = [0x9b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// CBOR map header declaring 2^63 entries (`0xbb` + u64 `0x8000000000000000`).
const MAP_BOMB_2_63: [u8; 9] = [0xbb, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// CBOR byte-string header declaring 0x04000000 bytes (`0x5a` + u32).
///
/// 67_108_864 is exactly `DecodeConfig::default().max_alloc`, so the size check
/// passes and the length is canonical. Five bytes of input previously committed
/// a 64 MiB zeroed allocation.
const BYTES_BOMB_64MIB: [u8; 5] = [0x5a, 0x04, 0x00, 0x00, 0x00];

/// Text-string variant of [`BYTES_BOMB_64MIB`] (`0x7a` + u32 `0x04000000`).
const TEXT_BOMB_64MIB: [u8; 5] = [0x7a, 0x04, 0x00, 0x00, 0x00];

#[test]
fn byte_string_bomb_rejected_before_allocating() {
    let result = from_slice::<Ipld>(&BYTES_BOMB_64MIB);
    assert!(
        matches!(
            result,
            Err(DecodeError::StringLengthExceedsInput {
                length: 67_108_864,
                remaining: 0,
            })
        ),
        "expected StringLengthExceedsInput, got {result:?}"
    );

    let result = from_slice_non_strict::<Ipld>(&BYTES_BOMB_64MIB);
    assert!(
        matches!(result, Err(DecodeError::StringLengthExceedsInput { .. })),
        "expected StringLengthExceedsInput, got {result:?}"
    );
}

#[test]
fn text_string_bomb_rejected_before_allocating() {
    let result = from_slice::<Ipld>(&TEXT_BOMB_64MIB);
    assert!(
        matches!(
            result,
            Err(DecodeError::StringLengthExceedsInput {
                length: 67_108_864,
                remaining: 0,
            })
        ),
        "expected StringLengthExceedsInput, got {result:?}"
    );
}

#[test]
fn string_bomb_over_a_reader_is_bounded() {
    // A reader has no known total length, so the incremental read carries it:
    // at most one 64 KiB chunk is reserved before EOF.
    let result = from_reader::<_, Ipld>(Cursor::new(BYTES_BOMB_64MIB.to_vec()));
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );

    let result = from_reader::<_, Ipld>(Cursor::new(TEXT_BOMB_64MIB.to_vec()));
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );
}

#[test]
fn string_bomb_with_unlimited_max_alloc_is_bounded() {
    // Worst case: max_alloc raised out of the way. The remaining-input bound
    // (slices) and the chunked read (readers) must still hold.
    let config = DecodeConfig {
        max_alloc: usize::MAX,
        ..DecodeConfig::default()
    };
    let huge = [0x5bu8, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let result = from_slice_with_config::<Ipld>(&huge, config.clone());
    assert!(
        matches!(result, Err(DecodeError::StringLengthExceedsInput { .. })),
        "expected StringLengthExceedsInput, got {result:?}"
    );

    let result = from_reader_with_config::<_, Ipld>(Cursor::new(huge.to_vec()), config);
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );
}

#[test]
fn legitimate_large_strings_still_decode() {
    // Multi-megabyte honest byte and text strings must round-trip: the bound is
    // exact for strings, so there are no false rejections.
    let blob = vec![0x5au8; 3 * 1024 * 1024 + 7];
    let bytes = atproto_dasl::to_vec(&serde_bytes::ByteBuf::from(blob.clone())).unwrap();
    let decoded: serde_bytes::ByteBuf = from_slice(&bytes).unwrap();
    assert_eq!(decoded.as_ref(), blob.as_slice());

    let text = "x".repeat(2 * 1024 * 1024 + 3);
    let bytes = atproto_dasl::to_vec(&text).unwrap();
    let decoded: String = from_slice(&bytes).unwrap();
    assert_eq!(decoded.len(), text.len());
}

#[test]
fn array_header_2_63_strict_does_not_panic() {
    let result = from_slice::<Ipld>(&ARRAY_BOMB_2_63);
    assert!(result.is_err(), "expected a typed error, got {result:?}");
}

#[test]
fn array_header_2_63_non_strict_does_not_panic() {
    let result = from_slice_non_strict::<Ipld>(&ARRAY_BOMB_2_63);
    assert!(result.is_err(), "expected a typed error, got {result:?}");
}

#[test]
fn map_header_2_63_rejected() {
    let result = from_slice::<Ipld>(&MAP_BOMB_2_63);
    assert!(result.is_err(), "expected a typed error, got {result:?}");
}

#[test]
fn canonical_1e9_array_header_rejected_without_reserving() {
    // 0x9a + u32 1_000_000_000. Canonical, passes minimality, and previously
    // drove a multi-gigabyte `Vec::reserve` before failing with UnexpectedEof.
    // The non-zero default count limit now catches it before any allocation.
    let payload = [0x9a, 0x3b, 0x9a, 0xca, 0x00];
    let result = from_slice::<Ipld>(&payload);
    assert!(
        matches!(
            result,
            Err(DecodeError::ArrayTooLarge { count, .. }) if count == 1_000_000_000
        ),
        "expected ArrayTooLarge, got {result:?}"
    );

    // With the count limit switched off, the remaining-input bound catches it.
    let config = DecodeConfig::default().with_unlimited_array_elements();
    let result = from_slice_with_config::<Ipld>(&payload, config);
    assert!(
        matches!(
            result,
            Err(DecodeError::CollectionLengthExceedsInput { count, .. }) if count == 1_000_000_000
        ),
        "expected CollectionLengthExceedsInput, got {result:?}"
    );
}

#[test]
fn count_within_limit_but_exceeding_input_is_rejected() {
    // 0x9a + u32 1_048_576. Well under the 2^24 default count limit, but the
    // four bytes that follow cannot possibly encode a million elements.
    let payload = [0x9a, 0x00, 0x10, 0x00, 0x00];
    let result = from_slice::<Ipld>(&payload);
    assert!(
        matches!(
            result,
            Err(DecodeError::CollectionLengthExceedsInput {
                count: 1_048_576,
                needed: 1_048_576,
                remaining: 0,
            })
        ),
        "expected CollectionLengthExceedsInput, got {result:?}"
    );

    // A map entry needs a key byte and a value byte, so the bound doubles.
    let payload = [0xba, 0x00, 0x10, 0x00, 0x00];
    let result = from_slice::<Ipld>(&payload);
    assert!(
        matches!(
            result,
            Err(DecodeError::CollectionLengthExceedsInput {
                count: 1_048_576,
                needed: 2_097_152,
                remaining: 0,
            })
        ),
        "expected CollectionLengthExceedsInput, got {result:?}"
    );
}

#[test]
fn explicit_unlimited_counts_still_safe() {
    let config = DecodeConfig::default()
        .with_unlimited_array_elements()
        .with_unlimited_map_entries();
    let result = from_slice_with_config::<Ipld>(&ARRAY_BOMB_2_63, config.clone());
    assert!(result.is_err(), "expected a typed error, got {result:?}");

    let result = from_slice_with_config::<Ipld>(&MAP_BOMB_2_63, config);
    assert!(result.is_err(), "expected a typed error, got {result:?}");
}

#[test]
fn stream_input_bomb_is_bounded() {
    // A reader does not communicate its total length, so the remaining-input
    // bound does not apply. The count limit and the clamped pre-allocation must
    // carry the payload on their own.
    let result = from_reader::<_, Ipld>(Cursor::new(ARRAY_BOMB_2_63.to_vec()));
    assert!(
        matches!(result, Err(DecodeError::ArrayTooLarge { .. })),
        "expected ArrayTooLarge, got {result:?}"
    );

    let result = from_reader::<_, Ipld>(Cursor::new(MAP_BOMB_2_63.to_vec()));
    assert!(
        matches!(result, Err(DecodeError::MapTooLarge { .. })),
        "expected MapTooLarge, got {result:?}"
    );
}

#[test]
fn stream_input_bomb_with_unlimited_counts_is_bounded() {
    // The worst case: a reader (so no input bound) with the count limit
    // switched off. Only the clamped pre-allocation stands between the payload
    // and the capacity-overflow panic, so this is the load-bearing assertion.
    let config = DecodeConfig::default()
        .with_unlimited_array_elements()
        .with_unlimited_map_entries();

    let result =
        from_reader_with_config::<_, Ipld>(Cursor::new(ARRAY_BOMB_2_63.to_vec()), config.clone());
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );

    let result = from_reader_with_config::<_, Ipld>(Cursor::new(MAP_BOMB_2_63.to_vec()), config);
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );
}

#[test]
fn nested_array_bomb_is_bounded() {
    // 256 nested single-element array headers, then a 2^63 array header. Guards
    // the per-nesting-level pre-allocation cap: without it each level would
    // speculatively reserve from the wire-declared count.
    let mut payload = vec![0x81u8; 256];
    payload.extend_from_slice(&ARRAY_BOMB_2_63);
    let result = from_slice::<Ipld>(&payload);
    assert!(result.is_err(), "expected a typed error, got {result:?}");
}

#[test]
fn legitimate_large_array_still_decodes() {
    // 100k small integers round-trip under the default config, so the new
    // limits do not reject honest data.
    let values: Vec<u32> = (0..100_000u32).collect();
    let bytes = atproto_dasl::to_vec(&values).unwrap();
    let decoded: Vec<u32> = from_slice(&bytes).unwrap();
    assert_eq!(decoded.len(), 100_000);

    let ipld: Ipld = from_slice(&bytes).unwrap();
    assert_eq!(ipld.as_list().map(Vec::len), Some(100_000));
}

#[test]
fn legitimate_large_map_still_decodes() {
    use std::collections::BTreeMap;

    let map: BTreeMap<String, u32> = (0..10_000u32).map(|i| (format!("k{i:06}"), i)).collect();
    let bytes = atproto_dasl::to_vec(&map).unwrap();
    let decoded: BTreeMap<String, u32> = from_slice(&bytes).unwrap();
    assert_eq!(decoded.len(), 10_000);
}

#[test]
fn truncated_array_reports_the_input_bound_on_slices() {
    // Behavior change: a slice input now rejects the declared count up front
    // instead of running out of bytes partway through. Both are errors, but the
    // variant differs, so this pins the new one.
    let payload = [0x83, 0x01, 0x02];
    let result = from_slice::<Ipld>(&payload);
    assert!(
        matches!(
            result,
            Err(DecodeError::CollectionLengthExceedsInput {
                count: 3,
                needed: 3,
                remaining: 2,
            })
        ),
        "expected CollectionLengthExceedsInput, got {result:?}"
    );

    // A reader input has no known total length, so truncation still surfaces
    // as `UnexpectedEof`.
    let result = from_reader::<_, Ipld>(Cursor::new(payload.to_vec()));
    assert!(
        matches!(result, Err(DecodeError::UnexpectedEof)),
        "expected UnexpectedEof, got {result:?}"
    );
}

#[test]
fn exactly_sized_collections_are_not_falsely_rejected() {
    // Each element is exactly one byte, so the array sits precisely on the
    // remaining-input bound. It must decode.
    let payload = [0x83, 0x01, 0x02, 0x03];
    let decoded: Vec<u8> = from_slice(&payload).unwrap();
    assert_eq!(decoded, vec![1, 2, 3]);

    // Same for a map with one-byte keys and one-byte values.
    let payload = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];
    let decoded: std::collections::BTreeMap<String, u8> = from_slice(&payload).unwrap();
    assert_eq!(decoded.len(), 2);
}
