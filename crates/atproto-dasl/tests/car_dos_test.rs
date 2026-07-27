//! Regression tests for CAR block denial-of-service payloads.
//!
//! Every payload here was confirmed to panic with "capacity overflow" (or to
//! allocate a huge buffer before checking the limit) prior to moving the size
//! guard ahead of the allocation and switching to an incremental `try_reserve`
//! read.

use atproto_dasl::car::MAX_CID_BYTE_LENGTH;
use atproto_dasl::{CarBlock, CarConfig, CarError, CarHeader, CarReader, CarWriter, LimitsConfig};
use std::io::Cursor;

/// LEB128 varint for 2^63: ten bytes, the exact confirmed payload.
const VARINT_2_63: [u8; 10] = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];

/// Encode a u64 as an unsigned LEB128 varint.
fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

/// A minimal valid CAR header followed by `tail`.
async fn car_with_tail(tail: &[u8]) -> Vec<u8> {
    let block = CarBlock::from_data(b"root".to_vec());
    let header = CarHeader::new(vec![block.cid.into()]).unwrap();
    let mut buffer = Vec::new();
    let writer = CarWriter::new(&mut buffer, header.roots.clone())
        .await
        .unwrap();
    writer.finish().await.unwrap();
    buffer.extend_from_slice(tail);
    buffer
}

#[test]
fn sync_block_read_2_63_length_does_not_panic() {
    let mut cursor = Cursor::new(VARINT_2_63.to_vec());
    let result = CarBlock::read_from(&mut cursor);
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { .. })),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[test]
fn from_bytes_2_63_length_does_not_panic() {
    let result = CarBlock::from_bytes(&VARINT_2_63);
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { .. })),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[tokio::test]
async fn async_block_read_2_63_length_does_not_panic() {
    // CarReader::next_block is the supposedly-safe path; it previously
    // allocated first and checked the limit afterwards.
    let car = car_with_tail(&VARINT_2_63).await;
    let mut reader = CarReader::new(Cursor::new(car)).await.unwrap();
    let result = reader.next_block().await;
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { .. })),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[tokio::test]
async fn car_reader_rejects_before_allocating() {
    // A declared 100 MB block with zero bytes of payload. Before the fix this
    // zero-filled 100 MB and only then compared against the 1 MB limit; now the
    // limit is applied to the declared length first.
    let car = car_with_tail(&varint(100 * 1024 * 1024)).await;
    let mut reader = CarReader::new(Cursor::new(car)).await.unwrap();
    let result = reader.next_block().await;
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { size, max })
            if size == 100 * 1024 * 1024 && max == (1024 * 1024 + MAX_CID_BYTE_LENGTH) as u64),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[test]
fn unlimited_limits_still_reject_the_bomb() {
    // With max_block_size == usize::MAX the size check is a no-op, so the
    // incremental try_reserve read is the only thing standing between the
    // payload and a capacity-overflow panic.
    let mut cursor = Cursor::new(VARINT_2_63.to_vec());
    let result = CarBlock::read_from_with_limits(&mut cursor, &LimitsConfig::unlimited());
    assert!(
        matches!(
            result,
            Err(CarError::Io(_)) | Err(CarError::AllocationFailed { .. })
        ),
        "expected a recoverable Io or AllocationFailed error, got {result:?}"
    );
}

#[tokio::test]
async fn unlimited_limits_still_reject_the_bomb_async() {
    let car = car_with_tail(&VARINT_2_63).await;
    let config = CarConfig::default().with_limits(LimitsConfig::unlimited());
    let mut reader = CarReader::with_config(Cursor::new(car), config)
        .await
        .unwrap();
    let result = reader.next_block().await;
    assert!(
        matches!(
            result,
            Err(CarError::Io(_)) | Err(CarError::AllocationFailed { .. })
        ),
        "expected a recoverable Io or AllocationFailed error, got {result:?}"
    );
}

#[test]
fn u64_max_length_rejected() {
    let mut payload = varint(u64::MAX);
    payload.extend_from_slice(&[0u8; 4]);
    let mut cursor = Cursor::new(payload);
    let result = CarBlock::read_from(&mut cursor);
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { size, .. }) if size == u64::MAX),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[test]
fn block_at_exactly_max_block_size_is_accepted() {
    // The frame budget is max_block_size + MAX_CID_BYTE_LENGTH, so a block whose
    // data sits exactly on the limit must still round-trip.
    let limits = LimitsConfig::default().with_max_block_size(4096);
    let block = CarBlock::from_data(vec![0xabu8; 4096]);
    let bytes = block.to_bytes().unwrap();

    let (decoded, consumed) = CarBlock::from_bytes_with_limits(&bytes, &limits).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded.data.len(), 4096);
    assert_eq!(decoded.cid, block.cid);
}

#[test]
fn block_one_byte_over_max_is_rejected() {
    // The post-parse check keeps the CID allowance from loosening the limit.
    let limits = LimitsConfig::default().with_max_block_size(4096);
    let block = CarBlock::from_data(vec![0xabu8; 4097]);
    let bytes = block.to_bytes().unwrap();

    let result = CarBlock::from_bytes_with_limits(&bytes, &limits);
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { size, max }) if size == 4097 && max == 4096),
        "expected BlockTooLarge, got {result:?}"
    );
}

#[test]
fn truncated_block_still_reports_io_error() {
    // An honest 1 KiB length prefix with only ten bytes of payload is a
    // truncation, and must keep reporting as such rather than as a limit
    // violation.
    let mut payload = varint(1024);
    payload.extend_from_slice(&[0u8; 10]);
    let mut cursor = Cursor::new(payload);
    let result = CarBlock::read_from(&mut cursor);
    assert!(
        matches!(result, Err(CarError::Io(_))),
        "expected Io, got {result:?}"
    );
}

#[test]
fn zero_length_block_still_rejected() {
    let mut cursor = Cursor::new(vec![0x00u8]);
    let result = CarBlock::read_from(&mut cursor);
    assert!(
        matches!(result, Err(CarError::InvalidBlock { .. })),
        "expected InvalidBlock, got {result:?}"
    );
}

#[test]
fn empty_input_is_still_eof() {
    let mut cursor = Cursor::new(Vec::new());
    assert!(CarBlock::read_from(&mut cursor).unwrap().is_none());
}

#[test]
fn default_limits_reject_blocks_over_one_megabyte() {
    // Documented behavior change: the bare read_from / from_bytes entry points
    // now inherit LimitsConfig::default(). The escape hatch is the _with_limits
    // variant.
    let block = CarBlock::from_data(vec![0u8; 1024 * 1024 + 1]);
    let bytes = block.to_bytes().unwrap();

    let result = CarBlock::from_bytes(&bytes);
    assert!(
        matches!(result, Err(CarError::BlockTooLarge { .. })),
        "expected BlockTooLarge, got {result:?}"
    );

    let (decoded, _) =
        CarBlock::from_bytes_with_limits(&bytes, &LimitsConfig::high_throughput()).unwrap();
    assert_eq!(decoded.data.len(), 1024 * 1024 + 1);
}
