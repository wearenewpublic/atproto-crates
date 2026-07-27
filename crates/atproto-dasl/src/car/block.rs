//! CAR block structure and operations.
//!
//! Each block in a CAR file consists of a CID and the block data.

use crate::car::config::LimitsConfig;
use crate::cid::{DAG_CBOR_CODEC, RAW_CODEC, SHA256_CODE, compute_cid};
use crate::errors::CarError;
use crate::varint;
use cid::Cid;
use std::io::{Read, Write};

/// Expected byte length of a DASL CID in binary form.
///
/// A DASL-conformant CID is always exactly 36 bytes:
/// 1 (version) + 1 (codec varint) + 1 (hash code) + 1 (digest length) + 32 (digest).
pub const DASL_CID_BYTE_LENGTH: usize = 36;

/// Largest CID prefix a CAR block frame can legitimately carry.
///
/// A worst-case CID prefix costs 1 byte of version varint, 9 bytes of codec
/// varint, 9 bytes of multihash code varint, 2 bytes of digest length varint and
/// a 64-byte digest (this crate uses `Multihash<64>`), for 85 bytes; rounded up
/// to 96 for headroom.
///
/// DASL CIDs are 36 bytes, so this bound exists only to keep the pre-allocation
/// check on the wire length from rejecting a legal frame. The exact
/// `max_block_size` check runs after the CID is parsed, so the slack cannot
/// loosen the real limit.
pub const MAX_CID_BYTE_LENGTH: usize = 96;

/// Chunk size for incremental block reads.
const READ_CHUNK: usize = 64 * 1024;

/// Read exactly `len` bytes without trusting `len` up front.
///
/// Commits at most `READ_CHUNK` bytes before the stream has proven it actually
/// holds them, and grows with `Vec::try_reserve`, so a hostile length produces a
/// recoverable error instead of a "capacity overflow" panic or an allocator
/// abort.
///
/// # Errors
///
/// Returns `CarError::AllocationFailed` if the allocator cannot satisfy a chunk,
/// and `CarError::Io` if the stream ends before `len` bytes are read.
fn read_exact_incremental<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, CarError> {
    let mut buf: Vec<u8> = Vec::new();
    let initial = len.min(READ_CHUNK);
    buf.try_reserve_exact(initial)
        .map_err(|e| CarError::AllocationFailed {
            requested: initial,
            reason: e.to_string(),
        })?;
    while buf.len() < len {
        let want = (len - buf.len()).min(READ_CHUNK);
        let start = buf.len();
        buf.try_reserve(want)
            .map_err(|e| CarError::AllocationFailed {
                requested: start + want,
                reason: e.to_string(),
            })?;
        buf.resize(start + want, 0);
        reader.read_exact(&mut buf[start..])?;
    }
    Ok(buf)
}

/// Convert a wire-declared frame length into a checked `usize`.
///
/// The frame budget is the data limit plus the largest CID that can precede the
/// data, since the CAR wire length covers both.
///
/// # Errors
///
/// Returns `CarError::BlockTooLarge` if the declared length exceeds the budget
/// or does not fit in `usize` (relevant on 32-bit targets, where a bare
/// `as usize` would silently truncate).
fn checked_frame_length(length: u64, limits: &LimitsConfig) -> Result<usize, CarError> {
    let max_frame = limits.max_block_size.saturating_add(MAX_CID_BYTE_LENGTH);
    let length_usize = usize::try_from(length).map_err(|_| CarError::BlockTooLarge {
        size: length,
        max: max_frame as u64,
    })?;
    if length_usize > max_frame {
        return Err(CarError::BlockTooLarge {
            size: length,
            max: max_frame as u64,
        });
    }
    Ok(length_usize)
}

/// Split a decoded frame into a CID and its data, enforcing the exact limit.
///
/// # Errors
///
/// Returns `CarError::InvalidCid` if the CID does not parse,
/// `CarError::InvalidBlock` if no data follows the CID, and
/// `CarError::BlockTooLarge` if the data exceeds `limits.max_block_size`.
fn split_frame(block_bytes: &[u8], limits: &LimitsConfig) -> Result<CarBlock, CarError> {
    let cid = Cid::try_from(block_bytes).map_err(|e| CarError::InvalidCid {
        reason: e.to_string(),
    })?;

    let cid_len = cid.to_bytes().len();
    if cid_len >= block_bytes.len() {
        return Err(CarError::InvalidBlock {
            reason: "block has no data after CID".to_string(),
        });
    }

    let data = block_bytes[cid_len..].to_vec();
    if data.len() > limits.max_block_size {
        return Err(CarError::BlockTooLarge {
            size: data.len() as u64,
            max: limits.max_block_size as u64,
        });
    }

    Ok(CarBlock { cid, data })
}

/// A single block in a CAR file.
///
/// # Format
///
/// ```text
/// varint(cid_bytes.len() + data.len()) + cid_bytes + data
/// ```
#[derive(Debug, Clone)]
pub struct CarBlock {
    /// Content identifier for this block.
    pub cid: Cid,
    /// Raw block data (typically DAG-CBOR encoded).
    pub data: Vec<u8>,
}

impl CarBlock {
    /// Create a new block from CID and data.
    #[must_use]
    pub fn new(cid: Cid, data: Vec<u8>) -> Self {
        Self { cid, data }
    }

    /// Create a block by computing CID from data.
    ///
    /// Uses CIDv1 with dag-cbor codec and sha2-256 hash.
    #[must_use]
    pub fn from_data(data: Vec<u8>) -> Self {
        let cid = compute_cid(&data);
        Self { cid, data }
    }

    /// Verify that the CID matches the data.
    ///
    /// # Errors
    ///
    /// Returns `CarError::CidMismatch` if the CID doesn't match.
    pub fn verify(&self) -> Result<(), CarError> {
        let computed = compute_cid(&self.data);
        if computed != self.cid {
            return Err(CarError::CidMismatch {
                expected: self.cid.to_string(),
                actual: computed.to_string(),
            });
        }
        Ok(())
    }

    /// Verify that the CID meets DASL format requirements.
    ///
    /// DASL requires CIDv1 with raw (0x55) or dag-cbor (0x71) codec and
    /// sha-256 (0x12) hash.
    ///
    /// # Errors
    ///
    /// Returns `CarError::InvalidCid` if the format is not DASL-compliant.
    pub fn verify_format(&self) -> Result<(), CarError> {
        if self.cid.version() != cid::Version::V1 {
            return Err(CarError::InvalidCid {
                reason: format!("expected CIDv1, got {:?}", self.cid.version()),
            });
        }

        let codec = self.cid.codec();
        if codec != DAG_CBOR_CODEC && codec != RAW_CODEC {
            return Err(CarError::InvalidCid {
                reason: format!(
                    "expected dag-cbor (0x71) or raw (0x55) codec, got 0x{:x}",
                    codec
                ),
            });
        }

        if self.cid.hash().code() != SHA256_CODE {
            return Err(CarError::InvalidCid {
                reason: format!(
                    "expected sha2-256 hash (0x12), got 0x{:x}",
                    self.cid.hash().code()
                ),
            });
        }

        let cid_len = self.cid.to_bytes().len();
        if cid_len != DASL_CID_BYTE_LENGTH {
            return Err(CarError::InvalidCid {
                reason: format!(
                    "DASL CID must be exactly {} bytes, got {}",
                    DASL_CID_BYTE_LENGTH, cid_len
                ),
            });
        }

        Ok(())
    }

    /// Get the raw CID bytes for encoding.
    #[must_use]
    pub fn cid_bytes(&self) -> Vec<u8> {
        self.cid.to_bytes()
    }

    /// Encode the block to bytes (with length prefix).
    ///
    /// # Errors
    ///
    /// Returns `CarError` if encoding fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CarError> {
        let cid_bytes = self.cid_bytes();
        let total_len = cid_bytes.len() + self.data.len();

        let mut result = Vec::with_capacity(10 + total_len);

        // Write length prefix
        varint::write_varint(&mut result, total_len as u64)?;

        // Write CID bytes
        result.extend_from_slice(&cid_bytes);

        // Write data
        result.extend_from_slice(&self.data);

        Ok(result)
    }

    /// Write block to a writer (with length prefix).
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if encoding or writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<usize, CarError> {
        let bytes = self.to_bytes()?;
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }

    /// Read a block from a reader using [`LimitsConfig::default`].
    ///
    /// Returns `None` at EOF. Blocks whose data exceeds the default
    /// `max_block_size` (1 MB) are rejected; use [`Self::read_from_with_limits`]
    /// for a different budget.
    ///
    /// # Errors
    ///
    /// Returns `CarError::InvalidBlock` if the block is malformed, or
    /// `CarError::BlockTooLarge` if it exceeds the default limits.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Option<Self>, CarError> {
        Self::read_from_with_limits(reader, &LimitsConfig::default())
    }

    /// Read a block from a reader, enforcing `limits` before allocating.
    ///
    /// The wire length is checked against `limits.max_block_size` plus
    /// [`MAX_CID_BYTE_LENGTH`] before any buffer is created, and the block data
    /// is checked exactly once the CID has been parsed. The buffer itself grows
    /// incrementally with `Vec::try_reserve`, so even
    /// [`LimitsConfig::unlimited`] cannot be turned into a panic or an
    /// allocator abort by a hostile length prefix.
    ///
    /// Returns `None` at EOF.
    ///
    /// # Errors
    ///
    /// Returns `CarError::BlockTooLarge` if the declared frame or the decoded
    /// data exceeds the limits, `CarError::AllocationFailed` if the allocator
    /// refuses a chunk, `CarError::Io` if the stream is truncated, and
    /// `CarError::InvalidBlock` or `CarError::InvalidCid` if the block is
    /// malformed.
    pub fn read_from_with_limits<R: Read>(
        reader: &mut R,
        limits: &LimitsConfig,
    ) -> Result<Option<Self>, CarError> {
        // Try to read length prefix
        let length = match varint::read_varint(reader) {
            Ok(len) => len,
            Err(crate::errors::VarintError::UnexpectedEof) => return Ok(None),
            Err(e) => return Err(CarError::Varint(e)),
        };

        if length == 0 {
            return Err(CarError::InvalidBlock {
                reason: "block length is zero".to_string(),
            });
        }

        let length = checked_frame_length(length, limits)?;
        let block_bytes = read_exact_incremental(reader, length)?;

        Ok(Some(split_frame(&block_bytes, limits)?))
    }

    /// Decode a block from bytes (with length prefix) using
    /// [`LimitsConfig::default`].
    ///
    /// Returns `(block, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if decoding fails, including
    /// `CarError::BlockTooLarge` when the block exceeds the default limits.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), CarError> {
        Self::from_bytes_with_limits(bytes, &LimitsConfig::default())
    }

    /// Decode a block from bytes (with length prefix), enforcing `limits`.
    ///
    /// Returns `(block, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns `CarError` if decoding fails. See
    /// [`Self::read_from_with_limits`] for the specific variants.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        limits: &LimitsConfig,
    ) -> Result<(Self, usize), CarError> {
        let mut cursor = std::io::Cursor::new(bytes);
        match Self::read_from_with_limits(&mut cursor, limits)? {
            Some(block) => Ok((block, cursor.position() as usize)),
            None => Err(CarError::InvalidBlock {
                reason: "unexpected end of input".to_string(),
            }),
        }
    }
}

/// Async versions of block I/O operations.
pub mod async_io {
    use super::*;
    use crate::varint::async_io as async_varint;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// Write block to an async writer.
    pub async fn write_block<W: AsyncWrite + Unpin>(
        writer: &mut W,
        block: &CarBlock,
    ) -> Result<usize, CarError> {
        let cid_bytes = block.cid_bytes();
        let total_len = cid_bytes.len() + block.data.len();

        // Write length prefix
        let prefix_len = async_varint::write_varint(writer, total_len as u64).await?;

        // Write CID bytes
        writer.write_all(&cid_bytes).await?;

        // Write data
        writer.write_all(&block.data).await?;

        Ok(prefix_len + total_len)
    }

    /// Async counterpart of [`super::read_exact_incremental`].
    ///
    /// # Errors
    ///
    /// Returns `CarError::AllocationFailed` if the allocator cannot satisfy a
    /// chunk, and `CarError::Io` if the stream ends early.
    async fn read_exact_incremental<R: AsyncRead + Unpin>(
        reader: &mut R,
        len: usize,
    ) -> Result<Vec<u8>, CarError> {
        let mut buf: Vec<u8> = Vec::new();
        let initial = len.min(READ_CHUNK);
        buf.try_reserve_exact(initial)
            .map_err(|e| CarError::AllocationFailed {
                requested: initial,
                reason: e.to_string(),
            })?;
        while buf.len() < len {
            let want = (len - buf.len()).min(READ_CHUNK);
            let start = buf.len();
            buf.try_reserve(want)
                .map_err(|e| CarError::AllocationFailed {
                    requested: start + want,
                    reason: e.to_string(),
                })?;
            buf.resize(start + want, 0);
            reader.read_exact(&mut buf[start..]).await?;
        }
        Ok(buf)
    }

    /// Read a block from an async reader, enforcing `limits` before allocating.
    ///
    /// Mirrors [`CarBlock::read_from_with_limits`]: the declared frame length is
    /// checked against `limits.max_block_size` plus [`MAX_CID_BYTE_LENGTH`]
    /// before any buffer exists, the buffer grows incrementally with
    /// `Vec::try_reserve`, and the data is checked exactly once the CID has been
    /// parsed.
    ///
    /// Returns `None` at EOF.
    ///
    /// # Errors
    ///
    /// Returns `CarError::BlockTooLarge`, `CarError::AllocationFailed`,
    /// `CarError::Io`, `CarError::InvalidBlock`, or `CarError::InvalidCid`.
    pub async fn read_block_with_limits<R: AsyncRead + Unpin>(
        reader: &mut R,
        limits: &LimitsConfig,
    ) -> Result<Option<CarBlock>, CarError> {
        // Try to read length prefix
        let length = match async_varint::read_varint(reader).await {
            Ok(len) => len,
            Err(crate::errors::VarintError::UnexpectedEof) => return Ok(None),
            Err(e) => return Err(CarError::Varint(e)),
        };

        if length == 0 {
            return Err(CarError::InvalidBlock {
                reason: "block length is zero".to_string(),
            });
        }

        let length = checked_frame_length(length, limits)?;
        let block_bytes = read_exact_incremental(reader, length).await?;

        Ok(Some(split_frame(&block_bytes, limits)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn test_block_from_data() {
        let data = b"test block data".to_vec();
        let block = CarBlock::from_data(data.clone());

        assert_eq!(block.data, data);
        assert!(block.verify().is_ok());
        assert!(block.verify_format().is_ok());
    }

    #[test]
    fn test_block_roundtrip() {
        let data = b"roundtrip test".to_vec();
        let block = CarBlock::from_data(data);

        let bytes = block.to_bytes().unwrap();
        let (decoded, consumed) = CarBlock::from_bytes(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.cid, block.cid);
        assert_eq!(decoded.data, block.data);
    }

    #[test]
    fn test_block_read_write() {
        let data = b"read write test".to_vec();
        let block = CarBlock::from_data(data);

        let mut buffer = Vec::new();
        block.write_to(&mut buffer).unwrap();

        let mut cursor = std::io::Cursor::new(&buffer);
        let decoded = CarBlock::read_from(&mut cursor).unwrap().unwrap();

        assert_eq!(decoded.cid, block.cid);
        assert_eq!(decoded.data, block.data);
    }

    #[test]
    fn test_block_verify_mismatch() {
        let data = b"original data".to_vec();
        let mut block = CarBlock::from_data(data);

        // Corrupt the data
        block.data = b"corrupted data".to_vec();

        assert!(matches!(block.verify(), Err(CarError::CidMismatch { .. })));
    }

    #[test]
    fn test_block_eof() {
        let empty: &[u8] = &[];
        let mut cursor = std::io::Cursor::new(empty);
        let result = CarBlock::read_from(&mut cursor).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_format_raw_codec() {
        let data = b"raw binary blob".to_vec();
        let cid = crate::cid::compute_raw_cid(&data);
        let block = CarBlock::new(cid, data);
        assert!(block.verify_format().is_ok());
    }

    #[test]
    fn test_verify_format_invalid_codec() {
        use multihash::Multihash;
        let data = b"test".to_vec();
        // Create a CID with an unsupported codec (0x50)
        let hash = sha2::Sha256::digest(&data);
        let mh = Multihash::<64>::wrap(SHA256_CODE, &hash).unwrap();
        let cid = Cid::new_v1(0x50, mh);
        let block = CarBlock::new(cid, data);
        assert!(matches!(
            block.verify_format(),
            Err(CarError::InvalidCid { .. })
        ));
    }

    #[tokio::test]
    async fn test_async_block_roundtrip() {
        let data = b"async roundtrip".to_vec();
        let block = CarBlock::from_data(data);

        let mut buffer = Vec::new();
        async_io::write_block(&mut buffer, &block).await.unwrap();

        let mut cursor = std::io::Cursor::new(&buffer);
        let decoded = async_io::read_block_with_limits(&mut cursor, &LimitsConfig::default())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(decoded.cid, block.cid);
        assert_eq!(decoded.data, block.data);
    }

    #[tokio::test]
    async fn test_async_eof() {
        let empty: &[u8] = &[];
        let mut cursor = std::io::Cursor::new(empty);
        let result = async_io::read_block_with_limits(&mut cursor, &LimitsConfig::default())
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
