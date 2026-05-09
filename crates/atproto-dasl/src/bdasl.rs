//! BDASL (Big DASL).
//!
//! Extends DASL CIDs with BLAKE3 hashing for large files, including
//! streaming verification capabilities using 1024-byte chunk granularity.
//!
//! BDASL uses BLAKE3 BAO (BLAKE3 Authenticated and Ordered) tree hashing to
//! enable streaming verification of large files without needing the entire file
//! in memory. The specification defines a 1024-byte chunk size for verification
//! operations.
//!
//! See <https://dasl.ing/bdasl.html> for the specification.

use crate::cid::{BLAKE3_CODE, CidCore, RAW_CODEC};

/// BDASL chunk size in bytes for streaming verification.
///
/// All BDASL streaming verification operates at 1024-byte granularity.
/// For HTTP range requests, byte ranges map to chunk ranges using ceiling
/// division.
pub const CHUNK_SIZE: usize = 1024;

/// BDASL hash type identifier.
///
/// BDASL supports BLAKE3 BAO tree hashing for streaming verification
/// of large files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BdaslHashType {
    /// Standard BLAKE3 hash (0x1e).
    Blake3,
    /// BLAKE3 BAO tree hash for streaming verification.
    /// Uses the same multihash code as BLAKE3 but with BAO-specific structure.
    Blake3Bao,
}

impl BdaslHashType {
    /// Get the multihash code for this hash type.
    pub fn code(&self) -> u64 {
        match self {
            BdaslHashType::Blake3 | BdaslHashType::Blake3Bao => BLAKE3_CODE,
        }
    }
}

/// A BDASL CID for large content.
///
/// BDASL CIDs always use the raw codec and BLAKE3 hash, with optional
/// BAO tree structure for streaming verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdaslCid {
    /// The underlying CID.
    cid: CidCore,
    /// The hash type used.
    hash_type: BdaslHashType,
}

impl BdaslCid {
    /// Create a BDASL CID from raw data using standard BLAKE3.
    pub fn from_data(data: &[u8]) -> Self {
        let cid = crate::cid::compute_raw_cid_blake3(data);
        Self {
            cid,
            hash_type: BdaslHashType::Blake3,
        }
    }

    /// Get the underlying CID.
    pub fn cid(&self) -> &CidCore {
        &self.cid
    }

    /// Get the hash type.
    pub fn hash_type(&self) -> BdaslHashType {
        self.hash_type
    }

    /// Verify that data matches this BDASL CID.
    pub fn verify(&self, data: &[u8]) -> bool {
        crate::cid::verify_cid_bytes(&self.cid, data).is_ok()
    }
}

/// Result of a streaming verification operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Verification succeeded.
    Valid,
    /// Verification failed — data does not match the expected hash.
    Invalid,
    /// More data is needed to complete verification.
    Incomplete,
}

/// Trait for streaming content verification.
///
/// Implementations of this trait allow verifying large files incrementally
/// without loading the entire file into memory.
pub trait StreamVerifier: Send + Sync {
    /// Feed a chunk of data to the verifier.
    fn update(&mut self, data: &[u8]);

    /// Finalize verification and check against the expected CID.
    fn finalize(self: Box<Self>) -> VerificationResult;

    /// Get the expected CID.
    fn expected_cid(&self) -> &CidCore;
}

/// A basic BLAKE3 stream verifier (non-BAO).
///
/// Accumulates a BLAKE3 hash incrementally and checks it against an expected CID.
pub struct Blake3Verifier {
    hasher: blake3::Hasher,
    expected: CidCore,
}

impl Blake3Verifier {
    /// Create a new verifier for the given CID.
    pub fn new(expected: CidCore) -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            expected,
        }
    }
}

impl StreamVerifier for Blake3Verifier {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self: Box<Self>) -> VerificationResult {
        use multihash::Multihash;

        let hash = self.hasher.finalize();
        let mh = match Multihash::<64>::wrap(BLAKE3_CODE, hash.as_bytes()) {
            Ok(mh) => mh,
            Err(_) => return VerificationResult::Invalid,
        };
        let computed = CidCore::new_v1(RAW_CODEC, mh);
        if computed == self.expected {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        }
    }

    fn expected_cid(&self) -> &CidCore {
        &self.expected
    }
}

/// Compute the chunk index for a byte offset.
///
/// Uses ceiling division: `chunk = ceil(byte_offset / CHUNK_SIZE)`.
/// This is used to map HTTP byte ranges to BDASL chunk ranges.
#[must_use]
pub fn byte_to_chunk(byte_offset: u64) -> u64 {
    byte_offset.div_ceil(CHUNK_SIZE as u64)
}

/// Compute the chunk range for a byte range.
///
/// Returns `(start_chunk, end_chunk)` using ceiling division per the BDASL
/// spec. Returned data includes complete interior chunks with boundary
/// chunks truncated to exact byte offsets.
#[must_use]
pub fn byte_range_to_chunks(start_byte: u64, end_byte: u64) -> (u64, u64) {
    (byte_to_chunk(start_byte), byte_to_chunk(end_byte))
}

/// Compute the total number of chunks for a given data length.
#[must_use]
pub fn chunk_count(data_len: u64) -> u64 {
    if data_len == 0 {
        return 0;
    }
    data_len.div_ceil(CHUNK_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bdasl_cid_from_data() {
        let data = b"hello world bdasl";
        let cid = BdaslCid::from_data(data);
        assert_eq!(cid.hash_type(), BdaslHashType::Blake3);
        assert!(cid.verify(data));
        assert!(!cid.verify(b"wrong data"));
    }

    #[test]
    fn test_blake3_verifier() {
        let data = b"streaming verification test";
        let cid = crate::cid::compute_raw_cid_blake3(data);

        let mut verifier = Box::new(Blake3Verifier::new(cid));
        verifier.update(&data[..10]);
        verifier.update(&data[10..]);
        assert_eq!(verifier.finalize(), VerificationResult::Valid);

        // Wrong data
        let mut verifier = Box::new(Blake3Verifier::new(cid));
        verifier.update(b"wrong data");
        assert_eq!(verifier.finalize(), VerificationResult::Invalid);
    }

    #[test]
    fn test_hash_type_code() {
        assert_eq!(BdaslHashType::Blake3.code(), BLAKE3_CODE);
        assert_eq!(BdaslHashType::Blake3Bao.code(), BLAKE3_CODE);
    }

    #[test]
    fn test_chunk_size() {
        assert_eq!(CHUNK_SIZE, 1024);
    }

    #[test]
    fn test_byte_to_chunk() {
        assert_eq!(byte_to_chunk(0), 0);
        assert_eq!(byte_to_chunk(1), 1);
        assert_eq!(byte_to_chunk(1023), 1);
        assert_eq!(byte_to_chunk(1024), 1);
        assert_eq!(byte_to_chunk(1025), 2);
        assert_eq!(byte_to_chunk(2048), 2);
        assert_eq!(byte_to_chunk(2049), 3);
    }

    #[test]
    fn test_byte_range_to_chunks() {
        assert_eq!(byte_range_to_chunks(0, 1024), (0, 1));
        assert_eq!(byte_range_to_chunks(1, 2048), (1, 2));
        assert_eq!(byte_range_to_chunks(1024, 3072), (1, 3));
    }

    #[test]
    fn test_chunk_count() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(1024), 1);
        assert_eq!(chunk_count(1025), 2);
        assert_eq!(chunk_count(10240), 10);
        assert_eq!(chunk_count(10241), 11);
    }
}
