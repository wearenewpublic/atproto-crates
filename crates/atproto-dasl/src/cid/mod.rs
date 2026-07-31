//! CID (Content Identifier) support for DAG-CBOR.
//!
//! CIDs are encoded with tag 42 and a multibase identity prefix (0x00).
//! This module provides serialization/deserialization support.

use crate::errors::{DaslCidError, DecodeError};
pub use cid::Cid as CidCore;
/// CID version, re-exported alongside [`CidCore`] so callers can check it
/// without taking their own dependency on the `cid` crate.
pub use cid::Version as CidVersion;
use serde::{Deserialize, Serialize, de, ser};
use std::fmt;
use std::str::FromStr;

/// Multibase identity prefix byte
pub const MULTIBASE_IDENTITY: u8 = 0x00;

/// CBOR tag for CIDs in DAG-CBOR
pub const CID_CBOR_TAG: u64 = 42;

/// CID wrapper for DAG-CBOR serialization.
///
/// This wrapper ensures proper encoding of CIDs in DAG-CBOR format:
/// - Tag 42 (`0xd82a`)
/// - Byte string containing identity multibase prefix + CID bytes
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cid(pub CidCore);

impl Cid {
    /// Create from an existing cid::Cid
    pub fn new(cid: CidCore) -> Self {
        Self(cid)
    }

    /// Create from raw CID bytes (without identity multibase prefix)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let cid = CidCore::try_from(bytes).map_err(|e| DecodeError::InvalidCid {
            reason: e.to_string(),
        })?;
        Ok(Self(cid))
    }

    /// Get the inner cid::Cid
    pub fn inner(&self) -> &CidCore {
        &self.0
    }

    /// Consume and return the inner cid::Cid
    pub fn into_inner(self) -> CidCore {
        self.0
    }

    /// Get the raw CID bytes (without identity multibase prefix)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Convert to bytes with identity multibase prefix for DAG-CBOR encoding
    pub fn to_dag_cbor_bytes(&self) -> Vec<u8> {
        let cid_bytes = self.0.to_bytes();
        let mut result = Vec::with_capacity(1 + cid_bytes.len());
        result.push(MULTIBASE_IDENTITY);
        result.extend_from_slice(&cid_bytes);
        result
    }

    /// Parse from DAG-CBOR bytes (with identity prefix)
    pub fn from_dag_cbor_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::InvalidCid {
                reason: "empty bytes".to_string(),
            });
        }

        if bytes[0] != MULTIBASE_IDENTITY {
            return Err(DecodeError::InvalidCid {
                reason: format!("expected identity prefix 0x00, got 0x{:02x}", bytes[0]),
            });
        }

        let cid = CidCore::try_from(&bytes[1..]).map_err(|e| DecodeError::InvalidCid {
            reason: e.to_string(),
        })?;

        Ok(Self(cid))
    }
}

impl FromStr for Cid {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // DASL CID spec requires base32lower encoding (multibase prefix 'b')
        if !s.starts_with('b') {
            return Err(DecodeError::InvalidCid {
                reason: format!(
                    "DASL CIDs must use base32lower encoding (prefix 'b'), got '{}'",
                    s.chars().next().unwrap_or(' ')
                ),
            });
        }
        let cid = CidCore::try_from(s).map_err(|e| DecodeError::InvalidCid {
            reason: e.to_string(),
        })?;
        Ok(Self(cid))
    }
}

impl Serialize for Cid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        // Use newtype_variant to signal tag 42 to the DAG-CBOR serializer
        // The serializer will detect the magic variant name and emit tag 42
        serializer.serialize_newtype_variant(
            "__cid_tag_42__",
            CID_CBOR_TAG as u32,
            "",
            &CidBytes(self.to_dag_cbor_bytes()),
        )
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        // The deserializer handles tag 42 specially
        deserializer.deserialize_newtype_struct("__cid_tag_42__", CidVisitor)
    }
}

/// Helper struct for serializing CID bytes
struct CidBytes(Vec<u8>);

impl Serialize for CidBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct CidVisitor;

impl<'de> de::Visitor<'de> for CidVisitor {
    type Value = Cid;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CID with CBOR tag 42")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Cid::from_dag_cbor_bytes(v).map_err(de::Error::custom)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Cid::from_dag_cbor_bytes(&bytes).map_err(de::Error::custom)
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cid({})", self.0)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<CidCore> for Cid {
    fn from(cid: CidCore) -> Self {
        Self(cid)
    }
}

impl From<Cid> for CidCore {
    fn from(cid: Cid) -> Self {
        cid.0
    }
}

impl AsRef<CidCore> for Cid {
    fn as_ref(&self) -> &CidCore {
        &self.0
    }
}

impl std::ops::Deref for Cid {
    type Target = CidCore;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// DASL-constrained CID that enforces all DASL requirements at construction.
///
/// Unlike the general `Cid` wrapper, `DaslCid` guarantees that the contained
/// CID is always valid per the strict DASL CID spec:
/// - CIDv1 only
/// - Codec: raw (0x55) or dag-cbor (0x71)
/// - Hash: SHA-256 (0x12) only
/// - Digest: exactly 32 bytes
///
/// For BLAKE3 (0x1e) large-file CIDs, use [`crate::bdasl::BdaslCid`] instead.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DaslCid(CidCore);

impl DaslCid {
    /// Create a DaslCid from a CidCore, validating DASL constraints.
    ///
    /// # Errors
    ///
    /// Returns `DaslCidError` if the CID violates any DASL constraint.
    pub fn new(cid: CidCore) -> Result<Self, DaslCidError> {
        Self::validate(&cid)?;
        Ok(Self(cid))
    }

    /// Create a DaslCid from raw bytes, validating DASL constraints.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DaslCidError> {
        let cid = CidCore::try_from(bytes).map_err(|e| DaslCidError::InvalidCid {
            reason: e.to_string(),
        })?;
        Self::new(cid)
    }

    /// Create a DaslCid by computing SHA-256 hash of dag-cbor data.
    pub fn from_dag_cbor_sha256(data: &[u8]) -> Self {
        Self(compute_cid(data))
    }

    /// Create a DaslCid by computing SHA-256 hash of raw data.
    pub fn from_raw_sha256(data: &[u8]) -> Self {
        Self(compute_raw_cid(data))
    }

    /// Get the inner CidCore reference.
    pub fn inner(&self) -> &CidCore {
        &self.0
    }

    /// Consume and return the inner CidCore.
    pub fn into_inner(self) -> CidCore {
        self.0
    }

    /// Convert to a general Cid wrapper.
    pub fn into_cid(self) -> Cid {
        Cid(self.0)
    }

    /// Verify that data matches this CID.
    pub fn verify_bytes(&self, data: &[u8]) -> Result<(), DecodeError> {
        verify_cid_bytes(&self.0, data)
    }

    fn validate(cid: &CidCore) -> Result<(), DaslCidError> {
        if cid.version() != cid::Version::V1 {
            return Err(DaslCidError::NotCidV1);
        }

        let codec = cid.codec();
        if codec != RAW_CODEC && codec != DAG_CBOR_CODEC {
            return Err(DaslCidError::InvalidCodec { codec });
        }

        let hash = cid.hash();
        let hash_code = hash.code();
        if hash_code != SHA256_CODE {
            return Err(DaslCidError::InvalidHash { hash: hash_code });
        }

        if hash.digest().len() != 32 {
            return Err(DaslCidError::InvalidDigestLength {
                len: hash.digest().len(),
            });
        }

        Ok(())
    }
}

impl fmt::Debug for DaslCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DaslCid({})", self.0)
    }
}

impl fmt::Display for DaslCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for DaslCid {
    type Target = CidCore;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<CidCore> for DaslCid {
    fn as_ref(&self) -> &CidCore {
        &self.0
    }
}

impl From<DaslCid> for Cid {
    fn from(dasl_cid: DaslCid) -> Self {
        Cid(dasl_cid.0)
    }
}

impl From<DaslCid> for CidCore {
    fn from(dasl_cid: DaslCid) -> Self {
        dasl_cid.0
    }
}

impl TryFrom<CidCore> for DaslCid {
    type Error = DaslCidError;

    fn try_from(cid: CidCore) -> Result<Self, Self::Error> {
        Self::new(cid)
    }
}

impl TryFrom<Cid> for DaslCid {
    type Error = DaslCidError;

    fn try_from(cid: Cid) -> Result<Self, Self::Error> {
        Self::new(cid.0)
    }
}

impl FromStr for DaslCid {
    type Err = DaslCidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // DASL CID spec requires base32lower encoding (multibase prefix 'b')
        if !s.starts_with('b') {
            return Err(DaslCidError::InvalidCid {
                reason: format!(
                    "DASL CIDs must use base32lower encoding (prefix 'b'), got '{}'",
                    s.chars().next().unwrap_or(' ')
                ),
            });
        }
        let cid = CidCore::try_from(s).map_err(|e| DaslCidError::InvalidCid {
            reason: e.to_string(),
        })?;
        Self::new(cid)
    }
}

/// An unvalidated CID for decoding non-DASL CIDs from DRISL data.
///
/// Unlike [`Cid`] and [`DaslCid`], `RawCid` stores arbitrary CID bytes
/// without enforcing any DASL constraints. This allows lossless decoding
/// of CBOR data containing CIDv0 or CIDs with non-standard codecs/hashes.
///
/// Use [`crate::DecodeConfig::with_use_raw_cid`] to decode CIDs as `RawCid`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RawCid(Vec<u8>);

impl RawCid {
    /// Create a RawCid from raw CID bytes (without identity multibase prefix).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw CID bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the raw CID bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Try to convert to a standard CID wrapper.
    ///
    /// Returns `None` if the bytes are not a valid CID.
    pub fn to_cid(&self) -> Option<Cid> {
        Cid::from_bytes(&self.0).ok()
    }

    /// Try to convert to a DASL-validated CID.
    ///
    /// Returns `None` if the CID is not valid or doesn't meet DASL constraints.
    pub fn to_dasl_cid(&self) -> Option<DaslCid> {
        DaslCid::from_bytes(&self.0).ok()
    }

    /// Convert to bytes with identity multibase prefix for DAG-CBOR encoding.
    pub fn to_dag_cbor_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.0.len());
        result.push(MULTIBASE_IDENTITY);
        result.extend_from_slice(&self.0);
        result
    }

    /// Parse from DAG-CBOR bytes (with identity prefix).
    pub fn from_dag_cbor_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::InvalidCid {
                reason: "empty bytes".to_string(),
            });
        }

        if bytes[0] != MULTIBASE_IDENTITY {
            return Err(DecodeError::InvalidCid {
                reason: format!("expected identity prefix 0x00, got 0x{:02x}", bytes[0]),
            });
        }

        Ok(Self(bytes[1..].to_vec()))
    }
}

impl fmt::Debug for RawCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as a CID string, fall back to hex
        if let Some(cid) = self.to_cid() {
            write!(f, "RawCid({})", cid)
        } else {
            write!(f, "RawCid(0x{})", hex_encode(&self.0))
        }
    }
}

impl fmt::Display for RawCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Try to display as a CID string, fall back to hex
        if let Some(cid) = self.to_cid() {
            write!(f, "{}", cid)
        } else {
            write!(f, "0x{}", hex_encode(&self.0))
        }
    }
}

/// Simple hex encoding for display purposes.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

impl Serialize for RawCid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_newtype_variant(
            "__cid_tag_42__",
            CID_CBOR_TAG as u32,
            "",
            &RawCidBytes(self.to_dag_cbor_bytes()),
        )
    }
}

/// Helper struct for serializing RawCid bytes.
struct RawCidBytes(Vec<u8>);

impl Serialize for RawCidBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for RawCid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_newtype_struct("__cid_tag_42__", RawCidVisitor)
    }
}

struct RawCidVisitor;

impl<'de> de::Visitor<'de> for RawCidVisitor {
    type Value = RawCid;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a raw CID with CBOR tag 42")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        RawCid::from_dag_cbor_bytes(v).map_err(de::Error::custom)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        RawCid::from_dag_cbor_bytes(&bytes).map_err(de::Error::custom)
    }
}

impl From<Vec<u8>> for RawCid {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<RawCid> for Vec<u8> {
    fn from(raw: RawCid) -> Self {
        raw.0
    }
}

/// JSON serialization for CIDs using the AT Protocol `$link` format.
///
/// Serializes CIDs as `{"$link": "<cid-string>"}` and deserializes
/// from the same format. Use with `#[serde(with = "atproto_dasl::cid::json")]`.
///
/// # Example
///
/// ```rust
/// use atproto_dasl::cid::{Cid, json};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Record {
///     #[serde(with = "atproto_dasl::cid::json")]
///     link: Cid,
/// }
/// ```
pub mod json {
    use super::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
    use std::collections::BTreeMap;

    /// Serialize a CID as `{"$link": "<cid-string>"}`.
    pub fn serialize<S: Serializer>(cid: &Cid, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = BTreeMap::new();
        map.insert("$link", cid.0.to_string());
        map.serialize(serializer)
    }

    /// Deserialize a CID from `{"$link": "<cid-string>"}`.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cid, D::Error> {
        let map: BTreeMap<String, String> = BTreeMap::deserialize(deserializer)?;
        let link = map
            .get("$link")
            .ok_or_else(|| de::Error::missing_field("$link"))?;
        link.parse::<Cid>().map_err(de::Error::custom)
    }

    /// Serialize an optional CID as `{"$link": "<cid-string>"}` or null.
    pub mod option {
        use super::*;

        /// Serialize an optional CID.
        pub fn serialize<S: Serializer>(
            cid: &Option<Cid>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match cid {
                Some(c) => {
                    let mut map = BTreeMap::new();
                    map.insert("$link", c.0.to_string());
                    map.serialize(serializer)
                }
                None => serializer.serialize_none(),
            }
        }

        /// Deserialize an optional CID.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Cid>, D::Error> {
            let opt: Option<BTreeMap<String, String>> = Option::deserialize(deserializer)?;
            match opt {
                None => Ok(None),
                Some(map) => {
                    let link = map
                        .get("$link")
                        .ok_or_else(|| de::Error::missing_field("$link"))?;
                    let cid: Cid = link.parse().map_err(de::Error::custom)?;
                    Ok(Some(cid))
                }
            }
        }
    }
}

/// DAG-CBOR multicodec identifier (0x71).
pub const DAG_CBOR_CODEC: u64 = 0x71;

/// Raw multicodec identifier (0x55).
pub const RAW_CODEC: u64 = 0x55;

/// SHA-256 multihash code (0x12).
pub const SHA256_CODE: u64 = 0x12;

/// BLAKE3 multihash code (0x1e).
pub const BLAKE3_CODE: u64 = 0x1e;

/// Allowed DASL CID codecs.
const DASL_CODECS: &[u64] = &[RAW_CODEC, DAG_CBOR_CODEC];

/// Allowed DASL CID hash algorithms (SHA-256 only per the CID spec).
const DASL_HASHES: &[u64] = &[SHA256_CODE];

/// Allowed DASL or BDASL CID hash algorithms (SHA-256 + BLAKE3).
const DASL_OR_BDASL_HASHES: &[u64] = &[SHA256_CODE, BLAKE3_CODE];

/// Validate that a CID meets strict DASL CID constraints.
///
/// DASL CIDs must be:
/// - CIDv1 (not CIDv0)
/// - Codec raw (0x55) or dag-cbor (0x71)
/// - Hash SHA-256 (0x12) only
/// - Digest exactly 32 bytes
///
/// Use [`validate_dasl_or_bdasl_cid`] if BLAKE3 (0x1e) should also be accepted.
pub fn validate_dasl_cid(cid: &CidCore) -> Result<(), DecodeError> {
    validate_cid_with_hashes(cid, DASL_HASHES)
}

/// Validate that a CID meets DASL or BDASL CID constraints.
///
/// Accepts both SHA-256 (0x12) and BLAKE3 (0x1e) hash algorithms.
/// Use this when processing content that may include BDASL large-file CIDs.
pub fn validate_dasl_or_bdasl_cid(cid: &CidCore) -> Result<(), DecodeError> {
    validate_cid_with_hashes(cid, DASL_OR_BDASL_HASHES)
}

/// Shared CID validation logic with configurable allowed hashes.
fn validate_cid_with_hashes(cid: &CidCore, allowed_hashes: &[u64]) -> Result<(), DecodeError> {
    if cid.version() != cid::Version::V1 {
        return Err(DecodeError::InvalidCid {
            reason: "DASL requires CIDv1".into(),
        });
    }

    if !DASL_CODECS.contains(&cid.codec()) {
        return Err(DecodeError::InvalidCid {
            reason: format!("codec 0x{:x} not allowed in DASL", cid.codec()),
        });
    }

    let hash = cid.hash();
    if !allowed_hashes.contains(&hash.code()) {
        return Err(DecodeError::InvalidCid {
            reason: format!("hash 0x{:x} not allowed in DASL", hash.code()),
        });
    }

    if hash.digest().len() != 32 {
        return Err(DecodeError::InvalidCid {
            reason: format!("digest length {} != 32", hash.digest().len()),
        });
    }

    Ok(())
}

/// Compute a CIDv1 with dag-cbor codec and sha2-256 hash.
///
/// This is the "blessed" CID format used by AT Protocol.
pub fn compute_cid(data: &[u8]) -> CidCore {
    use multihash::Multihash;
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(data);
    let mh = Multihash::<64>::wrap(SHA256_CODE, &hash)
        .expect("SHA256 hash should always fit in Multihash<64>");
    CidCore::new_v1(DAG_CBOR_CODEC, mh)
}

/// Serialize a value to DAG-CBOR and compute its CID.
///
/// Convenience function that combines DAG-CBOR serialization with CID
/// computation. The resulting CID uses CIDv1 with dag-cbor codec (0x71)
/// and sha2-256 hash.
///
/// # Errors
///
/// Returns `EncodeError` if DAG-CBOR serialization fails.
pub fn compute_cid_for<T: serde::Serialize>(value: &T) -> Result<CidCore, crate::EncodeError> {
    let bytes = crate::to_vec(value)?;
    Ok(compute_cid(&bytes))
}

/// Compute a CIDv1 with dag-cbor codec and BLAKE3 hash.
///
/// Uses the BLAKE3 hash algorithm instead of SHA-256. BLAKE3 is accepted
/// by the DASL specification as an alternative hash algorithm.
pub fn compute_cid_blake3(data: &[u8]) -> CidCore {
    use multihash::Multihash;

    let hash = blake3::hash(data);
    let mh = Multihash::<64>::wrap(BLAKE3_CODE, hash.as_bytes())
        .expect("BLAKE3 hash should always fit in Multihash<64>");
    CidCore::new_v1(DAG_CBOR_CODEC, mh)
}

/// Compute a CIDv1 with raw codec and sha2-256 hash.
///
/// Used for raw (non-CBOR) content like images and blobs.
pub fn compute_raw_cid(data: &[u8]) -> CidCore {
    use multihash::Multihash;
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(data);
    let mh = Multihash::<64>::wrap(SHA256_CODE, &hash)
        .expect("SHA256 hash should always fit in Multihash<64>");
    CidCore::new_v1(RAW_CODEC, mh)
}

/// Compute a CIDv1 with raw codec and BLAKE3 hash.
///
/// Used for raw (non-CBOR) content like images and blobs, using BLAKE3.
pub fn compute_raw_cid_blake3(data: &[u8]) -> CidCore {
    use multihash::Multihash;

    let hash = blake3::hash(data);
    let mh = Multihash::<64>::wrap(BLAKE3_CODE, hash.as_bytes())
        .expect("BLAKE3 hash should always fit in Multihash<64>");
    CidCore::new_v1(RAW_CODEC, mh)
}

/// Verify that data matches a given CID.
///
/// Recomputes the hash of the data using the CID's hash algorithm and codec,
/// then compares the resulting CID with the expected one.
///
/// # Errors
///
/// Returns `DecodeError::InvalidCid` if the CID uses an unsupported hash
/// algorithm, or if the computed CID does not match.
pub fn verify_cid_bytes(cid: &CidCore, data: &[u8]) -> Result<(), DecodeError> {
    use multihash::Multihash;
    use sha2::{Digest, Sha256};

    let hash_code = cid.hash().code();
    let digest = match hash_code {
        SHA256_CODE => {
            let hash = Sha256::digest(data);
            Multihash::<64>::wrap(SHA256_CODE, &hash).map_err(|e| DecodeError::InvalidCid {
                reason: e.to_string(),
            })?
        }
        BLAKE3_CODE => {
            let hash = blake3::hash(data);
            Multihash::<64>::wrap(BLAKE3_CODE, hash.as_bytes()).map_err(|e| {
                DecodeError::InvalidCid {
                    reason: e.to_string(),
                }
            })?
        }
        _ => {
            return Err(DecodeError::InvalidCid {
                reason: format!("unsupported hash algorithm: 0x{:x}", hash_code),
            });
        }
    };

    let computed = CidCore::new_v1(cid.codec(), digest);
    if &computed != cid {
        return Err(DecodeError::InvalidCid {
            reason: format!("CID mismatch: expected {}, computed {}", cid, computed),
        });
    }

    Ok(())
}

/// Verify that data from a reader matches a given CID.
///
/// Reads data from the reader, computes the hash, and compares with the
/// expected CID.
///
/// # Errors
///
/// Returns `DecodeError::InvalidCid` if the hash algorithm is unsupported
/// or the CID doesn't match. Returns `DecodeError::Io` on read errors.
pub fn verify_cid_reader<R: std::io::Read>(
    cid: &CidCore,
    mut reader: R,
) -> Result<(), DecodeError> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    verify_cid_bytes(cid, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::Multihash;

    fn create_test_cid() -> CidCore {
        // Create a simple CIDv1 with identity hash
        let hash = Multihash::<64>::wrap(0x12, &[0u8; 32]).unwrap();
        CidCore::new_v1(0x71, hash)
    }

    #[test]
    fn test_cid_roundtrip() {
        let original = create_test_cid();
        let cid = Cid::new(original);

        let bytes = cid.to_dag_cbor_bytes();
        assert_eq!(bytes[0], MULTIBASE_IDENTITY);

        let decoded = Cid::from_dag_cbor_bytes(&bytes).unwrap();
        assert_eq!(decoded.0, original);
    }

    #[test]
    fn test_cid_missing_identity_prefix() {
        let cid = create_test_cid();
        let bytes = cid.to_bytes(); // Raw bytes without identity prefix

        let result = Cid::from_dag_cbor_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_cid_empty_bytes() {
        let result = Cid::from_dag_cbor_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cid_from_str_base32lower() {
        let cid = Cid::new(compute_cid(b"test"));
        let s = cid.to_string();
        assert!(s.starts_with('b'));
        let parsed: Cid = s.parse().unwrap();
        assert_eq!(parsed, cid);
    }

    #[test]
    fn test_cid_from_str_rejects_non_base32lower() {
        // base58btc starts with 'z'
        let result = "zQmTest".parse::<Cid>();
        assert!(result.is_err());

        // base64 starts with 'm'
        let result = "mTest".parse::<Cid>();
        assert!(result.is_err());

        // empty string
        let result = "".parse::<Cid>();
        assert!(result.is_err());
    }

    #[test]
    fn test_cid_conversions() {
        let original = create_test_cid();
        let cid = Cid::from(original);
        let back: CidCore = cid.into();
        assert_eq!(back, original);
    }

    #[test]
    fn test_compute_cid_sha256() {
        let data = b"hello world";
        let cid = compute_cid(data);
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR_CODEC);
        assert_eq!(cid.hash().code(), SHA256_CODE);
        assert_eq!(cid.hash().digest().len(), 32);
    }

    #[test]
    fn test_compute_cid_blake3() {
        let data = b"hello world";
        let cid = compute_cid_blake3(data);
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR_CODEC);
        assert_eq!(cid.hash().code(), BLAKE3_CODE);
        assert_eq!(cid.hash().digest().len(), 32);
    }

    #[test]
    fn test_compute_raw_cid() {
        let data = b"raw content";
        let cid = compute_raw_cid(data);
        assert_eq!(cid.codec(), RAW_CODEC);
        assert_eq!(cid.hash().code(), SHA256_CODE);
    }

    #[test]
    fn test_compute_raw_cid_blake3() {
        let data = b"raw content";
        let cid = compute_raw_cid_blake3(data);
        assert_eq!(cid.codec(), RAW_CODEC);
        assert_eq!(cid.hash().code(), BLAKE3_CODE);
    }

    #[test]
    fn test_verify_cid_bytes_sha256() {
        let data = b"hello world";
        let cid = compute_cid(data);
        assert!(verify_cid_bytes(&cid, data).is_ok());
        assert!(verify_cid_bytes(&cid, b"wrong data").is_err());
    }

    #[test]
    fn test_verify_cid_bytes_blake3() {
        let data = b"hello world";
        let cid = compute_cid_blake3(data);
        assert!(verify_cid_bytes(&cid, data).is_ok());
        assert!(verify_cid_bytes(&cid, b"wrong data").is_err());
    }

    #[test]
    fn test_verify_cid_reader() {
        let data = b"hello world";
        let cid = compute_cid(data);
        assert!(verify_cid_reader(&cid, &data[..]).is_ok());
        assert!(verify_cid_reader(&cid, &b"wrong data"[..]).is_err());
    }

    #[test]
    fn test_validate_dasl_cid_valid() {
        let cid = compute_cid(b"test");
        assert!(validate_dasl_cid(&cid).is_ok());

        let cid = compute_raw_cid(b"test");
        assert!(validate_dasl_cid(&cid).is_ok());
    }

    #[test]
    fn test_validate_dasl_cid_rejects_blake3() {
        let cid = compute_cid_blake3(b"test");
        assert!(validate_dasl_cid(&cid).is_err());

        let cid = compute_raw_cid_blake3(b"test");
        assert!(validate_dasl_cid(&cid).is_err());
    }

    #[test]
    fn test_validate_dasl_or_bdasl_cid_accepts_blake3() {
        let cid = compute_cid_blake3(b"test");
        assert!(validate_dasl_or_bdasl_cid(&cid).is_ok());

        let cid = compute_raw_cid_blake3(b"test");
        assert!(validate_dasl_or_bdasl_cid(&cid).is_ok());

        // Also accepts SHA-256
        let cid = compute_cid(b"test");
        assert!(validate_dasl_or_bdasl_cid(&cid).is_ok());
    }

    #[test]
    fn test_dasl_cid_construction() {
        let dasl = DaslCid::from_dag_cbor_sha256(b"hello");
        assert_eq!(dasl.codec(), DAG_CBOR_CODEC);
        assert_eq!(dasl.hash().code(), SHA256_CODE);

        let dasl = DaslCid::from_raw_sha256(b"hello");
        assert_eq!(dasl.codec(), RAW_CODEC);
        assert_eq!(dasl.hash().code(), SHA256_CODE);
    }

    #[test]
    fn test_dasl_cid_rejects_blake3() {
        let blake3_cid = compute_cid_blake3(b"hello");
        assert!(DaslCid::new(blake3_cid).is_err());
    }

    #[test]
    fn test_dasl_cid_rejects_invalid() {
        // CIDv0 (identity hash, dag-pb codec)
        let hash = Multihash::<64>::wrap(0x00, &[0u8; 32]).unwrap();
        let v0_like = CidCore::new_v1(0x70, hash); // dag-pb codec
        assert!(DaslCid::new(v0_like).is_err());

        // Wrong codec
        let hash = Multihash::<64>::wrap(SHA256_CODE, &[0u8; 32]).unwrap();
        let bad_codec = CidCore::new_v1(0x70, hash); // dag-pb
        assert!(DaslCid::new(bad_codec).is_err());

        // Wrong hash
        let hash = Multihash::<64>::wrap(0x00, &[0u8; 32]).unwrap(); // identity
        let bad_hash = CidCore::new_v1(DAG_CBOR_CODEC, hash);
        assert!(DaslCid::new(bad_hash).is_err());

        // Wrong digest length
        let hash = Multihash::<64>::wrap(SHA256_CODE, &[0u8; 16]).unwrap();
        let bad_digest = CidCore::new_v1(DAG_CBOR_CODEC, hash);
        assert!(DaslCid::new(bad_digest).is_err());
    }

    #[test]
    fn test_dasl_cid_verify() {
        let data = b"hello world";
        let dasl = DaslCid::from_dag_cbor_sha256(data);
        assert!(dasl.verify_bytes(data).is_ok());
        assert!(dasl.verify_bytes(b"wrong").is_err());
    }

    #[test]
    fn test_dasl_cid_conversions() {
        let dasl = DaslCid::from_dag_cbor_sha256(b"test");
        let cid: Cid = dasl.clone().into();
        let core: CidCore = dasl.clone().into();
        assert_eq!(*dasl.inner(), core);
        assert_eq!(cid.0, core);

        // TryFrom back
        let back: DaslCid = DaslCid::try_from(core).unwrap();
        assert_eq!(back, dasl);
    }

    // --- RawCid tests ---

    #[test]
    fn test_raw_cid_roundtrip() {
        let original = create_test_cid();
        let raw = RawCid::from_bytes(original.to_bytes());

        let dag_cbor_bytes = raw.to_dag_cbor_bytes();
        assert_eq!(dag_cbor_bytes[0], MULTIBASE_IDENTITY);

        let decoded = RawCid::from_dag_cbor_bytes(&dag_cbor_bytes).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_raw_cid_to_cid() {
        let original = create_test_cid();
        let raw = RawCid::from_bytes(original.to_bytes());
        let cid = raw.to_cid().unwrap();
        assert_eq!(cid.0, original);
    }

    #[test]
    fn test_raw_cid_to_dasl_cid() {
        let dasl = DaslCid::from_dag_cbor_sha256(b"test");
        let raw = RawCid::from_bytes(dasl.inner().to_bytes());
        assert!(raw.to_dasl_cid().is_some());
    }

    #[test]
    fn test_raw_cid_invalid_bytes() {
        // Non-standard bytes that aren't a valid CID
        let raw = RawCid::from_bytes(vec![0xff, 0x01, 0x02]);
        assert!(raw.to_cid().is_none());
        assert!(raw.to_dasl_cid().is_none());
    }

    #[test]
    fn test_raw_cid_empty_dag_cbor_bytes() {
        let result = RawCid::from_dag_cbor_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_cid_display() {
        let original = create_test_cid();
        let raw = RawCid::from_bytes(original.to_bytes());
        let display = format!("{}", raw);
        // Should display as CID string since it's a valid CID
        assert!(!display.is_empty());
        assert!(!display.starts_with("0x"));
    }

    #[test]
    fn test_raw_cid_display_invalid() {
        let raw = RawCid::from_bytes(vec![0xff, 0x01]);
        let display = format!("{}", raw);
        // Should fall back to hex
        assert!(display.starts_with("0x"));
    }

    // --- JSON CID tests ---

    #[test]
    fn test_json_cid_roundtrip() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Record {
            #[serde(with = "json")]
            link: Cid,
        }

        let cid = Cid::new(compute_cid(b"hello"));
        let record = Record { link: cid.clone() };

        let json_str = serde_json::to_string(&record).unwrap();
        assert!(json_str.contains("$link"));

        let decoded: Record = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.link, cid);
    }

    #[test]
    fn test_json_cid_format() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct Record {
            #[serde(with = "json")]
            link: Cid,
        }

        let cid = Cid::new(compute_cid(b"test"));
        let record = Record { link: cid.clone() };

        let json_str = serde_json::to_string(&record).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Should be {"link": {"$link": "<cid-string>"}}
        let link_obj = parsed.get("link").unwrap().as_object().unwrap();
        assert!(link_obj.contains_key("$link"));
        assert_eq!(link_obj.len(), 1);
    }

    #[test]
    fn test_json_cid_option_some() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Record {
            #[serde(with = "json::option", default)]
            link: Option<Cid>,
        }

        let cid = Cid::new(compute_cid(b"hello"));
        let record = Record {
            link: Some(cid.clone()),
        };

        let json_str = serde_json::to_string(&record).unwrap();
        let decoded: Record = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.link, Some(cid));
    }

    #[test]
    fn test_json_cid_option_none() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Record {
            #[serde(with = "json::option", default)]
            link: Option<Cid>,
        }

        let record = Record { link: None };
        let json_str = serde_json::to_string(&record).unwrap();
        let decoded: Record = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.link, None);
    }

    #[test]
    fn test_json_cid_missing_link_field() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Record {
            #[serde(with = "json")]
            #[allow(dead_code)]
            link: Cid,
        }

        // Missing $link field
        let json_str = r#"{"link": {"wrong": "field"}}"#;
        assert!(serde_json::from_str::<Record>(json_str).is_err());
    }
}
