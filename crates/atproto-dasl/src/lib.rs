//! DASL (Data-Addressed Structures & Links) implementation for AT Protocol.
//!
//! This crate implements the [DASL framework](https://dasl.ing/) specifications:
//!
//! - **CID**: Content Identifiers - hashes with metadata for addressing resources by content
//! - **DRISL**: Deterministic Representation for Interoperable Structures and Links -
//!   deterministic CBOR encoding/decoding with serde integration
//! - **CAR**: Content-Addressable aRchives - serialized sets of content-addressed resources
//! - **MASL**: Metadata for Arbitrary Structures & Links - CBOR metadata documents
//! - **RASL**: Retrieval of Arbitrary Structures & Links - URL scheme and HTTP retrieval
//! - **BDASL**: Big DASL - large file hashing with streaming verification
//! - **Web Tiles**: Composable web documents and applications with security constraints
//!
//! # Example Usage
//!
//! ```rust
//! use atproto_dasl::{to_vec, from_slice};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, Debug, PartialEq)]
//! struct Post {
//!     text: String,
//!     likes: u64,
//! }
//!
//! let post = Post { text: "Hello!".into(), likes: 42 };
//!
//! // Serialize to DAG-CBOR bytes
//! let bytes = to_vec(&post).unwrap();
//!
//! // Deserialize back
//! let decoded: Post = from_slice(&bytes).unwrap();
//! assert_eq!(post, decoded);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Core DASL modules
pub mod atproto_json;
pub mod cid;
pub mod drisl;
pub mod errors;
pub mod value;

// CAR and storage
pub mod car;
pub mod storage;
pub mod varint;

// DASL specification modules
pub mod bdasl;
pub mod masl;
pub mod rasl;
pub mod tiles;

// Re-export primary types at crate root for ergonomics
pub use atproto_json::{ipld_from_json, json_from_ipld};
pub use cid::{
    Cid, CidCore, DAG_CBOR_CODEC, DaslCid, MULTIBASE_IDENTITY, RawCid, compute_cid_blake3,
    compute_cid_for, compute_raw_cid, compute_raw_cid_blake3, verify_cid_bytes, verify_cid_reader,
};
pub use drisl::{
    DEFAULT_MAX_ARRAY_ELEMENTS, DEFAULT_MAX_MAP_ENTRIES, DecodeConfig, EncodeConfig, TimeMode,
    from_reader, from_reader_non_strict, from_reader_with_config, from_slice,
    from_slice_non_strict, from_slice_with_config, to_vec, to_vec_with_config, to_writer,
    to_writer_with_config,
};
pub use errors::{
    CarError, DaslCidError, DecodeError, EncodeError, MaslError, RaslError, StorageError,
    TilesError, VarintError,
};
pub use value::Ipld;

// Re-export CAR and storage types
pub use car::{CarBlock, CarConfig, CarHeader, CarReader, CarWriter, LimitsConfig};
pub use storage::{BlockStorage, DiskStorage, MemoryStorage, SpillableBuffer, SpillableReader};

// Conditional re-exports for RASL features
#[cfg(feature = "reqwest")]
pub use rasl::fetch::{fetch_verified, fetch_verified_with_client};

#[cfg(feature = "axum")]
pub use rasl::handler::{directory_handler, func_handler, redirect_handler};

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_roundtrip_primitives() {
        // Boolean
        let bytes = to_vec(&true).unwrap();
        assert!(from_slice::<bool>(&bytes).unwrap());

        // Integer
        let bytes = to_vec(&42i32).unwrap();
        assert_eq!(from_slice::<i32>(&bytes).unwrap(), 42);

        // String
        let bytes = to_vec(&"hello").unwrap();
        assert_eq!(from_slice::<String>(&bytes).unwrap(), "hello");

        // Null (via Option)
        let none: Option<i32> = None;
        let bytes = to_vec(&none).unwrap();
        assert_eq!(from_slice::<Option<i32>>(&bytes).unwrap(), None);
    }

    #[test]
    fn test_roundtrip_struct() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Test {
            a: i32,
            b: String,
        }

        let original = Test {
            a: 42,
            b: "hello".to_string(),
        };
        let bytes = to_vec(&original).unwrap();
        let decoded: Test = from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_nested() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Inner {
            value: i32,
        }

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Outer {
            inner: Inner,
            list: Vec<i32>,
        }

        let original = Outer {
            inner: Inner { value: 42 },
            list: vec![1, 2, 3],
        };
        let bytes = to_vec(&original).unwrap();
        let decoded: Outer = from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_map_key_sorting() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert("z".to_string(), 1);
        map.insert("a".to_string(), 2);
        map.insert("m".to_string(), 3);

        let bytes = to_vec(&map).unwrap();

        assert_eq!(
            bytes,
            vec![0xa3, 0x61, 0x61, 0x02, 0x61, 0x6d, 0x03, 0x61, 0x7a, 0x01]
        );
    }

    #[test]
    fn test_strict_rejects_non_canonical() {
        let bytes = [0x18, 0x00];
        assert!(from_slice::<u8>(&bytes).is_err());
        assert_eq!(from_slice_non_strict::<u8>(&bytes).unwrap(), 0);
    }

    #[test]
    fn test_float_rejects_nan() {
        let result = to_vec(&f64::NAN);
        assert!(result.is_err());
    }

    #[test]
    fn test_float_rejects_infinity() {
        let result = to_vec(&f64::INFINITY);
        assert!(result.is_err());

        let result = to_vec(&f64::NEG_INFINITY);
        assert!(result.is_err());
    }
}
