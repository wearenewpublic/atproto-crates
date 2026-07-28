//! AT-URI parsing and validation for AT Protocol record identification.
//!
//! This module provides functionality to parse and validate AT Protocol URIs (AT-URIs),
//! which are used to uniquely identify records within the AT Protocol ecosystem.
//!
//! ## AT-URI Format
//!
//! AT-URIs follow the format: `at://authority/collection/record_key`
//!
//! - **authority**: A DID (Decentralized Identifier) - either did:plc or did:web
//! - **collection**: An NSID (Namespaced Identifier) specifying the record type
//! - **record_key**: A unique identifier for the specific record within the collection
//!
//! ## Example
//!
//! ```ignore
//! use atproto_record::aturi::ATURI;
//! use std::str::FromStr;
//!
//! let uri = "at://did:plc:abc123/app.bsky.feed.post/3k2k4j5h6g";
//! let aturi = ATURI::from_str(uri)?;
//!
//! assert_eq!(aturi.authority, "did:plc:abc123");
//! assert_eq!(aturi.collection, "app.bsky.feed.post");
//! assert_eq!(aturi.record_key, "3k2k4j5h6g");
//! ```
//!
//! ## Validation Rules
//!
//! - Must start with the `at://` scheme
//! - Authority must be a valid DID (handles are not supported)
//! - Collection and record_key must be non-empty
//! - Trailing slashes are not permitted

use std::fmt;
use std::str::FromStr;

use atproto_identity::resolve::{InputType, parse_input};

use crate::errors::AturiError;

/// Represents a parsed AT Protocol URI (AT-URI).
///
/// AT-URIs uniquely identify records within AT Protocol repositories by combining
/// three essential components: authority (DID), collection (NSID), and record key.
///
/// This struct provides validated access to these components after successful parsing
/// and implements `Display` for reconstructing the original URI format.
#[derive(Debug, Clone)]
pub struct ATURI {
    /// The authority component as a DID (e.g., "did:plc:abc123")
    pub authority: String,
    /// The collection component as an NSID (e.g., "app.bsky.feed.post")
    pub collection: String,
    /// The record key component (e.g., "3jui7kp54ic2i")
    pub record_key: String,
}

impl fmt::Display for ATURI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "at://{}/{}/{}",
            self.authority, self.collection, self.record_key
        )
    }
}

impl FromStr for ATURI {
    type Err = AturiError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let aturi = match input.strip_prefix("at://") {
            Some(value) => value,
            None => return Err(AturiError::MissingPrefix),
        };

        if aturi.ends_with('/') {
            return Err(AturiError::TrailingSlash);
        }

        let mut components = aturi.split('/');

        let authority = components.next().ok_or(AturiError::AuthorityMissing)?;

        if authority.is_empty() {
            return Err(AturiError::AuthorityMissing);
        }

        let did = match parse_input(authority) {
            Ok(InputType::Handle(_)) => return Err(AturiError::HandleNotSupported),
            Ok(InputType::Plc(did)) | Ok(InputType::Web(did)) | Ok(InputType::WebVH(did)) => did,
            Err(error) => return Err(AturiError::AuthorityParsingFailed { error }),
        };

        let nsid = components.next().ok_or(AturiError::CollectionMissing)?;

        if nsid.trim().is_empty() {
            return Err(AturiError::EmptyCollection);
        }

        let record_key = components.next().ok_or(AturiError::RecordKeyMissing)?;

        if record_key.trim().is_empty() {
            return Err(AturiError::EmptyRecordKey);
        }

        Ok(ATURI {
            authority: did,
            collection: nsid.to_string(),
            record_key: record_key.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::AturiError;
    use std::str::FromStr;

    #[test]
    fn test_valid_aturi_with_plc_did() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(result.collection, "app.bsky.feed.post");
        assert_eq!(result.record_key, "3jui7kp54ic2i");
    }

    #[test]
    fn test_valid_aturi_with_web_did() {
        let input = "at://did:web:example.com/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:web:example.com");
        assert_eq!(result.collection, "app.bsky.feed.post");
        assert_eq!(result.record_key, "3jui7kp54ic2i");
    }

    #[test]
    fn test_valid_aturi_with_nested_web_did() {
        let input = "at://did:web:example.com:8080:path:to:service/app.bsky.feed.like/3k2akjh32kj";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:web:example.com:8080:path:to:service");
        assert_eq!(result.collection, "app.bsky.feed.like");
        assert_eq!(result.record_key, "3k2akjh32kj");
    }

    #[test]
    fn test_missing_prefix_error() {
        let input = "did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::MissingPrefix));
    }

    #[test]
    fn test_wrong_prefix_error() {
        let input = "https://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::MissingPrefix));
    }

    #[test]
    fn test_trailing_slash_error() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7kp54ic2i/";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::TrailingSlash));
    }

    #[test]
    fn test_authority_missing_error() {
        let input = "at://";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::AuthorityMissing));
    }

    #[test]
    fn test_authority_missing_with_slash_error() {
        let input = "at:///";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::TrailingSlash));
    }

    #[test]
    fn test_handle_not_supported_error() {
        let input = "at://alice.bsky.social/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AturiError::HandleNotSupported
        ));
    }

    #[test]
    fn test_authority_parsing_failed_error() {
        let input = "at://invalid-did-format/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AturiError::AuthorityParsingFailed { .. }
        ));
    }

    #[test]
    fn test_empty_authority_parsing_failed_error() {
        let input = "at:///app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::AuthorityMissing));
    }

    #[test]
    fn test_collection_missing_error() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::CollectionMissing));
    }

    #[test]
    fn test_collection_missing_with_slash_error() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::TrailingSlash));
    }

    #[test]
    fn test_record_key_missing_error() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::RecordKeyMissing));
    }

    #[test]
    fn test_record_key_missing_with_slash_error() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::TrailingSlash));
    }

    #[test]
    fn test_extra_path_components_ignored() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7kp54ic2i/extra/components";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(result.collection, "app.bsky.feed.post");
        assert_eq!(result.record_key, "3jui7kp54ic2i");
    }

    #[test]
    fn test_complex_collection_nsid() {
        let input =
            "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/com.example.complex.collection.type/record123";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(result.collection, "com.example.complex.collection.type");
        assert_eq!(result.record_key, "record123");
    }

    #[test]
    fn test_complex_record_key() {
        let input = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/complex-record.key_with-symbols123";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(result.collection, "app.bsky.feed.post");
        assert_eq!(result.record_key, "complex-record.key_with-symbols123");
    }

    #[test]
    fn test_minimal_valid_aturi() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/b/c";
        let result = ATURI::from_str(input).unwrap();

        assert_eq!(result.authority, "did:plc:abcdefghijklmnopqrstuvwx");
        assert_eq!(result.collection, "b");
        assert_eq!(result.record_key, "c");
    }

    #[test]
    fn test_long_valid_aturi() {
        let very_long_did = "did:plc:abcdefghijklmnopqrstuvwx";
        let very_long_collection = "com.example.".to_string() + &"long".repeat(10) + ".collection";
        let very_long_record_key = "record".to_string() + &"x".repeat(50);
        let input = format!(
            "at://{}/{}/{}",
            very_long_did, very_long_collection, very_long_record_key
        );

        let result = ATURI::from_str(&input).unwrap();

        assert_eq!(result.authority, very_long_did);
        assert_eq!(result.collection, very_long_collection);
        assert_eq!(result.record_key, very_long_record_key);
    }

    #[test]
    fn test_empty_string_error() {
        let input = "";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::MissingPrefix));
    }

    #[test]
    fn test_only_prefix_error() {
        let input = "at://";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::AuthorityMissing));
    }

    #[test]
    fn test_whitespace_input_error() {
        let input = "   ";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::MissingPrefix));
    }

    #[test]
    fn test_malformed_did_web_authority() {
        let input = "at://did:invalid:notreal/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AturiError::AuthorityParsingFailed { .. }
        ));
    }

    #[test]
    fn test_did_method_key_authority() {
        let input = "at://did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp/app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AturiError::AuthorityParsingFailed { .. }
        ));
    }

    #[test]
    fn test_whitespace_authority_error() {
        let input = "at:// /app.bsky.feed.post/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AturiError::AuthorityParsingFailed { .. }
        ));
    }

    #[test]
    fn test_whitespace_collection_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/ /3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::EmptyCollection));
    }

    #[test]
    fn test_whitespace_record_key_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/ ";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::EmptyRecordKey));
    }

    #[test]
    fn test_empty_collection_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx//3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::EmptyCollection));
    }

    #[test]
    fn test_empty_record_key_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::TrailingSlash));
    }

    #[test]
    fn test_tab_collection_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/\t/3jui7kp54ic2i";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::EmptyCollection));
    }

    #[test]
    fn test_newline_record_key_error() {
        let input = "at://did:plc:abcdefghijklmnopqrstuvwx/app.bsky.feed.post/\n";
        let result = ATURI::from_str(input);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AturiError::EmptyRecordKey));
    }
}
