//! Core AT Protocol repository types.
//!
//! This module contains fundamental types for the AT Protocol repository
//! system, including strong references that combine URIs with content
//! identifiers for immutable referencing.

use crate::typed::{LexiconType, TypedLexicon};
use serde::{Deserialize, Serialize};

/// The namespace identifier for strong references
pub const STRONG_REF_NSID: &str = "com.atproto.repo.strongRef";

/// Strong reference to an AT Protocol record.
///
/// A strong reference combines an AT URI with a CID (Content Identifier),
/// providing both a location and a content hash. This ensures that the
/// reference points to a specific, immutable version of a record.
///
/// Strong references are commonly used to:
/// - Reference specific versions of records
/// - Create immutable links between records
/// - Ensure content integrity through CID verification
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::com::atproto::repo::{StrongRef, TypedStrongRef};
///
/// let strong_ref = StrongRef {
///     uri: "at://did:plc:example/app.bsky.feed.post/3k4duaz5vfs2b".to_string(),
///     cid: "bafyreib55ro5klxlwfxc5hzfonpdog6donvqvwdvjbloffqrmkenbqgpde".to_string(),
/// };
///
/// // Use TypedStrongRef for automatic $type field handling
/// let typed_ref = TypedStrongRef::new(strong_ref);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct StrongRef {
    /// AT URI pointing to a specific record
    /// Format: `at://[did]/[collection]/[rkey]`
    pub uri: String,
    /// Content Identifier (CID) of the record
    /// This ensures the reference points to a specific, immutable version
    pub cid: String,
}

impl LexiconType for StrongRef {
    fn lexicon_type() -> &'static str {
        STRONG_REF_NSID
    }
}

/// Type alias for StrongRef with automatic $type field handling.
///
/// This type wrapper ensures that the `$type` field is automatically
/// added during serialization and validated during deserialization.
pub type TypedStrongRef = TypedLexicon<StrongRef>;
