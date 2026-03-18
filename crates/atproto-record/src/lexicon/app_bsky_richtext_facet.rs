//! AT Protocol rich text facet types.
//!
//! This module provides types for annotating rich text content with semantic
//! meaning, based on the `app.bsky.richtext.facet` lexicon. Facets enable
//! mentions, links, hashtags, and other structured metadata to be attached
//! to specific byte ranges within text content.
//!
//! # Overview
//!
//! Facets consist of:
//! - A byte range (start/end indices in UTF-8 encoded text)
//! - One or more features (mention, link, tag) that apply to that range
//!
//! # Example
//!
//! ```ignore
//! use atproto_record::lexicon::app::bsky::richtext::facet::{Facet, ByteSlice, FacetFeature, Mention};
//!
//! // Create a mention facet for "@alice.bsky.social"
//! let facet = Facet {
//!     index: ByteSlice { byte_start: 0, byte_end: 19 },
//!     features: vec![
//!         FacetFeature::Mention(Mention {
//!             did: "did:plc:alice123".to_string(),
//!         })
//!     ],
//! };
//! ```

use serde::{Deserialize, Serialize};

/// Byte range specification for facet features.
///
/// Specifies the sub-string range a facet feature applies to using
/// zero-indexed byte offsets in UTF-8 encoded text. Start index is
/// inclusive, end index is exclusive.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::ByteSlice;
///
/// // Represents bytes 0-5 of the text
/// let slice = ByteSlice {
///     byte_start: 0,
///     byte_end: 5,
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ByteSlice {
    /// Starting byte index (inclusive)
    pub byte_start: usize,

    /// Ending byte index (exclusive)
    pub byte_end: usize,
}

/// Mention facet feature for referencing another account.
///
/// The text content typically displays a handle with '@' prefix (e.g., "@alice.bsky.social"),
/// but the facet reference must use the account's DID for stable identification.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::Mention;
///
/// let mention = Mention {
///     did: "did:plc:alice123".to_string(),
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Mention {
    /// DID of the mentioned account
    pub did: String,
}

/// Link facet feature for URL references.
///
/// The text content may be simplified or truncated for display purposes,
/// but the facet reference should contain the complete, valid URL.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::Link;
///
/// let link = Link {
///     uri: "https://example.com/full/path".to_string(),
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Link {
    /// Complete URI/URL for the link
    pub uri: String,
}

/// Tag facet feature for hashtags.
///
/// The text content typically includes a '#' prefix for display,
/// but the facet reference should contain only the tag text without the prefix.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::Tag;
///
/// // For text "#atproto", store just "atproto"
/// let tag = Tag {
///     tag: "atproto".to_string(),
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Tag {
    /// Tag text without '#' prefix
    pub tag: String,
}

/// Discriminated union of facet feature types.
///
/// Represents the different types of semantic annotations that can be
/// applied to text ranges. Each variant corresponds to a specific lexicon
/// type in the `app.bsky.richtext.facet` namespace.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::{FacetFeature, Mention, Link, Tag};
///
/// // Create different feature types
/// let mention = FacetFeature::Mention(Mention {
///     did: "did:plc:alice123".to_string(),
/// });
///
/// let link = FacetFeature::Link(Link {
///     uri: "https://example.com".to_string(),
/// });
///
/// let tag = FacetFeature::Tag(Tag {
///     tag: "rust".to_string(),
/// });
/// ```
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[serde(tag = "$type")]
pub enum FacetFeature {
    /// Account mention feature
    #[serde(rename = "app.bsky.richtext.facet#mention")]
    Mention(Mention),

    /// URL link feature
    #[serde(rename = "app.bsky.richtext.facet#link")]
    Link(Link),

    /// Hashtag feature
    #[serde(rename = "app.bsky.richtext.facet#tag")]
    Tag(Tag),
}

/// Rich text facet annotation.
///
/// Associates one or more semantic features with a specific byte range
/// within text content. Multiple features can apply to the same range
/// (e.g., a URL that is also a hashtag).
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::app::bsky::richtext::facet::{
///     Facet, ByteSlice, FacetFeature, Mention, Link
/// };
///
/// // Annotate "@alice.bsky.social" at bytes 0-19
/// let facet = Facet {
///     index: ByteSlice { byte_start: 0, byte_end: 19 },
///     features: vec![
///         FacetFeature::Mention(Mention {
///             did: "did:plc:alice123".to_string(),
///         }),
///     ],
/// };
///
/// // Multiple features for the same range
/// let multi_facet = Facet {
///     index: ByteSlice { byte_start: 20, byte_end: 35 },
///     features: vec![
///         FacetFeature::Link(Link {
///             uri: "https://example.com".to_string(),
///         }),
///         FacetFeature::Tag(Tag {
///             tag: "example".to_string(),
///         }),
///     ],
/// };
/// ```
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct Facet {
    /// Byte range this facet applies to
    pub index: ByteSlice,

    /// Semantic features applied to this range
    pub features: Vec<FacetFeature>,
}
