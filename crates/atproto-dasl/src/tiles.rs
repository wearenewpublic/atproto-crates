//! Web Tiles: composable web documents and applications.
//!
//! Web Tiles are content-addressed web applications that can safely be used
//! in arbitrary contexts and assembled from multiple sources. A tile is a
//! MASL Bundle Mode document with additional constraints:
//!
//! - Must have a `name` field (max 1000 chars / 100 graphemes)
//! - Must have a `/` root resource entry
//! - Resources are loaded from content-addressed storage
//!
//! Tiles can be distributed as CAR files (with `.tile` extension) or
//! published as AT Protocol records using the `ing.dasl.masl` lexicon.
//!
//! See <https://dasl.ing/tiles.html> for the specification.

use crate::errors::TilesError;
use crate::masl::Document;

/// Maximum length of a tile name in characters.
pub const MAX_NAME_CHARS: usize = 1000;

/// Maximum length of a tile name in graphemes.
pub const MAX_NAME_GRAPHEMES: usize = 100;

/// Default Content-Security-Policy for tile execution.
pub const DEFAULT_CSP: &str = "default-src 'self' blob: data:; script-src 'self' blob: data: 'unsafe-inline' 'wasm-unsafe-eval'; media-src 'self' blob: data:; manifest-src 'none'; base-uri 'none'";

/// Default sandbox attributes for tile execution.
pub const SANDBOX_ATTRS: &str =
    "allow-downloads allow-forms allow-modals allow-popups allow-same-origin allow-scripts";

/// Cross-Origin-Opener-Policy header value for tiles.
pub const COOP_HEADER: &str = "same-origin";

/// Cross-Origin-Resource-Policy header value for tiles.
pub const CORP_HEADER: &str = "cross-origin";

/// Permissions-Policy header value for tiles.
pub const PERMISSIONS_POLICY: &str = "interest-cohort=()";

/// Referrer-Policy header value for tiles.
pub const REFERRER_POLICY: &str = "no-referrer";

/// Validate a MASL document as a valid Web Tile manifest.
///
/// A valid tile manifest must:
/// - Be in bundle mode (have a non-empty `resources` map)
/// - Have a `name` field within length limits
/// - Have a `/` root resource entry in the resources map
/// - Pass standard MASL validation
///
/// # Errors
///
/// Returns `TilesError` if the document is not a valid tile manifest.
pub fn validate_tile(doc: &Document) -> Result<(), TilesError> {
    // Must pass base MASL validation first
    doc.validate().map_err(|e| TilesError::MaslValidation {
        reason: e.to_string(),
    })?;

    // Must be in bundle mode
    if !doc.is_bundle() {
        return Err(TilesError::NotBundleMode);
    }

    // Must have a name
    let name = doc
        .resource
        .name
        .as_deref()
        .ok_or(TilesError::MissingName)?;

    if name.is_empty() {
        return Err(TilesError::MissingName);
    }

    // Name length constraints
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(TilesError::NameTooLong {
            chars: name.chars().count(),
            max: MAX_NAME_CHARS,
        });
    }

    // Must have a root "/" resource
    if !doc.resources.contains_key("/") {
        return Err(TilesError::MissingRootResource);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;
    use crate::masl::{Document, Resource};
    use std::collections::BTreeMap;

    fn make_tile_doc(name: Option<&str>, has_root: bool) -> Document {
        let cid = Cid::new(crate::cid::compute_cid(b"test data"));
        let mut resources = BTreeMap::new();

        if has_root {
            resources.insert(
                "/".to_string(),
                Resource {
                    source: Some(cid.clone()),
                    content_type: Some("text/html".to_string()),
                    ..Default::default()
                },
            );
        }

        resources.insert(
            "/style.css".to_string(),
            Resource {
                source: Some(cid.clone()),
                content_type: Some("text/css".to_string()),
                ..Default::default()
            },
        );

        Document {
            resource: Resource {
                source: Some(cid),
                name: name.map(String::from),
                ..Default::default()
            },
            resources,
            prev: None,
            version: Some(1),
            roots: Vec::new(),
            doc_type: Some("ing.dasl.masl".to_string()),
        }
    }

    #[test]
    fn test_valid_tile() {
        let doc = make_tile_doc(Some("My Tile"), true);
        assert!(validate_tile(&doc).is_ok());
    }

    #[test]
    fn test_missing_name() {
        let doc = make_tile_doc(None, true);
        assert!(matches!(validate_tile(&doc), Err(TilesError::MissingName)));
    }

    #[test]
    fn test_empty_name() {
        let doc = make_tile_doc(Some(""), true);
        assert!(matches!(validate_tile(&doc), Err(TilesError::MissingName)));
    }

    #[test]
    fn test_name_too_long() {
        let long_name = "a".repeat(MAX_NAME_CHARS + 1);
        let doc = make_tile_doc(Some(&long_name), true);
        assert!(matches!(
            validate_tile(&doc),
            Err(TilesError::NameTooLong { .. })
        ));
    }

    #[test]
    fn test_missing_root_resource() {
        let doc = make_tile_doc(Some("My Tile"), false);
        assert!(matches!(
            validate_tile(&doc),
            Err(TilesError::MissingRootResource)
        ));
    }

    #[test]
    fn test_not_bundle_mode() {
        let cid = Cid::new(crate::cid::compute_cid(b"test"));
        let doc = Document {
            resource: Resource {
                source: Some(cid),
                name: Some("Single Mode".to_string()),
                ..Default::default()
            },
            resources: BTreeMap::new(),
            prev: None,
            version: None,
            roots: Vec::new(),
            doc_type: None,
        };
        assert!(matches!(
            validate_tile(&doc),
            Err(TilesError::NotBundleMode)
        ));
    }
}
