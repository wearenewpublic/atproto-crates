//! The `com.atproto.admin` subject union and status attribute.
//!
//! `updateSubjectStatus` and `getSubjectStatus` both address one of three
//! things — an account, a record, or a blob — through an open union
//! discriminated by `$type`. This module is that union.
//!
//! The spellings are load-bearing. `com.atproto.admin.defs#repoRef` and
//! `com.atproto.repo.strongRef` are what Ozone and `pdsadmin` put on the wire,
//! and a `$type` that differs by one character is a subject this server cannot
//! address at all — which is exactly the failure this replaces.

use serde::{Deserialize, Serialize};

/// A moderation status flag, `com.atproto.admin.defs#statusAttr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusAttr {
    /// Whether the status is in force.
    pub applied: bool,
    /// The moderation service's own identifier for the action. Optional, and
    /// opaque to the PDS — stored and handed back, never interpreted.
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// The subject of an admin status call: an account, a record, or a blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum SubjectRef {
    /// `com.atproto.admin.defs#repoRef` — a whole account.
    #[serde(rename = "com.atproto.admin.defs#repoRef")]
    Repo {
        /// DID of the account.
        did: String,
    },
    /// `com.atproto.repo.strongRef` — one record at one revision.
    #[serde(rename = "com.atproto.repo.strongRef")]
    Record {
        /// AT-URI of the record.
        uri: String,
        /// CID the moderator acted on.
        cid: String,
    },
    /// `com.atproto.admin.defs#repoBlobRef` — one blob in one account.
    #[serde(rename = "com.atproto.admin.defs#repoBlobRef")]
    Blob {
        /// DID of the account holding the blob.
        did: String,
        /// CID of the blob.
        cid: String,
        /// The record that references it, when the moderator knew one.
        #[serde(rename = "recordUri", skip_serializing_if = "Option::is_none")]
        record_uri: Option<String>,
    },
}

impl SubjectRef {
    /// The DID whose per-actor store holds this subject.
    ///
    /// For a record this is the AT-URI's authority, which is why the URI must
    /// parse before anything else happens.
    ///
    /// # Errors
    ///
    /// [`PdsError::InvalidSubject`](crate::errors::PdsError::InvalidSubject)
    /// when a record subject's URI is not a valid AT-URI.
    pub fn did(&self) -> Result<String, crate::errors::PdsError> {
        match self {
            SubjectRef::Repo { did } | SubjectRef::Blob { did, .. } => Ok(did.clone()),
            SubjectRef::Record { uri, .. } => Ok(parse_record_uri(uri)?.0),
        }
    }
}

/// Split a record AT-URI into `(authority, collection, rkey)`.
///
/// Structural only — it does not check that the authority is a well-formed
/// `did:plc`, matching `new AtUri(...)` in the reference. The authority is
/// looked up as an account immediately afterwards, which is the real check; a
/// stricter parse here would reject DID methods this server has not been taught
/// while adding nothing.
///
/// # Errors
///
/// [`PdsError::InvalidSubject`](crate::errors::PdsError::InvalidSubject) when
/// the URI is not `at://<did>/<collection>/<rkey>`.
pub fn parse_record_uri(uri: &str) -> Result<(String, String, String), crate::errors::PdsError> {
    let bad = |why: &str| crate::errors::PdsError::InvalidSubject {
        reason: format!("subject uri {uri} is not a record AT-URI: {why}"),
    };
    let rest = uri
        .strip_prefix("at://")
        .ok_or_else(|| bad("no at:// prefix"))?;
    let mut parts = rest.split('/');
    let authority = parts.next().unwrap_or_default();
    let collection = parts.next().ok_or_else(|| bad("no collection"))?;
    let rkey = parts.next().ok_or_else(|| bad("no record key"))?;
    if parts.next().is_some() {
        return Err(bad("too many path segments"));
    }
    if authority.is_empty() || collection.is_empty() || rkey.is_empty() {
        return Err(bad("empty path segment"));
    }
    if !authority.starts_with("did:") {
        return Err(bad("authority must be a DID"));
    }
    Ok((
        authority.to_string(),
        collection.to_string(),
        rkey.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Known-answer tests against the lexicon's own spellings. A round-trip
    // test would pass just as happily against a `$type` this server invented.

    #[test]
    fn a_repo_ref_uses_the_lexicon_type_string() {
        let parsed: SubjectRef = serde_json::from_value(json!({
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:alice",
        }))
        .unwrap();
        assert_eq!(
            parsed,
            SubjectRef::Repo {
                did: "did:plc:alice".to_string()
            }
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:alice"})
        );
    }

    #[test]
    fn a_record_subject_is_a_strong_ref_not_an_admin_def() {
        // `strongRef` lives in `com.atproto.repo`, not `com.atproto.admin.defs`
        // — the one member of this union whose namespace differs.
        let parsed: SubjectRef = serde_json::from_value(json!({
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:alice/app.bsky.feed.post/abc",
            "cid": "bafyreiabc",
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({
                "$type": "com.atproto.repo.strongRef",
                "uri": "at://did:plc:alice/app.bsky.feed.post/abc",
                "cid": "bafyreiabc",
            })
        );
    }

    #[test]
    fn a_blob_ref_omits_record_uri_when_absent() {
        let parsed: SubjectRef = serde_json::from_value(json!({
            "$type": "com.atproto.admin.defs#repoBlobRef",
            "did": "did:plc:alice",
            "cid": "bafkreiabc",
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json!({
                "$type": "com.atproto.admin.defs#repoBlobRef",
                "did": "did:plc:alice",
                "cid": "bafkreiabc",
            }),
            "recordUri is optional and must not be emitted as null"
        );

        let with_uri: SubjectRef = serde_json::from_value(json!({
            "$type": "com.atproto.admin.defs#repoBlobRef",
            "did": "did:plc:alice",
            "cid": "bafkreiabc",
            "recordUri": "at://did:plc:alice/app.bsky.feed.post/abc",
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&with_uri).unwrap()["recordUri"],
            "at://did:plc:alice/app.bsky.feed.post/abc"
        );
    }

    #[test]
    fn an_unknown_subject_type_is_refused() {
        let r: Result<SubjectRef, _> = serde_json::from_value(json!({
            "$type": "com.example.somethingElse",
            "did": "did:plc:alice",
        }));
        assert!(r.is_err());
    }

    #[test]
    fn status_attr_ref_is_spelled_ref_and_is_optional() {
        let applied: StatusAttr = serde_json::from_value(json!({"applied": true})).unwrap();
        assert!(applied.reference.is_none());
        assert_eq!(
            serde_json::to_value(&applied).unwrap(),
            json!({"applied": true})
        );

        let with_ref: StatusAttr =
            serde_json::from_value(json!({"applied": true, "ref": "mod-42"})).unwrap();
        assert_eq!(with_ref.reference.as_deref(), Some("mod-42"));
        assert_eq!(
            serde_json::to_value(&with_ref).unwrap(),
            json!({"applied": true, "ref": "mod-42"})
        );
    }

    #[test]
    fn a_record_subject_resolves_its_did_from_the_uri() {
        let s = SubjectRef::Record {
            uri: "at://did:plc:alice/app.bsky.feed.post/abc".to_string(),
            cid: "bafyreiabc".to_string(),
        };
        assert_eq!(s.did().unwrap(), "did:plc:alice");

        for bad in [
            "not-a-uri",
            "at://",
            "at://did:plc:alice",
            "at://did:plc:alice/app.bsky.feed.post",
            "at://did:plc:alice/app.bsky.feed.post/abc/extra",
            "at://did:plc:alice//abc",
            // A handle authority is not addressable here: the moderation
            // subject must name the repository itself.
            "at://alice.example/app.bsky.feed.post/abc",
        ] {
            let s = SubjectRef::Record {
                uri: bad.to_string(),
                cid: "bafyreiabc".to_string(),
            };
            assert!(s.did().is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn a_record_uri_splits_into_its_three_parts() {
        let (did, collection, rkey) =
            parse_record_uri("at://did:plc:alice/app.bsky.feed.post/abc").unwrap();
        assert_eq!(did, "did:plc:alice");
        assert_eq!(collection, "app.bsky.feed.post");
        assert_eq!(rkey, "abc");
    }
}
