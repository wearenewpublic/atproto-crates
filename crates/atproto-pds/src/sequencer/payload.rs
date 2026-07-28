//! Event bodies, in the shapes `com.atproto.sync.subscribeRepos` declares.
//!
//! The subscription's output is a **closed union**: a subscriber decodes each
//! frame against `#commit`, `#sync`, `#identity` or `#account` and rejects
//! anything matching none of them. A body that wraps the event in an envelope,
//! or spells `repo` as `did`, or omits a required field, is not a member of
//! that union — so a relay connects, parses the frame header successfully, and
//! then cannot map the body to anything.
//!
//! Note the asymmetry, which is the specification's and not a slip here:
//! `#commit` names the repository `repo`, while `#sync`, `#identity` and
//! `#account` name it `did`.
//!
//! # Storage
//!
//! Bodies are stored as DAG-CBOR, not JSON. JSON cannot express a link or a
//! byte string, so a body that round-tripped through it lost exactly the two
//! types this union depends on — a `cid-link` arrived as text, and `blocks`
//! could not survive at all. Storing the encoded form also means the frame
//! encoder does no re-encoding beyond splicing in the fields it owns.
//!
//! `seq` and `time` are **not** part of a stored body. Both belong to the
//! delivery rather than the event, and `seq` is not known until the row exists,
//! so [`splice_envelope`] adds them when the frame is built.

use atproto_dasl::Cid;
use serde::Serialize;

use crate::errors::{PdsError, PdsResult};
use atproto_repo::mst::RepoOp;

/// Body of a `#commit` event, less `seq` and `time`.
///
/// `rebase` and `tooBig` are required by the lexicon and deprecated by it in
/// the same breath; both are always false and are emitted because a conformant
/// decoder requires their presence, not because they carry meaning.
#[derive(Debug, Serialize)]
pub struct CommitBody {
    /// Deprecated, always false. Required.
    pub rebase: bool,
    /// Deprecated, always false. Required.
    #[serde(rename = "tooBig")]
    pub too_big: bool,
    /// DID of the repository this event comes from.
    pub repo: String,
    /// CID of the new commit object.
    pub commit: Cid,
    /// Revision of the new commit.
    pub rev: String,
    /// Revision of the previous commit from this repo, or null for the first.
    pub since: Option<String>,
    /// CARv1 slice carrying the blocks this commit wrote, rooted at `commit`.
    ///
    /// Not yet the Sync 1.1 covering proof (F-FIRE-06) — an inductive consumer
    /// needs the prior state of each touched key as well.
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    /// The record operations this commit performed.
    pub ops: Vec<RepoOp>,
    /// Blob CIDs referenced by this commit. Always empty — the write path does
    /// not yet walk records for blob refs (F-BLOB-02).
    pub blobs: Vec<Cid>,
    /// Prior MST root, for Sync 1.1 inductive verification.
    #[serde(rename = "prevData", skip_serializing_if = "Option::is_none")]
    pub prev_data: Option<Cid>,
}

/// Body of a `#sync` event, less `seq` and `time`.
#[derive(Debug, Serialize)]
pub struct SyncBody {
    /// DID of the repository.
    pub did: String,
    /// CARv1 rooted at the head commit and carrying that commit block.
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    /// Revision of the commit being asserted.
    pub rev: String,
}

/// Body of an `#identity` event, less `seq` and `time`.
#[derive(Debug, Serialize)]
pub struct IdentityBody {
    /// DID whose identity changed.
    pub did: String,
    /// The new handle, when one is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// Body of an `#account` event, less `seq` and `time`.
#[derive(Debug, Serialize)]
pub struct AccountBody {
    /// DID whose account state changed.
    pub did: String,
    /// Whether the account is currently active.
    pub active: bool,
    /// Why it is not, when it is not. Omitted when active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Encode an event body as DAG-CBOR for storage.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the body cannot be encoded.
pub fn encode<T: Serialize>(body: &T) -> PdsResult<Vec<u8>> {
    atproto_dasl::to_vec(body).map_err(|err| PdsError::Storage {
        reason: format!("encode event body: {err}"),
    })
}

/// Add the fields the delivery owns to a stored body.
///
/// `seq` orders the event in the stream and `time` records when it was
/// broadcast; neither is known when the body is built. Splicing operates on the
/// data model rather than on JSON, so a link stays a link and `blocks` stays
/// bytes.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the stored body is not a DAG-CBOR map.
pub fn splice_envelope(body: &[u8], seq: i64, time: &str) -> PdsResult<Vec<u8>> {
    use atproto_dasl::Ipld;

    let decoded: Ipld = atproto_dasl::from_slice(body).map_err(|err| PdsError::Storage {
        reason: format!("decode stored event body: {err}"),
    })?;
    let Ipld::Map(mut map) = decoded else {
        return Err(PdsError::Storage {
            reason: "stored event body is not a map".to_string(),
        });
    };
    map.insert("seq".to_string(), Ipld::Integer(i128::from(seq)));
    map.insert("time".to_string(), Ipld::String(time.to_string()));

    atproto_dasl::to_vec(&Ipld::Map(map)).map_err(|err| PdsError::Storage {
        reason: format!("encode event frame body: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_dasl::Ipld;
    use atproto_repo::mst::RepoOpAction;

    fn cid() -> Cid {
        Cid(
            "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
                .parse()
                .expect("test CID should parse"),
        )
    }

    fn decode(bytes: &[u8]) -> std::collections::BTreeMap<String, Ipld> {
        match atproto_dasl::from_slice::<Ipld>(bytes).expect("body should decode") {
            Ipld::Map(map) => map,
            other => panic!("expected a map, got {other:?}"),
        }
    }

    fn commit_body() -> CommitBody {
        CommitBody {
            rebase: false,
            too_big: false,
            repo: "did:plc:alice".to_string(),
            commit: cid(),
            rev: "3jui7kd2z2y2e".to_string(),
            since: None,
            blocks: Vec::new(),
            ops: vec![RepoOp {
                action: RepoOpAction::Create,
                path: "app.bsky.feed.post/aaa".to_string(),
                cid: Some(cid()),
                prev: None,
            }],
            blobs: Vec::new(),
            prev_data: None,
        }
    }

    /// Every field the lexicon marks required must be present after splicing.
    #[test]
    fn a_commit_body_carries_every_required_field() {
        let stored = encode(&commit_body()).unwrap();
        let framed = splice_envelope(&stored, 42, "2026-07-28T00:00:00.000Z").unwrap();
        let map = decode(&framed);

        for field in [
            "seq", "rebase", "tooBig", "repo", "commit", "rev", "since", "blocks", "ops", "blobs",
            "time",
        ] {
            assert!(
                map.contains_key(field),
                "#commit must carry {field}: {map:?}"
            );
        }
        assert!(
            !map.contains_key("payload"),
            "the body is the event, not an envelope around it"
        );
        assert!(
            !map.contains_key("did"),
            "#commit names the repository `repo`, not `did`"
        );
    }

    /// `commit` is a cid-link, so it must survive as a link and not as text.
    #[test]
    fn links_stay_links_through_storage_and_splicing() {
        let stored = encode(&commit_body()).unwrap();
        let framed = splice_envelope(&stored, 1, "now").unwrap();
        let map = decode(&framed);
        assert!(
            matches!(map["commit"], Ipld::Link(_)),
            "commit should be a link, got {:?}",
            map["commit"]
        );

        let Ipld::List(ops) = &map["ops"] else {
            panic!("ops should be a list")
        };
        let Ipld::Map(op) = &ops[0] else {
            panic!("an op should be a map")
        };
        assert!(
            matches!(op["cid"], Ipld::Link(_)),
            "a repoOp cid should be a link, got {:?}",
            op["cid"]
        );
    }

    /// `blocks` is typed `bytes`; it must not degrade to a string.
    #[test]
    fn blocks_stays_a_byte_string() {
        let stored = encode(&commit_body()).unwrap();
        let framed = splice_envelope(&stored, 1, "now").unwrap();
        assert!(matches!(decode(&framed)["blocks"], Ipld::Bytes(_)));
    }

    /// `since` is required and nullable — present as null on a first commit.
    #[test]
    fn since_is_present_and_null_for_a_first_commit() {
        let stored = encode(&commit_body()).unwrap();
        let framed = splice_envelope(&stored, 1, "now").unwrap();
        assert_eq!(decode(&framed)["since"], Ipld::Null);
    }

    #[test]
    fn the_other_event_types_name_the_repository_did() {
        for stored in [
            encode(&SyncBody {
                did: "did:plc:alice".to_string(),
                blocks: Vec::new(),
                rev: "3jui7kd2z2y2e".to_string(),
            })
            .unwrap(),
            encode(&IdentityBody {
                did: "did:plc:alice".to_string(),
                handle: Some("alice.test".to_string()),
            })
            .unwrap(),
            encode(&AccountBody {
                did: "did:plc:alice".to_string(),
                active: true,
                status: None,
            })
            .unwrap(),
        ] {
            let map = decode(&splice_envelope(&stored, 7, "now").unwrap());
            assert!(map.contains_key("did"), "{map:?}");
            assert!(!map.contains_key("repo"), "{map:?}");
            assert_eq!(map["seq"], Ipld::Integer(7));
            assert!(map.contains_key("time"));
        }
    }

    /// An active account carries no `status`; the field is optional, not
    /// nullable, so a null would be wrong.
    #[test]
    fn an_active_account_omits_status() {
        let stored = encode(&AccountBody {
            did: "did:plc:alice".to_string(),
            active: true,
            status: None,
        })
        .unwrap();
        let map = decode(&splice_envelope(&stored, 1, "now").unwrap());
        assert!(!map.contains_key("status"));
        assert_eq!(map["active"], Ipld::Bool(true));
    }

    #[test]
    fn an_inactive_account_names_its_status() {
        let stored = encode(&AccountBody {
            did: "did:plc:alice".to_string(),
            active: false,
            status: Some("takendown".to_string()),
        })
        .unwrap();
        let map = decode(&splice_envelope(&stored, 1, "now").unwrap());
        assert_eq!(map["status"], Ipld::String("takendown".to_string()));
    }
}
