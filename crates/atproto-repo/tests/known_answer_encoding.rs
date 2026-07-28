//! Byte-level known-answer tests for MST node and commit encoding.
//!
//! These assert against DAG-CBOR written out from the CBOR and AT Protocol
//! repository specifications, not against this crate's own output. That
//! distinction is the entire point: `crates/atproto-repo` already had
//! round-trip coverage of both structures (`mst/serialize.rs`,
//! `mst/tree.rs`), and it passed while every node and commit this crate
//! produced was six bytes short of the canonical encoding and hashed to a CID
//! no peer could recompute. Encode-then-decode agrees with itself no matter
//! what the encoder does.
//!
//! The specific defect these pin is the one behind that: `l`, `t` and `prev`
//! are **nullable, not optional**. Serializing them with
//! `skip_serializing_if = "Option::is_none"` drops the key from the map
//! instead of writing `null`, which changes the map header (`a2` to `a1`,
//! `a4` to `a3`), shortens the encoding, and changes the CID of the node and
//! of every ancestor up to the repo root.
//!
//! Each vector below records the byte layout it asserts, so a future failure
//! can be read without re-deriving anything.

use atproto_dasl::Cid;
use atproto_repo::mst::{MstNode, TreeEntry};
use atproto_repo::repo::{Commit, UnsignedCommit};

/// Record value CID used by every vector, taken from the upstream interop
/// fixtures' `leafValue`.
const VALUE_CID: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

/// Subtree CID used by the vectors that exercise a non-null `l` or `t`.
const SUBTREE_CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

/// A 22-byte MST key, the length used by the reference documentation's examples.
const KEY: &[u8] = b"app.bsky.feed.post/abc";

/// Parse one of the constants above into a [`Cid`].
fn cid(text: &str) -> Cid {
    Cid(text.parse().expect("test CID should parse"))
}

/// Assert that `value` encodes to exactly `expected_hex`, reporting both
/// encodings on failure.
fn assert_encodes_to<T: serde::Serialize>(label: &str, value: &T, expected_hex: &str) {
    let expected = hex::decode(expected_hex).expect("expected hex should decode");
    let actual = atproto_dasl::to_vec(value).expect("value should encode");
    assert_eq!(
        actual,
        expected,
        "\n{label} does not match the canonical DAG-CBOR encoding\n  \
         expected {} bytes: {expected_hex}\n  \
         actual   {} bytes: {}\n",
        expected.len(),
        actual.len(),
        hex::encode(&actual)
    );
}

/// A single-entry node with no subtrees encodes `l` and `t` as explicit nulls.
///
/// This is the minimal case: one record, no tree shape to get wrong. It is
/// what makes the defect unambiguous — the encoding was wrong even here.
///
/// ```text
/// a2                                        map(2)
///   61 65                                   text(1) "e"
///     81                                    array(1)
///       a4                                  map(4)
///         61 6b  56 "app.bsky.feed.post/abc"  "k" bytes(22)
///         61 70  00                          "p" unsigned(0)
///         61 74  f6                          "t" null      <-- omitted before this fix
///         61 76  d8 2a 58 25 00 <36 bytes>    "v" tag(42) bytes(37)
///   61 6c  f6                                "l" null      <-- omitted before this fix
/// ```
///
/// 82 bytes. Before the fix the node was `a1`, the entry `a3`, and the whole
/// thing 76 bytes.
#[test]
fn leaf_node_encodes_null_left_and_null_subtree() {
    let node = MstNode::new(vec![TreeEntry::new(0, KEY.to_vec(), cid(VALUE_CID))]);
    assert_encodes_to(
        "single-entry MST node",
        &node,
        "a2616581a4616b566170702e62736b792e666565642e706f73742f6162636170006174f6\
         6176d82a582500017112209d156bc3f3a520066252c708a9361fd3d089223842500e3713\
         d404fdccb33cef616cf6"
            .replace(['\n', ' '], "")
            .as_str(),
    );
}

/// A node carrying a left subtree writes the CID under `l` rather than a null.
///
/// Guards the other side of the branch: removing `skip_serializing_if` must not
/// change what happens when the value is present.
#[test]
fn node_with_left_subtree_encodes_the_cid() {
    let node = MstNode::with_left(
        cid(SUBTREE_CID),
        vec![TreeEntry::new(0, KEY.to_vec(), cid(VALUE_CID))],
    );
    assert_encodes_to(
        "MST node with a left subtree",
        &node,
        "a2616581a4616b566170702e62736b792e666565642e706f73742f6162636170006174f6\
         6176d82a582500017112209d156bc3f3a520066252c708a9361fd3d089223842500e3713\
         d404fdccb33cef616cd82a5825000171122065062a5a5a00fc16d73c6944237ccbc15b1c\
         4a7234489336891d091741a239d0"
            .replace(['\n', ' '], "")
            .as_str(),
    );
}

/// An entry carrying a right subtree writes the CID under `t` rather than a null.
#[test]
fn entry_with_right_subtree_encodes_the_cid() {
    let node = MstNode::new(vec![TreeEntry::with_tree(
        0,
        KEY.to_vec(),
        cid(VALUE_CID),
        cid(SUBTREE_CID),
    )]);
    assert_encodes_to(
        "MST node whose entry has a right subtree",
        &node,
        "a2616581a4616b566170702e62736b792e666565642e706f73742f6162636170006174d8\
         2a5825000171122065062a5a5a00fc16d73c6944237ccbc15b1c4a7234489336891d0917\
         41a239d06176d82a582500017112209d156bc3f3a520066252c708a9361fd3d089223842\
         500e3713d404fdccb33cef616cf6"
            .replace(['\n', ' '], "")
            .as_str(),
    );
}

/// DID used by the commit vectors.
const COMMIT_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

/// Revision (TID) used by the commit vectors.
const COMMIT_REV: &str = "3jui7kd2z2y2e";

/// A 64-byte signature, `00..3f`, used by the signed-commit vector.
fn commit_sig() -> Vec<u8> {
    (0u8..64).collect()
}

/// The bytes signed for an initial commit carry `prev` as an explicit null.
///
/// This is the vector that matters most for federation. [`UnsignedCommit`] is
/// what gets serialized and signed, so an omitted `prev` here means the
/// signature is over the wrong bytes and no peer can verify it — regardless of
/// what [`Commit`] does. The gap analysis cited only the attribute on
/// [`Commit`]; the copy on [`UnsignedCommit`] is the one on the signing path.
///
/// ```text
/// a5                                          map(5)
///   63 646964  78 20 "did:plc:ewvi…"          "did"     text(32)
///   63 726576  6d "3jui7kd2z2y2e"             "rev"     text(13)
///   64 64617461  d8 2a 58 25 00 <36 bytes>    "data"    tag(42)
///   64 70726576  f6                           "prev"    null   <-- omitted before this fix
///   67 76657273696f6e  03                     "version" unsigned(3)
/// ```
#[test]
fn unsigned_initial_commit_encodes_null_prev() {
    let commit = UnsignedCommit {
        did: COMMIT_DID.to_string(),
        version: 3,
        data: cid(VALUE_CID),
        rev: COMMIT_REV.to_string(),
        prev: None,
        prev_data: None,
    };
    assert_encodes_to(
        "unsigned initial commit",
        &commit,
        "a56364696478206469643a706c633a65777669376e787a796f756e367a687872687336346f\
         697a637265766d336a7569376b64327a327932656464617461d82a58250001711220\
         9d156bc3f3a520066252c708a9361fd3d089223842500e3713d404fdccb33cef6470726576\
         f66776657273696f6e03"
            .replace(['\n', ' '], "")
            .as_str(),
    );
}

/// A signed initial commit likewise carries `prev` as an explicit null.
#[test]
fn signed_initial_commit_encodes_null_prev() {
    let commit = Commit {
        did: COMMIT_DID.to_string(),
        version: 3,
        data: cid(VALUE_CID),
        rev: COMMIT_REV.to_string(),
        prev: None,
        prev_data: None,
        sig: commit_sig(),
    };
    assert_encodes_to(
        "signed initial commit",
        &commit,
        "a66364696478206469643a706c633a65777669376e787a796f756e367a687872687336346f\
         697a637265766d336a7569376b64327a3279326563736967584000010203040506070809\
         0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e\
         2f303132333435363738393a3b3c3d3e3f6464617461d82a582500017112209d156bc3f3a5\
         20066252c708a9361fd3d089223842500e3713d404fdccb33cef6470726576f6677665727\
         3696f6e03"
            .replace(['\n', ' '], "")
            .as_str(),
    );
}

/// Nodes written before this fix, without `l` or `t`, still decode.
///
/// The break was one-directional — this crate could always read the network's
/// bytes, the network could not verify this crate's — so the fix must not
/// invert it. Existing on-disk blocks have to keep loading, and re-encoding one
/// must now produce the canonical form.
#[test]
fn legacy_node_without_l_or_t_still_decodes_and_re_encodes_canonically() {
    let legacy = hex::decode(
        "a1616581a3616b566170702e62736b792e666565642e706f73742f61626361700061\
         76d82a582500017112209d156bc3f3a520066252c708a9361fd3d089223842500e37\
         13d404fdccb33cef"
            .replace(['\n', ' '], ""),
    )
    .expect("legacy hex should decode");

    let node: MstNode = atproto_dasl::from_slice(&legacy)
        .expect("a node written without `l`/`t` must still decode");
    assert_eq!(node.left, None, "absent `l` should decode as None");
    assert_eq!(node.entries.len(), 1);
    assert_eq!(
        node.entries[0].tree, None,
        "absent `t` should decode as None"
    );

    let re_encoded = atproto_dasl::to_vec(&node).expect("node should re-encode");
    assert_eq!(
        re_encoded.len(),
        82,
        "re-encoding a legacy node must produce the canonical 82-byte form, got {} bytes: {}",
        re_encoded.len(),
        hex::encode(&re_encoded)
    );
}
