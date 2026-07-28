//! Deletion must remove exactly one key and leave every other key intact.
//!
//! MST entries are prefix-compressed against the full key of the preceding
//! entry, so removing one changes the base its successor was encoded against.
//! Repairing that incorrectly does not fail — it silently rewrites a
//! neighbouring record's key, and because every later entry reconstructs
//! against the rewritten one, the damage runs to the end of the node.
//!
//! These tests assert the property that catches it: after deleting any single
//! key, the surviving key set is exactly the input minus that key. Nothing
//! about the encoding is asserted, because the failure is not visible in the
//! encoding — it is visible in what the tree says it contains.

use atproto_dasl::Cid;
use atproto_dasl::storage::MemoryStorage;
use atproto_repo::mst::Mst;

/// Twenty keys across four collections.
///
/// The collections are deliberately chosen to share long prefixes with each
/// other (`app.bsky.feed.like` / `app.bsky.feed.post`) and to diverge early
/// (`app.bsky.actor.profile` / `app.bsky.graph.follow`), because the defect
/// this guards against only shows where a key's compression base differs in
/// length from its neighbour's.
const KEYS: &[&str] = &[
    "app.bsky.actor.profile/aaaa",
    "app.bsky.actor.profile/bbbb",
    "app.bsky.actor.profile/cccc",
    "app.bsky.actor.profile/dddd",
    "app.bsky.actor.profile/eeee",
    "app.bsky.feed.like/aaaa",
    "app.bsky.feed.like/bbbb",
    "app.bsky.feed.like/cccc",
    "app.bsky.feed.like/dddd",
    "app.bsky.feed.like/eeee",
    "app.bsky.feed.post/aaaa",
    "app.bsky.feed.post/bbbb",
    "app.bsky.feed.post/cccc",
    "app.bsky.feed.post/dddd",
    "app.bsky.feed.post/eeee",
    "app.bsky.graph.follow/aaaa",
    "app.bsky.graph.follow/bbbb",
    "app.bsky.graph.follow/cccc",
    "app.bsky.graph.follow/dddd",
    "app.bsky.graph.follow/eeee",
];

fn leaf_value() -> Cid {
    Cid(
        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
            .parse()
            .expect("test CID should parse"),
    )
}

async fn tree_with(keys: &[&str]) -> Mst<MemoryStorage> {
    let value = leaf_value();
    let mut tree: Mst<MemoryStorage> = Mst::new_in_memory();
    for key in keys {
        tree.insert(key, value.clone())
            .await
            .unwrap_or_else(|err| panic!("insert {key}: {err}"));
    }
    tree
}

async fn sorted_keys(tree: &Mst<MemoryStorage>) -> Vec<String> {
    let mut keys: Vec<String> = tree
        .entries()
        .await
        .expect("entries should enumerate")
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    keys.sort();
    keys
}

/// Delete each key in turn from a fresh tree and check what survives.
///
/// Run as one test rather than twenty so a regression reports the full picture
/// — which keys corrupt, and how far the damage spreads — instead of the first
/// failure only.
#[tokio::test]
async fn deleting_any_single_key_leaves_the_rest_intact() {
    let mut failures = Vec::new();

    for victim in KEYS {
        let mut tree = tree_with(KEYS).await;
        if let Err(err) = tree.delete(victim).await {
            failures.push(format!("deleting {victim} errored: {err}"));
            continue;
        }

        let actual = sorted_keys(&tree).await;
        let mut expected: Vec<String> = KEYS
            .iter()
            .filter(|key| *key != victim)
            .map(|key| (*key).to_string())
            .collect();
        expected.sort();

        if actual != expected {
            let unexpected: Vec<&String> = actual
                .iter()
                .filter(|key| !KEYS.contains(&key.as_str()))
                .collect();
            let missing: Vec<&String> = expected
                .iter()
                .filter(|key| !actual.contains(key))
                .collect();
            failures.push(format!(
                "deleting {victim} corrupted the tree: {} unexpected key(s) {unexpected:?}, \
                 {} missing {missing:?}",
                unexpected.len(),
                missing.len()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} single-key deletes did not leave the tree intact:\n  {}",
        failures.len(),
        KEYS.len(),
        failures.join("\n  ")
    );
}

/// Deleting every key one at a time empties the tree and finds nothing left.
#[tokio::test]
async fn deleting_every_key_in_sequence_empties_the_tree() {
    let mut tree = tree_with(KEYS).await;
    for (deleted, victim) in KEYS.iter().enumerate() {
        tree.delete(victim)
            .await
            .unwrap_or_else(|err| panic!("delete {victim}: {err}"));

        let remaining = sorted_keys(&tree).await;
        assert_eq!(
            remaining.len(),
            KEYS.len() - deleted - 1,
            "after deleting {victim}, expected {} keys, got {remaining:?}",
            KEYS.len() - deleted - 1
        );
        for key in &remaining {
            assert!(
                KEYS.contains(&key.as_str()),
                "{key:?} is not a key that was ever inserted; \
                 a delete rewrote a neighbouring record"
            );
        }
    }
    assert!(sorted_keys(&tree).await.is_empty());
}

/// The first entry carries no prefix, so its successor's base changes from a
/// full key to the empty string when it is removed.
#[tokio::test]
async fn deleting_the_first_key_rebases_its_successor() {
    let mut tree = tree_with(KEYS).await;
    tree.delete(KEYS[0]).await.expect("delete should succeed");

    let remaining = sorted_keys(&tree).await;
    assert_eq!(remaining.len(), KEYS.len() - 1);
    assert_eq!(remaining[0], KEYS[1]);
}

/// Deleting the last entry needs no re-compression at all — nothing follows it.
#[tokio::test]
async fn deleting_the_last_key_leaves_the_others_untouched() {
    let mut tree = tree_with(KEYS).await;
    let last = KEYS[KEYS.len() - 1];
    tree.delete(last).await.expect("delete should succeed");

    let remaining = sorted_keys(&tree).await;
    let expected: Vec<String> = KEYS[..KEYS.len() - 1]
        .iter()
        .map(|key| (*key).to_string())
        .collect();
    assert_eq!(remaining, expected);
}

/// Two keys sharing no prefix beyond the namespace, deleted from between other
/// keys — the shape where the compression base shortens most sharply.
#[tokio::test]
async fn deleting_across_a_prefix_boundary_preserves_both_neighbours() {
    let keys = &[
        "app.bsky.feed.post/zzzz",
        "app.bsky.graph.block/aaaa",
        "app.bsky.graph.follow/aaaa",
    ];
    let mut tree = tree_with(keys).await;
    tree.delete("app.bsky.graph.block/aaaa")
        .await
        .expect("delete should succeed");

    assert_eq!(
        sorted_keys(&tree).await,
        vec![
            "app.bsky.feed.post/zzzz".to_string(),
            "app.bsky.graph.follow/aaaa".to_string(),
        ]
    );
}

/// Deleting a key that is not present must not disturb the tree.
#[tokio::test]
async fn deleting_an_absent_key_is_a_no_op() {
    let mut tree = tree_with(KEYS).await;
    let before = sorted_keys(&tree).await;
    tree.delete("app.bsky.feed.post/nope")
        .await
        .expect("deleting an absent key should not error");
    assert_eq!(sorted_keys(&tree).await, before);
}
