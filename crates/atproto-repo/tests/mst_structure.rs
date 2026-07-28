//! The MST must build the tree shape the protocol specifies, not a flat list.
//!
//! A key's layer is fixed by its hash: `sha256(key)`, leading zero bits, in
//! pairs. Keys land above layer 0 with probability 1/4, so a repository of any
//! realistic size has keys belonging on several layers. Putting them all in one
//! node produces a structure that is internally consistent, round-trips
//! perfectly, and hashes differently from every other implementation's — which
//! is why these tests assert *shape*, and why the upstream vectors in
//! `interop_mst.rs` are what ultimately prove the shape is the right one.

use atproto_dasl::Cid;
use atproto_dasl::storage::{BlockStorage, MemoryStorage};
use atproto_repo::mst::{Mst, MstNode, key_height};

fn value() -> Cid {
    Cid(
        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
            .parse()
            .expect("test CID should parse"),
    )
}

/// Keys of the form `app.bsky.feed.post/<n>`, which spread across layers.
fn generated_keys(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("app.bsky.feed.post/{i:013}"))
        .collect()
}

async fn tree_with(keys: &[String]) -> Mst<MemoryStorage> {
    let mut tree: Mst<MemoryStorage> = Mst::new_in_memory();
    for key in keys {
        tree.insert(key, value())
            .await
            .unwrap_or_else(|err| panic!("insert {key}: {err}"));
    }
    tree
}

async fn load(tree: &Mst<MemoryStorage>, cid: &cid::Cid) -> MstNode {
    let bytes = BlockStorage::get(tree.storage(), cid)
        .await
        .expect("storage read")
        .expect("node should exist");
    atproto_dasl::from_slice(&bytes).expect("node should decode")
}

/// Walk the tree, checking every node holds only keys of its own layer and
/// that subtrees sit exactly one layer below their parent.
async fn assert_layers_consistent(tree: &Mst<MemoryStorage>, cid: &cid::Cid, layer: u32) {
    let node = load(tree, cid).await;
    let mut previous = String::new();
    for entry in &node.entries {
        let key = entry.reconstruct_key(&previous).expect("key reconstructs");
        assert_eq!(
            key_height(&key),
            layer,
            "key {key:?} sits at layer {layer} but hashes to layer {}",
            key_height(&key)
        );
        previous = key;
    }
    if let Some(left) = &node.left {
        assert!(layer > 0, "a layer-0 node cannot have a subtree below it");
        Box::pin(assert_layers_consistent(tree, &left.0, layer - 1)).await;
    }
    for entry in &node.entries {
        if let Some(child) = &entry.tree {
            assert!(layer > 0, "a layer-0 node cannot have a subtree below it");
            Box::pin(assert_layers_consistent(tree, &child.0, layer - 1)).await;
        }
    }
}

/// Count nodes reachable from the root.
async fn count_nodes(tree: &Mst<MemoryStorage>, cid: &cid::Cid) -> usize {
    let node = load(tree, cid).await;
    let mut total = 1;
    if let Some(left) = &node.left {
        total += Box::pin(count_nodes(tree, &left.0)).await;
    }
    for entry in &node.entries {
        if let Some(child) = &entry.tree {
            total += Box::pin(count_nodes(tree, &child.0)).await;
        }
    }
    total
}

/// Thirty keys span three layers, so they cannot all live in one node.
#[tokio::test]
async fn keys_above_layer_zero_create_subtrees() {
    let keys = generated_keys(30);
    let heights: std::collections::BTreeSet<u32> = keys.iter().map(|k| key_height(k)).collect();
    assert!(
        heights.len() > 1,
        "this fixture is only meaningful if the keys span layers; got {heights:?}"
    );

    let tree = tree_with(&keys).await;
    let root = tree.root().expect("a non-empty tree has a root");
    assert!(
        count_nodes(&tree, root).await > 1,
        "30 keys spanning layers {heights:?} collapsed into a single node"
    );
}

/// Every key must sit in a node whose layer matches its own hash.
#[tokio::test]
async fn every_key_sits_at_the_layer_its_hash_dictates() {
    let keys = generated_keys(50);
    let tree = tree_with(&keys).await;
    let root = tree.root().expect("a non-empty tree has a root");
    let root_layer = key_height(
        &load(&tree, root)
            .await
            .entries
            .first()
            .expect("root should hold at least one key")
            .reconstruct_key("")
            .expect("key reconstructs"),
    );
    assert_layers_consistent(&tree, root, root_layer).await;
}

/// Structure must not cost content: every key inserted is still readable and
/// enumerable, in order.
#[tokio::test]
async fn every_key_remains_readable_and_ordered() {
    let keys = generated_keys(50);
    let tree = tree_with(&keys).await;

    for key in &keys {
        assert!(
            tree.get(key).await.expect("get should succeed").is_some(),
            "{key} is missing after insert"
        );
    }

    let listed: Vec<String> = tree
        .entries()
        .await
        .expect("entries should enumerate")
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut expected = keys.clone();
    expected.sort();
    assert_eq!(listed, expected, "enumeration must be sorted and complete");
}

/// Insertion order must not change the tree. A Merkle search tree is
/// history-independent by construction — the same key set has one shape,
/// whatever order it arrived in — and a root CID that depends on order would
/// diverge from a peer holding identical records.
#[tokio::test]
async fn the_root_is_independent_of_insertion_order() {
    let keys = generated_keys(40);
    let forward = tree_with(&keys).await;

    let mut shuffled = keys.clone();
    shuffled.reverse();
    let backward = tree_with(&shuffled).await;

    let mut interleaved: Vec<String> = Vec::new();
    let (front, back) = keys.split_at(keys.len() / 2);
    for (a, b) in front.iter().zip(back.iter()) {
        interleaved.push(b.clone());
        interleaved.push(a.clone());
    }
    let mixed = tree_with(&interleaved).await;

    assert_eq!(
        forward.root(),
        backward.root(),
        "reversed order changed the root"
    );
    assert_eq!(
        forward.root(),
        mixed.root(),
        "interleaved order changed the root"
    );
}

/// Deleting back to empty must return the tree to its original root, not to a
/// residue of structural layers.
#[tokio::test]
async fn deleting_back_to_a_prior_state_restores_its_root() {
    let keys = generated_keys(40);
    let base = tree_with(&keys[..30]).await;
    let base_root = *base.root().expect("root");

    let mut grown = tree_with(&keys[..30]).await;
    for key in &keys[30..] {
        grown.insert(key, value()).await.expect("insert");
    }
    for key in &keys[30..] {
        grown.delete(key).await.expect("delete");
    }

    assert_eq!(
        grown.root().copied(),
        Some(base_root),
        "growing and shrinking left a different tree than never growing"
    );
}

/// Deleting every key must empty the tree, not leave hollow layers behind.
#[tokio::test]
async fn deleting_everything_empties_the_tree() {
    let keys = generated_keys(40);
    let mut tree = tree_with(&keys).await;
    for key in &keys {
        tree.delete(key).await.expect("delete");
    }
    assert_eq!(tree.root(), None, "tree should be empty");
    assert!(tree.entries().await.expect("entries").is_empty());
}
