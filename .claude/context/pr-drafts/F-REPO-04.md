# feat(repo): build the MST by key height, with splitting, merging and trimming

## What and why

The write path never built subtrees. `key_height` was correct — `sha256(key)`, leading zero bits, in
pairs, matching the reference exactly — and then thrown away:

```rust
let _target_height = key_height(key);   // mst/tree.rs:236
```

`insert_recursive` never called itself and never set `l` or `t`, so every repository was one flat
node. A key reaches layer 1 or above with probability 1/4, so this diverges at about a dozen
records.

**Measured before this change:** 30 keys spanning three layers (24 at layer 0, five at layer 1, one
at layer 2) collapsed into a single 1,691-byte node with zero subtrees, rewritten in full on every
insert.

## The result

**All six upstream commit-proof vectors now pass, before and after commit.** This is the first time
the workspace has produced MST root CIDs a peer can recompute.

The `KNOWN_FAILURES` table added with the conformance harness did exactly what it was built for — it
failed the suite to report that its entries were stale, naming the finding each had been waiting on:

```
vector "two deep split" now PASSES — F-REPO-01 + F-REPO-04 appears to be fixed.
  Remove it from KNOWN_FAILURES in this file.
… ×6
```

The table is now empty. Worth recording, because it was the open question when the vectors first
landed: **F-REPO-01 corrected the node encoding and F-REPO-04 the tree shape, and neither alone
moved a single vector.** Both were load-bearing, exactly as the annotation predicted.

## How it works

Insert places a key at the layer its hash dictates — three cases, no others:

| Case | Action |
| --- | --- |
| key height **==** node layer | Slot in, splitting any subtree that spans the position it lands in |
| key height **<** node layer | Descend into the child before that position, creating intermediate layers when the gap is empty |
| key height **>** node layer | Split the existing tree around the key; both halves hang off a new root, with bare structural layers inserted when the jump is more than one |

Deletion needed the inverse to work at all:

- **Merge.** Removing a leaf can leave the subtrees that flanked it adjacent, which no valid node
  represents. Every key in the left is below every key in the right, so they are one subtree and are
  joined — recursively, when the seam is itself two subtrees.
- **Trim.** Layers left holding no key are dropped. A hollow layer is real structure to a hash, so
  leaving it gives a different root than the same content built from scratch.

## Two read paths changed with it — disclosed in advance

Both were silently broken the moment subtrees exist, and both were invisible while the tree was
always flat. I flagged these before starting rather than widening scope quietly:

- **`get`** descended on a `key_height` heuristic and only consulted `l` after its loop broke. It now
  follows the structural position: the first leaf at or after the key bounds the search, and anything
  smaller is in the child immediately before it.
- **`delete`** ignored `l` and `t` entirely, so a delete inside a subtree would have done nothing.
  It now recurses. (Noted as a hard dependency of this item when the delete-corruption fix landed.)

`diff.rs` and the CAR export path are untouched, as promised.

## Structure of the change

The algorithm is stated over a node's children as **one interleaved sequence** of leaves and
subtrees, in a new `mst/entries` module, rather than over the serialized `{l, e[{p,k,v,t}]}` form:

```
  l   e0   e0.t   e1   e1.t   e2 …
  ↓    ↓     ↓     ↓     ↓     ↓
Tree Leaf  Tree  Leaf  Tree  Leaf …
```

Prefix compression is derived when that sequence is written back, never carried — the same
discipline that removed the delete corruption in the previous branch, applied to the whole module.
`to_node` rejects adjacent subtrees, which is how the missing merge announced itself rather than
producing a quietly malformed node.

## Worked reference

`packages/repo/src/mst/mst.ts:228-300` (`add`), `:464-514` (`splitAround`, `appendMerge`),
`:519-533` (`createChild`, `createParent`), and `util.ts:38-44` (`layerForEntries`). arroba's
`split_around`/`append_merge`/`trim_top` (`mst.py:287-457,563-614`) and rsky-repo
(`mst/mod.rs:601,741`) implement the same shape.

## Testing

The six upstream vectors are the acceptance criterion and they are external — I did not invent them,
and they were chosen upstream to exercise exactly this ("two deep split", "two deep leafless split",
"merge and split in multi-op commit").

Alongside them, six structural tests asserting properties the vectors cannot localise:

| Test | Fails on `main`? |
| --- | --- |
| subtrees exist at all for layer-spanning keys | yes |
| every key sits at the layer its hash dictates | yes |
| all keys readable and enumeration sorted | no — content was never the problem |
| root independent of insertion order | no — order cannot matter in a flat node |
| grow-then-shrink returns the exact prior root | no |
| deleting everything empties the tree | no |

Stated plainly: two of the six fail against the previous code. The other four pass there for reasons
that stop being true once the tree has shape, which is why they are worth keeping.

Seven unit tests on the interleaved representation, including the adjacent-subtree rejection.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2066 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**Every root CID changes.** That is the entire point — they were wrong — but it means any stored
repository's root will not match what this code now computes for the same records. Nothing in the
workspace pins a root CID, and the firehose is not yet consumable by a relay for other reasons, so
there is no downstream consumer relying on the old values.

The rewrite touches the whole `mst/tree.rs` write path plus `get` and `delete`. The full suite passes
unchanged, including the delete-corruption tests from the previous branch and every PDS integration
test — those exercise real repositories through the HTTP layer, so the restructuring is covered end
to end and not only in unit tests.

`max_depth` now bounds real recursion rather than a loop that never recursed.

## What this does not do

- **No migration for existing repositories.** They will be re-rooted on the next write, which is
  correct, but nothing rebuilds them into canonical shape ahead of time.
- **Covering proofs** (F-FIRE-06) are still absent; the vectors' `blocksInProof` field is
  deliberately not asserted.
- Record encoding (F-REPO-05) and the firehose envelope (F-FIRE-01) are unchanged.

## Resolves

`F-REPO-04` (roadmap M1.10).

Because merging and trimming turned out to be required for delete to function at all — not merely
for canonical output — the split into two branches collapsed: `rootAfterCommit` went green with
`rootBeforeCommit`. There is no B-2 left to do.
