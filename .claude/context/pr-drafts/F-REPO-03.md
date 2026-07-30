# fix(repo): rebuild entry compression on delete instead of patching one neighbour

## What and why

`Mst::delete` silently corrupted records it was not asked to touch. This is the one finding in the
gap analysis that destroys user data in place.

MST entries are prefix-compressed against the full key of the **preceding** entry. Removing entry
`d` therefore changes the base that entry `d+1` was encoded against, and repairing that needs two
steps in order:

1. reconstruct `d+1`'s full key against `d` — its original base;
2. re-compress it against `d-1` — its new predecessor.

`delete_recursive` performed only the second. Both of its loops terminated at `d-1`, so
`prev_key` and `old_prev` held the *same* value, and `entries[d+1]` was rebuilt from a key it had
never been encoded against.

Nothing errored. A neighbouring record's key was rewritten in place — and because every later entry
reconstructs against the one before it, the damage ran to the end of the node rather than stopping
at one record.

## Evidence

`crates/atproto-repo/src/mst/tree.rs:365-392` before the fix. The in-line comment at `:378`
("Reconstruct with old prefix logic then recompute") shows the two-step subtlety was recognised and
implemented backwards.

Reproduced on a 20-key repository across four collections, deleting each key in turn from a fresh
tree:

```
3 of 20 single-key deletes did not leave the tree intact:
  deleting app.bsky.feed.like/aaaa    → 9 unexpected keys ["app.bsky.actor.profbbbb",
                                          "app.bsky.actorpost/aaaa", …], 9 missing
  deleting app.bsky.feed.post/aaaa    → 4 records vanish
  deleting app.bsky.graph.follow/aaaa → 4 keys become "app.bsky.feed.post/eeebbbb", …
```

Those are keys that were never inserted, at MST paths that no longer match their own AT-URIs.
`Mst::delete` is reached from `deleteRecord` and `applyWrites` (`repo/writer.rs:300,617`), so an
ordinary user deleting one post moved unrelated records — and the result was committed and signed.

The gap analysis measured "2 corrupt and 1 errored" on its own key set and described the effect as
rewriting "a neighbouring record's key". On this key set it is 3 corrupt, 0 errored, and the
cascade means the blast radius is the rest of the node, not one record.

## The fix

Not the index arithmetic. `delete_recursive` now derives every full key in the node, removes the
deleted one, and rebuilds the whole entry list's compression from the resulting key list.

That makes the error unrepresentable — there is no ordering left to get backwards — and it is what
the reference and every port do, at serialization time
(`packages/repo/src/mst/util.ts:80-110`), which is why the gap analysis found no comparison
implementation with an analogue of this bug.

## Testing

Six tests in a new `crates/atproto-repo/tests/mst_delete.rs`. **Two fail against the previous
code**, including the exhaustive sweep, which reports the full corruption picture rather than the
first failure.

The tests assert what the tree **contains**, not how it is encoded. That is deliberate: the failure
was never visible in the encoding. The node round-tripped perfectly — it simply described different
records than the ones that had been written. A round-trip or byte-level test would have passed
throughout.

Cases: every single-key delete from a fresh tree; every key deleted in sequence to empty; the first
entry (successor rebases to no prefix); the last entry (no re-compression needed); a delete across a
sharp prefix boundary; and an absent key as a no-op.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2053 passed, 0 failed, 63 ignored.**

## Risk and blast radius

Contained. The change alters only how a node's entries are re-encoded after a removal; it cannot
change which keys are present, only stop them being wrong. Node bytes change, but they are already
changing under the encoding fixes in M1.2 and will change again under M1.10.

**No repair path is included.** A repository that has already been corrupted by this stays
corrupted: the wrong keys are committed and signed, and there is no record of what they used to be.
Detecting it after the fact means comparing the MST's key set against `repo_record`, which is a
separate piece of work and not something this branch attempts.

## Found here, deliberately not fixed

`delete_recursive` takes a `depth` parameter, checks it against `max_depth`, and **never recurses**.
It ignores `node.left` and `entry.tree` entirely, so a delete inside a subtree silently does
nothing.

That is invisible today only because `insert` never builds subtrees (F-REPO-04). It becomes live the
moment height-aware insert lands, so **M1.10 has to carry the recursive delete with it** — noted in
the progress ledger as a dependency of that item.

## Resolves

`F-REPO-03` (roadmap M1.9).
