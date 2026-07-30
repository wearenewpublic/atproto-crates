# fix(repo): emit MST `l`/`t` and commit `prev` as null rather than omitting them

## What and why

The AT Protocol data model types four fields as **nullable, not optional**: the key must be present,
carrying `null` when there is no value. This workspace treated all four as optional and dropped the
key instead, via `#[serde(skip_serializing_if = "Option::is_none")]` on `MstNode.l`, `TreeEntry.t`,
and `prev` on both `Commit` and `UnsignedCommit`.

Omitting a key changes the CBOR map header, which changes the bytes, which changes the hash. So
**every MST root CID and every commit CID this workspace has ever produced differs from what a peer
computes** — including for a single-record repository, where tree shape cannot differ. CAR exports
are rejected, and commit signatures verify against the wrong bytes, because the attribute on
`UnsignedCommit.prev` sits directly on the signing path: `Commit::signing_bytes` serializes that
struct.

The break is one-directional and stays that way. This crate could always read the network's bytes;
the network could not verify this crate's.

## Evidence

### Before

| Site | |
| --- | --- |
| `crates/atproto-repo/src/mst/node.rs:30` | `#[serde(rename = "l", skip_serializing_if = "Option::is_none")]` |
| `crates/atproto-repo/src/mst/entry.rs:54` | same, for `t` |
| `crates/atproto-repo/src/repo/commit.rs:52` | `#[serde(skip_serializing_if = "Option::is_none")]` on `Commit.prev` |
| `crates/atproto-repo/src/repo/commit.rs:83` | the same on `UnsignedCommit.prev` — **the signing path** |

### After

All four clauses removed. No logic changes; the doc comment on each field now states why the key is
written unconditionally.

### What changes on the wire

Single-entry node, no subtrees:

```
before  a1 { e: [ a3 { k, p, v } ] }                        76 bytes
after   a2 { e: [ a4 { k, p, t: null, v } ], l: null }      82 bytes
```

Initial commit (five-key signed body):

```
before  a4 { did, rev, data, version }                     112 bytes
after   a5 { did, rev, data, prev: null, version }         118 bytes
```

The 76/82 pair reproduces the byte counts the gap analysis measured by execution.

## Worked reference

`packages/repo/src/mst/util.ts:80-88` — `serializeNodeData` initialises the node as `{ l: null, e: [] }`
and only overwrites `l` when a left subtree exists, and always writes `t: subtree` whether or not it
is null. `packages/repo/src/types.ts:21,27` types `prev` as `cidSchema.nullable()` on both
`_unsignedCommit` and `commit`.

indigo's commit struct carries the comment that `omitempty` "would break signature verification for
repo v3". dnproto (`src/repo/RepoMst.cs:152-158,208-214`) and zat (`src/internal/repo/mst.zig:571,600`)
both emit the keys explicitly. rsky-repo declares `NodeData { l: Option<Cid>, … }` with no skip. The
comparisons are unanimous — this is not "only the reference does this".

## Testing

New `crates/atproto-repo/tests/known_answer_encoding.rs` — six vectors asserting exact DAG-CBOR bytes
written out from the specification, **not** produced by this crate. Each carries its byte layout in a
doc comment.

| Vector | canonical | before fix |
| --- | ---: | ---: |
| single-entry node, no subtrees | 82 B | 76 B |
| node with a left subtree | 122 B | 119 B |
| entry with a right subtree | 122 B | 119 B |
| unsigned initial commit | 118 B | 112 B |
| signed initial commit | 188 B | 182 B |
| legacy node without `l`/`t` decodes, re-encodes to 82 B | — | fails |

**All six were confirmed failing against the unmodified code** by stashing the source changes and
re-running, with exactly those deltas.

That they are byte-level rather than round-trip is the point. `atproto-repo` already had round-trip
coverage of nodes and commits (`mst/serialize.rs`, `mst/tree.rs`) and it passed the entire time the
encoding was wrong, because encode-then-decode agrees with itself no matter what the encoder does.
No existing test in the workspace had to change: not one of 1997 pinned the old bytes.

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` are green — **2003 passed, 0 failed, 63 ignored.**

### What this does not fix

The six upstream commit-proof vectors in `crates/atproto-repo/tests/interop_mst.rs` still fail, and
their `KNOWN_FAILURES` entries are unchanged and still accurate. Their root CIDs move but do not
land on the upstream answers, because those vectors were chosen to exercise node splitting and
F-REPO-04 (the MST write path never builds subtrees) is also required. Both findings must land
before any of them flip — which is what the entries say.

## Risk and blast radius

**This changes the bytes every MST node and commit hashes to.** Existing repositories get a new MST
root CID and a new commit CID on their next write, and the blocks written under the old encoding
become unreferenced. That is the fix working, not a side effect, but it is a real migration note for
any live deployment and it is in the CHANGELOG.

Reading is unaffected in both directions, which the sixth vector pins: nodes stored without `l`/`t`
still decode (serde defaults a missing `Option` to `None`) and re-encoding one now produces the
canonical form. Verification of *old* commits against their *old* stored bytes is unchanged — the
stored `sig` is over the stored bytes.

## Deliberately out of scope

- **`prevData` inside the signed commit body** (F-REPO-02). Its two `skip_serializing_if` clauses at
  `commit.rs:59,93` are untouched. The reference schemas quoted above have no `prevData` on either
  commit type at all, so this is a field-presence question, not an attribute question, and removing
  the field belongs with that finding.
- **`RepoOp.cid` / `RepoOp.prev`** (`mst/diff.rs:170,173`) keep their skip attributes. They are
  firehose event fields, not part of any hashed structure; `#repoOp.cid` as null is F-FIRE-04.
- `Commit` and `UnsignedCommit` duplicate their field lists by hand, which is what let the attribute
  on the signing path drift out of the gap analysis's citation. Not restructured here.

## A correction to the gap analysis

The report describes F-REPO-01 as "removing three attributes" and cites `node.rs:30`, `entry.rs:54`
and `commit.rs:52`. There are **four**: it missed `commit.rs:83`, the same attribute on
`UnsignedCommit.prev`. Fixing only the three cited would have left the signed bytes wrong while
appearing to resolve the finding — the commit CID would be right and the signature over it would
not.

## Resolves

`F-REPO-01` (roadmap M1.2).
