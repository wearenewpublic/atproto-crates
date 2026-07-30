# B. Repo & data model — MST, commit objects, DAG-CBOR, CIDs, CAR

Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
and the [synthesis and roadmap](../50-synthesis-and-roadmap.md).

## Assessment

This area is not about how many endpoints a server answers. It is about whether the bytes it
produces are the same bytes every other implementation would produce for the same logical repository.
An AT Protocol repository is a Merkle Search Tree of `collection/rkey` → record CID, serialized as
DAG-CBOR nodes, rooted in a signed commit object, and shipped as a CAR v1 archive. Every layer is
content-addressed, so a one-byte difference anywhere — a map key emitted as absent instead of `null`,
a `$link` left as a string instead of a CBOR tag-42 link, a subtree that was never split — changes
the record CID, then the MST root, then the commit CID, then the signature. There is no partial
credit: either an independent verifier recomputes your root or it does not.

atproto-crates has built the lower half of this stack well and the upper half incorrectly. The DASL
layer (`crates/atproto-dasl`) is the best-engineered part of the workspace in this area: a strict
DAG-CBOR codec (`tests/strict_test.rs:10-135`), canonical map-key ordering
(`src/drisl/ser/serializer.rs:340-341,388-389,442`), an exactly-right CID profile
(`src/cid/mod.rs:690-697,730-737` plus the DASL validator at `:655-685`), and a streaming,
DoS-hardened CAR v1 reader (`src/car/reader.rs:129-181`) — better hardened than the reference's
`readCar`, which buffers the whole archive into a `BlockMap`
(`/tmp/gap-scratch/atproto/packages/repo/src/car.ts:56-66`).

The repo layer on top of it (`crates/atproto-repo`) does not produce conformant output. I verified
this by execution, not inference. The MST write path never splits: `insert_recursive` computes
`key_height(key)` and immediately discards it as `_target_height`
(`crates/atproto-repo/src/mst/tree.rs:236`) and never calls itself, so a 30-record repo containing
keys at heights 1, 2, 3 and 5 collapses into a single root node with 30 entries and zero subtrees.
The node encoding then omits `l` and `t` entirely instead of writing `null`
(`crates/atproto-repo/src/mst/node.rs:30`, `entry.rs:54`), so even a *one-record* repo — where tree
shape cannot differ — produces MST root `bafyreicdju2ykiut3j3kvuytqd4oaoe5fxgvgeexhuiqol55cw4zl2vkeu`
against the canonical shape's `bafyreiagd2nthpemvrihlk7jx4y6oxic2b6vegrewbie2uh4c45olsj5b4`. The
commit object omits `prev` when null and carries `prevData` inside the signed body, neither of which
the reference schema accepts. Records are encoded straight from `serde_json::Value`, so a blob ref
`{"$link":"bafk…"}` is stored as a literal CBOR map with a `$link` text key rather than a tag-42
link, and a JSON `1.5` is stored as a CBOR float. And `Mst::delete` corrupts the tree: in a
20-record four-collection repo, 2 of 20 single-record deletes silently rewrite the *following*
record's key, and 1 errors outright.

**Nothing here is "only the reference does this."** Every implementation I opened emits the canonical
node encoding, including dnproto — a single-user C# PDS with a hand-rolled DAG-CBOR stack — which
writes `"l": null` and `"t": null` explicitly
(`/tmp/gap-scratch/dnproto/src/repo/RepoMst.cs:144-160,192-215`), and zds, which hard-codes the byte
pair `0x61 'l' 0xf6` (`/tmp/gap-scratch/zat/src/internal/repo/mst.zig:571,600`). On the commit object,
indigo — the library cocoon builds on — carries a comment naming precisely this trap:
`Prev *cid.Cid \`json:"prev" cborgen:"prev"\` // NOTE: omitempty would break signature verification
for repo v3` (`indigo@v0.0.0-20260120225912/atproto/repo/commit.go:18` in the local module cache). On
low-S, the reference signs `lowS: true` for both curves and rejects high-S on verify
(`packages/crypto/src/p256/{keypair.ts:60,operations.ts:32}`), and arroba, pegasus, rsky-pds, dnproto
and zds each implement it by hand. On `$link` → tag 42, ten of eleven comparisons do the conversion;
the exception is arroba, whose `uploadBlob` returns 501 so the case barely arises. The framing for
this chapter is not "atproto-crates is behind the reference" but "atproto-crates is behind the entire
field, including the two implementations that are not trying to be general-purpose servers."

---

## Per-capability analysis

### CID profile and DAG-CBOR codec

`compute_cid` builds CIDv1 with `DAG_CBOR_CODEC` + SHA-256
(`crates/atproto-dasl/src/cid/mod.rs:690-697`); `compute_raw_cid` uses `RAW_CODEC` (`:730-737`) and
is what the PDS uses for blobs (`crates/atproto-pds/src/blob.rs:70`). The string form is base32lower
(confirmed by execution: `bafyrei…`, `bafkrei…`), and the wire form is tag 42 plus the
identity-multibase `0x00` prefix (`cid/mod.rs:13-16,55-61`), matching
`/tmp/gap-scratch/atproto/packages/lex/lex-cbor/src/encoding.ts:47-53`. A DASL validator enforces
CIDv1-only, codec ∈ {raw, dag-cbor}, hash ∈ {sha2-256, BLAKE3} and a 32-byte digest
(`cid/mod.rs:655-685`), applied to every CAR block by default (`car/config.rs:78-84` →
`car/reader.rs:176-179`) — stricter than pegasus, which accepts a zero-length digest
(`/tmp/gap-scratch/pegasus/ipld/lib/cid.ml:68`).

Map and struct serialization buffers `(encoded_key, encoded_value)` pairs and sorts by encoded key
bytes before writing the header (`drisl/ser/serializer.rs:340-341,388-389,442`). Because a CBOR
text-string header encodes its length in the first byte, that yields length-first-then-bytewise —
the DAG-CBOR canonical rule, matching pegasus's explicit `dag_cbor_key_compare`
(`/tmp/gap-scratch/pegasus/ipld/lib/dag_cbor.ml:4-7`). I confirmed the resulting commit key order:
`did`, `rev`, `data`, `prev`, `version`, `prevData`. Decode strictness is real and tested —
non-minimal integers, indefinite lengths, forbidden simple values, tags 0/1/2/3 and sub-64-bit floats
all rejected, NaN/Infinity rejected on encode (`crates/atproto-dasl/tests/strict_test.rs:10-135`).

**Classification: conformant**, with one process gap: the community DASL conformance vectors are a
git submodule (`.gitmodules` → `crates/atproto-dasl/tests/dasl-testing`) that is **empty in this
checkout**, and the harness panics on a missing fixture
(`crates/atproto-dasl/tests/dasl_compliance_test.rs:139`), so `cargo test -p atproto-dasl` cannot pass
without an explicit `git submodule update`. `.github/workflows/` contains only
`release-binaries.yml`, so nothing inits it.

### AT Protocol data model: `$link` → tag 42, `$bytes`, and non-integer numbers

This is the gap with the widest blast radius and it is not in `atproto-dasl` at all; it is the
missing JSON→IPLD conversion in the PDS write path. `RepoWriter` takes the client's
`serde_json::Value` and hands it straight to the DAG-CBOR encoder:
`atproto_dasl::to_vec(&value)` at `crates/atproto-pds/src/repo/writer.rs:223` (legacy path) and
`:545` (dispatch path). Grepping `crates/atproto-pds/src` for `$link` returns only
`blob.rs:42` — the `uploadBlob` response struct — and nothing on the ingest side.

Encoding the canonical image-post shape through that path produces:

```
…6472656661 6165 246c696e6b 783b 6261666b7265696232…   ("ref": {"$link": "bafkreib2…"})
…6573636f7265 fb3ff8000000000000                        ("score": 1.5 as CBOR float64)
```

No `d82a` (tag 42) anywhere. The reference converts `{"$link": …}` to a `Cid` before encoding
(`/tmp/gap-scratch/atproto/packages/lex/lex-json/src/blob.ts:54-57`, `lex-cbor/src/encoding.ts:47-53`)
and **throws** on any non-safe-integer number (`lex-cbor/src/encoding.ts:61-66`). Every comparison
except arroba does the conversion: tranquil-pds `json_to_ipld`
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/util.rs:283-296`, `$link` and `$bytes`), zds
`jsonToDagCbor` (`/tmp/gap-scratch/zds/src/storage/store.zig:5210-5230`, which additionally rejects
floats), alteran (`/tmp/gap-scratch/alteran/src/lib/repo-write-data.ts:64,96-108`, with a canonical
CID-string check), pegasus (`/tmp/gap-scratch/pegasus/pegasus/lib/user_store.ml:15`), metalbear
(`/tmp/gap-scratch/metalbear/src/repo_store.c:127-131`), dnproto
(`/tmp/gap-scratch/dnproto/src/repo/DagCborObject.cs:639-660`), rsky-pds
(`/tmp/gap-scratch/rsky/rsky-repo/src/util.rs:63-69`), cocoon via `atdata.UnmarshalJSON`
(`/tmp/gap-scratch/cocoon/server/repo.go:312,334`), cirrus via `@atproto/repo@0.8.12`.

**Classification: MISSING.** Consequence: every record containing a blob — profile avatars and
banners, image posts, video posts — has a record CID no other implementation would compute, and a
body that fails `blob`-typed lexicon validation on the receiving side.

### MST tree shape and key height

`key_height` itself is correct: SHA-256 of the key, count leading zero bits, divide by 2 for fanout 4
(`crates/atproto-repo/src/mst/key.rs:30-34`) — bit-for-bit equivalent to the reference's
`leadingZerosOnHash`, which counts the same quantity in 2-bit chunks
(`/tmp/gap-scratch/atproto/packages/repo/src/mst/util.ts:23-38`). Key ordering is bytewise
(`key.rs:94-96`) and keys must split as `collection/rkey` (`key.rs:60-88`).

The write path never uses it. `Mst::insert` calls `insert_recursive(root, …, 0)`
(`crates/atproto-repo/src/mst/tree.rs:208`); `insert_recursive` binds
`let _target_height = key_height(key);` at `:236`, discards it, splices the entry into the loaded
node's `entries` vector and stores the node (`:274-313`) — it never recurses, and
`delete_recursive` (`:342-423`) does not either. Only the read paths recurse (`:177,189,458,468`), so
the crate can *read* a conformant tree it can never *write*. Executed: 30 keys with heights
`{0: 23, 1: 4, 2: 1, 3: 1, 5: 1}` yield one root node, 30 entries, 0 subtrees, 1,597 bytes, and 30
stored blocks — one full-node rewrite per insert.

**Classification: PARTIAL (structurally incorrect).** Every serious comparison implements the real
algorithm: the reference (`packages/repo/src/mst/mst.ts:228-460`), arroba with
`split_around`/`append_merge`/`trim_top` (`/tmp/gap-scratch/arroba/arroba/mst.py:287-457,563-614`),
rsky-repo (`/tmp/gap-scratch/rsky/rsky-repo/src/mst/mod.rs:601,741`), pegasus's 1,898-line
`mist/lib/mst.ml`, zat's 2,318-line `mst.zig`, alteran's port
(`/tmp/gap-scratch/alteran/src/lib/mst/mst.ts`), cocoon via indigo's `node_insert.go`/`node_remove.go`,
cirrus via `@atproto/repo`. dnproto is the one partial — a real tree, rebuilt from the record table on
every write (`/tmp/gap-scratch/dnproto/src/pds/UserRepo.cs:225`).

### MST node wire encoding

`MstNode` declares `#[serde(rename = "l", skip_serializing_if = "Option::is_none")]`
(`crates/atproto-repo/src/mst/node.rs:30`) and `TreeEntry` the same for `t` (`mst/entry.rs:54`). The
canonical schema makes both **nullable, not optional** — `subTreePointer = z.nullable(schema.cid)`
used for `l` and `t` (`/tmp/gap-scratch/atproto/packages/repo/src/mst/mst.ts:45-56`) — and
`serializeNodeData` initializes `{ l: null, e: [] }` and always writes `t: subtree`
(`packages/repo/src/mst/util.ts:80-110`). Executed, for a single-entry node with no subtrees:

| | node map | entry map | length | node CID |
|---|---|---|---|---|
| atproto-crates | `a1` (`e`) | `a3` (`k`,`p`,`v`) | 76 B | `bafyreicdju2ykiut3j3kvuytqd4oaoe5fxgvgeexhuiqol55cw4zl2vkeu` |
| canonical | `a2` (`e`,`l`) | `a4` (`k`,`p`,`t`,`v`) | 82 B | `bafyreiagd2nthpemvrihlk7jx4y6oxic2b6vegrewbie2uh4c45olsj5b4` |

**Classification: DIVERGENT.** This alone guarantees a mismatched `data` CID for *any* repository,
independent of the flat-tree defect. Decoding is unaffected — `MstNode::from_bytes` parses the
canonical form correctly — so the break is one-directional: atproto-crates can read the network's
bytes but the network cannot verify atproto-crates'. The comparisons are unanimous: indigo
`cborgen:"l"`/`cborgen:"t"` with no `omitempty` (`indigo/atproto/repo/mst/encoding.go:18,27`), zat's
literal `0x61 'l' 0xf6` (`/tmp/gap-scratch/zat/src/internal/repo/mst.zig:571,600`), dnproto's explicit
null branches (`/tmp/gap-scratch/dnproto/src/repo/RepoMst.cs:152-158,208-214`), alteran's
`{ l: null, e: [] }` ([alteran notes](../impl-notes/alteran.md);
`/tmp/gap-scratch/alteran/src/lib/mst/serialize.ts:55,85`), and rsky-repo's
`NodeData { l: Option<Cid>, … }` with no skip (`/tmp/gap-scratch/rsky/rsky-repo/src/mst/mod.rs:244-247`).

### MST delete corrupts neighbouring keys

`delete_recursive` removes the entry, then tries to repair the prefix compression of the following
entry. It reconstructs that entry's key against `old_prev` — the key at index `delete_idx - 1`
(`crates/atproto-repo/src/mst/tree.rs:379-390`) — but entry `delete_idx + 1`'s `prefix_len` is
relative to the key at `delete_idx`, the entry just removed (`tree.rs:392`). Whenever the deleted key
and its successor share a longer prefix than the deleted key's predecessor does, the reconstruction
silently produces a wrong key.

Executed on `[…feed.like/aaaa, …feed.post/bbbb, …graph.follow/cccc, …graph.follow/dddd]`, deleting
`app.bsky.graph.follow/cccc` leaves `app.bsky.feed.post/bbbdddd` where
`app.bsky.graph.follow/dddd` used to be. Swept across a 20-record, four-collection repo:
**17 deletes clean, 2 corrupt, 1 errors** — and it cascades, because one bad key mis-seeds every later
reconstruction in the node, so a single delete moved nine records into a nonexistent
`app.bsky.actorpost` collection.

Reachable from the PDS: `deleteRecord` and `applyWrites` deletes call `mst.delete(&mst_key)` at
`crates/atproto-pds/src/repo/writer.rs:300` and `:617`, and because the tree is flat every record in
the repo lives in the one node the bug operates on. The relational `repo_record` index keeps the
correct URI, so `getRecord` and `listRecords` keep answering correctly — the damage is invisible until
`getRepo` exports the tree or the next delete of the affected record fails.

**Classification: DIVERGENT (data corruption).** No comparison has an analogue. Structurally they
cannot: the reference, arroba, alteran, zat and dnproto all keep full keys in memory and recompute
every prefix at serialization time (`packages/repo/src/mst/util.ts:80-110`;
`/tmp/gap-scratch/arroba/arroba/mst.py:1051`; `/tmp/gap-scratch/zat/src/internal/repo/mst.zig:583-598`;
`/tmp/gap-scratch/dnproto/src/repo/RepoMst.cs:164,262-266`), rather than patching individual
`prefix_len` fields in place.

### Commit object field set

`Commit` is `{did, version, data, rev, prev?, prevData?, sig}` with `skip_serializing_if` on both
optional CIDs (`crates/atproto-repo/src/repo/commit.rs:37-62`); `UnsignedCommit` mirrors it (`:68-89`).
`version` is hardcoded to 3 and enforced (`commit.rs:97,116,188-192`), and signing bytes are the DAG-CBOR
of the unsigned struct (`:129-142`) — both right. Two field-set divergences, verified by executing the
encoder:

- **Initial commits omit `prev` entirely** — the map header is `a4` over `did`, `rev`, `data`,
  `version`. The canonical schema is `prev: cidSchema.nullable()`
  (`/tmp/gap-scratch/atproto/packages/repo/src/types.ts:27` on `_unsignedCommit`, `:36` on
  `commit`) — nullable, not optional — and the
  reference writes `prev: null` on every commit it formats (`packages/repo/src/repo.ts:62,167,212`).
  A missing key fails the zod parse in `parseObjByDef` (`packages/repo/src/parse.ts:31-42`), which
  throws `UnexpectedObjectError` before any signature check runs.
- **`prevData` sits inside the signed commit body.** It is not a commit field anywhere in the
  reference: grepping `packages/` and `lexicons/` finds it only on `CommitDataWithOps`
  (`packages/pds/src/repo/types.ts:42`), the sequencer event (`sequencer/events.ts:32,140`) and
  `subscribeRepos.json:98`. Since zod strips unknown keys and `verifyCommitSig` re-encodes the
  *parsed* object (`packages/repo/src/util.ts:94-101`), a commit carrying `prevData` fails signature
  verification even when it parses.

**Classification: DIVERGENT.** rsky-repo shows the correct Rust shape — `prev: Option<Cid>` with no
`skip_serializing_if`, so serde emits `null`, and no `prevData` field
(`/tmp/gap-scratch/rsky/rsky-repo/src/types.rs:16-35`).

### Low-S signature normalization

`atproto_identity::key::sign` calls `try_sign` and returns `signature.to_vec()` unmodified for all
three ECDSA curves (`crates/atproto-identity/src/key.rs:434-463`), and `validate` verifies with no
malleability gate (`key.rs:296-414`). Per curve, from the vendored crates: **K-256 is low-S**, but by
accident of the dependency — `k256-0.13.4/src/ecdsa.rs:194` normalizes inside `SignPrimitive` and
`:200-203` rejects high-S on verify — and the PDS mints K-256 account keys
(`crates/atproto-pds/src/bin/pds.rs:425-430`), so production commit signatures happen to be
conformant. **P-256 is not**: `p256-0.13.2/src/ecdsa.rs:72,75` are the empty default `SignPrimitive`
and `VerifyPrimitive` impls, so any P-256 key produces a malleable signature the reference rejects
about half the time (`/tmp/gap-scratch/atproto/packages/crypto/src/p256/operations.ts:32`,
`lowS: !allowMalleable`). **P-384 is not either** (`p384-0.13.1/src/ecdsa.rs:69,72`), and is not an
atproto curve at all — the reference plugin registry is exactly `[p256Plugin, secp256k1Plugin]`
(`packages/crypto/src/plugins.ts:4`), so P-384 and Ed25519 signing keys are unverifiable by the
network regardless. The workspace already contains the right helper —
`crates/atproto-attestation/src/signature.rs:30-80` — and `atproto-pds` neither depends on nor
references that crate.

**Classification: PARTIAL.** The reference signs `lowS: true` on both curves
(`packages/crypto/src/{p256,secp256k1}/keypair.ts:60`); zds normalizes on sign *and* rejects high-S on
verify (`/tmp/gap-scratch/zat/src/internal/crypto/jwt.zig:284-286,291-297`); cocoon via indigo does
both (`indigo/atproto/atcrypto/p256.go:116,222`); rsky-pds normalizes in `rsky-crypto`
(`p256/operations.rs:92`, `secp256k1/operations.rs:63`); dnproto hand-wrote `NormalizeLowS` for both
curves (`/tmp/gap-scratch/dnproto/src/auth/Signer.cs:545-560`); pegasus normalizes on sign but not on
verify (`/tmp/gap-scratch/pegasus/kleidos/low_s.ml:25-56`); arroba normalizes explicitly, K-256 only
(`/tmp/gap-scratch/arroba/arroba/util.py:271-321`); alteran and cirrus inherit `@atproto/crypto`.

### Commit signature verification on read and import

`RepoConfig` declares `verify_signatures: true` by default (`crates/atproto-repo/src/config.rs:36,49`)
and nothing in `atproto-repo` ever reads it — the crate contains only the field, the builder (`:95-97`)
and its own unit tests, and `Repository::from_car_with_storage` sets `signature_verified: None`
(`repo/mod.rs:255-260`). On the PDS side, `verify_chain_signatures` is gated on an optional
`PlcVerifier` (`crates/atproto-pds/src/repo/import.rs:240-242`) that `RepoImporter::new` leaves as
`None` (`:113`), and **the handler never wires one** — `import_repo` attaches only the storage backend
(`http/write_handlers.rs:618-620`), and `with_plc_verifier` has no caller. That resolves the question
left open in [the inventory](../00-atproto-crates-inventory.md). No `commit.did == account_did` check
exists either (`import.rs:157-235`), and even enabled the key selection compares an ISO-8601 PLC
timestamp against a TID `rev` (`:424`), so it would always pick the newest key.

**Classification: MISSING — but the reference does the same, which changes the severity.** The
reference's `importRepo` passes `undefined` for both `did` and `signingKey`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/importRepo.ts:53-60`) and
`verifyRepoRoot` then skips both checks (`packages/repo/src/sync/consumer.ts:108-125`). Three
independents *do* verify: arroba (`/tmp/gap-scratch/arroba/arroba/xrpc_repo.py:241-244`), zds
(`/tmp/gap-scratch/zds/src/atproto/repo.zig:343-395`) and metalbear
(`/tmp/gap-scratch/metalbear/src/repo_store.c:2785-2856`); cocoon skips but re-signs locally
(`/tmp/gap-scratch/cocoon/server/handle_import_repo.go:105`). What the reference does that
atproto-crates does not is structural: `verifyDiff` yields `diff.writes`, and every one is pushed
through `store.record.indexRecord` + `store.repo.blob.insertBlobs` (`importRepo.ts:66-97`), so the
imported repo is immediately readable. atproto-crates writes blocks and `commit_obj` and stops — see
[migration](./31-migration.md).

### CAR v1 read, write, and export

The `atproto-dasl` CAR layer is correct and streaming both ways: `next_block` checks the declared wire
length against `max_block_size` *before* allocating, plus `max_block_count` and `max_car_size`, then
content- and format-verifies each block (`crates/atproto-dasl/src/car/reader.rs:129-181`); `CarWriter`
streams to any `AsyncWrite` (`car/writer.rs:60-77`); `stream_to_storage` pipes straight into a
`BlockStorage` (`car/reader.rs:184-193`). The PDS discards that. Every exporter walks reachability
into a `Vec<CarBlock>` then writes into a
`Vec<u8>` — `export_repo_car` (`crates/atproto-pds/src/repo/car_export.rs:56-108`),
`export_repo_car_since` (`:189-245`), and four backend variants (`:288-574`) — so a repo materializes
twice in RAM with no ceiling, and the walk **silently skips missing blocks** (`car_export.rs:66-71`),
exporting a corrupted repo as a short CAR with a success status. Import is buffered too:
`import_from_stream` drains every block into a `Vec` (`crates/atproto-pds/src/repo/import.rs:174-192`,
4 GiB default at `:112`) despite the module doc at `:21-27` claiming otherwise, and the handler
buffers the body into `Bytes` first (`http/write_handlers.rs:598`).

**Classification: PARTIAL** (library conformant, PDS wiring buffered). The reference streams `getRepo`
(`packages/pds/src/api/com/atproto/sync/getRepo.ts:36-45`), as does arroba
(`/tmp/gap-scratch/arroba/arroba/xrpc_sync.py:45-67`) and pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/repository.ml:434-504`); cocoon buffers its import too
(`/tmp/gap-scratch/cocoon/server/handle_import_repo.go:25-28`).

### Block storage and interop test coverage

Repo blocks live in a per-actor SQLite `repo_block(cid TEXT PK, data BLOB, indexed_at)`
(`crates/atproto-pds/migrations/actor/20260501000001_init.sql:24-28`) or a shared fjall keyspace keyed
`<did>\0<cid_str>` (`crates/atproto-pds/src/actor_store/fjall/keyspace.rs:313-315`). There is no
orphan reclamation: `SqlBlockStorage::remove` exists (`actor_store/sql/block_storage.rs:99-114`), no
delete path calls it, and `gc.rs:103-160` never touches `repo_block`, so superseded MST nodes are
retained forever — the same behaviour metalbear documents for itself
([metalbear notes](../impl-notes/metalbear.md)). Backend durability and pool churn belong to
[ops](./32-ops.md).

More consequential for this chapter: `crates/atproto-repo` has **no `tests/` directory at all**. The
MST tests are round-trip and self-consistency only (`mst/serialize.rs:39-121`, `mst/tree.rs:504-651`)
— `test_cid_deterministic` asserts the same input twice gives the same CID; nothing compares a node
or commit CID to a known-good value from another implementation. That is precisely why findings 2, 3
and 5 survived to an RC. arroba vendors and runs `atproto-interop-tests` fixtures in CI
(`/tmp/gap-scratch/arroba/arroba/tests/testdata/README.md:1`, `tests/test_testdata.py:26-96`); cocoon
inherits indigo's `mst_interop_test.go`, headed "tests which are the same across language
implementations"; zat ships `interop_tests.zig` ([zds notes](../impl-notes/zds.md)); pegasus has a
954-line MST suite plus a `sample.car` ([pegasus notes](../impl-notes/pegasus.md)); and arroba runs
the upstream commit-proof fixtures in CI ([arroba notes](../impl-notes/arroba.md)).
**Classification: MISSING.**

---

## Findings

1. **`Mst::delete` silently corrupts neighbouring record keys.**
   CLASS: DIVERGENT · **rc-blocker** (data corruption).
   Evidence: `crates/atproto-repo/src/mst/tree.rs:379-400` reconstructs entry `delete_idx + 1`
   against the key at `delete_idx - 1` instead of the deleted entry's own key. Executed: a 20-record
   four-collection repo yields 2 corrupt and 1 errored result across 20 single deletes; deleting
   `app.bsky.graph.follow/cccc` from a four-record repo rewrites the next key to
   `app.bsky.feed.post/bbbdddd`. Reachable from `deleteRecord`/`applyWrites` via
   `crates/atproto-pds/src/repo/writer.rs:300,617`.
   Comparison: no analogue in the eleven — the reference and every port re-derive prefixes from the
   full key list at serialization time (`packages/repo/src/mst/util.ts:80-110`), which cannot desync.
   Consequence: an ordinary user action silently moves records into wrong collections in the
   content-addressed tree. Invisible to `getRecord`/`listRecords` (which read SQL); visible in
   `getRepo` and in every subsequent commit root.

2. **MST nodes omit `l` and entries omit `t` instead of writing `null`.**
   CLASS: DIVERGENT · **rc-blocker**.
   Evidence: `crates/atproto-repo/src/mst/node.rs:30`, `mst/entry.rs:54`; executed one-entry node is
   `a1`/`a3`, 76 B, CID `bafyreicdju2y…` vs the canonical `a2`/`a4`, 82 B, `bafyreiagd2nt…`.
   Comparison: `packages/repo/src/mst/{mst.ts:45-56,util.ts:80-110}`; indigo
   `atproto/repo/mst/encoding.go:18,27`; `/tmp/gap-scratch/zat/src/internal/repo/mst.zig:571,600`;
   `/tmp/gap-scratch/dnproto/src/repo/RepoMst.cs:152-158,208-214`.
   Consequence: no repository this PDS produces has an MST root any peer can recompute, not even a
   single-record one.

3. **The MST write path is flat — `key_height` is computed and discarded.**
   CLASS: PARTIAL · **rc-blocker**.
   Evidence: `crates/atproto-repo/src/mst/tree.rs:236` (`let _target_height = …`); `insert_recursive`
   and `delete_recursive` never recurse (`:222-314`, `:342-423`). Executed: 30 keys spanning heights
   0–5 collapse to one node, 30 entries, 0 subtrees, 1,597 B, one full-node rewrite per insert.
   Comparison: `packages/repo/src/mst/mst.ts:228-460`; `/tmp/gap-scratch/arroba/arroba/mst.py:287-457`;
   `/tmp/gap-scratch/rsky/rsky-repo/src/mst/mod.rs:601,741`.
   Consequence: root CIDs diverge for any repo containing a height ≥ 1 key; a single write rewrites
   the whole tree block; a large repo emits one unbounded node.

4. **Records are DAG-CBOR-encoded straight from JSON — no `$link` → tag 42, no `$bytes`, floats pass.**
   CLASS: MISSING · **rc-blocker**.
   Evidence: `crates/atproto-pds/src/repo/writer.rs:223,545` encode `serde_json::Value` verbatim; the
   only `$link` in `crates/atproto-pds/src` is the `uploadBlob` response struct (`blob.rs:42`).
   Executed: a canonical image post encodes `$link` as a text map key and `1.5` as CBOR `fb`.
   Comparison: `packages/lex/lex-cbor/src/encoding.ts:47-66`;
   `/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/util.rs:283-296`;
   `/tmp/gap-scratch/zds/src/storage/store.zig:5210-5230`;
   `/tmp/gap-scratch/dnproto/src/repo/DagCborObject.cs:639-660`.
   Consequence: every record with a blob ref has a non-interoperable CID and a body that fails
   `blob`-typed validation downstream. Compounds [the `uploadBlob` envelope gap](./29-blobs.md).

5. **Initial commits omit the required `prev` key; all commits carry `prevData` inside the signed body.**
   CLASS: DIVERGENT · **rc-blocker**.
   Evidence: `crates/atproto-repo/src/repo/commit.rs:52-53,56-57,83-88`; executed initial unsigned
   commit is `a4{did,rev,data,version}`, second is `a6{…,prev,prevData}`.
   Comparison: `packages/repo/src/types.ts:27,36` + `repo.ts:62,167,212` (`prev` nullable, written as
   null); `parse.ts:31-42` + `util.ts:94-101` (parse-then-re-encode verification); indigo
   `atproto/repo/commit.go:18`; `/tmp/gap-scratch/rsky/rsky-repo/src/types.rs:16-35`.
   Consequence: a reference consumer throws `UnexpectedObjectError` on the first commit and fails
   signature verification on every later one.

6. **Imported repositories are never signature-verified and never DID-bound.**
   CLASS: MISSING · **stable-gap** (security-relevant; not an rc-blocker, because the reference
   behaves the same way).
   Evidence: `crates/atproto-pds/src/http/write_handlers.rs:618-620` builds the importer without
   `with_plc_verifier` (no caller anywhere); `import.rs:113` defaults it to `None`, `:240-242` gates
   the check on it, and no `commit.did == account_did` comparison exists in `:157-235`. Structural
   verification *is* done (`crates/atproto-repo/src/repo/inductive.rs:79-158`, called at `:232`).
   Comparison: the reference also passes `undefined` for `did` and `signingKey`
   (`.../repo/importRepo.ts:53-60` → `packages/repo/src/sync/consumer.ts:108-125`), so this is a gap
   against arroba, zds and metalbear, not against the reference.
   Consequence: a privileged session can import an arbitrary CAR — including another account's repo —
   and the PDS serves it as that account's history with foreign signatures intact.

7. **P-256 and P-384 signatures are not low-S normalized, and verification accepts high-S.**
   CLASS: PARTIAL · **stable-gap** (rc-blocker only if a non-K-256 signing key can be configured).
   Evidence: `crates/atproto-identity/src/key.rs:434-463` returns `try_sign` output unmodified;
   `p256-0.13.2/src/ecdsa.rs:72,75` and `p384-0.13.1/src/ecdsa.rs:69,72` are empty default impls. The
   correct helper exists at `crates/atproto-attestation/src/signature.rs:30-80`, unused by the PDS.
   Mitigating: K-256 account keys (`bin/pds.rs:425-430`) get normalization from
   `k256-0.13.4/src/ecdsa.rs:194,200-203`.
   Comparison: `packages/crypto/src/p256/{keypair.ts:60,operations.ts:32}`; zat
   `crypto/jwt.zig:284-286,291-297`; indigo `atcrypto/p256.go:116,222`; dnproto `Signer.cs:545-560`.
   Consequence: any P-256 key produces malleable signatures the network rejects ~50 % of the time, and
   `atproto-identity` is a published library other projects sign with.

8. **`RepoConfig::verify_signatures` is dead — nothing in `atproto-repo` verifies a commit.**
   CLASS: MISSING · **stable-gap**.
   Evidence: `crates/atproto-repo/src/config.rs:36,49,95-97` declare and default it with no read site;
   `Repository::from_car_with_storage` sets `signature_verified: None` (`repo/mod.rs:255-260`).
   Comparison: `packages/repo/src/util.ts:94-101` (`verifyCommitSig`).
   Consequence: a knob that reads as a safety guarantee is inert, and downstream users of the crate
   get no verification while believing the default provides it.

9. **CAR export and import are fully buffered, and export silently skips missing blocks.**
   CLASS: PARTIAL · **stable-gap**.
   Evidence: `crates/atproto-pds/src/repo/car_export.rs:56-108` (walk into `Vec`, write into `Vec`, no
   ceiling), `:66-71` (missing block → `continue`); `repo/import.rs:174-192` (drain to `Vec`, 4 GiB at
   `:112`) despite the doc at `:21-27`; `http/write_handlers.rs:598` buffers the body first. The
   library itself streams (`crates/atproto-dasl/src/car/{reader.rs:184-193,writer.rs:60-77}`).
   Comparison: `packages/pds/src/api/com/atproto/sync/getRepo.ts:36-45`;
   `/tmp/gap-scratch/arroba/arroba/xrpc_sync.py:45-67`.
   Consequence: memory proportional to repo size in both directions; a partially corrupted repo
   exports as a valid-looking short CAR.

10. **No interop or differential coverage for MST/commit bytes; the DASL submodule is empty and its
    harness panics.**
    CLASS: MISSING · **stable-gap** (process).
    Evidence: `crates/atproto-repo/` has no `tests/` directory; MST tests are round-trip only
    (`mst/serialize.rs:39-121`, `mst/tree.rs:504-651`). `.gitmodules` declares
    `crates/atproto-dasl/tests/dasl-testing`, which is empty, and `tests/dasl_compliance_test.rs:139`
    panics on a missing fixture; `.github/workflows/` holds only `release-binaries.yml`.
    Comparison: `/tmp/gap-scratch/arroba/arroba/tests/test_testdata.py:26-96`; indigo's
    `atproto/repo/mst/mst_interop_test.go`.
    Consequence: findings 2, 3 and 5 are exactly the class of defect a known-answer vector catches on
    the first run.

11. **Repo blocks are never garbage-collected.**
    CLASS: MISSING · **cosmetic** for RC, real at scale.
    Evidence: `crates/atproto-pds/src/actor_store/sql/block_storage.rs:99-114` implements `remove`
    with no caller; `crates/atproto-pds/src/gc.rs:103-160` never touches `repo_block`.
    Comparison: rsky-pds does ref-count-aware MST-block GC ([rsky notes](../impl-notes/rsky-pds.md));
    metalbear has the same unbounded growth ([metalbear notes](../impl-notes/metalbear.md)).
    Consequence: per-actor storage grows monotonically with every write.

### Not a finding

`key_height` itself (`crates/atproto-repo/src/mst/key.rs:30-34`), bytewise key ordering (`:94-96`),
the `version: 3` enforcement (`repo/commit.rs:188-192`), the signing-bytes construction (`:129-142`),
the canonical map ordering (`drisl/ser/serializer.rs:340-341,388-389,442`) and the CID profile
(`cid/mod.rs:655-697,730-737`) are all correct. Reporting them as gaps would be wrong.

### Where atproto-crates is ahead of the independent field

Two things, both in `atproto-dasl`. **CAR ingest hardening** — three ceilings enforced at the reader,
the per-block one checked before allocation, with a dedicated DoS suite
(`src/car/reader.rs:129-181`, `car/config.rs:87-97`, `tests/car_dos_test.rs`); nothing else in the
study enforces all three there. **CID profile validation** — CIDv0, non-{raw,dag-cbor} codecs,
non-{sha2-256, BLAKE3} hashes and non-32-byte digests all rejected (`src/cid/mod.rs:655-685`) and
applied to every CAR block by default (`car/config.rs:78-84`), where pegasus accepts a zero-length
digest. Neither offsets findings 1–5, but the foundation is sound enough that the fixes are edits to
`crates/atproto-repo`, not a codec rewrite.

---

## Confidence & unknowns

- **Highest confidence — executed, not inferred.** Findings 1–5 were each reproduced by compiling
  against `crates/atproto-repo` and `crates/atproto-dasl` from this worktree and printing the actual
  bytes and CIDs. The comparison sides of findings 2 and 5 were read from the reference zod schemas
  and indigo's `cborgen` tags directly, not inherited from an impl note.
- **High confidence** on findings 6 and 8–11: verified by opening the cited files in this pass.
  Finding 6 resolves the "did `import_repo` wire a PLC verifier?" question the inventory left open.
- **UNVERIFIED: tranquil-pds and metalbear byte-level node/commit encoding and low-S behaviour.**
  tranquil delegates to `jacquard-repo`/`jacquard-common` 0.9
  (`/tmp/gap-scratch/tranquil-pds/Cargo.toml:98-99`), metalbear to the external Wolfram library
  (`CMakeLists.txt:32`); neither is present here or in the local Cargo registry, so both are `?` in
  the matrix. Circumstantially tranquil walks the new MST to build covering proofs
  (`crates/tranquil-pds/src/repo_ops.rs:584-610`), which needs a real multi-level tree, and metalbear
  links libsecp256k1 (`README.md:207-209`), whose signer is low-S by construction — neither is proof.
- **UNVERIFIED: cocoon's exact pinned indigo revision.** cocoon pins
  `indigo v0.0.0-20260308004230-c55a189a51a9` (`/tmp/gap-scratch/cocoon/go.mod`); I read
  `v0.0.0-20260120225912-12d69fa4d209` from the local module cache for the commit-shape, MST-encoding
  and low-S citations. The code is long-stable, but the revision differs.
- **UNVERIFIED: whether `cborg`'s default map sorter is length-first.** `node_modules` is not
  populated here, so atproto-crates' ordering is asserted against the IPLD DAG-CBOR rule and against
  pegasus's independently written `dag_cbor_key_compare`
  (`/tmp/gap-scratch/pegasus/ipld/lib/dag_cbor.ml:4-7`), not against a read of `cborg`.
- **Partly inferred: the blast radius of finding 4.** `$link` appears in AT Protocol JSON for
  `blob.ref` and for fields typed `cid-link`; `com.atproto.repo.strongRef` carries `cid` as a plain
  string, so likes, reposts and replies are unaffected. I did not enumerate every `cid-link` field
  across `app.bsky.*`.
- **Cross-area overlap.** The absent `blocks` CAR on `#commit`, per-actor sequence numbers and the
  `payload`-nested frame body belong to [firehose](./25-firehose.md) and [Sync 1.1](./26-sync.md); the
  `uploadBlob` envelope and blob ref-counting to [blobs](./29-blobs.md); `importRepo`'s failure to
  populate `repo_record` to [migration](./31-migration.md); backend durability and pool churn to
  [ops](./32-ops.md). The permissioned-data namespace runs its own commit format and is out of scope —
  see [the permissioned-data overview](../permissioned/40-permissioned-overview.md).
