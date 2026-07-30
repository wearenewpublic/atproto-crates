# Synthesis and roadmap — what must change before `-rc` comes off

_Capstone of the atproto-crates `0.15.0-rc.1` release-candidate gap analysis._
_Inputs: [README](./README.md) · [inventory](./00-atproto-crates-inventory.md) ·
[coverage matrix](./20-coverage-matrix.md) ·
[capability areas A–L](./capability-areas/) ·
[permissioned data](./permissioned/40-permissioned-overview.md) ·
[per-implementation notes](./impl-notes/)._

Unqualified `crates/…` paths are relative to the worktree root
`/Users/nick/development/github.com/ngerakines/atproto-crates-studious-guide/.claude/worktrees/goofy-bell-de1699`.
Comparison paths under `/tmp/gap-scratch/` are the cloned comparison corpus described in the
[inventory](./00-atproto-crates-inventory.md).

---

## Bottom line

**Neither `-rc` suffix can come off today.** The two are blocked for structurally different reasons,
and — this is the most useful finding in the report — they are **not blocked on each other**.

The **PDS** is blocked on correctness, not on missing features. Its repository layer does not
currently produce AT Protocol repositories that any other implementation can verify: three
`#[serde(skip_serializing_if = "Option::is_none")]` attributes drop map keys that the spec requires
to be present-and-null, so every MST root CID and every commit CID this server has ever produced is
wrong (F-REPO-01). A separate defect in `Mst::delete` silently rewrites a neighbouring record's key
(F-REPO-03), which is data loss rather than non-conformance. The firehose emits a body that matches
no member of the `subscribeRepos` union and never carries repo blocks (F-FIRE-01, F-FIRE-02). The
OAuth authorization server is extensively built and unreachable, because PAR and token accept JSON
where every standard client sends form encoding (F-OAUTH-01) — and behind that wall sits an
authorization-code exfiltration chain (F-OAUTH-02 + F-OAUTH-03). Account migration fails at three
independent points in sequence (F-ACCT-01, F-MIG-01, F-BLOB-02). None of this was caught because
there is no CI running the test suite at all, and the conformance-vector submodule the project
declares is empty (F-OPS-01).

The **permissioned-data / spaces** track is blocked on two confidentiality holes and three
byte-level divergences, against a target that is still moving. Permissioned records are readable by
any other account on the same PDS (F-SPACE-07, inherited from the reference draft), and permissioned
blobs are readable by anyone at all through the public `com.atproto.sync.getBlob` (F-BLOB-03, *not*
inherited — this one is atproto-crates-specific). The signed-commit context string omits the author
DID, the commit has no `ver` field, and the space URI uses `ats://` where the draft lexicons type
every space reference as `at-uri` (F-SPACE-19, F-SPACE-04, F-SPACE-18). Those three are one
coordinated change of maybe a hundred lines and they must land together, because `space` is
length-prefixed into the signed context.

The honest counterweight: on the spaces track atproto-crates is **ahead of every comparison target on
integration and behind on byte-level conformance**. Its LtHash is byte-identical to the reference and
runs on the production write path; HappyView's is correct and dead code. Its commit signing, real
CIDs, `jti` replay guard and end-to-end client attestation all execute; the equivalent code in
HappyView does not. Fixing the byte layout is small and surgical. Fixing "the crypto was never
wired" would not be.

---

## How to read this document

Every finding carries a stable ID (`F-<AREA>-<nn>`) that the roadmap in §5 references. Classes are
the four the brief defines:

- **MISSING** — the capability does not exist.
- **PARTIAL** — present but incomplete enough to break a real workflow.
- **DIVERGENT** — present and working, on a different wire contract than the oracle.
- **OUT-OF-SCOPE** — deliberately deferred; §1.13 justifies each one as a defensible RC→stable call.

Severity is separate from class: **blocker** (must fix before dropping `-rc`), **stable-gap** (should
fix, does not block), **cosmetic**.

### Consolidated totals

| Class | Count | Of which PDS | Of which spaces |
| --- | ---: | ---: | ---: |
| MISSING | 59 | 49 | 10 |
| DIVERGENT | 70 | 61 | 9 |
| PARTIAL | 45 | 37 | 8 |
| OUT-OF-SCOPE | 8 | 5 | 3 |
| **Total** | **182** | **152** | **30** |

Cutting the same 174 numbered findings by severity rather than class: **78 blockers** (64 PDS, 14
spaces), **81 stable-gaps**, **15 cosmetic**. Findings given a full prose treatment below are the
blockers; stable-gaps and cosmetic items are indexed in tables with their evidence, worked reference
and one-line consequence, and the owning chapter carries the reasoning.

The split is by owning area, so two findings that bear on permissioned data are counted on the PDS
side because they live in the public surface: F-BLOB-03 (permissioned blobs served by the public
`com.atproto.sync.getBlob`) and F-OAUTH-12 (the scope-enforcement gap whose non-OAuth bypass is half
of F-SPACE-07). Everything with an `F-SPACE-*` ID is a 0016 conformance item.

Deduplicated: the `uploadBlob` envelope was reported in three chapters and appears once here
(F-BLOB-01); takedown enforcement was reported in four and appears twice (F-MOD-01 reads, F-MOD-02
writes); the firehose envelope was reported in four and appears once (F-FIRE-01). One finding carries
a compound class — F-OAUTH-02 is MISSING (client authentication) *and* DIVERGENT (caller-chosen
`cnf.jkt`) — and is counted once, under MISSING.

### Four framings that were verified and correct common misreadings

These are load-bearing. Reading the findings below without them produces wrong conclusions.

**Rate limiting is PARTIAL, not absent.** The `SlidingWindowLimiter` with Memory / SQL / Valkey
backends (`crates/atproto-pds/src/security.rs:314-520`) is better engineered than metalbear's, which
is the only comparison implementation with a global limiter. The gap is *coverage and key choice* —
four call sites out of 104 routes, every bucket keyed on caller-supplied input. See F-OPS-02.

**Write-time membership in spaces is a documented design decision, not an oversight.**
`crates/atproto-pds/src/space/writer.rs:6` states it: "The PDS does not enforce membership at write
time; consumers check at sync." The legitimate criticism is the consequence — a removed member keeps
writing to their own store, and every consumer must independently filter — not the absence of a
check the author intended to write.

**The spaces read-time authorization hole is shared with the reference draft.** The Phase 4 audit
opened `packages/pds/src/api/com/atproto/space/{getRecord.ts,util.ts}` on the `permissioned-data`
branch and found all three links of the chain present there too. F-SPACE-07 is scored as inherited,
with an upstream action attached. F-BLOB-03 is *not* shared and is scored fully against
atproto-crates.

**The dominant failure mode is "built but not wired", which lowers projected effort.** A rate limiter
with four call sites, `blob::add_ref` with no production caller, `RepoConfig::verify_signatures` never
read, `with_plc_verifier` never invoked, `service_auth_blacklist::contains` called only from its own
tests, an import path that persists blocks but writes no record index. A large share of the
remediation is connecting existing, already-tested code. The exceptions that are genuine build work
are called out explicitly in §5.

### The comparative score, stated with its qualifiers

Computed from the 280 staged matrix rows as `(Y + 0.5×~) / (rows applicable)`, excluding `n/a` and
`?`: bluesky-reference 92.9%, tranquil-pds 88.2%, rsky-pds 81.0%, zds 74.5%, cirrus 72.5%, alteran
70.6%, pegasus 69.6%, metalbear 67.7%, cocoon 61.5%, dnproto 42.1%, arroba 35.7%, **atproto-crates
32.1%** — last of twelve, with 65 `Y`, 49 `~`, 165 `N`, 1 `n/a`, 0 `?`.

Four qualifiers, all true, none of which rescues the headline. (1) atproto-crates has essentially no
scope exemptions (1 `n/a`) because it targets a full multi-account federated PDS; arroba (51 `n/a`),
cirrus (62) and alteran (65) score higher partly by legitimately declining scope. The fair comparison
is against tranquil-pds, rsky-pds and cocoon, which have the same ambition — 88.2%, 81.0%, 61.5%.
(2) The matrix scores only the public-PDS surface; roughly 11k lines of permissioned-data work
contribute nothing to it and no other implementation has an equivalent. (3) atproto-crates is the
only implementation with **zero `?` cells** — everything was verifiable from source, which is a real
credit to the codebase's documentation and structure and is why this report can be as specific as it
is. (4) The score measures breadth, not correctness. A row can score `Y` and still be built on a
wrong CID.

The project's own README carries both halves of the contradiction:
`crates/atproto-pds/README.md:3` says "EXPERIMENTAL - FOR THE LOVE OF GOD DON'T USE THIS YET." against
`:15-16`, "The PDS is **single-node deployable for federated public traffic**." The first sentence is
the accurate one today.

---

## 1. Consolidated classified findings

### 1.1 Repository, MST and encoding — `crates/atproto-repo`, `crates/atproto-dasl`

Owning chapter: [22-repo.md](./capability-areas/22-repo.md).

**F-REPO-01 · DIVERGENT · blocker — optional map keys are omitted where the spec requires
present-and-null, so every MST root CID and every commit CID is wrong.** This is one conceptual
mistake — "optional in Rust means omit on the wire" — expressed three times:
`#[serde(rename = "l", skip_serializing_if = "Option::is_none")]`
(`crates/atproto-repo/src/mst/node.rs:30`), the same on the per-entry subtree pointer
(`crates/atproto-repo/src/mst/entry.rs:54`), and the same on the commit's `prev`
(`crates/atproto-repo/src/repo/commit.rs:52`). The reference does the opposite deliberately:
`serializeNodeData` initialises the node as `{ l: null, e: [] }` and only overwrites `l` when a left
subtree exists (`/tmp/gap-scratch/atproto/packages/repo/src/mst/util.ts:80-88`), and `prev` is
`cidSchema.nullable()` (`packages/repo/src/types.ts:27,36`) written explicitly as `prev: null`
(`packages/repo/src/repo.ts:62,167`). indigo's commit struct carries the comment that `omitempty`
"would break signature verification for repo v3" (`atproto/repo/commit.go:18`); dnproto emits both
keys (`/tmp/gap-scratch/dnproto/src/repo/RepoMst.cs:152-158,208-214`) and so does zat
(`/tmp/gap-scratch/zat/src/internal/repo/mst.zig:571,600`). The 22-repo chapter verified this by
execution: a one-entry node encodes as `a1`/76 bytes with CID `bafyreicdju2ykiut3j3kvuytqd4oaoe5fxgvgeexhuiqol55cw4zl2vkeu`
against the canonical `a2`/82 bytes and `bafyreiagd2nthpemvrihlk7jx4y6oxic2b6vegrewbie2uh4c45olsj5b4`.
*Consequence:* no repository this PDS has ever produced has a root any peer can recompute, not even
a single-record one; CAR exports are rejected, commit signatures verify against the wrong bytes, and
a reference consumer throws `UnexpectedObjectError` on the very first commit. The fix is removing
three attributes. It is by a wide margin the best value-per-effort item in this report.

**F-REPO-02 · DIVERGENT · blocker — `prevData` is carried inside the signed commit body.**
`crates/atproto-repo/src/repo/commit.rs:56-57` places the `prevData` field in the commit struct that
is serialised for signing, so the signed body is `a6{did,rev,data,version,prev,prevData}` where the
reference signs a five-key object and keeps `prevData` on the firehose event
(`packages/repo/src/types.ts:16-35` compared with `/tmp/gap-scratch/rsky/rsky-repo/src/types.rs:16-35`).
*Consequence:* even after F-REPO-01 lands, the commit CID and the signature still differ from any
conformant peer, because the map has an extra key. Coverage matrix area B scores this `N` for
atproto-crates against `Y` for eight of the eleven comparisons.

**F-REPO-03 · DIVERGENT · blocker (silent data corruption) — `Mst::delete` reconstructs the following
entry against the wrong base key.** MST entries are prefix-compressed against the *full key of the
preceding entry*. Deleting `entry[i]` therefore needs two steps: reconstruct `entry[i+1]`'s full key
against `entry[i]`, then re-compress it against `entry[i-1]`. `crates/atproto-repo/src/mst/tree.rs:378-392`
performs only the second, building `old_prev` as the full key of `entry[delete_idx - 1]` and then
calling `node.entries[delete_idx + 1].reconstruct_key(&old_prev)` at `:392`. The in-line comment at
`:378` shows the two-step subtlety was recognised and implemented backwards. Reachable from
`deleteRecord` and `applyWrites` (`crates/atproto-pds/src/repo/writer.rs:300,617`). No comparison
implementation has an analogue — the reference and every port re-derive prefixes from the full key
list at serialization time (`packages/repo/src/mst/util.ts:80-110`), which cannot desync. The 22-repo
chapter verified by execution: a 20-record four-collection repo yields 2 corrupt and 1 errored result
across 20 single deletes; deleting `app.bsky.graph.follow/cccc` rewrites the next key to
`app.bsky.feed.post/bbbdddd`. *Consequence:* an ordinary user deleting one record silently moves a
different, untouched record into a wrong collection in the content-addressed tree, and the corruption
is committed and signed. This is the only finding in the report that destroys user data in place.

**F-REPO-04 · PARTIAL · blocker — the MST write path never builds subtrees.** `key_height`
(`crates/atproto-repo/src/mst/key.rs:30-34`) is correct — `sha256(key)`, leading zero bits, `/2`,
matching the reference's 2-bit grouping at `packages/repo/src/mst/util.ts:23-35` exactly. It is then
computed and discarded: `let _target_height = key_height(key);`
(`crates/atproto-repo/src/mst/tree.rs:236`). `insert_recursive` (`:222-320`) never calls itself and
never creates a subtree; the reader *can* descend (`get_recursive`, `:139-175`), so the structure
supports nesting and only the writer fails to produce it. Worked references: the reference
(`packages/repo/src/mst/mst.ts:228-460`), arroba (`/tmp/gap-scratch/arroba/arroba/mst.py:287-457`),
rsky (`/tmp/gap-scratch/rsky/rsky-repo/src/mst/mod.rs:601,741`). A key lands at height ≥ 1 with
probability 1/4, so `P(divergence)` is 94% at ten records and 99% at sixteen — the window in which
this is invisible is about a dozen records, not the fifty an earlier estimate suggested. Executed:
30 keys spanning heights 0–5 collapse to one node of 1,597 bytes, rewritten in full on every insert.
*Consequence:* wrong root CIDs at any realistic size, one unbounded node per repo, and a structurally
invalid hybrid if a reference-built repo is imported and then written to.

**F-REPO-05 · MISSING · blocker — records are DAG-CBOR-encoded straight from JSON.**
`crates/atproto-pds/src/repo/writer.rs:223,545` hand a `serde_json::Value` to the encoder; the only
`$link` literal in `crates/atproto-pds/src` is the `uploadBlob` response struct (`blob.rs:42`). No
`$link` → CBOR tag 42, no `$bytes`, and non-integer numbers pass through. Executed: a canonical image
post encodes `$link` as a text map key and `1.5` as CBOR `fb`. Worked references:
`packages/lex/lex-cbor/src/encoding.ts:47-66`;
`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/util.rs:283-296`;
`/tmp/gap-scratch/dnproto/src/repo/DagCborObject.cs:639-660`. *Consequence:* every record containing
a blob ref has a non-interoperable CID and a body that fails `blob`-typed validation downstream, which
compounds F-BLOB-01.

**F-REPO-06 · PARTIAL · stable-gap (blocker if a non-K-256 signing key is configurable) — P-256 and
P-384 signatures are not low-S normalized, and verification accepts high-S.**
`crates/atproto-identity/src/key.rs:434-463` returns `try_sign` output unmodified; the `p256` and
`p384` crates ship empty default normalization impls (`p256-0.13.2/src/ecdsa.rs:72,75`). The correct
helper exists in this very workspace at `crates/atproto-attestation/src/signature.rs:30-80` and the
PDS does not use it. K-256 account keys are mitigated because `k256` normalizes by construction.
Worked references: `packages/crypto/src/p256/{keypair.ts:60,operations.ts:32}`; indigo
`atcrypto/p256.go:116,222`. *Consequence:* a P-256 key produces malleable signatures the network
rejects roughly half the time — and `atproto-identity` is a published library that other projects
sign with, so the blast radius exceeds this PDS.

**F-REPO-07 · MISSING · stable-gap — `RepoConfig::verify_signatures` is dead.** Declared and defaulted
to `true` at `crates/atproto-repo/src/config.rs:36,49,95-97` with no read site anywhere;
`Repository::from_car_with_storage` sets `signature_verified: None` (`repo/mod.rs:255-260`). The
reference verifies (`packages/repo/src/util.ts:94-101`). *Consequence:* a knob that reads as a safety
guarantee is inert, and downstream users of the crate get no verification while believing the default
provides it.

**F-REPO-08 · MISSING · stable-gap — imported repositories are never signature-verified and never
DID-bound.** `crates/atproto-pds/src/http/write_handlers.rs:618-620` builds the importer without
`with_plc_verifier`, which has no caller anywhere in the workspace; `import.rs:113` defaults it to
`None` and `:240-242` gates the check on it. No `commit.did == account_did` comparison exists. The
*design* is genuinely more careful than most of the field — verifying each commit against the
historical signing key valid at that commit's `rev` (`import.rs:34-41`, `:365-416`) — but it never
runs, and the citation audit downgraded the corresponding "ahead of the field" credit for exactly
that reason. What ships is the inductive chain proof at `:232`. The reference behaves the same way
(`packages/pds/src/api/com/atproto/repo/importRepo.ts:53-60` re-signs), so this is a gap against
arroba (`xrpc_repo.py:241-243`), zds and tranquil (`repo/import.rs:130`), not against the reference.

**F-REPO-09 · PARTIAL · stable-gap — CAR export and import are fully buffered, and export silently
skips missing blocks.** `crates/atproto-pds/src/repo/car_export.rs:56-108` walks into a `Vec` with no
ceiling and `continue`s past a missing block at `:66-71`; `repo/import.rs:174-192` drains to a `Vec`
despite the streaming doc at `:21-27`. The library itself streams
(`crates/atproto-dasl/src/car/reader.rs:184-193`). Worked reference:
`packages/pds/src/api/com/atproto/sync/getRepo.ts:36-45`; arroba `xrpc_sync.py:45-67`.
*Consequence:* memory proportional to repo size in both directions, and a partially corrupted repo
exports as a valid-looking short CAR.

**F-REPO-10 · MISSING · cosmetic for RC, real at scale — repo blocks are never garbage-collected.**
`actor_store/sql/block_storage.rs:99-114` implements `remove` with no caller; `gc.rs:103-160` never
touches `repo_block`. rsky-pds does ref-count-aware MST-block GC; metalbear shares the gap.

### 1.2 Record operations — `com.atproto.repo.*`

Owning chapter: [23-records.md](./capability-areas/23-records.md).

**F-REC-01 · DIVERGENT · blocker — `describeRepo` omits the lexicon-required `didDoc`.**
`DescribeRepoResponse` (`crates/atproto-pds/src/repo/reader.rs:463-484`) has no `didDoc` and adds
non-lexicon snake_case `head_cid`/`head_rev`/`head_data`. All eleven comparisons emit it, including
cirrus (`xrpc/repo.ts:134-147`) and zds (`repo.zig:116`). *Consequence:* every `describeRepo` call
throws in a validating client, breaking account discovery and the migration handshake.

**F-REC-02 · DIVERGENT · blocker — `applyWrites` results carry no `$type` union discriminator.**
`WriteRecordResponse` (`crates/atproto-pds/src/http/write_handlers.rs:326-332`, emitted at `:93-102`,
`:398-407`) matches none of `#createResult`/`#updateResult`/`#deleteResult`, and delete results carry
a `uri` that `#deleteResult` does not define. Oracle: `applyWrites.json`'s closed output union and
`packages/lexicon/src/validators/complex.ts:165-174`. Eight comparisons discriminate correctly.
*Consequence:* batched writes are unusable from the reference client.

**F-REC-03 · DIVERGENT · blocker — `listRecords` emits `"cursor": null` when a page is exhausted.**
`crates/atproto-pds/src/repo/reader.rs:454-461` declares `Option<String>` with no
`skip_serializing_if`; the lexicon types `cursor` as a non-nullable string
(`packages/lexicon/src/validators/primitives.ts:172-177`). *Consequence:* the last page of every
pagination loop throws in `@atproto/api`. One-line fix — and note that it is the exact inverse of
F-REPO-01, where `skip_serializing_if` is *missing* and needs adding.

**F-REC-04 · DIVERGENT · blocker (silent data loss) — `swapCommit` is accepted and never enforced.**
`createRecord` declares `swapCommit` and never reads it, building a `WriteOp` with `swap_record: None`
(`crates/atproto-pds/src/http/write_handlers.rs:88-89,158-164`); `putRecord`, `deleteRecord` and
`applyWrites` omit it from their input structs entirely (`:182-194`, `:284-289`), and `swapRecord` is
dropped inside `applyWrites` (`:366,377,384`). `swapRecord` *is* honoured for standalone put/delete
(`:215`, `:265`). Eight of eleven comparisons enforce it; cocoon has the identical defect
(`repo.go:254`); arroba rejects requests carrying it outright (`xrpc_repo.py:31-36`).
*Consequence:* concurrent writers clobber each other and both receive HTTP 200. If full compare-and-swap
is out of reach for this release, arroba's explicit rejection is a correct and cheap stand-in.

**F-REC-05 · MISSING · blocker for the structural half, stable-gap for schema validation — no lexicon
validation and none of the schema-free structural checks either.** No `validate` field on any write
input; no `validate_record` call anywhere in `crates/atproto-pds/src/`; `repo/writer.rs:217`
interpolates `rkey` into the MST key unchecked and `:223-226` encodes the value without inspecting
`$type`. The engine exists in this workspace at
`crates/atproto-lexicon/src/validation/validate.rs:327` and the PDS depends on the crate
(`Cargo.toml:35`), using it only in `src/space/declaration.rs:31-32`. Worked reference:
`packages/pds/src/repo/prepare.ts:38-90,73-85,167-178,181-183`. *Consequence:* a record stored without
`$type` is undecodable by every consumer, and an `rkey` containing `/` lands at an MST path that does
not match its own AT-URI — neither recoverable once the commit is signed and sequenced.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence in one line |
| --- | --- | --- | --- | --- |
| F-REC-06 | `swapRecord` mismatch returns 403 `Forbidden` | DIVERGENT | stable-gap | `repo/writer.rs:246-256` → `http/errors.rs:63-65`; six comparisons emit 400 `InvalidSwap` (metalbear `repo_store.c:1751-1757`, zds `repo.zig:46`); clients cannot distinguish a conflict from an auth failure, so retry logic never fires |
| F-REC-07 | `applyWrites` has no batch-size cap | MISSING | stable-gap | only a non-empty check at `write_handlers.rs:345-351`, batch runs inside the per-DID write mutex (`repo/writer.rs:161-162`); six comparisons cap at 200 (`applyWrites.ts:85-86`); one request can hold a repo's write lock indefinitely |
| F-REC-08 | `deleteRecord` on a missing record returns 400 | DIVERGENT | stable-gap | `repo/writer.rs:290-292`; the reference no-ops (`deleteRecord.ts:75-78`); metalbear shares the deviation; idempotent cleanup flows fail on retry |
| F-REC-09 | `listRecords?reverse=true` bypasses the configured backend | PARTIAL | stable-gap | `repo/reader.rs:217-219` skips the trait branch, falling back to per-actor SQLite (`:94-96,260`); on `fjall` reverse pagination reads the wrong store |
| F-REC-10 | `getRecord` miss returns `NotFound`, not `RecordNotFound` | DIVERGENT | cosmetic | `http/errors.rs:50-52` vs `getRecord.json` `errors`; metalbear emits the declared name (`repo_store.c:1758-1761`) |
| F-REC-11 | `importRepo` returns an undeclared body | DIVERGENT | cosmetic | `write_handlers.rs:575-588`; `importRepo.json` declares no output, so nothing validates it — defensible as a diagnostic extension |

### 1.3 Blobs

Owning chapter: [29-blobs.md](./capability-areas/29-blobs.md).

**F-BLOB-01 · DIVERGENT · blocker — `uploadBlob` returns an envelope matching neither accepted
encoding.** `crates/atproto-pds/src/blob.rs:39-49` (used at `http/write_handlers.rs:507,549-555,570`)
emits `{$link, mimeType, size}`. The reference accepts exactly two JSON forms, both declared
`.strict()`: the typed `{$type: "blob", ref: <cid-link>, mimeType, size}` and the two-key legacy
`{cid, mimeType}` (`/tmp/gap-scratch/atproto/packages/lexicon/src/blob-refs.ts:5-13,15-21,23`), and
the legacy form is now rejected at write time anyway (`packages/pds/src/repo/prepare.ts:208-211`).
`$link` is not a key in either. All ten comparisons that serve `uploadBlob` emit the typed form —
dnproto `ComAtprotoRepo_UploadBlob.cs:85-99`, cocoon `handle_repo_upload_blob.go:143-146`, zds
`repo.zig:550-551`, tranquil `repo/blob.rs:207-212`. *Consequence:* `@atproto/api` throws on the
upload call itself, and a client that embeds the returned object produces a record the reference
validator rejects. Media is broken against every real client.

**F-BLOB-02 · MISSING · blocker — record→blob ref tracking is implemented, tested, and never
invoked.** The trait method (`actor_store/traits.rs:249-259`), all three backend impls
(`sql/public_realm.rs:452-514`, `fjall/public_realm.rs:560-600`, `blob_s3.rs:169`) and the free
functions (`blob.rs:115-174`) exist, with unit tests at `blob.rs:320-335` — and no production caller
anywhere. `repo/writer.rs` never extracts blob refs from a record value, despite the doc comment at
`blob.rs:111-114` asserting the writer calls it. Worked references: the reference
`blob/transactor.ts:187-240,301-317`; rsky-pds `blob/mod.rs:201-222,240-313`; cocoon
`repo.go:518-522,687-715`; alteran `db/dal.ts:204-230` — and metalbear's query-time scan
(`server.c:2882-2915`) is the lowest-effort variant if a write-path walker is too much for this
release. *Consequence:* `listMissingBlobs` is permanently `{"blobs": []}` and
`checkAccountStatus.expectedBlobs` permanently `0`, so a migrating client concludes there is nothing
to transfer and activates an account with none of its media, while every step reports success. Blob
GC also has no ref-counts to consult.

**F-BLOB-03 · MISSING · blocker (security, atproto-crates-specific) — permissioned-space blobs are
served with no authentication at all.** `get_blob` (`crates/atproto-pds/src/http/blob_handlers.rs:33-72`)
takes only `State` and `Query` — no auth extractor, no guard — which is correct for *public* repos
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getBlob.json`). The defect is that blobs uploaded
through the permissioned path land in the same CID-addressed store and are served by the same
endpoint; `com.atproto.space.getBlob` applies the space gate (`http/router.rs:319`) but nothing
prevents retrieval of identical bytes through the public route, and `listBlobs`
(`blob_handlers.rs:96-123`, backed by `blob.rs:178-203`) enumerates every stored CID. 0016 states
these blobs are fetched "via `com.atproto.space.getBlob` with the relevant space credential"
(`/tmp/gap-scratch/0016-README.md:379`). zds, the only other 0016 implementation, keeps a separate
`getPublicBlob` requiring a join to a public record
(`/tmp/gap-scratch/zds/src/storage/store.zig:2538-2563`) and joins the same way in its public
`listBlobs` (`:2566-2592`). *Consequence:* this reaches further than F-SPACE-07 — that requires an
account on the same PDS, this requires only a CID and no credential. CIDs are high-entropy but not
secret: they appear in oplog entries, in any AppView indexing the space, in logs, and to every member
including one since removed. A removed member retains permanent read access to every blob whose CID
they ever saw, and deleting a record from a space does not revoke it.

**F-BLOB-04 · MISSING · blocker (security + spec) — `getBlob`/`listBlobs` have no repo-availability
gate and materialise per-DID stores on demand.** `blob_handlers.rs:44-57,107-120` go straight to
`SqlActorStore::open`, which runs `create_dir_all` + `create_if_missing(true)` + migrations
(`actor_store/sql/store.rs:55-95`). Both lexicons declare
`RepoNotFound`/`RepoTakendown`/`RepoSuspended`/`RepoDeactivated`; only `BlobNotFound` is reachable.
Worked references: `sync/getBlob.ts:20` → `sync/util.ts:6-36`; tranquil `sync/util.rs:131-182`; zds
`sync.zig:181,252`. *Consequence:* taken-down accounts keep serving blobs (see F-MOD-01), and any
unauthenticated caller can materialise unbounded SQLite files by varying `did`, with no per-IP limit
anywhere on the sync surface (F-OPS-02).

**F-BLOB-05 · MISSING · blocker (security) — `getBlob` omits `nosniff`, `content-disposition` and
CSP.** `blob_handlers.rs:65-70` sets only `Content-Type`, echoing the unvalidated client-declared MIME
from `write_handlers.rs:522-527`. The reference sets all three and names the XSS risk in comments
(`sync/getBlob.ts:44,50,53`); so do metalbear (`server.c:5566-5595`), zds (`sync.zig:189-191`),
tranquil, alteran (`com.atproto.sync.getBlob.ts:71-72`) and rsky-pds. atproto-crates already sets all
three on `space.getBlob` (`space_handlers.rs:2262-2274`), so the fix is copying five lines across.
*Consequence:* an uploaded `text/html` blob renders as a document on the origin that also serves the
OAuth consent screen and session cookies — stored XSS against the authorization server.

**F-BLOB-06 · DIVERGENT · blocker — the 16 MiB upload ceiling is dead code; the real limit is axum's
2 MiB default.** `MAX_BLOB_BYTES` (`blob.rs:20`) is checked at `write_handlers.rs:531-539`, but the
handler extracts `axum::body::Bytes` (`:519`) and axum-core applies `DEFAULT_LIMIT = 2_097_152`
(`axum-core-0.5.6/src/ext_traits/request.rs:319,326`, extractor at
`axum-core-0.5.6/src/extract/request_parts.rs:100-108`) because no `DefaultBodyLimit` layer exists —
the router applies only the metrics pair (`http/router.rs:446-447`). The same cap bites `importRepo`
(`write_handlers.rs:598`). Worked reference: `PDS_BLOB_UPLOAD_LIMIT` (`config.ts:40`, `env.ts:19`).
*Consequence:* a typical phone photo fails with a plain-text 413 that is not an XRPC error body, and
`crates/atproto-pds/README.md:162-163` tells operators to size their reverse proxy for >1 GiB while
the application rejects at 2 MiB — so inbound migration fails for any non-trivial repo.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-BLOB-07 | No operator-tunable blob limit, no per-account quota | MISSING | stable-gap | `MAX_BLOB_BYTES` is a `const` (`blob.rs:20`), no knob in `bin/pds.rs`; alteran ships both a limit and a per-DID quota (`src/db/blob.ts:42`); operators can neither raise it for video nor lower it for abuse control |
| F-BLOB-08 | MIME trusted from the client header, never sniffed | PARTIAL | stable-gap | `write_handlers.rs:522-527` → `blob.rs:74-87` → `blob_handlers.rs:66-70`; sniffing in reference (`blob/transactor.ts:61-72`), cirrus (`xrpc/repo.ts:628-642`), alteran (`util.ts:121-164`), dnproto (`ComAtprotoRepo_UploadBlob.cs:105-130`); the type AppViews act on is attacker-chosen, compounding F-BLOB-05 |
| F-BLOB-09 | `PDS_BLOB_STORE_URL` documented, advertised, never read | DIVERGENT | stable-gap | declared with a behavioural doc at `bin/pds.rs:316-322`, no other occurrence; `HybridS3BlobStorage` (`blob_s3.rs:44-175`) referenced only from `tests/feature_s3.rs`; advertised at `README.md:122`; an operator who sets it silently gets bytes-in-SQLite (see F-OPS-06) |
| F-BLOB-10 | No temp/untethered stage, no orphan sweep | MISSING | stable-gap | `blob.rs:74-87` writes permanent rows, no temp table, `gc.rs` never mentions blobs; reference `putTemp`/`makePermanent` (`disk-blobstore.ts:31-33,75,82`); the lexicon's "deleted if not referenced within a window" is unimplemented |
| F-BLOB-11 | `listBlobs` does not model `since` | MISSING | stable-gap | `blob_handlers.rs:76-83`; honoured by reference, tranquil, rsky-pds, pegasus, alteran, zds; mirrors and interrupted migrations re-enumerate the full blob set every pass |
| F-BLOB-12 | `listBlobs` enumerates stored, not record-referenced, blobs | DIVERGENT | cosmetic in isolation | `blob.rs:178-203` selects `repo_blob`; the reference selects `record_blob` (`reader.ts:57-62`); this is the mechanism behind F-BLOB-03 |
| F-BLOB-13 | `listBlobs` always returns a cursor | DIVERGENT | cosmetic | `blob_handlers.rs:121` sets it unconditionally; pegasus emits one only on a full page (`listBlobs.ml:19-20`) |
| F-BLOB-14 | No reference-time MIME/size verification | MISSING | stable-gap | `repo/writer.rs` has no blob logic; only reference `verifyBlob` (`blob/transactor.ts:356-372`) and rsky-pds do this at all, so this is a weak-field gap |
| F-BLOB-15 | Blob-level takedown unaddressable | MISSING | stable-gap | `admin/handlers.rs:156-162,212-218` speak `{did,state}`, `repo_blob` has no `takedownRef` column (`migrations/actor/20260504000001_blobs.sql:12-20`); reference quarantine (`blob/transactor.ts:160-184`); an operator cannot remove one illegal blob without deleting the account — see F-MOD-03 |

### 1.4 Firehose and Sync 1.1

Owning chapters: [25-firehose.md](./capability-areas/25-firehose.md),
[26-sync.md](./capability-areas/26-sync.md).

**F-FIRE-01 · DIVERGENT · blocker — every event body is wrapped in a non-lexicon envelope and omits
required fields.** `crates/atproto-pds/src/sequencer/frame.rs:116-122` emits
`{seq, repo, time, payload: {...}}`; the `#commit` payload
(`crates/atproto-pds/src/repo/writer.rs:448-456`, duplicated at `:722-730`) is
`{did, rev, commit, data, prev, prevData, ops}`. Against `#commit.required` =
`[seq, rebase, tooBig, repo, commit, rev, since, blocks, ops, blobs, time]`, eight required fields are
missing, `repo` is spelled `did`, and `#sync`/`#identity`/`#account` receive `repo` where the def
requires `did`. The two-CBOR-object frame *header* is byte-correct, which makes this worse in
practice: a consumer connects successfully, parses the frame, and then finds a body it cannot map to
any union member. Every one of the eleven comparisons emits a flat lexicon-shaped body — the
reference at `sequencer/events.ts:25-37`, and hobby-tier alteran emits all twelve fields
(`src/worker/sequencer/payload.ts:69-83`). *Consequence:* `Frame.fromBytes` rejects on the first
missing required field and indigo relays see nil `Blocks`. No relay can ingest this stream.

**F-FIRE-02 · MISSING · blocker — no CARv1 `blocks` slice is ever built for the firehose.**
`car_export` is referenced only from `http/handlers.rs:191` (`getRepo`) and `:250` (`getBlocks`); the
commit-write path (`repo/writer.rs:397-470`) builds no CAR. `#commit.blocks` is a required `bytes`
field whose description mandates the commit block as the first CAR root. Eleven of eleven comparisons
ship one, including alteran (`src/services/car.ts:171-258`) and dnproto (`UserRepo.cs:291-295`). The
source is honest about this: `sequencer/frame.rs:110-114` says "for now we wrap the JSON-decoded
payload as-is". *Consequence:* record contents never reach the network. The stream is an existence
notification, not a data feed — and the honesty is exactly right for an `-rc` and exactly disqualifying
for a stable release, because federation is what the firehose is for.

**F-FIRE-03 · DIVERGENT · blocker — `#sync.blocks` is a block-count integer, not a CARv1.**
`crates/atproto-pds/src/sequencer/sync_event.rs:38` declares `pub blocks: usize`, serialised straight
through at `:72`, with the module doc conceding the point at `:26-28` and a test pinning
`blocks: 42`. Worked reference: `packages/pds/src/sequencer/events.ts:47-63`; cocoon
`server/repo_sync.go:19-43`; tranquil `sync/util.rs:331-363`. *Consequence:* the one recovery
mechanism Sync 1.1 offers for a broken commit stream carries no commit.

**F-FIRE-04 · DIVERGENT · blocker — the JSON-then-DAG-CBOR round trip corrupts CIDs and precludes byte
fields.** Payloads are stored as JSON (`writer.rs:457`, `sync_event.rs:74`, `manager.rs:383`,
`identity_handlers.rs:698`) and re-encoded from `serde_json::Value` at `frame.rs:115-125`.
`Cid::serialize` emits a newtype variant (`crates/atproto-dasl/src/cid/mod.rs:106-119`) that
serde_json renders as `{"": [bytes…]}`, hitting `RepoOp.cid`/`prev` (`crates/atproto-repo/src/mst/diff.rs:164-175`);
other CIDs become text strings where `cid-link` is declared. `RepoOp.cid` additionally carries
`skip_serializing_if` (`diff.rs:170-171`) though `#repoOp.cid` is *required and nullable* — the same
root cause as F-REPO-01. dnproto explicitly re-types CIDs to tag 42 before emitting
(`src/pds/UserRepo.cs:353-357`). *Consequence:* even a flattened body decodes to the wrong types, and
a `blocks` CAR could not survive this pipeline — so F-FIRE-02 cannot be fixed without fixing this
first.

**F-FIRE-05 · DIVERGENT · blocker — `seq` is per-actor, with no global stream sequence.**
`outbox.seq AUTOINCREMENT` is per-actor (`sequencer/outbox.rs:239`,
`actor_store/sql/public_realm.rs:339`, fjall `outbox_meta` at `fjall/public_realm.rs:390-409`), and
one client cursor is seeded into every repo's counter (`http/subscribe_handlers.rs:102-103`). All
eleven comparisons use one source (reference `sequencer/db/schema.ts:6`; cocoon `persist.go:67-96`).
*Consequence:* duplicate and non-monotonic `seq`, resume that skips events, and a re-created actor DB
that replays numbers a relay has already consumed.

**F-FIRE-06 · MISSING · blocker — no covering-proof construction exists.** No proof symbol anywhere in
`crates/atproto-repo/src/mst/` or `crates/atproto-pds/src/repo/`; the only inductive code is the
import-side verifier (`crates/atproto-repo/src/repo/inductive.rs:79-158`), which accepts missing
blocks on faith at `:114-135` and never recomputes a pre-image root. Worked references: arroba
(`/tmp/gap-scratch/arroba/arroba/mst.py:871-949`, with upstream interop fixtures passing in CI); the
reference (`packages/repo/src/mst/mst.ts:784-830` + `repo.ts:145-152`); tranquil-pds
(`repo_ops.rs:584-649`); pegasus (`repository.ml:386-398`). *Consequence:* even after F-FIRE-02 ships
a naive diff, inductive consumers reject the frames — and F-REPO-04 makes the roots wrong in the
first place.

**F-FIRE-07 · DIVERGENT · blocker on `PDS_STORAGE_PROFILE=fjall` — `#identity`/`#account` are written
where the reader never looks.** Emitters open SQLite directly (`http/identity_handlers.rs:693`,
`account/manager.rs:370`) while the reader dispatches through the configured backend
(`http/subscribe_handlers.rs:26-33`, always set at `bin/pds.rs:592`). SQLite dispatch resolves to the
same file, so only fjall is affected, and `fjall` is not a default feature
(`crates/atproto-pds/Cargo.toml:96`). *Consequence:* on fjall, handle changes and takedowns are
invisible to every subscriber.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-FIRE-08 | `#info` sent with the error opcode `-1` and body `{name, message}` | DIVERGENT | stable-gap | `frame.rs:144-158`; `FrameType.Error = -1` requires `{error, message?}` (`xrpc-server/src/stream/types.ts:17-21`) and `Frame.fromBytes` throws otherwise (`frames.ts:47-51`); cirrus keeps the two distinct (`account-do.ts:1099-1109`); the only out-of-band frame this PDS can send raises an exception in a reference decoder |
| F-FIRE-09 | `FutureCursor` never emitted; `OutdatedCursor` unreachable | MISSING | stable-gap | no `FutureCursor` occurrence in `crates/`, cursor accepted unchecked (`subscribe_handlers.rs:44-46`); `OutdatedCursor` appears only in docs and one unit test while the runtime call sends `"InternalError"` (`:94`); six and seven of eleven respectively implement them; a bad cursor yields a silent permanently-empty stream |
| F-FIRE-10 | Subscriber DID set fixed at connect, capped at 1000; per-tick pool churn | PARTIAL | stable-gap | `subscribe_handlers.rs:212-216` (`list_accounts(None, 1000)`), map built once at `:102-103`, `OutboxReader` reopened per DID per 5 s tick (`:108,117`); every comparison attaches subscribers to one event source; accounts created after a relay connects never appear on that connection |
| F-FIRE-11 | Outbox has no retention | MISSING | stable-gap | no prune path in any GC loop; windowed in reference, tranquil (72 h configurable), cocoon, dnproto, arroba; unbounded disk growth with no operator knob — four comparisons share it |
| F-FIRE-12 | `requestCrawl` inverted to an outbound announcer; nothing announces automatically | DIVERGENT | stable-gap | `http/handlers.rs:317-365` fans out to `state.crawlers` and always returns 200, `hostname` optional where the lexicon requires it; reference keeps the announcer private (`crawlers.ts:29-44`) and fires it from `sequenceEvts` (`sequencer.ts:170`); metalbear has the identical inversion; relays calling the canonical method are silently dropped and a fresh deployment never registers |
| F-FIRE-13 | Zero end-to-end firehose test coverage; unit tests defend the divergence | MISSING | blocker (process) | no test opens a WebSocket; the six unit tests at `frame.rs:162-255` assert `body["payload"]["rev"]` (`:237`); reference, cirrus, alteran (four files) and tranquil (three) all have dedicated firehose tests; one golden-frame assertion would have caught F-FIRE-01, F-FIRE-04 and F-FIRE-08 |
| F-FIRE-14 | `#account` emits `status: "active"` alongside `active: true` | DIVERGENT | cosmetic | `account/manager.rs:372-382`; the lexicon scopes `status` to `active=false` and omits `"active"` from `knownValues`; the reference emits `{did, active: true}` (`events.ts:102-105`) |
| F-SYNC-01 | `com.atproto.sync.listRepos` not routed | MISSING | blocker | absent from `http/router.rs`; the enumeration already exists as `list_account_dids` (`subscribe_handlers.rs:212-216`); **all eleven** route it (alteran `index.js:58`, dnproto `Pds.cs:209`, cirrus `index.ts:204`); a relay cannot discover which accounts this server hosts. Lowest effort-to-value fix in the sync area |
| F-SYNC-02 | `com.atproto.sync.getRecord` not routed | MISSING | stable-gap | absent from `router.rs`; no proof-CAR read path in `car_export.rs`; ten of eleven serve it, arroba with real covering proofs (`xrpc_sync.py:211-230`); consumers must pull the whole repo for one record's existence proof |
| F-SYNC-03 | `getBlocks` parses `cids` as a comma-separated string | DIVERGENT | stable-gap | `http/handlers.rs:241` declares `cids: String`, split at `:254-259`; the lexicon types it as an array, which XRPC encodes as repeated query params, so `?cids=a&cids=b` yields only the last value |
| F-SYNC-04 | `#sync` never emitted on account creation or activation | PARTIAL | stable-gap | `publish_sync` call sites are `repo/import.rs:332-336` and `admin/handlers.rs:1009,1013` only; nine comparisons emit it on create and/or activate (reference `sequencer.ts:199-224`, zds `server.zig:965`, dnproto `Pds.cs:328-341`); newly created accounts give consumers no re-anchor point |
| F-SYNC-05 | No-op updates neither rejected nor suppressed | MISSING | stable-gap | `repo/writer.rs:557-600` never compares the new record CID to the prior value; reference `putRecord.ts:130-136`, tranquil `write.rs:387-394`, alteran `repo-manager.ts:242-258`; permitted by the lexicon, so not a blocker |
| F-SYNC-06 | `com.atproto.sync.listReposByCollection` not routed | MISSING | stable-gap | absent from `router.rs`; only metalbear serves it (`server.c:6724`) and the reference PDS does not; genuinely low priority given the field |

### 1.5 OAuth — Authorization Server and Resource Server

Owning chapter: [27-oauth.md](./capability-areas/27-oauth.md).

**F-OAUTH-01 · DIVERGENT · blocker — PAR and token accept JSON only, not form encoding.**
`par_handler` takes `Json<ParInput>` (`crates/atproto-pds/src/oauth/par.rs:132-135`) and
`token_handler` takes `Json<TokenInput>` (`oauth/token.rs:100-103`), while `revoke_handler` correctly
uses `Form` (`oauth/revoke.rs:41`) — which shows the inconsistency is unintentional. RFC 9126 §2 and
RFC 6749 §4.1.3 both require `application/x-www-form-urlencoded`, the reference accepts both
(`create-oauth-middleware.ts:95,135,167`), and the reference client sends form encoding
(`packages/oauth/oauth-client/src/oauth-server-agent.ts:236-239`). *Consequence:*
`@atproto/oauth-client-node` and `-browser` receive HTTP 415 and cannot complete a single flow. An
extensively implemented authorization server is non-functional for every standard AT Protocol OAuth
client. **This is the canonical small-effort/high-impact item in the report: two extractor changes,
and the entire OAuth stack becomes reachable.**

**F-OAUTH-02 · MISSING + DIVERGENT · blocker (security, exploitable) — the token endpoint has no
client authentication and lets the caller choose its own `cnf.jkt`.** `/oauth/token` requires no
client authentication and no DPoP proof (`oauth/token.rs:100-124`), and the request-time thumbprint
wins over the PAR-pinned one: `let dpop_jkt = input.dpop_jkt.clone().or(auth.request.dpop_jkt.clone());`
(`token.rs:176`). The reference cross-checks the proof against the stored `dpop_jkt`
(`packages/oauth/oauth-provider/src/oauth-provider.ts:840-848`, with the session checks at `:933,937-942`).
*Consequence:* a stolen authorization code is redeemable by anyone and bindable to the attacker's key,
which defeats DPoP entirely; a leaked refresh token is bearer-usable despite carrying `cnf`.

**F-OAUTH-03 · MISSING · blocker (security, exploitable) — `redirect_uri` is never validated against
client metadata.** PAR stores the caller-supplied value verbatim without fetching client metadata
(`oauth/par.rs:202-223`), authorize echoes it unchecked (`oauth/authorize.rs:127-139`), and the
consent page navigates to it (`oauth/consent.rs:325-331`). The reference throws `Invalid redirect_uri`
(`packages/oauth/oauth-provider/src/client/client.ts:339-342`), and all ten independents constrain it.
*Consequence:* authorization-code exfiltration using a legitimate, trusted `client_id` with an
attacker-chosen redirect. **Chained with F-OAUTH-02 this is a complete account-takeover path against
any user who can be phished onto the consent URL**, and the compromise is invisible to the victim
because the client_id shown on the consent screen is genuine.

**F-OAUTH-04 · DIVERGENT · blocker (functional) — non-DPoP OAuth sessions break permanently after the
first refresh.** `issue_pair` stores `dpop_jkt.clone().unwrap_or_default()` — an empty `String` when
absent (`oauth/token.rs:290`) — and `handle_refresh` passes `Some(handle.dpop_jkt)` back (`:230`), so
`cnf` becomes `Some(jkt: "")` and `token_type` flips to `"DPoP"` (`:298`). Thereafter
`claims.cnf.is_some()` is true (`http/auth.rs:179`) and the proof thumbprint is compared against `""`
(`oauth/dpop.rs:81-87`), which can never match. *Consequence:* silent, unfixable `InvalidDpopProof`
for any client that does not send `dpop_jkt`.

**F-OAUTH-05 · MISSING · blocker (security, exploitable) — unguarded SSRF on the PAR metadata and
`jwks_uri` fetches, and on the spaces mint path.** PAR GETs a caller-supplied `client_id`
(`oauth/par.rs:414-415`) and then its `jwks_uri` (`:426-433`) with no scheme, host or address
restriction; a grep for `is_private|loopback|link_local|is_global|ssrf` across all of
`crates/atproto-pds/src/` returns zero. The workspace *has* a guard —
`crates/atproto-identity/src/host.rs` — and the PDS never calls it. The same hole exists on the spaces
attestation path: `client_id` is https-constrained (`space/mint_authz.rs:268`) but `jwks_uri` is not
(`:317-343`), fetched by a bare `reqwest::Client::builder()` with only a 10 s timeout
(`http/space_handlers.rs:1554-1558`). Worked reference: alteran guards the identical fetch.
*Consequence:* an unauthenticated caller drives the PDS to GET arbitrary internal URLs — cloud
metadata endpoints, internal admin panels, anything reachable from the pod.

**F-OAUTH-06 · MISSING · blocker (browser clients) — no CORS on any route, including the
protected-resource metadata document.** A grep for `cors|Access-Control` is empty and the router
applies only the metrics layer (`http/router.rs:442-447`). *Consequence:* browser OAuth clients fail
discovery before PAR is even attempted. Independent of F-OAUTH-01, so fixing the encoding alone does
not unblock `@atproto/oauth-client-browser`.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-OAUTH-07 | `private_key_jwt` advertised, not implemented | DIVERGENT | stable-gap | AS metadata claims it (`oauth/metadata.rs:57-80`) with no verification path; the metadata document promises more than the server delivers — a one-line honesty edit until it is built |
| F-OAUTH-08 | No server-issued DPoP nonces | MISSING | stable-gap | `expected_nonce_values` exists in the crate (`crates/atproto-oauth/src/dpop.rs:451-452`) but the PDS sets only `max_age_seconds` (`oauth/dpop.rs:71-72`); grep for `DPoP-Nonce|use_dpop_nonce` is empty; rsky-oauth implements nonces; replay resistance rests entirely on a time window |
| F-OAUTH-09 | `require_dpop_bound_access_tokens: true` advertised, not enforced | DIVERGENT | stable-gap | `metadata.rs:76` vs `token.rs:246-248,298`; a client that omits DPoP still receives a usable token |
| F-OAUTH-10 | Access-token revocation is a no-op | PARTIAL | stable-gap (security) | `oauth/revoke.rs:63-74` revokes refresh tokens correctly, `:75-82` does nothing for access tokens and no `jti` lookup exists on the request path; a revoked access token keeps working for its remaining 900 s while the endpoint returns success |
| F-OAUTH-11 | AS metadata omits nine fields clients read | PARTIAL | stable-gap | fourteen fields emitted at `metadata.rs:57-80`; `metadata.rs:75` is also narrower than the validator's ES384 accept (`crates/atproto-oauth/src/dpop.rs:574`); clients cannot discover capabilities the server has, including JAR (F-OAUTH-17) |
| F-OAUTH-12 | Granular scopes accepted and ignored outside `space:` | MISSING | blocker (security) | no `scope` reference in `http/write_handlers.rs`; `AuthSubject::scopes` exists (`http/auth.rs:96-101`) and `RepoScope` with collection and action is fully parsed (`crates/atproto-oauth/src/scopes.rs:42,509`, round-tripped by tests at `:1223-1254`); the only assertion helpers are the three `assert_space*` (`:1116-1141`) while `Scope::Rpc` parses at `:578` and `blob:` at `:433,688-702`. Reference, cocoon, cirrus, pegasus, tranquil-pds, zds and alteran all assert per-write. `scope=atproto` alone can write every collection, upload any MIME type, rotate the handle and proxy arbitrary calls — the authorization server's decisions are not enforced by the resource server |
| F-OAUTH-13 | `include:<nsid>` unresolved; `dereferenceScope` unrouted | MISSING | stable-gap | permission sets cannot be expanded, so a client asking for a named set gets nothing; zds expands `include:` into space scopes (`oauth/permission_sets.zig:636-640`) |
| F-OAUTH-14 | Inbound access tokens: `aud`/`iss` unchecked | MISSING | stable-gap | cross-realm token acceptance wherever `PDS_JWT_SECRET` is shared between deployments |
| F-OAUTH-15 | One symmetric secret signs four token classes; JWKS verifies none | DIVERGENT | stable-gap | `/oauth/jwks` publishes real keys with RFC 7638 `kid`s that no issued token is signed with, so no third party can verify an access token |
| F-OAUTH-16 | Authorization response is JSON + JS; denials never reach `redirect_uri` | DIVERGENT | stable-gap | `oauth/authorize.rs:59-65`; RFC 6749 §4.1.2.1 requires the denial to be delivered to the client's redirect; a user who clicks "deny" leaves the client hanging |
| F-OAUTH-17 | JAR request-object `aud` advisory; JAR unadvertised | DIVERGENT | stable-gap | on mismatch the code logs at debug and continues (`par.rs:383-397`) where RFC 9101 §4 makes it MUST-verify, so a request object minted for PDS-A is replayable at PDS-B. See §4 — the JAR implementation is itself a lead |
| F-OAUTH-18 | 60 s PAR and authorization-code lifetimes | DIVERGENT | stable-gap | the reference uses a 5-minute PAR TTL (`constants.ts:54`); a slow consent screen or a user reading the prompt exhausts the window |
| F-OAUTH-19 | `POST /oauth/authorize` unrate-limited, no CSRF token | MISSING | stable-gap | the consent POST is the one endpoint where a forged cross-site submission grants an authorization; `/oauth/token` *is* limited (`token.rs:104-114`), PAR and authorize are not |
| F-OAUTH-20 | Protected-resource metadata missing three fields | PARTIAL | cosmetic | `oauth/metadata.rs:85-93` |

### 1.6 Service auth and AppView proxying

Owning chapter: [28-service-auth.md](./capability-areas/28-service-auth.md).

**F-SVC-01 · DIVERGENT · blocker — proxying is non-functional as routed: the NSID is truncated and the
query string discarded.** The route is `/xrpc/app.bsky.{*nsid}` (`http/router.rs:109`) and the handler
consumes the captured value directly (`http/proxy_handlers.rs:120-128`). matchit 0.8.4 places the
literal prefix in the parent node so the catch-all captures only the remainder
(`matchit-0.8.4/src/tree.rs:369-393`) and axum passes route paths through verbatim
(`axum-0.8.8/src/routing/path_router.rs:83-88`) — both versions match `Cargo.lock`. Confirmed
empirically: `GET /xrpc/app.bsky.feed.getTimeline?limit=5` yields `nsid=feed.getTimeline` with the
query unused. `resolve_target`'s default-pin test `nsid.starts_with("app.bsky.")`
(`proxy_handlers.rs:104`) therefore never matches. *Consequence:* every unheadered `app.bsky.*` call
returns 503, and a headered one forwards `{appview}/xrpc/feed.getTimeline` with no query parameters.
No Bluesky client works against this PDS. The unit tests at `proxy_handlers.rs:359-430` pass because
they call `resolve_target` with a hand-written full NSID rather than going through the router.

**F-SVC-02 · MISSING · blocker — `Atproto-Proxy` DIDs are not resolved; only one operator-pinned
AppView is reachable.** Any DID other than `state.bsky_app_view_did` returns 502
(`proxy_handlers.rs:88-101`) and the `service-id` half of the header is parsed and thrown away. No
`chat.bsky.*`, `tools.ozone.*` or `com.atproto.label.*` routes exist. Ten of eleven resolve properly,
including cirrus (`xrpc-proxy.ts:112-142`), alteran (`src/lib/appview/did-resolver.ts:83-102`) and
dnproto (`AppBsky_Proxy.cs:60-118`, with an allow-list *and* an SSRF filter). *Consequence:* no
labeler, no feed generator, no chat, no Ozone, no third-party AppView. This is the capability that
makes a PDS a network participant.

**F-SVC-03 · DIVERGENT · blocker — service-auth JWTs carry `typ: "at+jwt"`, which the reference
verifier rejects outright.** All five minters emit it (`http/service_auth_handlers.rs:35,140`,
`identity_handlers.rs:327`, `proxy_handlers.rs:306`, `moderation_handlers.rs:175`,
`space/mint_authz.rs:490`). `packages/xrpc-server/src/auth.ts:88-104` throws `BadJwtType` for exactly
this value; `auth.ts:36-39` mints `typ: 'JWT'`. Seven comparisons emit `"JWT"`; none emits `at+jwt`.
*Consequence:* every token this PDS mints is rejected by the Bluesky AppView, by Ozone, and by any
`@atproto/xrpc-server`-based service. One-line fix, network-wide blast radius.

**F-SVC-04 · DIVERGENT · blocker (security) — `lxm` is optional at both mint and verify, yielding a
wildcard cross-service bearer.** Mint declares it `skip_serializing_if`
(`service_auth_handlers.rs:45,68-69`); verification only compares when the claim is present
(`space/service_auth.rs:151-157`). The reference treats a missing `lxm` as a failure with a dedicated
message (`packages/xrpc-server/src/auth.ts:119-127`). *Consequence:* any authenticated account calls
`getServiceAuth?aud=<target>` with no `lxm`, receives a 600-second token (F-SVC-06), and that token
satisfies every `lxm`-scoped method at any peer implementing the same lax check.

**F-SVC-05 · MISSING · blocker (security) — no `PROTECTED_METHODS`, `PRIVILEGED_METHODS`, takendown,
or `rpc:` scope gate at mint.** `service_auth_handlers.rs:93-176` contains no such check;
`AuthSubject::privileged()` has exactly one call site workspace-wide (`write_handlers.rs:601`);
`ScopesSet` ships only the three `assert_space*` helpers. The reference gates all four
(`packages/pds/src/api/com/atproto/server/getServiceAuth.ts:29,45-66,68-86,88-93` with a 16-NSID
`PROTECTED_METHODS` set at `pipethrough.ts:613-630`). Protected-method refusal exists in zds
(`server.zig:1083-1085`), tranquil (`service_auth.rs:139-147`), rsky (`get_service_auth.rs:34-41`) and
alteran (`com.atproto.server.getServiceAuth.ts:13-23`). *Consequence:* a non-privileged app-password
session can mint `lxm=com.atproto.server.createAccount` — the migration credential — and tokens for
every account-management NSID the reference protects.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-SVC-06 | `exp` interpreted as a TTL, not an absolute epoch; `BadExpiration` never returned | DIVERGENT | stable-gap | `service_auth_handlers.rs:131-136` (`q.exp.unwrap_or(60).clamp(1,600)` then `iat + ttl`); eight comparisons read it as an epoch; a client asking for 30 s gets 600 s, multiplying F-SVC-04's exposure |
| F-SVC-07 | `com.atproto.admin.revokeServiceAuth` has no effect | DIVERGENT | blocker (security control that reads as working) | `admin/handlers.rs:855` writes the row; `service_auth_blacklist::contains` (`:63`) has no production caller — grep finds only the definition, `lib.rs:58` and `gc.rs:137-139` — while the doc at `admin/handlers.rs:838-840` claims verifiers consult it; an operator revoking a leaked token sees 200 OK and a log line and is wrong. A no-op endpoint is worse than an absent one |
| F-SVC-08 | Inbound verification ignores the JWS header; no `jti` replay, `iat` or `nbf` check | PARTIAL | stable-gap | `space/service_auth.rs:132-142` decodes the payload only; `header_b64` reaches the signing input at `:168` unparsed; the reference parses the header and requires `alg` to be a string (`auth.ts:194-200`); a captured token is replayable for its whole (600 s) lifetime |
| F-SVC-09 | DPoP-bound tokens cannot use the proxy — `htu` derived from a synthetic `/` | DIVERGENT | stable-gap | `proxy_handlers.rs:244-261` builds auth `Parts` with `.uri("/")` at `:250`; cirrus verifies against the real request (`xrpc-proxy.ts:196-202`); every browser OAuth client 401s on proxied calls even after F-SVC-01/02 |
| F-SVC-10 | Proxied requests and responses drop protocol headers | PARTIAL | stable-gap | only `Content-Type` in each direction (`proxy_handlers.rs:195-199,227-238`); the reference forwards `accept-encoding`, `accept-language`, `atproto-accept-labelers`, `x-bsky-topics` (`pipethrough.ts:124-135`) and returns `atproto-repo-rev`, `atproto-content-labelers`, `retry-after` (`:527-558`); alteran carries a fourteen-header allow-list; label preferences are silently ignored |
| F-SVC-11 | No never-proxy `PROTECTED_METHODS` guard on the proxy path | MISSING | cosmetic today | `proxy_handlers.rs:63-116`; reference `pipethrough.ts:92-95`; becomes load-bearing the moment F-SVC-02 makes arbitrary namespaces proxyable |
| F-SVC-12 | `aud` validation accepts any string beginning `did:` | PARTIAL | cosmetic | `service_auth_handlers.rs:104-110`; the reference requires `isAtprotoDid || isAtprotoDidRefAbsolute` (`getServiceAuth.ts:38-42`); zds validates the `did#serviceId` shape |
| F-SVC-13 | `kid` serialises as literal `null` | DIVERGENT | cosmetic | `service_auth_handlers.rs:56-61,141`; moot until F-SVC-03 is fixed, since the header is rejected on `typ` first |
| F-SVC-14 | No canonical endpoint accepts an inbound service-auth token | MISSING | blocker | `verify_service_auth` has exactly two callers, both in Spaces (`space_handlers.rs:2096,2570`); `create_account` cannot read headers at all (`auth_handlers.rs:81-83`); reference, cocoon (`handle_server_create_account.go:81-95`), zds and tranquil all gate `createAccount`-with-existing-DID on service auth; an account cannot be migrated *into* this PDS under the standard flow — the other face of F-ACCT-02 |

### 1.7 Account lifecycle

Owning chapter: [21-accounts.md](./capability-areas/21-accounts.md).

**F-ACCT-01 · MISSING · blocker — `com.atproto.server.describeServer` is not routed.** No
`describeServer` literal in `crates/atproto-pds/src/http/router.rs`; the data already lives on
`HttpState` (`http/auth_handlers.rs:93-110,157`). All eleven comparisons route it, including cirrus
(`index.ts:278`), dnproto (`Pds.cs:190`) and alteran (`index.js:42`). This is normally filed as a
discovery nicety; it is more than that here, because the canonical migration sequence
(`/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md:105-112`) has the client call `describeServer` on the
*new* PDS to learn the correct `aud` for the service-auth token the old PDS must mint.
*Consequence:* 404 on the first request of every signup, login and migration flow — migration fails at
step 2, before `importRepo` or `listMissingBlobs` are ever reached.

**F-ACCT-02 · MISSING · blocker (security, exploitable anonymously) — `createAccount` adopts a
caller-supplied `did` with no proof of control.** The handler takes no `Parts` and applies no auth
(`http/auth_handlers.rs:81-84`, routed at `router.rs:117`); the BYO-DID branch uses the value verbatim
(`:184-185`); the account row is inserted `Active` (`account/manager.rs:158`); and
`PDS_INVITE_REQUIRED` defaults false (`bin/pds.rs:88-89`). The reference requires a service-auth token
from the DID's current host (`createAccount.ts:251-259`); so do cocoon
(`handle_server_create_account.go:81-95`), zds (`server.zig:700-752`) and tranquil
(`identity/account.rs:244-256`). Shared weakness with metalbear (`src/server.c:3373-3382`) and
pegasus. *Consequence:* anyone can squat an arbitrary DID, obtain a session bound to the victim's DID,
have the PDS serve `describeRepo`/`getRepo`/firehose events for it, and permanently deny the victim an
inbound migration to this host. Forged commits fail relay signature verification, so the damage is
bounded — but the lockout is not.

**F-ACCT-03 · DIVERGENT · blocker — accounts created for an inbound migration land `Active`.**
`account/manager.rs:158` binds `AccountState::Active` unconditionally, conceded by
`tests/migration_e2e.rs:148-158`. The canonical sequence requires the account to land *deactivated*
and be activated only after `submitPlcOperation`
(`/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md:27`); seven comparison columns create it deactivated
(reference `createAccount.ts:256`, rsky `create_account.rs:325`, tranquil `account.rs:439`, zds
`server.zig:152`, cirrus `account-do.ts:79-85`, pegasus `migrate/ops.ml:91-94`). *Consequence:* the
repo is publicly readable and emitting firehose events before the DID document points at this PDS, and
`activateAccount` becomes a no-op with nothing to gate.

**F-ACCT-04 · DIVERGENT · blocker (security) — `activateAccount` lets a taken-down account restore
itself.** `http/auth_handlers.rs:677-687` calls `set_state(sub, Active)` unconditionally;
`valid_transition(Takendown, Active)` returns `true` (`account/manager.rs:1102`); no auth guard checks
state (`http/auth.rs:154-198`). The reference gates activate behind a verifier that rejects taken-down
subjects (`packages/pds/src/auth-verifier.ts:628-634`) and asserts the DID document first.
*Consequence:* an admin takedown is reversible by the user with a single unprivileged call.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-ACCT-05 | `updateEmail` unrouted; the completion step uses an invented NSID | DIVERGENT | blocker (interop) | `confirmEmailUpdate` routed at `router.rs:176-179` with no canonical lexicon under `com/atproto/server/`; `updateEmail` absent; routed by eight comparisons; no standard client can change its email address on this PDS |
| F-ACCT-06 | `deleteAccount` drops the lexicon-required `did` and `password` | DIVERGENT | blocker (security) | `DeleteAccountInput` has only `token` (`auth_handlers.rs:1162-1166`), no bearer auth on the route; cocoon (`handle_server_delete_account.go:37-70`), metalbear and pegasus all verify all three; deletion is single-factor on a 43-character emailed token with no binding to the DID being deleted |
| F-ACCT-07 | `checkAccountStatus.validDid` hardcoded `true`; two required fields skippable | DIVERGENT | blocker (migration correctness) | `auth_handlers.rs:820`, doc at `:837`, `skip_serializing_if` at `:841-845` though `checkAccountStatus.json` marks `repoCommit`/`repoRev` required; rsky computes it (`get_account_info` path), the reference derives it from `assertValidDidDocumentForService`; cocoon hardcodes it too, so this is not universal; a migration tool polls past a DID document that does not yet point here |
| F-ACCT-08 | `createInviteCode` gated by an ordinary user session; issuance defaults enabled | DIVERGENT | blocker (invite-gated deployments) | `require_access_jwt` at `auth_handlers.rs:634`, `can_issue_invites` DEFAULT 1 (`migrations/accounts/20260506000002_invite_toggle.sql:9`), no `useCount` cap; reference uses an admin token (`createInviteCode.ts:20`), as do cocoon, metalbear, zds and pegasus; the first account on an invite-required PDS mints unlimited codes, so the gate stops constraining signups after one account |
| F-ACCT-09 | `refreshSession` performs no account-state check | MISSING | stable-gap (security) | `auth_handlers.rs:406-457` looks the account up only for `handle`/`did`, unlike `createSession` (`:319-328`); the reference loads with `includeTakenDown: true` and rejects a soft-deleted account before rotating (`refreshSession.ts:21-35`); a 90-day refresh token issued before a takedown keeps minting access tokens for 90 days after it — see F-MOD-02 |
| F-ACCT-10 | `getAccountInviteCodes` output is not `server.defs#inviteCode` | DIVERGENT | stable-gap | `auth_handlers.rs:1540-1556` emits `{code, disabled, availableUses, usedBy, createdAt}`; the def requires `available`, `forAccount`, `createdBy`, `uses`; invite-management UIs render nothing usable |
| F-ACCT-11 | `com.atproto.server.createInviteCodes` (batch) not routed | MISSING | stable-gap | absent from `router.rs`; routed by seven comparisons; bulk issuance requires N round-trips or direct SQL |
| F-ACCT-12 | `createAccount` requires `password` and ignores `recoveryKey`/`verificationCode`/`plcOp` | DIVERGENT | stable-gap | `CreateAccountInput` (`auth_handlers.rs:28-41`) vs a lexicon requiring only `handle`; the reference prepends `recoveryKey` to the rotation keys (`createAccount.ts:288-291`); a migrating user cannot supply their own recovery key and password-less OAuth-only signup is impossible |
| F-ACCT-13 | `getSession`/`createSession` omit the optional status fields | PARTIAL | stable-gap | `GetSessionResponse` emits `handle`, `did`, `email` only (`auth_handlers.rs:366-374`); `active`, `status`, `emailConfirmed`, `didDoc` never sent; clients cannot distinguish a deactivated account at login |
| F-ACCT-14 | `confirmEmail` drops the lexicon-required `email` | DIVERGENT | stable-gap | `ConfirmEmailInput` has only `token` (`auth_handlers.rs:1306-1309`); the confirmed address is never cross-checked against the token's account |
| F-ACCT-15 | `reserveSigningKey` is unauthenticated and non-idempotent | DIVERGENT | blocker (security) | `auth_handlers.rs:891-894` takes `(State, Json<Input>)` with no guard and persists a reservation row for a caller-supplied `did` (`:911-924`); a fresh key is generated on every call (`:897`) under a fresh row id (`:920-924`) so the dedupe guard never fires, contradicting the doc at `:887-889`; session-gated in tranquil, cocoon, rsky, pegasus and zds; metalbear also exposes it publicly, so this is not unique — an anonymous caller can force unbounded key generation and squat reservations, the precursor primitive for F-ACCT-02 |

### 1.8 Identity and DID

Owning chapter: [24-identity.md](./capability-areas/24-identity.md).

Context worth stating before the findings: this is the area where atproto-crates arrives with a real
structural advantage and largely fails to spend it. `atproto-identity` ships a spec-compliant
concurrent DNS-TXT-plus-HTTPS handle resolver with conflict detection (`src/resolve.rs:616-641`), a
full PLC operation model (`src/plc/operations.rs:84-118`), an operation-chain validator
(`src/plc/chain.rs:261`), did:web and did:webvh syntax validation (`src/validation.rs:517,607`) and
SSRF-safe hostname validation (`:178,391`). No comparison implementation has a library asset of that
quality behind its PDS. The `validation` module has **zero** call sites in `crates/atproto-pds/src/`.

**F-IDENT-01 · MISSING · blocker — no `#identity` firehose event on handle change.**
`emit_identity_event` (`http/identity_handlers.rs:688-706`) is called only from `refreshIdentity`
(`:664`); `do_update_handle` (`:155-280`), `admin.updateAccountHandle` (`admin/handlers.rs:628`),
`submitPlcOperation` (`auth_handlers.rs:1685-1710`) and `createAccount` emit nothing. Emitted by the
reference (`account-manager.ts:386-393`), cocoon (`handle_identity_update_handle.go:91`), rsky
(`update_handle.rs:60-70`), pegasus, tranquil (`identity/did.rs:612,638,695`), zds
(`identity.zig:225,292`) and metalbear. *Consequence:* renames never reach relays or AppViews, so the
new handle silently does not work anywhere off this PDS.

**F-IDENT-02 · PARTIAL · blocker — `updateHandle` performs no validation and no ownership proof.**
`do_update_handle` (`http/identity_handlers.rs:155-280`) goes straight from the raw string to the PLC
operation: no handle syntax validation, no TLD check, no service-domain constraint, no reserved-name
check, no bidirectional resolution proof for an off-service domain, no uniqueness pre-check, no rate
limit. `PDS_SERVICE_HANDLE_DOMAINS` is consulted only by `createAccount` and defaults empty
(`bin/pds.rs:241-242`). zds implements the full set — account-state gating, matching rate limits,
normalization, hosted-domain validation, external bidirectional resolution, a did:web cross-check, a
uniqueness check, a tombstone check and a rotation-key authorization check
(`/tmp/gap-scratch/zds/src/atproto/identity.zig:188-296`); tranquil does the same in Rust
(`identity/did.rs:523-700`). *Consequence:* any account claims any handle string and this PDS then
answers `resolveHandle` for it; a `UNIQUE` collision surfaces as a 500 *after* the PLC operation is
submitted, permanently desynchronising the DID document from the local row.

**F-IDENT-03 · DIVERGENT · blocker (security + interop) — `signPlcOperation` uses a non-lexicon input
shape and drops the email-token gate.** `SignPlcOperationInput { op }`
(`auth_handlers.rs:1592-1597`, deserialized at `:1650`, blind-signed at `:1657`); auth is
`require_access_jwt` only (`:1619`), with no `privileged()` check (`:1754-1759`). The reference takes
the canonical field set plus a `token` (`signPlcOperation.ts:13-17,41-51`); so do cocoon, pegasus, zds
and cirrus. Only alteran is equally ungated. *Consequence:* every canonical migration client 400s, and
a stolen two-hour access token suffices to have the PDS sign an arbitrary key-rotation operation with
the account's rotation key.

**F-IDENT-04 · MISSING · blocker — `GET /.well-known/atproto-did` is not served (nor
`/.well-known/did.json`).** Only two `.well-known` routes exist, both OAuth (`router.rs:253,257`).
Ten of eleven serve `atproto-did`; eight serve `did.json` (tranquil `lib.rs:471`, cocoon
`handle_well_known.go:53-67`, metalbear `server.c:6390`, cirrus `index.ts:113`, pegasus, alteran, zds
`router.zig:136`, dnproto `Pds.cs:215`) — the reference and rsky-pds also omit `did.json`, so
calibrate that half down. *Consequence:* the PDS cannot host a handle on its own domain without an
external web server synthesising the response, which is documented nowhere; and
`did:web:<host>` is unresolvable, which matters for spaces and service-auth peers that must resolve
this PDS's own document. This is also why the shipped `deploy/` cluster cannot federate (F-OPS-05).

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-IDENT-05 | `submitPlcOperation` validates nothing before forwarding | PARTIAL | stable-gap | `auth_handlers.rs:1685-1710` deserializes and POSTs, binding only `claims.sub`; the reference performs five checks (`submitPlcOperation.ts:19-53`), pegasus two, zds one; the guide's stated reason for routing the op through the new PDS — catching an operation that would break the account — is not delivered, and a malformed op permanently locks the user out of their identity |
| F-IDENT-06 | `activateAccount` does not validate the DID document and emits no `#identity`/`#sync` | PARTIAL | stable-gap | `auth_handlers.rs:677-688` → `set_state`, which emits `#account` only (`account/manager.rs:362,369-390`); reference `account-manager.ts:458` + `sequencer.ts:214-224`, plus rsky, metalbear, cirrus, zds and dnproto; note **no** implementation blocks activation on missing blobs — the canonical gate is the DID-document check, which is the one atproto-crates lacks |
| F-IDENT-07 | `getRecommendedDidCredentials` omits the operator's external rotation key | PARTIAL | stable-gap | `identity_handlers.rs:462-478` builds `rotationKeys` from `account.rotation_key_ref` only; `PlcConfig::external_rotation_key` (`plc.rs:60`, used at `:183-190`) is never consulted; the reference prepends `cfg.identity.recoveryDidKey`; a migration following the recommended credentials silently deletes the deployment's fallback recovery key |
| F-IDENT-08 | `refreshIdentity` reads `did` instead of `identifier`, returns a non-`identityInfo` body | DIVERGENT | stable-gap | `identity_handlers.rs:530-534`, response `:539-555` lacks `didDoc`, non-PLC DIDs skip the fetch (`:604-627`); rsky and metalbear are both conformant; canonical requests 400 |
| F-IDENT-09 | `resolveHandle` does not normalize or validate input and ignores account state | PARTIAL | stable-gap | `identity_handlers.rs:65-71` → `account/directory.rs:234-238` exact match, no lowercasing, no prefix stripping, no state filter, and no service-domain fast-fail (`:73-105`); `is_valid_handle` and `strip_handle_prefixes` exist in `atproto-identity` with no PDS call site; mixed-case handles fail, takendown accounts still resolve, and an unregistered handle in this server's own namespace may resolve to a foreign DID |
| F-IDENT-10 | did:web account DIDs break rather than degrade | PARTIAL | stable-gap | `do_update_handle` fetches the PLC audit log unconditionally (`identity_handlers.rs:216-224`) → 502 `PlcUnavailable`; `refreshIdentity` no-ops (`:621-627`); cocoon, pegasus, tranquil and zds all branch on DID method; a migrated did:web account is stuck and the failure reads as "PLC unavailable" |
| F-IDENT-11 | `requestPlcOperationSignature` returns a bearer token instead of emailing a code | DIVERGENT | stable-gap | `identity_handlers.rs:288-291,299-341`; the lexicon declares no output; reference, cocoon, metalbear, pegasus and zds all email a `plc_operation` token; the second factor is handed to whoever already holds the first — and given F-IDENT-03 no token is consumed anyway, so the endpoint is decorative |

### 1.9 Moderation and admin

Owning chapter: [30-moderation-admin.md](./capability-areas/30-moderation-admin.md).

**F-MOD-01 · PARTIAL · blocker (security) — account takedown is enforced on two public read paths and
nowhere else; bulk export is wide open.** `require_public_read` (`repo/reader.rs:510-518`, predicate
`account/state.rs:56-58`) is genuinely enforced at `:107` (`getRecord`) and `:209` (`listRecords`),
with a passing test at `reader.rs:695-704` — this half works and must not be reported as absent. But
`getRepo` (`http/handlers.rs:186-233`), `getBlocks` (`:245-296`), `getBlob`
(`http/blob_handlers.rs:33-72`), `listBlobs` (`:96-123`), `getLatestCommit` (`repo/reader.rs:382-397`)
and `describeRepo` (`:335-379`) contain no state check, and the four files behind the sync and blob
surface contain no `AccountState` reference of any kind. The reference gates all seven sync handlers
through `assertRepoAvailability` (`packages/pds/src/api/com/atproto/sync/util.ts:6-36`); so do zds
(`sync.zig:181,210,252,272`), tranquil (`sync/util.rs:131-182`) and rsky. *Consequence:* two of
roughly nine public read paths are gated, so a takedown removes record-level reads while the account's
complete repo CAR, raw blocks and every blob stay anonymously downloadable. A takedown for illegal
content does not remove the content. The three declared takedown errors are unreachable on all five
sync endpoints that declare them.

**F-MOD-02 · MISSING · blocker (security) — takedown blocks no writes and invalidates no live
sessions.** `AccountState::allows_writes` (`account/state.rs:60-64`) has no production caller; the
write guard chain `require_session` → `require_authn` (`http/write_handlers.rs:71-74`,
`http/auth.rs:154-184`) never reads account state; `oauth::handle_refresh` (`oauth/token.rs:188-234`)
does not look the account up at all; the refresh TTL is 90 days (`account/session.rs:26`). Worked
references: the reference's `AuthScope.Takendown`, rsky `auth_verifier.rs:994`, zds `repo.zig:587-594`
at seven call sites, tranquil's `Auth<NotTakendown>` (`repo/blob.rs:242`, `repo/import.rs:48`).
*Consequence:* a taken-down account keeps writing records and publishing firehose commits until its
refresh token expires — up to 90 days after the moderation action.

**F-MOD-03 · DIVERGENT · blocker (interop) — `updateSubjectStatus`/`getSubjectStatus` use a
project-local shape, and record- and blob-level takedown are unaddressable.**
`admin/handlers.rs:156-162` takes `{did, state}` and `:204-218` returns `{did, state}` with `did`
required and the `uri`/`blob` union members ignored, against the canonical subject union in
`updateSubjectStatus.json`. The reference, rsky (`update_subject_status.rs:28-59`) and tranquil
(`admin/status.rs:169-205,257-265,291-299`) all handle all three subject kinds; zds parses the
canonical union for the account case (`server.zig:995-1050`). *Consequence:* Ozone and `pdsadmin`
cannot drive this PDS's takedowns at all, and no public-realm record or blob can be taken down by any
means.

**F-MOD-04 · PARTIAL · blocker (security) — admin Basic-auth compares non-constant-time, ships a live
default password, and is unrate-limited.** `admin/handlers.rs:80` and `admin/dashboard.rs:71` use
`!=`; the default `"admin-default-CHANGE-ME"` at `:34` is active unless `PDS_PRODUCTION=true`
(`:90-95`, `config.rs:52-58`). metalbear constant-time compares (`server.c:262-292`); the reference
additionally accepts a moderation-service JWT for attribution (`auth-verifier.ts:137-149`).
*Consequence:* a timing oracle against the one secret protecting every admin verb, and unconfigured
non-production deployments ship a known password.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-MOD-05 | Four admin request/response shapes fail canonical clients | DIVERGENT | stable-gap | `accountView.indexedAt` absent from `getAccountInfo`/`getAccountInfos`/`searchAccounts` — all emit `createdAt` (`admin/handlers.rs:105-122,286-297`); `sendEmail` omits the required `senderDid` and makes optional `subject` required (`:494-504`); `updateAccountEmail` reads `did` where the lexicon requires `account` (`:558-565`) — a hard deserialization failure; `searchAccounts` requires an undeclared `q` and ignores the declared `email` (`:275-283`); rsky and tranquil serve `accountView` correctly |
| F-MOD-06 | `disableAccountInvites`/`enableAccountInvites` mounted under `com.atproto.server.*` | DIVERGENT | stable-gap | `router.rs:413,417`, handlers `admin/handlers.rs:877,889`, input field `did` vs lexicon-required `account` (`:866-871`); reference `admin/index.ts:23-24`; a 404 for canonical callers on an otherwise working feature — a one-line routing fix |
| F-MOD-07 | `admin.deleteAccount` performs no data erasure | PARTIAL | stable-gap (data protection) | `admin/handlers.rs:253-270` sets state and stops; the reference destroys the actor store (`admin/deleteAccount.ts:12-19`); combined with F-MOD-01, a "deleted" account's repo and blobs remain publicly served |
| F-MOD-08 | `getInviteCodes` unpaginated and non-conforming; `disableInviteCodes` ignores `accounts` | DIVERGENT | stable-gap | `admin/handlers.rs:337-343,346-364,1050-1068`; unbounded response on a large deployment, no per-account bulk revocation |
| F-MOD-09 | The denylist has no operator interface and is checked only at signup | PARTIAL | stable-gap | `denylist::contains` called only at `auth_handlers.rs:115,130`; `do_update_handle` does not consult it; no XRPC route or CLI subcommand calls `denylist::add` (`bin/atproto-pds-admin.rs:41-111`); banning requires hand-written SQL, and a banned handle can be adopted post-signup via `updateHandle` |
| F-MOD-10 | `createReport` forwards an unvalidated body | PARTIAL | cosmetic | `moderation_handlers.rs:47` takes raw `Bytes`; the lexicon-required `reasonType`/`subject` are never parsed; rsky validates before proxying; low impact since the moderation service is the real validator |
| F-MOD-11 | `getAccountInfos` parses the array param `dids` as a comma-joined string | DIVERGENT | cosmetic | `admin/handlers.rs:415-425,449-454`; pegasus has the identical bug, so a shared blind spot rather than an outlier |

### 1.10 Account migration

Owning chapter: [31-migration.md](./capability-areas/31-migration.md). Migration is not a "partial"
capability — the sequence documented at `/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md` **cannot be
completed today**, and it fails at three independent points in order: F-ACCT-01 (no `describeServer`,
so the handshake never starts), F-MIG-01 (no record index after import), F-BLOB-02 (no blob refs to
enumerate). Any one alone breaks it.

**F-MIG-01 · PARTIAL · blocker — `importRepo` writes no record index, so an imported repo is invisible
to every record-read API.** All three record readers resolve through `repo_record` —
`repo/reader.rs:133,141` (`getRecord`), `:268,280` (`listRecords`), `:353` (`describeRepo`) — and
`crates/atproto-pds/src/repo/import.rs` never writes it. It persists blocks (`:246-263`) and a
`CommitRow` into `commit_obj` (`:278,300`) and stops. The module doc at `:9-10` claims the import will
"index records into …", so this is a doc-vs-code mismatch alongside F-BLOB-02 and F-MOD-01's
`Deactivated` case. Worked references: `packages/pds/src/api/com/atproto/repo/importRepo.ts:84-95`;
cirrus `account-do.ts:1023-1035`; cocoon `handle_import_repo.go:72-101`; zds `repo.zig:343-395`;
tranquil `sync/import.rs:304-361`. *Consequence:* `importRepo` reports success, the commit chain
verifies inductively (that part genuinely works, `import.rs:232-233`), and the account then presents
as empty — `getRecord` not-found for everything, `listRecords` an empty page, `describeRepo` no
collections. Silent data loss from the user's perspective.

**F-MIG-02 · MISSING · blocker — `app.bsky.actor.getPreferences`/`putPreferences` are not
implemented.** No implementation in `crates/atproto-pds/src`; the catch-all proxy
(`http/router.rs:109-113` → `proxy_handlers.rs:120,132`) forwards them to an AppView that has no such
handler (absent from `/tmp/gap-scratch/atproto/packages/bsky/src/api/app/bsky/actor/`), while the
reference PDS owns them (`getPreferences.ts:46`). Served locally by all eleven, including cirrus
(`index.ts:382,387`), dnproto (`Pds.cs:199-200`), zds (`router.zig:182-183`) and arroba's stubs
(`app.py:90-98`). *Consequence:* private-state migration is impossible in both directions, and muted
words, feed preferences and content-label settings are broken for every logged-in user.

**F-MIG-03 · PARTIAL · stable-gap — no migration tooling, and the end-to-end test certifies the broken
behaviour.** No migration CLI in `crates/atproto-pds/src/bin`; no operator runbook anywhere.
`tests/migration_e2e.rs:5-6` documents a flow using service auth and `plcOp` while `:135-144` sends
neither, `:148-158` works around the always-active defect, and `:176-185` asserts
`listMissingBlobs == []` as correct. tranquil ships an 11-step wizard plus `tests/plc_migration.rs`
and `tests/whole_story.rs`; cirrus ships `pds migrate`/`identity`/`activate`; alteran and dnproto ship
scripts. *Consequence:* the suite gives false confidence that migration works, which is plausibly how
this area reached RC in its current state.

### 1.11 Cross-cutting operations

Owning chapter: [32-ops.md](./capability-areas/32-ops.md).

**F-OPS-01 · MISSING · blocker (process — the headline finding) — nothing runs the test suite, and the
conformance-vector submodule is empty.** `.github/workflows/` contains exactly one file,
`release-binaries.yml`; there is no workflow running `cargo test`, `cargo clippy` or `cargo fmt` on
push or pull request, against the claim at `crates/atproto-pds/README.md:29-32` that there is.
`.gitmodules` declares `crates/atproto-dasl/tests/dasl-testing` → `hyphacoop/dasl-testing`, and the
directory is empty, so the harness panics on the missing fixture
(`crates/atproto-dasl/tests/dasl_compliance_test.rs:139`). `crates/atproto-repo` has no `tests/`
directory at all; its MST coverage is round-trip only (`mst/serialize.rs:39-121`,
`mst/tree.rs:504-651`) — it verifies that the code agrees with itself, never that it agrees with the
protocol. Worked references: arroba runs the vendored upstream `atproto-interop-tests` commit-proof
fixtures in CI (`/tmp/gap-scratch/arroba/arroba/tests/test_testdata.py:26-96`); indigo ships
`mst_interop_test.go`; the reference ships `interop-test-files/` at the root of
`/tmp/gap-scratch/atproto`; cocoon, rsky, metalbear, cirrus, alteran and zds all run CI.
*Consequence:* every one of F-REPO-01, F-REPO-02, F-REPO-03, F-REPO-04 and F-FIRE-01 is precisely the
class of defect a known-answer vector catches on its first run, and round-trip tests cannot detect any
of them because encode-then-decode succeeds perfectly against a wrong encoding. **This reframes the
whole report constructively: the repo layer's failures are not a careless codebase — the code is well
documented, uses structured errors and is thoughtfully architected — they are the predictable result
of a self-consistent test suite with no external oracle and no CI to run it.**

**F-OPS-02 · PARTIAL · blocker — rate limiting reaches 4 of 104 routes, every bucket key is
attacker-controlled, and there is no per-IP limiting anywhere.** State the machinery fairly first: a
`SlidingWindowLimiter` with Memory, SQL and Valkey backends (`security.rs:314-520`,
`valkey_backend.rs:138-190`), held on `HttpState` (`http/state.rs:56`, default 300 req / 60 s at
`:139,182`), constructed at `bin/pds.rs:533,591` and GC'd at `:727`. It is invoked at four call sites:
`createAccount:{handle}` (`auth_handlers.rs:87`), `createSession:{identifier}` (`:300`),
`requestPasswordReset:{email}` (`:1404`, and that one is fail-open — `let _ = try_acquire`) and
`oauth-token:{client_id}` (`oauth/token.rs:106`). There is no middleware layer: the router applies
only the optional metrics pair (`router.rs:446-447`). `bin/pds.rs:745` uses plain `axum::serve`, and a
grep for `ConnectInfo|X-Forwarded-For|peer_addr` yields only the listen-address parse. Worked
references: metalbear installs a global limiter into its XRPC server (`src/server.c:6958-6959`),
operator-tunable via `METALBEAR_RATE_LIMIT` (`src/main.c:243-244`); alteran limits per IP
(`src/lib/ratelimit.ts:16-19`, `createSession.ts:16-17`); pegasus keys on `identifier ^ "-" ^ request_ip`.
*Consequence, in two halves:* (a) every key is derived from caller-supplied input, so a password
sprayer varies `identifier` and a signup flood varies `handle` to get a fresh bucket per attempt — the
limiter does not bound the attack it most resembles a defence against; and (b) all repo writes, all
sync reads, `subscribeRepos`, the whole spaces namespace, `/oauth/par`, `/oauth/authorize` and every
admin route are unbounded. The gap is coverage and key choice, not capability.

**F-OPS-03 · PARTIAL · blocker (security) — the shipped container cannot send email, and reset tokens
are written to the log at INFO.** `EmailService::Disabled::send` logs the full rendered `body` at INFO
(`email.rs:75-83`), and that body contains the password-reset and account-deletion confirmation
tokens. The stub is meant for development — the log line says "dev-only" and the constructor warns
messages "will be logged only" (`:59-61`) — but the *shipped production image selects it*: `smtp` is a
non-default feature (`Cargo.toml:125-128`) and the Dockerfile builds `--features clap,hickory-dns`
(`Dockerfile:63,83`), so in the published container `EmailService` is always `Disabled`. Reference,
cocoon, metalbear and zds all ship working delivery. *Consequence:* two things at once. Anyone who can
read logs — operators, a log aggregator, a sidecar, a crash reporter, a mounted volume — can complete
a password reset for **any** account and take it over; and the user never receives the mail, so
`requestPasswordReset` and `requestAccountDelete` silently fail while returning success, converting
two capabilities scored `Y` in coverage area A into unusable flows in the only shipped build.
Remediation is small: add `smtp` to the image and never log the rendered body.

**F-OPS-04 · MISSING · blocker — no backup or restore path of any kind.** Grep over
`crates/atproto-pds/src/`, the README and `deploy/` returns three unrelated hits; no admin subcommand,
no snapshot step in `deploy/Makefile`. cocoon has one (`server.go:673-691`), pegasus has one
(`s3/backup.ml:25-60`), and **dnproto — single-user tier — ships `BackupAccount.cs`**.
*Consequence:* a host holding other people's repositories has no tooled or documented way to take or
restore a consistent copy.

**F-OPS-05 · PARTIAL · blocker — the shipped `deploy/` cluster cannot resolve its own `did:web`.**
`deploy/well-known/*` is never mounted (`docker-compose.yml:20-22,45-47,70-72`), cloudflared routes
hostnames straight to the container, and no `/.well-known/did.json` route exists in `router.rs` (see
F-IDENT-04). *Consequence:* the project's own reference deployment cannot federate, and no test in
the repository would catch it.

**F-OPS-06 · DIVERGENT · blocker — the Postgres backend panics on the record-write path and is never
constructed by the shipped binary; S3 is likewise unreachable.**
`AccountPool::as_sqlite` (`account/pool.rs:94-101`) is
`Self::Postgres(_) => panic!("AccountPool::as_sqlite called on a Postgres pool")`, and the record
writer reaches the accounts pool with a SQLite-dialect `?`-placeholder query at
`repo/writer.rs:360-364` where Postgres requires `$1`. Postgres and S3 are schema'd
(`migrations/postgres/20260507000001_init.sql`), feature-gated, tested (`tests/feature_postgres.rs`,
`feature_postgres_live.rs`, `feature_s3.rs`) and documented — and never constructed by
`crates/atproto-pds/src/bin/pds.rs`. This is a distinct and more serious category than the
"built but not wired" pattern: unwired-but-correct code is inert, whereas this is a **documented
supported deployment mode that would crash the process**. *Consequence:* the advertised horizontal-scale
story is unreachable through the shipped binary, and reachable would be worse. A stable release must
either wire and fix it or explicitly document Postgres and S3 as unsupported.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-OPS-07 | The limiter is untunable and its default backend is volatile | PARTIAL | stable-gap | window hardcoded 300/60 s (`bin/pds.rs:551-554,1102-1105,1113-1116`, `http/state.rs:139,182`), no bypass list; `PDS_DURABILITY_PROFILE` defaults to `memory` (`bin/pds.rs:140`) against the crate's own caveat (`security.rs:11-14`) with no check in `config.rs:42-75`; metalbear exposes both knobs (`config.example.toml:64-65`) and the reference has bypass keys and IPs (`rate-limits.ts:21-30`); a relay cannot be exempted and buckets clear on restart |
| F-OPS-08 | Metrics are two counters, undocumented-as-shipped, and unauthenticated | PARTIAL | stable-gap | `metrics.rs:80-89` against the `:6-9` doc promising histograms; no auth on `/metrics` while `deploy/cloudflared/config.yml.tmpl:10-23` forwards every path; mitigated today only by the feature being absent from the image; tranquil (`metrics.rs:27-190`) and cocoon do better, and the reference has none at all |
| F-OPS-09 | `--config` is documented with a precedence chain and never read | MISSING | stable-gap | `bin/pds.rs:42` documents it, `:44` declares the field, nothing reads it, no TOML loader exists; metalbear has `src/config_file.c`, tranquil an `example.toml` |
| F-OPS-10 | The production gate misses bind address, handle domains and durability profile | PARTIAL | stable-gap | `config.rs:42-75` checks only JWT secret, admin password and service DID; `bin/pds.rs:239-242` notes an empty `PDS_SERVICE_HANDLE_DOMAINS` accepts any handle |
| F-OPS-11 | The shipped image omits seven optional features, making their env knobs inert | DIVERGENT | stable-gap | `Dockerfile:63,83`; the `valkey` branch (`bin/pds.rs:537-559`) is `#[cfg]`-ed out so `PDS_VALKEY_URL` fails silently; `RUST_VERSION=1.85` (`Dockerfile:30`) also contradicts `rust-version = "1.90"` (`Cargo.toml:30`) |
| F-OPS-12 | `wait_drain()` is never called; background workers are abandoned on shutdown | PARTIAL | stable-gap | defined at `shutdown.rs:82-85` with a 30 s `DEFAULT_SHUTDOWN_DEADLINE` at `:19`; `bin/pds.rs:762-764` drops the token and tracker instead, contradicting `README.md:129-131` |
| F-OPS-13 | Unified GC is SQLite-only | PARTIAL | stable-gap | `gc.rs:92-96,136` hardcode `SqlitePool`; `prune_space_oplogs` `debug!`-skips non-SQLite actors (`:236-241`); so Postgres gets no GC and fjall never prunes space oplogs, and `notify_attempt`, `email_token`, `oauth_par`, `jti_replay` and `rate_limit_window` grow without bound |
| F-OPS-14 | No published container image and no self-host installer | PARTIAL | stable-gap | `release-binaries.yml` builds four CLI binaries, not `pds`; `deploy/` is a five-service test cluster; the reference ships `installer.sh` and six independents publish images |
| F-OPS-15 | No operator runbook, though three source sites defer to one | MISSING | stable-gap | `valkey_backend.rs:215-218`, `tests/feature_s3.rs:6-7`, `metrics.rs:11-13`; `find docs -type f` is empty; zds and alteran both sit below atproto-crates in tier and above it here |
| F-OPS-16 | The notifier sends no user-agent and its backoff is documented three ways | PARTIAL | cosmetic | `reqwest::Client::new()` (`notifier.rs:263`) against the UA-carrying client at `bin/pds.rs:625`; the `:222` formula yields ≈510 s versus "≈ 4 min" (`bin/pds.rs:218`) and "~1.5h" (`notifier.rs:17,28`) |
| F-OPS-17 | 429s carry no `RateLimit-*` headers and use a non-canonical error name | DIVERGENT | cosmetic | `auth_handlers.rs:69-77` emits `"RateLimited"` where canonical is `RateLimitExceeded`; `http/errors.rs:34-45` sets no headers; the reference sets them at `rate-limiter-http.ts:78-81` |

### 1.12 Permissioned data / spaces (proposal 0016)

Owning chapter: [40-permissioned-overview.md](./permissioned/40-permissioned-overview.md), with
comparison detail in [42-happyview.md](./permissioned/42-happyview.md),
[41-contrail.md](./permissioned/41-contrail.md) and [43-stratos.md](./permissioned/43-stratos.md).

**Fairness note that governs this whole subsection.** 0016 is an open, self-declared work-in-progress
draft; its README says "Details, terminology, and behaviors are all likely to change". atproto-crates'
own code anticipates the churn (`crates/atproto-space/src/types.rs:5`). These are drift against a
draft that moved, not carelessness. They are still hard interop breaks today, and — critically — the
draft lexicons **already landed** on the `bluesky-social/atproto` `permissioned-data` branch at HEAD
`3f6c96d` (2026-07-02), fetched to `/tmp/gap-scratch/lex-0016/` (19 files under `space/`, 8 under
`simplespace/`), so every namespace and field-name divergence below is checkable *today* against a
concrete oracle rather than against prose. HappyView is the only same-direction interop yardstick;
contrail and stratos are alternative designs and are never used here for wire conformance.

**F-SPACE-19 · DIVERGENT · blocker — the commit `ctx` omits the author DID.** The spec construction is
`"atproto-space-v1" || len+space || len+author || len+rev || len+ikm`
(`/tmp/gap-scratch/0016-README.md:306-310`), corroborated by
`/tmp/gap-scratch/lex-0016/space/defs.json`, whose `signedCommit.sig` is described as a "Signature over
ctx (space, author DID, rev, ikm)". atproto-crates has `SpaceContext { space, rev }`
(`crates/atproto-space/src/commit.rs:58-64`) and `encode_ctx` emits only `[space, rev, ikm]`
(`:71-81`, loop at `:76`), with both construction sites matching (`space/writer.rs:310-313`,
`http/space_handlers.rs:1226-1229`). HappyView's `encodeCtx` iterates `[space, author, rev, ikm]` with
the ordering asserted by test (`/tmp/gap-scratch/happyview/src/spaces/commit.rs:18-44,158-184`), and so
does the reference. *Consequence:* `sig` and `mac` are computed over different bytes than any
conformant peer, so every commit atproto-crates emits fails verification in both directions — plus a
weaker security property, because the signature no longer binds the author, losing the draft's
deliberate domain separation within a space. **Cheapest high-value fix on the spaces track: one field,
two call sites.**

**F-SPACE-04 · MISSING · blocker — the `ver` field is absent from the signed commit.**
`lex-0016/space/defs.json` lists `ver` first in `signedCommit.required` (`["ver","hash","mac","ikm","sig","rev"]`),
currently `1`. The `Commit` struct (`crates/atproto-space/src/commit.rs:87-102`) has only
hash/mac/ikm/sig/rev, and `SignedCommitDto` (`space_handlers.rs:1146-1158`) likewise; the doc comment
at `commit.rs:85` asserting the wire field order "matches the lexicon required set
`[hash, mac, ikm, sig, rev]`" is now stale. HappyView carries `ver` and rejects `ver != 1`
(`commit.rs:9-16,88-93`); the reference's `createCommit` returns `{ver: COMMIT_VERSION, …}`.
*Consequence:* every emitted commit fails schema validation on a required field before any crypto
runs, and there is no version discriminator with which to negotiate a future ctx construction.

**F-SPACE-18 · DIVERGENT · blocker — the space URI uses `ats://` where every draft lexicon types the
field as `at-uri`.** `pub const ATS_SCHEME: &str = "ats://"` (`crates/atproto-space/src/types.rs:13`),
hard-required by `SpaceUri::parse` (`:122`), yielding `ats://<authority>/<type>/<skey>` (`:89,114`) and
a six-segment record URI (`:187`). The draft is `at://{spaceDid}/space/{spaceType}/{skey}/…`
(`0016-README.md:307`), the reference defines it in `packages/syntax/src/space-uri.ts`, and the space
parameter is typed `"format": "at-uri"` in `getLatestCommit.json`, `getRepo.json`, `listRepoOps.json`
and the rest. HappyView migrated and now rewrites `ats://` as legacy
(`/tmp/gap-scratch/happyview/src/spaces/mod.rs:38-52,67-71`) — a directly portable worked reference —
while contrail independently chose `ats://` too (`packages/contrail-base/src/spaces/uri.ts:20-22`).
*Consequence:* two failures at once. A parameter typed `at-uri` rejects an `ats://` value under lexicon
validation, and because `space` is length-prefixed into `ctx`, the differing string changes the signed
bytes even if F-SPACE-19 and F-SPACE-04 were fixed. **These three must land as one change.**

**F-SPACE-07 · MISSING · blocker (security, exploitable — but inherited from the reference draft) —
there is no read-time membership enforcement, so any authenticated local account can read any other
local account's permissioned records.** The chain, every link opened: (1) `resolve_record_auth`
(`http/space_handlers.rs:1080-1120`) calls `require_authn` for the subject and then sets
`let target_repo = repo.map(|r| r.to_string()).unwrap_or(sub);` at `:1113-1114` — the caller-supplied
`repo` query parameter is adopted verbatim with no comparison against the subject and no membership
lookup, while auth is recorded as `SpaceReadAuth::OwnPds { account_did: <the CALLER> }` (`:1116-1118`);
(2) `assert_space_scope` (`:1859-1868`) opens with `if !subject.is_oauth() { return Ok(()); }`, so
every app-password session bypasses space-scope enforcement entirely; (3) `SpaceReader::verify_auth`
(`space/reader.rs:214-216`) is a documented no-op for the `OwnPds` variant; (4) `get_record`
(`:91-114`) then opens the target store and returns the record with no membership, authority or
caller-vs-target check anywhere. Exploit: authenticate as any local account with an ordinary app
password, then
`GET /xrpc/com.atproto.space.getRecord?space=<uri>&collection=<c>&rkey=<k>&repo=<victim DID>`. The same
override reaches `listRecords`. **Scoped honestly:** the Phase 4 audit opened the reference on the
`permissioned-data` branch and found all three links shared —
`packages/pds/src/api/com/atproto/space/getRecord.ts` destructures `repo` straight from `params` into
`ctx.actorStore.read(repo, …)`, and `.../space/util.ts:32-37` skips the scope check for every non-OAuth
credential. Per the fairness rule, this is **not** an atproto-crates authoring error; it is a real and
serious hole in 0016 as currently implemented by everyone following it. Worked references exist and are
cheap: HappyView calls `require_membership` on every read (`src/spaces/service.rs:75-118`) with a
`read_self` tier (`scope.rs:24-63`), and contrail runs `authorizeRead` + `checkAccess` on all read
routes (`packages/contrail-record-host/src/routes.ts:125-195`). *Consequence:* the confidentiality
property the entire permissioned-data feature exists to provide does not hold against any other account
on the same PDS. Fix locally **and** raise upstream. Note also that the one test in this area,
`get_record_oauth_with_repo_override` (`tests/http_phase7_spaces.rs:803-851`), does *not* lock in
arbitrary cross-account reads — its reader is the space authority and its target is a member the
authority added — but it does pin the non-OAuth bypass path, and the absence of a regression test for a
non-member reading another account's records is itself part of the gap.

**F-SPACE-30 · PARTIAL · blocker (availability) — `Box::leak` on every authenticated space record
read.** `http/space_handlers.rs:1113` calls `Box::leak(sub.clone().into_boxed_str())` on the hottest
authenticated path in the spaces surface, permanently leaking the caller's DID string on every request.
The permissioned chapter files this under "operational hazards" as outside 0016 conformance scope; it
is reclassified here as a real defect, because any authenticated caller can drive unbounded process
memory growth with ordinary reads. Same line as F-SPACE-07, so both fixes touch the same code.

| ID | Capability | Class | Severity | Evidence · worked reference · consequence |
| --- | --- | --- | --- | --- |
| F-SPACE-01 | `com.atproto.space.getRepo` (CAR full-state recovery) | MISSING | blocker | no route; only `com.atproto.sync.getRepo` at `http/router.rs:83`; no CAR builder or DRISL index under `crates/atproto-space/src` or `crates/atproto-pds/src/space`. HappyView routes it (`routes.rs:236`) with a two-root header, DAG-CBOR index and sorted record blocks (`src/spaces/car.rs:60-151`); `lex-0016/space/getRepo.json`. A syncer past its oplog retention has **no recovery path**, and `listRecords` cannot substitute because it returns no values (F-SPACE-03). Largest functional gap on the permissioned surface |
| F-SPACE-02 | `com.atproto.space.getLatestCommit` | MISSING | blocker | absent; only `com.atproto.sync.getLatestCommit` (`router.rs:76`, `handlers.rs:148`, `repo/reader.rs:382`). HappyView serves the conformant name and aliases `getRepoState` to the same handler (`routes.rs:229,233`) — the directly portable fix. With F-SPACE-01 also absent there is **no conformant path to repo state at all** |
| F-SPACE-03 | Record values inlined in `listRecords`/`listRepoOps`; `excludeValues`, `reverse` | MISSING | blocker | `SpaceRecordItem` is `{collection, rkey, cid}` (`space_handlers.rs:990-998`), `RecordOpEntry` has no value field (`:1283-1295`), no `excludeValues` in `RepoOplogQuery` (`:1264-1276`), and the in-code comment at `:988` contradicts the lexicon it names. HappyView inlines via `LEFT JOIN` (`oplog.rs:101-174`) with an `excludeValues` opt-out (`routes.rs:1106-1128`); both `listRepoOps.json#opEntry` and `listRecords.json#record` inline by default. Sync degrades to one `getRecord` round trip per record with no bulk path — initial backfill is unusable and the pull design becomes quadratic |
| F-SPACE-05 | `hash` on `notifyWrite` and `listRepos#repo` | MISSING | stable-gap | `NotifyWritePayload {space, repo, rev}` (`space/notify.rs:49-56`), `RepoRef {did, rev}` (`space_handlers.rs:2299-2305`); `notifyWrite.json` requires `hash` explicitly so "the space host can maintain each repo's hash for listRepos". HappyView omits it too (`db.rs:1022-1024`) — **no worked reference exists**. The hash-propagation loop from repo host to space host is absent, so `listRepos` cannot tell a syncer which repos changed |
| F-SPACE-06 | Space-credential revocation | MISSING | blocker for spaces GA | grep for `revoke` across `crates/atproto-space/src` and `crates/atproto-pds/src/space` returns zero; TTL is 7200 s (`credential.rs:55`). HappyView has the portable design: a `revoked_at` migration (`migrations/sqlite/20260707000000_…sql:1-4`), `sha256(token)` (`auth.rs:56-57`), `revoke_space_credentials_for_member` (`db.rs:330-348`) called before the row delete (`service.rs:395-397`) and checked on every request (`routes.rs:386-388`). A removed member keeps full read access for up to two hours; space deletion likewise revokes nothing. Not a draft requirement, and still a reviewer-visible defect |
| F-SPACE-08 | Cross-PDS space-credential verification | MISSING | blocker for the multi-PDS topology | `SpaceReader::authority_public_key` resolves only from the local account table (`space/reader.rs:236-254`), and `remote_space_credential_key`/`remote_space_host_endpoint` (`http/space_auth.rs:301,329`) have **no caller in the workspace** — classic built-but-not-wired. HappyView resolves the issuer's DID document for an `#atproto_space` method and converts `publicKeyMultibase` to JWK (`credential.rs:277-306,312-345`). A member's PDS cannot verify a credential minted by a remote authority, confining spaces to single-instance deployments |
| F-SPACE-09 | `com.atproto.simplespace.checkUserAccess` server side | MISSING | blocker for the managing-app policy | the client half is conformant (`space/mint_authz.rs:400-453`); there is no server route, and `walking-club-appview/src/server.rs:33-67` registers only `notifyWrite` (`:59`); `managingApp` is an unvalidated string (`space/config.rs:185`) while mint-time resolution needs a `did:…#fragment` (`space_handlers.rs:1609-1613`). HappyView is outbound-only and breaks three ways (POST vs GET, `did` vs `user`, `granted` vs `authorized`) with no service auth (`src/spaces/auth.rs:137-159`). One of the three documented mint policies has no working path, so a space configured `managing-app` silently denies every mint |
| F-SPACE-10 | Lexicon validation of permissioned record values | MISSING | stable-gap | the `validate` param is `#[allow(dead_code)]` and never read (`space_handlers.rs:722,772`); `validationStatus` is hardcoded absent (`:889`). No worked reference among the targets — contrail constrains collections instead (`adapter.ts:97-110`), HappyView via `allowedCollections` (`service.rs:57-73`). Structurally invalid records land in permissioned repos and every consumer rediscovers the breakage at read time |
| F-SPACE-11 | `getSpace` serves a fabricated config from the caller's own store | PARTIAL | blocker for client UX | viewer is the caller's own DID (`space_handlers.rs:423-428`), `SpaceService::get_space` opens the caller's store (`space/service.rs:133`), and member stores get a space row with hardcoded defaults via `INSERT OR IGNORE` (`actor_store/sql/space_repo_storage.rs:40`) — while the handler's own doc comment at `:423-424` says it should read the authority's store. HappyView reads the authority row (`src/spaces/routes.rs:461-465`). A client cannot discover a space's real app-access policy before minting and is told "open" when the space is `allowList`; a member who never wrote gets `SpaceNotFound` |
| F-SPACE-12 | `space.getBlob`'s `space` parameter is decorative | PARTIAL | blocker (with F-BLOB-03) | the handler gates on `space` and then fetches by `(repo, cid)` only — `crate::blob::get_blob(&store, &q.cid)` (`space_handlers.rs:2243`). contrail keys `spaces_blobs` on the space URI and rejects records referencing blobs not uploaded to that space (`contrail-record-host/src/routes.ts:224-239`). Widens the cross-account read from records to blobs |
| F-SPACE-13 | `registerNotify` cannot target a remote authority | PARTIAL | stable-gap | opens `SqlActorStore::open(manager.data_dir(), &space.space_did)` (`space_handlers.rs:2454`) and requires a local space row plus a local authority key (`:2480`); the draft permits a repo host to serve this for a remote authority's space; with F-SPACE-08, notify fan-out works only when authority and members share a PDS |
| F-SPACE-14 | Takedown applies only on the read path | PARTIAL | stable-gap | the reader consults `space_record_takedown` (`space/reader.rs:104,148-167`); `SpaceSync` never does (`space/sync.rs:56-68`); no writer path and no op-listing call site (`space_handlers.rs:1322`). stratos states the rule as an invariant (`docs/operator/security.md:24`). A taken-down record's create op, CID, collection and rkey stay visible in the oplog and folded into the LtHash — and since `listRecords` returns no values anyway (F-SPACE-03), takedown currently hides nothing from a syncer |
| F-SPACE-15 | Space deletion is not a containment boundary | PARTIAL | stable-gap | `SpaceSync::list_repo_ops` does not call `ensure_space_live` (`space/sync.rs:56-68`) unlike `get_repo_state` (`:46`); `ensure_space_live` returns `Ok(())` when the authority DB is not local (`space/config.rs:320-323`); `fire_notify_space_deleted` has no retry (`space_handlers.rs:314-399`). A tombstoned space's oplog stays readable, a remote authority's deletion is unenforced until a best-effort notification lands, and outstanding credentials survive (F-SPACE-06) |
| F-SPACE-16 | Unclamped page limits | PARTIAL | stable-gap | `listRecords` `unwrap_or(50)` with no clamp (`space_handlers.rs:1039`, lexicon max 100); `listRepoOps` `unwrap_or(100)` with no clamp (`:1330`, lexicon max 1000); a single request can demand an unbounded page |
| F-SPACE-17 | No clock-skew allowance, no TTL upper bound | PARTIAL | stable-gap | `check_exp` (`crates/atproto-space/src/credential.rs:255-261`) has no skew tolerance and no iat-in-future check; `space_credential_ttl_secs` is unvalidated (`http/state.rs:103,150`); a client two seconds fast produces a briefly unusable 60 s delegation token, and an operator can configure an arbitrarily long-lived credential with no revocation to compensate |
| F-SPACE-20 | `getRepoState` instead of `getLatestCommit` | DIVERGENT | stable-gap | routed at `http/router.rs:327`; params and the `{commit?}` envelope match the draft (`space_handlers.rs:1195-1200`) — only the name and `ver` differ. The NSID is absent from `lex-0016`; HappyView routes both names to one handler (`routes.rs:229,233`). A conformant client 404s on the method it knows; harmless only if the draft adopts the alias |
| F-SPACE-21 | `listRepoOps` `since` cursor encoding | DIVERGENT | stable-gap | requires a composite `"<rev>__<idx>"` token and 400s otherwise (`space_handlers.rs:1273,1331-1340,1354`), motivated by the regression test `batch_larger_than_limit_pages_fully` (`crates/atproto-space/src/space_repo.rs:634-680`); the lexicon describes `since` as "operations after this revision". **atproto-crates is right on the merits and wrong on the wire** — a bare-rev cursor drops the tail of an atomic batch larger than `limit`, a bug latent in the draft. Fix: accept a bare rev as `(rev, 0)` while still emitting the composite token, and file upstream |
| F-SPACE-22 | Config key `mintPolicy` instead of `policy` | DIVERGENT | stable-gap | `space/config.rs:206,260` read it, `:232` emits it, `space_handlers.rs:232` declares it; `lex-0016/simplespace/defs.json` and `updateSpace.json` require `policy`. HappyView has the identical bug and stamps a `$type` on a non-validating object (`src/spaces/simplespace.rs:325-330`) — **no worked reference**. A conformant client sending `policy` has its value silently ignored and the space left on its previous policy: a silent-failure config bug, not a 400. Needs an upstream issue so both implementations fix it together |
| F-SPACE-23 | `applyWrites` and `listSpaces` parameter and result shapes | DIVERGENT | blocker for conformant clients | `applyWrites` input has no `repo` and no `validate` (`space_handlers.rs:618-625`) and outputs `{rev, setHash, uris, cids}`, where `lex-0016/space/applyWrites.json` requires `repo` and `validate` and returns `{results: [union]}`; `listSpaces` takes `filter`/`cursor`/`limit` (`router.rs:291`) with no cursor in the output and extra fields, where the lexicon defines `type`/`did`/`limit`/`cursor`. Writes always target the authenticated subject; filtering by space type or DID is not expressible and pagination is not resumable |
| F-SPACE-24 | `getRecord` response URI drops the author segment; `repo` optional | DIVERGENT | stable-gap | `format!("{}/{}/{}", uri, collection, rkey)` (`space_handlers.rs:962`) yields five segments while `RecordUri::parse` requires six (`crates/atproto-space/src/types.rs:231`) and the writer itself emits six (`space/writer.rs:275-278`); `repo` is optional at `:905`. The reference builds `${space}/${repo}/${collection}/${rkey}` and marks `repo` required. The returned URI does not round-trip through atproto-crates' own parser |
| F-SPACE-25 | `client_id` claim on the space credential | DIVERGENT | stable-gap (extension) | `SpaceCredential` adds a snake_case `client_id` (`crates/atproto-space/src/credential.rs:96-100`) and `register_notify` keys subscriptions on it (`space_handlers.rs:2499-2502`); the reference `SpaceCredentialPayload` is `{iss, sub, iat, exp, jti}` (`packages/space/src/credential.ts:21-27`) and HappyView's has no such claim. **Settled by the audit:** `0016-README.md:219-223,233-239` does *not* mandate it, so this stays a useful extension carrying attested app identity past the mint. The open item is the inverse — `register_notify` degrades against reference-minted credentials, falling back to keying every subscription on the space authority |
| F-SPACE-26 | `SpaceNotFound` maps to 400 generally and 404 in three handlers | DIVERGENT | cosmetic | `PdsError::SpaceNotFound` → 400 (`http/errors.rs:53-57`) with inline 404s at `space_handlers.rs:1579-1585,2357-2363,2468-2474`, and a `SpaceError` catch-all flattening everything to 400 (`errors.rs:105-108`); the draft specifies error names only. Status-driven clients see inconsistent results for the same condition, and the catch-all surfaces the internal `error-atproto-space-*` taxonomy to callers |

### 1.13 OUT-OF-SCOPE — deliberate deferrals, and why each is defensible

Eight items are classified OUT-OF-SCOPE. Each needs a justification for why deferring past `-rc` is
defensible, not merely convenient.

**Phone verification and email second-factor auth** (`verificationPhone`,
`describeServer.phoneVerificationRequired`, `createSession.authFactorToken`,
`updateEmail.emailAuthFactor`). *Defensible because* the reference is the **only** implementation in
the entire twelve-column field that has either. Shipping without a capability no independent
implementation has is a documented limitation, not a gap. Action: list them in the README's known
limitations rather than the roadmap.

**`com.atproto.sync.getHostStatus`, `listHosts` and `notifyOfUpdate`.** *Defensible because* the
lexicons themselves say "Implemented by relays"; the reference PDS serves none of the three, and no
comparison implementation serves `getHostStatus` or `listHosts`. This is the correct RC→stable
decision and requires no work at all.

**`com.atproto.admin.updateAccountSigningKey`.** *Defensible because* no implementation in the
comparison routes it, including the reference
(`packages/pds/src/api/com/atproto/admin/index.ts:17-31`). Adding it would be leading the field on a
verb nobody uses.

**OpenTelemetry metrics/logs pipelines** beyond what exists. *Defensible because* no peer offers a
baseline to conform to — the reference has no metrics at all — and atproto-crates is already ahead
here (`telemetry.rs:32-67`, §4). The genuine gap is metrics *content* and auth (F-OPS-08), which is
tracked as a stable-gap rather than deferred.

**Notifier transport pluggability.** *Defensible because* the 0016 notification design is still
settling; building an abstraction over a contract that may change is premature. The concrete defects
in the current notifier (F-OPS-16) are tracked.

**Member LtHash and the member oplog** (`crates/atproto-space/src/space_members.rs:94-158`, tables at
`migrations/actor/20260501000001_init.sql:86,131`). *Defensible because* the draft explicitly calls
the member list "host-internal state … not a synced protocol structure"
(`lex-0016/simplespace/addMember.json`), and atproto-crates correctly keeps it off the wire
(rationale in `space/sync.rs:17-19`). This is a *correct* walling-off, not a gap. One cost worth
noting: `MemberAlreadyExists` (`space_members.rs:112-116`) forces the `rows_affected() > 0`
idempotency guard at `space/service.rs:94`.

**`com.atproto.admin.takedownSpaceRecord`** (`router.rs:403`, rows at
`migrations/actor/20260506000002_space_record_takedown.sql:17`). *Defensible because* the draft has no
moderation surface for permissioned records at all, so this is a legitimate operator-necessity
extension rather than a divergence. Its incompleteness is tracked separately as F-SPACE-14, which is
the right split.

**contrail and stratos design differences** — appview-side storage, invite tokens,
enrollment-as-consent, membership manifests, group-controlled DIDs, boundary strings, service-held
signing keys, the stub/hydration split. *Defensible because* neither project contains a single
`com.atproto.space.*` NSID (exhaustive greps in both chapters), so they are alternative answers rather
than missing capabilities. Two are worth importing as *ideas* rather than conformance items: stratos's
read-leakage invariant stated explicitly (`docs/operator/security.md:24`) and contrail's enrollment
host-consent gate (`contrail-record-host/src/schema.ts:28-33`).

---

## 2. Security and spec-compliance blockers

These are the true RC→stable blockers. Ranked by exploitability × blast radius, with each labelled
either **exploitable today** or **latent conformance gap** — the distinction matters for sequencing,
because an exploitable defect on a deployed instance is an incident and a conformance gap is a bug.

### Tier 1 — exploitable today, remote or near-remote, account-takeover class

**1. Authorization-code exfiltration chained to unauthenticated code redemption
(F-OAUTH-03 + F-OAUTH-02).** *Exploitable today.* An attacker constructs an authorization URL using a
**legitimate, trusted `client_id`** with an attacker-controlled `redirect_uri`, which PAR stores
verbatim (`oauth/par.rs:202-223`) and the consent page happily navigates to (`oauth/consent.rs:325-331`).
The consent screen the victim sees names the genuine client, so nothing looks wrong. The code lands at
the attacker's endpoint, and because `/oauth/token` requires no client authentication and no DPoP proof
(`oauth/token.rs:100-124`) and lets the caller pick its own `cnf.jkt` (`:176`), the attacker redeems it
and binds the resulting session to their own key. Full account takeover with a phish and no malware.
Highest priority in the report. Worked reference: `client.ts:339-342` (redirect validation) and
`oauth-provider.ts:840-848` (proof cross-check).

**2. Password-reset and account-delete tokens written to the application log at INFO in the shipped
container (F-OPS-03).** *Exploitable today by anyone with log access.* `email.rs:75-83` logs the
rendered body; the published image always selects the `Disabled` service because `smtp` is not a
default feature and the Dockerfile omits it. Logs are routinely lower-trust than the credential store
and are frequently shipped off-host to aggregators. Every account on the instance is takeable by an
operator, a sidecar, a crash reporter, or anyone who can read a mounted volume.

**3. Unauthenticated DID squatting via `createAccount` (F-ACCT-02), with `reserveSigningKey` as its
precursor (F-ACCT-15).** *Exploitable today, anonymously.* No auth on the handler
(`auth_handlers.rs:81-84`), the caller's `did` used verbatim (`:184-185`), account created `Active`.
The attacker obtains a session bound to the victim's DID and permanently denies them an inbound
migration. Blast radius is bounded by relay signature verification rejecting the forged commits — the
lockout is not bounded.

**4. Permissioned-space blobs are world-readable through the public `com.atproto.sync.getBlob`
(F-BLOB-03).** *Exploitable today with no credential at all.* Reach exceeds F-SPACE-07: that requires
an account on the same PDS; this requires only a CID. CIDs are high-entropy so this is not enumerable,
but they are not secrets — they appear in space oplog entries, in `listRepoOps` output, in any AppView
indexing the space, in logs, and to every member including one since removed. A removed member retains
permanent access to every blob whose CID they ever saw. **This one is not shared with the reference
draft; zds solves it with a public-record join (`store.zig:2538-2563`).**

**5. Cross-tenant permissioned record read (F-SPACE-07).** *Exploitable today with any app password on
the same instance.* Scored as inherited from the reference draft, which shares all three links of the
chain — but the consequence is the same for a deployed instance, and both HappyView and contrail show
a per-read membership check is affordable. Fix locally, raise upstream.

**6. Stored XSS on the authorization-server origin via `getBlob` (F-BLOB-05).** *Exploitable today.*
`blob_handlers.rs:65-70` sets only `Content-Type`, echoing an unvalidated client-declared MIME
(`write_handlers.rs:522-527`, F-BLOB-08). Upload `text/html`, get a victim to open the blob URL, and
script executes on the origin that also serves the OAuth consent screen and session cookies —
which chains directly back into blocker 1. atproto-crates already sets all three headers on
`space.getBlob` (`space_handlers.rs:2262-2274`), so this is copying five lines.

**7. Moderation actions do not take effect (F-MOD-01 + F-MOD-02 + F-ACCT-04).** *Exploitable today.*
A taken-down account keeps writing records and publishing firehose commits for up to 90 days
(`account/session.rs:26`); its complete repo CAR, raw blocks and all blobs stay anonymously
downloadable through the ungated sync surface; and it can restore itself with one unprivileged call to
`activateAccount`. For a host holding third-party content, "we took it down" is not true in any of the
three senses an operator would mean it.

**8. Any app-password session can have an arbitrary PLC operation signed (F-IDENT-03).** *Exploitable
today.* `auth_handlers.rs:1592-1597,1650,1657` blind-sign the submitted operation behind
`require_access_jwt` only (`:1619`), with no `privileged()` check and no emailed confirmation token.
A stolen two-hour access token becomes permanent control of the account's identity, because the
attacker can rotate the keys. Compounded by F-IDENT-05, which forwards to the PLC directory without
validating anything.

**9. Unrestricted cross-service credential minting (F-SVC-04 + F-SVC-05).** *Exploitable today.* Any
authenticated account calls `getServiceAuth?aud=<target>` with no `lxm`
(`service_auth_handlers.rs:45,68-69`), receives a 600-second token (F-SVC-06), and — with no
`PROTECTED_METHODS`/`PRIVILEGED_METHODS`/takendown/`rpc:` gate (`:93-176`) — can mint
`lxm=com.atproto.server.createAccount`, the migration credential. Blunted in practice only by
F-SVC-03, which makes the tokens unusable at real peers; **fixing F-SVC-03 without these makes it
live**, a second sequencing constraint alongside the OAuth one.

**10. SSRF from an unauthenticated request (F-OAUTH-05).** *Exploitable today.* PAR GETs a
caller-supplied `client_id` URL and its `jwks_uri` (`oauth/par.rs:414-415,426-433`) with no scheme,
host or address restriction, and the same hole exists on the spaces mint path
(`space/mint_authz.rs:317-343`). Cloud metadata endpoints, internal admin panels, anything reachable
from the pod. The workspace's own guard (`crates/atproto-identity/src/host.rs`) is never called.

**11. Least privilege is unavailable: OAuth scopes are parsed and never enforced (F-OAUTH-12).**
*Exploitable today by any client holding a token.* `scope=atproto` writes every collection, uploads
any MIME type, rotates the handle and proxies arbitrary calls. The authorization server's decisions
are not enforced by the resource server, which is a category error rather than a missing feature.

**12. Denial of service on the hottest authenticated space path (F-SPACE-30)** and **13. rate limiting
that does not bound the attacks it resembles a defence against (F-OPS-02).** *Both exploitable today.*
`Box::leak` (`space_handlers.rs:1113`) leaks a string per authenticated space read; and because every
rate-limit bucket key is caller-supplied, a password sprayer varies `identifier` and a signup flood
varies `handle` for a fresh bucket per attempt, with no per-IP limit anywhere and 100 of 104 routes
unlimited. The latter compounds F-BLOB-04, where an unauthenticated caller materialises unbounded
per-DID SQLite files by varying `did`.

**14. Two security controls that read as working and are not (F-SVC-07, F-MOD-04).** *Exploitable
today.* `admin.revokeServiceAuth` writes a blacklist row nothing reads while its doc
(`admin/handlers.rs:838-840`) claims verifiers consult it, so an operator who revokes a leaked token
sees 200 OK and is wrong; and admin Basic-auth compares with `!=` (`:80`) — a timing oracle against
the one secret protecting every admin verb — while shipping a live default password outside
`PDS_PRODUCTION=true`.

### Tier 2 — latent conformance gaps: not attacker-triggered, but disqualifying for a stable release

**15. Every repository CID this PDS produces is non-conformant (F-REPO-01 + F-REPO-02).** *Latent.*
Three `skip_serializing_if` attributes drop map keys the data model requires to be present-and-null,
so the MST node encoding, the entry encoding and the commit body all hash differently from what any
peer computes. Verified by execution down to the byte count and the CID pair. No external verifier can
validate any repository, CAR exports are rejected, and commit signatures attest to bytes nobody else
derives. Three lines to fix, and until they are fixed every downstream repo-layer effort is wasted.

**16. `Mst::delete` silently corrupts a neighbouring record's key (F-REPO-03).** *Latent, and the
worst of the latent set because it destroys user data.* Not attacker-triggered — ordinary
`deleteRecord` traffic causes it, at a rate the 22-repo chapter measured as 2 corrupt plus 1 errored
out of 20 single deletes on a four-collection repo. Ranks above F-REPO-01 despite F-REPO-01 being
cheaper: F-REPO-01 breaks interop, F-REPO-03 loses data.

**17. The firehose is not consumable by any relay (F-FIRE-01 + F-FIRE-02 + F-FIRE-03 + F-FIRE-04 +
F-FIRE-05).** *Latent.* Non-union envelope, no CARv1 blocks anywhere, `#sync.blocks` as an integer,
CIDs corrupted by a JSON round trip, and per-actor rather than global sequence numbers. All eleven
comparisons emit a flat lexicon-shaped body inside a correct frame and eleven of eleven ship a real
CARv1, so this is emphatically not a "nobody does this" case. The source is honest about the
incompleteness in-place (`sequencer/frame.rs:110-114`, `sync_event.rs:26-28`), which is exactly right
for an `-rc` and exactly disqualifying for stable, because federation is what the firehose is for.

**18. The spaces commit format diverges in three coupled ways (F-SPACE-19 + F-SPACE-04 +
F-SPACE-18).** *Latent, with a security sub-component.* The `ctx` omits the author DID, the commit has
no `ver`, and the URI scheme is `ats://`. The security sub-component is real if minor: dropping the
author from `ctx` loses the draft's deliberate author domain separation, so a signature attests to
less than it should within a space. Must land as one change, because `space` is length-prefixed into
`ctx`.

**19. Three one-to-few-line wire defects that break every real client (F-BLOB-01, F-SVC-03,
F-REC-03).** *All latent.* The `uploadBlob` envelope parses as neither `.strict()` reference schema,
so `@atproto/api` throws on the upload call and any record embedding the result is rejected — media
is broken against every real client, and ten of eleven comparisons emit the typed form. Service-auth
`typ: "at+jwt"` makes the reference verifier throw `BadJwtType`
(`packages/xrpc-server/src/auth.ts:88-104`), so every token this PDS mints is rejected by the Bluesky
AppView, by Ozone and by every `@atproto/xrpc-server`-based service. And `listRecords` emits
`"cursor": null`, so the last page of every pagination loop throws.

**20. P-256/P-384 signatures are not low-S normalized and high-S is accepted on verify
(F-REPO-06).** *Latent, conditional.* Mitigated for the default K-256 account keys, which normalize by
construction. It becomes live the moment a P-256 signing key is configurable — and `atproto-identity`
is a published library other projects sign with, so the blast radius exceeds this PDS. The correct
helper already exists in the workspace at `crates/atproto-attestation/src/signature.rs:30-80`.

**21. `swapCommit` accepted and never enforced (F-REC-04).** *Latent, causes silent data loss.*
Concurrent writers clobber each other and both receive HTTP 200 rather than `InvalidSwap`. arroba's
explicit rejection of requests carrying `swapCommit` (`xrpc_repo.py:31-36`) is a correct and cheap
stand-in if full compare-and-swap is out of reach for this release.

**22. Every standard OAuth client receives HTTP 415 (F-OAUTH-01), and browser clients fail discovery
before that (F-OAUTH-06).** *Latent — an interop wall, not a security defect.* Listed here because it
is the gate in front of every Tier 1 OAuth finding: while it stands, the exploitable chain in blocker
1 is unreachable through a standard client, which is the only reason the whole OAuth surface is not an
active incident. Fixing F-OAUTH-01 without F-OAUTH-02 and F-OAUTH-03 would **make the takeover chain
live**. They must ship together — this is the single most important sequencing constraint in the
roadmap.

**23. DPoP is advertised as mandatory, enforced only where a thumbprint happens to be bound, and
permanently broken for one class of client (F-OAUTH-09 + F-OAUTH-04 + F-OAUTH-08, with F-SVC-09 on the
proxy path).** *Mostly latent; the F-OAUTH-04 half is a live functional break today.* Four distinct
defects sit on one mechanism, which is why they are grouped rather than ranked separately.

*Advertised, not enforced.* `require_dpop_bound_access_tokens: true` (`oauth/metadata.rs:76`) tells
every client the server will not accept a non-bound token. It will. `issue_pair` attaches `cnf` only
when a `dpop_jkt` is present (`oauth/token.rs:245-247`) and returns `token_type: "Bearer"` otherwise
(`:298`), and `require_authn` demands a proof only when `claims.cnf.is_some()`
(`http/auth.rs:179-180`). A client that simply omits DPoP receives a working bearer token. Underneath
that, the sole read of the `DPoP` request header anywhere in the crate is `oauth/dpop.rs:56`, reached
only from `http/auth.rs:180` — so the token endpoint itself never sees a proof, which is the F-OAUTH-02
half of blocker 1 seen from the DPoP side. The net effect is that proof-of-possession is opt-in by the
caller on a server whose metadata says it is compulsory.

*Permanently broken for non-DPoP clients.* `issue_pair` stores `dpop_jkt.clone().unwrap_or_default()`
into the refresh handle (`oauth/token.rs:290`), an empty `String` when the client sent no thumbprint;
`handle_refresh` hands it back as `Some(handle.dpop_jkt)` (`:229`); `cnf` therefore becomes
`Some(jkt: "")` (`:245-247`) and `token_type` flips to `"DPoP"` (`:298`). From that moment
`claims.cnf.is_some()` is true, a proof is required (`http/auth.rs:179`), and the proof's thumbprint is
compared against `""` (`oauth/dpop.rs:81-87`), which no key can ever match. A non-DPoP session works
until its first refresh and is unrecoverable afterwards — the client cannot fix it, because no proof it
can construct will satisfy the comparison.

*No server-issued nonce.* RFC 9449 §8.2 lets the server pin proof freshness to a value it chose rather
than to the client's clock. A grep for `DPoP-Nonce` or `use_dpop_nonce` across
`crates/atproto-pds/src/` is empty. Three worked references, two of them independents: the reference
sets the header and CORS-exposes it on every OAuth response
(`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/router/create-oauth-middleware.ts:213-219`)
with a dedicated `use_dpop_nonce` error (`.../errors/use-dpop-nonce-error.ts:13`); zds issues nonces on
both the resource and authorization-server challenges, rotates them on a 60-second counter with a ±1
tolerance, and **requires** the claim on every proof (`/tmp/gap-scratch/zds/src/internal/dpop.zig:7-8,23-45,120-121,199-208`);
tranquil-pds sets `DPoP-Nonce` and returns `use_dpop_nonce`
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/oauth/verify.rs:228,319-322,413`) with an
end-to-end test that asserts the challenge round trip (`tests/auth_extractor.rs:482-536`). The
machinery is already modelled in this workspace's own crate — `expected_nonce_values`
(`crates/atproto-oauth/src/dpop.rs:451`) — and the PDS sets only `max_age_seconds`
(`oauth/dpop.rs:71-72`). *Consequence:* proof freshness rests on the client's clock inside a 60-second
window, and the server has no way to force rotation.

*And the proxy path derives `htu` from a synthetic URL.* `build_parts_for_authn` builds the
authentication `Parts` with `.uri("/")` (`http/proxy_handlers.rs:247-249`), so a DPoP proof bound to
the real request URL cannot validate. Every browser OAuth client 401s on proxied calls even after
F-SVC-01 and F-SVC-02 are fixed — a dependency worth noting against M1.12.

**Calibration, and a narrowing of how §1.5 phrases F-OAUTH-08.** Replay resistance here does *not* rest
entirely on a time window, and the report should not be read that way. `oauth/dpop.rs:89-106` extracts
the proof's `jti` and calls `check_and_insert` with a 120-second TTL against the shared
`JtiReplayGuard`, which has memory, SQLite and Valkey backends and is garbage-collected on the unified
tick (`gc.rs:143`) — a real single-use guard that survives a restart on the durable profiles. The
accurate gap is narrower than "no replay protection": what is missing is
the *server-issued* nonce, not the single-use check. Stated the other way round, this is a mechanism
that is largely built and correct, undermined by an advertisement it does not honour and by an
`unwrap_or_default()` — which is the report's dominant failure mode showing up once more, and why the
remediation is already sized S. The roadmap handles this split correctly and needs no change: the two
enforcement defects are in the stable gate (M2.5 for the empty-thumbprint break, M4.4 for the metadata
honesty fix), while nonces sit in M4.10, deferred on the defensible ground that a single-use `jti`
guard already covers the attack a nonce is principally there to stop.

### Not blockers, stated to prevent over-correction

The write-time membership model in spaces is a documented design decision
(`crates/atproto-pds/src/space/writer.rs:6`), not an oversight, and should not be scored as one. The
read-time authorization hole is shared with the reference draft. Rate limiting exists and is
well-engineered; the gap is coverage and key choice. `com.atproto.sync.getBlob` being public is
correct for public repos — the defect is only that permissioned blobs share the store.

---

## 3. "Even a smaller project does this"

The independent field is stronger than usually assumed, so this list is longer than it would be
against a weaker corpus. Every row cites both sides. Tiers are as verified: **single-user** = cirrus,
dnproto; **hobby-experiment** = alteran; everything else in this section is a solo or small-team
"serious" project.

**Server discovery and identity endpoints.** `com.atproto.server.describeServer` is routed by cirrus
(`index.ts:278`), dnproto (`src/pds/Pds.cs:190`) and alteran (`index.js:42`) — and by all eleven
comparisons — while atproto-crates does not route it at all (F-ACCT-01), even though the data it needs
is already on `HttpState` (`http/auth_handlers.rs:93-110`). Ten of eleven serve
`GET /.well-known/atproto-did`; eight serve `/.well-known/did.json`, including cirrus
(`index.ts:113`), alteran and dnproto (`Pds.cs:215`). atproto-crates serves neither (F-IDENT-04), which
is why its own shipped `deploy/` cluster cannot resolve its `did:web` (F-OPS-05). Calibration: the
reference and rsky-pds also omit `did.json`, so only the `atproto-did` half is a clear embarrassment.

**Firehose fundamentals.** alteran — the only hobby-experiment tier project in the corpus — emits all
twelve `#commit` fields in a flat lexicon-shaped body (`src/worker/sequencer/payload.ts:69-83`) and
builds a real CARv1 (`src/services/car.ts:171-258`); dnproto does the same
(`src/pds/UserRepo.cs:229-238,291-295`) and additionally re-types CIDs to CBOR tag 42 before emitting
(`:353-357`). atproto-crates emits a `{seq, repo, time, payload}` envelope with eight required fields
missing and no CAR at all (F-FIRE-01, F-FIRE-02, F-FIRE-04). alteran also ships four dedicated firehose
test files and cirrus ships firehose tests; atproto-crates has none (F-FIRE-13).

**MST and commit encoding.** dnproto emits `l` and `t` as explicit nulls
(`src/repo/RepoMst.cs:152-158,208-214`), as does zat (`src/internal/repo/mst.zig:571,600`), and dnproto
converts `$link` to tag 42 (`src/repo/DagCborObject.cs:639-660`). atproto-crates omits all three
(F-REPO-01, F-REPO-05). This is the sharpest single row in the list: a single-user C# PDS gets the
byte format right where a 19-crate Rust workspace does not.

**Relay-facing enumeration.** `com.atproto.sync.listRepos` is routed by all eleven — alteran
(`index.js:58`), dnproto (`Pds.cs:209`), cirrus (`index.ts:204`) — and not by atproto-crates
(F-SYNC-01), which already has the enumeration internally as `list_account_dids`
(`subscribe_handlers.rs:212-216`). This is the cheapest fix in the sync area.

**AppView proxying.** cirrus (`xrpc-proxy.ts:112-142`), alteran
(`src/lib/appview/did-resolver.ts:83-102`) and dnproto (`AppBsky_Proxy.cs:60-118`, with an allow-list
*and* an SSRF filter) all resolve `Atproto-Proxy` DIDs against the DID document. atproto-crates
accepts exactly one operator-pinned AppView and 502s everything else (F-SVC-02) — and its proxy route
is broken anyway (F-SVC-01). alteran also carries a fourteen-header proxy allow-list
(`src/lib/appview/proxy.ts:19-34`) against atproto-crates' single `Content-Type` (F-SVC-10), and
alteran gates `getServiceAuth` on protected and privileged methods
(`com.atproto.server.getServiceAuth.ts:13-23,21-23`) where atproto-crates gates neither (F-SVC-05).

**Preferences.** `app.bsky.actor.get/putPreferences` are served locally by all eleven, including
cirrus (`index.ts:382,387`), dnproto (`Pds.cs:199-200`) and even arroba's stubs (`app.py:90-98`).
atproto-crates proxies them to an AppView that has no such handler (F-MIG-02), breaking muted words,
feed preferences and content labels for every logged-in user.

**Per-IP rate limiting.** alteran limits by IP (`src/lib/ratelimit.ts:16-19`, applied at
`createSession.ts:16-17`); pegasus keys on `identifier ^ "-" ^ request_ip`; metalbear installs a global
limiter into its XRPC server (`src/server.c:6958-6959`), operator-tunable via `METALBEAR_RATE_LIMIT`
(`src/main.c:243-244`). atproto-crates has a better-engineered limiter applied to four endpoints, all
keyed on attacker-controlled input, with no per-IP path anywhere (F-OPS-02). The correct framing is
coverage, not capability — but the outcome on a deployed instance is the same.

**Blob handling.** alteran ships both an operator-tunable size limit and a per-DID quota
(`src/db/blob.ts:42`); atproto-crates has a hardcoded 16 MiB constant that is dead code behind axum's
2 MiB default (F-BLOB-06, F-BLOB-07). alteran (`src/lib/util.ts:121-164`), cirrus
(`xrpc/repo.ts:628-642`) and dnproto (`ComAtprotoRepo_UploadBlob.cs:105-130`) all sniff MIME rather
than trusting the client header (F-BLOB-08), and alteran sets `nosniff` and friends on `getBlob`
(`com.atproto.sync.getBlob.ts:71-72`) where atproto-crates sets none (F-BLOB-05).

**Backup.** dnproto — single-user tier — ships `BackupAccount.cs`. cocoon has `server.go:673-691` and
pegasus `s3/backup.ml:25-60`. atproto-crates, a multi-account host holding other people's
repositories, has no backup or restore path of any kind (F-OPS-04).

**Operator documentation.** zds and alteran both ship operator runbooks. atproto-crates has three
source sites that defer to a runbook (`valkey_backend.rs:215-218`, `tests/feature_s3.rs:6-7`,
`metrics.rs:11-13`) and `find docs -type f` is empty (F-OPS-15).

**Continuous integration.** cocoon (`go-test.yml`), rsky (`rust.yml:141-142,167`), metalbear, cirrus,
alteran and zds all run CI. atproto-crates has one workflow, `release-binaries.yml`, and no test run
of any kind (F-OPS-01) — while its README claims otherwise
(`crates/atproto-pds/README.md:29-32`). arroba goes further and runs the upstream
`atproto-interop-tests` fixtures as a gate (`arroba/tests/test_testdata.py:26-96`), which is exactly
the mechanism that would have caught F-REPO-01 through F-REPO-04 on their first run.

**Error-name conformance.** dnproto (`ComAtprotoRepo_CreateRecord.cs:62`), alteran
(`repo-write-validation.ts:438`), metalbear, zds, tranquil and pegasus all emit `InvalidSwap` on a
swap mismatch; atproto-crates emits a 403 `Forbidden` (F-REC-06). metalbear emits the declared
`RecordNotFound` (`repo_store.c:1758-1761`) where atproto-crates emits generic `NotFound` (F-REC-10).

**Fairness in the other direction.** Several gaps are shared and should not be listed as
embarrassments: metalbear also exposes `reserveSigningKey` publicly and also allows BYO-DID without
proof; cocoon also hardcodes `checkAccountStatus.validDid` and shares the `swapCommit` defect; the
reference itself omits `/.well-known/did.json`, does not verify imported repo signatures, and shares
the spaces read-authorization hole. And the single-user projects legitimately decline scope on
multi-account concerns — 62 `n/a` cells for cirrus and 65 for alteran are scope, not omission.

---

## 4. Where atproto-crates leads the independent field

A report that only lists faults is not decision-useful. Every item below was verified rather than
assumed, and two candidates the brief suggested are **explicitly not claimed** because the evidence
does not support them (see the end of this section).

**The permissioned-data cryptographic core is correct and — uniquely outside Bluesky's own branch —
wired into the production write path.** The LtHash element encoding is byte-identical to the
reference: `record_element_bytes` is `format!("{collection}/{rkey}/{cid}").into_bytes()`
(`crates/atproto-space/src/set_hash.rs:167-169`) against the reference's `formatRecordElement`
(`packages/space/src/util.ts:18-25`), with geometry pinned by a 65,536-add wraparound test
(`set_hash.rs:243-250`) and a known-answer digest for the empty state (`:187-198`). And it *runs*:
`SpaceWriter::apply_writes_locked` folds ops into the set hash and calls `create_commit` on the real
write path (`crates/atproto-pds/src/space/writer.rs:335`, folding at
`crates/atproto-space/src/space_repo.rs:127-269`). HappyView's equivalent is imported only by
`src/spaces/integration_tests.rs:11`, its `sign_commit` has no production caller, its `lthash_state`
column stays 2048 zero bytes and its oplog table is never written (`src/spaces/oplog.rs:5-30`);
contrail and stratos have no set hash at all. **This is the finding that most rebalances the spaces
comparison.** HappyView has the correct `ctx` byte layout in code that does not execute;
atproto-crates has the wrong layout in code that does. The first is a small surgical fix; the second
is not.

**Record identity is real.** DAG-CBOR through `atproto_dasl::to_vec` plus `compute_cid`
(`space/writer.rs:285-288`), where HappyView fabricates `bafyrei` + hex from a 20-byte truncated
sha256 of `serde_json` output (`src/spaces/service.rs:26-30`) that is not multibase-decodable and does
not match its own CAR export (`car.rs:65-67`), and contrail writes `cid: null` on every record
(`packages/contrail-record-host/src/routes.ts:248`). Because the LtHash element is defined over the
record CID, an implementation with fake CIDs could not produce a comparable digest even if it wired
the hash in.

**The credential path is the strongest of the four compared, on four counts.** The delegation token is
signed by the account's own key (`http/space_auth.rs:74-96`, used at `space_handlers.rs:1451-1452`),
which is what makes it verifiable by a third-party space host — HappyView signs with the instance
`TOKEN_ENCRYPTION_KEY` (`routes.rs:926`), so its token proves "HappyView says this member asked", not
"this member signed". On receipt the issuer's key is resolved from the local table or the issuer's DID
document (`space_auth.rs:107-116,245-291`) and `typ`, `kid`, `alg`, signature, `aud`, `sub` and `exp`
are checked in order (`crates/atproto-space/src/credential.rs:307-338`). The `jti` is then consumed
through a **single-use replay guard sized to the token's remaining lifetime, with memory, SQLite and
Valkey backends so it survives a restart** (`space_handlers.rs:1529-1542`,
`crates/atproto-pds/src/security.rs:44-54`) — **no comparison target has a `jti` guard at all**. And
client attestation is verified end to end and actually gates the mint: `typ`, `iss == sub`, an https
metadata URL, `aud`, expiry, a 300-second lifetime cap, `jti`, then a metadata fetch, inline `jwks` or
`jwks_uri` resolution, `kid` selection and JWS verification (`space/mint_authz.rs:229-376`), with the
attested `client_id` driving `#open`/`#allowList` and an outright refusal when an `#allowList` space is
approached unattested (`:128-143,136-140`, test at `tests/http_phase7_spaces.rs:1054`). HappyView's
attestation module is dead code and its allowlist checks a HappyView-issued API key
(`src/spaces/auth.rs:244-259`); contrail's `AppPolicy` keys on a `clientId` no production path
populates (`packages/contrail-base/src/spaces/auth.ts:97-101,142-146`). Signing is also key-agnostic —
`atproto_identity::key::KeyData` (`commit.rs:41`) with `alg` derived from the key type
(`credential.rs:150-157`) — where HappyView hardwires secp256k1 (`commit.rs:3,51`), so a P-256 account
cannot produce a HappyView commit at all.

**Sync hygiene and write-path engineering.** The `(rev, idx)` oplog cursor is correct where the draft
is not, preventing a bare-rev `since` from dropping the tail of an atomic batch larger than `limit`,
pinned by `batch_larger_than_limit_pages_fully` (`crates/atproto-space/src/space_repo.rs:634-680`) —
a latent bug that will bite the reference too, and worth an upstream issue rather than a local retreat.
`notifyWrite` is contentless (`space/notify.rs:49-56`) with the receiving handler pinning
`claims.iss == payload.repo` (`space_handlers.rs:2107-2113`) so a PDS cannot deliver on another repo's
behalf, where HappyView's carries collection, rkey and CID (`routes.rs:59-65`) and ships an internal
UUID a syncer cannot resolve (`notifications.rs:63-69`). Permissioned writes are provably off the
public firehose — greps for sequencer symbols from space code and space symbols from
`crates/atproto-pds/src/sequencer/*` both come back empty, and `apply_writes_locked` ends at
`repo.apply_commit(prepared)` plus the outbound notify (`space/writer.rs:254-353`) with `space_record`
never entering the MST or block store; contrail, HappyView and stratos achieve this trivially by never
reaching a PDS, while atproto-crates achieves it while *being* the PDS. Concurrency is handled
properly, with a per-`(member_did, space_uri)` `tokio::Mutex` from a `DashMap`
(`space/writer.rs:64,95-100,116-117`) and the existence probe *inside* the lock (`:164-182,208-222`)
so create-versus-update cannot race. And takedown is already indistinguishable from absence on the
single-record read path (`space/reader.rs:104` → the same `404 RecordNotFound` branch as a genuine
miss), where contrail returns `403 not-member` and leaks existence
(`contrail-record-host/src/routes.ts:150,189`).

**Breadth of the spaces surface.** Twenty routes across `com.atproto.space.*` and
`com.atproto.simplespace.*`, roughly 11k lines across `crates/atproto-space` (3,363),
`crates/atproto-pds/src/space/**` (5,145) and `space_handlers.rs` (2,984). **No other PDS in the
twelve-column field has any permissioned-data surface at all**, which is why this work contributes
nothing to the 32.1% coverage score and must never be presented as absent from the engineering ledger.

**`atproto-dasl` is the strongest single component in the workspace.** CAR ingest hardening enforces
three ceilings at the reader with the per-block one checked *before* allocation, plus a dedicated DoS
suite (`src/car/reader.rs:129-181`, `car/config.rs:87-97`, `tests/car_dos_test.rs`); nothing else in
the study enforces all three at the reader, and the reference's `readCar` buffers (`car.ts:56-66`).
CID profile validation rejects CIDv0, non-`{raw, dag-cbor}` codecs, non-`{sha2-256, BLAKE3}` hashes
and non-32-byte digests (`src/cid/mod.rs:655-685`), applied to every CAR block by default
(`car/config.rs:78-84`), where pegasus accepts a zero-length digest.

**RFC 9101 signed request objects (JAR) at PAR.** `oauth/par.rs:258-400` accepts a `request` JWS,
resolves the client's `jwks`/`jwks_uri` (`:405-457`), accepts `ES256|ES256K|ES384` (`:285-294`),
enforces `iss == client_id` (`:311-319`) and `exp`/`nbf` (`:332-350`), and verifies the signature
(`:372-378`). The reference implements JAR; **not one of the ten independents does** — a
`request_object` grep across all of them returns only metadata declarations. The irony is that
atproto-crates does not advertise it (F-OAUTH-11), so no client will use it, and the embedded `aud` is
advisory only (F-OAUTH-17).

**`space:` scopes with human-readable consent.** The 0016 scope grammar is parsed and enforced at
roughly 37 call sites, and the consent page goes further than anyone's: it resolves space-owner DIDs
to bidirectionally-verified handles and space-type NSIDs to their declaration `name`, so a user sees
people and spaces rather than DIDs (`oauth/consent.rs:80-110,412-464`). Only two other projects have a
`space:` grammar at all — zds, which enforces it, and rsky, whose module is explicitly parsing-only.
Caveat: `assert_space_scope` returns `Ok(())` for any non-OAuth subject
(`space_handlers.rs:1866-1868`), which is half of F-SPACE-07.

**Admin surface breadth and a hashed denylist.** Twelve canonical `com.atproto.admin.*` methods
(`router.rs:359-426`) — more than every independent except tranquil-pds's fourteen, and more than
cocoon, arroba, dnproto and cirrus (zero each), zds (one) and pegasus (seven). It is also the only
implementation with a **hashed** identifier denylist; tranquil-pds's slur regex filter is the nearest
analogue and stores plaintext.

**Observability, transactional integrity, and read-surface detail.** OpenTelemetry wiring
(`telemetry.rs:32-67`, initialised at `bin/pds.rs:767`) is ahead of the field — the reference has no
metrics at all. Commit, blocks, records and the outbox row land in one backend-native transaction — a
sqlx `Transaction` (`actor_store/sql/public_realm.rs:618-703`) or a single `fjall::Batch`
(`fjall/public_realm.rs:834-872`) — with per-DID write serialization, so a crash cannot leave a commit
without its event; dnproto's seq counter is a non-atomic read-delete-insert pair
(`src/pds/db/PdsDb.cs:986-995`). On the read surface, `getRepo` implements a real `since` diff export
(`http/handlers.rs:215-226`, `repo/car_export.rs:362-450`) where cocoon, cirrus, alteran and dnproto
accept `since` and return the full repo anyway; `getRepoStatus` returns the complete lexicon shape
including optional `rev` (`repo/reader.rs:419-428`) where arroba omits it and collapses every status to
`deactivated`; the five-state account vocabulary distinguishes `takendown`/`suspended`/`deactivated`
(`account/state.rs:14-27`) where arroba, cocoon and metalbear can report only `deactivated`; the
`#sync` *trigger* set fires after `importRepo` (`repo/import.rs:333-336`) and on `forceRepoSync`
(`admin/handlers.rs:1009-1013`), the two situations the event was designed for; and the deprecated
event types are cleanly absent (`sequencer/outbox.rs:14-25` is exactly the current union, where arroba
still writes `#tombstone` rows).

**The standalone crate ecosystem.** Nineteen workspace members. `atproto-identity` alone ships a
concurrent DNS-plus-HTTPS handle resolver with conflict detection (`src/resolve.rs:616-641`), a full
PLC operation model (`src/plc/operations.rs:84-118`), a chain validator (`src/plc/chain.rs:261`),
did:web and did:webvh syntax validation and SSRF-safe hostname validation — **no comparison
implementation has a library asset of that quality behind its PDS**. Add `atproto-dasl`,
`atproto-oauth`, `atproto-lexicon` and `atproto-attestation`, all independently usable. And the whole
codebase is legible enough that this analysis produced **zero `?` cells** in the coverage matrix, where
every other column has between 9 and 36.

### Two candidate leads that are explicitly NOT claimed

**Sync 1.1 `prevData` work is not a lead.** `prevData` is present (`repo/commit.rs:56-57`) but it is
carried *inside the signed commit body*, which is F-REPO-02 — coverage matrix area B scores
atproto-crates `N` on "commit carries no non-spec fields" against `Y` for eight comparisons. The
tracking exists; the placement is a divergence, not an advantage.

**Backend pluggability is only half real.** The trait-based storage dispatch is genuine and the
SQLite/fjall pair works, and the Valkey backend for the rate limiter and the `jti` guard is real
(`valkey_backend.rs:131-211`). But Postgres and S3 are never constructed by the shipped binary and
Postgres panics on the record-write path (F-OPS-06), and `PDS_BLOB_STORE_URL` is documented and never
read (F-BLOB-09). Two of the five advertised backends are unreachable, so "SQLite/Postgres/Fjall/S3/
Valkey" cannot be claimed as a lead until F-OPS-06 is resolved one way or the other.

**Inductive CAR import verification is a modest, qualified lead.** The inductive chain proof does run
(`crates/atproto-repo/src/repo/inductive.rs:79-158`, called at `repo/import.rs:232`) and the reference
does not verify at all on import (`importRepo.ts:53-60` re-signs). But it accepts missing blocks on
faith (`:114-135`) and never recomputes a pre-image root, and the more careful historical-key
signature check the code was designed around never executes (F-REPO-08). Credit for the structural
proof that ships; the citation audit downgraded the broader claim, and this report keeps it
downgraded.

---

## 5. Prioritised remediation roadmap

Four milestones. Within each, items are ordered by value-per-effort, and the **small-effort /
high-impact** items are flagged ★. Effort sizes are S (hours), M (days), L (weeks), XL (a month or
more), estimated on the "built but not wired" finding — a large share of this work is connecting
existing tested code rather than designing it.

**Read the two sequencing constraints before the tables.**

1. **M1.1 must be first.** Without an external oracle, none of the encoding fixes can be *shown* to be
   correct — round-trip tests pass against a wrong encoding. Doing M1.1 first is what makes M1.2
   provable rather than hopeful, and what stops the rest regressing.
2. **F-OAUTH-01 must not ship alone.** Fixing the JSON-vs-form encoding is the single cheapest,
   highest-impact change in the report — and it is also the wall currently standing in front of the
   account-takeover chain (F-OAUTH-02 + F-OAUTH-03). Shipping M1.4 without M2.1 and M2.2 makes an
   unexploitable defect exploitable. **They go out in the same release.**

### M1 — Interop-blocking correctness

| # | Item | Finding IDs | Effort | Depends on |
| --- | --- | --- | ---: | --- |
| M1.1 ★ | CI workflow running `cargo fmt`/`clippy`/`test`; initialise the `dasl-testing` submodule; vendor the upstream `interop-test-files` MST and commit vectors as a gate | F-OPS-01, F-FIRE-13 | S | — |
| M1.2 ★ | Remove three `skip_serializing_if` attributes: MST node `l`, MST entry `t`, commit `prev` | F-REPO-01 | S (3 lines) | M1.1 to prove |
| M1.3 ★ | Move `prevData` out of the signed commit body onto the firehose event | F-REPO-02 | S | M1.1, M1.2 |
| M1.4 ★ | PAR and token endpoints accept `application/x-www-form-urlencoded` (mirror `revoke.rs:41`) | F-OAUTH-01 | S (2 lines) | **must ship with M2.1 + M2.2** |
| M1.5 ★ | `uploadBlob` returns the typed `{$type, ref, mimeType, size}` envelope | F-BLOB-01 | S | — |
| M1.6 ★ | Service-auth JWS header emits `typ: "JWT"` at all five minters | F-SVC-03 | S (1 line ×5) | — |
| M1.7 ★ | Route `describeServer`, `com.atproto.sync.listRepos`, `/.well-known/atproto-did`, `/.well-known/did.json` | F-ACCT-01, F-SYNC-01, F-IDENT-04 | S | — |
| M1.8 ★ | Shape fixes: `listRecords` cursor omitted when absent; `#repoOp.cid` emitted as null; `applyWrites` result `$type` discriminators; `describeRepo.didDoc` | F-REC-03, F-FIRE-04 (part), F-REC-02, F-REC-01 | S each | — |
| M1.9 | `Mst::delete` prefix-rebase fix — reconstruct against the deleted entry's own key, then re-compress | F-REPO-03 | M | M1.1 |
| M1.10 | Height-aware MST insert with node splitting and merging | F-REPO-04 | L | M1.1, M1.2 |
| M1.11 | Record encode path: `$link` → CBOR tag 42, `$bytes`, reject non-integer numbers | F-REPO-05 | M | M1.1 |
| M1.12 | AppView proxy: forward the full NSID and query string; resolve `Atproto-Proxy` DIDs against the DID document; add `chat.bsky.*`, `tools.ozone.*`, `com.atproto.label.*` | F-SVC-01, F-SVC-02 | M | — |
| M1.13 | Firehose: emit flat lexicon-shaped bodies, encode payloads as CBOR natively instead of round-tripping through JSON, and adopt a global stream sequence | F-FIRE-01, F-FIRE-04, F-FIRE-05 | L | M1.2, M1.3 |
| M1.14 | Build real CARv1 slices for `#commit` and `#sync` | F-FIRE-02, F-FIRE-03 | L | M1.10, M1.13 |

M1.1 through M1.8 are collectively a few days of work and close five interop walls. M1.9 through
M1.14 are genuine implementation and are the bulk of the milestone.

### M2 — Stable-release table stakes (security, migration, enforcement)

| # | Item | Finding IDs | Effort | Depends on |
| --- | --- | --- | ---: | --- |
| M2.1 ★ | Fetch and validate client metadata at PAR; reject `redirect_uri` values not registered by the client | F-OAUTH-03 | M | ships with M1.4 |
| M2.2 ★ | Require client authentication and a DPoP proof at `/oauth/token`; pin `cnf.jkt` from the PAR-stored value and never from the request | F-OAUTH-02 | M | ships with M1.4 |
| M2.3 ★ | Never log rendered email bodies; add `smtp` to the shipped image | F-OPS-03 | S | — |
| M2.4 ★ | `getBlob` sets `nosniff`, `content-disposition`, CSP — copy from `space_handlers.rs:2262-2274` | F-BLOB-05 | S | — |
| M2.5 ★ | Stop non-DPoP sessions breaking on refresh: store `Option<String>` rather than `unwrap_or_default()` | F-OAUTH-04 | S | — |
| M2.6 ★ | Add a `DefaultBodyLimit` layer sized to the blob ceiling; make both operator-tunable | F-BLOB-06, F-BLOB-07, F-OPS-11 (part) | S | — |
| M2.7 ★ | Constant-time admin password compare; refuse to start with the default password outside dev | F-MOD-04 | S | — |
| M2.8 ★ | Move `disable`/`enableAccountInvites` to `com.atproto.admin.*`; emit `accountView.indexedAt`; fix `updateAccountEmail`'s `account` field | F-MOD-06, F-MOD-05 | S | — |
| M2.9 ★ | Low-S normalization for P-256/P-384 using the existing helper at `crates/atproto-attestation/src/signature.rs:30-80`; reject high-S on verify | F-REPO-06 | S | M1.1 |
| M2.10 ★ | CORS on the discovery documents and the OAuth routes | F-OAUTH-06 | S | — |
| M2.11 | Apply the workspace SSRF guard (`crates/atproto-identity/src/host.rs`) to PAR metadata, `jwks_uri`, and the spaces attestation fetches | F-OAUTH-05 | S/M | — |
| M2.12 | Enforce account state on writes, on refresh, and on every public read path including all five sync endpoints and both blob endpoints; gate `activateAccount` on not-takendown | F-MOD-01, F-MOD-02, F-ACCT-09, F-ACCT-04, F-BLOB-04 | M | — |
| M2.13 | Gate `createAccount`-with-existing-DID on inbound service auth; create migrating accounts `Deactivated`; authenticate `reserveSigningKey` | F-ACCT-02, F-ACCT-03, F-ACCT-15, F-SVC-14 | M | — |
| M2.14 | Enforce OAuth scopes on repo writes, blob upload and `rpc:`; add the missing `assert_*` helpers | F-OAUTH-12 | M | — |
| M2.15 | Service auth: require `lxm` at mint and verify; add `PROTECTED_METHODS`/`PRIVILEGED_METHODS`/takendown/`rpc:` gates; treat `exp` as an epoch; consult the revocation blacklist in `verify_service_auth` | F-SVC-04, F-SVC-05, F-SVC-06, F-SVC-07 | M | — |
| M2.16 | Blob ref walker on the record write path, calling the existing `add_ref` | F-BLOB-02 | M | — |
| M2.17 | `importRepo` populates `repo_record` and blob refs | F-MIG-01 | M | M2.16 |
| M2.18 | Implement `app.bsky.actor.get/putPreferences` locally | F-MIG-02 | M | — |
| M2.19 | Enforce `swapCommit` on all four write paths (or reject requests carrying it, arroba-style, as an interim) | F-REC-04 | M (S interim) | — |
| M2.20 | Identity: emit `#identity` on every handle change; validate handles and prove ownership in `updateHandle`; canonical `signPlcOperation` input plus the email-token gate; validate in `submitPlcOperation` | F-IDENT-01, F-IDENT-02, F-IDENT-03, F-IDENT-05 | L | — |
| M2.21 | Canonical `updateSubjectStatus`/`getSubjectStatus` subject union, enabling record and blob takedown | F-MOD-03, F-BLOB-15 | M | — |
| M2.22 | Per-IP rate-limiting middleware with IP-derived bucket keys; make the window tunable; fix the fail-open on `requestPasswordReset` | F-OPS-02, F-OPS-07 | M | — |
| M2.23 | Structural record checks: reject records with no `$type`, validate `rkey` against the record-key grammar | F-REC-05 (structural half) | M | — |
| M2.24 | Decide Postgres/S3: either construct and fix them, or remove them from the README and mark them unsupported | F-OPS-06, F-BLOB-09 | M / S | — |
| M2.25 | Full lexicon validation on writes using `crates/atproto-lexicon` | F-REC-05 (schema half) | L | M2.23 |
| M2.26 | Covering-proof construction for the firehose CAR slice | F-FIRE-06 | L | M1.10, M1.14 |

### M3 — Spaces GA

Note the sequencing gift: **permissioned records never enter the MST or the block store**
(`space_record` is disjoint, verified in §4), so M3 does **not** depend on M1's repo-layer work. The
spaces track can be brought to GA in parallel with, or ahead of, the PDS track.

| # | Item | Finding IDs | Effort | Depends on |
| --- | --- | --- | ---: | --- |
| M3.1 ★ | Commit format, as one coordinated change: add the author DID as the second length-prefixed field in `ctx`, add `ver: 1` to the signed commit, switch the URI scheme to `at://{did}/space/{type}/{skey}` | F-SPACE-19, F-SPACE-04, F-SPACE-18 | M | — (must land together) |
| M3.2 ★ | Fix `Box::leak` on `space_handlers.rs:1113` | F-SPACE-30 | S | — |
| M3.3 | Read-time authorization: stop adopting the caller-supplied `repo` verbatim, add a membership predicate on every space read, and make `assert_space_scope` apply to app-password sessions | F-SPACE-07 | M | — |
| M3.4 | Stop serving permissioned blobs from `com.atproto.sync.getBlob`; key blobs to the space and reject cross-space references | F-BLOB-03, F-SPACE-12 | M | M2.12 |
| M3.5 ★ | `getSpace` reads the authority's store rather than the caller's | F-SPACE-11 | S | — |
| M3.6 | Inline record values in `listRecords` and `listRepoOps`; add `excludeValues` and `reverse` | F-SPACE-03 | M | — |
| M3.7 | `com.atproto.space.getRepo` (CAR with commit root + DRISL index + sorted record blocks) and `com.atproto.space.getLatestCommit` (keeping `getRepoState` as an alias) | F-SPACE-01, F-SPACE-02, F-SPACE-20 | L | M3.1 |
| M3.8 ★ | Add `hash` to `notifyWrite` and `listRepos#repo` | F-SPACE-05 | S | M3.7 for the value to be meaningful |
| M3.9 | Space-credential revocation, portable from HappyView's `revoked_at` design | F-SPACE-06 | M | — |
| M3.10 | Cross-PDS credential verification: wire the two remote resolvers that already exist at `http/space_auth.rs:301,329` | F-SPACE-08 | M | — |
| M3.11 ★ | Wire-shape conformance: `applyWrites` input `repo`+`validate` and union results; `listSpaces` `type`/`did`/`cursor`; six-segment `getRecord` URI with required `repo`; accept `policy` as well as `mintPolicy`; clamp page limits; add clock-skew tolerance and a TTL ceiling; consistent `SpaceNotFound` status | F-SPACE-23, F-SPACE-22, F-SPACE-24, F-SPACE-16, F-SPACE-17, F-SPACE-26 | M | M3.1 |
| M3.12 ★ | Accept a bare rev as `(rev, 0)` on `listRepoOps.since` while still emitting the composite token; file the batch-tail-drop issue upstream | F-SPACE-21 | S | — |
| M3.13 | `com.atproto.simplespace.checkUserAccess` server side; validate `managingApp` as `did:…#fragment` | F-SPACE-09 | M | — |
| M3.14 | Apply takedown on the sync/oplog path; make space deletion a containment boundary | F-SPACE-14, F-SPACE-15 | M | M3.9 |
| M3.15 | Lexicon validation of permissioned record values; emit `validationStatus` | F-SPACE-10 | M | M2.25 |
| M3.16 | `registerNotify` for a remote authority | F-SPACE-13 | M | M3.10 |

### M4 — Ops hardening and nice-to-have

| # | Item | Finding IDs | Effort |
| --- | --- | --- | ---: |
| M4.1 ★ | Mount `deploy/well-known/` so the reference cluster can resolve its own `did:web` | F-OPS-05 | S (after M1.7) |
| M4.2 ★ | Read `--config`; extend the production gate to bind address, handle domains and durability profile; align `RUST_VERSION`; call `wait_drain()` | F-OPS-09, F-OPS-10, F-OPS-11, F-OPS-12 | S each |
| M4.3 ★ | `RateLimit-*` headers and the canonical `RateLimitExceeded` error name | F-OPS-17 | S |
| M4.4 ★ | Metadata honesty: stop advertising `private_key_jwt`, align `require_dpop_bound_access_tokens`, add the nine missing AS metadata fields including JAR | F-OAUTH-07, F-OAUTH-09, F-OAUTH-11, F-OAUTH-20 | S |
| M4.5 ★ | Firehose polish: `#info` on the correct opcode, `#account` without `status:"active"`, `FutureCursor` and `OutdatedCursor` | F-FIRE-08, F-FIRE-14, F-FIRE-09 | S/M |
| M4.6 | Backup and restore tooling | F-OPS-04 | L |
| M4.7 | Operator runbook and migration tooling/wizard | F-OPS-15, F-MIG-03 | M |
| M4.8 | Published container image and self-host installer | F-OPS-14 | M |
| M4.9 | Retention and GC: outbox window, repo-block reclamation, non-SQLite GC | F-FIRE-11, F-REPO-10, F-OPS-13 | M |
| M4.10 | Server-issued DPoP nonces; real access-token revocation; `aud`/`iss` checks on inbound tokens; asymmetric token signing; RFC-conformant authorization responses; longer PAR TTL; CSRF token on the consent POST | F-OAUTH-08, F-OAUTH-10, F-OAUTH-14, F-OAUTH-15, F-OAUTH-16, F-OAUTH-18, F-OAUTH-19 | M/L |
| M4.11 | Metrics content and authentication; fjall event split-brain; subscriber-set refresh; automatic crawler notification | F-OPS-08, F-FIRE-07, F-FIRE-10, F-FIRE-12 | M |
| M4.12 | Blob lifecycle: temp staging, orphan sweep, MIME sniffing, reference-time verification, `listBlobs.since` | F-BLOB-10, F-BLOB-08, F-BLOB-14, F-BLOB-11, F-BLOB-12, F-BLOB-13 | M |
| M4.13 | Streaming CAR export/import; `applyWrites` batch cap; `InvalidSwap`/`RecordNotFound` error names; idempotent `deleteRecord`; `getBlocks` array `cids`; `reverse` backend dispatch; no-op update suppression; `sync.getRecord`; `listReposByCollection` | F-REPO-09, F-REC-07, F-REC-06, F-REC-08, F-REC-09, F-REC-10, F-REC-11, F-SYNC-02, F-SYNC-03, F-SYNC-05, F-SYNC-06 | M |
| M4.14 | Remaining identity, account and admin shape items | F-IDENT-06…11, F-ACCT-05…14, F-MOD-07…11, F-SVC-08…13 | M/L |

### The minimum set — stated separately for each `-rc`

**(a) Dropping `-rc` on the PDS requires all of:**

> **M1 in full** (M1.1–M1.14) — correctness of the repository format, the firehose, the proxy and the
> discovery endpoints. Without M1.2/M1.3/M1.9/M1.10 the server does not produce conformant AT Protocol
> repositories, which is the core thing a PDS is for; without M1.13/M1.14 it cannot federate.
>
> **M2 items M2.1 through M2.24** — the security enforcement, the migration path, and the deployment
> decisions. Specifically: the OAuth takeover chain (M2.1, M2.2, shipped with M1.4), the log-token
> leak (M2.3), the blob XSS surface (M2.4), takedown enforcement (M2.12), DID-control proof (M2.13),
> scope enforcement (M2.14), service-auth gating (M2.15), the three migration blockers (M2.16, M2.17,
> M2.18), optimistic concurrency (M2.19), the identity endpoints (M2.20), the admin subject union
> (M2.21), rate-limit coverage and keying (M2.22), structural record checks (M2.23), and an explicit
> Postgres/S3 decision (M2.24).

**Explicitly NOT in the PDS gate, with justification:** M2.25 (full lexicon validation — the
structural half in M2.23 is what prevents unrecoverable damage; schema validation is a quality
improvement that the reference itself applies only server-side and that no consumer depends on for
decodability); M2.26 (covering proofs — Sync 1.1 is newer than the stable PDS surface and four of
eleven comparisons lack them, so shipping stable with a documented "covering proofs not yet
implemented" note is defensible); and all of M4 (ops hardening — genuinely important for a hosted
service, not for a correct one, with the exception of M4.1, which should ride along because it is a
one-line follow-on to M1.7 and its absence makes the project's own reference deployment
non-functional).

**(b) Dropping `-rc` on the permissioned-data features requires all of:**

> **M3.1** — the coupled `ctx` / `ver` / URI-scheme change. Nothing interoperates until this lands,
> and its three parts cannot be split.
> **M3.2** — the `Box::leak` fix. One line, and it is an availability defect on the hottest path.
> **M3.3 + M3.4** — the two confidentiality holes. A feature whose entire purpose is access control
> cannot ship stable while any local account reads any other's records and any anonymous caller reads
> the blobs.
> **M3.5 + M3.6 + M3.7 + M3.8** — the sync path. Without inlined values, `getRepo` and
> `getLatestCommit`, a syncer that falls behind its oplog retention has no recovery path at all, and
> backfill is quadratic. A feature that cannot sync is not GA.
> **M3.11 + M3.12** — the wire shapes a conformant client actually sends.

**Explicitly NOT in the spaces gate, with justification:** M3.9 (revocation — not a draft requirement,
and the two-hour TTL bounds the exposure; it is a reviewer-visible defect and a strong stable-release
candidate, not an interop blocker); M3.10 and M3.16 (cross-PDS verification and remote
`registerNotify` — these gate the *multi-PDS topology*, so the honest framing is to ship stable with
"spaces are supported within a single instance" documented, and to treat multi-PDS as the next
milestone); M3.13 (`checkUserAccess` — one of three mint policies, and the other two work; document
`managing-app` as unsupported); M3.14 and M3.15 (oplog takedown and value validation — real gaps, no
worked reference for the latter anywhere in the field).

**One thing the spaces gate cannot include, and must state instead:** 0016 is an open WIP draft.
"Spaces GA" cannot mean "spec-conformant", because there is no frozen spec. The defensible claim is
**"conformant to the draft lexicons at `3f6c96d` (2026-07-02), with the confidentiality properties the
design promises actually enforced"** — and that claim must be dated in the release notes, because it
will expire.

---

## 6. Benchmarks and thresholds that would change the recommendation

These are tied to observable events, not to judgement calls. Each states what would reclassify and
what the worked reference would be.

**The draft lexicons already exist, so most spaces divergences are checkable today.**
`bluesky-social/atproto` `permissioned-data` HEAD `3f6c96d` (2026-07-02, "bring impl up to date with
lexicons & proposal") carries 19 `space/` and 8 `simplespace/` files plus a reference implementation in
`packages/space/*` and `packages/pds/src/api/com/atproto/space/*`. Nothing in §1.12 is waiting on the
draft to firm up before it can be *measured* — only some of it is waiting before it can be *decided*.

**If the draft freezes `at://{did}/space/{type}/{skey}`,** F-SPACE-18 reclassifies from DIVERGENT to
MISSING and becomes a migration rather than a design difference. Worked reference:
`/tmp/gap-scratch/happyview/src/spaces/mod.rs:38-114` — parse the new form, rewrite `ats://` on the way
in, accept both for a release. If the draft instead adopts a distinct scheme — which two of four
implementations independently chose — F-SPACE-18 collapses entirely and HappyView migrated the wrong
way. **Either way M3.1 is worth doing**, because the `ctx` and `ver` halves are unambiguous.

**If the draft freezes the `ctx` layout** as `[space, author, rev, ikm]` — which
`lex-0016/space/defs.json` already states and the reference already implements — F-SPACE-19 hardens
from drift-against-a-moving-target into a flat conformance failure with no defence. This is the single
threshold most likely to be crossed, because the lexicon and the reference already agree.

**If `policy` stays the config key,** F-SPACE-22 reclassifies from DIVERGENT to MISSING, since there
is then no reading under which `mintPolicy` is an alternative spelling rather than an unrecognized
field. HappyView shares the bug, so this wants an upstream issue rather than a unilateral fix — and
the silent-ignore behaviour should become a 400 regardless of which name wins.

**If `getRepoState` is adopted upstream as an alias,** F-SPACE-20 is harmless. If not, F-SPACE-02
hardens from a naming inconvenience into a hard sync blocker, because with F-SPACE-01 also open there
is then no conformant route to a repo's current commit hash at all.

**If `since` is redefined as an opaque cursor,** F-SPACE-21 becomes conformant and the `(rev, idx)`
token becomes the correct reading. If `since` stays a revision, accept a bare rev as `(rev, 0)` and
file the batch-tail-drop issue upstream, because that bug will bite the reference implementation too.

**If the draft adds a read-time membership predicate,** F-SPACE-07 stops being defensible inheritance
and becomes a spec violation. Fix it either way — an OAuth-only scope check plus a verbatim `repo`
parameter is a cross-tenant read on a system whose entire purpose is access control, and both
HappyView (`src/spaces/service.rs:75-118`) and contrail
(`packages/contrail-record-host/src/routes.ts:125-195`) show a per-read check is affordable. Because
the hole is shared, raise it against the draft rather than only patching downstream.

**If the reference closes the hole in its own branch first,** the "inherited" framing evaporates and
F-SPACE-07 becomes an ordinary atproto-crates blocker. Watch
`packages/pds/src/api/com/atproto/space/util.ts` specifically.

**If the draft adds credential revocation,** F-SPACE-06 moves from addition to conformance item, and
HappyView's `revoked_at` design is directly portable. It also interacts with F-SPACE-15: without
revocation, space deletion is not a containment boundary either.

**If the draft specifies a status-code mapping for its error names,** F-SPACE-26 becomes a conformance
item rather than a client-experience defect. Today only names are specified.

**Settled, and worth recording so it is not re-litigated:** the 0016 README does **not** mandate
`client_id` in the credential payload (`0016-README.md:219-223,233-239`; the example payload is
`{iss, sub, iat, exp, jti}` and the reference's `SpaceCredentialPayload` matches). F-SPACE-25 stays an
extension. The open item is the inverse — `register_notify`'s dependency on the claim
(`space_handlers.rs:2499-2502`) needs auditing against reference-minted credentials, which carry none.

**If HappyView and atproto-crates converge on parameter naming, spaces interop risk drops
materially** — HappyView is the only same-direction yardstick in the field, so two conformant
implementations of the same namespace is the strongest available signal. **But note that HappyView
itself diverges from the draft** on `mintPolicy` (identical bug), on routing `getRepoState`, on taking
`{grant}` in the request body rather than an `Authorization` header, and on omitting `hash` from
`notifyWrite`. "Conformance" is currently a moving target for everyone, and agreement between two
implementations is not the same as agreement with the draft. Where atproto-crates and HappyView both
diverge, that is a signal about the draft's stability; where only one diverges, that is a bug in the
one.

**PDS-side thresholds are mechanical rather than political.** If the upstream `interop-test-files` MST
and commit vectors are adopted as a CI gate and pass, F-REPO-01 through F-REPO-04 are *provably*
closed rather than believed closed — that is the single observable event that should change how this
report's repo-layer conclusions are read. If a real relay successfully ingests the stream and reports a
monotonic cursor, F-FIRE-01 through F-FIRE-05 are closed by observation rather than by inspection; none
of the firehose findings have been reproduced against a live relay, only against the lexicon. And if a
scripted `@atproto/oauth-client-node` completes PAR → authorize → token against a running instance,
F-OAUTH-01 through F-OAUTH-05 move from source-read conclusions to verified behaviour — the OAuth
chapter is explicit that no end-to-end reproduction was performed.

**If Postgres and S3 are still unconstructed at 1.0,** they must be removed from
`crates/atproto-pds/README.md` rather than documented as supported. A documented deployment mode that
panics on the first write (F-OPS-06) is worse than an absent one, on exactly the same reasoning as
F-SVC-07's inert revocation endpoint.

---

## 7. Confidence and provenance

Every atproto-crates claim in this document traces to a line that an area agent read in this worktree
and that the Phase 4 citation audit re-opened. The audit logs record **576 CONFIRMED, 57 DRIFTED
(line numbers corrected in place), 15 WRONG (claims corrected or downgraded in place), 0
UNRESOLVABLE** across the four audit passes. This synthesis inherits every correction: notably the
`refreshSession` reference behaviour (the check is in the handler, not the verifier), the
`importRepo` historical-key credit (downgraded to design-not-behaviour because the verifier is never
constructed), the takedown-enforcement framing (PARTIAL with two paths genuinely gated, not absent),
the rate-limiting framing (coverage and key choice, not absence), and the spaces read-authorization
scoping (shared with the reference draft, not atproto-crates-specific).

Findings marked "executed" — F-REPO-01, F-REPO-02, F-REPO-03, F-REPO-04, F-REPO-05 — were reproduced
by compiling against `crates/atproto-repo` and `crates/atproto-dasl` from this worktree and printing
actual bytes and CIDs. Everything else is source-read against the canonical lexicons under
`/tmp/gap-scratch/atproto/lexicons/` and the reference implementation under
`/tmp/gap-scratch/atproto/packages/`.

**Where the evidence is thin, stated rather than rounded up.** No finding in this report has been
reproduced against a running instance: the DID-squatting path, the OAuth takeover chain, the
firehose rejection by a live relay, and the cross-tenant space read are all verified line by line in
source with no live request issued. tranquil-pds and metalbear read as `?` across most of the repo
area for structural reasons — their MST, commit and CBOR code lives in un-vendored dependencies
(`jacquard-repo`/`jacquard-common` 0.9 and an external Wolfram library respectively) — so "atproto-crates
is behind the field on MST encoding" rests on nine columns, not eleven. cocoon's pinned indigo
revision differs from the one read locally. And the serde_json citations behind F-FIRE-04 were read in
registry version 1.0.151 while `Cargo.lock` pins 1.0.149.

**Cross-links:** [README](./README.md) · [inventory](./00-atproto-crates-inventory.md) ·
[coverage matrix](./20-coverage-matrix.md) ·
[A. accounts](./capability-areas/21-accounts.md) · [B. repo](./capability-areas/22-repo.md) ·
[C. records](./capability-areas/23-records.md) · [D. identity](./capability-areas/24-identity.md) ·
[E. firehose](./capability-areas/25-firehose.md) · [F. sync](./capability-areas/26-sync.md) ·
[G. OAuth](./capability-areas/27-oauth.md) · [H. service auth](./capability-areas/28-service-auth.md) ·
[I. blobs](./capability-areas/29-blobs.md) ·
[J. moderation](./capability-areas/30-moderation-admin.md) ·
[K. migration](./capability-areas/31-migration.md) · [L. ops](./capability-areas/32-ops.md) ·
[permissioned overview](./permissioned/40-permissioned-overview.md) ·
[contrail](./permissioned/41-contrail.md) · [HappyView](./permissioned/42-happyview.md) ·
[stratos](./permissioned/43-stratos.md) · [impl-notes](./impl-notes/)
