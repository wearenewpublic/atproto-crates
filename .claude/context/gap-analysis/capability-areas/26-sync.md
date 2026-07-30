# F. Sync 1.1 — inductive firehose, host status, and the `com.atproto.sync.*` read surface

Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
and the [synthesis and roadmap](../50-synthesis-and-roadmap.md).

## Assessment

Sync 1.1 is the contract that lets a relay validate a repository without storing it. It replaced
"trust the PDS and re-download whenever anything looks wrong" with an inductive scheme: every
`#commit` frame carries `prevData` (the MST root of the prior commit), a per-op `prev` (the pre-image
record CID for updates and deletes), and a CAR slice in the `blocks` field holding enough MST nodes
to *invert* each operation and recompute the prior root. If the recomputed root equals `prevData`,
the consumer has proved the commit follows from a state it already trusts, using only the bytes in
the frame. The `#sync` event covers what induction cannot — activation, import, key rotation — with a
one-block CAR of the commit so a consumer can re-anchor. The read surface (`getRepo`, `getBlocks`,
`getRecord`, `getLatestCommit`, `getRepoStatus`, `listRepos`, `getBlob`, `listBlobs`) is the repair
path. All of it is checked against `/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/` and the
reference behaviour in `/tmp/gap-scratch/atproto/packages/pds/src/`.

atproto-crates has the *data model* for Sync 1.1 and almost none of the *wire format*. The commit
object carries `prevData` correctly — `Commit.prev_data` at `crates/atproto-repo/src/repo/commit.rs:56-57`,
populated from the previous commit's `data_cid` at `crates/atproto-pds/src/repo/writer.rs:509-512`
and threaded into `UnsignedCommit::new_with_prev_data` at `writer.rs:664-670`. Per-op `prev` is
modelled exactly to the lexicon — `ops_with_prev_cids` at `crates/atproto-repo/src/mst/diff.rs:183-211`
emits `prev` for update and delete and omits it for create, which is precisely what
`subscribeRepos.json#repoOp` requires. And then the `#commit` payload
(`crates/atproto-pds/src/repo/writer.rs:722-730`) is a JSON object with seven keys —
`did`, `rev`, `commit`, `data`, `prev`, `prevData`, `ops` — and no `blocks` field of any kind. There
is no CAR slice. There is no covering-proof machinery anywhere in the workspace; grepping
`crates/atproto-repo/src` and `crates/atproto-pds/src` for `covering`/`proof` returns only DPoP
proof-of-possession code and unrelated doc comments. The frame encoder then nests the whole payload
under a `payload` key (`crates/atproto-pds/src/sequencer/frame.rs:116-121`), so no event body matches
its lexicon def even before the missing fields are counted.

**This is the one place where atproto-crates sits below every other implementation in the study,
including the two that are not trying to be general-purpose servers.** Emitting a CAR slice on
`#commit` is universal: the reference builds it in `packages/pds/src/sequencer/events.ts:23-30`;
alteran — the hobby-experiment tier — builds one at `/tmp/gap-scratch/alteran/src/services/car.ts:171-258`;
cirrus — single-user tier — unions `newBlocks` and `relevantBlocks` before `blocksToCarFile` at
`/tmp/gap-scratch/cirrus/packages/pds/src/sequencer.ts:165-173`; dnproto — single-user, in C# — writes
commit, MST path and record blocks root-first at `/tmp/gap-scratch/dnproto/src/pds/UserRepo.cs:291-295`.
Twelve implementations, eleven emit repo blocks on the firehose. Covering proofs specifically are
weaker across the field — arroba, tranquil-pds, rsky-pds, pegasus, zds and cirrus construct them
deliberately, while cocoon, metalbear and dnproto ship a diff or a root-to-leaf path that is not
provably sufficient, and alteran ships none — but "the proof set may be short a block" is a different
class of problem from "there are no blocks." A relay pointed at an atproto-crates PDS today learns
that a commit happened and learns nothing about what changed.

The read surface is the better half of the story, and it is genuinely mixed rather than uniformly
weak. `getRepo` with a working `since` diff export (`crates/atproto-pds/src/http/handlers.rs:215-226`
→ `crates/atproto-pds/src/repo/car_export.rs:362-450`) puts atproto-crates ahead of cocoon, cirrus,
alteran and dnproto, all of which accept `since` and ignore it. `getRepoStatus`
(`crates/atproto-pds/src/repo/reader.rs:400-429`) returns `did`, `active`, `status` *and* the optional
`rev`, which is more of the lexicon shape than arroba, cirrus, alteran or dnproto manage — dnproto's
returns the *service* DID. But `com.atproto.sync.listRepos` is not routed at all, and every single
one of the other eleven implementations routes it; the query is already written
(`list_account_dids`, `crates/atproto-pds/src/http/subscribe_handlers.rs:212-216`) and simply not
exposed. `com.atproto.sync.getRecord` is likewise absent where ten of eleven have it. And none of the
sync read endpoints check account state, so a taken-down repo is fully exportable — the reference
gates all seven of its sync handlers through `assertRepoAvailability`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/sync/util.ts:6-36`).

Two things in the task brief turn out to be non-gaps, and it is worth saying so plainly.
`com.atproto.sync.getHostStatus` and the `hostStatus` value set (`active`/`idle`/`offline`/`throttled`/
`banned`, `sync/defs.json`) are relay-side: the lexicon says "Implemented by relays"
(`sync/getHostStatus.json`), the reference PDS does not serve it (`grep getHostStatus`
over `/tmp/gap-scratch/atproto/packages/pds/src` returns nothing), and no implementation in this
study serves it. Not serving it is correct, not a gap. `listReposByCollection` is a real PDS-side
method, but the reference PDS does not implement it either and exactly one of the eleven
comparisons does — metalbear, at `/tmp/gap-scratch/metalbear/src/server.c:6724` with the handler at
`:5604`. Its absence from atproto-crates is a stable-gap, not an RC blocker, and it is unfair to
frame it otherwise.

---

## Capability analysis

### `prevData` on commits — PARTIAL

The value is computed correctly. `apply_writes_dispatch` reads the prior commit through
`backend.commit_obj.latest(did)` and captures `row.data_cid` as `prev_data_cid`
(`crates/atproto-pds/src/repo/writer.rs:509-512`); it is parsed and passed to
`UnsignedCommit::new_with_prev_data` (`writer.rs:661-670`), lands in the signed commit object
(`crates/atproto-repo/src/repo/commit.rs:56-57`, `#[serde(rename = "prevData")]`), and is persisted in
`commit_obj.prev_data_cid` (`crates/atproto-pds/migrations/actor/20260501000001_init.sql:10-20`). So
a consumer that fetches the commit block out of band gets a spec-shaped `prevData`.

On the wire it degrades. The firehose payload carries `"prevData": commit_row.prev_data_cid`
(`writer.rs:722-730`), an `Option<String>`, which the frame encoder round-trips through
`serde_json::Value` and re-encodes as a DAG-CBOR **text string**
(`crates/atproto-pds/src/sequencer/frame.rs:115-121`). The lexicon types `prevData` as `cid-link`,
which on the CBOR wire is tag 42 with an identity-multibase prefix. A consumer decoding the frame
with a lexicon-aware CBOR reader gets a type error, not a CID. The same applies to `commit`, which
the lexicon also types `cid-link`. The code itself flags the round-trip as lossy at `frame.rs:107-114`.

Comparison: reference emits `prevData` as a proper cid-link
(`packages/pds/src/sequencer/events.ts:32`, `packages/pds/src/actor-store/repo/transactor.ts:159,184`).
tranquil-pds (`crates/tranquil-pds/src/sync/frame.rs:44-45`), cocoon (`server/repo.go:554`, tested at
`server/firehose_sync_test.go:84-120`), rsky-pds, metalbear, pegasus (`repository.ml:404`),
zds (`store.zig:2094`), cirrus (`sequencer.ts:181`) and dnproto (`UserRepo.cs:330,353-357` — explicitly
re-typed as CBOR tag 42) all emit it typed correctly.

### Per-op `prev` — PARTIAL

`ops_with_prev_cids` (`crates/atproto-repo/src/mst/diff.rs:183-211`) is a faithful reading of
`#repoOp`: `Add → {action: create, cid: Some, prev: None}`, `Update → {cid: Some(new), prev: Some(old)}`,
`Delete → {cid: None, prev: Some(old)}`. This is better than cocoon, which sets `prev` only on
deletes and omits it on updates (`/tmp/gap-scratch/cocoon/server/repo.go:465-470,479-486`), and better
than dnproto, which omits it on updates entirely (`/tmp/gap-scratch/dnproto/src/pds/UserRepo.cs:166-171`).

The divergence is in serialization. `RepoOp.cid` carries
`#[serde(skip_serializing_if = "Option::is_none")]` (`diff.rs:170-171`), so a delete op emits
`{"action":"delete","path":"…","prev":"…"}` with no `cid` key. `subscribeRepos.json#repoOp` lists
`cid` in `required` and separately in `nullable` — the key must be present with a null value.
Omitting a required key fails lexicon validation on every delete.

### Covering-proof blocks in the CAR slice — MISSING

There is no CAR slice, and there is no proof construction. The `#commit` payload
(`crates/atproto-pds/src/repo/writer.rs:722-730` on the dispatch path, `:448-456` on the legacy path)
has no `blocks` key. `crates/atproto-repo/src/mst/` contains `key.rs`, `node.rs`, `entry.rs`,
`tree.rs`, `serialize.rs` and `diff.rs`; none has an analogue of the reference's
`MST.getCoveringProof` / `proofForKey` / `proofForLeftSib` / `proofForRightSib`
(`/tmp/gap-scratch/atproto/packages/repo/src/mst/mst.ts:784-830`), which the reference invokes once
per write and merges into `relevantBlocks` (`packages/repo/src/repo.ts:145-152`) before
`blocksToCarFile` (`packages/pds/src/sequencer/events.ts:23-30`).

The only inductive code in the workspace is a *verifier*, `verify_inductive`
(`crates/atproto-repo/src/repo/inductive.rs:79-158`), used on the import path
(`crates/atproto-pds/src/repo/import.rs:232-233`). It is not a Sync 1.1 verifier either: it walks the
new MST from `new_root` and, when a referenced block is missing from the slice, accepts it "on faith"
so long as `prev_data` is `Some` (`inductive.rs:114-135`). It never reconstructs the pre-image tree
and never compares a recomputed root against `prev_data`, which is the entire point of induction.
Contrast zat's `verifyCommitDiff`, which does compare and raises `PrevDataMismatch`
(`/tmp/gap-scratch/zat/src/internal/repo/repo.zig:401`, error at `:474`); the accompanying
`/tmp/gap-scratch/zat/REPORT-mst-inversion-prevdata.md` shows exactly why the comparison matters —
an MST delete that left an emptied subtree in place produced a valid-looking commit whose inversion
did not reproduce `prevData`, and the downstream relay dropped 1.5 M frames before anyone noticed.
That report is also a warning for atproto-crates specifically: the MST write path here is flat
(`key_height` computed and discarded at `crates/atproto-repo/src/mst/tree.rs:236`; `insert_recursive`
never recurses), so root CIDs already diverge from the reference for any key set containing a
height ≥ 1 key. Covering proofs cannot be correct on top of a tree whose roots are wrong.

Field comparison, ordered by strength: arroba is the benchmark — `MST.add_covering_proofs`
(`/tmp/gap-scratch/arroba/arroba/mst.py:871-949`) implements the proposal-0006 inversion proof set
including left- and right-neighbour spine walks, and passes the vendored upstream
`atproto-interop-tests` commit-proof fixtures in CI
(`/tmp/gap-scratch/arroba/arroba/tests/test_testdata.py:44-96`). tranquil-pds runs an inverse-op walk
over the new MST and warns when the proof would be short
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/repo_ops.rs:584-618`), then merges write-set,
read-set and diff blocks (`:628-649`, `:766-768`). pegasus computes `Cached_mst.proof_for_keys` per
touched path (`/tmp/gap-scratch/pegasus/pegasus/lib/repository.ml:386-398`). rsky-pds and zds build
proof-shaped sets by construction; cirrus gets it free by unioning `@atproto/repo`'s
`relevantBlocks`. cocoon ships the MST write-diff with no explicit proof step
(`/tmp/gap-scratch/cocoon/server/repo.go:448-503`), metalbear a `repo_rev > since` window that its own
analysis says can be short a block, dnproto the root-to-leaf path with no siblings. alteran ships
`getUnstoredBlocks()` — newly created nodes only — and concedes a relay will be missing blocks.

### No-op update rejection — MISSING

Neither rejected nor suppressed. In `apply_writes_dispatch`, the `Create | Update` arm computes the
new record CID, compares nothing against `prior_value`, and pushes an `MstDiff::Update` whenever a
prior value existed (`crates/atproto-pds/src/repo/writer.rs:557-600`). Grepping
`crates/atproto-pds/src/repo/` and `crates/atproto-repo/src/` for `no-op|noop|no_op` returns nothing.
A `putRecord` of byte-identical content mints a fresh TID `rev`, signs a new commit, writes an outbox
row and emits a frame.

This is a quality gap rather than a hard lexicon violation — `subscribeRepos.json#commit` states
"empty commits are allowed" — but it is the behaviour that generates the churn relays complain about,
and the field is split. The reference short-circuits explicitly
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/putRecord.ts:130-136`, returning
`commit: null`), as do tranquil-pds
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/repo/record/write.rs:387-394`), rsky-pds and
alteran (`/tmp/gap-scratch/alteran/src/services/repo-manager.ts:242-258`). arroba omits the op but
still emits a commit (`/tmp/gap-scratch/arroba/arroba/storage.py:596-605`). cocoon, metalbear,
pegasus, zds, cirrus and dnproto do not check at all — atproto-crates is in the majority, which is
why this is a stable-gap and not a blocker.

### The `#sync` event — DIVERGENT

`#sync` exists as an event type (`crates/atproto-pds/src/sequencer/outbox.rs:14-25`) and has a
publisher (`crates/atproto-pds/src/sequencer/sync_event.rs:47`, `:58`). Two problems.

First, the payload shape. `encode_payload` emits `{did, rev, head, blocks}` where `blocks` is a
`usize` block count (`sync_event.rs:67-73`); the module doc says so outright at `:26-38`. The lexicon
requires `blocks` to be a CARv1 byte string (≤ 10 000 bytes) whose header names the commit block as
first root, plus `seq` and `time` in the body. Nothing here is a CAR, and `head` is not a lexicon
field. Reference: `formatSeqSyncEvt` calls `blocksToCarFile(data.cid, data.blocks)`
(`packages/pds/src/sequencer/events.ts:47-63`). cocoon builds a single-block CAR rooted at the signed
commit (`/tmp/gap-scratch/cocoon/server/repo_sync.go:19-43`); tranquil-pds does the same
(`crates/tranquil-pds/src/sync/util.rs:331-363`); dnproto uses `GenerateFrameWithBlocks`
(`src/pds/Pds.cs:328-341`); cirrus matches the required set exactly
(`packages/pds/src/sequencer.ts:262`). zds emits a real CAR but roots it at the MST data CID rather
than the commit CID (`store.zig:5666-5669`) — wrong, but recoverable. Only alteran is in the same
category as atproto-crates: its `#sync` is a duplicate of `#account` carrying neither `blocks` nor
`rev` (`/tmp/gap-scratch/alteran/src/lib/firehose/frames.ts:162-168`).

Second, the call sites. `publish_sync` / `publish_sync_via_backend` are invoked from exactly two
places: after a CAR import (`crates/atproto-pds/src/repo/import.rs:332-336`) and from the
project-defined `com.atproto.admin.forceRepoSync` (`crates/atproto-pds/src/admin/handlers.rs:1009,1013`).
Account creation and `activateAccount` emit nothing. The reference emits `#sync` atomically inside
`sequenceAccountCreation` and `sequenceAccountActivation`
(`packages/pds/src/sequencer/sequencer.ts:199-224`); tranquil-pds at provisioning and activation;
cocoon at creation and activation; rsky-pds, metalbear, zds, cirrus and dnproto at activation;
pegasus at creation; arroba at repo create. Emitting on import is the one call site *not* shared by
most of the field — the coverage here is inverted relative to everyone else, and an account that
signs up on an atproto-crates PDS never announces a re-anchor point.

### Host status values and `getHostStatus` — OUT-OF-SCOPE

`com.atproto.sync.defs#hostStatus` (`active`/`idle`/`offline`/`throttled`/`banned`) describes an
*upstream host as seen by a relay*. `getHostStatus.json` states "Implemented by relays" and takes a
`hostname`, not a DID. The reference PDS does not implement it; neither does any of the eleven
comparisons. Not routing it is the correct decision and needs no remediation.

The related-but-distinct question is the *account* status vocabulary shared by `getRepoStatus`,
`listRepos` and `#account`: `takendown`/`suspended`/`deleted`/`deactivated`/`desynchronized`/`throttled`.
atproto-crates models five of six — `AccountState` at `crates/atproto-pds/src/account/state.rs:14-27`
covers `active`, `deactivated`, `takendown`, `suspended`, `deleted` — and has no producer for
`desynchronized` or `throttled`. Neither does the reference PDS, and pegasus explicitly notes the same
(`sequencer.ml:58-72`, "no writer for any of them"). Not a gap. What atproto-crates does have that
several peers lack is a real `takendown`/`suspended` distinction rather than collapsing everything to
`deactivated` — arroba (`xrpc_sync.py:70-87`), cocoon (`models/models.go:58-64`) and metalbear
(`server.c:2809`) can only ever report `deactivated`.

### `listReposByCollection` — MISSING (stable-gap)

Not routed (`crates/atproto-pds/src/http/router.rs` has no such literal; confirmed against the
not-routed sweep in the endpoint inventory). The lexicon carries no relay-only qualifier and the
method is the sanctioned way for a consumer to backfill one collection without walking every repo.
But the reference PDS does not serve it, and only metalbear does among the eleven
(`/tmp/gap-scratch/metalbear/src/server.c:6724`, handler `:5604-5620`). tranquil-pds, cocoon, rsky-pds,
pegasus, zds, arroba, cirrus, alteran and dnproto all lack it, and several of their own notes call it
out as a genuine gap. atproto-crates is in the majority; this is a stable-gap.

### The `com.atproto.sync.*` read surface

| NSID | atproto-crates | Evidence / divergence |
|---|---|---|
| `getRepo` | routed, real, `since` works | `router.rs:83` → `handlers.rs:186-231`; diff at `car_export.rs:362-450`. No account-state gate. Fully buffered in RAM, no size ceiling. |
| `getLatestCommit` | routed, real | `router.rs:76` → `reader.rs:380-395`. No account-state gate. |
| `getRepoStatus` | routed, real, full shape | `router.rs:80` → `reader.rs:400-429`. Emits `did`/`active`/`status`/`rev`. |
| `getBlocks` | routed, DIVERGENT param | `router.rs:85` → `handlers.rs:241,254-259`. `cids` is a lexicon array; handler declares `String` and splits on `,`, so canonical `?cids=a&cids=b` fails. |
| `getBlob` | routed, real | `router.rs:89` → `blob_handlers.rs:33-72`. No account-state gate; MIME echoed verbatim from upload. |
| `listBlobs` | routed, PARTIAL | `router.rs:93` → `blob_handlers.rs:76-83`. `since` (tid) is not modelled, so incremental blob sync is impossible. |
| `listRepos` | **not routed** | Query already exists at `subscribe_handlers.rs:212-216`. |
| `getRecord` | **not routed** | No proof-CAR read path exists. |
| `listReposByCollection` | **not routed** | See above. |
| `getHostStatus` / `listHosts` | not routed | Correct — relay-side. |
| `requestCrawl` | routed, DIVERGENT | `router.rs:103` → `handlers.rs:317-365`; see below. |
| `notifyOfUpdate` | not routed | Relay-side; tranquil-pds and zds stub it, others omit it. |
| `subscribeRepos` | routed, real transport | `router.rs:97` → `subscribe_handlers.rs:56`. Adds non-lexicon `did` and `encoding` params (additive, harmless). |
| `getCheckout` / `getHead` | not routed | Deprecated upstream. Not a gap. |

`requestCrawl` deserves its own note. The lexicon is *inbound* — a peer asks this service to crawl
the named hostname. `handlers.rs:317-365` instead fans **out**, POSTing `requestCrawl` to every entry
in `state.crawlers` and returning 200 unconditionally. A relay that calls this endpoint gets a 200
and is never registered. metalbear has the identical inversion
(`/tmp/gap-scratch/metalbear/src/server.c:6947`, forwarder at `:4925-5008`), so atproto-crates is not
alone; tranquil-pds and zds route the NSID as a 200-returning no-op stub, which is wrong but inert.
The reference keeps the outbound announcer as a private `Crawlers` class
(`/tmp/gap-scratch/atproto/packages/pds/src/crawlers.ts:29-44`) and does not route the NSID at all.

The second half of that finding is worse than the first. `state.crawlers` is referenced by nothing
except the `requestCrawl` handler (`grep crawlers crates/atproto-pds/src` → `bin/pds.rs:251,595`,
`http/state.rs:110,152,195,355-356`, `http/handlers.rs:307,331,340`). There is no automatic
announcement on write. The reference calls `this.crawlers.notifyOfUpdate()` inside `sequenceEvts`
(`packages/pds/src/sequencer/sequencer.ts:170`), throttled to 20 minutes. cocoon announces on boot and
on subscriber disconnect (`server/server.go:631-635`, `handle_sync_subscribe_repos.go:145`); metalbear
on every write, throttled; pegasus every 20 minutes on publish (`sequencer.ml:461,490-505`);
tranquil-pds via `crawlers.rs:96-108`; alteran and dnproto via background jobs. An atproto-crates PDS
never tells a relay it exists unless an operator manually POSTs to its own endpoint.

### Availability gating on sync reads — DIVERGENT (moderation bypass)

`repo.getRecord` and `repo.listRecords` call `require_public_read`
(`crates/atproto-pds/src/repo/reader.rs:107`, `:209`, definition at `:510-518`). None of the sync read
paths do: `get_repo` (`handlers.rs:186-231`) resolves the handle and exports; `get_latest_commit`
(`reader.rs:380-395`) queries `commit_obj` directly; `get_blocks` (`handlers.rs:245-290`),
`get_blob` (`blob_handlers.rs:33-72`) and `list_blobs` (`blob_handlers.rs:96`) likewise. The
consequence is that `com.atproto.sync.getRepo` on a `takendown` account returns the complete
repository, and the `RepoTakendown` / `RepoSuspended` / `RepoDeactivated` errors declared in
`getRepo.json`, `getBlocks.json`, `getBlob.json`, `listBlobs.json` and `getLatestCommit.json` can
never be raised. The reference routes all seven through `assertRepoAvailability`
(`packages/pds/src/api/com/atproto/sync/util.ts:6-36`), which also carries the admin-or-self bypass.
rsky-pds gates blob reads (`actor_store/blob/mod.rs:91,107-115`) and zds gates `getBlob` on takedown.
This is a genuine moderation-enforcement hole, not a cosmetic one — the takedown state is written
and displayed but does not restrain the highest-bandwidth read path on the server.

---

## Findings

1. **`#commit` frames carry no `blocks` CAR slice.** — CLASS: MISSING — **rc-blocker**.
   Evidence: `crates/atproto-pds/src/repo/writer.rs:722-730` (dispatch) and `:448-456` (legacy) build
   the payload with no `blocks` key; `crates/atproto-pds/src/sequencer/frame.rs:116-121` encodes only
   what the payload contains. Comparison: all eleven others emit repo blocks — reference
   `packages/pds/src/sequencer/events.ts:23-30`, and even alteran (`src/services/car.ts:171-258`) and
   dnproto (`src/pds/UserRepo.cs:291-295`). Consequence: no relay, AppView or mirror can ingest a
   single record from this firehose. The stream is an existence notification, not a data feed.

2. **No covering-proof construction exists.** — CLASS: MISSING — **rc-blocker**.
   Evidence: no proof symbol anywhere in `crates/atproto-repo/src/mst/` or
   `crates/atproto-pds/src/repo/`; the only inductive code is the import-side verifier
   `crates/atproto-repo/src/repo/inductive.rs:79-158`, which accepts missing blocks on faith at
   `:114-135` and never recomputes a pre-image root. Comparison: arroba
   `/tmp/gap-scratch/arroba/arroba/mst.py:871-949` with upstream interop fixtures passing in CI;
   reference `packages/repo/src/mst/mst.ts:784-830` + `packages/repo/src/repo.ts:145-152`;
   tranquil-pds `repo_ops.rs:584-649`; pegasus `repository.ml:386-398`. Consequence: even after
   finding 1 is fixed by shipping a naive diff, inductive consumers will reject frames. Compounded by
   the flat-MST defect (`crates/atproto-repo/src/mst/tree.rs:236`), which makes the root CIDs wrong
   in the first place — see the [inventory](../00-atproto-crates-inventory.md).

3. **`#sync.blocks` is a block-count integer, not a CARv1.** — CLASS: DIVERGENT — **rc-blocker**.
   Evidence: `crates/atproto-pds/src/sequencer/sync_event.rs:67-73`, acknowledged in the module doc at
   `:26-38`. Comparison: reference `packages/pds/src/sequencer/events.ts:47-63`; cocoon
   `server/repo_sync.go:19-43`; tranquil-pds `sync/util.rs:331-363`; cirrus `sequencer.ts:262`.
   Consequence: the one recovery mechanism Sync 1.1 provides for broken commit streams cannot be
   applied by any conformant consumer.

4. **Firehose event bodies are nested under a `payload` key and omit lexicon-required fields.** —
   CLASS: DIVERGENT — **rc-blocker**.
   Evidence: `crates/atproto-pds/src/sequencer/frame.rs:116-121` emits
   `{seq, repo, time, payload: {...}}`; `#commit` requires `seq`, `rebase`, `tooBig`, `repo`, `commit`,
   `rev`, `since`, `blocks`, `ops`, `blobs`, `time` at the top level. `since` is absent entirely
   (the payload carries `prev`/`prevData` instead). Comparison: every implementation in the study
   emits a flat body; even arroba's one gap here is a null `since` (`firehose.py:416`), not a
   restructured envelope. Consequence: no event body validates against its lexicon def.

5. **`prevData` and `commit` are emitted as CBOR text strings, not `cid-link`.** — CLASS: DIVERGENT —
   **rc-blocker** (subsumed by finding 4 in practice, distinct in fix).
   Evidence: `crates/atproto-pds/src/repo/writer.rs:722-730` stores `.to_string()` forms; the JSON →
   `serde_json::Value` → DAG-CBOR round trip at `frame.rs:115-121` cannot produce tag 42, and the code
   says so at `:107-114`. Comparison: dnproto explicitly re-types CIDs to tag 42 before emitting
   (`src/pds/UserRepo.cs:353-357`). Consequence: even a flattened body decodes to the wrong types.

6. **`com.atproto.sync.listRepos` is not routed.** — CLASS: MISSING — **rc-blocker**.
   Evidence: absent from `crates/atproto-pds/src/http/router.rs`; the enumeration already exists as
   `list_account_dids` (`crates/atproto-pds/src/http/subscribe_handlers.rs:212-216`). Comparison:
   **all eleven** others route it — reference `packages/pds/src/api/com/atproto/sync/listRepos.ts:8`,
   arroba `xrpc_sync.py:90`, metalbear `server.c:6722`, pegasus `bin/main.ml:232`, zds `router.zig:202`,
   cirrus `index.ts:204`, alteran `index.js:58`, dnproto `Pds.cs:209`, plus tranquil-pds, cocoon,
   rsky-pds. Consequence: a relay cannot discover which accounts this server hosts. Lowest
   effort-to-value fix in this chapter.

7. **Sync read endpoints do not enforce account state.** — CLASS: DIVERGENT — **rc-blocker**
   (moderation enforcement, security-adjacent).
   Evidence: `crates/atproto-pds/src/http/handlers.rs:186-231` (`getRepo`), `:245-290` (`getBlocks`),
   `crates/atproto-pds/src/repo/reader.rs:380-395` (`getLatestCommit`),
   `crates/atproto-pds/src/http/blob_handlers.rs:33-72` (`getBlob`), `:96` (`listBlobs`) — none calls
   `require_public_read` (`reader.rs:510-518`), which the repo read paths do use at `reader.rs:107,209`.
   Comparison: reference gates all seven sync handlers through `assertRepoAvailability`
   (`packages/pds/src/api/com/atproto/sync/util.ts:6-36`; call sites in `getRepo.ts:34`,
   `getBlocks.ts:19`, `getBlob.ts:20`, `listBlobs.ts:18`, `getLatestCommit.ts:16`,
   `getRepoStatus.ts:11`, `getRecord.ts:20`). Consequence: a taken-down repository is fully
   exportable by any anonymous caller, and the three declared takedown errors
   (`RepoTakendown`/`RepoSuspended`/`RepoDeactivated`) are unreachable on all five sync read
   endpoints that declare them.

8. **`com.atproto.sync.getRecord` is not routed.** — CLASS: MISSING — **stable-gap**.
   Evidence: absent from `crates/atproto-pds/src/http/router.rs`; no proof-CAR read path exists in
   `crates/atproto-pds/src/repo/car_export.rs`. Comparison: ten of eleven serve it — arroba with real
   covering proofs (`xrpc_sync.py:211-230`), reference, tranquil-pds, cocoon, rsky-pds, metalbear,
   pegasus, cirrus, alteran, dnproto (broken but present); only zds omits it. Consequence: a consumer
   cannot fetch an existence/non-existence proof for a single record and must pull the whole repo.

9. **`#sync` is never emitted on account creation or activation.** — CLASS: PARTIAL — **stable-gap**.
   Evidence: `publish_sync` call sites are `crates/atproto-pds/src/repo/import.rs:332-336` and
   `crates/atproto-pds/src/admin/handlers.rs:1009,1013` only; `createAccount`
   (`http/auth_handlers.rs:81`) and `activateAccount` (`:677`) emit nothing.
   Comparison: reference `packages/pds/src/sequencer/sequencer.ts:199-224`; tranquil-pds
   `identity/provision.rs:198-206` + `server/account_status.rs:462-470`; cocoon
   `handle_server_create_account.go:253` + `handle_server_activate_account.go:54`; rsky-pds
   `activate_account.rs:46-52`; metalbear `sequencer.c:210-238`; zds `server.zig:965`; cirrus
   `account-do.ts:1321`; dnproto `Pds.cs:328-341`; pegasus `createAccount.ml:128-130`.
   Consequence: newly created and newly activated accounts give consumers no re-anchor point.

10. **`#repoOp.cid` is omitted on deletes instead of emitted as null.** — CLASS: DIVERGENT —
    **stable-gap**. Evidence: `crates/atproto-repo/src/mst/diff.rs:170-171`
    (`skip_serializing_if = "Option::is_none"`) against `subscribeRepos.json#repoOp`, which lists
    `cid` in `required` and in `nullable`. Consequence: every delete op fails strict lexicon
    validation. One-line fix.

11. **No-op updates are neither rejected nor suppressed.** — CLASS: MISSING — **stable-gap**.
    Evidence: `crates/atproto-pds/src/repo/writer.rs:557-600` never compares the new record CID to
    `prior_value`; no `no-op` guard anywhere in `crates/atproto-pds/src/repo/`. Comparison: reference
    `packages/pds/src/api/com/atproto/repo/putRecord.ts:130-136`; tranquil-pds
    `crates/tranquil-api/src/repo/record/write.rs:387-394`; alteran `services/repo-manager.ts:242-258`;
    rsky-pds. Not done by cocoon, metalbear, pegasus, zds, cirrus, dnproto; arroba omits the op but
    still commits. Consequence: redundant writes churn the firehose and the MST. Permitted by the
    lexicon ("empty commits are allowed"), hence not a blocker.

12. **`com.atproto.sync.requestCrawl` is mounted as an outbound announcer, and nothing announces
    automatically.** — CLASS: DIVERGENT — **stable-gap**.
    Evidence: `crates/atproto-pds/src/http/handlers.rs:317-365` fans out to `state.crawlers` and always
    returns 200; `hostname` is optional where the lexicon requires it; `state.crawlers` has no other
    consumer (`http/state.rs:110,355-356`). Comparison: reference keeps the announcer private
    (`packages/pds/src/crawlers.ts:29-44`) and fires it from `sequenceEvts`
    (`packages/pds/src/sequencer/sequencer.ts:170`); metalbear has the identical NSID inversion
    (`server.c:6947`, `:4925-5008`). Consequence: relays calling the canonical method are silently
    dropped, and a fresh deployment never registers itself.

13. **`com.atproto.sync.getBlocks` parses `cids` as a comma-separated string.** — CLASS: DIVERGENT —
    **stable-gap**. Evidence: `crates/atproto-pds/src/http/handlers.rs:241` declares `cids: String`,
    split at `:254-259`. The lexicon types `cids` as an array, which the XRPC HTTP binding encodes as
    repeated query params. Consequence: `?cids=a&cids=b` from any canonical client yields only the
    last value; `?cids=a,b` is required instead.

14. **`com.atproto.sync.listBlobs` does not model `since`.** — CLASS: MISSING — **cosmetic**.
    Evidence: `ListBlobsQuery` at `crates/atproto-pds/src/http/blob_handlers.rs:76-83` has only
    `did`/`cursor`/`limit`. Comparison: the reference implements it, but cocoon
    (`handle_sync_list_blobs.go:25`), metalbear (`server.c:2829-2831`), cirrus, alteran and dnproto all
    accept and ignore it, and arroba raises on it (`xrpc_sync.py:263-264`). Consequence: incremental
    blob reconciliation during migration falls back to a full listing. Weak across the field, so
    cosmetic here.

15. **`com.atproto.sync.listReposByCollection` is not routed.** — CLASS: MISSING — **stable-gap**.
    Evidence: absent from `crates/atproto-pds/src/http/router.rs`. Comparison: only metalbear serves
    it (`server.c:6724`, `:5604`); the reference PDS does not. Consequence: collection-scoped backfill
    requires walking every repo. Genuinely low priority given the field.

16. **`com.atproto.sync.getHostStatus`, `listHosts` and `notifyOfUpdate` are not routed.** —
    CLASS: OUT-OF-SCOPE — not a gap. `getHostStatus.json` and `listHosts.json` say "Implemented by
    relays"; the reference PDS serves none of the three, and no comparison implementation serves
    `getHostStatus` or `listHosts`. This is the correct RC→stable decision and requires no work.

### Where atproto-crates is ahead of the independent field

Three items, all on the read surface. `getRepo` implements a real `since` diff export
(`crates/atproto-pds/src/http/handlers.rs:215-226`, `crates/atproto-pds/src/repo/car_export.rs:362-450`)
where cocoon, cirrus, alteran and dnproto accept `since` and return the full repo anyway.
`getRepoStatus` returns the complete lexicon shape including the optional `rev`
(`crates/atproto-pds/src/repo/reader.rs:419-428`) where arroba omits `rev` and collapses every status
to `deactivated`, cirrus and alteran hardcode `active: true` in `listRepos`, and dnproto returns the
service DID as the subject. And the account-status vocabulary distinguishes `takendown` from
`suspended` from `deactivated` (`crates/atproto-pds/src/account/state.rs:14-27`) where arroba, cocoon
and metalbear can only ever report `deactivated`. None of this offsets findings 1–7, but it does mean
the read half of Sync is closer to shippable than the write half.

---

## Confidence & unknowns

- **High confidence** on findings 1–6 and 9–14: each was verified by opening the cited atproto-crates
  file and the cited lexicon or reference file directly during this pass, not inherited from the
  inventory. Finding 6's field comparison was cross-checked against each project's own route
  registration line.
- **Medium confidence** on finding 7's severity framing. The gating gap is verified in source, but I
  did not read the full middleware stack outside `http/router.rs`; the router applies only the
  optional metrics layer (`router.rs:442-447`), so a middleware-level account-state gate is unlikely
  but not disproven.
- **UNVERIFIED: whether the reference's consumer would accept an atproto-crates commit if `blocks`
  were populated with a naive MST write-diff.** This needs a differential harness — build the same
  repo in both and run `/tmp/gap-scratch/atproto/packages/repo/src/sync/consumer.ts` against the
  frame. Given the flat-MST defect the roots differ regardless, so the question is currently moot.
- **UNVERIFIED: cocoon's, pegasus's and rsky-pds's `#sync` CAR contents beyond their impl-note
  citations** (`/tmp/gap-scratch/cocoon/server/repo_sync.go:19-43`,
  `pegasus/lib/sequencer.ml:236-240`, rsky `sequencer/events.rs:179`). The cocoon and tranquil-pds
  citations I spot-checked held.
- **Cross-area overlap.** Firehose sequencing — per-actor `seq` with no global sequence
  (`migrations/actor/20260501000001_init.sql:56-61`; every DID seeded with the same client cursor at
  `crates/atproto-pds/src/http/subscribe_handlers.rs:102-103`) — determines whether an inductive
  consumer can resume at all, but the transport belongs to the firehose chapter. It is not counted
  above; see the [synthesis](../50-synthesis-and-roadmap.md). The permissioned-data namespace runs
  its own commit and sync format and is out of scope here; see
  [the permissioned-data overview](../permissioned/40-permissioned-overview.md).
