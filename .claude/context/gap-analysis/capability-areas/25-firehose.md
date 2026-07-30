# E. Firehose / event stream

Part of the atproto-crates 0.15.0-rc.1 release-candidate gap analysis.
See [README](../README.md), [inventory](../00-atproto-crates-inventory.md),
[coverage matrix](../20-coverage-matrix.md),
[synthesis and roadmap](../50-synthesis-and-roadmap.md).

## Assessment

The firehose is the one interface a PDS cannot get away with approximating. Everything else a
PDS serves is a request/response the caller can retry or work around; `com.atproto.sync.subscribeRepos`
is the sole channel by which a repository's contents reach a relay, and from there every AppView.
The contract is narrow and entirely mechanical: a WebSocket where each message is one binary payload
holding two concatenated DAG-CBOR objects — a header `{op: 1, t: "#commit"}` and then a body whose
fields are exactly the ones the lexicon def names, at the body's top level, with no wrapper. The
canonical union is `#commit | #sync | #identity | #account | #info`
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json`, `main.message.schema.refs`);
`#handle`, `#migrate` and `#tombstone` are gone from that file entirely. `#commit` requires eleven
fields — `seq`, `rebase`, `tooBig`, `repo`, `commit`, `rev`, `since` (nullable), `blocks`, `ops`,
`blobs`, `time` — and `blocks` is the load-bearing one: a CARv1 of the commit block plus the MST diff
and covering proofs, capped at 2 MB, with the commit CID first in the CAR header roots. Without
`blocks` there is no data on the stream at all, only metadata about data that lives somewhere else.

atproto-crates has built the *plumbing* for this and not the *payload*. The routed handler is real
(`crates/atproto-pds/src/http/router.rs:96-99` → `crates/atproto-pds/src/http/subscribe_handlers.rs:56`),
the durable outbox is real and transactional with the commit, the two-object DAG-CBOR header framing
is byte-correct, and the live broadcast bus with a poll fallback is a sensible design. But the body
that goes inside that correct frame is a locally-invented envelope,
`{seq, repo, time, payload: {...}}` (`crates/atproto-pds/src/sequencer/frame.rs:116-122`), which
matches no member of the union. Beneath the wrapper, the `#commit` payload
(`crates/atproto-pds/src/repo/writer.rs:448-456` and the identical dispatch-path copy at `:722-730`)
is `{did, rev, commit, data, prev, prevData, ops}` — no `blocks` CAR is built anywhere for the
firehose, and the only CAR writers in the crate are wired to `getRepo`/`getBlocks`
(`crates/atproto-pds/src/http/handlers.rs:191`, `:250`). The `#sync` event's `blocks` field is an
integer block *count* rather than CAR bytes (`crates/atproto-pds/src/sequencer/sync_event.rs:68-73`),
which the source comment concedes (`sync_event.rs:26-28`). Sequence numbers are allocated per actor,
not per stream, so `seq` values repeat across repos and a single `cursor` is applied to every repo's
private counter (`crates/atproto-pds/src/http/subscribe_handlers.rs:102-103`). None of this is
exercised by a test: the crate's integration suite never opens a WebSocket
(see [ops inventory](../00-atproto-crates-inventory.md); `grep` for `subscribe` in
`crates/atproto-pds/tests/` yields only a stale doc comment).

The comparison is the harshest in this report, because there is no "only the reference does this"
defence available anywhere in the area. All eleven comparisons emit a flat, lexicon-shaped body
inside a correct two-CBOR-object frame; eleven of eleven ship a CARv1 in `#commit.blocks` (alteran's
lacks covering proofs and metalbear's is short a block in one case, but both ship one); eleven of
eleven allocate `seq` from a single monotonic source. That includes both implementations below the
"serious" line — **alteran**, an explicitly hobby-experiment Cloudflare Worker, emits all twelve
`#commit` fields including `blocks`, `since` and `prevData`
(`/tmp/gap-scratch/alteran/src/worker/sequencer/payload.ts:69-83`) and ships four firehose test
files; **cirrus**, a single-user PDS, hand-rolls `encodeFrame` correctly
(`/tmp/gap-scratch/cirrus/account-do.ts:1077-1086`), emits `FutureCursor` and `OutdatedCursor`, and
tests `prevData` on every commit. When a hobby Worker and a single-user PDS both put records on the
wire and the RC candidate does not, the gap is not a maturity difference — it is a missing feature.

The honest summary is that atproto-crates' firehose is architecturally sound and semantically
inoperative. A relay that connects to it will complete the WebSocket handshake, receive well-formed
binary frames with a valid header, and then fail to decode a single event body — `@atproto/xrpc-server`'s
`Frame.fromBytes` will hand the body to the `#commit` validator, which will reject on the first of
eight missing required fields, and indigo-based relays will find a nil `Blocks` slice with nothing to
parse. Nothing about the repository ever reaches an AppView. Everything needed to fix it exists in
the crate already — the MST diff, the block storage, the CAR writer, the atomic commit path — so this
is a wiring problem of perhaps a few hundred lines, not a rewrite. But shipping 0.15.0 stable with
this unfixed would mean shipping a PDS whose contents are invisible to the network.

## Per-capability analysis

### Frame framing: header + body concatenation — correct

The part the brief flagged as the silent killer is the part atproto-crates gets right. `encode_event`
(`crates/atproto-pds/src/sequencer/frame.rs:77-131`) serializes `FrameHeader { op: i8, t: String }`
(`frame.rs:52-57`) with `atproto_dasl::to_vec`, appends the body bytes to the same buffer
(`frame.rs:126`), and sends one `Message::Binary`
(`crates/atproto-pds/src/http/subscribe_handlers.rs:72-79`) — exactly the reference's
`Buffer.concat([encode(this.header), encode(this.body)])`
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/stream/frames.ts:21-23`), with
`FrameType.Message = 1` / `Error = -1` matching (`stream/types.ts:3-6`). No length prefix, no
JSON-in-binary, no per-object framing.

Canonical map-key ordering is also correct, by a slightly indirect route: `atproto-dasl` buffers
entries and sorts on the *encoded* key bytes (`crates/atproto-dasl/src/drisl/ser/serializer.rs:341`,
`:389`), and because a CBOR text-string header byte carries the length in its low bits below 24,
that is length-first-then-bytewise for every key in the atproto data model. The header serializes
`t` before `op`, matching `@ipld/dag-cbor`.

**No finding.** Worth stating because a byte-level error here would be invisible until a relay
silently dropped the feed.

### `#commit` body shape — DIVERGENT, the top blocker in this area

Two problems compose. The envelope first: `encode_event`'s CBOR branch builds

```rust
// crates/atproto-pds/src/sequencer/frame.rs:116-122
let body = serde_json::json!({
    "seq": seq, "repo": did, "time": time, "payload": payload_value,
});
```

so three lexicon fields land at the top level and everything else sits under a `payload` key that
appears in no lexicon. `repo` is emitted for *every* event type, but `#sync`, `#identity` and
`#account` all require `did` — the `#commit` def says so itself ("all other message types name this
field 'did'"), so those three lose their only required identity field and gain an undefined one.

Underneath, the payload is not the lexicon shape either. `RepoWriter` builds `{did, rev, commit,
data, prev, prevData, ops}` (`crates/atproto-pds/src/repo/writer.rs:448-456`, identical dispatch-path
copy at `:722-730`). Against `#commit`'s eleven required fields: `rebase`, `tooBig`, `since`,
`blocks` and `blobs` are absent, `repo` is spelled `did`, `seq` and `time` exist only in the
envelope, and two non-lexicon fields (`data`, `prev`) are added. `prevData` and per-op `prev` are
present and correctly derived — genuine Sync-1.1 work, attached to a body no consumer can parse.

Comparison: the reference builds the flat object and CBOR-encodes it at sequence time
(`/tmp/gap-scratch/atproto/packages/pds/src/sequencer/events.ts:25-37`), spreading `seq` and `time`
at emit (`subscribeRepos.ts:46-51`). tranquil has a typed `CommitFrame`
(`crates/tranquil-pds/src/sync/frame.rs:44-62`); rsky's `CommitEvt` documents *why* `prev` is `None`
and `too_big` is `false` under Sync 1.1 (`src/sequencer/events.rs:52-54`, `:254`); alteran — hobby
tier — emits the full twelve-field set (`src/worker/sequencer/payload.ts:69-83`).

**DIVERGENT — rc-blocker (Finding 1).**

### `#commit.blocks` — the CAR diff is never built — MISSING

No code path in `atproto-pds` produces a CARv1 for the firehose. `car_export` is referenced from two
HTTP read handlers only (`crates/atproto-pds/src/http/handlers.rs:191` for `getRepo`, `:250` for
`getBlocks`); the commit-write transaction (`crates/atproto-pds/src/repo/writer.rs:397-470`) inserts
the commit block into `repo_block` but assembles no CAR, and no `blocks` key exists at any nesting
level of the payload.

That is the difference between a firehose and a change-notification ping. The lexicon is explicit:
`blocks` is "CAR file containing relevant blocks, as a diff since the previous repo state. The commit
must be included as a block, and the commit block CID must be the first entry in the CAR header
'roots' list." Without it a consumer cannot learn what a record contains; it would have to issue a
`getRecord` per op, which does not scale to a relay.

Every comparison ships a CAR, and the better ones ship covering proofs: reference `blocksToCarFile`
(`events.ts:21-30`), rsky proofs plus a backfill of blocks relevant to ops but absent from the diff
(`src/actor_store/mod.rs:596-605`), tranquil an inverse-op walk that warns when the proof would be
short (`src/repo_ops.rs:584-618`), arroba proposal-0006 inversion (`arroba/mst.py:871-949`), pegasus
`proof_for_keys` (`lib/repository.ml:386-398`), zds lazily-loaded path blocks
(`src/storage/store.zig:5568-5580`). Even the weakest ship something — alteran without sibling proofs
(`src/services/car.ts:171-258`), metalbear every block since the previous rev
(`src/repo_store.c:2537-2540`), dnproto the root-to-leaf path (`src/pds/UserRepo.cs:229-238`). Those
are quality gaps in a CAR that exists.

**MISSING — rc-blocker (Finding 2).**

### JSON-then-DAG-CBOR round trip corrupts CIDs — DIVERGENT

Even setting shape aside, the storage-and-re-encode pipeline mangles CID values. Payloads are
persisted as **JSON** (`serde_json::to_vec` at `crates/atproto-pds/src/repo/writer.rs:457`,
`crates/atproto-pds/src/sequencer/sync_event.rs:74`, `crates/atproto-pds/src/account/manager.rs:383`,
`crates/atproto-pds/src/http/identity_handlers.rs:698`), then decoded to a `serde_json::Value` and
DAG-CBOR-re-encoded at send time (`crates/atproto-pds/src/sequencer/frame.rs:115-125`). The comment
at `frame.rs:107-114` concedes this is lossy for byte fields — which alone would make a `blocks` CAR
uncarryable — but the concrete damage today is to CIDs.

`atproto_dasl::Cid`'s `Serialize` impl signals tag 42 through a magic newtype variant carrying a
bytes payload (`crates/atproto-dasl/src/cid/mod.rs:106-119`, helper at `:135-142`). Against a
DAG-CBOR serializer that yields the correct `0xd8 0x2a` tag; against **serde_json** it yields
`{"": [ …bytes as numbers… ]}` — `serialize_newtype_variant` inserts the variant name (here the empty
string) as an object key (`serde_json-1.0.151/src/value/ser.rs:205-218`) and `serialize_bytes`
renders a slice as an array of numbers (`ser.rs:172-175`). `RepoOp.cid` and `RepoOp.prev` are
`Option<Cid>` (`crates/atproto-repo/src/mst/diff.rs:164-175`) flowing through the `json!` macro at
`writer.rs:448-456`, so every op CID becomes that map and the re-encode turns it into a CBOR map with
an empty-string key over an integer array — not a tag-42 cid-link. The other CIDs (`commit`, `data`,
`prev`, `prevData`) are `.to_string()`'d and arrive as text strings where `cid-link` is declared.
Smaller and related: `RepoOp.cid` is `skip_serializing_if` (`diff.rs:170-171`), but `#repoOp` lists
`cid` as required-and-nullable — a delete must emit `cid: null`, not omit the key.

The reference avoids all of this by storing `cborEncode(evt)` once (`events.ts:42`); metalbear goes
further and stores the fully framed bytes at append, so replayed frames are byte-identical to what
live subscribers saw (`src/sequencer.c:103-180`, replay at `:530-532`).

**DIVERGENT — rc-blocker (Finding 3).** Subsumed by the fix for Findings 1-2 if the sequencer is
changed to store DAG-CBOR directly.

### `seq` is per-actor, not per-stream — DIVERGENT

The lexicon has one `cursor` parameter and describes `seq` as "The stream sequence number of this
message" — one monotonic sequence per server. atproto-crates allocates per actor: SQLite
`outbox.seq INTEGER PRIMARY KEY AUTOINCREMENT` per actor database read back via
`last_insert_rowid()` (`crates/atproto-pds/src/sequencer/outbox.rs:239`,
`crates/atproto-pds/src/actor_store/sql/public_realm.rs:339`), and under fjall a read-modify-write of
`outbox_meta[<did>]` (`crates/atproto-pds/src/actor_store/fjall/public_realm.rs:390-409`). The
subscriber papers over it by fanning one client cursor across every repo:

```rust
// crates/atproto-pds/src/http/subscribe_handlers.rs:102-103
let mut cursors: BTreeMap<String, Option<i64>> =
    dids.into_iter().map(|did| (did, params.cursor)).collect();
```

A client reconnecting at `cursor=50` skips the first 50 events of *every* repo, including repos it
has never seen. `seq` values collide across repos, so the stream is not ordered by `seq` and a
consumer tracking a high-water mark goes backwards constantly. arroba's source carries the
operational lesson: emitting non-monotonic seq "breaks Bluesky's own relays for our PDS"
(`arroba/firehose.py:326-330`), and it refuses non-monotonic emission outright (`:436-443`).

Every comparison uses one source — reference `sequencer/db/schema.ts:6`, tranquil's dedicated
gapless `firehose_seq` (`migrations/20260529_firehose_outbox_sequencing.sql`), cocoon's mutex-guarded
counter (`server/persist.go:67-96`), zds' `nextSeqLocked` over `MAX(seq)`
(`src/storage/store.zig:4832`). cocoon and metalbear go further and seed from the wall clock on a
cold database so a rebuilt data directory never re-issues numbers a relay holds (`persist.go:45-56`,
`sequencer.c:240-297`) — a hazard atproto-crates has in sharper form, since a re-created actor DB
restarts that repo at 1.

**DIVERGENT — rc-blocker (Finding 4).**

### Cursor resume, `FutureCursor`, `OutdatedCursor`, `ConsumerTooSlow`

Backfill itself works: `run_subscriber` drains each DID's outbox in pages of 100
(`crates/atproto-pds/src/http/subscribe_handlers.rs:124-152`) before and between live-event waits,
over a durable outbox that survives restart. What is missing is the error vocabulary.

`FutureCursor` does not exist in the crate; a cursor beyond the head is accepted silently and yields
a stream that looks healthy and delivers nothing. `OutdatedCursor` exists only as a string in doc
comments and a unit test (`crates/atproto-pds/src/sequencer/outbox.rs:23`,
`crates/atproto-pds/src/sequencer/frame.rs:133`, `:242`, `:252`) — the single runtime
`encode_info` call sends `"InternalError"` (`subscribe_handlers.rs:94`). `ConsumerTooSlow` is absent
too: no bounded outbox, no disconnect-on-lag, the send simply awaits (`subscribe_handlers.rs:72-79`).

Fairness cuts differently per error. `FutureCursor` is implemented by the reference
(`subscribeRepos.ts:29-31`), tranquil, rsky, metalbear, cirrus and arroba — a majority including a
single-user PDS — while pegasus, zds, dnproto and alteran lack it, so atproto-crates is in a minority
but not alone. `OutdatedCursor` is emitted by seven of eleven, including the hobby tier.
`ConsumerTooSlow` is genuinely rare: only the reference (`outbox.ts:93-101`), rsky
(`sequencer/outbox.rs:120-124`) and pegasus (`sequencer.ml:507-518`) implement it; tranquil
deliberately replays the missed range from Postgres instead, and six others have no backpressure at
all. **Do not grade atproto-crates down for `ConsumerTooSlow`** — its broadcast-lag-then-poll-from-
durable-outbox recovery (`subscribe_handlers.rs:188-193`) is the same self-healing strategy tranquil
chose, and it is defensible.

**`FutureCursor` MISSING — stable-gap (Finding 6); `OutdatedCursor` MISSING — stable-gap
(Finding 7); `ConsumerTooSlow` MISSING — majority behaviour, explicitly not a gap.**

### `#info` frames use the error opcode — DIVERGENT

`encode_info` builds header `op: -1` with body `{name, message}`
(`crates/atproto-pds/src/sequencer/frame.rs:144-158`). Per the lexicon `#info` is a *message* in the
union, so a conformant frame is `{op: 1, t: "#info"}` with body `{name, message?}`. Opcode `-1` is
the error frame, whose body the reference validates as `{error, message?}`
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/stream/types.ts:17-21`), and `Frame.fromBytes`
throws `Invalid error frame body` when that parse fails (`frames.ts:47-51`). The extra `t` in the
header is harmless — `l.object` is not strict about unknown keys
(`/tmp/gap-scratch/atproto/packages/lex/lex-schema/src/schema/object.ts:59-93`) — but `name` where
`error` is required is not. cirrus keeps the two straight explicitly
(`account-do.ts:1099-1109`), as does tranquil (`sync/frame.rs:100-104`, error frames at
`sync/util.rs:512-524`).

**DIVERGENT — stable-gap (Finding 8).**

### `#sync`, `#identity`, `#account` payloads — PARTIAL / DIVERGENT

All three exist as `EventType` variants with real emitters — more than several comparisons manage
(pegasus has an `#info` type with no emitter; alteran's `/identity` and `/account` DO handlers are
never called from `src/`). Each payload is off:

- **`#sync`** requires `{seq, did, blocks, rev, time}` with `blocks` a CAR containing the commit
  block, ≤ 10 000 bytes. atproto-crates emits `{did, rev, head, blocks: <usize count>}`
  (`crates/atproto-pds/src/sequencer/sync_event.rs:68-73`) — `blocks` is a number, `head` is a
  non-lexicon stand-in for the CAR, and `sync_event.rs:26-28` admits it. Its call sites are
  `importRepo` completion (`crates/atproto-pds/src/repo/import.rs:333-336`) and
  `com.atproto.admin.forceRepoSync` (`crates/atproto-pds/src/admin/handlers.rs:1009-1013`) — a
  *better* trigger set than most of the field, several of which emit `#sync` only at account
  creation. Building a one-block CAR here is ten lines against an existing writer.
- **`#identity`** emits `{did, handle}` (`crates/atproto-pds/src/http/identity_handlers.rs:694-697`),
  correct as far as it goes; the envelope then supplies `repo` where `did` is required.
- **`#account`** emits `{did, active, status}` (`crates/atproto-pds/src/account/manager.rs:372-382`)
  with `status` unconditional — including `status: "active"` when `active` is true. The lexicon
  scopes `status` to `active=false` and does not list `"active"` in `knownValues`; the reference
  emits `{did, active: true}` with no `status`
  (`/tmp/gap-scratch/atproto/packages/pds/src/sequencer/events.ts:102-105`).

One thing is unambiguously right: `EventType` is exactly `Commit | Sync | Identity | Account | Info`
(`crates/atproto-pds/src/sequencer/outbox.rs:14-25`) — no `#handle`, `#migrate` or `#tombstone`.
arroba still writes `#tombstone` rows (`arroba/storage.py:292-308`) and rsky can persist `handle`
rows its own union cannot deserialize (`src/sequencer/events.rs:274-285` vs `:176`).

**`#sync` DIVERGENT — rc-blocker (Finding 5); `#account.status` DIVERGENT — cosmetic (Finding 9);
deprecated events correctly absent — no finding.**

### fjall profile: `#identity` and `#account` are written where nothing reads them — DIVERGENT

`emit_identity_event` and `emit_account_event` open a per-actor **SQLite** store directly
(`crates/atproto-pds/src/http/identity_handlers.rs:693`,
`crates/atproto-pds/src/account/manager.rs:370`) regardless of the configured profile, while
`subscribe_handlers::open_outbox` routes through the `PublicRealmBackend` dispatch whenever one is
wired (`crates/atproto-pds/src/http/subscribe_handlers.rs:26-33`), which `bin/pds.rs:592` always
does. Under SQLite the dispatch resolves to the same per-actor file
(`crates/atproto-pds/src/actor_store/sql/public_realm.rs:327`, `:348`) and the events are found;
under `PDS_STORAGE_PROFILE=fjall` (`crates/atproto-pds/src/bin/pds.rs:385-397`) the reader looks in
fjall and the writer wrote to SQLite. `fjall` is not a default feature
(`crates/atproto-pds/Cargo.toml:96`), which bounds the blast radius to operators who opt in.

**DIVERGENT — rc-blocker for the fjall profile, stable-gap overall (Finding 10).**

### Operational limits: subscriber scale, retention, relay discovery — PARTIAL / MISSING

Three operational gaps sit outside the wire format. First, **subscriber scale**: the DID set is
resolved once at connection time from `list_accounts(None, 1000)`
(`crates/atproto-pds/src/http/subscribe_handlers.rs:212-216`) and the `cursors` map is never extended
(`:102-103`), so accounts beyond the first thousand are never tailed and an account created *after* a
relay connects stays invisible for the life of that connection — weeks, for a relay. The poll loop
also re-opens an `OutboxReader` per DID per five-second tick (`:117`, `:108`), meaning a fresh SQLite
pool per account per tick. Every comparison attaches subscribers to a single event source, so new
accounts appear automatically. There is no server-initiated keepalive either — but neither does the
reference send one, its keepalive being client-side in `WebSocketKeepAlive`
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/stream/subscription.ts:27-31`), so that specific
omission is *not* a reference-parity gap; rsky pings at 30 s
(`src/apis/com/atproto/sync/subscribe_repos.rs:132,319-322`), metalbear at 20 s sized against nginx's
`proxy_read_timeout` (`src/sequencer.c:556-565`), and atproto-crates instead leans on
`keepAliveTimeout: 600s` at the tunnel (`deploy/cloudflared/config.yml.tmpl:15`, `:18`, `:21`).

Second, **retention**: nothing prunes the outbox, so the firehose log grows without bound and there
is no window against which an `OutdatedCursor` decision could be made. The combination is at least
coherent — unbounded retention means no cursor is ever outdated — and the field is genuinely split.
Reference has `PDS_REPO_BACKFILL_LIMIT_MS`, tranquil `firehose.backfill_hours` default 72
(`example.toml:407`), cocoon an hourly 72 h prune (`server/persist.go:171-181`), dnproto a 72 h
hourly delete (`src/pds/db/PdsDb.cs:1193`). But metalbear's retention runs once at startup
(`src/server.c:7020-7023`), cirrus' `pruneOldEvents` is called only from a test
(`packages/pds/test/firehose.test.ts:839`), and pegasus and zds never delete at all.

Third, **relay discovery**: the reference calls `crawlers.notifyOfUpdate()` from the sequencer on
every sequenced batch, throttled to twenty minutes (`packages/pds/src/sequencer/sequencer.ts:170`,
`packages/pds/src/crawlers.ts:17-27`); rsky does the same (`src/crawlers.rs:37-60`), metalbear
notifies from the write path on the same floor (`src/server.c:4825-4840`), and pegasus
(`lib/sequencer.ml:490-502`), arroba (`app.py:196-202`) and dnproto
(`src/pds/BackgroundJobs.cs:143-158`) all have automatic paths. atproto-crates has `state.crawlers`
and a fan-out loop that fires only when someone POSTs `requestCrawl` *to* this PDS
(`crates/atproto-pds/src/http/handlers.rs:331-363`); no write path triggers it, so a fresh deployment
is never announced. Two related items belong to the endpoints chapter: the handler inverts the
lexicon's semantics (the receiver should register the caller), and it is unauthenticated with a
caller-supplied `hostname` (`handlers.rs:317-330`).

**PARTIAL — stable-gap (Finding 11); MISSING — stable-gap (Findings 12 and 13).**


### Test coverage — MISSING

No test in `crates/atproto-pds/tests/` opens a WebSocket. The only match for `subscribe` is a doc
comment in `http_phase8_polish.rs:6` claiming "subscribeRepos broadcast wakeup propagates writes
immediately" — a claim no test body substantiates. Frame encoding has six unit tests in
`crates/atproto-pds/src/sequencer/frame.rs:162-255`, and they assert the *current* envelope shape
(`body["payload"]["rev"]` at `:237`, `v["payload"]["rev"]` at `:207`), so they lock the divergence in
rather than catching it. Cursor resume, `?encoding=json`, the `did` filter and backfill are all
unexercised.

Compare: the reference has `packages/pds/tests/sync/subscribe-repos.test.ts` and a dedicated
`tests/sequencer.test.ts`; cirrus — single-user — has `packages/pds/test/firehose.test.ts` with a
case asserting "emits prevData on every commit so relays can run MST inversion" (`:475`); alteran —
hobby tier — ships `tests/firehose.test.ts`, `firehose-parse.test.ts`,
`firehose-integration.test.ts` and `sequencer-cursor.test.ts`; tranquil ships three
(`firehose_validation.rs`, `firehose_inline_blocks.rs`, `mst_firehose_e2e.rs`).

**MISSING — rc-blocker (Finding 14).** Not because tests are shippable functionality, but because the
absence of any end-to-end firehose test is the direct cause of a correct-looking implementation that
emits undecodable events.


## Findings

| # | Finding | Class | Severity |
|---|---|---|---|
| 1 | `#commit` body wrapped in a non-lexicon `{seq, repo, time, payload}` envelope | DIVERGENT | rc-blocker |
| 2 | No CARv1 `blocks` is ever built for the firehose | MISSING | rc-blocker |
| 3 | JSON-then-DAG-CBOR round trip corrupts op CIDs and precludes byte fields | DIVERGENT | rc-blocker |
| 4 | `seq` is per-actor; no global stream sequence; cursor fanned across repos | DIVERGENT | rc-blocker |
| 5 | `#sync.blocks` is an integer block count, not a CAR | DIVERGENT | rc-blocker |
| 6 | `FutureCursor` never emitted | MISSING | stable-gap |
| 7 | `OutdatedCursor` unreachable; no backfill-window concept | MISSING | stable-gap |
| 8 | `#info` sent with error opcode `-1` and body `{name,…}` instead of `{error,…}` | DIVERGENT | stable-gap |
| 9 | `#account` emits `status: "active"` alongside `active: true` | DIVERGENT | cosmetic |
| 10 | fjall profile: `#identity`/`#account` written to SQLite, read from fjall | DIVERGENT | rc-blocker (fjall only) |
| 11 | Subscriber DID set fixed at connect, capped at 1000; per-tick pool churn | PARTIAL | stable-gap |
| 12 | Outbox has no retention; log grows unbounded | MISSING | stable-gap |
| 13 | No automatic crawler notification on write | MISSING | stable-gap |
| 14 | Zero end-to-end firehose test coverage; unit tests lock in the divergence | MISSING | rc-blocker |
| — | `ConsumerTooSlow` absent | MISSING | **not a gap** — majority behaviour |

**1 — `#commit` body wrapped in a non-lexicon envelope.** DIVERGENT / rc-blocker.
`crates/atproto-pds/src/sequencer/frame.rs:116-122` emits `{seq, repo, time, payload}`; the payload
(`crates/atproto-pds/src/repo/writer.rs:448-456`, `:722-730`) is `{did, rev, commit, data, prev,
prevData, ops}` — `rebase`, `tooBig`, `since`, `blocks`, `blobs` absent, `repo` spelled `did`, and
`#sync`/`#identity`/`#account` get `repo` where the def requires `did`. Reference:
`sequencer/events.ts:23-35` + `subscribeRepos.ts:46-51`; hobby-tier alteran emits all twelve fields
(`src/worker/sequencer/payload.ts:69-83`). *Consequence:* the body validates against no union member,
so `Frame.fromBytes` rejects on the first missing required field and indigo relays see nil `Blocks`.

**2 — No CARv1 `blocks` is ever built for the firehose.** MISSING / rc-blocker.
`car_export` is referenced only from `crates/atproto-pds/src/http/handlers.rs:191` (`getRepo`) and
`:250` (`getBlocks`); the commit-write path (`crates/atproto-pds/src/repo/writer.rs:397-470`) builds
no CAR. All eleven comparisons ship one (reference `events.ts:21-30` … dnproto `UserRepo.cs:229-238`).
*Consequence:* record contents never reach the network. Largest single gap in this area.

**3 — Payload JSON round trip corrupts CIDs and precludes byte fields.** DIVERGENT / rc-blocker.
Payloads stored as JSON (`writer.rs:457`, `sync_event.rs:74`, `manager.rs:383`,
`identity_handlers.rs:698`) and re-encoded from `serde_json::Value` at `frame.rs:115-125`.
`Cid::serialize` emits a newtype variant (`crates/atproto-dasl/src/cid/mod.rs:106-119`) that
serde_json renders `{"": [bytes…]}` (`serde_json-1.0.151/src/value/ser.rs:205-218`, `:172-175`),
hitting `RepoOp.cid`/`prev` (`crates/atproto-repo/src/mst/diff.rs:164-175`); other CIDs become text
strings where `cid-link` is declared. Also `RepoOp.cid` is `skip_serializing_if` (`diff.rs:170`)
though `#repoOp.cid` is required-and-nullable. Cf. reference `cborEncode(evt)` (`events.ts:42`).
*Consequence:* no tag-42 cid-links, and a `blocks` CAR could not survive this pipeline.

**4 — `seq` is per-actor; no global stream sequence.** DIVERGENT / rc-blocker.
Per-actor `outbox.seq AUTOINCREMENT` (`crates/atproto-pds/src/sequencer/outbox.rs:239`,
`crates/atproto-pds/src/actor_store/sql/public_realm.rs:339`) and per-DID `outbox_meta`
(`crates/atproto-pds/src/actor_store/fjall/public_realm.rs:390-409`); one client cursor seeded into
every repo's counter (`crates/atproto-pds/src/http/subscribe_handlers.rs:102-103`). All eleven use
one source (reference `sequencer/db/schema.ts:6`; cocoon `persist.go:67-96`). *Consequence:*
duplicate and non-monotonic `seq`; resume skips events; a re-created actor DB replays numbers a relay
already consumed.

**5 — `#sync.blocks` is a block count, not a CAR.** DIVERGENT / rc-blocker.
`crates/atproto-pds/src/sequencer/sync_event.rs:68-73` emits `{did, rev, head, blocks: <usize>}`;
conceded at `:26-28`. Cf. reference `events.ts:47-63`; metalbear cites the 10 000-byte cap in-comment
(`repo_store.c:2579-2605`). *Consequence:* a desynchronized consumer's recovery path carries no
commit. The trigger set here is better than most of the field; only the payload is wrong.

**6 — `FutureCursor` never emitted.** MISSING / stable-gap.
No occurrence anywhere in `crates/`; cursor accepted unchecked
(`crates/atproto-pds/src/http/subscribe_handlers.rs:44-46`, `:102-103`). Declared in
`subscribeRepos.json` `main.errors` and implemented by six of eleven. *Consequence:* a bad cursor
yields a silent, permanently empty stream instead of a diagnosable error.

**7 — `OutdatedCursor` unreachable; no backfill-window concept.** MISSING / stable-gap.
The name appears only in doc comments (`crates/atproto-pds/src/sequencer/outbox.rs:23`,
`crates/atproto-pds/src/sequencer/frame.rs:133`) and one unit test (`frame.rs:242`, `:252`); the
single runtime `encode_info` call sends `"InternalError"` (`subscribe_handlers.rs:94`). Emitted by
seven of eleven, including the hobby tier. *Consequence:* a consumer resuming past the retained
window cannot distinguish "caught up" from "gap". Masked today by unbounded retention (Finding 12).

**8 — `#info` sent with the error opcode.** DIVERGENT / stable-gap.
`crates/atproto-pds/src/sequencer/frame.rs:144-158` — header `{op: -1, t: "#info"}`, body
`{name, message}`. `FrameType.Error = -1` requires body `{error, message?}`
(`xrpc-server/src/stream/types.ts:17-21`) and `Frame.fromBytes` throws on a body lacking `error`
(`frames.ts:47-51`); cirrus keeps the two distinct (`account-do.ts:1099-1109`). *Consequence:* the
only out-of-band frame this PDS can send raises an exception inside a reference consumer's decoder.

**9 — `#account` emits `status: "active"` alongside `active: true`.** DIVERGENT / cosmetic.
`crates/atproto-pds/src/account/manager.rs:372-382` populates `status` unconditionally; the lexicon
scopes it to `active=false` and omits `"active"` from `knownValues`, and the reference emits
`{did, active: true}` with no `status` (`packages/pds/src/sequencer/events.ts:102-105`).
*Consequence:* a strict consumer may read the unknown status as a non-active reason. One-line fix.

**10 — fjall profile writes `#identity`/`#account` where the reader never looks.** DIVERGENT /
rc-blocker on `PDS_STORAGE_PROFILE=fjall`, stable-gap overall.
Emitters open SQLite directly (`crates/atproto-pds/src/http/identity_handlers.rs:693`,
`crates/atproto-pds/src/account/manager.rs:370`) while the reader dispatches through the backend
(`crates/atproto-pds/src/http/subscribe_handlers.rs:26-33`, always set at `bin/pds.rs:592`). SQLite
dispatch resolves to the same file (`actor_store/sql/public_realm.rs:327`), so only fjall is
affected; `fjall` is not in `default` (`crates/atproto-pds/Cargo.toml:96`). *Consequence:* on fjall,
handle changes and takedowns are invisible to every subscriber.

**11 — Subscriber DID set fixed at connect and capped at 1000; per-tick pool churn.** PARTIAL /
stable-gap.
`crates/atproto-pds/src/http/subscribe_handlers.rs:212-216` (`list_accounts(None, 1000)`), map built
once at `:102-103`, `OutboxReader` re-opened per DID per five-second tick (`:117`, `:108`). Every
comparison attaches subscribers to one event source, so new accounts appear automatically.
*Consequence:* accounts created after a relay connects never appear on that connection; O(accounts)
pool construction every five seconds.

**12 — Outbox has no retention.** MISSING / stable-gap.
No prune path for `outbox` in any GC loop. Windowed in reference, tranquil (72 h configurable),
cocoon, dnproto and arroba; unbounded or effectively so in pegasus, zds, cirrus (prune only in a
test) and metalbear (prune runs once at startup). *Consequence:* unbounded disk growth with no
operator knob; four comparisons share the problem.

**13 — No automatic crawler notification on write.** MISSING / stable-gap.
`state.crawlers` is read only by the inbound `requestCrawl` handler
(`crates/atproto-pds/src/http/handlers.rs:331-363`); cf. reference `sequencer.ts:170` →
`crawlers.ts:17-27`. atproto-crates is the only implementation with no automatic path.
*Consequence:* a new deployment is never announced to a relay without manual operator action.

**14 — Zero end-to-end firehose test coverage.** MISSING / rc-blocker.
No test in `crates/atproto-pds/tests/` opens a WebSocket; `http_phase8_polish.rs:6` is a doc comment.
The six unit tests at `crates/atproto-pds/src/sequencer/frame.rs:162-255` assert the divergent
envelope (`body["payload"]["rev"]` at `:237`) and therefore defend the bug. Reference, cirrus,
alteran (four files) and tranquil (three) all have dedicated firehose tests. *Consequence:* the
mechanism was verified and the contract was not — one golden-frame assertion against reference bytes
would have caught Findings 1, 3 and 8.

### Where atproto-crates is ahead of the field

Three points, none of which offset the blockers but all of which are real:

The `#sync` **trigger set** is better than most. atproto-crates fires `#sync` after `importRepo`
completes (`crates/atproto-pds/src/repo/import.rs:333-336`) and on operator-initiated
`com.atproto.admin.forceRepoSync` (`crates/atproto-pds/src/admin/handlers.rs:1009-1013`) — the two
situations the event was designed for. arroba emits `#sync` only from `Repo.create`; pegasus only from
`createAccount`; zds only from `activateAccount`; cocoon and tranquil emit none after `importRepo`
(cocoon's `importRepo` emits neither `#commit` nor `#sync`). Fix the payload and this becomes the
best `#sync` story outside the reference.

Commit, blocks, records and the outbox row land in **one backend-native transaction** — a sqlx
`Transaction` (`crates/atproto-pds/src/actor_store/sql/public_realm.rs:618-703`) or a single
`fjall::Batch` (`crates/atproto-pds/src/actor_store/fjall/public_realm.rs:834-872`) — with per-DID
write serialization (`crates/atproto-pds/src/repo/writer.rs:95`, `:139-144`). A crash cannot leave a
commit without its event or vice versa. dnproto's seq counter, by contrast, is a non-atomic
read-delete-insert pair (`/tmp/gap-scratch/dnproto/src/pds/db/PdsDb.cs:986-995`).

The **deprecated event types are cleanly absent**. `EventType` is exactly the current union
(`crates/atproto-pds/src/sequencer/outbox.rs:14-25`), with no `#handle`, `#migrate` or `#tombstone`.
arroba still writes `#tombstone` rows (`storage.py:292-308`) and rsky-pds can persist `handle` rows
its own union cannot deserialize (`sequencer/events.rs:274-285` vs `:176`).

## Confidence & unknowns

High confidence on everything asserted about atproto-crates: every claim above was read directly out
of the named file at the named lines during this review, and the load-bearing ones (frame envelope,
absent CAR, per-actor seq, `#sync` payload, `#info` opcode) were re-opened after the inventory flagged
them. The lexicon claims come from
`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json`, opened in full.

The serde_json rendering of a `Cid` in Finding 3 (`{"": [bytes…]}`) is derived from three sources read
directly — the `Serialize` impl (`crates/atproto-dasl/src/cid/mod.rs:106-142`), serde_json's
`serialize_newtype_variant` (`value/ser.rs:205-218`) and its `serialize_bytes` (`:172-175`) — but was
**not executed**. (Citation caveat: those two line numbers were read in the local registry copy of
serde_json **1.0.151**, while the workspace `Cargo.lock` pins **1.0.149**, whose source is not
present locally. The line numbers are therefore 1.0.151's; whether they shift by a line or two in
1.0.149 was not checked, and the argument does not depend on it.) Running one assertion over `serde_json::to_string(&repo_op)` would settle it in
seconds; I did not, because the review scope forbids modifying source. The finding does not depend on
the exact rendering — any JSON form of a `Cid` fails to become a tag-42 cid-link after the round trip
— but the specific `{"": […]}` shape is inference from source rather than observation.

Three comparison cells are inherited rather than re-verified and are marked `?` in the matrix:
cocoon's slow-consumer behaviour is delegated to indigo's `events.EventManager` (that indigo version
is not in the local module cache); metalbear's frame *encoder* `wf_sync_publish_event` lives in
Wolfram, outside the repository — what is verified there is the storage-and-replay model and the
event-type set; arroba's framing is delegated to `lexrpc.flask_server` (`app.py:123`), also not local.
zds' firehose test coverage is likewise `?` — it has a `build.zig:126` test step but no
firehose-specific test file I could locate.

I did not attempt a live interop test. Connecting a real relay or an `@atproto/xrpc-server`
`Subscription` to a running atproto-crates PDS and capturing the first frame would convert Findings
1, 3 and 8 from source-derived to observed, and is the highest-value next step before fix work
starts. The `?encoding=json` mode (`crates/atproto-pds/src/sequencer/frame.rs:33-49`) is documented
as non-spec and opt-in; browsers cannot set `Accept` through the WebSocket API so the accidental-trip
risk appears nil, but I did not test it.

Related chapters: the permissioned-data commit format has its own signed-commit divergences documented
in [permissioned overview](../permissioned/40-permissioned-overview.md); `requestCrawl`'s inverted
semantics and missing auth belong to the endpoints chapter. Per-implementation detail for every
comparison cited here is in [impl-notes](../impl-notes/bluesky-reference.md) and its siblings:
[arroba](../impl-notes/arroba.md), [tranquil-pds](../impl-notes/tranquil-pds.md),
[rsky-pds](../impl-notes/rsky-pds.md), [cocoon](../impl-notes/cocoon.md),
[metalbear](../impl-notes/metalbear.md), [pegasus](../impl-notes/pegasus.md),
[zds](../impl-notes/zds.md), [cirrus](../impl-notes/cirrus.md),
[alteran](../impl-notes/alteran.md), [dnproto](../impl-notes/dnproto.md).
