# zds — implementation notes

Source: `/tmp/gap-scratch/zds` (server) and `/tmp/gap-scratch/zat` (toolkit).
Canonical lexicons checked against `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

> **Caveat on the lexicon checkout.** `/tmp/gap-scratch/atproto` is on branch
> `permissioned-data` (commit `3f6c96d "bring impl up to date with lexicons & proposal"`).
> That branch carries `lexicons/com/atproto/space/**` and `lexicons/com/atproto/simplespace/**`,
> which do **not** exist on `main`. Every `com.atproto.*` claim below about
> `server`/`repo`/`sync`/`identity`/`admin`/`moderation` is stable across branches;
> claims about `space`/`simplespace` are against the draft branch only.

> **Correction to the task framing.** zds was assigned as a "lowest maturity tier,
> look for primitives not endpoints" implementation. The code does not support that
> framing. zds is 22,632 lines of Zig across 50 source files
> (`find /tmp/gap-scratch/zds/src -name '*.zig' | xargs wc -l`), routes **46 canonical
> `com.atproto.*` NSIDs** plus 25 draft `space`/`simplespace` NSIDs, and every routed
> handler I opened performs real work — I found no `unimplemented`/`TODO` stub in the
> `com.atproto.*` surface. The primitives inventory is still given below (§14) because
> it was asked for, but zds is not thin.

---

## 1. Language, stack, build, license

Zig, `minimum_zig_version = "0.16.0"` (`/tmp/gap-scratch/zds/build.zig.zon:5`); CI pins
exactly `zig version == 0.16.0` (`/tmp/gap-scratch/zds/.tangled/workflows/ci.yml`, the
`test "$(zig version)" = "0.16.0"` line). Build system is `zig build`
(`/tmp/gap-scratch/zds/build.zig:72` produces the `zds` binary; `:89` `zds-bench`; `:106`
`zds-plc-repair`).

Dependencies (`/tmp/gap-scratch/zds/build.zig.zon:6-40`): `zat` **pinned at v0.3.10**
(`:7-10`), `zqlite` (SQLite binding), `webauthn`, `httpz` (HTTP/1.1 + websocket),
`websocket.zig`, `metrics`, and the lazily-fetched `bluesky-social/atproto-interop-tests`.
`metrics` is wired only into the vendored `httpz` module (`/tmp/gap-scratch/zds/build.zig:49`);
`grep -rn '@import("metrics")' src/` returns nothing, so zds itself does not emit metrics
through it.

**LICENSE: zds has no license file.** `ls -a /tmp/gap-scratch/zds` shows no `LICENSE`,
`LICENCE`, or `COPYING`, and `README.md` names none. zat is MIT
(`/tmp/gap-scratch/zat/LICENSE:1-3`, "Copyright (c) 2025 nate nowack"). Treat zds as
all-rights-reserved-by-default until the author states otherwise.

Test counts (`grep -rc '^test "'`): 106 test declarations in zds, 549 in zat. CI runs
`zig build test` plus `tools/smoke.sh`.

## 2. Multi-account, deployment model

Multi-account. `com.atproto.server.createAccount` mints a fresh `did:plc` per signup via a
genesis PLC operation (`/tmp/gap-scratch/zds/src/atproto/server.zig`, the `plc.createGenesisOperation`
/ `plc.submitOperation` branch inside `createAccount`), gated by invite codes when
`ZDS_INVITE_REQUIRED=true`. `store.listResidents` (`/tmp/gap-scratch/zds/src/storage/store.zig:627`)
and `com.atproto.sync.listRepos` enumerate multiple hosted repos.

Deployment: single static binary. Container image published to `atcr.io/zat.dev/zds`
(`/tmp/gap-scratch/zds/README.md:100-125`); multi-arch Dockerfile builds with
`-Doptimize=ReleaseSafe` onto `debian:bookworm-slim`
(`/tmp/gap-scratch/zds/Dockerfile`). Fly.io deployment config with a persistent volume at
`/data` and `ZDS_PERMISSIONED_DATA = "true"` (`/tmp/gap-scratch/zds/fly.toml`). Local dev
runs behind Caddy (`/tmp/gap-scratch/zds/dev/Caddyfile`). No systemd unit, no installer
script, no serverless variant in-tree.

Config is CLI flags with `ZDS_*` env fallbacks (`/tmp/gap-scratch/zds/src/internal/cli.zig:80`,
`:281`), applied to process-global mutable state in `/tmp/gap-scratch/zds/src/core/config.zig`.

## 3. Storage backends

One SQLite file plus one blob directory.

| Data | Engine | Location |
|---|---|---|
| accounts, sessions, app passwords, passkeys, OAuth requests/tokens, invite codes, preferences, audit, rate limits | SQLite (`zqlite`) | `ZDS_DB` (default `dev/zds.sqlite3`) |
| repo blocks, commits, records, `seq_events` firehose frames | same SQLite file | tables `repo_blocks`, `commits`, `records`, `seq_events` |
| blob metadata (cid, did, mime, size) | same SQLite file | table `blobs` (`/tmp/gap-scratch/zds/src/storage/store.zig:5960`) |
| blob bytes | flat filesystem | `ZDS_BLOBSTORE_PATH/<did>/<cid>` (`/tmp/gap-scratch/zds/src/storage/blobstore.zig`, `blobPath`) |

Schema is inline DDL in `const schema_statements` at
`/tmp/gap-scratch/zds/src/storage/store.zig:5898` and following (e.g. `seq_events` at `:5948`,
`blobs` at `:5960`, `expected_blobs` at `:6231`). There is no separate migrations directory;
migrations are hand-written Zig functions gated on a `migrations` table
(`migrate()` at `:4084`, `markMigrationApplied` at `:4372`).

Notable: unlike the reference PDS, zds uses **one shared SQLite database for all accounts**,
not per-actor SQLite files. Writes serialize on a per-DID lane
(`write_lanes.lock` at `/tmp/gap-scratch/zds/src/storage/store.zig:1958`,
`/tmp/gap-scratch/zds/src/internal/sharded_locks.zig`) and then on a global `db_mutex` (`:2025`).

## 4. Endpoint coverage snapshot

The route table is a single comptime array: `pub const endpoints = [_]Endpoint{...}` at
`/tmp/gap-scratch/zds/src/http/router.zig:112-247`, matched by exact method+path in
`route()` at `:249-258`. Dispatch to handlers is the `switch (route)` at
`/tmp/gap-scratch/zds/src/http/server.zig:74-158`. There is no path-prefix or wildcard
matching — an unlisted NSID falls to `.not_found` → `UnknownMethod` (`server.zig:157`).

### com.atproto.server. (20 canonical)

| NSID | Registered | Handler |
|---|---|---|
| describeServer | router.zig:155 | server.zig:102 → `atproto_server.describeServer` (real) |
| reserveSigningKey | router.zig:156 | server.zig:103 (real) |
| createAccount | router.zig:157 | server.zig:104 (real: PLC genesis or migration-by-`did`) |
| createInviteCode | router.zig:158 | server.zig:105 (real, admin token) |
| createInviteCodes | router.zig:159 | server.zig:106 (real) |
| getAccountInviteCodes | router.zig:160 | server.zig:107 (real) |
| listAppPasswords | router.zig:162 | server.zig:109 (real) |
| createAppPassword | router.zig:163 | server.zig:110 (real) |
| revokeAppPassword | router.zig:164 | server.zig:111 (real) |
| createSession | router.zig:170 | server.zig:117 (real) |
| refreshSession | router.zig:171 | server.zig:118 (real, rotating token family) |
| getSession | router.zig:172 | server.zig:119 (real) |
| getServiceAuth | router.zig:173 | server.zig:120 (real, see §5) |
| activateAccount | router.zig:174 | server.zig:121 (real, emits #account/#identity/#sync) |
| deactivateAccount | router.zig:175 | server.zig:122 (real) |
| requestEmailConfirmation | router.zig:176 | server.zig:123 (real, sends mail) |
| confirmEmail | router.zig:177 | server.zig:124 (real) |
| requestEmailUpdate | router.zig:178 | server.zig:125 (real) |
| updateEmail | router.zig:179 | server.zig:126 (real) |
| checkAccountStatus | router.zig:180 | server.zig:127 (real) |

Canonical `com.atproto.server.*` **not** served: `deleteAccount`, `deleteSession`,
`requestAccountDelete`, `requestPasswordReset`, `resetPassword`. Verified against
`ls /tmp/gap-scratch/atproto/lexicons/com/atproto/server/`.

**Five non-canonical NSIDs are squatted in the `com.atproto.server.*` namespace**:
`startPasskeyRegistration`, `finishPasskeyRegistration`, `listPasskeys`, `deletePasskey`,
`updatePasskey` (`router.zig:165-169`). No such files exist under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/`. `README.md:139-141` describes
passkeys but does not flag the namespace collision;
`/tmp/gap-scratch/zds/docs/architecture.md:34-35` does ("Passkeys are outside the official
PDS surface ZDS tracks for compatibility").

### com.atproto.repo. (10 of 10 canonical)

All ten non-`strongRef` repo methods are routed at `router.zig:185-194` and dispatched at
`server.zig:130-139`: `createRecord`, `putRecord`, `describeRepo`, `getRecord`,
`listRecords`, `deleteRecord`, `applyWrites`, `importRepo`, `uploadBlob`,
`listMissingBlobs`. Full family coverage. `importRepo` really parses and verifies the CAR
(`/tmp/gap-scratch/zds/src/atproto/repo.zig:356` `zat.loadCommitFromCAR`, `:362`
`verifyImportedRepoCar`, `:364` `Mst.loadFromBlocks`).

### com.atproto.sync. (9 routed)

| NSID | Registered | Notes |
|---|---|---|
| getBlob (GET+HEAD) | router.zig:196-197 | real; takedown-gated |
| getRepo (GET+HEAD) | router.zig:198-199 | real; supports `since` diff CAR; concurrency-capped |
| getLatestCommit | router.zig:200 | real |
| listRepos | router.zig:202 | real, cursored |
| listBlobs | router.zig:204 | real |
| subscribeRepos | router.zig:206 | real websocket, see §7 |
| getRepoStatus | router.zig:207 | real |
| notifyOfUpdate | router.zig:208 | **stub — `return http_api.json(request, .ok, "{}")`**, `/tmp/gap-scratch/zds/src/atproto/sync.zig:334-336` |
| requestCrawl | router.zig:209 | **stub — `return http_api.json(request, .ok, "{}")`**, `sync.zig:338-340` |

Canonical sync methods **not served**: `getBlocks`, `getRecord`, `getHostStatus`,
`listHosts`, `listReposByCollection` (plus deprecated `getCheckout`, `getHead`). Verified
by listing `/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/`.
`listReposByCollection` and `getHostStatus` are both absent — `route()` returns `.not_found`.

zds is an outbound crawl *client* as well: `notifyCrawlers` fans out POSTs to
`ZDS_CRAWLERS` (`sync.zig:356-418`), called at boot (`src/main.zig:69`).

### com.atproto.identity. (6 of 9 canonical)

`getRecommendedDidCredentials`, `requestPlcOperationSignature`, `signPlcOperation`,
`submitPlcOperation`, `resolveHandle`, `updateHandle` — `router.zig:211-216`,
`server.zig:149-154`. All real; `signPlcOperation` gates on an emailed token, fetches the
last PLC op, CBOR-encodes and signs (`/tmp/gap-scratch/zds/src/atproto/identity.zig:65-114`).
Missing: `refreshIdentity`, `resolveDid`, `resolveIdentity`.

### com.atproto.admin. (1 of 15) and com.atproto.moderation. (0 of 1)

Only `com.atproto.admin.updateSubjectStatus` (`router.zig:161`,
`/tmp/gap-scratch/zds/src/atproto/server.zig:981`), guarded by a static admin bearer token
(`requireAdminToken`, `:986`). Not served: `getSubjectStatus`, `getAccountInfo(s)`,
`searchAccounts`, `deleteAccount`, `sendEmail`, `updateAccountEmail/Handle/Password/SigningKey`,
`disable/enableAccountInvites`, `disableInviteCodes`, `getInviteCodes`.
`com.atproto.moderation.createReport` is **not** served — zds does not accept reports.
`com.atproto.label.*` and `com.atproto.temp.*`: nothing served.

Two proprietary admin/account NSIDs exist: `dev.zat.account.listSessions` and
`dev.zat.admin.listSessions` (`router.zig:152-153`). Correctly namespaced under `dev.zat`.

### com.atproto.space. / com.atproto.simplespace. (25, experimental)

18 `space.*` + 7 `simplespace.*` NSIDs, all mapped to one route enum value and
sub-dispatched by string compare in
`/tmp/gap-scratch/zds/src/atproto/space.zig:21-67`. Gated behind `ZDS_PERMISSIONED_DATA`;
when off, every one returns `501 MethodNotImplemented` (`space.zig:22-29`). The names match
the draft lexicons on the `permissioned-data` branch. One deliberate near-stub:
`com.atproto.simplespace.checkUserAccess` authenticates the caller fully and then
unconditionally returns `{"authorized":false}` (`space.zig:303`) — the router itself
documents this ("Generic PDS handling denies by default", `router.zig:246`).

### Other

`app.bsky.actor.getPreferences` / `putPreferences` (`router.zig:182-183`) are served
locally. All other appview traffic goes through the generic `atproto-proxy` path
(`/tmp/gap-scratch/zds/src/atproto/proxy.zig:138` `shouldProxy`, invoked ahead of routing at
`server.zig:65-72`).

### README vs code

`README.md` has no endpoint checklist, so there is nothing to contradict. Its "behavior"
section (`README.md:127-148`) matches the code I read: proxying, unknown-schema
`validationStatus: "unknown"`, disk blobstore, invite-code tables, app-password revocation
cascading to sessions, `ZDS_PERMISSIONED_DATA` gating. `docs/operations.md:197-205` claims
migration support; the routes back it (§8).

## 5. Auth posture

Three stacked mechanisms, all real.

**Password/app-password sessions.** `createSession`/`refreshSession`/`getSession`. JWTs are
minted in `/tmp/gap-scratch/zds/src/auth/tokens.zig:67-153`, but acceptance requires the
`jti` to be live in the session table — `store.sessionTokenIsActive(did, jti, scope)`,
called from `/tmp/gap-scratch/zds/src/http/api.zig:148`. So revocation is authoritative,
not merely advisory. Scope ladder `com.atproto.access` / `appPass` / `appPassPrivileged`
at `api.zig:174-179`.

**Full OAuth authorization server.** Not a client — zds *is* the AS.
- `.well-known/oauth-protected-resource` (`router.zig:138`) and
  `.well-known/oauth-authorization-server` (`:139`), metadata built in
  `/tmp/gap-scratch/zds/src/atproto/oauth.zig:59` and `:70`.
- Metadata advertises `"require_pushed_authorization_requests":true`,
  `"code_challenge_methods_supported":["S256"]`,
  `"token_endpoint_auth_methods_supported":["none","private_key_jwt"]`,
  `"dpop_signing_alg_values_supported":["ES256","ES256K"]`,
  `"client_id_metadata_document_supported":true`,
  `"authorization_response_iss_parameter_supported":true` (`oauth.zig:70`).
- **PAR** enforced: `par()` at `oauth.zig:88`, rejects non-S256 PKCE at `:127`, mints
  `urn:ietf:params:oauth:request_uri:` (`:13`, `:146`).
- **PKCE** verified at exchange: `pkceMatches` at `oauth.zig:1092`, called `:464`.
- **private_key_jwt** client auth: metadata fetch, `client_assertion_type` and
  `client_assertion` validation, `aud` check against `config.publicUrl()`, JWKS fetch, and
  ES256/P-256 + ES256K/secp256k1 curve matching (`oauth.zig:579-694`).
- **DPoP with server nonces**: `/tmp/gap-scratch/zds/src/internal/dpop.zig` — rolling
  time-bucketed nonce (`nonceForCounter`, `:211`), ±1 bucket tolerance (`validNonce`,
  `:199-202`), `use_dpop_nonce` challenges for both AS (`:41`) and RS (`:33`), `htu`/`htm`
  binding (`:183`, `:232`), jkt thumbprint (`:169`), and `jti` replay rejection via
  `store.recordDpopJti` (`store.zig:1374`).
- Resource-side binding is enforced: a DPoP-bound token presented as `Bearer`, or a `cnf.jkt`
  mismatch, is rejected (`api.zig:116-139`).
- Passkeys (WebAuthn) are an alternate credential on the OAuth login page
  (`router.zig:147-148`).

**Service auth — minted and verified.**
- *Minted*: `getServiceAuth` (`/tmp/gap-scratch/zds/src/atproto/server.zig:1058-1099`)
  validates `aud` shape including `did#fragment` (`:1101-1107`), requires `lxm` to be a
  valid NSID, refuses a blocklist of protected methods (`:1083`), enforces granular OAuth
  `rpc:` scope (`:1086`), and requires `lxm` when the token carries granular scopes (`:1089`).
  Also minted for outbound proxying (`proxy.zig:95`).
- *Verified*: inbound service JWTs are parsed, `lxm`-matched, DID-resolved and
  signature-checked in two places —
  `/tmp/gap-scratch/zds/src/atproto/repo.zig:459-513` (uploadBlob) and
  `/tmp/gap-scratch/zds/src/atproto/space.zig:1013-1047`. The uploadBlob path additionally
  pins `aud` to the server DID or `<serverDid>#atproto_pds` (`repo.zig:516-521`).
  `createAccount` for an existing DID is service-auth gated (`verifyCreateAccountServiceAuth`).

## 6. Sync 1.1 status

**#sync events: emitted, but with a CAR-root bug.** `syncEventFrame` is at
`/tmp/gap-scratch/zds/src/storage/store.zig:5656-5679`. The canonical lexicon
(`sync/subscribeRepos.json`, `#sync.blocks`) says: "CAR file containing the commit, as a
block. The CAR header must include the commit block CID as the first 'root'." zds writes:

```zig
const root_raw = try cidRawFromText(allocator, commit_cid);
const car_bytes = try zat.car.writeAlloc(allocator, .{
    .roots = &.{.{ .raw = data_cid_raw }},                     // ← MST data root
    .blocks = &.{.{ .cid_raw = root_raw, .data = commit_data }}, // ← commit block
});
```

`data_cid_raw` is the commit's `data` field, i.e. the MST root, not the commit CID —
see `latestCommitRawLocked` at `store.zig:5069-5074`. So the CAR root names a block that is
not in the CAR, and the commit CID is not the first root. The `#commit` path gets this
right (`commitEventFrame`, `store.zig:5567`/`:5578` — root is the commit CID).
`sequenceSyncEvent` (`store.zig:1141-1150`) is called from exactly one site:
`activateAccount` (`/tmp/gap-scratch/zds/src/atproto/server.zig:965`). No periodic or
recovery-driven `#sync`.

**prevData on commits: yes.** `applyWritesMeasured` passes the previous commit's MST root
as `prev_data_raw` (`store.zig:2094`, `if (current) |root| root.data_cid_raw else null`)
into `commitEventFrame` → `commitEventFrameFromCar` (`:5699`) →
`zat.firehose.encodeCommitEvent`. `since` is the previous commit's rev (`:2093`).
A migration `rebuildSeqEventsSync11Locked` (`store.zig:5456`) backfills `prevData` onto
historical events by decoding each prior commit's `data` CID (`commitDataCidRawLocked`, `:5508`).

**Per-op `prev`: yes for update and delete, absent for create — correct.**
`store.zig:5584-5598`: creates pass `null`, updates and deletes pass
`prev_record_cids[idx]` gathered by `previousRecordCidsLocked` (`:4891-4901`). zat emits the
`prev` key only when non-null (`/tmp/gap-scratch/zat/src/internal/streaming/firehose.zig:595-597`,
`:605-607`), matching the lexicon's "For creations, field should not be defined".

**Covering-proof blocks in the CAR slice: yes, by construction.** The tree is loaded lazily
(`zat.mst.Mst.loadLazy`, `store.zig:1990`) against a DB-backed block reader, mutated, then
`writeMstBlocks` → `tree.collectBlocks` (`store.zig:5101-5103`). `collectBlocks` skips
unloaded stubs (`/tmp/gap-scratch/zat/src/internal/repo/mst.zig:464`, `:524`
`if (isUnloadedStub(node)) return;`), so the emitted set is the newly materialized
root-to-leaf path plus whatever the mutation had to touch — the proof shape, not the whole
tree. Commit block + record blocks + MST path blocks are assembled at `store.zig:5568-5580`.

**No-op update rejection: NOT implemented.** I grepped
`/tmp/gap-scratch/zds/src/storage/store.zig` and `src/atproto/repo.zig` for
`no-op|noop|unchanged|identical` — no hits. `applyWritesMeasured` has no comparison of the
new record CID against `prev_record_cids`, and no comparison of the new MST root against
the previous one. A `putRecord` writing byte-identical content still allocates a seq,
signs a new commit, and emits a `#commit` frame. Swap preconditions *are* enforced
(`requireWriteSwapsLocked`, `store.zig:4866-4889`), but that is a different check.

**`getHostStatus` / `listReposByCollection`: neither is routed.** Both exist in the
canonical lexicons (`sync/getHostStatus.json`, `sync/listReposByCollection.json`); neither
string appears in `/tmp/gap-scratch/zds/src/http/router.zig`.

**⚠ zat version pin vs. the MST prevData bug.**
`/tmp/gap-scratch/zat/REPORT-mst-inversion-prevdata.md` documents this: `Mst.deleteFromNode`
recursed into a child subtree and marked the parent dirty but never dropped the child when
the delete emptied it. Because MST nodes are content-addressed, the emptied node still
serialized as a real block and changed every ancestor CID, so the tree no longer equalled a
tree that never contained the key — the equality that commit-proof inversion depends on.
Downstream, `verifyCommitDiff` returned `PrevDataMismatch` for valid second commits produced
by `@atproto/repo`, and the relay zlay dropped ~1.5M commits
(`REPORT-mst-inversion-prevdata.md:1-30`). Only the root was trimmed; the recursive case was
not. The fix (`pruneIfEmpty`, now at
`/tmp/gap-scratch/zat/src/internal/repo/mst.zig:390`, `:400`) shipped in **zat 0.3.19**
(`/tmp/gap-scratch/zat/CHANGELOG.md:15-17`). **zds pins zat v0.3.10**
(`/tmp/gap-scratch/zds/build.zig.zon:8-9`), nine releases earlier. The trigger shape is
ordinary — a repo with two records whose keys differ in height, then deleting the lower one.
I could not fetch the v0.3.10 tarball to read its `mst.zig` directly, so this is a
version-pin inference from the changelog, not a source diff: see "Confidence & unknowns".

## 7. Firehose

Implemented as a real producer. `com.atproto.sync.subscribeRepos` upgrades to a websocket
(`/tmp/gap-scratch/zds/src/atproto/sync.zig:293-316`) and spawns a detached OS thread per
connection (`afterInit`, `:33-41`).

- **Framing**: DAG-CBOR header `{op:1, t:"#..."}` immediately followed by the payload map,
  written as one binary websocket frame. Header built at `store.zig:5706-5711` (and by zat
  at `/tmp/gap-scratch/zat/src/internal/streaming/firehose.zig:528-545`); the websocket
  binary frame header is hand-rolled at `sync.zig:129-143` (`0x82`, then 7-bit / u16 / u64
  length forms) and written straight to the socket fd (`writeSocketAll`, `:145-165`).
- **Event types emitted**: `#commit` (`store.zig:5693`), `#sync` (`:5670`), `#identity`
  (`:5646`), `#account` (`:5626`). No `#info`, no `#labels`.
- **Seq source**: a monotonic counter in SQLite — `nextSeqLocked` (`store.zig:4832`),
  loaded at startup by `loadNextSeqLocked` (`:4818`) from `MAX(seq)` across `commits` and
  `seq_events`. Frames are persisted as blobs in `seq_events` inside the same transaction
  as the commit (`store.zig:2102-2110`), so the log survives restart.
- **Cursor resume**: `?cursor=` parsed at `sync.zig:305-309`, then
  `store.listSeqEvents(cursor, 100)` (`store.zig:2971`) pages `WHERE seq > ? ORDER BY seq ASC`.
  A malformed cursor silently degrades to 0 (`catch 0`, `sync.zig:307`) rather than
  returning the spec'd `FutureCursor` error.
- **Backfill window: unbounded.** Nothing prunes `seq_events` except account deletion
  (`store.zig:6529`, `DELETE FROM seq_events WHERE did = ?`). Every event since genesis is
  replayable, and the DB grows without bound.
- **Slow-consumer handling: none beyond a connection cap.** Max 32 concurrent
  subscribeRepos connections (`sync.zig:12`, `:294-299`) → `429 RateLimitExceeded`. Per
  connection, the streaming thread blocks in `writeSocketAll`, spinning on `EAGAIN` with
  `std.Thread.yield()` (`sync.zig:154-157`). There is no per-consumer outbound buffer, no
  lag detection, and no disconnect-the-laggard policy. Wakeups come from a global
  generation counter + condvar (`/tmp/gap-scratch/zds/src/storage/eventlog.zig:17-39`).
- Notable: `listSeqEvents` calls `backfillSeqEventsLocked` (`store.zig:2974`) on **every**
  poll, which re-scans `commits LEFT JOIN seq_events` for gaps while holding `db_mutex`.

Consumer-side, zat ships a full firehose client with reconnect/backoff and
accept-then-advance cursor semantics (`/tmp/gap-scratch/zat/src/internal/streaming/firehose.zig:713`,
`:779`, `:807-808`) plus a Jetstream client (`src/internal/streaming/jetstream.zig`). zds
does not consume either.

## 8. Account migration / import-export

All the pieces are present and routed:

| Method | Route | Status |
|---|---|---|
| `repo.importRepo` | router.zig:192 | real — CAR loaded, DID matched to session, commit verified, MST rebuilt (`repo.zig:343-395`) |
| `repo.listMissingBlobs` | router.zig:194 | real — `writeMissingBlobsJson` (`store.zig:2636`) via `expected_blobs LEFT JOIN blobs` |
| `server.checkAccountStatus` | router.zig:180 | real — `writeAccountStatusJson` (`store.zig:2686`) |
| `server.activateAccount` | router.zig:174 | real, and emits #account+#identity+#sync (`server.zig:963-965`) |
| `server.deactivateAccount` | router.zig:175 | real (`server.zig:976`) |
| `server.reserveSigningKey` | router.zig:156 | real (`store.zig:901`) |
| `identity.signPlcOperation` | router.zig:213 | real, email-token gated (`identity.zig:65-114`) |
| `identity.submitPlcOperation` | router.zig:214 | real, POSTs to `ZDS_PLC_DIRECTORY` (`identity.zig:115-153`) |
| `identity.getRecommendedDidCredentials` | router.zig:211 | real (`identity.zig:16-46`) |
| `repo.uploadBlob` | router.zig:193 | accepts service auth as well as bearer (`repo.zig:447-457`) |
| `server.createAccount` with existing `did` + `plcOp` | router.zig:157 | real migration path (`createAccount`, the `existing_did` branch) |
| `sync.getRepo` with `since` | router.zig:198 | real incremental export (`store.zig:2800`) |

`docs/operations.md:197-205` claims PDS Moover compatibility; the routes support the claim.
Migration trace tooling exists at `/tmp/gap-scratch/zds/dev/migration-trace.mjs`.

## 9. did:plc vs did:web

**Service DID**: either. `config.serverDid()` defaults to `did:web:localhost`
(`/tmp/gap-scratch/zds/src/core/config.zig:4`), set via `--server-did` / `ZDS_SERVER_DID`;
the production Fly config uses `did:web:pds.zat.dev` (`fly.toml`). zds serves its own
`/.well-known/did.json` (`/tmp/gap-scratch/zds/src/atproto/server.zig:29-38`) advertising a
single `#atproto_pds` service — so a `did:web` service DID is self-hosted. Nothing signs or
submits a PLC op for the *service* DID.

**Account DIDs**: `did:plc` for new signups (genesis op built and submitted in
`createAccount`); `did:web` accounts are supported on the migration path — an externally
supplied `did` is accepted after handle→DID bidirectional check, and
`getRecommendedDidCredentials` short-circuits `rotationKeys` to `[]` for
`did:web:` accounts (`/tmp/gap-scratch/zds/src/atproto/identity.zig:25-26`).

zat resolves both methods and only both: `Did.Method` enum
(`/tmp/gap-scratch/zat/src/internal/syntax/did.zig:29`), `DidResolver.resolve` switching
`.plc → resolvePlc`, `.web → resolveWeb`
(`/tmp/gap-scratch/zat/src/internal/identity/did_resolver.zig:46-49`). No `did:webvh`.
SSRF preflight rejects loopback did:web hosts (`did_resolver.zig:173`,
`/tmp/gap-scratch/zat/src/internal/identity/network_safety.zig`).

## 10. Blobs

**Where**: bytes on disk at `<ZDS_BLOBSTORE_PATH>/<did>/<cid>`, one file per blob, written
through libc `fopen`/`fwrite` (`/tmp/gap-scratch/zds/src/storage/blobstore.zig`, `put` and
`writeFileC`). Metadata (cid, did, mime_type, size) in the `blobs` SQLite table
(`store.zig:2507`, schema `:5960`).

**Validation**: size cap via `ZDS_BLOB_UPLOAD_LIMIT` enforced at read time
(`repo.zig:431-434` → `413 payload_too_large`). MIME is taken verbatim from the request
`content-type`, defaulting to `application/octet-stream` (`repo.zig:427`) — no sniffing, no
allowlist. OAuth `blob:` scope checked when the caller is an OAuth token
(`repo.zig:428-430`). The CID is computed server-side by `store.putBlob` (`store.zig:2493`).

**Reference tracking**: yes. `expected_blobs(blob_cid, record_uri)` is populated from blob
refs found while staging each record (`store.zig:2076-2082`), cleared on record delete
(`:2058`) and on overwrite (`:2074`). `getPublicBlob` only serves a blob that has at least
one live `expected_blobs` row (`store.zig:2548-2556`), so an orphaned blob is unreachable
over `sync.getBlob`.

**GC: none.** `blobstore.delete` exists (`blobstore.zig:29`) but
`grep -rn blobstore src/ | grep delete` finds no caller. Deleting a record removes the
reference row but leaves the bytes on disk and the row in `blobs` forever. There is no
sweeper, no refcount decrement, no quota.

## 11. Moderation / admin surface, takedown enforcement

Surface is one endpoint: `com.atproto.admin.updateSubjectStatus`
(`/tmp/gap-scratch/zds/src/atproto/server.zig:981`), authenticated by a shared static
`ZDS_ADMIN_TOKEN` (`requireAdminToken`, `:986`) — not per-moderator, not auditable to a
person. It sets/clears `takendown` and `deactivated`, and refuses the contradictory
combination (`:1011-1013`). No `getSubjectStatus` to read state back over XRPC; operators
read it from the `/admin/sessions` HTML page (`router.zig:151`) or SQLite.

**Enforcement is real and applied on both read and write paths.**
`AccountStatus` is `{active, takendown, suspended, deactivated, deleted}`
(`store.accountStatus`, `store.zig:1114`).
- Public sync reads gate through `requirePublicRepoAvailable`
  (`/tmp/gap-scratch/zds/src/atproto/sync.zig:342-354`) — `takendown` → `400 RepoTakendown`,
  `suspended` → `RepoSuspended`, `deactivated` → `RepoDeactivated`, `deleted` → `404`.
  Applied to `getBlob` (`:181`), `getRepo` (`:210`), `listBlobs` (`:252`),
  `getLatestCommit` (`:272`).
- Repo writes gate through `requireActiveAccount`
  (`/tmp/gap-scratch/zds/src/atproto/repo.zig:587-594`), called at `:21`, `:62`, `:195`,
  `:232`, `:350`, `:426`, `:566`.
- Status transitions emit `#account` firehose events (`server.zig:1048`).

`/tmp/gap-scratch/zds/docs/account-takedown-runbook.md:44-53` states plainly that only
`active`, `deactivated`, `takendown` have operator workflows and that "`suspended` and
`deleted` are reserved vocabulary from the protocol, but ZDS does not yet expose operator
workflows for them." The code agrees: `setAccountTakendown` and `setAccountActive`
(`store.zig:1088`, `:1065`) are the only mutators, and neither can produce `suspended`.

zds accepts no reports (`com.atproto.moderation.createReport` unrouted) and emits no labels.

## 12. Rate limiting, metrics, health, ops

- **Rate limiting**: a generic `consumeRateLimit(subject, action, now, window, limit)`
  exists (`store.zig:567`) with a SQLite-backed counter, but it is wired to exactly **one**
  endpoint: `identity.updateHandle`, at 10/5min and 50/day
  (`/tmp/gap-scratch/zds/src/atproto/identity.zig:199`, `:203`). There is no global
  per-IP or per-account limiter on `createAccount`, `createSession`, `createRecord`, or
  `uploadBlob`. Two hard concurrency caps stand in: 32 subscribeRepos connections
  (`sync.zig:12`) and `ZDS_MAX_CONCURRENT_REPO_EXPORTS` full `getRepo` exports
  (`sync.zig:214-220`), both returning `429 RateLimitExceeded`.
- **Metrics**: no Prometheus/OpenMetrics endpoint. There is an in-process latency/status
  recorder (`/tmp/gap-scratch/zds/src/internal/telemetry.zig`, invoked per request at
  `server.zig:54-62`) surfaced only as an HTML page at `/stats`
  (`/tmp/gap-scratch/zds/src/http/stats.zig`). `/api` and `/api/openapi.json` generate an
  endpoint inventory and an OpenAPI 3.1 document from the same route table
  (`/tmp/gap-scratch/zds/src/internal/api_reference/openapi.zig`) — a genuinely nice
  operator affordance.
- **Health**: `GET|HEAD /xrpc/_health` returning `{"version":…,"status":"ok"}`
  (`server.zig:186-195`), version injected at build time via `build_options`.
- **Ops story**: `docs/operations.md`, `docs/account-takedown-runbook.md`,
  `docs/invite-codes.md`, `docs/comail.md`, `docs/passkeys.md`, plus `tools/smoke.sh`,
  `tools/smoke-permissioned.sh`, `tools/plc_repair.zig`, `bench/` with a comparison harness
  against the official PDS (`bench/run-official-pds.sh`). Structured-ish logging is a
  hand-rolled `log.err/info/debug` with printf-style key=value strings
  (`/tmp/gap-scratch/zds/src/core/log.zig`), not JSON.

## 13. Notable spec deviations and explicitly-unsupported features

Author's own candid statements, each checked against code:

1. `README.md:144-148`: permissioned-data routes "are experimental and operator gated with
   `ZDS_PERMISSIONED_DATA` … the upstream proposal is still moving and this surface is not
   a stable compatibility contract." **Code agrees** — `space.zig:22-29` returns 501 when off.
2. `docs/architecture.md:6-8`: "It does not implement an appview. Appview requests are
   forwarded through the generic `atproto-proxy` path." **Code agrees** — `proxy.zig:138`,
   plus locally-served `app.bsky.actor.*Preferences` only.
3. `docs/account-takedown-runbook.md:51-52`: "`suspended` and `deleted` are reserved
   vocabulary from the protocol, but ZDS does not yet expose operator workflows for them."
   **Code agrees** (§11).
4. `docs/architecture.md:34-35`: "Passkeys are outside the official PDS surface ZDS tracks
   for compatibility." **Code partially disagrees in spirit** — they are outside the spec,
   but they are exposed *inside* the `com.atproto.server.*` namespace (`router.zig:165-169`),
   which is namespace squatting on Bluesky's NSID authority.
5. `docs/permissioned-data-proposal-94.md:203-206`: "ZDS exposes the proposal namespace
   directly and does not [use its] own older namespace." **Code agrees**.

Deviations the docs do *not* mention:

6. **`#sync` CAR root is the MST data CID, not the commit CID** — contradicts
   `sync/subscribeRepos.json` `#sync.blocks`. `store.zig:5666-5669`. (§6)
7. **No no-op write suppression** — a semantically empty `putRecord` still produces a
   sequenced commit and a firehose frame. (§6)
8. **zat pinned at v0.3.10**, predating the 0.3.19 MST empty-subtree prune fix that
   `REPORT-mst-inversion-prevdata.md` documents as producing non-canonical MST roots and
   `PrevDataMismatch` on relay inversion. (§6)
9. **`sync.getBlocks`, `sync.getRecord`, `sync.listReposByCollection`, `sync.getHostStatus`
   all absent** — relays and mirrors that expect the Sync-1.1 read surface will get
   `UnknownMethod`.
10. **`sync.requestCrawl` and `sync.notifyOfUpdate` return `{}` without doing anything**
    (`sync.zig:334-340`). A relay pointing at zds gets a 200 and no crawl.
11. **No `moderation.createReport`, no `admin.getSubjectStatus`, no label subsystem.**
12. **No account deletion path** — `server.deleteAccount`, `server.requestAccountDelete`,
    `admin.deleteAccount` all unrouted; blob bytes are never GC'd (§10).
13. **No password reset** — `requestPasswordReset`/`resetPassword` unrouted, so a user who
    forgets a password has no self-service recovery.
14. **`server.deleteSession` unrouted** — clients cannot log out server-side over the
    standard method (revocation exists, but only via app-password revoke or OAuth revoke).
15. **Malformed firehose cursor silently resets to 0** instead of erroring (`sync.zig:307`).
16. **No license file** (§1) — a real adoption blocker independent of protocol conformance.

## 14. Primitives inventory in zat (as requested)

`zat` v0.3.22 at HEAD, 18,398 lines. Public surface is `/tmp/gap-scratch/zat/src/root.zig`.

| Primitive | Present | Citation |
|---|---|---|
| `AtUri` | yes | `root.zig:12` → `src/internal/syntax/at_uri.zig` (339 lines) |
| `Tid`, `Did`, `Handle`, `Nsid`, `Rkey` | yes | `root.zig:7-11` |
| DID resolution (plc + web) | yes | `root.zig:16` → `src/internal/identity/did_resolver.zig:46-49` |
| Handle resolution (HTTPS well-known + DNS TXT over DoH) | yes | `root.zig:17` → `src/internal/identity/handle_resolver.zig:38`, `:48`, `:92` |
| SSRF guards on resolution | yes | `src/internal/identity/network_safety.zig` |
| DAG-CBOR encode/decode | yes | `root.zig:38` → `src/internal/repo/cbor.zig` (1,579 lines) + RFC 8949 vectors (`cbor_rfc8949_test.zig`) |
| CAR v1 read/write | yes | `root.zig:39` → `src/internal/repo/car.zig` (754 lines) |
| MST | yes | `root.zig:37` → `src/internal/repo/mst.zig` (2,318 lines); lazy load, `putReturn`/`deleteReturn`, `invertOp` (`:1061`) |
| Commit signing | yes | `root.zig:45` `signCommit` |
| Repo verification (full CAR) | yes | `root.zig:43` `verifyCommitCar` → `src/internal/repo/repo.zig:53` |
| Sync-1.1 diff verification | yes | `root.zig:54` `verifyCommitDiff` → `repo.zig:401`, `PrevDataMismatch` at `:474` |
| Firehose client (raw CBOR) | yes | `root.zig:70` `FirehoseClient` → `src/internal/streaming/firehose.zig:713` |
| Firehose event *encoder* | yes | `firehose.zig:430` `encodeCommitEvent` (zds's producer path) |
| Jetstream client | yes | `root.zig:65` |
| JWT / did:key / multibase / multicodec / keypairs | yes | `root.zig:27-31` |
| OAuth client toolkit (2.1 + DPoP) | yes | `root.zig:34` → `src/internal/oauth/{client,primitives}.zig` |
| XRPC client + HTTP transport | yes | `root.zig:20-21` |
| Lexicon runtime / codegen | **no** | `docs/roadmap.md` "maybe later": "lexicon codegen — probably a separate project" |
| `did:webvh` | **no** | only `.plc`/`.web` in `did_resolver.zig:46-49` |
| Session/token refresh management | **no** | `docs/roadmap.md` non-goals: "token refresh/session management — app-specific" |

zat claims to pass the Bluesky interop suite (`docs/roadmap.md`, "where it is"); the
dependency is wired lazily in `build.zig.zon:34-38` and exercised by
`src/internal/testing/interop_tests.zig`.

## 15. Maturity tier

**serious.**

zds routes 46 canonical `com.atproto.*` methods with working handlers across a real
multi-account store, ships a complete OAuth 2.1 authorization server (PAR + S256 PKCE +
DPoP with rotating server nonces + private_key_jwt + both well-knowns), produces a durable
resumable firehose with Sync-1.1 `prevData`, per-op `prev`, and covering-proof CAR slices,
and implements the full account-migration set end to end — that is not hobby scope, and the
operator docs, takedown runbook, benchmark harness against the official PDS, and
auto-generated OpenAPI reinforce it. It falls short of "reference" on concrete, citable
points rather than vibes: no license, one shared SQLite for all accounts, a `#sync` CAR
whose root is the wrong CID, no no-op write suppression, no blob GC or account deletion, a
single shared admin token as the whole moderation surface, rate limiting on exactly one
endpoint, and a zat pin nine releases behind a fix for an MST bug that is known to break
relay commit-proof inversion.

---

## Confidence & unknowns

- **UNVERIFIED: zat v0.3.10's actual `mst.zig`.** I read zat at HEAD (v0.3.22), where
  `pruneIfEmpty` exists (`src/internal/repo/mst.zig:390`, `:400`). The claim that zds's
  pinned v0.3.10 lacks it rests on `CHANGELOG.md:15-17` attributing the fix to 0.3.19 and
  on `REPORT-mst-inversion-prevdata.md:98-101` saying zlay "pins zat v0.3.10 … and needs a
  released version carrying this fix". To confirm, fetch
  `https://tangled.org/zat.dev/zat/archive/v0.3.10.tar.gz` and diff `deleteFromNode`.
- **UNVERIFIED: runtime behavior.** I did not build or run zds (no Zig 0.16 toolchain
  available in this environment). Every claim is static reading of source. In particular I
  did not observe an actual `#sync` frame on the wire to confirm the CAR-root finding
  empirically — but `syncEventFrame` (`store.zig:5656-5679`) and
  `latestCommitRawLocked` (`:5069-5074`) are unambiguous about which CID lands in `.roots`.
- **UNVERIFIED: whether the `#sync` CAR-root ordering actually breaks any consumer.** The
  lexicon text is explicit; whether real relays enforce it, I did not test.
- **UNVERIFIED: `com.atproto.space.*` / `simplespace.*` conformance to the draft.** I
  confirmed the NSIDs exist in the `permissioned-data` branch lexicons and that each is
  dispatched, but I did not diff request/response shapes against
  `lexicons/com/atproto/space/*.json` field by field.
- **UNVERIFIED: OAuth end-to-end.** I read the metadata document, PAR, PKCE, DPoP, and
  private_key_jwt code paths and they are substantive, but I did not run a client against
  them. In particular I did not verify `iss` is returned on the authorization response
  despite `authorization_response_iss_parameter_supported:true` being advertised
  (`oauth.zig:70`).
- **Partially verified: handler-by-handler "real work" claims.** I opened
  `describeServer`, `createAccount`, `getServiceAuth`, `updateSubjectStatus`,
  `activate/deactivateAccount`, all six `identity.*`, `importRepo`, `uploadBlob`,
  `listMissingBlobs`, all nine `sync.*`, and `space.dispatch` + three space handlers. The
  remaining `repo.*` and `server.*` handlers I confirmed only by their dispatch target in
  `server.zig:74-158` and their store-layer callees; I did not read every body.
- **UNVERIFIED: whether the repository is public / who else runs it.** `fly.toml` names
  `pds.zat.dev` and README references `atcr.io/zat.dev/zds`, but I did not check whether
  that host is live or whether any third party operates a zds instance.
- Both checkouts are shallow (`git rev-list --count HEAD` = 1 for each), so I could not
  read commit history, contributor count, or release cadence beyond what the changelogs
  state. zds `build.zig.zon:3` declares version `0.1.1`; zat HEAD is `v0.3.22`.
