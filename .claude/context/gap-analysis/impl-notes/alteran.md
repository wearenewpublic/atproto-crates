# alteran — implementation notes

Source examined: `/tmp/gap-scratch/alteran` @ `6bfa4be` ("Fix Deno publish TypeScript config", 2026-06-20).
All citations below are absolute paths under that scratch checkout. Canonical lexicons read from
`/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

## 1. Language, stack, build, license

TypeScript 5 (strict), targeting the Cloudflare Workers runtime. Deno is the task runner / package
manager / test runner; npm packages resolve through `nodeModulesDir: "auto"`
(`/tmp/gap-scratch/alteran/deno.json:19`). The product is not a server binary — it is an **Astro
integration** published to npm as `@alteran-social/astro` v0.9.7
(`/tmp/gap-scratch/alteran/package.json:2-3`) and to JSR via `deno.json:2-4`. The integration
default-export injects Astro routes and swaps the Cloudflare adapter's server entrypoint for
alteran's own (`/tmp/gap-scratch/alteran/index.js:127-206`).

Runtime dependencies of note: `@atproto/crypto`, `@atproto/syntax`, `@atproto/api`, `@did-plc/lib`,
`@ipld/dag-cbor`, `@ipld/car`, `multiformats`, `drizzle-orm`, `hono`, `jose`
(`/tmp/gap-scratch/alteran/package.json:40-58`). Note that `hono` is a declared dependency and
AGENTS.md claims "Hono 4 for XRPC routing" (`/tmp/gap-scratch/alteran/AGENTS.md:147`), but no source
file imports it — routing is pure Astro file-based routing plus a hand-rolled prefix check in the
Worker entrypoint. `src/app.ts` is a 14-line shim that lazily imports `_worker`
(`/tmp/gap-scratch/alteran/src/app.ts:1-14`).

License: MIT, "Copyright (c) 2025 Rawkode Academy" (`/tmp/gap-scratch/alteran/LICENSE:1-3`).

CI runs build + `deno test -A --no-check tests/` + `deno check` on 4 entry files only
(`/tmp/gap-scratch/alteran/.github/workflows/ci.yml`, `/tmp/gap-scratch/alteran/deno.json:33,35`).
63 test files exist under `tests/`.

## 2. Single-user vs multi-account; deployment model

Strictly single-user, and the single account is *configuration*, not a row created by an API call.
`PDS_DID` and `PDS_HANDLE` are required secrets (`/tmp/gap-scratch/alteran/src/lib/config.ts:7-10`);
`validateConfigOrThrow` fails the whole Worker if either is missing
(`/tmp/gap-scratch/alteran/src/lib/config.ts:165-179`, invoked at
`/tmp/gap-scratch/alteran/src/worker/runtime.ts:45`). The account row is lazily created on first
successful login from `USER_PASSWORD`
(`/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.server.createSession.ts:48-61`). `seed()` is an
explicit no-op (`/tmp/gap-scratch/alteran/src/db/seed.ts:1-6`).

Deployment is Cloudflare-only: Workers + D1 + R2 + one Durable Object (`Sequencer`), wired in
`/tmp/gap-scratch/alteran/wrangler.jsonc:18-38`, with `dev`/`staging`/`production` env blocks from
line 52. Alternative IaC via Alchemy (`deno task iac:deploy`,
`/tmp/gap-scratch/alteran/deno.json:44-46`). No container, no systemd, no self-host path — the
Workers runtime is a hard dependency (D1 bindings, R2 bindings, DO, `cloudflare:workers` import at
`/tmp/gap-scratch/alteran/src/middleware.ts:2`).

## 3. Storage backends

| Concern | Engine | Where |
|---|---|---|
| Accounts, app passwords, sessions, OAuth state | Cloudflare D1 (SQLite) via Drizzle | schema `/tmp/gap-scratch/alteran/src/db/schema.ts:9` (`account`), `:157` (`app_password`), `:20` (`refresh_token`), `:41` (`oauth_session`) |
| Repo root / commit history | D1 | `repo_root` `:61`, `commit_log` `:111` (full commit JSON + base64 sig) |
| MST blocks | D1, **base64 text column** | `blockstore` `:126-129` (`bytes: text`); writes at `/tmp/gap-scratch/alteran/src/db/repo.ts:171-203` |
| Denormalized record copies | D1 | `record` `:67` |
| Blobs | Cloudflare R2 | binding `ALTERAN_BLOBS`, key `blobs/by-cid/<b64url(sha256)>` (`/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.repo.uploadBlob.ts:224`) |
| Blob metadata / refcounts / quota | D1 | `blob` `:80`, `blob_usage` `:92`, `blob_quota` `:139` |

Migrations are Drizzle-generated SQL under `/tmp/gap-scratch/alteran/migrations/` (0000–0013),
config at `/tmp/gap-scratch/alteran/drizzle.config.ts`. Schema-of-record is
`/tmp/gap-scratch/alteran/src/db/schema.ts`.

Two sources of truth coexist for records: the MST (canonical per the comment at
`/tmp/gap-scratch/alteran/src/services/repo-manager.ts:346-364`) and the D1 `record` table.
`repo.listRecords` reads the MST (`.../com.atproto.repo.listRecords.ts:26-38`) while
`repo.getRecord` reads the `record` table (`.../com.atproto.repo.getRecord.ts:32-38`) — they can
disagree.

## 4. Endpoint coverage snapshot

The route table is the `CORE_ROUTES` array in `/tmp/gap-scratch/alteran/index.js:5-70`; each entry is
`injectRoute`d at `/tmp/gap-scratch/alteran/index.js:204`. `subscribeRepos` is *not* in that array —
it is intercepted ahead of Astro in the Worker entrypoint
(`/tmp/gap-scratch/alteran/src/worker/runtime.ts:109-133`).

### com.atproto.server.*

| NSID | Registered | Status |
|---|---|---|
| `describeServer` | index.js:42 | real |
| `createSession` | index.js:38 | real (password + app-password, IP lockout) |
| `refreshSession` | index.js:44 | real (rotating, single-use) |
| `getSession` | index.js:43 | real |
| `deleteSession` | index.js:39 | real |
| `checkAccountStatus` | index.js:36 | **non-conformant output** (below) |
| `getServiceAuth` | index.js:61 | real |
| `createAppPassword` | index.js:37 | real |
| `listAppPasswords` | index.js:40 | real |
| `revokeAppPassword` | index.js:41 | real |

`checkAccountStatus` returns `active`/`head`/`rev`/`recordCount`/`blobCount`/`seq`
(`.../com.atproto.server.checkAccountStatus.ts:76-95`) but the canonical lexicon requires
`activated`, `validDid`, `repoCommit`, `repoRev`, `repoBlocks`, `indexedRecords`,
`privateStateValues`, `expectedBlobs`, `importedBlobs`
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/checkAccountStatus.json`). `activated` and
`validDid` are absent; `repoBlocks` is hardcoded `0` (line 89).

Not routed at all: `createAccount` (501 by policy), `deleteAccount`, `activateAccount`,
`deactivateAccount`, `requestAccountDelete`, `updateEmail`, `confirmEmail`,
`requestEmailConfirmation`, `requestEmailUpdate`, `requestPasswordReset`, `resetPassword`,
`reserveSigningKey`, invite-code methods.

### com.atproto.repo.*

| NSID | Registered | Status |
|---|---|---|
| `createRecord` | index.js:28 | real (MST + signed commit + firehose) |
| `putRecord` | index.js:34 | real; no-op path short-circuits without a commit (`repo-manager.ts:242-258`) |
| `deleteRecord` | index.js:29 | real |
| `applyWrites` | index.js:27 | real, batched (`services/repo/apply-prepared-writes.ts:46-143`) |
| `getRecord` | index.js:31 | real, reads D1 `record`; proxies to AppView for foreign repos |
| `listRecords` | index.js:33 | real, reads MST |
| `describeRepo` | index.js:30 | **partial** — `collections` is a hardcoded 5-element list (`.../com.atproto.repo.describeRepo.ts:38-44`), not derived from the repo |
| `uploadBlob` | index.js:35 | real |
| `listMissingBlobs` | index.js:32 | real (scans D1 `record` JSON) |
| `importRepo` | — | **absent**. CAR parsing exists (`src/lib/car-reader.ts`) and is exercised by `tests/import-repo.test.ts`, but no route; the only importer is the offline `scripts/import-car-to-d1.ts` |

### com.atproto.sync.*

| NSID | Registered | Status |
|---|---|---|
| `subscribeRepos` | worker/runtime.ts:109 | real WebSocket → Sequencer DO |
| `getRepo` | index.js:53 | real full-CAR snapshot; **`since` accepted and ignored** (`.../com.atproto.sync.getRepo.ts:16`) |
| `getCheckout` | index.js:47 | real (alias of getRepo, plus a non-standard `from`/`to` range mode) |
| `getBlocks` | index.js:45 | real; 404s if *any* requested CID is missing, and lists every requested CID as a CAR root (`.../getBlocks.ts:41-48`) |
| `getRecord` | index.js:52 | real MST-path proof CAR (`services/car.ts:270-364`) |
| `getLatestCommit` | index.js:51 | real |
| `getHead` | index.js:50 | returns `{root}` only (deprecated method) |
| `getRepoStatus` | index.js:54 | real |
| `listRepos` | index.js:58 | real, but `active: true` is hardcoded (`.../listRepos.ts:24`) and ignores `account_state` |
| `listBlobs` | index.js:57 | real, validates did/since/limit |
| `getBlob` | index.js:49 | real, R2-backed |
| `getRepo.json`, `getCheckout.json`, `getBlocks.json`, `getRepo.range` | index.js:46,48,55,56 | **non-standard debug routes**, not AT Protocol NSIDs. `getRepo.range` fabricates blocks `{type:'commit',rev,head,ts}` that are not repo blocks (`services/car.ts:101-112`) |
| `getHostStatus`, `listReposByCollection`, `notifyOfUpdate`, `requestCrawl`, `listHosts` | — | **absent** (`requestCrawl` exists only as an *outbound* client, `src/lib/relay.ts:37-44`) |

### com.atproto.identity.*

| NSID | Registered | Status |
|---|---|---|
| `resolveHandle` | index.js:24 | real for the local handle; otherwise proxies to the AppView |
| `updateHandle` | index.js:26 | **stub** — unconditional 501 (`.../com.atproto.identity.updateHandle.ts:11-20`) |
| `getRecommendedDidCredentials` | index.js:22 | real (derives did:key from `REPO_SIGNING_KEY`, merges live PLC rotation keys) |
| `signPlcOperation` | index.js:60 | real, signs with `PDS_PLC_ROTATION_KEY`; **email token accepted and not enforced** (`.../signPlcOperation.ts:13-14,37`) |
| `submitPlcOperation` | index.js:25 | real POST proxy to `plc.directory`; does not validate the op belongs to the account despite the doc comment saying it does (`.../submitPlcOperation.ts:12-14` vs `:29-64`) |
| `requestPlcOperationSignature` | index.js:23 | **no-op 200** by design (`.../requestPlcOperationSignature.ts:30`) |
| `resolveDid`, `resolveIdentity`, `refreshIdentity` | — | absent |

### com.atproto.admin.* / moderation.* / label.* / temp.*

None routed. `com.atproto.admin.*` and a fixed list of signup/invite/temp methods return 501 from the
catch-all before authentication (`/tmp/gap-scratch/alteran/src/lib/unsupported-routes.ts:1-32`,
consulted at `/tmp/gap-scratch/alteran/src/pages/xrpc/[...nsid].ts:36-38`).
`com.atproto.moderation.createReport`, `com.atproto.label.queryLabels`, and
`com.atproto.label.subscribeLabels` are not routed and are not on the 501 list, so they fall through
to the catch-all's authenticated `404 NotImplemented` (`[...nsid].ts:50-55`).

### Non-`com.atproto` surface

Local `app.bsky` handlers: `actor.getPreferences`, `actor.putPreferences`, `labeler.getServices`,
`unspecced.getConfig`, `unspecced.getAgeAssuranceState` (index.js:63-67). Everything else matching
`app.bsky.` / `chat.bsky.` / `tools.ozone.` is proxied upstream with a minted ES256K service JWT
(`[...nsid].ts:11-17,57` → `src/lib/appview/proxy.ts:54`).

### README vs code

The README's "P0 Implementation — Core Protocol Compliance ✅" checklist
(`/tmp/gap-scratch/alteran/README.md:334-361`) is unreliable:
- README.md:103 claims "Responses include `x-ratelimit-*` headers". `checkRate` builds a `Headers`
  object at `/tmp/gap-scratch/alteran/src/lib/ratelimit.ts:37-40` and then **returns `null` without
  attaching it** (line 42). The 429 response (`:54-59`) also carries no rate-limit headers. No other
  file sets `x-ratelimit-*`. **The claim is false.**
- README.md:105 claims non-allowlisted origins "are denied at the CORS layer (no wildcard fallback)".
  `PDS_CORS_ORIGIN` is only ever read to emit a *warning* (`src/lib/config.ts:78-81`); the middleware
  unconditionally sets `Access-Control-Allow-Origin: *` (`src/middleware.ts:52`). **False.**
- README.md:294 claims `uploadBlob` enforces a MIME allowlist. The check is commented out:
  "Skip MIME type validation during migration — accept all types"
  (`/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.repo.uploadBlob.ts:82-83`). **False.**
- README.md:299 documents `sync.getHead` → `{root, rev}`; the handler returns `{root}` only
  (`.../com.atproto.sync.getHead.ts:15`).
- README.md:313-315 documents JSON firehose frames `{"type":"hello"...}` / `{"type":"commit"...}`.
  No such frames exist; the wire format is DAG-CBOR (below), and there is no hello/greeting frame.
- README.md:237-238 documents `PDS_ACCESS_TTL_SEC` / `PDS_REFRESH_TTL_SEC`. They are parsed into
  `getConfig()` (`src/lib/config.ts:221-222`) and **never read by the token issuer**, which hardcodes
  120 minutes / 90 days (`src/lib/session-tokens.ts:11-12`).
- README.md:99 and :180-186 list `ACCESS_TOKEN`/`REFRESH_TOKEN` as the HMAC keys; README.md:381-382
  instead says `REFRESH_TOKEN` + `REFRESH_TOKEN_SECRET`. The live signer uses `SESSION_JWT_SECRET`
  with a D1-persisted random fallback (`src/lib/session-tokens.ts:15-24`); `ACCESS_TOKEN` appears
  nowhere in `src/`.
- README.md:470-472 and :579-580, :646-647 link `P0_COMPLETE.md`, `P0_IMPLEMENTATION_SUMMARY.md`,
  `PROGRESS.md`, `P1.md`, `P1_IMPLEMENTATION_SUMMARY.md`, `P3.md`, `P3_IMPLEMENTATION_SUMMARY.md` —
  none of these files exist in the repository.

`docs/API.md` and `docs/SINGLE_USER_BOUNDARIES.md` are markedly more honest than README.md.

## 5. Auth posture

Three credential paths, all real:

1. **Session JWTs.** HS256 via `jose`, with a genuine access/refresh split enforced by the JOSE
   header `typ`: `at+jwt` for access, `refresh+jwt` for refresh
   (`/tmp/gap-scratch/alteran/src/lib/session-tokens.ts:161-172`). Claims include `sub`, `aud`
   (= service DID), `iat`, `exp`, `scope`, and `jti` on refresh (`:62-92`). `verifyAccessToken`
   rejects a refresh `typ` and vice versa (`:126-142`, `:103-124`), and the bearer path rejects any
   token carrying a DPoP `cnf` claim (`src/lib/jwt.ts:78-81`). Refresh tokens are single-use with
   `nextId` chaining and revocation rows (`src/db/schema.ts:20-38`). Access TTL 120 min, refresh TTL
   90 days (`session-tokens.ts:11-12`). A legacy hand-rolled HS256 path remains as a fallback in
   `src/lib/jwt.ts:124-161` keyed on `REFRESH_TOKEN`/`REFRESH_TOKEN_SECRET`.
2. **App passwords.** Scrypt-hashed rows, privileged flag, matched during `createSession`
   (`src/db/app-password.ts`, `.../createSession.ts:74-77`); scope taxonomy in
   `src/lib/auth-scope.ts`.
3. **Full OAuth authorization server.** PAR (`src/pages/oauth/par.ts`), authorize + consent
   (`src/pages/oauth/authorize.ts`, `consent.ts`), token (`token.ts`), revoke (`revoke.ts`), AS JWKS
   (`jwks.ts`). PKCE S256 verified at `src/pages/oauth/token.ts:75-76`. DPoP proof verification with
   `htm`/`htu`/`iat` window/JKT thumbprint and server-issued rotating nonce
   (`src/lib/oauth/dpop.ts:100-149`), with per-`jti` replay rejection backed by a D1 `secret` table
   insert-once (`:64-76`). Access/refresh tokens are bound via `cnf.jkt`
   (`session-tokens.ts:69-74`). Client auth supports `none` and `private_key_jwt` with `jwks` or
   remotely fetched `jwks_uri` (`src/lib/oauth/clients.ts:354-393,440-481`). Both well-knowns are
   served: `/.well-known/oauth-authorization-server`
   (`src/entrypoints/well-known/oauth-authorization-server.ts:13-36`, advertises
   `require_pushed_authorization_requests: true`, `code_challenge_methods_supported: ["S256"]`,
   `dpop_signing_alg_values_supported: ["ES256"]`) and `/.well-known/oauth-protected-resource`
   (`.../oauth-protected-resource.ts:13-20`). Refresh rotation detects replay and revokes the session
   (`src/pages/oauth/token.ts:160-218`).

**Service auth.** Minting is real and ES256K over `REPO_SIGNING_KEY` with `iss`/`aud`/`lxm`/`exp`/`jti`
(`src/lib/appview/service-jwt.ts:40-69`), exposed through `com.atproto.server.getServiceAuth` with
scope gating, protected-method denylist, and 60 s / 1 h expiry bounds
(`.../com.atproto.server.getServiceAuth.ts:10-19,62-80`). Verification exists
(`src/lib/service-auth.ts:144-184`: resolves `did:web`/`did:plc`, checks `aud`, `exp`, and the
ES256K signature) but is wired into exactly **one** route — `uploadBlob`
(`.../com.atproto.repo.uploadBlob.ts:144-150`). No `iat`/`jti` replay protection on the verify side.

## 6. Sync 1.1 status

- **`#commit` fields.** The payload builder emits `seq, rebase, tooBig, repo, commit, prev, rev,
  since, blocks, ops, blobs, time` plus `prevData` when derivable
  (`/tmp/gap-scratch/alteran/src/worker/sequencer/payload.ts:69-83`). `prevData` is recovered by
  looking up the previous `commit_log` row and parsing its stored `data` CID (`:47-53`) — so it is
  present only when the commit has a `prev` pointer and the row parses. `since` likewise
  (`:38-64`).
- **Per-op `prev`.** Emitted for updates and deletes:
  `apply-prepared-writes.ts:67,80`, `repo-manager.ts:267-269`, `deleteRecord` handler at
  `/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.repo.deleteRecord.ts:83-88`. Creates
  correctly omit it. Round-tripped through the DO by `worker/sequencer/cid-helpers.ts:20-32`.
- **Covering proofs — absent.** The firehose CAR is built by
  `/tmp/gap-scratch/alteran/src/services/car.ts:171-258`: commit block, then `newMstBlocks`, then one
  record block per op. `newMstBlocks` comes from `MST.getUnstoredBlocks()`
  (`src/lib/mst/mst.ts:149-170`), which returns **only nodes not already in the blockstore** — i.e.
  newly-created path nodes. There is no analogue of the reference implementation's per-write
  `getCoveringProof` pass (`/tmp/gap-scratch/bluesky-atproto/packages/repo/src/repo.ts:145-152`,
  `packages/repo/src/mst/mst.ts:784-791`), which additionally ships the immediate left and right
  sibling proof nodes. A relay doing inductive verification will be missing blocks.
- **No-op updates.** `putRecord` compares the incoming record CID to the MST entry and returns
  `{uri, cid, ops: []}` with no commit and no sequencer notification
  (`src/services/repo-manager.ts:242-258`; handler gate at
  `.../com.atproto.repo.putRecord.ts:74`). This satisfies the "don't emit empty commits" rule.
- **`#sync` event — wrong shape.** The canonical `#sync` requires `{seq, did, blocks, rev, time}`
  (`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json`, `defs.sync`). alteran's
  `SyncMessage` is `{seq, did, time, active, status?}`
  (`src/lib/firehose/frames.ts:162-168`) and is emitted only as a duplicate of `#account`, described
  in-code as "Compatibility #sync emission for clients on the legacy topic"
  (`src/worker/sequencer/broadcast.ts:79-82`). It carries neither `blocks` nor `rev`. This is not the
  Sync 1.1 `#sync` event.
- **`getHostStatus` / `listReposByCollection`:** not implemented (verified against
  `/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getHostStatus.json` and
  `listReposByCollection.json`; no matching route in `index.js` and no handler file).

## 7. Firehose

Implemented. `GET /xrpc/com.atproto.sync.subscribeRepos` is intercepted before Astro
(`src/worker/runtime.ts:109-133`); non-WebSocket requests get 426. All traffic is funneled to a single
Durable Object instance `idFromName('default')` (`:130`).

- **Framing:** each WebSocket message is `dagCbor(header) || dagCbor(body)` with header
  `{op: 1, t: '#commit'}` (`src/lib/firehose/frames.ts:45-49,82-85`, encoders at `:214-234`). That is
  the correct AT Protocol subscription framing, notwithstanding the misleading "Deprecated for WS
  firehose" comments at `:43-44` and `:171-173`. The 4-byte-length-prefixed `toFramedBytes()`
  (`:55-64`) is not used on the wire.
- **Event types emitted in practice:** `#commit` and `#info` only. The DO exposes `/identity` and
  `/account` POST handlers (`src/worker/sequencer.ts:88-89`) but **nothing in `src/` ever calls
  them** — the only sequencer client is `notifySequencer`, which always POSTs `/commit`
  (`src/lib/sequencer.ts:11`). `#identity`/`#account`/`#sync` are therefore dead code paths today.
- **Sequence source:** `seq` is the `commit_log.seq` INTEGER PRIMARY KEY, reconciled against DO
  storage on construction (`src/worker/sequencer.ts:54-80`) and reused if the commit CID already has
  a row (`:120-170`).
- **Cursor resume:** `?cursor=` is parsed and validated (`src/worker/sequencer/upgrade.ts:38-45`); a
  future cursor gets an `#info` `OutdatedCursor` frame then a 1008 close (`:76-95`). Replay is served
  from the in-memory buffer first, falling back to `commit_log` **capped at 100 rows**
  (`src/worker/sequencer.ts:250-296`). Note the lexicon's `FutureCursor` error name is not used;
  alteran sends `OutdatedCursor`, which the lexicon lists as an `#info` name, not a cursor-ahead
  signal.
- **Backfill window:** in-memory buffer of `PDS_SEQ_WINDOW` (default 512) events
  (`src/worker/sequencer.ts:50`); D1 `commit_log` is the durable backstop.
- **Slow consumers:** there is no per-socket backpressure. Overflow of the shared buffer drops the
  oldest event and broadcasts an `#info` `FramesDropped` frame to all clients
  (`src/worker/sequencer.ts:324-350`). `FramesDropped` is not a lexicon-known `#info` name. Sends
  that throw are counted and ignored (`src/worker/sequencer/broadcast.ts:33-40`); connections are
  never closed for lag, so `ConsumerTooSlow` is never signalled.
- WebSocket hibernation is used by default (`src/worker/sequencer.ts:239`,
  `upgrade.ts:97-103`).

## 8. Account migration / import-export

| Method | State |
|---|---|
| `com.atproto.repo.importRepo` | **not routed**. Parser + tests exist; import is an offline script (`scripts/import-car-to-d1.ts`) |
| `com.atproto.repo.listMissingBlobs` | routed, real (index.js:32) |
| `com.atproto.server.checkAccountStatus` | routed, output missing two required fields (§4) |
| `com.atproto.server.activateAccount` / `deactivateAccount` | **not routed** — the names appear only in scope tables (`src/lib/auth-scope.ts:76,80`; `src/lib/appview/auth-policy.ts:33,36`). The `account_state` FSM (`src/lib/account-state.ts:16-21`, table at `src/db/schema.ts:149`) exists and is read by write paths, but no XRPC method can transition it |
| `com.atproto.identity.signPlcOperation` | routed, real |
| `com.atproto.identity.submitPlcOperation` | routed, real |
| `com.atproto.identity.getRecommendedDidCredentials` | routed, real |
| `com.atproto.identity.requestPlcOperationSignature` | routed, deliberate no-op 200 |
| `com.atproto.sync.getRepo` / `getBlob` / `listBlobs` | routed (export side works) |

Net: an *outbound* migration (export CAR + blobs, sign and submit a PLC op) is workable; an
*inbound* migration to alteran requires the offline script, and the account cannot be
deactivated/activated over the wire.

## 9. did:plc vs did:web

Both are accepted as the account/service DID — `PDS_DID` is opaque configuration, validated only as
starting with `did:` (`src/lib/config.ts:84-87`). README.md:330 says "This single-user PDS uses
`did:web`", but `wrangler.jsonc:58` ships a `did:plc:` value for the dev env, and the PLC endpoints
(`signPlcOperation`, `submitPlcOperation`, `getRecommendedDidCredentials`) hardcode
`https://plc.directory` (`.../signPlcOperation.ts:59,72`, `.../submitPlcOperation.ts:58`,
`.../getRecommendedDidCredentials.ts:67`) with no configurable directory host.

`did:web` support is first-class on the serving side: `/.well-known/did.json` is generated from
`REPO_SIGNING_KEY` with a `Multikey` `#atproto` verification method and an
`AtprotoPersonalDataServer` service entry (`src/entrypoints/well-known/did.json.ts:53-79`), and
`/.well-known/atproto-did` is served only when the request Host matches the configured handle
(`src/entrypoints/well-known/atproto-did.ts:12-21`). Service-auth verification resolves both
`did:web` and `did:plc` issuers (`src/lib/service-auth.ts:63-70`).

## 10. Blobs

Stored in R2 under content-addressed keys `blobs/by-cid/<base64url(sha256 digest)>`
(`.../com.atproto.repo.uploadBlob.ts:215-227`); the returned ref is a proper CIDv1 raw (`0x55`) +
sha2-256 (`:220-221`), and the response uses the `{$type: 'blob', ref: {$link}, mimeType, size}`
shape (`:116-123`).

Validation: size cap `PDS_MAX_BLOB_SIZE` (default 5 MiB) enforced both streaming
(`readBodyBounded`, `src/lib/util.ts:31-75`) and post-hoc (`:218`); `gzip`/`deflate`/`deflate-raw`
content-encodings are decompressed with the cap applied to the decompressed stream (`:163-173`);
MIME is sniffed from magic bytes and preferred over the client header
(`src/lib/util.ts:121-164`, resolution at `:187-196`). **The MIME allowlist is disabled** (`:82-83`).
The whole blob is materialized in memory, contradicting AGENTS.md's "R2: stream blobs" rule
(`/tmp/gap-scratch/alteran/AGENTS.md:99`).

Ref-counting is real: `blob_usage` rows are written/removed in the same D1 batch as the commit
(`src/db/dal.ts:96,204-230`), `getBlob` refuses to serve a blob with no usage rows
(`.../com.atproto.sync.getBlob.ts:52-54`), and unreferenced keys are swept opportunistically on write
paths (`sweepEligibleUnreferencedBlobKeys`, `src/db/blob.ts:166`; called from
`.../putRecord.ts:87`, `.../deleteRecord.ts:126`, `.../uploadBlob.ts:85`). A per-DID quota is
enforced at registration (`registerBlobRefWithQuota`, `src/db/blob.ts:42`). A manual sweep route
exists at `POST /debug/gc/blobs`, gated to non-production/localhost
(`src/pages/debug/gc/blobs.ts:7-17`).

Blockstore and commit-log GC are **written but never invoked**: `pruneOrphanedBlocks`
(`src/lib/blockstore-gc.ts:130`) and `pruneOldCommits` (`src/lib/commit-log-pruning.ts:20`) have no
callers anywhere in `src/`, `scripts/`, or `tests/` — despite README.md:142-153 presenting them as
the retention story. D1 growth is therefore unbounded in practice.

## 11. Moderation / admin / takedown

None. `com.atproto.admin.*` returns 501 by policy
(`src/lib/unsupported-routes.ts:14,21-32`); `com.atproto.moderation.createReport` and
`com.atproto.label.*` are unrouted. `tools.ozone.*` is proxied to a configured external Ozone
(`src/lib/config.ts:29-30`, `[...nsid].ts:11-17`). `app.bsky.labeler.getServices` is served locally
from `src/lib/labeler.ts`.

Takedown *enforcement* exists as internal plumbing only: the `account_state` FSM has a `takendown`
state (`src/lib/account-state.ts:16-21`), auth contexts carry `isTakendown`
(`src/pages/xrpc/com.atproto.server.getServiceAuth.ts:115-118`), and write paths check
`isAccountActive`. But no endpoint can *set* that state, so takedowns are D1-surgery-only. The
project states this is deliberate: "It does not provide hosted moderation administration, public
report triage, or labeler/Ozone operations"
(`/tmp/gap-scratch/alteran/docs/SINGLE_USER_BOUNDARIES.md:62-64`).

## 12. Rate limiting, metrics, health, ops

- **Rate limiting:** D1-backed fixed-window counter, buckets `writes` (default 60/min) and `blob`
  (30/min), keyed by DID on write paths (`src/lib/ratelimit.ts:4-46`). It creates its `rate_limit`
  table with `CREATE TABLE IF NOT EXISTS` on every call (`:20`) — the table is not in the Drizzle
  schema. It is **fail-open** on any exception (`:43-45`) and, as noted, emits no rate-limit headers.
  Separately, `createSession` has a real per-IP lockout: 5 failures → 15 minutes
  (`.../createSession.ts:16-17,80-116`).
- **JSON body cap:** real. `readJsonBounded` requires `Content-Type: application/json`, reads
  `PDS_MAX_JSON_BYTES` (default 65536), rejects on `Content-Length` and again on accumulated stream
  bytes, cancelling the reader (`src/lib/util.ts:22-29,31-75`). Wired into `createRecord`,
  `putRecord`, `deleteRecord`, `applyWrites`, `putPreferences`. `createSession` and
  `createAppPassword` use the older `readJson`, which hardcodes 64 KiB and reads the full body first
  (`src/lib/util.ts:15-20`).
- **Metrics:** an in-memory counter/histogram collector (`src/lib/metrics.ts:142-193`) fed from
  middleware (`src/middleware.ts:99,127`). **No endpoint exposes it** — it dies with the isolate. The
  only introspection is `GET /debug/sequencer`, which proxies the DO's `/metrics`
  (`src/worker/runtime.ts:92-108`).
- **Health:** `GET /health` checks D1 `SELECT 1` and an R2 `list({limit:1})`, returning 503 on
  failure (`src/pages/health.ts:14-67`); `GET /ready` checks D1 only (`src/pages/ready.ts`).
- **Logging:** structured JSON to `console.log` with a per-request UUID echoed as `X-Request-ID`
  (`src/middleware.ts:74-108`), plus Cloudflare observability (`wrangler.jsonc:39`). Note
  `src/lib/jwt.ts:44-160` logs verification progress via `console.error` on every request, including
  header contents.
- **Relay announcement:** `com.atproto.sync.requestCrawl` is fired at `bsky.network` at most once per
  12 h per isolate (`src/lib/relay.ts:55-81`), skipped for relay-initiated paths
  (`src/worker/runtime.ts:78-84`).
- Ops docs: `docs/SECRET_ROTATION.md`, `docs/MIGRATION_GUIDE.md`, `docs/SINGLE_USER.md`, plus ~28
  helper scripts in `scripts/` (including `repair-mst-from-record-table.ts` and
  `verify-mst-completeness.ts`, which are themselves a signal about repo-integrity incidents).

## 13. Notable spec deviations and explicitly-unsupported features

The project's own top-of-README warning, verbatim
(`/tmp/gap-scratch/alteran/README.md:3-4`):

> [!WARNING]
> This project was built using agentic coding tools and is currently undergoing a systematic review by a human in their spare time. Nobody should use this project as their PDS yet.

Deliberate non-goals, from `docs/SINGLE_USER_BOUNDARIES.md:13-19`: public account signup; invite
codes; signup queues and phone verification; hosted account recovery; in-product ToS acceptance;
moderation administration, report triage, and running a labeler/Ozone. Code agrees — those NSIDs are
in the 501 set at `src/lib/unsupported-routes.ts:1-12`. The same doc is careful to say stable 501s
are guaranteed *only* for the documented list (`:21-23`), which matches the catch-all behaviour.

Deviations the docs do **not** cover, all code-verified:

1. `#sync` frames have the `#account` shape, not the Sync 1.1 shape (§6).
2. No covering-proof blocks in the firehose CAR (§6).
3. `#identity` and `#account` are never emitted (§7).
4. `checkAccountStatus` omits the required `activated` and `validDid` (§4).
5. `describeRepo.collections` is a hardcoded literal (§4).
6. `sync.getRepo` silently ignores `since`, so every fetch is a full snapshot (§4).
7. Four non-NSID sync routes (`*.json`, `getRepo.range`) are injected into `/xrpc/`, one of which
   returns synthetic non-repo blocks (§4).
8. `identity.updateHandle` is an unconditional 501 even though the DID document and
   `atproto-did` well-known are generated from config (§4).
9. `signPlcOperation` accepts and ignores the email challenge token — a deliberate single-user
   choice, documented in the handler comment, but a divergence from the lexicon's intent.
10. Rate-limit headers, CORS origin enforcement, MIME allowlist, and TTL configuration are all
    documented and not implemented (§4).
11. Blockstore/commit-log pruning is documented and never called (§10).
12. `listRepos` reports `active: true` unconditionally (§4).
13. `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*` proxying **requires authentication for every
    request** (`[...nsid].ts:40-48`), including methods that are public upstream.

## 14. Maturity tier

**hobby-experiment.**

The README instructs that nobody should use it as their PDS (`README.md:3-4`), and the code bears
that out: three separately-documented capabilities (rate-limit headers, CORS enforcement, blob MIME
allowlist) are dead or disabled, two GC utilities have no callers, the metrics collector has no
readout, and the firehose ships a mis-shaped `#sync` event, no covering proofs, and no
`#identity`/`#account` emission at all. That said, the OAuth authorization server (PAR + PKCE + DPoP
with nonce and replay rejection + `private_key_jwt` + both well-knowns), the MST/commit machinery,
and the blob ref-counting are substantially more built-out than the tier name suggests — this is a
low-maturity project with a few unexpectedly deep subsystems, not a toy.

## Confidence & unknowns

- **Not run.** No build, test, or live request was executed; every claim above is from reading
  source. Runtime behaviour of the Astro `injectRoute` + Cloudflare adapter composition
  (`index.js:194-205`) is inferred from the code, not observed.
- **Covering proofs.** I verified that `encodeBlocksForCommit` adds only commit block + unstored MST
  nodes + op record blocks, and that the reference implementation additionally calls
  `getCoveringProof` per write. I did **not** construct a repo and diff the two CARs, so the exact
  set of missing blocks per operation shape is UNVERIFIED.
- **`prevData` completeness.** Derived by re-parsing the previous `commit_log.data` JSON
  (`payload.ts:47-53`). I did not verify empirically how often that lookup fails (e.g. after commit
  log pruning, or for the first commit), so the practical `prevData` hit rate is UNVERIFIED.
- **Test coverage claims.** 63 test files exist; I read only `tests/import-repo.test.ts`'s header.
  Whether the suite meaningfully exercises the firehose wire format or OAuth end-to-end is
  UNVERIFIED.
- **AS JWKS purpose.** `/oauth/jwks` publishes a generated ES256 P-256 key
  (`src/lib/oauth/as-keys.ts:7-29`) while access tokens are HS256. I did not find any code that signs
  with that key; whether it is vestigial or reserved is UNVERIFIED.
- **`hono` dependency.** Declared and referenced in AGENTS.md but I found no `import ... from 'hono'`
  in `src/`. I did not grep the published `index.js` bundle output (there is none in-tree), so a
  build-time use is UNVERIFIED but unlikely.
- **`iac/` directory.** Referenced by AGENTS.md:162 and `deno.json:44-46` but not present in this
  checkout; the Alchemy deployment path is UNVERIFIED.
- **Lexicon conformance beyond the eight files opened.** I read `subscribeRepos.json`,
  `checkAccountStatus.json`, `getServiceAuth.json`, `listMissingBlobs.json`, `getRepoStatus.json`,
  `listRepos.json`, `getHostStatus.json`, `listReposByCollection.json`. Field-level conformance of the
  other routed methods (e.g. `applyWrites` result unions, `describeServer` links/contact) is
  UNVERIFIED against the JSON.
