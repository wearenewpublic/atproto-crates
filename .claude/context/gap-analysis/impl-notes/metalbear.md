# MetalBear — implementation notes

Source examined: `/tmp/gap-scratch/metalbear` @ `6beac9b` ("docs(security): route reports
through the private advisory form"). Version `0.6.1` (`CMakeLists.txt:2`, `README.md:21`).
All citations below are paths relative to that checkout unless noted.

**Important scoping caveat up front:** MetalBear is the PDS application layer only. Every
protocol primitive — DAG-CBOR, CID, CAR, MST, commit signing, PLC operation build/sign,
JWT/DPoP verification, the WebSocket XRPC server, the rate limiter, the firehose *frame
encoder* (`wf_sync_publish_event`) — lives in the sibling **Wolfram** SDK
(`CMakeLists.txt:21-32`, which hard-fails if `../wolfram` is absent). That checkout was
**not** present under `/tmp/gap-scratch`, so anything reached through a `wf_*` call is
marked UNVERIFIED. The "hand-rolls everything in C" scrutiny therefore lands mostly on
Wolfram, not here.

---

## 1. Language, stack, build, license

C11, no extensions (`CMakeLists.txt:4-6`). CMake ≥ 3.20. One static library
`metalbear_core` from 19 `.c` files plus a 332-line `main.c` (`CMakeLists.txt:35`,
`src/main.c`). 16,381 lines of C total across `src/`; `src/server.c` alone is 7,065 lines.
Warnings are `-Wall -Wextra -Wpedantic` (`CMakeLists.txt:54`).

External deps: SQLite3, pthreads, and (through Wolfram) libmicrohttpd, libcurl, OpenSSL,
libsecp256k1, cJSON, libzstd, zlib (`README.md:207-209`, `Dockerfile:15-31`).

License: **AGPL-3.0** (`LICENSE:1-2`; `README.md:448-451` notes the network-use clause).

The only non-C component is `frontend/`, a SvelteKit landing page prerendered to static
files that reads the server's own XRPC endpoints in the browser (`README.md:419-423`).

Tests: 12 ctest binaries (`CMakeLists.txt:63-143`), ~5,600 lines, largest being
`test/test_server.c` (1,859 lines) and `test/test_repo_store.c` (880). GitHub Actions CI
(`.github/workflows/ci.yml`, `release.yml`).

## 2. Multi-account, deployment model

**Multi-account, genuinely.** There is no configured "the account". Accounts arrive only
through `com.atproto.server.createAccount` (`README.md:296-299`); each gets an isolated
data directory (`src/server.c:3402-3410`) and its own SQLite bundle. A host-wide registry
(`accounts.sqlite3`) maps DID → handle → data directory (`src/account_registry.c:64-90`,
`src/server.c:6545`), and every request resolves through an LRU-ish account cache
(`src/server.c:6603-6613`, `src/account_cache.c`). The design record is
`docs/multi-account.md`. Numerous comments in `server.c` record the migration away from a
single baked-in account (e.g. `src/server.c:1238-1240`, `src/server.c:280-286` in
`oauth_routes.c`, `src/server.c:646-648`).

Deployment: container-first. Three published images — Debian bookworm-slim (~168 MB),
Alpine/musl (~40 MB), and a dev image with toolchain + tests (`README.md:167-187`,
`Dockerfile`, `Dockerfile.alpine`). Prebuilt release tarballs for linux x86_64/aarch64 and
macOS arm64 (`README.md:197-204`). `scripts/setup.sh --hostname …` provisions a host end to
end (`README.md:230-238`). No systemd unit ships in the repo. **It does not terminate
TLS** — bind to loopback, reverse-proxy in front, and the proxy must forward WebSocket
upgrades or the firehose never serves (`README.md:212-214`, `README.md:395-399`).

Config: TOML file (`./config.toml` or `$METALBEAR_CONFIG`) with environment override;
unknown keys are a hard error with a line number (`README.md:240-268`,
`config.example.toml`, `src/config_file.c`). Only two CLI flags exist: `--version` and
`--help` (`README.md:308-310`).

## 3. Storage backends

Everything is SQLite (plus a flat blob directory). No Postgres, no S3.

| Store | File | Schema |
|---|---|---|
| Account registry, invite codes, takedowns | `<data>/accounts.sqlite3` | `src/account_registry.c:66-88` |
| Firehose event log | `<data>/sequencer.sqlite3` | `src/sequencer.c:316-322` |
| OAuth AS state (PAR/code/refresh/signing key) | `<data>/server_oauth.sqlite3` | `src/oauth.c:190-205`, `src/server.c:6533` |
| Moderation reports | `<data>/reports.sqlite3` | `src/report.c:28-42` |
| PLC rotation / reserved keys | `<data>/…` via `key_rotation` | `src/server.c:6506`, `src/key_rotation.c` |
| **Per account:** repo blocks + record index | `<acct>/repo.sqlite3` | `src/repo_store.c:687-699` |
| Per account: session secret + refresh chain | `<acct>/auth.sqlite3` | `src/auth.c:362-368` |
| Per account: state, credentials, app passwords, email tokens, prefs | `<acct>/account.sqlite3` | `src/account.c:44-64` |
| Per account: blobs | flat files + `.mime` sidecar | `src/blob_store.c:228-259` |

Per-account file layout is assembled in `src/account_context.c:68-74`.

Repo storage detail: `blocks(cid TEXT PRIMARY KEY, data BLOB, repo_rev TEXT)`
(`src/repo_store.c:692-693`) and a denormalised `records(collection, rkey, cid, value)`
index (`:696-699`) used by `listRecords`. Blocks are written `INSERT OR IGNORE`
(`src/repo_store.c:518-519`) and **never deleted** — there is no `removedCids` handling, so
the block table grows monotonically with every commit and retains unreachable MST nodes
forever.

Two RAM characteristics worth flagging: `metalbear_repo_store_open` calls
`load_all_blocks(s)` (`src/repo_store.c:818`), holding the **entire repo** in an in-memory
`wf_car`; and `metalbear_blob_store_new` reads **every blob's bytes** off disk into a
linked list at open (`src/blob_store.c:119-175`). Both are fine at the ~1 MB/account scale
the README benchmarks (`README.md:385`) and are a hard ceiling above it.

## 4. Endpoint coverage snapshot

Routes are registered in three places: the bulk in `src/server.c` (two `if(...)` chains at
`:6642-6710` / `:6712-6733` and a third at `:6757-6953`), the repo/label family in
`src/repo_store.c:2884-2921`, and `subscribeRepos` in `src/sequencer.c:734-739`. Blob
routes also exist in `src/blob_store_server.c:180-214` but the live server overrides them
with its own limit-enforcing handlers (`src/server.c:6704-6709`).

Method types (query/procedure/subscription) were cross-checked against
`/tmp/gap-scratch/atproto/lexicons/com/atproto/**`; **all 73 registrations match the
canonical lexicon type.**

### com.atproto.server (25)

| NSID | Kind | Registered | Notes |
|---|---|---|---|
| describeServer | q | `server.c:6643` | real; emits `did`, `availableUserDomains`, `inviteCodeRequired`, `contact`, `links` (`:686-…`) |
| createAccount | p | `server.c:6647` | real; see §9 for DID handling |
| createSession | p | `server.c:6674` | real (scrypt verifier + app-password path) |
| getSession / refreshSession / deleteSession | q/p/p | `:6676`, `:6678`, `:6680` | real |
| createAppPassword / listAppPasswords / revokeAppPassword | p/q/p | `:6682`, `:6685`, `:6688` | real; privileged flag persisted (`account.c:54-57`) |
| deactivateAccount / activateAccount | p/p | `:6691`, `:6694` | real; emits `#account` + `#identity` + `#sync` |
| getServiceAuth | q | `:6697` | real; see §5 |
| requestAccountDelete / deleteAccount | p/p | `:6758`, `:6761` | real; email token + password |
| requestEmailConfirmation / confirmEmail / requestEmailUpdate / updateEmail | p×4 | `:6769`-`:6778` | real (email delivery only when SMTP configured) |
| requestPasswordReset / resetPassword | p/p | `:6781`, `:6784` | real |
| getAccountInviteCodes | q | `:6787` | real |
| checkAccountStatus | q | `:6790` | real (`server.c:3879`) |
| reserveSigningKey | p | `:6793` | real, unauthenticated by design (`server.c:3931-3941`) |
| createInviteCode / createInviteCodes | p/p | `:6796`, `:6799` | real; **admin-Basic gated**, not bearer (`server.c:244-245`) |

### com.atproto.identity (9)

| NSID | Kind | Registered | Notes |
|---|---|---|---|
| resolveHandle | q | `server.c:6649` | local registry only (`server.c:776-791`) |
| resolveDid / resolveIdentity | q/q | `:6651`, `:6654` | local first, else network (PLC dir / did:web well-known) |
| refreshIdentity | p | `:6657` | real |
| getRecommendedDidCredentials | q | `:6660` | real (`server.c:1233-1283`) |
| updateHandle | p | `:6663` | real; constrained to the configured `user_domain` |
| requestPlcOperationSignature | p | `:6665` | real — mails a token (`server.c:1372-1418`) |
| **signPlcOperation** | p | `:6668` | **STUB.** Returns an *unsigned* skeleton with `"prev": ""` and no `sig`. Its own comment: `src/server.c:1446-1448` — "The full implementation would fetch the last operation from the PLC directory and apply updates; here we return a signed operation skeleton that a PLC client can complete." Defaults are also wrong-typed: `verificationMethods.atproto` defaults to `acct->did` (a `did:plc:`, not a `did:key:`) at `server.c:1543`, and `rotationKeys` defaults to `server->service_did` (a `did:web:`) at `server.c:1524`. |
| **submitPlcOperation** | p | `:6671` | **STUB.** Validates structure then returns `{}` without contacting the directory — `src/server.c:1576-1577`: "In a full implementation, we would submit to the PLC directory here. For now, acknowledge the operation." Its rotation-key check also compares against `service_did` rather than a `did:key` (`server.c:1562-1568`), so it can only ever pass for operations that embed a `did:web`. |

### com.atproto.repo (10)

| NSID | Kind | Registered |
|---|---|---|
| createRecord | p | `repo_store.c:2889` |
| putRecord | p | `repo_store.c:2891` |
| deleteRecord | p | `repo_store.c:2895` |
| applyWrites | p | `repo_store.c:2897` |
| getRecord | q | `repo_store.c:2900` |
| describeRepo | q | `repo_store.c:2903` |
| listRecords | q | `repo_store.c:2906` |
| importRepo | p | `repo_store.c:2918` |
| uploadBlob | p | `server.c:6704` |
| listMissingBlobs | q | `server.c:6706` |

All real. Writes go through lexicon validation against a shipped corpus, honour the
`validate` tri-state, and report `validationStatus`
(`repo_store.c:1675-1723`, `repo_store.c:383-421`); unknown collections are accepted as
`unknown` rather than rejected (`repo_store.c:394-397`). CAS via `swapCommit`/`swapRecord`
is implemented and returns `InvalidSwap` (`repo_store.c:1745-1757`). `describeRepo`
resolves the *authoritative* DID document to compute `handleIsCorrect` rather than agreeing
with itself (`repo_store.c:2276-2305`).

### com.atproto.sync (13)

| NSID | Kind | Registered | Notes |
|---|---|---|---|
| getLatestCommit | q | `repo_store.c:2912` | real |
| getRepo | q | `server.c:6714` | real; `since` maps to `repo_rev > ?` (`repo_store.c:2537-2540`) |
| getBlocks | q | `server.c:6716` | real, dedupes CIDs (`repo_store.c:2607-2650`) |
| getRecord | q | `server.c:6727` | CAR with commit + record block only (`repo_store.c:2652-2700`) |
| getRepoStatus | q | `server.c:6718` | real; `status` only ever `"deactivated"` (`server.c:2809`) |
| listRepos | q | `server.c:6722` | real; **integer-offset cursor** (`server.c:5703-5711`) |
| listReposByCollection | q | `server.c:6724` | real (`server.c:5604+`) |
| listBlobs | q | `server.c:6720` | real, but `since` is accepted and ignored — "MetalBear's blob store does not track per-blob revisions" (`server.c:2829-2831`) |
| getBlob | q | `server.c:6709` | real, with `nosniff` + `Content-Disposition: attachment` + `default-src 'none'; sandbox` (`server.c:5566-5595`) |
| getHead | q | `server.c:6729` | deprecated shim (`server.c:5151`) |
| getCheckout | q | `server.c:6731` | deprecated; literally `return get_repo(...)` (`server.c:5193-5198`) |
| subscribeRepos | ws | `sequencer.c:737-738` | real; see §7 |
| requestCrawl | p | `server.c:6947` | **not a PDS endpoint.** The canonical lexicon (`sync/requestCrawl.json`) is the *relay* side. MetalBear re-implements it as an outbound forwarder that echoes the caller's body to every configured crawler (`server.c:4925-5008`). It is on the public/unauthenticated list (`server.c:226`), so any anonymous caller can make this host issue `requestCrawl(hostname=<anything>)` at `bsky.network`, rate-limit permitting. |

### com.atproto.admin (13)

All 13 registered at `server.c:6903-6941`: `getAccountInfo`, `getAccountInfos`,
`getSubjectStatus`, `updateSubjectStatus`, `sendEmail`, `updateAccountHandle`,
`updateAccountEmail`, `updateAccountPassword`, `enableAccountInvites`,
`disableAccountInvites`, `getInviteCodes`, `disableInviteCodes`, `deleteAccount`. All
gated by HTTP Basic `admin:<password>`, constant-time compared (`server.c:262-292`).
Handlers do real work — but see §11 on takedown enforcement.

### Other

- `com.atproto.moderation.createReport` — p, `server.c:6943`; persists locally to
  `reports.sqlite3` (`report.c:28-42`). Not forwarded anywhere.
- `com.atproto.label.queryLabels` — q, `repo_store.c:2909`.
- `com.atproto.temp.checkSignupQueue` — q, `server.c:6951`; hardcoded
  `{ "activated": true }` (`server.c:5202-5215`). Honest stub, labelled as such.
- `_health` — q, `server.c:6645`; returns `{ "version": … }` only (`server.c:766-774`).
  Served at `/xrpc/_health`.
- HTTP (non-XRPC) routes: `/.well-known/did.json`, `/.well-known/atproto-did`, `/`,
  `/operator.json` (`server.c:6389-6416`), plus the 7 OAuth routes
  (`oauth_routes.c:502-517`).
- ~40 `app.bsky.*` / `chat.bsky.*` AppView-proxy routes (`server.c:6802-6900`) and local
  `app.bsky.actor.{get,put}Preferences` (`server.c:6801-6805`, backed by
  `account.sqlite3 preferences`).

### Canonical `com.atproto.*` methods NOT served

`admin.searchAccounts`, `admin.updateAccountSigningKey`, `label.subscribeLabels`,
`lexicon.resolveLexicon`, `sync.getHostStatus`, `sync.listHosts`, `sync.notifyOfUpdate`,
`temp.addReservedHandle`, `temp.checkHandleAvailability`, `temp.dereferenceScope`,
`temp.fetchLabels`, `temp.requestPhoneVerification`, `temp.revokeAccountCredentials`.
(`sync.getHostStatus` and `sync.listHosts` are relay-side, so their absence is correct for
a PDS.)

### README vs code

The README's feature list is broadly accurate on *what routes exist*. Discrepancies found:

- `README.md:38-39` says `listBlobs` is "backed by Wolfram's `wf_blob_store_list`". The
  handler calls MetalBear's own `metalbear_blob_store_list` (`server.c:2843`), and the
  `since` parameter is ignored.
- `README.md:71-72` advertises `updateSubjectStatus` as applying "takedown, deactivation, or
  reactivation status". Takedown is *recorded* but never *enforced* — see §11. The
  README's own Status section (`README.md:409-410`) contradicts the feature list here.
- `README.md:111` says backups are "compressed". `src/backup.c` has no compression at all
  (grep for `zlib|zstd|compress|deflate` in `src/backup.c` returns nothing); the format is a
  bespoke `METALBEAR_BACKUP_V1` container with per-file CRC32 (`src/backup.c:14-27`).
  Worse: `metalbear_backup_*` is referenced from nowhere in `src/`, `pdsadmin/`, or
  `scripts/` — only from `test/test_backup.c`. **There is no way to take a backup from the
  shipped binary or admin CLI.**
- `README.md:31` claims `getServiceAuth` JWTs are "repository-key-signed" — correct
  (`repo_store.c:2704-2718` signs with the account's `s->key`).

## 5. Auth posture

**Session/app-password auth: real and reasonably careful.** HS256 JWTs with `typ` split
between `at+jwt` and `refresh+jwt`, a per-account 32-byte secret generated on first use and
persisted in `auth.sqlite3` (`auth.c:317-343`), refresh rotation with a recorded successor
and a 2-hour reuse grace window (`auth.c:493-616`), revocation, and app-password-scoped
sessions (`com.atproto.access` / `appPass` / `appPassPrivileged`, `auth.c:140-173`).
Verification checks `alg`, `typ`, `scope`, `aud == service_did`, `sub == account_did`,
`iat`, `exp` (`auth.c:290-297`). Passwords and app passwords are scrypt verifiers with
random salts (`README.md:358-359`, `account.c:51-57`).

Route classification: a fixed public list (`server.c:201-230`), a fixed admin-Basic list
(`server.c:235-258`), and everything else requires a bearer token
(`server.c:432-551`). Deactivated accounts are blocked except on a small allow-list
(`server.c:417-424`). Full-access-only routes are enumerated (`server.c:426-430`).

**Service auth: minted, never verified.** `getServiceAuth` is a real implementation with
audience syntax validation, `lxm` NSID validation, a protected-method deny-list
(`server.c:1901-1924`), a privileged-method check against app-password scope
(`server.c:1927-1930`), and expiry bounds (≤3600s with `lxm`, ≤60s without)
(`server.c:1975-1983`). But **nothing in MetalBear verifies an inbound service-auth JWT**:
`authenticate()` (`server.c:432`) handles exactly two credential shapes — admin Basic, and
an HS256 session JWT verified against the account's own auth store. An inter-service
request bearing an ES256K service JWT signed by another PDS is rejected.

**OAuth: a complete authorization server whose tokens the resource server does not
accept.** The seven endpoints exist (`oauth_routes.c:502-517`): RFC 8414 metadata, RFC 9728
protected-resource metadata, JWKS, PAR, authorize, token, revoke. PAR persists
`code_challenge` + `dpop_jkt` (`oauth.c:250-293`), the code exchange enforces S256 PKCE and
`dpop_jkt` equality (`oauth.c:509-513`), refresh rotates one-shot
(`oauth.c:562-568`), and access tokens are ES256 JWTs carrying `cnf.jkt`
(`oauth.c:377-428`). Three problems:

1. **`/oauth/authorize` authenticates nobody.** It takes `login_hint`, resolves it to a
   DID, and immediately mints an authorization code and 302s to the client's
   `redirect_uri` (`oauth_routes.c:287-341`). No password, no session cookie, no consent
   screen. Anyone who can reach the endpoint can obtain a fully-scoped OAuth session for
   any account on the host by naming its handle. The README describes this as
   "Authorization endpoint with auto-approval" (`README.md:86`).
2. **DPoP is a form field, not a proof.** `/oauth/par` and `/oauth/token` read `dpop_jkt`
   from the request parameters (`oauth_routes.c:213-218`, `:401`, `:420`) instead of
   validating a `DPoP` header proof JWT per RFC 9449. There is no nonce issuance
   (`use_dpop_nonce`), no `htu`/`htm`/`ath` checking at these endpoints, and no
   `jkt`-from-thumbprint derivation. `metalbear_oauth_verify_request()` — which *does*
   wrap Wolfram's real proof validator and replay cache (`oauth.c:597-621`) — **is dead
   code: it is called from nowhere in `src/`, `include/`, or `test/`.**
3. **OAuth tokens cannot authenticate an XRPC call.** `authenticate()` runs
   `jwt_subject()` then `metalbear_auth_verify_access_scope()` (`server.c:500-521`), which
   requires `alg == HS256` and an HMAC match against the account's session secret
   (`auth.c:290`). An ES256 OAuth access token fails that unconditionally. The OAuth store
   is only ever touched by the `/oauth/*` handlers (`server.c` mentions `oauth` at lines
   17, 19, 123, 6533-6542, 6747-6752, 7040 — none inside the auth path).

`private_key_jwt` is advertised in the metadata (`oauth_routes.c:130-131`) but no client
assertion is parsed anywhere in `oauth_routes.c`.

## 6. Sync 1.1 status

Better than one would expect, with one structural gap.

- **`#sync` events: yes.** Emitted on account activation (`sequencer.c:210-238`), on
  `importRepo` (`repo_store.c:2849`), and on startup reconciliation when a repo's head does
  not match its newest logged event (`sequencer.c:399-474`). The CAR carries exactly one
  block — the commit — with an explicit comment citing the lexicon's `maxLength: 10000` and
  the reference's `getBlocks([root.cid])` (`repo_store.c:2579-2605`).
- **`prevData` on commits: yes.** The previous commit is parsed and its `data` CID carried
  through (`repo_store.c:972-985` → `sequencer.c:361-362`).
- **Per-op `prev`: yes.** `metalbear_repo_store_op.prev`/`has_prev` is populated for updates
  and deletes (`repo_store.c:1000-1008`, copied at `sequencer.c:386-387`), and the lexicon
  `#repoOp` does define `prev` (verified in `sync/subscribeRepos.json`).
- **Batched `applyWrites` produces one `#commit` with all ops** (`sequencer.c:363-391`).
- **Covering-proof blocks: NOT assembled as such.** The `#commit` `blocks` field is
  `metalbear_repo_store_export(s, previous.rev, …)`, i.e. `SELECT cid FROM blocks WHERE
  repo_rev > ?` (`repo_store.c:2537-2540`). That is "every block written since the previous
  revision", not the reference's `relevantBlocks` = union of
  `data.getCoveringProof(dataKey)` per op plus added leaves plus the commit block
  (`/tmp/gap-scratch/atproto/packages/repo/src/repo.ts:145-159`). In the common case the
  rewritten root→leaf MST path is new, so the two coincide. They diverge in exactly the
  case the reference handles explicitly at
  `/tmp/gap-scratch/atproto/packages/pds/src/actor-store/repo/transactor.ts:177-186` — a
  record whose CID is unchanged but whose position moved. MetalBear's `INSERT OR IGNORE`
  (`repo_store.c:518`) leaves such a block stamped with its *original* `repo_rev`, so it
  falls out of the `repo_rev > since` window and the proof is short a block.
- **No-op updates: not rejected, not suppressed.** `metalbear_repo_store_put_record` has no
  content-equality short-circuit (`repo_store.c` put path, ~`:1745`-`:1825`): an identical
  `putRecord` mints a new rev, a new commit, and a `#commit` whose `data` equals its
  `prevData`.
- **Full `getRepo` returns unreachable blocks.** With no `since`, the export is
  `SELECT cid FROM blocks ORDER BY repo_rev DESC` (`repo_store.c:2540`) — every block ever
  written, including superseded MST nodes and replaced record leaves, since nothing is ever
  deleted.
- **`getHostStatus`**: not implemented (relay-side, so correctly absent).
  **`listReposByCollection`**: implemented (`server.c:6724`, handler at `server.c:5604`).

## 7. Firehose

`com.atproto.sync.subscribeRepos` is a real WebSocket subscription registered via
`wf_xrpc_server_register_ws` (`sequencer.c:734-739`).

- **Storage model:** frames are serialized *once* at append time by
  `wf_sync_publish_event()` and stored as a BLOB in `sequencer.sqlite3`
  (`sequencer.c:103-180`). Replay is a straight `SELECT seq,frame FROM events WHERE seq>?
  ORDER BY seq LIMIT 1` (`sequencer.c:530-532`) — so cursor resume survives restarts
  natively, and historical frames are byte-identical to what live subscribers saw.
- **Event types emitted:** `#commit`, `#sync`, `#identity`, `#account`, `#info`
  (`sequencer.c:125-148`, `:591-603`). That is the complete `main.message.refs` set from
  the canonical `sync/subscribeRepos.json`.
- **Seq source:** SQLite `INTEGER PRIMARY KEY AUTOINCREMENT` rowid, but **seeded from the
  wall clock** on an empty log (`sequencer.c:260-297`) so a restored/rebuilt data directory
  never re-issues sequence numbers a consumer already holds. The rationale comment
  (`sequencer.c:240-259`) explicitly notes the reference PDS has the opposite hazard. This
  is a thoughtful deviation, not an accident.
- **Cursor handling:** non-integer cursor → `InvalidRequest`; cursor > current →
  `FutureCursor`; cursor below the retention high-water mark → `#info{OutdatedCursor}`
  emitted *before* replay rather than a silent jump (`sequencer.c:678-719`,
  `sequencer.c:588-604`). The `pruned_through` meta key is the honest basis for that
  (`sequencer.c:77-101`, written at `sequencer.c:786-796`).
- **Keepalive:** WS ping every 20s by default, configurable, sized against nginx's 60s
  `proxy_read_timeout` (`sequencer.c:556-565`, `:663-669`).
- **Backfill window / retention:** `retention_max_age_seconds` (default 30 days) and
  `retention_min_events` (default 1000) (`server.c:7012-7018`), pruned by
  `metalbear_sequencer_retain` — **which runs exactly once, at startup**
  (`server.c:7020-7023`). A process that stays up for months never prunes. README is honest
  about this (`README.md:122`).
- **Slow-consumer handling: none.** Each subscriber gets a detached pthread
  (`sequencer.c:724-731`) that polls with 250 ms condvar waits (`sequencer.c:617-629`) and
  writes with a blocking `wf_xrpc_server_ws_send`; there is no bounded outbox, no
  backpressure metric, and no "consumer too slow, disconnect" path. N subscribers = N
  threads each issuing one SQLite query per event.

### Byte-format fidelity

The frame encoder itself (`wf_sync_publish_event`, `wf_sync_publish_error`,
`wf_subscribe_decode_frame`) is Wolfram's — **UNVERIFIED**. What is visible on the
MetalBear side:

- Record JSON → DAG-CBOR conversion is hand-written here (`repo_store.c` `cbor_from_json`).
  It correctly rejects non-integral and >2^53 numbers with the comment "DAG-CBOR forbids
  floats / oversized ints", maps `null`/`false`/`true` to simple values 22/20/21, and
  round-trips single-key `{"$link":…}` / `{"$bytes":…}` objects to CBOR link/bytes.
  Canonical map-key ordering happens inside `wf_cbor_serialize` — UNVERIFIED.
- The reverse path (`cbor_to_json`, `repo_store.c:424+`) goes through `cJSON` doubles, so
  integers above 2^53 in an *imported* repo are mangled in the `records.value` index and
  therefore in `getRecord`/`listRecords` JSON output — though not in the stored CBOR block
  or its CID.
- Firehose op paths are built into a fixed `char[512]` with `snprintf`
  (`sequencer.c:341`, `:380-382`). A `collection/rkey` longer than 511 bytes is **silently
  truncated** into the emitted `#commit` op path rather than erroring.
- Every DID/rev/handle field is `snprintf`'d into fixed Wolfram-owned buffers
  (`sequencer.c:187-207`, `:344-358`); those capacities are UNVERIFIED, so the same
  silent-truncation class may apply elsewhere.

## 8. Account migration / import-export

| Piece | State |
|---|---|
| `repo.importRepo` | **Real.** CAR body verified via `wf_repo_import` against the store's DID + signing key, blocks merged, head swapped, record index rebuilt, `#sync` emitted (`repo_store.c:2785-2856`). Bad CAR → `InvalidCAR` without touching the existing repo. |
| `repo.listMissingBlobs` | **Real and careful.** Walks every record's JSON for modern `{"$type":"blob"}` and legacy `{cid,mimeType}` refs, dedupes by CID, sorts ascending, cursor is strictly-greater-than (`server.c:2872-3018`). Comments cite rsky-pds' contract as the model. |
| `server.checkAccountStatus` | **Real.** `activated`, `validDid`, `repoCommit`, `repoRev`, `repoBlocks`, `indexedRecords`, `expectedBlobs`, `importedBlobs`; `privateStateValues` hardcoded 0 (`server.c:3879-3927`). |
| `server.activateAccount` / `deactivateAccount` | **Real**, with firehose `#identity` + `#account` + `#sync` on activation (`sequencer.c:210-238`). |
| `server.reserveSigningKey` | **Real**, unauthenticated, reserves in the host key store (`server.c:3931-3953`). |
| `identity.getRecommendedDidCredentials` | **Real** (`server.c:1233-1283`) — but note it returns the account's *signing* did:key as its sole `rotationKeys` entry (`server.c:1268-1270`), which is not what the host actually uses to sign PLC ops (that is the server-wide rotation key, `server.c:3177-3180`). |
| `identity.requestPlcOperationSignature` | **Real** (emails a token). |
| `identity.signPlcOperation` | **STUB** — unsigned skeleton, see §4. |
| `identity.submitPlcOperation` | **STUB** — never reaches the directory, see §4. |
| `createAccount` `plcOp` / `recoveryKey` | **Ignored.** Neither string appears anywhere in `src/`. The canonical `server/createAccount.json` defines both. |

Net: **outbound** migration off MetalBear works to the extent the operator drives PLC by
hand; **inbound** migration cannot complete through the protocol, because the two endpoints
that would rewrite the DID document are stubs.

## 9. did:plc vs did:web

**Service DID:** `did:web` is the documented and exercised path
(`config.example.toml:16`, `README.md:302`). `main.c:100-105` refuses to start on a
malformed `did:plc:` service DID but permits any syntactically valid DID. The host serves
its own document at `/.well-known/did.json` (`server.c:6389-6390`) and answers
`/.well-known/atproto-did` per-hostname (`:6392-6393`).

**Account DIDs:** three paths in `create_account` (`server.c:3373-3401`):

1. Caller supplies `did` → **taken verbatim**, with no check that the document resolves,
   that it lists this PDS as `atproto_pds`, or that the caller controls it
   (`server.c:3374-3383`).
2. `plc_url` configured (default `https://plc.directory`, `config.example.toml:39`) →
   **mints a real `did:plc`**: fresh secp256k1 account key, host rotation key signs the
   genesis op, deterministic DID computed from the *signed* op "matching the `@did-plc/lib`
   reference implementation", then submitted to the directory
   (`server.c:3150-3272`). This is the real thing.
3. Otherwise → generates a bare **`did:key:`** as the account DID
   (`server.c:3393-3401`). `did:key` is not a valid AT Protocol account DID method; such an
   account can never federate. It is a silent fallback, not an error.

`did:web` account DIDs are supported for *resolution* (`server.c:889-928`) and the server
recognises did:webs whose document it publishes itself (`server.c:929-951`), but nothing
mints one.

## 10. Blobs

Stored as flat files under the account directory, one file per CID plus a `<cid>.mime`
sidecar, with a full in-memory mirror (`blob_store.c:16-28`, `:228-259`).

- **Validation:** CID is computed server-side from the bytes (`wf_cid_of_bytes`,
  `server.c:5488`), so the returned `$link` is always correct. MIME is taken verbatim from
  `Content-Type` with no sniffing, no allow-list, and no lexicon `accept`/`maxSize` check
  at upload time. Size is capped by a single global `blob_upload_limit` (default 5 MB,
  `config.example.toml:69`, enforced at `server.c:5472-5477`).
- **Serving hardening is good:** `X-Content-Type-Options: nosniff`,
  `Content-Disposition: attachment` with the CID sanitised to `[A-Za-z0-9]` before it goes
  into the header, and `Content-Security-Policy: default-src 'none'; sandbox`
  (`server.c:5566-5595`).
- **GC / ref-counting: none.** `metalbear_blob_store_delete` exists
  (`blob_store.c:302-353`) but is called from no handler. Blobs uploaded and never
  referenced, or referenced by a since-deleted record, stay on disk and in RAM forever.
  `listMissingBlobs` walks refs → blobs; nothing walks blobs → refs.
- The blob CID validity check is `[A-Za-z0-9]+` only (`blob_store.c:96-105`) — it does not
  verify multibase/multicodec structure, but it is sufficient to keep path traversal out of
  `blob_path()`.

## 11. Moderation / admin, and takedown enforcement

Admin surface is 13 `com.atproto.admin.*` procedures behind HTTP Basic (§4), driven by
`pdsadmin/metalbear-admin.sh`, which mirrors the reference `pdsadmin` script
(`README.md:130-143`, `pdsadmin/metalbear-admin.sh:1-16`).

`com.atproto.moderation.createReport` persists reports into `reports.sqlite3`
(`report.c:28-42`). There is no read-back endpoint and no forwarding to a moderation
service — reports are write-only from the operator's perspective unless they open SQLite.

**Takedown is recorded but never enforced.** `admin.updateSubjectStatus` writes into a
`subject_takedown(did, uri, blob_cid, takedown_ref, created_at)` table
(`account_registry.c:84-88`, `account_registry.c:513-555`) and `admin.getSubjectStatus`
reads it back (`server.c:4189-4202`). Grepping `takedown` across `src/` and `include/`
returns **only** those two call sites plus the registry accessors — no read path
(`getRecord`, `listRecords`, `getRepo`, `getBlob`, `subscribeRepos`) and no write path ever
consults it. A taken-down repo, record, or blob is served exactly as before, and no
`#account` event with `status: "takendown"` is ever emitted (the only statuses produced are
`"deactivated"` at `sequencer.c:509` and `"deleted"` at `server.c:679-680`). This matches
the README's Status section and contradicts its feature list — see §13.

Account deletion: `server.deleteAccount` requires password + emailed token, revokes all
sessions, deletes credentials, deactivates, removes the registry row, emits
`#account{active:false, status:"deleted"}`, and retracts the DNS TXT record
(`server.c:620-684`). It does **not** delete the data directory; `admin.deleteAccount` does
(`README.md:69-70`, handler at `server.c:4753+`).

## 12. Rate limiting, metrics, health, ops

- **Rate limiting:** a token bucket is constructed from `limits.rate_limit` /
  `rate_limit_window_seconds` (default 100/60s in code, `server.c:6572-6577`; 3000/60 in
  the shipped example, `config.example.toml:64-65`) and installed globally
  (`server.c:6958-6959`). The bucket implementation, and therefore whether it actually keys
  on client IP as `README.md:147` claims, is `wf_rate_limiter_new` in Wolfram —
  **UNVERIFIED**. The README itself warns the default budget is too low for one AppView or a
  backfilling relay (`README.md:390-393`).
- **Metrics: none.** No Prometheus endpoint, no counters, no `/metrics` route — grep for
  `prometheus|metrics` across `src/` returns nothing.
- **Logging:** four `LOG_*` macros over a `metalbear_log` printf shim to stderr
  (`server.c:98-101`). Unstructured, no request IDs, no levels beyond the four.
- **Health:** `/xrpc/_health` returning `{version}` only (`server.c:766-774`) — no
  dependency checks, no readiness/liveness split.
- **Backups:** implemented as a library (`src/backup.c`, custom container + CRC32) but
  **not reachable from the binary or the admin CLI** (§4). Restore likewise.
- **Key rotation:** `metalbear_key_rotation_rotate()` exists (`src/key_rotation.c`) and
  `reserveSigningKey` uses the reserve path, but no XRPC or CLI surface triggers a rotation.
- **DNS handle publication:** Cloudflare only (`src/handle_dns.c`); a provider named without
  credentials is refused at startup (`README.md:291-294`).
- **Crawl announcement:** `requestCrawl` fired at configured relays on every write, throttled
  to once per 20 minutes (`server.c:4884` `notify_crawlers`, wired at `server.c:6589`,
  interval `config.example.toml:77`).

## 13. Notable spec deviations and the project's own Status section

The README's Status section, verbatim (`README.md:401-417`):

> ## Status
>
> MetalBear federates. A running instance is consumed by Bluesky's relays and by
> several third-party ones, its commits verify against the key published in the
> PLC directory, and its posts, profile and media appear on the Bluesky AppView.
>
> Still missing or unproven for production use:
>
> - no takedown model, so only `deactivated` and `deleted` account statuses are
>   ever reported
> - `listRepos` paginates on an integer offset rather than a keyset, so concurrent
>   account creation can skip or repeat an entry across pages
> - account deletion does not purge that DID's earlier firehose events
> - no metrics or structured operational logging
> - automatic `_atproto` record publication is implemented for Cloudflare only;
>   on any other DNS provider the operator writes one TXT record per account by
>   hand, or handles never resolve

Verification of each claim against the C source:

| Claim | Verdict | Evidence |
|---|---|---|
| No takedown model; only `deactivated`/`deleted` reported | **TRUE** | takedown table written/read only at `server.c:4189-4202` and `:4276-4288`; no enforcement anywhere. `getRepoStatus` hardcodes `"deactivated"` (`server.c:2809`), `listRepos` likewise (`server.c:5765`), `#account` statuses are `"deactivated"` (`sequencer.c:509`) and `"deleted"` (`server.c:679-680`). |
| `listRepos` integer-offset pagination | **TRUE** | cursor parsed with `strtol` into a row offset (`server.c:5703-5711`), next cursor is the scan index (`server.c:5775-5781`). |
| Deletion does not purge earlier firehose events | **TRUE** | `delete_account` (`server.c:620-684`) and `admin_delete_account` (`server.c:4753+`) never call into the sequencer except to append one `#account`; the only DELETE against `events` is retention (`sequencer.c:767-768`). |
| No metrics or structured logging | **TRUE** | no metrics route; `LOG_*` → stderr printf (`server.c:98-101`). |
| Cloudflare-only DNS publication | **TRUE** | `src/handle_dns.c` is the only provider; `config.example.toml:108` — "the only one implemented". |

Additional deviations the README does not mention:

1. **`repo=<handle>` is not accepted on public reads.** The lexicons declare `repo` as
   `at-identifier` (verified in `repo/getRecord.json`, `listRecords.json`,
   `describeRepo.json`), but `request_account_did` only accepts a `did:`-prefixed value or
   an `at://` URI (`server.c:338-361`); anything else returns NULL and the handler answers
   `RepoNotFound` (`repo_store.c:2100-2108`). Handle-addressed reads fail.
2. **`repo` is ignored on authenticated writes.** `request_account_did` returns
   `authed_subject` before ever looking at `repo` (`server.c:341-342`), so a write naming
   another DID silently lands in the caller's own repo instead of erroring.
3. **`createAccount` requires `email` and `password`** (`server.c:3294-3308`); the lexicon
   requires only `handle`.
4. **OAuth authorize has no user authentication** (§5) — the single most consequential
   deviation on this list.
5. **OAuth access tokens are not accepted by the XRPC layer** (§5).
6. **Inbound service auth is not verified** (§5).
7. **`signPlcOperation` / `submitPlcOperation` are stubs** (§4, §8).
8. **`did:key` account-DID fallback** when no PLC directory is configured (§9).
9. **`sync.requestCrawl` is an unauthenticated outbound forwarder** with an
   attacker-controlled body (§4).
10. **Blob GC and block GC do not exist** (§3, §10).
11. **Backup/restore is unreachable code** (§4, §12).
12. **`listBlobs` ignores `since`** (`server.c:2829-2831`).
13. **Handle label length is clamped to 3–18 characters** on createAccount
    (`server.c:3355-3360`) — a local policy, not a protocol rule.

## 14. Maturity tier

**serious.**

It is multi-account, it mints real `did:plc` identities and submits them to the directory,
it serves a durable restart-surviving firehose with `#sync`/`prevData`/per-op-`prev` and
honest `OutdatedCursor` semantics, it validates records against a shipped lexicon corpus,
and the README's federation claim is specific and falsifiable rather than aspirational —
that is well past hobby-experiment, and the code is littered with comments recording
specific federation bugs found and fixed against live relays. What holds it below
"reference" is a set of load-bearing gaps that are structural rather than cosmetic: the
OAuth authorization endpoint authenticates nobody and its tokens are not accepted by the
resource server, inbound service auth is unverified, both PLC-operation endpoints are
stubs so inbound migration cannot complete, takedown is recorded but never enforced, and
there is no GC, no metrics, and no reachable backup path.

---

## Confidence & unknowns

Verified by reading MetalBear's own C source, with every route registration and every
NSID cross-checked against `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

**UNVERIFIED — would need the Wolfram checkout** (`WOLFRAM_SOURCE_DIR`, absent from
`/tmp/gap-scratch`):

- `wf_sync_publish_event` / `wf_sync_publish_error` / `wf_subscribe_decode_frame` — the
  actual firehose frame bytes: header/body CBOR framing, `$type`/`op` header fields, field
  ordering, whether deprecated `#commit` fields (`rebase`, `tooBig`, `blobs`, `prev`) are
  emitted. **The single largest gap in this review's coverage of byte-format fidelity.**
- `wf_cbor_serialize` — canonical DAG-CBOR map-key ordering, definite-length encoding,
  tag-42 CID encoding.
- `wf_repo_create_record` / `wf_repo_update_record` / `wf_repo_delete_record` /
  `wf_repo_import` — MST fanout, key-height derivation, prefix compression, commit
  `version: 3` field set, signing-bytes construction.
- `wf_car_write` — CAR v1 header/varint framing.
- `wf_plc_operation_build` / `_sign` / `_compute_did` / `wf_plc_submit_operation_raw`.
- `wf_rate_limiter_new` — **whether the limiter actually keys on client IP** as
  `README.md:147` claims, and whether the bucket is per-route or global.
- `wf_oauth_verify_request` / `wf_oauth_pkce_from_verifier` / `wf_oauth_dpop_replay_cache`
  — correct, but the first is dead code in MetalBear so its quality is moot.
- `wf_server_create_service_auth` — service-auth JWT claim set and ES256K signing.
- `wf_validate_record` / `wf_lexicon_registry` — depth of lexicon validation.
- `wf_xrpc_server_ws_send` blocking/buffering semantics, which determine what a slow
  firehose consumer actually does to the server.
- Fixed-buffer capacities in `wf_subscribe_event` (`data.commit.rev`, `.did`, `ops[].action`)
  — MetalBear `snprintf`s into them, so silent truncation thresholds are unknown.

**Not verified for other reasons:**

- The README's federation claim ("consumed by Bluesky's relays … posts appear on the
  Bluesky AppView", `README.md:403-405`) is an operational assertion about a live host; it
  cannot be confirmed or refuted from source. Nothing in the code contradicts it, and the
  `did:plc` minting path (`server.c:3150-3272`) is the real mechanism it would require.
- Performance figures (`README.md:370-388`) were not reproduced.
- `scripts/setup.sh` and the release workflow were not read in detail.
- The `frontend/` SvelteKit app was not read.
- No build or test run was attempted (Wolfram absent, so the build cannot configure).
- `src/handle_dns.c`, `src/email.c`, `src/key_rotation.c`, and `src/account_cache.c` were
  read only in outline.
