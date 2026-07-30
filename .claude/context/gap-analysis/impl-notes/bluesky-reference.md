# Bluesky reference PDS (bluesky-social/atproto packages/pds + bluesky-social/pds)

Two repos, one product. `bluesky-social/atproto` holds the server library (`@atproto/pds`) and the canonical
lexicon JSON. `bluesky-social/pds` (a.k.a. "bsky-pds") is a ~500-line self-host wrapper: Dockerfile, compose
file, an Ubuntu/Debian installer, and a `pdsadmin` shell CLI. Nothing in the second repo implements protocol —
it imports `@atproto/pds` and calls `PDS.create()` (`/tmp/gap-scratch/bsky-pds/service/index.ts:3,14`).

Snapshot: `atproto` at commit `d3bbeb5fe87f8c389c2f18abd2bc055ef916a63a` (2026-07-28), `@atproto/pds` version
`0.5.21` (`/tmp/gap-scratch/atproto/packages/pds/package.json:3`). The self-host wrapper pins `@atproto/pds`
`0.5.9` (`/tmp/gap-scratch/bsky-pds/service/package.json` dependencies) and publishes image tag `0.4`
(`/tmp/gap-scratch/bsky-pds/compose.yaml:19`, `/tmp/gap-scratch/bsky-pds/service/index.ts:7`) — the distro tag
and the library version deliberately diverge.

This is the spec oracle for the rest of the gap analysis: where the lexicon JSON under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/**` and this server disagree, the lexicon wins, but in practice
they are generated from each other (`codegen:lex` script, `packages/pds/package.json`).

---

## 1. Language, stack, build, license

TypeScript on Node ≥22 (`packages/pds/package.json` `engines.node`), ESM (`"type": "module"`), built with
`tsgo --build tsconfig.build.json`. HTTP layer is Express 4 with `express-async-errors`, `cors`, and a custom
compression middleware (`packages/pds/src/index.ts:117-133`). XRPC routing, validation, rate limiting and
WebSocket framing come from the sibling `@atproto/xrpc-server` package. SQL access is Kysely over
`better-sqlite3`. Logging is `pino` / `pino-http`. Crypto is `@atproto/crypto` (P-256 and secp256k1 only —
`packages/crypto/src/index.ts:10-14`). Monorepo tooling: pnpm workspaces, Jest.

Notable direct deps: `@did-plc/lib` (PLC operations), `jose` (JWT), `zod`, `undici` (outbound proxying),
`ioredis` (optional shared rate-limit / scratch store), `nodemailer` + `handlebars` (transactional email),
`@atproto/oauth-provider` (the full authorization server).

License: dual MIT / Apache-2.0 in both repos (`/tmp/gap-scratch/atproto/LICENSE.txt:1-8`,
`/tmp/gap-scratch/bsky-pds/LICENSE.txt:1-8`). The Docker image is labelled MIT
(`/tmp/gap-scratch/bsky-pds/Dockerfile:41`).

## 2. Multi-account, deployment model

Multi-account, and multi-tenant in the strong sense: every account gets its own SQLite database and its own
signing keypair on disk, sharded two levels deep by a hash of the DID
(`packages/pds/src/actor-store/actor-store.ts:28-33` — `<directory>/<hash[0:2]>/<did>/store.sqlite` plus a
sibling `key` file). Account rows, invite codes, app passwords, OAuth state and repo roots live in one shared
`account.sqlite`; the firehose lives in a third `sequencer.sqlite`.

There is also an "entryway" mode: when `PDS_ENTRYWAY_URL` is set, a dozen endpoints re-register as
pass-through proxies to a central entryway service instead of doing local work (see §4 for the list). That is
how bsky.social itself is deployed — many PDS instances behind one account/identity authority. Self-hosters
leave it unset.

Deployment for self-hosters is Docker Compose driven by systemd. `installer.sh` installs docker-ce, writes
`/pds/pds.env` with generated secrets (`installer.sh:324-342`: `openssl rand --hex 16` for
`PDS_JWT_SECRET`/`PDS_ADMIN_PASSWORD`, a raw secp256k1 DER-trimmed key for
`PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` at `installer.sh:16`), writes a Caddyfile that terminates TLS for
`*.${PDS_HOSTNAME}` and `${PDS_HOSTNAME}` (`installer.sh:304-312`), fetches `compose.yaml`, and installs a
`Type=oneshot RemainAfterExit=yes` unit that shells out to `docker compose up --detach`
(`installer.sh:362-382`). It opens ufw 80/443 (`installer.sh:384-394`) and drops `pdsadmin` into
`/usr/local/bin` (`installer.sh:399-406`). The compose stack is three containers: caddy, pds, and watchtower
on an `@midnight` schedule for auto-update (`compose.yaml:28-39`).

## 3. Storage backends

Everything is SQLite via `better-sqlite3` + Kysely `SqliteDialect` (`packages/pds/src/db/db.ts:27-47`). There
is no Postgres dialect in `packages/pds`.

| Store | Engine / location | Schema | Migrations |
|---|---|---|---|
| Accounts, invites, app passwords, OAuth tokens/devices/clients, repo roots | one shared SQLite (`PDS_ACCOUNT_DB_LOCATION`, default under `PDS_DATA_DIRECTORY`) | `packages/pds/src/account-manager/db/schema/` (15 tables incl. `account.ts`, `actor.ts`, `app-password.ts`, `invite-code.ts`, `refresh-token.ts`, `token.ts`, `device.ts`, `authorization-request.ts`, `repo-root.ts`) | `account-manager/db/migrations/001-init.ts` … `007-lexicon-failures-index.ts` |
| Repo blocks, records, backlinks, blob metadata, prefs (per account) | one SQLite **per DID** at `<actorStoreDirectory>/<hash2>/<did>/store.sqlite` | `packages/pds/src/actor-store/db/schema/` (`repo-block.ts`, `repo-root.ts`, `record.ts`, `record-blob.ts`, `blob.ts`, `backlink.ts`, `account-pref.ts`) | single `actor-store/db/migrations/001-init.ts` |
| Firehose | third SQLite (`PDS_SEQUENCER_DB_LOCATION`) | `packages/pds/src/sequencer/db/schema.ts:5-19` — one table `repo_seq(seq autoinc, did, eventType, event BLOB, invalidated, sequencedAt)` | `sequencer/db/migrations/001-init.ts` |
| DID cache | fourth SQLite (`PDS_DID_CACHE_DB_LOCATION`) | `packages/pds/src/did-cache/` | — |
| Blobs | disk (`DiskBlobStore`, `packages/pds/src/disk-blobstore.ts:17-33`, per-DID subdirectories, plus `tmp` and `quarantine` dirs) or S3 via `@atproto/aws` (`PDS_BLOBSTORE_S3_*`) | blob rows in the per-actor `blob` / `record_blob` tables | — |
| Rate limits / scratch (optional) | Redis (`PDS_REDIS_SCRATCH_ADDRESS`) | — | — |

Block storage is content bytes in-row: `repo_block(cid, repoRev, size, content BLOB)`
(`packages/pds/src/actor-store/db/schema/repo-block.ts:1-6`). `repoRev` is what makes
`com.atproto.sync.getRepo?since=` a cheap indexed range scan.

## 4. Endpoint coverage snapshot

Registration is `server.add(com.atproto.<ns>.<method>, …)` against the codegen'd lexicon objects; each family
has an `index.ts` that calls the per-file registrars. The directory layout under
`packages/pds/src/api/com/atproto/` **is** the endpoint list. Every file below was opened or grepped; there
are zero `NotImplemented` throws anywhere in `packages/pds/src/api` (verified: `grep -rn 'NotImplemented|not
implemented|TODO: implement'` returns nothing).

Wiring: `packages/pds/src/api/index.ts:7-8` → `api/com/atproto/index.ts:12-18` (admin, identity, moderation,
repo, server, sync, temp) and `api/app/bsky/index.ts`.

### com.atproto.server (24 routed)

Registrar: `packages/pds/src/api/com/atproto/server/index.ts:30-54`.

| NSID | file:line of `server.add` | notes |
|---|---|---|
| describeServer | `server/describeServer.ts:8` | |
| createAccount | `server/createAccount.ts:24` | real; PLC create op or BYO-DID |
| createInviteCode | `server/createInviteCode.ts:10` (entryway) / `:19` (local) | |
| createInviteCodes | `server/createInviteCodes.ts:12` / `:21` | |
| getAccountInviteCodes | `server/getAccountInviteCodes.ts:13` | |
| reserveSigningKey | `server/reserveSigningKey.ts:6` | 15-line file, mints+stores a reserved keypair |
| requestAccountDelete | `server/requestAccountDelete.ts:12` | |
| deleteAccount | `server/deleteAccount.ts:21` / `:40` | |
| requestPasswordReset | `server/requestPasswordReset.ts:9` | |
| resetPassword | `server/resetPassword.ts:26` / `:37` | |
| requestEmailConfirmation | `server/requestEmailConfirmation.ts:42` / `:58` | |
| confirmEmail | `server/confirmEmail.ts:13` / `:28` | |
| requestEmailUpdate | `server/requestEmailUpdate.ts:48` / `:64` | |
| updateEmail | `server/updateEmail.ts:14` / `:30` | |
| createSession | `server/createSession.ts:39` / `:50` | |
| deleteSession | `server/deleteSession.ts:9` / `:16` | |
| getSession | `server/getSession.ts:15` | |
| refreshSession | `server/refreshSession.ts:18` | |
| createAppPassword | `server/createAppPassword.ts:20` / `:36` | |
| listAppPasswords | `server/listAppPasswords.ts:17` / `:32` | |
| revokeAppPassword | `server/revokeAppPassword.ts:17` / `:33` | |
| getServiceAuth | `server/getServiceAuth.ts:22` | mints service JWTs; see §5 |
| checkAccountStatus | `server/checkAccountStatus.ts:7` | real counts from actor store |
| activateAccount | `server/activateAccount.ts:20` (entryway) / `:30` (local) | |
| deactivateAccount | `server/deactivateAccount.ts:20` / `:32` | |

Where two line numbers appear, the first is the entryway-proxy variant and the second is the local
implementation; only one is registered at boot depending on `ctx.entrywayClient`.

### com.atproto.repo (10 routed)

Registrar: `repo/index.ts:15-24`.

| NSID | file:line |
|---|---|
| applyWrites | `repo/applyWrites.ts:39` |
| createRecord | `repo/createRecord.ts:20` |
| deleteRecord | `repo/deleteRecord.ts:17` |
| describeRepo | `repo/describeRepo.ts:9` |
| getRecord | `repo/getRecord.ts:8` |
| listRecords | `repo/listRecords.ts:7` |
| putRecord | `repo/putRecord.ts:29` |
| uploadBlob | `repo/uploadBlob.ts:11` |
| listMissingBlobs | `repo/listMissingBlobs.ts:6` |
| importRepo | `repo/importRepo.ts:17` |

Full lexicon coverage for this family: every JSON in `lexicons/com/atproto/repo/` except the pure-schema
`defs.json` and `strongRef.json` is routed.

### com.atproto.sync (11 routed, 2 of them deprecated)

Registrar: `sync/index.ts:16-26`.

| NSID | file:line | notes |
|---|---|---|
| getBlob | `sync/getBlob.ts:11` | |
| getBlocks | `sync/getBlocks.ts:11` | |
| getLatestCommit | `sync/getLatestCommit.ts:8` | |
| getRepoStatus | `sync/getRepoStatus.ts:8` | |
| getRecord | `sync/getRecord.ts:12` | |
| getRepo | `sync/getRepo.ts:21` | CAR stream, `since=` diff, own 6000pt/5min bucket |
| subscribeRepos | `sync/subscribeRepos.ts:8` | WebSocket |
| listBlobs | `sync/listBlobs.ts:9` | |
| listRepos | `sync/listRepos.ts:12` | returns `rev`, `active`, `status` |
| getCheckout | `sync/deprecated/getCheckout.ts:9` | deprecated lexicon, still served |
| getHead | `sync/deprecated/getHead.ts:8` | deprecated lexicon, still served |

**Not routed** (verified by absence from `grep -rn 'server\.add(' packages/pds/src/api`):
`com.atproto.sync.requestCrawl`, `notifyOfUpdate`, `getHostStatus`, `listHosts`, `listReposByCollection`.
Four of those five are correct by spec — the lexicons say "Implemented by relays" / "implemented by Relay"
(`lexicons/com/atproto/sync/getHostStatus.json` main description; `listHosts.json`; `notifyOfUpdate.json`;
`requestCrawl.json` describes a PDS *calling* a relay). The PDS is the **client** of `requestCrawl`, not the
server: `packages/pds/src/crawlers.ts:34-39` sends `com.atproto.sync.requestCrawl {hostname}` to each
configured crawler, debounced to 20 minutes (`crawlers.ts:6,17-28`), fired from
`sequencer.sequenceEvts()` (`packages/pds/src/sequencer/sequencer.ts:170`).

`com.atproto.sync.listReposByCollection` is the one genuine absence: its lexicon
(`lexicons/com/atproto/sync/listReposByCollection.json`) carries no "implemented by relays" qualifier, and the
reference PDS does not serve it.

### com.atproto.identity (6 routed)

Registrar: `identity/index.ts:11-16`.

| NSID | file:line |
|---|---|
| resolveHandle | `identity/resolveHandle.ts:9` |
| updateHandle | `identity/updateHandle.ts:31` / `:55` |
| getRecommendedDidCredentials | `identity/getRecommendedDidCredentials.ts:6` |
| requestPlcOperationSignature | `identity/requestPlcOperationSignature.ts:21` / `:36` |
| signPlcOperation | `identity/signPlcOperation.ts:21` / `:37` |
| submitPlcOperation | `identity/submitPlcOperation.ts:9` |

Not routed: `com.atproto.identity.resolveDid`, `resolveIdentity`, `refreshIdentity`. Those three lexicons
exist (`lexicons/com/atproto/identity/`) but describe general identity-directory behaviour, not PDS behaviour.

### com.atproto.admin (13 routed)

Registrar: `admin/index.ts:18-30`. Auth is HTTP Basic `admin:<PDS_ADMIN_PASSWORD>`
(`packages/pds/src/auth-verifier.ts:137-149`) or a moderation-service JWT for the `moderator` verifier
(`auth-verifier.ts:167-175`).

| NSID | file:line |
|---|---|
| updateSubjectStatus | `admin/updateSubjectStatus.ts:8` |
| getSubjectStatus | `admin/getSubjectStatus.ts:8` |
| getAccountInfo | `admin/getAccountInfo.ts:7` |
| getAccountInfos | `admin/getAccountInfos.ts:7` |
| enableAccountInvites | `admin/enableAccountInvites.ts:6` |
| disableAccountInvites | `admin/disableAccountInvites.ts:6` |
| disableInviteCodes | `admin/disableInviteCodes.ts:6` |
| getInviteCodes | `admin/getInviteCodes.ts:17` (entryway **stub**) / `:25` (real) |
| updateAccountHandle | `admin/updateAccountHandle.ts:9` / `:38` |
| updateAccountEmail | `admin/updateAccountEmail.ts:6` |
| updateAccountPassword | `admin/updateAccountPassword.ts:10` / `:21` |
| sendEmail | `admin/sendEmail.ts:6` |
| deleteAccount | `admin/deleteAccount.ts:6` |

The one true stub in the whole surface: in entryway mode `getInviteCodes` registers a handler that
unconditionally throws `InvalidRequestError('Account invites are managed by the entryway service')`
(`admin/getInviteCodes.ts:17-21`). Self-hosters never hit it.

### com.atproto.moderation (1 routed)

`createReport` — `moderation/createReport.ts:9`. It does **no** local moderation; it mints a service-auth
header for the configured report service and forwards the call
(`moderation/createReport.ts:19-38`). The lexicon itself says "Implemented by moderation services (with PDS
proxying)". Default report service in the self-host env is `https://mod.bsky.app` /
`did:plc:ar7c4by46qjdydhdevvrndac` (`/tmp/gap-scratch/bsky-pds/sample.env:11-12`).

### com.atproto.temp (1 routed)

`checkSignupQueue` — `temp/checkSignupQueue.ts:8`, self-described as "A TEMPORARY UNSPECCED ROUTE"
(`temp/checkSignupQueue.ts:6`). Returns `{activated: true}` when there is no entryway.

### Non-com.atproto surface

11 `app.bsky.*` routes are implemented locally rather than proxied, for read-after-write consistency:
`actor.getPreferences` / `putPreferences` / `getProfile` / `getProfiles`, `feed.getActorLikes` /
`getAuthorFeed` / `getFeed` / `getPostThread` / `getTimeline`, `notification.registerPush` / `unregisterPush`
(each `server.add` line listed by the same grep; e.g. `api/app/bsky/actor/getPreferences.ts:15`). Everything
else is caught by `catchall: proxyHandler(ctx)` (`packages/pds/src/index.ts:89`) and forwarded to the AppView
with a minted service JWT (`packages/pds/src/pipethrough.ts:134`).

Non-XRPC HTTP: `GET /` ASCII banner, `GET /robots.txt`, `GET /xrpc/_health` returning `{version}` and 503 on
DB failure (`packages/pds/src/basic-routes.ts:8-49`); `GET /.well-known/atproto-did` serving handles on
`serviceHandleDomains` (`packages/pds/src/well-known.ts:8-29`); the whole OAuth router (§5). The self-host
wrapper adds one route of its own, `GET /tls-check?domain=` (`/tmp/gap-scratch/bsky-pds/service/index.ts:17`).

**README vs code:** the self-host README does not publish an endpoint checklist, so there is nothing to
contradict. Its only capability claim is the federation-status list (all six items ticked,
`/tmp/gap-scratch/bsky-pds/README.md:63-75`), which the code supports.

## 5. Auth posture

Three credential families, all real.

**Legacy session JWTs and app passwords.** `createSession` / `refreshSession` / `deleteSession` issue and
rotate bearer JWTs. Scopes are a closed enum: `com.atproto.access`, `.refresh`, `.appPass`,
`.appPassPrivileged`, `.signupQueued`, `.takendown` (`packages/pds/src/auth-scope.ts:2-9`), with
`ACCESS_FULL ⊂ ACCESS_PRIVILEGED ⊂ ACCESS_STANDARD` tiers (`auth-scope.ts:11-19`). Verification is
`verifyBearerJwt` (`auth-verifier.ts:468`).

**Full OAuth 2.1 authorization server** via `@atproto/oauth-provider`, mounted before CORS
(`packages/pds/src/index.ts:128`, `packages/pds/src/auth-routes.ts:38-48`). Routed endpoints:
`/oauth/par` (`packages/oauth/oauth-provider/src/router/create-oauth-middleware.ts:92`), `/oauth/token`
(`:132`), `/oauth/revoke` (`:164`), `/oauth/jwks` (`:84`), `/.well-known/oauth-authorization-server` (`:76`),
plus the interactive `/oauth/authorize` and `/oauth/authorize/redirect`
(`create-authorization-page-middleware.ts:67,213`) and `/.well-known/change-password`
(`create-account-page-middleware.ts:45`). `/.well-known/oauth-protected-resource` is served by the PDS itself
(`auth-routes.ts:31-36`) and refuses non-HTTPS resource URLs outside dev mode (`auth-routes.ts:24-29`).

Advertised metadata (`packages/oauth/oauth-provider/src/metadata/build-metadata.ts`):
`require_pushed_authorization_requests: true` (`:126`), `pushed_authorization_request_endpoint` (`:124`),
`code_challenge_methods_supported` (`:69`), `dpop_signing_alg_values_supported` (`:129`),
`token_endpoint_auth_methods_supported` from `Client.AUTH_METHODS_SUPPORTED` (`:114`, which is where
`private_key_jwt` lives), `authorization_response_iss_parameter_supported: true` (`:98`),
`require_request_uri_registration: true` (`:107`), `client_id_metadata_document_supported: true` (`:139`).
DPoP nonces are issued on every OAuth-authenticated request via
`this.oauthVerifier.nextDpopNonce()` → `DPoP-Nonce` response header (`auth-verifier.ts:361-364`), with the
nonce machinery in `packages/oauth/oauth-provider/src/dpop/{dpop-manager,dpop-nonce,dpop-proof}.ts`.

**Inter-service auth, both directions.** Minting: `getServiceAuth`
(`api/com/atproto/server/getServiceAuth.ts:96-102`) signs with the account's own keypair
(`:94`), caps `exp` at 1 hour, or 1 minute when no `lxm` is bound (`:68-86`), rejects `lxm` in
`PROTECTED_METHODS` (`:88-92`), and blocks takendown accounts from minting anything except a token for
`createAccount` (`:48-53`) — precisely the migration escape hatch. Outbound proxy tokens are minted per-request
at `pipethrough.ts:134`. Verifying: `verifyServiceJwt` (`auth-verifier.ts:524-570`) parses the request NSID,
resolves the issuer DID doc, extracts the `atproto` (or `atproto_label`) verification method, and asserts the
`aud` matches this service's DID or the entryway's (`:560-568`).

The `PROTECTED_METHODS` set (`pipethrough.ts:613-620+`) — `admin.sendEmail`,
`identity.requestPlcOperationSignature`, `identity.signPlcOperation`, `identity.updateHandle`,
`server.activateAccount`, `server.confirmEmail`, `server.createAppPassword`, … — may never be reached via
service auth or proxying. `PRIVILEGED_METHODS` (`:605-608`) is the chat lexicons plus
`com.atproto.server.createAccount`.

## 6. Sync 1.1 status

Fully implemented; this is the definition of the target.

**`#sync` events.** Event type `sync` exists in the sequencer's type union
(`packages/pds/src/sequencer/db/schema.ts:3`) and is built by `formatSeqSyncEvt`
(`packages/pds/src/sequencer/events.ts:47-63`), which CARs just the commit block. Emit sites:
`sequenceSync` (`sequencer.ts:181-183`), atomically bundled into account creation
(`sequencer.ts:199-211` — identity + account + commit + sync in one insert) and account activation
(`sequencer.ts:213-225`), plus the `rebuild-repo` and `rotate-keys` ops scripts
(`scripts/rebuild-repo.ts:109`, `scripts/rotate-keys.ts:109`). Activation pulls the sync payload from
the actor store: `account-manager.ts:483-492`.

**`prevData` on commits.** Threaded through `CommitDataWithOps.prevData`
(`packages/pds/src/repo/types.ts:40-43`), populated from the loaded repo's MST root before the write
(`actor-store/repo/transactor.ts:163-164,189`), and serialised onto the wire event
(`sequencer/events.ts:32`, schema at `events.ts:140`). Initial commits correctly set `prevData: null`
(`transactor.ts:75`).

**Per-op `prev`.** Built in `formatCommit`: for every write the current record CID is fetched and, if present,
attached as `op.prev` (`transactor.ts:130-141`) — so creates omit it and updates/deletes carry it, matching
the lexicon's "required for inductive firehose" note (`lexicons/com/atproto/sync/subscribeRepos.json`
`repoOp.prev`).

**Covering-proof blocks in the CAR slice.** `Repo.formatCommit` calls `data.getCoveringProof(...)` for every
written key and unions the proofs into `relevantBlocks`
(`packages/repo/src/repo.ts:146-152`), then adds the new leaves (`:159`) and the new commit block (`:178`).
The transactor additionally back-fills any new-record block that the diff omitted because its CID was
unchanged (`transactor.ts:177-185`). `formatSeqCommit` CARs `newBlocks ∪ relevantBlocks`
(`sequencer/events.ts:21-30`). Commits over 2 MB are rejected outright
(`transactor.ts:89-92`), matching the lexicon's `blocks.maxLength: 2000000`.

**No-op rejection.** `putRecord` compares the prepared write's CID against the current record and returns
`commit: null` without touching the repo or the sequencer if they match
(`packages/pds/src/api/com/atproto/repo/putRecord.ts:130-136`; the `sequenceCommit` call at `:151` is inside
the branch that is skipped). So an identical re-put emits nothing.

**`getRepoStatus`** is routed (`sync/getRepoStatus.ts:8`) and reports takedown/deactivation via
`assertRepoAvailability` (`sync/util.ts:6-36`). **`listRepos`** returns `rev`, `active` and `status`
(`sync/listRepos.ts:36-45`). **`getHostStatus` is not routed and should not be** — relay-side per its lexicon.
**`listReposByCollection` is not routed** (see §4).

## 7. Firehose

`com.atproto.sync.subscribeRepos` is a real WebSocket subscription
(`packages/pds/src/api/com/atproto/sync/subscribeRepos.ts:8-72`). Four event types are emitted — `commit`,
`sync`, `identity`, `account` (`subscribeRepos.ts:46-69`) — plus `info` frames; the union in the lexicon is
`#commit | #sync | #identity | #account | #info`, so coverage is complete.

Framing is the standard two-CBOR-object frame: header then body, concatenated
(`packages/xrpc-server/src/stream/frames.ts:21-22`), with `MessageFrame` carrying `{op: 1, t: '#commit'}` and
`ErrorFrame` carrying `{op: -1}` (`frames.ts:62-75,102-110`). The subscription generator is wrapped so any
thrown error becomes a terminal `ErrorFrame` (`packages/xrpc-server/src/server.ts:569-576`). Note the explicit
comment that outgoing subscription messages are **not** validated against the lexicon schema
(`server.ts:542-543`).

Sequence numbers come from SQLite `AUTOINCREMENT` on `repo_seq.seq`
(`packages/pds/src/sequencer/db/schema.ts:6`) — which is exactly why the "fix a relay desync" recipe in the
self-host README pokes `sqlite_sequence` directly (`/tmp/gap-scratch/bsky-pds/README.md:387`).

Cursor resume is three-phase (backfill → cutover → stream) and is documented in the code
(`packages/pds/src/sequencer/outbox.ts:25-33`). A cursor beyond the current head throws `FutureCursor`
(`subscribeRepos.ts:29-31`). A cursor older than the backfill window (`PDS_REPO_BACKFILL_LIMIT_MS`) yields an
`#info` frame with `name: 'OutdatedCursor'` and then restarts from the earliest event inside the window
(`subscribeRepos.ts:31-38`). Backfill pages 500 at a time and cuts over when within half a page
(`outbox.ts:107-121`).

Slow consumers: the outbox holds an `AsyncBuffer` capped at `PDS_MAX_SUBSCRIPTION_BUFFER` (default 500,
`outbox.ts:20`); overflow raises `AsyncBufferFullError`, translated to
`InvalidRequestError('Stream consumer too slow', 'ConsumerTooSlow')` (`outbox.ts:93-101`). The sequencer
itself polls the DB in a loop with exponential backoff capped at one second
(`sequencer.ts:135-163`) rather than using triggers.

Deleting an account collapses its whole history to a single tombstone: `sequenceAccountDeletion` inserts the
deleted-account event and then deletes every other `repo_seq` row for that DID (`sequencer.ts:227-237`).

## 8. Account migration / import-export

Every endpoint in the migration path is implemented and does real work.

| Endpoint | Where | What it actually does |
|---|---|---|
| `repo.importRepo` | `repo/importRepo.ts:17-100` | Streams CAR, requires exactly one root (`:38-41`), runs `verifyDiff` against the current repo (`:54-61`), rewrites the commit `rev` to a fresh TID (`:62`), applies, then re-indexes every record and re-links blob refs (`:67-97`). Gated on `PDS_ACCEPTING_REPO_IMPORTS` (`:29-31`) and `PDS_MAX_REPO_IMPORT_SIZE` (`:19`). |
| `repo.listMissingBlobs` | `repo/listMissingBlobs.ts:6` | real query against per-actor blob tables |
| `server.checkAccountStatus` | `server/checkAccountStatus.ts:7-49` | returns `repoCommit`, `repoRev`, `repoBlocks`, `indexedRecords`, `expectedBlobs`, `importedBlobs`, `activated`, `validDid`. `privateStateValues` is hardcoded `0` (`:44`). |
| `server.deactivateAccount` / `activateAccount` | `server/deactivateAccount.ts:20/:32`, `server/activateAccount.ts:20/:30` | activation calls `assertValidDidDocumentForService` first (`account-manager.ts:463`) and then emits account+identity+sync atomically (`:487-492`) |
| `identity.getRecommendedDidCredentials` | `identity/getRecommendedDidCredentials.ts:6` | 50-line real handler |
| `identity.requestPlcOperationSignature` | `identity/requestPlcOperationSignature.ts:21/:36` | emails a challenge token |
| `identity.signPlcOperation` | `identity/signPlcOperation.ts:37-…` | requires the email token (`:42-51`), refuses tombstoned DIDs (`:53-56`), signs an update op with the server rotation key (`:57`) |
| `identity.submitPlcOperation` | `identity/submitPlcOperation.ts:9` | submits and then emits an identity event (`:53`) |
| `server.reserveSigningKey` | `server/reserveSigningKey.ts:6` | 15 lines, mints and stores a reserved key |
| `server.getServiceAuth` | `server/getServiceAuth.ts:22` | the token the *old* PDS gives you (§5) |

BYO-DID account creation is the migration entry point: passing `did` to `createAccount` requires the request
to be authenticated as that DID (`createAccount.ts:255-260`), rejects a client-supplied `plcOp`
(`:201-203`), and lands the account in `deactivated` state (`:263`).

The self-host repo documents the flow in `/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md`, four phases,
precisely:

1. **Create account** — call `com.atproto.server.getServiceAuth` on the *old* PDS to get a JWT signed by your
   DID's signing key (`ACCOUNT_MIGRATION.md:23`); use it as Bearer on `com.atproto.server.createAccount`
   against the *new* PDS (`:25`); result is a deactivated account with an empty repo and a new signing key
   (`:27`).
2. **Migrate data** — `com.atproto.sync.getRepo` (old) → `com.atproto.repo.importRepo` (new) (`:33`); then
   `com.atproto.sync.listBlobs` (old) → for each, `com.atproto.sync.getBlob` (old) →
   `com.atproto.repo.uploadBlob` (new) (`:35`); then `app.bsky.actor.getPreferences` (old) →
   `app.bsky.actor.putPreferences` (new) (`:37`). Check progress with
   `com.atproto.server.checkAccountStatus`, find gaps with `com.atproto.repo.listMissingBlobs` (`:39`).
3. **Update identity** — `com.atproto.identity.getRecommendedDidCredentials` (new) (`:45`); generate your own
   extra rotation key and prepend it (`:45`); `com.atproto.identity.requestPlcOperationSignature` (old) for
   the email token, then `com.atproto.identity.signPlcOperation` (old) with that token (`:47`); submit via
   `com.atproto.identity.submitPlcOperation` (new) rather than directly to plc.directory, because the new PDS
   sanity-checks the op (`:49`). did:web users must update their own `.well-known` (`:51`).
4. **Finalize** — re-check `checkAccountStatus`, then `com.atproto.server.activateAccount` on the new PDS,
   which validates the DID doc, activates, and emits identity + commit events (`:57-59`); then
   `deleteAccount` or `deactivateAccount` (with optional `deleteAfter`) on the old PDS (`:61`).

The doc opens with a destructive-operation warning and says outright not to migrate a primary account
(`ACCOUNT_MIGRATION.md:5-8`), and as of May 2025 defers to the atproto.com guide and the `goat` CLI (`:3`).
A runnable-ish TypeScript example is inlined at `:74-203`.

## 9. did:plc vs did:web

**Service DID:** defaults to `did:web:${hostname}` and is overridable via `PDS_SERVICE_DID`
(`packages/pds/src/config/config.ts:23`), validated at boot (`:25-27`). The self-host installer never sets
`PDS_SERVICE_DID`, so every self-hosted PDS is a `did:web`.

**Account DIDs:** did:plc is the default and only creatable method — `formatDidAndPlcOp` always builds a
`plc.createOp` with the server rotation key, an optional `PDS_RECOVERY_DID_KEY`, and an optional client-supplied
`recoveryKey`, in that priority order (`createAccount.ts:288-303`). Bring-your-own DIDs of any method are
accepted for migration: `assertValidDidDocumentForService` branches on `did.startsWith('did:plc')` — PLC DIDs
go through `plcClient.getDocumentData` and additionally require the server's rotation key to be present
(`server/util.ts:82-88`, `:116-122`); anything else resolves through the generic `idResolver`
(`:89-98`) and is checked only for the `atproto_pds` endpoint matching `publicUrl` and the verification method
matching the local keypair (`:124-135`). A did:web account therefore works, but the PDS can never rotate it —
`ACCOUNT_MIGRATION.md:51` says as much.

## 10. Blobs

Storage is `DiskBlobStore` per DID under `PDS_BLOBSTORE_DISK_LOCATION`
(`packages/pds/src/disk-blobstore.ts:17-33,59-60`), with separate `tmp` and `quarantine` trees
(`:31-33`), or S3 when `PDS_BLOBSTORE_S3_BUCKET` is set. Metadata lives in the per-actor `blob` table;
record→blob edges in `record_blob`.

Upload path (`repo/uploadBlob.ts:11-52`): a permission check on the declared MIME
(`:14-17`), a 1000-uploads-per-day rate limit (`:19-22`), then `uploadBlobAndGetMetadata` which concurrently
computes size, SHA-256 and a *sniffed* MIME type from the stream
(`actor-store/blob/transactor.ts:61-72`) and derives the CID from the raw hash (`:71`). The sniffed type wins
over the user-declared one (`:72`). The blob is tracked untethered, and promoted to permanent immediately if a
record already references it (`uploadBlob.ts:37-40`). On promotion `verifyBlob` re-checks the stored MIME and
size against what the record claims (`blob/transactor.ts:356-362`), and refuses to serve/promote anything with
a `takedownRef` (`:85`, `:254`).

GC is reference-counted and synchronous with the write: `deleteDereferencedBlobs`
(`blob/transactor.ts:187-240`) deletes `record_blob` rows for the touched URIs, re-queries which of those blob
CIDs are still referenced elsewhere (`:204-208`), unions that with blobs newly referenced by this same write
(`:210-217`), deletes the surviving orphans from the `blob` table (`:224-227`), and schedules the actual object
deletion on the background queue after commit (`:229-236`). Called from `processWrites`
(`blob/transactor.ts:115`). Repo-block GC is analogous: `getDuplicateRecordCids` rescues blocks still
referenced by other records before removal (`actor-store/repo/transactor.ts:169-175,215-230`).

Default upload cap in the self-host env is 100 MB (`/tmp/gap-scratch/bsky-pds/sample.env:7`).

## 11. Moderation / admin, takedown enforcement

The PDS is not a moderation service. `createReport` proxies to `PDS_REPORT_SERVICE_URL`
(`moderation/createReport.ts:19-38`); labeling lives in Ozone; there is no label emission here.

What it does own is takedown *enforcement* at three levels, all keyed on a `takedownRef` column:

- **Account** — `actor.takedownRef` (`account-manager/db/schema/actor.ts:8`). `assertRepoAvailability`
  (`sync/util.ts:6-36`) throws `RepoTakendown` / `RepoDeactivated` and is called from every sync read:
  `getBlob.ts:20`, `getBlocks.ts:19`, `getRecord.ts:20`, `getRepo.ts:34`, `getRepoStatus.ts:11`,
  `listBlobs.ts:18`, `getLatestCommit.ts:16`, the two deprecated routes, and `repo/describeRepo.ts:14`. The
  account's owner and admins bypass it (`sync/util.ts:21-23`).
- **Record** — `record.takedownRef` (`actor-store/db/schema/record.ts:9`); `repo.getRecord` 404s a
  taken-down record (`repo/getRecord.ts:18`); written by `actor-store/record/transactor.ts:102-107`.
- **Blob** — `blob.takedownRef` (`actor-store/db/schema/blob.ts:9`), set at
  `actor-store/blob/transactor.ts:157-162`, with the quarantine directory as the physical destination.

Takendown accounts still get a constrained auth scope (`AuthScope.Takendown`,
`auth-scope.ts:8`) so they can complete a migration out — see the `getServiceAuth` carve-out in §5.

Admin surface: the 13 `com.atproto.admin.*` methods in §4, Basic-auth gated
(`auth-verifier.ts:137-149`). `pdsadmin` drives a subset of them (§12).

## 12. Rate limiting, metrics, health, ops

**Rate limiting** (`packages/pds/src/rate-limits.ts:11-58`, wired at `index.ts:112`), enabled by
`PDS_RATE_LIMITS_ENABLED` (default `true` in the self-host env, `sample.env:15`). Backed by Redis when
`PDS_REDIS_SCRATCH_ADDRESS` is set, otherwise an in-memory limiter (`:18-20`). One global bucket of 3000
points per IP per 5 minutes, with `com.atproto.sync.getRepo` explicitly excluded from it because it has its own
6000/5min budget (`rate-limits.ts:36-43`, `sync/getRepo.ts:28-31`). Two shared write buckets: 5000/hour and
35000/day, priced create=3 / put=2 / delete=1 (`:46-57`). Per-route limits also exist (uploadBlob 1000/day,
`repo/uploadBlob.ts:19-22`). Bypass by header `x-ratelimit-bypass` matching `PDS_RATE_LIMIT_BYPASS_KEY`, or by
source IP in `PDS_RATE_LIMIT_BYPASS_IPS` (`rate-limits.ts:21-30`).

**Metrics:** none. `grep -rn 'prom-client|prometheus|/metrics' packages/pds/src packages/pds/package.json`
returns nothing. The `dbStatsInterval` / `sequencerStatsInterval` fields are declared and cleared in `destroy()`
but never assigned anywhere in the tree (`packages/pds/src/index.ts:65-66,152-153`) — vestigial. Observability
is structured pino logs, per-subsystem (`packages/pds/src/logger.ts:6-18`), toggled by `LOG_ENABLED`.

**Health:** `GET /xrpc/_health` → `{version}`, 503 with `{version, error}` if `select 1` against the account DB
fails (`basic-routes.ts:39-49`). Graceful shutdown uses `http-terminator` plus a 90s keep-alive
(`index.ts:141-149`).

**Config surface:** 101 environment variables read in `packages/pds/src/config/env.ts` (every one prefixed
`PDS_` except `LOG_*`). The self-host README documents only 20 of them
(`/tmp/gap-scratch/bsky-pds/README.md:332-354`) — the rest are for the bsky.social entryway deployment
(S3 blobstore, KMS rotation keys, hCaptcha, redis, entryway JWT verify keys, OAuth theming colors).

**`pdsadmin`** (`/tmp/gap-scratch/bsky-pds/pdsadmin.sh`): a curl-based dispatcher that downloads
`https://raw.githubusercontent.com/bluesky-social/pds/main/pdsadmin/<cmd>.sh` to a tempfile and executes it as
root (`pdsadmin.sh:6,19-28`) — remote code fetched on every invocation, worth flagging. Subcommands
(`pdsadmin/help.sh:10-43`):

| Command | Underlying call |
|---|---|
| `update` | `docker compose pull` + recreate (`pdsadmin/update.sh:33`) |
| `account list` | `com.atproto.sync.listRepos` then `com.atproto.admin.getAccountInfo` per DID (`account.sh:32,38`) |
| `account create <EMAIL> <HANDLE>` | `com.atproto.server.createInviteCode` then `com.atproto.server.createAccount` (`account.sh:69,73`) |
| `account delete <DID>` | `com.atproto.admin.deleteAccount` (`account.sh:121`) |
| `account takedown <DID>` | `com.atproto.admin.updateSubjectStatus` with a `com.atproto.admin.defs#repoRef` (`account.sh:147,161`) |
| `account untakedown <DID>` | same endpoint, cleared (`account.sh:186,199`) |
| `account reset-password <DID>` | `com.atproto.admin.updateAccountPassword` (`account.sh:224`) |
| `request-crawl [HOST]` | POSTs `com.atproto.sync.requestCrawl` to the relay (`request-crawl.sh:32`) |
| `create-invite-code` | `com.atproto.server.createInviteCode` (`create-invite-code.sh:17`) |
| `help` | — |

The image also ships the Go `goat` CLI v0.2.2, built from source in the Dockerfile
(`/tmp/gap-scratch/bsky-pds/Dockerfile:11,29`); the installer's closing banner points at
`docker exec pds goat pds admin` (`installer.sh:416`).

## 13. Spec deviations and explicitly-unsupported features

There is no "Status" or "Known issues" section in either README; `bluesky-social/pds`'s README instead
advertises full federation with six ticked capabilities (`/tmp/gap-scratch/bsky-pds/README.md:63-75`), which the
code backs up. The candid parts are elsewhere:

- **Account migration is dangerous and under-recommended.** "Account migration is a potentially destructive
  operation… we do not recommend migrating your primary account yet"
  (`/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md:6-8`). Code agrees only partially: the guardrails are real
  (`signPlcOperation` requires an email token, `activateAccount` validates the DID doc), but nothing prevents a
  user from signing away rotation-key control.
- **Relay desync is a known operational failure mode** with a manual `sqlite3 UPDATE sqlite_sequence` recipe
  (`README.md:364-396`). Code agrees: `repo_seq.seq` is a plain SQLite autoincrement
  (`sequencer/db/schema.ts:6`), so re-installing on the same hostname genuinely does rewind the cursor.
- **`checkAccountStatus.privateStateValues` is hardcoded to 0** (`server/checkAccountStatus.ts:44`), while
  `ACCOUNT_MIGRATION.md:39` describes it as "how many private state values are stored". Preferences are the
  only private state and they are counted separately.
- **`com.atproto.temp.checkSignupQueue` is self-labelled "A TEMPORARY UNSPECCED ROUTE"**
  (`temp/checkSignupQueue.ts:6`).
- **Deprecated routes still served:** `sync.getCheckout` and `sync.getHead`, kept in a `deprecated/`
  subdirectory but registered (`sync/index.ts:25-26`).
- **Deprecated wire fields still populated:** `formatSeqCommit` always writes `rebase: false`, `tooBig: false`,
  `blobs: []` (`sequencer/events.ts:34-36`) because the lexicon still marks them required.
- **Outbound subscription messages are not lexicon-validated** — explicit `@NOTE` at
  `packages/xrpc-server/src/server.ts:542-543`.
- **`com.atproto.sync.listReposByCollection` is unrouted** despite having no relay-only qualifier in its
  lexicon (§4).
- **No Postgres.** SQLite only for the PDS (`packages/pds/src/db/db.ts:27-47`). This is a deliberate
  single-node design, not an oversight, but it is a hard scaling boundary.
- **No metrics endpoint** (§12).
- **`pdsadmin` fetches and roots-executes scripts from GitHub on every run** (`pdsadmin.sh:19-28`).

### Permissioned data / spaces: definitively absent

Requested check, run across the whole `atproto` tree excluding `node_modules`, `.git`, `dist`:

| Term | Hits | Evidence |
|---|---|---|
| `com.atproto.space` | 0 | `grep -rn 'com.atproto.space' .` → count=0 |
| `permissioned` | 3 | only `packages/pds/tests/preferences.test.ts:205,231,248` — test names about app-password-gated *preferences*, unrelated to permissioned data |
| `ltHash` | 0 | count=0 |
| `setHash` | 0 | count=0 |
| `MemberGrant` | 0 | count=0 |
| `delegation` | 0 | count=0 |
| `space` in `lexicons/` | 1 | `lexicons/tools/ozone/moderation/defs.json:1139` — the substring inside the literal `'ozone/workspace'` |
| `space` in `packages/pds/src` | 1 | `packages/pds/src/pipethrough.ts:317` — `'proxy header cannot contain spaces'` |

The lexicon namespaces present are `app/bsky`, `chat/bsky`, `com/atproto`, `com/germnetwork`,
`internal/bsky`, `site/standard`, `tools/ozone` (`find lexicons -maxdepth 2 -type d`). **There is no
permissioned-data, spaces, or `com.atproto.space` lexicon or implementation anywhere in the Bluesky reference
tree.** For Phase 3 this means the reference PDS provides no oracle at all for the 0016 draft — atproto-crates'
spaces work has no upstream to be measured against, and any comparison must be against the draft spec itself.

## 14. Maturity tier

**reference.**

It is the implementation the lexicons are generated from and the one every other PDS is diffed against: 66
routed `com.atproto.*` methods with exactly one stub (an entryway-mode-only `getInviteCodes`), a complete
OAuth 2.1 authorization server with PAR/PKCE/DPoP-nonce/private_key_jwt, Sync 1.1 in full (`#sync` events,
`prevData`, per-op `prev`, covering proofs, no-op suppression), and a documented four-phase account-migration
path whose every endpoint does real work. It ships with a one-command installer, an admin CLI, rate limiting,
takedown enforcement at account/record/blob granularity, and per-account database isolation — the gaps that
remain (no Postgres, no metrics endpoint, `listReposByCollection` unrouted) are deliberate scope choices or
small omissions, not missing foundations.

---

## Confidence & unknowns

Verified by opening source: all endpoint registrations (via exhaustive `grep -rn 'server\.add('` over
`packages/pds/src/api`, cross-checked against the directory listing and each family's `index.ts`); the
sequencer emit sites and event shapes; `prevData` / per-op `prev` / covering-proof construction; the no-op
`putRecord` short-circuit; blob GC; takedown enforcement call sites; the OAuth metadata flags; the DB engine
and schema locations; the full bsky-pds ops surface; the permissioned-data greps.

Not verified:

- **Runtime behaviour.** Nothing was executed. All claims are static-source claims. In particular, "route
  registered AND handler does real work" was judged by reading each handler, not by exercising it.
- **`@atproto/oauth-provider` internals beyond metadata and route registration.** I confirmed the advertised
  flags in `build-metadata.ts` and the router paths, and that `AUTH_METHODS_SUPPORTED` is the source of
  `token_endpoint_auth_methods_supported`, but I did not open `client/` to enumerate that constant's members —
  so "private_key_jwt is supported" is inferred from the atproto OAuth spec and the metadata plumbing, not read
  off a literal. UNVERIFIED: the literal contents of `Client.AUTH_METHODS_SUPPORTED`.
- **The exact members of `PROTECTED_METHODS`.** I read `pipethrough.ts:613-620` and the list continues past
  line 620; the seven entries quoted are confirmed, the tail is not.
- **Whether `PDS_ENTRYWAY_*` mode is still exercised in production.** The dual registrations exist in source;
  I did not confirm bsky.social's current topology.
- **The 0.5.9-vs-0.5.21 delta.** The self-host wrapper pins `@atproto/pds` 0.5.9 while the monorepo checkout is
  at 0.5.21. Everything in §4-§12 was read from the 0.5.21 source. UNVERIFIED: whether the shipped Docker image
  differs in any of the cited behaviours. Would need the 0.5.9 tag checked out to diff.
- **`getRecommendedDidCredentials`, `listMissingBlobs`, `reserveSigningKey`, `deactivateAccount` handler
  bodies** were confirmed to exist, be registered, and be non-trivial in length (50/29/15/41 lines), but I read
  only their imports and registration lines, not their full logic.
- **`@atproto/sync` package** was listed but not read; it is a consumer-side library and does not affect the
  PDS's emit behaviour.
- **hCaptcha, mailer templates, and the OAuth UI** were not examined.
