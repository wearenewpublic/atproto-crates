# cirrus — single-user PDS on Cloudflare Workers

**Path convention for this file:** every `packages/…`, `apps/…`, `demos/…`, `docs/…`, `plans/…` citation below is
rooted at `/tmp/gap-scratch/cirrus/`. Lexicon citations are absolute under
`/tmp/gap-scratch/atproto/lexicons/`.

Version examined: `@getcirrus/pds@0.18.0` (`packages/pds/package.json:3`), single commit `0aec631 ci: release (#194)`.

---

## 1. Language, stack, build, licence

TypeScript, ESM-only, targeting the Cloudflare Workers runtime. `tsconfig.json:6` sets `target: es2022`,
`lib: ["es2022"]` (no DOM), `strict` plus `noUncheckedIndexedAccess` and `noImplicitOverride`. pnpm workspaces
(`pnpm-workspace.yaml:1-5`) over `packages/*`, `demos/*`, `apps/*`, `docs`. Build is `tsdown`
(`packages/pds/package.json:20`), tests are `vitest` 4.1.0-beta with `@cloudflare/vitest-pool-workers`
(`packages/pds/package.json:56`), formatting is Prettier, dead-code check is `knip`.

HTTP layer is Hono (`packages/pds/src/index.ts:5,79`). Crypto/JWT is `jose` + `@atproto/crypto`
(secp256k1 only). Lexicon validation and syntax come from the `@atcute/*` family; repo/MST/CAR mechanics come
from `@atproto/repo@0.8.12` (`pnpm-lock.yaml:533`).

Licence: **MIT**, declared in `package.json:14` and `packages/pds/package.json:76`, and in the README footer
(`README.md:123`). There is **no LICENSE file in the repository** — `find . -iname 'LICENSE*'` (excluding
node_modules) returns nothing.

Three published packages: `@getcirrus/pds` (the server + CLI), `@getcirrus/oauth-provider` (standalone OAuth 2.1
AS for Workers), `create-pds` (scaffolder). Plus a non-published conformance web app `apps/check` and an Astro
docs site.

## 2. Single-user model and deployment

Single-user is baked in at the process level, not enforced per-request by a lookup:

- Module-load assertion of a single account's identity: `packages/pds/src/index.ts:39-62` requires
  `DID`, `HANDLE`, `PDS_HOSTNAME`, `AUTH_TOKEN`, `SIGNING_KEY`, `SIGNING_KEY_PUBLIC`, `JWT_SECRET`,
  `PASSWORD_HASH` and throws at import time if any is absent.
- Exactly one Durable Object instance, keyed by the literal string `"account"`:
  `packages/pds/src/index.ts:104` `env.ACCOUNT.idFromName("account")`.
- Every repo/sync handler hard-compares the requested DID to `c.env.DID` and 404s otherwise
  (`packages/pds/src/xrpc/sync.ts:31-39`, `71-79`, `144-152`, `193-201`, `266-274`, `312-320`, `449-457`;
  `packages/pds/src/xrpc/repo.ts:120-128`, `179-187`, `236-244`).
- `createSession` only accepts the one configured identifier (`packages/pds/src/xrpc/server.ts:74-82`).
- `listRepos` returns a single hardcoded entry (`packages/pds/src/xrpc/sync.ts:101-118`).
- `resolveHandle` answers only for the local handle and lets everything else fall through to the proxy
  (`packages/pds/src/index.ts:286-292`).
- The OAuth `verifyUser` callback ignores any username and compares against the one `PASSWORD_HASH`
  (`packages/pds/src/oauth.ts:201-208`).
- A code comment states the single-tenancy assumption explicitly and names what would break if it changed:
  `packages/pds/src/oauth.ts:135-141` ("cirrus PDS is single-tenant per Worker isolate (one account DID per
  deployment) … If cirrus ever becomes multi-tenant, this map needs to be keyed by `${did}:${nsid}`").

Deployment is **serverless-only**: a Cloudflare Worker + one SQLite-backed Durable Object + an R2 bucket. The
scaffolded `wrangler.jsonc` (`packages/create-pds/templates/pds-worker/wrangler.jsonc`) declares
`durable_objects.bindings[0] = {name: "ACCOUNT", class_name: "AccountDurableObject"}`, the SQLite migration
`new_sqlite_classes: ["AccountDurableObject"]`, and `r2_buckets[0] = {binding: "BLOBS", bucket_name:
"pds-blobs"}`, with `compatibility_flags: ["nodejs_compat"]` and `observability.enabled: true`. The user's own
worker entrypoint is one line (`packages/create-pds/templates/pds-worker/src/index.ts:2`:
`export { default, AccountDurableObject } from "@getcirrus/pds";`). No container, no systemd, no reverse proxy,
no database to run. Secrets go to Wrangler secrets (`AUTH_TOKEN`, `SIGNING_KEY`, `JWT_SECRET`, `PASSWORD_HASH`);
public config goes to `vars`.

Consequence for the firehose: because a Durable Object is a real addressable stateful object, cirrus **can**
hold long-lived WebSockets — it uses Cloudflare's hibernation API (`packages/pds/src/account-do.ts:1201`
`this.ctx.acceptWebSocket(server)`), with connection state stashed in `serializeAttachment`
(`account-do.ts:1204-1208`) so an idle socket does not keep the DO billing. Broadcast iterates
`this.ctx.getWebSockets()` (`account-do.ts:1172`). This is the single most important architectural fact: unlike a
plain-Worker design, a relay's persistent `subscribeRepos` connection survives.

The counter-consequence is that the same single-threaded DO is a shared bottleneck, and the authors document
having been bitten by it: `packages/pds/src/account-do.ts:1046-1053` explains that R2 puts were moved *out* of
the DO because "awaiting an R2 put inside it … pins the input gate, and Cloudflare resets the object when a
storage op can't complete in time, dropping the firehose and desyncing the relay." The blob write therefore
happens in the stateless Worker (`packages/pds/src/xrpc/repo.ts:666-678`) and only a tracking row crosses into
the DO.

`DATA_LOCATION` (`packages/pds/src/index.ts:94-110`) selects DO jurisdiction (`"eu"` = hard guarantee) or a
location hint; the README warns it is immutable after first deploy (`packages/pds/README.md:389-391`).

## 3. Storage backends

| Concern | Engine | Where |
|---|---|---|
| Repo blocks (MST nodes + record blocks) | Durable Object SQLite, table `blocks(cid PK, bytes, rev)` | `packages/pds/src/storage.ts:40-46` |
| Repo head | DO SQLite, single-row `repo_state(root_cid, rev, seq, active, email)` | `packages/pds/src/storage.ts:49-60` |
| Firehose log | DO SQLite, `firehose_events(seq INTEGER PK AUTOINCREMENT, event_type, payload BLOB, created_at)` | `packages/pds/src/storage.ts:63-70` |
| Preferences | DO SQLite, single-row JSON blob `preferences(data)` | `packages/pds/src/storage.ts:73-79` |
| Blob accounting | DO SQLite, `record_blob(recordUri, blobCid)` + `imported_blobs(cid, size, mimeType)` | `packages/pds/src/storage.ts:82-96` |
| Collection cache (for describeRepo) | DO SQLite, `collections(collection PK)` | `packages/pds/src/storage.ts:99-101` |
| Passkeys / registration tokens | DO SQLite, `passkeys`, `passkey_tokens` | `packages/pds/src/storage.ts:104-119` |
| App passwords (bcrypt) | DO SQLite, `app_passwords(name PK, password_hash, created_at)` | `packages/pds/src/storage.ts:122-126` |
| OAuth codes/tokens/PAR/clients/nonces/permission-set cache | DO SQLite, separate schema | `packages/pds/src/oauth-storage.ts` (init at `account-do.ts:86-87`) |
| Blob bytes | Cloudflare R2, key `${did}/${cid}` | `packages/pds/src/blobs.ts:33` |
| Account identity/secrets | Worker env vars + Wrangler secrets — **not** in any DB | `packages/pds/src/types.ts:41-57` |

Schema is created idempotently on first DO access (`packages/pds/src/account-do.ts:73-101`), with one ad-hoc
`ALTER TABLE … ADD COLUMN email` migration guarded by try/catch (`packages/pds/src/storage.ts:129-134`). There is
no migration framework; the docs acknowledge the schema "can change between minor versions"
(`docs/src/content/docs/project/status.md:45`).

`SqliteRepoStorage` implements `@atproto/repo`'s `RepoStorage`/`ReadableBlockstore`
(`packages/pds/src/storage.ts:25-28`). Two spots reach into private internals of upstream types
(`(blocks as unknown as {map: Map<…>}).map` at `storage.ts:222` and `storage.ts:256`, `(commit.removedCids as
unknown as {set: Set<string>}).set` at `storage.ts:270`), justified in comments as an iterator-compat
workaround for Workers. That is an upstream-coupling fragility.

Note: DO SQLite has no `BEGIN/COMMIT` here — `applyCommit` relies on Cloudflare's implicit per-request
atomicity (`packages/pds/src/storage.ts:251-252`).

## 4. Endpoint coverage snapshot (verified against code, not the README)

Route table is `packages/pds/src/index.ts`; OAuth sub-app is `packages/pds/src/oauth.ts`. Every NSID below was
checked against the canonical lexicon JSON in `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

### com.atproto.sync

| NSID | Registered | Handler | Real work? |
|---|---|---|---|
| `getRepo` | `index.ts:189` | `xrpc/sync.ts:7` → `account-do.ts:861` | Yes — streams CAR via `writeCarStream`. **`since` param (lexicon `getRepo.json`) is ignored**; always full export (`account-do.ts:874`) |
| `getRepoStatus` | `index.ts:192` | `xrpc/sync.ts:47` | Yes |
| `getLatestCommit` | `index.ts:195` | `xrpc/sync.ts:120` | Yes |
| `getBlocks` | `index.ts:198` | `xrpc/sync.ts:231` → `account-do.ts:907` | Yes |
| `getBlob` | `index.ts:201` | `xrpc/sync.ts:287` | Yes — direct R2 read in the Worker, with content-type sniffing fallback (`sync.ts:348-372`) |
| `listRepos` | `index.ts:204` | `xrpc/sync.ts:101` | Partially — returns the one repo, but **`active: true` is hardcoded** (`sync.ts:114`) even when deactivated, and `limit`/`cursor` are ignored |
| `listBlobs` | `index.ts:207` | `xrpc/sync.ts:169` | Yes — R2 `list()` with cursor. **`since` param ignored** |
| `getRecord` | `index.ts:210` | `xrpc/sync.ts:383` → `account-do.ts:935` | Yes — proof CAR via `@atproto/repo`'s `getRecords` |
| `subscribeRepos` | `index.ts:215` | `account-do.ts:1188` (via `fetch`, `account-do.ts:1763`) | Yes |
| `listReposByCollection` | — | — | **Not routed.** Falls to the catch-all proxy (`index.ts:563`) |
| `getHostStatus`, `listHosts`, `requestCrawl`, `notifyOfUpdate` | — | — | **n/a for a PDS** — lexicons say "Implemented by relays" (`getHostStatus.json`, `listHosts.json`, `notifyOfUpdate.json`). cirrus *calls* `requestCrawl`/`getHostStatus` outbound from the CLI (`cli/utils/pds-client.ts:1101,1146`) |
| `getCheckout`, `getHead` | — | — | n/a — lexicons marked DEPRECATED |

### com.atproto.repo

| NSID | Registered | Handler | Real work? |
|---|---|---|---|
| `describeRepo` | `index.ts:230` (middleware, local-DID only) | `xrpc/repo.ts:96` | Yes, incl. lazy collection backfill (`account-do.ts:234-243`) |
| `getRecord` | `index.ts:238` | `xrpc/repo.ts:153` | Yes |
| `listRecords` | `index.ts:246` | `xrpc/repo.ts:208` | Yes (limit capped at 100, `repo.ts:246`) |
| `createRecord` | `index.ts:255` | `xrpc/repo.ts:258` → `account-do.ts:332` | Yes |
| `putRecord` | `index.ts:267` | `xrpc/repo.ts:384` → `account-do.ts:501` | Yes. **`swapRecord`/`swapCommit` from the lexicon are silently ignored** (grep finds zero occurrences in `packages/pds/src`) |
| `deleteRecord` | `index.ts:258` | `xrpc/repo.ts:340` → `account-do.ts:434` | Yes. `swapRecord`/`swapCommit` ignored |
| `applyWrites` | `index.ts:264` | `xrpc/repo.ts:452` → `account-do.ts:591` | Yes — 200-op cap enforced twice (`repo.ts:479`, `account-do.ts:611`), validate-all-then-commit, per-op prev captured pre-batch (`account-do.ts:716-723`). `swapCommit` ignored |
| `uploadBlob` | `index.ts:261` | `xrpc/repo.ts:604` | Yes — 60 MB cap (`repo.ts:645`), MIME sniffing + scope check |
| `importRepo` | `index.ts:270` | `xrpc/repo.ts:682` → `account-do.ts:972` | Yes — 100 MB cap, `readCarWithRoot`, DID-match assertion |
| `listMissingBlobs` | `index.ts:273` | `xrpc/repo.ts:771` → `storage.ts:490` | Yes |

All 11 `com.atproto.repo` methods are served locally. Reads use `app.use` middleware so a foreign `repo=` value
falls through to the AppView proxy rather than 404ing.

### com.atproto.server

| NSID | Registered | Real work? |
|---|---|---|
| `describeServer` | `index.ts:278` | Yes — `{did, availableUserDomains: [], inviteCodeRequired: false}` (`xrpc/server.ts:40-46`); satisfies the lexicon's required `did` + `availableUserDomains` |
| `createSession` | `index.ts:325` | Yes — account password or app password (`xrpc/server.ts:52`) |
| `refreshSession` | `index.ts:328` | Yes (`xrpc/server.ts:151`) |
| `getSession` | `index.ts:331` | Yes; accepts `DPoP` and `Bearer` (`xrpc/server.ts:236`) |
| `deleteSession` | `index.ts:334` | **Stub** — returns `{}` and revokes nothing; the code says so (`xrpc/server.ts:344-349`: "In a full implementation, we'd revoke the refresh token") |
| `createAppPassword` | `index.ts:337` | Yes (`xrpc/server.ts:561`) |
| `listAppPasswords` | `index.ts:340` | Yes (`xrpc/server.ts:607`) |
| `revokeAppPassword` | `index.ts:343` | Yes (`xrpc/server.ts:637`) |
| `checkAccountStatus` | `index.ts:348` | Yes — returns every field the lexicon requires; `privateStateValues` hardcoded 0 (`xrpc/server.ts:383`) |
| `activateAccount` | `index.ts:351` | Yes + emits `#account`/`#identity`/`#sync` (`account-do.ts:1297`) |
| `deactivateAccount` | `index.ts:354` | Yes + emits `#account` (`account-do.ts:1336`) |
| `getServiceAuth` | `index.ts:375` | Yes (`xrpc/server.ts:408`). **Lexicon `exp` param is ignored** — fixed 5 min (`service-auth.ts:7,74`) |
| `getAccountInviteCodes` | `index.ts:279` | **Stub, legitimately** — returns `{codes: []}` (`xrpc/server.ts:627-631`); n/a for single-user with `inviteCodeRequired:false` |
| `requestEmailUpdate` | `index.ts:360` | **Stub** — always `{tokenRequired:false}` (`xrpc/server.ts:482`) |
| `requestEmailConfirmation` | `index.ts:365` | **Stub** — `{}` (`xrpc/server.ts:492`) |
| `updateEmail` | `index.ts:370` | Real but trivial — stores a string in `repo_state.email` (`xrpc/server.ts:501`, `storage.ts:371`); no verification |
| `createAccount`, `deleteAccount`, `requestAccountDelete`, `createInviteCode(s)`, `confirmEmail`, `requestPasswordReset`, `resetPassword`, `reserveSigningKey` | — | **Not routed.** `createAccount`/`deleteAccount`/invites/password-reset are correctly **n/a** for single-user. `reserveSigningKey` is *not* n/a — a target PDS uses it during inbound migration; cirrus supplies the equivalent via `getRecommendedDidCredentials` instead |

### com.atproto.identity

| NSID | Registered | Real work? |
|---|---|---|
| `resolveHandle` | `index.ts:286` | Yes for the local handle only; others proxy (`index.ts:286-292`) |
| `getRecommendedDidCredentials` | `index.ts:295` | Yes (`xrpc/identity.ts:67`). Note: it returns the **signing key as the sole rotation key** (`identity.ts:74`) — see §13 |
| `requestPlcOperationSignature` | `index.ts:303` | **Deliberate no-op** returning 200 (`xrpc/identity.ts:122-129`); the token is obtained out-of-band via CLI |
| `signPlcOperation` | `index.ts:308` | Yes — fetches the PLC audit log, merges, CBOR-signs with the account key (`xrpc/identity.ts:139-207`) |
| `submitPlcOperation` | `index.ts:313` | Yes — forwards to `https://plc.directory` (`xrpc/identity.ts:260-298`) |
| `updateHandle` | — | **Not routed** (grep: zero hits in `packages/pds/src`). Handle changes require redeploying `HANDLE` + `pds emit-identity` |
| `refreshIdentity`, `resolveDid`, `resolveIdentity` | — | Not routed; fall to proxy |

### com.atproto.admin / com.atproto.moderation / com.atproto.temp

Zero `com.atproto.admin.*` and zero `com.atproto.temp.*` routes. One moderation route:
`com.atproto.moderation.createReport` is registered at `index.ts:557` but is a **pure proxy** —
`handleCreateReportProxy` (`xrpc-proxy.ts:409-422`) routes to `did:plc:ar7c4by46qjdydhdevvrndac`
(`xrpc-proxy.ts:17`, Bluesky's mod service) with `#atproto_labeler`, or to whatever the client's
`atproto-proxy` header names. It stores nothing locally.

### Non-standard / vendor NSIDs

cirrus registers four `gg.mk.experimental.*` methods, which are **not in any lexicon** and will not be
understood by generic clients: `resetMigration` (`index.ts:357`), `getMigrationToken` (`index.ts:318`),
`emitIdentityEvent` (`index.ts:409`), `getFirehoseStatus` (`index.ts:420`).

### app.bsky and everything else

`app.bsky.actor.getPreferences`/`putPreferences` served locally (`index.ts:382,387`).
`app.bsky.ageassurance.getState` is an admitted stub always returning `status: "assured"` (`index.ts:395-406`).
`app.bsky.feed.getFeed` gets special service-auth-audience handling (`index.ts:551`, `xrpc-proxy.ts:378`).
Everything else under `/xrpc/*` hits the catch-all (`index.ts:563`) and is forwarded to `api.bsky.app` (or
`api.bsky.chat` for `chat.bsky.*`) with a minted service JWT (`xrpc-proxy.ts:169-180`). There is **no 501** and
no method allow-list — an unknown NSID is proxied, so a client cannot distinguish "unimplemented" from
"AppView rejected it". The docs say this explicitly
(`docs/src/content/docs/reference/endpoints.md:16`).

### README vs code disagreements (all verified)

- `docs/src/content/docs/reference/endpoints.md:88` claims `submitPlcOperation` and
  `getRecommendedDidCredentials` "are not registered locally and fall through to the AppView proxy". **False** —
  both are registered (`index.ts:295`, `index.ts:313`).
- `packages/pds/README.md:460` and `docs/.../endpoints.md:67` list `com.atproto.server.getAccountStatus`.
  **No such lexicon exists** (`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/` has `checkAccountStatus.json`,
  not `getAccountStatus.json`), and no such route is registered. The CLI method named `getAccountStatus`
  actually calls `checkAccountStatus` (`cli/utils/pds-client.ts:291`).
- `packages/pds/README.md:611` says "No moderation — no reporting"; `index.ts:557` does route
  `com.atproto.moderation.createReport` (as a proxy).
- `packages/pds/README.md:443` says uploadBlob limit is 60 MB (matches `repo.ts:645`), but
  `plans/todo/endpoint-implementation.md:35` still says 5 MB, and the same plan doc lists app passwords,
  `getLatestCommit` and sync `getRecord` as unimplemented TODOs (`plans/todo/endpoint-implementation.md:88-105`)
  when all three ship. Treat `plans/todo/` as stale.
- `docs/.../endpoints.md` omits `getAccountInviteCodes`, `listMissingBlobs` auth, the four
  `gg.mk.experimental.*` methods, and `moderation.createReport`.

## 5. Auth posture

Four accepted credential classes, all funnelled through `packages/pds/src/middleware/auth.ts:89`:

1. **Static operator bearer token** `AUTH_TOKEN` — compared with `===` (`auth.ts:145`), granted the legacy
   fully-trusted scope `com.atproto.access` (`auth.ts:146`, `auth.ts:33`). Not a spec construct; a cirrus-ism.
2. **Session JWTs** — HS256 over `JWT_SECRET`, `typ: at+jwt` / `refresh+jwt`, aud = `did:web:${PDS_HOSTNAME}`,
   120 min access / 90 day refresh (`packages/pds/src/session.ts:16-17,29-64`). Refresh tokens are **never
   stored or revoked** — `deleteSession` is a no-op (`xrpc/server.ts:344`), so a leaked refresh token is valid
   for 90 days unless `JWT_SECRET` is rotated. Expired tokens deliberately return HTTP 400 `ExpiredToken`
   to match the reference PDS (`auth.ts:176-186`).
3. **App passwords** — `xxxx-xxxx-xxxx-xxxx`, bcrypt cost 10 (`xrpc/server.ts:592`), matched by format regex
   then linear bcrypt scan (`xrpc/server.ts:85-103`). App-password sessions get the same
   `com.atproto.access` scope as the account password — i.e. **no privilege reduction** vs. the reference PDS,
   which marks app-password sessions and blocks privileged methods.
4. **OAuth 2.1 DPoP-bound access tokens** — full local authorization server.

The OAuth AS is real, not a shim. `packages/oauth-provider/src/provider.ts:898-941` advertises:
PAR endpoint with `require_pushed_authorization_requests: true`, `code_challenge_methods_supported: ["S256"]`,
`token_endpoint_auth_methods_supported: ["none","private_key_jwt"]`,
`token_endpoint_auth_signing_alg_values_supported: ["ES256"]`, `dpop_signing_alg_values_supported: ["ES256"]`,
`authorization_response_iss_parameter_supported: true`, `client_id_metadata_document_supported: true`, and
`scopes_supported: ["atproto","transition:generic","transition:email","transition:chat.bsky"]`.
DPoP nonce challenge is implemented (`provider.ts:718-731` returns `use_dpop_nonce` + `DPoP-Nonce` header;
`dpop.ts:174-175`), and `jti` replay is prevented by a persisted single-use check
(`provider.ts:710`, `account-do.ts:1602`). `private_key_jwt` client auth is in `oauth-provider/src/client-auth.ts`.
Well-knowns served: `/.well-known/oauth-authorization-server` (`oauth.ts:260`),
`/.well-known/oauth-protected-resource` (`oauth.ts:272`), `/oauth/jwks` (`oauth.ts:266` — deliberately empty,
`provider.ts:947-953`, because access tokens are HS256). Plus `/oauth/authorize`, `/oauth/token`, `/oauth/par`,
`/oauth/revoke`, `/oauth/userinfo`, `/oauth/passkey-auth`.

Granular atproto scopes are enforced, not just parsed: `requireScope`/`buildScopeChecker`
(`middleware/auth.ts:46-87`) drive `assertRepo` (`xrpc/repo.ts:285,367,414,529`), `assertBlob`
(`xrpc/repo.ts:622,638`), and `assertRpc` on the proxy path (`xrpc-proxy.ts:210`), backed by
`@atproto/oauth-scopes`. `include:` permission-set lexicons are resolved over the network and cached in DO
SQLite with 24 h stale-while-revalidate / 90 d hard expiry (`oauth.ts:145-184`). Legacy paths (static token,
session JWT, service JWT) short-circuit all scope checks (`middleware/auth.ts:33,51`).

Passkeys / WebAuthn via `@simplewebauthn/server` for both registration (`index.ts:434-524`) and OAuth sign-in
(`oauth.ts:210-230`, `/oauth/passkey-auth`).

**Service auth: minted, but only self-verified.** Minting is real ECDSA ES256K over the account signing key
(`service-auth.ts:69-97`), used by `getServiceAuth` and by every proxied request (`xrpc-proxy.ts:268-274`).
Verification (`service-auth.ts:104-162`) resolves **nothing** — it hardcodes `expectedIssuer = c.env.DID` and
verifies against the local `SIGNING_KEY` (`middleware/auth.ts:193-198`). So cirrus accepts only service JWTs it
issued itself (the video-service callback case). It **cannot authenticate an inbound inter-service request from
a different PDS/AppView/labeler**, because that would require resolving the issuer's DID document and checking
its `#atproto` key. `lxm` binding *is* enforced on the tokens it does verify (`middleware/auth.ts:204-234`).
Note also `verifySignature(..., {allowMalleableSig: true})` at `service-auth.ts:154-156`.

## 6. Sync 1.1 status

Substantially implemented, and there are targeted tests for it.

- **`prevData` on every commit.** Captured pre-commit at `account-do.ts:380,452,535,739`
  (`const prevData = repo.commit.data`), threaded through `CommitData.prevData`
  (`sequencer.ts:134`) and emitted at `sequencer.ts:181`. Tested at
  `packages/pds/test/firehose.test.ts:475` ("emits prevData on every commit so relays can run MST inversion")
  and `:624` ("prevData on commit N equals the prior commit's data MST root").
- **Per-op `prev`.** Delete: `account-do.ts:466`. Put/update: `account-do.ts:554`. applyWrites: prev CIDs read
  from **pre-batch** MST state only (`account-do.ts:716-723`, with the comment explaining that this matches the
  reference PDS so an intra-batch create+delete yields no `prev`), applied at `account-do.ts:770,785`.
  Serialized at `sequencer.ts:189`. Matches `repoOp` in
  `/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json` (`prev` optional).
- **Covering-proof blocks in the CAR slice.** `sequencer.ts:165-173` unions `newBlocks` **and**
  `relevantBlocks` from `@atproto/repo`'s `CommitData` before `blocksToCarFile`, with a comment naming the
  MST-inversion requirement. This is the correct sync 1.1 behaviour and is the part most naive implementations
  get wrong.
- **`#sync` events.** `Sequencer.sequenceSync` (`sequencer.ts:262`) exists and matches the lexicon's required
  `{seq, did, blocks, rev, time}`. **It is called from exactly one site**: `rpcActivateAccount`
  (`account-do.ts:1321`). It is **not** emitted after `importRepo` (`account-do.ts:972-1042` has no sequencer
  call) nor after signing-key rotation. `docs/.../concepts/firehose.md:21` claims "repo import, key rotation,
  account activation" all emit `#sync`; only activation does. In the intended migration flow activation follows
  import, so the practical gap is narrow but real.
- **`#account` events.** Emitted on activate (`account-do.ts:1303`) and deactivate (`account-do.ts:1342`,
  `status: "deactivated"`). No `takendown`/`suspended`/`deleted` producer exists.
- **`#identity` events.** Emitted on activate (`account-do.ts:1309`) and via the non-standard
  `gg.mk.experimental.emitIdentityEvent` (`index.ts:409`, `account-do.ts:1444`), with `handle` correctly
  optional per sync 1.1 (`sequencer.ts:225-234`).
- **200-ops-per-commit cap** enforced (`account-do.ts:31-32,611`).
- **No-op updates are NOT rejected.** `rpcPutRecord` (`account-do.ts:501-586`) never compares the incoming
  record CID against `existingCid`; it unconditionally calls `formatCommit` + `applyCommit`. A client that
  re-puts identical bytes produces a new commit and a new firehose event. (The sync 1.1 spec does permit empty
  commits — `subscribeRepos.json` `#commit` description: "empty commits are allowed" — so this is a
  quality-of-implementation gap, not a hard violation.)
- **`tooBig` is hardcoded `false`** (`sequencer.ts:193`); `blobs` is hardcoded `[]` (`sequencer.ts:194`), which
  the docs admit (`docs/.../concepts/firehose.md:48`).
- `getHostStatus` / `listHosts` / `requestCrawl` / `notifyOfUpdate`: **n/a** — relay-side per lexicon. cirrus is
  a *client* of `requestCrawl` and `getHostStatus` from its CLI (`cli/utils/pds-client.ts:1101,1146`;
  invoked from `cli/commands/activate.ts:242,337`).
- `listReposByCollection`: **missing**, and it is a PDS-side method. Trivial to add for a single-user server
  (answer = the local DID or empty) but not present.

## 7. Firehose

Implemented as a Durable Object WebSocket with hibernation.

- Upgrade path: Worker checks the `Upgrade` header (`index.ts:216-222`) then forwards the raw request to the DO
  via `fetch` rather than RPC, because a `WebSocket` cannot cross the RPC boundary (`index.ts:224-226`,
  `account-do.ts:1761-1768`).
- **Framing** is manual: `encodeFrame` concatenates two DAG-CBOR objects, header then body
  (`account-do.ts:1077-1086`). Header for data frames is `{op: 1, t: "#" + type}` (`account-do.ts:1092`); error
  frames use `{op: -1}` (`account-do.ts:1099-1103`); `#info` uses `{op: 1, t: "#info"}` (`account-do.ts:1109`).
  CBOR is `@atcute/cbor` through a compat shim that converts `@atproto` CID objects to `CidLink`
  (`packages/pds/src/cbor-compat.ts:86-89`).
- **Event types emitted:** `#commit`, `#identity`, `#sync`, `#account` (`sequencer.ts:118-122`). No `#handle`,
  `#migrate`, `#tombstone` (correctly — those are removed in sync 1.1).
- **Seq source:** SQLite `AUTOINCREMENT` on `firehose_events.seq`, returned by `INSERT … RETURNING seq`
  (`storage.ts:64`, `sequencer.ts:199-208`). Monotonic and durable, and correctly allocated inside the
  single-threaded DO so there is no interleaving hazard.
- **Cursor resume:** `?cursor=N` parsed at `account-do.ts:1192-1193`, backfill at `account-do.ts:1118-1164`.
  `cursor > latestSeq` → `#error FutureCursor` then close 1008 (`account-do.ts:1125-1133`). Cursor older than
  the retained window → `#info OutdatedCursor` and resume from `earliestSeq - 1`, stream stays open
  (`account-do.ts:1138-1147`). **Backfill is capped at 1000 events in a single shot**
  (`account-do.ts:1149` `getEventsSince(effectiveCursor, 1000)`) and there is no loop — a consumer more than
  1000 events behind receives 1000 and then only live events, silently skipping the middle. That is a
  correctness bug for a relay resuming after a long outage.
- **Backfill window / retention:** `Sequencer.pruneOldEvents` exists (`sequencer.ts:426`) but is **called only
  from a test** (`packages/pds/test/firehose.test.ts:839`). The DO alarm (`account-do.ts:119-127`) runs
  `runCleanup()`, which prunes passkey tokens and OAuth rows only (`account-do.ts:106-113`). So in production
  the firehose log **grows without bound**, and `docs/.../concepts/firehose.md:61` ("the replay window is
  bounded by an internal retention default of 10000 events") is wrong about the deployed behaviour.
- **Slow consumers:** none. `broadcastEvent` (`account-do.ts:1169-1183`) does a bare `ws.send` per socket in a
  try/catch that only `console.error`s. No buffering, no back-pressure, no disconnect-on-lag, no outbox. The
  docs are candid: "Slow consumers do not back-pressure the writer; the firehose is fire-and-forget by design"
  (`docs/.../concepts/firehose.md:81`).
- Operator visibility: `gg.mk.experimental.getFirehoseStatus` returns per-socket cursor/IP/connectedAt and
  `latestSeq` (`index.ts:420`, `account-do.ts:1469-1495`).

## 8. Account migration / import-export

This is cirrus's strongest area, and the claim in the README ("Account migration from existing PDS (tested and
verified)", `README.md:63`) is supported by the code.

**Inbound (other PDS → cirrus), driven by `pds migrate`** (`packages/pds/src/cli/commands/migrate.ts`):

1. `pds init` writes `INITIAL_ACTIVE=false` for a migration setup, so the DO starts deactivated
   (`account-do.ts:79-85`, `storage.ts:59-60`).
2. `pds migrate` health-checks the target, resolves the DID to find the source PDS
   (`migrate.ts:128-144`), and reads target state via `checkAccountStatus`
   (`migrate.ts:156`, `cli/utils/pds-client.ts:291`).
3. Authenticates to the **source** with `com.atproto.server.createSession` (`migrate.ts:345`).
4. `com.atproto.sync.getRepo` from source (`migrate.ts:365`, `pds-client.ts:181`) →
   `com.atproto.repo.importRepo` to cirrus (`migrate.ts:380`, `pds-client.ts:324`).
   Server side: `readCarWithRoot` validates single-root, `putMany` bulk-inserts, `Repo.load` verifies, DID is
   asserted equal to `env.DID` or the import is destroyed and rejected (`account-do.ts:997-1019`).
   Import is refused on an *active* account with an existing root (`account-do.ts:983-988`).
5. Blob refs are extracted from every imported record into `record_blob` during the same walk
   (`account-do.ts:1023-1035`, `extractBlobCids` at `account-do.ts:1816`).
6. Preferences copied via `app.bsky.actor.getPreferences`/`putPreferences` (`migrate.ts:395-409`).
7. Blob backfill loop: `com.atproto.repo.listMissingBlobs` (paged) → source `com.atproto.sync.getBlob` →
   target `com.atproto.repo.uploadBlob`, resumable, failures collected and retried on re-run
   (`migrate.ts:429-473`).
8. `pds identity` (`cli/commands/identity.ts`) performs the PLC rotation **against the source PDS**:
   `requestPlcOperationSignature` → email token → `signPlcOperation` with the cirrus endpoint + new signing
   `did:key` (`identity.ts:236-273`) → the CLI submits directly to `plc.directory`
   (`identity.ts:292`, `cli/utils/plc-client.ts`).
9. `pds activate` (`cli/commands/activate.ts`) runs three pre-flight checks — handle resolution, DID document
   points at cirrus, repo/blob completeness (`activate.ts:34-57`, `cli/utils/checks.ts`) — then calls
   `com.atproto.server.activateAccount` (`activate.ts:305`), which flips `active` and emits
   `#account` + `#identity` + `#sync` (`account-do.ts:1297-1330`), then calls the relay's
   `com.atproto.sync.requestCrawl` (`activate.ts:337`, `pds-client.ts:1146`) and offers to emit an extra
   `#identity` (`activate.ts:363`).
10. `pds migrate --clean` uses the non-standard `gg.mk.experimental.resetMigration` (`index.ts:357`,
    `account-do.ts:1409`), which refuses to run on an active account.

**Outbound (cirrus → other PDS):**
`gg.mk.experimental.getMigrationToken` (`index.ts:318`, `xrpc/identity.ts:309`) mints a stateless
HMAC-SHA256 token over `{did, exp}` with a 15 min TTL (`packages/pds/src/migration-token.ts:17,65-79`).
`com.atproto.identity.signPlcOperation` (`index.ts:308`, `xrpc/identity.ts:139`) validates that token, pulls the
current non-nullified op from the PLC audit log (`identity.ts:212-224`), merges the caller's requested
`rotationKeys`/`alsoKnownAs`/`verificationMethods`/`services`, and returns a signed op.
`com.atproto.identity.submitPlcOperation` (`index.ts:313`) forwards to `plc.directory`.
`com.atproto.identity.requestPlcOperationSignature` returns 200 without doing anything, by design — the token
comes from the CLI, not email (`xrpc/identity.ts:122-129`).
`com.atproto.identity.getRecommendedDidCredentials` (`index.ts:295`) lets a target PDS discover what to put in
its PLC op.

Coverage check against the standard migration checklist: `importRepo` ✅, `listMissingBlobs` ✅,
`checkAccountStatus` ✅, `activateAccount`/`deactivateAccount` ✅, `signPlcOperation` ✅,
`submitPlcOperation` ✅, `requestPlcOperationSignature` ✅ (no-op), `getRecommendedDidCredentials` ✅.
Missing from the standard set: `com.atproto.server.createAccount` (so a *target* tool cannot provision the
cirrus account over the wire — it must be provisioned by `pds init` + `wrangler deploy`) and
`com.atproto.server.reserveSigningKey`.

## 9. did:plc vs did:web

Both supported for the **account DID**, selected at setup time. `pds init` defaults to
`did:web:${hostname}` for a fresh account (`cli/commands/init.ts:365`) and accepts a pasted
`did:plc:…` for a migration (`init.ts:246`). The Worker serves `/.well-known/did.json`
(`index.ts:113`, document built in `xrpc/identity.ts:32-57`) and `/.well-known/atproto-did`
(`index.ts:118`), so did:web self-hosting works with no extra infrastructure.

**The service DID is always `did:web:${PDS_HOSTNAME}`** and is computed inline rather than configured:
`xrpc/server.ts:122,168,295`, `middleware/auth.ts:150`, `xrpc-proxy.ts:231`. It is used as the JWT audience for
all session tokens. There is no `did:plc` option for the service identity.

DID **resolution** of third parties supports plc + web only, via `@atcute/identity-resolver`
(`packages/pds/src/did-resolver.ts:46-56`), with a 3 s timeout, a Workers-cache-backed DID cache
(`packages/pds/src/did-cache.ts`), and a document-id-matches-request assertion (`did-resolver.ts:94-97`).
No `did:webvh`.

Limitation: the PLC rotation CLI hard-refuses non-`did:plc` (`cli/commands/identity.ts:99-104`), which is
correct — did:web has no PLC log. But it means a did:web cirrus account has **no key-rotation story at all**;
the README says so bluntly (`README.md:94-97`: "Old signatures become unverifiable – followers may see
warnings … there's no cryptographic proof of continuity").

## 10. Blobs

Stored in R2 under `${did}/${cid}` (`packages/pds/src/blobs.ts:33`). CID is computed as CIDv1 / raw codec /
SHA-256 via `@atcute/cid` (`blobs.ts:29`) — correct for atproto blob refs.

Write path deliberately bypasses the DO (`xrpc/repo.ts:666-678`, rationale at `account-do.ts:1046-1053`); only
`rpcTrackBlob` crosses into SQLite (`account-do.ts:1055-1062`). Read path also bypasses the DO
(`xrpc/sync.ts:333-335`), with a content-type sniff-and-tee fallback when R2 metadata is missing or `*/*`
(`xrpc/sync.ts:348-372`, detector in `packages/pds/src/format.ts`).

Validation: 60 MB hard cap (`xrpc/repo.ts:645-654`); MIME is sniffed from bytes and the sniffed value — not the
client-declared header — drives the OAuth `blob:` scope check (`xrpc/repo.ts:628-642`, with a comment
explaining the anti-spoofing reasoning). Legacy (pre-`$type: blob`) blob refs are rejected at record-write time
(`packages/pds/src/validation.ts:198-219`).

**No GC and no ref-counting.** `record_blob` is written from exactly one call site — the `importRepo` walk
(`account-do.ts:1033`) — and `removeRecordBlobs` (`storage.ts:441`) has **zero callers** outside `storage.ts`
(verified by grep). So blobs uploaded through normal `uploadBlob` are never associated with the records that
reference them, deleting a record never dereferences its blobs, and nothing ever deletes an R2 object. The
tables are migration-progress accounting, not a lifecycle system. Cost is silently monotonic. Also: there is no
"unreferenced blob" quarantine — `uploadBlob` stores immediately with no pending state.

## 11. Moderation / admin / takedown

Effectively absent, and declared out of scope. Zero `com.atproto.admin.*` routes. `createReport` is proxied to
Bluesky's labeler (§4). There is **no takedown enforcement path**: `AccountStatus` in `sequencer.ts:51-55`
types `"takendown" | "suspended" | "deleted" | "deactivated"`, but `sequenceAccount` is only ever called with
`deactivated`/active (`account-do.ts:1303,1342`), and nothing reads a takedown state when serving records.
`getRepoStatus` can only report `deactivated` (`xrpc/sync.ts:94-98`). No label store, no
`com.atproto.label.*`, no `com.atproto.temp.fetchLabels`.

The project states this as policy, not oversight: `docs/src/content/docs/project/status.md:31` — "Moderation
tooling. Cirrus is a PDS, not an AppView or a moderation service" — and `:32` "Admin operations for other
users. Single-user means single-owner. There are no admin endpoints to manage other accounts."
For a single-owner PDS this is a defensible n/a for the *admin* surface; the absence of any self-takedown /
suspended status is a genuine (if low-priority) gap.

## 12. Rate limiting, metrics, health, ops

- **Rate limiting: none.** Zero `rateLimit`/`ratelimit` identifiers anywhere in `packages/*/src`. The docs
  confirm: "Cirrus does not implement any rate limiting beyond what Cloudflare provides"
  (`docs/src/content/docs/concepts/costs-and-limits.md:38`). No per-IP throttle on `createSession`, so
  app-password/account-password brute-forcing is bounded only by bcrypt cost and Cloudflare's platform limits.
- **Health:** `GET /xrpc/_health` (`index.ts:125-133`) does a real `SELECT 1` round-trip into the DO
  (`account-do.ts:1461-1464`) and returns `{status, version}` / 503. Non-standard path but matches the
  reference PDS convention.
- **Metrics:** no Prometheus/OTel/StatsD. Observability is Cloudflare-native (`observability.enabled: true` in
  the wrangler template), plus a human-facing `GET /status` HTML dashboard (`index.ts:177`,
  `packages/pds/src/dashboard.ts`) and a terminal TUI `pds dashboard` (`cli/commands/dashboard.ts`, 1061 lines)
  that shows per-collection record counts, relay host status, live firehose subscribers and cursors.
  `docs/src/content/docs/operate/monitor.md:88` is candid: "Cirrus does not emit a stable, documented catalogue
  of log lines."
- **Logging:** bare `console.error` at ~6 sites (`account-do.ts:1180,1247`, `xrpc/sync.ts:472`,
  `index.ts:448`). No structured logging, no request IDs, no levels.
- **Ops story:** a genuinely good `citty`-based CLI — `init`, `migrate`, `identity`, `activate`, `deactivate`,
  `migrate-token`, `status`, `dashboard`, `emit-identity`, `passkey add|list|remove`,
  `app-password create|list|revoke`, `secret key|jwt|password` (`packages/pds/src/cli/commands/`). Plus
  `apps/check`, a deployable browser conformance suite that runs anonymous read checks and (after sign-in) a
  live write probe specifically to validate sync 1.1 `prevData`/`ops[].prev` on a fresh sample
  (`apps/check/src/checks/index.ts:28-36`, `apps/check/src/checks/firehose.ts:326-379`).
- **Tests:** ~14.6k lines across 22 unit specs, 5 CLI specs, 8 oauth-provider specs and 6 Workers-pool e2e
  specs (`packages/pds/test/`, `packages/oauth-provider/test/`, `packages/pds/e2e/`). Real coverage of the
  hard parts (firehose framing, prevData, migration, DPoP, scopes).

## 13. Notable spec deviations and explicitly-unsupported features

The project's own candid statements, each verified against code:

- `README.md:56` — "⚠️ **This is experimental beta software under active development.** … not all edge cases
  have been discovered. Consider backing up important data before migrating a primary account." Consistent
  with the single-`ALTER TABLE` migration story (`storage.ts:129-134`).
- `packages/pds/README.md:606-611` "Limitations": single-user only, no account creation, no email, no
  moderation. Code agrees on the first three; the fourth is imprecise (see §4 — `createReport` is proxied).
- `docs/.../project/status.md:23` — "Granular scope coverage. Most endpoints enforce scope; a few admin-style
  endpoints still need fine-grained checks." Code agrees: `requireScope` is applied on repo writes, blobs and
  the proxy, but **not** on `activateAccount`/`deactivateAccount`/`updateEmail`/`getServiceAuth`/
  `createAppPassword`/`listMissingBlobs`/`importRepo` (`index.ts:270-379` — these get `requireAuth` only).
- `docs/.../reference/endpoints.md:16` — "❌ … the Worker falls through to the auto-proxy … Cirrus does not
  return 501." Confirmed at `index.ts:563`.

Deviations the project does *not* flag:

1. **`swapRecord` / `swapCommit` are accepted and ignored** on `putRecord`, `deleteRecord`, `applyWrites`
   (lexicons `/tmp/gap-scratch/atproto/lexicons/com/atproto/repo/putRecord.json` etc. define them; grep finds
   zero references in `packages/pds/src`). A client relying on compare-and-swap for optimistic concurrency
   gets silent last-write-wins. On a single-user server the blast radius is small but non-zero (two clients).
2. **`getServiceAuth`'s `exp` parameter is ignored** — always 5 minutes (`service-auth.ts:7,74`).
3. **`getRepo`'s `since` and `listBlobs`'s `since` are ignored** (`account-do.ts:874`, `xrpc/sync.ts:214-218`).
4. **`sync.listRepos` reports `active: true` unconditionally** (`xrpc/sync.ts:114`), contradicting
   `getRepoStatus` on a deactivated account.
5. **Firehose backfill truncates at 1000 events with no continuation** (`account-do.ts:1149`).
6. **Firehose retention is never applied** — `pruneOldEvents` has no production caller (§7).
7. **`getRecommendedDidCredentials` returns the *signing* key as the sole rotation key**
   (`xrpc/identity.ts:70-76`). The reference PDS keeps rotation keys distinct from the signing key; conflating
   them means anyone who obtains the signing key can rewrite the DID document, and there is no separate
   recovery key.
8. **Service-JWT verification cannot authenticate other services** (§5) — hardcoded issuer + local key.
9. **Refresh tokens are unrevocable**; `deleteSession` is a no-op (`xrpc/server.ts:344-349`).
10. **App-password sessions are indistinguishable from full sessions** — both get `com.atproto.access`
    (`session.ts:36`), so an app password can call `getServiceAuth`, `signPlcOperation` and
    `deactivateAccount`. The reference PDS restricts privileged methods for app-password sessions.
11. **Non-standard `gg.mk.experimental.*` NSIDs** carry migration-reset, migration-token, identity-emit and
    firehose-status (`index.ts:318,357,409,420`).
12. **`app.bsky.ageassurance.getState` always returns `assured`** (`index.ts:395-406`) — an admitted stub.
13. **Record validation is a fixed table of 19 hardcoded lexicons** (`packages/pds/src/validation.ts:39-68`),
    fail-open for anything else with `validationStatus: "unknown"` (`validation.ts:136-141`). No dynamic
    lexicon resolution. This matches the reference PDS's optimistic posture but the known-schema set is frozen
    at build time.
14. **No LICENSE file** despite MIT declarations (§1).

## 14. Maturity tier

**single-user.**

It is unambiguously a single-purpose, single-account server — the identity is a module-level env assertion
(`index.ts:39-62`), the DO id is the literal `"account"` (`index.ts:104`), and multi-tenancy is explicitly
off the roadmap (`docs/.../project/status.md:29`). Within that scope the engineering quality is well above
hobby: all 11 `com.atproto.repo` methods, 9 `com.atproto.sync` methods, a real OAuth 2.1 authorization server
with PAR/PKCE/DPoP-nonce/private_key_jwt and enforced granular scopes, a correct sync 1.1 firehose including
`prevData`, per-op `prev` and covering-proof blocks, a complete and tested bidirectional migration flow, ~14.6k
lines of tests, and a shipped conformance-checker app. It falls short of "serious" only because the omissions
that matter for a general-purpose PDS — no rate limiting, no blob GC, unbounded firehose log with a truncating
1000-event backfill, no inbound service-auth verification, no CAS, no takedown — are structural rather than
cosmetic.

---

## Confidence & unknowns

Verified by reading source: every route registration and handler in `packages/pds/src/index.ts`,
`xrpc/{sync,repo,server,identity}.ts`, `account-do.ts`, `sequencer.ts`, `storage.ts`, `blobs.ts`,
`middleware/auth.ts`, `service-auth.ts`, `session.ts`, `migration-token.ts`, `validation.ts`,
`did-resolver.ts`, `oauth.ts`, `cbor-compat.ts`, `types.ts`; the OAuth metadata handler in
`packages/oauth-provider/src/provider.ts:890-953`; the wrangler templates; and the endpoint/status docs. All
NSID assertions were cross-checked against the lexicon JSON under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/`.

Not verified:

- **UNVERIFIED: whether the emitted `#commit` CAR actually satisfies a real relay's MST-inversion check.** I
  confirmed cirrus unions `newBlocks + relevantBlocks` (`sequencer.ts:165-173`) and that `@atproto/repo@0.8.12`
  is the pinned dependency (`pnpm-lock.yaml:533`), but `node_modules` is not installed in this checkout, so I
  could not read upstream's `formatCommit` to confirm `relevantBlocks` is populated with the full covering
  proof for every op shape. Would need the installed package or an end-to-end capture against a relay.
- **UNVERIFIED: `packages/oauth-provider/src/{par,client-auth,dpop,tokens,scopes,ui}.ts` internals.** I read
  the advertised metadata, the nonce/jti call sites, and the file inventory, but not the full 4.3k lines. The
  §5 claims about PAR one-time-use semantics, PKCE verifier comparison, and `private_key_jwt` signature
  validation rest on the metadata declaration plus test-file names (`test/par.test.ts`, `test/pkce.test.ts`,
  `test/client-auth.test.ts`), not on line-level reading of those implementations.
- **UNVERIFIED: runtime behaviour of the 1000-event backfill truncation.** Read from
  `account-do.ts:1149` with no surrounding loop; not reproduced against a live DO.
- **UNVERIFIED: whether Cloudflare's DO input-gate atomicity actually makes `applyCommit` crash-safe.** The
  code asserts it in a comment (`storage.ts:251-252`); I did not test the failure mode. Note the authors added
  `invalidateRepoCache()` (`account-do.ts:218-221`) specifically because JS state and SQLite state can diverge
  on rollback, which suggests the guarantee is narrower than "transactional".
- **UNVERIFIED: `packages/pds/src/cli/commands/init.ts` full key-generation and secret-deployment path** (845
  lines). I read the DID/handle prompts and the key-recovery messaging only.
- **UNVERIFIED: whether any relay currently subscribes to a production cirrus deployment.** The README claims
  migration is "tested and verified" (`README.md:63`) and `docs/.../project/status.md:16` says "Verified
  end-to-end"; I have no independent evidence.
- **UNVERIFIED: exact per-request behaviour under Cloudflare's 128 MB Worker memory limit for the 100 MB
  `importRepo` cap** (`xrpc/repo.ts:714`) — the CAR is buffered whole via `arrayBuffer()`
  (`xrpc/repo.ts:701`), which looks likely to OOM near the cap, but I did not test it.
