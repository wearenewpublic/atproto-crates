# cocoon — implementation notes

Source snapshot: `/tmp/gap-scratch/cocoon`, git HEAD `263b01f087a69c91c72217ac6b55f65971caa12d` (2026-07-03, "Fix panics during token validation (#120)").
All citations below are relative to that source root. Canonical lexicons checked under `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

Size: 133 `.go` files, 12,123 non-test LOC, 2,203 test LOC.

---

## 1. Language, stack, build, license

Go. `go.mod:1-3` declares `module github.com/haileyok/cocoon`, `go 1.26.1`. Single binary built from one main package (`cmd/cocoon/main.go`, the only file under `cmd/`).

Stack:
- HTTP framework: `github.com/labstack/echo/v4` (`go.mod:26`), used for every route (`server/server.go:289`).
- ORM: `gorm.io/gorm` with both `gorm.io/driver/sqlite` and `gorm.io/driver/postgres` drivers (`go.mod:34-36`); thin wrapper in `internal/db/db.go`.
- AT Protocol primitives are taken wholesale from indigo — `github.com/bluesky-social/indigo` (`go.mod:9`) supplies `atproto/repo` (commit + MST), `atproto/repo/mst`, `atproto/atcrypto`, `atproto/atdata`, `atproto/syntax`, `events` (the firehose event manager), `carstore.LdWrite`, and the generated `api/atproto` CBOR types. See imports at `server/repo.go:13-21`.
- CLI: `github.com/urfave/cli/v2` (`go.mod:30`), subcommands wired at `cmd/cocoon/main.go:169-176`: `run`, create-rotation-key, create-private-jwk, `create-invite-code`, `reset-password`, `recommit-repos`.
- Metrics: `prometheus/client_golang` + `echo-contrib/echoprometheus` (`server/server.go:294`).

Build: `Makefile:30-32` (`go build -ldflags "-X main.Version=$(VERSION)" -o cocoon ./cmd/cocoon`); `Makefile:35-47` cross-compiles 11 GOOS/GOARCH pairs. `Makefile:61-75` gives `test`/`lint`/`fmt`/`check`. CI runs `go vet ./...` and `go test -race ./...` with CGO on (`AGENTS.md:73-76`; `.github/workflows/go-test.yml`). Tests require cgo because of `mattn/go-sqlite3` (`AGENTS.md:13-16`).

License: MIT, `LICENSE:1-3` — "Copyright (c) 2025 me@haileyok.com". `README.md:285-287` also notes the bundled `server/static/pico.css` is MIT.

## 2. Multi-account, deployment model

**Multi-account.** Accounts are rows in `repos` + `actors` (`models/models.go:18-73`), keyed by DID, with per-account signing keys (`models.Repo.SigningKey`, `models/models.go:34`). Signup is gated by invite codes by default (`cmd/cocoon/main.go:86-90`, `COCOON_REQUIRE_INVITE` defaults `true`; enforced in `server/handle_server_create_account.go:111-137`). Invite codes are minted by an admin over HTTP Basic (`server/server.go:591-592`, `server/middleware.go:23-36`) or by CLI (`README.md:196-199`).

**Deployment**: single process, container-first.
- `Dockerfile:1-24` (Debian bookworm build + slim runtime, `CMD ["/cocoon", "run"]`), plus `Dockerfile.alpine`.
- Three compose files: `docker-compose.yaml` (SQLite + Caddy), `docker-compose.postgres.yaml`, `docker-compose.noproxy.yaml`. The default stack runs four services — `init-keys`, `cocoon`, `create-invite`, `caddy` (`README.md:85-90`); `cocoon` uses `network_mode: host` (`docker-compose.yaml:31`).
- TLS terminated by Caddy: `Caddyfile:1-9` reverse-proxies `{$COCOON_HOSTNAME}` → `localhost:8080`; `Caddyfile.postgres:2` → `cocoon:8080`.
- Prebuilt images published to ghcr (`docker-compose.yaml:8`, `.github/workflows/docker-image.yml`).
- Configuration is entirely env vars (`COCOON_*`), `.env.example:1-12`, loaded via `godotenv/autoload` (`cmd/cocoon/main.go:20`).
- No systemd unit, no serverless target, no installer script beyond `init-keys.sh` / `create-initial-invite.sh`.

Hard startup requirements: `COCOON_ADMIN_PASSWORD` (`server/server.go:281-283`) and `COCOON_SESSION_SECRET` (`server/server.go:285-287`, panics if unset).

## 3. Storage backends

One relational database holds *everything* except optionally blobs. `server/server.go:606-619` runs `AutoMigrate` over the whole schema; there are no migration files — the Go structs in `models/models.go` and `oauth/provider/models.go` **are** the schema.

| Data | Table / type | Where |
|---|---|---|
| Accounts (email, bcrypt password, signing key, head root+rev, prefs, 2FA, all the e-mail one-shot codes) | `repos` / `models.Repo` | `models/models.go:18-42` |
| Handle ↔ DID | `actors` / `models.Actor` | `models/models.go:70-73` |
| Repo blocks (MST nodes, records, commits) | `blocks` / `models.Block` — PK `(did, cid)`, secondary index on `rev` | `models/models.go:110-115` |
| Denormalized record index (for `listRecords`/`getRecord`) | `records` / `models.Record`, value stored as DAG-CBOR bytes | `models/models.go:101-108` |
| Blobs | `blobs` + `blob_parts` (64 KiB chunks) or S3 | `models/models.go:117-131` |
| Sessions | `tokens`, `refresh_tokens` | `models/models.go:86-99` |
| Invite codes | `invite_codes` | `models/models.go:80-84` |
| Reserved signing keys (migration) | `reserved_keys` | `models/models.go:133-138` |
| Firehose event log | `event_records` / `models.EventRecord` | `models/models.go:140-146`, migrated separately at `server/persist.go:32` |
| OAuth tokens + authorization requests | `oauth_tokens`, `oauth_authorization_requests` | `oauth/provider/models.go`, migrated at `server/server.go:617-618` |

Engine: SQLite by default, Postgres opt-in via `COCOON_DB_TYPE=postgres` / `DATABASE_URL` (`cmd/cocoon/main.go:46-57`; driver selection in `cmd/cocoon/main.go`). The blockstore is an `ipfs-blockstore` implementation over the same DB — `sqlite_blockstore/sqlite_blockstore.go:15-58`, selected in `server/blockstore_variant.go:23-30`. Note `MustReturnBlockstoreVariant` *panics* on any value other than `"sqlite"` (`server/blockstore_variant.go:14-21`), so `COCOON_BLOCKSTORE_VARIANT` has exactly one legal value despite being a configurable flag (`cmd/cocoon/main.go:157-161`). Under Postgres the "sqlite blockstore" is still what runs — the name is historical; it issues plain SQL against `blocks` through the generic `db.DB` wrapper.

Blobs: DB-backed by default; `COCOON_S3_BLOBSTORE_ENABLED=true` puts them at `blobs/{did}/{cid}` in S3 (`server/handle_repo_upload_blob.go:127-134`). Per-blob `Storage` column records which (`models/models.go:123`).

Backups: hourly `VACUUM INTO` → S3, SQLite only, skipped for Postgres (`server/server.go:673-691`, `server/server.go:676-679`).

## 4. Endpoint coverage snapshot

The complete route table is `func (s *Server) addRoutes()`, `server/server.go:496-597`. There is no generated router and no lexicon-driven dispatch: every route is a literal path string. Everything below was read out of that function, not the README.

Middleware legend: **pub** = no auth; **sess** = `handleLegacySessionMiddleware` + `handleOauthSessionMiddleware` (accepts a Bearer session JWT, an `lxm`-scoped service-auth JWT, or a DPoP OAuth token — `server/middleware.go:38-324`); **admin** = HTTP Basic `admin:$COCOON_ADMIN_PASSWORD` (`server/middleware.go:23-36`).

### com.atproto.identity.*

| NSID | HTTP | Registration | Auth | Real work? |
|---|---|---|---|---|
| `resolveHandle` | GET | `server/server.go:514` | pub | yes — DNS TXT then `/.well-known/atproto-did` via `identity.Passport` (`server/handle_server_resolve_handle.go:31`, `identity/identity.go:81-89`) |
| `getRecommendedDidCredentials` | GET | `server/server.go:558` | sess | yes (`server/handle_identity_get_recommended_did_credentials.go:19`) |
| `updateHandle` | POST | `server/server.go:559` | sess | yes; submits a PLC op for `did:plc:` accounts, DB-only for others (`server/handle_identity_update_handle.go:43-102`) |
| `requestPlcOperationSignature` | POST | `server/server.go:560` | sess | yes (emails a one-shot code) |
| `signPlcOperation` | POST | `server/server.go:561` | sess | yes (`server/handle_identity_sign_plc_operation.go:44-90`) |
| `submitPlcOperation` | POST | `server/server.go:562` | sess | yes; emits `#identity` (`server/handle_identity_submit_plc_operation.go:80-81`) |

Not routed: `resolveDid`, `resolveIdentity`, `refreshIdentity`.

### com.atproto.server.*

| NSID | HTTP | Registration | Auth | Notes |
|---|---|---|---|---|
| `createAccount` | POST | `server/server.go:515` | pub / service-auth | Service-auth JWT required only when an existing `did` is supplied (`server/handle_server_create_account.go:81-95`) |
| `createSession` | POST | `server/server.go:516` | pub | password + optional `authFactorToken` (`server/handle_server_create_session.go:20-24`) |
| `describeServer` | GET | `server/server.go:517` | pub | `availableUserDomains` is always exactly `["."+hostname]`, TODO at `server/handle_server_describe_server.go:27` |
| `reserveSigningKey` | POST | `server/server.go:518` | **pub** | unauthenticated key minting; each call inserts a `reserved_keys` row (`server/handle_server_reserve_signing_key.go:40-64`) |
| `getSession` | GET | `server/server.go:555` | sess | yes |
| `refreshSession` | POST | `server/server.go:556` | refresh JWT | scope check at `server/middleware.go:169-176` |
| `deleteSession` | POST | `server/server.go:557` | sess | yes |
| `confirmEmail` | POST | `server/server.go:563` | sess | yes |
| `requestEmailConfirmation` | POST | `server/server.go:564` | sess | yes |
| `requestPasswordReset` | POST | `server/server.go:565` | **pub** | explicit comment `// AUTH NOT REQUIRED FOR THIS ONE` |
| `requestEmailUpdate` | POST | `server/server.go:566` | sess | yes |
| `resetPassword` | POST | `server/server.go:567` | **sess** | deviation — see §13; handler dereferences `e.Get("repo")` at `server/handle_server_reset_password.go:22` |
| `updateEmail` | POST | `server/server.go:568` | sess | yes |
| `getServiceAuth` | GET | `server/server.go:569` | sess | yes — see §5 |
| `checkAccountStatus` | GET | `server/server.go:570` | sess | partial stub — `Activated`/`ValidDid` hardcoded `true`, `ImportedBlobs` hardcoded `0` (`server/handle_server_check_account_status.go:28-33`) |
| `deactivateAccount` | POST | `server/server.go:571` | sess | sets `deactivated`, emits `#account` (`server/handle_server_deactivate_account.go:33-46`); `deleteAfter` explicitly ignored (`:17-19`) |
| `activateAccount` | POST | `server/server.go:572` | sess | emits `#account` + `#sync` (`server/handle_server_activate_account.go:38-57`) |
| `requestAccountDelete` | POST | `server/server.go:573` | sess | yes |
| `deleteAccount` | POST | `server/server.go:574` | **pub** | body carries did + password + emailed token, all verified (`server/handle_server_delete_account.go:37-70`); deletes blocks/records/blobs/tokens/actor/repo in one tx (`:87-137`) |
| `createInviteCode` | POST | `server/server.go:591` | admin | code is a bare `uuid.NewString()` (`server/handle_server_create_invite_code.go:34`) |
| `createInviteCodes` | POST | `server/server.go:592` | admin | yes |

Not routed: `getAccountInviteCodes`, `createAppPassword`, `listAppPasswords`, `revokeAppPassword`.

### com.atproto.repo.*

| NSID | HTTP | Registration | Auth | Notes |
|---|---|---|---|---|
| `describeRepo` | GET | `server/server.go:520` | pub | resolves the DID doc and cross-checks the handle (`server/handle_repo_describe_repo.go:39-67`); DID-only lookup (`:27`) |
| `listRecords` | GET | `server/server.go:522` | pub | reads the `records` table |
| `getRecord` | GET | `server/server.go:523` | pub | DID-only lookup (`server/handle_repo_get_record.go:38`) |
| `listMissingBlobs` | GET | `server/server.go:577` | sess | walks all records, diffs referenced blob CIDs against `blobs` (`server/handle_repo_list_missing_blobs.go:40-90`) |
| `createRecord` | POST | `server/server.go:578` | sess | → `applyWrites` |
| `putRecord` | POST | `server/server.go:579` | sess | → `applyWrites`; `swapCommit` accepted but unused (`server/repo.go:253` `// TODO make use of swap commit`) |
| `deleteRecord` | POST | `server/server.go:580` | sess | → `applyWrites` |
| `applyWrites` | POST | `server/server.go:581` | sess | the real engine, `server/repo.go:254-574` |
| `uploadBlob` | POST | `server/server.go:582` | sess | **absent from the README checklist** |
| `importRepo` | POST | `server/server.go:583` | sess | see §8 |

### com.atproto.sync.*

| NSID | HTTP | Registration | Auth | Notes |
|---|---|---|---|---|
| `listRepos` | GET | `server/server.go:521` | pub | unpaginated; hardcoded `LIMIT 500`, `Cursor` always `nil` (`server/handle_repo_list_repos.go:22-49`) despite `limit`/`cursor` in the lexicon |
| `getRecord` | GET | `server/server.go:524` | pub | returns a proof CAR: commit block + MST path nodes + record block (`server/repo.go:576-632`) |
| `getBlocks` | GET | `server/server.go:525` | pub | yes |
| `getLatestCommit` | GET | `server/server.go:526` | pub | yes |
| `getRepoStatus` | GET | `server/server.go:527` | pub | works, but carries `// TODO: make this actually do the right thing` (`server/handle_sync_get_repo_status.go:15`) |
| `getRepo` | GET | `server/server.go:528` | pub | dumps **every** block ever stored for the DID (`server/handle_sync_get_repo.go:47`); the lexicon's `since` diff param is ignored |
| `subscribeRepos` | GET (ws) | `server/server.go:529` | pub | see §7 |
| `listBlobs` | GET | `server/server.go:530` | pub | `since` param not implemented (`// TODO: add tid param`, `server/handle_sync_list_blobs.go:25`) |
| `getBlob` | GET | `server/server.go:531` | pub | DB or S3; 302 to CDN when configured (`server/handle_sync_get_blob.go:78-80`) |

Not routed: `requestCrawl` (outbound only — see §13), `notifyOfUpdate`, `getHostStatus`, `listReposByCollection`, `getCheckout`, `getHead`.

### com.atproto.label.* / moderation.* / admin.* / temp.*

| NSID | Registration | Status |
|---|---|---|
| `label.queryLabels` | `server/server.go:534` | **stub** — returns `{"labels":[]}` unless an `atproto-proxy` header or `COCOON_FALLBACK_PROXY` is set, in which case it forwards (`server/handle_label_query_labels.go:24-33`) |
| `label.subscribeLabels` | — | not routed |
| `moderation.createReport` | — | **not routed**; only reachable through the catch-all proxy (`server/server.go:596`) |
| `com.atproto.admin.*` (all 16) | — | **none routed** |
| `com.atproto.temp.*` (all 7) | — | none routed |

### Non-lexicon / app.bsky / infrastructure routes

| Path | Registration | Notes |
|---|---|---|
| `GET /xrpc/_health` | `server/server.go:506` | returns `{"version": "cocoon <ver>"}` (`server/handle_health.go:5-9`) |
| `GET /.well-known/did.json` | `server/server.go:507` | service DID doc (`server/handle_well_known.go:53-67`) |
| `GET /.well-known/atproto-did` | `server/server.go:508` | serves account handles under `*.hostname` (`server/handle_well_known.go:69-100`) |
| `GET /.well-known/oauth-protected-resource` | `server/server.go:509` | `server/handle_well_known.go:102-112` |
| `GET /.well-known/oauth-authorization-server` | `server/server.go:510` | `server/handle_well_known.go:114-145` |
| `GET /`, `GET /robots.txt`, `GET /static/*` | `server/server.go:501,505,511` | ASCII-art landing page (`server/handle_root.go:5-39`) |
| `/account`, `/account/{signin,signout,switch,revoke}` | `server/server.go:537-542` | cookie-session web UI, templates in `server/templates/` |
| `/oauth/{jwks,authorize,par,token,revoke}` | `server/server.go:545-552` | see §5 |
| `app.bsky.actor.getPreferences` / `putPreferences` | `server/server.go:586-587` | stored as a JSON blob on `repos.preferences`; source comment: "This is kinda lame. Not great to implement app.bsky in the pds, but alas" (`server/handle_actor_get_preferences.go:10`) |
| `app.bsky.feed.getFeed` | `server/server.go:588` | proxy shim that re-targets the service-auth `aud`/`lxm` (`server/handle_proxy.go:99-110`) — **absent from the README checklist** |
| `app.bsky.ageassurance.getState` | `server/server.go:589` | **fabricated response** — always `status: "assured", access: "full"` (`server/handle_age_assurance.go:14-23`) — absent from README |
| `GET|POST /xrpc/*` | `server/server.go:595-596` | catch-all proxy, requires auth; mints a per-request ES256K service-auth JWT signed with the *user's* repo key (`server/handle_proxy.go:112-153`) |

### README checklist vs. code

`README.md:215-216` is the project's own disclaimer:

> "Just because something is implemented doesn't mean it is finished. Tons of these are returning bad errors, don't do validation properly, etc. I'll make a "second pass" checklist at some point to do all of that."

and `README.md:235`:

> `- [x] com.atproto.repo.importRepo` (Works "okay". Use with extreme caution.)

Verified discrepancies:

**README overstates:**
1. `README.md:275` marks `com.atproto.sync.requestCrawl` `[x]` under "Sync". No route exists. The only `requestCrawl` in the codebase is an *outbound* client call to the configured relays (`server/server.go:644-671`, invoked at `server/server.go:631-635` on boot and `server/handle_sync_subscribe_repos.go:145` on disconnect). A request to `/xrpc/com.atproto.sync.requestCrawl` falls through to the authenticated catch-all proxy (`server/server.go:596`).
2. `README.md:281` marks `com.atproto.moderation.createReport` `[x]`. No route. The parenthetical ("should be handled by proxying") is accurate about intent, but the checkbox implies a handler that does not exist; without an `atproto-proxy` header or `COCOON_FALLBACK_PROXY` the catch-all errors out (`server/handle_proxy.go:26-29,59-63`).
3. `README.md:280` marks `com.atproto.label.queryLabels` `[x]`. Routed, but the non-proxy path is a hardcoded empty list (`server/handle_label_query_labels.go:30-33`).
4. `README.md:242` marks `com.atproto.server.checkAccountStatus` `[x]`; two of the nine response fields are hardcoded and a third is always zero (`server/handle_server_check_account_status.go:29-33`).
5. `README.md:270` marks `com.atproto.sync.getRepoStatus` `[x]`; the handler is tagged `// TODO: make this actually do the right thing` (`server/handle_sync_get_repo_status.go:15`).

**README understates** (routed and functional, but not listed anywhere in the checklist):
6. `com.atproto.repo.uploadBlob` — `server/server.go:582`. This is a significant omission: it is the only way to get a blob into the PDS.
7. `com.atproto.server.createSession` — `server/server.go:516`.
8. `com.atproto.server.getSession` — `server/server.go:555`.
9. `app.bsky.feed.getFeed` — `server/server.go:588`.
10. `app.bsky.ageassurance.getState` — `server/server.go:589`.
11. The whole OAuth authorization-server surface (`/oauth/par`, `/oauth/token`, `/oauth/authorize`, `/oauth/revoke`, `/oauth/jwks`, both OAuth well-knowns) is absent from the README; only `README.md:253,261` obliquely says app passwords will never be added.

**README is accurate:** `getAccountInviteCodes` unchecked (`README.md:251`); `listAppPasswords`/`revokeAppPassword` struck through (`:253,261`); `notifyOfUpdate` struck through (`:274`).

## 5. Auth posture

**Both** a legacy session-JWT stack and a full OAuth authorization server. No app passwords, by design (`README.md:253`).

*Session JWTs.* `createSession` issues an access + refresh pair persisted in `tokens`/`refresh_tokens` (`models/models.go:86-99`). `handleLegacySessionMiddleware` (`server/middleware.go:38-235`) parses the JWT unverified first (`:59`), branches on `alg`: non-`ES256K` tokens are verified against the server's own ECDSA key (`:100-114`); `ES256K` tokens are verified by reconstructing the public key from the account's stored *private* signing key (`:150-162`). It enforces `scope == "com.atproto.access"` (or `com.atproto.refresh` on the refresh route) at `:169-176`, checks token presence in the DB so signout/rotation actually revoke (`:186-203`), and checks `exp` (`:205-213`). Two-factor via emailed code is supported (`models.TwoFactorType`, `models/models.go:11-16`; `server/two_factor_test.go`).

*Service auth — minting.* `getServiceAuth` (`server/handle_server_get_service_auth.go:27-123`) hand-builds an `ES256K`/`secp256k1` JWT signed with the account's repo key, with `iss`/`aud`/`jti`/`exp`/`iat` and optional `lxm`. It refuses recursive minting (`:46-48`) and caps `exp` at +60s without `lxm`, +1h with (`:50-58`). The catch-all proxy mints the same shape inline (`server/handle_proxy.go:112-153`).

*Service auth — verifying.* Two independent paths:
- `validateServiceAuth` (`server/service_auth.go:42-91`) resolves the issuer's DID doc, extracts the signing key, verifies via a registered `ES256K` JWT method (`server/service_auth.go:15-40`), and enforces `lxm` + `aud` in `validateServiceAuthClaims` (`:96-104`). Used only by `createAccount` (`server/handle_server_create_account.go:85`).
- The session middleware's inline `lxm` branch (`server/middleware.go:71-98`) checks `lxm` against the last path segment and `aud` against the server DID, then looks the issuer up as a **local** repo. Cross-PDS service auth therefore does not work through this path — it needs a local `repos` row for the issuer.

*OAuth authorization server.* Fully present:
- Metadata at `/.well-known/oauth-authorization-server` (`server/handle_well_known.go:114-145`) advertising `require_pushed_authorization_requests: true`, `code_challenge_methods_supported: ["S256"]`, `dpop_signing_alg_values_supported: ["ES256"]`, `token_endpoint_auth_methods_supported: ["none","private_key_jwt"]`, `client_id_metadata_document_supported: true`, and `authorization_response_iss_parameter_supported: true`.
- PAR at `/oauth/par` (`server/server.go:550`, `server/handle_oauth_par.go:21-117`).
- PKCE verified at `server/handle_oauth_token.go:99-112`, implementation `verifyPKCE` at `:273-296` (S256 only).
- DPoP: proof checking in `oauth/dpop/manager.go:68`, validating `jti` replay via an expiring LRU (`oauth/dpop/jti_cache.go:16-28`, checked at `manager.go:164-171`), `htm` (`:173-180`), `htu` (`:182-194`), and `ath` binding when an access token is present (`:209-222`), plus JWK thumbprint → `jkt` (`:224-233`). Server-issued nonces with rotation in `oauth/dpop/nonce.go:33-107`; `use_dpop_nonce` challenges emitted at `server/handle_oauth_par.go:39-49`, `server/handle_oauth_token.go:52-58`, `server/middleware.go:266-272`.
- `private_key_jwt` client assertion handled in `oauth/provider/client_auth.go:58-60`+.
- Access tokens are DPoP-bound: the resource middleware compares the stored `dpop_jkt` against the presented proof (`server/middleware.go:297-300`).
- Scopes: `atproto`, `transition:email`, `transition:generic`, `transition:chat.bsky` (`server/handle_well_known.go:14-20`), with a granular `repo:<nsid>?action=` parser (`oauth/scopes/parser.go`) enforced on writes (`server/scope_enforcement.go:29-56`). Note `server/scope_enforcement.go:30-37`: a session with no `scopes` set at all — i.e. every legacy password session — is treated as unrestricted.

*Admin*: HTTP Basic with a fixed `admin` username against `COCOON_ADMIN_PASSWORD`, non-constant-time string compare (`server/middleware.go:25-27`), guarding only the two invite-code endpoints.

## 6. Sync 1.1 status

Mostly there, with gaps.

- **`#sync` events: emitted.** Builder at `server/repo_sync.go:19-43` (single-block CAR whose header root is the signed commit); emitter `emitRepoSync` at `server/repo_sync.go:48-63`. Call sites: account creation (`server/handle_server_create_account.go:253`), account activation (`server/handle_server_activate_account.go:54`), and the `recommit-repos` maintenance command (`server/recommit.go:128`). **Not** emitted after `importRepo`.
- **`prevData` on commits: emitted.** Read from the previous commit block before the write (`server/repo.go:176-188`, `:266-270`) and attached to the `#commit` event at `server/repo.go:554`. Covered by `TestApplyWritesEmitsPrevData` (`server/firehose_sync_test.go:84-120`).
- **Per-op `prev` on deletes: emitted.** `server/repo.go:479-486` sets `Prev` from the pre-delete record CID for delete ops. Create/update ops set `Cid` only (`:465-470`), which matches the `#repoOp` lexicon (`prev` is optional).
- **Blocks in the commit CAR:** header with the new commit as sole root (`server/repo.go:448-454`); the record block for each create/update (`:472-478`); the *previous* record block for each delete (`:488-494`); then every block written through the recording blockstore during the commit (`:499-503`) — that is the MST write-diff from `r.MST.WriteDiffBlocks` (`server/repo.go:191`) plus the newly signed commit block (`:219-225`). There is no explicit "covering proof" construction step and no test asserting the proof property.
- **No-op updates: NOT rejected.** No comparison of the new record CID against the existing one anywhere in `applyWrites` (`server/repo.go:254-574`); `grep -i "no-op\|noop\|unchanged"` across `server/` returns only unrelated comments. Writing an identical record produces a fresh commit and a fresh `#commit` event.
- `tooBig` is hardcoded `false` (`server/repo.go:557`); there is no large-commit split path. `since` is set from the pre-write rev (`:552`).
- **`getHostStatus`: not implemented** (no route in `server/server.go:496-597`).
- **`listReposByCollection`: not implemented** (no route). The `records` table has an index on `(did, nsid)` (`models/models.go:102-104`) so the query would be cheap, but nothing exposes it.

## 7. Firehose

`com.atproto.sync.subscribeRepos` is implemented at `server/handle_sync_subscribe_repos.go:35-151`.

- **Transport/framing**: `btcsuite/websocket` upgrade (`:41`), binary messages, each frame = indigo `events.EventHeader` CBOR + the event object CBOR, written to the same writer and flushed with `wc.Close()` (`:98-136`). Error frames use `EvtKindErrorFrame` (`:110-113`).
- **Event types**: `#commit`, `#sync`, `#identity`, `#account`, `#info` (`server/handle_sync_subscribe_repos.go:18-33`) — the complete union from `subscribeRepos.json`. `#info` is mapped but nothing in cocoon ever constructs a `RepoInfo`.
- **Seq source**: a single monotonic counter in `DbPersister`, incremented under a mutex and stamped onto the event (`server/persist.go:67-96`). On a cold DB it seeds from `time.Now().Unix()` rather than 0, with an explicit comment that this is "kind of hacky" because relays may already hold a nonzero cursor (`server/persist.go:45-56`). Seq values set at emit sites (e.g. `time.Now().UnixMicro()` in `server/handle_server_activate_account.go:43`) are overwritten by the persister.
- **Cursor resume**: `?cursor=` parsed at `:52-60`, passed as `since` to `evtman.Subscribe` (`:67-69`); replay served by `DbPersister.Playback`, paging 500 rows at a time from `event_records` (`server/persist.go:122-157`).
- **Backfill window**: 72 hours. Retention is passed as `72*time.Hour` at `server/server.go:418`; an hourly goroutine deletes older rows (`server/persist.go:171-181`). Not configurable by env var.
- **Slow consumers**: `Subscribe` is indigo's `events.EventManager`; cocoon supplies a filter that always returns true (`:67-69`) and does not implement any buffering or drop policy of its own. Per-connection metrics only (`metrics/metrics.go:13-23`). UNVERIFIED: indigo's buffering/eviction behaviour for a stalled subscriber (that indigo version is not in the local module cache).
- Reconnect: on stream end the server fires `requestCrawl` at the configured relays, rate-limited to once per minute (`:142-148`, `server/server.go:651-653`).

## 8. Account migration / import-export

| Piece | Status |
|---|---|
| `com.atproto.repo.importRepo` | Routed (`server/server.go:583`). Reads the entire CAR into memory (`server/handle_import_repo.go:25-28`), collects all blocks, **reverses** them (`:55`), `PutMany`s them, opens the repo at `header.Roots[0]` (`:62`), walks the MST to populate `records` (`:72-101`), then **re-signs a brand-new commit with the local signing key** (`:105`). It never verifies the incoming commit signature, never checks that the root's `did` matches the authenticated account, and emits **no** `#commit` and **no** `#sync` afterward. The README's "use with extreme caution" (`README.md:235`) is well earned. |
| `com.atproto.repo.listMissingBlobs` | Routed, real (`server/handle_repo_list_missing_blobs.go:24-102`). Cursor is CID-string ordered rather than repo order. |
| `com.atproto.server.checkAccountStatus` | Routed; partially stubbed (`Activated`/`ValidDid` hardcoded true, `ImportedBlobs` always 0 — `server/handle_server_check_account_status.go:29-33`). |
| `activateAccount` / `deactivateAccount` | Routed, real; both emit `#account`, activate additionally emits `#sync` (`server/handle_server_activate_account.go:38-57`, `server/handle_server_deactivate_account.go:33-46`). `deleteAfter` is parsed and ignored in both (`:17-19`). |
| `requestPlcOperationSignature` / `signPlcOperation` / `submitPlcOperation` | All routed and real. `signPlcOperation` fetches the PLC audit log, patches `verificationMethods`/`rotationKeys`/`alsoKnownAs`/`services` from the request onto the latest op, and signs (`server/handle_identity_sign_plc_operation.go:56-90`). Both reject non-`did:plc:` accounts (`:40-42`, `server/handle_identity_submit_plc_operation.go:37`). |
| `getRecommendedDidCredentials` | Routed, real (`server/handle_identity_get_recommended_did_credentials.go:10-26`). |
| `reserveSigningKey` | Routed, real, **unauthenticated** (`server/server.go:518`); persists to `reserved_keys` and is consumed on `createAccount` with a matching `did` (`server/handle_server_create_account.go:143-161`). |
| Inbound migration (`createAccount` with an existing DID) | Supported: requires a service-auth JWT with `lxm=com.atproto.server.createAccount` issued by the incoming DID (`server/handle_server_create_account.go:81-95`). Note that in this path the genesis-commit / `#identity` / `#sync` block at `:222-256` is skipped entirely — the account has no repo head until `importRepo` runs. |
| Export | `com.atproto.sync.getRepo` returns every stored block, not a `since` diff (`server/handle_sync_get_repo.go:47`). |

The `README.md:3-4` warning is the author's own: *"I migrated and have been running my main account on this PDS for months now without issue, however, I am still not responsible if things go awry, particularly during account migration. Please use caution."*

## 9. did:plc vs did:web

- **Service DID**: whatever `COCOON_DID` is set to; both examples ship `did:web:` (`README.md:33`, `.env.example:1`). `/.well-known/did.json` serves a doc with `id` = that value and a single `#atproto_pds` service entry (`server/handle_well_known.go:53-67`). Nothing validates that the configured DID is resolvable or matches the hostname.
- **Account DIDs**: created as `did:plc:` only. `createAccount` calls `plcClient.CreateDID` + `SendOperation` against `https://plc.directory` (`server/handle_server_create_account.go:171-183`; default service `plc/client.go:36-38`; DID derivation `plc/client.go:176`). There is no code path that creates a `did:web:` account.
- **Resolution**: both methods resolve. `identity.DidToDocUrl` maps `did:plc:` → `plc.directory`, `did:web:` → `https://<host>/.well-known/did.json`, and errors on anything else (`identity/identity.go:92-100`). No `did:webvh`.
- **Imported accounts** may hold a non-PLC DID (`createAccount` accepts any `did` that passes `syntax.ParseDID`), and the PLC-specific endpoints then hard-refuse: `signPlcOperation` (`server/handle_identity_sign_plc_operation.go:40-42`), `submitPlcOperation` (`server/handle_identity_submit_plc_operation.go:37`). `updateHandle` degrades gracefully — it skips the PLC op and updates only the local `actors` row (`server/handle_identity_update_handle.go:43-102`), which for a `did:web:` account leaves the DID doc's `alsoKnownAs` stale with no reconciliation.

## 10. Blobs

- **Upload** (`server/handle_repo_upload_blob.go:34-149`): streams the body in 64 KiB chunks (`:20`, `:65`), writing each as a `blob_parts` row (DB mode) while also accumulating the whole payload in an in-memory `bytes.Buffer` (`:66,81`) so the CID can be computed at the end (`:102`). Consequences: peak memory is the full blob size regardless of storage mode, and **there is no size limit, no mime-type sniffing, and no validation of the declared `content-type`** — the header is echoed straight back as `mimeType` (`:40-43`, `:146`).
- **Storage**: `blob_parts` rows, or S3 at `blobs/{did}/{cid}` (`:127-134`). The `blobs.storage` column records which (`models/models.go:123`).
- **Serving** (`server/handle_sync_get_blob.go:19-80+`): DB parts concatenated into a buffer (with a `// TODO: we can just stream this` at `:66`), or S3 proxied, or a 302 to `COCOON_S3_CDN_URL` (`:78-80`). Deactivated repos are refused with `RepoDeactivated` (`:44-49`).
- **Ref-counting**: yes. `blobs.ref_count` starts at 0 on upload (`server/handle_repo_upload_blob.go:51`), is incremented per referencing record on create/update (`server/repo.go:518-522`, impl `:672-685`), decremented on delete with `RETURNING`, and the blob + parts are hard-deleted when the count reaches 0 (`server/repo.go:687-715`).
- **Known GC holes, from the source's own comments:** S3-backed blobs are never removed when the ref count hits zero — `// TODO: this does _not_ handle deletions of blobs that are on s3 storage!!!!` (`server/repo.go:702-703`). Separately, a blob uploaded but never referenced keeps `ref_count = 0` forever and no sweeper exists — `grep` finds no orphan-blob job. Also `getBlobCidsFromCbor` (`server/repo.go:734-757`) has a `return` inside a `for` loop at `:746-748` that stops after the first map entry when it encounters a blob node.

## 11. Moderation / admin

Effectively absent.

- **Zero `com.atproto.admin.*` routes** and zero `com.atproto.moderation.*` routes (`server/server.go:496-597`). The only admin-authenticated endpoints in the whole server are `createInviteCode` and `createInviteCodes` (`server/server.go:591-592`).
- **No takedown concept.** `grep -rni "takedown|suspended|tombstone"` over the Go sources returns exactly one hit: `DbPersister.TakeDownRepo`, which is an empty stub satisfying indigo's persister interface (`server/persist.go:159-161`). `models.Repo.Status()` can only ever return `nil` or `"deactivated"` (`models/models.go:58-64`), so the `takendown` / `suspended` account states in `com.atproto.sync.defs` are unrepresentable.
- **Labels**: `queryLabels` returns an empty list (§4); there is no label store, no `subscribeLabels`, and no labeler integration.
- Out-of-band operator tools: CLI `create-invite-code` and `reset-password` (`cmd/cocoon/main.go:169-176`), plus a cookie-session web UI at `/account` for end users to view and revoke their own OAuth sessions (`server/server.go:537-542`).

## 12. Rate limiting, metrics, health, ops

- **Rate limiting: none.** `grep -rn "RateLimit|ratelimit|Throttle"` over the Go sources returns no hits. The only registered echo middlewares are `RemoveTrailingSlash`, slog logging, cookie sessions, prometheus, and a wide-open CORS policy — `AllowOrigins: ["*"]`, `AllowHeaders: ["*"]`, `AllowMethods: ["*"]`, `AllowCredentials: true`, `MaxAge: 100_000_000` (`server/server.go:291-301`). The single rate limit anywhere is self-imposed: `requestCrawl` at most once per minute (`server/server.go:651-653`).
- **Metrics**: Prometheus. Echo request metrics via `echoprometheus` (`server/server.go:294`) plus three custom collectors — `cocoon_relays_connected`, `cocoon_relay_sends`, `cocoon_repo_operations` (`metrics/metrics.go:12-30`). Exposed on a separate listener configured by `telemetry.CLIFlagMetricsListenAddress` (`cmd/cocoon/main.go:166-167`, started at `:200`).
- **Health**: `GET /xrpc/_health` → `{"version": ...}` (`server/handle_health.go:5-9`). No readiness probe, no DB-liveness check.
- **Logging**: structured `log/slog` throughout, level from `COCOON_LOG_LEVEL` (`cmd/cocoon/main.go:190-195`), request logs via `samber/slog-echo`.
- **Backups**: hourly SQLite `VACUUM INTO` → S3 when `COCOON_S3_BACKUPS_ENABLED` (`server/server.go:673-691`, `:736-741`); explicitly disabled for Postgres (`:676-679`, `README.md:127`).
- **Shutdown**: `Serve` blocks on `ctx.Done()` and returns after printing to stdout (`server/server.go:637-641`); the HTTP server is never gracefully drained and `s.httpd.ListenAndServe()` failures `panic` (`server/server.go:623-627`).
- **Maintenance tooling**: `recommit-repos` re-signs repos whose stored `rev` is not a valid TID and re-announces them with `#sync` + `#identity` + `#account` (`server/recommit.go:95-151`), with a dry-run mode (`:111-114`).

## 13. Notable spec deviations and explicitly-unsupported features

The project's own candid framing, `README.md:6`:

> "Cocoon is a PDS implementation in Go. It is highly experimental, and is not ready for any production use."

and `README.md:215-216` (quoted in full in §4) on the endpoint checklist being aspirational.

Verified deviations, code-first:

1. **`resetPassword` requires an authenticated session.** Registered with both session middlewares (`server/server.go:567`) and the handler unconditionally dereferences `e.Get("repo")` (`server/handle_server_reset_password.go:22`). A user who has forgotten their password — the entire point of the endpoint — cannot call it. `requestPasswordReset` is correctly public (`server/server.go:565`). Operators fall back to the CLI `reset-password` (`README.md:201-204`).
2. **No app passwords, ever.** `README.md:253` — "not going to add app passwords" — and `:261` likewise for `revokeAppPassword`. Code agrees: no routes, no `app_passwords` table.
3. **`at-identifier` params are DID-only.** The lexicons give `repo` as `at-identifier` (handle *or* DID) for `getRecord`, `describeRepo`, `listRecords`, `putRecord`, `applyWrites`. Cocoon queries by DID: `handle_repo_get_record.go:38` (`WHERE did = ?`), `handle_repo_describe_repo.go:27` (`getRepoActorByDid`), `common.go:55-63`; `putRecord` even validates the field as `atproto-did` (`server/handle_repo_put_record.go:12`). Passing a handle fails.
4. **No lexicon/record validation.** `applyWrites` writes whatever DAG-CBOR it is handed and always reports `validationStatus: "valid"` — `// TODO: obviously this might not be true atm lol` (`server/repo.go:352`, `:421`). The `validate` input flag is carried into the `Op` struct (`server/repo.go:112`) and never read.
5. **`swapCommit` and `swapRecord` are not enforced.** `// TODO make use of swap commit` (`server/repo.go:253`); `swapCommit` is threaded to `applyWrites` and dropped; `SwapRecord` is only used to decide create-vs-update (`server/handle_repo_put_record.go:44-46`).
6. **`createRecord` with an existing rkey silently becomes an update** rather than erroring (`server/repo.go:284-290`).
7. **`app.bsky.ageassurance.getState` returns a fabricated "assured/full" for every account** (`server/handle_age_assurance.go:14-23`).
8. **`sync.getRepo` ignores `since`** and returns the whole block history (`server/handle_sync_get_repo.go:47`); **`sync.listRepos` ignores `limit`/`cursor`** (`server/handle_repo_list_repos.go:27,48`); **`sync.listBlobs` ignores `since`** (`server/handle_sync_list_blobs.go:25`).
9. **No `#commit` or `#sync` after `importRepo`** (§8) — a migrated repo's new head is never announced to relays.
10. **No no-op-update suppression** (§6).
11. **`getHostStatus`, `listReposByCollection`, `admin.*`, `moderation.*`, `temp.*`, `label.subscribeLabels` are all unimplemented** (§4).
12. **Legacy sessions bypass OAuth scope enforcement entirely** (`server/scope_enforcement.go:30-37`).
13. `COCOON_BLOCKSTORE_VARIANT` accepts one value and panics on anything else (`server/blockstore_variant.go:19`).

## 14. Maturity tier

**serious.**

It implements 37 `com.atproto.*` XRPC methods across five families with a working MST/commit pipeline, a complete OAuth 2.1 authorization server (PAR + PKCE + DPoP with nonce, `ath`, and `jti` replay protection, `private_key_jwt`, both well-knowns), a persisted resumable firehose emitting all four event types including Sync 1.1 `#sync` and `prevData`, service-auth minting *and* verification, migration in and out, Prometheus metrics, ~2.2k lines of tests, CI with `-race`, published multi-arch images, and Postgres/S3 scale-out paths — far past what one person's toy needs. It is not `reference` because moderation, admin, rate limiting, record validation, `swapCommit`/`swapRecord`, takedown state, `getHostStatus`, and `listReposByCollection` are all simply absent, several handlers return hardcoded values, and the author's own README opens with "highly experimental, and is not ready for any production use" (`README.md:6`).

---

## Confidence & unknowns

- **Verified by reading source**: every route registration and its middleware chain (`server/server.go:496-597`); every handler cited above was opened; the commit/firehose path (`server/repo.go`, `server/persist.go`, `server/repo_sync.go`, `server/handle_sync_subscribe_repos.go`) was read end to end; the schema (`models/models.go`, `server/server.go:606-619`); DPoP claim checks (`oauth/dpop/manager.go`, by grep with line numbers plus the surrounding `CheckProof` signature); build/deploy files. All lexicon assertions (method existence, parameter names, `#commit`/`#sync` field sets, `at-identifier` formats) come from opening the JSON under `/tmp/gap-scratch/atproto/lexicons/com/atproto/`.
- **UNVERIFIED — slow-consumer / backpressure behaviour of the firehose.** Cocoon delegates fan-out to indigo's `events.EventManager` (`server/server.go:449`) and adds no policy of its own. The exact indigo pseudo-version in `go.mod:10` (`v0.0.0-20260308004230-c55a189a51a9`) is not in the local module cache, so buffer sizes and eviction were not read. Would need that module source.
- **UNVERIFIED — whether the `#commit` CAR always constitutes a spec-complete Sync 1.1 covering proof.** I documented exactly which blocks are written (`server/repo.go:448-503`); whether the MST write-diff is sufficient for exclusion proofs in every tree shape was not proven, and no test asserts it. Would need to run a relay-side verifier against generated commits.
- **UNVERIFIED — runtime behaviour.** Nothing was executed: no build, no test run, no live request. All "does real work" judgements are from reading handler bodies.
- **UNVERIFIED — `oauth/provider/provider.go` and `oauth/client/manager.go` internals.** I read the metadata document, PAR entry, PKCE verification, DPoP checks, and `client_auth.go:27-60`; client-metadata fetching/caching and the authorization-code lifecycle were only spot-checked by function signature.
- **UNVERIFIED — DPoP `htu`/`ath`/`jti` checks were confirmed by grep with line numbers** rather than reading `oauth/dpop/manager.go:68-238` in full; the claim names and comparisons are quoted from those lines, but surrounding control flow (e.g. whether any branch can skip them) was not traced.
- Whether the deployed `COCOON_DID` is ever cross-checked against `.well-known/did.json` or the hostname: no such check was found, but I did not exhaustively read `server/server.go:120-290` (config construction).
