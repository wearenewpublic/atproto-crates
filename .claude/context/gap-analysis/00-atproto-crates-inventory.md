# Phase 0 — atproto-crates source-derived inventory (PDS + permissioned data)

| | |
|---|---|
| Workspace version | `0.15.0-rc.1` (`Cargo.toml:38-55`; `crates/atproto-pds/Cargo.toml:3`, `crates/atproto-space/Cargo.toml:3`) |
| Git HEAD | `18b826f` — *fix(security): bound validation recursion and wire-length allocation, harden SSRF and OAuth subject binding (#77)* |
| Branch | `claude/atproto-crates-rc-gap-analysis-c6604d` |
| Date | 2026-07-28 |
| Repo root | `/Users/nick/development/github.com/ngerakines/atproto-crates-studious-guide/.claude/worktrees/goofy-bell-de1699` |
| Canonical lexicons compared against | `/tmp/gap-scratch/atproto/lexicons/com/atproto/**` |
| Reference implementation compared against | `/tmp/gap-scratch/atproto/packages/**` (bluesky-social/atproto) |

This is the factual baseline for the release-candidate gap analysis. Everything here was read in source; nothing is recalled. All repo-relative paths are under the repo root above. Where an underlying research pass could not establish a claim, it is carried forward verbatim into [§8 Confidence & unknowns](#8-confidence--unknowns) rather than smoothed over.

Downstream documents that build on this baseline:

- [`./20-coverage-matrix.md`](./20-coverage-matrix.md) — endpoint-by-endpoint conformance scoring
- [`./capability-areas/`](./capability-areas/) — per-area deep dives
- [`./permissioned/40-permissioned-overview.md`](./permissioned/40-permissioned-overview.md) — the 0016 spaces track
- [`./50-synthesis-and-roadmap.md`](./50-synthesis-and-roadmap.md) — ranked remediation plan
- [`./README.md`](./README.md) — index

---

## 1. Workspace map

`Cargo.toml:2-22` declares **19 workspace members** (plus one excluded member, `crates/atproto-dasl/fuzz`, at `Cargo.toml:23-25`). Every member is pinned to `0.15.0-rc.1` through `[workspace.dependencies]` (`Cargo.toml:38-55`). The workspace is Rust edition 2024, `rust-version = "1.90"`, `resolver = "3"`, and `unsafe_code = "forbid"` (`Cargo.toml:29-30`, `:26`, `:126-127`).

The membership list is worth stating plainly because two of the project's own documents get it wrong: the root `README.md:9` says "This workspace contains 17 crates" and enumerates 17, and `CLAUDE.md:67-81` enumerates 12. Neither mentions `atproto-pds` or `atproto-space` at all (see [§7.4](#74-documentation-state)).

| Member (`Cargo.toml` line) | Role (from each crate's own `description`) |
|---|---|
| `crates/atpmcp` (`:3`) | MCP server exposing DAG-CBOR CID generation |
| `crates/atproto-client` (`:4`) | HTTP client for AT Protocol services with OAuth and identity integration |
| `crates/atproto-dasl` (`:5`) | DASL — CIDs, DRISL (DAG-CBOR), CAR v1, block storage, varint |
| `crates/atproto-extras` (`:6`) | Facet parsing and rich-text utilities |
| `crates/atproto-identity` (`:7`) | DID resolution, handle resolution, cryptographic key operations |
| `crates/atproto-jetstream` (`:8`) | Jetstream event consumer — WebSocket streaming with compression |
| `crates/atproto-oauth-aip` (`:9`) | AIP OAuth tools |
| `crates/atproto-oauth-axum` (`:10`) | Axum integration for AT Protocol OAuth workflows |
| `crates/atproto-oauth` (`:11`) | OAuth workflow implementation — PKCE, DPoP, JWT, scopes, storage |
| **`crates/atproto-pds` (`:12`)** | **AT Protocol Personal Data Server — server library and `pds` binary** |
| `crates/atproto-record` (`:13`) | Record signature operations, TID generation, AT-URI parsing, CID generation |
| `crates/atproto-repo` (`:14`) | Repository handling — CAR v1 serialization and Merkle Search Tree operations |
| **`crates/atproto-space` (`:15`)** | **Permissioned-data spaces — primitives for the 0016 Permissioned Data draft (LtHash, signed commits, delegation-token / space-credential JWTs)** |
| `crates/atproto-tap` (`:16`) | TAP (Trusted Attestation Protocol) service consumer |
| `crates/atproto-xrpcs-helloworld` (`:17`) | Complete example XRPC service with did:web + JWT auth |
| `crates/atproto-xrpcs` (`:18`) | Building blocks for XRPC services with JWT authorization |
| `crates/atproto-lexicon` (`:19`) | Lexicon resolution and validation |
| `crates/atproto-attestation` (`:20`) | Attestation utilities for creating and verifying record signatures |
| `crates/atpxrpc` (`:21`) | XRPC client with persistent session management |

---

## 2. Which crates implement the PDS, and which implement permissioned data

The PDS is **one crate**: `crates/atproto-pds`. It is both a library (`#![warn(missing_docs)]` enforced at `crates/atproto-pds/src/lib.rs:32`) and the `pds` binary (`crates/atproto-pds/src/bin/pds.rs`, 1136 lines), plus a small operator CLI (`crates/atproto-pds/src/bin/atproto-pds-admin.rs`, 276 lines). Every HTTP route in the server is registered in a single flat axum `Router` built by `build_router` at `crates/atproto-pds/src/http/router.rs:27-433`; there is no route-mounting anywhere else in the tree.

Permissioned data is **split across two crates**. `crates/atproto-space` (3363 LOC) holds the protocol primitives — the `ats://` URI grammar, the LtHash set commitment, the signed-commit construction, and the two JWT credential types. `crates/atproto-pds/src/space/**` (5145 LOC) plus `crates/atproto-pds/src/http/space_handlers.rs` (2984 LOC) and `crates/atproto-pds/src/http/space_auth.rs` (536 LOC) hold the server-side implementation: storage, HTTP handlers, mint authorization, notification fan-out. Storage backends live at `crates/atproto-pds/src/actor_store/{sql,fjall}/space_*.rs` with schema in `crates/atproto-pds/migrations/actor/*.sql`.

The alignment target for the spaces work is stated in the code, not inferred: `crates/atproto-space/src/lib.rs:30` names the **0016 Permissioned Data draft**, and `crates/atproto-space/README.md:6-8` calls it "the authoritative alignment target for this crate". `CHANGELOG.md:84` records the decision as "taking the spec as the source of truth over the reference implementation". This matters for everything downstream: spaces divergences must be scored against 0016, not against bluesky-social/atproto.

### 2.1 Discovery evidence

| Claim | Evidence |
|---|---|
| `atproto-pds` is the only crate serving XRPC for the PDS | All 104 `.route(...)` registrations are in `crates/atproto-pds/src/http/router.rs`; the only `.layer(...)` in the file is the optional metrics middleware at `router.rs:441-448` |
| The `pds` binary *is* the space host | `deploy/docker-compose.yml:14-15`, `:39-40`, `:64-65` — `pds1`, `pds2`, and `space-host` all run the same `atproto-pds` image. There is no separate space-host binary |
| Spaces do not reach the public firehose | Grep for `outbox\|OutboxReader\|EventType\|publish_sync\|subscribeRepos\|firehose` across `crates/atproto-pds/src/space/**` and `space_handlers.rs` returns exactly one hit — a doc comment at `space/notify.rs:3` |
| Spaces do not use the MST or CAR path | `repo/writer.rs:29` imports the sequencer; the space writer imports nothing of the kind. Permissioned state lives in dedicated tables (§6.4) |
| `atproto-oauth-aip` / `atproto-oauth-axum` are not involved | `crates/atproto-pds/Cargo.toml` `[dependencies]` lists `atproto-oauth.workspace = true` and neither of the other two — no feature, no dev-dependency. Zero references to `atproto_oauth_aip::*` or `atproto_oauth_axum::*` anywhere in `crates/atproto-pds/src/` |
| `atproto-pds` does not depend on `atproto-attestation` | `grep atproto[-_]attestation crates/atproto-pds/` → no matches |
| Spaces NSIDs are unratified, but the draft lexicons exist and were compared | On `main`, `ls /tmp/gap-scratch/atproto/lexicons/com/atproto/` returns `admin identity label lexicon moderation repo server sync temp` — no `space/`, no `simplespace/`. The draft lexicons live on the `permissioned-data` branch (HEAD `3f6c96d`, 2026-07-02) and were fetched to `/tmp/gap-scratch/lex-0016/`: 19 `space/` + 8 `simplespace/` files. Conformance was computed against those — see §3.10 and [`./permissioned/40-permissioned-overview.md`](./permissioned/40-permissioned-overview.md) |
| No lexicon JSON for spaces exists in this repo either | `find . -name '*.json' \| grep -i space` matches only `deploy/well-known/space-host/.well-known/did.json`. In-repo wire shapes are Rust DTOs only; the oracle is the fetched draft, not anything vendored here |

### 2.2 Crate-level supporting roles

`atproto-repo` supplies the commit object and MST (`crates/atproto-repo/src/repo/commit.rs`, `crates/atproto-repo/src/mst/`). `atproto-dasl` supplies DAG-CBOR serialization, CID computation, and the CAR reader/writer. `atproto-identity` supplies signing, validation, and DID-document resolution. `atproto-oauth` contributes exactly three things to the PDS — the scope grammar (`atproto_oauth::scopes`, used at `http/auth.rs:96-99`, `oauth/consent.rs:23,443-464`, and ~25 sites in `http/space_handlers.rs`), the DPoP proof validator (`atproto_oauth::dpop::{DpopValidationConfig, validate_dpop_jwt}`, `oauth/dpop.rs:24`), and one JWK type (`atproto_oauth::jwk::WrappedJsonWebKeySet`, `space/mint_authz.rs:27`). Everything else in `crates/atproto-oauth/src/` — `jwt.rs`, `pkce.rs`, `workflow.rs`, `storage.rs`, `storage_lru.rs`, `resources.rs`, `encoding.rs` — is unused by the PDS.

---

## 3. XRPC endpoint inventory

`build_router` (`crates/atproto-pds/src/http/router.rs:27-433`) registers **103 distinct route paths across 104 `.route(...)` calls** — `/oauth/authorize` is registered twice, once for GET and once for POST. `/metrics` is added separately by the feature-gated `with_metrics` (`router.rs:441-448`), so the base router is 102 paths. Of the 91 paths under `/xrpc/`, **89 are distinct `com.atproto.*` NSIDs**, one is the convention endpoint `/xrpc/_health` (which is not a lexicon — no JSON exists for it under `/tmp/gap-scratch/atproto/lexicons/com/atproto/`), and one is the `/xrpc/app.bsky.{*nsid}` wildcard proxy registered for GET/POST/PUT/DELETE (`router.rs:109`).

**There are zero stubs in the literal sense.** `grep -rn 'todo!()\|unimplemented!()\|NotImplemented' crates/atproto-pds/src/` returns nothing. Every registered route reaches storage, a real cryptographic operation, or a real network call. What exists instead of stubs is a different failure mode, and the analysis downstream should not conflate the two: **two handlers are PARTIAL** (`com.atproto.identity.refreshIdentity` is a no-op for non-PLC DIDs, `identity_handlers.rs:621-627`; `com.atproto.admin.deleteAccount` sets state without erasing data, `admin/handlers.rs:266-269`), **two return 503 when unconfigured** (`com.atproto.moderation.createReport` at `moderation_handlers.rs:61-74`, the `app.bsky.*` proxy at `proxy_handlers.rs:145-149`), and **one is semantically inverted** (`com.atproto.sync.requestCrawl`, §3.4). The real gaps are shape divergences against the canonical lexicons, not missing implementations.

The 89 NSIDs break down by namespace as follows.

| Namespace | Routed NSIDs | Canonical lexicons exist? |
|---|---:|---|
| `com.atproto.server.*` | 25 | yes (2 of the 25 are misnamespaced admin methods; 1 has no lexicon at all) |
| `com.atproto.space.*` | 17 | not on `main`; **draft lexicons exist** on the `permissioned-data` branch and were used as the oracle (§3.10) |
| `com.atproto.admin.*` | 15 | yes (3 of the 15 are project-defined with no canonical counterpart) |
| `com.atproto.repo.*` | 10 | yes |
| `com.atproto.sync.*` | 8 | yes |
| `com.atproto.identity.*` | 7 | yes |
| `com.atproto.simplespace.*` | 6 | not on `main`; **draft lexicons exist** on the `permissioned-data` branch and were used as the oracle (§3.10) |
| `com.atproto.moderation.*` | 1 | yes |

### 3.1 Auth guard vocabulary

Every guard is called **inline inside its handler**. There is no auth middleware layer (`http/router.rs:27-433`).

| Guard | Definition | Accepts |
|---|---|---|
| `require_authn` | `http/auth.rs:154` | app-password session JWT (`typ=at-pp-access`, `session::verify_access`, line 163) **OR** OAuth access JWT (`typ=at-oauth-access`, line 169); enforces RFC 9449 DPoP when `cnf.jkt` present (line 179-181) |
| `require_authn_sub` | `http/auth.rs:189` | same as above, returns only the subject DID |
| `require_access_jwt` | `http/auth_handlers.rs:1754` | **app-password session access JWT ONLY** — calls `session::verify_access` (line 1759) and never tries OAuth. OAuth bearers are rejected |
| `session::verify_refresh` | used at `http/auth_handlers.rs:411`, `:469` | refresh-flavored session JWT |
| `require_admin` | `admin/handlers.rs:37` | HTTP Basic auth, password compared to `state.admin_password` / `DEFAULT_ADMIN_PASSWORD` (line 80-86). Non-constant-time `!=` compare |
| `require_session` (writes) | `http/write_handlers.rs:71` | thin wrapper over `require_authn` (line 73) |
| `require_session_auth` / `require_session_subject` (spaces) | `http/space_handlers.rs:133` / `:124` | wrappers over `require_authn` / `require_authn_sub` |
| `require_any_authn` | `http/space_handlers.rs:1766` | verified SpaceCredential JWT (`classify` → `verify_space_credential_for`, lines 1772-1783) **OR** session/OAuth via `require_authn` (line 1786) |
| `require_space_credential` | `http/space_handlers.rs:1793` | verified SpaceCredential **only**; session/OAuth rejected 401 (line 1799-1805) |
| `resolve_record_auth` | `http/space_handlers.rs:1080` | dispatches on token `typ`: SpaceCredential (needs `repo` param), DelegationToken (rejected, line 1101), else session/OAuth via `require_authn` (line 1111) |
| space service auth | `crate::space::service_auth::verify_service_auth`, called at `http/space_handlers.rs:2096` and `:2570` | DID-document-resolved JWT with `iss`/`aud`/`lxm` binding |
| delegation-token grant | `http/space_handlers.rs:1492-1527` | `DelegationToken` JWT in `Authorization: Bearer`, single-use via `jti_guard` (line 1532) |
| *(none)* | — | public / token-in-body / unauthenticated |

### 3.2 Health, proxy, and non-lexicon routes

| Route | Method | Route file:line | Handler file:line | Auth guard | Real/stub |
|---|---|---|---|---|---|
| `/_alive` | GET | `http/router.rs:29` | `http/handlers.rs:23` | none | REAL (returns 200 unconditionally) |
| `/_ready` | GET | `http/router.rs:30` | `http/handlers.rs:28` | none | REAL — acquires accounts pool + `conn.ping()` (`:37`), 503 `NotReady` on failure |
| `/xrpc/_health` | GET | `http/router.rs:31` | `http/handlers.rs:47` | none | REAL — emits `{version, status, setHash}`. Not a canonical NSID. `setHash` is a non-standard extension documented at `http/handlers.rs:43-44` |
| `/xrpc/app.bsky.{*nsid}` | GET/POST/PUT/DELETE | `http/router.rs:109` | `http/proxy_handlers.rs:120` → `proxy_call` `:132` | `require_authn_sub` at `proxy_handlers.rs:165` | REAL for the operator-configured AppView; **502 `ProxyDidUnknown`** for any other `Atproto-Proxy` DID (`:97-101`); **503 `ProxyUnavailable`** when no AppView configured (`:145-149`). Arbitrary DID-doc service resolution is NOT implemented |
| `/admin`, `/admin/` | GET | `http/router.rs:430,431` | `admin/dashboard.rs:87` (re-exported `admin/mod.rs:11`) | `require_admin` at `dashboard.rs:91` | REAL (HTML dashboard) |
| `/metrics` | GET | `http/router.rs:445` (feature `metrics`) | `crate::metrics::metrics_handler` | **none** | REAL (feature-gated) |

### 3.3 `com.atproto.repo.*`

| NSID | Method | Route | Handler | Auth guard | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|---|
| `getRecord` | GET | `router.rs:34` | `handlers.rs:69` | none (public — matches lexicon "Does not require auth") | REAL | none for params. Output `uri`/`cid`/`value` all emitted (`repo/reader.rs:434-441`) |
| `listRecords` | GET | `router.rs:38` | `handlers.rs:107` | none | REAL (limit clamped 1..=100 at `repo/reader.rs:210`) | `cursor` serialized without `skip_serializing_if` (`repo/reader.rs:458`) so an exhausted page emits `"cursor": null`; lexicon types `cursor` as `string` |
| `describeRepo` | GET | `router.rs:42` | `handlers.rs:132` | none | REAL | **Lexicon requires `didDoc`** (`repo/describeRepo.json` required = handle, did, didDoc, collections, handleIsCorrect). `DescribeRepoResponse` (`repo/reader.rs:465-484`) has no `didDoc`; emits non-lexicon `head_cid`/`head_rev`/`head_data` instead |
| `createRecord` | POST | `router.rs:47` | `write_handlers.rs:144` | `require_session` `:149`; `assert_subject` `:152` | REAL | Declares `swapCommit` (`:88-89`) but **never reads it** — CAS guard not enforced (`WriteOp` at `:158-164` sets `swap_record: None`). `validate` not modelled |
| `putRecord` | POST | `router.rs:51` | `write_handlers.rs:197` | `require_session` `:202`, `assert_subject` `:205` | REAL (honors `swapRecord` at `:215`) | `swapCommit` and `validate` ignored (absent from `PutRecordInput` `:182-194`) |
| `deleteRecord` | POST | `router.rs:55` | `write_handlers.rs:247` | `require_session` `:252`, `assert_subject` `:255` | REAL (honors `swapRecord` `:265`) | `swapCommit` ignored |
| `applyWrites` | POST | `router.rs:59` | `write_handlers.rs:335` | `require_session` `:340`, `assert_subject` `:343` | REAL | (a) `validate` + `swapCommit` ignored (`ApplyWritesInput` `:284-289`). (b) Output `results` items are `WriteRecordResponse` (`:326-332`) with no `$type` discriminator — they do not match the lexicon union `#createResult`/`#updateResult`/`#deleteResult`; each result nests a redundant `commit`. (c) Delete results carry a `uri`, which `#deleteResult` does not define |
| `listMissingBlobs` | GET | `router.rs:63` | `write_handlers.rs:450` | `require_session` `:455` | REAL (SQL walk / trait dispatch) | none material; `limit` default 500 matches lexicon, no clamp applied (`:456`). **Always returns `{"blobs": []}` in practice** — see §4.6 |
| `uploadBlob` | POST | `router.rs:67` | `write_handlers.rs:516` | `require_session` `:521` | REAL | **Output shape is wrong.** Lexicon `blob` is a lex-`blob` (`{"$type":"blob","ref":{"$link":…},"mimeType":…,"size":…}`). `crate::blob::BlobRef` (`blob.rs:39-49`) serializes as `{"$link":…,"mimeType":…,"size":…}` — no `$type`, no `ref` wrapper |
| `importRepo` | POST | `router.rs:71` | `write_handlers.rs:595` | `require_session` `:600` **plus** `claims.privileged()` `:601-607` | REAL (CARv1 inductive import) | Lexicon defines **no output**; handler returns `{headCid, headRev, blocksIngested, commitsIndexed}` (`:574-588`). Non-fatal but non-conformant |

### 3.4 `com.atproto.sync.*`

| NSID | Method | Route | Handler | Auth guard | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|---|
| `getLatestCommit` | GET | `router.rs:76` | `handlers.rs:148` | none | REAL | none (`cid`,`rev` emitted `:154`) |
| `getRepoStatus` | GET | `router.rs:80` | `handlers.rs:164` | none | REAL | none (`did`,`active` required and present, `repo/reader.rs:497-508`) |
| `getRepo` | GET | `router.rs:83` | `handlers.rs:186` | none | REAL — full CAR or `since=` diff slice (`:215-226`) | none |
| `getBlocks` | GET | `router.rs:85` | `handlers.rs:245` | none | REAL | Lexicon `cids` is `array of cid` (repeated query params). Handler declares `cids: String` and splits on `,` (`:241`, `:254-259`) — the canonical `?cids=a&cids=b` wire form is not parsed |
| `getBlob` | GET | `router.rs:89` | `blob_handlers.rs:33` | none (documented public at `:3-6`) | REAL | none. No account-state/takedown gate applied, unlike `repo/reader.rs:510` `require_public_read` on repo reads |
| `listBlobs` | GET | `router.rs:93` | `blob_handlers.rs:96` | none | REAL | **Lexicon param `since` (tid) is not modelled** — `ListBlobsQuery` (`:76-83`) has only `did`/`cursor`/`limit`; incremental blob sync is impossible |
| `subscribeRepos` | GET (WS) | `router.rs:97` | `subscribe_handlers.rs:56` | **none** (no auth call in the handler or `run_subscriber` `:81`) | REAL — durable outbox + broadcast bus, CBOR header‖body framing (`sequencer/frame.rs`) | Lexicon params: only `cursor`. Handler adds non-lexicon `did` and `encoding` (`:44-53`); the `did` filter is documented as a PDS-local helper (`:47-48`). Body shape does not match any lexicon def — see §4.5 |
| `requestCrawl` | POST | `router.rs:103` | `handlers.rs:317` | **none** | REAL but **semantically inverted** | Lexicon: "Request a service to persistently crawl hosted repos" — the receiver should register the caller's hostname. This handler instead **fans out** to `state.crawlers`, POSTing `requestCrawl` to each configured crawler (`:340-362`), and always returns 200. Lexicon `hostname` is **required**; handler makes body and field both optional (`body: Option<Json<…>>` `:319`, `hostname: Option<String>` `:309`) |

### 3.5 `com.atproto.server.*`

| NSID | Method | Route | Handler | Auth guard | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|---|
| `createAccount` | POST | `router.rs:117` | `auth_handlers.rs:81` | none (public) | REAL — denylist, invite peek/redeem, PLC genesis, implicit `__primary__` app password | Lexicon requires only `handle`; handler makes `password` **non-optional** (`:40`) so a lexicon-valid password-less signup fails deserialization. Ignores lexicon fields `verificationCode`, `verificationPhone`, `recoveryKey`, `plcOp` (absent from `CreateAccountInput` `:28-41`). Output omits optional `didDoc` |
| `createSession` | POST | `router.rs:121` | `auth_handlers.rs:295` | none (public) | REAL | Ignores lexicon inputs `authFactorToken`, `allowTakendown` (`CreateSessionInput` `:287-292`). Output omits optional `didDoc`/`email`/`emailConfirmed`/`active`/`status` (`SessionResponse` `:45-56`) |
| `getSession` | GET | `router.rs:125` | `auth_handlers.rs:377` | `require_access_jwt` `:381` — **session JWT only, OAuth rejected** | REAL | Required `handle`+`did` present. Optional `active`/`status`/`emailConfirmed`/`didDoc` not emitted (`:366-374`) |
| `refreshSession` | POST | `router.rs:129` | `auth_handlers.rs:406` | refresh JWT `session::verify_refresh` `:411` + JTI replay guard `:419-428` | REAL | Output omits optional fields as above |
| `deleteSession` | POST | `router.rs:133` | `auth_handlers.rs:464` | refresh JWT `:469` | REAL (JTI blacklisted `:477`) | none |
| `createAppPassword` | POST | `router.rs:137` | `auth_handlers.rs:509` | `require_access_jwt` `:514` | REAL | none |
| `listAppPasswords` | GET | `router.rs:141` | `auth_handlers.rs:552` | `require_access_jwt` `:556` | REAL | none (`#appPassword` requires name+createdAt; both emitted `:534-542`) |
| `revokeAppPassword` | POST | `router.rs:145` | `auth_handlers.rs:583` | `require_access_jwt` `:588` | REAL | none |
| `createInviteCode` | POST | `router.rs:149` | `auth_handlers.rs:629` | `require_access_jwt` `:634` | REAL (+ `can_issue_invites` gate `:639-664`) | none |
| `getServiceAuth` | GET | `router.rs:153` | `service_auth_handlers.rs:93` | `require_authn` `:102` | REAL — signs with the caller's atproto key | `exp` semantics diverge — see §5.4 |
| `activateAccount` | POST | `router.rs:157` | `auth_handlers.rs:677` | `require_access_jwt` `:681` | REAL | none |
| `deactivateAccount` | POST | `router.rs:161` | `auth_handlers.rs:697` | `require_access_jwt` `:702` | REAL (persists `deleteAfter` `:708-721`) | none |
| `checkAccountStatus` | GET | `router.rs:165` | `auth_handlers.rs:740` | `require_access_jwt` `:744` | REAL — real counts from `repo_block`/`repo_record`/`repo_blob_ref`/`repo_blob` (`:782-798`) | Lexicon marks `repoCommit` and `repoRev` **required**; the struct skips them when `None` (`:841-845`), so an empty repo returns a body missing two required fields. `validDid` is **hardcoded `true`** (`:820`) — no DID-document check performed |
| `reserveSigningKey` | POST | `router.rs:169` | `auth_handlers.rs:891` | **NONE** — signature is `(State, Json<Input>)`, no `Parts`, no guard call (`:891-894`) | REAL (generates + persists a P-256 key) | Unauthenticated key-minting: any caller can force key generation and a `signing_key` reservation row for an arbitrary `did` (`:916-924`). Lexicon input/output shapes match |
| `requestEmailUpdate` | POST | `router.rs:173` | `auth_handlers.rs:964` | `require_access_jwt` `:969` | REAL (token + email dispatch) | Lexicon defines **no input**; handler requires `{email}` (`:932-935`). Output `tokenRequired` matches |
| `confirmEmailUpdate` | POST | `router.rs:177` | `auth_handlers.rs:1032` | **none** — token in body is the auth (`:1026-1027`) | REAL | **No such lexicon exists.** `/tmp/gap-scratch/atproto/lexicons/com/atproto/server/` has no `confirmEmailUpdate.json`; the canonical completion method is `com.atproto.server.updateEmail` (`server/updateEmail.json`), which is **not routed** |
| `requestAccountDelete` | POST | `router.rs:181` | `auth_handlers.rs:1101` | `require_access_jwt` `:1105` | REAL | none (lexicon has no input/output) |
| `deleteAccount` | POST | `router.rs:185` | `auth_handlers.rs:1173` | **none** — token in body is the auth (`:1168-1169`) | REAL | **Lexicon requires `did`, `password`, `token`.** `DeleteAccountInput` (`:1162-1166`) has only `token`; `did` and `password` are neither read nor verified |
| `getAccountInviteCodes` | GET | `router.rs:189` | `auth_handlers.rs:1570` | `require_access_jwt` `:1574` | REAL | Lexicon params `includeUsed`, `createAvailable` not modelled. Output items must be `com.atproto.server.defs#inviteCode` (required `code`, `available`, `disabled`, `forAccount`, `createdBy`, `createdAt`, `uses`); handler emits `{code, disabled, availableUses, usedBy, createdAt}` (`:1542-1556`) — missing `available`, `forAccount`, `createdBy`, `uses` |
| `requestEmailConfirmation` | POST | `router.rs:224` | `auth_handlers.rs:1237` | `require_access_jwt` `:1241` | REAL | none |
| `confirmEmail` | POST | `router.rs:228` | `auth_handlers.rs:1317` | **none** — token in body (`:1311-1312`) | REAL | **Lexicon requires `email` AND `token`.** `ConfirmEmailInput` (`:1306-1309`) has only `token`; the required `email` is neither read nor cross-checked |
| `requestPasswordReset` | POST | `router.rs:233` | `auth_handlers.rs:1390` | **none** (by design — locked-out user, `:1386-1389`) | REAL (always 200, rate-limited `:1402-1405`) | none |
| `resetPassword` | POST | `router.rs:237` | `auth_handlers.rs:1477` | **none** — token in body | REAL (updates both `account.password_hash` and `__primary__`) | none |
| `disableAccountInvites` | POST | `router.rs:413` | `admin/handlers.rs:877` | `require_admin` `:882` | REAL | **Wrong namespace.** Canonical NSID is `com.atproto.admin.disableAccountInvites`; nothing named `com.atproto.server.disableAccountInvites` exists. Lexicon requires `account`, handler reads `did` (`admin/handlers.rs:866-871`); `note` ignored |
| `enableAccountInvites` | POST | `router.rs:417` | `admin/handlers.rs:889` | `require_admin` `:894` | REAL | Same two divergences vs `admin/enableAccountInvites.json` |

### 3.6 `com.atproto.identity.*`

| NSID | Method | Route | Handler | Auth guard | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|---|
| `signPlcOperation` | POST | `router.rs:193` | `auth_handlers.rs:1613` | `require_access_jwt` `:1619` | REAL (signs with `account.rotation_key_ref`) | **Input shape is entirely different.** Lexicon properties: `token`, `rotationKeys`, `alsoKnownAs`, `verificationMethods`, `services`. Handler requires a single `op` field holding a complete unsigned PLC operation (`SignPlcOperationInput` `:1594-1597`, deserialized as `UnsignedOperation` `:1650`). None of the five lexicon fields is read; the emailed-`token` gate is absent. Output `{operation}` matches |
| `submitPlcOperation` | POST | `router.rs:197` | `auth_handlers.rs:1685` | `require_access_jwt` `:1690` | REAL | none (`operation` required and read `:1676-1679`) |
| `resolveHandle` | GET | `router.rs:201` | `identity_handlers.rs:60` | none (public) | REAL — local directory, then DNS+HTTP dual resolution when `dns_resolver` is wired, else HTTP-only (`:85-105`) | none |
| `updateHandle` | POST | `router.rs:205` | `identity_handlers.rs:136` | `require_authn_sub` `:142` | REAL — full PLC audit-log → `new_update` → sign → submit → local update (`do_update_handle` `:155-280`) | none |
| `requestPlcOperationSignature` | POST | `router.rs:209` | `identity_handlers.rs:299` | `require_authn_sub` `:304` | REAL — mints a 60 s `lxm`-locked service-auth JWT | Lexicon defines **no output**; handler returns `{token}` (`:288-291`). Semantics differ: the canonical flow emails a confirmation token, this returns a signed JWT directly to the caller |
| `getRecommendedDidCredentials` | GET | `router.rs:214` | `identity_handlers.rs:410` | `require_authn_sub` `:417` | REAL — builds from local key store, no PLC round-trip | none |
| `refreshIdentity` | POST | `router.rs:219` | `identity_handlers.rs:572` | `require_authn_sub` `:580` (any authenticated caller may refresh **any** DID — documented at `:568-571`) | **PARTIAL** — `did:plc:` re-queries PLC and reconciles `account.handle` (`:604-660`); **non-PLC DIDs are a no-op** re-fetch (`:621-627`), only the `#identity` outbox event is emitted | **Lexicon requires input field `identifier`.** `RefreshIdentityInput` (`:530-534`) declares `did`; a canonical `{"identifier": "..."}` request fails deserialization. Lexicon output is an empty object; handler returns `{did, handle, handleUpdated, identityEventEmitted}` |

### 3.7 `com.atproto.moderation.*`

| NSID | Method | Route | Handler | Auth guard | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|---|
| `createReport` | POST | `router.rs:242` | `moderation_handlers.rs:44` | `require_authn_sub` `:52` | REAL when configured; **503 `ModerationServiceUnavailable`** when `PDS_REPORT_SERVICE_DID`/`_URL` unset (`:61-74`). Forwards the body verbatim upstream with a minted service-auth bearer (`:96-110`) and echoes the upstream status+body (`:126-135`) | The handler never parses the body, so lexicon-required `reasonType` and `subject` are **not validated**. Output is whatever upstream returns; the PDS does not guarantee the required `id`/`reportedBy`/`createdAt` output fields |

### 3.8 `com.atproto.admin.*`

All gated by `require_admin` (HTTP Basic, `admin/handlers.rs:37`).

| NSID | Method | Route | Handler | Real/stub | Lexicon divergences |
|---|---|---|---|---|---|
| `getAccountInfo` | GET | `router.rs:359` | `admin/handlers.rs:125` (guard `:130`) | REAL | Output must be `com.atproto.admin.defs#accountView` (required `did`, `handle`, **`indexedAt`**). `AccountInfoResponse` (`:105-122`) emits `createdAt` instead; `indexedAt` absent. Handler also accepts a handle (`:132-136`) — benign superset |
| `getAccountInfos` | GET | `router.rs:363` | `admin/handlers.rs:443` (`:448`) | REAL (sequential lookups `:474-485`) | Lexicon `dids` is an **array** (repeated query params, max 100). Handler declares `dids: String` split on `,` (`:421-425`, `:449-454`). Same `indexedAt` gap. Missing DIDs silently dropped (`:475`) |
| `getSubjectStatus` | GET | `router.rs:367` | `admin/handlers.rs:221` (`:226`) | REAL but wrong shape | **Major shape divergence.** Lexicon params all optional (`did`, `uri`, `blob`); handler makes `did` **required** (`:204-209`) and ignores `uri`/`blob` (no record- or blob-level status). Lexicon output requires `subject` (a `$type`-tagged union of `#repoRef` / `strongRef` / `#repoBlobRef`) plus optional `takedown`/`deactivated` `#statusAttr`; handler returns `{did, state}` (`:212-218`) |
| `updateSubjectStatus` | POST | `router.rs:371` | `admin/handlers.rs:174` (`:179`) | REAL (writes `account.state`) | **Major shape divergence.** Lexicon input requires `subject` (union) with optional `takedown`/`deactivated`; handler reads `{did, state}` (`:156-162`) where `state` is a PDS-internal `AccountState` string. Record- and blob-level takedowns not addressable. Output likewise `{did, state}` |
| `deleteAccount` | POST | `router.rs:375` | `admin/handlers.rs:253` (`:258`) | **PARTIAL** — sets state to `Deleted` (`:266-269`); no data erasure in the handler | Input `did` matches lexicon |
| `searchAccounts` | GET | `router.rs:379` | `admin/handlers.rs:310` (`:315`) | REAL | Lexicon params are `email`, `cursor`, `limit`. Handler **requires** an undeclared `q` (`:275-283`) and never reads `email`. Output items missing `indexedAt` |
| `getInviteCodes` | GET | `router.rs:383` | `admin/handlers.rs:377` (`:382`) | REAL (returns **all** codes when `createdBy` omitted, `:374-376`) | Lexicon params are `sort`, `limit`, `cursor` — none read. Handler takes an undeclared `createdBy` (`:337-343`); result unpaginated. Output emits `availableUses`/`usedBy` instead of `available`/`uses`, omits `forAccount` (`:346-364`), no `cursor` |
| `sendEmail` | POST | `router.rs:387` | `admin/handlers.rs:520` (`:525`) | REAL via `EmailService`; with SMTP disabled the stub logs and still returns `sent:true` (documented `:509-513`) | **Lexicon-required `senderDid` not modelled** (`SendEmailInput` `:494-504`); lexicon-optional `comment` ignored. Conversely `subject` is optional in the lexicon but **required** by the handler. Output `{sent}` matches |
| `updateAccountEmail` | POST | `router.rs:390` | `admin/handlers.rs:575` (`:580`) | REAL | **Lexicon requires `account`; handler reads `did`** (`:558-565`). A canonical request fails deserialization. `email_confirmed_at` deliberately untouched (`:569-574`) |
| `updateAccountHandle` | POST | `router.rs:394` | `admin/handlers.rs:628` (`:633`) | REAL (reuses `do_update_handle` `:634`) | none |
| `updateAccountPassword` | POST | `router.rs:398` | `admin/handlers.rs:660` (`:665`) | REAL (updates both `account.password_hash` and `__primary__` `:692-710`) | none |
| `takedownSpaceRecord` | POST | `router.rs:403` | `admin/handlers.rs:745` (`:750`) | REAL (INSERT/DELETE in `space_record_takedown` `:768-817`) | **No canonical lexicon** — project-defined NSID |
| `revokeServiceAuth` | POST | `router.rs:408` | `admin/handlers.rs:842` (`:847`) | REAL (`service_auth_blacklist::add` `:855`) — but see §5.6-C: **functionally a no-op** | **No canonical lexicon** — project-defined NSID |
| `disableInviteCodes` | POST | `router.rs:421` | `admin/handlers.rs:1037` (`:1042`) | REAL (per-code `invite::disable` `:1064-1068`) | Lexicon has no required fields and accepts `codes` **and** `accounts`; handler requires a non-empty `codes` (`:1050-1056`) and ignores `accounts` — per-account bulk disable unimplemented |
| `forceRepoSync` | POST | `router.rs:426` | `admin/handlers.rs:965` (`:970`) | REAL (emits a `#sync` outbox event `:1002-1016`) | **No canonical lexicon** — project-defined NSID |

### 3.9 OAuth routes (RFC-shaped, no lexicons)

| Route | Method | Route | Handler | Auth guard | Real/stub |
|---|---|---|---|---|---|
| `/oauth/par` | POST | `router.rs:246` | `oauth/par.rs:132` | none (client identified in the request; JWS request-object verified at `:143` when `request` present) | REAL |
| `/oauth/authorize` | GET | `router.rs:247` | `oauth/consent.rs:43` | none — `peek_par` only (`:45-58`) | REAL (HTML consent page) |
| `/oauth/authorize` | POST | `router.rs:248` | `oauth/authorize.rs:47` | user credentials in body — `app_password::verify` at `:105` | REAL |
| `/oauth/token` | POST | `router.rs:249` | `oauth/token.rs:100` | grant-based (`authorization_code` / `refresh_token`, `:115-117`); rate-limited per `client_id` `:104-109` | REAL |
| `/oauth/revoke` | POST | `router.rs:250` | `oauth/revoke.rs:39` | none (RFC 7009 — always 200, `:53-55`) | REAL |
| `/oauth/jwks` | GET | `router.rs:251` | `oauth/jwks.rs:42` | none | REAL |
| `/.well-known/oauth-authorization-server` | GET | `router.rs:253` | `oauth/metadata.rs:52` | none | REAL |
| `/.well-known/oauth-protected-resource` | GET | `router.rs:257` | `oauth/metadata.rs:85` | none | REAL |

### 3.10 `com.atproto.simplespace.*` and `com.atproto.space.*`

**Lexicon divergence for both namespaces IS verified — see [../permissioned/40-permissioned-overview.md](./permissioned/40-permissioned-overview.md).** No `space/` or `simplespace/` directory exists on the `main` branch of `bluesky-social/atproto`, which is what a naive `ls` of `/tmp/gap-scratch/atproto/lexicons/com/atproto/` shows. The draft lexicons do exist, on that repository's `permissioned-data` branch at HEAD `3f6c96d` (2026-07-02, *"bring impl up to date with lexicons & proposal"*), and were fetched for this analysis to `/tmp/gap-scratch/lex-0016/` — 19 files under `space/` and 8 under `simplespace/`. The reference TypeScript implementation lives on the same branch (`packages/space/src/*.ts`, `packages/syntax/src/space-uri.ts`).

The NSID-by-NSID conformance check against those lexicons is performed in [the permissioned-data overview](./permissioned/40-permissioned-overview.md) and [the HappyView comparison](./permissioned/42-happyview.md). Headline results, not re-derived here:

- **MISSING as server:** `com.atproto.space.getLatestCommit`, `com.atproto.space.getRepo`, `com.atproto.simplespace.checkUserAccess`.
- **DIVERGENT:** `com.atproto.space.getRepoState` is a local invention with no draft counterpart; the commit `ctx` omits the author DID; `signedCommit` lacks the required `ver`; the URI scheme is `ats://` rather than the draft's `at://{did}/space/{type}/{skey}`; the config field is `mintPolicy` where the draft says `policy`; and `notifyWrite` omits the required `hash`.
- **CORRECT:** the LtHash construction matches the reference byte for byte including element encoding, and the deniable-commit construction is not merely implemented but wired into the production write path (§6.4).

Semantics are covered in [§6](#6-permissioned-data--spaces).

| NSID | Method | Route | Handler | Auth guard | Real/stub |
|---|---|---|---|---|---|
| `simplespace.createSpace` | POST | `router.rs:262` | `space_handlers.rs:177` | `require_session_auth` `:182` + `assert_space_manage(Create)` `:209` | REAL |
| `simplespace.updateSpace` | POST | `router.rs:266` | `space_handlers.rs:243` | `require_session_auth` `:248` + `assert_space_manage(Update)` `:251` | REAL |
| `simplespace.deleteSpace` | POST | `router.rs:270` | `space_handlers.rs:284` | `require_session_auth` `:289` + `assert_space_manage(Delete)` `:292` | REAL (+ best-effort `notifySpaceDeleted` fan-out `:305`) |
| `simplespace.addMember` | POST | `router.rs:274` | `space_handlers.rs:490` | `require_session_auth` `:495` + `assert_space_manage(Update)` `:498` | REAL |
| `simplespace.removeMember` | POST | `router.rs:278` | `space_handlers.rs:511` | `require_session_auth` `:516` + `assert_space_manage(Update)` `:519` | REAL |
| `simplespace.listMembers` | GET | `router.rs:282` | `space_handlers.rs:566` | `require_session_auth` `:571` + `assert_space_scope(Read)` `:574` | REAL |
| `space.getSpace` | GET | `router.rs:287` | `space_handlers.rs:415` | `require_any_authn` `:421` + `assert_space_read_opt` `:422` | REAL |
| `space.listSpaces` | GET | `router.rs:291` | `space_handlers.rs:461` | `require_session_subject` `:466` — **no `space:` scope gate applied** | REAL |
| `space.applyWrites` | POST | `router.rs:295` | `space_handlers.rs:631` | `require_session_auth` `:636` + per-op `assert_space_scope` `:674` | REAL |
| `space.createRecord` | POST | `router.rs:299` | `space_handlers.rs:729` | `require_session_auth` `:734`, `require_repo_matches_subject` `:736`, `assert_space_scope(Create)` `:738` | REAL |
| `space.putRecord` | POST | `router.rs:303` | `space_handlers.rs:779` | `:784`, `:786`, `assert_space_scope(Create)` `:791` **and** `(Update)` `:799` | REAL |
| `space.deleteRecord` | POST | `router.rs:307` | `space_handlers.rs:829` | `:834`, `:836`, `assert_space_scope(Delete)` `:838` | REAL |
| `space.getRecord` | GET | `router.rs:311` | `space_handlers.rs:920` | `resolve_record_auth` `:926` + `assert_space_record_read` `:928` | REAL |
| `space.listRecords` | GET | `router.rs:315` | `space_handlers.rs:1011` | `resolve_record_auth` `:1017` + `assert_space_record_read` `:1023` | REAL (keys-only output) |
| `space.getBlob` | GET | `router.rs:319` | `space_handlers.rs:2204` | `resolve_record_auth` `:2216` + `assert_space_scope(Read)` `:2218` + `verify_read_auth` `:2228` | REAL (nosniff/attachment/CSP headers `:2262-2274`) |
| `space.listRepos` | GET | `router.rs:323` | `space_handlers.rs:2328` | `require_space_credential` `:2336` — **credential only**, session/OAuth rejected 401 | REAL |
| `space.getRepoState` | GET | `router.rs:327` | `space_handlers.rs:1245` | `require_any_authn` `:1251` + `assert_space_read_opt` `:1252` | REAL |
| `space.listRepoOps` | GET | `router.rs:331` | `space_handlers.rs:1322` | `require_any_authn` `:1328` + `assert_space_read_opt` `:1329` | REAL |
| `space.getDelegationToken` | GET | `router.rs:335` | `space_handlers.rs:1419` | `require_authn` `:1425` **plus** an OAuth-only check — `client_id().is_none()` → 403 (`:1432-1438`) — + `assert_space_scope(Read)` `:1442` | REAL |
| `space.getSpaceCredential` | POST | `router.rs:339` | `space_handlers.rs:1484` | delegation-token bearer `:1492`, verified locally `:1504` or cross-PDS `:1517`, single-use `jti` `:1532`; then mint-time USER (`mintPolicy`) + APP (`appAccess`) axes `:1595-1640` | REAL |
| `space.registerNotify` | POST | `router.rs:344` | `space_handlers.rs:2434` | space-credential only — `classify` `:2445`, `verify_space_credential` `:2481` | REAL (24 h TTL `:2426`) |
| `space.notifyWrite` | POST | `router.rs:349` | `space_handlers.rs:2069` | service auth `verify_service_auth` `:2096` + `iss == payload.repo` `:2107` + membership check `:2128` | REAL (owner fan-out `:2140` + receipt `:2168`) |
| `space.notifySpaceDeleted` | POST | `router.rs:354` | `space_handlers.rs:2545` | service auth `:2570` with peeked `aud` `:2563` + `iss == space.space_did` `:2579` | REAL — tombstones (`deleted_at`) rather than purging, documented `:2536-2544` |

### 3.11 Canonical `com.atproto.*` lexicon methods NOT routed

Computed by intersecting every `query`/`procedure`/`subscription` `main` def in the six in-scope directories against the `/xrpc/com.atproto.*` literals in `http/router.rs`.

| NSID | Type | Lexicon file |
|---|---|---|
| `com.atproto.server.createInviteCodes` | procedure | `/tmp/gap-scratch/atproto/lexicons/com/atproto/server/createInviteCodes.json` |
| `com.atproto.server.describeServer` | query | `…/server/describeServer.json` |
| `com.atproto.server.updateEmail` | procedure | `…/server/updateEmail.json` |
| `com.atproto.sync.getCheckout` | query | `…/sync/getCheckout.json` |
| `com.atproto.sync.getHead` | query | `…/sync/getHead.json` |
| `com.atproto.sync.getHostStatus` | query | `…/sync/getHostStatus.json` |
| `com.atproto.sync.getRecord` | query | `…/sync/getRecord.json` |
| `com.atproto.sync.listHosts` | query | `…/sync/listHosts.json` |
| `com.atproto.sync.listRepos` | query | `…/sync/listRepos.json` |
| `com.atproto.sync.listReposByCollection` | query | `…/sync/listReposByCollection.json` |
| `com.atproto.sync.notifyOfUpdate` | procedure | `…/sync/notifyOfUpdate.json` |
| `com.atproto.identity.resolveDid` | query | `…/identity/resolveDid.json` |
| `com.atproto.identity.resolveIdentity` | query | `…/identity/resolveIdentity.json` |
| `com.atproto.admin.disableAccountInvites` | procedure | `…/admin/disableAccountInvites.json` |
| `com.atproto.admin.enableAccountInvites` | procedure | `…/admin/enableAccountInvites.json` |
| `com.atproto.admin.updateAccountSigningKey` | procedure | `…/admin/updateAccountSigningKey.json` |

Notes on that list:

- **`com.atproto.server.describeServer` is the most consequential miss.** It is the first call every atproto client (including `bsky.app` and `goat`) makes against a PDS, to learn `did`, `availableUserDomains`, and `inviteCodeRequired`. Its absence means a 404 on the very first request of a normal login/signup flow. The data it needs already sits in `HttpState` — `service_did`, `service_handle_domains` used at `http/auth_handlers.rs:93-110`, `invite_required` at `:157`.
- **`com.atproto.sync.listRepos`** is required by relays to enumerate hosted accounts. `list_account_dids` (`http/subscribe_handlers.rs:212-215`) already implements the query; it is just not exposed.
- **`com.atproto.admin.disableAccountInvites` / `enableAccountInvites`** have working handlers (`admin/handlers.rs:877`, `:889`) mounted at the wrong NSID (§3.5). Routing them under `com.atproto.admin.*` and renaming `did`→`account` closes both gaps.
- `com.atproto.sync.getHead` and `getCheckout` are deprecated upstream; `getHostStatus`/`listHosts` are relay-side methods a PDS is not expected to serve.
- `com.atproto.identity.resolveDid` / `resolveIdentity` are newer additions; the routed `resolveHandle` covers the older half of the surface.
- Directories out of scope for the not-routed sweep: `com/atproto/label/*`, `com/atproto/lexicon/*`, `com/atproto/temp/*`. None are routed. `com.atproto.temp.checkHandleAvailability` and `checkSignupQueue` are part of the reference signup flow; whether any client hard-requires them is **UNVERIFIED**.

### 3.12 Notable endpoint divergences, stated plainly

**A. `require_access_jwt` rejects OAuth tokens on 14 endpoints.** `http/auth_handlers.rs:1754-1759` calls only `session::verify_access`. Every handler using it — `getSession`, `createAppPassword`, `listAppPasswords`, `revokeAppPassword`, `createInviteCode`, `activateAccount`, `deactivateAccount`, `checkAccountStatus`, `requestEmailUpdate`, `requestAccountDelete`, `requestEmailConfirmation`, `getAccountInviteCodes`, `signPlcOperation`, `submitPlcOperation` — returns 401 for a valid OAuth access token, even though `http/auth.rs:154` exists precisely to accept both. The repo-write path (`http/write_handlers.rs:71`), the identity path, the spaces path, and `getServiceAuth` all use the unified guard. This is an inconsistency confined to one file, not a design decision documented anywhere in `auth.rs`.

**B. `reserveSigningKey` has no authentication.** `http/auth_handlers.rs:891` takes `(State, Json<Input>)`. There is no `Parts` extractor and no guard invocation. Every other `com.atproto.server.*` mutation is guarded. The handler generates a P-256 key, persists it to the key store (`:911-915`), and writes a `signing_key` reservation row keyed on a caller-supplied `did` (`:916-924`).

**C. Three account-lifecycle endpoints drop lexicon-required credential fields.** `com.atproto.server.deleteAccount` (`:1162-1166`) models only `token` where the lexicon requires `did`, `password`, `token` — account deletion is single-factor on a 43-char emailed token, with no password re-confirmation. `com.atproto.server.confirmEmail` (`:1306-1309`) models only `token` where the lexicon requires `email` + `token`, so the confirmed address is never cross-checked. `com.atproto.server.confirmEmailUpdate` is not a real NSID, and the canonical `com.atproto.server.updateEmail` is not routed at all.

**D. `com.atproto.identity.signPlcOperation` is a different protocol.** The lexicon (`identity/signPlcOperation.json`) accepts `{token?, rotationKeys?, alsoKnownAs?, verificationMethods?, services?}` — the PDS composes the operation from those parts and gates on an emailed `token`. This implementation instead demands the client hand over a fully-formed `UnsignedOperation` in an `op` field (`auth_handlers.rs:1594-1597`, `:1650`) and gates only on the session JWT. Any canonical client (goat, the TS `@atproto/api` migration flow) fails here.

**E. `com.atproto.identity.refreshIdentity` field name.** Lexicon input is `{identifier}` (required). Handler declares `{did}` (`identity_handlers.rs:530-534`). Canonical requests fail deserialization with a 422/400.

**F. `com.atproto.sync.requestCrawl` semantics are reversed.** The lexicon's `requestCrawl` is an **inbound** request: a peer asks this service to crawl the named hostname. `http/handlers.rs:317-365` instead uses the route as an **outbound** announcer, POSTing to every entry in `state.crawlers` and returning 200 unconditionally (`:333`, `:365`). A relay calling this endpoint gets a 200 and is never registered.

**G. Array-typed query params are parsed as comma-separated strings.** `com.atproto.sync.getBlocks` `cids` (`http/handlers.rs:241`, `:254`) and `com.atproto.admin.getAccountInfos` `dids` (`admin/handlers.rs:424`, `:449`) are lexicon arrays, which the XRPC HTTP binding encodes as repeated query params. Both handlers split a single string on `,`. `?cids=a&cids=b` will not work; `?cids=a,b` will.

**H. `uploadBlob` output is not a lex-blob.** `crate::blob::BlobRef` (`blob.rs:39-49`) serializes `{"$link", "mimeType", "size"}`. The lexicon output type is `blob`, whose JSON form is `{"$type":"blob","ref":{"$link":…},"mimeType":…,"size":…}`. A client that round-trips the returned object into a record value produces a record the PDS's own blob-ref tracking may not recognize as a blob.

**I. `com.atproto.admin.{get,update}SubjectStatus` model only accounts.** Both handlers speak `{did, state}` (`admin/handlers.rs:156-162`, `:212-218`) instead of the lexicon's `subject` union (`#repoRef` / `com.atproto.repo.strongRef` / `#repoBlobRef`) plus `#statusAttr`. Record-level and blob-level takedown — the primary reason ozone calls these — is unreachable through the canonical shape. The PDS does implement record takedown, but only for Spaces, under the project-defined `com.atproto.admin.takedownSpaceRecord`.

**J. Admin field-name mismatches.** `admin.updateAccountEmail` reads `did` where the lexicon requires `account` (`admin/handlers.rs:558-565`). `admin.searchAccounts` requires an undeclared `q` and ignores the declared `email` (`:275-283`). `admin.getInviteCodes` reads an undeclared `createdBy` and ignores `sort`/`limit`/`cursor` (`:337-343`). `admin.sendEmail` omits the required `senderDid` (`:494-504`).

**K. `accountView.indexedAt` is missing everywhere.** `getAccountInfo`, `getAccountInfos`, and `searchAccounts` all return `createdAt` where `com.atproto.admin.defs#accountView` requires `indexedAt` (`admin/handlers.rs:105-122`, `:286-297`).

**L. `checkAccountStatus.validDid` is hardcoded.** `auth_handlers.rs:820` sets `valid_did: true` unconditionally, with the comment "`true` iff the DID resolves to this PDS" (`:838`). No resolution is performed, so a migrated-away account still reports `validDid: true`. `repoCommit`/`repoRev` are lexicon-required but carry `skip_serializing_if = "Option::is_none"` (`:841-845`).

**M. Invite toggles are namespaced under `com.atproto.server.*`.** `http/router.rs:413,417` register `com.atproto.server.disableAccountInvites` / `enableAccountInvites`. The canonical NSIDs are `com.atproto.admin.disableAccountInvites` / `enableAccountInvites`. Neither canonical path is routed, so ozone/admin tooling gets a 404.

**N. `subscribeRepos` is unauthenticated and per-account-fanned.** `http/subscribe_handlers.rs:56` and `run_subscriber` `:81` contain no auth call — matching the public-firehose model. But `list_account_dids` caps at 1000 accounts (`:214`) and the loop re-opens one outbox per DID per poll cycle (`:117`), so this is a per-account fan-in rather than a single global sequence; the lexicon's `seq` is per-DID here, not server-global.

**O. `swapCommit` is never enforced.** `createRecord` declares `swapCommit` (`write_handlers.rs:88-89`) and never reads it; `putRecord`, `deleteRecord`, and `applyWrites` do not model it at all. The lexicon's `InvalidSwap` error can therefore never be raised for commit-level CAS. `swapRecord` **is** honored on `putRecord` (`:215`) and `deleteRecord` (`:265`) but not inside `applyWrites` (`:366`, `:377`, `:384` all set `swap_record: None`).

**P. `describeRepo` omits required `didDoc`.** `repo/reader.rs:465-484` has no `didDoc` field. Clients that resolve a PDS via `describeRepo` — including the `bsky.app` login path — get a response missing a lexicon-required key.

**Q. Account-level takedown is enforced on 2 of roughly 9 public read paths — PARTIAL, not missing.** The predicate is real and correct: `AccountState::allows_public_read()` is `matches!(self, AccountState::Active | AccountState::Deactivated)` (`crates/atproto-pds/src/account/state.rs:56-58`), so `Takendown` / `Suspended` / `Deleted` do block public reads wherever the guard is actually invoked. The guard is `require_public_read`, defined at `crates/atproto-pds/src/repo/reader.rs:510-518`, and it is invoked at **exactly two** call sites: `get_record` (guard at `repo/reader.rs:107`, fn at `:99`) and `list_records` (guard at `:209`, fn at `:200`). There is a passing test — `get_record_takendown_account_denied` (`repo/reader.rs:695-704`) asserts `PdsError::AuthDenied`.

The guard is **not** invoked by `describe_repo` (`repo/reader.rs:335`), `get_latest_commit` (`:382`), or `get_repo_status` (`:400`). The entire sync and blob surface contains zero account-state references: `repo/car_export.rs` (`getRepo`), `blob.rs` (`getBlob`), `http/handlers.rs` (`getBlocks`), and `http/blob_handlers.rs` (`listBlobs`) each return no hits for `allows_public_read|require_public_read|AccountState`. The consequence is that a takedown removes record-level reads while leaving bulk export open: a taken-down account's **complete repository** remains downloadable via `com.atproto.sync.getRepo`, its raw blocks via `getBlocks`, and its media via `getBlob`.

Two doc-vs-code mismatches sit alongside this. `crates/atproto-pds/src/account/state.rs:18-19` documents `Deactivated` as "repo not accessible to public sync", but `allows_public_read()` returns **true** for `Deactivated` (`:56-58`), so deactivated accounts remain publicly readable even on the two gated paths. And the `Takendown` doc comment at `state.rs:20-22` claims takedown "blocks reads and writes" while enforcement is partial as described above. Separately, record-level and blob-level takedown do not exist at all in the public realm — only account-level state — which is the same gap [I] describes from the lexicon side. (Space records are the exception: they have a real per-record takedown table, §6.7.)

---

## 4. Storage layers

The PDS has two storage tiers with different lifecycles. Per-actor repo data (commits, blocks, records, blob bytes, the outbox, and *all* Spaces tables) lives in one store **per DID**. Global data (accounts, app passwords, invites, email tokens, signing-key references, OAuth state, replay guards, rate-limit windows) lives in one shared accounts database. Signing keys themselves are neither — they are files on disk (`FileKeyStore::new(<data_dir>/keys)`, `bin/pds.rs:422-423`), with `account.signing_key_ref` holding e.g. `file:...`.

The per-actor tier has two implementations, and **the choice is compile-time, not runtime**. `crates/atproto-pds/src/actor_store/mod.rs:31-53` defines `StorageProfile { Sqlite, Fjall }`; `compiled()` (`:41-53`) resolves purely from `#[cfg(feature = "fjall")]`. `PDS_STORAGE_PROFILE` is only a **validator** — `resolve()` (`actor_store/mod.rs:89-106`) errors with `StorageProfileMismatch` if the env value disagrees with the compiled feature, and `"postgres"` is explicitly not a valid value (`actor_store/mod.rs:376`). Startup wiring is `crates/atproto-pds/src/bin/pds.rs:367-411`.

Three of the seven backends that exist in source are **never constructed by the binary**. Postgres and S3 are implemented, schema'd, tested, and documented, but `bin/pds.rs` declares `postgres_url` at `:328-329` and `blob_store_url` at `:321-322` and references neither anywhere else. That is not a soft gap: `RepoWriter` reads the signing key with raw SQLite-flavored SQL against `self.accounts.pool()` (`repo/writer.rs:361-369`, `:674-682`), and `AccountManager::pool()` is `as_sqlite()`, which **panics** on a Postgres pool (`account/pool.rs:98-101`). Even if `PDS_POSTGRES_URL` were wired, every write would panic.

### 4.1 Backends and selection

| Backend | Scope | Selected by | Wired at runtime? |
|---|---|---|---|
| **SQLite per-actor** (`actor_store/sql/`) | per-DID file `<data_dir>/actors/<sha256(did)>.sqlite` (`actor_store/sql/store.rs:21-32`) | default (no `fjall` feature) | yes — `bin/pds.rs:381-383` |
| **fjall** (`actor_store/fjall/`) | ONE LSM database at `<data_dir>/fjall`, all actors in shared keyspaces keyed `<did>\0<...>` (`actor_store/fjall/keyspace.rs:74-106, 291-297`) | `--features fjall` + `PDS_STORAGE_PROFILE=fjall` | yes — `bin/pds.rs:385-401` |
| **SQLite accounts DB** (global) | one file `<data_dir>/accounts.sqlite` (`bin/pds.rs:415-420`) | always | yes |
| **PostgreSQL accounts DB** (global) | `account/postgres.rs:45-69`, `account/directory.rs:126-131` | `--features postgres` + `PDS_POSTGRES_URL` | **NO — not wired.** `AccountDirectory::open_postgres` is called only from `crates/atproto-pds/tests/feature_postgres_live.rs:74` |
| **S3 blob bytes** (`blob_s3.rs::HybridS3BlobStorage`) | bytes → `s3://<bucket>/<prefix>/<did>/<cid>`; refs stay relational (`blob_s3.rs:97-103, 169-175`) | `--features s3` + `PDS_BLOB_STORE_URL` | **NO — not wired.** Referenced only from `crates/atproto-pds/tests/feature_s3.rs` |
| **In-memory** | `SqlActorStore::open_memory` (`actor_store/sql/store.rs:102-124`), `AccountDirectory::open_memory`, `OAuthState::Memory` (`oauth/state.rs:93,114`) | tests only | OAuth uses SQL in prod (`bin/pds.rs:599`) |
| **Valkey/Redis** | `valkey_backend.rs` — JTI replay + rate limits only | `--features valkey` + `PDS_VALKEY_URL` (`bin/pds.rs:309`) | yes (conditional) |

Table placement: per-actor holds `commit_obj`, `repo_block`, `repo_record`, `repo_blob`, `repo_blob_ref`, `outbox`, and **all** Spaces tables. Global (`accounts.sqlite`) holds `account`, `app_password`, `invite_code`, `email_token`, `signing_key`, `service_auth_blacklist`, `notify_attempt`, `denylist`, `oauth_par`, `oauth_code`, `oauth_refresh`, `jti_replay`, `rate_limit_window`.

### 4.2 Dispatch layer and its three structural gaps

`PublicRealmBackend` (`actor_store/mod.rs:147-171`) bundles five `Arc<dyn …>` trait objects — `commit_obj`, `repo_record`, `outbox`, `blob`, `atomic` — plus a `BackendKind` used to build an owned per-actor `ActorBlockStorage` (`actor_store/mod.rs:336-358`), because the MST needs `&mut BlockStorage`.

**SQL dispatch opens a new pool per operation.** `actor_store/sql/public_realm.rs:29-31` is:

```rust
async fn open_pool(data_dir: &Path, did: &str) -> PdsResult<SqlitePool> {
    Ok(SqlActorStore::open(data_dir, did).await?.pool().clone())
}
```

`SqlActorStore::open` creates an 8-connection pool **and runs the sqlx migrator** (`actor_store/sql/store.rs:77-89`) on *every* trait call. Pools are never cached or closed. The comment at `sql/public_realm.rs:22-28` acknowledges this ("Future optimization: a `DashMap<did, SqlitePool>` cache").

**The Spaces realm never dispatches.** `FjallSpaceRepoStorage` / `FjallSpaceMembersStorage` are exported (`actor_store/fjall/mod.rs:44-47`) but no production code constructs them — `grep -rn "FjallSpace" crates/atproto-pds/src` matches only the fjall module itself and its own tests. The whole `space/` module hard-codes SQLite: `space/service.rs:7,95`, `space/writer.rs:8,121`, `space/sync.rs:21,48`, `space/reader.rs`, `space/inbound.rs:13`, `space/config.rs:292`, `space/notify.rs:83,147`, `gc.rs:208,236`. Under `PDS_STORAGE_PROFILE=fjall` the public realm lives in fjall while Spaces silently write per-actor SQLite files — a **split-brain data layout**.

**A Postgres accounts pool breaks the repo writer**, as described above (`repo/writer.rs:361-369`, `:674-682`; `account/pool.rs:98-101`).

### 4.3 Schema

**Per-actor SQLite** — `migrations/actor/20260501000001_init.sql`:

| Table | Columns / keys |
|---|---|
| `commit_obj` (`:10-20`) | `cid TEXT PK`, `rev`, `data_cid`, `prev_cid`, `prev_data_cid`, `signature_blob BLOB`, `created_at`; `INDEX idx_commit_rev(rev)` |
| `repo_block` (`:24-28`) | `cid TEXT PK` (base32lower string), `data BLOB`, `indexed_at` |
| `repo_record` (`:31-42`) | `uri TEXT PK`, `cid`, `collection`, `rkey`, `rev`, `indexed_at`, `UNIQUE(collection,rkey)`; indexes on `collection`, `cid` |
| `repo_blob_ref` (`:45-53`) | PK `(record_uri, blob_cid)`, `mime_type`, `size`; `INDEX idx_repo_blob_ref_blob(blob_cid)` |
| `outbox` (`:56-63`) | `seq INTEGER PK AUTOINCREMENT`, `event_type`, `payload BLOB`, `created_at`; `INDEX idx_outbox_created` |
| `space` (`:69-84`) | `uri PK`, `is_owner`, `is_member`, `created_at`, `mint_policy` (default `member-list`), `app_access` JSON, `managing_app`, `deleted_at` |
| `space_member_state` (`:86-90`) | `space PK → space(uri) CASCADE`, `set_hash BLOB`, `rev` |
| `space_repo` (`:92-96`) | `space PK`, `set_hash BLOB`, `rev` |
| `space_record` (`:98-109`) | PK `(space, collection, rkey)`, `cid`, `value BLOB`, `repo_rev`, `indexed_at`; `INDEX (space, repo_rev)` |
| `space_member` (`:111-117`) | PK `(space, did)`, `member_rev`, `added_at` |
| `space_record_oplog` (`:119-129`) | PK `(space, rev, idx)`, `action`, `collection`, `rkey`, `cid`, `prev` |
| `space_member_oplog` (`:131-138`) | PK `(space, rev, idx)`, `action`, `did` |
| `space_credential_recipient` (`:155-163`) | PK `(space, repo, service_did)` (`repo=''` sentinel for whole-space), `service_endpoint`, `last_issued_at`, `expires_at` |

Plus `repo_blob(cid TEXT PK, mime_type, size INTEGER, data BLOB, created_at)` + `idx_repo_blob_created` (`20260504000001_blobs.sql:12-20`) — blob **bytes live inside the per-actor SQLite file** by default, rationale at `:7-10`; `space_received_op` PK `(space, rev, nsid)`, `issuer_did`, `set_hash BLOB`, `received_at` (`20260506000001_space_received_op.sql:16-26`); and `space_record_takedown` PK `(space, collection, rkey)`, `taken_at` (`20260506000002_space_record_takedown.sql:17-26`).

**Accounts SQLite** — `migrations/accounts/20260501000001_init.sql`: `account` (`:9-19`) with `did PK`, `handle UNIQUE`, `email UNIQUE`, `email_confirmed_at`, `password_hash` (Argon2id — `account/manager.rs:14-17,248`), `created_at`, `state` (default `active`), `signing_key_ref`, `pds_managed_rotation`, plus later columns `rotation_key_ref` (`20260505000001:14`), `delete_after` (`20260505000002:16`), `can_issue_invites` (`20260506000002:9`); `app_password` (`:24-33`); `invite_code` (`:49-56`); `email_token` (`:58-65`) + `new_email` (`20260505000002:15`); `signing_key` (`:73-81`); `service_auth_blacklist` (`:83-88`); `notify_attempt` (`:92-111`, the DLQ for outbound `notifyWrite`); `denylist` (`:115-120`). `oauth_session` and `plc_op_token` were created (`:35-47`, `:67-71`) and **dropped** by `20260506000001_drop_dead_schema.sql:20-24`.

`20260505000003_oauth_state.sql` adds `oauth_par` (`:11-25`), `oauth_code` (`:27-38`), and `oauth_refresh` (`:40-49`). **`oauth_refresh` has no `expires_at`** — the GC never prunes it (`gc.rs:262-278` handles only `oauth_par` + `oauth_code`), so it grows unbounded. `20260506000003_durable_state.sql` adds `jti_replay(jti PK, expires_at)` (`:15-20`) and `rate_limit_window(id PK AUTOINCREMENT, key, request_at_ms)` (`:29-35`).

**There is no session table.** App-password sessions are stateless HS256 JWTs (`account/session.rs:82-105, 164-194`), access TTL 7200 s, refresh TTL 7 776 000 s (`:23,26`). `deleteSession` and password-change therefore cannot revoke an outstanding access JWT — no revocation store exists for them.

**Postgres** — `migrations/postgres/20260507000001_init.sql`, one consolidated DDL mirroring the SQLite accounts schema with `INTEGER→BIGINT`, `BLOB→BYTEA`, int-booleans→`BOOLEAN` (rationale `:10-16`): `account` (`:24-37`), `app_password` (`:44-51`), `invite_code` (`:57-64`), `email_token` (`:68-74`), `signing_key` (`:80-86`), `service_auth_blacklist` (`:92-95`), `denylist` (`:99-104`), `notify_attempt` (`:108-121`), `oauth_par` (`:127-139`), `oauth_code` (`:143-149`), `oauth_refresh` (`:153-160`), `jti_replay` (`:166-169`), `rate_limit_window` (`:173-177`). Timestamps remain `TEXT`, not `TIMESTAMPTZ` (acknowledged `:13-16`).

**fjall keyspaces** — `actor_store/fjall/keyspace.rs:19-37`, 15 keyspaces, every key `<did>\0<suffix>` (`:291-297`): `commit_obj` (`:301-303`, value DAG-CBOR `CommitValue`, `fjall/public_realm.rs:55-64`), `commit_by_rev` (`:307-309`, secondary index for `latest()`), `repo_block` (`:313-315`), `repo_record` (`:325-327`), `repo_record_by_collection` (`:333-341`), `repo_blob` (`:390-392`), `repo_blob_ref` (`:359-367`), `outbox` (`:404-410`), `outbox_meta` (`:433-435`), and six space keyspaces (`:212-282`) that are unused at runtime. fjall has **no** `space`, `space_credential_recipient`, `space_received_op`, or `space_record_takedown` keyspace.

### 4.4 Repo data model — commit and MST

The commit struct is `crates/atproto-repo/src/repo/commit.rs:37-62`: `did`, `version: u64` (always 3), `data: Cid` (MST root), `rev: String` (TID), optional `prev`, optional `prev_data` (serialized `prevData`), and `sig: Vec<u8>`. **Repo version 3** is hardcoded at `commit.rs:98,119,229,247` and enforced by `Commit::validate` (`commit.rs:188-192` → `UnsupportedCommitVersion`).

Writer sites: unsigned build at `repo/writer.rs:349-355` (legacy) / `:664-670` (dispatch); signing bytes at `:356-358` / `:671-673` via `atproto_dasl::to_vec(&unsigned)`, with the canonical form from `commit.rs:129-142` (`signing_bytes()` rebuilds the `UnsignedCommit` without `sig`); sign+assemble at `:376-385` / `:689-698`; persist at `:392-405` (legacy raw SQL) / `:735-744` (via `CommitBatch` → `AtomicCommitWriter`); commit block bytes to `repo_block` at `:408-416`, `actor_store/sql/public_realm.rs:644`, `actor_store/fjall/public_realm.rs:851-855`. `rev` is a fresh TID per commit (`repo/writer.rs:333` / `:649`). When the MST goes empty the writer materializes `MstNode::empty()` and uses its CID as `data` (`:314-330`, `:630-646`).

DAG-CBOR canonicality: `atproto-dasl` sorts map keys by encoded key bytes (`crates/atproto-dasl/src/drisl/ser/serializer.rs:340-341, 388-389, 442`) — length-first-then-bytewise for text keys. CIDs encode as tag 42 + identity-multibase `0x00` prefix (`crates/atproto-dasl/src/cid/mod.rs:13-16, 55-61`). Block CIDs are CIDv1 / dag-cbor `0x71` / sha2-256 (`cid/mod.rs:690-697`); blob CIDs CIDv1 / raw `0x55` / sha2-256 (`cid/mod.rs:730-737`).

**BLOCKER — the MST write path is flat; `key_height` is never applied.** `crates/atproto-repo/src/mst/key.rs:29-34` defines `key_height` as `count_leading_zero_bits(sha256(key)) / 2` (fanout 4). `Mst::insert` (`mst/tree.rs:202-220`) calls `insert_recursive(root, key, value, 0)`, and `insert_recursive` (`mst/tree.rs:222-314`) computes `let _target_height = key_height(key);` at `:236` — **discarded, prefixed with `_`** — then splices the entry into the loaded node's `entries` vec and stores it. It never calls itself; `grep insert_recursive` yields only the definition (`:222`) and the single call from `insert` (`:208`). `delete_recursive` (`mst/tree.rs:342-420`) is likewise non-recursive. Only the **read** paths recurse (`get_recursive` `:177,189`; `collect_entries` `:458,468`).

Consequence: every repo is a single root `MstNode` holding all N entries in one block, with `left: None` and no `TreeEntry.tree` subtrees. This produces a different MST root CID than the reference implementation for any key set containing a height ≥ 1 key, so `data`/commit CIDs will not match upstream; a single record write rewrites the entire tree block; and a large repo emits one arbitrarily-large MST node block.

Supporting detail: key validation (`mst/key.rs:60-88`) requires a `/` with non-empty `collection` + `rkey`; ordering is bytewise (`mst/key.rs:94-96`); depth is guarded by `config.limits.max_depth` at `mst/tree.rs:229-233`, `:346-350`; `RepoConfig::default()` is `verify_cids: true, verify_signatures: true, strict_cid_format: true` (`crates/atproto-repo/src/config.rs:45-54`), used by the writer at `repo/writer.rs:196`, `:519`.

### 4.5 Signatures, CAR, and the firehose

**Curves.** `atproto_identity::key::sign` (`crates/atproto-identity/src/key.rs:428-478`) supports P-256, P-384, K-256, and Ed25519 (public-key variants return `PrivateKeyRequiredForSignature`, `:430-433`); `validate` (`:296-414`) covers the same set. The PDS mints account signing keys as **K-256** (`AccountManager::new(..., KeyType::K256Private)` at `bin/pds.rs:425-430`).

**Low-S normalization is absent from the PDS and `atproto-identity`.** `key.rs:434-463` calls `signing_key.try_sign(content)` and returns `signature.to_vec()` unmodified for all three ECDSA curves. `grep -r normalize` over `crates/` finds the helper only in `crates/atproto-attestation/src/signature.rs:30-40` (`normalize_signature` → `normalize_p256` `:43-62` / `normalize_k256` `:64-80`, both using `parsed.normalize_s()`), and `atproto-pds` has no dependency on `atproto-attestation`. Per curve, verified in the vendored crates:

- **K-256** — low-S *is* produced, by the `k256` crate, not by this code: `k256-0.13.4/src/ecdsa.rs:194` is `let sig_low = sig.normalize_s().unwrap_or(sig);` inside `impl SignPrimitive<Secp256k1> for Scalar`. Verification also rejects high-S (`k256-0.13.4/src/ecdsa.rs:200-203`). Since the PDS signs commits with K-256 (`bin/pds.rs:429`), production commit signatures are low-S.
- **P-256** — **NOT normalized.** `p256-0.13.2/src/ecdsa.rs:72` is `impl SignPrimitive<NistP256> for Scalar {}` — the empty default impl; `:75` `impl VerifyPrimitive<NistP256> for AffinePoint {}` likewise does not reject high-S. Any P-256 key routed through `key::sign` yields a malleable, possibly-high-S signature. This matters for `did:web`/P-256 accounts.
- **P-384** — same as P-256; `atproto-attestation::normalize_signature` explicitly rejects P-384 with `UnsupportedKeyType` (`signature.rs:37-39`).

**CAR export is fully buffered, not streaming.** Every exporter in `repo/car_export.rs` walks reachability into a `Vec<CarBlock>` in memory, then writes into a `Vec<u8>` buffer and returns `PdsResult<Vec<u8>>`: `export_repo_car` (`:30-110`, head lookup `:34-40`, DFS `:56-89`, buffer alloc `:92`, `CarWriter` over `&mut buffer` `:93-108`), `export_repo_car_since` (`:130-246`, baseline set `:189`, delta walk `:192-225`, buffer `:228-245`), and `export_repo_car_from_storage` (`:288-337`), `export_repo_car_via_backend` (`:343-359`), `export_repo_car_since_via_backend` (`:362-450`), `export_blocks_car_via_backend` (`:486-528`), `export_blocks_car` (`:531-574`). `atproto_dasl::car::CarWriter` *is* an async streaming writer (`crates/atproto-dasl/src/car/writer.rs:37-77`), but the PDS hands it a `Vec<u8>` sink, so the whole repo materializes in RAM twice. No size ceiling. Root is always the head commit CID (`car_export.rs:93`, `:229`, `:320`); child discovery decodes each block as `MstNode`, else `Commit`, else leaf (`:74-87`); missing blocks are silently skipped in the full export (`:67-71`), so a corrupted repo exports as a partial CAR with no error. `since` is a rev (TID), matching `com.atproto.sync.getRepo`'s `since: {type: string, format: tid}`; the same-rev shortcut emits a root-only CAR (`car_export.rs:167-179`, `:389-400`).

**CAR import is also buffered, despite the module doc.** `import.rs:21-27` claims "we avoid buffering the whole CAR", but `import_from_stream` drains every block into `let mut blocks: Vec<CarBlock> = Vec::new();` (`:174-192`) before doing anything, bounded only by `max_bytes` (default **4 GiB**, `import.rs:112`). `write_handlers::import_repo` reads the request body into `axum::body::Bytes` first (`http/write_handlers.rs:595-599`), buffering it a second time.

Import does verify: (1) CAR header version + roots (`CarReader::new`, `import.rs:166`; `CarConfig::default().verify_cids = true` at `crates/atproto-dasl/src/car/config.rs:78` makes `next_block` content-verify each block, `car/reader.rs:171-177`); (2) the commit chain walked backward from root via `prev`, requiring every link present — `build_commit_chain` (`import.rs:462-500`), missing `prev` is `InvalidCommit` (`:470-474`), a root that doesn't decode as `Commit` is rejected (`:207-216`, `:476-492`); (3) `prev_data` continuity, each commit's `prev_data` equal to the prior commit's `data` (`import.rs:220-235`); (4) MST integrity via `verify_inductive` per commit (`import.rs:232-233` → `crates/atproto-repo/src/repo/inductive.rs:79-158`, recomputing every block's CID at `:88-99`, requiring `new_root` present at `:102-106`, walking the new MST and requiring each referenced block be in the slice or covered by `prev_data` at `:114-151`).

Signatures are **only checked when opted in**: `verify_chain_signatures` runs only `if let Some(verifier) = &self.plc_verifier` (`import.rs:240-242`), and `RepoImporter::new` sets `plc_verifier: None` (`:113`). The check itself (`import.rs:365-403`) fetches the PLC audit log once, filters nullified ops, and picks the historical key via `historical_signing_key_at_rev` (`:418-454`). That helper compares a PLC ISO-8601 `created_at` string against a **TID** `rev` with `entry.created_at.as_str() <= rev` (`:424`) — the code's own doc calls this "a coarse heuristic" (`:407-417`). TIDs (base32-sortable, e.g. `3jui7kd2z2y2e`) and ISO-8601 strings (`2026-01-01T…`) are not in the same lexical space, so for real data `"2026-…" <= "3jui…"` is always true and the loop always selects the **last** active PLC op — the current key, never a historical one. Rotated-key repos would fail import; the "historical" property does not hold. The unit test at `:617-662` passes only because it feeds ISO-8601 strings as `rev`.

**BLOCKER — import never indexes `repo_record`.** Blocks land in the blockstore (`import.rs:244-270`) and commits in `commit_obj` (`:272-316`), but no `repo_record` write exists anywhere in the file. The single occurrence of the string `repo_record` in `crates/atproto-pds/src/repo/import.rs` is the **module doc comment at `import.rs:10`**, which claims the module will "index records into `repo_record`" — the doc asserts exactly the behavior the code does not implement. Since `getRecord` / `listRecords` / `describeRepo` read `repo_record` (`repo/reader.rs:133,141,268,280,353`), an imported account's records are invisible to every read endpoint even though `getRepo` would return them. Blob refs are likewise not reconstructed, so `listMissingBlobs` after import returns nothing, breaking the migration loop documented at `import.rs:5-6`. Post-import a `#sync` event is emitted best-effort (`import.rs:321-339`). `import_from_stream` also opens a `SqlActorStore` unconditionally at `:162` — creating a SQLite file even under fjall — and only branches for the block/commit writes (`:245`, `:277`).

**The sequence number is per-actor, not global.** SQLite gets it from `outbox.seq INTEGER PRIMARY KEY AUTOINCREMENT` (`migrations/actor/20260501000001_init.sql:56-61`) via `result.last_insert_rowid()` (`sequencer/outbox.rs:239`, `actor_store/sql/public_realm.rs:339,697`); fjall does a read-modify-write of `outbox_meta[<did>]` (`actor_store/fjall/public_realm.rs:390-409`, `:766-773`) with key `<did>\0<seq_be_u64>` for ordering (`keyspace.rs:404-410`). But `com.atproto.sync.subscribeRepos` declares one `cursor: integer` and every event body requires `seq: integer` described as "The stream sequence number of this message" — a single monotonic stream. `run_subscriber` builds `cursors: BTreeMap<did, Option<i64>>` and seeds **every** DID with the same client cursor (`http/subscribe_handlers.rs:102-103`), then emits each DID's per-actor seq on the wire (`:132-146`, `:167-181`). A client resuming at `cursor=50` skips the first 50 events of every repo, and duplicate `seq` values appear across repos. Cursor resume is not spec-conformant.

Atomicity is sound: the commit + commit block + record upserts/deletes + outbox row land in one backend-native transaction — sqlx `Transaction` (`actor_store/sql/public_realm.rs:618-703`) or one `fjall::Batch` (`actor_store/fjall/public_realm.rs:834-872`). Writes are serialized per-DID by an async mutex map (`repo/writer.rs:95, 139-144, 161-162`).

**Durability.** SQLite uses WAL + `mmap_size=64MiB` + a 5 s busy timeout (`actor_store/sql/store.rs:70-75`); `synchronous` is not set, so the sqlx/SQLite default applies. **fjall does not fsync.** `FjallActorStore::persist()` exists (`actor_store/fjall/keyspace.rs:109-114`, `PersistMode::SyncAll`) but is called **only from tests** (`keyspace.rs:447`, `block_storage.rs:283`). `Batch::commit()` fsyncs only when a durability mode was set — `fjall-3.1.4/src/batch/mod.rs:29,43` default `durability: None`, and `:119-129` skips `journal_writer.persist(mode)` when `None`. The PDS never calls `.durability(...)`. Under the fjall profile an acknowledged `createRecord` can be lost on host crash.

**Backpressure.** The live path is a `tokio::sync::broadcast` channel, capacity **1024** by default (`sequencer/event_bus.rs:46-51, 75-79`), wired via `EventBus::default()` at `http/state.rs:140,183`. Publish is fire-and-forget (`event_bus.rs:55-59`). A lagged subscriber gets `RecvError::Lagged(n)`, which the handler logs and ignores, relying on the 5 s poll fallback to backfill from the durable outbox (`http/subscribe_handlers.rs:188-193`, `:108`). The lexicon's `FutureCursor` and `ConsumerTooSlow` errors are never emitted — `grep -r "ConsumerTooSlow\|FutureCursor" crates/atproto-pds/src` returns nothing; `encode_info` only ever sends `OutdatedCursor` / `InternalError` (`sequencer/frame.rs:134-160`, called once at `subscribe_handlers.rs:94`). There is no backlog bound and no connection drop for slow consumers; the socket send simply awaits (`subscribe_handlers.rs:72-79`). The subscriber also enumerates DIDs with `list_accounts(None, 1000)` (`subscribe_handlers.rs:212-216`) — repos beyond the first 1000 are never tailed — and re-opens an `OutboxReader` per DID per 5 s poll cycle (`:117`), which under SQLite means a fresh pool + migration run per DID per tick.

**Event types** are `Commit | Sync | Identity | Account | Info` (`sequencer/outbox.rs:14-25`), matching the lexicon union `#commit | #sync | #identity | #account | #info` exactly. There is no `#handle` and no `#tombstone` — correct, those were removed from the current lexicon.

| Event | Emit site | Notes |
|---|---|---|
| `#commit` | `repo/writer.rs:460-468` (legacy), `:741` via `CommitBatch.outbox_event_type` (dispatch) | real work |
| `#sync` | `sequencer/sync_event.rs:51` (`publish_sync`), `:64` (`publish_sync_via_backend`); caller `repo/import.rs:332-336` | real work |
| `#identity` | `http/identity_handlers.rs:688-706` | **SQLite-only** — opens `SqlActorStore` directly at `:693`, ignoring the backend |
| `#account` | `account/manager.rs:369-390`, called from `set_state` at `:362` | **SQLite-only** — `SqlActorStore::open` at `:370` |
| `#info` | never appended; only the parse fallback (`sequencer/outbox.rs:174,189`) and `encode_info` for out-of-band frames | no durable `#info` rows |

**BLOCKER — under fjall, `#identity` and `#account` are unreachable.** Those two emitters write to a per-actor **SQLite** outbox, while `subscribe_handlers::open_outbox` reads through the fjall dispatch whenever `state.public_realm_backend` is `Some` (`subscribe_handlers.rs:26-33`) — which `bin/pds.rs:592` always sets. The events are persisted where nothing reads them.

**BLOCKER — the frame body does not match any lexicon def.** Framing itself is correct: `sequencer/frame.rs` implements `header || body` DAG-CBOR framing, header `{op:1,t:"#commit"}` / `{op:-1,t:"#info"}` (`frame.rs:50-57, 98-129, 144-159`), default CBOR with `?encoding=json` opt-in (`frame.rs:33-47`). But `encode_event` emits the event fields **nested under a `payload` key** (`sequencer/frame.rs:116-121`):

```rust
let body = serde_json::json!({ "seq": seq, "repo": did, "time": time, "payload": payload_value });
```

The lexicon requires them at the top level of the body object. Comparing the actual `#commit` payload (`repo/writer.rs:448-456` / `:722-730`) — `{did, rev, commit, data, prev, prevData, ops}` — against `subscribeRepos.json#commit`, which requires `["seq","rebase","tooBig","repo","commit","rev","since","blocks","ops","blobs","time"]`:

| Lexicon field | Present? |
|---|---|
| `seq` | only in the envelope, not the body |
| `rebase` (bool, deprecated) | **missing** |
| `tooBig` (bool, deprecated) | **missing** |
| `repo` (did) | **missing** — payload uses `did` |
| `commit` (cid-link) | present, but as a **string**, not a CBOR tag-42 cid-link |
| `rev` | present |
| `since` (tid, nullable) | **missing** — payload carries `prev`/`prevData` CIDs instead |
| `blocks` (bytes, CAR, ≤2 MB, commit block first root) | **missing entirely — no CAR diff is ever produced for the firehose** |
| `ops` | present (`ops_with_prev_cids(&diffs)`, `repo/writer.rs:447`, `:721`) |
| `blobs` | **missing** |
| `time` | only in the envelope |
| extra: `data`, `prev`, `prevData` | not in the lexicon |

The absent `blocks` CAR is the single largest firehose gap: relays and AppViews cannot ingest records at all from this stream. `#sync` is equally off — the lexicon requires `["seq","did","blocks","rev","time"]` with `blocks` a CAR containing the commit block (≤10 000 bytes); the PDS emits `{did, rev, head, blocks: <usize count>}` (`sequencer/sync_event.rs:67-73`), where `blocks` is a **block-count integer**, and the code comments admit it (`sync_event.rs:26-28`). `#identity` payload `{did, handle}` (`identity_handlers.rs:694-697`) is missing required `seq` + `time` in the body. `#account` payload `{did, active, status}` (`account/manager.rs:372-382`) is missing required `time`; the `status` values it emits (`active`/`deactivated`/`takendown`/`suspended`/`deleted`) are within `knownValues` except `"active"`, which the lexicon only allows when `active=false`. Compounding all of this, payloads are stored as **JSON** in the outbox (`serde_json::to_vec`, `writer.rs:457`, `sync_event.rs:74`, `manager.rs:383`, `identity_handlers.rs:698`) and re-decoded to `serde_json::Value` before DAG-CBOR re-encode (`frame.rs:115`) — lossy for byte fields, as the code notes at `frame.rs:107-114`. A CBOR `bytes` `blocks` field could not survive this round trip even if it were populated.

### 4.6 Blob lifecycle

Upload is `com.atproto.repo.uploadBlob` → `write_handlers::upload_blob` (`http/router.rs:67-68`, `http/write_handlers.rs:516-571`), with the body fully buffered into `axum::body::Bytes` (`:519`). MIME type is taken verbatim from the `Content-Type` header, defaulting to `application/octet-stream` (`write_handlers.rs:522-527`) — **no allowlist, no sniffing, no validation** — and `getBlob` echoes it straight back into the response `Content-Type` (`http/blob_handlers.rs:66-70`). Size is capped at 16 MiB (`MAX_BLOB_BYTES = 16 * 1024 * 1024`, `blob.rs:20`), enforced in two places (dispatch path `write_handlers.rs:531-539`, legacy path inside `put_blob` at `blob.rs:62-69`), both returning `PdsError::AuthDenied` — a 403-flavored XRPC error, not the lexicon's `BlobTooLarge`. The check happens *after* the whole body is in memory, so a hostile 1 GiB upload is buffered before rejection. CID computation is correct: `compute_raw_cid` → CIDv1 / raw `0x55` / sha2-256 (`write_handlers.rs:540`, `blob.rs:70`, `crates/atproto-dasl/src/cid/mod.rs:730-737`). Storage is an idempotent `INSERT OR IGNORE` into per-actor `repo_blob` (`blob.rs:74-87`, `actor_store/sql/public_realm.rs:420-437`) or the fjall `repo_blob` keyspace.

**There is no temp/quarantine stage.** Uploaded bytes go straight into `repo_blob` as permanent per-actor rows; there is no `temp_blob` table in any migration, no TTL on unreferenced blobs, and `gc.rs` never touches `repo_blob`. An authenticated account can park unlimited unreferenced 16 MiB blobs with no reclamation path.

**BLOCKER — ref-counting plumbing exists and is completely unused.** The trait declares `BlobStorage::add_ref` / `drop_refs_for_record` / `delete_blob` (`actor_store/traits.rs:249-259`); the SQL impl is `actor_store/sql/public_realm.rs:452-514`, the fjall impl `actor_store/fjall/public_realm.rs:560-600`, plus free functions `blob::add_ref` (`blob.rs:115-130`) and `blob::drop_record_refs` (`blob.rs:135-174`). **No caller exists.** `grep -rn "add_ref\|drop_refs_for_record\|drop_record_refs" crates/atproto-pds/src` returns only the trait declarations, the two backend impls, the S3 delegations (`blob_s3.rs:169-175`), and unit tests (`sql/public_realm.rs:822-833`, `fjall/public_realm.rs:1095-1135`, `blob.rs:321-335`). The repo writer never scans record values for blob refs — `repo/writer.rs` contains no reference to `blob` at all. Three consequences follow: `repo_blob_ref` is always empty in production, so `com.atproto.repo.listMissingBlobs` (`write_handlers.rs:453-501`, both branches) always returns `{"blobs": []}` and the account-migration loop documented at `repo/import.rs:5-6` cannot work; blob GC never fires, because `drop_record_refs` is the only orphan-reclaim path (`blob.rs:153-172`) and nothing calls it, so deleting a record leaves its blobs forever; and the blob is never bound to a record, so `getBlob` serves any uploaded CID for the DID regardless of whether a record references it (`blob_handlers.rs:33-72`, unauthenticated per lexicon).

GC (`gc.rs::tick_with`, `:103-160`) prunes on a `PDS_GC_INTERVAL_SECS` tick: `notify_attempt` state=`delivered` at 7 d (`:30`, `:117-121`, `:174-187`), state=`failed` at 30 d (`:32`, `:122-126`), `email_token` past `expires_at` (`:127-135`), `service_auth_blacklist` past `expires_at` (`:136-141`), `oauth_par` + `oauth_code` past `expires_at` (`:142`, `:262-278`), `jti_replay` via `JtiReplayGuard::gc()` (`:143`), `rate_limit_window` via `SlidingWindowLimiter::gc()` (`:144`), and `space_record_oplog` + `space_member_oplog` at 30 d default / `PDS_SPACE_OPLOG_RETENTION_DAYS` (`:37`, `:146-157`, `:203-260`) as a per-actor SQLite-only sweep (`:208, 236`). **Not covered:** `repo_blob` (orphan blobs), `outbox` (the firehose log grows forever), `oauth_refresh` (no `expires_at` column exists), and `repo_block` (orphan MST/record blocks after deletes — `SqlBlockStorage::remove` exists at `sql/block_storage.rs:99-114` but nothing calls it from a delete path). `run_or_log` swallows per-table failures with a `tracing::warn` and returns 0 (`gc.rs:164-172`); `prune_space_oplogs` opens a `SqlActorStore` per account in pages of 200 (`gc.rs:212-258`).

### 4.7 Ranked storage gaps

**Blockers**

1. **MST is flat** — `key_height` computed and discarded (`crates/atproto-repo/src/mst/tree.rs:236`); `insert_recursive`/`delete_recursive` never recurse. Root CIDs diverge from the reference for any repo containing a height ≥ 1 key.
2. **`#commit` carries no `blocks` CAR** (`repo/writer.rs:448-456`, `:722-730`) — required by `subscribeRepos.json#commit`. Downstream consumers cannot ingest records.
3. **Firehose body nested under `payload`** (`sequencer/frame.rs:116-121`), missing `repo`/`since`/`rebase`/`tooBig`/`blobs`/`time` — no event body matches its lexicon def.
4. **`importRepo` never writes `repo_record`** (`repo/import.rs`; the sole mention is the doc comment at `:10` claiming the opposite) — imported repos are invisible to `getRecord`/`listRecords`/`describeRepo`.
5. **Per-actor `seq`, no global sequence** (`migrations/actor/…init.sql:57`; `subscribe_handlers.rs:102-103`) — `cursor` resume is incorrect and `seq` values collide across repos.
6. **Blob ref-counting never invoked** — `listMissingBlobs` always empty, blob GC never runs, migration loop broken.
7. **fjall profile: `#identity` + `#account` written to SQLite, read from fjall** (`identity_handlers.rs:693`, `account/manager.rs:370` vs `subscribe_handlers.rs:26-33`).
8. **fjall profile: no fsync** — `persist()` never called in production; `fjall::Batch` default `durability: None` (`fjall-3.1.4/src/batch/mod.rs:29,119`).

**Majors**

9. `#sync.blocks` is a block-count integer, not CAR bytes (`sequencer/sync_event.rs:67-73`).
10. Import signature verification is opt-in (`import.rs:113`, `:240-242`) and its "historical key" selection compares ISO-8601 to TID (`import.rs:424`), always resolving to the newest key.
11. SQL trait dispatch opens a fresh pool + runs migrations on **every** call (`actor_store/sql/public_realm.rs:29-31`); pools never cached or closed.
12. P-256 / P-384 signatures are not low-S normalized (`crates/atproto-identity/src/key.rs:434-452`; `p256-0.13.2/src/ecdsa.rs:72`), and verification does not reject high-S.
13. Spaces realm is SQLite-only regardless of profile (`space/*.rs`), producing split storage under fjall.
14. CAR export is fully buffered in RAM with no size ceiling (`repo/car_export.rs:56-109`).
15. No `ConsumerTooSlow` / `FutureCursor`, no backlog bound, no slow-consumer disconnect (`subscribe_handlers.rs`).
16. `subscribeRepos` tails at most 1000 DIDs (`subscribe_handlers.rs:214`).
17. Postgres and S3 backends are implemented, tested, documented — and never constructed by `bin/pds.rs` (`:321-329` unused). `RepoWriter` would panic on a Postgres accounts pool (`repo/writer.rs:361`, `account/pool.rs:98-101`).

**Minors**

18. `uploadBlob` returns the deprecated blob shape without `$type`/`ref` (`blob.rs:39-49`).
19. No MIME allowlist or sniffing on upload; declared type echoed on `getBlob` (`write_handlers.rs:522-527`, `blob_handlers.rs:66-70`).
20. No temp-blob stage and no orphan-blob GC.
21. `outbox` and `oauth_refresh` have no retention (`gc.rs`).
22. App-password sessions are stateless JWTs with a 90-day refresh TTL and no revocation store (`account/session.rs:26`, `:164-194`).
23. Full CAR export silently skips missing blocks instead of erroring (`car_export.rs:67-71`).
24. `SqlBlockStorage::cids()` does a blocking full-table load inside `block_in_place` (`sql/block_storage.rs:124-142`).

---

## 5. Auth flows

The PDS carries **four distinct credential systems** and, inside the spaces layer, a fifth and sixth. App-password sessions and OAuth access tokens are both hand-rolled HS256 compact JWS signed with the same process-wide `PDS_JWT_SECRET`. Service auth is asymmetric, signed with the calling account's own `#atproto` key and verified by resolving the issuer's DID document. Admin is HTTP Basic. Spaces add delegation tokens and space credentials (ES256/ES256K, §6.3), and verify a third-party client-attestation JWT.

The single most consequential structural fact is that **`state.jwt_secret` (`http/state.rs:31`) signs and verifies all four of** app-password access JWTs, app-password refresh JWTs, OAuth access tokens, and OAuth refresh tokens (`account/session.rs:82`, `oauth/token.rs:278-281`). The only separation between the four classes is the `typ` header string. No key rotation is possible without invalidating every live token; no third party (AppView, entryway) can verify a PDS-issued OAuth token; a single secret disclosure forges all four classes. The reference signs access tokens asymmetrically and publishes the verification key (`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/signer/signer.ts:45-68`).

The second structural fact is that **the PDS reimplements the OAuth Authorization Server itself.** `atproto-oauth` contributes only the scope grammar, the DPoP proof validator, and a JWK type (§2.2). The PDS hand-rolls JWS mint/verify in **seven** independent places — `oauth/token.rs:335-388`, `account/session.rs:82-158`, `service_auth_handlers.rs:152-175`, `space/service_auth.rs:101-172`, `proxy_handlers.rs:318-345`, `identity_handlers.rs:315-341`, `mint_authz.rs:496-511` — and hand-rolls PKCE at `oauth/token.rs:316-320` rather than using `atproto_oauth::pkce`.

### 5.1 App-password sessions

Token format is a hand-rolled compact JWS, **HS256 only**. Mint at `crates/atproto-pds/src/account/session.rs:82-105` (`alg: "HS256"`, `typ` = the discriminator, HMAC-SHA256 over `b64url(header).b64url(payload)`); verify at `:107-158`, rejecting `alg != "HS256"` (`:121-125`) and `typ` mismatch (`:126-130`), doing a constant-time `mac.verify_slice` (`:141`), and rejecting `exp <= now` (`:152-156`). The `typ` discriminators are `at-pp-access` / `at-pp-refresh` (`session.rs:29,32`).

`SessionClaims` carries `sub` (account DID), `iss` (service DID), `apw` (app-password row id), `privileged` (bool), `iat`, `exp`, and `jti` (16 random bytes hex) — `session.rs:41-57`, `random_jti` at `:75-80`. `issue_pair` mints both tokens from one `SessionClaims` base, differing only in `exp` and a fresh `jti` (`session.rs:164-194`). Defaults are access **2 h** (`DEFAULT_ACCESS_TTL_SECS = 7200`, `session.rs:23`) and refresh **90 d** (`DEFAULT_REFRESH_TTL_SECS = 7_776_000`, `session.rs:26`), hardcoded at every call site — `auth_handlers.rs:351-352`, `:447-448`, `:272-273` — and therefore **not operator-configurable**, unlike the OAuth TTLs (`HttpState::oauth_access_ttl_secs` / `oauth_refresh_ttl_secs`, `http/state.rs:87-94`).

| Mint site | Location | Notes |
|---|---|---|
| `createAccount` | `http/auth_handlers.rs:266-275` | issues an implicit `__primary__` app-password row (`privileged=true`) at `:248-264`, then mints against it |
| `createSession` | `http/auth_handlers.rs:345-354` | |
| `refreshSession` | `http/auth_handlers.rs:441-450` | |

Rotation and revocation are partial. `refreshSession` is single-use — the presented refresh `jti` is inserted into `JtiReplayGuard` with TTL = remaining lifetime, and a second presentation 401s (`auth_handlers.rs:412-428`). `deleteSession` marks the refresh `jti` best-effort, errors only logged (`:464-482`). But **there is no revocation of app-password access JWTs**: `deleteSession` does not invalidate the paired access token, which stays valid for the remainder of its 2 h TTL. And password reset updates both `account.password_hash` and the `__primary__` app-password hash (`auth_handlers.rs:1526-1532`) but **does not** invalidate any outstanding session — a stolen 90-day refresh token survives a password reset.

Password verification is Argon2id with `Params::default()` and a random salt (`account/manager.rs:1063-1085`). `createSession` authenticates **only** against `app_password` rows (`auth_handlers.rs:331-343`); `manager.verify_password` is not consulted there. It works for the account password only because `createAccount` writes the user's password into the `__primary__` row (`:248-264`) and `resetPassword` keeps both in sync (`:1526-1532`). `POST /oauth/authorize` does try both (`oauth/authorize.rs:107-118`). `app_password::verify` runs a full Argon2 verification against **every** app-password row for the DID until one matches (`account/app_password.rs:383-394`).

Lexicon deltas: `createSession` input accepts `authFactorToken` and `allowTakendown`, and `CreateSessionInput` (`auth_handlers.rs:286-292`) has neither — no 2FA/email-auth-factor support, no `AuthFactorTokenRequired` / `AccountTakedown` errors. `createSession` / `refreshSession` output may carry `didDoc`, `email`, `emailConfirmed`, `emailAuthFactor`, `active`, `status`; `SessionResponse` (`:45-56`) emits only the four required fields. `getSession` likewise emits `handle`/`did`/`email` only (`GetSessionResponse`, `:365-374`). `createSession.identifier` is documented as "Handle or other identifier supported by the server" (email in the reference), but the handler branches only on `did:` prefix vs handle lookup (`:305-309`) — an email identifier will not resolve, even though `is_email_shape` exists at `:1713-1726`.

### 5.2 OAuth Authorization Server

The PDS ships its own AS at `crates/atproto-pds/src/oauth/` (`mod.rs:19-27`).

**PAR (RFC 9126) is implemented with gaps.** `POST /oauth/par` → `oauth/par.rs:132-200` stores an `OAuthRequest` keyed by `urn:ietf:params:oauth:request_uri:<64 hex>` (`par.rs:177-194`) with a 60 s TTL (`PAR_TTL_SECS`, `oauth/state.rs:37`). Validated: `response_type == "code"` (`:147-153`), `code_challenge_method == "S256"` (`:154-160`), scope contains `atproto` (`:161-167`), `code_challenge` non-empty (`:168-174`). **Not validated: `redirect_uri` is never checked against the client-metadata document's `redirect_uris`** — in the inline path (`par.rs:202-223`) the client-metadata document is never fetched at all. JAR / signed request objects (RFC 9101) **are** supported: `par.rs:258-400` verifies the JWS against the client's `jwks` / `jwks_uri` resolved from `GET <client_id>` (`par.rs:405-457`), accepts `ES256|ES256K|ES384` (`:285-294`), enforces `iss == client_id` (`:311-319`), `exp`/`nbf` (`:332-350`), and the real signature (`:372-378`).

**PKCE enforces S256.** `code_challenge_method` must be `S256` at PAR (`par.rs:154-160`), and `code_verifier` is mandatory at token exchange (`oauth/token.rs:160-173`). Verification is `b64url_nopad(SHA256(verifier)) == challenge` (`token.rs:316-320`). `plain` is never accepted.

**DPoP (RFC 9449) is resource-side only.** It is enforced on resource requests when the access token carries `cnf.jkt` (`http/auth.rs:179-181` → `oauth/dpop.rs:44-109`). The underlying validator is `atproto_oauth::dpop::validate_dpop_jwt` (`crates/atproto-oauth/src/dpop.rs:533+`), checking `typ == "dpop+jwt"` (`:558-564`), `alg ∈ {ES256, ES384, ES256K}` (`:574-580`), header `jwk`, `jti` presence (`:629-634`), `htm` (`:636-653`), plus `htu`/`ath`/`iat` per config. `htm`/`htu` are derived from the live request with query+fragment stripped, honouring `X-Forwarded-Proto`/`X-Forwarded-Host` (`http/auth.rs:207-235`). `ath` is required for resource requests — `DpopValidationConfig::for_resource_request` sets `expected_access_token_hash` (`crates/atproto-oauth/src/dpop.rs:485-492`), called at `oauth/dpop.rs:71`. Proof `jti` is single-use for 120 s via `JtiReplayGuard` (`oauth/dpop.rs:90-106`), and the thumbprint is compared against `cnf.jkt` (`:81-87`).

**Server-issued DPoP nonces are not implemented.** `DpopValidationConfig.expected_nonce_values` exists (`crates/atproto-oauth/src/dpop.rs:451-452`) but the PDS never populates it (`oauth/dpop.rs:71-72` sets only `max_age_seconds`). Grep for `DPoP-Nonce` / `use_dpop_nonce` across `crates/` returns only client-side handling inside `atproto-oauth` and its error enum — nothing in `atproto-pds`. The reference issues and rotates nonces (`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/dpop/dpop-nonce.ts:34-107`). **No DPoP proof is required at `/oauth/par`, `/oauth/token`, or `/oauth/revoke`** — `token_handler` takes `dpop_jkt` as a plain JSON body field (`oauth/token.rs:44-45`) with no proof.

**Client authentication is not implemented.** `token_handler` (`oauth/token.rs:100-124`) reads `client_id` from the body and never authenticates it. `handle_code` only compares the body `client_id` to the PAR-stored value (`token.rs:146-152`); `handle_refresh` compares it to the refresh JWT claim (`token.rs:201-207`). There is no `client_assertion` / `client_assertion_type` field on `TokenInput` (`token.rs:30-46`) and no `private_key_jwt` verification anywhere, despite the metadata advertising it (`oauth/metadata.rs:77-80`). The client-metadata document is fetched **only** on the JAR path (`par.rs:409-421`), and nothing validates it against the atproto client-metadata rules — no check of `client_id` self-consistency, `redirect_uris`, `grant_types`, `scope`, `application_type`, `dpop_bound_access_tokens`, or `token_endpoint_auth_method`. The reference validates all of these in `/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/client/client.ts` (e.g. `redirect_uris` at `:375-382`).

**Token issuance** — `issue_pair`, `oauth/token.rs:236-307`:

| Aspect | atproto-pds | Reference |
|---|---|---|
| Signature | **HS256**, `state.jwt_secret` (`token.rs:335-354`) | asymmetric via `keyset.createJwt` (`signer/signer.ts:45-68`) |
| `typ` header | `at-oauth-access` / `at-oauth-refresh` (`token.rs:24,27`) | `at+jwt` (RFC 9068) (`signer.ts:57-68`) |
| Verifiable by third parties | **no** (shared symmetric secret) | yes, via `/oauth/jwks` |
| DPoP-bound | yes when `dpop_jkt` present → `cnf.jkt` (`token.rs:246-248,261`) | yes (`token/token-manager.ts:89-90`) |
| `token_type` | `"DPoP"` if bound else `"Bearer"` (`token.rs:298`) | same |
| Claims | `sub`,`iss`,`aud`,`client_id`,`scope`,`cnf`,`iat`,`exp`,`jti` (`token.rs:66-86`) | `jti`,`sub`,`exp`,`iat`,`iss`,`aud?`,`scope?`,`client_id?`,`cnf?` (`signer/access-token-payload.ts`) |
| `iss` value | `did:web:<host>` reconstructed from `service_did` (`token.rs:257`, `:309-314`) — a **DID**, not the issuer URL | the issuer origin URL |
| Access TTL | `state.oauth_access_ttl_secs`, default 900 s (`oauth/state.rs:28`) | ~15 min |
| Refresh TTL | `state.oauth_refresh_ttl_secs`, default 30 d (`oauth/state.rs:31`) | |
| Auth-code TTL | 60 s (`AUTH_CODE_TTL_SECS`, `oauth/state.rs:34`) | |

`verify_oauth_jwt` (`token.rs:358-388`) checks `alg == HS256`, `typ`, HMAC, and `exp`. It does **not** check `iss`, `aud`, `nbf`, or `iat`, and never consults the revocation guard. `/oauth/jwks` (`oauth/jwks.rs:42-67`) publishes the PDS signing key(s) with `use=sig`, an `alg` from the key type, and an RFC-7638 thumbprint `kid` (`:87-99`); its own doc comment concedes the access tokens are HS256 and therefore not verifiable with anything it publishes (`jwks.rs:7-9`). With `pds_signing_key` unset it returns `{"keys":[]}`.

Refresh rotation is single-use and durable: `handle_refresh` calls `oauth.rotate_refresh(old_jti, new_jti)` and 400s `invalid_grant` when the handle is gone (`token.rs:209-223`); `OAuthState::rotate_refresh` dispatches to the memory or SQL backend (`oauth/state.rs:188-197`), and the SQL backend is wired in production (`bin/pds.rs:598`), so rotation survives restart. Revocation (`POST /oauth/revoke`, `oauth/revoke.rs:39-56`) is form-encoded (`Form(input)`, `:41`), honours `token_type_hint` ordering (`:44-47`), and always returns 200 (`:53-55`); refresh revocation drops the rotation handle (`:64-74`) and is effective, access revocation inserts the `jti` into `JtiReplayGuard` (`:75-82`) and is **ineffective** (§5.6-D). No client authentication, no `client_id` check.

The authorization endpoint renders a hand-rolled HTML consent page (`oauth/consent.rs:43-78`, `render_consent` at `:201-345`) that `peek`s (does not consume) the PAR row; submission is intercepted by inline JS that POSTs JSON to `/oauth/authorize` and then client-side-redirects to `body.redirect_uri + ?code&state&iss` (`consent.rs:305-333`). `POST /oauth/authorize` (`oauth/authorize.rs:47-140`) consumes the PAR row, resolves identifier → DID (`:82-94`), rejects non-`Active`/`Deactivated` accounts (`:96-105`), verifies app-password then account password (`:107-125`), and issues a 32-byte hex code (`:127-146`). It returns `{code, state, iss, redirect_uri}` as JSON — the RFC 9207 `iss` is present in the body (`:39-41`, `:131`) but the server never performs the 302 redirect itself.

### 5.3 The two well-known documents

Both derive the issuer as `https://<host>` from `did:web:<host>` (`oauth/metadata.rs:52-93`, `:95-101`).

`/.well-known/oauth-authorization-server` emits (`metadata.rs:11-40, 56-81`): `issuer`, `authorization_endpoint`, `token_endpoint`, `pushed_authorization_request_endpoint`, `require_pushed_authorization_requests: true`, `revocation_endpoint`, `jwks_uri`, `response_types_supported: ["code"]`, `grant_types_supported: ["authorization_code","refresh_token"]`, `code_challenge_methods_supported: ["S256"]`, `scopes_supported: ["atproto","transition:generic","transition:chat.bsky"]`, `dpop_signing_alg_values_supported: ["ES256","ES256K"]`, `require_dpop_bound_access_tokens: true`, `token_endpoint_auth_methods_supported: ["none","private_key_jwt"]`.

Missing relative to the reference (`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/metadata/build-metadata.ts`):

| Field | Ref line | Impact |
|---|---|---|
| `authorization_response_iss_parameter_supported` | `:98` | RFC 9207; `@atproto/oauth-client` reads it to decide whether to require `iss` on the callback |
| `client_id_metadata_document_supported` | `:139` | the atproto client-id-as-URL signal |
| `request_object_signing_alg_values_supported` | `:101` | PAR JAR is implemented (`par.rs:285`) but unadvertised |
| `request_parameter_supported`, `request_uri_parameter_supported`, `require_request_uri_registration` | `:105-107` | |
| `token_endpoint_auth_signing_alg_values_supported` | `:115` | required if `private_key_jwt` is advertised (RFC 8414 §2) |
| `subject_types_supported` | `:39` | |
| `response_modes_supported` | `:57` | |
| `ui_locales_supported`, `display_values_supported`, `prompt_values_supported` | `:76-95` | |
| `scopes_supported` omits `transition:email` | `:33` | |

Three advertised values are incorrect. `token_endpoint_auth_methods_supported` advertises `private_key_jwt`, which the token endpoint does not implement — a confidential client following the metadata sends `client_assertion` and has it silently ignored (`TokenInput`, `token.rs:30-46`, has no such field), so it is authenticated as a public client. `dpop_signing_alg_values_supported` lists `["ES256","ES256K"]` but `validate_dpop_jwt` also accepts `ES384` (`crates/atproto-oauth/src/dpop.rs:574`). And `require_dpop_bound_access_tokens: true` is a claim the server does not enforce: a PAR/token exchange with no `dpop_jkt` yields `cnf: None` and `token_type: "Bearer"` (`token.rs:246-248`, `:298`), and `require_authn` then skips DPoP entirely (`http/auth.rs:179`).

`/.well-known/oauth-protected-resource` emits `resource` and `authorization_servers` only (`metadata.rs:44-49, 86-93`). Missing vs the reference (`/tmp/gap-scratch/atproto/packages/pds/src/auth-routes.ts:16-36`): `bearer_methods_supported: ['header']` (`:19`), `scopes_supported: []` (`:20`), `resource_documentation` (`:21`). The reference also sets `Access-Control-Allow-Origin/Method/Headers: *` on this response (`:32-34`); the Rust handler returns a bare `Json<...>` with no CORS headers, and there is no CORS layer in the router (`http/router.rs:27-433`), so browser clients (`@atproto/oauth-client-browser`) cannot read it.

### 5.4 Scopes: recognized vs enforced

`atproto_oauth::scopes::Scope` parses `Account`, `Identity`, `Blob`, `Repo`, `Rpc`, `Space`, `Atproto`, `Transition`, `Include`, `OpenId`, `Profile`, `Email` (`crates/atproto-oauth/src/scopes.rs:34-59`). At PAR there is exactly one check — the string must contain the bare token `atproto` (`oauth/par.rs:161-167`). Any other token, known or unknown or malformed, is stored verbatim and copied into the access token's `scope` claim (`token.rs:260`). There is no allow-list, no rejection of unrecognized scopes, and no `include:<nsid>` permission-set resolution anywhere in the PDS. On the consent page, `describe_scope` (`oauth/consent.rs:377-401`) renders friendly text for `atproto`, `transition:*`, and `space:*` (via the real 0016 grammar, `:412+`); everything else falls through to `"request access to scope `<s>`"` (`:400`), so `repo:app.bsky.feed.post`, `rpc:*`, `blob:*/*`, `account:email`, `identity:*`, and `include:...` all render as opaque strings.

**Enforcement covers space scopes and nothing else.** The `ScopesSet` API exposes assertions for space scopes only — `allows_space`, `allows_space_with`, `allows_space_manage`, `assert_space`, `assert_space_with`, `assert_space_manage` (`crates/atproto-oauth/src/scopes.rs:1092-1141`). There is no `assert_repo` / `assert_rpc` / `assert_blob` / `assert_account` / `assert_identity`.

| Check | Where | Applies to |
|---|---|---|
| `assert_space` / `assert_space_with` | `http/space_handlers.rs:1859-1914` (helper), called at `:209,251,292,422,498,519,574,674,738,791,799,838,928,1023,1252,1329,1442,1846,1971,1983,2218` | `com.atproto.space.*` only |
| `assert_space_manage` | `http/space_handlers.rs:1916-1935` | `com.atproto.space.*` only |
| `privileged()` | `http/write_handlers.rs:601-608` | `com.atproto.repo.importRepo` only |

`AuthSubject::privileged()` (`http/auth.rs:110-118`) maps to the `privileged` claim for app-password sessions, and for OAuth to the literal presence of `transition:generic` in the scope string. That is the **only** place any `transition:` scope affects behaviour. Everything else is accepted and ignored:

- `com.atproto.repo.createRecord` / `putRecord` / `deleteRecord` / `applyWrites` / `uploadBlob` gate on subject-equals-repo only (`assert_subject`, `http/write_handlers.rs:113-127`). An OAuth token with `scope="atproto"` and nothing else can write any collection in the owner's repo. The reference gates per-write: `permissions.assertRepo({ action, collection })` at `/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/applyWrites.ts:119`.
- `com.atproto.identity.updateHandle` (`http/identity_handlers.rs:136-145`), `requestPlcOperationSignature` (`:299-304`), `signPlcOperation` / `submitPlcOperation` — subject only. Reference: `permissions.assertIdentity({attr:'handle'})` at `.../identity/updateHandle.ts:13`, `assertIdentity({attr:'*'})` at `.../identity/signPlcOperation.ts:16` and `.../submitPlcOperation.ts:12`.
- `app.bsky.*` proxy (`http/proxy_handlers.rs:165`) — subject only. Reference: `permissions.assertRpc(params)` at `/tmp/gap-scratch/atproto/packages/pds/src/pipethrough.ts:68`.
- `com.atproto.server.requestEmailConfirmation` etc. — no `account:email` check. Reference: `permissions.assertAccount({attr:'email',action:'manage'})` at `.../server/requestEmailConfirmation.ts:18`.

App-password sessions return an **empty** `ScopesSet` (`http/auth.rs:96-101`), so they satisfy no space scope and are structurally excluded from `com.atproto.space.*` — intentional and documented at `http/auth.rs:80-88`.

### 5.5 Service auth

Minting is `http/service_auth_handlers.rs:93-176`; the caller must pass `require_authn` (`:102`). Claims are `iss` = caller DID, `aud`, `lxm` (omitted when absent, `:68-69`), `iat`, `exp`, `jti` = 16 random bytes b64url (`:63-73`, `:86-90`, `:143-150`). It is signed with the **calling account's own `#atproto` signing key**, fetched from the `KeyStore` via `local_signing_key` (`:129` → `http/space_auth.rs:74-103`), with header `alg` from `jws_alg(&signing_key)` and `typ: "at+jwt"` (`:138-142`). Other minters share the shape: `identity_handlers.rs:299-341` (`lxm` hardcoded to `com.atproto.identity.signPlcOperation`), `proxy_handlers.rs:286-345` (`lxm` = the proxied NSID, 60 s), `moderation_handlers.rs:150-190`, `space/mint_authz.rs:473-511`, `space/service_auth.rs:81-113`.

Verification has exactly one implementation in the tree: `crates/atproto-pds/src/space/service_auth.rs:125-172`. It checks `aud == expected_aud` (`:145-150`) and `exp` (`:158-160`), then resolves the issuer's `#atproto` Multikey from its DID document (`:162-164`, `:181-213`) and verifies the signature (`:165-170`). Callers are `http/space_handlers.rs:2096-2103` (`notifyWrite`, `aud` = space owner DID, plus `iss == payload.repo` at `:2106-2112`) and `:2570-2578` (`notifySpaceDeleted`, `aud` peeked unverified from the token itself at `:2564-2569`, then `iss == space.space_did` at `:2579-2585`).

Three things it does not do. **`lxm` is only conditionally enforced**: `if let Some(lxm) = claims.lxm.as_deref() && lxm != expected_lxm` (`space/service_auth.rs:151-157`). A token minted **without** an `lxm` claim passes every method, and `getServiceAuth` makes `lxm` optional (`service_auth_handlers.rs:44-45`, skipped on serialization when `None` at `:68-69`), so any account can mint a wildcard token and present it at both `notifyWrite` and `notifySpaceDeleted`. **The JWS header is never parsed** — the verifier decodes only the payload (`:138-142`) and passes `header_b64` through into the signing input (`:168`), so `typ` and `alg` are unchecked, as are `iat`/`nbf`. **There is no replay protection**: `jti` is minted (`service_auth_handlers.rs:149`) but `verify_service_auth` never records or checks it.

Deltas vs the reference (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/getServiceAuth.ts`):

| Concern | Reference | atproto-pds |
|---|---|---|
| `exp` semantics | absolute Unix epoch; rejects past, caps at +1 h, caps method-less tokens at +1 min (`:67-84`) | treated as a **TTL in seconds**, `clamp(1,600)` then `exp = iat + ttl` (`service_auth_handlers.rs:131-136`). The lexicon (`.../server/getServiceAuth.json`) says "The time in Unix Epoch seconds that the JWT expires" |
| `BadExpiration` error | thrown (`:70-84`) | never emitted — no such error name in the handler |
| protected methods | `PROTECTED_METHODS` rejected outright (`:86-91`) | no check |
| privileged methods | `PRIVILEGED_METHODS` require a privileged access scope (`:56-66`) | no check — a non-privileged session can mint `lxm=com.atproto.server.createAccount` (the migration token) |
| takendown accounts | blocked except for `createAccount` (`:45-54`) | no check; `require_authn` has no account-state lookup |
| OAuth scope | `permissions.assertRpc({aud, lxm})` (`:29`) | no scope check |
| `aud` validation | `isAtprotoDid(aud) \|\| isAtprotoDidRefAbsolute(aud)` (`:37-41`) | `aud.starts_with("did:")` only (`service_auth_handlers.rs:104-110`) |

Minor: `JwtHeader.kid: Option<String>` is set to `None` but has no `skip_serializing_if` (`service_auth_handlers.rs:56-61`, `:141`), so the emitted header is `{"alg":...,"typ":"at+jwt","kid":null}`.

### 5.6 Security-relevant findings

**A. PAR/authorize never validates `redirect_uri` against the client-metadata document — auth-code exfiltration.** `oauth/par.rs:202-223` (inline path) stores the caller-supplied `redirect_uri` verbatim; the client-metadata document is not fetched on this path at all. `oauth/authorize.rs:127-139` echoes it back unchecked, and the consent page's JS navigates the browser to it (`oauth/consent.rs:325-330`). An attacker PARs with a legitimate `client_id` and an attacker-controlled `redirect_uri`, phishes the victim to the resulting consent URL, and receives a valid authorization code — which is not client-authenticated at `/oauth/token` (finding B). The reference rejects this (`.../oauth-provider/src/client/client.ts:375-382`).

**B. No client authentication and no DPoP proof at `/oauth/token`; the client picks its own `cnf.jkt`.** `oauth/token.rs:100-124` requires nothing beyond the body. `handle_code` prefers the request-time `dpop_jkt` over the PAR-pinned one — `let dpop_jkt = input.dpop_jkt.clone().or(auth.request.dpop_jkt.clone());` (`token.rs:176`). A stolen authorization code can be redeemed by anyone and bound to the attacker's key, defeating the DPoP binding. The reference requires a DPoP proof and cross-checks it against the stored `dpop_jkt` (`.../oauth-provider/src/oauth-provider.ts:826-829`). Same for refresh: `handle_refresh` (`token.rs:188-234`) verifies only the refresh JWT's HMAC — no proof-of-possession — so a leaked refresh token is bearer-usable despite being `cnf`-bound (reference: `oauth-provider.ts:1063-1077`).

**C. `admin.revokeServiceAuth` is a no-op.** `service_auth_blacklist::add` is called at `admin/handlers.rs:855`, but `service_auth_blacklist::contains` (`service_auth_blacklist.rs:63-101`) has **no** production caller — a full-tree grep finds only `tests/feature_postgres_live.rs:412,417,427,432`. `verify_service_auth` (`space/service_auth.rs:125-172`) never consults it. The handler doc at `admin/handlers.rs:838-840` asserts the opposite.

**D. `/oauth/revoke` on an access token is a no-op.** `revoke.rs:75-82` inserts the access token's `jti` into `JtiReplayGuard`, but `require_authn` (`http/auth.rs:154-184`) never queries the guard for the access token's `jti` — the only `check_and_insert` on the request path is for the **DPoP proof's** `jti` (`oauth/dpop.rs:97-106`). Full grep of `jti_guard` outside `security.rs`/tests: `gc.rs:143`, `oauth/dpop.rs:97`, `oauth/revoke.rs:80`, `auth_handlers.rs:419,477`, `space_handlers.rs:1533,1564`, `http/auth.rs:180`. A revoked access token keeps working for its full TTL.

**E. One symmetric secret spans every role** — see the §5 opening paragraph (`http/state.rs:31`, `account/session.rs:82`, `oauth/token.rs:278-281`).

**F. No `aud` / `iss` check on inbound OAuth tokens.** `verify_oauth_jwt` (`oauth/token.rs:358-388`) validates `alg`, `typ`, HMAC, `exp` — and nothing else. `aud` and `iss` are minted (`:257-259`) and never verified. Any deployment sharing a `PDS_JWT_SECRET` across services (multi-realm, blue/green, entryway) cross-accepts tokens.

**G. PAR request-object `aud` is advisory only.** `oauth/par.rs:383-397`: on `aud` mismatch the code emits `tracing::debug!(... "aud mismatch (advisory)")` and continues. The comment at `:380-382` claims the spec "recommends but doesn't require"; RFC 9101 §4 makes `aud` a MUST-verify for the AS. A request object minted for PDS-A is replayable at PDS-B.

**H. SSRF: unguarded fetch of caller-supplied URLs.** `oauth/par.rs:405-457` builds a `reqwest::Client` (`:409-413` — it does set `user_agent` and a 10 s timeout) and `GET`s `client_id` verbatim (`:417`) and then `jwks_uri` verbatim (`:427-433`). There is **no scheme check** (`http://` accepted), **no host validation**, **no private/loopback/link-local rejection**, and **no redirect cap**. The SSRF hardening from `18b826f` landed in `atproto-identity` (`crates/atproto-identity/src/host.rs`, `web.rs`, `resolve.rs` per `git show 18b826f --stat`); `crates/atproto-pds` received only a version bump, and `par.rs` does not call those helpers. Grep of `crates/atproto-pds/src/` for `is_private|loopback|link_local|ssrf` returns nothing. `space/mint_authz.rs:317-339` has the same unbounded fetch but at least requires `https://` (`:268-272`).

**I. Per-request memory leak on the authenticated space-read path.** `http/space_handlers.rs:1113`: `let did_static: &'a str = Box::leak(sub.clone().into_boxed_str());`. Every authenticated `com.atproto.space.getRecord` / `listRecords` call permanently leaks the caller's DID string. Sole `Box::leak` in the crate. Unauthenticated-to-authenticated remote memory exhaustion.

**J. `lxm` is optional on both sides of service auth** (`service_auth_handlers.rs:44-45`, `:68-69`; `space/service_auth.rs:151-157`). Combined with the missing `PROTECTED_METHODS`/`PRIVILEGED_METHODS` gates (§5.5), any authenticated account can mint an unrestricted cross-service bearer.

**K. Service-auth verification ignores the JWS header** (`space/service_auth.rs:132-142`, `:168`). Signature verification still uses the DID-document key, so this is not directly forgeable, but a claimed `alg` has no bearing on verification and confusing-header tokens are accepted.

**L. Admin defaults and comparison.** Default password `"admin-default-CHANGE-ME"` is live whenever `PDS_ADMIN_PASSWORD` is unset **and** `PDS_PRODUCTION` is not `true` (`admin/handlers.rs:34`, `:90-95`; `config.rs:52-58`; `bin/pds.rs:97`). Comparison is a non-constant-time `!=` on `&str` (`admin/handlers.rs:80`, `admin/dashboard.rs:71`). Admin auth exists in two byte-identical copies — `admin/handlers.rs:37-88` for all `com.atproto.admin.*` JSON handlers, and `admin/dashboard.rs:24-79` for `/admin` and `/admin/`. No rate limit on any admin route.

**M. Signing keys are stored in plaintext on disk.** `FileKeyStore::put` writes the private key as a `did:key:` string, mode 0600 (`keys.rs:63-103`). The trait doc at `keys.rs:19-21` says implementations "are expected to encrypt at rest"; `FileKeyStore` does not — filesystem ACLs are the only protection. These are the per-account `#atproto` signing keys and the PDS rotation key.

**N. Password reset does not invalidate sessions.** `reset_password` (`auth_handlers.rs:1477-1538`) and `admin.updateAccountPassword` update hashes only. No refresh-token generation counter, no bulk `jti` invalidation. Refresh tokens issued before the reset remain valid for up to 90 days (`session.rs:26`).

**O. Refresh tokens minted from a non-DPoP grant are permanently unusable (functional break).** `issue_pair` stores `dpop_jkt.clone().unwrap_or_default()` into `RefreshHandle` (`token.rs:290`) — an empty `String` when no jkt was present. `handle_refresh` then passes `Some(handle.dpop_jkt)` back into `issue_pair` (`token.rs:230`), so `cnf` becomes `Some(DpopConfirmation { jkt: "" })` (`token.rs:246-248`) and `token_type` flips to `"DPoP"` (`token.rs:298`). On the next resource request `claims.cnf.is_some()` is true (`http/auth.rs:179`) and `verify_dpop_proof` compares the proof thumbprint against `""` (`oauth/dpop.rs:81-87`), which can never match. Every non-DPoP OAuth session becomes unusable after its first refresh.

**P. Interop: PAR and token accept JSON only.** `par_handler` and `token_handler` use axum's `Json` extractor (`oauth/par.rs:132-135`, `oauth/token.rs:100-103`), which requires `Content-Type: application/json`. RFC 6749/9126 mandate `application/x-www-form-urlencoded`, and the reference client sends exactly that (`/tmp/gap-scratch/atproto/packages/oauth/oauth-client/src/oauth-server-agent.ts:239-243`, `:261-266`). `@atproto/oauth-client-*` will 415 against this PDS. (`revoke_handler` correctly uses `Form` — `oauth/revoke.rs:41`.)

**Q. No CSRF protection on the consent form.** `oauth/consent.rs:280-303` renders a form with no anti-CSRF token, and `POST /oauth/authorize` accepts a bare JSON body with no origin/referer/state binding (`oauth/authorize.rs:47-50`). Mitigated in practice by the fact that the POST also carries the user's password.

**R. Argon2 amplification on `createSession`.** `app_password::verify` (`account/app_password.rs:383-394`) loops every app-password row for the DID and runs a full Argon2id verification per row. With the 300/min limiter (`http/state.rs:139`) and a user holding N app passwords, one attacker gets 300·N Argon2 evaluations per minute per targeted account.

### 5.7 Verified-absent

- No DPoP nonce issuance or `use_dpop_nonce` challenge in `crates/atproto-pds/` (grep across `crates/`: only `atproto-oauth` client-side handling + error enum).
- No `client_assertion` / `private_key_jwt` handling anywhere (grep `crates/`).
- No `Access-Control-*` / CORS layer on any route (`http/router.rs:27-433`).
- No account-state (takendown/suspended) check inside `require_authn` (`http/auth.rs:154-198`) — state is checked only at `createSession` (`auth_handlers.rs:319-328`) and `POST /oauth/authorize` (`oauth/authorize.rs:96-105`).
- No `com.atproto.server.updateEmail`, `createInviteCodes`, `describeServer`, or `com.atproto.admin.updateAccountSigningKey` routes, all canonical lexicons.

---

## 6. Permissioned data / spaces

Spaces are a parallel data plane. They do not use the MST, do not produce CAR files, do not touch the sequencer, and never appear on the public firehose (§2.1). They have their own address grammar, their own set-commitment primitive, their own credential JWTs, their own storage tables, and their own two-hop push-then-pull sync protocol. Everything is aligned to the **0016 Permissioned Data draft** (`crates/atproto-space/src/lib.rs:30`), and the crate's spec citations are line-numbered into that draft.

Two caveats bound this section. First, wire-shape conformance **can** be computed and **was**: the draft `com.atproto.space.*` / `com.atproto.simplespace.*` lexicons exist on the `bluesky-social/atproto` `permissioned-data` branch (HEAD `3f6c96d`, 2026-07-02) and were fetched to `/tmp/gap-scratch/lex-0016/`; the NSID-by-NSID results live in [../permissioned/40-permissioned-overview.md](./permissioned/40-permissioned-overview.md) rather than here (see §3.10). What remains genuinely uncertain is not the comparison but its shelf life — 0016 is an explicitly work-in-progress draft, so a divergence recorded today is a statement about interop with an in-flight design, not about correctness. Second, `PERMISSIONED-DATA-CONFORMANCE-REVIEW.md` at the worktree root is **stale relative to the code it describes**: its §1 items 1, 3, 4 and 5 (unverified space credentials on host reads; `listRepos` accepting OAuth; rev-granular oplog cursor tail-skip; stubbed `declared_collections`) are all fixed in the current tree — see `space_handlers.rs:1766-1816`, `space_handlers.rs:2336`, `crates/atproto-space/src/storage.rs:22-64`, `crates/atproto-pds/src/space/declaration.rs`. Code is the authority throughout.

### 6.1 Addressing and root of trust

A space is a 3-tuple `(space_did, space_type, space_key)` rendered as an `ats://` URI. `ATS_SCHEME = "ats://"` is `crates/atproto-space/src/types.rs:13`; the struct is `types.rs:93-102`; wire form `ats://<authority-did>/<space-type>/<space-key>` is `types.rs:154-162` (`Display`) and `types.rs:120-151` (`parse`). Parsing requires the `ats://` prefix, exactly three non-empty `/`-separated segments, and a first segment starting with `did:` (`types.rs:142-144`).

| Component | Rule | Cite |
|---|---|---|
| `SpaceType` | NSID: ≥3 dot-separated segments, each non-empty, `[A-Za-z0-9-]`, no leading/trailing `-` | `types.rs:287-301` |
| `SpaceKey` | rkey syntax: 1–512 UTF-8 bytes, charset `[A-Za-z0-9._:~-]`, not `.` or `..` | `types.rs:274-283`, cap const `types.rs:48` |
| `space_did` | only `starts_with("did:")` — **no method or format validation** | `types.rs:142` |

Permissioned records are **six**-segment: `ats://<spaceDid>/<spaceType>/<skey>/<authorDid>/<collection>/<rkey>` (`types.rs:186-204`). Parsing requires exactly 6 non-empty segments — a 7th is rejected, not absorbed into rkey (`types.rs:230-233`) — with segment 3 a DID (`types.rs:244`) and segment 4 a valid NSID (`types.rs:249`). The author DID is part of the address because records are **not colocated**: each author's records live in that author's own per-actor store (`types.rs:190-193`, URI built at `crates/atproto-pds/src/space/writer.rs:275-278`).

Multiple spaces per authority are supported — `space.uri` is the PK (`migrations/actor/20260501000001_init.sql:69-84`), so any number of `(type, skey)` pairs coexist under one authority DID; `createSpace` auto-generates a TID `skey` when omitted (`space_handlers.rs:197-199`); test `list_spaces_filters` creates two spaces for one owner (`space/service.rs:929-955`).

**Authority == owner == `space_did`.** There is no separate `authority_did` / `creator_did` / `owner_did` field. Every ownership check is `uri.space_did != caller`: `createSpace` requires the explicit `did` input to equal the authenticated caller (`space_handlers.rs:186-196`) and defaults the authority to the caller; `updateSpace` (`service.rs:235-239`), `deleteSpace` (`:302-306`), `addMember`/`removeMember` (`:475-479`), `listMembers` (`:504-508`), and `member_state` (`:519-523`) all return `PdsError::NotSpaceOwner` → 403 (`http/errors.rs:58-62`). Owner-as-member is implicit: `SpaceService::is_member` returns `true` unconditionally when `uri.space_did == did` (`service.rs:363-365`), *and* `createSpace` seeds the owner into `space_member` on first creation (`service.rs:94-106`).

Key resolution: the credential-signing key comes from the authority DID document, preferring `#atproto_space` and falling back to `#atproto` (0016 line 92's MAY-coincide allowance) — `http/space_auth.rs:301-321`. The host endpoint prefers `#atproto_space_host`, falls back to `#atproto_pds` — `space_auth.rs:329-350`. For locally-hosted authorities the PDS uses the account's own signing key (`space/reader.rs:236-254`).

A space type NSID resolves to a `com.atproto.lexicon.schema` record whose `defs.main` is `{"type":"space", key, name, collections[]}` (`space/declaration.rs:38-48`, parsed at `:140-150`). Resolution runs NSID → `_lexicon.<name>.<reversed-authority>` DNS TXT → authority DID → DID doc → `AtprotoPersonalDataServer` → `com.atproto.repo.getRecord` (`declaration.rs:94-132`, DNS name construction `:155-166`). It is fail-closed — any failure yields `None` and an empty collection set (`declaration.rs:22-25`, consumed at `space_handlers.rs:2005-2023`) — with a TTL cache including negative caching (`declaration.rs:202-254`).

### 6.2 Membership and the LtHash commitment

The member list lives in the **authority's** per-actor SQLite DB: `space_member (space, did, member_rev, added_at)` PK `(space, did)` (`migrations/actor/20260501000001_init.sql:111-117`), plus `space_member_state (space PK, set_hash BLOB, rev TEXT)` (`:86-90`) and `space_member_oplog (space, rev, idx, action, did)` (`:131-138`). The SQL impl is `actor_store/sql/space_members_storage.rs` (`SqlSpaceMembersStorage`); the trait is `SpaceMembersStorage` (`crates/atproto-space/src/storage.rs:287-309` — `current_state`, `is_member`, `list_members`, `apply_commit`); the orchestrator is `SpaceMembers` (`crates/atproto-space/src/space_members.rs:56-166`).

A second, fjall-backed impl exists (`actor_store/fjall/space_members_storage.rs:32`, key layout `member_key = <space_uri>\0<did>` at `actor_store/fjall/keyspace.rs:243-249`) and is **dead code from the PDS's perspective**: `grep -rn "FjallSpace" crates/atproto-pds/src` matches only the fjall module itself and its own tests. Every PDS call site hardcodes `SqlActorStore` + `SqlSpaceMembersStorage`/`SqlSpaceRepoStorage` (`service.rs:95`, `service.rs:482`, `writer.rs:120-123`, `reader.rs:101-110`, `sync.rs:47-50`).

Only the authority may mutate the list. `apply_member_op` (`service.rs:468-494`) rejects `uri.space_did != owner_did` before anything else, then `ensure_not_deleted`. At the HTTP layer `add_member`/`remove_member` additionally require OAuth `space:…?manage=update` (`space_handlers.rs:498-502`, `:519-523`); the subject DID passed to the service *is* the bearer's own DID (`:496`, `:517`), so a non-authority caller is caught by the `NotSpaceOwner` check. Commits go through `SpaceMembers::format_commit(&[MemberOp])` → `PreparedMemberCommit` → `apply_commit`, atomic in one SQL transaction (`sql/space_members_storage.rs:116-152+`). `format_commit` (`space_members.rs:94-158`) loads current state, rehydrates the SetHash, checks duplicate-add (`MemberAlreadyExists`, `:112-116`) and remove-non-member (`NotAMember`, `:124-129`), mutates the lattice, generates one TID `rev` shared by the batch, and emits oplog entries with dense `idx`.

**There is no signed member commit**, explicitly documented at `service.rs:465-467` and `space/sync.rs:17-19`: "The 0016 Permissioned Data draft has no member commits or member-list sync." No `create_commit` call exists in the member path and there is no member-oplog read endpoint. The member `set_hash` is a local commitment only. The in-memory test store even drops the member oplog entries (`space_members.rs:271-273`).

The set commitment is **LtHash**, in `crates/atproto-space/src/set_hash.rs`. Trait `SetHash` is `:39-73`; the single production impl is `LtHash` (`:86-90`).

| Property | Value | Cite |
|---|---|---|
| Hash function (element expansion) | **BLAKE3 in XOF mode** | `set_hash.rs:94-104` |
| State size | **2048 bytes** = `LANES(1024) * 2` | `set_hash.rs:30-32` |
| Lane layout | 1024 lanes of `u16`, **little-endian**, lane *i* = `u16::from_le_bytes([buf[2i], buf[2i+1]])` | `set_hash.rs:99-103`, `:128-136` |
| `empty()` | all-zero lanes | `set_hash.rs:108-112` |
| `add(e)` | expand `e` → 1024 lanes; `lane = lane.wrapping_add(other)` — mod 2^16 | `set_hash.rs:114-119` |
| `remove(e)` | `lane = lane.wrapping_sub(other)` — mod 2^16, **total** (no membership check; negative states allowed) | `set_hash.rs:121-126`, doc `:46-52` |
| `state_bytes()` | the 2048-byte LE serialization (this is what is persisted) | `set_hash.rs:128-136` |
| `from_state_bytes()` | rejects any length ≠ 2048 → `SpaceError::SetHashCodec` | `set_hash.rs:138-152` |
| `digest()` (the 32-byte commitment in a `Commit.hash`) | **`sha256(state_bytes())`** | `set_hash.rs:154-156` |

It is homomorphic and incremental: order-independent and add/remove-inverse (tests `set_hash.rs:200-220`), lane arithmetic wraps at 65536 (`:242-250`). `format_commit` rehydrates the prior 2048-byte state and applies only the deltas, never recomputing from scratch (`space_repo.rs:128-132`, member equivalent `space_members.rs:95-99`); an update is `remove(old_element)` then `add(new_element)` (`space_repo.rs:201-206`).

Element encodings are interop-critical and byte-exact: a **record element** is UTF-8 of `"{collection}/{rkey}/{cid}"` (`set_hash.rs:167-169`, slash before the CID; test `:259-264`); a **member element** is the bare DID UTF-8 bytes (`set_hash.rs:176-178`). The empty-repo commitment is `sha256(2048 zero bytes)` = `e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad`, **not** 32 zero bytes (`set_hash.rs:186-198`). The PDS binds the algorithm in one place: `pub type PdsSetHash = atproto_space::set_hash::LtHash` (`crates/atproto-pds/src/realm.rs:24`), `SET_HASH_NAME = "lthash"` (`realm.rs:28`). No XOR or ltHash-alternative impl exists.

### 6.3 Credentials — four token shapes

`crates/atproto-space/src/credential.rs` defines two; the PDS verifies a third and mints/verifies a fourth.

**Delegation token**

| Field | Value | Cite |
|---|---|---|
| `typ` header | `atproto-space-delegation+jwt` | `credential.rs:40` |
| `kid` header | `#atproto` | `credential.rs:46` |
| `alg` | `ES256` (P-256) or `ES256K` (K-256) — anything else (P-384, Ed25519) **rejected at mint and verify** | `credential.rs:150-157` |
| Signer | the **member's** atproto signing key | `credential.rs:273-295` |
| TTL | **60 s** (`DELEGATION_TOKEN_TTL_SECS`) | `credential.rs:52` |
| Claims | `iss` (member DID), `aud` = `<spaceDid>#atproto_space_host`, `sub` = the `ats://` space URI, `iat`, `exp`, `jti` (UUIDv4-shaped from OS RNG) | `credential.rs:72-87`, `:281-288`; audience helper `:59-62`; jti gen `:120-144` |
| No `lxm`, no `client_id` | asserted by test | `credential.rs:476-494` |

**Space credential**

| Field | Value | Cite |
|---|---|---|
| `typ` header | `atproto-space-credential+jwt` | `credential.rs:43` |
| `kid` header | `#atproto_space` | `credential.rs:49` |
| `alg` | ES256 / ES256K only | `credential.rs:150-157` |
| Signer | the **authority's** space signing key | `credential.rs:351-374` |
| TTL | **7200 s / 2 h** (`SPACE_CREDENTIAL_TTL_SECS`); overridable per-deployment via `HttpState::space_credential_ttl_secs` | `credential.rs:55`; `http/state.rs:103,150,193,340` |
| Claims | `iss` (authority DID), `sub` (`ats://` URI), `client_id` (snake_case; **omitted entirely** when no attestation), `iat`, `exp`, `jti`. **No `aud`.** | `credential.rs:90-107`, `:360-367`; tests `:596-634` |

Both use compact `b64url(header).b64url(payload).b64url(sig)` with the signature over `"<header>.<payload>"` (`credential.rs:171-199`).

**Client attestation** (verified, never minted by the PDS) — `crates/atproto-pds/src/space/mint_authz.rs`, `typ = atproto-client-attestation+jwt` (`:146`). Checks in order (`:229-377`): compact-JWS shape (`:237-240`); `typ` exact match (`:252-261`); `iss == sub` and an `https://` client-metadata URL (`:264-272`); `aud == <spaceDid>#atproto_space_host` (`:275-284`); `iat`/`exp` present, unexpired, lifetime ≤ **300 s** (`MAX_ATTESTATION_LIFETIME_SECS`, `:206`, `:288-302`); `jti` present and **consumed through the replay guard before the signature check** (`:306-314`); client-metadata fetch with inline `jwks` winning over `jwks_uri` (`:317-348`); key selected by `kid`, or the sole JWK when `kid` absent — multi-key + no `kid` is rejected (`:351-363`); ECDSA verification over `header.payload` (`:369-374`).

**Inter-PDS service auth** — `crates/atproto-pds/src/space/service_auth.rs`: `typ = "at+jwt"` (`:28`), TTL 60 s (`:31`), claims `{iss, aud, lxm, iat, exp, jti}` (`:42-57`). Details and gaps in §5.5.

**The exchange flow** is two steps. `GET com.atproto.space.getDelegationToken` mints the delegation token for a member holding OAuth **with a `client_id`** (app-password sessions rejected, 403) plus `space:…?action=read` — `space_handlers.rs:1419-1461`, client_id gate `:1432-1438`, scope gate `:1442-1449`, mint `:1452`. `POST com.atproto.space.getSpaceCredential` exchanges it, with the delegation token itself as the bearer and no other auth — `space_handlers.rs:1484-1736`. Internals: bearer read (`:1492`), unverified `iss` peek (`:1498`), verify against the **local** account key first (`:1504`), and on `404 AccountNotFound` fall back to **remote** DID-document resolution (`:1506-1525`, resolver `space_auth.rs:209-242`); the delegation `jti` is consumed for single use *before* minting (`:1531-1542`); mint-time authz runs (§6.5); the credential is minted at `:1645-1658`; the consumer self-registers as a notify recipient at `:1708-1733`.

What verification actually checks: `verify_delegation_token` (`credential.rs:307-338`) → shared `verify_jwt` (`:201-253`) validates 3-part shape, header `typ` (`:219-225`), header `kid` (`:226-232`), header `alg` matching the key's algorithm (`:233-240`), the **ECDSA signature** (`:242-245`), then `aud == <expected_authority>#atproto_space_host` (`:320-327`), `sub == expected space URI` (`:328-335`), and `exp > now` (`:336`, `check_exp` at `:255-261`). `verify_space_credential` (`:385-415`) follows the same header/signature path, then `iss == expected authority DID` (`:398-404`), `sub == expected space` (`:405-412`), `exp` (`:413`). So: signature yes, audience yes (delegation only — the space credential has no `aud` by design), expiry yes, space binding yes via `sub`. There is no `nbf` and no clock-skew allowance; `exp <= now` is a hard fail. `jti` single-use is *not* in the crate — the caller enforces it (`space_handlers.rs:1532-1542` for delegation, `mint_authz.rs:311` for attestation), backed by `JtiReplayGuard` (memory-LRU / SQLite / Valkey, `crates/atproto-pds/src/security.rs:44-95`).

**Gap:** PDS-side credential verification at read time resolves the authority's public key from the **local accounts table only** (`reader.rs:236-254`), so a PDS that is not the authority's host cannot verify a presented credential — it 404s on `account … signing_key_ref`. Remote resolution exists (`space_auth.rs:301-313`, `remote_space_credential_key`) but is **not wired** into `SpaceReader::verify_auth`.

### 6.4 Write path, read path, and storage

Permissioned state lives entirely in the per-actor SQLite file, one per DID (`SqlActorStore::open(data_dir, did)`). Each member's space records live in that member's own DB — there is no shared per-space database.

| Table | Purpose | Cite |
|---|---|---|
| `space` | PK `uri`; `is_owner`, `is_member`, `created_at`, `mint_policy`, `app_access`, `managing_app`, `deleted_at` | `init.sql:69-84` |
| `space_repo` | per-space record commitment: `space PK, set_hash BLOB, rev TEXT` | `init.sql:92-96` |
| `space_record` | PK `(space, collection, rkey)`; `cid`, `value BLOB` (DAG-CBOR), `repo_rev`, `indexed_at`; index on `(space, repo_rev)` | `init.sql:98-109` |
| `space_record_oplog` | PK `(space, rev, idx)`; `action`, `collection`, `rkey`, `cid`, `prev` | `init.sql:119-129` |
| `space_member` / `space_member_state` / `space_member_oplog` | §6.2 | `init.sql:86-90`, `:111-117`, `:131-138` |
| `space_credential_recipient` | PK `(space, repo, service_did)`; `repo=''` is the whole-space sentinel; `service_endpoint`, `last_issued_at`, `expires_at` | `init.sql:155-163` |
| `space_received_op` | PK `(space, rev, nsid)`; `issuer_did`, `set_hash BLOB`, `received_at` | `20260506000001_space_received_op.sql:16-26` |
| `space_record_takedown` | PK `(space, collection, rkey)`; `taken_at` | `20260506000002_space_record_takedown.sql:18-27` |

`SqlSpaceRepoStorage` is `actor_store/sql/space_repo_storage.rs`. `apply_commit` (`:154-249`) runs record changes + oplog inserts + the `space_repo` upsert inside **one** `sqlx` transaction (`:159-163`, `:245-247`), and lazily inserts a `space` row with `is_owner=0, is_member=0` to satisfy the FK (`:34-48`) — which means a *reader/writer's* store holds a shell row for spaces it does not own. `read_oplog` uses `(rev > ? OR (rev = ? AND idx > ?)) ORDER BY rev, idx` (`:270-283`), which is what makes an atomic batch larger than `limit` page fully (regression test `:401-444`). Fjall equivalents exist but are unreachable (§6.2): `actor_store/fjall/space_repo_storage.rs`, key layouts `record_key = <space>\0<collection>\0<rkey>` (`keyspace.rs:212-220`), `oplog_key = <space>\0<rev>\0<idx:010>` (`:265-273`), `repo_state_key = <space>` (`:235-237`); values are **JSON**-encoded (`space_repo_storage.rs:66-71`) and commits use a native fjall `WriteBatch`.

The write path is `SpaceWriter::apply_writes_locked` (`writer.rs:254-353`): (1) per-`(member_did, space_uri)` `tokio::sync::Mutex` from a `DashMap` (`writer.rs:64`, `:95-100`, acquired `:116-117`); (2) auto-TID for an empty rkey on Create (`:266-270`); (3) six-segment output URI including the author DID (`:275-278`); (4) value → **DAG-CBOR** via `atproto_dasl::to_vec`, CID via `atproto_dasl::cid::compute_cid` (`:285-289`); (5) `repo.format_commit` — incremental LtHash + oplog (`:307`); (6) resolve the member's signing key via `account.signing_key_ref` → `KeyStore` (`:316-329`); (7) **`create_commit(...)` is called and the result is discarded** — `let _signed_commit = …` at `writer.rs:334-335`, since only `{set_hash_state, rev}` is persisted and `space_repo` has no signature column; (8) `repo.apply_commit` — durable (`:337`); (9) best-effort `notifyWrite` to the owner PDS (`:344`).

**Commits are signed on demand at read time, not stored.** `create_commit` (`crates/atproto-space/src/commit.rs:113-121`) builds:

```
hash := setHash.digest()                       // sha256(2048-byte state) = 32 bytes
ikm  := 32 random bytes (OS RNG)               // fresh per commit — commit.rs:118-119
ctx  := "atproto-space-v1" || u16be(len(space))||space || u16be(len(rev))||rev || u16be(len(ikm))||ikm
sig  := ECDSA_sign(user_signing_key, ctx)      // NEVER over `hash` — commit.rs:141-145
mac  := HMAC-SHA256(HKDF-Expand-only(prk=ikm, info=ctx, 32B), hash)  // commit.rs:160-175
```

`ctx` encoding is `commit.rs:71-81` with the domain tag `"atproto-space-v1"` at `commit.rs:50` (no length prefix on the tag itself). HKDF is **expand-only**, `Hkdf::from_prk(ikm)`, no salt, no extract (`commit.rs:161-168`). Verification: `verify_commit` recomputes the MAC constant-time (`commit.rs:188-216`, rejecting `ikm.len() != 32` at `:189-193`); `verify_commit_signature` checks `sig` over the reconstructed `ctx` (`commit.rs:228-236`). The deniability rationale is documented at `commit.rs:28-32`. Signing happens in the HTTP layer at `getRepoState` and caught-up `listRepoOps` via `signed_commit_from_state` (`space_handlers.rs:1210-1238`), using `local_signing_key(manager, q.repo)` — the **repo account's** key, which requires the repo to be local to this PDS. Wire form is atproto lex-data `{"$bytes": "<base64 standard, unpadded>"}` for `hash`/`mac`/`ikm`/`sig` (`space_handlers.rs:1146-1189`). Because `ikm` is regenerated on every call, two `getRepoState` calls for an unchanged repo return different `mac`/`sig`/`ikm` with an identical `hash`.

**Three commit-format divergences against the 0016 draft, verified by opening both sides.** The oracle is the 0016 README (`/tmp/gap-scratch/0016-README.md`, raw from `bluesky-social/proposals` main) plus the draft lexicon defs (`/tmp/gap-scratch/lex-0016/space/defs.json`, from the atproto `permissioned-data` branch at HEAD `3f6c96d`, 2026-07-02). 0016 is a moving WIP draft and this crate's own code anticipates churn (`crates/atproto-space/src/types.rs:5` notes the scheme "can change without …"), so these are drift against a spec that moved, not carelessness. They are hard interop breaks today.

- **`ctx` omits the author DID.** The spec (`0016-README.md:306-310`) specifies `ctx = "atproto-space-v1" || u16be(len(space))||space || u16be(len(author))||author || u16be(len(rev))||rev || u16be(len(ikm))||ikm`, corroborated by `lex-0016/space/defs.json`, whose `signedCommit.sig` reads "Signature over ctx (space, author DID, rev, ikm) by the user's atproto signing key." This implementation has `SpaceContext { space, rev }` (`crates/atproto-space/src/commit.rs:59-64`) and `encode_ctx` emits only `[space, rev, ikm]` (`commit.rs:71-81`). The author DID is never bound. Both `sig` and `mac` are therefore computed over different bytes than any conformant peer produces, so every commit this implementation emits fails verification by a conformant reader, and vice versa. It also drops the spec's explicit author binding, weakening what the signature attests to within a space.
- **`ver` is absent from the signed commit.** `lex-0016/space/defs.json` gives `signedCommit.required = ["ver","hash","mac","ikm","sig","rev"]` with `ver` an integer, currently 1 (also `0016-README.md:325`, `:332`). The `Commit` struct carries `hash`, `mac`, `ikm`, `sig`, `rev` only (`commit.rs:87-103`), and its own doc comment at `commit.rs:85` asserts "Wire field order matches the lexicon required set `[hash, mac, ikm, sig, rev]`" — a statement that is now stale. Emitted commits fail lexicon validation on a required field, and there is no version discriminator with which to negotiate future commit-format changes.
- **The URI scheme is `ats://`, not the spec's `at://…/space/…`.** `ATS_SCHEME` is `"ats://"` (`crates/atproto-space/src/types.rs:13`), giving space URIs `ats://<authority-did>/<space-type>/<space-key>` (`types.rs:89`, `:114`) and record URIs `ats://<spaceDid>/<spaceType>/<skey>/<authorDid>/<collection>/<rkey>` (`types.rs:187`). The spec form is `at://{spaceDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}` (`0016-README.md:307`), and the draft lexicons type the `space` param as `"format": "at-uri"` (`lex-0016/space/getLatestCommit.json`, `getRepo.json`, `listRepoOps.json`). This fails twice over: a param typed `at-uri` rejects an `ats://` value under lexicon validation, and because `space` is length-prefixed into `ctx`, the differing string changes the signed bytes even if the first two items were fixed. The scheme fix and the `ctx` fix must land together.

**Checked and conformant:** per-call `ikm` regeneration — the fact that `mac`/`sig` differ across calls for an unchanged repo — is **correct**, not a bug. `0016-README.md:315` states "A new `ikm` is generated for each reader the commit is served to."

**Integration status, stated for fairness.** Unlike some surveyed implementations, the deniable commit here is genuinely wired into the live write path: `create_commit` (`crates/atproto-space/src/commit.rs:118-143`) is invoked from `crates/atproto-pds/src/space/writer.rs:335`; record CIDs are real DAG-CBOR CIDs computed via `atproto_dasl` (`space/writer.rs:285-288`); LtHash is the real lattice hash the spec selects; and client attestation is verified end-to-end (`crates/atproto-pds/src/space/mint_authz.rs:229-376`). The accurate characterisation is a correct architecture running with a wrong `ctx` byte layout — a surgical fix — rather than an absent implementation. The comparative framing belongs to [`./permissioned/40-permissioned-overview.md`](./permissioned/40-permissioned-overview.md) and [`./permissioned/42-happyview.md`](./permissioned/42-happyview.md).

**Membership is NOT enforced at write time**, stated explicitly at `space/writer.rs:6` ("The PDS does not enforce membership at write time; consumers check at sync") and `reader.rs:13-17`. `SpaceWriter::apply_writes` (`writer.rs:104-127`) does per-(member DID, space URI) mutex → `ensure_space_live` (tombstone gate) → open the **writer's own** store → commit. No `space_member` lookup appears anywhere in `writer.rs`. What *is* enforced at write time: session/OAuth authn (`space_handlers.rs:636` / `:734` / `:784` / `:834`); `repo` must equal the bearer subject (`require_repo_matches_subject`, `space_handlers.rs:857-867`, called at `:736`, `:786`, `:836` → 403 `InvalidRequest`); per-op OAuth `space:` scope with the op's collection (`:674` applyWrites, `:738` create, `:791`+`:799` put — which requires **both** create and update — `:838` delete), with a shortfall producing 403 `InvalidToken` and the needed scope string (`:1901-1908`); and the space tombstone (`ensure_space_live` at `writer.rs:119`, `:167`, `:211` → `PdsError::SpaceNotFound`).

At read time, `resolve_record_auth` (`space_handlers.rs:1080-1124`) dispatches on JWT `typ`: a **SpaceCredential** requires the `repo` param (400 `InvalidRequest` if missing, `:1088-1094`), skips the OAuth scope gate entirely (`subject: None`, `:1098`), and is fully verified in `SpaceReader::verify_auth` (`reader.rs:214-229`); a **delegation token** is rejected outright, 400 `InvalidToken` (`:1101-1105`); **OAuth/session** goes through `require_authn` (DPoP enforced when `cnf.jkt` present) with `repo` defaulting to the subject (`:1110-1121`). Scope checks on reads: `getRecord` at `:928`, `listRecords` at `:1023` (passing `collection`, which may be `None`), `getBlob` whole-space `read` at `:2218`. `assert_space_record_read` (`:1960-1993`) grants own-repo + single-collection via `read_self` (also satisfied by `read`), and own-repo cross-collection **or any other member's repo** only via whole-space `read`. Host/sync reads (`getSpace`, `getRepoState`, `listRepoOps`) use `require_any_authn` (`:1766-1787`) + `assert_space_read_opt` (`:1839-1857`), with SpaceCredential bearers skipping the scope check but having their credential verified against the space (`:1772-1783`). `listRepos` is **space-credential only**, OAuth rejected 401 (`require_space_credential`, `:1793-1816`, called at `:2336`).

Write-time membership is a **documented design decision, not an oversight** — `space/writer.rs:6` states it outright, and the model pushes authorization to the consumer. The legitimate criticism is the consequence, which is real: a removed member can continue writing to their own per-actor store in that space, and every consumer must independently filter, so the security property depends on every reader implementing that filtering correctly.

**Membership is not checked at read time either.** `SpaceReader` never consults `space_member`; the only `is_member` call site in the whole HTTP layer is the inbound `notifyWrite` fan-out gate (`space_handlers.rs:2124-2134`). Consequence: a valid space credential for space *S* plus an arbitrary `repo=<did>` reads that DID's *S* records from this PDS's local stores, with no verification that `<did>` is a member. For the session/OAuth flavour specifically, `verify_auth` returns `Ok(())` for `SpaceReadAuth::OwnPds` (`space/reader.rs:214-216`), documented as relying on the HTTP-layer OAuth/session check — and the reference draft implementation behaves the same way on both halves: its `assertSpaceScope` opens with `if (auth.credentials.type !== 'oauth') return` (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/space/util.ts:32-37`), and its `getRecord` handler takes `repo` verbatim from `params` into `ctx.actorStore.read(repo, …)` with no caller-versus-target comparison and no membership lookup (`.../space/getRecord.ts`). This is a shared gap in the draft design, not an implementation-specific defect, and should be tracked as 0016 firms up rather than scored against this codebase.

Two further gaps. **`listSpaces` has no `space:` scope gate** — `space_handlers.rs:461-478` calls only `require_session_subject` (`:466`), with no `assert_space_scope`; every other space endpoint gates. And **`getSpace` has a viewer discrepancy**: the doc comment at `space_handlers.rs:423-424` says the config is described "from the authority's store", but the code passes `subject.sub()` as the viewer when OAuth-authenticated (`:425-428`), and `SpaceService::get_space` opens *that* DID's per-actor store (`service.rs:133`). Only the credential path (`subject == None`) falls back to `uri.space_did`.

What an unauthorized read returns is **inconsistent by design surface, not by intent**:

| Case | Status / name | Cite |
|---|---|---|
| No/invalid space credential on record reads | 403 `Forbidden` (`PdsError::AuthDenied` → `StatusCode::FORBIDDEN`) | `reader.rs:220-225`; mapping `http/errors.rs:63-65` |
| No/invalid space credential on host/sync reads (`getSpace`, `getRepoState`, `listRepoOps`) | **401 `Unauthorized`** | `space_handlers.rs:1776-1782` |
| `listRepos` with an OAuth bearer instead of a credential | **401 `Unauthorized`** | `space_handlers.rs:1800-1804` |
| Insufficient OAuth `space:` scope | **403 `InvalidToken`** | `space_handlers.rs:1901-1908`, `:1937-1944` |
| Record absent **or taken down** | **404 `RecordNotFound`** — the takedown gate is indistinguishable from absence | `space_handlers.rs:947-953`; gate `reader.rs:104-106` |
| Tombstoned space (`deleted_at` set) | **400 `SpaceNotFound`** via `PdsError::SpaceNotFound` | `http/errors.rs:53-57` |
| … except in `getSpaceCredential`, `listRepos`, `registerNotify`, which construct 404 `SpaceNotFound` / 404 `SpaceDeleted` directly | 404 | `space_handlers.rs:1579-1592`, `:2357-2363`, `:2468-2474` |
| Non-authority attempting owner ops | 403 `NotSpaceOwner` | `http/errors.rs:58-62` |

Record-level denial degrades to 404 (good — no existence oracle for takedowns), auth failures are 403/401, and `SpaceNotFound` is 400 through the generic error mapping but 404 when constructed inline.

### 6.5 Mint policy and app access

Two independent axes, both of which must pass. Both live in `crates/atproto-pds/src/space/config.rs` + `mint_authz.rs`.

**USER axis — `mintPolicy`.** `enum MintPolicy` (`config.rs:35-47`) has wire values `public` | `member-list` (**default**) | `managing-app` (`config.rs:52-58`, `:61-70`; unknown values rejected). The decision is `mint_authz.rs:101-115`: `public` authorizes anyone; `member-list` authorizes iff `is_member`, else `MintDenial::UserNotAuthorized`; `managing-app` returns `Ok(None)`, deferring to a network call. That call — `check_user_access` (`mint_authz.rs:400-453`) — resolves the `managingApp` service identifier to an endpoint (`space_handlers.rs:1609-1622`) and `GET`s `com.atproto.simplespace.checkUserAccess?space=&user=&clientId=` with a 60 s `at+jwt` service-auth bearer signed by the authority, `lxm = com.atproto.simplespace.checkUserAccess` (`mint_authz.rs:475-512`). `{authorized:false}` → `UserNotAuthorized`; unreachable → `NotAuthorized`. **This PDS does not serve `checkUserAccess`** — no route exists in `router.rs`; it is outbound-only.

**APP axis — `appAccess`.** `enum AppAccess` (`config.rs:77-87`) is an open union with `$type` refs `com.atproto.simplespace.defs#open` (default) and `#allowList { allowed: [client_id] }` (`config.rs:25-29`). The decision is `mint_authz.rs:128-143`: `#open` authorizes with or without an attestation; `#allowList` authorizes **only** if a *verified* attestation yielded a `client_id` present in `allowed` — unlisted → `AppNotAuthorized`, no attestation at all → `AppNotAuthorized`. There is **no denylist** (`AppAccess` has exactly two variants; storage form is `{"type":"open"}` / `{"type":"allowList","allowed":[…]}`, `config.rs:92-99`, column default `'{"type":"open"}'`, `init.sql:78`). There is **no `accessMode`** field anywhere in the crate.

Storage is three columns on `space`: `mint_policy TEXT NOT NULL DEFAULT 'member-list'`, `app_access TEXT NOT NULL DEFAULT '{"type":"open"}'`, `managing_app TEXT` (`init.sql:74-80`), set at `createSpace` (`service.rs:63-77`), patched field-wise at `updateSpace` (`service.rs:259-294`; `managingApp: ""` clears to NULL at `:280-285`), and surfaced by `getSpace` as `{"$type":"com.atproto.simplespace.defs#spaceConfig", mintPolicy, appAccess, managingApp?}` (`config.rs:229-239`). `MintDenial` variants map to lexicon error names `UserNotAuthorized` / `AppNotAuthorized` / `InvalidClientAttestation` / `NotAuthorized` (`mint_authz.rs:66-74`); `InvalidClientAttestation` → 400, everything else → 403 (`space_handlers.rs:2035-2047`).

Separate from mint policy is the OAuth `space:` scope model (`crates/atproto-oauth/src/scopes/space_permission.rs`). Actions are `read_self` (own repo, collection-constrained, does **not** grant `getDelegationToken`), `read` (all repos, ignores collection, grants `getDelegationToken`, implies `read_self`), `create`, `update`, `delete` (`space_permission.rs:70-84`). The default action set when the param is omitted is `{read, create, update, delete}` (`:97-100`). Manage verbs are `create` | `update` | `delete` (`:139-146`). Scope string form is e.g. `space:com.example.space?did=…&skey=…&collection=…&action=read&action=create` (`crates/atproto-oauth/src/scopes.rs:2432`), with wildcard `space:*` (`scopes.rs:2376`).

### 6.6 Sync, notification, and reconciliation

Sync is **two-hop push, then pull**.

**HOP 1 — writer PDS → owner PDS.** `SpaceWriter::fire_notify_write` (`writer.rs:364-461`) resolves `<ownerDid>#atproto_pds` from the DID doc (`:379-404`), mints a 60 s service-auth token `lxm=com.atproto.space.notifyWrite` (`:406-422`), and POSTs `{space, repo, rev}` (`NotifyWritePayload`, `notify.rs:48-56`; NSID const `notify.rs:43`). Entirely best-effort — every failure is logged and swallowed (`:441-460`); a write never fails on a missed notification.

**Owner-side receipt + HOP 2 fan-out.** The `notify_write` handler (`space_handlers.rs:2069-2178`) decodes → parses the space → `verify_service_auth(aud = space.space_did, lxm = notifyWrite)` (`:2096-2104`) → requires **`claims.iss == payload.repo`** (`:2107-2113`, 403) → if the owner is local, requires **`is_member(space, payload.repo)`** or 403 (`:2124-2134`) → `enqueue_writes` fan-out (`:2140-2147`) → persists a receipt (`:2168-2176`). `enqueue_writes` (`notify.rs:179-199` → `enqueue_for_space` `:202-245`) reads matching `space_credential_recipient` rows and appends one `notify_attempt` per recipient with a per-recipient service-auth token (`iss = authority`, `aud = recipient service DID`). Recipient matching (`list_recipients`, `notify.rs:75-109`): expired rows skipped, `repo = ''` whole-space rows always match, per-repo rows match only when `repo == writer_repo`. Actual delivery is `crate::notifier::Notifier::tick` (`notify.rs:12`).

Subscription registration happens two ways (`notify.rs:26-31`): `getSpaceCredential` self-registers the consumer whole-space with no expiry (`upsert_recipient`, `notify.rs:115-130`; called `space_handlers.rs:1710-1716`), and `POST com.atproto.space.registerNotify` (`space_handlers.rs:2434-2517`) is **space-credential-only** (`:2445-2451`), verified against the authority's key (`:2481-2493`), keyed on `credential.client_id` falling back to `credential.iss` (`:2499-2502`), TTL **24 h** (`REGISTER_NOTIFY_TTL_SECS`, `:2426`), returning `{expiresAt}`.

**PULL side** is `SpaceSync` (`space/sync.rs`): `get_repo_state(space, repo_did)` → `RepoState {set_hash (full 2048-byte state), rev}` from the **repo account's** store (`sync.rs:45-52`), tombstone-gated (`:46`); and `list_repo_ops(space, repo_did, since, limit)` → `OplogPage` (`sync.rs:56-68`) — **with no `ensure_space_live` on this path**, unlike `get_repo_state`. The cursor is `(rev, idx)`-granular, wire-encoded `"<rev>__<idx>"` (`crates/atproto-space/src/storage.rs:22-64`), consumed at `space_handlers.rs:1331-1340` and re-emitted at `:1349-1355`. `listRepoOps` attaches the freshly-signed commit **only when caught up** (`ops.len() < limit`) — `space_handlers.rs:1346`, `:1368-1374`.

Reconciliation is partial. Receipt dedup is `INSERT OR IGNORE INTO space_received_op` keyed `(space, rev, nsid)` (`space/inbound.rs:60-63`), so re-delivery is an idempotent 200 (`inbound.rs:11`). Writer-set discovery via `com.atproto.space.listRepos` derives `{did, rev}` from `SELECT issuer_did, MAX(rev) … GROUP BY issuer_did` over the owner's `space_received_op` (`space_handlers.rs:2366-2384`) — so the writer set is *observed from notifications*, not from the member list, and **a member who wrote while notifications were failing never appears**. The oplog-gap signal `SpaceError::OplogGap` is declared (`crates/atproto-space/src/errors.rs:155-162`) and documented in the trait (`storage.rs:277`), but **neither the SQL nor the fjall `read_oplog` ever returns it** — no retention/pruning exists on that path, so the variant is currently unreachable. There is **no state-comparison / rebuild loop and no anti-entropy sweep** in this repo; the syncer role is explicitly out of scope. The consumer half of the loop is demonstrated in `walking-club-appview/`, which serves `/xrpc/com.atproto.space.notifyWrite` (`walking-club-appview/src/server.rs:59`), keeps a `registerNotify` keepalive (`walking-club-appview/src/space/notify.rs:36-80`), and pulls on the resulting `NotifyJob` (`space/notify.rs:21`).

### 6.7 Blobs, takedown, deletion

**Blobs.** There is **no space-scoped upload** — `com.atproto.repo.uploadBlob` (`router.rs:66-67`) is the only upload route, there is no `com.atproto.space.uploadBlob`, and `crates/atproto-pds/src/space/` contains no blob code at all (one doc-comment hit at `reader.rs:180`). `com.atproto.space.getBlob` (`space_handlers.rs:2204-2276`) requires an explicit `repo` param (`:2216`), applies the whole-space `read` scope gate for OAuth subjects (`:2218-2226`) and `verify_read_auth` (`:2227-2230`), then reads from the **ordinary** blobstore — the public-realm backend or `crate::blob::get_blob` on the repo's per-actor store (`:2233-2246`) — returning 404 `BlobNotFound` when missing (`:2247-2253`), with `nosniff`, `content-disposition: attachment`, and `content-security-policy: default-src 'none'; sandbox` (`:2262-2274`).

**The permissioned gate is bypassable by CID.** The same bytes are served unauthenticated by `com.atproto.sync.getBlob` (`router.rs:88-89` → `http/blob_handlers.rs:33-72`) — that handler takes no `parts`/bearer and performs no auth check. Anyone who learns a blob CID plus repo DID reads it, permissioned space or not. There is also no blob-ref extraction, no `space_blob` join table, and no per-space refcount or GC linkage: `space_record.value` is opaque DAG-CBOR (`init.sql:98-107`) and nothing walks it for blob refs.

**Takedown of space records.** Table `space_record_takedown (space, collection, rkey, taken_at)` lives in the **owner's** per-actor store (`20260506000002_space_record_takedown.sql:18-27`), applied and lifted by admin-only `com.atproto.admin.takedownSpaceRecord` (`admin/handlers.rs:745-750` for `require_admin`; insert `:768-787`, delete on `takedown:false` `:794-803`). Enforcement is at read: `get_record` returns `Ok(None)` → 404 `RecordNotFound` (`reader.rs:103-106`, `space_handlers.rs:947-953`), and `list_records` filters the page by the taken-down rkey set (`reader.rs:148-152` single-collection, `:163-167` cross-collection), with helpers `is_record_taken_down` (`reader.rs:259-278`) and `taken_down_rkeys` (`:282-299`); test at `reader.rs:628-687`. **Gaps:** the gate is **read-only** — `SpaceWriter` never consults `space_record_takedown`, so the author can still update or delete a taken-down record, and the row remains in `space_record` and in the LtHash commitment. It is also not consulted by `list_repo_ops`, so op metadata (collection/rkey/cid) for a taken-down record still syncs to consumers.

**Space deletion lifecycle.** (1) The authority tombstones: `SpaceService::delete_space` (`service.rs:301-354`) is owner-only, sets `space.deleted_at` (`:310-312`), is idempotent on an already-deleted row and 404/`SpaceNotFound` on a genuinely absent one (`:318-333`), then **purges the authority's own repo data** — `DELETE FROM space_record, space_record_oplog, space_repo WHERE space = ?` (`:344-352`, citing spec line 363) — keeping the `space` row as the tombstone (`:335-343`). (2) The tombstone gate is `ensure_not_deleted` (`config.rs:290-305`) and `ensure_space_live` (`config.rs:319-326`, which is a **no-op when the authority's store is not local**, `:321-323`), wired into writes (`writer.rs:119`, `:167`, `:211`), reads (`reader.rs:74-77` → `get_record:100`, `list_records:136`), `getRepoState` (`sync.rs:46`), member mutations (`service.rs:481`), and `listMembers` (`service.rs:510`); `getSpace` collapses deleted and missing into `SpaceNotFound` (`service.rs:147-151`) and `listSpaces` filters `deleted_at IS NULL` (`service.rs:391`). **Not gated:** `list_repo_ops` (`sync.rs:56-68`) and `getBlob`. (3) Fan-out is `fire_notify_space_deleted` (`space_handlers.rs:314-399`), best-effort after the tombstone is durable, targeting distinct `space_credential_recipient.service_did` ∪ `space_member.did` minus the authority (`:346-366`), resolving each target's `#atproto_pds` endpoint and POSTing `{space}` with a service-auth token `lxm=com.atproto.space.notifySpaceDeleted` (`:372-397`), all errors swallowed (`:397`). (4) On the recipient side, `notify_space_deleted` (`space_handlers.rs:2545-2619`) peeks the unverified `aud` to learn the recipient (`:2563-2569`), runs full `verify_service_auth` against it (`:2570-2578`), then requires `claims.iss == space.space_did` or 401 `UntrustedIss` (`:2579-2585`); a non-DID `aud` or non-local recipient is a silent 200 no-op (`:2588-2599`). The effect is `UPDATE space SET deleted_at = ? WHERE uri = ? AND deleted_at IS NULL` on the recipient's store (`:2606-2617`) — **tombstone only, no purge**, deliberately: the handler documents the PDS as a repo-host (0016 line 365, flag-not-erase) and the "delete every copy" behavior of line 367 as a syncer-role obligation (`:2538-2544`). (5) **Not implemented:** no undelete/restore path; no cascade of `space_credential_recipient` cleanup on tombstone (the FK `ON DELETE CASCADE` never fires because the row is never deleted); no revocation of already-minted space credentials — a 2-hour credential outlives the tombstone, since `getSpaceCredential` refuses to mint new ones with 404 `SpaceDeleted` (`space_handlers.rs:1586-1592`) but `SpaceReader::verify_auth` never rechecks deletion for an existing token beyond `ensure_space_live`, which is itself a no-op for non-local authorities.

### 6.8 Spaces NSID surface

All 24 spaces-related routes are real — no stubs, no `todo!()`, no `unimplemented!()`; every route reaches storage or a real crypto/network operation. The route table is §3.10 plus `com.atproto.admin.takedownSpaceRecord` (`router.rs:402-405` → `admin/handlers.rs:745`).

One NSID is referenced but **not served here**: `com.atproto.simplespace.checkUserAccess` is outbound only, called against a configured `managingApp` (`mint_authz.rs:414`) and scoped as the service-auth `lxm` (`mint_authz.rs:495`). No route exists in `router.rs`.

Other `$type` strings in the namespace: `com.atproto.simplespace.defs#spaceConfig` (`config.rs:25`), `#open` (`config.rs:27`), `#allowList` (`config.rs:29`); `com.atproto.space.defs#signedCommit`, referenced in docs only (`crates/atproto-space/src/commit.rs:83`, `space_handlers.rs:1139`) and implemented as the `SignedCommitDto` Rust struct; and `com.atproto.space.listRecords#record`, `com.atproto.space.listRepoOps#opEntry`, `com.atproto.space.listRepos#repo`, named in doc comments at `space_handlers.rs:988`, `:1278`, `:2293` — again Rust DTOs only.

---

## 7. Ops, tests, docs

### 7.1 Rate limiting, observability, email, notifications

**Rate limiting exists but is narrow, per-identifier-string only, and there is no per-IP limiting anywhere.** The machinery itself is real and reasonably engineered — this must not be characterised as "no rate limiting". `crates/atproto-pds/src/security.rs:305-520` defines `SlidingWindowLimiter` (enum at `:311`, `impl` at `:348`, public `try_acquire` at `:414`, `MemoryLimiterInner::try_acquire` at `:450`, `SqlLimiterInner::try_acquire` at `:506`) with three backends: Memory (in-process per-key deque bounded by `max_keys`, `security.rs:305-306`), Sql (`rate_limit_window` in the accounts DB, `security.rs:307-309`, whose own doc warns "SQL-backed limiting under heavy load can become a bottleneck; Valkey is the recommended production path"), and Valkey/Redis (`valkey_backend.rs:131-211`, per-key `ZSET` with `ZREMRANGEBYSCORE`/`ZCARD`/`ZADD`+`EXPIRE` pipelined atomically). Selection is `bin/pds.rs:533-564` — Valkey wins when the `valkey` feature is compiled **and** `PDS_VALKEY_URL` is non-empty, otherwise `PDS_DURABILITY_PROFILE` picks `sql` or `memory` (`bin/pds.rs:1089-1120`); **the default is `memory`** (`bin/pds.rs:141`), which loses all limiter state on restart. The limit is **300 requests / 60 s per key**, hardcoded and not configurable (`bin/pds.rs:1102-1105`, `:1113-1116`, `:551-554`; `http/state.rs:139`, `:182`).

It is applied at exactly **four** call sites, three of which are unauthenticated endpoints:

| Route | Key | Citation |
|---|---|---|
| `com.atproto.server.createAccount` | `createAccount:{handle}` | `http/auth_handlers.rs:87` |
| `com.atproto.server.createSession` | `createSession:{identifier}` | `http/auth_handlers.rs:300` |
| `com.atproto.server.requestPasswordReset` | `requestPasswordReset:{email}` | `http/auth_handlers.rs:1401-1405` |
| `POST /oauth/token` | `oauth-token:{client_id}` | `oauth/token.rs:104-115` |

The shared helper is `enforce_rate_limit` (`http/auth_handlers.rs:69-77`, returns `429 RateLimited`). `requestPasswordReset` **discards the result** — `let _ = state.rate_limiter.try_acquire(...)` at `:1401`, documented as intentional fail-open at `:1399-1400` — so that site records requests but never rejects. An exhaustive grep for `rate_limiter|try_acquire|SlidingWindowLimiter|RateLimited` over `crates/atproto-pds/src/` finds no other hits outside `security.rs`, `valkey_backend.rs`, `gc.rs` (GC only), and `bin/pds.rs` (wiring only). There is no axum middleware layer applying a limiter. Consequently **unlimited**: every `com.atproto.repo.*` write, every `com.atproto.sync.*` read, `subscribeRepos` WS connections, every `com.atproto.space.*` / `com.atproto.simplespace.*` endpoint including `getDelegationToken`/`getSpaceCredential`, `/oauth/par`, `/oauth/authorize` (the password-entry endpoint), `/oauth/revoke`, `refreshSession`, `deleteSession`, all `com.atproto.admin.*`, `/admin`, and `com.atproto.sync.requestCrawl`.

Per-IP limiting is absent at the transport level, not just unimplemented: a grep for `ConnectInfo|X-Forwarded-For|x-forwarded-for|SocketAddr|remote_addr|peer_addr` over `crates/atproto-pds/src/` returns two hits, both in `bin/pds.rs:25` and `:681` — the **listen** address parse. The router is served with plain `axum::serve(listener, app)` (`bin/pds.rs:745`), **not** `into_make_service_with_connect_info`, so peer IP is not even available to handlers. Keys are identifier-scoped with no client-IP dimension, so an attacker rotates identifiers to bypass, and can lock a known victim out of `createSession` by burning their 300/min budget.

**Observability.** Three unauthenticated health endpoints (§3.2), registered at `router.rs:29-31`; `/xrpc/_health` is the container `HEALTHCHECK` (`crates/atproto-pds/Dockerfile:118-119`) and the compose healthcheck (`deploy/docker-compose.yml:32`, `:57`, `:82`). Prometheus exposes **exactly two metric families**: `atproto_pds_http_requests` (labels `{method, route}`, `metrics.rs:32-39`) and `atproto_pds_http_responses` (labels `{method, route, status}`, `metrics.rs:43-51`), registered at `metrics.rs:80-89`. That is the entire metric surface — no latency histograms, no in-flight gauges, no per-subsystem counters (no GC, notifier, space-commit, DB-pool, or firehose-subscriber metrics). The export format string is `application/openmetrics-text; version=1.0.0; charset=utf-8` (`metrics.rs:133`). Mounting is `with_metrics` (`router.rs:441-448`), called from `bin/pds.rs:671-678` **only when `PDS_METRICS_BIND` is `Some`** — even though per `metrics.rs:11-15` the flag does not bind a separate listener, it only gates whether the handler is mounted on the main listener. **`/metrics` has no authentication** (`grep -n "require_admin\|Authorization\|auth" crates/atproto-pds/src/metrics.rs` → no hits); the module doc (`metrics.rs:11-13`) punts the ACL to the operator's reverse proxy, but in the shipped `deploy/` that proxy is cloudflared, whose ingress (`deploy/cloudflared/config.yml.tmpl:13-21`) forwards **all** paths to the container with no path ACL.

OpenTelemetry is traces-only: `telemetry.rs:32-67` sets up an OTLP HTTP/protobuf span exporter with `Sampler::AlwaysOn`, `RandomIdGenerator`, a batch exporter on the Tokio runtime, and a `service.name` resource attribute, with W3C `TraceContextPropagator` installed globally (`telemetry.rs:37`) and graceful degradation to `None` on init failure (`:45-52`); the off-feature stub is `:77-99`. Wired at `bin/pds.rs:1122-1136` and flushed on exit at `:767`. No OTel metrics or logs pipeline exists. Structured logging is `tracing` + `tracing-subscriber` with `EnvFilter` and `fmt::layer().with_target(true)` (`bin/pds.rs:1131-1135`), filter from `RUST_LOG` defaulting to `"info,atproto_pds=debug"` (`bin/pds.rs:59`) with a hardcoded fallback to the same string on parse failure (`:1125`); background loops are `#[instrument]`-ed (`:772`, `:795`, `:844`, `:895`). **Gap:** no request-ID / trace-ID propagation into HTTP responses and no access log — no `tower_http::trace` layer is applied in `build_router`.

**Email.** `crates/atproto-pds/src/email.rs` has two backends on one enum (`email.rs:27-36`): `EmailService::Disabled` (**the `#[default]`**, `:31-32`), whose `send` logs `to`/`subject`/**full body** at `INFO` with a `dev-only:` prefix and returns `Ok(())` (`:75-83`); and `EmailService::Smtp(Box<SmtpBackend>)` gated `#[cfg(feature = "smtp")]`, using `lettre::AsyncSmtpTransport<Tokio1Executor>::from_url` (`:110-114`) and `Message::builder()` with a plain-text body only (`:126-133`) — no HTML part, no templating. `from_env` (`:44-65`) requires **both** `PDS_EMAIL_SMTP_URL` and `PDS_EMAIL_FROM_ADDRESS`; with the feature off it warns and returns `Disabled` (`:51-57`). Wired at `bin/pds.rs:524-525`. **`smtp` is not a default feature** (`crates/atproto-pds/Cargo.toml:96`, `:128`), and the shipped container is built `--features clap,hickory-dns` (`crates/atproto-pds/Dockerfile:82-84`), so **the reference deployment cannot send email at all** — every confirmation URL and reset token is written to `INFO` logs instead. Mail-sending flows are `requestEmailUpdate` (`router.rs:172-175`), `requestAccountDelete` (`:180-183`), `admin.sendEmail` (`:387`), `requestEmailConfirmation` / `requestPasswordReset` (`:223-235`).

**The notifier** is a second, unrelated notification system: a DLQ-backed outbound POST worker over `notify_attempt` (`crates/atproto-pds/src/notifier.rs`). `enqueue_notification` (`:62-80`) inserts a `state='pending'` row; `Notifier::tick` drains due rows in batches of 50 (`bin/pds.rs:854-859`) and POSTs them; retry is `backoff_ms = initial_backoff_ms * 2^next_count` (`notifier.rs:222`) with give-up at `max_attempts`; spawned at `bin/pds.rs:700-706` on a `PDS_NOTIFIER_INTERVAL_SECS` ticker (default 5 s). It is **not pluggable** — `Notifier` is a concrete struct holding a `reqwest::Client` (`notifier.rs:246-260`), with no trait, no alternate transport, and no webhook-signing hook; payload/`nsid`/`content_type`/`auth_token` are per-row columns, which is the only extensibility. Its HTTP client is built with `reqwest::Client::new()` (`bin/pds.rs:855`, `notifier.rs:263`) — **no `user_agent()`**, unlike every other outbound client in the binary (`bin/pds.rs:625`, `http/handlers.rs` requestCrawl).

### 7.2 Configuration, secrets, and deployment

`crates/atproto-pds/src/config.rs` is **not** the config surface — it is only a startup-safety validator (`validate_production_safety`, `config.rs:42-75`). The real configuration is the clap `Args` struct at `bin/pds.rs:41-330` plus one direct `std::env::var` read. Exhaustive basis: `grep -rn 'env::var(' crates/atproto-pds/src/` → 1 hit; `grep -rn 'env = "' crates/atproto-pds/src/` → 42 hits (40 in `pds.rs`, 2 in `atproto-pds-admin.rs`).

| Env var | Flag | Default | Line |
|---|---|---|---|
| *(none)* | `--config` | none — **NOTE 1** | `pds.rs:43-44` |
| `PDS_PORT` | `--port` | `4800` | `pds.rs:47-48` |
| `PDS_BIND` | `--bind` | `127.0.0.1` | `pds.rs:51-52` |
| `PDS_DATA_DIRECTORY` | `--data-dir` | `./data` | `pds.rs:55-56` |
| `RUST_LOG` | `--log` | `info,atproto_pds=debug` | `pds.rs:59-60` |
| `PDS_SERVICE_DID` | `--service-did` | `did:web:localhost` | `pds.rs:63-64` |
| `PDS_HOSTNAME` | `--hostname` | none (derived from `did:web:` suffix, `pds.rs:961-974`) | `pds.rs:68-69` |
| **`PDS_JWT_SECRET`** | `--jwt-secret` | `dev-only-jwt-secret-32-bytes-min!` | `pds.rs:72-77` |
| **`PDS_ADMIN_PASSWORD`** | `--admin-password` | `admin-default-CHANGE-ME` | `pds.rs:80-85` |
| `PDS_INVITE_REQUIRED` | `--invite-required` | `false` | `pds.rs:88-89` |
| `PDS_DID_PLC_URL` | `--plc-directory` | none (PLC genesis disabled) | `pds.rs:93-94` |
| `PDS_PRODUCTION` | `--production` | `false` | `pds.rs:97-98` |
| `PDS_NOTIFIER_INTERVAL_SECS` | `--notifier-interval-secs` | `5` (1..=3600) | `pds.rs:103-109` |
| `PDS_ACCOUNT_GC_INTERVAL_SECS` | `--account-gc-interval-secs` | `3600` (1..=86400) | `pds.rs:114-120` |
| `PDS_EMAIL_SMTP_URL` | `--smtp-url` | none | `pds.rs:125-126` |
| `PDS_EMAIL_FROM_ADDRESS` | `--email-from-address` | none | `pds.rs:130-131` |
| `PDS_DURABILITY_PROFILE` | `--durability-profile` | `memory` (`memory`\|`sql`) | `pds.rs:137-143` |
| `PDS_GC_INTERVAL_SECS` | `--gc-interval-secs` | `86400` (60..=604800) | `pds.rs:149-155` |
| `PDS_REPORT_SERVICE_DID` | `--report-service-did` | none → `createReport` 503 | `pds.rs:162-163` |
| `PDS_REPORT_SERVICE_URL` | `--report-service-url` | none | `pds.rs:169-170` |
| `PDS_OAUTH_ACCESS_TOKEN_TTL_SECONDS` | `--oauth-access-token-ttl-seconds` | `900` (60..=86400) | `pds.rs:174-180` |
| `PDS_OAUTH_REFRESH_TOKEN_TTL_SECONDS` | `--oauth-refresh-token-ttl-seconds` | `2592000` (60..=31536000) | `pds.rs:185-191` |
| `PDS_SPACE_OPLOG_RETENTION_DAYS` | `--space-oplog-retention-days` | `30` (0..=3650; `0` disables) | `pds.rs:199-205` |
| `PDS_SPACE_NOTIFY_RETRY_INITIAL_BACKOFF_MS` | `--space-notify-retry-initial-backoff-ms` | `1000` (50..=600000) | `pds.rs:209-215` |
| `PDS_SPACE_NOTIFY_RETRY_MAX_ATTEMPTS` | `--space-notify-retry-max-attempts` | `8` (1..=32) | `pds.rs:219-225` |
| `PDS_SPACE_CREDENTIAL_TTL_SECONDS` | `--space-credential-ttl-seconds` | `SPACE_CREDENTIAL_TTL_SECS` (7200) | `pds.rs:229-235` |
| `PDS_SERVICE_HANDLE_DOMAINS` | `--service-handle-domains` | empty = **any handle accepted** | `pds.rs:241-242` |
| `PDS_CRAWLERS` | `--crawlers` | empty (requestCrawl is a no-op) | `pds.rs:250-251` |
| `PDS_BSKY_APP_VIEW_DID` | `--bsky-app-view-did` | none | `pds.rs:259-260` |
| `PDS_BSKY_APP_VIEW_URL` | `--bsky-app-view-url` | none | `pds.rs:264-265` |
| **`PDS_PLC_ROTATION_KEY_DID_KEY`** | `--plc-rotation-key-did-key` | none | `pds.rs:273-274` |
| **`PDS_PLC_ROTATION_KEY_PRIVATE`** | `--plc-rotation-key-private` | none (b64url; both-or-neither, `pds.rs:1058-1062`) | `pds.rs:278-279` |
| **`PDS_OAUTH_KEYS_JWK_SET`** | `--oauth-keys-jwk-set` | none → auto-generate P-256 + persist (`pds.rs:942-956`) | `pds.rs:285-286` |
| `PDS_OTEL_ENDPOINT` | `--otel-endpoint` | none | `pds.rs:293-294` |
| `PDS_METRICS_BIND` | `--metrics-bind` | none — **NOTE 2** | `pds.rs:302-303` |
| `PDS_VALKEY_URL` | `--valkey-url` | none | `pds.rs:309-310` |
| `PDS_VALKEY_KEY_PREFIX` | `--valkey-key-prefix` | `atproto-pds:` | `pds.rs:313-314` |
| `PDS_BLOB_STORE_URL` | `--blob-store-url` | none (per-actor SQLite blobs) | `pds.rs:321-322` |
| **`PDS_POSTGRES_URL`** | `--postgres-url` | none | `pds.rs:328-329` |
| `PDS_STORAGE_PROFILE` | *(env only, no flag)* | empty → compiled-in profile | `actor_store/mod.rs:81-83` |

**NOTE 1 — `--config` is dead.** `pds.rs:42` documents the precedence "env > --config > /etc/atproto-pds/config.toml > defaults", but `args.config` is never read after `Args::parse()`; grep for `args.config` in `bin/pds.rs` returns only the field declaration at `:44`. No TOML loader exists in the crate. **NOTE 2 — `PDS_METRICS_BIND` is a boolean in disguise.** It is typed `Option<String>` but never parsed as an address; `bin/pds.rs:672` only checks `.is_some()`, confirmed by `metrics.rs:11-15`. The `atproto-pds-admin` binary reads `PDS_ADMIN_BASE_URL` (default `http://127.0.0.1:4800`, `atproto-pds-admin.rs:25-30`) and `PDS_ADMIN_PASSWORD` (`:34-35`). Test-only: `PDS_POSTGRES_TEST_URL` (`tests/feature_postgres_live.rs:57`).

Enforced-in-production secrets are `PDS_JWT_SECRET` (≥32 bytes always; rejected if the dev sentinel when `PDS_PRODUCTION=true`), `PDS_ADMIN_PASSWORD` (rejected if sentinel), and `PDS_SERVICE_DID` (rejected if `did:web:localhost` or not `did:`-prefixed) — `config.rs:42-75`, all issues collected and reported together (`:70-74`), wired at `bin/pds.rs:357`. **Without `PDS_PRODUCTION=true` the dev sentinels boot silently** — `config.rs:52` gates all sentinel checks behind `if config.production`, and `bin/pds.rs:97` defaults `PDS_PRODUCTION` to `false`. Optional secrets: `PDS_OAUTH_KEYS_JWK_SET` (private JWKs inline in an env var — `pds.rs:982-1045` accepts `d` for P-256/P-384/secp256k1), `PDS_PLC_ROTATION_KEY_PRIVATE`, `PDS_EMAIL_SMTP_URL` (may embed credentials), `PDS_POSTGRES_URL`, `PDS_VALKEY_URL`, and AWS creds via the SDK default chain (`pds.rs:319-320`). **Gaps in the production gate:** it does not check `PDS_BIND` (a production deploy can silently stay on `127.0.0.1`), does not require `PDS_SERVICE_HANDLE_DOMAINS` (empty = any handle accepted, `pds.rs:239-240`), and does not warn when `PDS_DURABILITY_PROFILE=memory` in production.

**Deployment.** There are two Dockerfiles, only one of which builds the PDS. `crates/atproto-pds/Dockerfile` is a 4-stage `cargo-chef` build — `rust:1.85-bookworm` builder (`:30`), `debian:bookworm-slim` runtime (`:89`), non-root user `pds` uid/gid 1000 (`:98-101`), `EXPOSE 3000`, `HEALTHCHECK` on `/xrpc/_health` (`:118-119`), baked `PDS_DATA_DIRECTORY=/var/lib/pds`, `PDS_BIND=0.0.0.0`, `PDS_PORT=3000`, `RUST_LOG=info` (`:110-113`). Its **feature set is `clap,hickory-dns` only** (`:63`, `:83`), so the shipped image has **no** `metrics`, `otel`, `smtp`, `valkey`, `s3`, `postgres`, or `fjall` — setting `PDS_METRICS_BIND`/`PDS_OTEL_ENDPOINT`/`PDS_EMAIL_SMTP_URL`/`PDS_VALKEY_URL` against it is inert, the last one silently since the valkey precedence branch at `pds.rs:537-559` is `#[cfg]`-ed out. It also pins `ARG RUST_VERSION=1.85` (`:30`) against a workspace `rust-version = "1.90"` (`Cargo.toml:30`) with `resolver = "3"` (`Cargo.toml:26`). The root `Dockerfile` does **not** build `pds` or `atproto-pds-admin` at all — it builds 15 CLI binaries into `gcr.io/distroless/cc-debian12` (`Dockerfile:31`, `:40-54`), and its `LABEL binaries=` list (`:80`) omits `pds`, `atproto-pds-admin`, `atpdid`, `atpcid`, and `atptid`.

`deploy/` holds the Walking Club test cluster — 16 files, compose project `wccluster` (`deploy/docker-compose.yml:1`), five services on one bridge network: `pds1`, `pds2`, and `space-host` all running the **same** `atproto-pds` image (`:14-15`, `:39-40`, `:64-65`), plus `walking-club-appview` and `cloudflared`. Secrets are file-mounted read-only at `/run/secrets` and `cat`-ed into env by a `/bin/sh -c` entrypoint wrapper (`:23-29`) for `PDS_JWT_SECRET`, `PDS_ADMIN_PASSWORD`, and `PDS_OAUTH_KEYS_JWK_SET`, generated idempotently by `deploy/init/00-gen-secrets.sh:8-22` (`openssl rand -hex 32` / `-hex 24`, plus `atpdid key generate p256 --jwk`). **Dead secret:** `00-gen-secrets.sh:16-21` generates `plc_rotation.didkey` + `plc_rotation.priv` per service, but no compose service exports `PDS_PLC_ROTATION_KEY_DID_KEY` / `PDS_PLC_ROTATION_KEY_PRIVATE` (`docker-compose.yml:26-28`, `:51-53`, `:76-78`) and neither appears in any `deploy/env/*.env`. Reverse-proxy expectations are `deploy/cloudflared/config.yml.tmpl:10-23` — hostname→container ingress with `keepAliveTimeout: 600s` on the three PDS hostnames (for `subscribeRepos` WS) and no path-level ACL, so `/metrics` and `/admin` would be publicly routed if enabled; `crates/atproto-pds/Dockerfile:14-16` and `crates/atproto-pds/README.md:162-163` state the proxy is expected to handle TLS, large bodies (>1 GiB for `importRepo`), and WS upgrades.

**`did:web` resolution is broken in this deployment.** `deploy/well-known/{pds1,pds2,space-host}/.well-known/did.json` exist as static files declaring both `#atproto_pds` and `#atproto_space_host` services, but no compose service mounts `deploy/well-known` (volumes are only `*_data:/var/lib/pds` and `./secrets/*:/run/secrets` — `docker-compose.yml:20-22`, `:45-47`, `:70-72`), cloudflared routes the hostname straight to the PDS container (`config.yml.tmpl:13-21`), and the PDS router serves **no** `/.well-known/did.json` route — `grep -rn "atproto-did\|well-known" crates/atproto-pds/src/http/router.rs` returns only the two OAuth metadata routes (`router.rs:253`, `:257`). So `https://pds1.ngerakines.dev/.well-known/did.json` returns 404 and `did:web:pds1.ngerakines.dev` cannot resolve.

The deployment is **multi-account**, not single-user: `AccountDirectory` is a shared accounts DB (`bin/pds.rs:415-419`), each account gets its own actor store keyed by DID (`actor_store/mod.rs:33-45`), `createAccount` is a public route (`router.rs:116-119`), invite gating is optional (`PDS_INVITE_REQUIRED`, default `false`), admin `searchAccounts` / `getAccountInfos` are batch operations (`router.rs:362-365`, `:378-381`), and `deploy/init/40-create-accounts.sh:32-34` creates three accounts across three instances. Orchestration is `deploy/Makefile` with targets `secrets`, `images`, `tunnel`, `config`, `accounts`, `up`, `down`, `nuke`, `logs`, `ps` (`Makefile:12-52`), auto-detecting `podman-compose` else `docker compose` (`Makefile:5`); `deploy/init/10-build-images.sh` builds both images from the repo root; `deploy/init/20-create-tunnel.sh` bootstraps cloudflared creds + DNS routes. **No Kubernetes manifests, no Helm chart, no systemd unit, no Terraform** — `find deploy -type f` returns only those 16 files.

**CI does not exist as documented.** `crates/atproto-pds/README.md:29-32` claims `cargo fmt --all -- --check`, `cargo clippy ... -D warnings`, and `cargo test --workspace --all-features` are enforced on every push and PR, citing `.github/workflows/ci.yml`. **That file does not exist.** `ls .github/workflows/` returns only `release-binaries.yml`, a `workflow_dispatch`/tag-triggered cross-compile of 4 CLI binaries (`atpcid`, `atpmcp`, `atpxrpc`, `atptid`) that runs **no** fmt/clippy/test step and does **not** build `pds`.

### 7.3 Backup, GC, and shutdown

**Backup and restore are missing entirely.** `grep -rin "backup\|restore\|snapshot" crates/atproto-pds/src/ crates/atproto-pds/README.md deploy/` yields three hits, none backup-related (`blob.rs:136` "Snapshot which CIDs…", `http/handlers.rs:180` and `repo/car_export.rs:116` firehose "snapshot at `since`"). There is no backup CLI subcommand (`atproto-pds-admin` has only `version`, `invite list`, `account info|search|delete`, `takedown apply|lift|status` — `bin/atproto-pds-admin.rs:41-111`), no volume-snapshot or `sqlite3 .backup` step in `deploy/Makefile`, and no documented restore procedure in either README. The only account-data egress path is per-account `com.atproto.sync.getRepo` CAR export (`router.rs:83`) plus `com.atproto.repo.importRepo` (`router.rs:70-73`) — the account-migration path, which covers neither the accounts DB, keys, OAuth state, spaces tables, nor blobs.

GC runs as **three independent loops**. (a) The unified GC (`src/gc.rs`, driven by `unified_gc_loop` at `bin/pds.rs:896-936` on `PDS_GC_INTERVAL_SECS`, default 86400 s) prunes the tables listed in §4.6, each best-effort with WARN-on-failure (`gc.rs:164-172`), reporting via `GcReport` (`gc.rs:41-61`) as one structured line (`bin/pds.rs:922-932`). Two constraints: the oplog sweep is **SQLite-only** — `prune_space_oplogs` opens `SqlActorStore::open` per DID (`gc.rs:236`) and merely `debug!`-skips on failure (`:238-241`), so **a fjall deployment's space oplogs are never pruned** — and it walks every account 200 at a time (`gc.rs:215-224`) with two `DELETE` statements per actor, i.e. O(accounts) DB-file opens per daily tick. The unified GC's SQL is hardcoded `SqlitePool` throughout (`gc.rs:92-96`, `:136` constructs `AccountPool::Sqlite(pool.clone())`), so a `PDS_POSTGRES_URL` deployment would get **no unified GC** — `unified_gc_loop` is fed `notifier_pool`, which is `AccountManager::pool()` typed `SqlitePool` (`bin/pds.rs:659-664`, `:846`, `:897`). (b) Account-deletion GC (`account_deletion_loop`, `bin/pds.rs:796-838`, on `PDS_ACCOUNT_GC_INTERVAL_SECS`, default 3600 s) walks `deactivated` accounts with `delete_after <= now` and calls `set_state(did, Deleted)` so the `#account` firehose event fires alongside the SQL update (`pds.rs:792-794`, `:829`). (c) Blob orphan GC is not a loop at all — `drop_record_refs` (`blob.rs:132-173`) is meant to delete blob rows reaching zero refs on record delete, but nothing calls it (§4.6). There is no background sweep for blobs orphaned by crash or partial write, and no S3 orphan reaper.

**Graceful shutdown never uses its drain deadline.** `ShutdownController` (`shutdown.rs:25-84`) provides `wait_drain()` with a 30 s deadline (`shutdown.rs:19`, `:80-83`), but `bin/pds.rs:762-764` does only `info!("draining tasks"); drop(token); drop(tracker);`. `grep -rn "wait_drain" crates/atproto-pds/` returns hits only inside `shutdown.rs` itself and its own unit tests. Background workers are **not joined** on exit — the process proceeds to `telemetry::shutdown()` (`pds.rs:767`) and returns immediately. Axum's own `with_graceful_shutdown` (`pds.rs:745-747`) still drains in-flight HTTP requests, but the notifier / GC / deletion loops are abandoned mid-tick, contradicting `crates/atproto-pds/README.md:129-131`. Signals handled are SIGTERM + SIGINT only, via `tokio::signal::unix` (`shutdown.rs:14`, `:66-73`) — **Unix-only**, no `#[cfg(windows)]` path.

### 7.4 Tests

`crates/atproto-pds/tests/` holds **157 integration test functions across 23 files**, plus roughly **440 in-crate unit tests** across `src/` (`grep -rc "#\[test\]\|#\[tokio::test\]" crates/atproto-pds/src/`), densest in `src/oauth/consent.rs` (19), `src/security.rs` (18), `src/http/space_handlers.rs` (16), `src/space/mint_authz.rs` (13), `src/space/service.rs` (12).

| File | #tests | Coverage |
|---|---:|---|
| `http_phase7_spaces.rs` | 30 | Largest suite. `simplespace` createSpace (round-trip, auth-required, auto-`skey`, did-must-match-caller), updateSpace, deleteSpace, owner-seeded member list, add/remove/list members, non-owner add rejected. `com.atproto.space` applyWrites (+empty-batch rejection), single-op create/put/delete, repo-must-match-subject, keys-only paginated listRecords, cross-collection listRecords, getRecord with `repo` override under OAuth, `getRepoState` signed commit. Auth: delegation→credential exchange, `client_id` requirement, non-member denial, `#allowList` denial of unattested apps, idempotent recipient registration, wrong-space credential rejection, OAuth rejection on `listRepos`, **forged-credential rejection on read methods** (`forge_space_credential` at `:165-185`), `getBlob` gating, `registerNotify` credential requirement, `notifyWrite`/`notifySpaceDeleted` service-auth requirements |
| `http_phase6_admin.rs` | 20 | Admin Basic-auth on every route; getAccountInfo(s) (+empty-list rejection), searchAccounts, getInviteCodes, disableInviteCodes, disableAccountInvites blocking create; takedown apply/lift and takedown blocking public reads; deleteAccount terminal; sendEmail with/without email; updateAccountEmail; updateAccountPassword (round-trip + short-password rejection); revokeServiceAuth blacklist row; forceRepoSync 404-when-no-commits |
| `http_phase3_auth.rs` | 14 | createAccount→getSession, createSession by handle+password, wrong-password rejection, refreshSession new tokens, refresh-with-access-JWT rejected, invite gating (missing/unknown code, redemption records the real DID), app passwords (create→session, list excludes primary, revoke invalidates), createInviteCode, dead-schema tables dropped after migration |
| `http_phase4_oauth.rs` | 10 | `.well-known` documents, `/oauth/jwks` shape, full PAR→authorize→token flow, non-S256 PKCE rejected, missing `atproto` scope rejected, PKCE mismatch rejected, refresh rotation, decline→`access_denied`, unsupported grant_type, **OAuth state persists across restart** |
| `http_phase5_lifecycle.rs` | 10 | deactivate↔activate, listMissingBlobs empty, importRepo rejects malformed CAR, email-update request→confirm (+replay rejection), deactivate-with-past-`delete_after`→GC deletes, account-delete request→confirm, denylisted handle blocks createAccount, getAccountInviteCodes |
| `http_phase2.rs` | 8 | `/xrpc/_health`, `/_alive` + `/_ready`, getRecord round-trip + 400-on-missing, listRecords pagination, describeRepo collections, getRepoStatus, handle-based lookups |
| `http_phase3_writes.rs` | 8 | createRecord round-trip, no-auth rejected, cross-account write rejected, put→delete, applyWrites atomic batch, auto-rkey TID, duplicate create rejected, write advances `getLatestCommit` |
| `http_phase9_user_endpoints.rs` | 8 | requestEmailConfirmation 412/400 paths, confirmEmail sets `email_confirmed_at`, requestPasswordReset 200-for-unknown-email, resetPassword round-trip + short-password rejection, createReport 503-when-unconfigured |
| `identity_endpoints.rs` | 8 | resolveHandle local + 404, requestPlcOperationSignature, getRecommendedDidCredentials, refreshIdentity emits event for did:web |
| `feature_postgres_live.rs` | 6 | **Only runs with `PDS_POSTGRES_TEST_URL` set** (`:57-61`); otherwise skips with INFO and passes. Postgres branch of AccountDirectory, email_token, invite, app_password, denylist, service_auth_blacklist |
| `http_phase8_polish.rs` | 5 | OAuth `/token` rate-limit burst rejection, reserveSigningKey `did:key:`, requestEmailUpdate shape validation, consent-page 404 on unknown `request_uri` |
| `http_phase5_service_auth.rs` | 5 | getServiceAuth signature verifies, requires session, rejects non-DID `aud`, clamps max TTL, omits `lxm` when absent |
| `dpop_enforcement.rs` | 3 | DPoP-bound token rejected without proof, accepted with fresh proof, replay rejected |
| `http_phase2_fjall_blob.rs` | 3 | fjall uploadBlob/getBlob/listBlobs round-trip, unknown-CID 404, idempotent upload. Gated on `fjall` |
| `http_phase9_blobs.rs` | 3 | uploadBlob round-trip, auth required, listMissingBlobs empty |
| `migration_e2e.rs` | 3 | Full migration sequence (service-auth `lxm=createAccount` → createAccount(did, plcOp) → importRepo → listMissingBlobs → activate → session still works), invalid-CAR clean failure, importRepo requires privileged session |
| `public_realm_dispatch.rs` | 3 | Full `PublicRealmBackend` across all four storage traits in lockstep (writer batch, DID isolation, overwrite, outbox cursor) — sqlite always, fjall gated |
| `feature_otel.rs` | 3 | `init_otlp_layer` returns `Some`/`None`. Symbol-existence only |
| `notifier_e2e.rs` | 2 | Notifier delivers to a live local axum recipient; marks failure on 5xx |
| `feature_s3.rs` | 2 | `HybridS3BlobStorage: BlobStorage` compile assertion; `open` errors on non-`s3://`. **No live S3** |
| `feature_metrics.rs` | 1 | `Metrics::new()` → record → `export()` contains both counter families. **Does not go through the router** |
| `feature_valkey.rs` | 1 | `redis::Client::open("not-a-valid-url")` errors; type-existence of `ValkeyClient::connect`. **No live Valkey** |
| `feature_postgres.rs` | 1 | `PostgresAccountStore::connect` rejects a malformed DSN. **No live Postgres** |

`crates/atproto-space` has **52 unit tests and no `tests/` directory** — `ls crates/atproto-space/` returns `Cargo.toml`, `README.md`, `src`. Distribution: `credential.rs` 12 `#[test]`, `types.rs` 11, `commit.rs` 9, `set_hash.rs` 8, `storage.rs` 3, plus `space_repo.rs` 6 `#[tokio::test]` and `space_members.rs` 3; `errors.rs` and `lib.rs` have none. `proptest` is a declared dev-dependency (`crates/atproto-space/Cargo.toml:38`) but **no `proptest!` block exists in the crate** — `grep -c "proptest!" crates/atproto-space/src/*.rs` returns 0 for every file.

Unit tests do cover the spaces primitives well: LtHash algebra + known-answer digest (`set_hash.rs:180-271`), commit ctx byte layout and tamper/domain-separation cases (`commit.rs:238-388`), JWT header exactness and claim mismatches (`credential.rs:417-656`), the full mint decision matrix (`mint_authz.rs:514-643`), `#atproto_space`/`#atproto_space_host` selection with fallback (`space_auth.rs:368-430`), and oplog batch-larger-than-limit paging in both the in-memory (`space_repo.rs:634-680`) and SQL (`sql/space_repo_storage.rs:401-444`) stores.

**Substantiated coverage gaps**, each backed by the grep that produced no hit:

1. **`subscribeRepos` has ZERO test coverage, including cursor resume.** `grep -rn "subscribe\|WebSocket\|ws://\|upgrade" crates/atproto-pds/tests/*.rs` — the only `subscribe` hit is the **doc comment** at `http_phase8_polish.rs:6`. No test body opens a WS. The handler's `cursor`, `did`, and `encoding` params (`subscribe_handlers.rs:44-54`) are all unexercised, as are the `?encoding=json` fallback, CBOR frame encoding, backfill-from-outbox, and broadcast wakeup.
2. **`com.atproto.sync.requestCrawl` is untested.** `grep -rn "requestCrawl" crates/atproto-pds/tests/` → NONE. The handler makes unauthenticated outbound POSTs to every entry in `PDS_CRAWLERS` with a caller-supplied `hostname` and no auth check (`router.rs:102-105`).
3. **`Atproto-Proxy` / `app.bsky.*` proxying is untested.** `grep -rln "proxy" crates/atproto-pds/tests/` → NONE. (`app.bsky` appears in 6 test files only as a record-collection NSID in fixtures.) `proxy_handlers.rs` has 6 in-crate unit tests but no end-to-end HTTP coverage.
4. **`com.atproto.sync.getBlocks` is untested.** `grep -rn "getBlocks" crates/atproto-pds/tests/` → NONE. Route at `router.rs:84-87`.
5. **`com.atproto.admin.takedownSpaceRecord` is untested.** `grep -rn "takedownSpaceRecord" crates/atproto-pds/tests/` → NONE. Route at `router.rs:402-405`. Account-level takedown *is* covered.
6. **`com.atproto.identity.submitPlcOperation` is untested.** `grep -rn "submitPlcOperation" crates/atproto-pds/tests/` → NONE. `updateHandle` is likewise only route-reachable — `identity_endpoints.rs:12-14` says so explicitly.
7. **The unified GC has no integration test.** `grep -rn "gc::tick" crates/atproto-pds/tests/` → NONE; `grep -rn "oplog" crates/atproto-pds/tests/` → NONE. `gc.rs` has 4 in-crate unit tests (`:299-398`) using `TickOptions::default()` — `data_dir: None` — so the `space_*_oplog` sweep (`gc.rs:146-157`, `:203-260`) is **never executed by any test**.
8. **Rate limiting is tested at 1 of 4 sites.** `grep -rn "rate_limit" crates/atproto-pds/tests/` → `http_phase8_polish.rs` only. `grep -rn "createSession:" crates/atproto-pds/tests/` → NONE; `grep -rn "RateLimited" crates/atproto-pds/tests/` → NONE. The SQL and Valkey limiter backends are untested end-to-end.
9. **No live-backend test for any optional backend.** `feature_valkey.rs`, `feature_s3.rs`, `feature_postgres.rs`, `feature_metrics.rs`, `feature_otel.rs` are symbol-existence / error-path smoke tests only, each saying so in its own module doc (`feature_valkey.rs:5-7`, `feature_s3.rs:5-7`, `feature_postgres.rs:6-8`).
10. **`/metrics` is never exercised through the router.** `grep -rn "with_metrics" crates/atproto-pds/tests/` → NONE; `metrics_middleware` (`metrics.rs:157-172`) has no test.
11. **Graceful shutdown of the real binary is untested.** `grep -rn "ShutdownController" crates/atproto-pds/tests/` → NONE. The 3 tests in `shutdown.rs:96-140` exercise the controller in isolation, including `wait_drain` — the one method `bin/pds.rs` never calls.
12. **No `atproto-space` integration tests at all.** No cross-crate test drives `SpaceRepo` + `SpaceMembers` + `LtHash` + credential mint/verify together against a real storage backend; `http_phase7_spaces.rs` is the only integration coverage and it goes through the HTTP layer.
13. **Stale test doc claims.** `http_phase5_lifecycle.rs:7` says "`importRepo` returns 501 NotImplemented with structured error"; the actual test is `import_repo_rejects_malformed_car` and the body comments at `:191` say "we don't expect 501 anymore".

### 7.5 Documentation state

What exists is genuinely good where it exists. `crates/atproto-pds/README.md` (189 lines) covers production status, the full XRPC surface list, storage profiles, a complete Cargo-feature table (`:111-124`), binaries, build commands, container instructions, and test commands. `crates/atproto-space/README.md` (71 lines) covers the module list, a spec-alignment statement with line-number citations into the 0016 draft, and a `rust,ignore` quick-start. Rustdoc is dense and high-quality throughout, with `#![warn(missing_docs)]` enforced at `crates/atproto-pds/src/lib.rs:32` and every module carrying a `//!` header. Each `deploy/` script has a header comment explaining purpose and prerequisites (`00-gen-secrets.sh:2`, `10-build-images.sh:2-4`, `20-create-tunnel.sh:2-3`, `40-create-accounts.sh:2-6`).

**Stale or wrong:**

1. `crates/atproto-pds/README.md:29-32` cites `.github/workflows/ci.yml`, which does not exist (§7.2).
2. `crates/atproto-pds/README.md:78-80` lists "Inbound `notifyWrite` / `notifyMembership` receipts" under Federation. `notifyMembership` was **removed in 0.15.0-alpha.2** (`CHANGELOG.md:88`) and `grep -rn "notifyMembership" crates/ --include="*.rs"` finds it only in a comment at `tests/notifier_e2e.rs:35`. No such route exists.
3. `crates/atproto-pds/README.md:129-131` claims the shutdown controller "cancels long-lived workers, lets in-flight requests complete" — `wait_drain()` is never called (§7.3).
4. `crates/atproto-pds/src/security.rs:6` — "every authenticated XRPC call passes through a rate limiter" is false (§7.1).
5. `crates/atproto-pds/src/metrics.rs:6-9` claims `text/plain; version=0.0.4` output and "status code histograms"; the code emits `application/openmetrics-text; version=1.0.0` (`metrics.rs:133`) and registers two counters and zero histograms. `bin/pds.rs:299-300` repeats the histogram claim.
6. **Notifier backoff totals are wrong in two places, in two different directions.** With defaults (`initial=1000ms`, `max_attempts=8`) the schedule per `notifier.rs:222` is 2+4+8+16+32+64+128+256 s = **510 s ≈ 8.5 min**. `bin/pds.rs:218` says "Default 8 (≈ 4 min total backoff)"; `notifier.rs:17` and `:28` say "8 → ~1.5h with backoff" / "cumulative ~1.5h". Neither matches the formula.
7. `bin/pds.rs:42` documents a config-file precedence chain that is not implemented (§7.2 NOTE 1).
8. `crates/atproto-pds/src/lib.rs:9-27` lists "Library modules (all stable)" but omits `blob`, `denylist`, `email`, `gc`, `notifier`, `service_auth_blacklist`, `telemetry`, `valkey_backend`, `metrics` — all `pub mod` at `lib.rs:36-62`.
9. Root `Dockerfile:2` says "all 15 binaries from the workspace"; the `LABEL binaries=` at `:80` omits five.
10. `crates/atproto-pds/Dockerfile:30` pins `RUST_VERSION=1.85` against workspace `rust-version = "1.90"`.
11. `tests/http_phase8_polish.rs:6` and `tests/http_phase5_lifecycle.rs:7` describe tests that no longer exist or no longer assert what they say (§7.4 items 1, 13).

**Missing:**

1. **Root `README.md` does not mention `atproto-pds` or `atproto-space` at all.** It says "This workspace contains 17 crates" (`README.md:9`) and enumerates 17, while `Cargo.toml:2-22` lists **19**. `grep -n "atproto-pds\|atproto-space" README.md` → no hits; the only PDS mention is a generic bullet at `README.md:347`. Neither crate appears in the Quick Start dependency block (`README.md:58-68`).
2. **`CLAUDE.md` does not mention either crate** — `grep -n "atproto-pds\|atproto-space" CLAUDE.md` → no hits. Its Architecture list (`CLAUDE.md:67-81`) is 12 crates and also omits `atpmcp`, `atpxrpc`, `atproto-tap`, `atproto-lexicon`, `atproto-extras`. It claims "14 CLI tools" (`CLAUDE.md:84`) with no PDS entry, and gives no error-code conventions, module maps, or build commands for either crate.
3. `CLAUDE.prompts.md` is a generic prompt scratchpad (65 lines) with no PDS/spaces content.
4. **`docs/` contained only empty directories** before this document — `docs/gap-analysis/{capability-areas,permissioned,impl-notes}`.
5. **No operator runbook**, despite three source files deferring to one that does not exist: `valkey_backend.rs:222-223` ("exercised manually + via the operator runbook"), `tests/feature_s3.rs:6-7` ("exercised in the operator runbook, not in CI"), `metrics.rs:11-13` (delegates the `/metrics` ACL to "the operator"). No backup/restore, upgrade, migration-rollback, incident, or key-rotation procedure is documented anywhere.
6. **No CHANGELOG entry for the PDS/spaces work in `0.15.0-rc.1`** (§7.6).

### 7.6 The project's own stated caveats and scope limits

Direct quotes with line numbers, because they set the bar the gap analysis is measured against.

- `crates/atproto-pds/README.md:3` — the bluntest statement in the repo: `EXPERIMENTAL - FOR THE LOVE OF GOD DON'T USE THIS YET.`
- `crates/atproto-pds/README.md:15-16` — the scope claim: `The PDS is **single-node deployable for federated public traffic**.`
- `crates/atproto-pds/README.md:9-11` — `is the second PDS implementation overall to ship Spaces, the first in Rust.`
- `crates/atproto-space/README.md:12-14` — `> **Status: experimental**. The 0016 Permissioned Data draft is still settling.` and `> The production `SetHash` is `LtHash`, the lattice hash the spec selects (spec § "Commit digest").`
- `crates/atproto-space/README.md:6-8` — the alignment target: `[0016 Permissioned Data draft](...), which is the authoritative alignment target for this crate`
- `CHANGELOG.md:92` — the only maturity statement the changelog makes about either crate, two releases old: `AT Protocol PDS + permissioned-data Spaces (alpha-ready) — new `atproto-pds` and `atproto-space` crates ...`
- `CHANGELOG.md:88` — the one explicit removal of scope: `Permissioned-data member-sync machinery (`getMemberState` / `getMemberOplog` / `notifyMembership`); member-list management (`addMember` / `removeMember` / `listMembers`) is retained.`
- `CHANGELOG.md:84` — `taking the spec as the source of truth over the reference implementation`

**Notably absent:** the `## [0.15.0-rc.1] - 2026-07-27` section (`CHANGELOG.md:10-80`) contains **only** `### Security` and `### Changed` entries for `atproto-lexicon`, `atproto-dasl`, `atproto-identity`, and `atproto-oauth`. It has **zero** mention of `atproto-pds` or `atproto-space`, and the changelog contains **no** "Known limitations", "RC caveats", "Not production ready", or "Unsupported" section anywhere (`grep -n "caveat\|not production\|limitation\|Known" CHANGELOG.md` → no hits). The most recent maturity label the changelog attaches to the PDS is still **"alpha-ready"** from `0.15.0-alpha.1`, while the crate version is now `0.15.0-rc.1`.

In-code scope limits worth recording alongside those:

- `oauth/token.rs:97-99` — the `/oauth/token` limiter is documented as the credential-stuffing guard, implying no broader coverage.
- `security.rs:11-14` — the memory backend is "Fine for DPoP (60s-bounded), gap for OAuth refresh rotation (30-day TTL, single-use per RFC 6749 §6) and service-auth." Memory is still the **default** (`bin/pds.rs:141`).
- `security.rs:308-309` — "SQL-backed limiting under heavy load can become a bottleneck; Valkey is the recommended production path."
- `valkey_backend.rs:118-123` and `:169-172` — the Valkey JTI guard and rate limiter **fail open** on Redis errors (a replayed JTI is accepted, a rate limit is not enforced) by design, relying on operator alerting off the `tracing::error!`.
- `admin/dashboard.rs:10-12` — "Bigger UIs (record-level moderation, takedown bulk-ops) are an operational-tooling concern, kept outside the PDS binary."
- `metrics.rs:11-15` — the metrics endpoint deliberately does not bind its own listener and delegates the ACL to the operator's reverse proxy.

---

## 8. Confidence & unknowns

### 8.1 Citations spot-checked for this document

Twenty citations were re-opened at the cited line during composition. All twenty confirmed, with one correction and one imprecision noted below. A second, independent pass re-opened a further seven load-bearing citations concentrated on the two orchestrator-verified corrections (account takedown, rate limiting) — see the second table.

| # | Citation | Claim | Result |
|---|---|---|---|
| 1 | `crates/atproto-repo/src/mst/tree.rs:236` | `let _target_height = key_height(key);` — discarded | **CONFIRMED** verbatim |
| 2 | `crates/atproto-pds/src/sequencer/frame.rs:116-121` | body nested under a `payload` key | **CONFIRMED** verbatim |
| 3 | `crates/atproto-pds/src/http/auth_handlers.rs:891-894` | `reserve_signing_key(State, Json<Input>)` — no `Parts`, no guard | **CONFIRMED** |
| 4 | `crates/atproto-space/src/set_hash.rs:154-156` | `digest()` = `Sha256::digest(self.state_bytes())` | **CONFIRMED** |
| 5 | `crates/atproto-pds/src/http/space_handlers.rs:1113` | `Box::leak(sub.clone().into_boxed_str())` | **CONFIRMED** verbatim |
| 6 | `crates/atproto-pds/src/oauth/token.rs:290` | `dpop_jkt: dpop_jkt.clone().unwrap_or_default()` | **CONFIRMED** verbatim |
| 7 | `crates/atproto-pds/src/actor_store/mod.rs:41-53` | `StorageProfile::compiled()` is `#[cfg(feature = "fjall")]`-only | **CONFIRMED** |
| 8 | `crates/atproto-pds/src/security.rs:6` | "every authenticated XRPC call passes through a rate limiter" | **CONFIRMED** verbatim (and false, per §7.1) |
| 9 | `crates/atproto-pds/src/bin/pds.rs:141` | `PDS_DURABILITY_PROFILE` default `"memory"` | **CONFIRMED** |
| 10 | `crates/atproto-space/src/credential.rs:40,43,46,49,52,55` | the two `typ`/`kid` constants and both TTLs | **CONFIRMED** all six |
| 11 | `crates/atproto-pds/src/space/writer.rs:334-335` | `let _signed_commit = create_commit(...)` — discarded | **CONFIRMED** verbatim |
| 12 | `crates/atproto-pds/src/repo/import.rs` | no `repo_record` write | **CONFIRMED with correction** — see below |
| 13 | `crates/atproto-pds/src/http/auth.rs:154-184` | `require_authn` accepts session then OAuth, DPoP only when `cnf.is_some()` | **CONFIRMED** |
| 14 | `crates/atproto-pds/src/http/router.rs` | route counts | **CONFIRMED with a precise count** — 104 `.route(...)` calls, 103 distinct paths, 91 under `/xrpc/`, 89 distinct `com.atproto.*` NSIDs |
| 15 | `crates/atproto-pds/src/http/auth_handlers.rs:1754-1760` | `require_access_jwt` calls only `session::verify_access` | **CONFIRMED** |
| 16 | `crates/atproto-space/src/set_hash.rs:30-32` | `LANES = 1024`, `STATE_BYTES = LANES * 2` | **CONFIRMED** |
| 17 | `crates/atproto-pds/src/space/service.rs:363-365` | `is_member` returns `true` when `uri.space_did == did` | **CONFIRMED** |
| 18 | `crates/atproto-pds/src/http/space_handlers.rs:461-470` | `list_spaces` calls only `require_session_subject`, no scope gate | **CONFIRMED** |
| 19 | `crates/atproto-pds/src/oauth/par.rs:405-420` | unguarded `GET client_id` | **CONFIRMED with an imprecision fixed** — see below |
| 20 | `grep -rn "wait_drain" crates/atproto-pds/` | only `shutdown.rs` + its own tests | **CONFIRMED** (`shutdown.rs:64,82,113,132`) |

**Correction carried into §4.5 / §4.7.** The storage research said `grep repo_record crates/atproto-pds/src/repo/import.rs` returns "no matches". It returns **one** match — the module doc comment at `import.rs:10`, which reads "persist all blocks to the per-actor block-store, **index records into `repo_record`**, and write the latest signed commit into `commit_obj`". There is still no `repo_record` write in the code. The finding is unchanged and slightly strengthened: the module documents behavior it does not implement.

**Imprecision fixed in §5.6-H.** The auth research described `oauth/par.rs:409-413` as building "a bare `reqwest::Client`". It is not bare — it sets `.user_agent(crate::user_agent())` and `.timeout(Duration::from_secs(10))`. The SSRF finding is unaffected: there is still no scheme check, no host validation, no private/loopback/link-local rejection, and no redirect cap.

**Second pass — seven additional citations re-opened.** These target the two findings the orchestrator personally verified and the two claims most likely to be overstated.

| # | Citation | Claim | Result |
|---|---|---|---|
| 21 | `crates/atproto-pds/src/repo/reader.rs:107` and `:209` | `require_public_read(&account.state, &account.did)?;` is the first statement after `resolve()` in `get_record` and `list_records` | **CONFIRMED** verbatim at both — this is what makes takedown PARTIAL rather than absent (§3.12-Q) |
| 22 | `crates/atproto-pds/src/repo/reader.rs:510-518` | `require_public_read` definition returning `PdsError::AuthDenied` | **CONFIRMED** verbatim |
| 23 | `crates/atproto-pds/src/account/state.rs:56-58` | `allows_public_read()` = `matches!(self, AccountState::Active \| AccountState::Deactivated)` | **CONFIRMED** verbatim — `Deactivated` really does allow public reads |
| 24 | `crates/atproto-pds/src/security.rs` limiter machinery | the sliding-window implementation is real, not a stub | **CONFIRMED with the range corrected** — enum `:311`, `impl` `:348`, `try_acquire` `:414` / `:450` / `:506`; §7.1 previously cited `:299-346`, now `:305-520` |
| 25 | `crates/atproto-pds/src/blob.rs:39-49` | `BlobRef` serializes `$link`/`mimeType`/`size` with no `$type` and no `ref` wrapper | **CONFIRMED** verbatim, including the doc comment calling it "the canonical blob ref envelope … per the upstream lexicon" — which it is not |
| 26 | `crates/atproto-pds/src/oauth/token.rs:176` | `let dpop_jkt = input.dpop_jkt.clone().or(auth.request.dpop_jkt.clone());` | **CONFIRMED** verbatim, with the source comment "prefer the request-time jkt, fall back to PAR-time jkt" |
| 27 | `crates/atproto-space/src/commit.rs:59-81` | `SpaceContext { space, rev }` and `encode_ctx` emitting only `[space, rev, ikm]` | **CONFIRMED** verbatim — the struct is `:59-64` (fields `space`, `rev`) and the loop `for field in [space, rev, ikm]` is `:76`; the author DID is absent from both, and the doc comment at `:54-57` states the `[space, rev, ikm]` order explicitly |

### 8.2 UNVERIFIED — carried forward from the research passes

These are stated as unverified in the source sections and must not be treated as established in [`./20-coverage-matrix.md`](./20-coverage-matrix.md) or [`./50-synthesis-and-roadmap.md`](./50-synthesis-and-roadmap.md) without further work.

**Lexicon conformance for spaces.**

- ~~**`com.atproto.space.*` and `com.atproto.simplespace.*` divergence is entirely UNVERIFIED.**~~ **RESOLVED — no longer an unknown.** The original statement was true only of the `main` branch of `bluesky-social/atproto`, which is what a bare `ls` of `/tmp/gap-scratch/atproto/lexicons/com/atproto/` shows, and true of this repo (`find . -name '*.json' | grep -i space` still matches only `deploy/well-known/space-host/.well-known/did.json`, so the in-repo wire shapes remain Rust DTOs). The draft lexicons **do** exist, on the `permissioned-data` branch at HEAD `3f6c96d` (2026-07-02), and were fetched to `/tmp/gap-scratch/lex-0016/` — 19 files under `space/`, 8 under `simplespace/` — alongside the reference TypeScript implementation (`packages/space/src/*.ts`, `packages/pds/src/api/com/atproto/space/*.ts`, `packages/syntax/src/space-uri.ts`). The NSID-by-NSID conformance check was performed against those and lives in [`./permissioned/40-permissioned-overview.md`](./permissioned/40-permissioned-overview.md) and [`./permissioned/42-happyview.md`](./permissioned/42-happyview.md); headline results are summarised at §3.10 and §6.4. What remains genuinely uncertain is only the shelf life of the comparison — 0016 is a self-declared WIP draft.
- `com.atproto.admin.takedownSpaceRecord`, `com.atproto.admin.revokeServiceAuth`, `com.atproto.admin.forceRepoSync`: project-defined NSIDs with no canonical counterpart. No divergence can be computed.
- Whether `/xrpc/_health` has a canonical definition: no `_health` lexicon exists in the comparison tree (it is a bare convention endpoint, not an NSID).
- Whether any client hard-requires `com.atproto.temp.checkHandleAvailability` / `checkSignupQueue`, which are part of the reference signup flow and not routed here.

**Storage and request handling.**

- Whether `http/write_handlers.rs::import_repo` (beyond line 620) calls `RepoImporter::with_plc_verifier`. The storage pass did not trace that function past line 620. This determines whether import signature verification is ever actually enabled in the HTTP path.
- Whether an axum `DefaultBodyLimit` caps `uploadBlob` / `importRepo` bodies before the in-handler size check. Would need the full middleware stack in `http/router.rs` / `http/mod.rs`.
- The SQLite `synchronous` pragma's effective value — it is not set explicitly, so the sqlx/SQLite default applies, and that default was not confirmed.

**Auth.**

- Whether findings §5.6-A (redirect_uri exfiltration), §5.6-B (no client auth / attacker-chosen `cnf.jkt`), and §5.6-O (non-DPoP refresh permanently unusable) reproduce end-to-end against a running instance. This inventory is source-read only; confirming them needs a live PDS plus a scripted PAR→authorize→token exchange.
- Whether any real AppView rejects the literal `"kid": null` header emitted by `getServiceAuth` (`service_auth_handlers.rs:141`). Needs a live AppView.
- Whether `PDS_PRODUCTION=true` is set in any shipped deployment manifest — the auth pass did not read the deploy infra. (The ops pass did read `deploy/`; cross-checking that against `deploy/env/*.env` is a small open item.)

**Ops.**

- Whether `crates/atproto-pds/Dockerfile` currently builds successfully given the `RUST_VERSION=1.85` vs `rust-version = "1.90"` / `resolver = "3"` mismatch. Would need `docker build -f crates/atproto-pds/Dockerfile .`.
- Whether the `walking-club-appview` service (referenced from `deploy/docker-compose.yml:88-117`) has its own ops surface. `walking-club-appview/` was not opened.
- Runtime behavior of the Valkey and S3 backends against live servers — no live test exists in-repo and none was stood up.
- Whether the `deploy/` cluster has ever been run end-to-end. The `did:web` 404 in §7.2 suggests the `.well-known/did.json` step is manual or unfinished, but no note either way was found.

### 8.3 Confidence summary

| Area | Confidence | Basis |
|---|---|---|
| Route inventory and auth guards (§3) | **High** | `router.rs` read in full; route count independently recomputed; every guard opened |
| `com.atproto.*` lexicon divergences (§3.3–3.8) | **High** | Canonical lexicon JSON opened per method |
| Spaces wire-shape conformance (§6) | **High** on the draft as of `3f6c96d`, **Low** on shelf life | Checked against the `permissioned-data` draft lexicons at `/tmp/gap-scratch/lex-0016/` plus the reference TypeScript; results in [`./permissioned/40-permissioned-overview.md`](./permissioned/40-permissioned-overview.md). The draft is explicitly WIP (§8.2) |
| Spaces *behavioral* inventory (§6) | **High** | Every claim traced to source; 6 of the 20 spot-checks were in this area |
| Storage schema and dispatch (§4.1–4.3) | **High** | Migrations and keyspace definitions read directly |
| MST flatness (§4.4) | **High** | Verified verbatim at `mst/tree.rs:236`; call-graph confirmed by grep |
| Firehose frame conformance (§4.5) | **High** | Frame code and lexicon both opened; verified verbatim |
| Import behavior (§4.5) | **High** for `repo_record`, **Medium** for signature wiring | The `with_plc_verifier` question is open (§8.2) |
| OAuth AS conformance (§5.2–5.3) | **High** on source-read, **Medium** on exploitability | Reference implementation compared line-by-line; no live exercise (§8.2) |
| Rate limiting and observability (§7.1) | **High** | Exhaustive greps recorded in the ops pass |
| Deployment (§7.2) | **High** on files read, **Low** on whether it has ever run | §8.2 |
| Test coverage claims (§7.4) | **High** | Every gap backed by the grep that produced no hit |
