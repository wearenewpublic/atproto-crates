# tranquil-pds — implementation notes

Snapshot: `/tmp/gap-scratch/tranquil-pds`, HEAD `1dc0c40`, committed 2026-07-26, workspace version `0.6.6`
(`Cargo.toml:29`). Paths below are relative to that root; canonical lexicons are under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/`.

## 1. Language, stack, build, license

Rust edition 2024, toolchain pinned to `1.96.0` (`rust-toolchain.toml:2`), Cargo workspace of 22 crates
(`Cargo.toml:3-26`). axum 0.8 (`ws`, `macros`), rustls, optional HTTP/3 over quinn+h3
(`crates/tranquil-server/src/http3.rs`, `.../tls.rs`). Postgres via `sqlx` 0.8 with compile-time query
checking (456-file `.sqlx` offline cache checked in). Repo/MST/commit primitives come from
`jacquard-repo`/`jacquard-common` 0.9 plus `iroh-car` 0.5 — not hand-rolled.

Builds: `justfile`, `flake.nix` + `module.nix` (NixOS module), and a three-stage `Dockerfile`
(node/pnpm frontend → `rust:1.96-slim-trixie` builder with optional UPX → distroless runtime,
`Dockerfile:1-11`).

License is split (`LICENSE:1-5`): code **AGPL-3.0-or-later** (`Cargo.toml:31`), docs CC BY-SA 4.0.

Size: 154,197 lines of non-test Rust under `crates/`; 215,106 with tests. Integration suite is 81 files /
37,711 lines in `crates/tranquil-pds/tests/`.

## 2. Multi-account, deployment

Multi-account. `users` is UUID-keyed with unique `handle`/`did`, `is_admin`, `takedown_ref`,
`deactivated_at`, `migrated_to_pds` (`migrations/20251211_initial_schema.sql:14-39`). When invite codes
are required and `count_users() == 0` the server prints a bootstrap invite code
(`crates/tranquil-pds/src/state.rs:258-266`).

Deployment: containers (`docker-compose.prod.yaml` pulling `atcr.io/tranquil.farm/tranquil-pds:latest`,
`README.md:53-65`; Podman quadlets in `deploy/quadlets/` for app/db/nginx/minio/valkey/pod), systemd via
`module.nix:165,206-216`, OpenRC in `deploy/openrc/`, or bare binary. The binary has `validate`,
`config-template` and `healthcheck` subcommands (`crates/tranquil-server/src/main.rs:30-38`), the last
hitting `/xrpc/_health` (`:131-164`). Config precedence env → `--config` → `/etc/tranquil-pds/config.toml`
→ defaults (`README.md:37-38`), documented across 22.5 KB of `example.toml`.

## 3. Storage backends

Two repo backends selected by `storage.repo_backend` (`crates/tranquil-pds/src/state.rs:221-256`):

| Concern | Postgres (default) | `tranquil-store` (experimental) |
|---|---|---|
| Accounts/OAuth/sessions | Postgres, `sqlx::migrate!("./migrations")` at boot (`state.rs:249-252`) | `tranquil_store::metastore` (`state.rs:530-560`) |
| Repo blocks | `blocks(cid BYTEA PK, data BYTEA)` (`migrations/20251211_initial_schema.sql:74-78`), `PostgresBlockStore` (`state.rs:294`) | `TranquilBlockStore` on disk (`state.rs:480-483`) |
| Firehose log | `repo_seq` (`migrations/20251211_initial_schema.sql:160-177`) | segmented event log (`crates/tranquil-store/src/eventlog/`) |
| Blobs | filesystem or S3, either way | same |

`state.rs:223` logs `"tranquil-store repo backend active. EXPERIMENTAL!"`;
`docs/5_INSTALL_USING_EMBEDDED_DB.md:6-7` says "experimental. Risk of total data loss" and confirms the
server "opens no postgres connection at all" in that mode.

Schema: `migrations/`, 48 forward-only files from `20251211_initial_schema.sql` (348 lines, 40+ tables) to
`20260721_backfill_invite_code_for_account.sql`. Account-vs-repo split in Postgres: `users` (`:14`),
`user_keys` (encrypted signing key + `encryption_version`, `:60-66`), `repos` (one row per user,
`repo_root_cid`/`repo_rev`, `:67-73`), `records` (`repo_id,collection,rkey` unique, per-record
`takedown_ref`, `:79-92`), global `blocks` (`:74-78`) with per-user reachability in `user_blocks`
(`migrations/20260106_clear_user_blocks.sql`, `20260107_add_repo_rev_to_user_blocks.sql`), `blobs`
(`:93-102`), `record_blobs` (`migrations/20251243_record_blobs.sql`), nine `oauth_*` tables (`:197-309`),
and `user_totp`/`backup_codes`/`passkeys`/`webauthn_challenges` (`:310-348`).

Blob backends: `FilesystemBlobStorage` / `S3BlobStorage`, chosen in
`crates/tranquil-storage/src/lib.rs:570-591` (S3 feature-gated; logs a rebuild hint at `:584`).
Cache/coordination: `create_cache` (`crates/tranquil-cache/src/lib.rs:171-212`) returns Valkey/Redis or
the built-in foca-based gossip cache `tranquil-ripple`; ripple is the default (`:175`).

## 4. Endpoint coverage snapshot

Router: `tranquil_api::api_routes().merge(tranquil_sync::sync_routes())` under `/xrpc`
(`crates/tranquil-server/src/main.rs:328`, `crates/tranquil-pds/src/lib.rs:97`). Verified against
`crates/tranquil-api/src/lib.rs` and `crates/tranquil-sync/src/lib.rs`, not the README. Unrouted `/xrpc/*`
returns 501 `MethodNotImplemented` with an `atproto-proxy` hint (`crates/tranquil-pds/src/lib.rs:79-83`).

**server.** (all `crates/tranquil-api/src/lib.rs`) describeServer `:33`, createAccount `:37`,
createSession `:41`, getSession `:45`, deleteSession `:52`, refreshSession `:56`, getServiceAuth `:68`,
checkAccountStatus `:87`, activateAccount `:115`, deactivateAccount `:119`, requestAccountDelete `:123`,
deleteAccount `:127`, requestPasswordReset `:131`, resetPassword `:135`, requestEmailUpdate `:203`,
confirmEmail `:212`, updateEmail `:216`, reserveSigningKey `:232`, listAppPasswords `:284`,
createAppPassword `:288`, revokeAppPassword `:292`, createInviteCode `:296`, createInviteCodes `:300`,
getAccountInviteCodes `:304`. All real handlers.
**Missing: `requestEmailConfirmation`** — the NSID appears only in the proxy allow-list
(`crates/tranquil-pds/src/api/proxy.rs:75`) and the service-auth protected list
(`crates/tranquil-api/src/server/service_auth.rs:37`); it is not routed, though
`server/requestEmailConfirmation.json` exists canonically.
Also routed here but **not in the canonical lexicon set** (`ls .../lexicons/com/atproto/server/`
confirms): `confirmSignup` `:60`, `resendVerification` `:64`, `verifyMigrationEmail` `:236`,
`resendMigrationVerification` `:240`, `createTotpSecret`/`enableTotp`/`disableTotp`/`getTotpStatus`
`:308-320`, `regenerateBackupCodes` `:321`, five passkey methods `:325-344`. Working handlers, but they
squat on the `com.atproto.*` namespace.

**repo.** createRecord `:76` (`repo/record/write.rs:119`), putRecord `:77` (`write.rs:320`), getRecord
`:78` (`read.rs:58`), deleteRecord `:79` (`delete.rs:35`), listRecords `:80` (`read.rs:128`),
describeRepo `:81` (`meta.rs:17`), uploadBlob `:82` (`blob.rs:47`, body limit from `server.max_blob_size`
at `lib.rs:28-29`), applyWrites `:86` (`batch.rs:330`), importRepo `:264` (`import.rs:48`),
listMissingBlobs `:95` (`blob.rs:240`). Full canonical coverage, all real.

**sync.** (all `crates/tranquil-sync/src/lib.rs`) getLatestCommit `:22`, listRepos `:23`, getBlob `:24`,
listBlobs `:25`, getRepoStatus `:26`, getBlocks `:29`, getRepo `:30` (with `since` diff path
`repo.rs:183-260` and an export semaphore `repo.rs:146-155`), getRecord `:31` (inclusion-proof CAR
`repo.rs:324-343`), subscribeRepos `:32`, getHead `:33` / getCheckout `:34` (deprecated, admin-or-self
gated, `deprecated.rs:20-43`). **Stubs:** notifyOfUpdate `:27` and requestCrawl `:28` log and return empty
(`crates/tranquil-sync/src/crawl.rs:16-22,29-34`) — both are relay-side per their lexicon descriptions, so
defensible; the *outbound* requestCrawl to configured relays is real
(`crates/tranquil-pds/src/crawlers.rs:96-108`). **Missing: `listReposByCollection`** — canonical
PDS-side query, genuine gap. `getHostStatus`/`listHosts` are absent but relay-only, so not gaps.

**identity.** resolveHandle `:72`, updateHandle `:244`, getRecommendedDidCredentials `:91`
(`identity/did.rs:480-515`), requestPlcOperationSignature `:248`, signPlcOperation `:252`,
submitPlcOperation `:256`. Plus non-canonical `_identity.verifyHandleOwnership` `:260`.
**Missing: `resolveDid`, `resolveIdentity`, `refreshIdentity`** — all three exist canonically.

**admin.** getAccountInfo/getAccountInfos/searchAccounts `:103-114`, deleteAccount `:268`,
updateAccountEmail/Handle/Password `:272-283`, getInviteCodes `:345`, disableAccountInvites `:362`,
enableAccountInvites `:366`, disableInviteCodes `:370`, getSubjectStatus `:374`, updateSubjectStatus
`:378` (`admin/status.rs`), sendEmail `:382`. **Missing: `updateAccountSigningKey`.** Private surface:
`_admin.getServerStats`, `_admin.setAdminStatus`, Signal link/unlink, `_server.getConfig`,
`_admin.updateServerConfig` (`:349-361`).

**moderation / temp.** `moderation.createReport` `:99` — real, and forwards to an external report service
when `moderation.report_service_url` + `report_service_did` are set
(`crates/tranquil-api/src/moderation/mod.rs:74-92`), else stores in `reports`.
`temp.checkSignupQueue` `:383` — **effectively a stub**, always `{activated: true}` with no queue position
(`crates/tranquil-api/src/temp.rs:31-36`). `temp.dereferenceScope` `:387` — real logic
(`temp.rs:51-124`) but registered **POST with a JSON body**, while
`.../lexicons/com/atproto/temp/dereferenceScope.json` declares `"type": "query"` with a required `scope`
*query parameter*. Wire-incompatible with a conforming client.

**Other.** ~60 routes in `_account.*`/`_admin.*`/`_delegation.*`/`_server.*` for the web UI
(`lib.rs:46-51,139-202,207-231,391-440`); `app.bsky.actor.get/putPreferences` behind
`feature = "bsky-support"` (`:442-451`); age-assurance stubs behind `feature = "bsky"` (`:453-462`);
`/.well-known/did.json` + `/atproto-did` (`:467-473`); `/health`, `/robots.txt`, `/u/{handle}/did.json`
(`:489-497`); Telegram/Discord webhooks (`:475-487`). An `atproto-proxy` layer wraps `/xrpc`
(`crates/tranquil-pds/src/lib.rs:85`, `api/proxy.rs:150-260`) with a `PROTECTED_METHODS` never-proxy list
(`proxy.rs:20-110`).

## 5. Auth posture

`AuthSource` is `Session | OAuth | Service{claims}` (`crates/tranquil-pds/src/auth/mod.rs:139-142`); app
passwords arrive through `createSession` and become session tokens carrying a scope string
(`crates/tranquil-api/src/server/session.rs:128-190,307-309`; `migrations/20251234_app_password_scopes.sql`,
`20251235_session_token_scope.sql`). Session and OAuth tokens are both HS256 — OAuth access tokens are
`at+jwt` with an `sid` claim resolved against the `oauth_token` row (`oauth/verify.rs:103-183`), i.e.
reference tokens rather than self-contained ones.

**Full OAuth authorization server**, routes at `crates/tranquil-oauth-server/src/lib.rs:7-81`:

- **PAR** `POST /oauth/par` (`:15`), `require_pushed_authorization_requests: true`
  (`endpoints/metadata.rs:109`), request URIs `urn:ietf:params:oauth:request_uri:{uuid}`
  (`crates/tranquil-types/src/lib.rs:803-809`), 600 s TTL (`endpoints/par.rs:14`).
- **PKCE** mandatory: `code_challenge` required (`par.rs:76-80`), `plain` explicitly rejected
  (`par.rs:264-275`), verified at exchange (`endpoints/token/grants.rs:89`, `token/helpers.rs:19`).
- **DPoP**: `typ=dpop+jwt`, alg allow-list, `htm`/`htu` match, `iat` skew, `ath` binding, jkt thumbprint
  (`crates/tranquil-oauth/src/dpop.rs:102-186`); jti replay table `oauth_dpop_jti` checked at
  `crates/tranquil-pds/src/oauth/verify.rs:80-88`; jkt compared to the token's `dpop_jkt` at `:89-93`.
- **Nonce**: HMAC-derived and self-validating, emitted on every `/oauth/*` and `/xrpc/*` response by
  `dpop_nonce_middleware` (`oauth/verify.rs:404-416`, wired at `crates/tranquil-pds/src/lib.rs:88` and
  `crates/tranquil-oauth-server/src/lib.rs:78-80`).
- **private_key_jwt**: JWKS fetch, kid selection, iss/sub == client_id, exp/iat window, ES256/ES384/EdDSA
  verify (`crates/tranquil-oauth/src/client.rs:392-559`). RS256/384/512 pass the alg check at `:447-455`
  but `verify_rsa` unconditionally errors (`:651-660`).
- **Well-knowns**: `/.well-known/oauth-protected-resource` and `/oauth-authorization-server`
  (`crates/tranquil-oauth-server/src/lib.rs:83-95`, `endpoints/metadata.rs:60-129`) advertising
  `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported`, revocation
  and introspection.
- **Scopes**: `transition:*` plus a granular `repo:`/`blob:`/`rpc:`/`account:`/`identity:`/`include:`
  system in `crates/tranquil-scopes/` (2,200 lines). PAR refuses mixed transition+granular
  (`par.rs:210-214`) and enforces client-registered scopes (`:216-227`).

**Service auth, both directions.** Minting at `getServiceAuth`
(`crates/tranquil-api/src/server/service_auth.rs:58-`) with an `lxm` scope check and a
`PROTECTED_METHODS` deny-list (`:23-44`). Verification in `crates/tranquil-pds/src/auth/service.rs:169-238`:
exp, `aud == did:web:{hostname}`, `lxm` match (`*` wildcard allowed, `auth/mod.rs:60-62`), signature
against the issuer's `#atproto` verification method resolved from PLC or did:web (`:245-300`).

Auth gaps: (a) service-token verification is **ES256K-only** — `service.rs:184-188` rejects any other
`alg`, and key parsing errors `UnsupportedKeyType: expected secp256k1` (`service.rs:52`), so a P-256
peer cannot authenticate; (b) the **DPoP nonce is optional** — `dpop.rs:153-155` validates it only
`if let Some(nonce)`; (c) `client_assertion` **`aud` is unchecked and `jti` is not replay-checked**
(grepping `"aud"`/`"jti"` in `crates/tranquil-oauth/src/client.rs` returns nothing); (d) metadata
advertises `ES512` (`metadata.rs:104,114`) with no `ES512` arm in either
`verify_dpop_signature` (`dpop.rs:195-204`) or the client-assertion dispatch (`client.rs:546-554`);
(e) `oauth_protected_resource.scopes_supported` is hardcoded `vec![]` (`metadata.rs:69`).

## 6. Sync 1.1

One of the more complete non-reference sync-1.1 implementations I have read.

- **`#sync`**: `FrameType::Sync` (`crates/tranquil-pds/src/sync/frame.rs:17-18`),
  `SyncFrame{did,rev,blocks,seq,time}` (`:84-92`), built by `format_sync_event`
  (`crates/tranquil-pds/src/sync/util.rs:331-363`, commit block only in the CAR). Emitted at provisioning
  (`crates/tranquil-api/src/identity/provision.rs:198-206`) and `activateAccount`
  (`crates/tranquil-api/src/server/account_status.rs:462-470`) — the only two call sites of
  `sequence_sync_event`.
- **`prevData`**: `CommitFrame.prev_data` serialized as `prevData` (`sync/frame.rs:44-45`).
  `CommitFrameBuilder::build()` leaves it `None` (`frame.rs:205`); it is filled from the persisted
  `prev_data_cid` in `prepare_commit_event` (`sync/util.rs:386-390`). Written at commit time
  (`crates/tranquil-pds/src/repo_ops.rs:1078`) from the previous commit's `data` CID captured at
  `repo_ops.rs:216-229`; column `repo_seq.prev_data_cid` (`migrations/20251211_initial_schema.sql:170`).
- **Per-op `prev`**: `RepoOp.prev: Option<Cid>` (`sync/frame.rs:62`), populated from ops JSON at
  `repo_ops.rs:1026-1060` — `update` and `delete` carry `prev`, `create` does not.
- **Covering-proof blocks**: yes, deliberately. `finalize_repo_write` (`repo_ops.rs:567-810`) runs an
  inverse-op walk over the new MST (`:584-610`), warning `"firehose proof walk: ops not invertible on new
  MST, consumer will reject frame"` (`:611-618`) when the proof would be short. It then collects every CID
  the write *read* but did not write (`:628-649`) and merges written + read + diff `new_mst_blocks` into
  the event's inline block set (`:766-768`), persisted on the event row (`repo_ops.rs:1062-1068`,
  `migrations/20260407_inline_event_blocks.sql`) and written into the frame CAR (`sync/util.rs:422-434`).
- **No-op update rejection**: `putRecord` short-circuits when the computed record CID equals the existing
  MST entry, returning `commit: None` and emitting nothing
  (`crates/tranquil-api/src/repo/record/write.rs:387-394`).
- `since` on `#commit` is decoded from the previous commit block when it is inline
  (`sync/util.rs:456-461`), else `None`.
- `getHostStatus` absent (relay-only, not a gap); `listReposByCollection` absent (real gap).

Caveat: `importRepo` sequences a `#commit` with **empty `ops`, `prev_cid: None`, `prev_data_cid: None`**
(`crates/tranquil-api/src/repo/import.rs:350-375`) rather than a `#sync`; the later `activateAccount`
`#sync` is what actually re-anchors inductive consumers.

## 7. Firehose

Real axum WebSocket handler (`crates/tranquil-sync/src/subscribe_repos.rs:29-35`).

- **Framing**: two concatenated DAG-CBOR objects, `FrameHeader{op:1,t}` then payload
  (`sync/util.rs:217-241`); error frames use `op: -1` (`:512-524`).
- **Event types**: `#commit`, `#identity`, `#account`, `#sync`, `#info` (`sync/frame.rs:9-21`), dispatched
  at `sync/util.rs:443-464` — matches the canonical union in `.../sync/subscribeRepos.json`.
- **Seq source**: Postgres. `repo_seq.seq` was `BIGSERIAL`
  (`migrations/20251211_initial_schema.sql:160-161`) until
  `migrations/20260529_firehose_outbox_sequencing.sql` turned it into an outbox: rows take a `BIGSERIAL id`
  on insert and `seq` is assigned later from a dedicated `firehose_seq`, so seq is gapless in *publish*
  order. A listener calls `assign_pending_sequences()` then drains and broadcasts
  (`crates/tranquil-sync/src/listener.rs:61-93`), driven by a DB notification channel with a 1 s poll
  fallback (`:48-58`).
- **Cursor / backfill**: `cursor > head` → `FutureCursor` error frame + close
  (`subscribe_repos.rs:138-146`). Window is `firehose.backfill_hours`, default 72 (`example.toml:407`,
  read at `:117-119`); an out-of-window cursor gets an `OutdatedCursor` `#info` frame and is
  fast-forwarded (`:160-181`). Backfill drains in 1000-row batches (`:19,185-234`), then a cutover pass
  (`:236-265`), then live broadcast. Buffer size `firehose.buffer_size` default 10000
  (`example.toml:399`, `state.rs:361-362`).
- **Slow consumers**: `ConsumerTooSlow` is **not implemented** — on `RecvError::Lagged` tranquil re-reads
  the missed range from Postgres and replays it (`subscribe_repos.rs:281-287`, `recover_lagged_events`
  `:51-105`). `ErrorFrameName` has only `FutureCursor` (`sync/frame.rs:100-104`). More forgiving than the
  reference, but a consumer written to expect a `ConsumerTooSlow` disconnect will never see one.

## 8. Account migration / import-export

`repo.importRepo` (`lib.rs:264`) parses the CAR (`sync/import.rs:59`), verifies the commit signature
against the DID doc via `CarVerifier::verify_car` (`repo/import.rs:130`) or a structure-only path
(`:122`), applies it (`sync/import.rs:304-361`), then re-signs a fresh commit with the local key
(`import.rs:224-231`). `repo.listMissingBlobs` (`:95`) LEFT JOINs `record_blobs` against `blobs`
(`crates/tranquil-db/src/postgres/blob.rs:238-248`). `server.checkAccountStatus` `:87`;
`activateAccount`/`deactivateAccount` `:115`/`:119` (activate emits `#account` + `#identity` + `#sync`,
`server/account_status.rs:411-480`); `identity.getRecommendedDidCredentials` `:91` (returns empty
`rotationKeys` for did:web, `identity/did.rs:497-504`); `requestPlcOperationSignature` `:248`,
`signPlcOperation` `:252` (refuses did:web, `plc/sign.rs:44`), `submitPlcOperation` `:256` (refuses
did:web, `plc/submit.rs:29`); `reserveSigningKey` `:232`.

Extras: `verifyMigrationEmail`/`resendMigrationVerification` (`:236-243`), an `inbound_migration` flag
(`migrations/20260523_add_inbound_migration_flag.sql`), and an 11-step Svelte inbound wizard
(`frontend/src/components/migration/InboundWizard.svelte`, `OfflineInboundWizard.svelte`).
`createAccount` accepts an existing `did:plc:` only when a service-auth token from that DID is presented
and the issuer matches (`crates/tranquil-api/src/identity/account.rs:238-258,348-358`).

## 9. did:plc vs did:web

**Service DID is always `did:web:{hostname}`** — served at `/.well-known/did.json`
(`crates/tranquil-api/src/identity/did.rs:128-159`, constructed at `:145-149` with `%3A` port encoding),
reported by `describeServer` (`server/meta.rs:78`), and used as the expected `aud` for inbound service
tokens (`crates/tranquil-pds/src/auth/service.rs:153-157`). No did:plc option for the service identity.

**Account DIDs**, three modes via `did_type` (`crates/tranquil-api/src/identity/account.rs:312-347`):
`"plc"` default → `submit_plc_genesis` (`account.rs:380`, `identity/provision.rs:45`); `"web"` →
PDS-hosted subdomain `did:web:{handle}.{hostname}` (`account.rs:315`, `common.rs:203`), gated by
`server.enable_pds_hosted_did_web` (`example.toml:35`), docs served from the subdomain
(`identity/did.rs:134-143`, `serve_handle_did_doc` `:162`) and `/u/{handle}/did.json` (`:214`);
`"web-external"` → BYO, requiring a pre-reserved signing key, with the flow spelled out in the error text
at `identity/did.rs:330` and ownership checked by `verify_did_web` (`account.rs:336-341`).

did:web accounts get override rows for `alsoKnownAs`/verification methods
(`migrations/20251244_did_web_overrides.sql`, read at `identity/did.rs:187-204`) and
`_account.updateDidDocument`/`getDidDocument` (`lib.rs:198-202`), refused for non-did:web accounts
(`crates/tranquil-api/src/server/migration.rs:38-41`). Outbound resolution handles both methods
(`crates/tranquil-pds/src/did.rs:167-178,345-348`); anything else is rejected with "Only did:web and
did:plc are allowed in atproto" (`did.rs:12`).

## 10. Blobs

Stored outside the repo DB; `blobs` holds only cid → `storage_key`, mime, size, owner, takedown ref
(`migrations/20251211_initial_schema.sql:93-102`). Backend chosen at
`crates/tranquil-storage/src/lib.rs:570-591`.

Validation on `uploadBlob` (`crates/tranquil-api/src/repo/blob.rs`): scope check on the declared content
type (`:62-64`), size ceiling both as an axum body limit (`crates/tranquil-api/src/lib.rs:28-29`) and
in-handler (`blob.rs:94`), and MIME sniffed with the `infer` crate over the first 8 KiB of the staged
object, falling back to the client hint (`:26-30,122-126`).

**GC asymmetry.** Repo *blocks* get real refcounting: `DroppedBlocks{unreachable, decrements}` computed
from the MST diff (`crates/tranquil-pds/src/repo_ops.rs:700-714`), a periodic reachability walk reporting
`leaked_blocks`/`repaired_blocks`/`phantom_blocks_purged` (`crates/tranquil-pds/src/scheduled.rs:509-528`),
and compaction for the tranquil-store backend (`:497-508`). *Blobs* do not: `record_blobs` records
record→blob edges (`migrations/20251243_record_blobs.sql`, backfill at `scheduled.rs:310-352`), but the
only blob deletion path is account teardown — `process_scheduled_deletions` → `delete_account_data`
(`scheduled.rs:690-745`). No sweep deletes a blob orphaned by a record delete, so blob storage grows
monotonically for a live account.

## 11. Moderation / admin and takedown enforcement

`admin.updateSubjectStatus` covers all three subject kinds (`crates/tranquil-api/src/admin/status.rs`):
repo → `set_user_takedown`/`update_repo_status` (`:169-205`), record → `set_record_takedown` (`:257-265`),
blob → `update_blob_takedown` (`:291-299`); `getSubjectStatus` reads them back (`:54,82,114`).

Enforcement runs through `assert_repo_availability`, mapping `takedown_ref.is_some()` →
`AccountStatus::Takendown` → `RepoTakendown` and `deactivated_at` → `RepoDeactivated`
(`crates/tranquil-pds/src/sync/util.rs:131-182`), called on every public sync read (`sync/repo.rs:50,127,279`;
`sync/commit.rs:47`; `sync/blob.rs:31,84`; `sync/deprecated.rs:70,110`). On writes an
`Auth<NotTakendown>` extractor gates `uploadBlob` and `importRepo` (`repo/blob.rs:242`,
`repo/import.rs:48`). Takedown state is reflected in `#account` events (`sync/commit.rs:124-125`).

Also present: a handle/word slur filter carrying its own content warning
(`crates/tranquil-pds/src/moderation/mod.rs:1-14`, regexes `:22-33`, extra words from
`server.banned_words`) and external report forwarding
(`crates/tranquil-api/src/moderation/mod.rs:74-92`). No local labeler, no `com.atproto.label.*` surface.

**Admin UI** is Svelte 5 + Vite in `frontend/`, served as static files at `/app` with SPA fallback
(`crates/tranquil-pds/src/lib.rs:129-149`). `frontend/src/components/dashboard/AdminContent.svelte`
(547 lines) covers server stats (`:94`), account search (`:110`), server config incl. name/logo/theme
colors (`:175,331-390`), Signal device link/unlink (`:243-283`) and account deletion (`:314-320`). It does
not surface takedowns. Sibling panels: app passwords, comms, controllers/delegation, DID document, invite
codes, passkeys, password, repo browser, security, sessions, settings.

## 12. Rate limiting, metrics, health, ops

**Rate limiting is per-endpoint, not middleware.** An axum extractor `RateLimited<P>` /
`OAuthRateLimited<P>` is added to individual handler signatures
(`crates/tranquil-pds/src/rate_limit/extractor.rs:167-195`), plus `check_user_rate_limit*` for DID-keyed
limits (`:248-277`). Twenty policies (`extractor.rs:18-116`) with quotas at
`crates/tranquil-pds/src/state.rs:127-210` — login 10/min, account creation 10/h, TOTP verify 5/5min,
OAuth token 300/min, PAR 30/min, handle update 10/5min plus 50/day.

`check_rate_limit` (`state.rs:428-476`) consults **both** an in-process `governor` keyed limiter
(`rate_limit/mod.rs:13-42`) **and** a distributed limiter, rejecting if either denies. The distributed one
is where Valkey lands: `RedisRateLimiter` runs an INCR+EXPIRE Lua script under an `rl:` prefix
(`crates/tranquil-cache/src/lib.rs:92-128`) and fails **open** on Redis error (`:110-113`). Selection is
`cache.backend`; `"valkey"` needs `VALKEY_URL` plus the `valkey` cargo feature (default-on for the server
binary, `crates/tranquil-server/Cargo.toml:44`), otherwise it warns and falls back to `tranquil-ripple`
(`crates/tranquil-cache/src/lib.rs:178-201`). So Valkey is supported and is the multi-node story, but the
**default distributed limiter is ripple, not Valkey**. `server.disable_rate_limiting` short-circuits
everything (`state.rs:429-431`).

Metrics: Prometheus text at `GET /metrics` (`crates/tranquil-pds/src/lib.rs:100`,
`crates/tranquil-pds/src/metrics.rs:77`) with a request middleware (`lib.rs:104`) and named series for
HTTP, auth-cache hit/miss, firehose subscribers and events, block ops, comms queue depth, rate-limit
rejections, and DB queries (`metrics.rs:27-190`); dashboards in `observability/`.

Health: `/health` and `/xrpc/_health` both call `infra.health_check()` and 503 on failure
(`crates/tranquil-api/src/server/meta.rs:102-119`). Ops: SIGHUP TLS reload
(`crates/tranquil-server/src/main.rs:363-368,390`), graceful shutdown on SIGTERM/Ctrl-C (`:440-476`), a
panic hook that cancels the shutdown token (`:170-175`), a relay-notification circuit breaker (`:300`),
and `config validate` checking secrets, PLC rotation key, TLS material and reserved-TLD handle domains
(`:53-90`).

## 13. Spec deviations and self-declared gaps

**`KNOWN_ISSUES.md` is 22 lines and lists exactly one issue.** There is no "Status" or broader
known-gaps section in it or the README:

> `KNOWN_ISSUES.md:3` "## stream.place iOS app OAuth flow fails"
> `:5` "OAuth flow with stream.place's iOS app (using expo-web-browser's ASWebAuthenticationSession) does
> not complete. After user approves consent, the redirect from our PDS to stream.place's callback URL is
> not followed by ASWebAuthenticationSession."
> `:7` "What does work with stream.place: everything else :P" — and `:15-22` lists eight attempted fixes,
> all failed.

A real open interop bug against a shipping client; nothing in the code contradicts it.

README claims checked against code: passkeys/2FA/TOTP/backup codes/trusted devices (`README.md:14`) —
confirmed (`migrations/20251211_initial_schema.sql:310-348`, `20251226_trusted_devices.sql`, routes
`lib.rs:308-344,166-177`, `webauthn-rs` 0.5 + `totp-rs` 5). SSO (`:15`) — confirmed, six providers
(`example.toml:579-671`, 1,415 lines at `crates/tranquil-oauth-server/src/sso_endpoints.rs`). did:web
(`:16`) — confirmed, §9. Multi-channel comms (`:17`) — confirmed
(`crates/tranquil-comms/src/sender.rs:150,377,475`, `crates/tranquil-comms/src/email/`, Signal via a
vendored `presage` git dep; Discord/Telegram self-register webhooks at boot,
`crates/tranquil-server/src/main.rs:222-292`). Granular scopes + consent UI and scoped app passwords
(`:18-19`) — confirmed (`crates/tranquil-scopes/`, `migrations/20251234_app_password_scopes.sql`,
`/oauth/authorize/consent` at `crates/tranquil-oauth-server/src/lib.rs:40-41`). Delegation (`:20`) —
confirmed (`migrations/20251237_account_delegation.sql`, `20260316_cross_pds_delegation.sql`,
`_delegation.*` at `lib.rs:408-439`, 591 lines at `endpoints/delegation.rs`).

Two README statements where code disagrees:

- `README.md:23` "does require postgres running separately" is **stale** — the `tranquil-store` embedded
  backend removes that (`crates/tranquil-pds/src/state.rs:221-224`,
  `docs/5_INSTALL_USING_EMBEDDED_DB.md:11`), unmentioned in the README. Both label it experimental, so
  conservative rather than wrong.
- `README.md:13` "It is a superset of the reference PDS" is **not literally true** — five canonical
  methods are unrouted: `sync.listReposByCollection`, `identity.resolveDid`, `identity.resolveIdentity`,
  `identity.refreshIdentity`, `admin.updateAccountSigningKey`, `server.requestEmailConfirmation` (six,
  counting the last). Verified absent from `crates/tranquil-api/src/lib.rs` and
  `crates/tranquil-sync/src/lib.rs`, present under `/tmp/gap-scratch/atproto/lexicons/com/atproto/`.

Ranked deviations: (1) `temp.dereferenceScope` POST-with-body vs canonical GET query
(`lib.rs:387-390`, `temp.rs:51-55`); (2) ~20 non-canonical NSIDs squatting in `com.atproto.server.*`;
(3) service-token verification ES256K-only (`auth/service.rs:184-188`); (4) DPoP nonce never required
(`dpop.rs:153-155`); (5) `client_assertion` audience unchecked (`client.rs:466-516`); (6) no
`ConsumerTooSlow` (`subscribe_repos.rs:281-287`); (7) `temp.checkSignupQueue` always `activated: true`
(`temp.rs:31-36`); (8) `describeServer` emits five non-lexicon fields (`server/meta.rs:87-91`); (9) no
orphan-blob GC (§10); (10) `importRepo` sequences an empty `#commit` instead of `#sync`
(`repo/import.rs:350-375`); (11) `panic = "abort"` (`Cargo.toml`) plus a panic hook that cancels the
shutdown token (`crates/tranquil-server/src/main.rs:171-175`) means one handler panic takes the process
down.

## 14. Maturity tier

**serious.**

154 kLOC across 22 crates, AGPL, multi-contributor, with a complete OAuth 2.1 authorization server
(PAR + PKCE + DPoP + nonce + private_key_jwt + both well-knowns), sync-1.1 `prevData` / per-op `prev` /
covering-proof emission driven by an explicit inverse-op proof walk, working two-way migration, two
swappable storage engines, Prometheus metrics, TLS reload, HTTP/3, a 37 kLOC integration suite, and
packaged deployments for containers, Nix, systemd and OpenRC. The residual gaps — six unrouted canonical
endpoints, a POST-vs-GET mismatch on `dereferenceScope`, ES256K-only service auth, an optional DPoP nonce
— are specific fixable defects of a production system rather than the structural absences of a prototype;
it falls short of "reference" only because it deviates from the canonical lexicons in ways a conforming
client can observe.

## Confidence & unknowns

- **UNVERIFIED: runtime behavior.** Nothing was executed. Every claim is a static read of source at
  `1dc0c40`. No build, no migrations run, no endpoint exercised.
- **UNVERIFIED: that the reference PDS serves each endpoint I called missing.** I confirmed those NSIDs
  exist canonically and are absent from tranquil's router; I did not open `/tmp/gap-scratch/bsky-pds` or
  `/tmp/gap-scratch/bluesky-pds` to confirm the reference implements them.
- **UNVERIFIED: `tranquil-store` completeness.** I read the wiring (`state.rs:479-560`) and the docs, not
  the crate. Whether its metastore serves every `RepoRepository` method the Postgres path does is
  unchecked, and its event-log path (`crates/tranquil-store/src/eventlog/`) is unread — so §7's seq-source
  description is verified only for the Postgres backend.
- **UNVERIFIED: whether an unsigned CAR can be imported.** `repo/import.rs:122` offers
  `verify_car_structure_only` alongside the signature-verifying path at `:130`; I did not trace the
  condition that selects between them.
- **UNVERIFIED: DPoP nonce enforcement at the token endpoint specifically.** `grants.rs:122-124` returns a
  nonce challenge when a DPoP-bound flow arrives with *no proof*; I did not read the full branch to see
  whether a proof *lacking a nonce claim* is challenged there, as distinct from the general path at
  `dpop.rs:153-155`.
- **UNVERIFIED: admin UI completeness.** My "does not surface takedowns" claim comes from grepping
  `AdminContent.svelte` alone; I did not read the other 13 dashboard components in full.
- **UNVERIFIED: absence of orphan-blob GC.** I grepped `delete_blob*`, `orphan`, `unreferenced` and read
  `scheduled.rs`'s loop body and `process_scheduled_deletions`. A reaper named something I did not guess
  would have been missed.
- **UNVERIFIED: `#sync` emission under the tranquil-store backend.** `sequence_sync_event` has exactly two
  non-definition call sites, but that backend may sequence events through a path I did not read.
