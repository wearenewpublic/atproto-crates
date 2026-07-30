# rsky-pds — implementation notes

Source examined: `/tmp/gap-scratch/rsky/rsky-pds/**` at commit `6d5412b6924a4bd407ec22f7f68738922cd4c48f`
("Merge pull request #208 from rabble/upstream-fix-expired-token", Thu Jul 16 2026). All citations below are
relative to `/tmp/gap-scratch/rsky/` unless stated otherwise. Canonical lexicons cross-checked against
`/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

**Headline correction to the received description.** rsky-pds is *no longer* a Postgres/Diesel service.
`grep -rn "diesel|sqlx|tokio-postgres|postgres|DATABASE_URL"` over `rsky-pds/src`, `rsky-pds/Cargo.toml`
and `rsky-pds/Dockerfile` returns zero hits. The dependency list is `rusqlite = { workspace = true }`
(`rsky-pds/Cargo.toml:50`) and the crate README opens with "All state lives in SQLite databases and a
blobstore. No external database server is required." (`rsky-pds/README.md:6-9`). The *monorepo* README still
carries the old claim — "It differs from the canonical Typescript implementation by using Postgres instead of
SQLite, s3 compatible blob storage instead of on-disk, and mailgun for emailing" (`README.md:45`) — which is
now stale on two of three counts (SQLite is used; disk blobstore exists alongside S3). Mailgun is still real
(`rsky-pds/Cargo.toml:43`, `rsky-pds/src/mailer/mod.rs`).

---

## 1. Language, stack, build, licence

Rust, edition 2021, toolchain pinned to `1.86` (`rust-toolchain:2-3`). Cargo workspace member
`rsky-pds` v0.3.0, `publish = false` (`rsky-pds/Cargo.toml:2-8`). ~57.4k lines of Rust under
`rsky-pds/src` (213 `.rs` files).

Web framework is **Rocket 0.5.1** pinned exactly (`rsky-pds/Cargo.toml:49`), with `rocket_ws` 0.1.1 for the
firehose websocket (`rsky-pds/Cargo.toml:75`). Templating is askama (`rsky-pds/Cargo.toml:15`) for the OAuth
consent/sign-in pages. Routes are registered by **listing every handler function in a single
`routes![...]` macro** inside `build_rocket()` — `rsky-pds/src/lib.rs:311-454`; each handler carries its own
`#[rocket::get("/xrpc/<nsid>...")]` / `#[rocket::post(...)]` attribute at its definition site. There is no
generated dispatch table and no lexicon-driven router. `main.rs` is 12 lines and just launches
`build_rocket(None)`.

Workspace-internal deps used by the PDS: `rsky-common`, `rsky-crypto`, `rsky-identity`, `rsky-lexicon`,
`rsky-repo`, `rsky-syntax`, `rsky-oauth`, plus the Blacksky-specific `rsky-space` / `rsky-space-host`
(`rsky-pds/Cargo.toml:45,51-58`).

Licence: **Apache-2.0** — `LICENSE` (Apache License Version 2.0, January 2004), declared at
`rsky-pds/Cargo.toml:6` and `README.md:200`.

## 2. Multi-account; deployment model

Multi-account. `com.atproto.server.createAccount` is a real signup path with invite codes, email validation,
handle-domain checks and per-account PLC minting (`rsky-pds/src/apis/com/atproto/server/create_account.rs:44-241`),
and the account DB has `actor` / `account` / `app_password` / `invite_code` tables
(`rsky-pds/src/account_manager/db.rs:13,23,34,56`). `com.atproto.sync.listRepos` enumerates hosted repos
(`rsky-pds/src/apis/com/atproto/sync/list_repos.rs:119`). Invites are on by default
(`PDS_INVITE_REQUIRED`, `rsky-pds/README.md:107`).

Deployment: a single statically-configured binary, container-first. `rsky-pds/Dockerfile` is a two-stage
build (`rust` builder → `debian:bookworm-slim`) whose runtime layer is just the binary plus `ca-certificates`
(`rsky-pds/Dockerfile:69-81`). Startup command is `ROCKET_ADDRESS=0.0.0.0 ROCKET_PORT=${PORT:-2583} ./rsky-pds`
(`rsky-pds/Dockerfile:81`). Configuration is entirely environment variables via `env_to_cfg()`
(`rsky-pds/src/config/mod.rs:136-...`), with `dotenv()` loaded at boot (`rsky-pds/src/lib.rs:206`). No systemd
unit, no installer script, no serverless packaging in this crate. Persistence expectation is "Mount a volume
at `PDS_DATA_DIRECTORY`" (`rsky-pds/README.md:38`, `Dockerfile:76`). TLS is available via Rocket's `tls`
feature (`rsky-pds/Cargo.toml:49`) but nothing in-crate configures it.

## 3. Storage backends

Three service-level SQLite databases plus one SQLite DB **per actor**, all through a hand-rolled async
wrapper over a single `rusqlite::Connection` behind a `Mutex`, executed on the blocking pool with sqlite-style
busy backoff (`rsky-pds/src/db/sqlite.rs:60-115`; WAL + `synchronous=NORMAL` + `foreign_keys=ON` at
`rsky-pds/src/db/sqlite.rs:76-85`). Migrations are embedded `&'static str` SQL applied in slice order and
recorded in a `migrations` table, with out-of-order and unknown-migration detection
(`rsky-pds/src/db/migrator.rs:30-58`).

| Store | Engine | Schema location | Tables |
|---|---|---|---|
| accounts / sessions / invites / OAuth | SQLite (`account.sqlite`) | `rsky-pds/src/account_manager/db.rs:10-` | `actor`, `account`, `app_password`, `refresh_token`, `repo_root`, `invite_code`, `invite_code_use`, `email_token`, `authorization_request`, `device`, `account_device`, `authorized_client`, `token`, `used_refresh_token`, `lexicon` (lines 13,23,34,42,50,56,65,71,79,93,101,113,123,143,150) |
| firehose event log | SQLite (`sequencer.sqlite`) | `rsky-pds/src/sequencer/db.rs:10-24` | `repo_seq (seq INTEGER PRIMARY KEY AUTOINCREMENT, did, eventType, event BLOB, invalidated, sequencedAt)` |
| DID document cache | SQLite (`did_cache.sqlite`) | `rsky-pds/src/did_cache.rs:15` | `did_doc` |
| per-actor repo/records/blob-metadata | SQLite (`actors/<shard>/<did>/store.sqlite`) | `rsky-pds/src/actor_store/db/mod.rs:14-143` | `repo_root`, `repo_block`, `record`, `blob`, `record_blob`, `backlink`, `account_pref`, plus 10 `space_*` tables for the Blacksky spaces extension |
| blob bytes | local disk **or** S3 | `rsky-pds/src/actor_store/disk_blobstore.rs`, `rsky-pds/src/actor_store/aws/s3.rs` | n/a |

`<shard>` = first two hex chars of sha256(DID); each actor also gets a `key` file holding its repo signing key
(`rsky-pds/README.md:11-20`). Open actor DBs are LRU-cached (`PDS_ACTOR_STORE_CACHE_SIZE`, default 100 —
`rsky-pds/README.md:66`). Setting both `PDS_BLOBSTORE_DISK_LOCATION` and `PDS_BLOBSTORE_S3_BUCKET` is an error
(`rsky-pds/README.md:23-24`).

## 4. Endpoint coverage snapshot

All routes are mounted at `rsky-pds/src/lib.rs:311-440`; the per-handler path strings are the citations below.
Every `com.atproto.*` route enumerated here has a real handler body — I found **no `todo!()`, `unimplemented!()`
or "not implemented" stub among the routed `com.atproto.*` handlers** (`grep -rn "todo!()|unimplemented!" apis/`
returns exactly one hit, `rsky-pds/src/apis/com/atproto/server/mod.rs:161`, which is inside a
commented-out `validate_existing_did` block, lines 155-162, and is not routed).

### com.atproto.server — 25/25 canonical methods routed

| NSID | Registration |
|---|---|
| activateAccount | `apis/com/atproto/server/activate_account.rs:61` |
| checkAccountStatus | `apis/com/atproto/server/check_account_status.rs:60` |
| confirmEmail | `apis/com/atproto/server/confirm_email.rs:62` |
| createAccount | `apis/com/atproto/server/create_account.rs:40` |
| createAppPassword | `apis/com/atproto/server/create_app_password.rs:9` |
| createInviteCode | `apis/com/atproto/server/create_invite_code.rs:12` |
| createInviteCodes | `apis/com/atproto/server/create_invite_codes.rs:11` |
| createSession | `apis/com/atproto/server/create_session.rs:104` |
| deactivateAccount | `apis/com/atproto/server/deactivate_account.rs:10` |
| deleteAccount | `apis/com/atproto/server/delete_account.rs:65` |
| deleteSession | `apis/com/atproto/server/delete_session.rs:6` |
| describeServer | `apis/com/atproto/server/describe_server.rs:9` |
| getAccountInviteCodes | `apis/com/atproto/server/get_account_invite_codes.rs:146` |
| getServiceAuth | `apis/com/atproto/server/get_service_auth.rs:54` |
| getSession | `apis/com/atproto/server/get_session.rs:9` |
| listAppPasswords | `apis/com/atproto/server/list_app_passwords.rs:8` |
| refreshSession | `apis/com/atproto/server/refresh_session.rs:49` |
| requestAccountDelete | `apis/com/atproto/server/request_account_delete.rs:40` |
| requestEmailConfirmation | `apis/com/atproto/server/request_email_confirmation.rs:40` |
| requestEmailUpdate | `apis/com/atproto/server/request_email_update.rs:46` |
| requestPasswordReset | `apis/com/atproto/server/request_password_reset.rs:53` |
| reserveSigningKey | `apis/com/atproto/server/reserve_signing_key.rs:19` |
| resetPassword | `apis/com/atproto/server/reset_password.rs:8` |
| revokeAppPassword | `apis/com/atproto/server/revoke_app_password.rs:9` |
| updateEmail | `apis/com/atproto/server/update_email.rs:60` |

Canonical directory listing (`atproto/lexicons/com/atproto/server/`) contains exactly these 25 plus `defs.json`.
Full coverage.

`describeServer` is env-driven only and reads `PDS_SERVICE_HANDLE_DOMAINS` / `PDS_INVITE_REQUIRED` directly
rather than the parsed config (`apis/com/atproto/server/describe_server.rs:11-16`); `phoneVerificationRequired`
is hardcoded `None` (line 22).

### com.atproto.repo — 10/10 canonical methods routed

| NSID | Registration |
|---|---|
| applyWrites | `apis/com/atproto/repo/apply_writes.rs:128` |
| createRecord | `apis/com/atproto/repo/create_record.rs:115` |
| deleteRecord | `apis/com/atproto/repo/delete_record.rs:96` |
| describeRepo | `apis/com/atproto/repo/describe_repo.rs:52` |
| getRecord | `apis/com/atproto/repo/get_record.rs:70` |
| importRepo | `apis/com/atproto/repo/import_repo.rs:74` |
| listMissingBlobs | `apis/com/atproto/repo/list_missing_blobs.rs:12` |
| listRecords | `apis/com/atproto/repo/list_records.rs:77` |
| putRecord | `apis/com/atproto/repo/put_record.rs:126` |
| uploadBlob | `apis/com/atproto/repo/upload_blob.rs:94` |

### com.atproto.sync — 11 routed, 5 canonical NSIDs absent

| NSID | Registration |
|---|---|
| getBlob | `apis/com/atproto/sync/get_blob.rs:48` |
| getBlocks | `apis/com/atproto/sync/get_blocks.rs:61` |
| getCheckout (deprecated) | `apis/com/atproto/sync/get_checkout.rs:40` |
| getHead (deprecated) | `apis/com/atproto/sync/get_head.rs:51` |
| getLatestCommit | `apis/com/atproto/sync/get_latest_commit.rs:41` |
| getRecord | `apis/com/atproto/sync/get_record.rs:62` |
| getRepo | `apis/com/atproto/sync/get_repo.rs:51` |
| getRepoStatus | `apis/com/atproto/sync/get_repo_status.rs:55` |
| listBlobs | `apis/com/atproto/sync/list_blobs.rs:55` |
| listRepos | `apis/com/atproto/sync/list_repos.rs:119` |
| subscribeRepos | `apis/com/atproto/sync/subscribe_repos.rs:38` |

Not served: `getHostStatus`, `listHosts`, `notifyOfUpdate`, `requestCrawl` (all four are relay-side per their
own lexicon descriptions — e.g. `sync/getHostStatus.json` says "Implemented by relays", `sync/listHosts.json`
likewise) and **`listReposByCollection`**, which is *not* relay-scoped
("Enumerates all the DIDs which have records with the given collection NSID.",
`atproto/lexicons/com/atproto/sync/listReposByCollection.json`) — that one is a genuine PDS-side gap.
rsky-pds is a *client* of `requestCrawl`, not a server: `crawlers.rs:56` POSTs to
`{service}/xrpc/com.atproto.sync.requestCrawl` on upstream relays.

### com.atproto.identity — 9/9 canonical methods routed

| NSID | Registration |
|---|---|
| getRecommendedDidCredentials | `apis/com/atproto/identity/get_recommended_did_credentials.rs:15` |
| refreshIdentity | `apis/com/atproto/identity/refresh_identity.rs:13` |
| requestPlcOperationSignature | `apis/com/atproto/identity/request_plc_operation_signature.rs:89` |
| resolveDid | `apis/com/atproto/identity/resolve_did.rs:9` |
| resolveHandle | `apis/com/atproto/identity/resolve_handle.rs:79` |
| resolveIdentity | `apis/com/atproto/identity/resolve_identity.rs:115` |
| signPlcOperation | `apis/com/atproto/identity/sign_plc_operation.rs:15` |
| submitPlcOperation | `apis/com/atproto/identity/submit_plc_operation.rs:154` |
| updateHandle | `apis/com/atproto/identity/update_handle.rs:80` |

### com.atproto.admin — 13 routed, 2 absent

| NSID | Registration |
|---|---|
| deleteAccount | `apis/com/atproto/admin/delete_account.rs:38` |
| disableAccountInvites | `apis/com/atproto/admin/disable_account_invites.rs:10` |
| disableInviteCodes | `apis/com/atproto/admin/disable_invite_codes.rs:27` |
| enableAccountInvites | `apis/com/atproto/admin/enable_account_invites.rs:10` |
| getAccountInfo | `apis/com/atproto/admin/get_account_info.rs:77` |
| getAccountInfos | `apis/com/atproto/admin/get_account_infos.rs:46` |
| getInviteCodes | `apis/com/atproto/admin/get_invite_codes.rs:152` |
| getSubjectStatus | `apis/com/atproto/admin/get_subject_status.rs:94` |
| sendEmail | `apis/com/atproto/admin/send_email.rs:51` |
| updateAccountEmail | `apis/com/atproto/admin/update_account_email.rs:37` |
| updateAccountHandle | `apis/com/atproto/admin/update_account_handle.rs:66` |
| updateAccountPassword | `apis/com/atproto/admin/update_account_password.rs:10` |
| updateSubjectStatus | `apis/com/atproto/admin/update_subject_status.rs:85` |

Absent: `com.atproto.admin.searchAccounts`, `com.atproto.admin.updateAccountSigningKey` (both present in
`atproto/lexicons/com/atproto/admin/`).

### com.atproto.moderation / temp / label

`moderation.createReport` — `apis/com/atproto/moderation/create_report.rs:21`. It validates `reasonType` is
non-empty and then **proxies to the configured report service**; there is no local moderation store
(`apis/com/atproto/moderation/create_report.rs:8-42`, `pipethrough_procedure`).

`temp.checkSignupQueue` — `apis/com/atproto/temp/check_signup_queue.rs:9`. Honest constant-response stub by
design: `activated: true, place_in_queue: None` with the doc comment "Since rsky-pds is not an entryway,
accounts are never queued and are always activated." Not served: `temp.checkHandleAvailability`,
`temp.dereferenceScope`, `temp.revokeAccountCredentials`, `temp.addReservedHandle`, `temp.fetchLabels`,
`temp.requestPhoneVerification`. `com.atproto.label.queryLabels` / `subscribeLabels` are not routed at all.

### Non-canonical extensions

Two families are served under the `com.atproto.*` namespace that do **not** exist in the canonical lexicon
tree (`ls atproto/lexicons/com/atproto/ | grep -i space` → nothing): `com.atproto.simplespace.*` (6 routes,
`lib.rs:377-382`) and `com.atproto.space.*` (18 routes, `lib.rs:383-400`), backed by repo-local lexicons at
`lexicons/com/atproto/space/` and `lexicons/com/atproto/simplespace/` (27 JSON files total) and roughly 4.6k
lines of handler/store code. Squatting the `com.atproto` NSID authority for a vendor extension is a namespace
deviation worth flagging.

### Catch-all proxy

`apis/mod.rs:58` (`GET /xrpc/<nsid>?<query..>`, rank 2) and `apis/mod.rs:90` (`POST /xrpc/<nsid>`, rank 2)
forward unmatched XRPC calls to the AppView. The allowlist is an `FromParam` impl that accepts only NSIDs
starting `app.bsky.` or `chat.bsky` (`apis/mod.rs:26-31`), so `com.atproto.*` methods never fall through to
the proxy — an unrouted `com.atproto.*` NSID 404s. `chat.bsky.*` privileged methods are gated behind
`AuthScope::Access | AppPassPrivileged` (`apis/mod.rs:36-53`, list at `pipethrough.rs:532-550`).

A dozen `app.bsky.*` read endpoints are served locally with read-after-write overlay
(`lib.rs:413-423`, `src/read_after_write/viewer.rs`).

## 5. Auth posture

**Legacy session JWTs + app passwords: yes.** ES256K access/refresh tokens signed with
`PDS_JWT_KEY_K256_PRIVATE_KEY_HEX` (`auth_verifier.rs:43-49`); access TTL 2h, refresh TTL 90d
(`account_manager/helpers/auth.rs:111,133`). Scopes are the legacy set `com.atproto.access` /
`.refresh` / `.appPass` / `.appPassPrivileged` / `.signupQueued` (`auth_verifier.rs:52-80`). Refresh tokens
are persisted with rotation chaining in the `refresh_token` table (`account_manager/helpers/auth.rs:218-310`).

**Full OAuth authorization server: yes, and it is no longer partial.** `rsky-oauth` (workspace crate,
`rsky-pds/Cargo.toml:45`) is wired into Rocket as `SharedOAuthProvider` (`src/oauth/mod.rs:24-58`) and
mounted at `lib.rs:427-437`:

| Endpoint | Registration |
|---|---|
| `POST /oauth/par` | `src/oauth/routes.rs:166` |
| `POST /oauth/token` | `src/oauth/routes.rs:210` |
| `POST /oauth/revoke` | `src/oauth/routes.rs:257` |
| `GET /oauth/jwks` | `src/oauth/routes.rs:285` |
| `GET /.well-known/oauth-authorization-server` | `src/oauth/routes.rs:292` |
| `GET /.well-known/oauth-protected-resource` | `src/oauth/routes.rs:300` |
| `GET /oauth/authorize` + sign-in / select / accept / reject | `lib.rs:433-437`, HTML via askama (`src/oauth/templates.rs`) |

The published AS metadata declares `require_pushed_authorization_requests: true`,
`code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["none",
"private_key_jwt"]`, `dpop_signing_alg_values_supported: ["ES256","ES256K"]`,
`client_id_metadata_document_supported: true`, `authorization_response_iss_parameter_supported: true`
(`rsky-oauth/src/provider.rs:741-777`). PKCE is *mandatory* and only S256 accepted — a missing
`code_challenge_method` is rejected with "code_challenge_method is required"
(`rsky-oauth/src/client.rs:131-147`). DPoP nonces rotate from `PDS_DPOP_SECRET` with an in-memory replay
store (`src/oauth/mod.rs:35-52`), and every OAuth response carries `DPoP-Nonce` +
`Access-Control-Expose-Headers` (`src/oauth/routes.rs:100-106`).

Resource-side verification is real: `Authorization: DPoP <token>` is detected
(`auth_verifier.rs:856-865`) and validated through `provider.verify_access_token(...)` with the reconstructed
`htm`/`htu` and the `ath`-bound access token (`auth_verifier.rs:889-900`); failures stage a
`WWW-Authenticate: DPoP error=...` header (`auth_verifier.rs:913-923`). Granted scopes are mapped onto the
legacy model — `atproto` is required, `transition:chat.bsky` ⇒ `AppPassPrivileged`, `transition:generic` ⇒
`AppPass`, anything else errors (`auth_verifier.rs:842-854`). **Consequence: the new granular scope grammar
(`repo:*`, `blob:*`, `rpc:*`, `account:email`, `include:`) is not modelled** — only the two transition scopes
are honoured, and `com.atproto.temp.dereferenceScope` is unimplemented.

**Service auth (inter-service JWT):** both directions exist. Minting is
`com.atproto.server.getServiceAuth` (`apis/com/atproto/server/get_service_auth.rs:54`) via
`create_service_jwt` (`account_manager/helpers/auth.rs:147-186`, ES256K, low-S normalised at line 178, with
`lxm` and `jti`). Verification of inbound service JWTs is `xrpc_server/auth.rs:44-120` — checks expiry,
audience against own DID, and signature against the issuer's `atproto` verification method with a
rotation-retry (`xrpc_server/auth.rs:91-107`).

Two deviations in this area, both verifiable from the source alone:

1. `get_service_auth` validates the caller's requested `exp` (`get_service_auth.rs:22-33`) and then
   **discards it**: `create_service_jwt(ServiceJwtParams { iss, aud, exp: None, lxm, jti: None })`
   (`get_service_auth.rs:42-48`). Every minted token therefore uses the default expiry.
2. Time units are inconsistent. `create_service_jwt` computes `now` in **microseconds**
   (`auth.rs:149-152`) then sets `exp = (now + MINUTE) / 1000` (`auth.rs:153-155`) where
   `MINUTE = 60_000` (`rsky-common/src/time.rs:8`), yielding milliseconds-since-epoch plus 60. The verifier
   compares a **microsecond** `now` against that value: `if now > payload.exp as u128 { bail!("JwtExpired") }`
   (`xrpc_server/auth.rs:59-66`). The canonical `exp` claim is seconds. This is an internal unit mismatch and
   a wire-format mismatch with the TS reference; I did not run the code to observe the failure mode.

**Admin auth:** HTTP Basic against `PDS_ADMIN_PASSWORD` / `PDS_ADMIN_PASS`
(`auth_verifier.rs:1162-1163`, parser at `auth_verifier.rs:1167`), exposed as `Moderator`
(`auth_verifier.rs:641-646`) and `AdminToken` (`auth_verifier.rs:676-686`) request guards.

Two further inline `@TODO`s admit missing checks: `create_invite_code.rs:21` and
`create_invite_codes.rs:20` both carry "@TODO: verify admin auth token".

## 6. Sync 1.1 status

Substantially implemented — this is one of rsky-pds's stronger areas.

- **`#sync` events emitted.** `SeqEvt::TypedSyncEvt` exists (`sequencer/events.rs:179`), built by
  `format_seq_sync_evt` (`sequencer/events.rs:332-345`) and dispatched over the wire at
  `apis/com/atproto/sync/subscribe_repos.rs:251-277`. Emit sites: account creation
  (`create_account.rs:193-207`) and `activateAccount` (`activate_account.rs:52`).
- **`prevData` on commits.** `CommitEvt.prev_data` serialises as `prevData` and is skipped when `None`
  (`sequencer/events.rs:61-62`); it is populated from the pre-write MST root:
  `let previous_data = repo.commit.data; ... prev_data: Some(previous_data)`
  (`actor_store/mod.rs:578, 606-610`). It is threaded onto the wire frame at `subscribe_repos.rs:182`.
  Initial `create_repo` correctly emits `prev_data: None` (`actor_store/mod.rs:473`).
- **Deprecated `prev` dropped.** `CommitEvt.prev` is documented "DEPRECATED -- unused in sync v1.1. Retained
  for deserializing legacy events." (`sequencer/events.rs:52-54`) and set to `None` at build time with the
  comment "deprecated in Sync 1.1; reference implementation omits it" (`sequencer/events.rs:257`).
  `too_big` is hardcoded `false` "always false in Sync 1.1" (`sequencer/events.rs:254`).
- **Per-op `prev`.** `CommitEvtOp.prev` is "For updates and deletes, the previous record CID. Omitted for
  creates." (`sequencer/events.rs:41-42`). It is populated for *every* write, not just swap-checked ones —
  see the explicit comment "op.prev must be populated for every update/delete, not only swap-checked writes"
  and the unconditional `get_record` lookup at `actor_store/mod.rs:554-574`.
- **Covering-proof blocks in the CAR slice.** `rsky-repo` builds a separate `relevant_blocks` map by walking
  `add_blocks_for_path` for each written key (`rsky-repo/src/repo.rs:254-261`), adds the new leaves
  (`repo.rs:268`) and the new commit block (`repo.rs:287`). The PDS then backfills any relevant block missing
  from the diff — "find blocks that are relevant to ops but not included in diff (for instance a record that
  was moved but cid stayed the same)" (`actor_store/mod.rs:596-605`). `format_seq_commit` merges
  `new_blocks` + `relevant_blocks` into the CAR (`sequencer/events.rs:230-231, 250`). There is a dedicated
  regression test `includes_all_relevant_blocks_for_proof_commit_data` (`rsky-repo/src/repo.rs:816`).
- **No-op updates rejected.** `putRecord` compares the existing record CID with the prepared write CID and
  skips `process_writes` entirely when equal, so no commit is formed and nothing is sequenced
  (`apis/com/atproto/repo/put_record.rs:98-115`).
- `sync_evt_data_from_commit` hard-fails if the commit block is absent from `relevant_blocks`
  (`sequencer/events.rs:347-360`), with a test at `sequencer/tests.rs:478-488`.
- **`getRepoStatus`** is implemented and maps the full Sync-1.1 status vocabulary including
  `Desynchronized` and `Throttled` (`apis/com/atproto/sync/get_repo_status.rs:37-47`).
- **Gaps:** `com.atproto.sync.getHostStatus` and `com.atproto.sync.listReposByCollection` are not served
  (absent from `lib.rs:401-411`). `getHostStatus` is relay-scoped by its own lexicon so this is expected;
  `listReposByCollection` is not.

Account-status events cover the full enum including `Desynchronized`/`Throttled`
(`sequencer/events.rs:313-321`). Note `TypedHandleEvt` is **commented out** of the `SeqEvt` union
(`sequencer/events.rs:176`) even though `format_seq_handle_update` still writes `handle` rows to
`repo_seq` (`sequencer/events.rs:274-285`, called at `identity/update_handle.rs:69`) — those rows can be
written but cannot be deserialised back into a `SeqEvt` (`sequencer/events.rs:192-206` has no `"handle"` arm),
so a stored legacy handle event would error the stream at `Unknown event type`.

## 7. Firehose

`com.atproto.sync.subscribeRepos` is implemented as a Rocket `rocket_ws` stream
(`apis/com/atproto/sync/subscribe_repos.rs:38-327`).

- **Framing:** DAG-CBOR header concatenated with DAG-CBOR body —
  `[struct_to_cbor(&self.header)?, struct_to_cbor(&self.body)?].concat()`
  (`xrpc_server/stream/frames.rs:59`), with `MessageFrameHeader { op, t }` and `ErrorFrameHeader`
  (`xrpc_server/stream/types.rs`). `t` is set to `#commit` / `#sync` / `#identity` / `#account`
  (`subscribe_repos.rs:184,210,237,264`).
- **Event types emitted:** `#commit`, `#identity`, `#account`, `#sync` (four arms,
  `subscribe_repos.rs:158,198,224,251`). No `#handle`, no `#tombstone`, no `#info` other than the
  `OutdatedCursor` notice.
- **Seq source:** `repo_seq.seq INTEGER PRIMARY KEY AUTOINCREMENT` in `sequencer.sqlite`
  (`sequencer/db.rs:13-14`).
- **Cursor resume:** supported. A cursor beyond `curr()` yields an `ErrorFrame{error:"FutureCursor"}`
  (`subscribe_repos.rs:83-91`).
- **Backfill window:** `PDS_REPO_BACKFILL_LIMIT_MS` (`README.md:113`, `config`
  `subscription.repo_backfill_limit_ms`). A cursor older than the window yields a `#info` message frame
  named `OutdatedCursor` — "Requested cursor exceeded limit. Possibly missing events" — and the stream then
  restarts from the earliest event inside the window (`subscribe_repos.rs:93-121`).
- **Slow-consumer handling:** an `AsyncBuffer` bounded by `PDS_MAX_SUBSCRIPTION_BUFFER` (default 500,
  `sequencer/outbox.rs:30-42`); overflow surfaces as `AsyncBufferFullError` → `anyhow!("Stream consumer too
  slow.")` (`sequencer/outbox.rs:120-124`) which the route converts into an `EventStreamError` error frame and
  closes (`subscribe_repos.rs:139-146`). A 30s server ping keeps the socket alive
  (`subscribe_repos.rs:132, 319-322`).
- One structural smell: the outbox's event-emitter callback spawns a **fresh `tokio::runtime::Runtime` per
  batch** and `block_on`s it (`sequencer/outbox.rs:82-88`).

Relay notification: `Crawlers::notify_of_update` POSTs `requestCrawl` to each `PDS_CRAWLERS` host, rate-limited
to once per 20 minutes (`crawlers.rs:7, 37-60`).

## 8. Account migration / import-export

All the standard migration verbs are present and non-trivial:

| Method | Site | Notes |
|---|---|---|
| `repo.importRepo` | `apis/com/atproto/repo/import_repo.rs:74` | streams CAR with a `Content-Length`-enforced 100 MB cap (`IMPORT_REPO_LIMIT`, line 34), `read_stream_car_with_root`, then `verify_diff` from `rsky-repo::sync::consumer` (line 20) and replays writes |
| `repo.listMissingBlobs` | `apis/com/atproto/repo/list_missing_blobs.rs:12` | backed by a `record_blob` rows-without-`blob`-row query (`actor_store/blob/mod.rs:413-414`) |
| `server.checkAccountStatus` | `apis/com/atproto/server/check_account_status.rs:60` | real counts: `repo_blocks`, `indexed_records`, `imported_blobs`, `expected_blobs`, `valid_did` (lines 29-56). `private_state_values` hardcoded `0` (line 52) |
| `server.activateAccount` | `apis/com/atproto/server/activate_account.rs:61` | asserts the DID doc points at this PDS, then emits `#account` + `#identity` + `#sync` (lines 21, 46-52) |
| `server.deactivateAccount` | `apis/com/atproto/server/deactivate_account.rs:10` | |
| `identity.signPlcOperation` | `apis/com/atproto/identity/sign_plc_operation.rs:15` | requires a `PlcOperation` email token (lines 29-36), fetches the last op from the PLC directory, merges omitted fields from it |
| `identity.submitPlcOperation` | `apis/com/atproto/identity/submit_plc_operation.rs:154` | sequences an `#identity` event afterwards (line 186) |
| `identity.requestPlcOperationSignature` | `apis/com/atproto/identity/request_plc_operation_signature.rs:89` | |
| `identity.getRecommendedDidCredentials` | `apis/com/atproto/identity/get_recommended_did_credentials.rs:15` | returns `alsoKnownAs`, `atproto` verification method, PDS rotation key, `atproto_pds` service endpoint (lines 30-52) |

**One hard blocker for the canonical inbound-migration flow:** `createAccount` explicitly rejects the
`plcOp` input — `return Err(ApiError::InvalidRequest("Unsupported input: \`plcOp\`"))`
(`apis/com/atproto/server/create_account.rs:257-261`) — even though the canonical lexicon defines it
("A signed DID PLC operation to be submitted as part of importing an existing account to this instance",
`atproto/lexicons/com/atproto/server/createAccount.json`). The bring-your-own-DID path (`input.did` present)
still works and creates the account `deactivated = true`
(`create_account.rs:316-333`), which is the intended migration entry point.

Also worth flagging in that same block: the requester check reads
`if input_did == requester.unwrap_or("n/a") { return Err(ApiError::AuthRequiredError(...)) }`
(`create_account.rs:317-322`) — the comparison rejects when the supplied DID *matches* the authenticated
issuer and permits when it does not. The canonical semantic (and the error message "Missing auth to create
account with did:") is the inverse. I am reporting the operator as written; I did not execute it.

## 9. did:plc vs did:web

**Account DIDs: did:plc only, in practice.** `format_did_and_plc_op` always builds a PLC create op
(`create_account.rs:347-378`) and there is no did:web minting path. A pre-existing did:web *can* be handed in
via `input.did`, but such an account is created deactivated and **can never be activated**:
`activate_account` calls `assert_valid_did_documents_for_service`
(`activate_account.rs:21`), which does `if did.starts_with("did:plc") { ... } else { bail!("Not yet
supporting did:web") }` (`apis/com/atproto/server/mod.rs:99-118`). The same function backs
`is_valid_did_doc_for_service`, so `checkAccountStatus.validDid` is likewise always false for a did:web
account (`check_account_status.rs:42-44`). So the "did:plc-only" characterisation still holds today —
verified, not assumed.

Resolution of *foreign* did:web is fine: `rsky-identity` ships a `DidWebResolver`
(`rsky-identity/src/did/web_resolver.rs:13`) registered in the multi-method resolver
(`rsky-identity/src/did/did_resolver.rs:46-47`), and that resolver is the one the PDS constructs
(`rsky-pds/src/lib.rs:254-268`).

**Service DID: `did:web` by default but not self-served.** `PDS_SERVICE_DID` defaults to
`format!("did:web:{hostname}")` (`config/mod.rs:145`). There is **no `/.well-known/did.json` route** — grep for
`did.json` across `rsky-pds/src` returns nothing; the only `.well-known` routes are `/atproto-did`
(`well_known.rs:23`) and the two OAuth metadata documents (`oauth/routes.rs:292,300`). An operator relying on
the default therefore has an unresolvable service DID unless a reverse proxy serves the document. Handle
resolution via `/.well-known/atproto-did` *is* served, gated on the `Host` header matching a configured
service handle domain (`well_known.rs:23-58`).

## 10. Blobs

Bytes live in one of two backends selected at boot by `BlobstoreFactory`
(`actor_store/blobstore.rs`, wired at `lib.rs:252`): local disk
(`actor_store/disk_blobstore.rs`, 482 lines) or S3 via `aws-sdk-s3` (`actor_store/aws/s3.rs`, 332 lines).
Metadata lives in the per-actor `blob` table plus a `record_blob` join table
(`actor_store/db/mod.rs:39,50`).

Upload path `upload_blob_and_get_metadata` runs sha256, MIME sniffing via `infer`, and image inspection
concurrently, then promotes from a temp key (`actor_store/blob/mod.rs:130-145`). Size cap is
`PDS_BLOB_UPLOAD_LIMIT`, default 5 MB (`config/mod.rs`, `README.md:55`).

**GC / ref-counting is real.** `process_write_blobs` calls `delete_dereferenced_blobs`
(`actor_store/blob/mod.rs:201, 222`), which deletes `record_blob` rows for the affected record URIs with
`RETURNING "blobCid"` (line 240), re-checks whether any surviving row still references each CID (line 261),
and only then calls `blobstore.delete_many(cids)` (line 313). MST-block GC is likewise ref-count-aware:
`get_duplicate_record_cids` removes CIDs still referenced by another record before they are marked removed
(`actor_store/mod.rs:588-594`).

Takedown is enforced at read time — `get_blob_metadata` selects
`FROM blob WHERE cid = ?1 AND "takedownRef" IS NULL` and `get_blob` goes through it
(`actor_store/blob/mod.rs:91, 107-115`), so `com.atproto.sync.getBlob` cannot serve a taken-down blob.
There is also a quarantine/unquarantine blobstore operation (`actor_store/blob/mod.rs:525-526`).

## 11. Moderation / admin surface & takedown enforcement

`com.atproto.admin.updateSubjectStatus` handles all three canonical subject shapes:
`RepoRef` → `takedown_account`, `StrongRef` → `update_record_takedown_status`, `RepoBlobRef` →
`update_blob_takedown_status` (`apis/com/atproto/admin/update_subject_status.rs:28-59`); it also handles the
`deactivated` attribute for repos (lines 61-71) and sequences an `#account` event afterwards (lines 73-78).
`getSubjectStatus` mirrors it (`apis/com/atproto/admin/get_subject_status.rs:94`).

Enforcement:
- account level — `takedownRef` is checked in the auth guard when `check_takedown` is set
  (`auth_verifier.rs:994`), which the `AccessFull`-family guards do (`auth_verifier.rs:280,386,420`), and
  account listings filter `actor."takedownRef" IS NULL` (`account_manager/helpers/account.rs:82`);
  read paths go through `assert_repo_availability` (`sync/get_repo.rs:43`, `sync/get_blob.rs:33`).
- record level — `update_record_takedown_status` on the actor store.
- blob level — enforced in `get_blob_metadata` as noted above.
- `AccountStatus::Takendown` surfaces on the firehose (`sequencer/events.rs:314`) and in
  `getRepoStatus` (`sync/get_repo_status.rs:42`).

Report intake is proxy-only (§4). There is no local labeler, no `com.atproto.label.*` surface, and no
`tools.ozone.*` routes.

## 12. Rate limiting, metrics, health, ops

- **Rate limiting: none.** `grep -rn "rate_limit|RateLimit|ratelimit|governor|tower::limit"` over
  `rsky-pds/src` returns zero hits. `apis/com/atproto/server/create_session.rs:112` carries an explicit
  `// @TODO: Add rate limiting` on the login handler.
- **Metrics: none.** `grep -rn "prometheus|metrics|opentelemetry"` over `rsky-pds/src` returns zero hits.
  The roadmap lists telemetry as unstarted: "Adding telemetry in the services mentioned above to yield
  observability" (`ROADMAP.md:77`).
- **Health: two endpoints.** `GET /xrpc/_health` runs `SELECT 1` against the account DB and returns a version
  string, 503 on failure (`lib.rs:125-153`); `GET /xrpc/_health/live` is a pure liveness probe with the
  comment "must never touch the database" (`lib.rs:155-159`).
- **Logging:** `tracing` + `tracing-subscriber` (`Cargo.toml:72-73`) with `#[tracing::instrument(skip_all)]`
  on essentially every handler.
- **Hardening:** Rocket `Shield` with `NoSniff` (`lib.rs:309, 444`) and a permissive CORS fairing —
  `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`
  (`lib.rs:186-194`), a combination browsers reject and which signals the CORS policy has not been thought
  through for credentialed use.
- **Tests:** 3.5k lines of integration tests across 5 files (`tests/integration_tests.rs` 553,
  `tests/oauth_tests.rs` 723, `tests/expired_token_tests.rs` 149, plus 1.9k lines of spaces tests), with
  unit tests in `auth_verifier.rs`, `did_cache.rs`, `sequencer/tests.rs`, `actor_store/tests.rs`,
  `background.rs`, `space_scope.rs`.
- A separate `rsky-pdsadmin` crate exists in the workspace (not examined per scope).

## 13. Notable spec deviations & explicitly-unsupported features

The project's own candid status text:

> "***This library is a work in progress. Things will change. Things are incomplete. Things will break. Until
> the project reaches version 1.0.0, stability will not be guaranteed.***" — `README.md:24-25`

The monorepo roadmap still lists as **unchecked** for rsky-pds: stability/stress testing, multi-backend blob
storage, "Implement server-side OAuth flows including DPoP", "Integrate support for scoped auth and private
state", and user-facing web pages (`ROADMAP.md:15-28`). **Code disagrees with the roadmap on OAuth**: PAR,
PKCE-S256, DPoP with nonce rotation, private_key_jwt, both well-knowns, and askama-rendered sign-in/consent
pages all exist today (§5) — those two roadmap boxes are stale, not the code. Scoped auth remains genuinely
unimplemented (`auth_verifier.rs:842-854` only understands the two transition scopes).

`TODO.md` is not about the PDS at all — it is a Blacksky community-posts feature list
(`TODO.md:1`, items scoped to `blacksky.community` and `rsky-wintermute`).

Deviations verified in code:

1. Monorepo README claims Postgres; the crate is SQLite (`README.md:45` vs `rsky-pds/Cargo.toml:50`,
   `rsky-pds/README.md:6-9`).
2. `createAccount` rejects `plcOp` (`create_account.rs:257-261`) — blocks the lexicon-defined
   signed-PLC-op import path.
3. `createAccount` requester/DID comparison is written as `==` where the error message implies `!=`
   (`create_account.rs:317-322`).
4. did:web account DIDs cannot be activated (`apis/com/atproto/server/mod.rs:116`).
5. Service DID defaults to `did:web:{hostname}` but no `did.json` is served (§9).
6. `getServiceAuth` discards the requested `exp` (`get_service_auth.rs:42-48`); service-JWT `exp` units are
   inconsistent between minting and verification (§5).
7. `com.atproto.sync.listReposByCollection` and `com.atproto.admin.searchAccounts` /
   `updateAccountSigningKey` are unimplemented.
8. Two vendor families are served under the reserved `com.atproto` namespace (`com.atproto.space.*`,
   `com.atproto.simplespace.*`) — `lib.rs:377-400`.
9. `#handle` events are written to `repo_seq` but removed from the deserialisable `SeqEvt` union
   (`sequencer/events.rs:176, 192-206` vs `274-285`).
10. `checkAccountStatus.privateStateValues` hardcoded `0` (`check_account_status.rs:52`).
11. CORS `*` + `allow-credentials: true` (`lib.rs:186-194`).
12. No rate limiting anywhere, including on `createSession` (`create_session.rs:112`).

## 14. Maturity tier

**serious.**

It is a multi-account, container-deployable PDS with full `com.atproto.server`/`repo`/`identity` coverage, a
working Sync-1.1 firehose (covering proofs, `prevData`, per-op `prev`, `#sync` events, no-op suppression),
a complete OAuth 2.1 authorization server with PAR/PKCE-S256/DPoP/private_key_jwt, real blob ref-counting and
GC, a full takedown surface, migration verbs including `importRepo` with CAR diff verification, and 3.5k
lines of integration tests — far beyond hobby scope, and it backs a real deployment (blacksky). It falls short
of "reference" because of concrete correctness and operational gaps: no rate limiting or metrics at all,
did:web accounts unactivatable, `plcOp` import rejected, no self-served service `did.json`, service-JWT `exp`
unit inconsistency, and the project's own README still warning that things are incomplete and will break
before 1.0.0.

---

## Confidence & unknowns

Verified by reading source: everything above with a `file:line` citation. Endpoint coverage was derived from
`grep -rn '"/xrpc/'` over `rsky-pds/src` cross-referenced against the `routes![...]` list at `lib.rs:311-440`
and against the canonical lexicon directory listings; I did not rely on any project checklist.

Not verified:

- **Runtime behaviour.** I did not build or run rsky-pds. The service-JWT `exp` unit mismatch (§5 item 2) and
  the `createAccount` requester comparison (§8) are read off the source; I did not execute them or write a
  test to observe the failure. UNVERIFIED: whether some upstream coercion or a caller-side workaround makes
  either benign in practice — would need `cargo test -p rsky-pds` plus a live service-auth round trip.
- **Conformance testing.** UNVERIFIED: whether the emitted firehose frames actually validate against a real
  relay / `@atproto/repo` consumer, and whether the covering-proof set is complete for every MST shape.
  Would need running the binary against `bluesky-social/atproto` interop tests.
- **`rsky-oauth` internals beyond the surface I quoted.** I read `client.rs` (PKCE/private_key_jwt),
  `provider.rs:741-786` (metadata) and `dpop.rs` signatures. UNVERIFIED: nonce rotation correctness, replay
  store eviction, refresh-token rotation race handling.
- **`rsky-repo` MST correctness.** I read the commit-formatting path (`repo.rs:230-300`) but not the MST
  implementation itself.
- **The `com.atproto.space.*` / `simplespace.*` extension semantics.** ~4.6k lines skipped per scope; I only
  established that they are routed, repo-local-lexicon-backed, and not canonical.
- **`rsky-pdsadmin`.** Out of scope; not read. UNVERIFIED whether it supplies an ops/CLI story that would
  change §12.
- **README/env-var accuracy.** The crate README's env table (`rsky-pds/README.md:44-121`) was spot-checked
  against `config/mod.rs` for `PDS_SERVICE_DID`, `PDS_INVITE_REQUIRED`, `PDS_BLOB_UPLOAD_LIMIT`,
  `PDS_SERVICE_HANDLE_DOMAINS` and the blobstore/DPoP vars; the remaining ~30 entries were not each traced to
  a `env_str`/`env_int` call site.
- **Git history.** I read one commit's tree. UNVERIFIED: how recently the Postgres→SQLite migration landed,
  or whether a Postgres build path survives on another branch.
