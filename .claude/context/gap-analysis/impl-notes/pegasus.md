# pegasus — implementation notes

Source root `/tmp/gap-scratch/pegasus/**`; citations are repo-relative to it. Lexicon claims checked against `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`. The local clone is a single squashed commit (`7c18e8ed`, 2026-05-31), so no history-based claims are possible.

## 1. Language, stack, build, licence

OCaml 5.4.1 on dune (`dune-project:1`; every package pins `(ocaml (= 5.4.1))`, e.g. `:59`). Eight opam packages — `pegasus`, `frontend`, `mist`, `ipld`, `kleidos`, `hermes`, `hermes-cli`, `hermes_ppx` — plus a `tailwindcss` shim (`dune-project:53-186`). HTTP is Dream (`bin/main.ml:283`, port 8008); DB is Caqti + `ppx_rapper` (`dune-project:63-65,83-84`); the web UI is MLX/melange/server-reason-react (`dune-project:91-104`, dialect at `:188-194`).

The build needs several unmerged forks pinned in-tree — Dream (`dune-project:24-29`), `ppx_rapper` (`:30-35`), `gluten-lwt` (`:37-41`) — and, notably, **a personally forked dune**, pinned at `Dockerfile:5` (`DUNE_PIN=git+https://github.com/futurGH/dune#336d7bd…`) and installed by `tools/update` per `README.md:142`.

Licence: **MPL-2.0** (`dune-project:12`, `LICENSE:1`, `Dockerfile:50`).

## 2. Multi-account, deployment model

Multi-account: accounts share an `actors` table (`pegasus/lib/migrations/data_store/001_initial_schema.sql:1-15`) and `sync.listRepos` pages over all of them (`pegasus/lib/api/sync/listRepos.ml:14`). Signup is invite-gated by default (`pegasus/lib/env.ml:31-32`). Handles are subdomains: `describeServer` advertises `availableUserDomains = ["." ^ hostname]` (`pegasus/lib/api/server/describeServer.ml:6`) and `/.well-known/atproto-did` only answers for `Host` ending in `.{PDS_HOSTNAME}` (`pegasus/lib/api/well_known.ml:69-83`).

Deployment is Docker Compose: two-stage Dockerfile producing `/bin/pegasus` + `/bin/gen-keys` (`Dockerfile:43-46`) with a Caddy sidecar terminating TLS for `{$PDS_HOSTNAME}, *.{$PDS_HOSTNAME}` (`Caddyfile:1-3`, `docker-compose.yaml:37-48`); published image `ghcr.io/futurgh/pegasus:latest` (`docker-compose.yaml:4`). No systemd unit, no Helm, no serverless. CLI subcommands: `serve`, `create-invite`, `migrate-blobs`, `rebuild-mst` (`bin/main.ml:332-369`).

## 3. Storage backends

**SQLite only** — "Currently only SQLite is supported. Open to pull requests for other databases!" (`pegasus/README.md:40`) — in a database-per-account layout.

| Data | Engine / location | Schema |
|---|---|---|
| accounts, invites, firehose log, OAuth state, 2FA, passkeys, reserved keys | one shared `{data_dir}/pegasus.db` (`pegasus/lib/util/constants.ml:4-6`) | `pegasus/lib/migrations/data_store/001…008*.sql` |
| MST blocks, commit, records, blob metadata, blob→record refs | one SQLite file per DID, `{data_dir}/store/{did ':'→'_'}.db` (`constants.ml:8-13`) | `pegasus/lib/migrations/user_store/001…003*.sql` |
| blob bytes | `{data_dir}/blobs/{did}/{cid}` or S3 (`pegasus/lib/blob_store.ml:13-16`) | `blobs.storage` column, `002_blob_storage_field.sql:1` |

The user store holds `mst`, `repo_commit` (singleton, `CHECK (id = 0)`), `records`, `blobs`, `blobs_records` (`user_store/001_initial_schema.sql:1-33`). Records live in `records.data`, not the generic block table; `export_car` reassembles by streaming MST nodes and batch-fetching leaves (`pegasus/lib/repository.ml:434-504`). SQLite runs WAL + `foreign_keys=ON` + `synchronous=NORMAL` + `busy_timeout=5000` (`pegasus/lib/util/sqlite_.ml:16-25`). Optional S3 handles blobs and/or whole-`.db` backups on an interval (`pegasus/lib/s3/backup.ml:25-60`, started `bin/main.ml:282`); `PDS_S3_CDN_URL` turns `getBlob` into a 302 (`pegasus/lib/api/sync/getBlob.ml:12-17`).

## 4. Endpoint coverage snapshot

The route table is one OCaml list, `bin/main.ml:10-248`, dispatched at `:290-294`. **Every registered handler contains real logic** — no stubs, no "not implemented", and exactly one TODO in `pegasus/lib` (`api/server/deactivateAccount.ml:10`, `deleteAfter` ignored). The READMEs carry no coverage checklist to contradict; `frontend/README.md:21-22` does list account login/signup at `/login` and `/signup` where the routes are `/account/login` and `/account/signup` (`bin/main.ml:70,72`).

### com.atproto.server. (20 routed)

| NSID | Registered | Auth (`Xrpc.handler ~auth:`) |
|---|---|---|
| describeServer | `bin/main.ml:112-114` | Any |
| createAccount | `:146-148` | **Any (none)** |
| createSession | `:149-151` | Any + inline rate limit |
| getSession | `:152` | Authorization |
| refreshSession / deleteSession | `:153-155`, `:156-158` | Refresh |
| getServiceAuth | `:159-161` | Authorization |
| checkAccountStatus | `:162-164` | Any (asserts DID inline) |
| activateAccount | `:165-167` | Bearer |
| deactivateAccount | `:192-194` | Authorization |
| deleteAccount | `:189-191` | Any + password + emailed `del-` token (`api/server/deleteAccount.ml:41-53`) |
| requestAccountDelete | `:186-188` | Authorization |
| requestEmailConfirmation / confirmEmail | `:168-170`, `:174-176` | Authorization |
| requestEmailUpdate / updateEmail | `:171-173`, `:201-203` | Authorization |
| requestPasswordReset / resetPassword | `:177-179`, `:180-182` | Any |
| reserveSigningKey | `:183-185` | Any |
| createInviteCode / createInviteCodes | `:140-142`, `:143-145` | Admin |

Unrouted: `createAppPassword`, `listAppPasswords`, `revokeAppPassword`, `getAccountInviteCodes`. Those strings appear nowhere in `bin` or `pegasus/lib` — **pegasus has no app passwords.**

### com.atproto.repo. (9 routed — complete)

`applyWrites` `bin/main.ml:218`, `createRecord` `:219`, `putRecord` `:220`, `getRecord` `:221`, `listRecords` `:222`, `deleteRecord` `:223`, `uploadBlob` `:224`, `importRepo` `:225`, `describeRepo` `:115`, `listMissingBlobs` `:195-197`. All writes funnel through `Repository.apply_writes` (`pegasus/lib/repository.ml:204-406`) with `swapRecord`/`swapCommit` enforced at `:214-218, 235-243, 280-293, 351-361`.

### com.atproto.sync. (9 routed, all unauthenticated)

`getRepo` `:227`, `getRepoStatus` `:228`, `getLatestCommit` `:229-231`, `listRepos` `:232`, `getRecord` `:233`, `getBlocks` `:234`, `getBlob` `:235`, `listBlobs` `:236`, `subscribeRepos` `:237-239`.

Unrouted: `listReposByCollection`, `getHostStatus`, `listHosts`, `notifyOfUpdate`, `requestCrawl`, `getCheckout`, `getHead`. `getHostStatus`/`listHosts` are relay-side per the lexicon ("Implemented by relays", `sync/getHostStatus.json`), so their absence is correct; **`listReposByCollection` is a real PDS-side gap.** pegasus is a `requestCrawl` *client* only, firing at most every 20 minutes on publish (`pegasus/lib/sequencer.ml:461, 490-505`).

### com.atproto.identity. (6 routed)

`resolveHandle` `:116-118`, `updateHandle` `:198-200`, `getRecommendedDidCredentials` `:205-207`, `requestPlcOperationSignature` `:208-210`, `signPlcOperation` `:211-213`, `submitPlcOperation` `:214-216`. Unrouted: `resolveDid`, `resolveIdentity`, `refreshIdentity`.

### com.atproto.admin. (7 routed, all `~auth:Admin`)

`deleteAccount` `:120-122`, `getAccountInfo` `:123-125`, `getAccountInfos` `:126-128`, `getInviteCodes` `:129-131`, `sendEmail` `:132`, `updateAccountEmail` `:133-135`, `updateAccountHandle` `:136-138`. `Admin` is HTTP Basic with username literally `admin` plus `PDS_ADMIN_PASSWORD` (`pegasus/lib/auth.ml:215-225`). Unrouted: `updateSubjectStatus`, `getSubjectStatus`, `updateAccountPassword`, `updateAccountSigningKey`, `searchAccounts`, `disableInviteCodes`, `enable/disableAccountInvites`.

### com.atproto.moderation. / label. / temp. / lexicon.

**Zero routes.** Greps for `createReport`, `queryLabels`, `subscribeLabels`, `fetchLabels`, `checkHandleAvailability`, `checkSignupQueue`, `dereferenceScope`, `resolveLexicon` across `bin` and `pegasus/lib` return nothing.

### Non-`com.atproto.*`

Three `app.bsky.*` routes are served locally rather than proxied: `actor.getPreferences` (`:241-243`, reads the `actors.preferences` column, `api/proxy/appBskyActorGetPreferences.ml:4-13`), `actor.putPreferences` (`:244-246`), and `feed.getFeed` (`:247`), which resolves the generator record and re-proxies as `getFeedSkeleton` (`api/proxy/appBskyFeedGetFeed.ml:26-46`). Everything else under `/xrpc/**` falls through to an `atproto-proxy`-header service proxy (`:296-297`, `pegasus/lib/xrpc.ml:253-339`) that 404s when the header is absent (`:334-339`).

## 5. Auth posture

Both legacy and OAuth, dispatched on the `Authorization` scheme (`pegasus/lib/auth.ml:434-455`): `Basic` → admin, `Bearer` → service auth if the JWT carries `lxm` else session JWT, `DPoP` → OAuth, otherwise cookie session.

- **Session JWTs** — ES256/ES256K on the server key, `scope` of `com.atproto.access`/`com.atproto.refresh`, `aud = Env.did`, `jti` checked against a `revoked_tokens` table (`pegasus/lib/jwt.ml:89-116`, `auth.ml:21-47`); 3h/7d (`jwt.ml:4-6`).
- **Full OAuth AS** — `/oauth/par`, `/oauth/authorize` (GET+POST), `/oauth/token` (`bin/main.ml:25-30`) with both well-knowns (`api/well_known.ml:20-28`, `:30-67`). PAR is mandatory (`well_known.ml:39`) and enforced: PAR itself requires a DPoP proof (`api/oauth_/par.ml:5-6`), rejects non-`S256` PKCE and unregistered `redirect_uri` (`par.ml:16-19`), and the token endpoint verifies the S256 verifier plus the PAR-bound `jkt` (`api/oauth_/token.ml:50-68`). `iss` is returned on both allow and deny redirects (`api/oauth_/authorize.ml:225-229, 244-248`).
- **DPoP** is thorough: `typ=dpop+jwt`, alg ∈ {ES256, ES256K} cross-checked against `jwk.crv`, **nonce required** (absent ⇒ `use_dpop_nonce`) against an HMAC-rotating prev/curr/next window, `htm`/`htu` with loopback-aware normalisation, clock bounds, a `jti` replay table, and `ath` bound to the access token and *forbidden* without one (`pegasus/lib/oauth/dpop.ml:153-247`; nonce `:45-87`; jti `:89-96`).
- **Scopes** — a real engine covering `transition:*` plus granular `repo:`/`blob:`/`rpc:`/`account:`/`identity:` (`pegasus/lib/oauth/scopes.ml`, 666 lines; assertions `auth.ml:64-118`; call sites `api/repo/putRecord.ml:21-24`, `api/repo/uploadBlob.ml:14`, `api/server/getServiceAuth.ml:15`). Permission sets resolve over DNS `_lexicon.` TXT plus fetched lexicon records (`pegasus/lib/lexicon_resolver.ml:36-58, 117-135`).
- **Service auth, both directions.** Minting: `getServiceAuth` (`api/server/getServiceAuth.ml:16-25`) and the outbound proxy (`xrpc.ml:286-294`) sign `{iss,aud,lxm,exp}` with the *account's* key (`jwt.ml:118-122`). Verifying: `Jwt.verify_service_jwt` (`jwt.ml:131-207`) checks `exp`, `aud = Env.did`, `lxm` against the request NSID, resolves the issuer DID, reads `#atproto`, and **retries with a cache-skipping re-resolve on signature failure to survive key rotation** (`:178-206`).
- **Beyond the reference PDS**: TOTP, email 2FA, WebAuthn passkeys and security keys, backup codes — routes at `bin/main.ml:36-99`, modules `pegasus/lib/{totp,two_factor,passkey,security_key}.ml`.

Gap: **`private_key_jwt` is advertised but not implemented.** `token_endpoint_auth_methods_supported` lists it (`api/well_known.ml:61-62`) and `client_assertion`/`client_assertion_type` are parsed into the request types (`pegasus/lib/oauth/types.ml:12-13, 23-24`), but grep finds no consumer in `par.ml` or `token.ml` — confidential clients are effectively unauthenticated.

## 6. Sync 1.1 status

Mostly there, with two real holes.

- **`#sync` events** — type, encoder, parser and emitter all exist (`pegasus/lib/sequencer.ml:53, 236-240, 386-400, 749-758`), but `sequence_sync` has exactly **one** call site: account creation (`api/server/createAccount.ml:128-130`). Post-migration activation emits `#account` + `#identity` only (`api/account_/migrate/ops.ml:167-173`; also `api/server/activateAccount.ml:6`), and `importRepo` emits **nothing** (`api/repo/importRepo.ml:14-18` has no sequencer call). The canonical post-migration `#sync` is missing.
- **`prevData` on commits** — emitted: `apply_writes` passes `~prev_data:prev_commit.data` (`repository.ml:404`), serialised only when present (`sequencer.ml:229-234`).
- **Per-op `prev`** — emitted: `Update` → `old_cid` (`repository.ml:311`), `Delete` → `cid` (`:364`), `Create` → `None` (`:254`); field declared at `sequencer.ml:33-38`.
- **Covering-proof blocks in the CAR slice** — yes. `Cached_mst.proof_for_keys` computes the proof for every touched path and merges it with the new leaf blocks before CAR assembly, with the commit block consed as root (`repository.ml:386-398`; proof walk `mist/lib/mst.ml:762-840`).
- **Reject no-op updates** — **not implemented.** The `Update` branch never compares `new_cid` to `old_cid` (`repository.ml:306-346`), so an identical re-write still commits and emits. The reference PDS short-circuits this (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/putRecord.ts:129-135`). Worse, `putRecord` without `swapRecord` maps onto a `Create` (`api/repo/putRecord.ml:52-59`), and `Create` hard-errors `InvalidSwap` when the path exists (`repository.ml:235-243`) — while the lexicon requires putRecord to "Write a repository record, creating **or updating** it as needed" (`repo/putRecord.json`).
- Commits are v3 with `prev = None` always (`repository.ml:190`); `rev` is forced strictly monotonic by bumping the previous TID when the clock has not advanced (`:176-189`).
- `getHostStatus` / `listReposByCollection` unrouted; only the latter is a PDS obligation.

## 7. Firehose

A Dream websocket (`bin/main.ml:237-239`, `api/sync/subscribeRepos.ml:1-40`).

- **Framing** — DAG-CBOR header `{op:1,t:"#…"}` (or `{op:-1}`) concatenated with the DAG-CBOR body in one binary frame (`sequencer.ml:262-310`, `Bytes.cat` at `:305`); `$type`, `seq`, `time` injected into the body map at `:299`.
- **Event types** — `#commit`, `#sync`, `#identity`, `#account`, `#info` (`sequencer.ml:146-156`). `#info` has no emitter and is rejected on DB replay (`:443`). The `#account` status enum includes `takendown`/`throttled`/`desynchronized` (`:58-72`) with no writer for any of them.
- **Seq source** — SQLite autoincrement `firehose.seq INTEGER PRIMARY KEY` (`data_store/001_initial_schema.sql:23-28`) assigned by `append_firehose_event` (`sequencer.ml:566-568`).
- **Cursor resume / backfill** — `?cursor=N` (`subscribeRepos.ml:5-9`) drives `stream_with_backfill` (`sequencer.ml:672-723`), which tries a 2048-frame in-memory ring first (`:457, 542-557`) then falls back to DB pages of 1000 (`:700-703`); the live loop also patches seq gaps from the DB (`:634-651`). The backfill window is effectively unbounded — no `DELETE` on the `firehose` table exists in `pegasus/lib`, a durability win and a disk-growth risk. A non-integer cursor silently becomes `0` (`subscribeRepos.ml:7`) and there is **no `FutureCursor` error**, which the lexicon defines.
- **Slow consumers** — per-subscriber queue capped at 1000; overflow closes the subscriber with reason `ConsumerTooSlow` and sends an error frame before hangup (`sequencer.ml:459, 507-518, 609-617`).
- No zstd dictionary compression; no `label.subscribeLabels`.

## 8. Account migration / import-export

The full inbound set, plus a driven wizard the reference PDS lacks.

| Piece | Where |
|---|---|
| `repo.importRepo` | `bin/main.ml:225`; CAR ingest `repository.ml:506-586` |
| `repo.listMissingBlobs` | `:195-197`; SQL anti-join `user_store.ml:219-231` |
| `server.checkAccountStatus` | `:162-164`; block/record/blob counts `api/server/checkAccountStatus.ml:13-32` |
| `server.activateAccount` / `deactivateAccount` | `:165-167`, `:192-194` |
| `identity.getRecommendedDidCredentials` | `:205-207`; `pegasus/lib/plc.ml:228-235` |
| `identity.requestPlcOperationSignature` / `signPlcOperation` / `submitPlcOperation` | `:208-216` |
| `server.reserveSigningKey` | `:183-185` |
| outbound wizard `/account/migrate` | `:77-78`; `api/account_/migrate/{migrate,ops,remote,state}.ml` (991 + 191 + 235 lines) |

`signPlcOperation` gates on an emailed auth code and merges client fields over the latest audit-log entry (`api/identity/signPlcOperation.ml:14-57`); `submitPlcOperation` validates against the account handle and signing key before POSTing (`api/identity/submitPlcOperation.ml:18-27`). Inbound migration `createAccount` verifies a `com.atproto.server.createAccount`-bound service JWT and creates the account deactivated (`api/account_/migrate/ops.ml:8-27, 84, 91-94`).

Two defects. (1) **`reserveSigningKey` is write-only**: it generates and persists a key (`api/server/reserveSigningKey.ml:18-25`), but neither `createAccount` (`api/server/createAccount.ml:51`) nor the migration path (`migrate/ops.ml:76-79`) reads it back — both mint a *fresh* K-256 keypair, and `get_reserved_key_by_did` has exactly one caller, `reserveSigningKey` itself. A client following reserve → PLC → createAccount ends up with a DID document naming a key the PDS does not hold. (2) **`importRepo` emits no firehose event** (`api/repo/importRepo.ml:14-18`), so relays learn nothing about imported state.

## 9. did:plc vs did:web

Both methods resolve, nothing else: `resolve_plc`/`resolve_web` dispatched on prefix with an explicit fall-through (`pegasus/lib/id_resolver.ml:168-222`); handle resolution accepts either from DNS TXT or `/.well-known/atproto-did` (`:6-45`).

- **Service DID** — `did:web:{PDS_HOSTNAME}` by default, overridable via `PDS_DID` (`pegasus/lib/env.ml:29`), served at `/.well-known/did.json` (`bin/main.ml:15`).
- **Account DIDs** — `did:plc:` is the only kind pegasus *creates*: `createAccount` calls `Plc.submit_genesis` when no DID is supplied (`api/server/createAccount.ml:61-73`), deriving `"did:plc:" ^ first-24-of-base32-sha256` (`plc.ml:206`). Imported `did:web:` accounts work read-side and the wizard skips the PLC step for them with a "requires manual" notice (`migrate/migrate.ml:82-83, 105, 116`). All three PLC XRPC methods hard-reject non-`did:plc` subjects (`signPlcOperation.ml:7-8`, `submitPlcOperation.ml:7-8`), and `updateHandle` skips the PLC leg for non-plc DIDs (`identity_util.ml:61, 99`) — so a `did:web` account's `alsoKnownAs` is updated *nowhere*: the local handle changes and the DID document does not.

## 10. Blobs

Stored at `{data_dir}/blobs/{did}/{cid}` or S3 key `blobs/{did}/{cid}` (`blob_store.ml:13-16`), selected by `PDS_S3_BLOBS_ENABLED` (`:92-99`); metadata in the per-user `blobs` table.

**Validation**: the CID is computed from the bytes as `Cid.create Raw data` (`api/repo/uploadBlob.ml:16`) so it cannot be forged; MIME comes from the header or a sniffer fallback (`:7-13`, `util/mime_sniff.ml`). There is **no size limit and no MIME allowlist** — the only gate is the OAuth blob scope (`:14`) — and the whole body is read into memory (`Dream.body`, `:6`).

**Ref counting / GC**: real. `blobs_records` has `ON DELETE CASCADE` (`user_store/003_cascade_blobs_records.sql:2-5`) with `PRAGMA foreign_keys=ON` (`util/sqlite_.ml:19`). On record update, removed refs are diffed and `delete_unreferenced_blobs` drops rows with no remaining referrer (`repository.ml:327-341`, SQL `user_store.ml:279-290`); on record delete, `delete_orphaned_blobs_by_record_path` runs in the same transaction and the files are unlinked (`user_store.ml:648-660`, SQL `:292-305`). Refs are extracted structurally via `Util.find_blob_refs` (`repository.ml:259-261, 315-318, 559-562`). Records referencing not-yet-uploaded blobs are not rejected; the dangling refs surface in `listMissingBlobs`.

## 11. Moderation / admin surface and takedown enforcement

**No moderation surface and no takedown enforcement.** No `com.atproto.moderation.*`, no `admin.updateSubjectStatus`/`getSubjectStatus`, no label emission or `queryLabels`. `Takendown` exists only as a `#account` status variant (`sequencer.ml:61-62, 77-78, 94`) with no writer. The sole enforcement primitive is account *deactivation*, checked in every auth verifier and in `Repository.load ~ensure_active` (`auth.ml:234-239, 327-332`; `repository.ml:421-426`).

What exists is the seven Basic-auth XRPC routes (§4) plus a server-rendered **admin dashboard**:

| Page | Route | Actions |
|---|---|---|
| index | `/admin` (`bin/main.ml:101`) | redirects to `/admin/users` or `/admin/login` (`api/admin_/index.ml:2-7`) |
| login | `/admin/login` (`:102-103`) | password form → admin cookie session |
| users | `/admin/users` (`:104-105`) | `create_account`, `change_handle`, `change_email`, `change_password`, `send_password_reset`, `deactivate`, `reactivate`, `delete` (`api/admin_/users.ml:118, 202, 217, 228, 236, 246, 251, 258`); filtered cursor-paged listing (`:26-50`) |
| invites | `/admin/invites` (`:106-107`) | `create_invite`, `update_invite`, `delete_invite` (`api/admin_/invites.ml:39, 63, 76`) |
| blobs | `/admin/blobs`, `/admin/blobs/view` (`:108-110`) | browse/preview, `delete_blob` (`api/admin_/blobs.ml:129-160, 189`) |

## 12. Account frontend

A second server-rendered surface for end users, routed at `bin/main.ml:32-99`, templated in `frontend/src/templates/*.mlx` (SSR via server-reason-react, hydrated by a melange bundle compiled into the binary with `ocaml-crunch`, `dune:40-60`, served from `bin/main.ml:250-267`).

| Page | Route(s) | Notable |
|---|---|---|
| account home | `/account` | `save`, `reactivate`, `deactivate`, `request_delete`, `confirm_delete`, `cancel_delete`, `request_email_change`, `confirm_email_change`, `request_email_confirmation` (`api/account_/index.ml:128-277`) |
| security | `/account/security` + `/backup-codes`, `/totp/*`, `/keys/*` (`:34-65`) | `change_password`, `enable_email_2fa`, `disable_email_2fa` (`security/index.ml:77, 105, 109`) |
| passkeys | `/account/passkeys/**` (`:83-99`) | register/verify/rename/delete plus **unauthenticated passkey login** |
| permissions | `/account/permissions` | `revoke_app`, `sign_out_device` (`permissions.ml:90, 102`) |
| identity | `/account/identity` | PLC-only; refuses non-plc (`identity.ml:56-60`) |
| migrate | `/account/migrate` | resumable outbound migration wizard |
| login / signup / switch / logout / reset | `:70-82` | multi-account cookie sessions + account switcher (`frontend/src/components/AccountSwitcher.mlx`; `Session.list_logged_in_actors` used at `oauth_/authorize.ml:153`) |
| OAuth consent | `/oauth/authorize` | `OauthAuthorizePage.mlx`, rendered with resolved permission sets (`authorize.ml:160-172`) |

## 13. Cross-language datapoint: primitives reimplemented from scratch

Everything below the HTTP layer is in-house; nothing binds a C atproto library.

| Primitive | Library | Lines | Fidelity |
|---|---|---|---|
| CID | `ipld/lib/cid.ml` | 161 | strict DASL profile + one extension |
| DAG-CBOR | `ipld/lib/dag_cbor.ml` | 427 | canonical ordering correct; floats diverge from atproto |
| CAR v1 | `ipld/lib/car.ml` | 216 | streaming read+write, varint, DAG-CBOR header |
| MST | `mist/lib/mst.ml` | 1898 | full, incl. proof generation; storage-agnostic |
| K-256 / P-256 | `kleidos/{kleidos,low_s,rfc6979}.ml` | 236 + 57 | RFC 6979 + low-S on sign; verify does not normalise |
| TID | `mist/lib/tid.ml` | — | `to/of_timestamp_us` used for rev monotonicity |
| XRPC client + lexicon codegen | `hermes/`, `hermes-cli/`, `hermes_ppx/` | — | PPX `[%xrpc get "nsid"]`, e.g. `sequencer.ml:498` |
| lexicon record validation | `pegasus/lib/record_validator.ml` | 481 | grapheme-aware `maxGraphemes`, unions, refs, cycle guard |

**CID.** `create` writes `[0x01, codec, 0x12, 32, sha256…]` — CIDv1 and SHA-256 only (`cid.ml:31-43`); `decode_first` rejects any other version, codec (raw `0x55` / dag-cbor `0x71` only) or hash (`:57-77`). String form is base32 (`:107-116`), length-gated to exactly 59 or 8 chars (`:89`), which incidentally rejects other multibase forms. Binary form carries the mandatory `0x00` identity-multibase prefix (`:127-131`, checked on `of_bytes` `:123-124`). Two deviations: a **zero-length digest is accepted as a legal CID** (`:68`, `create_empty` `:45-55`) — no DASL profile permits that, though `create_empty` has no caller in the PDS — and `codec_of_byte` defaults anything non-raw to dag-cbor (`:29`), harmless only because `decode_first` validated first.

**DAG-CBOR canonical map ordering — correct.** `dag_cbor_key_compare` sorts **length first, then bytewise** (`dag_cbor.ml:4-7`) and the encoder emits `ordered_map_bindings` rather than the `Map.Make(String)` natural order (`:14-16`, used `:204-205`). That matches the reference, whose cborg `compareBytes` is `b1.length < b2.length ? -1 : b1.length > b2.length ? 1 : compare(b1,b2)` (`…/node_modules/cborg/lib/2bytes.js:131-133`, reused for strings via `export const encodeString = encodeBytes` in `lib/3string.js`).

**CID tag 42 — correct on encode, lax on decode.** Encoding writes tag 42 then a byte string of `Cid.to_bytes` (already `0x00`-prefixed) — `dag_cbor.ml:175-181`, matching `packages/lex/lex-cbor/src/encoding.ts:47-53`. Decoding ignores the additional-info nibble after major type 6 and unconditionally reads the *next* byte as the tag (`:369-370`); correct for the canonical `0xd8 0x2a`, but a stream with an inline small tag (`0xc0`–`0xd7`) would be misparsed rather than rejected. It does require major type 2 after the tag (`:373-377`) and rejects every tag but 42 (`:386`).

**Other DAG-CBOR notes.** Integers are clamped to ±(2^53−1) on encode and decode (`:153-159`, `:256-257`) — JS-safe-integer behaviour, not full CBOR. Indefinite lengths, `undefined` (0xf7) and float16/32 are rejected (`:387-399`). But **floats are accepted and emitted** (`write_float` `:161`, dispatch `:193-194`, decode `:395`; tests exercise `` `Float 3.14`` at `ipld/test/test_dag_cbor.ml:95, 183-184`), while the AT Protocol data model forbids them — the reference encoder throws "Non-integer numbers … are not supported by the AT Data Model" (`packages/lex/lex-cbor/src/encoding.ts:58-65`). pegasus hedges with "**mostly** DASL-compliant" (`README.md:105`, `ipld/README.md:3`). The decoder also does not verify that a received map's keys arrived canonically ordered, unlike cborg's `strict: true` (`encoding.ts:76`).

**MST.** Depth is `leading_zeros_on_hash` in **2-bit chunks** of SHA-256, i.e. fanout 4 (`mist/lib/util.ml:1-19`) — the atproto rule. Nodes are the spec's `{l, e:[{p,k,v,t}]}` with prefix compression (`mist/lib/mst.ml:20-32`, compress/decompress `:1169-1195`). Keys validate as `collection/rkey` with the allowed charset and a 1024-byte cap (`util.ml:33-47`). Storage is genuinely swappable: `Mst.Make` is a functor over a `Blockstore` signature with memory, overlay and write-caching backends (`mist/lib/storage/storage.ml:1-34`), which the PDS uses to buffer a whole `applyWrites` batch and flush atomically (`repository.ml:5-7, 219, 374-380`). A 954-line test suite plus a `sample.car` fixture back it.

**Crypto.** Signing is deterministic RFC 6979 (`kleidos/rfc6979.ml`, used `kleidos.ml:83, 153`) over HACL\*, and **low-S normalisation is applied to every signature produced** — `s > n/2 ⇒ s := n − s` with correct group orders for both curves (`low_s.ml:25-30, 32-38, 50-56`; call sites `kleidos.ml:86, 156`). Verification does **not** normalise or reject high-S: `K256.verify`/`P256.verify` pass the signature through unchanged (`kleidos.ml:90-93, 160-163`); whether HACL\* enforces low-S itself is **UNVERIFIED**. The one place pegasus normalises before verifying is DPoP proof validation (`oauth/dpop.ml:139-146`). Only K-256 and P-256 are supported (`kleidos.ml:199-213`) — no Ed25519, no P-384, correct for atproto. Oddity: `K256.generate_keypair` draws the private scalar from `Mirage_crypto_ec.P256.Dsa.generate` then derives the K-256 public key from it, with a comment acknowledging the cross-curve reuse (`kleidos.ml:105-110`).

## 14. Notable spec deviations and unsupported features

The project ships no "Status" or "Known issues" section — `README.md`, `pegasus/README.md`, `ipld/README.md`, `mist/README.md`, `kleidos/README.md` contain none. The only candid self-assessments are `ipld/README.md:3` ("a **mostly** DASL-compliant implementation") and `pegasus/README.md:40` ("Currently only SQLite is supported"). Everything below is from code.

1. **No app passwords at all** (§4) — legacy app-password clients cannot authenticate.
2. **`putRecord` cannot update without `swapRecord`** — routes to `Create`, which throws `InvalidSwap` on an existing path (`api/repo/putRecord.ml:52-59` + `repository.ml:235-243`). Contradicts the lexicon.
3. **No no-op suppression on writes** (§6) — redundant writes churn the firehose.
4. **`createAccount` is unauthenticated and honours a caller-supplied `did`** with no proof of control: default `Any` auth (`bin/main.ml:146-148`, `xrpc.ml:127`) and `create_account` only checks the DID is not already local before adopting it (`api/server/createAccount.ml:53-60`). The service-JWT check exists only on the migration wizard's internal path (`migrate/ops.ml:8-27`), not on the XRPC route.
5. **`/.well-known/did.json` emits `service` as a single object, not an array** (`api/well_known.ml:14-18`); the document also omits `verificationMethod` and `alsoKnownAs`.
6. **`describeServer` hardcodes `did:web:{hostname}`** (`api/server/describeServer.ml:5`) instead of `Env.did`, so it lies when `PDS_DID` is overridden (`env.ml:29`).
7. **`admin.getAccountInfos` mis-parses its array param** — the lexicon declares `dids: array` (repeated query params), but the handler reads `Dream.query req "dids"` (first value only) and splits on commas (`api/admin/getAccountInfos.ml:5-9`), so `?dids=a&dids=b` returns one result. `getBlocks` does it correctly via `Xrpc.parse_query`, which groups repeats into JSON arrays (`xrpc.ml:172-193`).
8. **`private_key_jwt` advertised but unimplemented** (§5).
9. **Lexicon validation is opt-in only** — `validate: true` validates; `false` *and unset* both yield `validationStatus: "unknown"` with no checking (`api/repo/createRecord.ml:23-36`, `putRecord.ml:26-39`), where the lexicon says unset means "validate only for known Lexicons".
10. **`getServiceAuth` ignores `exp`** — tokens are always 5 minutes (`jwt.ml:2, 118-122`) and `BadExpiration` is never returned.
11. **No `FutureCursor` error** on `subscribeRepos` (§7).
12. **`#commit.blobs` always empty**, `tooBig`/`rebase` always false (`sequencer.ml:46-49, 219-228, 732-741`) — consistent with the lexicon's deprecation notes, so acceptable.
13. **DAG-CBOR accepts floats** (§13).
14. **No moderation, labels, or takedowns** (§11).
15. **`did:web` accounts get no `alsoKnownAs` maintenance** on handle change (§9).
16. **`reserveSigningKey` result never used**; **`importRepo` silent on the firehose** (§8).

## 15. Rate limiting, metrics, health, ops

**Rate limiting** is an in-process fixed-window token bucket (`pegasus/lib/rate_limiter.ml:11-52`) with two shared limiters registered at startup — `repo-write-hour` 5000/hr and `repo-write-day` 35000/day (`bin/main.ml:4-8`) — keyed by DID and charged per-op (create 3, put 2, delete 1: `createRecord.ml:5`, `putRecord.ml:5`, `deleteRecord.ml:5`). Nine routes opt in (`createRecord`, `putRecord`, `deleteRecord`, `updateHandle`, `resetPassword`, `requestPasswordReset`, `requestAccountDelete`, `requestEmailUpdate`, `requestEmailConfirmation`), plus `createSession`, which consumes inline after body parsing so it can key on identifier+IP (`api/server/createSession.ml:34-44`). Standard `RateLimit-*` headers are returned (`xrpc.ml:84-97`). **`applyWrites` and `uploadBlob` are not rate-limited**, and all state is per-process and lost on restart.

**Health** is `GET /xrpc/_health` → `{"version": "pegasus <git-short-sha>"}` (`bin/main.ml:14`, `api/health.ml:1-4`; the string is generated at build time from `GIT_REV`, `dune:101`, fed by `Dockerfile:7-8`). **Metrics: none** — no Prometheus endpoint, no counters, no OpenTelemetry anywhere in the tree. Logging is Dream/Logs with a configurable level (`env.ml:12-21`) and deliberate silencing of noisy cohttp/tls sources (`bin/main.ml:273-280`).

Ops tooling: `rebuild-mst <did>` rebuilds the tree from the `records` table and re-commits (`bin/main.ml:319-330`, `repository.ml:588-607`); `migrate-blobs` moves local blobs to S3 (`bin/main.ml:309-317`); periodic S3 backup copies every `.db` file (`s3/backup.ml:25-60`). Emails degrade to stdout when SMTP is unset (`README.md:83`, `env.ml:72-115`). CORS is wide open (`Allow-Headers: *`, `xrpc.ml:353-362`).

Tests: alcotest suites for `ipld` (cid, dag_cbor), `mist` (mst 954 lines, tid, util) and `pegasus` (sequencer, scopes, record_validator) — `ipld/test/dune`, `mist/test/dune`, `pegasus/test/dune`. One CI workflow, `.github/workflows/build.yml`. **No HTTP-level or interop tests** for the XRPC surface.

## 16. Maturity tier

**serious.** It is a genuinely multi-account server with a complete repo/sync/identity surface, a from-scratch but faithful IPLD + MST + crypto stack, a real OAuth authorization server with correct DPoP nonce handling and scope enforcement, service auth minted *and* verified with key-rotation retry, working blob ref-counting, and both an admin dashboard and an end-user account frontend — well past what "single-user" or "hobby-experiment" implies. It falls short of "reference" on concrete correctness gaps (`putRecord` cannot update, unauthenticated `createAccount` accepting an arbitrary DID, `#sync` emitted only at account creation, no app passwords, no moderation/takedown, `service` serialised as an object in the service DID document) and on a build that depends on a personally forked dune.

## Confidence & unknowns

- **UNVERIFIED: whether HACL\*'s `K256.Libsecp256k1.verify` / `P256.verify` reject high-S signatures.** pegasus normalises on sign (`kleidos.ml:86, 156`) but not on verify (`:90-93, 160-163`), while DPoP verification does normalise first (`oauth/dpop.ml:139-146`). Needs: reading the vendored HACL\* bindings, or a high-S round-trip test.
- **UNVERIFIED: `mist/lib/tid.ml` internals.** I confirmed the API is used for rev monotonicity (`repository.ml:176-189`) but did not read the encoder, so I cannot assert the 13-char base32-sortable format or clockid handling.
- **UNVERIFIED: `pegasus/lib/oauth/scopes.ml` semantics.** 666 lines; I confirmed the assertion call sites and that both `transition:*` and granular scopes parse, but did not audit the matching rules against the atproto scope spec.
- **UNVERIFIED: `Util.find_blob_refs` completeness.** Not read — determines whether GC and `listMissingBlobs` are sound for blobs nested in arrays/unions rather than at the top level.
- **UNVERIFIED: MST correctness beyond the algorithm sketch.** I read node encoding, the depth function, key validation and `proof_for_keys`, but not the 1898-line insert/delete/split/merge body; the 954-line test suite is circumstantial evidence only.
- **UNVERIFIED: whether `proof_for_keys` output matches the exact block set Sync 1.1 requires.** The mechanism exists and is merged with new leaves (`repository.ml:386-398`); I did not diff it against the reference PDS's diff-block computation for a worked example.
- **UNVERIFIED: whether the OAuth `authorize` GET handler validates the `request_uri` → `client_id` binding.** I read the POST path in full (`api/oauth_/authorize.ml:174-249`) and only the tail of the GET path.
- **UNVERIFIED: firehose disk growth.** No `DELETE FROM firehose` found in `pegasus/lib`, but I did not exhaustively search generated SQL or triggers beyond the OAuth cleanup triggers at `data_store/001_initial_schema.sql:70-86`.
- **UNVERIFIED: whether the melange client bundle adds network surface.** I read the route table and server handlers, not `frontend/client/*.mlx`.
- The clone is a single squashed commit, so **no claims about release cadence, contributor count, issue-tracker health, or production deployments** are possible from this source.
