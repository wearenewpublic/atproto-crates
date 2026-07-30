# K. Account migration & import/export

Related: [inventory](../00-atproto-crates-inventory.md) · [coverage matrix](../20-coverage-matrix.md) · [synthesis & roadmap](../50-synthesis-and-roadmap.md) · [README](../README.md) · [permissioned-data overview](../permissioned/40-permissioned-overview.md)

## Assessment

Account migration is the one capability where a PDS is judged not on what it serves but on whether a
*sequence* completes. The canonical sequence is written down at
`/tmp/gap-scratch/bsky-pds/ACCOUNT_MIGRATION.md`: the old PDS mints a service-auth JWT scoped to
`lxm=com.atproto.server.createAccount` (`:23`); the client calls `describeServer` on the new PDS to learn
the `aud` for that token (`:105-112`); `createAccount` on the new PDS accepts the caller's existing DID
*because* of that token and lands the account **deactivated** with an empty repo (`:27`); the client
streams a CAR from `sync.getRepo` into `repo.importRepo` (`:33`); enumerates blobs with `sync.listBlobs`
and re-uploads each through `repo.uploadBlob`, using `repo.listMissingBlobs` on the new PDS to find what
is still absent (`:35`, `:39`); copies private state with `app.bsky.actor.getPreferences` /
`putPreferences` (`:37`); rotates identity through `getRecommendedDidCredentials` →
`requestPlcOperationSignature` → `signPlcOperation` (on the **old** PDS, gated by an emailed token) →
`submitPlcOperation` (on the **new** PDS, which validates the operation so the user cannot lock
themselves out, `:49`); and finally calls `activateAccount`, which the guide says will check the DID is
set up correctly, flip the account active, and emit identity and commit events on the firehose (`:59`).
Every step is load-bearing: skip the deactivated state and you federate a repo the DID document does not
point at; skip blob-ref indexing and the backfill loop silently believes it is finished.

atproto-crates routes **almost every endpoint in that list** and, on the surface, looks complete. It is
not. Reading the handlers, four of the sequence's five integrity checks are absent and two steps are
wired to code paths that cannot produce a correct result. The new PDS never verifies that the caller
controls the DID it is claiming — `create_account` is declared `(State, Json<CreateAccountInput>)` with
no `Parts` extractor and no guard (`crates/atproto-pds/src/http/auth_handlers.rs:81-83`), and the only
inbound service-auth verifier in the whole tree is the spaces-scoped one
(`/tmp/gap-scratch/inv/auth.md:253`). The account is created `Active` unconditionally
(`crates/atproto-pds/src/account/manager.rs:158`), so it never passes through the deactivated state the
flow depends on. `importRepo` ingests blocks and commits but writes no record index and no blob refs, so
the imported repo is invisible to `getRecord`/`listRecords` and `listMissingBlobs` returns `[]` forever
(`crates/atproto-pds/src/repo/import.rs`; the only `repo_record` token in that file is in a doc comment
at `:10`). `signPlcOperation` speaks a completely different protocol from the lexicon and applies no
confirmation gate (`auth_handlers.rs:1594-1597`, `:1619`). `submitPlcOperation` POSTs whatever it is
handed with zero validation (`auth_handlers.rs:1685-1710`). `activateAccount` performs no pre-flight at
all (`auth_handlers.rs:677-688`). And `app.bsky.actor.getPreferences`/`putPreferences` are not
implemented anywhere — they fall into the blanket `app.bsky.*` proxy (`http/router.rs:109-113`) and get
forwarded to an AppView that does not implement them (verified: no such handler exists under
`/tmp/gap-scratch/atproto/packages/bsky/src/api/app/bsky/actor/`; in the reference topology the *PDS*
owns them, `/tmp/gap-scratch/atproto/packages/pds/src/api/app/bsky/actor/getPreferences.ts:46`).

Against the independent field this reads badly, because migration is exactly where the independent field
is strong. **cirrus — a single-user PDS — is the best non-reference implementation of this area that I
read.** Its import walks every imported record and writes blob refs in the same pass
(`/tmp/gap-scratch/cirrus/packages/pds/src/account-do.ts:1023-1035`), refuses to import over an active
repo (`:983-988`), asserts the CAR's DID equals the account DID and destroys the import if it does not
(`:1012-1019`), starts migrated accounts deactivated via `INITIAL_ACTIVE=false` (`:79-85`), copies
preferences (`cli/commands/migrate.ts:395-409`), runs a resumable blob backfill loop
(`migrate.ts:429-473`), and gates activation behind three pre-flight checks including "DID document
points at cirrus" (`cli/commands/activate.ts:34-57`) before emitting `#account` + `#identity` + `#sync`
(`account-do.ts:1297-1330`). tranquil-pds is comparable and adds an 11-step inbound wizard; zds verifies
a full service-auth JWT on `createAccount` (issuer, `aud`, `exp`, `lxm`, DID resolution, signature —
`/tmp/gap-scratch/zds/src/atproto/server.zig:700-752`) *and* supports the `plcOp` + reserved-signing-key
path, which the reference only offers in entryway mode; cocoon requires a `lxm`-bound service-auth token
whose issuer must equal the signup DID (`/tmp/gap-scratch/cocoon/server/handle_server_create_account.go:81-95`).
Three capabilities that atproto-crates lacks are present in **every single one of the eleven
comparisons**: `describeServer` is routed everywhere, `app.bsky.actor.get/putPreferences` are served or
at least handled locally everywhere (arroba stubs them, `/tmp/gap-scratch/arroba/app.py:90-98`), and
every comparison that routes `activateAccount` at all emits more than a bare `#account`.

Two fairness corrections are owed. First, **no implementation — including the reference — refuses to
activate while blobs are still missing.** The reference's `activateAccount` calls
`ctx.accountManager.activateAccount(did)` (`.../server/activateAccount.ts:33`) which runs
`assertValidDidDocumentForService` (`account-manager/account-manager.ts:458`) and nothing else; the blob
check in the canonical flow is a client-side recommendation ("we recommend doing a final check of
`checkAccountStatus`", `ACCOUNT_MIGRATION.md:57`). The real server-side gate is the **DID-document**
check — PDS endpoint matches, signing key matches the stored keypair, server rotation key present
(`api/com/atproto/server/util.ts:114-135`) — and that gate is implemented by the reference and by
rsky-pds (`/tmp/gap-scratch/rsky/rsky-pds/src/apis/com/atproto/server/activate_account.rs:21`), and
approximated client-side by cirrus. atproto-crates has neither. Second, the missing BYO-DID proof is
**not unique to atproto-crates**: metalbear's `createAccount` is a public route that adopts a
caller-supplied `did` with no binding (`/tmp/gap-scratch/metalbear/src/server.c:206`, handler `:3283`),
pegasus's service-JWT check lives only on its internal wizard path and not on the XRPC route
(`impl-notes/pegasus.md:217`), and rsky-pds has the check but with an inverted comparison
(`create_account.rs:318` errors when the token DID *matches*). That does not make it acceptable — the
reference, cocoon, tranquil-pds and zds all get it right — but it belongs in the "widespread field
weakness" bucket rather than the "atproto-crates is uniquely broken" bucket.

---

## Per-capability analysis

### Step 0 — `describeServer` on the target PDS  · **MISSING**

The migration example's first call against the new PDS is `describeServer`, because the returned `did`
becomes the `aud` of the service-auth JWT the old PDS mints (`ACCOUNT_MIGRATION.md:105-112`).
atproto-crates does not route it (not-routed sweep in `/tmp/gap-scratch/inv/endpoints.md`). All eleven
comparisons do — cirrus `index.ts:278`, dnproto `Pds.cs:190`, zds `router.zig:155`, arroba
`xrpc_server.py:55`, pegasus `bin/main.ml:113`, alteran `index.js:42`, tranquil `lib.rs:34`, cocoon
`server.go:517`, rsky `describe_server.rs:9`, metalbear `server.c:6643`. This is the "even a hobby PDS
does this" category, and it makes the flow unstartable. (Primary owner: endpoint-coverage chapter.)

### Step 1 — `getServiceAuth` on the source PDS  · **present, correct**

`crates/atproto-pds/src/http/service_auth_handlers.rs:93-176` mints an `iss`/`aud`/`lxm`/`iat`/`exp`/`jti`
JWT signed with the account's own key, validating that `aud` is a DID (`:104-110`) and `lxm` a valid NSID
(`:112-118`). This is the one migration step atproto-crates does as well as the field. Cross-area
caveats: `exp` is treated as a TTL rather than an absolute epoch (`:131-136`, contradicting
`getServiceAuth.json`), and with no `PRIVILEGED_METHODS` gate any non-privileged app-password session can
mint the `lxm=createAccount` token (`/tmp/gap-scratch/inv/auth.md:272`). arroba does not serve it at all
(`impl-notes/arroba.md:188`); cirrus and pegasus ignore `exp` and pin 5 minutes.

### Step 2 — proof of DID control on `createAccount`  · **MISSING** *(security)*

`create_account` (`auth_handlers.rs:81-83`) has no `Parts` extractor and calls no auth guard. When
`input.did` is present the handler adopts it verbatim; the in-code comment at `:180-183` states the
intent, that a caller-supplied DID is simply trusted on the migration path. No `Authorization` header is
read anywhere on this path, and `/tmp/gap-scratch/inv/auth.md:253` establishes that the sole inbound
service-auth verifier in the tree is `crates/atproto-pds/src/space/service_auth.rs`, reachable only from
spaces handlers. So any unauthenticated caller can `POST createAccount` with someone else's DID, receive
a session bound to it (`:266-275`), and permanently occupy that DID and handle in the account table
(uniqueness enforced at `account/manager.rs:87-123`). Relays would reject the resulting commits — the
fresh local signing key is not in the victim's DID document — so this is DID-squatting and migration
denial rather than full takeover, but it does block the real owner from ever migrating in. The reference
binds `input.did !== requester` where `requester` comes from
`ctx.authVerifier.userServiceAuthOptional` (`createAccount.ts:250-254`); cocoon verifies the token with
`lxm=com.atproto.server.createAccount` and requires `authDid == signupDid`
(`handle_server_create_account.go:81-95`); zds runs a six-check verification
(`src/atproto/server.zig:700-752`); tranquil compares the provided DID to the migration token's issuer
(`crates/tranquil-api/src/identity/account.rs:244-256`).

### Step 2b — the account must land deactivated  · **DIVERGENT**

`AccountManager::create_account` binds `AccountState::Active.as_str()` unconditionally into the INSERT
(`crates/atproto-pds/src/account/manager.rs:158`); there is no `deactivated` parameter on
`CreateAccountParams` and no branch on whether a DID was supplied. The project's own end-to-end test
concedes the problem in a comment and works around it by explicitly calling `deactivateAccount`
immediately after signup (`crates/atproto-pds/tests/migration_e2e.rs:148-158`). The reference sets
`deactivated = true` whenever `input.did` is supplied (`createAccount.ts:256`); rsky-pds
(`create_account.rs:325`), tranquil (`account.rs:439`), pegasus (`migrate/ops.ml:91-94`), zds
(`server.zig:152`), cirrus (`account-do.ts:79-85`) and arroba (import creates `status='deactivated'`,
`xrpc_repo.py:259`) all do the same. cocoon is the one serious peer that shares the gap — its
`Deactivated` column exists (`models/models.go:38`) but `handle_server_create_account.go` never sets it.

### Step 2c — `plcOp` / `recoveryKey` on `createAccount`  · **MISSING** *(defensible)*

`CreateAccountInput` (`auth_handlers.rs:28-41`) models only `email`, `handle`, `did`, `inviteCode`,
`password`; the lexicon also defines `plcOp`, `recoveryKey`, `verificationCode`, `verificationPhone`.
The reference **rejects** `plcOp` on a non-entryway PDS, so this is nearly reference-only — except that
zds implements it fully, pairing `plcOp` with a `reserveSigningKey`-issued key it then consumes
(`server.zig:132-152`). Ignoring it is a defensible RC→stable decision; documenting the flow as
`createAccount(did=..., plcOp=...)` in `tests/migration_e2e.rs:6` when the field cannot deserialize is
not.

### Step 3 — `importRepo`  · **PARTIAL** *(the central defect)*

The route exists (`http/router.rs:71`), is guarded by session **plus** a `privileged()` check
(`http/write_handlers.rs:600-607` — stricter than the field, and correct), and the importer does real
work: CARv1 header/root validation, content-verified blocks, a backward commit-chain walk requiring every
`prev` link, `prev_data` continuity, and per-commit `verify_inductive` (`repo/import.rs:166-243`). What
it does not do is index anything a reader can see. `grep repo_record crates/atproto-pds/src/repo/import.rs`
matches only the module doc at `:10` that *claims* records will be indexed into `repo_record`; since
`repo/reader.rs` sources `getRecord`, `listRecords` and `describeRepo` from that table
(`:133,141,268,280,353`), a fully imported account reads as empty through every record endpoint while
`sync.getRepo` happily re-exports the blocks. Nothing populates `repo_blob_ref` either: `blob::add_ref`
(`crates/atproto-pds/src/blob.rs:115`) has no production caller anywhere in the tree — the full-tree grep
returns only its definition, the two backend impls, the S3 delegation (`blob_s3.rs:169-175`) and unit
tests. The reference does both in the import transaction, `store.record.indexRecord(...)` plus
`store.repo.blob.insertBlobs(uri, recordBlobs)` (`.../repo/importRepo.ts:84-95`); so do cirrus
(`account-do.ts:1023-1035`), pegasus (`repository.ml:559-562`), cocoon (`handle_import_repo.go:72-101`),
zds (`repo.zig:343-395`) and tranquil (`sync/import.rs:304-361`).

For calibration: a rough `importRepo` is normal in this field and the honest implementations say so.
cocoon's README checklist annotates the method — `Works "okay". Use with extreme caution.`
(`/tmp/gap-scratch/cocoon/README.md:235`, verified verbatim) — and earns it: its importer verifies no
commit signature, never checks that the CAR root's `did` matches the authenticated account, and emits no
`#commit`/`#sync` (`impl-notes/cocoon.md:248`). atproto-crates is *stronger* than cocoon on structural
verification and weaker on the thing that decides whether migration works at all: indexing.

Two secondary gaps. Signature verification of the incoming chain exists as code but is never wired —
`RepoImporter::new` sets `plc_verifier: None` (`import.rs:113`), the check is guarded by
`if let Some(verifier)` (`:240-242`), and `with_plc_verifier` has no caller outside its definition at
`:133`; even wired, the historical-key selector compares a PLC ISO-8601 `created_at` against a TID `rev`
with `<=` (`:424`) and so always picks the newest key. And `importRepo` returns a JSON body
(`write_handlers.rs:574-588`) where the lexicon declares no output — harmless but non-conformant.

### Step 4 — the blob backfill loop  · **PARTIAL / effectively broken**

Source-side enumeration works: `sync.listBlobs` pages over stored blobs (`http/blob_handlers.rs:96-122`)
and `sync.getBlob` serves bytes (`:33-72`); `uploadBlob` stores and content-addresses correctly
(`write_handlers.rs:516-571`). But the loop's termination condition — `listMissingBlobs` — reads
`repo_blob_ref ⨝ repo_blob` (`write_handlers.rs:450-501`), and `repo_blob_ref` is never written, so the
endpoint returns `{"blobs": []}` on a freshly imported repo with thousands of outstanding blobs;
`checkAccountStatus.expectedBlobs` reads the same table (`auth_handlers.rs:791-795`) and is always `0`.
The project's own test asserts the broken behaviour as correct —
`assert_eq!(body["blobs"].as_array().unwrap().len(), 0)` (`tests/migration_e2e.rs:176-185`). Separately,
`sync.listBlobs` does not model the lexicon's `since` (tid) parameter (`blob_handlers.rs:76-83`), so
incremental blob sync is impossible, and `uploadBlob` returns an envelope matching neither accepted
lex-`blob` form (`blob.rs:39-49`; see `/tmp/gap-scratch/verified-commit-divergences.md` P1). Every
comparison that routes `listMissingBlobs` backs it with real ref data: reference
(`.../repo/listMissingBlobs.ts:16-18`), cirrus (`storage.ts:490`), tranquil
(`crates/tranquil-db/src/postgres/blob.rs:238-248`), cocoon (`handle_repo_list_missing_blobs.go:40-90`),
pegasus (`user_store.ml:219-231`), zds (`store.zig:2636`), metalbear
(`include/metalbear/repo_store.h:318`), rsky, alteran (`index.js:32`). arroba and dnproto do not serve it.

### Step 5 — private state (`app.bsky.actor.get/putPreferences`)  · **MISSING**

There is no preferences implementation in atproto-crates: a full-tree grep for
`getPreferences|putPreferences` under `crates/atproto-pds/src` returns exactly one hit, a doc comment on
`CheckAccountStatusResponse::private_state_values` (`auth_handlers.rs:852`). Every `app.bsky.*` NSID
falls into the catch-all proxy (`http/router.rs:109-113` → `http/proxy_handlers.rs:120,132`), which
forwards to the configured AppView or 503s when none is configured (`proxy_handlers.rs:145-149`). But
preferences are **PDS-private state, not AppView state**: the reference PDS reads and writes them in its
own actor store (`.../app/bsky/actor/getPreferences.ts:46`, `putPreferences.ts:56`) and the AppView has
no such handler at all (nothing under
`/tmp/gap-scratch/atproto/packages/bsky/src/api/app/bsky/actor/`), so the proxy target will 404. Note
also that `checkAccountStatus.privateStateValues` here counts *app passwords* (`auth_handlers.rs:814-816`),
which is not what the field means. The gap is not migration-only — it breaks muted words, feed pinning
and content-label settings for every logged-in user. Local handling is universal across the field:
cirrus `index.ts:382,387`; dnproto `src/pds/Pds.cs:199-200`; zds `src/http/router.zig:182-183`;
metalbear `src/server.c:6802-6806`; pegasus `bin/main.ml:241-246`; cocoon
`server/handle_actor_get_preferences.go:10`, whose source comment concedes the awkwardness of serving
`app.bsky` from a PDS; rsky `src/apis/app/bsky/actor/get_preferences.rs:34`; tranquil
`crates/tranquil-api/src/lib.rs:445,449`; alteran (`impl-notes/alteran.md:160`); arroba as a
non-persisting stub (`app.py:90-98`).

### Steps 6–8 — identity rotation  · **DIVERGENT** *(security)*

`getRecommendedDidCredentials` is real and lexicon-shaped (`http/identity_handlers.rs:410-460`).
Everything after it diverges.

`requestPlcOperationSignature` (`identity_handlers.rs:299-341`) returns `{token}` — a 60-second
`lxm`-locked service-auth JWT — in the response body, where the lexicon declares no output and the
canonical semantics are to email a confirmation code. Returning the second factor to whoever already
holds the first is not a second factor. cirrus and alteran also no-op this endpoint by design, so a
non-canonical shape has precedent, but both compensate with a real out-of-band secret (cirrus's signed
CLI migration token, `migration-token.ts:65-79`).

`signPlcOperation` is a different protocol. The lexicon accepts
`{token?, rotationKeys?, alsoKnownAs?, verificationMethods?, services?}` and has the PDS compose the
operation; atproto-crates requires a single `op` field carrying a complete `UnsignedOperation`
(`auth_handlers.rs:1594-1597`, deserialized at `:1650`) and signs it blind with the account's rotation
key (`:1657`) — no token, no field merge, no check that `op.prev` matches the account's current PLC head,
no privilege check (`require_access_jwt` at `:1619` resolves to bare `session::verify_access`,
`:1754-1759`). Two consequences: canonical clients cannot drive the endpoint at all, and any app-password
session can have an arbitrary PLC operation signed with the account's rotation key. The reference
requires the emailed `plc_operation` token and throws without it
(`.../identity/signPlcOperation.ts:41-51`) on top of `ACCESS_FULL` + `assertIdentity({attr:'*'})`
(`:13-17`); cocoon emails a one-shot code (`handle_identity_sign_plc_operation.go:56-90`), pegasus gates
on an emailed auth code (`api/identity/signPlcOperation.ml:14-57`), zds is email-token gated
(`src/atproto/identity.zig:65-114`), metalbear mints a `plc_operation` email token
(`src/server.c:1391-1393`), cirrus validates its HMAC migration token (`xrpc/identity.ts:139-207`). Only
alteran — the hobby-experiment tier — is equally ungated (`impl-notes/alteran.md:144`).

`submitPlcOperation` (`auth_handlers.rs:1685-1710`) deserializes and POSTs. The reference performs five
checks first — server rotation key present in `op.rotationKeys`, `atproto_pds` service type and endpoint,
`verificationMethods.atproto` equal to the stored signing key, `alsoKnownAs[0]` equal to the account
handle (`.../identity/submitPlcOperation.ts:23-50`) — and the migration guide names exactly this as the
reason to route the operation through the new PDS (`ACCOUNT_MIGRATION.md:49`). atproto-crates performs
none of them, so the endpoint offers no more protection than curling `plc.directory` directly. pegasus
validates against the account handle and signing key (`api/identity/submitPlcOperation.ml:18-27`);
alteran does not validate either.

### Step 9 — `checkAccountStatus` and `activateAccount`  · **PARTIAL / DIVERGENT**

`checkAccountStatus` (`auth_handlers.rs:740-860`) computes real counts from the per-actor tables, which
is more than cocoon (`Activated`/`ValidDid` hardcoded, `ImportedBlobs` always 0) or dnproto (4 of 9
fields) manage. Two defects: `valid_did` is hardcoded `true` (`:820`) with a doc comment claiming it
means "`true` iff the DID resolves to this PDS" (`:837`), and the lexicon-required `repoCommit`/`repoRev`
carry `skip_serializing_if = "Option::is_none"` (`:841-845`) so an empty repo emits a body missing two
required fields. Because `expectedBlobs` is sourced from the never-populated `repo_blob_ref`, the field
the migration guide tells you to poll ("how many blobs it is expecting… and how many have been
uploaded", `ACCOUNT_MIGRATION.md:39`) is structurally unable to report a shortfall.

`activateAccount` (`auth_handlers.rs:677-688`) is three lines: verify the session JWT, `set_state(Active)`,
return 200. There is no DID-document pre-flight, no handle check, no repo check. `set_state` does emit a
`#account` event best-effort (`account/manager.rs:362`, `emit_account_event` `:369-390`), but no
`#identity` and no `#sync` — the two events the migration guide explicitly promises
(`ACCOUNT_MIGRATION.md:59`). **The direct answer to "does the server refuse to activate while blobs are
still missing" is: no — and neither does anyone else, including the reference.** The gate that actually
exists upstream is the DID-document check in `assertValidDidDocumentForService`
(`api/com/atproto/server/util.ts:72-135`, invoked from `account-manager.ts:458`), which rsky-pds
reproduces exactly (`activate_account.rs:21`) and cirrus reproduces client-side in `pds activate`
(`cli/commands/activate.ts:34-57`). Emitting the full `#account` + `#identity` + `#sync` triple on
activation is done by the reference, rsky, tranquil (`server/account_status.rs:411-480`), cirrus
(`account-do.ts:1297-1330`), zds (`src/atproto/server.zig:963-965`) and even dnproto
(`ComAtprotoServer_ActivateAccount.cs`); cocoon emits `#account` + `#sync`.

### Step 10 — clean-up on the source PDS  · **PARTIAL**

`deactivateAccount` (`auth_handlers.rs:697-731`) is real and persists `deleteAfter` with an hourly GC
loop — better than cocoon and pegasus, which both parse and ignore it. `deleteAccount` (`:1173`) is
lexicon-divergent in a security-relevant way: the lexicon requires `did`, `password` and `token`, and
`DeleteAccountInput` (`:1162-1166`) models only `token`, making permanent deletion single-factor on an
emailed string. That is primarily an auth-area finding, noted here because it ends the flow.

### Migration tooling, docs and tests  · **PARTIAL**

There is no migration CLI, wizard or runbook. tranquil-pds ships an 11-step Svelte inbound wizard plus
`verifyMigrationEmail`/`resendMigrationVerification`; cirrus ships `pds migrate`/`identity`/`activate`
with resumable blob backfill; pegasus has `/account/migrate`; alteran and dnproto ship out-of-band
scripts (`scripts/migrate-back-to-bsky-manual.sh`, `src/cli/commands/BackupAccount.cs`). atproto-crates
has `crates/atproto-pds/tests/migration_e2e.rs` (3 tests), whose module doc describes a flow the test
does not exercise — it claims step 1 is a service-auth JWT and step 2 is
`createAccount(did=..., plcOp=...)` (`:5-6`) while the body posts `{"did","handle","password"}` with no
`Authorization` header (`:135-144`) — and which asserts both broken behaviours as expected results.

---

## Endpoint scorecard (atproto-crates)

| Migration step | NSID | Routed | Verdict |
|---|---|---|---|
| discover target | `com.atproto.server.describeServer` | no | MISSING |
| mint proof | `com.atproto.server.getServiceAuth` | `router.rs:153` | OK (`exp` semantics diverge) |
| reserve key | `com.atproto.server.reserveSigningKey` | `router.rs:169` | PARTIAL — **unauthenticated** (`auth_handlers.rs:891`) |
| provision | `com.atproto.server.createAccount` | `router.rs:117` | DIVERGENT — no DID proof, always Active, `plcOp` ignored |
| export | `com.atproto.sync.getRepo` | `router.rs:83` | OK (full + `since` diff) |
| import | `com.atproto.repo.importRepo` | `router.rs:71` | PARTIAL — no record index, no blob refs, sigs unverified |
| enumerate blobs | `com.atproto.sync.listBlobs` | `router.rs:93` | PARTIAL — `since` not modelled |
| fetch blob | `com.atproto.sync.getBlob` | `router.rs:89` | OK |
| upload blob | `com.atproto.repo.uploadBlob` | `router.rs:67` | DIVERGENT — non-lex blob envelope |
| find gaps | `com.atproto.repo.listMissingBlobs` | `router.rs:63` | PARTIAL — always empty |
| private state | `app.bsky.actor.get/putPreferences` | proxied only | MISSING |
| recommend creds | `com.atproto.identity.getRecommendedDidCredentials` | `router.rs:214` | OK |
| request signature | `com.atproto.identity.requestPlcOperationSignature` | `router.rs:209` | DIVERGENT — returns a JWT, not an emailed token |
| sign PLC op | `com.atproto.identity.signPlcOperation` | `router.rs:193` | DIVERGENT — different input shape, no gate |
| submit PLC op | `com.atproto.identity.submitPlcOperation` | `router.rs:197` | PARTIAL — zero validation |
| poll status | `com.atproto.server.checkAccountStatus` | `router.rs:165` | PARTIAL — `validDid` hardcoded, `expectedBlobs` always 0 |
| finalize | `com.atproto.server.activateAccount` | `router.rs:157` | PARTIAL — no pre-flight, no `#identity`/`#sync` |
| clean up | `com.atproto.server.deactivateAccount` | `router.rs:161` | OK (`deleteAfter` honoured) |
| clean up | `com.atproto.server.deleteAccount` | `router.rs:185` | DIVERGENT — single-factor |

---

## Findings

Each entry: CLASS · severity · evidence (atproto-crates) · comparison · consequence.

**1. `createAccount` adopts a caller-supplied DID with no proof of control.** MISSING · **rc-blocker
(security)**. `auth_handlers.rs:81-83` has no `Parts` and no guard; `:180-183` says the DID is trusted;
`/tmp/gap-scratch/inv/auth.md:253` shows the only inbound service-auth verifier is spaces-scoped.
Reference `createAccount.ts:250-254`; cocoon `handle_server_create_account.go:81-95`; zds
`server.zig:700-752`; tranquil `identity/account.rs:244-256`. Shared weakness: metalbear
(`src/server.c:206`, `:3283`), pegasus (XRPC route unchecked), rsky (inverted check,
`create_account.rs:318`). Any unauthenticated caller can occupy any DID and handle here, obtaining a
session bound to the victim's DID and permanently denying them an inbound migration.

**2. `importRepo` writes no record index and no blob refs.** PARTIAL · **rc-blocker**.
`crates/atproto-pds/src/repo/import.rs` — `repo_record` appears only in the doc comment at `:10`;
`blob.rs:115` (`add_ref`) has no production caller tree-wide; readers source `repo_record` at
`repo/reader.rs:133,141,268,280,353`. Reference `.../repo/importRepo.ts:84-95`; cirrus
`account-do.ts:1023-1035`; pegasus `repository.ml:559-562`; cocoon `handle_import_repo.go:72-101`; zds
`repo.zig:343-395`; tranquil `sync/import.rs:304-361`. A migrated account reads as empty through every
record endpoint and the blob loop can never discover work — this alone makes the sequence non-functional.

**3. Preferences (`app.bsky.actor.get/putPreferences`) are not implemented.** MISSING · **rc-blocker**.
No implementation in `crates/atproto-pds/src`; the catch-all proxy at `http/router.rs:109-113` →
`proxy_handlers.rs:120,132` forwards them to an AppView that has no such handler (absent from
`/tmp/gap-scratch/atproto/packages/bsky/src/api/app/bsky/actor/`), while the reference PDS owns them
(`.../app/bsky/actor/getPreferences.ts:46`). Served locally by all eleven: cirrus `index.ts:382,387`;
dnproto `Pds.cs:199-200`; zds `router.zig:182-183`; metalbear `server.c:6802-6806`; pegasus
`bin/main.ml:241-246`; rsky `get_preferences.rs:34`; tranquil `lib.rs:445,449`; arroba stubs
(`app.py:90-98`). Private-state migration is impossible in both directions, and muted words / feed prefs
/ content labels are broken for every logged-in user.

**4. `createAccount` always creates the account `Active`.** DIVERGENT · **rc-blocker**.
`account/manager.rs:158`; conceded by `tests/migration_e2e.rs:148-158`. Reference `createAccount.ts:256`;
rsky `create_account.rs:325`; tranquil `account.rs:439`; zds `server.zig:152`; cirrus
`account-do.ts:79-85`; pegasus `migrate/ops.ml:91-94`; arroba `xrpc_repo.py:259`. cocoon shares the gap.
The PDS announces an account whose DID document still points at the old PDS, and `activateAccount`
becomes a no-op with nothing to gate.

**5. `signPlcOperation` uses a non-lexicon input shape and applies no confirmation gate.** DIVERGENT ·
**rc-blocker (security + interop)**. `auth_handlers.rs:1594-1597` (`op` field), `:1650`, `:1657` (blind
sign), `:1619` → `:1754-1759` (no `privileged()` check). Reference
`.../identity/signPlcOperation.ts:13-17,41-51`; cocoon `handle_identity_sign_plc_operation.go:56-90`;
pegasus `signPlcOperation.ml:14-57`; zds `identity.zig:65-114`; metalbear `server.c:1391-1393`; cirrus
`xrpc/identity.ts:139-207`. Only alteran (hobby tier) is equally ungated. goat and `@atproto/api` cannot
drive rotation here at all, and any app-password session can have an arbitrary PLC operation signed with
the account's rotation key.

**6. `submitPlcOperation` validates nothing before forwarding to the PLC directory.** PARTIAL ·
**rc-blocker**. `auth_handlers.rs:1685-1710`. Reference `.../identity/submitPlcOperation.ts:23-50`
performs five checks; pegasus `submitPlcOperation.ml:18-27` performs two. alteran likewise does not
validate. The guide's stated reason for routing the op through the new PDS — catching an operation that
would leave the account broken (`ACCOUNT_MIGRATION.md:49`) — is not delivered; a malformed op silently
and permanently locks the user out of their identity.

**7. `activateAccount` performs no pre-flight and emits no `#identity`/`#sync`.** PARTIAL ·
**rc-blocker**. `auth_handlers.rs:677-688`; `#account` only, via `account/manager.rs:362,369-390`.
Reference `activateAccount.ts:33` → `account-manager.ts:458` → `server/util.ts:72-135`; rsky
`activate_account.rs:21,46-52`; tranquil `server/account_status.rs:411-480`; cirrus
`account-do.ts:1297-1330` (+ CLI pre-flight `cli/commands/activate.ts:34-57`); zds `server.zig:963-965`;
dnproto emits all three. Note **no** implementation, reference included, blocks activation on missing
blobs — the canonical gate is the DID-document check, which atproto-crates lacks. An account can go
active while its DID still resolves to the old PDS, and relays are never told the repo moved.

**8. `describeServer` is not routed, so the flow cannot be started by a standard client.** MISSING ·
**rc-blocker**. Not-routed table in `/tmp/gap-scratch/inv/endpoints.md`; `http/router.rs`. Routed by all
eleven (cirrus `index.ts:278`; zds `router.zig:155`; arroba `xrpc_server.py:55`; dnproto `Pds.cs:190`; …).
`goat account migrate` and the canonical TS example both fail on their first call to the new PDS.
(Primary owner: endpoint-coverage chapter; restated as a migration precondition.)

**9. `listMissingBlobs` and `checkAccountStatus.expectedBlobs` are structurally always zero.** PARTIAL ·
**rc-blocker**. `write_handlers.rs:450-501` and `auth_handlers.rs:791-795` both read `repo_blob_ref`,
which nothing writes (finding 2); asserted as correct by `tests/migration_e2e.rs:176-185`. Real in
reference, cirrus, tranquil, cocoon, pegasus, zds, metalbear, rsky and alteran. The client's blob loop
terminates immediately and the migration completes with zero media.

**10. `com.atproto.server.reserveSigningKey` is unauthenticated.** DIVERGENT · **rc-blocker (security)**
— jointly owned by the auth chapter. `auth_handlers.rs:891-894` (signature is `(State, Json<Input>)`);
key persisted and a reservation row written for a caller-supplied `did` at `:911-924`. Session-gated in
tranquil (`lib.rs:233`), cocoon (`server.go:518`), rsky, pegasus, zds (`server.zig:59-74`); metalbear
also lists it public (`server.c:208`). An anonymous caller can force unbounded key generation and squat
reservation rows for arbitrary DIDs — the exact primitive the BYO-DID path depends on.

**11. `requestPlcOperationSignature` returns a bearer token instead of emailing a confirmation code.**
DIVERGENT · **stable-gap**. `identity_handlers.rs:288-291,299-341`; the lexicon declares no output. The
reference, cocoon, metalbear, pegasus and zds all email a `plc_operation` token; cirrus
(`xrpc/identity.ts:122-129`) and alteran no-op it by design but replace it with a real out-of-band
secret. The second factor is handed to whoever already holds the first; given finding 5 no token is
consumed anyway, so the endpoint is decorative.

**12. `checkAccountStatus.validDid` is hardcoded and two required fields are conditionally omitted.**
DIVERGENT · **stable-gap**. `auth_handlers.rs:820`, `:837` (contradicting doc comment), `:841-845`.
Reference `checkAccountStatus.ts:32`; tranquil, pegasus, zds, cirrus and metalbear compute it. cocoon
hardcodes it too (`handle_server_check_account_status.go:29-33`); dnproto omits 5 of 9 fields. A client
polling status is told the identity is correct before any PLC operation has been submitted.

**13. `importRepo` never verifies the incoming commit-chain signature, and the historical-key selector is
unsound.** PARTIAL · **stable-gap**. `repo/import.rs:113` (`plc_verifier: None`), `:240-242`, `:133`
(`with_plc_verifier` has no caller), `:424` (ISO-8601 `created_at` compared to a TID `rev`). The
reference does not verify either (`.../repo/importRepo.ts:54-63` re-signs), so this is not a
reference-parity demand — but arroba (`xrpc_repo.py:241-243`) and tranquil (`repo/import.rs:130`) do.
A CAR whose commits were never signed by the DID's key imports cleanly; low marginal risk while finding
1 stands, but it must close alongside it.

**14. `sync.listBlobs` does not model the lexicon's `since` parameter.** DIVERGENT · **stable-gap**.
`http/blob_handlers.rs:76-83` vs `/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/listBlobs.json`.
An interrupted migration must re-walk the whole blob set; incremental resume is impossible source-side.

**15. `createAccount` ignores `plcOp`, `recoveryKey`, `verificationCode`, `verificationPhone`.** MISSING ·
**cosmetic** (defensible as OUT-OF-SCOPE with a doc fix). `auth_handlers.rs:28-41` vs
`.../lexicons/com/atproto/server/createAccount.json`. The reference rejects `plcOp` on a non-entryway
PDS; only zds implements it (`server.zig:132-152`). Functionally harmless once finding 1 is fixed, but
`tests/migration_e2e.rs:6` and `repo/import.rs:3-6` both document a flow that uses `plcOp`.

**16. The end-to-end migration test certifies the broken behaviour.** PARTIAL · **stable-gap**.
`tests/migration_e2e.rs:5-6` (doc claims service auth + `plcOp`) vs `:135-144` (no `Authorization`, no
`plcOp`); `:148-158` (works around always-active); `:176-185` (asserts `listMissingBlobs == []`). cirrus
exercises migration through `packages/pds/e2e/` plus a real CLI; tranquil ships `tests/plc_migration.rs`,
`tests/import_with_verification.rs`, `tests/whole_story.rs`. The suite gives false confidence that
migration works, which is plausibly how this area reached RC in its current state.

**17. No migration tooling, wizard, or operator runbook.** MISSING · **stable-gap**. No migration CLI in
`crates/atproto-pds/src/bin`; `/tmp/gap-scratch/inv/ops.md:465` records that no operator runbook exists
at all. tranquil ships an 11-step wizard; cirrus `pds migrate`/`identity`/`activate`; pegasus
`/account/migrate`; alteran and dnproto ship scripts. Even once the endpoints are fixed there is nothing
an operator can hand a user.

**Severity roll-up:** 10 rc-blockers (1–10, of which 8 is primarily owned by the endpoint-coverage
chapter and 10 by the auth chapter), 6 stable-gaps (11–14, 16, 17), 1 cosmetic (15). Genuine security
issues: 1, 5, 6, 10 (DID squatting, ungated rotation-key signing, unvalidated PLC submission, anonymous
key minting). Spec-compliance failures that break the flow without being exploitable: 2, 3, 4, 7, 8, 9.
The rest is correctness and hygiene.

---

## Confidence & unknowns

High confidence on everything sourced from `crates/atproto-pds/src`: every atproto-crates claim above was
re-opened at the cited line during this pass — the handler signatures for `create_account`,
`activate_account`, `sign_plc_operation`, `submit_plc_operation`; the `AccountState::Active` bind at
`account/manager.rs:158`; the absent `repo_record` writes and `add_ref` callers; the body of
`tests/migration_e2e.rs`. Reference claims come from `/tmp/gap-scratch/atproto/packages/pds/src/api/**`
and `account-manager/**`; every canonical shape was checked against
`/tmp/gap-scratch/atproto/lexicons/com/atproto/**`. Verified first-hand for the comparisons: cirrus
`account-do.ts:975-1045,1290-1330`; cocoon `handle_server_create_account.go:75-95` and `README.md:235`;
zds `server.zig:108-180,700-752`; rsky `create_account.rs:40-80,305-345` and `activate_account.rs`;
tranquil `account.rs:230-265,340-365,439`; metalbear `server.c:190-230,1834-1930,3283+`; arroba
`xrpc_repo.py:205-262` and `app.py:75-105`; plus route-table greps for `describeServer`,
`reserveSigningKey`, `getRecommendedDidCredentials` and the preference endpoints in all eleven trees.

Unknowns and softer cells:

- **UNVERIFIED:** whether the reference's `verifyDiff` performs any signature check beyond MST structure.
  I read `.../repo/importRepo.ts` in full but not `@atproto/repo`'s `verifyDiff`. This affects only how
  generous finding 13's comparison row is; the atproto-crates side is certain.
- **UNVERIFIED:** whether pegasus, metalbear or rsky verify the incoming commit signature on import — I
  read their route registrations, not their importer bodies, so those cells are `?`.
- **UNVERIFIED:** dnproto's exact `createAccount` posture. `grep createAccount src/pds/Pds.cs` finds no
  route and `impl-notes/dnproto.md:442` states account creation is absent, so the BYO-DID rows are scored
  `N`/`n/a` without an exhaustive sweep of `src/pds`.
- **UNVERIFIED:** the exact error a client sees for a proxied `app.bsky.actor.putPreferences`. The
  handler's absence from `/tmp/gap-scratch/atproto/packages/bsky` establishes the gap; the failure mode
  would need a live AppView.
- The `com.atproto.space.*` surface has no migration story at all — space records live outside the public
  repo (see [permissioned-data overview](../permissioned/40-permissioned-overview.md)) and neither
  `importRepo` nor `getRepo` covers them, so an account that migrates away silently loses all
  permissioned data. Arguably OUT-OF-SCOPE while spaces are themselves pre-stable; scored as an open
  design question rather than a finding because no code addresses it either way.
