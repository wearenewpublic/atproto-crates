# J. Moderation & admin

*Capability-area chapter of the atproto-crates 0.15.0-rc.1 release-candidate gap analysis.
See [../README.md](../README.md) for scope, [../00-atproto-crates-inventory.md](../00-atproto-crates-inventory.md)
for the underlying inventory, [../20-coverage-matrix.md](../20-coverage-matrix.md) for the
cross-implementation matrix, and [../50-synthesis-and-roadmap.md](../50-synthesis-and-roadmap.md)
for the consolidated remediation plan.*

## Assessment

A PDS is not a moderation service, and no implementation in this comparison pretends otherwise —
the reference itself proxies `com.atproto.moderation.createReport` upstream and keeps labeling in
Ozone. What a PDS *does* own is two things: an administrative control plane (`com.atproto.admin.*`)
that an operator or a moderation service can drive over the wire, and — much more importantly — the
**enforcement** of the takedown decisions that control plane records. A takedown row that no read or
write path consults is not moderation; it is a note to self.

On raw breadth, atproto-crates is at the very top of the independent field. It routes twelve of the
fifteen canonical `com.atproto.admin.*` methods at their correct NSIDs
(`crates/atproto-pds/src/http/router.rs:359-426`), which is one short of the reference's thirteen
and second only to tranquil-pds's fourteen. It includes `searchAccounts`, which the reference,
rsky-pds, metalbear, and pegasus all omit. It ships three project-defined admin verbs on top
(`takedownSpaceRecord`, `revokeServiceAuth`, `forceRepoSync`), an HTML admin dashboard
(`crates/atproto-pds/src/admin/dashboard.rs:87`), an admin CLI
(`crates/atproto-pds/src/bin/atproto-pds-admin.rs:41-111`), a hashed handle/email denylist
(`crates/atproto-pds/src/denylist.rs`), and a genuine service-auth-signed `createReport` proxy
(`crates/atproto-pds/src/http/moderation_handlers.rs:44-136`) that is closer to the reference's
design than anything else in the field except tranquil-pds and rsky-pds. Against cocoon (zero admin
routes, no takedown concept at all), arroba (none), pegasus (seven admin routes, no subject-status
endpoints), dnproto (none), and zds (one admin route), this is an unusually complete surface.

The problem is that almost none of it is reachable by a conforming client, and the part that matters
most is only half enforced. `updateSubjectStatus` and `getSubjectStatus` — the two endpoints Ozone and
`pdsadmin` actually call — speak a project-local `{did, state}` shape instead of the lexicon's
`$type`-tagged `subject` union plus `#statusAttr`
(`crates/atproto-pds/src/admin/handlers.rs:156-162`, `:204-218`). That is not a cosmetic naming
issue: it means record-level and blob-level takedown are *unaddressable*, and it means zds — a
"serious"-tier implementation that routes exactly one admin method — is nonetheless the one that a
stock `pdsadmin account takedown` invocation can drive, because zds parses the canonical union and
returns a canonical `subject` in its response (`/tmp/gap-scratch/zds/src/atproto/server.zig:995-1050`).
Four more admin methods diverge on field names or parameter shapes badly enough to hard-fail
deserialization for a canonical caller.

Enforcement is the more serious half. atproto-crates has a well-designed five-state account FSM with
`allows_public_read()` and `allows_writes()` predicates and unit tests asserting the intended
semantics (`crates/atproto-pds/src/account/state.rs:54-102`; the read predicate is
`Active | Deactivated` at `:56-58`). Enforcement is **partial, not absent** — that distinction
matters and the rest of this chapter is scoped to it. Record-level reads *are* gated:
`allows_public_read()` is consulted at exactly two sites, `getRecord` and `listRecords`
(`crates/atproto-pds/src/repo/reader.rs:107`, `:209`), and a passing test asserts the takedown denial
(`get_record_takendown_account_denied`, `repo/reader.rs:695-704`). What is not gated is everything
else: `getRepo`, `getBlocks`, `getBlob`, `listBlobs`, `getLatestCommit`, and `describeRepo` all serve
a taken-down account's data to anonymous callers — so a takedown removes the record-level reads while
leaving **bulk export wide open**, which is arguably the worse half. `allows_writes()` meanwhile has
**zero production callers**: the write path never consults account state at all. The reference gates
all of those read paths through one helper
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/sync/util.ts:6-36`), as do tranquil-pds,
rsky-pds, and zds. metalbear is the honest calibration point here: it records takedowns without
enforcing them and says so in its own README
([../impl-notes/metalbear.md](../impl-notes/metalbear.md) §11). atproto-crates lands between the two:
a state machine whose doc comment says takedown "blocks reads and writes"
(`crates/atproto-pds/src/account/state.rs:20-22`) while the code blocks two of roughly nine public
read paths and no writes at all. A moderation control plane that silently under-enforces is worse
than none.

A second doc-vs-code mismatch sits in the same file and should be fixed alongside: `Deactivated` is
documented as "repo not accessible to public sync"
(`crates/atproto-pds/src/account/state.rs:17-19`), but `allows_public_read()` returns `true` for it
(`:56-58`), so a voluntarily deactivated account stays publicly readable on the two gated paths as
well as everywhere else.

---

## Per-capability analysis

### 1. `com.atproto.admin.updateSubjectStatus` / `getSubjectStatus` — subject shape

**CLASS: DIVERGENT.** The canonical input (`/tmp/gap-scratch/atproto/lexicons/com/atproto/admin/updateSubjectStatus.json`)
requires a `subject` that is a union of `com.atproto.admin.defs#repoRef` (account),
`com.atproto.repo.strongRef` (record), and `com.atproto.admin.defs#repoBlobRef` (blob), plus optional
`takedown` and `deactivated` objects of type `#statusAttr` (`{applied: bool, ref?: string}`). The
output requires `subject` echoed back. atproto-crates instead defines
`UpdateSubjectStatusInput { did, state }` where `state` is one of the PDS-internal strings
`active|deactivated|takendown|suspended|deleted`
(`crates/atproto-pds/src/admin/handlers.rs:156-162`), calls `manager.set_state`
(`:187-196`), and returns `{did, state}` (`:197-200`). `getSubjectStatus` mirrors it: `did` is a
**required** query param where all three lexicon params are optional, and `uri`/`blob` are not read
at all (`:204-218`).

Three consequences follow. Ozone's takedown flow, `pdsadmin account takedown`
(`/tmp/gap-scratch/bsky-pds/pdsadmin/account.sh:147,161` per
[../impl-notes/bluesky-reference.md](../impl-notes/bluesky-reference.md) §12), and every other
canonical admin client will receive a 400 on deserialization. Record-level takedown of a public-realm
repo record has no representation at all — the only record takedown table in the schema is
`space_record_takedown`, which is Spaces-only
(`crates/atproto-pds/migrations/actor/20260506000002_space_record_takedown.sql:17-26`). Blob-level
takedown likewise does not exist. The reference (`admin/updateSubjectStatus.ts:8`, enforcement via
`record.takedownRef` and `blob.takedownRef`), rsky-pds
(`apis/com/atproto/admin/update_subject_status.rs:28-59` handling all three shapes), and tranquil-pds
(`crates/tranquil-api/src/admin/status.rs:169-205,257-265,291-299`) all cover all three subject kinds.
metalbear records all three in a `subject_takedown(did, uri, blob_cid, …)` table but enforces none.

### 2. Account-takedown enforcement on read paths

**CLASS: PARTIAL — and this is the security-relevant crux of the area.**

`require_public_read` (`crates/atproto-pds/src/repo/reader.rs:510-518`) rejects any state where
`allows_public_read()` is false, i.e. `takendown`, `suspended`, `deleted`. It is called from exactly
two places: `RepoReader::get_record` (`:107`) and `RepoReader::list_records` (`:209`), and both are
genuinely enforced — `get_record_takendown_account_denied` (`repo/reader.rs:695-704`) asserts
`PdsError::AuthDenied` against a `takendown` row. Everything else that serves repo bytes ignores
account state:

| Endpoint | Handler | Consults account state? |
|---|---|---|
| `com.atproto.repo.getRecord` | `repo/reader.rs:99` | **yes** (`:107`) |
| `com.atproto.repo.listRecords` | `repo/reader.rs:200` | **yes** (`:209`) |
| `com.atproto.repo.describeRepo` | `repo/reader.rs:335-379` | no |
| `com.atproto.sync.getRepo` | `http/handlers.rs:186-233` | no |
| `com.atproto.sync.getBlocks` | `http/handlers.rs:245-296` | no |
| `com.atproto.sync.getBlob` | `http/blob_handlers.rs:33-72` | no |
| `com.atproto.sync.listBlobs` | `http/blob_handlers.rs:96-123` | no |
| `com.atproto.sync.getLatestCommit` | `repo/reader.rs:382-397` | no |
| `com.atproto.sync.getRepoStatus` | `repo/reader.rs:400-429` | reports it (`:421`), does not gate |

The whole sync/blob surface is state-blind by construction, not by oversight in one handler: a grep
for `allows_public_read|require_public_read|AccountState` returns **zero** hits in each of
`crates/atproto-pds/src/repo/car_export.rs` (getRepo), `blob.rs` (getBlob),
`http/handlers.rs` (getBlocks) and `http/blob_handlers.rs` (listBlobs).

The practical effect: after a moderator takes an account down, `getRecord` returns 401 for a single
record while `GET /xrpc/com.atproto.sync.getRepo?did=…` still streams the complete CAR containing
that record's block, and `getBlob` still serves every image. For a takedown motivated by illegal
content, the content remains publicly retrievable by an unauthenticated caller. The reference applies
`assertRepoAvailability` to `getBlob`, `getBlocks`, `getRecord`, `getRepo`, `getRepoStatus`,
`listBlobs`, `getLatestCommit`, both deprecated sync routes, and `repo/describeRepo`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/sync/util.ts:6-36` plus the ten call
sites verified by grep), with a deliberate self/admin bypass at `:21-23`. zds applies
`requirePublicRepoAvailable` to `getBlob`, `getRepo`, `listBlobs`, and `getLatestCommit`
(`/tmp/gap-scratch/zds/src/atproto/sync.zig:181,210,252,272`; helper at `:342-354`) and to three repo
reads (`/tmp/gap-scratch/zds/src/atproto/repo.zig:112,141,176`). tranquil-pds routes every public sync
read through `assert_repo_availability` (`crates/tranquil-pds/src/sync/util.rs:131-182`). rsky-pds
does the same at `sync/get_repo.rs:43` and `sync/get_blob.rs:33`. This is not a
reference-only capability: three independent "serious" implementations do it, and one of them (zds)
does it with a *smaller* admin surface than atproto-crates.

### 3. Account-takedown enforcement on write paths and live sessions

**CLASS: MISSING.**

`AccountState::allows_writes` (`crates/atproto-pds/src/account/state.rs:60-64`) has no caller outside
its own unit test — a full-tree grep for `allows_writes` returns `state.rs:62`, `:89`, `:92`, `:95`,
`:98`, `:101` and nothing else. The repo write guard `require_session`
(`crates/atproto-pds/src/http/write_handlers.rs:71-74`) delegates to `require_authn`
(`crates/atproto-pds/src/http/auth.rs:154-184`), which verifies a JWT signature and (when bound) a
DPoP proof, and never opens the account directory. `assert_subject`
(`write_handlers.rs:113-126`) checks only that the token subject equals the target repo.

Session issuance *does* check state — `create_session` refuses anything that is not `Active` or
`Deactivated` (`crates/atproto-pds/src/http/auth_handlers.rs:319-328`), as does the OAuth authorize
path (`crates/atproto-pds/src/oauth/authorize.rs:96-100`). But refresh does not.
`refresh_session` loads the `AccountRow` at `auth_handlers.rs:429-440` purely to read the handle, and
mints a fresh token pair without inspecting `account.state` (`:441-456`). `oauth::handle_refresh`
(`crates/atproto-pds/src/oauth/token.rs:188-234`) never touches the account directory at all. With
`DEFAULT_REFRESH_TTL_SECS = 7_776_000` (90 days, `crates/atproto-pds/src/account/session.rs:26`), a
taken-down account holding a refresh token retains full write access indefinitely, and every write it
makes is sequenced onto the firehose for relays to fan out.

The field: the reference confines taken-down accounts to a restricted `AuthScope.Takendown`
sufficient only to migrate out ([../impl-notes/bluesky-reference.md](../impl-notes/bluesky-reference.md) §11);
rsky-pds checks `takedownRef` inside the auth verifier when `check_takedown` is set
(`auth_verifier.rs:994`, enabled by the `AccessFull` guards at `:280,386,420`); zds calls
`requireActiveAccount` at seven write sites (`/tmp/gap-scratch/zds/src/atproto/repo.zig:21,62,195,232,350,426,566`,
helper `:587-594`); tranquil-pds gates `uploadBlob` and `importRepo` with an `Auth<NotTakendown>`
extractor (`crates/tranquil-pds/src/repo/blob.rs:242`, `repo/import.rs:48`). Even pegasus, which has
no takedown concept whatsoever, checks account *deactivation* in every auth verifier and in
`Repository.load ~ensure_active` (`pegasus/lib/auth.ml:234-239,327-332`; `repository.ml:421-426`).

One thing atproto-crates does get right: state transitions append a `#account` outbox event with
`active` and `status` (`crates/atproto-pds/src/account/manager.rs:369-390`), so downstream relays are
told about the takedown even though this PDS keeps serving the data. The payload sets
`"status": "active"` for the `Active` case, which is outside the lexicon's `knownValues`
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json` `#account`, where `status`
is documented as meaningful only when `active=false`) — cosmetic, but worth fixing alongside.

### 4. `com.atproto.moderation.createReport` as a proxy

**CLASS: PARTIAL — and the design is right.** `crates/atproto-pds/src/http/moderation_handlers.rs:44`
authenticates the caller with the unified session/OAuth guard (`:52`), mints a 60-second service-auth
JWT signed with the *caller's* atproto key and scoped with `lxm=com.atproto.moderation.createReport`
(`:78`, `mint_service_auth` at `:158-212`), POSTs the body to
`<PDS_REPORT_SERVICE_URL>/xrpc/com.atproto.moderation.createReport` (`:96-110`), and echoes the
upstream status and body (`:126-135`). This matches the reference's `moderation/createReport.ts:19-38`
almost step for step, and the lexicon's own description ("Implemented by moderation services (with PDS
proxying)") confirms proxying is correct behavior.

Two shortfalls. The handler takes `body: axum::body::Bytes` and never parses it, so the
lexicon-required `reasonType` and `subject` are not validated locally — a malformed report is
forwarded and the upstream decides. rsky-pds at least checks `reasonType` is non-empty before
proxying (`apis/com/atproto/moderation/create_report.rs:8-42`). And when
`PDS_REPORT_SERVICE_DID`/`_URL` are unset the endpoint is a hard `503 ModerationServiceUnavailable`
(`:61-74`) — defensible as an explicit unconfigured state, but it means a default deployment has no
report path at all. The field is split: tranquil-pds forwards when configured and otherwise persists
locally (`crates/tranquil-api/src/moderation/mod.rs:74-92`); metalbear persists locally into
`reports.sqlite3` with no forwarding and no read-back (`report.c:28-42`); cirrus proxies to a
hardcoded Bluesky labeler DID (`xrpc-proxy.ts:409-422`); cocoon, arroba, pegasus, zds, dnproto, and
alteran route it nowhere.

### 5. Invite management

**CLASS: DIVERGENT (namespace) + PARTIAL (shape).** `disableAccountInvites` and
`enableAccountInvites` have working handlers (`crates/atproto-pds/src/admin/handlers.rs:877`, `:889`,
flag write at `set_invite_flag` `:898+`) mounted at `com.atproto.server.disableAccountInvites` /
`enableAccountInvites` (`crates/atproto-pds/src/http/router.rs:413,417`). No such NSIDs exist; the
canonical ones are `com.atproto.admin.disableAccountInvites` /
`com.atproto.admin.enableAccountInvites`, which are unrouted — so a canonical caller gets a 404 on a
feature that is fully implemented. The input field also diverges: the lexicon requires `account`,
the handler reads `did` (`InviteToggleInput` `:866-871`), and the optional `note` is dropped.

`disableInviteCodes` is routed correctly but requires a non-empty `codes` array and ignores the
lexicon's `accounts` array entirely (`:1050-1068`), so bulk per-account code revocation — the reason
the field exists — is unimplemented. `getInviteCodes` ignores all three declared params
(`sort`, `limit`, `cursor`), takes an undeclared `createdBy` instead (`:337-343`), returns every code
in the system unpaginated, and emits `availableUses`/`usedBy` where
`com.atproto.server.defs#inviteCode` requires `available`, `uses`, `forAccount`, `createdBy`
(`:346-364`). The reference, rsky-pds, metalbear, tranquil-pds, and pegasus all route the three invite
endpoints; only atproto-crates puts two of them in the wrong namespace.

### 6. Account views and the account-mutation verbs

**CLASS: DIVERGENT (shapes) with real working logic underneath.**
`com.atproto.admin.defs#accountView` requires `did`, `handle`, and **`indexedAt`**;
`AccountInfoResponse` (`crates/atproto-pds/src/admin/handlers.rs:105-122`) and `SearchAccountItem`
(`:286-297`) emit `createdAt` plus a non-lexicon `state`, and `indexedAt` appears nowhere.
`searchAccounts` requires an undeclared `q` and never reads the declared `email` (`:275-283`), so
email lookup — the endpoint's purpose — is unavailable. `getAccountInfos` declares `dids: String`
and splits on commas (`:415-425`, `:449-454`) where the lexicon types it as an array; pegasus has the
identical bug (`api/admin/getAccountInfos.ml:5-9`), so this one is a shared blind spot.
`updateAccountEmail` reads `did` where the lexicon requires `account` (`:558-565`). `sendEmail` omits
the required `senderDid` and the optional `comment` while making the optional `subject` required
(`:494-504`), and returns `sent: true` when SMTP is disabled and the body was only logged
(documented `:509-513`).

Underneath the shape problems the logic is sound. `updateAccountHandle` (`:628-636`) reuses the same
PLC-signing path as the user-facing `identity.updateHandle`, and `updateAccountPassword`
(`:660-710`) correctly writes both `account.password_hash` and the `__primary__` app-password row so
the OAuth and `createSession` login paths stay in lockstep (`:692-710`) — a detail several
implementations get wrong. Routing `searchAccounts` at all puts atproto-crates ahead of the
reference, rsky-pds, metalbear, and pegasus, none of which route it (verified by grep over
`/tmp/gap-scratch/atproto/packages/pds/src` — zero hits). Only tranquil-pds also has it.
`com.atproto.admin.updateAccountSigningKey` is unrouted, but so it is everywhere else in the
comparison including the reference — a non-gap.

### 7. `deleteAccount` — no erasure

**CLASS: PARTIAL.** `admin.deleteAccount` (`crates/atproto-pds/src/admin/handlers.rs:253-270`) sets
state to `Deleted` and returns 200. Nothing removes the per-actor SQLite store, the blocks, or the
blobs — and the deferred deletion loop does the same thing
(`crates/atproto-pds/src/bin/pds.rs:829`, `set_state(&did, AccountState::Deleted)` with no purge).
Since `Deleted` fails `allows_public_read()`, `getRecord`/`listRecords` will refuse, but per finding 2
`getRepo` and `getBlob` will not, so a "deleted" account's entire repo and every blob remain publicly
downloadable. The reference explicitly orders unlink → sequence deletion → `ctx.actorStore.destroy(did)`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/admin/deleteAccount.ts:12-19`). This is a
data-protection issue as much as a moderation one.

### 8. Email / handle denylist

**CLASS: PARTIAL.** `crates/atproto-pds/src/denylist.rs` stores SHA-256-truncated-to-8-byte hashes of
handles and email addresses so the plaintext never lands in the DB — a genuinely good design that
only tranquil-pds's slur/word filter (`crates/tranquil-pds/src/moderation/mod.rs:1-14`, regexes
`:22-33`) comes close to in this field. But it is consulted at exactly two places, both inside
`createAccount` (`crates/atproto-pds/src/http/auth_handlers.rs:115-128` for handle, `:130-139` for
email) — a full-tree grep for `denylist::` finds no other production caller. `do_update_handle`
(`crates/atproto-pds/src/http/identity_handlers.rs:155-280`) does not consult it, so a user can
rename into a banned handle after signup, and `admin.updateAccountEmail` does not consult it either.

Worse for operations: there is **no way to populate the denylist over any interface**.
`denylist::add` is a library function; no XRPC route calls it, and the admin CLI has only
`version`, `invite list`, `account info|search|delete`, and `takedown apply|lift|status`
(`crates/atproto-pds/src/bin/atproto-pds-admin.rs:41-111`). Operators must write SQL by hand.
There is also no reserved-subdomain list — a grep for `reserved` across `auth_handlers.rs` and
`account/` finds only the `reserveSigningKey` row id — where the reference ships a compiled-in
`reservedSubdomains` table checked at `handle/index.ts:46` and a `hasExplicitSlur` filter applied in
both `account-manager.ts:27` and `repo/prepare.ts:27`. Neither of the reference's lists is
operator-editable either, so this is a design difference more than a ranking.

### 9. Spaces record takedown

**CLASS: PARTIAL.** The project-defined `com.atproto.admin.takedownSpaceRecord`
(`crates/atproto-pds/src/http/router.rs:403`, handler `admin/handlers.rs:745`) inserts or deletes a
row in `space_record_takedown` in the owner's per-actor store (`:768-817`), and `SpaceReader`
consults it on `get_record` and `list_records` (`crates/atproto-pds/src/space/reader.rs:89`, `:257`,
`:266`, `:288`), returning `404 RecordNotFound` so the takedown is indistinguishable from absence —
a good choice that avoids an existence oracle. No other implementation in this comparison has any
permissioned-data moderation surface whatsoever, because none of them implement permissioned data;
see [../permissioned/40-permissioned-overview.md](../permissioned/40-permissioned-overview.md).

The gate is read-only, though. A grep for `space_record_takedown` across `crates/atproto-pds/src` and
`crates/atproto-space/src` returns hits only in `admin/handlers.rs` and `space/reader.rs`: the space
writer never consults it, so the record's author can still update or delete a taken-down record; the
row stays in `space_record` and in the LtHash commitment; and `listRepoOps`
(`crates/atproto-pds/src/http/space_handlers.rs:1322`) still ships the op metadata
(collection/rkey/CID) for taken-down records to sync consumers. The admin endpoint itself has no
integration coverage — `grep -rn "takedownSpaceRecord" crates/atproto-pds/tests/` returns nothing,
while account-level takedown *is* covered (`crates/atproto-pds/tests/http_phase6_admin.rs`). The
read-side gate is unit-tested in-module (`takedown_hides_record_from_get_and_list`,
`crates/atproto-pds/src/space/reader.rs:629`), so what is untested is the write-and-apply path, not
the filter.

### 10. Admin authentication and the inert `revokeServiceAuth`

**CLASS: PARTIAL (both), security-relevant.** Every admin route is gated by `require_admin`
(`crates/atproto-pds/src/admin/handlers.rs:37-93`), HTTP Basic against a single shared password, with
three verified problems: a non-constant-time `!=` comparison (`:80`, repeated in
`admin/dashboard.rs:71`); the default password `"admin-default-CHANGE-ME"` (`:34`) live whenever
`PDS_ADMIN_PASSWORD` is unset and `PDS_PRODUCTION` is not `true` (`:90-95`, `config.rs:52-58`,
`bin/pds.rs:97`); and no rate limit on any admin route. The shared-secret model itself is the field
norm — zds uses a static `ZDS_ADMIN_TOKEN`, pegasus and metalbear use Basic — but the reference also
accepts a moderation-service JWT so actions are attributable to a person
(`auth-verifier.ts:137-149`), and metalbear, in C, compares in constant time (`server.c:262-292`).

Separately, `com.atproto.admin.revokeServiceAuth` (`:838-860`) writes a row via
`service_auth_blacklist::add` (`:855`) under a doc comment asserting that "Inbound service-auth
verifiers check `service_auth_blacklist::contains` before honoring a token" (`:838-840`). They do
not: a full-tree grep finds `contains` referenced only in
`crates/atproto-pds/tests/feature_postgres_live.rs:412,417,427,432`, and
`crate::space::service_auth::verify_service_auth` never calls it. Revoking a service-auth JTI has no
effect on any request. The NSID is project-defined so there is no comparison baseline, but an admin
endpoint whose documented security guarantee is unimplemented is worse than no endpoint.

---

## Findings

1. **Account takedown is enforced on the two record-level reads and nowhere else; bulk export is
   ungated.**
   CLASS: PARTIAL · severity: **rc-blocker (security)**.
   Evidence: `require_public_read` (`crates/atproto-pds/src/repo/reader.rs:510-518`, predicate
   `account/state.rs:56-58`) is called at `:107` (`getRecord`) and `:209` (`listRecords`) — both
   genuinely enforced, with a passing test at `repo/reader.rs:695-704`. `getRepo`
   (`http/handlers.rs:186-233`), `getBlocks` (`:245-296`), `getBlob` (`http/blob_handlers.rs:33-72`),
   `listBlobs` (`:96-123`), `getLatestCommit` (`repo/reader.rs:382-397`), and `describeRepo`
   (`:335-379`) contain no state check; the four files behind the sync/blob surface contain no
   `AccountState` reference of any kind.
   Comparison: reference `sync/util.ts:6-36` + ten call sites; zds `sync.zig:181,210,252,272`;
   tranquil `sync/util.rs:131-182`; rsky `sync/get_repo.rs:43`, `sync/get_blob.rs:33`.
   Consequence: two of roughly nine public read paths are gated, so a takedown removes record-level
   reads while a taken-down or deleted account's complete repo CAR, raw blocks and all of its blobs
   stay anonymously downloadable. A takedown for illegal content does not remove the content.

2. **Takedown does not block writes and does not invalidate live sessions.**
   CLASS: MISSING · severity: **rc-blocker (security)**.
   Evidence: `AccountState::allows_writes` (`crates/atproto-pds/src/account/state.rs:60-64`) has no
   production caller; `require_session` → `require_authn` (`http/write_handlers.rs:71-74`,
   `http/auth.rs:154-184`) never reads account state; `refresh_session`
   (`http/auth_handlers.rs:406-457`) loads the row at `:429-440` but does not check `account.state`,
   unlike `create_session` (`:319-328`); `oauth::handle_refresh` (`oauth/token.rs:188-234`) does not
   look the account up at all. Refresh TTL is 90 days (`account/session.rs:26`).
   Comparison: reference `AuthScope.Takendown`; rsky `auth_verifier.rs:994`; zds `repo.zig:587-594`
   at seven call sites; tranquil `Auth<NotTakendown>` (`repo/blob.rs:242`, `repo/import.rs:48`).
   Consequence: a taken-down account keeps writing records and publishing firehose commits until its
   refresh token expires.

3. **`updateSubjectStatus` / `getSubjectStatus` use a project-local shape; record- and blob-level
   takedown are unaddressable.**
   CLASS: DIVERGENT · severity: **rc-blocker (interop)**.
   Evidence: `crates/atproto-pds/src/admin/handlers.rs:156-162` (`{did, state}` input), `:204-218`
   (`{did, state}` output, `did` required, `uri`/`blob` ignored) vs
   `/tmp/gap-scratch/atproto/lexicons/com/atproto/admin/updateSubjectStatus.json` and
   `getSubjectStatus.json`.
   Comparison: reference, rsky (`update_subject_status.rs:28-59`), tranquil
   (`admin/status.rs:169-205,257-265,291-299`) all three subject kinds; zds parses the canonical union
   for the account case (`/tmp/gap-scratch/zds/src/atproto/server.zig:995-1050`).
   Consequence: Ozone and `pdsadmin` cannot drive this PDS's takedowns at all; no public-realm record
   or blob can be taken down by any means.

4. **`admin.revokeServiceAuth` writes a blacklist row that nothing reads.**
   CLASS: PARTIAL · severity: **rc-blocker (security)**.
   Evidence: `crates/atproto-pds/src/admin/handlers.rs:838-860`; `service_auth_blacklist::contains`
   has no production caller (grep hits only `tests/feature_postgres_live.rs:412,417,427,432`);
   `space/service_auth.rs` never consults it.
   Comparison: project-defined NSID, no baseline.
   Consequence: the documented revocation guarantee is false; a compromised service-auth token cannot
   be revoked.

5. **Admin Basic-auth: non-constant-time compare, live default password, no rate limit.**
   CLASS: PARTIAL · severity: **rc-blocker (security)**.
   Evidence: `crates/atproto-pds/src/admin/handlers.rs:80` and `admin/dashboard.rs:71` use `!=`;
   default `"admin-default-CHANGE-ME"` at `:34`, active unless `PDS_PRODUCTION=true`
   (`:90-95`, `config.rs:52-58`).
   Comparison: metalbear constant-time compares (`server.c:262-292`); reference also accepts a
   moderation-service JWT for attribution (`auth-verifier.ts:137-149`).
   Consequence: timing oracle against the one secret protecting every admin verb; unconfigured
   non-production deployments ship a known password.

6. **`disableAccountInvites` / `enableAccountInvites` are mounted under `com.atproto.server.*`.**
   CLASS: DIVERGENT · severity: stable-gap.
   Evidence: `crates/atproto-pds/src/http/router.rs:413,417`; handlers `admin/handlers.rs:877,889`;
   input field `did` vs lexicon-required `account` (`:866-871`).
   Comparison: reference `admin/index.ts:23-24`; rsky, metalbear, tranquil all correct.
   Consequence: 404 for canonical callers on a fully working feature; a one-line routing fix.

7. **`admin.deleteAccount` performs no data erasure.**
   CLASS: PARTIAL · severity: stable-gap (data-protection).
   Evidence: `crates/atproto-pds/src/admin/handlers.rs:253-270`; deletion loop
   `crates/atproto-pds/src/bin/pds.rs:829`.
   Comparison: reference destroys the actor store (`admin/deleteAccount.ts:12-19`).
   Consequence: combined with finding 1, a "deleted" account's repo and blobs remain publicly served.

8. **Four admin request/response shapes fail canonical clients outright.**
   CLASS: DIVERGENT · severity: stable-gap (each).
   (a) `accountView.indexedAt` absent from `getAccountInfo`, `getAccountInfos`, and `searchAccounts`
   — all three emit `createdAt` instead (`crates/atproto-pds/src/admin/handlers.rs:105-122`,
   `:286-297`), so a lexicon-validating client rejects every account response.
   (b) `sendEmail` omits the lexicon-required `senderDid` and makes the optional `subject` required
   (`:494-504`), so the moderator identity behind an email is never recorded.
   (c) `updateAccountEmail` reads `did` where the lexicon requires `account` (`:558-565`) — a hard
   deserialization failure.
   (d) `searchAccounts` requires an undeclared `q` and ignores the declared `email` (`:275-283`),
   removing email-based lookup, the endpoint's entire purpose. Only tranquil-pds also routes
   `searchAccounts` (`:103-114`); the reference does not route it at all.

9. **`admin.getInviteCodes` ignores `sort`/`limit`/`cursor`, is unpaginated, and returns a
   non-conforming item shape; `disableInviteCodes` ignores `accounts`.**
   CLASS: DIVERGENT · severity: stable-gap.
   Evidence: `crates/atproto-pds/src/admin/handlers.rs:337-343`, `:346-364`, `:1050-1068`.
   Consequence: unbounded response on a large deployment; per-account bulk code revocation absent.

10. **The denylist has no operator interface and is checked only at signup.**
    CLASS: PARTIAL · severity: stable-gap.
    Evidence: `denylist::contains` called only at `crates/atproto-pds/src/http/auth_handlers.rs:115`
    and `:130`; `do_update_handle` (`http/identity_handlers.rs:155-280`) does not consult it; no XRPC
    route or CLI subcommand calls `denylist::add`
    (`crates/atproto-pds/src/bin/atproto-pds-admin.rs:41-111`).
    Consequence: banning a handle or email requires hand-written SQL, and a banned handle can be
    adopted post-signup via `updateHandle`.

11. **Spaces record takedown is read-only, leaks through `listRepoOps`, and its admin path is
    untested.**
    CLASS: PARTIAL · severity: stable-gap.
    Evidence: outside its own in-module test (`space/reader.rs:629-687`), `space_record_takedown` is
    referenced only in `admin/handlers.rs:768-817` and `space/reader.rs:257,266,288`; no writer and
    no op-listing call site (`http/space_handlers.rs:1322`).
    Consequence: the author can still mutate a taken-down record, and its op metadata still syncs to
    space members.

12. **`createReport` forwards an unvalidated body.**
    CLASS: PARTIAL · severity: cosmetic.
    Evidence: `crates/atproto-pds/src/http/moderation_handlers.rs:47` takes raw `Bytes`; the
    lexicon-required `reasonType`/`subject` are never parsed. rsky validates `reasonType` before
    proxying (`apis/com/atproto/moderation/create_report.rs:8-42`). Low impact — the moderation
    service is the real validator.

13. **`getAccountInfos` parses the array param `dids` as a comma-joined string.**
    CLASS: DIVERGENT · severity: cosmetic.
    Evidence: `crates/atproto-pds/src/admin/handlers.rs:415-425`, `:449-454`. Pegasus has the
    identical bug (`api/admin/getAccountInfos.ml:5-9`), so `?dids=a&dids=b` returning one result is
    a shared blind spot rather than an outlier.

14. **`#account` events emit `"status": "active"`.**
    CLASS: DIVERGENT · severity: cosmetic.
    Evidence: `crates/atproto-pds/src/account/manager.rs:374-381`; the lexicon documents `status` as
    meaningful only when `active=false` and does not list `"active"` among its `knownValues`.

15. **`com.atproto.admin.updateAccountSigningKey` is unrouted.**
    CLASS: OUT-OF-SCOPE · severity: cosmetic.
    Justification: no implementation in this comparison routes it, including the reference
    (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/admin/index.ts:17-31`). Deferring it
    past stable is defensible.

**Tally: 5 rc-blockers, 6 stable-gaps (finding 8 bundles four separate shape defects), 4 cosmetic —
one of which is classified OUT-OF-SCOPE.**

---

## Where atproto-crates is ahead of the independent field

Three places, all real. It routes twelve canonical `com.atproto.admin.*` methods, which is more than
every independent implementation except tranquil-pds's fourteen, and more than cocoon (zero), arroba
(zero), dnproto (zero), alteran (501-by-policy), cirrus (zero), zds (one), and pegasus (seven). It is
the only implementation with a **hashed** identifier denylist — tranquil-pds's slur regex filter is
the nearest analogue and stores plaintext word lists. And `takedownSpaceRecord` gives it the only
moderation surface for permissioned data anywhere in the comparison, simply because no one else
implements permissioned data.

---

## Confidence & unknowns

Every atproto-crates claim above was verified by opening the cited file, not inferred from the
inventory. The three grep-based negative claims — `allows_writes` has no production caller,
`service_auth_blacklist::contains` has no production caller, and `denylist::add` has no route or CLI
caller — were each run over the full `crates/` tree and are as strong as a grep can be; a caller
reached through a macro or a dynamically constructed path would not show up, though none of these
crates use such patterns.

Comparison claims for the reference and zds were verified directly in source
(`sync/util.ts`, `admin/index.ts`, `admin/deleteAccount.ts`, `server.zig`, `sync.zig`, `repo.zig`).
Claims about tranquil-pds, rsky-pds, metalbear, pegasus, cocoon, cirrus, arroba, alteran, and dnproto
rest on the per-implementation notes, which are themselves source-cited; I spot-checked the reference
and zds rather than all eleven, so the line-level citations for the other nine carry the impl-note
authors' confidence rather than mine.

Two things are genuinely unknown. **UNVERIFIED:** whether a taken-down account in atproto-crates can
still complete an outbound migration — the reference deliberately preserves a constrained
`AuthScope.Takendown` for exactly that, and since atproto-crates does not restrict taken-down
sessions at all the question is moot today, but it will matter once finding 2 is fixed and the
carve-out has to be designed in. **UNVERIFIED:** whether the `space_record_takedown` gate holds for
the fjall storage backend — the storage inventory records that fjall has no
`space_record_takedown` keyspace at all, which would mean the gate silently does nothing there, but I
did not open the fjall backend to confirm how `SpaceReader` behaves when the table is absent.
