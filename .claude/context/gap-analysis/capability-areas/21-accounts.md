# A. Account lifecycle

Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
and the [synthesis and roadmap](../50-synthesis-and-roadmap.md).

## Assessment

Account lifecycle is the part of a PDS that a client touches before it touches anything else. A
client discovers the server with `com.atproto.server.describeServer`, learns whether an invite code
is needed and which handle suffixes are on offer, creates an account, logs in, and from then on the
server has to keep a durable notion of *what state that account is in* — active, deactivated,
suspended, taken down, deleted — and broadcast changes to that state on the firehose as `#account`
events so relays and AppViews stop serving a repo the host has stopped serving. Migration rides on
the same surface: `reserveSigningKey`, a bring-your-own-DID `createAccount`, `importRepo`,
`checkAccountStatus` polled until the numbers line up, then `activateAccount` on the new host and
`deactivateAccount` on the old one.

atproto-crates has built most of the individual verbs and built several of them well. Twenty-two
`com.atproto.server.*` and account-adjacent routes are registered and backed by real handlers
(`crates/atproto-pds/src/http/router.rs:116-241`); app-password CRUD is complete against the lexicon;
the state machine models all five canonical states with an explicit legality table
(`crates/atproto-pds/src/account/state.rs:14-27`,
`crates/atproto-pds/src/account/manager.rs:1087-1108`); `#account` events fire on every transition
(`crates/atproto-pds/src/account/manager.rs:361-390`); and the `deleteAfter` hint on
`deactivateAccount` is honoured by a background reaper (`crates/atproto-pds/src/bin/pds.rs:716`,
`:796`) — something cocoon and pegasus both parse and discard. On the raw count of implemented
account verbs it sits comfortably in the middle of the serious field.

What it is missing is the load-bearing parts. **`com.atproto.server.describeServer` is not routed at
all.** Every one of the eleven comparison implementations routes it — the reference, all six other
serious PDSes, the single-user ones (cirrus at `index.ts:278`, dnproto at `src/pds/Pds.cs:190`), and
the hobby-experiment (alteran at `index.js:42`). This is the single clearest "even a hobby PDS does
this" gap in the whole area: it is the first request a normal signup or login flow makes, the data it
returns is already sitting in `HttpState`, and its absence is a 404 on request number one.
**Account state is enforced on public reads but not on writes** — `AccountState::allows_writes`
(`crates/atproto-pds/src/account/state.rs:62`) has zero production callers, so a taken-down,
suspended, or deactivated account can still create records, upload blobs, and apply writes. And
**`activateAccount` lets a taken-down account restore itself**: the handler calls
`set_state(sub, Active)` unconditionally (`crates/atproto-pds/src/http/auth_handlers.rs:684-687`) and
`valid_transition(Takendown, Active)` returns `true`
(`crates/atproto-pds/src/account/manager.rs:1102`), while nothing on the authenticated path ever
looks at account state. Moderation on this PDS is advisory.

The third theme is credential-shaped lexicon divergence. Three endpoints drop fields the lexicon
marks required, and in each case the dropped field is the second factor: `deleteAccount` requires
`did`, `password`, and `token` but models only `token`; `confirmEmail` requires `email` and `token`
but models only `token`; and the email-change completion step is a made-up NSID,
`com.atproto.server.confirmEmailUpdate`, while the canonical `com.atproto.server.updateEmail` is not
routed. cocoon, metalbear, and pegasus all verify password + emailed token on `deleteAccount`, so
this is not a "nobody does it" gap. Set against that, the account-state model itself is better than
most of the independent field — cocoon and metalbear have no takedown concept, pegasus has
`Takendown` as an enum variant with no writer, zds documents that `suspended` and `deleted` have no
operator workflow. atproto-crates models and transitions all five; it just does not act on them.

---

## Per-capability analysis

### Server discovery: `describeServer` — **MISSING**

The canonical lexicon (`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/describeServer.json`)
requires `did` and `availableUserDomains`, and optionally carries `inviteCodeRequired`,
`phoneVerificationRequired`, `links`, and `contact`. There is no `describeServer` literal anywhere in
`crates/atproto-pds/src/http/router.rs` (verified by grep over the whole router; the
`com.atproto.server.*` block runs `:116-241`). The data is already on `HttpState`: `service_did`,
`service_handle_domains` (read at `crates/atproto-pds/src/http/auth_handlers.rs:93-110`), and
`invite_required` (read at `:157`).

The reference handler is fifteen lines that read exactly those config values
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/describeServer.ts:8-27`). Every
comparison routes it: tranquil `crates/tranquil-api/src/lib.rs:33`, cocoon `server/server.go:517`,
rsky `apis/com/atproto/server/describe_server.rs:9`, metalbear `src/server.c:6643`, arroba
`xrpc_server.py:55`, pegasus `bin/main.ml:112-114`, zds `router.zig:155`, cirrus `index.ts:278`,
alteran `index.js:42`, dnproto `src/pds/Pds.cs:190`. Two return degraded values — dnproto hardcodes
`inviteCodeRequired`/`phoneVerificationRequired` true (`ComAtprotoServer_DescribeServer.cs:15-16`)
and pegasus hardcodes `did:web:{hostname}` (`api/server/describeServer.ml:5`) — but they answer.

### `createAccount`: happy path real, migration path unguarded — **PARTIAL / DIVERGENT**

The handler at `crates/atproto-pds/src/http/auth_handlers.rs:81` does real work: a rate-limit keyed
on handle (`:87`), enforcement of operator-pinned handle suffix domains (`:93-110`), a
privacy-preserving handle and email denylist (`:112-141`), a three-phase invite peek → create →
redeem with a documented TOCTOU note (`:140-242`), PLC genesis when no DID is supplied (`:186-202`),
and an implicit `__primary__` app-password row so `createSession` works immediately (`:244-264`).
That is more care than several of the comparisons take.

Three divergences from `createAccount.json`. The lexicon requires only `handle`, but
`CreateAccountInput` (`:28-41`) declares `password: String` non-optional, so a lexicon-valid
password-less request fails deserialization before the handler runs. `verificationCode`,
`verificationPhone`, `recoveryKey`, and `plcOp` are absent from the input struct entirely — a
`recoveryKey` from a migrating user is dropped rather than prepended to the genesis rotation keys the
way the reference does
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/createAccount.ts:288-291`). And
the output omits the optional `didDoc`.

The serious problem is the bring-your-own-DID branch. `create_account` takes `(State, Json<Input>)`
with no `Parts` extractor and no auth call at all (`:81-84`), and the BYO-DID path is
`if let Some(d) = input.did.clone() { (d, None, None) }` (`:184-185`) — the caller-supplied DID is
adopted verbatim, with no proof of control and no service-auth token, and the account is created
`Active` (the row insert binds `AccountState::Active` at
`crates/atproto-pds/src/account/manager.rs:158`; asserted by the round-trip test at `:1150`). The reference
rejects a mismatched requester outright and marks BYO-DID accounts `deactivated = true` so they
cannot serve until `activateAccount` runs (`createAccount.ts:251-259`); tranquil, cocoon, and zds all
require a service-auth token issued by the incoming DID
(`impl-notes/tranquil-pds.md:260`, `server/handle_server_create_account.go:81-95`,
`impl-notes/zds.md:259`). In fairness two serious implementations share the gap — metalbear adopts a
supplied DID with no check (`/tmp/gap-scratch/metalbear/src/server.c:3373-3382`) and pegasus is
flagged for the same by its own note (`impl-notes/pegasus.md:217`) — while rsky's check is written
`==` where the message implies `!=` (`impl-notes/rsky-pds.md:523`). Four of eleven get it right, and
atproto-crates is on the wrong side.

Not shipping `plcOp` is defensible: the reference reads it only in **entryway** mode
(`createAccount.ts:131-160`), rsky rejects it (`create_account.rs:257-261`), metalbear ignores it
(`impl-notes/metalbear.md:396`), and only zds implements a real `did` + `plcOp` branch
(`impl-notes/zds.md:388`).

### Account states and enforcement — **PARTIAL, with a security hole**

The model is good. `AccountState` covers `Active`, `Deactivated`, `Takendown`, `Suspended`, `Deleted`
(`crates/atproto-pds/src/account/state.rs:14-27`), `valid_transition` encodes a real FSM with
`Deleted` terminal (`crates/atproto-pds/src/account/manager.rs:1087-1108`), and `set_state` rejects
illegal transitions before writing (`:319-324`). Compare: cocoon has no takedown concept at all —
`models.Repo.Status()` returns only `nil` or `"deactivated"` (`models/models.go:58-64`); metalbear
records takedowns in a table nothing enforces (`impl-notes/metalbear.md:460-467`); pegasus has
`Takendown` as a status variant with no writer (`impl-notes/pegasus.md:114,156`); zds documents that
`suspended` and `deleted` have no operator workflow
(`/tmp/gap-scratch/zds/docs/account-takedown-runbook.md:44-53`). On modelling, atproto-crates is at
the top of the independent field.

Enforcement is where it breaks. Public repo reads are gated — `require_public_read` runs on the
record read paths (`crates/atproto-pds/src/repo/reader.rs:107`, `:209`, definition `:510`) and
`getRepoStatus.active` reflects `allows_public_read` (`:421`). Writes are not: `allows_writes`
(`crates/atproto-pds/src/account/state.rs:62`) is referenced only by its own unit test, and
`createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, and `uploadBlob` guard on
subject-equals-repo alone (`assert_subject`,
`crates/atproto-pds/src/http/write_handlers.rs:113-127`; call sites `:152`, `:205`, `:255`, `:343`).
The reference sets `checkDeactivated: true` and `checkTakedown: true` on those exact handlers
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/createRecord.ts:55-56`,
`applyWrites.ts:76-77`), zds routes every repo write through `requireActiveAccount`
(`/tmp/gap-scratch/zds/src/atproto/repo.zig:587-594`, seven call sites), rsky checks `takedownRef` in
the auth guard (`impl-notes/rsky-pds.md:465`), and tranquil gates `uploadBlob` and `importRepo`
behind an `Auth<NotTakendown>` extractor (`repo/blob.rs:242`, `repo/import.rs:48`).

`createSession` does check state — it rejects anything that is not `Active` or `Deactivated`
(`crates/atproto-pds/src/http/auth_handlers.rs:319-328`) — but `refreshSession` does not
(`:406-455`), so a 90-day refresh token issued before a takedown keeps minting fresh access tokens
afterwards, and `require_authn` / `require_access_jwt` never consult account state at all
(`crates/atproto-pds/src/http/auth.rs:154-198`, `auth_handlers.rs:1754-1760`).

### `#account` events — **PARTIAL / DIVERGENT (shared with the firehose area)**

`set_state` calls `emit_account_event`, which appends a payload of `{did, active, status}` to the
per-actor outbox (`crates/atproto-pds/src/account/manager.rs:361-390`). Emission on every transition
is correct and is more than pegasus (`takendown` never written) or metalbear (only `deactivated` and
`deleted` ever produced) manage.

Two divergences against `subscribeRepos.json`'s `#account` def, which requires `seq`, `did`, `time`,
`active` at the top level with an optional `status`. First, the CBOR frame encoder nests the whole
payload under a `payload` key and names the DID field `repo`, producing
`{seq, repo, time, payload: {did, active, status}}`
(`crates/atproto-pds/src/sequencer/frame.rs:116-121`) — no conformant subscriber finds `active` where
the lexicon says it is. That is a frame-level defect affecting every event type, so it belongs
primarily to the firehose chapter, but it lands here too. Second, the payload sets `status: "active"`
when the account is active (`manager.rs:375-381`), where the lexicon treats `status` as meaningful
only when `active=false`; cosmetic, since `knownValues` is open.

### `activate` / `deactivate` / `checkAccountStatus` / delete — **DIVERGENT**

`deactivateAccount` (`crates/atproto-pds/src/http/auth_handlers.rs:697`) matches the lexicon and
persists `deleteAfter` (`:708-721`) with a background reaper that walks expired rows hourly
(`crates/atproto-pds/src/bin/pds.rs:716`, `:796-808`). cocoon parses `deleteAfter` and explicitly
ignores it (`server/handle_server_deactivate_account.go:17-19`); pegasus has a TODO doing the same
(`api/server/deactivateAccount.ml:10`). atproto-crates is ahead here.

`activateAccount` (`:677`) is a bare `set_state(sub, Active)`. It performs none of the checks the
reference does — the reference calls `assertValidDidDocumentForService` before activating
(`impl-notes/bluesky-reference.md:377`), rsky asserts the DID document points at this PDS
(`apis/com/atproto/server/activate_account.rs:21`), and zds, cirrus, metalbear, dnproto, and cocoon
all emit the `#account` + `#identity` + `#sync` trio on activation while atproto-crates emits only
`#account`. Combined with the missing takedown gate, `activateAccount` is a self-service takedown
reversal.

`checkAccountStatus` (`:740`) reads real counts from the per-actor store (`:782-798`) — better than
cocoon (`Activated`/`ValidDid` hardcoded, `ImportedBlobs` always 0,
`server/handle_server_check_account_status.go:29-33`), dnproto (4 of 9 required fields,
`ComAtprotoServer_CheckAccountStatus.cs:30-31`) and alteran (wrong field names,
`impl-notes/alteran.md:92-96`). But `valid_did` is hardcoded `true` (`:820`) under a doc comment
claiming it means "the DID resolves to this PDS" (`:837`), and `repoCommit` / `repoRev` carry
`skip_serializing_if = "Option::is_none"` (`:841-845`) though the lexicon marks both required — so a
fresh empty account returns a body missing two required fields at exactly the moment a migration tool
polls it.

`requestAccountDelete` (`:1101`) issues a 32-byte token with a 1-hour TTL and mails it (`:1128-1157`).
`deleteAccount` (`:1173`) then accepts `{token}` only (`DeleteAccountInput`, `:1162-1166`) where the
lexicon requires `did`, `password`, and `token`, and takes no bearer auth. cocoon verifies all three
(`server/handle_server_delete_account.go:37-70`), metalbear requires password + emailed token
(`impl-notes/metalbear.md:116`, `:471`), pegasus requires password + a `del-` token
(`api/server/deleteAccount.ml:41-53`). Deletion here is also state-only — `set_state(Deleted)` with
no data erasure (`:1211-1214`), where cocoon deletes blocks, records, blobs, tokens, actor, and repo
in one transaction (`:87-137`).

### App passwords — **complete**

`createAppPassword` (`:509`), `listAppPasswords` (`:552`), and `revokeAppPassword` (`:583`) all match
their lexicons — `#appPassword` requires `name` + `password` + `createdAt` on create and `name` +
`createdAt` on list, and both are emitted with the optional `privileged` flag (`:494-507`,
`:531-542`), over Argon2id hashes with per-row salts
(`crates/atproto-pds/src/account/manager.rs:1063-1085`). Hiding the implicit `__primary__` row from
the list (`:565`) is a sensible call.

This is a capability where atproto-crates is **ahead of much of the independent field**: cocoon has
declared it will never add app passwords (`README.md:253`, `:261`), pegasus routes none of the three
(`impl-notes/pegasus.md:56`), arroba stubs `listAppPasswords` to a hardcoded empty array
(`xrpc_server.py:75`), and dnproto serves none. The one caveat is behavioural rather than lexical:
`app_password::verify` runs a full Argon2 verification against every row for the DID until one
matches (`crates/atproto-pds/src/account/app_password.rs:383-394`), so `createSession` cost grows
linearly in the number of app passwords a user holds.

### Email and password update flows — **DIVERGENT**

`requestEmailUpdate` (`:964`) returns `tokenRequired` as specified, though the lexicon defines **no
input** and the handler requires `{email}` (`:930-935`). The completion step is routed as
`com.atproto.server.confirmEmailUpdate` (`crates/atproto-pds/src/http/router.rs:176-179`), which is
**not a lexicon** — no such file exists under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/`. The canonical completion method,
`com.atproto.server.updateEmail`, is not routed, though the reference, tranquil, cocoon, rsky,
metalbear, pegasus, zds, and cirrus all serve it; a stock client changing its email gets a 404.

`confirmEmail` (`:1317`) accepts `{token}` only (`ConfirmEmailInput`, `:1306-1309`) where the lexicon
requires `email` **and** `token`, so the address being confirmed is never cross-checked against the
token's account. `requestPasswordReset` (`:1390`, correctly unauthenticated and rate-limited at
`:1402-1405`) and `resetPassword` (`:1477`) are both conformant, and `resetPassword` updates both
`account.password_hash` and the `__primary__` app-password row (`:1526-1532`) — worth noting because
cocoon's `resetPassword` sits behind session middleware and is therefore unusable by the very users
it exists for (`server/handle_server_reset_password.go:22`, `impl-notes/cocoon.md:304`).

### Invite codes — **DIVERGENT**

`createInviteCode` (`:629`) is gated by `require_access_jwt` — an ordinary account session — plus a
`can_issue_invites` column check (`:639-664`). That column defaults to true
(`crates/atproto-pds/migrations/accounts/20260506000002_invite_toggle.sql:9`,
`crates/atproto-pds/migrations/postgres/20260507000001_init.sql:36`), and no cap is applied to
`useCount`. On a deployment running `PDS_INVITE_REQUIRED=true`, the first account through the door
can mint unlimited codes with unlimited uses and the gate is over. The reference requires
`ctx.authVerifier.adminToken`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/createInviteCode.ts:20`); so do
cocoon (`server/server.go:591`), metalbear (`src/server.c:244-245`), zds (`impl-notes/zds.md:103`),
and pegasus (`bin/main.ml:140-142`). The reference's user-facing path is instead
`getAccountInviteCodes` with `createAvailable=true`, which mints *earned* codes under server policy;
atproto-crates routes `getAccountInviteCodes` (`:1570`) but ignores both `includeUsed` and
`createAvailable` and has no earning policy at all.

`getAccountInviteCodes` also emits the wrong shape. `com.atproto.server.defs#inviteCode` requires
`code`, `available`, `disabled`, `forAccount`, `createdBy`, `createdAt`, `uses`; the handler emits
`{code, disabled, availableUses, usedBy, createdAt}` (`:1540-1556`) — three required fields absent and
two renamed. `com.atproto.server.createInviteCodes` (the batch form) is not routed; the reference,
tranquil, cocoon, rsky, metalbear, pegasus, and zds all route it.

### `com.atproto.admin.getAccountInfo` — **DIVERGENT (cosmetic)**

Routed and real (`crates/atproto-pds/src/admin/handlers.rs:125`), accepting a handle as well as a DID
(`:132-136`), a benign superset. The output must be `com.atproto.admin.defs#accountView`, which
requires `did`, `handle`, and `indexedAt`; `AccountInfoResponse` (`:105-122`) emits `createdAt`
instead. The same substitution affects `getAccountInfos` (`:443`) and `searchAccounts` (`:310`).

---

## Routing summary

| NSID | atproto-crates | Note |
|---|---|---|
| `server.describeServer` | **not routed** | all eleven comparisons route it |
| `server.createAccount` | `router.rs:117` | BYO-DID unauthenticated; `password` wrongly required |
| `server.createInviteCode` | `router.rs:149` | user-session gated, not admin |
| `server.createInviteCodes` | **not routed** | 7 of 11 comparisons route it |
| `server.getAccountInviteCodes` | `router.rs:189` | output is not `defs#inviteCode` |
| `server.activateAccount` | `router.rs:157` | no DID-doc check; allows takendown→active |
| `server.deactivateAccount` | `router.rs:161` | `deleteAfter` honoured by a real reaper |
| `server.checkAccountStatus` | `router.rs:165` | `validDid` hardcoded; two required fields skippable |
| `server.deleteAccount` / `requestAccountDelete` | `router.rs:185`, `:181` | request conformant; delete drops `did` + `password` |
| `server.createAppPassword` / `listAppPasswords` / `revokeAppPassword` | `router.rs:137,141,145` | conformant |
| `server.requestEmailUpdate` / `confirmEmailUpdate` | `router.rs:173`, `:177` | lexicon defines no input; `confirmEmailUpdate` is an **invented NSID** |
| `server.updateEmail` | **not routed** | canonical email-change completion method |
| `server.confirmEmail` | `router.rs:228` | required `email` not modelled |
| `server.requestPasswordReset` / `resetPassword` | `router.rs:233,237` | conformant |
| `admin.getAccountInfo` | `router.rs:359` | `indexedAt` missing |

---

## Findings

**1. `com.atproto.server.describeServer` is not routed.** CLASS: MISSING · SEVERITY: **rc-blocker**.
Evidence: no `describeServer` literal in `crates/atproto-pds/src/http/router.rs`; the data already lives on `HttpState` (`crates/atproto-pds/src/http/auth_handlers.rs:93-110`, `:157`).
Comparison: routed by all eleven, including cirrus (`index.ts:278`), dnproto (`src/pds/Pds.cs:190`) and alteran (`index.js:42`).
Consequence: 404 on the first request of every standard signup and login flow; clients cannot discover `availableUserDomains` or `inviteCodeRequired`.

**2. Account state is never enforced on the write path.** CLASS: MISSING · SEVERITY: **rc-blocker (security)**.
Evidence: `AccountState::allows_writes` (`crates/atproto-pds/src/account/state.rs:62`) has no production caller; repo writes guard only `assert_subject` (`crates/atproto-pds/src/http/write_handlers.rs:113-127`, called at `:152`, `:205`, `:255`, `:343`).
Comparison: reference `createRecord.ts:55-56` / `applyWrites.ts:76-77`; zds `repo.zig:587-594`; rsky `impl-notes/rsky-pds.md:465`; tranquil `repo/blob.rs:242`.
Consequence: a taken-down or suspended account keeps writing records and uploading blobs and the firehose keeps carrying its commits. Moderation actions do not take effect.

**3. `activateAccount` lets a taken-down account restore itself.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (security)**.
Evidence: unconditional `set_state(sub, Active)` (`crates/atproto-pds/src/http/auth_handlers.rs:677-687`); `valid_transition(Takendown, Active)` is `true` (`crates/atproto-pds/src/account/manager.rs:1102`); no auth guard checks state (`crates/atproto-pds/src/http/auth.rs:154-198`).
Comparison: reference gates activate behind a verifier that rejects taken-down subjects (`/tmp/gap-scratch/atproto/packages/pds/src/auth-verifier.ts:628-634`) and asserts the DID document first (`impl-notes/bluesky-reference.md:377`).
Consequence: an admin takedown is reversible by the user with a single call.

**4. `createAccount` adopts a caller-supplied `did` with no proof of control.** CLASS: MISSING · SEVERITY: **rc-blocker (security)**.
Evidence: handler takes no `Parts` and no auth (`crates/atproto-pds/src/http/auth_handlers.rs:81-84`); BYO-DID branch at `:184-185`; account created `Active` (`crates/atproto-pds/src/account/manager.rs:158`).
Comparison: reference `createAccount.ts:251-259`; tranquil `impl-notes/tranquil-pds.md:260`; cocoon `server/handle_server_create_account.go:81-95`; zds `impl-notes/zds.md:259`. Shared gap with metalbear (`src/server.c:3373-3382`) and pegasus (`impl-notes/pegasus.md:217`).
Consequence: anyone can squat an arbitrary DID, which the PDS will then serve `describeRepo`, `getRepo`, and firehose events for.

**5. `com.atproto.server.updateEmail` is not routed; the completion step uses an invented NSID.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (interop)**.
Evidence: `confirmEmailUpdate` routed at `crates/atproto-pds/src/http/router.rs:176-179`, handler `auth_handlers.rs:1032`; no `confirmEmailUpdate.json` under `/tmp/gap-scratch/atproto/lexicons/com/atproto/server/`; `updateEmail` absent from the router.
Comparison: routed by reference, tranquil, cocoon, rsky, metalbear, pegasus, zds, cirrus.
Consequence: no standard client can change its email address on this PDS.

**6. `deleteAccount` drops the lexicon-required `did` and `password`.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (security)**.
Evidence: `DeleteAccountInput` has only `token` (`crates/atproto-pds/src/http/auth_handlers.rs:1162-1166`); no bearer auth on the route.
Comparison: cocoon `server/handle_server_delete_account.go:37-70`; metalbear `impl-notes/metalbear.md:116`; pegasus `api/server/deleteAccount.ml:41-53`.
Consequence: deletion is single-factor on a 43-character emailed token, with no password re-confirmation and no binding to the DID being deleted.

**7. `checkAccountStatus.validDid` is hardcoded and two required fields are skippable.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (migration correctness)**.
Evidence: `valid_did: true` at `crates/atproto-pds/src/http/auth_handlers.rs:820`, doc comment `:837`; `repoCommit`/`repoRev` carry `skip_serializing_if` at `:841-845` though `checkAccountStatus.json` marks both required.
Comparison: rsky computes it (`impl-notes/rsky-pds.md:385`); the reference derives it from `assertValidDidDocumentForService`. cocoon hardcodes it too (`handle_server_check_account_status.go:29-33`), so this is not universal.
Consequence: a migration tool polls past a DID document that does not yet point at this PDS, and a new empty account returns a lexicon-invalid body.

**8. `createInviteCode` is gated by an ordinary user session, and issuance defaults to enabled.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (invite-gated deployments)**.
Evidence: `require_access_jwt` at `crates/atproto-pds/src/http/auth_handlers.rs:634`; `can_issue_invites` defaults true (`crates/atproto-pds/migrations/accounts/20260506000002_invite_toggle.sql:9`); no `useCount` cap.
Comparison: reference `createInviteCode.ts:20` (adminToken); cocoon `server/server.go:591`; metalbear `src/server.c:244-245`; zds `impl-notes/zds.md:103`; pegasus `bin/main.ml:140-142`.
Consequence: the first account on an invite-required PDS can mint unlimited codes, so the invite gate stops constraining signups after one account.

**9. `#account` frame body is nested under `payload` and keys the subject as `repo`.** CLASS: DIVERGENT · SEVERITY: **rc-blocker (shared with the firehose area)**.
Evidence: `crates/atproto-pds/src/sequencer/frame.rs:116-121` emits `{seq, repo, time, payload:{...}}`; `subscribeRepos.json`'s `#account` requires `seq`, `did`, `time`, `active` at the top level.
Comparison: every comparison that emits `#account` emits the flat shape (tranquil `sync/frame.rs:9-21`, cocoon `handle_sync_subscribe_repos.go:18-33`, rsky `sequencer/events.rs:314`).
Consequence: relays cannot read `active` or `status` from an atproto-crates `#account` event.

**10. `confirmEmail` drops the lexicon-required `email`.** CLASS: DIVERGENT · SEVERITY: stable-gap.
Evidence: `ConfirmEmailInput` has only `token` (`crates/atproto-pds/src/http/auth_handlers.rs:1306-1309`); `confirmEmail.json` requires `email` and `token`.
Comparison: cocoon, metalbear, rsky, zds, pegasus all route a conformant `confirmEmail`.
Consequence: a conformant client's request still works (extras are ignored), but the confirmed address is never cross-checked against the token's account.

**11. `refreshSession` performs no account-state check.** CLASS: MISSING · SEVERITY: stable-gap (security).
Evidence: `crates/atproto-pds/src/http/auth_handlers.rs:406-455` looks the account up only for `handle`/`did`; `createSession` does check (`:319-328`).
Comparison: the reference's `refreshSession` handler loads the account with `includeTakenDown: true` and rejects a soft-deleted one before rotating the token (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/refreshSession.ts:21-35`). (Its `authVerifier.refresh()` does *not* itself call `verifyStatus` — the check lives in the handler.)
Consequence: a 90-day refresh token issued before a takedown keeps minting access tokens for 90 days after it.

**12. `getAccountInviteCodes` output is not `com.atproto.server.defs#inviteCode`.** CLASS: DIVERGENT · SEVERITY: stable-gap.
Evidence: handler emits `{code, disabled, availableUses, usedBy, createdAt}` (`crates/atproto-pds/src/http/auth_handlers.rs:1540-1556`); the def requires `available`, `forAccount`, `createdBy`, `uses`. Params `includeUsed` / `createAvailable` are not modelled.
Comparison: reference, tranquil, rsky, metalbear, zds all serve the canonical shape.
Consequence: invite-management UIs render nothing usable.

**13. `com.atproto.server.createInviteCodes` is not routed.** CLASS: MISSING · SEVERITY: stable-gap.
Evidence: absent from `crates/atproto-pds/src/http/router.rs`.
Comparison: routed by reference, tranquil, cocoon, rsky, metalbear, pegasus, zds.
Consequence: bulk invite issuance requires N round-trips or direct SQL.

**14. `createAccount` requires `password` and ignores `recoveryKey` / `verificationCode` / `plcOp`.** CLASS: DIVERGENT · SEVERITY: stable-gap.
Evidence: `CreateAccountInput` (`crates/atproto-pds/src/http/auth_handlers.rs:28-41`); `createAccount.json` requires only `handle`.
Comparison: reference honours `recoveryKey` (`createAccount.ts:288-291`); metalbear also requires email and password (`impl-notes/metalbear.md:544`) and ignores `recoveryKey`, so the required-password half is a shared deviation. `plcOp` is reference-entryway-only plus zds.
Consequence: a migrating user cannot supply their own recovery rotation key, and password-less (OAuth-only) signup is impossible.

**15. `getSession` / `createSession` omit the optional status fields.** CLASS: PARTIAL · SEVERITY: stable-gap.
Evidence: `GetSessionResponse` emits `handle`, `did`, `email` only (`crates/atproto-pds/src/http/auth_handlers.rs:366-374`); `SessionResponse` emits the four required fields (`:44-56`). `active`, `status`, `emailConfirmed`, `didDoc` are never sent.
Comparison: reference sends all of them; cirrus and alteran do too.
Consequence: clients cannot distinguish a deactivated account from an active one at login, and cannot cache the DID document.

**16. `admin.getAccountInfo` returns `createdAt` where `accountView` requires `indexedAt`.** CLASS: DIVERGENT · SEVERITY: cosmetic.
Evidence: `AccountInfoResponse` (`crates/atproto-pds/src/admin/handlers.rs:105-122`); same in `getAccountInfos` (`:443`) and `searchAccounts` (`:310`).
Comparison: rsky (`apis/com/atproto/admin/get_account_info.rs:77`), tranquil, and metalbear all serve `accountView`.
Consequence: ozone-style tooling sees a missing required field; low practical impact until an admin UI is pointed at it.

**17. `reserveSigningKey` is unauthenticated.** CLASS: DIVERGENT · SEVERITY: stable-gap.
Evidence: `crates/atproto-pds/src/http/auth_handlers.rs:891-894` — no `Parts`, no guard; persists a reservation row keyed on a caller-supplied `did` (`:916-924`).
Comparison: cocoon's is also unauthenticated (`server/server.go:518`), so this is a shared posture rather than an outlier; the reference gates it behind an access verifier.
Consequence: unauthenticated key generation and reservation-row growth — a DID-squatting precursor to finding 4 rather than an independent break.

**Not counted against the RC.** Phone verification (`verificationPhone`, `describeServer.phoneVerificationRequired`) and email second-factor auth (`createSession.authFactorToken`, `updateEmail.emailAuthFactor`) are implemented only by the reference across the entire field. Treating them as **OUT-OF-SCOPE** for RC → stable is defensible; list them as known limitations rather than gaps.

---


## Confidence & unknowns

Every atproto-crates claim above was read in source at the cited line during this pass, and the
routing table was cross-checked against `crates/atproto-pds/src/http/router.rs` directly rather than
taken from the inventory. Every lexicon assertion follows from opening the canonical JSON under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/{server,admin}/`. Reference-side citations for
`createAccount`, `createInviteCode`, `describeServer`, `activateAccount`, `deactivateAccount`,
`auth-verifier.ts`, `createRecord.ts`, and `applyWrites.ts` were opened directly, as was metalbear's
BYO-DID branch at `src/server.c:3373-3382`. Remaining comparison cells rest on the per-implementation
notes, which are themselves source-cited.

- **UNVERIFIED**: whether findings 2, 3, and 4 reproduce end-to-end against a running instance —
  confirming them needs a live PDS, an admin takedown, and a subsequent write.
- **UNVERIFIED**: whether any real relay tolerates the `payload`-nested `#account` frame (finding 9).
- **UNVERIFIED**: `emit_account_event` opens a per-actor store
  (`crates/atproto-pds/src/account/manager.rs:370`); whether a takedown of an account whose actor
  store was never created (BYO-DID with no `importRepo`) silently drops the event was not traced.
- **UNVERIFIED**: comparison support for `recoveryKey` beyond the reference and metalbear, which is
  why that capability is deliberately not a matrix row. Several matrix cells for `deleteAfter`,
  `confirmEmail` field validation, and `deleteAccount` purge extent are marked `?` for the same
  reason.
- The spaces/permissioned-data account surface is out of scope here; see
  [the permissioned-data overview](../permissioned/40-permissioned-overview.md).

Per-implementation detail: [bluesky-reference](../impl-notes/bluesky-reference.md) ·
[tranquil-pds](../impl-notes/tranquil-pds.md) · [cocoon](../impl-notes/cocoon.md) ·
[rsky-pds](../impl-notes/rsky-pds.md) · [metalbear](../impl-notes/metalbear.md) ·
[cirrus](../impl-notes/cirrus.md) · [arroba](../impl-notes/arroba.md) ·
[pegasus](../impl-notes/pegasus.md) · [alteran](../impl-notes/alteran.md) ·
[zds](../impl-notes/zds.md) · [dnproto](../impl-notes/dnproto.md)
