# Stratos — permissioned-data comparison target

Source read: `/tmp/gap-scratch/stratos` at commit `1a8f42c706ccf17ea52b4c42d6eeca5ee88f89e6`
(`main`, 2026-07-12, "Merge pull request #108 from NorthskySocial/fix/decouple-client-package").
The clone is shallow — `git log --oneline | wc -l` returns 1 — so commit history is not available as
a maturity signal. All file:line citations below are relative to that tree.

## What Stratos is

Stratos is Northsky Social's TypeScript "private, boundary-aware data layer for AT Protocol"
(`README.md:3-5`), which "keeps private records off the user's PDS, publishes enrollment metadata
back to the PDS for discovery, and lets downstream AppViews serve boundary-filtered content without
inventing a separate identity model." The pnpm workspace has six packages (`README.md:20-27`,
`AGENTS.md:25-33`): `stratos-core` (domain logic, MST commit builder), `stratos-service` (the
HTTP/XRPC service), `stratos-client`, `stratos-indexer` (a standalone Deno indexer that writes into
an AppView PostgreSQL), `stratos-feedgen`, and a Svelte demo `webapp` (`webapp/package.json:29-35`
lists `@sveltejs/vite-plugin-svelte`).

**Maturity — state this plainly.** This is experimental. The demo client is a Svelte app in the same
repo, `package.json:4` marks the root as `"private": true`, and the workspace packages carry
`"version": "0.1.0"` / `"0.0.1"`. Northsky's own "Beginning Phase 2" post is quoted as saying they
have "sent out ~1,050 invites and have ~280 users on our PDS so far" and lists Private Data as an
*upcoming* Phase-2 endeavour — so any claim that Stratos is "in production for those users" is
aspirational, not confirmed. UNVERIFIED: the ~20-star figure and the Phase-2 post text; both are
external to the clone and I did not fetch them.

**License — report honestly.** There is **no LICENSE file** in the repository. `find` for
`LICENSE*` / `COPYING*` outside `node_modules` returns nothing. The metadata that does exist
disagrees with itself: root `package.json:10` declares `"license": "MIT"`, `stratos-core/package.json:83`
and `stratos-service/package.json:96` declare MIT, `stratos-indexer/deno.json:4` declares
`"license": "MPL-2.0"`, and `stratos-client`, `stratos-feedgen` and `webapp` declare no license at
all. Treat the licensing as unresolved.

**Lexicon namespace — confirmed `zone.stratos.*`, not `app.stratos.*`.** `lexicons/` contains
exactly one tree, `lexicons/zone/stratos/`, with 19 JSON files: `defs.json`, `actor/enrollment.json`,
`boundary/defs.json`, `embed/images.json`, `enrollment/{status,unenroll}.json`,
`feed/{getTimeline,post}.json`, `feedgen/{describeFeed,getFeed}.json`,
`identity/resolveEnrollments.json`, `repo/{hydrateRecord,hydrateRecords,importRepo}.json`,
`server/listDomains.json`, and `sync/{getBlob,getRepo,subscribeRecords,uploadBlob}.json`. A
repository-wide grep for `app.stratos` returns nothing.

## Axis 1 — Space/grant modeling

There is no "space" object and no skey. The unit of access control is a **boundary**, defined in
`docs/guide/glossary.md:9` as "a service-qualified identifier in `{serviceDid}/{name}` format (e.g.
`did:web:stratos.example.com/engineering`)". That definition is load-bearing in code:
`stratos-core/src/validation/boundary-qualification.ts:30-32` builds the value by string
concatenation, `:54-58` detects a qualified value as one starting with `did:` and containing `/`,
and `:100-110` asserts a boundary's DID prefix equals the local service DID. The lexicon carries the
same contract — `lexicons/zone/stratos/boundary/defs.json` types `Domain.value` as a string with
`maxLength: 253` described as "Service-qualified boundary identifier in the format
`{serviceDid}/{domainName}`".

The root of trust is **the Stratos service instance**, not the user and not a separate authority
DID. The set of legal boundary names is operator configuration: `STRATOS_ALLOWED_DOMAINS`, described
in `README.md:110` as a "Comma-separated list of valid boundary values", is qualified with the
service DID at `stratos-service/src/config.ts:446-449`. A boundary is therefore not addressable
independently of the service that owns it; there is no equivalent of 0016's
`at://{spaceDid}/space/{spaceType}/{skey}/…` addressing. A user may hold many boundaries at once
(`lexicons/zone/stratos/actor/enrollment.json:18-25`, `maxLength: 50`) and may enroll with several
services, one enrollment record per service
(`lexicons/zone/stratos/actor/enrollment.json:6`, `docs/architecture/enrollment-signing.md:52`).

Correction to the working characterisation given to me: `STRATOS_ALLOWED_DOMAINS` is **not** a PDS
domain allowlist. It is the boundary-name vocabulary. PDS-domain scoping is a *separate* variable,
`STRATOS_ALLOWED_PDS_ENDPOINTS` (`README.md:129`, `stratos-service/src/config.ts:68`), consumed by
`isPdsAllowed` at `stratos-core/src/enrollment/domain.ts:51-66`.

The service also mints and **holds the user's repo signing key**. `docs/architecture/enrollment-signing.md:19-21`
states that enrollment generates "a per-user P-256 keypair — private key stored on the service", and
`stratos-service/src/context.ts:144-158` confirms it: `getActorSigningKey` loads or *creates* the
keypair server-side, and every write path calls it (`api/records/create.ts:98`, `update.ts:193`,
`delete.ts:56`, `batch.ts:164`) before `signCommit`
(`stratos-service/src/features/mst/internal/signer.ts:41-63`).

## Axis 2 — Membership management

Membership lives in the service's own enrollment store, keyed by DID, and is mutated by the
operator, not by users or by a group owner. At OAuth enrollment the service assigns boundaries from
config (`selectEnrollBoundaries` at `stratos-service/src/oauth/routes.ts:178-184`, applied in
`oauth/handlers/callback.ts:160-172`, defaulting to `cfg.stratos.allowedDomains` per
`stratos-service/src/index.ts:351`). Ongoing changes go through Express-mounted admin routes —
`/xrpc/zone.stratos.admin.setBoundaries` (`stratos-service/src/features/enrollment/handler.ts:435-480`)
and a matching remove-boundary route (`:398-427`) — both gated by the cookie-session admin verifier
(`stratos-service/src/infra/auth/verifiers.ts:379-419`) plus a `STRATOS_ADMIN_DIDS` allowlist. Note
that no `zone.stratos.admin.*` lexicon file exists; these are code-only endpoints.

There is no set hash, no LtHash, and no commit-level membership digest. Members learn of changes
because the service re-writes the user's PDS enrollment record with the new boundary list
(`oauth/handlers/callback.ts:183-196`, `features/enrollment/handler.ts` `updatePdsEnrollmentRecord`),
and because the enrollment event is republished on the sync stream
(`lexicons/zone/stratos/sync/subscribeRecords.json` `#enrollment`, emitted at
`stratos-service/src/subscription/subscribe-records.ts:246-252`).

A consequence worth naming: **a user's group memberships are public**. The PDS enrollment record
carries `boundaries` in cleartext (`lexicons/zone/stratos/actor/enrollment.json:18-25`, written at
`oauth/handlers/callback.ts:188`), so anyone reading the public repo — or the public firehose —
learns which boundaries a given DID belongs to. Separately,
`zone.stratos.enrollment.status` returns another user's boundaries to *any* authenticated caller,
not only to the subject (`features/enrollment/handler.ts:103-115`: the gate is
`if (authenticatedDid)`, and the DID compared is not the requested one).

## Axis 3 — Auth/authz enforcement points

Both write time and read time.

On write, `createRecord` requires DPoP OAuth (`stratos-service/src/api/handlers.ts:47-51` with
`authVerifier.standard`, implemented at `infra/auth/verifiers.ts:171-198`), requires an active
enrollment (`api/records/create.ts:80-87`), rejects service identities
(`:91-96`, `ServiceWriteForbidden`), restricts writes to the caller's own repo (`:236-238`), and
restricts collections to `zone.stratos.*` (`:242-248`). Boundary values are then validated against
the service vocabulary (`stratos-core/src/validation/stratos-validation.ts:312-340`) and against the
caller's *own* enrolled boundaries — a user cannot address a boundary they are not in
(`api/records/validation.ts:56-68`, error `ForbiddenBoundary`). Replies cannot escalate beyond the
parent's boundaries (`stratos-validation.ts:277-282`).

On read, `canAccessRecord` (`stratos-core/src/hydration/domain.ts:14-34`) grants access if the
viewer is the owner, denies unauthenticated viewers outright, and otherwise requires a non-empty
intersection between the record's boundaries and the viewer's. One default deserves attention:
`:28-30` grants access to a record with **no** boundaries to every enrolled user. Posts are required
to carry a boundary (`stratos-validation.ts:295-304`), so this is reachable only for collections
without a registered validator — the factory registers only post and enrollment validators
(`stratos-validation.ts:23-29`).

**404-not-403 discipline — partially true, and the doc overstates it.** `docs/operator/security.md:24`
and `docs/architecture/hydration.md:84-97` both claim access-denied is returned as 404 "to avoid
leaking record existence". Two of three read paths honour it. `com.atproto.repo.getRecord` throws the
*identical* `'Record not found', 'RecordNotFound'` error for a boundary miss
(`api/records/read.ts:63`) as for a genuinely absent record (`:43`, `:52`), so the two are
indistinguishable. `zone.stratos.sync.getRepo` likewise disguises a non-owner request as
`RepoNotFound` (`api/handlers/repo-read-handlers.ts:91-96`). But the hydration path deliberately
distinguishes them: `HydrationServiceImpl.hydrateRecord` returns `{status: 'blocked', reason:
'boundary'}` (`features/hydration/adapter.ts:177-179`), the handler converts that to a distinct
`RecordBlocked` error (`features/hydration/handler.ts:166-171`), and the lexicon enumerates both
`RecordNotFound` and `RecordBlocked` as separate errors
(`lexicons/zone/stratos/repo/hydrateRecord.json` `errors`). The batch form does the same, returning
separate `notFound` and `blocked` arrays (`adapter.ts:288-302`, `handler.ts:23-31`,
`lexicons/zone/stratos/repo/hydrateRecords.json`). A caller who can reach `hydrateRecord` can
therefore probe for the existence of records it may not read. So: the *idea* is documented and the
`getRecord`/`getRepo` paths implement it; the hydration API contradicts it.

UNVERIFIED: the actual HTTP status. All of these are `InvalidRequestError` from
`@atproto/xrpc-server`; `node_modules` is not present in the clone, so I could not confirm whether
that maps to 400 or 404 on the wire. The indistinguishability argument rests on the error *name*,
which is identical, not on the status code.

Viewer identity is taken strictly from the credential, as characterised. `features/hydration/handler.ts:67-73`
and `:97-103` both carry the comment "Viewer identity is derived strictly from the authenticated
credential; a client-supplied `did` cannot override it", and the code passes `did ?? null` from the
auth context into `getHydrationContext`, which resolves boundaries from that DID alone (`:145-155`).
The read handlers do the same (`api/handlers/repo-read-handlers.ts:20-26`, `:51-56`).

## Axis 4 — App-view access control

There is a trusted-consumer concept, but it is config-driven service *enrollment*, not an app
allowlist attached to a space. `ServiceEnrollment` entries
(`stratos-core/src/enrollment/service-enrollment.ts:12-24`) name a DID, a set of qualified
boundaries, and an optional `did:key`; they are loaded from `STRATOS_SERVICE_ENROLLMENTS` or
`STRATOS_SERVICE_ENROLLMENTS_FILE` (`stratos-service/src/config.ts:71-79`, `:407-442`), validated
against `allowedDomains`, and reconciled into the enrollment store at startup
(`features/enrollment/service-reconciler.ts:60`) with `isService = true`. Downstream services
authenticate with an inter-service auth JWT, not OAuth: `createSubscribeAuthVerifier`
(`infra/auth/verifiers.ts:433-459`) accepts only `Authorization: Bearer` service JWTs with
`lxm = zone.stratos.sync.subscribeRecords`, and the stream handler then refuses any caller with zero
boundaries and scopes the whole stream to the caller's boundary set
(`subscription/subscribe-records.ts:315-331`). Service identities are read-only by construction
(`api/records/create.ts:91-96`).

Docs and code disagree here. `docs/operator/security.md:88-92`, `docs/operator/deployment.md:78` and
`docs/operator/troubleshooting.md:17` all instruct operators to set `STRATOS_ALLOWED_APPVIEWS`. That
variable does not exist in the env schema (`stratos-service/src/config.ts:19-145`) and appears
nowhere in TypeScript. Trust the code: the mechanism is `STRATOS_SERVICE_ENROLLMENTS`.

## Axis 5 — Record read/write paths

Permissioned records live **off the PDS**, in Stratos's own per-actor MST repositories — as
characterised. `createRecord` encodes the record, computes its CID
(`api/records/create.ts:169-170`), and commits it into the actor's MST via the `@atcute/mst`-backed
builder (`stratos-core/src/mst/builder.ts:50-70`, commit `version: 3`, `:19`), signed with the
service-held per-actor key (`features/mst/internal/signer.ts:41-63`). Storage is one SQLite DB per
actor or one Postgres schema per actor (`README.md:157-162`, `AGENTS.md:256-261`), with tables
`stratos_repo_root`, `stratos_repo_block`, `stratos_record`, `stratos_blob`
(`stratos-core/src/db/schema/tables.ts:13-72`). Records are stored **in the clear** — a
repository-wide grep for `encrypt` across `docs/` and both `src/` trees returns zero hits. This is
trust-in-the-platform, not end-to-end encryption; the operator can read everything.

Only a stub goes to the PDS. `generateStub` (`stratos-core/src/stub/domain.ts:10-26`) emits
`{$type, source: {vary: 'authenticated', subject: {uri, cid}, service}, createdAt}` — no text, no
boundary. The shape is lexicon-defined at `lexicons/zone/stratos/defs.json` (`source` /
`subjectRef`, `service` typed `format: did` with an optional fragment). The write is fire-and-forget
onto a background queue (`api/records/create.ts:131-139`, `features/stub/internal/background-queue.ts`)
and lands on the PDS through the user's retained OAuth session
(`features/stub/adapter.ts:47-95`, calling `com.atproto.repo.createRecord` at `:84-90`). The
`source.subject.cid` is what lets an AppView detect tampering after hydration
(`docs/architecture/hydration.md:110-117`).

The characterisation "CID-verified stub" is accurate as to intent, with a caveat: the CID check is
described as something the *AppView* performs (`docs/architecture/hydration.md:112-117` shows client
code), and `hydrateRecord` accepts an optional `cid` param that it compares server-side
(`features/hydration/adapter.ts:157-160`). Nothing forces a consumer to check.

One documented endpoint is missing from the code. `zone.stratos.repo.importRepo` has a lexicon, an
enum entry (`api/handlers.ts:35`), and is documented in at least seven places (`AGENTS.md:318`,
`stratos-service/README.md:69`, `docs/client/api-reference.md:169`, `docs/operator/security.md:12`,
`docs/operator/architecture.md:42`, `docs/guide/concepts.md:83`,
`docs/client/repo-export-import.md:90-96`) — but `registerHandlers` (`api/handlers.ts:43-103`) never
registers it, and `IMPORT_REPO` appears nowhere else in `stratos-service/src`.

## Axis 6 — Sync / event behavior

Push streaming, not oplog pull, and no set-hash reconciliation. `zone.stratos.sync.subscribeRecords`
is a WebSocket subscription whose `#commit` messages carry `{seq, did, time, rev, ops}` with the
**full record inline** (`lexicons/zone/stratos/sync/subscribeRecords.json` `#recordOp.record`,
`type: unknown`). Cursors are integer sequence numbers, not TIDs, and resumption is
`cursor`-based with an `OutdatedCursor` info frame. Events are filtered per subscriber to the
boundaries that subscriber is enrolled in, with an optional single-`domain` narrowing
(`subscription/subscribe-records.ts:157-167`, `:315-331`). Full recovery is
`zone.stratos.sync.getRepo`, a CAR export restricted to the repo owner
(`api/handlers/repo-read-handlers.ts:83-96`).

Permissioned content stays off the public firehose in the sense that the *content* never reaches the
PDS. Metadata does not: the stub is an ordinary public PDS record, so its existence, timing,
collection, rkey, and the pointer to the Stratos service are all on the public firehose, and the
enrollment record publishes the author's boundary memberships (Axis 2). The
`stratos-indexer` is what closes the loop for AppViews — it reads the PDS firehose to discover
enrollments and subscribes per-actor to `subscribeRecords` (`README.md:164-176`,
`docs/guide/introduction.md:21-29`, `stratos-indexer/src/pds/pds-firehose.ts`,
`src/sync/stratos-sync.ts`), writing `stratos_record` (full record JSON), `stratos_record_boundary`,
`stratos_boundary`, `stratos_enrollment` and `stratos_sync_cursor` rows into the AppView Postgres
(`stratos-indexer/src/storage/schema.ts:6-56`). So the AppView database holds plaintext private
records plus the boundary rows needed to filter at query time — a second full-trust custodian.

## Axis 7 — Interop with the 0016 direction

None. A repository-wide grep for `com.atproto.space`, `simplespace`, `delegation`,
`spaceCredential`, `LtHash`/`ltHash`, and `setHash` across all `.ts`, `.json` and `.md` files
(excluding lockfiles and `node_modules`) returns **zero** matches. There is no delegation
token, no space credential, no `atproto-space-delegation+jwt` / `atproto-space-credential+jwt`, no
authority DID separate from the service DID, no `listRepoOps`, no `notifyWrite`/`registerNotify`, and
no per-space mint policy or app-access mode. The credential model is entirely different: DPoP OAuth
for users, `iss`/`aud` service-auth JWTs for services (`infra/auth/verifiers.ts:207-233`, `:433-459`),
and a service-signed enrollment attestation (secp256k1 over DAG-CBOR `{boundaries, did, signingKey}`,
`lexicons/zone/stratos/actor/enrollment.json:44-58`, `docs/architecture/enrollment-signing.md:26-36`)
as the public verifiability story. Stratos is an independent point in the design space and is
explicit about it.

## What atproto-crates could learn from Stratos

Two ideas are worth stealing, and one anti-pattern is worth naming.

**The read-leakage discipline, stated as a rule and mostly implemented.** `docs/operator/security.md:24`
writes the rule down — denied reads return the same answer as absent reads, so existence does not
leak — and `api/records/read.ts:63` and `api/handlers/repo-read-handlers.ts:91-96` implement it by
throwing the byte-identical error. That is a cheap, testable invariant that atproto-crates could
adopt across `com.atproto.space.getRecord` / `listRecords` / `getRepo`: an unauthorized read must be
indistinguishable from a missing record, including error name, error message, and timing class.
Stratos also shows the failure mode to guard against — a second API surface added later
(`hydrateRecord`) reintroduced a distinguishable `RecordBlocked` result and quietly broke the
invariant the docs still assert. If atproto-crates adopts the rule, it needs a test that enumerates
*every* read endpoint, not a convention.

**The boundary abstraction as a service-qualified string.** `{serviceDid}/{name}` is a single
opaque, comparable token that carries its own authority prefix. Access control reduces to set
intersection (`stratos-core/src/hydration/domain.ts:43-46`), cross-service confusion is a one-line
prefix assert (`validation/boundary-qualification.ts:100-110`), and the value round-trips through
lexicons, storage rows, and stream filters without a parser. 0016's space identity is richer
(authority DID + type NSID + skey) and that richness buys real things, but there is a lesson in
Stratos's collapse to a string: a permission label that is self-qualifying, comparable with `==`,
and safe to log is a good internal representation even when the wire format is structured. It is
also worth copying the write-side check that a user may only *address* boundaries they themselves
hold (`api/records/validation.ts:56-68`) — that closes an escalation path that pure read-time
filtering leaves open.

**The anti-pattern:** Stratos maintains two divergent copies of boundary validation —
`BaseValidator.validateBoundaryDomains` (`stratos-core/src/validation/base.ts:67-86`), which after
stripping the DID prefix compares a *bare* name against the configured (qualified) list, and
`StratosValidator.validateBoundaryDomains` (`validation/stratos-validation.ts:312-340`), which
accepts either form. Only the second is on the live write path (`api/records/validation.ts:91-93`);
`ValidatorFactory` is never constructed in `stratos-service`. The two would disagree on every
qualified boundary if the first were ever wired up — duplicated authorization logic where only one
copy is reachable is the shape of a future privilege bug.

## Why this is NOT an interop target for atproto-crates

Stratos shares no wire surface with 0016 and no trust model with atproto-crates' direction. Its
namespace is `zone.stratos.*`, its records live in a repo the PDS knows nothing about, its
credentials are DPoP OAuth plus ad-hoc service JWTs rather than the delegation-token →
space-credential exchange, its membership state is operator-managed rows in the service's own
database rather than a committed member list, and it has no notion of a space authority distinct
from the hosting service. More fundamentally, the Stratos service mints and holds each user's repo
signing key (`stratos-service/src/context.ts:144-158`,
`docs/architecture/enrollment-signing.md:19-21`) and stores every record in plaintext, and the
downstream AppView indexer replicates that plaintext into a second database
(`stratos-indexer/src/storage/schema.ts:22-27`). An implementation that follows 0016 — where writes
flow through the user's own PDS on the ordinary repo write path and the user's account key signs —
cannot meet Stratos halfway without abandoning that. Treat Stratos as a design-space reference for
*ideas* (the leakage rule, the boundary token, the stub/hydration split), not as a conformance
target or a protocol partner. HappyView remains the only same-direction interop yardstick.

## Confidence & unknowns

High confidence, read directly in source: the `zone.stratos.*` namespace and its 19 lexicon files;
off-PDS MST storage with a `source`-field stub on the PDS; the `{serviceDid}/{name}` boundary
format; read-time intersection filtering with viewer identity taken only from the credential;
enrollment modes `open`/`allowlist` with `STRATOS_ALLOWED_DIDS` and `STRATOS_ALLOWED_PDS_ENDPOINTS`;
plaintext storage with no encryption anywhere; service-held per-actor signing keys; zero overlap
with the `com.atproto.space` namespace; and the absence of a LICENSE file.

Corrections to the characterisations I was asked to check: (a) `STRATOS_ALLOWED_DOMAINS` is the
boundary-name vocabulary, not a PDS-domain scope — that is `STRATOS_ALLOWED_PDS_ENDPOINTS`;
(b) "unauthorized reads return 404" holds for `getRecord` and `getRepo` but is contradicted by
`hydrateRecord` / `hydrateRecords`, which return a distinct `RecordBlocked` / `blocked` result.

Unknowns. UNVERIFIED: the GitHub star count, and the exact text and date of Northsky's "Beginning
Phase 2" post — both outside the clone. UNVERIFIED: whether `InvalidRequestError` from
`@atproto/xrpc-server` yields HTTP 400 or 404, since `node_modules` is absent; I would need the
installed package's `errors` module or a live request to settle it. UNVERIFIED: whether the
documented-but-unregistered `importRepo` handler exists on a branch or was removed — the shallow
clone gives no history. UNVERIFIED: any deployment facts — instance count, user count, uptime —
nothing in the tree speaks to them. Not read in depth: `stratos-feedgen/`, the Postgres storage
adapters, the blob/bloom-filter path, and `test/` end-to-end scripts.
