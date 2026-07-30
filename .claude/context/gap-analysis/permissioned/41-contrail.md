# contrail — permissioned-data comparison target

Source read: `/tmp/gap-scratch/contrail`, git HEAD `fa3d4cd` ("Merge pull request #62 from
flo-bit/changeset-release/main", 2026-06-17). All `packages/…` and `docs/…` paths below are
relative to that checkout unless prefixed with `crates/`, which means this repository.

## What contrail is

Contrail is a TypeScript library for building AT Protocol appviews — it calls itself "a library
for easily creating (serverless) atproto backends/appviews" (`README.md:5`) and labels itself
"**pre-alpha.** Expect breaking changes" (`README.md:3`, echoed at `development.md:3`). It is MIT
licensed to a single author (`LICENSE:1`, "MIT License Copyright (c) 2026 flo-bit"). The published
packages sit at version `0.12.2` (`packages/contrail/package.json:3`).

The default deployment target is Cloudflare Workers with a D1 database, with adapters for
`node:sqlite` and PostgreSQL (`README.md:7-8`; `packages/contrail-base/src/adapters/sqlite.ts`,
`.../postgres.ts`). Routing is Hono; identity, CBOR, CID, Jetstream, and service-auth verification
all come from the `@atcute/*` family. The monorepo is pnpm + turbo, released through changesets,
with build/test/typecheck CI on every PR (`.github/workflows/ci.yml`).

Six library packages matter here. `@atmo-dev/contrail-base` holds the shared spaces primitives —
URI parsing, ACL, credentials, binding resolution, membership manifests
(`packages/contrail-base/src/index.ts:23-50`). `@atmo-dev/contrail-appview` is the public-record
side (Jetstream ingestion, backfill, query layer); `@atmo-dev/contrail-authority` implements the
"space authority" role (member list, credential signing); `@atmo-dev/contrail-record-host` the
"record host" role (record and blob storage, enrollment); `@atmo-dev/contrail-community` layers
group-controlled DIDs and an access-level ladder on top; `@atmo-dev/contrail` is the umbrella.
`packages/contrail/src/core/spaces/*` still contains a near-identical copy of the base spaces
sources; the split packages are the live path.

Test coverage is substantial for a pre-alpha: 87 `*.test.ts` files, 53 of them in
`packages/contrail/tests` (including `spaces-acl`, `spaces-credentials`, `spaces-binding`,
`spaces-enrollment`, `spaces-blobs`, `spaces-e2e`, `spaces-manifest`) and 20 in
`packages/contrail-community/tests`.

**Does it use any `com.atproto.space.*` NSID? No — definitively zero.** An exhaustive grep across
the whole checkout for `atproto.space`, `atproto.simplespace`, `getDelegationToken`,
`space-delegation`, `space-credential`, `listRepoOps`, `notifyWrite`, and `registerNotify` returns
three hits, all of which are an unrelated Hono helper named `registerNotifyRoute`
(`packages/contrail-appview/src/core/router/index.ts:8,188`;
`packages/contrail-appview/src/core/router/notify.ts:160`). Greps for `0016`, `LtHash`, `setHash`,
and `oplog` return nothing at all. Contrail emits its space endpoints under the deployment's own
namespace — ``const SPACE = `${config.namespace}.space` `` (`packages/contrail-record-host/src/routes.ts:49`,
`packages/contrail-authority/src/routes.ts:48`) — and ships lexicon templates under
`tools.atmo.space.*` (`packages/lexicons/lexicon-templates/spaces/*.json`). What contrail actually
tracks is Daniel Holmgren's earlier leaflet post: `docs/06-spaces.md:153` ("The design follows
Daniel Holmgren's permissioned data rough spec", linking `dholms.leaflet.pub/3mhj6bcqats2o`),
restated at `packages/contrail-base/src/spaces/uri.ts:5-6` and
`refs/spaces-spec-mapping.md:3-5` ("March 2026"). Proposal 0016 itself is never mentioned.

The single most important architectural fact: **permissioned records are stored in the appview's
own SQL database and never touch anyone's PDS.** `refs/spaces-spec-mapping.md:11-14` states it
plainly ("For permissioned data it currently stores everything in its own database"), and
`docs/06-spaces.md:150` repeats it. The code agrees — see axis 5.

## The seven axes

| Axis | contrail's answer |
|---|---|
| 1 Space modeling | `ats://<ownerDid>/<type>/<key>`; owner is a user or community DID; skey = TID |
| 2 Membership | `spaces_members` table on the authority; owner-only mutation; binary; no hash |
| 3 Auth enforcement | Both read and write; ES256 space credential, service-auth JWT, or invite token |
| 4 App-view control | `appPolicy {mode, apps[]}` at issuance; enrollment is the host's consent gate |
| 5 Record paths | Appview SQL tables, one per collection; no MST, no commit, no CID |
| 6 Sync | SSE catch-up-then-live over a `time_us` cursor; permissioned writes never see a firehose |
| 7 0016 interop | Namespaced `<ns>.space.*`; no `com.atproto.space.*`; tracks the older leaflet sketch |

### 1. Space and grant modeling

A space is the triple `(ownerDid, type, key)`, serialized as
`ats://<ownerDid>/<type>/<key>` (`packages/contrail-base/src/spaces/uri.ts:20-22`). The scheme
choice is deliberate: the module docstring says `ats://` is "distinct from atproto record URIs
(`at://`) so the two can't be confused at any layer (logs, params, dispatch)"
(`uri.ts:3-6`). Parsing rejects any extra path segments (`uri.ts:28-29`). This is the same wire
form this repository settled on (`crates/atproto-space/src/types.rs:13,89`), which is a notable
convergence given neither cites the other — though both diverge from the 0016 draft lexicons,
which declare space references as `"format": "at-uri"` (`/tmp/gap-scratch/lex-0016/space/getSpace.json`,
`.../getDelegationToken.json`).

There is a real skey concept: `spaces.key` is caller-supplied or TID-minted —
`const key = body.key ?? nextTid()` (`packages/contrail-authority/src/routes.ts:141`). Multiple
spaces per owner are supported and uniqueness is enforced by URI (`routes.ts:144-145` returns 409
`AlreadyExists`). The root of trust is the service-auth JWT issuer: `createSpace` takes the owner
DID straight from `sa.issuer` and adds that DID as the first member (`routes.ts:142,149,156`).
Nothing verifies that the caller *should* be able to create a space — anyone with a valid
service-auth JWT can, which is the intended design.

Contrail deliberately declines to mint a canonical URI for a record inside a space, because the
spec "is explicitly undecided about authority (user vs space owner), so we don't expose those as a
canonical record address — they're storage-internal" (`uri.ts:8-11`). Records are addressed by the
tuple `(space_uri, collection, authorDid, rkey)`
(`packages/contrail-base/src/spaces/types.ts:259-262`).

### 2. Membership management

The member list is a plain SQL table on the authority — `spaces_members (space_uri, did, added_at,
added_by)` with PK `(space_uri, did)`
(`packages/contrail-appview/src/core/spaces/schema.ts:27-34`). It is not a repository record, not
published on the owner's PDS, and carries no commitment: there is no set hash, no LtHash, no ECMH,
no commit signature anywhere in the codebase. The project's own mapping doc marks this as a known
divergence ("Member list as PDS record → server-side state on authority ⚠️") and marks "ECMH commit
/ sync log" as ❌ unimplemented (`refs/spaces-spec-mapping.md`).

Mutation is owner-only. `addMember` and `removeMember` both check
`space.ownerDid !== sa.issuer → 403 not-owner` (`packages/contrail-authority/src/routes.ts:180-182`
and `197-199`); the owner cannot be removed (`routes.ts:200-202`); a non-owner can self-remove via
`leaveSpace`, and the owner cannot (`routes.ts:207-223`). Membership is binary — the ACL treats
owner-or-member as full read+write, with the single refinement that delete is scoped to your own
records and the owner gets no bypass (`packages/contrail-base/src/spaces/acl.ts:38-66`, with the
rationale spelled out at `acl.ts:42-46`).

Members learn about their membership by pulling, not by push — there is no `notifyMembership` and no
enrollment record. Two mechanisms substitute. Invite tokens are a first-class primitive with three
kinds, `join`/`read`/`read-join` (`packages/contrail-base/src/spaces/types.ts:141-158`), stored
SHA-256-hashed and redeemed atomically (`types.ts:239-241`). And a **membership manifest**:
`<ns>.space.getMembershipManifest` returns an ES256 JWT listing every space the caller belongs to,
capped at 500 with a 2h TTL, so an appview can filter a unioned query without replicating the
authority's member tables (`packages/contrail-authority/src/routes.ts:337-379`;
`packages/contrail-base/src/spaces/manifest.ts:1-33`). Both are contrail inventions with no 0016
counterpart.

The community package adds a second membership source: `community_access_levels (space_uri, subject,
subject_kind CHECK IN ('did','space'), access_level, …)`
(`packages/contrail-community/src/schema.ts:20-31`) allows a *space* to be the subject of a grant,
producing group-of-groups delegation. `resolveEffectiveLevel` walks that graph with a depth cap of 8,
capping the level at each hop by the path minimum (`packages/contrail-community/src/acl.ts:20-51`);
`flattenEffectiveMembers` collapses it to a DID set (`acl.ts:55-80`); cycles are rejected before a
grant lands (`acl.ts:110-132`); and a reconciler pushes the diff into `spaces_members` after every
change, re-running for every space that delegates to the changed one
(`packages/contrail-community/src/reconcile.ts:13-47`). The spaces layer stays ignorant of levels —
it only ever sees "this DID is a member."

### 3. Auth and authz enforcement points

Enforcement happens at both read time and write time, on the record host. Reads —
`listRecords`, `getRecord`, `getBlob`, `listBlobs` — all run `authorizeRead` and then, on the JWT
path, `checkAccess({op: "read", …})` (`packages/contrail-record-host/src/routes.ts:125-195`,
`370-446`). Writes — `putRecord`, `deleteRecord`, `uploadBlob` — run `resolveCaller` and then
`checkAccess({op: "write"|"delete", …})` (`routes.ts:197-368`).

Three credential types are accepted, in a fixed precedence documented at `routes.ts:3-11` and
implemented at `routes.ts:52-78`:

1. `X-Space-Credential: <jwt>` — an ES256 (P-256) JWT minted by the authority, header
   `{alg: "ES256", typ: "JWT", kid: "<authorityDid>#atproto_space_authority"}`, payload
   `{iss, sub, space, scope, iat, exp}` (`packages/contrail-base/src/spaces/credentials.ts:19-32`,
   `104-120`), signed and verified with hand-rolled Web Crypto to avoid a JWT dependency
   (`credentials.ts:16-17`). Default TTL is 2 hours, chosen so "revocation (kicked-from-space) is
   observable within 2h" (`packages/contrail-base/src/spaces/types.ts:29-31`).
2. `?inviteToken=…` or `Authorization: Bearer atmo-invite:<token>` — read-only bearer access
   (`packages/contrail-base/src/spaces/auth.ts:159-187`).
3. `Authorization: Bearer <service-auth-jwt>` — a standard atproto service-auth token, verified by
   `@atcute/xrpc-server`'s `ServiceJwtVerifier` with `aud` pinned to the authority's `serviceDid`
   and `lxm` derived from the request path (`auth.ts:24-41`, `62-111`).

The exchange is **one step**, not two: a caller presents a service-auth JWT to
`<ns>.space.getCredential`, the authority checks membership and app policy, and mints
(`packages/contrail-authority/src/routes.ts:253-291`). There is no delegation token, no `jti`, no
`aud`-less/`aud`-bearing distinction, and the JWT `typ` is the generic `"JWT"` rather than 0016's
`atproto-space-credential+jwt`. `refreshCredential` re-issues from an unexpired credential but
still re-checks membership (`routes.ts:293-328`).

Crucially, when a credential is presented the record host does **not** re-check membership or app
policy — "the record host trusts it: no member check, no app-policy check (those happen at issuance
time on the authority side)" (`routes.ts:9-11`), implemented as the `if (!caller.viaCredential)`
guards at `routes.ts:210,268,305` and `if (authz.via === "jwt")` at `routes.ts:137,176,382`. The
credential is checked only for signature, expiry, space match, and scope
(`credentials.ts:186-212`; `routes.ts:491-497`). Revocation therefore lags by up to the credential
TTL, which the code acknowledges.

On the 404-vs-403 question: an unauthorized read of an existing space returns **403** with
`reason: "not-member"` (`routes.ts:150,189`), which discloses the space's existence. A **404**
`not-enrolled` is returned when the space isn't in this host's enrollment table
(`routes.ts:86-91`), and a 404 when the space row is missing.

### 4. App-view access control

Contrail has an app-policy concept but no allowlist of *app views* and no mint policy. `AppPolicy`
is `{mode: "allow" | "deny", apps: string[]}` (`packages/contrail-base/src/spaces/types.ts:6-11`),
with semantics that read backwards from the field names: mode `"allow"` treats `apps[]` as a
**denylist**, mode `"deny"` treats it as an **allowlist**
(`packages/contrail-base/src/spaces/acl.ts:33-35`, duplicated at
`packages/contrail-authority/src/routes.ts:410-412`). It is evaluated at credential issuance
(`routes.ts:274-277`) and on every JWT-path record operation (`acl.ts:48-50`).

There is a wiring gap worth flagging. The policy keys off `ServiceAuth.clientId`, described as "OAuth
client_id of the caller, if the JWT carries one" (`packages/contrail-base/src/spaces/auth.ts:47-48`),
but neither `createServiceAuthMiddleware` (`auth.ts:97-101`) nor `verifyServiceAuthRequest`
(`auth.ts:142-146`) ever populates it — they set only `issuer`, `audience`, and `lxm`. Every
production call site therefore passes `clientId: undefined`, which makes `listed` false
(`acl.ts:33`), so an `allow`-mode policy permits everything and a `deny`-mode policy denies
everyone. The only non-undefined `clientId` values come from tests, which substitute their own
middleware reading an `X-Test-App` header (`packages/contrail/tests/spaces-e2e.test.ts:39`,
`spaces-blobs.test.ts:43`) or call `checkAccess` directly (`spaces-acl.test.ts:145,154,167,176`).
The project's own deferred list records "App policy enforcement in both `allow` and `deny` modes
(clientId checks)" as a missing test (`refs/spaces-later.md:56-57`). App policy appears inert on the
shipped auth path — but see "Confidence & unknowns."

There is no client attestation, no `#open`/`#allowList` app-access mode, and no notion of a trusted
app view. The nearest structural analogue is **enrollment**: the record host keeps
`record_host_enrollments (space_uri PRIMARY KEY, authority_did, enrolled_at, enrolled_by)`
(`packages/contrail-record-host/src/schema.ts:28-33`), and every record-host route hard-gates on it
(`routes.ts:80-93`). The docstring frames it as the host's consent layer: "without it, anyone with a
valid credential could create unbounded storage on your host" (`docs/06-spaces.md`, Enrollment).
`<ns>.recordHost.enroll` requires the caller to be the space owner (`routes.ts:110-115`);
in-process deployments auto-enroll from `createSpace` (`packages/contrail-authority/src/routes.ts:158-165`).

Which DID may sign for a space is resolved through a pluggable chain
(`packages/contrail-base/src/spaces/binding.ts`): local config (`:45-54`), the enrollment table
(`:62-71`), a PDS record at `at://<owner>/<type>/<key>` whose `authority` field names the issuer
(`:109-156`, validating `$type`, `createdAt`, and a `did:plc`/`did:web` pattern at `:148-152`), the
owner's DID-doc `#atproto_space_authority` service entry (`:166-191`), and finally
owner-self-issuance (`:78-85`). By default only the local and enrollment resolvers are wired; the
other two are exported but not composed in (`refs/spaces-later.md:36-48`).

### 5. Record read/write paths and storage schema

This is where contrail diverges hardest from the 0016 direction. `<ns>.space.putRecord` validates
enrollment, resolves the caller, runs the ACL, verifies any referenced blob CIDs exist, mints an
rkey (`body.rkey ?? nextTid()`), and writes straight into the appview's database
(`packages/contrail-record-host/src/routes.ts:197-253`). No PDS is contacted. The record host's
`putRecord` resolves a per-collection table via `spacesRecordsTableName(short)` and throws if the
collection isn't declared in this deployment's config
(`packages/contrail-record-host/src/adapter.ts:97-110`).

The storage schema is relational, not content-addressed
(`packages/contrail-appview/src/core/db/schema.ts:92-104`):

```sql
CREATE TABLE spaces_records_<short> (
  space_uri TEXT NOT NULL, uri TEXT NOT NULL, did TEXT NOT NULL, rkey TEXT NOT NULL,
  cid TEXT, record <json>, time_us BIGINT NOT NULL, indexed_at BIGINT NOT NULL,
  PRIMARY KEY (space_uri, did, rkey)
)
```

The `cid` column is nullable and every write sets it to `null` — `cid: null` at
`packages/contrail-record-host/src/routes.ts:248` and again at
`packages/contrail-community/src/router.ts:1086`. There is no MST, no commit block, no CAR, no
revision, and no signature over anything a member writes. A record's integrity rests entirely on the
operator's database. Alongside it sit `spaces` and `spaces_members` on the authority
(`packages/contrail-appview/src/core/spaces/schema.ts:13-34`), `spaces_invites` (`:47-59`),
`spaces_blobs` (`:36-44`), and `record_host_enrollments` (`:65-71`).

Blobs are handled locally: `uploadBlob` computes a raw (0x55) CID over the bytes
(`packages/contrail-record-host/src/routes.ts:346-347`), stores bytes on a pluggable `BlobAdapter`,
and returns an atproto-shaped `{$type: "blob", ref: {$link}, mimeType, size}` (`routes.ts:360-367`).
`putRecord` rejects records referencing blobs never uploaded to that space (`routes.ts:224-239`);
orphans are GC'd after a grace period (`packages/contrail-base/src/spaces/types.ts:20-23`).

Public records take an entirely separate path — Jetstream ingest into `records_<short>`
(`packages/contrail-appview/src/core/jetstream.ts:217-218`) plus backfill via
`com.atproto.repo.listRecords` (`packages/contrail-appview/src/core/backfill.ts:216`). A unified
`listRecords` unions public records with every space the caller belongs to when no `spaceUri` is
given (`packages/contrail-appview/src/core/db/records.ts:859`).

The one place contrail writes to a PDS is community publishing: `<ns>.community.putRecord` decrypts
a stored app password, opens a session, and proxies `com.atproto.repo.createRecord` against the
community account's PDS (`packages/contrail-community/src/router.ts:938-970`; delete at `:1025`).
That path is explicitly for **public** records under a shared identity. In-space community records
go to the appview like everything else, with the community DID as `authorDid` and `cid: null`
(`router.ts:1081-1089`), gated at `admin`+ (`router.ts:1074-1077`).

### 6. Sync and event behavior

There is no operation log, no set-hash reconciliation, no `listRepoOps`, no `getRepo` CAR export,
and no write-notification protocol. `refs/spaces-spec-mapping.md` marks both "ECMH commit / sync
log" and "Pull-based sync, write notifs" as ❌ with the note "Out of scope until federated sync
exists."

What exists instead is a per-space SSE stream, `<ns>.recordHost.sync`
(`packages/contrail-record-host/src/sync.ts:58-223`), running two phases: a catch-up that scans each
per-collection table for `time_us > since` and emits every row as `record.created`
(`sync.ts:226-304`), then a live phase subscribing to an in-process pubsub topic `space:<uri>`
(`sync.ts:159-189`). The cursor is a raw `time_us` integer (`sync.ts:296`), not a TID revision, and
there is no digest for a client to compare against — divergence is undetectable. The module is candid
about its limits: past deletions are never replayed because the row is gone, and there is a race
window between catch-up and live subscribe (`sync.ts:10-15`). Auth is a space credential only
(`sync.ts:69-95`).

Permissioned writes are structurally off the public firehose: since they never reach a PDS, no
`subscribeRepos` event can exist. Fan-out is internal — the publishing decorator emits to
`space:<uri>` and, for community-owned spaces, `community:<did>`
(`packages/contrail-appview/src/core/realtime/publishing-adapter.ts:22-33`;
`packages/contrail-base/src/realtime/types.ts:78-83`). Public-record ingest is the mirror image:
Jetstream plus a `notify` route that takes an `at://` URI and pulls the record from the author's PDS
(`packages/contrail-appview/src/core/router/notify.ts:24-40`).

### 7. Interop with the 0016 direction

Contrail speaks none of 0016's wire protocol. There is no `com.atproto.space.*` or
`com.atproto.simplespace.*` NSID anywhere (exhaustive grep, above); endpoints are namespaced per
deployment, so a real deployment exposes e.g. `com.example.space.putRecord`
(`packages/contrail-record-host/src/routes.ts:49`), and the shipped lexicon templates are
`tools.atmo.space.*` (`packages/lexicons/lexicon-templates/spaces/getCredential.json` and siblings).
Access is negotiated with a one-step service-auth-JWT → space-credential exchange, not the
delegation-token → space-credential exchange.

The overlap is vocabulary and shape rather than protocol: the `ats://owner/type/key` URI, the
owner+type+skey triple, a ~2-hour credential lifetime chosen to match "the rough spec"
(`docs/06-spaces.md:43`), an app allow/deny dimension, and the DID-doc service entry
`#atproto_space_authority` (`packages/contrail-base/src/spaces/binding.ts:171`). Contrail also adds
concepts 0016 lacks: enrollment-as-host-consent, the signed membership manifest, three-kind invite
tokens, `spaceExt.whoami`, and a PDS-resident `tools.atmo.space.declaration` record naming the
`authority` and `recordHost` DIDs for a space
(`packages/lexicons/lexicon-templates/spaces/declaration.json`) — the only artifact in the entire
design that lives on a user's PDS.

The project is clear-eyed about the delta: `refs/spaces-spec-mapping.md` carries a
concept-by-concept alignment table and a "Migration readiness" list of six required changes (member
list to PDS records, records federating from user PDSes, greenfield ECMH commits and sync log,
endpoint renaming, possible `(did, read|write)` member tuples, possibly forcing `iss = owner DID`).
`docs/06-spaces.md:153` claims migration "is mostly data movement — the wire surface your app speaks
doesn't change," which holds for the app-facing API and not for anything below it.

## Group-controlled DIDs, the ladder, and two doc/code disagreements

`community.mint` generates three P-256 keypairs — signing, contrail-held rotation, creator-held
recovery rotation — builds and signs a `did:plc` genesis op with contrail's rotation key, submits it
to `plc.directory`, encrypts and stores the signing and contrail rotation keys, and returns the
creator's recovery key exactly once (`packages/contrail-community/src/router.ts:164-231`). The PLC
machinery is hand-rolled with Web Crypto and a minimal DAG-CBOR encoder
(`packages/contrail-community/src/plc.ts:1-3`). `community.adopt` instead stores an app password for
an existing account, and `community.provision` creates a fresh `did:plc` plus a PDS account with a
caller-supplied rotation key, guarded by a fail-closed PDS allowlist and a default-deny
`allowProvisioning` switch (`packages/contrail-community/src/types.ts:78-108`). Two reserved spaces,
`$admin` and `$publishers`, are bootstrapped per community (`types.ts:160-165`), and public
publishing requires `member`+ in `$publishers` (`router.ts:901-910`).

The docs disagree with the code twice here. `docs/07-communities.md` shows
`levels: ["admin", "moderator"]` in its config example and says "Your deployment defines the rest via
`config.community.levels`"; the code has a fixed, non-configurable four-level ladder —
`type AccessLevel = "member" | "manager" | "admin" | "owner"` with `ACCESS_LEVELS` as a `const`
array (`packages/contrail-community/src/types.ts:7-14`) — and `CommunityConfig` (`types.ts:66-109`)
has no `levels` field at all. `refs/community-spec-mapping.md` is the accurate description
("Access-level ladder → `member`/`manager`/`admin`/`owner` ⚠️ 4 levels vs the post's 8"). Second,
the same doc implies all three modes publish; the router refuses publishing outright for
`mode === "mint"` (`router.ts:892-897`), so minted communities can hold spaces but cannot publish
public records.

## Where atproto-crates is ahead / behind / simply different

**Ahead.** This repository implements the 0016 cryptographic core that contrail has no counterpart
for. `crates/atproto-space/src/set_hash.rs:1-24` implements LtHash (BLAKE3-XOF, 1024 `u16` lanes,
`sha256(state)` as the carried digest) behind a `SetHash` trait; `crates/atproto-space/src/commit.rs:83`
implements the signed commit (`com.atproto.space.defs#signedCommit`);
`crates/atproto-space/src/credential.rs:1-45` implements the real two-step flow with the correct
`typ` headers (`atproto-space-delegation+jwt`, `atproto-space-credential+jwt`), the 60-second
delegation TTL, the `kid` values, and client attestation via `client_id`. Contrail has none of
these — no digest, no commit, no delegation token, no attestation. This repository also serves the
actual `com.atproto.space.*` and `com.atproto.simplespace.*` NSIDs from the PDS
(`crates/atproto-pds/src/http/space_handlers.rs:1-29`), including `listRepoOps`, `getRepoState`, and
the `notifyWrite` notifier (`crates/atproto-pds/src/notifier.rs:349`), which is the entire sync axis
contrail marks as out of scope. And records live in the user's own permissioned repo rather than an
operator's database.

**Behind.** Contrail ships a lot of appview machinery this repository does not attempt: Jetstream
ingestion and backfill, a config-driven query layer with range filters and FTS, feeds, label
hydration, blob GC, a client-side reactive sync store, and a lexicon codegen CLI. On the
permissioned side specifically, contrail has three things worth stealing conceptually. First,
**enrollment as an explicit host-consent gate** — `record_host_enrollments` plus a 404 on every
unenrolled route (`packages/contrail-record-host/src/routes.ts:80-93`) — a problem 0016 does not
address at all, per `refs/spaces-spec-mapping.md`. Second, the **signed membership manifest**
(`packages/contrail-authority/src/routes.ts:337-379`), which lets a reader filter a cross-space
union without replicating the member list. Third, **invite tokens as a protocol primitive** with
`join`/`read`/`read-join` kinds and bearer read grants
(`packages/contrail-base/src/spaces/types.ts:141-158`), where 0016 defers onboarding to apps.
Contrail also has a worked multi-tenant deployment story (`docs/10-deployment-shapes.md`) covering
authority-only and record-host-only splits.

**Simply different.** The two projects answer a different question. Contrail's spaces are an
operator-hosted permission layer for an appview — fast, simple, operator-readable, with no
federation story and an explicit "no E2EE (data is operator-readable)" disclaimer
(`docs/06-spaces.md`, "What's not here"). This repository is building the protocol-level thing:
per-user permissioned repos with verifiable commits and cross-host sync. Contrail's group-controlled
DIDs (mint / adopt / provision) have no analogue here and address a governance problem 0016 leaves
open; conversely, contrail's binary membership deliberately collapses a distinction 0016 may keep.
The `ats://` URI form is the one place they independently agree.

## Confidence & unknowns

High confidence: the storage schema, the write path, the credential format, the absence of any
`com.atproto.space.*` NSID, and the absence of LtHash/oplog/commit primitives. All were read
directly and the negative claims rest on exhaustive greps over the checkout.

Moderate confidence on the app-policy finding. I traced every assignment to `ServiceAuth.clientId`
in `packages/**` and found none outside tests. UNVERIFIED: whether a consumer application can inject
its own middleware that populates `clientId` — the tests do exactly that, so the hook exists in
practice even if the library never uses it. I did not run the test suite; all conclusions are from
reading source, not execution.

UNVERIFIED: whether `packages/contrail/src/core/spaces/*` (the duplicated copy of the base spaces
sources) is dead code. `packages/contrail/package.json` depends on all four split packages via
`workspace:*` while `packages/contrail/src/index.ts:41-59` re-exports from `./core/spaces/*`; I did
not trace which copy a consumer resolves at runtime. Every file:line citation above is from the
split packages.

UNVERIFIED: adoption. Beyond the in-repo reference apps (`apps/group-chat`, `apps/rsvp-atmo`,
`apps/contrail-e2e`, two minimal examples) I have no evidence of deployments. Version 0.12.2, a
self-declared pre-alpha label, and a single named author is the extent of what the source supports.

UNVERIFIED: whether upstream has moved toward 0016 since HEAD `fa3d4cd` (2026-06-17). The 0016 draft
lexicons in `/tmp/gap-scratch/lex-0016` are dated 2026-07-02 — after this checkout — so contrail's
silence on 0016 may reflect the clone date rather than a standing decision.
