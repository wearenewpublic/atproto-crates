# Permissioned data — overview and cross-implementation comparison

Companion files: [contrail](./41-contrail.md), [HappyView](./42-happyview.md),
[stratos](./43-stratos.md). Repository-wide context:
[inventory](../00-atproto-crates-inventory.md),
[synthesis and roadmap](../50-synthesis-and-roadmap.md),
[gap-analysis README](../README.md).

> Note on cross-links: `../00-atproto-crates-inventory.md` now exists on disk;
> `../50-synthesis-and-roadmap.md` and `../README.md` do not yet (verified by `ls` against
> `docs/gap-analysis/`, which currently holds `00-atproto-crates-inventory.md`,
> `20-coverage-matrix.md`, `capability-areas/`, `impl-notes/`, and `permissioned/`). The two
> outstanding files are produced by sibling workflows; the links are written to their agreed paths.

Unqualified `crates/…` paths are relative to the worktree root
`/Users/nick/development/github.com/ngerakines/atproto-crates-studious-guide/.claude/worktrees/goofy-bell-de1699`.

## 1. Framing

Proposal 0016 ("permissioned data") addresses a *space* by an authority DID plus a space-type NSID
plus a space key, gates it with a two-step credential exchange, commits each member's contribution
with a homomorphic set hash rather than a Merkle tree, and has consumers learn about writes by
pulling an operation log instead of reading a public firehose. Concretely: a delegation token minted
by the user's own PDS (`typ: atproto-space-delegation+jwt`, 60-second TTL, signed by the user's
account signing key) is presented to the space authority, which returns a space credential
(`typ: atproto-space-credential+jwt`, no `aud`, roughly two hours) usable against any repo host
serving that space. Integrity comes from LtHash: a 2048-byte lattice state of 1024 little-endian
`u16` lanes into which each record folds as `{collection}/{rkey}/{cid}` expanded through BLAKE3-XOF
and added mod 2^16, with the commit `hash` being `sha256(state)`. Commit signatures are deniable —
a fresh 32-byte `ikm` per commit, a signature over a context string rather than over the hash, and
`mac = HMAC-SHA256(HKDF-SHA256(ikm, ctx), hash)` binding the two. Sync is `listRepoOps` with a
`since` revision plus a set-hash comparison at the head, `getRepo` returning a CAR for full recovery,
and `notifyWrite` as a contentless push that tells a syncer to go pull.

0016 is an open, self-declared work-in-progress draft (PR #94 by dholms). Its README says so in
those words: "This is a proposal, not the final specification. Details, terminology, and behaviors
are all likely to change" (`/tmp/gap-scratch/0016-spec-digest.md:3-4`). What *has* materialized
since the proposal text is a set of draft lexicons on the `bluesky-social/atproto`
`permissioned-data` branch at HEAD `3f6c96d` (2026-07-02, "bring impl up to date with lexicons &
proposal"), fetched to `/tmp/gap-scratch/lex-0016/` — 19 files under `space/` and 8 under
`simplespace/`. Those lexicons are a materially stronger oracle than the prose, and they settle
questions the prose leaves open: `space/defs.json` marks `ver` as required on `signedCommit` and
states that `sig` covers "ctx (space, author DID, rev, ikm)"; `simplespace/defs.json` names the user
authorization field `policy`, not `mintPolicy`; `space/notifyWrite.json` requires a `hash` field
"[so the] space host [can] maintain each repo's hash for listRepos"; every space reference across
the family carries `"format": "at-uri"`. The same branch carries a reference implementation
(`packages/space/*`, `packages/pds/src/api/com/atproto/space/*`), which is a third and sharper
oracle for crypto details.

The ecosystem has not converged on any of this. Per Bluesky's Spring 2026 roadmap, Blacksky,
Northsky, and Habitat are each building parallel non-public-data extensions, and the three targets
compared here confirm the spread: two of them do not use the `com.atproto.space.*` namespace at all
and store permissioned records somewhere other than a PDS. Divergence from 0016 is therefore a
statement about interop with one in-flight design, not about correctness — and in at least one place
(the `(rev, idx)` oplog cursor, D4 below) atproto-crates is right on the merits and wrong on the
wire.

The grading consequence is asymmetric. **HappyView is the only same-direction interop yardstick**:
same `com.atproto.space.*` / `com.atproto.simplespace.*` split, same delegation-token →
space-credential exchange with the same `typ` strings and TTLs, same LtHash parameters and
deniable-commit construction ([42-happyview.md](./42-happyview.md), §D.7). Where atproto-crates and
HappyView both diverge from the lexicons, that is a signal about the draft's stability; where only
one diverges, that is a bug in the one. **contrail and stratos are alternative points in the design
space**, not conformance oracles — neither contains a single `com.atproto.space.*` NSID (exhaustive
greps in [41-contrail.md](./41-contrail.md) and [43-stratos.md](./43-stratos.md)), and both store
permissioned records in a service's own SQL database. They are read here for ideas
(enrollment-as-host-consent, invite tokens, signed membership manifests, the read-leakage rule,
service-qualified boundary tokens) and never for wire conformance.

## 2. The three comparison targets

**contrail** ([41-contrail.md](./41-contrail.md)) is a TypeScript library for building serverless
appviews, self-labelled "pre-alpha", published at 0.12.2, MIT, single author. Its spaces subsystem
tracks Daniel Holmgren's earlier leaflet sketch rather than 0016 — the mapping doc says so at
`refs/spaces-spec-mapping.md:3-5` — and its defining architectural choice is that permissioned
records live in the appview's own SQL tables and never touch anyone's PDS
(`refs/spaces-spec-mapping.md:11-14`, code at `packages/contrail-record-host/src/routes.ts:197-253`).
There is no set hash, no commit, no operation log, and the `cid` column is written `null` on every
record (`routes.ts:248`). Access is a one-step service-auth-JWT → ES256 space-credential exchange
(`packages/contrail-authority/src/routes.ts:253-291`). Its genuinely novel contributions are
enrollment as an explicit host-consent gate (`packages/contrail-record-host/src/schema.ts:28-33`),
signed membership manifests (`packages/contrail-authority/src/routes.ts:337-379`), three-kind invite
tokens (`packages/contrail-base/src/spaces/types.ts:141-158`), and group-controlled `did:plc`
identities with an access-level ladder (`packages/contrail-community/src/router.ts:164-231`).

**HappyView** ([42-happyview.md](./42-happyview.md)) is a lexicon-driven Rust AppView (axum, sqlx
over `Any`, MIT, "Lexicon Community") whose spaces subsystem sits behind a `feature.spaces_enabled`
flag. It occupies an unusual position: the *closest namespace and vocabulary match* to 0016 outside
Bluesky's own branch, combined with a *contrail-shaped storage decision*. Records are rows in
`happyview_space_records` (`migrations/sqlite/20260429000002_create_space_records.sql`) rather than
in a PDS repo, and record identity is a fabricated string,
`format!("bafyrei{}", hex::encode(&sha256(serde_json::to_vec(record))[..20]))`
(`src/spaces/service.rs:26-30`), which is not a decodable CID. Its LtHash (`src/spaces/lthash.rs`),
its signed commit including `ver` and the author DID in `ctx` (`src/spaces/commit.rs:9-16,18-44`),
and its client attestation (`src/spaces/client_attestation.rs`) are all correct, well-tested, and
have **no production caller** — each established by grepping all of `src/` and `tests/`. Its one
clear lead is credential revocation
(`migrations/sqlite/20260707000000_add_revoked_at_to_space_credentials.sql:1-4`,
`src/spaces/db.rs:330-348`, called from `service.rs:395-397`).

**stratos** ([43-stratos.md](./43-stratos.md)) is Northsky Social's TypeScript "boundary-aware data
layer", experimental, with no LICENSE file and self-contradicting license metadata. It shares no
wire surface with 0016 — a repository-wide grep for `com.atproto.space`, `simplespace`,
`delegation`, `spaceCredential`, `LtHash`, and `setHash` returns zero matches. Its unit of access
control is a *boundary*, a service-qualified string `{serviceDid}/{name}`
(`stratos-core/src/validation/boundary-qualification.ts:30-32`), and its trust model is
fundamentally different: the Stratos service mints and holds each user's repo signing key
(`stratos-service/src/context.ts:144-158`), stores every record in plaintext in its own per-actor
MST repositories, and the downstream indexer replicates that plaintext into a second database
(`stratos-indexer/src/storage/schema.ts:22-27`). Only a CID-bearing stub reaches the PDS
(`stratos-core/src/stub/domain.ts:10-26`). Its transferable ideas are the read-leakage rule stated
as an explicit invariant (`docs/operator/security.md:24`) and the write-side check that a user may
only address boundaries they themselves hold (`api/records/validation.ts:56-68`).

## 3. The axes matrix

| Sub-question | atproto-crates | contrail | HappyView | stratos | 0016 draft |
|---|---|---|---|---|---|
| **1. Space identifier shape** | `ats://<did>/<type>/<skey>` (`crates/atproto-space/src/types.rs:13,122`) | `ats://<ownerDid>/<type>/<key>` (`spaces/uri.ts:20-22`) | `at://<did>/space/<type>/<skey>`; `ats://` rewritten as legacy (`src/spaces/mod.rs:41-52,67-71`) | none — boundary string `{serviceDid}/{name}` (`boundary-qualification.ts:30-32`) | `at://<did>/space/<type>/<skey>`, `format: at-uri` (`lex-0016/space/getSpace.json`) |
| **1b. skey concept** | first-class `SpaceKey`, rkey grammar, TID auto-gen (`types.rs:68-74`; `space_handlers.rs:197-199`) | yes, `body.key ?? nextTid()` (`contrail-authority/routes.ts:141`) | yes, own column, `UNIQUE(did,type_nsid,skey)` (`20260627000000_proposal_0016_alignment.sql:9-10,20`) | none | yes, optional, TID if omitted (`simplespace/createSpace.json`) |
| **1c. Root of trust** | authority DID's account signing key; `create_space` forces `authority == caller` (`space_handlers.rs:186-196`) | service-auth JWT issuer; anyone may create (`contrail-authority/routes.ts:142,156`) | `authority_did`, distinct from `creator_did` (`types.rs:166-167`) | the Stratos service instance; boundary vocabulary is operator config (`config.ts:446-449`) | space authority DID |
| **1d. Multiple spaces per owner** | yes, `space` keyed on full URI (`20260501000001_init.sql:69-70`) | yes, 409 on duplicate URI (`routes.ts:144-145`) | yes | n/a (boundaries, many per user) | yes |
| **2. Member list location** | authority's per-actor SQLite `space_member` (`20260501000001_init.sql:111-117`) | authority SQL `spaces_members` (`spaces/schema.ts:27-34`) | `happyview_space_members` (`20260429000001_create_space_members.sql`) | service enrollment store, keyed by DID | host-internal, "not a synced protocol structure" (`simplespace/addMember.json`) |
| **2b. Who mutates it** | authority only + `space:…manage` OAuth verb (`service.rs:468-493`; `space_handlers.rs:498-502`) | owner only; non-owner self-remove (`routes.ts:180-182,207-223`) | authority or HappyView super-admin (`service.rs:32-55`) | operator, via `zone.stratos.admin.setBoundaries` (`enrollment/handler.ts:435-480`) | the authority |
| **2c. Membership commitment** | member LtHash + oplog, internal only, never on the wire (`space_members.rs:94-158`; `sync.rs:17-19`) | none; mapping doc marks it ⚠️ | none, plain rows | none | none (draft has no member commits) |
| **2d. How members learn** | they don't; discovered by attempting a mint | pull: invite tokens + signed membership manifest (`routes.ts:337-379`) | poll `listSpaces`/`listMembers`; invites (`routes.rs:813-903`) | PDS enrollment record rewritten + sync-stream event (`callback.ts:183-196`) | no notification; discovered at mint time |
| **3. Credential exchange** | two-step, delegation → credential (`crates/atproto-space/src/credential.rs:40-55`) | one-step, service-auth JWT → credential (`routes.ts:253-291`) | two-step, but input is `{grant}` in body (`routes.rs:155-157`) | none; DPoP OAuth + service JWTs | two-step, token in `Authorization` header (`getSpaceCredential.json`) |
| **3b. Delegation token signer** | user's account signing key, local table or resolved DID doc (`space_auth.rs:74-116,245-291`) | n/a | instance `TOKEN_ENCRYPTION_KEY` (`routes.rs:926`) — instance-local only | n/a | user's account signing key |
| **3c. Credential signer / alg** | authority account `#atproto` key; ES256 or ES256K from key type (`credential.rs:150-157`) | per-authority P-256, `ES256`, `typ: "JWT"` (`credentials.ts:19-32`) | per-space P-256, ES256, `kid: #atproto_space` (`credential.rs:178-182`) | n/a | authority, no `aud`, ~2 h |
| **3d. Revocation** | none (grep `revoke` over `crates/atproto-space/src`, `crates/atproto-pds/src/space` → 0 hits) | none; TTL only, documented as ≤2 h lag (`spaces/types.ts:29-31`) | `revoked_at` + member-scoped revoke on removeMember (`db.rs:330-348`) | n/a | none; TTL only |
| **4. Write-time authz** | repo ownership only; membership explicitly not checked (`writer.rs:6`; `space_handlers.rs:857-867`) | ACL `checkAccess({op:"write"})` on the host (`routes.ts:197-368`) | `require_membership` + `can_write()` (`service.rs:112-116`) | enrollment + own-repo + boundary-you-hold (`create.ts:80-96,236-248`; `validation.ts:56-68`) | not explicit in the lexicons |
| **5. Read-time authz** | none for session/OAuth callers — `verify_auth` is `Ok(())` for `OwnPds` (`reader.rs:214-216`) | `authorizeRead` + `checkAccess({op:"read"})` (`routes.ts:125-195`) | `require_membership` on every read (`service.rs:75-118`) + `read_self` tier (`scope.rs:24-63`) | boundary-set intersection (`hydration/domain.ts:14-34`) | reference has the same hole, including verbatim `repo` (`packages/pds/.../space/getRecord.ts`, `.../space/util.ts:32-37`) |
| **5b. Unauthorized read outcome** | 404 `RecordNotFound` for absent/taken-down; 403 `Forbidden` for a bad credential (`errors.rs:63-65`) | 403 `not-member` (leaks existence); 404 `not-enrolled` (`routes.ts:86-91,150,189`) | 403 non-member, but 404 on `getSpace` to hide existence (`routes.rs:441-448`) | 404-equivalent on `getRecord`/`getRepo`; distinct `RecordBlocked` on `hydrateRecord` (`hydration/handler.ts:166-171`) | error names only; no status mandated |
| **4/6. App-identity gating** | `#open`/`#allowList` against an *attested* `client_id` (`mint_authz.rs:128-143`) | `AppPolicy{mode,apps[]}`, keyed on a `clientId` never populated in production (`spaces/auth.ts:97-101,142-146`) | `allowList` against a HappyView-issued API key (`auth.rs:244-259`) | `STRATOS_SERVICE_ENROLLMENTS` + inter-service JWT (`verifiers.ts:433-459`) | `#open`/`#allowList` on attested `client_id` (`simplespace/defs.json`) |
| **4b. Client attestation** | verified end-to-end: typ, iss==sub, aud, 300 s cap, jti, JWKS fetch, JWS (`mint_authz.rs:229-376`) | none | implemented and **dead code** (`client_attestation.rs`, no caller) | none | required for `#allowList` |
| **5c. Record storage location** | writer's own per-actor store, `space_record` table, disjoint from the MST (`20260501000001_init.sql:98-107`) | appview SQL, one table per collection (`db/schema.ts:92-104`) | AppView SQL `happyview_space_records` | service-side per-actor MST, off-PDS (`db/schema/tables.ts:13-72`) | writer's repo host |
| **5d. Record CID** | real CIDs via `atproto_dasl::to_vec` + `compute_cid` (`writer.rs:285-288`) | `cid: null` on every write (`routes.ts:248`) | fabricated `bafyrei`+hex, 20-byte truncated sha256 of JSON (`service.rs:26-30`) | real CIDs, `@atcute/mst` (`create.ts:169-170`) | `format: cid` throughout |
| **6. Commit signing** | deniable commit implemented and wired into the write path (`commit.rs:118-143`; `writer.rs:335`) | none | implemented; `sign_commit` has no production caller | MST commit v3 signed by service-held per-actor key (`mst/internal/signer.ts:41-63`) | deniable commit, `ver` required |
| **6b. Commit `ctx` fields** | `[space, rev, ikm]` — **author DID absent** (`commit.rs:58-64,71-81`) | n/a | `[space, author, rev, ikm]` (`commit.rs:18-44`) | n/a | `(space, author DID, rev, ikm)` (`space/defs.json`) |
| **6c. Set-hash primitive** | LtHash, 1024 lanes, BLAKE3-XOF, element `{coll}/{rkey}/{cid}` (`set_hash.rs:30-32,167-169`) | none | identical LtHash, but unwired (`lthash.rs:4-9,75-77`) | none | LtHash, same parameters |
| **7. Incremental sync** | `listRepoOps` + `(rev, idx)` cursor, metadata-only entries (`space_handlers.rs:1283-1295,1354`) | per-space SSE over a `time_us` cursor, no digest (`record-host/sync.ts:58-223`) | `listRepoOps` reads an oplog table that is never written (`oplog.rs:5-30`, no caller) | WebSocket `subscribeRecords`, records inline, integer seq | `listRepoOps` with `since` revision + values inlined by default |
| **7b. Full recovery** | none — no `getRepo`, no CAR (grep: only `com.atproto.sync.getRepo` at `router.rs:83`) | none | `getRepo` CAR export, well-formed but with a third distinct CID per block (`car.rs:60-151,65-67`) | `zone.stratos.sync.getRepo` CAR, owner-only | `getRepo` CAR: commit root, DRISL index root, record blocks |
| **7c. Write notification** | contentless `{space, repo, rev}`, service auth, `iss == repo` (`notify.rs:49-56`; `space_handlers.rs:2107-2113`) | none (in-process pubsub only) | content-bearing `{space, did, collection, rkey, cid}`, payload carries a UUID not a URI (`routes.rs:59-65`; `notifications.rs:63-69`) | none | contentless `{space, repo, rev, hash}` |
| **7d. Off the public firehose** | verified: zero sequencer references either direction (§D.3 of the axis map) | structurally yes — never reaches a PDS | structurally yes — never reaches a PDS | content yes; **stub, timing, and boundary memberships are public** | yes, by design |
| **7e. Namespace** | `com.atproto.space.*` + `com.atproto.simplespace.*`, 20 routes | `<deployment-ns>.space.*`; templates `tools.atmo.space.*` | same as atproto-crates + `dev.happyview.space.*` aliases | `zone.stratos.*` only | `com.atproto.space.*` + `com.atproto.simplespace.*` |

## 4. atproto-crates classified findings

Classes: **MISSING** (the capability does not exist), **PARTIAL** (present but incomplete enough to
break a real workflow), **DIVERGENT** (present and working, but on a different wire contract than
the draft), **OUT-OF-SCOPE** (an intentional difference or an extension, not a gap).

### MISSING

**M1 — Full-state recovery (`com.atproto.space.getRepo`).** No route exists; the only `getRepo` in
the workspace is `com.atproto.sync.getRepo` at `crates/atproto-pds/src/http/router.rs:83`, which
serves the public repo. Nothing under `crates/atproto-space/src/` or `crates/atproto-pds/src/space/`
produces a CAR, and there is no DRISL index-block builder. HappyView has a worked reference:
`routes.rs:236` routes it, `src/spaces/car.rs:60-151` serializes a two-root header (commit, then a
DAG-CBOR index of `"collection/rkey"` → tag-42 CID link sorted lexicographically) followed by record
blocks in sorted order, per `lex-0016/space/getRepo.json`. Shipping stable without this means a
syncer that falls behind its oplog retention window has no recovery path at all. It cannot fall back
to `listRecords`, because that method never returns record values (M3), so the only remaining option
is one `getRecord` round-trip per record with no way to enumerate what to fetch. This is the single
largest functional gap on the permissioned surface.

**M2 — `com.atproto.space.getLatestCommit`.** A repo-wide grep finds only the public-repo
`com.atproto.sync.getLatestCommit` (`router.rs:76`, handler `handlers.rs:148`, reader
`repo/reader.rs:382`). The space method is served instead under a name the draft does not define,
`getRepoState` (`router.rs:327`) — see D3. HappyView routes both names, `getLatestCommit` at
`routes.rs:229` and `getRepoState` at `routes.rs:233` as a back-compat alias to the same handler,
which is exactly the migration shape atproto-crates needs. Consequence: a draft-conformant syncer
asking for the current commit gets a 404 and cannot complete a set-hash reconciliation cycle,
because the commit `hash` it needs to compare against is only reachable under a name it does not
know to call.

**M3 — Record values are never returned by any listing method.** `SpaceRecordItem`
(`crates/atproto-pds/src/http/space_handlers.rs:990-998`) is exactly `{collection, rkey, cid}`, and
`RecordOpEntry` (`space_handlers.rs:1283-1295`) has no `value` field at all; neither
`ListSpaceRecordsQuery` nor `RepoOplogQuery` (`space_handlers.rs:1264-1276`) accepts
`excludeValues`. The lexicons say the opposite in both places: `space/listRecords.json#record`
describes `value` as "Inlined by default; omitted when excludeValues is set", and
`space/listRepoOps.json#opEntry` says `value` "carries the record's current value for creates and
updates, unless excludeValues was set". Worth flagging explicitly per the docs-versus-code rule: the
comment at `space_handlers.rs:988` asserts the keys-only shape *is* what
`com.atproto.space.listRecords#record` specifies, and the lexicon it names contradicts it. HappyView
implements the correct default — `src/spaces/oplog.rs:101-174` inlines values via a LEFT JOIN and
`routes.rs:1106-1128` treats `excludeValues=true` as the opt-out. Combined with M1, a syncer against
an atproto-crates host can learn that records exist and what their CIDs are, but cannot materialize
a single record value without an additional round trip per record, which makes the sync design
quadratic in practice and unusable for initial backfill.

**M4 — `ver` on the signed commit.** `Commit` (`crates/atproto-space/src/commit.rs:87-102`, verified
by reading the struct: fields are `hash`, `mac`, `ikm`, `sig`, `rev`) has no `ver` field, and
neither does the wire type `SignedCommitDto` (`space_handlers.rs:1146-1158`).
`lex-0016/space/defs.json` lists `ver` first in `"required"` and defines it as the version
corresponding to the `atproto-space-v1` ctx tag. HappyView's `SignedCommit` carries `ver` and
rejects `ver != 1` (`src/spaces/commit.rs:9-16,88-93`); the reference `createCommit` returns
`{ver: COMMIT_VERSION, …}`. Because this is a type-level omission rather than a serialization
choice, every commit atproto-crates emits fails schema validation at a conforming consumer before
any cryptography is attempted, and there is no forward path to a version-2 ctx construction.

**M5 — `hash` on `notifyWrite` and on `listRepos#repo`.** The outbound payload is
`{space, repo, rev}` (`crates/atproto-pds/src/space/notify.rs:49-56`, verified) and `RepoRef` emits
`{did, rev}` (`space_handlers.rs:2299-2305`). `lex-0016/space/notifyWrite.json` requires
`{space, repo, rev, hash}` and states the reason inline: the hash "lets the space host maintain each
repo's hash for listRepos". `lex-0016/space/listRepos.json#repo` defines the matching `hash` field.
HappyView omits it in the same place (`src/spaces/db.rs:1022-1024`), so there is no worked reference
here — both same-direction implementations have dropped the same field. Consequence: the entire
hash-propagation loop from repo host to space host is absent, so a syncer cannot use `listRepos` to
tell which repos have changed and must instead issue a per-repo commit fetch, which M2 has already
made unreachable under the conformant name.

**M6 — Space-credential revocation.** A grep for `revoke` across `crates/atproto-space/src` and
`crates/atproto-pds/src/space` returns zero hits (verified). Removing a member takes effect only at
the *next* mint; an already-issued credential stays valid for the full 7200-second TTL
(`crates/atproto-space/src/credential.rs:55`), and space deletion does not revoke either (D.5 of the
axis map). HappyView is ahead here and its implementation is directly portable: hash the token at
mint (`src/spaces/auth.rs:56-57`), add a nullable `revoked_at`
(`migrations/sqlite/20260707000000_add_revoked_at_to_space_credentials.sql:1-4`), stamp it for all
of a member's outstanding credentials in `db::revoke_space_credentials_for_member`
(`src/spaces/db.rs:330-348`) called *before* the membership row is deleted (`service.rs:395-397`),
and check on every credential-authenticated read (`routes.rs:386-388`). The draft does not require
this, so it is an addition rather than a conformance item — but a two-hour window in which a removed
member retains full read access to a space is the kind of property a security reviewer will treat as
a defect regardless of what the draft says.

**M7 — Read-time membership enforcement, and the cross-account read it permits.** Three facts
compose into a real hole. `resolve_record_auth` (`space_handlers.rs:1080-1124`) takes the `repo`
query parameter verbatim as `target_repo` (line 1114) with no relationship check;
`assert_space_scope` (`space_handlers.rs:1866-1868`, verified: `if !subject.is_oauth() { return
Ok(()); }`) skips scope checking entirely for a non-OAuth subject, and an app-password session is
`AuthSubject::Session`; and `SpaceReader::verify_auth` is a literal `Ok(())` for the `OwnPds` variant
(`crates/atproto-pds/src/space/reader.rs:214-216`, verified). Net effect: any account holding an
app-password session on the PDS can read any other local account's permissioned records, in any
space, by supplying `repo=<victim DID>`, regardless of membership. `getBlob` has the same shape
with an extra wrinkle: the `space` parameter never enters the lookup, which is
`crate::blob::get_blob(&store, &q.cid)` on `(repo, cid)` alone (`space_handlers.rs:2243`).

**Scope this correctly: all three links are shared with the reference draft implementation, and it
must not be scored as an atproto-crates-specific defect.** The reference
`packages/pds/src/api/com/atproto/space/getRecord.ts` destructures `repo` straight from `params` and
calls `ctx.actorStore.read(repo, …)` with no caller-versus-target comparison and no membership
lookup, and its `assertSpaceScope` opens with `if (auth.credentials.type !== 'oauth') return`
(`packages/pds/src/api/com/atproto/space/util.ts:32-37`) — the same OAuth-only gate. The draft
lexicon says as much: `listRecords.json` and `getRecord.json` describe themselves as "Callable with
either OAuth (for the authenticated user's own data) or a space credential", but nothing in the
schema or the reference code constrains `repo` to the authenticated user. This is an open question
in the 0016 draft's read-authorization design, and it should be raised upstream rather than booked
solely against this codebase.

The local evidence is likewise narrower than it first appears. The integration test
`get_record_oauth_with_repo_override` (`crates/atproto-pds/tests/http_phase7_spaces.rs:803-851`)
does perform a cross-account read with an app-password token (`create_account_and_token` returns the
`accessJwt` from `createAccount`, i.e. a `typ=at-pp-access` session JWT, despite the test's name) and
asserts `200 OK` — but the reader is the *space authority* and the target is a member it added
(`:807-814`), which is plausibly intended behaviour. What the test does not do is pin the boundary:
nothing in the code path restricts the override to the authority or to members, so the test locks in
the permissive shape without exercising the abusive case.

The finding stands as a local hardening item regardless of how the draft settles, because worked
references exist on both sides: HappyView enforces membership on every single read via
`service::require_membership` (`src/spaces/service.rs:75-118`) and contrail runs `authorizeRead` plus
`checkAccess` on all four read routes (`packages/contrail-record-host/src/routes.ts:125-195`). An
access-control system whose read path performs no access control for the most common credential type
on the box is worth closing ahead of the spec, and a regression test asserting that a non-member
cross-account read is refused would prevent the shape from being re-locked-in.

**M8 — Cross-PDS space-credential verification is unwired.** `SpaceReader::authority_public_key`
(`reader.rs:236-254`) resolves the authority key only from the local `account` table and returns
`PdsError::NotFound` otherwise. The two functions that would resolve it remotely,
`remote_space_credential_key` and `remote_space_host_endpoint`
(`crates/atproto-pds/src/http/space_auth.rs:301,329`), have no caller anywhere in the workspace.
HappyView does close this loop as a consumer: `credential.rs:277-306` resolves `claims.iss`'s DID
document and selects the verification method whose id ends `#atproto_space`, converting
`publicKeyMultibase` to a JWK by stripping the P-256 multicodec prefix (`credential.rs:312-345`).
Consequence: a member's PDS cannot verify a credential minted by a remote authority, which blocks
the multi-PDS topology 0016 assumes and confines atproto-crates spaces to single-instance
deployments.

**M9 — `com.atproto.simplespace.checkUserAccess` has no server anywhere in the workspace.** The
*calling* half is faithful — `crates/atproto-pds/src/space/mint_authz.rs:400-453` issues a GET with
params `space`, `user`, and optional `clientId`, bearing service auth with `lxm` set to the method
NSID, and parses `{authorized}`, which matches `lex-0016/simplespace/checkUserAccess.json` exactly.
But the draft assigns the server role to the managing app, and the in-repo managing app does not
implement it: `walking-club-appview/src/server.rs:33-67` registers exactly one XRPC route,
`com.atproto.space.notifyWrite` (line 59). Compounding it, `managing_app` is stored as an
unvalidated free string (`crates/atproto-pds/src/space/config.rs:185`) and mint-time resolution goes
through `resolve_service_endpoint` (`space_handlers.rs:1609-1613` calling
`crates/atproto-pds/src/space/recipient.rs:149-171`), which splits the identifier on `#` and resolves
the left half as a DID document — so a bare URL resolves to nothing and falls into the
`403 NotAuthorized` at `space_handlers.rs:1616-1622` before the callback is attempted. HappyView is no better — its `checkUserAccess`
call is outbound-only and breaks three ways against the lexicon (POST instead of GET, `did` instead
of `user`, `granted` instead of `authorized`, at `src/spaces/auth.rs:137-159`) and sends no service
auth at all (comment at `auth.rs:150-152`). Consequence: one of the three documented mint policies
has no end-to-end path, so a space configured `managing-app` silently denies every mint.

**M10 — Lexicon validation of permissioned record values.** The `validate` parameter on
`createRecord` and `putRecord` is declared, marked `#[allow(dead_code)]` (verified at
`space_handlers.rs:722` and `772`), and never read; `validationStatus` is hardcoded absent (line
889). No schema validation is performed on permissioned records under any setting. Neither HappyView
nor contrail validates either, so there is no worked reference among the comparison targets —
contrail instead constrains which *collections* a deployment accepts
(`packages/contrail-record-host/src/adapter.ts:97-110`), and HappyView does the same per space via
`allowedCollections` (`src/spaces/service.rs:57-73`). Consequence: an app can write structurally
invalid records into a permissioned repo and every consumer discovers it at read time, individually.

### PARTIAL

**P1 — `getSpace` serves a fabricated config.** The handler computes `viewer` as the caller's own
DID (`space_handlers.rs:423-428`) and `SpaceService::get_space` opens
`SqlActorStore::open(&self.data_dir, viewer_did)` (`crates/atproto-pds/src/space/service.rs:133`),
but the real config lives in the *authority's* store. A member's store acquires a `space` row on
first write via `INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at) VALUES (?, 0, 0,
?)` (`crates/atproto-pds/src/actor_store/sql/space_repo_storage.rs:40`), which takes
`mint_policy='member-list'` and `app_access='{"type":"open"}'` from the column defaults. So a member
calling `getSpace` receives invented defaults, and a member who has never written gets
`SpaceNotFound`. The handler's own doc comment at lines 423-424 says it should "describe from the
authority's store regardless of which member's credential authorized the read" — code and comment
disagree, and the code is what runs. HappyView reads the authority's row directly
(`src/spaces/routes.rs:461-465`). Consequence: a client cannot discover a space's actual app-access
policy before attempting a mint, and will be told the space is `open` when it is `allowList`.

**P2 — `getBlob`'s `space` parameter is decorative.** The handler gates on `space` and then fetches
by `(repo, cid)` with the space absent from the lookup (`space_handlers.rs:2243`). Combined with M7,
this widens the cross-account read from records to blobs. contrail scopes blobs to the space
explicitly, keying `spaces_blobs` on the space URI and rejecting records that reference blobs never
uploaded to that space (`packages/contrail-record-host/src/routes.ts:224-239`).

**P3 — `registerNotify` cannot register against a remote authority.** The handler opens
`SqlActorStore::open(manager.data_dir(), &space.space_did)` (`space_handlers.rs:2454`) and requires
a local `space` row plus a local authority key (line 2480). The draft permits a repo host to serve
this for a remote authority's space. Consequence, together with M8: the notify fan-out works only
when authority and members share a PDS.

**P4 — Takedown is applied only on the read path.** `com.atproto.admin.takedownSpaceRecord`
(`router.rs:403`) writes rows the reader consults (`crates/atproto-pds/src/space/reader.rs:104` for
the single-record case, `148-167` for listings), but `SpaceSync` never consults
`space_record_takedown` (`crates/atproto-pds/src/space/sync.rs:56-68`), so the create op and its CID
remain visible in the oplog and the element remains folded into the LtHash. Since `listRecords`
returns no values anyway (M3), takedown currently hides nothing from a syncer that follows the
oplog. Stratos's stated rule is the model to adopt here — denied and absent must be indistinguishable
across *every* read surface (`docs/operator/security.md:24`), and Stratos itself shows the failure
mode, having reintroduced a distinguishable `RecordBlocked` on a later-added API
(`features/hydration/handler.ts:166-171`).

**P5 — Space deletion does not gate the oplog and does not revoke.**
`SpaceSync::list_repo_ops` (`sync.rs:56-68`) does not call `ensure_space_live`, unlike its sibling
`get_repo_state` (`sync.rs:46`), so a tombstoned space's oplog stays readable; and
`ensure_space_live` returns `Ok(())` when the authority's actor DB is not local
(`crates/atproto-pds/src/space/config.rs:320-323`), so a member's PDS enforces nothing about a remote
authority's deletion until a best-effort `notifySpaceDeleted` arrives, with no retry in
`fire_notify_space_deleted` (`space_handlers.rs:314-399`). Together with M6, deletion is not a
containment boundary.

**P6 — Unclamped `limit` on both listing methods.** `listRecords` is `unwrap_or(50)` with no clamp
(`space_handlers.rs:1039`) against a lexicon maximum of 100, and `listRepoOps` is `unwrap_or(100)`
with no clamp (line 1330) against a maximum of 1000. A single request can ask for an unbounded page.

**P7 — Expiry checking has no skew allowance and no configured upper bound.** `check_exp`
(`crates/atproto-space/src/credential.rs:255-261`) has no clock-skew tolerance and no
`iat`-in-the-future check, so a client whose clock runs two seconds fast produces a 60-second
delegation token that is briefly unusable, and `space_credential_ttl_secs`
(`crates/atproto-pds/src/http/state.rs:103,150`) is not validated against any maximum, so an operator
can configure an arbitrarily long-lived credential with no revocation to compensate (M6).

### DIVERGENT

**D1 — The `ats://` URI scheme.** `ATS_SCHEME` is `"ats://"` (`crates/atproto-space/src/types.rs:13`,
verified) and `SpaceUri::parse` hard-requires the prefix (line 122). The draft uses ordinary `at://`
URIs with a literal `space` marker segment where a collection NSID would sit —
`at://{authorityDid}/space/{spaceType}/{skey}` — with every lexicon field typed
`"format": "at-uri"`, and the reference `packages/syntax/src/space-uri.ts` giving the disambiguation
rule that a real collection NSID always has at least two dots while the marker has none. atproto-crates
and contrail independently agree on `ats://` (`packages/contrail-base/src/spaces/uri.ts:20-22`,
with a docstring arguing that a distinct scheme prevents confusion "at any layer"), which is a
genuine design argument, but HappyView has already migrated to the draft form and now treats `ats://`
as legacy input it rewrites on the way in (`src/spaces/mod.rs:41-52,67-71`). Consequence: no request
body, no `sub` claim, no commit `ctx`, and no database key lines up with a conformant peer, and the
migration touches everything. `types.rs:5-6` documents the newtypes as abstracted so the scheme "can
change without callers needing to update", which is the right hedge and makes this a bounded change.

**D2 — The commit `ctx` omits the author DID.** `SpaceContext` carries only `space` and `rev`
(`crates/atproto-space/src/commit.rs:58-64`, verified), and `encode_ctx` iterates `[space, rev, ikm]`
(line 76, verified). Both construction sites build the two-field context
(`crates/atproto-pds/src/space/writer.rs:310-313` and `space_handlers.rs:1226-1229`). The lexicon is
unambiguous: `sig` is "Signature over ctx (space, author DID, rev, ikm)"
(`lex-0016/space/defs.json`), the reference `encodeCtx` iterates `[space.space, space.author,
space.rev, ikm]` (`packages/space/src/commit.ts:62-68`, with the byte layout spelled out in the
comment at `:52-60` and matching `0016-README.md:306-310`), and HappyView matches the lexicon with
`tag || space || author || rev || ikm`
(`src/spaces/commit.rs:18-44`, ordering asserted at `commit.rs:158-184`). Two consequences, and both
matter. Wire incompatibility is total, because the ctx byte strings differ in length and content, so
every signature and every MAC fails cross-verification in both directions. And the security property
is weaker: with `author` absent, a signature binds only `(space, rev, ikm)`, which is precisely the
domain separation the reference adds deliberately. This is the cheapest high-value fix on the list —
one field, two call sites.

**D3 — `getRepoState` instead of `getLatestCommit`.** The route at `router.rs:327` (verified) serves
an NSID that appears nowhere in the draft lexicons. Params (`space` + `repo`, both required) and the
output envelope (`{commit?}` with `commit` skipped on an empty repo, `space_handlers.rs:1195-1200`)
both match `lex-0016/space/getLatestCommit.json`; only the name and the missing `ver` (M4) differ.
HappyView routes both names to the same handler (`routes.rs:229,233`), which is the compatible move.

**D4 — The `since` cursor encoding.** `RepoOplogQuery` requires a composite `"<rev>__<idx>"` token
(`space_handlers.rs:1273,1331-1340,1354`) and rejects anything else with a 400; the lexicon describes
`since` as "Return operations after this revision" (`lex-0016/space/listRepoOps.json`). The
regression test `batch_larger_than_limit_pages_fully`
(`crates/atproto-space/src/space_repo.rs:634-680`) demonstrates why: a bare-rev cursor silently drops
the tail of an atomic batch larger than `limit`, because all ops in a batch share a rev. The draft
has this bug latent. atproto-crates is right on the merits and wrong on the wire; the fix that
preserves both is to accept a bare rev as an alias for `(rev, 0)` while continuing to emit the
composite token, and to raise the issue upstream.

**D5 — `mintPolicy` instead of `policy`.** The field is read and written as `mintPolicy` throughout —
`config.rs:206` and `config.rs:260` on the read side, `config.rs:232` on the wire side,
`space_handlers.rs:232` on the input struct (all verified by grep) — while
`lex-0016/simplespace/defs.json` requires the key `policy` and `updateSpace.json` uses the same name.
HappyView has the identical bug and compounds it by stamping
`"$type": "com.atproto.simplespace.defs#spaceConfig"` on an object that does not validate against
the def it names (`src/spaces/simplespace.rs:325-330`), so there is no worked reference among the
targets. Consequence: a draft-conformant client sending `policy` has its value silently ignored and
the space left on its previous policy, which is a silent-failure mode rather than a 400 — the worst
class of config bug.

**D6 — `applyWrites` and `listSpaces` shapes.** `applyWrites` input carries no `repo` and no
`validate`, so its target is always the authenticated subject (`space_handlers.rs:618-625`), and its
output is `{rev, setHash, uris, cids}` rather than the lexicon's `{results: [union]}`. `listSpaces`
takes `filter`/`cursor`/`limit` where the lexicon defines `type`/`did`/`limit`/`cursor`, and its
output has no `cursor` while carrying extra fields. Consequence: a conformant client cannot express a
batch write against a named repo, cannot filter spaces by type or DID, and cannot resume pagination.

**D7 — `getRecord`'s response URI drops the author segment.** The handler builds
`format!("{}/{}/{}", uri, q.collection, q.rkey)` (`space_handlers.rs:962`, verified), producing the
five-segment `ats://did/type/skey/collection/rkey`. That string does not round-trip through
`RecordUri::parse`, which requires exactly six segments (`crates/atproto-space/src/types.rs:231`),
and it disagrees with atproto-crates' *own* writer, which emits the six-segment form
(`crates/atproto-pds/src/space/writer.rs:275-278`). The reference builds
`${space}/${repo}/${collection}/${rkey}` (`packages/pds/src/api/com/atproto/space/getRecord.ts`, the
handler's returned `body.uri`). Separately, the `repo` parameter is optional here
(`space_handlers.rs:905`) where `lex-0016/space/getRecord.json` marks it required.

**D8 — The `client_id` claim on the space credential.** `SpaceCredential` adds a snake_case
`client_id` (`crates/atproto-space/src/credential.rs:96-100`) that the reference
`SpaceCredentialPayload` does not carry (`packages/space/src/credential.ts:21-27` — exactly
`{iss, sub, iat, exp, jti}`), and `register_notify` keys subscriptions on it
(`space_handlers.rs:2499-2502`), falling back to the issuer when absent. HappyView's credential has
no such claim (`src/spaces/credential.rs:155-161`).

*Previously flagged UNVERIFIED; now resolved against the proposal README on disk
(`/tmp/gap-scratch/0016-README.md`).* **The README does not mandate it.** Its space-credential
example payload is `{iss, sub, iat, exp, jti}` (`0016-README.md:233-239`), and its explicit
enumeration of how a space credential differs from a delegation token
(`0016-README.md:219-223`) lists only the `typ` header, the signer, and the absent `aud` — no
`client_id`. The README does use the attested `client_id`, but at the authority's decision points
rather than inside the minted credential: for `#allowList` evaluation (`0016-README.md:586`) and as a
`checkUserAccess` parameter (`:594`). The in-code citation at `credential.rs:96-98` ("spec lines 221,
228") therefore points at prose about the attestation, not at a credential field. So D8 is a genuine
**extension**, not a conformance item, and it is the extension that makes the attested app identity
reusable past the mint. The live risk is the reverse of the one originally posed: because
reference-minted credentials carry no `client_id`, `register_notify` keys every such subscription on
the credential issuer (the space authority) instead of on the subscribing app, collapsing distinct
consumers onto one recipient row. That fallback is at `space_handlers.rs:2499-2502` and wants a test
against a reference-shaped credential.

**D9 — `SpaceNotFound` maps to 400 in the general path and 404 in three handlers.**
`PdsError::SpaceNotFound` becomes HTTP 400 via `crates/atproto-pds/src/http/errors.rs:53-57`, while
`getSpaceCredential`, `listRepos`, and `registerNotify` construct 404s inline
(`space_handlers.rs:1579-1585`, `2357-2363`, `2468-2474`). The error *name* is consistent; the status
code is not, which will confuse status-driven clients. The related `SpaceError` catch-all
(`errors.rs:105-108`) flattens record-exists, record-not-found, member-exists, and every crypto
failure into one 400 whose message includes the internal `error-atproto-space-*` code.

### OUT-OF-SCOPE

**O1 — The member LtHash and member oplog.** `SpaceMembers::format_commit`
(`crates/atproto-space/src/space_members.rs:94-158`) folds member DIDs into a per-space member set
hash persisted in `space_member_state` and writes `space_member_oplog` rows
(`migrations/actor/20260501000001_init.sql:86,131`), and nothing exposes either over XRPC. The draft
has no member commits — `addMember.json` calls the member list "host-internal state … not a synced
protocol structure" — and `crates/atproto-pds/src/space/sync.rs:17-19` says so in a comment. This is
correctly walled off, not a gap. It does impose one cost: `MemberAlreadyExists` on a duplicate add
(`space_members.rs:112-116`) forces `create_space` to guard owner-seeding behind `rows_affected() >
0` (`service.rs:94`) to stay idempotent.

**O2 — `com.atproto.admin.takedownSpaceRecord`.** The draft has no moderation surface for
permissioned records at all. An operator-necessity extension, not a divergence (though see P4 for
its incompleteness).

**O3 — Everything contrail and stratos do differently.** Appview-side record storage, invite tokens,
enrollment-as-consent, membership manifests, group-controlled DIDs, boundary strings, service-held
signing keys, and the stub/hydration split are alternative answers to the same problem, not
capabilities atproto-crates is missing. Two of them are worth *importing* as ideas (P4 cites
stratos's leakage rule; §6 below revisits contrail's enrollment gate), but none is a conformance
item.

**O4 — Two operational hazards that are neither conformance nor design items.**
`resolve_record_auth` does `Box::leak(sub.clone().into_boxed_str())` on every record read
(`space_handlers.rs:1113`, verified), which is an unbounded per-request memory leak on the hottest
space endpoint, reachable by any authenticated caller. And `verify_client_attestation` fetches
`client_id` and then possibly `jwks_uri` (`crates/atproto-pds/src/space/mint_authz.rs:317-343`);
`client_id` is constrained to `https://` (line 268) with a 10-second client timeout, but `jwks_uri`
is taken from the fetched document with no scheme or host restriction.

*Previously flagged UNVERIFIED; now resolved.* **The workspace's SSRF guard does not cover these
fetches.** The guard lives in `crates/atproto-identity/src/host.rs` (added by `18b826f`), and a grep
of the whole of `crates/atproto-pds/src/` for `is_private|loopback|link_local|is_global|ssrf|host::`
returns zero hits. The client the mint path uses is a bare `reqwest::Client::builder()` carrying only
a 10-second timeout and a user-agent (`space_handlers.rs:1554-1558`); nothing consults an allowlist,
rejects private or loopback destinations, or caps redirects. The `https://` check on `client_id`
(`mint_authz.rs:268`) is the only restriction on the whole chain, and it does not apply to
`jwks_uri` at all. This is the same shape the inventory records for the OAuth PAR path, so the fix is
shared: route both through the `atproto-identity` host guard.

## 5. Where atproto-crates leads

**The cryptographic core is correct and, uniquely outside Bluesky's own branch, wired into the
production write path.** LtHash matches the reference byte for byte including the element encoding —
`record_element_bytes` is `format!("{collection}/{rkey}/{cid}").into_bytes()`
(`crates/atproto-space/src/set_hash.rs:167-169`), identical to the reference `formatRecordElement`
(`packages/space/src/util.ts:18-25`, which returns `` `${collection}/${rkey}/${cid}` ``) and to
HappyView's `lthash.rs:75-77` — with geometry pinned by a 65 536-add wraparound test
(`set_hash.rs:243-250`) and a known-answer digest for the empty state (`set_hash.rs:187-198`). And
`SpaceWriter::apply_writes_locked` folds ops into the set hash and calls `create_commit` on the real
write path (`crates/atproto-pds/src/space/writer.rs:335`,
`crates/atproto-space/src/space_repo.rs:127-269`). HappyView's equivalent is imported only by
`src/spaces/integration_tests.rs:11`, `sign_commit` has no production caller, its `lthash_state`
column stays 2048 zero bytes and its oplog table is never written (`src/spaces/oplog.rs:5-30`, no
caller); contrail and stratos have no set hash at all. Record identity is likewise real — DAG-CBOR
plus a CID through `atproto_dasl` (`writer.rs:285-288`) — where HappyView fabricates a `bafyrei`+hex
string from a truncated sha256 of `serde_json` output (`src/spaces/service.rs:26-30`) that is not
multibase-decodable and does not match the RAW-codec CIDs of its own CAR export (`car.rs:65-67`),
and contrail writes `cid: null` on every record (`packages/contrail-record-host/src/routes.ts:248`).
Since the LtHash element is defined over the record CID, an implementation with fake CIDs could not
produce a comparable digest even if it wired the hash in.

**The credential path is the strongest of the four.** The delegation token is signed by the
account's own key (`crates/atproto-pds/src/http/space_auth.rs:74-96`, used at
`space_handlers.rs:1451-1452`), which is what makes it verifiable by a third-party space host;
HappyView signs with the instance's `TOKEN_ENCRYPTION_KEY` (`src/spaces/routes.rs:926`), so its
token proves "HappyView says this member asked", not "this member signed". On receipt, atproto-crates
resolves the issuer's key from the local account table or the issuer's DID document
(`space_auth.rs:107-116,245-291`) and checks `typ`, `kid`, `alg`, the ECDSA signature, `aud`, `sub`,
and `exp` in that order (`crates/atproto-space/src/credential.rs:307-338`). It then consumes the
`jti` through a replay guard sized to the token's remaining lifetime, mapping a collision to
`403 InvalidToken` (`space_handlers.rs:1529-1542`), with memory, SQLite, and Valkey backends
(`crates/atproto-pds/src/security.rs:44-54`) so single-use survives restart. No comparison target has
a `jti` guard. Client attestation is verified end to end and actually gates the mint: `typ`,
`iss == sub`, an https metadata URL, `aud`, expiry, a 300-second lifetime cap, `jti`, then a metadata
fetch, inline `jwks` or `jwks_uri` resolution, `kid` selection, and JWS verification
(`crates/atproto-pds/src/space/mint_authz.rs:229-376`), with the attested `client_id` driving
`#open`/`#allowList` and an outright refusal when an `#allowList` space is approached unattested
(`mint_authz.rs:128-143,136-140`; test at `crates/atproto-pds/tests/http_phase7_spaces.rs:1054`).
HappyView's attestation module is dead code and its allowlist checks a HappyView-issued API key
(`src/spaces/auth.rs:244-259`); contrail's `AppPolicy` keys on a `clientId` no production path
populates (`packages/contrail-base/src/spaces/auth.ts:97-101,142-146`). Signing is also key-agnostic
here — commits go through `atproto_identity::key::KeyData`
(`crates/atproto-space/src/commit.rs:41`) and the JWS `alg` is derived from the key type while
rejecting anything but ES256/ES256K (`credential.rs:150-157`) — where HappyView hardwires secp256k1
(`commit.rs:3,51`), so a P-256 account cannot produce a HappyView commit.

**Sync hygiene and write-path engineering.** `notifyWrite` is contentless
(`crates/atproto-pds/src/space/notify.rs:49-56`) and the receiving handler pins `claims.iss ==
payload.repo` so a PDS cannot deliver on another repo's behalf (`space_handlers.rs:2107-2113`);
HappyView's carries collection, rkey, and CID (`src/spaces/routes.rs:59-65`) and ships an internal
`space_id` UUID a syncer cannot resolve back to a space (`src/spaces/notifications.rs:63-69`). The
`(rev, idx)` oplog cursor is correct where the draft is not, with the tail-drop it prevents pinned by
`batch_larger_than_limit_pages_fully` (`crates/atproto-space/src/space_repo.rs:634-680`). Permissioned
writes provably cannot reach the public firehose: greps for sequencer symbols from space code and for
space symbols from `crates/atproto-pds/src/sequencer/*` both come back empty, and structurally
`apply_writes_locked` ends at `repo.apply_commit(prepared)` plus the outbound notify without ever
building a commit event, a `#commit` frame, or an outbox row (`writer.rs:254-353`). Concurrency is
handled properly — a per-`(member_did, space_uri)` `tokio::Mutex` from a `DashMap`
(`writer.rs:64,95-100,116-117`) with the existence probe *inside* the lock
(`writer.rs:164-182,208-222`) so create-versus-update cannot race, and an idempotent delete
(`writer.rs:222-235`). Finally, takedown and non-existence are already indistinguishable on the
single-record read path, both landing on `404 RecordNotFound`
(`crates/atproto-pds/src/space/reader.rs:104` returning `Ok(None)` into the same branch as a genuine
miss at `space_handlers.rs:947-953`); contrail by contrast returns `403 not-member` and leaks
existence (`packages/contrail-record-host/src/routes.ts:150,189`). P4 is about extending that
discipline to the oplog, not about fixing this path.

## 6. Open questions the draft could resolve, with reclassification thresholds

**If the proposal freezes `at://{did}/space/{type}/{skey}`**, D1 stops being a defensible design
difference and becomes a migration: DIVERGENT reclassifies to MISSING, with HappyView's
`src/spaces/mod.rs:38-114` (parse the new form, rewrite `ats://` on the way in, accept both for a
release) as the worked reference. If the draft instead adopts a distinct scheme — which two of four
implementations independently chose — D1 collapses and HappyView migrated the wrong way.

**If `policy` stays the config key**, D5 reclassifies from DIVERGENT to MISSING, since there is then
no reading under which `mintPolicy` is an alternative spelling rather than an unrecognized field.
HappyView shares the bug, so this wants an upstream issue; the silent-ignore behavior should become a
400 regardless of which name wins.

**If `getRepoState` is adopted upstream as an alias**, D3 is harmless. If not, M2 hardens from a
naming inconvenience into a hard sync blocker, because with `getRepo` also absent (M1) there is then
no conformant route to a repo's current commit hash.

**If `since` is redefined as an opaque cursor**, D4 becomes conformant and the `(rev, idx)` token
becomes the correct reading of the spec. If `since` stays a revision, atproto-crates should accept a
bare rev as `(rev, 0)` and file the batch-tail-drop issue upstream, because that bug will bite the
reference implementation too.

**Settled since this file was drafted: the README does not mandate `client_id` in the credential
payload** (`0016-README.md:219-223`, `:233-239`), so D8 stays an extension rather than becoming a
conformance item, and HappyView is not behind on it. What that leaves open is the inverse:
`register_notify`'s dependency on the claim (`space_handlers.rs:2499-2502`) still needs auditing
against reference-minted credentials, which carry none and therefore fall back to keying every
subscription on the space authority. See D8.

**If the draft adds a read-time membership predicate** — which the reference currently lacks
(`packages/pds/src/api/com/atproto/space/getRecord.ts`, `.../space/util.ts:32-37`) — M7 stops being
defensible inheritance and becomes a spec violation. It should be fixed locally either way: an
OAuth-only scope check plus a verbatim `repo` parameter is a cross-tenant read on a system whose
entire purpose is access control, and both HappyView (`src/spaces/service.rs:75-118`) and contrail
(`packages/contrail-record-host/src/routes.ts:125-195`) show a per-read membership check is
affordable. Because the hole is shared, it is also worth raising against the draft rather than only
patching downstream.

**If the draft adds credential revocation**, M6 becomes a conformance item and HappyView's
`revoked_at` design is the reference. If not, M6 is still worth doing, and it interacts with P5:
without revocation, space deletion is not a containment boundary either. Likewise, **if the draft
specifies a status-code mapping for its error names**, D9 becomes checkable; today only names are
specified, so the 400-versus-404 split is a client-experience defect rather than a conformance one.
