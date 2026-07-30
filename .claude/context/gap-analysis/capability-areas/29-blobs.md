# I. Blobs

*Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
the [synthesis and roadmap](../50-synthesis-and-roadmap.md), and the
[permissioned-data overview](../permissioned/40-permissioned-overview.md).*

## Assessment

Blobs are the one part of a PDS where the protocol deliberately splits work across two moments in
time. `com.atproto.repo.uploadBlob` takes bytes and hands back a reference; the lexicon says plainly
that "the blob will be deleted if it is not referenced within a time window (eg, minutes)" and that
"blob restrictions (mimetype, size, etc) are enforced when the reference is created"
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/repo/uploadBlob.json`). A conforming implementation
therefore needs four things that have nothing to do with storing bytes: an envelope shape clients can
embed verbatim into a record, a record→blob edge table populated when the record lands, a
reference-time check that the record's claim matches what was stored, and a sweeper for everything
never referenced. On top sit three read endpoints — `sync.getBlob`, `sync.listBlobs`,
`repo.listMissingBlobs` — whose contracts carry availability errors and an incremental-sync parameter.

atproto-crates stores bytes correctly and gets content addressing right: CIDv1 / raw `0x55` /
sha2-256, computed server-side from the body so it cannot be forged
(`crates/atproto-pds/src/http/write_handlers.rs:540`, `crates/atproto-pds/src/blob.rs:70`,
`crates/atproto-dasl/src/cid/mod.rs:730-737`). Almost everything layered on top is absent or
mis-shaped. The returned envelope is `{"$link","mimeType","size"}` (`blob.rs:39-49`), matching
neither JSON form the reference lexicon accepts. The ref-counting layer exists, is trait-abstracted
across two backends and is unit tested — and has no production caller, so `repo_blob_ref` is
permanently empty, which makes `listMissingBlobs` always return `{"blobs": []}`, blob GC never run,
and `checkAccountStatus.expectedBlobs` permanently `0`. The public `getBlob` performs no
repo-availability check, sets none of the three headers the reference calls "Important Security
headers", and serves any CID in the account's blob table — including blobs referenced only from a
permissioned space, which the 0016 draft says need a space credential
(`/tmp/gap-scratch/0016-README.md:379`).

The independent field is unkind here, and this is the calibration that matters: **every one of the
ten comparison implementations that serves `uploadBlob` returns the typed
`{"$type":"blob","ref":{"$link":…},"mimeType":…,"size":…}` envelope.** That includes dnproto, a
single-user C# PDS that hardcodes the shape and documents it in a comment
(`/tmp/gap-scratch/dnproto/src/pds/xrpc/ComAtprotoRepo_UploadBlob.cs:85-99`), and metalbear, which
builds it by hand in C with cJSON (`/tmp/gap-scratch/metalbear/src/server.c:5510`). Only arroba does
not, and only because its `uploadBlob` is a deliberate `501`
(`/tmp/gap-scratch/arroba/arroba/xrpc_repo.py:279`). This is the one field in the area where
atproto-crates is alone. The missing `getBlob` security headers are nearly as bad: reference,
metalbear, zds, tranquil, alteran and rsky-pds all set at least the CSP, and metalbear and zds set
all three. Ref-counting is more mixed — reference, rsky-pds, cocoon, pegasus, tranquil, alteran and
zds populate a record→blob table on write, while cirrus, metalbear and dnproto do not — so
atproto-crates is in the minority but not alone. Orphan GC is genuinely rare (reference, rsky-pds,
pegasus, alteran, cocoon-in-DB-mode), so its absence is a stable-gap rather than a blocker.
Conversely, per-record MIME/size verification at reference time is done by exactly two
implementations (reference and rsky-pds), and *nobody at all* enforces the lexicon's `accept` /
`maxSize` blob constraints — the reference's blob validator only checks `instanceof BlobRef`
(`/tmp/gap-scratch/atproto/packages/lexicon/src/validators/blob.ts:12-17`). Do not ding
atproto-crates for the latter two.

Where atproto-crates is ahead: it implements `com.atproto.space.getBlob` from the 0016
permissioned-data draft, with a real space-credential/OAuth read gate and the full set of blob
security headers (`crates/atproto-pds/src/http/space_handlers.rs:2204-2274`). Only zds also ships
that endpoint (`/tmp/gap-scratch/zds/src/atproto/space.zig:45`, routed
`/tmp/gap-scratch/zds/src/http/router.zig:230`). The irony is that zds also closed the companion
hole atproto-crates left open: it keeps a separate `getPublicBlob` that serves only blobs joined to a
*public* record (`/tmp/gap-scratch/zds/src/storage/store.zig:2538-2563`), so a space-only blob is
unreachable over `com.atproto.sync.getBlob`. atproto-crates serves both endpoints from the same
unfiltered `repo_blob` table.

---

## Upload: the envelope (the top RC blocker)

`com.atproto.repo.uploadBlob` is routed at `crates/atproto-pds/src/http/router.rs:67-68` to
`write_handlers::upload_blob` (`http/write_handlers.rs:516`) behind `require_session` (`:521`). The
handler buffers the body, computes the raw CID, `INSERT OR IGNORE`s a row into the per-actor
`repo_blob` table, and returns `UploadBlobResponse { blob: BlobRef }` (`:503-508`, `:549-555`, `:570`).

`BlobRef` serializes as `$link`, `mimeType`, `size` (`crates/atproto-pds/src/blob.rs:39-49`). The
lexicon output type is `blob`, and the reference accepts exactly two encodings, both `.strict()`: the
typed form `{ $type: "blob", ref: <cid-link>, mimeType, size }`
(`/tmp/gap-scratch/atproto/packages/lexicon/src/blob-refs.ts:5-13`) and the legacy two-key
`{ cid, mimeType }` (`:15-21`), unioned at `:23`. atproto-crates' shape has no `$type`, no `ref`
wrapper, and `$link` is a member of neither object, so under `.strict()` it parses as neither. A
client that uploads an image and embeds the result produces a record `@atproto/api` and the reference
validator both reject — and the legacy form is no escape hatch, because `prepareWrite` now throws
`Legacy blobs are not allowed` (`/tmp/gap-scratch/atproto/packages/pds/src/repo/prepare.ts:208-211`).
**CLASS: DIVERGENT.** This is the orchestrator-verified P1 and the highest-value fix in the chapter:
a two-field struct change with no knock-on effects, since nothing else in the codebase reads
`BlobRef` back.

## Upload: size limits, and where the limit actually bites

The declared ceiling is `MAX_BLOB_BYTES = 16 * 1024 * 1024` (`blob.rs:20`), checked on the dispatch
path (`write_handlers.rs:531-539`) and inside `put_blob` (`blob.rs:62-69`). Both return
`PdsError::AuthDenied`, not the lexicon's `BlobTooLarge`.

That check is unreachable. The handler takes `body: axum::body::Bytes` (`write_handlers.rs:519`), and
axum's `Bytes` extractor applies a default 2 MiB request-body limit unless a `DefaultBodyLimit` layer
says otherwise — `const DEFAULT_LIMIT: usize = 2_097_152`
(`~/.cargo/registry/…/axum-core-0.5.6/src/ext_traits/request.rs:319`, applied in the no-override
branch at `:326`, reached from the `Bytes` extractor at
`axum-core-0.5.6/src/extract/request_parts.rs:100-108`, whose `from_request` calls
`into_limited_body()`). A repo-wide grep for `DefaultBodyLimit`,
`RequestBodyLimitLayer` and `.layer(` across `crates/atproto-pds/src/` returns only the two metrics
layers at `http/router.rs:446-447`. The effective ceiling is therefore 2 MiB and a 3 MiB upload fails
with axum's plain-text `413`, not an XRPC error. This *corrects* the UNVERIFIED note at
`inv/storage.md:343` in both directions: the 1 GiB buffering concern does not materialise, but the
documented 16 MiB ceiling is dead code. **CLASS: DIVERGENT.**

The limit is also not configurable. Every serious comparison exposes a knob — the reference's
`PDS_BLOB_UPLOAD_LIMIT`, default 5 MB
(`/tmp/gap-scratch/atproto/packages/pds/src/config/config.ts:40`, `env.ts:19`); rsky-pds' identically
named variable; metalbear's `blob_upload_limit`, default 5 MB
(`/tmp/gap-scratch/metalbear/config.example.toml:69`, enforced `src/server.c:5472-5477`); zds'
`ZDS_BLOB_UPLOAD_LIMIT`; tranquil's `server.max_blob_size`; alteran's `PDS_MAX_BLOB_SIZE`. Cocoon and
pegasus have no cap at all, so atproto-crates is not last — but a hardcoded constant the framework
silently overrides is worse than either. **CLASS: MISSING.** There is no per-account quota either;
alteran, a hobby-experiment Workers PDS, enforces one (`/tmp/gap-scratch/alteran/src/db/blob.ts:42`).

## Upload: MIME handling

The MIME type is read verbatim from `Content-Type`, defaulting to `application/octet-stream`
(`write_handlers.rs:522-527`), stored as given, and echoed into the `Content-Type` of every `getBlob`
response (`crates/atproto-pds/src/http/blob_handlers.rs:66-70`). No sniffing, no allowlist, no
cross-check.

Sniffing is close to universal, and in several implementations the sniffed value deliberately *wins*:
the reference computes it concurrently with the hash and prefers it
(`/tmp/gap-scratch/atproto/packages/pds/src/actor-store/blob/transactor.ts:61-72`); rsky-pds uses
`infer` (`/tmp/gap-scratch/rsky/rsky-pds/src/actor_store/blob/mod.rs:130-145`); tranquil sniffs the
first 8 KiB (`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/repo/blob.rs:26-31,122-126`);
cirrus sniffs and uses the sniffed type for its scope check specifically to defeat spoofing
(`/tmp/gap-scratch/cirrus/packages/pds/src/xrpc/repo.ts:628-642`, size cap `:643-654`); pegasus falls
back to a sniffer (`/tmp/gap-scratch/pegasus/pegasus/lib/api/repo/uploadBlob.ml:7-13`); even dnproto
has hand-rolled magic-byte checks (`ComAtprotoRepo_UploadBlob.cs:52-55,105-130`). Cocoon and metalbear
take the header verbatim, as atproto-crates does. **CLASS: PARTIAL** — a stable-gap alone, a security
issue combined with the missing response headers below.

## Reference-time constraint enforcement

There is no reference-time hook at all: `crates/atproto-pds/src/repo/writer.rs` contains no blob
logic, its only "blob" match being the `signature_blob` column at `:393`. Nothing walks a record
value for blob refs, so nothing can compare the record's declared `mimeType`/`size` against the
stored row the way the reference's `verifyBlob`
(`/tmp/gap-scratch/atproto/packages/pds/src/actor-store/blob/transactor.ts:356-372`, raising
`InvalidMimeType`/`InvalidSize`) or rsky-pds' port
(`/tmp/gap-scratch/rsky/rsky-pds/src/actor_store/blob/mod.rs:333,548-559`) do. Those two are the only
implementations in the field that do this, so **CLASS: MISSING, severity stable-gap.** Note
explicitly that nobody, reference included, enforces the lexicon's `accept`/`maxSize` constraints
(`/tmp/gap-scratch/atproto/packages/lexicon/src/validators/blob.ts:12-17`).

## Ref-counting: built, tested, never wired

This is the structural failure of the area. The trait declares `add_ref`, `drop_refs_for_record` and
`delete_blob` (`crates/atproto-pds/src/actor_store/traits.rs:249-259`); the SQL backend implements
them (`actor_store/sql/public_realm.rs:452-514`), the fjall backend implements them
(`actor_store/fjall/public_realm.rs:560-600`), free functions exist (`blob.rs:115-174`), and orphan
reclamation is unit tested (`blob.rs:320-335`, `sql/public_realm.rs:822-833`,
`fjall/public_realm.rs:1095-1135`). A grep for `add_ref|drop_refs_for_record|drop_record_refs` across
`crates/atproto-pds/src` and `tests` returns only those declarations, implementations, the S3
delegations (`blob_s3.rs:169-175`) and the tests. No handler, writer or import path calls them.
**CLASS: MISSING.** Four consequences follow mechanically, all user-visible:

1. `listMissingBlobs` is correctly shaped and paginated (`write_handlers.rs:417-501`; `MissingBlob`
   carries `cid` + `recordUri` per `#recordBlob`; limits clamped to `[1,1000]` at `blob.rs:214` and
   `sql/public_realm.rs:552`) and always returns `{"blobs": []}`, left-joining from an empty table.
2. `checkAccountStatus` computes `expectedBlobs` as `COUNT(DISTINCT blob_cid) FROM repo_blob_ref`
   (`http/auth_handlers.rs:791-794`) — permanently `0` — while `importedBlobs` counts `repo_blob`
   (`:795-798`). A migration tool comparing the two concludes the transfer succeeded regardless.
3. Deleting a record never dereferences its blobs, and `crates/atproto-pds/src/gc.rs` never touches
   `repo_blob`. Blob storage grows monotonically.
4. `getBlob` cannot distinguish a referenced blob from an untethered upload, which feeds the
   access-control finding below.

Compare: the reference runs `deleteDereferencedBlobs` synchronously with the write and schedules
object deletes on commit (`blob/transactor.ts:187-240`); pegasus diffs removed refs and unlinks files
in the same transaction (`/tmp/gap-scratch/pegasus/pegasus/lib/repository.ml:327-341`,
`user_store.ml:279-305`); cocoon increments/decrements `blobs.ref_count` and hard-deletes at zero
(`/tmp/gap-scratch/cocoon/server/repo.go:518-522,687-715`); alteran writes `blob_usage` rows in the
same D1 batch and sweeps opportunistically (`/tmp/gap-scratch/alteran/src/db/dal.ts:96,204-230`,
`src/db/blob.ts:166`). tranquil and zds populate the edge table but never sweep
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/scheduled.rs:690-745` is the only delete path;
`/tmp/gap-scratch/zds/src/storage/blobstore.zig:29` has no caller). cirrus, metalbear and dnproto do
neither.

## Temp staging

There is no untethered stage: bytes land in permanent `repo_blob` rows on upload (`blob.rs:74-87`),
no `temp_blob` table exists in any migration, and no TTL sweep runs. The lexicon's "deleted if it is
not referenced within a time window" is unimplemented, so any authenticated account can park
unbounded unreferenced blobs. The reference stages via `putTemp`/`makePermanent` with separate `tmp`
and `quarantine` trees (`/tmp/gap-scratch/atproto/packages/pds/src/disk-blobstore.ts:31-33,75,82`);
tranquil copies `temp_key` → `storage_key` and cleans up on failure
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/repo/blob.rs:171-182`); rsky-pds promotes
from a temp key (`blob/mod.rs:130-145`). Cocoon, metalbear, pegasus, cirrus, alteran, zds and dnproto
also store immediately. **CLASS: MISSING, severity stable-gap** — most of the field is here too.

## `com.atproto.sync.getBlob`

Routed unauthenticated at `http/router.rs:89`, handled at `http/blob_handlers.rs:33-72`. Public
access is correct per the lexicon. Three things are wrong with it.

**No availability gate.** The lexicon declares `BlobNotFound`, `RepoNotFound`, `RepoTakendown`,
`RepoSuspended` and `RepoDeactivated`; the handler can only emit the first (`blob_handlers.rs:58-64`).
There is no account lookup — it goes straight to `SqlActorStore::open(manager.data_dir(), &q.did)`
(`:51`). The reference calls `assertRepoAvailability` first
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/sync/getBlob.ts:20`, helper
`sync/util.ts:6-36`); tranquil calls `assert_repo_availability` on every public sync read including
blobs (`crates/tranquil-pds/src/sync/util.rs:131-182`, sites `sync/blob.rs:31,84`); rsky-pds does the
same (`apis/com/atproto/sync/get_blob.rs:32`); zds gates with `requirePublicRepoAvailable`
(`src/atproto/sync.zig:181,252`); cocoon refuses deactivated repos
(`server/handle_sync_get_blob.go:44-49`). This is *majority* behaviour among the serious field, not a
reference-only nicety. It also has a resource consequence: `SqlActorStore::open` runs `create_dir_all`
and `create_if_missing(true)` and applies migrations
(`crates/atproto-pds/src/actor_store/sql/store.rs:55-95`), so an unauthenticated request with an
arbitrary `did` materialises a fresh migrated SQLite file (filename is `sha256(did)`, so no traversal
— `store.rs:21-26`). With no per-IP or per-route limiting on the sync surface (orchestrator-verified
finding R1), that is
an unauthenticated disk-fill primitive. **CLASS: MISSING, severity rc-blocker (security + spec).**

**No security headers.** The response sets only `Content-Type`, from the unvalidated stored MIME
(`blob_handlers.rs:65-70`). The reference sets `x-content-type-options: nosniff`,
`content-disposition: attachment; filename="<cid>"` and `content-security-policy: default-src 'none';
sandbox`, with comments explaining the purpose is to stop an uploaded HTML blob executing on the PDS
origin (`sync/getBlob.ts:39-53`). metalbear sets all three
(`/tmp/gap-scratch/metalbear/src/server.c:5566-5595`); zds sets all three
(`/tmp/gap-scratch/zds/src/atproto/sync.zig:189-191`); tranquil sets nosniff + CSP
(`crates/tranquil-sync/src/blob.rs:45-46`); alteran sets nosniff + CSP
(`/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.sync.getBlob.ts:71-72`); rsky-pds sets CSP plus
a global `NoSniff` shield (`apis/com/atproto/sync/get_blob.rs:76`,
`/tmp/gap-scratch/rsky/rsky-pds/src/lib.rs:309`). atproto-crates already writes exactly these three on
its own `com.atproto.space.getBlob` (`http/space_handlers.rs:2262-2274`), so the omission is an
oversight, not a position. Since the PDS origin also hosts the OAuth consent screen and session
cookies, stored XSS from an uploaded blob is a real chain. **CLASS: MISSING, severity rc-blocker
(security).**

**Serves permissioned blobs.** `sync.getBlob` reads the same per-actor `repo_blob` table
(`blob_handlers.rs:37-57`) that `space.getBlob` reads (`space_handlers.rs:2232-2245`) — there is no
separate space blobstore in the crate. A blob uploaded for a permissioned space is fetchable by anyone
with the DID and CID, and the CID comes from the unauthenticated `sync.listBlobs`, which lists every
row in `repo_blob` regardless of references (`blob.rs:178-203`). 0016 states such blobs "are stored on
the authoring repo's host and fetched via `com.atproto.space.getBlob` with the relevant space
credential" (`/tmp/gap-scratch/0016-README.md:379`), and the draft lexicon gives that endpoint its own
error set (`/tmp/gap-scratch/lex-0016/space/getBlob.json`). zds — the only other 0016 implementation —
closes exactly this hole with `getPublicBlob` requiring a join through `expected_blobs` to a public
`records` row (`/tmp/gap-scratch/zds/src/storage/store.zig:2538-2563`), and its public `listBlobs`
joins the same way (`:2566-2592`). **CLASS: DIVERGENT, severity rc-blocker (security).** See
[the permissioned-data overview](../permissioned/40-permissioned-overview.md).

## `com.atproto.sync.listBlobs`

Routed at `http/router.rs:93`, handled at `blob_handlers.rs:96-123`. `ListBlobsQuery` models only
`did`, `cursor` and `limit` (`:76-83`) — the lexicon's `since` (format `tid`) is absent, so
incremental blob sync is impossible and a mirroring relay re-enumerates everything on every pass. The
reference filters by joining `record_blob` to `record.repoRev > since`
(`/tmp/gap-scratch/atproto/packages/pds/src/actor-store/blob/reader.ts:63-67`); tranquil has
`list_blobs_since_rev` (`crates/tranquil-sync/src/blob.rs:95-99`); rsky-pds threads it through
(`sync/list_blobs.rs:38,68`); pegasus passes it to the store
(`/tmp/gap-scratch/pegasus/pegasus/lib/api/sync/listBlobs.ml:17`); alteran validates it as a TID and
applies it (`src/pages/xrpc/com.atproto.sync.listBlobs.ts:18,24,33`); zds filters on `r.rev > ?`
(`store.zig:2572-2592`). Ignoring it is common enough — cocoon has a literal `// TODO: add tid param`
(`/tmp/gap-scratch/cocoon/server/handle_sync_list_blobs.go:25`), metalbear documents that its store
has no per-blob revisions (`src/server.c:2829-2831`), cirrus and dnproto ignore it — so this is a
**stable-gap, CLASS: MISSING**, not a blocker.

Two smaller divergences. The reference enumerates *record-referenced* blobs (`reader.ts:57-62`);
atproto-crates enumerates *stored* blobs, so untethered uploads appear in the sync listing —
**CLASS: DIVERGENT, cosmetic in isolation**, but it is the mechanism behind the permissioned-blob
leak. And the cursor is set to the last CID unconditionally (`blob_handlers.rs:121`) even on a short
page, so a client always makes one extra empty request; pegasus emits a cursor only when the page is
full (`listBlobs.ml:19-20`). **CLASS: DIVERGENT, cosmetic.**

## Storage backends

The default is bytes-in-SQLite: `repo_blob(cid, mime_type, size, data BLOB, created_at)` in the
per-actor database (`crates/atproto-pds/migrations/actor/20260504000001_blobs.sql:12-20`, rationale
`:7-10`), with a fjall keyspace as the alternative. `HybridS3BlobStorage` is a complete `BlobStorage`
implementation (`crates/atproto-pds/src/blob_s3.rs:107-175`) that is unreachable at runtime: the CLI
flag is declared with a doc comment promising it "uses an AWS-SDK-backed `S3BlobStore` instead of the
per-actor SQLite blob tables" (`crates/atproto-pds/src/bin/pds.rs:316-322`), `blob_store_url` appears
nowhere else in `crates/atproto-pds/src`, the type's only non-doc references are in
`crates/atproto-pds/tests/feature_s3.rs`, and `crates/atproto-pds/README.md:122` advertises the
feature. **CLASS: DIVERGENT (documented capability absent at runtime), severity stable-gap.** For
context the reference offers disk or S3 (`config.ts:63-91`), rsky-pds disk or S3, tranquil filesystem
or S3, cocoon DB-chunks or S3 with a CDN 302, pegasus disk or S3 with a `migrate-blobs` command,
cirrus and alteran R2, and metalbear/zds/dnproto flat files. Bytes-in-SQLite is a defensible default;
a flag that silently does nothing is not.

## Takedown, moderation, and the `blob:` scope

Blob-level takedown is unreachable: `com.atproto.admin.updateSubjectStatus` reads `{did, state}`
rather than the lexicon's `subject` union, so `#repoBlobRef` cannot be addressed
(`crates/atproto-pds/src/admin/handlers.rs:156-162`, `:212-218`; see
[moderation and admin](./30-moderation-admin.md)), and there is no quarantine concept or
`takedownRef` column on `repo_blob`. The reference quarantines the object and filters takedowns out of
`getBlobMetadata` (`blob/transactor.ts:160-184`, `reader.ts:20-28`); tranquil implements
`update_blob_takedown` (`crates/tranquil-api/src/admin/status.rs:291-299`); rsky-pds filters
`takedownRef IS NULL` on read (`blob/mod.rs:91,107-115`). metalbear has the table but never consults
it; cocoon, pegasus, cirrus, alteran, zds and dnproto have no blob takedown. **CLASS: MISSING,
severity stable-gap.**

The OAuth `blob:` scope is parsed with full MIME-pattern support
(`crates/atproto-oauth/src/scopes.rs:433,688-702`) and never asserted — `ScopesSet` exposes space
assertions only, with no `assert_blob` (`inv/auth.md` §4), and `upload_blob` gates on
`require_session` alone (`write_handlers.rs:521`). The reference asserts it on the request encoding
(`repo/uploadBlob.ts:14-17`), as do tranquil (`repo/blob.rs:62-64`), pegasus (`uploadBlob.ml:14`), zds
(`/tmp/gap-scratch/zds/src/atproto/repo.zig:428-430`) and cirrus (against the *sniffed* type,
`xrpc/repo.ts:628-642`). But cocoon — with a complete OAuth 2.1 AS — parses `blob:` and enforces only
`repo:` (`/tmp/gap-scratch/cocoon/oauth/scopes/parser.go:212` vs
`/tmp/gap-scratch/cocoon/server/scope_enforcement.go:29-54`), and rsky-pds, metalbear, alteran and
dnproto do not model granular scopes at all. **CLASS: MISSING, severity stable-gap** — mid-field, not
behind it.

## Endpoint conformance summary

| Endpoint | Routed | Auth | Shape | Notes |
| --- | --- | --- | --- | --- |
| `com.atproto.repo.uploadBlob` | `router.rs:67` | `require_session` | **wrong** | envelope matches neither accepted form (`blob.rs:39-49`) |
| `com.atproto.repo.listMissingBlobs` | `router.rs:63` | `require_session` | correct | always empty — `repo_blob_ref` never written |
| `com.atproto.sync.getBlob` | `router.rs:89` | none (correct) | correct | no availability gate, no security headers, serves space blobs |
| `com.atproto.sync.listBlobs` | `router.rs:93` | none (correct) | correct | `since` unmodelled; lists untethered blobs; always emits a cursor |
| `com.atproto.space.getBlob` | `router.rs:319` | space read auth | correct | ahead of the field; full security headers (`space_handlers.rs:2262-2274`) |

---


## Findings

**B1 — `uploadBlob` returns a blob envelope matching no accepted form.** CLASS: DIVERGENT ·
severity **rc-blocker**. `crates/atproto-pds/src/blob.rs:39-49` (used at
`http/write_handlers.rs:507,549-555,570`) emits `{$link,mimeType,size}`; the lexicon output type is
`blob`, whose only two accepted JSON forms are both `.strict()`
(`/tmp/gap-scratch/atproto/packages/lexicon/src/blob-refs.ts:5-13,15-21,23`). All ten comparisons
that serve `uploadBlob` emit the typed form — dnproto `ComAtprotoRepo_UploadBlob.cs:85-99`, metalbear
`server.c:5510`, cocoon `handle_repo_upload_blob.go:23-31,143-146`, pegasus `uploadBlob.ml:21-24`,
zds `repo.zig:550-551`, tranquil `repo/blob.rs:207-212`. Consequence: a client that embeds the
returned object into a record produces a record the reference validator rejects, so media upload is
broken against the bsky app and `@atproto/api`; the legacy encoding is no fallback because the
reference now rejects it at write time (`packages/pds/src/repo/prepare.ts:208-211`).

**B2 — record→blob ref tracking is implemented and tested but never invoked.** CLASS: MISSING ·
severity **rc-blocker**. Trait `actor_store/traits.rs:249-259`, impls
`actor_store/sql/public_realm.rs:452-514` and `actor_store/fjall/public_realm.rs:560-600`, free
functions `blob.rs:115-174`, unit tests `blob.rs:320-335` — and no production caller anywhere in
`crates/atproto-pds/src` or `tests`; `repo/writer.rs` has no blob logic. Comparison: reference
`blob/transactor.ts:187-240,301-317`; rsky-pds `blob/mod.rs:201-222,240-313`; cocoon
`repo.go:518-522,687-715`; pegasus `repository.ml:327-341`; alteran `db/dal.ts:204-230`; zds
`store.zig:2058,2074`; tranquil `migrations/20251243_record_blobs.sql`. Consequence:
`listMissingBlobs` is permanently `{"blobs": []}` so the migration loop documented at
`repo/import.rs:5-6` cannot complete; `checkAccountStatus.expectedBlobs` is permanently `0`
(`http/auth_handlers.rs:791-794`) so a migration verifier reports false success; deleted records
never release their blobs.

**B3 — blobs referenced only from a permissioned space are served unauthenticated.** CLASS:
DIVERGENT · severity **rc-blocker (security)**. `http/blob_handlers.rs:33-72` and `:96-123` are
ungated and read the same per-actor `repo_blob` table as the space-gated
`http/space_handlers.rs:2232-2245`; `blob.rs:178-203` lists every stored CID. 0016 states these
blobs are fetched "via `com.atproto.space.getBlob` with the relevant space credential"
(`/tmp/gap-scratch/0016-README.md:379`, lexicon `/tmp/gap-scratch/lex-0016/space/getBlob.json`). zds,
the only other 0016 implementation, keeps a separate `getPublicBlob` requiring a join to a public
record (`/tmp/gap-scratch/zds/src/storage/store.zig:2538-2563`) and joins the same way in its public
`listBlobs` (`:2566-2592`). Consequence: `listBlobs(did)` → every CID → `getBlob(did, cid)` is a
complete unauthenticated read path for data the space-credential system exists to protect.

**B4 — `getBlob`/`listBlobs` have no repo-availability gate and open per-DID stores on demand.**
CLASS: MISSING · severity **rc-blocker (security + spec)**. `blob_handlers.rs:44-57` and `:107-120`
go straight to `SqlActorStore::open`, which runs `create_dir_all` + `create_if_missing(true)` +
migrations (`actor_store/sql/store.rs:55-95`; same via `open_pool`, `sql/public_realm.rs:29-31`).
Both lexicons declare `RepoNotFound`/`RepoTakendown`/`RepoSuspended`/`RepoDeactivated`; only
`BlobNotFound` is reachable. Comparison: reference `sync/getBlob.ts:20` + `sync/util.ts:6-36`;
tranquil `sync/util.rs:131-182` from `sync/blob.rs:31,84`; rsky-pds `sync/get_blob.rs:32`; zds
`sync.zig:181,252`; cocoon `handle_sync_get_blob.go:44-49`. Consequence: taken-down and deactivated
accounts keep serving blobs, and any unauthenticated caller can materialise unbounded migrated
SQLite files by varying `did`, with no per-IP limiting anywhere on the sync surface.

**B5 — `getBlob` omits `nosniff`, `content-disposition` and CSP.** CLASS: MISSING · severity
**rc-blocker (security)**. `http/blob_handlers.rs:65-70` sets only `Content-Type`, echoing the
unvalidated client-declared MIME from `write_handlers.rs:522-527`. Comparison: reference
`sync/getBlob.ts:44,50,53` (comments name the XSS risk); metalbear `server.c:5566-5595`; zds
`sync.zig:189-191`; tranquil `tranquil-sync/src/blob.rs:45-46`; alteran
`com.atproto.sync.getBlob.ts:71-72`; rsky-pds `sync/get_blob.rs:76` plus `lib.rs:309`.
atproto-crates already sets all three on `space.getBlob` (`space_handlers.rs:2262-2274`).
Consequence: an uploaded `text/html` blob renders as a document on the origin that also serves the
OAuth consent screen and session cookies.

**B6 — the 16 MiB upload ceiling is dead code; the real limit is axum's 2 MiB default.** CLASS:
DIVERGENT · severity **rc-blocker**. `MAX_BLOB_BYTES` (`blob.rs:20`) is checked at
`write_handlers.rs:531-539` and `blob.rs:62-69`, but the handler extracts `axum::body::Bytes`
(`write_handlers.rs:519`) and axum-core applies `DEFAULT_LIMIT = 2_097_152`
(`axum-core-0.5.6/src/ext_traits/request.rs:319,326`; `Bytes` extractor
`axum-core-0.5.6/src/extract/request_parts.rs:100-108`) because no
`DefaultBodyLimit` layer exists in the crate — the only layers are the metrics pair at
`http/router.rs:446-447`. Versions per `Cargo.lock:1074-1076,1111-1113`. Comparison: reference
default 5 MB via `PDS_BLOB_UPLOAD_LIMIT` (`config.ts:40`, `env.ts:19`). Consequence: a typical phone
photo fails with a plain-text `413` that is not an XRPC error body, and the rejection is invisible in
source that documents 16 MiB. This corrects `inv/storage.md:343` in both directions.

**B7 — no operator-tunable blob size limit and no per-account quota.** CLASS: MISSING · severity
**stable-gap**. `MAX_BLOB_BYTES` is a `const` (`blob.rs:20`) and `bin/pds.rs` exposes no blob knob
beyond the non-functional `blob_store_url`. Comparison: `PDS_BLOB_UPLOAD_LIMIT` (reference,
rsky-pds), `blob_upload_limit` (metalbear, `config.example.toml:69`), `ZDS_BLOB_UPLOAD_LIMIT`,
`server.max_blob_size` (tranquil), `PDS_MAX_BLOB_SIZE` plus a per-DID quota (alteran,
`src/db/blob.ts:42`). Consequence: operators cannot raise the ceiling for video nor lower it for
abuse control, and one account can consume unbounded disk.

**B8 — MIME is trusted from the client header, never sniffed.** CLASS: PARTIAL · severity
**stable-gap** (security-relevant in combination with B5). `write_handlers.rs:522-527` reads the
header, `blob.rs:74-87` stores it, `blob_handlers.rs:66-70` echoes it. Comparison: sniffing in
reference (`blob/transactor.ts:61-72`, sniffed wins), rsky-pds (`blob/mod.rs:130-145`), tranquil
(`repo/blob.rs:26-31,122-126`), cirrus (`xrpc/repo.ts:628-642`), alteran (`src/lib/util.ts:121-164`),
dnproto (`ComAtprotoRepo_UploadBlob.cs:105-130`); cocoon and metalbear also trust the header.
Consequence: the type AppViews act on is attacker-chosen.

**B9 — `PDS_BLOB_STORE_URL` is documented and advertised but never read.** CLASS: DIVERGENT ·
severity **stable-gap**. Declared with a behavioural doc comment at `bin/pds.rs:316-322`;
`blob_store_url` has no other occurrence in `crates/atproto-pds/src`; `HybridS3BlobStorage`
(`blob_s3.rs:44-175`) is referenced only from `tests/feature_s3.rs`; advertised at
`crates/atproto-pds/README.md:122`. Comparison: the reference treats the equivalent config as
load-bearing and errors when both backends are set (`config.ts:64-66`). Consequence: an operator who
sets the variable silently gets bytes-in-SQLite.

**B10 — no temp/untethered stage and no orphan-blob sweep.** CLASS: MISSING · severity
**stable-gap**. `blob.rs:74-87` writes permanent rows; there is no temp table in
`crates/atproto-pds/migrations/actor/`; `gc.rs` never mentions blobs. Comparison: reference
`putTemp`/`makePermanent` plus a quarantine tree (`disk-blobstore.ts:31-33,75,82`), tranquil
`repo/blob.rs:171-182`, rsky-pds `blob/mod.rs:130-145`; most of the independent field also stores
immediately. Consequence: the lexicon's "deleted if not referenced within a time window" is
unimplemented and unreferenced uploads accumulate without bound.

**B11 — `listBlobs` does not model `since`.** CLASS: MISSING · severity **stable-gap**.
`ListBlobsQuery` (`blob_handlers.rs:76-83`) has `did`/`cursor`/`limit` only; the lexicon declares
`since` as a `tid`. Comparison: honoured by reference (`reader.ts:63-67`), tranquil
(`sync/blob.rs:95-99`), rsky-pds (`sync/list_blobs.rs:38,68`), pegasus (`listBlobs.ml:17`), alteran
(`com.atproto.sync.listBlobs.ts:18,24,33`), zds (`store.zig:2572-2592`); ignored by cocoon
(`handle_sync_list_blobs.go:25`), metalbear (`server.c:2829-2831`), cirrus and dnproto. Consequence:
mirrors re-enumerate the full blob set on every pass.

**B12 — `listBlobs` enumerates stored blobs rather than record-referenced ones.** CLASS: DIVERGENT ·
severity **cosmetic in isolation** (it is the mechanism behind B3). `blob.rs:178-203` selects from
`repo_blob`; the reference selects from `record_blob` (`reader.ts:57-62`) and zds joins
`expected_blobs` → `records` (`store.zig:2566-2592`). Consequence: untethered uploads are advertised
to sync consumers as part of the repo.

**B13 — `listBlobs` always returns a cursor, including on the final page.** CLASS: DIVERGENT ·
severity **cosmetic**. `blob_handlers.rs:121` sets `cursor = cids.last()` unconditionally; pegasus
emits one only when the page is full (`listBlobs.ml:19-20`). Consequence: one wasted round trip per
enumeration; correct clients still terminate.

**B14 — reference-time MIME/size verification is absent.** CLASS: MISSING · severity **stable-gap**.
`repo/writer.rs` has no blob logic (only `signature_blob` at `:393`). Only two implementations in the
whole field do this — reference `verifyBlob` (`blob/transactor.ts:356-372`) and rsky-pds
(`blob/mod.rs:333,548-559`) — and nobody, reference included, enforces the lexicon's
`accept`/`maxSize` (`packages/lexicon/src/validators/blob.ts:12-17`). Consequence: a record may
claim a mimeType/size that does not match the stored blob.

**B15 — blob-level takedown is unaddressable.** CLASS: MISSING · severity **stable-gap**.
`admin/handlers.rs:156-162,212-218` speak `{did, state}` instead of the lexicon `subject` union, and
`repo_blob` has no `takedownRef` column (`migrations/actor/20260504000001_blobs.sql:12-20`).
Comparison: reference quarantine (`blob/transactor.ts:160-184`, `reader.ts:20-28`), tranquil
(`admin/status.rs:291-299`), rsky-pds (`blob/mod.rs:91,107-115`); most others have none either.
Consequence: an operator cannot remove one illegal blob without deleting the account. See
[moderation and admin](./30-moderation-admin.md).

**B16 — the OAuth `blob:` scope is parsed but never enforced.** CLASS: MISSING · severity
**stable-gap**. `crates/atproto-oauth/src/scopes.rs:433,688-702` parses it; `upload_blob` gates on
`require_session` alone (`write_handlers.rs:521`) and no `assert_blob` exists (`inv/auth.md` §4).
Enforced by reference (`repo/uploadBlob.ts:14-17`), tranquil (`repo/blob.rs:62-64`), pegasus
(`uploadBlob.ml:14`), zds (`repo.zig:428-430`) and cirrus (`xrpc/repo.ts:628-642`); *not* enforced by
cocoon (`scope_enforcement.go:29-54`), rsky-pds, metalbear, alteran or dnproto. Consequence: a token
scoped `blob:image/*` can upload anything. Middle-of-the-field, not a blocker.

### Severity roll-up

| Severity | Findings |
| --- | --- |
| rc-blocker | B1, B2, B3, B4, B5, B6 |
| stable-gap | B7, B8, B9, B10, B11, B14, B15, B16 |
| cosmetic | B12, B13 |

Three of the six rc-blockers are security findings (B3, B4, B5) and three are interop/functional
(B1, B2, B6). B1 and B5 are each a few lines; B3 and B4 share one helper (an account lookup plus a
reference join); B6 is a single layer. B2 is the only one needing real work — a blob-ref walker in
the write path, which is also the precondition for B10 and B14.

## Confidence & unknowns

High confidence on everything asserted about atproto-crates: every blob-touching file in
`crates/atproto-pds` was opened directly (`blob.rs`, `blob_s3.rs`, `http/blob_handlers.rs`, the
`uploadBlob`/`listMissingBlobs` handlers in `http/write_handlers.rs`, `actor_store/sql/public_realm.rs`,
`actor_store/sql/store.rs`, the routing table, and the space `getBlob` handler), and the negative
claims (no caller for `add_ref`, no blob logic in `repo/writer.rs`, no blob GC in `gc.rs`, no
`DefaultBodyLimit`, `blob_store_url` unused) are each grep-verified across `crates/atproto-pds/src`
and `crates/atproto-pds/tests`.

The axum body-limit finding (B6) is verified from the vendored axum-core 0.5.6 source and the
lockfile, not from a running server. If a reverse proxy in front of the PDS imposes its own limit the
observable behaviour changes, but the 2 MiB extractor limit applies regardless of what is upstream.
I did not exercise an actual >2 MiB upload.

Comparison cells for the reference, metalbear, zds, cocoon, tranquil, pegasus, dnproto, alteran,
cirrus and rsky-pds on the load-bearing rows (envelope shape, security headers, availability gate,
`since`, ref-counting) were re-opened in source rather than taken from the impl notes. arroba's blob
story is taken from its impl note plus the `501` stub line; I did not read its Datastore blob model
in full, so its remote-blob validation details are second-hand.

Unverified: whether atproto-crates' fjall `FjallBlobStorage::list_all_cids` has the same "lists
untethered blobs" semantics as the SQL path (I read the SQL path and the trait, and the fjall impl's
ref functions, but not its listing query end to end) — the finding does not depend on it, since the
SQL path is the default. Also unverified: whether any deployment documentation outside
`crates/atproto-pds/README.md:122` promises S3 blob storage.
