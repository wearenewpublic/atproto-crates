# C. Record operations — `com.atproto.repo.*`, optimistic concurrency, and lexicon validation

Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
the [synthesis and roadmap](../50-synthesis-and-roadmap.md), and the
[permissioned-data overview](../permissioned/40-permissioned-overview.md). Per-implementation context:
[bluesky-reference](../impl-notes/bluesky-reference.md), [tranquil-pds](../impl-notes/tranquil-pds.md),
[cocoon](../impl-notes/cocoon.md), [rsky-pds](../impl-notes/rsky-pds.md),
[metalbear](../impl-notes/metalbear.md), [cirrus](../impl-notes/cirrus.md),
[arroba](../impl-notes/arroba.md), [pegasus](../impl-notes/pegasus.md),
[alteran](../impl-notes/alteran.md), [zds](../impl-notes/zds.md), [dnproto](../impl-notes/dnproto.md).

## Assessment

`com.atproto.repo.*` is the surface every client touches, and the one with the least tolerance for
improvisation, because the reference client validates *both* directions against the lexicon:
`XrpcClient.call` runs `assertValidXrpcOutput` on every successful response and converts a failure
into a thrown `XRPCInvalidResponseError`
(`/tmp/gap-scratch/atproto/packages/xrpc/src/xrpc-client.ts:109-118`). A response that is "close
enough" is not close enough — `@atproto/api` throws before the caller sees a byte. That fact
reclassifies several items here from cosmetic to interop-fatal, and it is the lens the chapter uses.

atproto-crates routes all ten repo methods and the machinery underneath them is real: a per-DID
serialized writer that builds an MST, content-addresses records, signs a commit and appends to a
durable outbox (`crates/atproto-pds/src/repo/writer.rs:210-400`); a CARv1 importer that verifies the
commit chain inductively (`crates/atproto-pds/src/repo/import.rs:232`); a blob store with
ref-counting and orphan GC (`crates/atproto-pds/src/blob.rs`). Nothing is a stub. The problem is the
*envelope*. Four methods emit JSON the canonical lexicon rejects, three of them on the hot path of a
normal client session: `uploadBlob` returns a blob object matching neither accepted encoding,
`describeRepo` omits the required `didDoc`, `applyWrites` returns union members with no `$type`
discriminator, and `listRecords` emits `"cursor": null` on the final page of every pagination loop.
Each makes `@atproto/api` throw. None is hard to fix — they are field-shape bugs, not missing
subsystems — but shipping any one as stable means the PDS does not work with the reference client.

The comparison field is unforgiving in a way that matters for grading. On the blob envelope, **every
one of the ten independent implementations that implements `uploadBlob` gets it right** — cocoon
(`/tmp/gap-scratch/cocoon/server/handle_repo_upload_blob.go:23-31`), rsky-pds
(`/tmp/gap-scratch/rsky/rsky-lexicon/src/blob_refs.rs:45-52`), tranquil-pds
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/repo/blob.rs:207-216`), metalbear in C
(`/tmp/gap-scratch/metalbear/src/server.c:5510-5521`), pegasus in OCaml
(`/tmp/gap-scratch/pegasus/pegasus/lib/api/repo/uploadBlob.ml:19-24`), zds in Zig
(`/tmp/gap-scratch/zds/src/atproto/repo.zig:528-556`), cirrus
(`/tmp/gap-scratch/cirrus/packages/pds/src/blobs.ts:38-43`), alteran — the hobby-experiment tier — which
comments the requirement in the source
(`/tmp/gap-scratch/alteran/src/pages/xrpc/com.atproto.repo.uploadBlob.ts:115-123`), and dnproto, which
pastes the expected JSON above the builder
(`/tmp/gap-scratch/dnproto/src/pds/xrpc/ComAtprotoRepo_UploadBlob.cs:81-95`). The eleventh, arroba,
returns `501 Not implemented` (`/tmp/gap-scratch/arroba/arroba/xrpc_repo.py:273-279`) — it declines
rather than gets it wrong. `didDoc` in `describeRepo` is likewise universal: all eleven emit it,
including cirrus and zds, which synthesise one inline
(`/tmp/gap-scratch/cirrus/packages/pds/src/xrpc/repo.ts:134-147`,
`/tmp/gap-scratch/zds/src/atproto/repo.zig:116`). These are not "only the reference does this" gaps but
"everyone including the hobby projects does this" gaps, the most damaging category to ship.

Two areas are genuinely mixed and atproto-crates should be graded gently on them. Commit-level
`swapCommit` CAS is enforced by eight of eleven, but cocoon — serious-tier, 37 `com.atproto.*` methods
— has the identical accept-and-ignore defect (`applyWrites` takes a `swapCommit *string` at
`/tmp/gap-scratch/cocoon/server/repo.go:254` and never reads it), cirrus does not model the field, and
arroba rejects any request carrying it (`xrpc_repo.py:34-36`), which is the honest failure mode. Full
lexicon-schema validation is done by six of eleven, so declining to validate is respectable company.
But atproto-crates performs none of the *schema-free* checks — `$type` present, `$type == collection`,
record-key syntax — that nearly every other implementation does, including dnproto and metalbear. That
asymmetry, in a workspace that ships its own lexicon validator in `crates/atproto-lexicon` and does not
use it on its own write path, is the most striking single thing in this area.

---

## The routed surface

| NSID | route | handler | auth | verdict |
|---|---|---|---|---|
| `getRecord` | `http/router.rs:33` | `http/handlers.rs:69` | public | conformant |
| `listRecords` | `http/router.rs:37` | `http/handlers.rs:107` | public | `cursor: null` on last page |
| `describeRepo` | `http/router.rs:41` | `http/handlers.rs:132` | public | missing required `didDoc` |
| `createRecord` | `http/router.rs:46` | `http/write_handlers.rs:144` | session/OAuth | `swapCommit` ignored, no validation |
| `putRecord` | `http/router.rs:50` | `http/write_handlers.rs:197` | session/OAuth | `swapRecord` honored; `swapCommit`/`validate` absent |
| `deleteRecord` | `http/router.rs:54` | `http/write_handlers.rs:247` | session/OAuth | `swapRecord` honored; errors on missing record |
| `applyWrites` | `http/router.rs:58` | `http/write_handlers.rs:335` | session/OAuth | results lack `$type`; no `swapRecord`; no cap |
| `listMissingBlobs` | `http/router.rs:62` | `http/write_handlers.rs:450` | session/OAuth | queries a table nothing writes |
| `uploadBlob` | `http/router.rs:66` | `http/write_handlers.rs:516` | session/OAuth | envelope matches no accepted form |
| `importRepo` | `http/router.rs:70` | `http/write_handlers.rs:595` | session/OAuth + privileged | returns an undeclared body |

---

## Write path

### `createRecord`, `putRecord`, `deleteRecord` — **PARTIAL**

The three single-record procedures share `RepoWriter::apply_writes`, the strongest part of this area:
writes serialized per-DID behind a mutex, records DAG-CBOR encoded and content-addressed, MST mutated
and diffed, signed commit appended with an outbox row
(`crates/atproto-pds/src/repo/writer.rs:210-400`). `createRecord` rejects an existing key
(`writer.rs:241-245`) and generates a TID when `rkey` is absent
(`crates/atproto-pds/src/http/write_handlers.rs:154`); `putRecord` is a true upsert. The gaps are at
the handler edges. Neither `PutRecordInput` (`write_handlers.rs:182-194`) nor
`DeleteRecordInput` (`:234-245`) models `swapCommit` or `validate`; `CreateRecordInput` declares
`swap_commit` at `:88-89` and the constructed `WriteOp` hard-codes `swap_record: None` at `:163`, so
the field is parsed and discarded. Neither output carries the optional `validationStatus`.

Two behavioural divergences are worth separating. `deleteRecord` on a record that does not exist
returns `PdsError::NotFound` from `writer.rs:290-292`, mapped to HTTP 400 `NotFound` at
`crates/atproto-pds/src/http/errors.rs:50-52`; the lexicon describes the method as "Delete a repository
record, **or ensure it doesn't exist**" and the reference short-circuits to a no-op success
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/deleteRecord.ts:75-78`). In fairness,
metalbear behaves the same way (`/tmp/gap-scratch/metalbear/src/repo_store.c:1194-1195`), so this is not
a lone deviation. Separately, a `swapRecord` mismatch produces `PdsError::AuthDenied`, mapped to 403
`Forbidden` at `errors.rs:63-65`. The lexicon declares exactly one error for these methods —
`InvalidSwap` — and clients branch on that name to decide whether to retry. metalbear documents this and
emits `400 InvalidSwap` (`repo_store.c:1743-1757`); so do zds (`repo.zig:46`), tranquil-pds
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/api/error.rs:296`), pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/repository.ml:214-216`), alteran
(`/tmp/gap-scratch/alteran/src/lib/repo-write-validation.ts:438`) and dnproto
(`ComAtprotoRepo_CreateRecord.cs:62`). A 403 reads to a client as an auth problem, not a concurrency
conflict.

### `swapCommit` optimistic concurrency — **DIVERGENT** (carried forward from P2)

`createRecord` accepts the field and never reads it (`write_handlers.rs:88-89`, `:163`); `putRecord`,
`deleteRecord` and `applyWrites` (`:284-289`) do not model it at all. Inside `applyWrites` even
`swapRecord` is dropped — all three branches set `swap_record: None` (`:366`, `:377`, `:384`). The
lexicon's only declared error for these four methods therefore cannot be raised for commit-level CAS,
so a client that reads the head, computes a change and writes back with `swapCommit` gets a silent
success when another writer has already moved the head. That is lost-update, not a slow error path.

The field: the reference threads `swapCommitCid` into `processWrites` on all four methods
(`createRecord.ts:71`, `putRecord.ts:94`, `deleteRecord.ts:66`, `applyWrites.ts:167`); tranquil-pds passes
it into `begin_repo_write` everywhere (`.../record/write.rs:147`, `:348`, `.../delete.rs:60`,
`.../batch.rs:243`); rsky-pds compares against the current root
(`/tmp/gap-scratch/rsky/rsky-pds/src/actor_store/mod.rs:527-530`); metalbear checks all four entry points
(`repo_store.c:1062`, `:1127`, `:1199`, `:1277`); pegasus compares before applying (`repository.ml:214`);
zds parses and enforces (`repo.zig:659-667`); alteran carries it as `expectedCommitCid` into a
conditional root update (`/tmp/gap-scratch/alteran/src/db/repo.ts:37-51`); dnproto compares against the
stored commit CID (`ComAtprotoRepo_CreateRecord.cs:57-64`). The exceptions are cocoon (same
accept-and-ignore defect, `repo.go:254`), cirrus (field unparsed) and arroba, which rejects any request
containing `swapCommit` or `swapRecord` (`xrpc_repo.py:31-36`) — the useful contrast, since declining a
guarantee you do not provide is safe and silently not providing it is not.

### `applyWrites` — **DIVERGENT** (carried forward from P4)

The input side is correct — `ApplyWritesEntry` uses `#[serde(tag = "$type")]` with the exact NSIDs
(`write_handlers.rs:292-323`), matching the closed input union. The output side is not.
`ApplyWritesResponse.results` is `Vec<WriteRecordResponse>` (`:327-332`) and `WriteRecordResponse`
(`:93-102`) has no `$type`, so no member of the closed output union can match. The TS union validator
rejects this before it considers refs: a value that is not a discriminated object fails with "must be
an object which includes the `$type` property"
(`/tmp/gap-scratch/atproto/packages/lexicon/src/validators/complex.ts:165-174`). Each result also
nests a redundant commit copy (`:398-407`) and delete results carry a `uri` that `#deleteResult` does
not define — harmless, since the object validator only iterates declared properties
(`complex.ts:99-124`) — but the missing discriminator is fatal.

Everyone else discriminates: the reference builds typed results (`applyWrites.ts:210-222`); tranquil-pds
serde-renames to the three result NSIDs (`.../record/batch.rs:306-320`); zds writes the literal strings
(`repo.zig:317-330`); metalbear stamps them with a comment explaining that a strict client rejects the
response otherwise (`repo_store.c:1410-1419`); dnproto declares them as constants
(`/tmp/gap-scratch/dnproto/src/pds/UserRepo.cs:477-479`); alteran emits `#deleteResult` explicitly
(`/tmp/gap-scratch/alteran/src/services/repo/apply-prepared-writes.ts:69`); pegasus maps into typed
variants (`applyWrites.ml:70-85`); cirrus types `$type` on its results
(`/tmp/gap-scratch/cirrus/packages/pds/src/account-do.ts:593`, `:602`). cocoon emits a `$type` with the
*wrong* value — the input op types (`repo.go:98-100`, `:348-353`) — which also fails the closed union,
so it has a sibling of this bug rather than a clean record. rsky-pds returns nothing at all
(`Result<(), ApiError>` at `/tmp/gap-scratch/rsky/rsky-pds/src/apis/com/atproto/repo/apply_writes.rs:135`),
technically conformant because the output schema has `required: []`, but useless to a caller.

`applyWrites` also has no batch-size cap. The reference rejects more than 200
(`applyWrites.ts:85-86`); so do tranquil-pds (`MAX_BATCH_WRITES`, `.../batch.rs:24`), rsky-pds
(`apply_writes.rs:55-56`), cirrus (`xrpc/repo.ts:479-484`), metalbear (`repo_store.c:2022-2024`) and
alteran (`repo-write-validation.ts:200-201`). atproto-crates checks only non-emptiness
(`write_handlers.rs:345-351`), and each op does MST work plus a block write inside a held per-DID
mutex, so an authenticated client can pin a repo's write lock for an unbounded period.

### OAuth scope enforcement on writes — **MISSING**

`require_session` (`write_handlers.rs:71-74`) wraps `require_authn` and returns an `AuthSubject`
exposing a parsed `ScopesSet` (`crates/atproto-pds/src/http/auth.rs:96-101`). No write handler consults
it — `grep -n scope crates/atproto-pds/src/http/write_handlers.rs` returns nothing. The `repo:` scope
grammar is fully implemented including collection and `action` parameters
(`crates/atproto-oauth/src/scopes.rs:42`, `:509`; round-tripped by tests at `:1223-1254`), but the only assertion helper is
`assert_space` (`scopes.rs:1116`), used by the spaces path. So a token granted
`repo:app.bsky.feed.like?action=create` can create, update and delete records in any collection and
upload blobs of any MIME type. The reference asserts per-write (`permissions.assertRepo` /
`assertBlob`), as do cocoon (`handle_repo_apply_writes.go:62-67`), cirrus (`xrpc/repo.ts:285-288`),
pegasus (`applyWrites.ml:22-32`), zds (`repo.zig:32`, `:74`, `:207`, `:258`), tranquil-pds
(`.../repo/blob.rs:64`) and alteran (`uploadBlob.ts:79`). This is a security finding, not a conformance
one: the authorization server issues scoped tokens the resource server does not honor.

---

## Read path

### `getRecord` — **conformant**

`GetRecordParams` models all four lexicon params including optional `cid`
(`crates/atproto-pds/src/http/handlers.rs:55-66`), and `cid` is genuinely honored as an exact-match filter
on both the trait-dispatch and legacy paths (`crates/atproto-pds/src/repo/reader.rs:120-127`, `:131-140`).
Output is `{uri, cid, value}` (`reader.rs:192-196`), matching `getRecord.json`. The only nit is the error
name: a miss returns `NotFound` rather than the declared `RecordNotFound` (`errors.rs:50-52`), where
metalbear gets it right (`repo_store.c:1758-1761`).

### `listRecords` — **DIVERGENT**

Pagination works, `limit` is clamped to 1..=100 (`reader.rs:210`) and `reverse` is supported. Two
problems. The serious one: `ListRecordsResponse.cursor` is `Option<String>` with no
`skip_serializing_if` (`reader.rs:454-461`), so an exhausted page serialises `"cursor": null`.
`listRecords.json` types `cursor` as a plain `string` with no `nullable` entry, and the TS object
validator does not treat `null` as absent — it reaches the string validator, which rejects it
(`/tmp/gap-scratch/atproto/packages/lexicon/src/validators/primitives.ts:172-177`), and the object
validator propagates the failure (`complex.ts:104`, `:135-140`). Because `XrpcClient` asserts output
validity, the *final page of every pagination loop* throws in `@atproto/api`. Anything that enumerates
a collection — migration tooling, backup, account export — fails at the end rather than the start,
which is the worst place to fail. The inventory recorded this as a note; client-side validation makes
it an interop break.

The second: when `reverse=true` the trait-dispatch branch is skipped by construction
(`if let Some(backend) = self.backend.as_ref() && !reverse`, `reader.rs:217-219`) and the request falls
through to a legacy path that opens a per-actor SQLite store directly from `data_dir`
(`reader.rs:94-96`, `:260`). On a build using the `fjall` backend — a real optional feature,
`crates/atproto-pds/Cargo.toml:99` — that store is not the record store, so `reverse=true` would return
an empty page. The code path is unambiguous; I did not run a fjall deployment to observe the result.

### `describeRepo` — **DIVERGENT** (carried forward from P3)

`describeRepo.json` requires `handle`, `did`, `didDoc`, `collections`, `handleIsCorrect`.
`DescribeRepoResponse` (`crates/atproto-pds/src/repo/reader.rs:463-484`) has four of five: there is no
`didDoc` field anywhere in the struct. It instead adds three undeclared fields — `head_cid`, `head_rev`
and `head_data` — which are also snake_case, unlike every other field in the response, so even as an
extension they break AT Protocol JSON convention.

Because `didDoc` is required, the object validator fails with "must have the property `didDoc`"
(`complex.ts:127-134`) and `@atproto/api` throws. `describeRepo` is how a client confirms which PDS
hosts a repo and reads the service endpoint out of the DID document, so this breaks account discovery
and parts of migration. All eleven comparison implementations emit it, from rsky-pds resolving a real
document (`/tmp/gap-scratch/rsky/rsky-pds/src/apis/com/atproto/repo/describe_repo.rs:44`) down to
cirrus and zds synthesising a minimal one. There is no reading under which this is optional.

---

## Blobs

### `uploadBlob` — **DIVERGENT, the top finding in this area** (carried forward from P1)

`UploadBlobResponse.blob` is `crate::blob::BlobRef` (`write_handlers.rs:505-508`), which serialises as
`{"$link": …, "mimeType": …, "size": …}` (`crates/atproto-pds/src/blob.rs:37-49`). The lexicon output
type is a lex-`blob` (`/tmp/gap-scratch/atproto/lexicons/com/atproto/repo/uploadBlob.json`) and the
reference accepts exactly two encodings, both declared `.strict()` in zod: the typed form
`{$type, ref, mimeType, size}` and the two-key legacy form `{cid, mimeType}`
(`/tmp/gap-scratch/atproto/packages/lexicon/src/blob-refs.ts:5-23`). The emitted object has no `$type`,
no `ref` wrapper, and `$link` is not a key in either form, so it parses as neither.

I traced the client-side consequence rather than assuming it. `httpResponseBodyParse` runs
`jsonStringToLex` on every JSON response
(`/tmp/gap-scratch/atproto/packages/xrpc/src/util.ts:363-366`), reaching `ipldToLex`, which only
converts an object into a `BlobRef` when it has `$type: 'blob'` or a string `cid` plus a string
`mimeType` (`/tmp/gap-scratch/atproto/packages/lexicon/src/serialize.ts:65-72`). The emitted object
satisfies neither hint, so it stays a plain object; the lex `blob` validator then rejects anything not
`instanceof BlobRef` (`.../validators/blob.ts:11-17`) and `assertValidXrpcOutput` turns that into a
throw. The failure is therefore *not* deferred until the blob is embedded in a record — **the
`uploadBlob` call itself throws** in `@atproto/api`. Every media path is dead from the first upload.

This is the cleanest comparison in the chapter: ten of eleven emit the typed form and the eleventh
returns 501. Two of them — metalbear (`server.c:2883-2884`) and the reference's own `allowLegacy`
handling — explicitly parse *both* accepted forms when scanning records, which is the level of care the
ecosystem has converged on.

### `listMissingBlobs` and blob-ref tracking — **PARTIAL, and it does not work**

The endpoint is routed and its SQL is real (`write_handlers.rs:450-501`, joining `repo_blob_ref`
against `repo_blob` via `crates/atproto-pds/src/blob.rs:210-235`). But nothing ever populates
`repo_blob_ref` from a record write. `blob::add_ref` (`blob.rs:111-129`) carries the doc comment
"Called from the writer after a record write that contains a blob ref"; its only call sites are unit
tests (`blob.rs:324`, `:326`; `actor_store/sql/public_realm.rs:822-823`;
`actor_store/fjall/public_realm.rs:1095-1096`). `RepoWriter::apply_writes` never inspects a record for
blob references — the only match for "blob" in `crates/atproto-pds/src/repo/writer.rs` is
`signature_blob` on line 393, an unrelated column. So `listMissingBlobs` always returns empty and the
migration flow it exists for is silently broken; blobs are never ref-counted, so `drop_record_refs` and
its orphan GC (`blob.rs:131-170`) never fire and uploads accumulate forever; and there is no
upload-then-reference lifecycle, so the reference's "untethered blob expires if unreferenced" model has
no analogue.

Every other implementation serving the endpoint solves this one of two ways. Ref-table maintenance on
write: tranquil-pds calls `extract_blob_cids` per value (`.../record/write.rs:255`, `:430`,
`.../batch.rs:84`); cocoon increments and decrements a `ref_count` and deletes at zero
(`repo.go:672-707`); rsky-pds runs `blobs_for_write` → `find_blob_refs` during prepare
(`/tmp/gap-scratch/rsky/rsky-pds/src/repo/prepare.rs:48-84`); pegasus stores and replaces per-path refs
(`/tmp/gap-scratch/pegasus/pegasus/lib/repository.ml:259-321`); zds collects blob CIDs while staging
(`repo.zig:739`, `/tmp/gap-scratch/zds/src/storage/store.zig:2004-2008`); alteran collects into the write
context (`/tmp/gap-scratch/alteran/src/services/repo/blob-refs.ts:24`). Or a query-time scan: metalbear
walks every record's JSON for both blob encodings when the endpoint is called
(`/tmp/gap-scratch/metalbear/src/server.c:2882-2915`), which needs no bookkeeping and would be the
low-effort way to make the endpoint honest here. dnproto and arroba do not route it — a clean N rather
than a broken Y.

### `importRepo` — **PARTIAL**

A CARv1 reader that walks the commit chain in `rev` order and verifies it inductively
(`crates/atproto-pds/src/repo/import.rs:232`), gated behind a session plus a
`claims.privileged()` check (`write_handlers.rs:600-607`). It also carries a per-commit ECDSA check
against the *historical* signing key at that `rev` (`verify_chain_signatures`,
`crates/atproto-pds/src/repo/import.rs:365-416`) — but that path is dead in production: it runs only
when a `PlcVerifier` is wired (`:240-242`), `RepoImporter::new` defaults it to `None` (`:113`), and
`with_plc_verifier` (`:133`) has no caller anywhere in the workspace. See
[repo finding 6](./22-repo.md). The lexicon divergence is narrow: `importRepo.json`
declares no output and the handler returns `{headCid, headRev, blocksIngested, commitsIndexed}`
(`write_handlers.rs:575-588`). A method with no output schema is not validated against, so this is
cosmetic — extra diagnostic data on a migration endpoint is arguably useful. Noted so it reads as a
deliberate choice rather than an accident.

---

## Lexicon validation

**MISSING.** No write handler validates record values against a lexicon, and none models the `validate`
flag. `CreateRecordInput` (`write_handlers.rs:77-90`), `PutRecordInput` (`:182-194`) and
`ApplyWritesInput` (`:284-289`) have no `validate` field, so a client sending `validate: true` gets no
error and no validation. `grep -rn validate_record crates/atproto-pds/src/` returns nothing, and
neither `createRecord` nor `putRecord` emits `validationStatus`.

None of the structural checks that need no schema are performed either. `$type` is never inspected —
the writer DAG-CBOR-encodes `op.value` verbatim (`crates/atproto-pds/src/repo/writer.rs:223-226`), so a
record with no `$type`, or one contradicting its collection, is stored and served as-is and will be
undecodable by any consumer. Record keys are never validated:
`mst_key = format!("{}/{}", op.collection, op.rkey)` (`writer.rs:217`) accepts any string, including
one containing `/`, which would place the record at a different MST path than its AT-URI implies.
Collection NSIDs are never validated.

The sharpest internal contradiction in this area is that the workspace ships a complete lexicon
validation engine — `atproto_lexicon::validation::validate_record`
(`crates/atproto-lexicon/src/validation/validate.rs:327`) plus `validate_record_with_schema`,
`validate_query_params`, `validate_procedure_input` and limit-bounded variants — and the PDS *depends*
on the crate (`crates/atproto-pds/Cargo.toml:35`), using exactly two items from it, both in the spaces
declaration parser (`crates/atproto-pds/src/space/declaration.rs:31-32`). The public-realm write path
imports none of it.

| Implementation | Schema validation | `validate` honored | `$type` reconciled | rkey syntax |
|---|---|---|---|---|
| bluesky-reference | yes, 20+ known schemas (`prepare.ts:38-90`) | tri-state (`:73-85`) | yes (`:167-178`) | yes (`:181-183`) |
| tranquil-pds | yes, plus **dynamic lexicon resolution** (`record/validation.rs:11-19`) | tri-state (`write.rs:149-167`) | yes | yes (`tranquil-types/src/lib.rs:400-404`) |
| metalbear | yes, lexicon registry (`repo_store.c:383-420`) | tri-state (`:1677-1690`) | yes (`:370-381`) | yes (`:1184`) |
| cirrus | yes, `@atcute/lexicons` (`validation.ts:1-70`, `:134-154`) | tri-state (`:103-106`) | yes | yes (`:126`) |
| alteran | yes, `@atproto/api` `lexicons.validate` (`repo-write-validation.ts:366-380`) | yes | yes | yes (`:331`) |
| pegasus | yes, `Record_validator` (`applyWrites.ml:34-54`) | tri-state | yes | yes (`record_validator.ml:66-69`) |
| zds | known-type + record-key rules only (`store.zig:4915-4945`) | tri-state (`repo.zig:650-658`) | yes (`store.zig:4924`) | partial (`:4930-4939`) |
| rsky-pds | `$type` presence + match only (`prepare.rs:163-187`) | bool (`:206-210`) | yes | no (helper unused in the PDS) |
| cocoon | none; `validationStatus` hard-coded `"valid"` (`repo.go:352`) | no | stamps when absent (`:318-320`) | yes (`:299-303`) |
| dnproto | none | no | stamps (`UserRepo.cs:138`) | unverified |
| arroba | none (collection allowlist only) | no | no | no |
| **atproto-crates** | **none** | **no** | **no** | **no** |

Six of eleven do real schema validation, so declining that is a defensible stable-gap. Doing none of
the four columns, when the three cheapest are covered by nine, six and six implementations, is the
finding.

---

## Findings

Severity is separated deliberately: 1-5 and 8 are genuine spec-compliance or security blockers, 9-12
are real but survivable, 13-15 are cosmetic.

**1. `uploadBlob` returns a blob envelope matching neither accepted encoding.** DIVERGENT /
**rc-blocker** (spec-compliance). Evidence: `crates/atproto-pds/src/blob.rs:37-49`,
`http/write_handlers.rs:505-508`; oracle `packages/lexicon/src/blob-refs.ts:5-23`,
`validators/blob.ts:11-17`, `serialize.ts:65-72`, `packages/xrpc/src/xrpc-client.ts:109-118`. Field: ten
of eleven emit the typed form; arroba returns 501. Consequence: `@atproto/api` throws on the upload call
itself — all media broken against real clients.

**2. `describeRepo` omits the lexicon-required `didDoc`.** DIVERGENT / **rc-blocker**. Evidence:
`repo/reader.rs:463-484` — no `didDoc`, plus snake_case `head_*` fields; oracle
`lexicons/com/atproto/repo/describeRepo.json`, `validators/complex.ts:127-134`. Field: all eleven emit
it, including cirrus (`xrpc/repo.ts:134-147`) and zds (`repo.zig:116`). Consequence: every
`describeRepo` call throws; account discovery and migration break.

**3. `applyWrites` results carry no `$type` union discriminator.** DIVERGENT / **rc-blocker**. Evidence:
`write_handlers.rs:93-102`, `:327-332`, `:398-407`; oracle `applyWrites.json` closed output union,
`complex.ts:165-174`. Field: eight discriminate correctly; cocoon uses the wrong value
(`repo.go:98-100`); rsky-pds returns no body. Consequence: batched writes are unusable from the
reference client.

**4. `listRecords` emits `"cursor": null` when a page is exhausted.** DIVERGENT / **rc-blocker**.
Evidence: `repo/reader.rs:454-461` — `Option<String>` with no `skip_serializing_if`; oracle
`listRecords.json` (`cursor` is a non-nullable `string`), `validators/primitives.ts:172-177`,
`complex.ts:104`, `:135-140`. Consequence: the last page of every pagination loop throws in
`@atproto/api`. One-line fix.

**5. `swapCommit` is accepted and never enforced on any write path.** DIVERGENT / **rc-blocker**
(silent data loss). Evidence: `write_handlers.rs:88-89`, `:163` (declared, discarded); `:182-194`,
`:234-245`, `:284-289` (not modelled); `:366`, `:377`, `:384` (`swapRecord` dropped inside
`applyWrites`). Field: eight of eleven enforce it; cocoon has the identical defect (`repo.go:254`);
cirrus omits it; arroba rejects requests carrying it (`xrpc_repo.py:31-36`). Consequence: concurrent
writers clobber each other and both receive HTTP 200. If full CAS is out of reach for this release,
arroba's explicit rejection is a correct and cheap stand-in.

**6. No lexicon validation, and none of the schema-free structural checks either.** MISSING /
**stable-gap** for schema validation, **rc-blocker** for the `$type` and record-key checks. Evidence: no
`validate` field on any write input (`write_handlers.rs:77-90`, `:182-194`, `:284-289`); no
`validate_record` call anywhere in `crates/atproto-pds/src/`; `repo/writer.rs:217` interpolates `rkey`
into the MST key unchecked; `:223-226` encodes the value without inspecting `$type`. The engine exists
at `crates/atproto-lexicon/src/validation/validate.rs:327` and the PDS depends on the crate
(`Cargo.toml:35`) but uses it only in `src/space/declaration.rs:31-32`. Field: see the table above.
Consequence: a record stored without `$type` is undecodable by every consumer, and an `rkey` containing
`/` lands at an MST path that does not match its own AT-URI — neither recoverable once the commit is
signed and sequenced.

**7. `listMissingBlobs` queries a table that record writes never populate.** PARTIAL / **stable-gap**.
Evidence: `blob.rs:111-129` (`add_ref`, called only from tests at `:324`, `:326`,
`actor_store/sql/public_realm.rs:822-823`, `actor_store/fjall/public_realm.rs:1095-1096`); no blob-ref
scan in `repo/writer.rs`. Field: six maintain refs on write; metalbear scans at query time
(`server.c:2882-2915`), the lowest-effort fix here. Consequence: the endpoint always returns empty, the
migration flow it exists for silently does nothing, and blobs are never garbage-collected.

**8. OAuth `repo:` and blob scopes are parsed but never asserted on writes.** MISSING / **rc-blocker**
(security). Evidence: no `scope` reference in `http/write_handlers.rs`; `AuthSubject::scopes` exists
(`http/auth.rs:96-101`); `RepoScope` with collection and `action` is fully parsed
(`crates/atproto-oauth/src/scopes.rs:42`, `:509`; round-tripped by tests at `:1223-1254`); the only assertion helper is
`assert_space` (`:1116`). Field: reference, cocoon, cirrus, pegasus, tranquil-pds, zds and alteran assert
per-write. Consequence: a narrowly scoped token has full write authority over every collection and can
upload any MIME type — the authorization server's decisions are not enforced by the resource server.

**9. `swapRecord` mismatch returns 403 `Forbidden` instead of 400 `InvalidSwap`.** DIVERGENT /
**stable-gap**. Evidence: `repo/writer.rs:246-256` raises `PdsError::AuthDenied`; `http/errors.rs:63-65`
maps it to 403. Field: metalbear (`repo_store.c:1751-1757`), zds (`repo.zig:46`), tranquil-pds
(`api/error.rs:296`), pegasus (`repository.ml:214-216`), alteran (`repo-write-validation.ts:438`) and
dnproto (`ComAtprotoRepo_CreateRecord.cs:62`) all emit `InvalidSwap`. Consequence: clients cannot tell
a concurrency conflict from an auth failure, so retry logic never fires.

**10. `applyWrites` has no batch-size cap.** MISSING / **stable-gap** (availability). Evidence: only a
non-empty check at `write_handlers.rs:345-351`; the batch runs inside the per-DID write mutex
(acquired at `repo/writer.rs:161-162`)
(`repo/writer.rs:210-400`). Field: reference, tranquil-pds, rsky-pds, cirrus, metalbear and alteran cap
at 200. Consequence: an authenticated client can hold a repo's write lock indefinitely with one request.

**11. `deleteRecord` on a nonexistent record returns 400 instead of a no-op success.** DIVERGENT /
**stable-gap**. Evidence: `repo/writer.rs:290-292`, mapped to 400 `NotFound` at `http/errors.rs:50-52`.
Field: the reference no-ops (`deleteRecord.ts:75-78`); metalbear behaves as atproto-crates does
(`repo_store.c:1194-1195`), so this is not a lone deviation. Consequence: idempotent-delete and cleanup
flows fail on a second attempt.

**12. `listRecords?reverse=true` bypasses the configured storage backend.** PARTIAL / **stable-gap**.
Evidence: `repo/reader.rs:217-219` skips the trait branch when `reverse` is set; the fallback opens a
per-actor SQLite store (`reader.rs:94-96`, `:260`); `fjall` is a real feature (`Cargo.toml:99`).
Consequence: on a non-SQL storage profile, reverse pagination would read the wrong store. Reasoned from
the code path, not observed at runtime.

**13. `getRecord` miss returns `NotFound` rather than the declared `RecordNotFound`.** DIVERGENT /
**cosmetic**. Evidence: `http/errors.rs:50-52`; oracle `getRecord.json` `errors: [RecordNotFound]`.
Field: metalbear emits `RecordNotFound` (`repo_store.c:1758-1761`).

**14. `importRepo` returns a body the lexicon does not declare.** DIVERGENT / **cosmetic**. Evidence:
`write_handlers.rs:575-588`; `importRepo.json` declares no output, so nothing validates it. Defensible
as a diagnostic extension; listed for completeness.

**15. No `validationStatus` in write outputs.** MISSING / **cosmetic** (follows from finding 6).
Evidence: `write_handlers.rs:93-102`. The field is optional, so omitting it is conformant; it becomes
emittable for free once finding 6 is addressed.

Totals: **7 rc-blockers** (1, 2, 3, 4, 5, 8, and the `$type`/record-key half of 6), **6 stable-gaps**
(the schema-validation half of 6, plus 7, 9, 10, 11, 12), **3 cosmetic** (13, 14, 15).

---

## Where atproto-crates is ahead

`importRepo`'s *design* is genuinely strong. Verifying each imported commit's signature against the
*historical* signing key valid at that commit's `rev` rather than the current key
(`crates/atproto-pds/src/repo/import.rs:34-41` for the model, `:365-416` for the implementation) is
more careful than arroba, which notes in a comment that the imported signature comes from the old
PDS's key and does not check it (`/tmp/gap-scratch/arroba/arroba/xrpc_repo.py:232-234`).
**Downgraded on verification, though:** that check never runs, because nothing constructs the
`PlcVerifier` it is gated on (`import.rs:113`, `:240-242`; `with_plc_verifier` at `:133` has no
caller). What the shipped import path actually guarantees is the inductive chain proof at `:232`.
Credit for the design, not for the behaviour.

The blob subsystem is the same shape: per-record ref rows, orphan counting, GC on the last
dereference (`blob.rs:111-170`) is a more complete design than most of the field, and it too is
unwired — finding 7. And `getRecord`'s `cid` parameter is honored on
both storage paths, which several implementations skip.

## Confidence & unknowns

Everything asserted about atproto-crates was read from the cited lines in this worktree; every lexicon
claim was read from the canonical JSON under `/tmp/gap-scratch/atproto/lexicons/com/atproto/repo/`; and
the four client-side rejection paths (blob envelope, missing `didDoc`, missing union `$type`, null
`cursor`) were traced through `packages/lexicon` and `packages/xrpc` to the throw site rather than
inferred. Comparison claims are each backed by a line I opened.

Three limits. No runtime testing: consequences are derived from source and lexicon semantics, and finding
12 in particular is a code-path reading rather than an observed empty response. My `@atproto/api`
reasoning uses the `packages/lexicon` + `packages/xrpc` validator pair; the repository also contains a
newer `@atproto/lex-data` stack that `prepare.ts` uses server-side, and I did not verify which path every
shipped client takes — the conclusions do not depend on it, since a blob object with neither `$type` nor
a top-level `cid` is invalid under either stack, but the exact error type a given client throws may
differ. Finally, for cirrus and alteran I checked repo-write behaviour without auditing their single-user
scoping decisions; I marked no cell `n/a` here, because record operations are in scope for a single-user
PDS and both implement them.
