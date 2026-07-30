# PDS coverage matrix

Twelve tables, one per capability area, each scoring the same twelve implementations against the
granular capabilities that area owns. Read a row across to see how the field behaves on one
capability, and a column down to see one implementation's shape; every symbol was set by reading
the cited source, and the per-area chapters linked from each heading carry the reasoning that this
file deliberately omits. Start with the maturity tiers below — an `N` from a single-user hobby
project and an `N` from a multi-account server that advertises the feature are not the same finding.

**Legend.** `Y` = full, verified in source. `~` = partial / happy-path / stub. `N` = absent.
`n/a` = not applicable to that project's scope. `?` = could not verify.

See also: [README.md](./README.md) ·
[00-atproto-crates-inventory.md](./00-atproto-crates-inventory.md) ·
[50-synthesis-and-roadmap.md](./50-synthesis-and-roadmap.md) ·
[40-permissioned-overview.md](./permissioned/40-permissioned-overview.md)

## Maturity tiers

| Implementation | Language | Tier | Multi-account? |
| --- | --- | --- | :-: |
| atproto-crates | Rust | *subject of this review* | yes |
| bluesky-reference | TypeScript / Node | reference | yes |
| tranquil-pds | Rust | serious | yes |
| cocoon | Go | serious | yes |
| rsky-pds | Rust | serious | yes |
| metalbear | C11 | serious | yes |
| cirrus | TypeScript / Cloudflare Workers | single-user | no |
| arroba | Python | serious | yes (library); demo app is single-repo |
| pegasus | OCaml | serious | yes |
| alteran | TypeScript / Cloudflare Workers | hobby-experiment | no |
| zds | Zig | serious | yes |
| dnproto | C# / .NET 10 | single-user | no |

Tiers are quoted from the per-implementation notes under
[impl-notes/](./impl-notes/). Three columns — cirrus, alteran and dnproto — are single-account by
construction, not by omission: the account is configuration rather than a row created over XRPC.
arroba is a library plus a demo application, so its server-side cells describe what the demo binds,
not what the library can do.

## A. Account lifecycle — see [21-accounts.md](./capability-areas/21-accounts.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.server.describeServer | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | ~ |
| com.atproto.server.createAccount (routed, real signup) | Y | Y | Y | Y | Y | Y | n/a | n/a | Y | n/a | Y | n/a |
| createAccount: BYO-DID requires proof of control | N | Y | Y | Y | ~ | N | n/a | n/a | N | n/a | Y | n/a |
| createAccount: signed `plcOp` migration input | N | ~ | ? | N | N | N | n/a | n/a | N | n/a | Y | n/a |
| Invite codes required + redeemed at signup | Y | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| createInviteCode is admin-gated (not user-session) | N | Y | ? | Y | ? | Y | n/a | n/a | Y | n/a | Y | n/a |
| com.atproto.server.createInviteCodes (batch) | N | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | n/a |
| getAccountInviteCodes output matches server.defs#inviteCode | N | Y | Y | N | Y | Y | n/a | ~ | N | n/a | Y | N |
| Full 5-state account model (active/deactivated/takendown/suspended/deleted) | Y | Y | Y | N | Y | ~ | ~ | ~ | ~ | ~ | ~ | ~ |
| Account state enforced on repo writes | N | Y | ~ | N | Y | N | n/a | n/a | ~ | ~ | Y | ~ |
| Account state enforced on public repo reads | Y | Y | Y | ~ | Y | N | n/a | ~ | ~ | ~ | Y | ~ |
| #account firehose event emitted on state change | Y | Y | Y | Y | Y | ~ | Y | Y | ~ | N | Y | Y |
| #account frame body matches lexicon shape (flat seq/did/time/active) | N | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | Y |
| com.atproto.server.activateAccount | ~ | Y | Y | Y | Y | Y | Y | n/a | Y | N | Y | Y |
| com.atproto.server.deactivateAccount honours `deleteAfter` | Y | Y | Y | N | ? | ? | ? | n/a | N | N | ? | ? |
| com.atproto.server.checkAccountStatus (all 9 required fields, real) | ~ | Y | Y | ~ | ~ | ~ | ~ | N | Y | N | Y | ~ |
| com.atproto.server.requestAccountDelete | Y | Y | Y | Y | Y | Y | n/a | N | Y | n/a | N | n/a |
| deleteAccount verifies did + password + token (lexicon-required) | N | Y | ? | Y | ? | Y | n/a | N | Y | n/a | N | n/a |
| deleteAccount actually erases repo/blob data | N | Y | Y | Y | ? | ~ | n/a | N | ? | n/a | N | n/a |
| App password CRUD (create + list + revoke) | Y | Y | Y | N | Y | Y | Y | N | N | Y | Y | N |
| com.atproto.server.updateEmail (canonical email-change completion) | N | Y | Y | Y | Y | Y | ~ | N | Y | N | Y | N |
| confirmEmail verifies lexicon-required `email` alongside `token` | N | Y | ? | ? | ? | ? | n/a | N | ? | N | ? | N |
| requestPasswordReset + resetPassword (usable while locked out) | Y | Y | Y | ~ | Y | Y | n/a | N | Y | n/a | N | n/a |
| com.atproto.admin.getAccountInfo returns defs#accountView (incl. indexedAt) | ~ | Y | Y | N | Y | Y | n/a | N | Y | n/a | N | N |

### Notes

- **atproto-crates `describeServer` = N.** `http/router.rs:116-241` contains no `describeServer` literal. Every other column serves it, including the three single-user projects. It is the first call a client, a migration tool and a relay operator all make.
- **atproto-crates `#account` frame body = N.** `sequencer/frame.rs:116-121` nests the body under a `payload` key and names the subject `repo`; the lexicon body is flat `{seq, did, time, active, status}`. alteran is the only other N and for a different reason — its `#sync` frames carry the `#account` shape (`alteran.md:430`).
- **atproto-crates `deleteAccount` = N on data erasure.** `auth_handlers.rs:1207-1210` sets `state = Deleted` and stops. zds is the only other implementation with no erase path at all, and it also never GCs blobs (`zds.md:531-532`).
- **metalbear account state on public reads = N.** `getRepoStatus` hardcodes `deactivated` (`server.c:2809`) and no read path consults the takedown table. The state model is write-only on an otherwise serious-tier multi-account server.
- **arroba's four Ns here are product scope, not defects.** It binds no port; account endpoints exist only in the demo `app.py`, so invite codes, `requestAccountDelete` and password reset are unserved by construction (`arroba.md:105-106`).
- **Reconciliation — dnproto `com.atproto.admin.getAccountInfo`.** This area emitted `n/a`, area J emitted `N`. Opening `dnproto/src/pds/Pds.cs`: there *is* a full operator admin surface at `/admin/*` (`:227-244`, passkey-authenticated), so admin is in scope for dnproto; there is simply no `com.atproto.admin.*` XRPC. Reconciled to **N** in both areas.
- **dnproto `describeServer` = ~, and area K reconciled down to match.** `Pds.cs:190` routes a real handler, but `InviteCodeRequired` and `PhoneVerificationRequired` are C# literal `true` (`ComAtprotoServer_DescribeServer.cs:16-17`) on a server that has no invite flow and no phone verification. Area K originally scored the same endpoint `Y`.

## B. Repository, MST and encoding — see [22-repo.md](./capability-areas/22-repo.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| MST: recursive insert/delete with split and merge | N | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | ~ |
| MST: key-height rule (SHA-256 leading zeros / 2, fanout 4) | Y | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | ? |
| MST node encoding: `l` emitted as null when there is no left subtree | N | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| MST entry encoding: `t` emitted as null when there is no right subtree | N | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| MST delete preserves neighbouring keys (no prefix-compression corruption) | N | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| Commit object: `prev` always present (null when there is none) | N | Y | ? | Y | Y | ? | Y | Y | ? | ? | ? | Y |
| Commit object carries no non-spec fields (`prevData` kept out of the signed body) | N | Y | Y | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| Commit `version: 3` enforced on parse | Y | Y | ? | Y | Y | ? | Y | Y | ? | ? | ? | Y |
| Commit signing bytes = DAG-CBOR of the commit minus `sig` | Y | Y | ? | Y | Y | ? | Y | Y | Y | Y | ? | Y |
| Imported repo's commit signature verified (com.atproto.repo.importRepo) | N | N | ? | N | ? | Y | ? | Y | ? | ? | Y | ? |
| Low-S normalization applied when signing with K-256 | ~ | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| Low-S normalization applied when signing with P-256 | N | Y | n/a | Y | Y | ? | n/a | n/a | Y | n/a | Y | Y |
| High-S signatures rejected on verify | ~ | Y | ? | Y | Y | ? | Y | ? | N | Y | Y | ? |
| DAG-CBOR canonical map-key ordering (length-first, then bytewise) | Y | Y | ? | Y | Y | ? | Y | Y | Y | Y | Y | Y |
| Strict DAG-CBOR decode (non-minimal ints, indefinite lengths, non-42 tags rejected) | Y | Y | ? | Y | Y | ? | Y | Y | ~ | Y | Y | ~ |
| Record encode: JSON `$link` converted to CBOR tag 42 | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| Record encode: non-integer numbers rejected (AT data model) | N | Y | N | Y | ? | Y | Y | ? | N | ? | Y | ? |
| CID profile: CIDv1 / dag-cbor 0x71 / sha2-256 / base32lower string form | Y | Y | Y | Y | Y | ? | Y | Y | ~ | Y | Y | Y |
| Blob CID: CIDv1 / raw 0x55 / sha2-256 | Y | Y | Y | Y | Y | ? | Y | n/a | Y | Y | Y | Y |
| CAR v1 read is streaming with explicit block/size/count limits | Y | ~ | ~ | ~ | ? | ? | ~ | Y | Y | ~ | ~ | ~ |
| getRepo CAR export streams rather than buffering the whole repo | N | Y | ? | ? | ? | ? | ~ | Y | Y | ? | ? | N |
| MST/commit byte-level interop vectors exercised in tests | N | Y | ? | Y | ? | ? | ~ | ~ | ~ | ? | ~ | N |
| Superseded repo blocks reclaimed (MST-node GC) | N | Y | Y | ? | Y | N | ? | ? | ? | ? | ? | n/a |

### Notes

- **atproto-crates MST insert = N.** `mst/tree.rs:236` discards the computed key height, so `insert_recursive` never recurses. `mst/key.rs:30-34` computes the height correctly and nothing consumes it. Every other column is `Y` or `?`; this is the single most load-bearing N in the matrix.
- **The four `skip_serializing_if` cells (`l`, `t`, `prev`, delete-neighbour) are one defect with four faces.** serde omits the key instead of emitting null, so an empty MST node encodes as `map(1)` rather than `map(2)` and an initial commit as `map(4)`. cocoon's vendored indigo carries the comment that omitempty "would break signature verification" (`repo/commit.go:18`).
- **tranquil-pds and metalbear read as `?` across most of this area for structural reasons.** tranquil's MST, commit and CBOR live in the un-vendored `jacquard-repo` / `jacquard-common` 0.9 crates (`Cargo.toml:98-99`); metalbear's live in an external Wolfram library that is not in the repository (`CMakeLists.txt:32`). Read those two columns here as "delegated, unaudited" rather than "missing".
- **atproto-crates `$link` → CBOR tag 42 = N.** `writer.rs:223,545` hand the `serde_json::Value` straight to the encoder, so blob refs and strongRefs inside records are stored as ordinary CBOR maps, not cid-links. arroba has the identical defect (`storage.py:582,128`).
- **atproto-crates CAR reading = Y is the strongest cell in the column.** `dasl/car/reader.rs:129-181` is the only streaming reader with a pre-allocation length check plus three explicit caps; the reference's `readCar` buffers (`car.ts:56-66`).
- **pegasus high-S rejection = N.** `kleidos.ml:90-93,160-163` passes the signature through unchanged on verify — the only outright N in a row where six implementations are Y.

## C. Records and writes — see [23-records.md](./capability-areas/23-records.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.repo.createRecord | ~ | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.putRecord | ~ | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.deleteRecord | ~ | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.applyWrites | ~ | Y | Y | ~ | ~ | Y | Y | N | Y | Y | Y | Y |
| com.atproto.repo.getRecord | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.listRecords | ~ | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.describeRepo | ~ | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| describeRepo emits lexicon-required didDoc | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.repo.uploadBlob | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| uploadBlob returns a valid lex-blob envelope | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| com.atproto.repo.importRepo | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | N |
| com.atproto.repo.listMissingBlobs | ~ | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | N |
| blob refs extracted from record values on write | N | Y | Y | Y | Y | Y | ~ | N | Y | Y | Y | N |
| swapCommit enforced (commit-level CAS) | N | Y | Y | N | Y | Y | N | ~ | Y | Y | Y | Y |
| swapRecord enforced (record-level CAS) | ~ | Y | Y | N | Y | Y | N | ~ | Y | Y | Y | N |
| CAS failure reported as lexicon error name InvalidSwap | N | Y | Y | N | N | Y | N | N | Y | Y | Y | Y |
| lexicon schema validation of record values | N | Y | Y | N | N | Y | Y | N | Y | Y | ~ | N |
| validate flag honored (tri-state true/false/unset) | N | Y | Y | N | ~ | Y | Y | N | Y | Y | Y | N |
| validationStatus in create/put/applyWrites output | N | Y | Y | ~ | N | Y | Y | N | Y | Y | Y | Y |
| record $type reconciled/enforced against collection | N | Y | Y | ~ | Y | Y | Y | N | Y | Y | Y | ~ |
| record-key syntax validated on write | N | Y | Y | Y | N | Y | Y | N | Y | Y | ~ | ? |
| applyWrites results carry union $type discriminators | N | Y | Y | N | N | Y | Y | N | Y | Y | Y | Y |
| applyWrites batch size capped | N | Y | Y | N | Y | Y | Y | N | N | Y | N | N |
| OAuth repo/blob scope asserted on record writes | N | Y | Y | Y | ? | ? | Y | N | Y | Y | Y | ? |

### Notes

- **Lexicon validation is the field's most commonly skipped capability.** atproto-crates has no `validate_record` call anywhere in `crates/atproto-pds/src`; cocoon hardcodes `validationStatus: "valid"` behind a TODO (`repo.go:352`); rsky-pds checks only that `$type` exists (`prepare.rs:163-168`); arroba has an allowlist of collections and nothing more (`xrpc_repo.py:24`). Five of twelve are N.
- **cocoon `validationStatus` = ~ is worse for a consumer than N.** Emitting the literal `"valid"` for every write tells a downstream indexer that unvalidated records passed validation.
- **atproto-crates `InvalidSwap` = N.** CAS failures surface as HTTP 403 `AuthDenied` (`errors.rs:63-65`), so a client cannot distinguish a lost race from a permission failure and will not retry.
- **arroba's six Ns here trace to two 501 stubs.** `applyWrites` (`xrpc_repo.py:265-270`) and `uploadBlob` (`:273-279`) are unimplemented, which cascades into the blob-ref, `$type`-discriminator and batch-cap rows.
- **atproto-crates `describeRepo` omits `didDoc` entirely** (`reader.rs:463-484`) while adding snake_case `head_*` fields. All ten independent implementations emit it; this is one of only three rows where atproto-crates is alone at N against a clean 10/10.
- **`listMissingBlobs` is `~` here but `N` in areas I and K on purpose.** This row asks only whether the NSID is routed with the right shape, which it is (`write_handlers.rs:450-501`). Whether it can ever return data is scored in area I.

## D. Identity and handles — see [24-identity.md](./capability-areas/24-identity.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.identity.resolveHandle (routed; authoritative for local accounts) | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y | Y | ~ |
| resolveHandle network fallback (DNS TXT _atproto + HTTPS /.well-known/atproto-did) | Y | Y | Y | Y | Y | N | N | ~ | Y | N | Y | N |
| resolveHandle normalizes/validates the handle before lookup | N | Y | Y | ? | ~ | Y | ? | ? | ? | ? | Y | ? |
| GET /.well-known/atproto-did served for hosted handles | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| GET /.well-known/did.json served (service DID and/or did:web account docs) | N | N | Y | Y | N | Y | Y | N | Y | Y | Y | Y |
| com.atproto.identity.updateHandle (routed, real PLC update) | Y | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| updateHandle validates handle syntax + proves ownership of off-service domains | N | Y | Y | ? | ? | ~ | n/a | N | ? | n/a | Y | N |
| updateHandle per-account rate limit | N | Y | Y | ? | ? | ~ | n/a | N | Y | n/a | Y | N |
| #identity firehose event emitted on handle change / PLC submit | N | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| com.atproto.identity.getRecommendedDidCredentials (returns the real rotation key) | Y | Y | Y | Y | Y | ~ | ~ | N | Y | Y | Y | N |
| requestPlcOperationSignature emails a challenge code (lexicon semantics, no output) | N | Y | ? | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| signPlcOperation accepts the lexicon input (token/rotationKeys/alsoKnownAs/verificationMethods/services) | N | Y | ? | Y | Y | N | Y | N | Y | Y | Y | N |
| signPlcOperation enforces the email/challenge token before signing | N | Y | ? | Y | Y | N | n/a | N | Y | n/a | Y | N |
| submitPlcOperation validates the op against service constraints before submitting | N | Y | ~ | ~ | ? | N | N | N | Y | N | Y | N |
| com.atproto.identity.refreshIdentity (routed and lexicon-conformant) | ~ | N | N | N | Y | Y | N | N | N | N | N | N |
| com.atproto.identity.resolveDid / resolveIdentity routed | N | N | N | N | ~ | Y | N | N | N | N | N | N |
| did:plc genesis at createAccount (mints and submits a real did:plc) | Y | Y | Y | Y | Y | Y | n/a | ~ | Y | n/a | Y | N |
| createAccount with a caller-supplied DID requires proof of control | N | Y | Y | Y | ~ | ? | n/a | n/a | Y | n/a | ? | N |
| activateAccount emits #account + #identity + #sync | ~ | Y | Y | ? | Y | Y | Y | ? | ~ | N | Y | Y |
| did:web account DIDs maintained (handle change and/or document publishing) | N | ~ | Y | ~ | N | ~ | Y | ~ | N | Y | ~ | Y |
| did:webvh resolution | N | N | N | N | N | N | N | N | N | N | N | N |

### Notes

- **`did:webvh` is N in all twelve columns.** atproto-crates is the only one that even carries the code — `validation.rs:607` plus a `webvh/` module — it just has no PDS caller. Read this row as field-wide absence, not a gap.
- **`/.well-known/did.json` = N includes the reference.** A grep for `did.json` over `packages/pds/src` and `bsky-pds` returns nothing, and rsky-pds serves only `/.well-known/atproto-did` (`well_known.rs:23`). atproto-crates' N is company, not an outlier.
- **atproto-crates `updateHandle` = Y but its validation row = N.** `identity_handlers.rs:155-280` performs no syntax, TLD, uniqueness or domain-ownership check before submitting the PLC operation. zds does all four (`identity.zig:213-261`).
- **metalbear and cirrus `getRecommendedDidCredentials` = ~ for the same bug.** Both put the account's *signing* did:key into `rotationKeys` (`server.c:1268-1270`; `xrpc/identity.ts:71-74`). A migration that trusts this response attaches an unrecoverable rotation key. Area K's `Y` for both was reconciled down to `~`. cirrus additionally emits `endpoint` where the DID-document schema wants `serviceEndpoint`.
- **metalbear's PLC endpoints are stubs.** `signPlcOperation` emits an unsigned skeleton with `prev: ''` (`server.c:1446-1448`) and `submitPlcOperation` never contacts the directory (`:1576-1577`), so inbound migration cannot complete on a server that is otherwise serious tier.
- **`refreshIdentity` = N in nine columns including the reference,** which declines it deliberately as directory-side work (`bluesky-reference.md:188`). atproto-crates' `~` is a divergent input field name (`did` instead of `identifier`) rather than an absence.

## E. Firehose — see [25-firehose.md](./capability-areas/25-firehose.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.sync.subscribeRepos routed (WebSocket) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Two-CBOR-object frame layout (header \|\| body, one binary msg) | Y | Y | Y | Y | Y | ? | Y | ? | Y | Y | Y | Y |
| #commit body matches lexicon required field set (flat, no wrapper) | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | ~ |
| #commit.blocks CARv1 diff present on the wire | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Covering-proof blocks included in the #commit CAR | N | Y | Y | ~ | Y | ~ | Y | Y | Y | N | Y | ~ |
| #commit.prevData emitted (inductive firehose) | ~ | Y | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y |
| #repoOp.prev on update and delete; cid null on delete | ~ | Y | Y | ~ | Y | Y | Y | Y | Y | Y | Y | ~ |
| #sync event lexicon-shaped (blocks = CAR containing the commit) | N | Y | Y | Y | Y | Y | Y | Y | Y | N | ~ | Y |
| #identity event emitted | ~ | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | Y |
| #account event emitted with correct status semantics | ~ | Y | Y | Y | Y | Y | ~ | Y | ~ | N | Y | Y |
| #info sent as a message frame (op=1, t='#info', body {name,message}) | N | Y | Y | ~ | Y | Y | Y | Y | N | Y | N | N |
| FutureCursor error on cursor beyond head | N | Y | Y | N | Y | Y | Y | Y | N | N | N | N |
| OutdatedCursor #info on cursor older than the retained window | N | Y | Y | N | Y | Y | Y | Y | N | Y | N | N |
| ConsumerTooSlow / bounded outbox with disconnect-on-lag | N | Y | N | ? | Y | N | N | N | Y | N | N | N |
| Global monotonic seq (one stream sequence, not per-repo) | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | ~ |
| Cursor resume / backfill from the durable log | ~ | Y | Y | Y | Y | Y | ~ | Y | Y | ~ | Y | ~ |
| Event log durable across restart (written with the commit) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| Backfill window / retention pruning of the event log | N | Y | Y | Y | Y | ~ | N | Y | N | ~ | N | Y |
| Server-initiated WebSocket keepalive ping | N | N | N | N | Y | Y | ~ | N | N | ~ | N | ~ |
| Automatic requestCrawl notification to configured relays | N | Y | Y | ~ | Y | Y | ~ | Y | Y | Y | ~ | Y |
| Deprecated #handle / #migrate / #tombstone correctly absent | Y | Y | Y | Y | ~ | Y | Y | N | Y | Y | Y | Y |
| Firehose test coverage (frame/cursor/event shape) | N | Y | Y | ~ | ~ | N | Y | Y | Y | Y | ? | N |

### Notes

- **atproto-crates `#commit` body = N and `#commit.blocks` = N are the same wound.** `frame.rs:116-122` nests everything under a `payload` key, and no CAR is ever produced for the firehose (`writer.rs:448-456`; `car_export` is called only from the two sync read handlers). Every other column is Y on the blocks row. A relay cannot consume this stream at all.
- **atproto-crates global monotonic seq = N.** `sequencer/outbox.rs:239` sequences per actor and `subscribe_handlers.rs:102` fans one client cursor across repos, so cursors are not comparable between repos and resume is unsound on a multi-account host.
- **`ConsumerTooSlow` = N in eight columns.** Only the reference (`outbox.ts:93-101`), rsky-pds and pegasus bound the outbox and disconnect a lagging consumer. This is a field-wide weak spot rather than an atproto-crates-specific one.
- **Server-initiated keepalive = N in the reference too** — keepalive is client-side there (`subscription.ts:27-31`). rsky-pds (30s) and metalbear (20s, explicitly sized against nginx's 60s idle timeout, `sequencer.c:556-565`) chose to add it anyway.
- **arroba is the only implementation still emitting `#tombstone`.** `Storage.tombstone_repo` (`storage.py:292-308`) writes the deprecated event that Sync 1.1 removed.
- **cirrus retention = N.** `pruneOldEvents` exists but is called only from a test (`firehose.test.ts:839`), so the event log grows without bound inside a Durable Object.

## F. Sync 1.1 — see [26-sync.md](./capability-areas/26-sync.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| #commit carries a CAR slice in `blocks` | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| covering-proof blocks (op-inversion proof set) in the #commit CAR | N | Y | Y | ~ | Y | ~ | Y | Y | Y | N | Y | ~ |
| #commit prevData emitted as a cid-link | ~ | Y | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y |
| #repoOp per-op `prev` on updates and deletes (absent on creates) | ~ | Y | Y | ~ | Y | Y | Y | Y | Y | Y | Y | ~ |
| #commit body matches the lexicon field set (flat; seq/repo/since/time/rebase/tooBig/blobs) | N | Y | Y | Y | Y | Y | Y | ~ | ? | Y | Y | ? |
| no-op update rejected or suppressed (no empty commit emitted) | N | Y | Y | N | Y | N | N | ~ | N | Y | N | N |
| #sync event carries a CARv1 of the commit block | N | Y | Y | Y | Y | Y | Y | Y | ? | N | ~ | Y |
| #sync emitted on account creation and/or activation | N | Y | Y | Y | Y | Y | Y | Y | ~ | N | Y | Y |
| com.atproto.sync.subscribeRepos routed (WebSocket, correct framing) | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| com.atproto.sync.getRepo | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y |
| getRepo `since` diff export actually implemented | Y | Y | Y | N | Y | Y | N | Y | ? | N | Y | N |
| com.atproto.sync.getLatestCommit | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | N |
| com.atproto.sync.getRepoStatus returns full lexicon shape (did/active/status/rev) | Y | Y | Y | ~ | Y | ~ | Y | ~ | Y | Y | Y | N |
| com.atproto.sync.getBlocks (with array-typed `cids` param) | ~ | Y | Y | Y | Y | Y | Y | Y | Y | ~ | N | N |
| com.atproto.sync.getRecord (existence/non-existence proof CAR) | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | ~ |
| com.atproto.sync.listRepos | N | Y | Y | ~ | Y | ~ | ~ | Y | Y | ~ | Y | ~ |
| com.atproto.sync.getBlob | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y | Y | ~ |
| com.atproto.sync.listBlobs `since` (tid) supported | N | Y | Y | N | Y | N | N | N | Y | Y | Y | N |
| com.atproto.sync.listReposByCollection | N | N | N | N | N | Y | N | N | N | N | N | N |
| com.atproto.sync.getHostStatus / listHosts (relay-side per lexicon) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| com.atproto.sync.requestCrawl routed with correct inbound semantics | N | n/a | ~ | n/a | n/a | N | n/a | n/a | n/a | n/a | ~ | n/a |
| automatic outbound crawler announcement on repo activity | N | Y | Y | Y | Y | Y | ~ | ~ | Y | Y | ? | Y |
| sync read endpoints enforce takedown/suspended/deactivated state | N | Y | ? | N | ~ | N | ~ | Y | ? | ~ | ~ | N |
| inductive verification of an inbound commit (recompute pre-image root vs prevData) | ~ | Y | Y | N | ? | ~ | ? | Y | ? | N | Y | ? |

### Notes

- **`getHostStatus` / `listHosts` is n/a in all twelve columns.** The lexicon itself says "Implemented by relays" and the reference PDS does not serve it. A blank row, not a gap row.
- **`requestCrawl` is n/a in eight columns because for a PDS it is an outbound call.** atproto-crates and metalbear are N rather than n/a because both *invert* it into an unauthenticated outbound forwarder (`handlers.rs:317-365`; `server.c:4925-5008`) that any caller can use to make the server spray relays.
- **No-op update suppression = N in seven columns.** Only the reference, tranquil-pds, rsky-pds and alteran avoid emitting an empty commit; dnproto re-signs and emits a commit with zero ops (`UserRepo.cs:246-249`).
- **atproto-crates `getRepo since` = Y is a genuine strength** — `car_export.rs:362-450` is a real diff export. cirrus, alteran and dnproto all accept `since` and silently return the full repo.
- **Reconciliation — `listBlobs since`.** This area had it `N`/`?`, area I had it fully resolved, area K had it all-`?`. Opened the two that mattered: tranquil-pds honours it (`tranquil-sync/src/blob.rs:99`, `list_blobs_since_rev`) and zds threads it into `store.writeBlobListJson` (`sync.zig:256`). All three areas now carry area I's resolved row; nothing that was resolved in two areas disagreed.
- **zds `getBlocks` and `getRecord` = N.** Neither is in `src/http/router.zig`, so a relay cannot fetch individual blocks or existence-proof CARs from zds despite an otherwise complete sync surface.

## G. OAuth authorization server — see [27-oauth.md](./capability-areas/27-oauth.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| POST /oauth/par routed (PAR, RFC 9126) | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | ~ |
| PAR + token accept application/x-www-form-urlencoded | N | Y | Y | Y | Y | ~ | Y | N | Y | Y | Y | Y |
| PKCE S256 required at PAR and verified at token exchange | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| client-metadata document fetched and validated at PAR | ~ | Y | Y | Y | Y | N | Y | N | Y | Y | Y | N |
| redirect_uri validated (against client metadata or allowlist) | N | Y | Y | Y | Y | ~ | Y | N | Y | Y | Y | ~ |
| confidential-client auth: private_key_jwt (RFC 7523) | N | Y | Y | Y | Y | N | Y | N | N | Y | Y | N |
| DPoP proof required at the AS endpoints (par / token) | N | Y | Y | Y | Y | N | Y | N | Y | Y | Y | Y |
| PAR-pinned dpop_jkt not overridable at token exchange | N | Y | Y | Y | Y | ~ | Y | N | Y | Y | Y | ~ |
| server-issued DPoP nonces (DPoP-Nonce / use_dpop_nonce) | N | Y | Y | Y | Y | N | Y | N | Y | Y | Y | N |
| DPoP enforced on resource requests (htm/htu/ath/jti/jkt) | Y | Y | Y | Y | Y | ~ | Y | N | Y | Y | Y | Y |
| rotating single-use refresh tokens | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| revocation endpoint (RFC 7009) effective for access tokens | ~ | Y | Y | Y | Y | ~ | Y | N | N | Y | Y | N |
| inbound access token: aud and iss verified at the resource server | N | Y | Y | ? | ? | Y | ? | N | Y | Y | ? | Y |
| access tokens third-party-verifiable via published JWKS | N | Y | N | ? | ? | Y | N | N | Y | N | ? | N |
| GET /oauth/jwks routed | Y | Y | Y | Y | Y | Y | ~ | N | N | Y | Y | ~ |
| /.well-known/oauth-authorization-server served (RFC 8414) | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | ~ |
| AS metadata advertises authorization_response_iss_parameter_supported + client_id_metadata_document_supported | N | Y | Y | Y | Y | Y | Y | N | ? | ? | Y | ? |
| /.well-known/oauth-protected-resource served (RFC 9728) | ~ | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | ~ |
| CORS headers on OAuth discovery / endpoints (browser clients) | N | Y | Y | Y | Y | N | Y | N | Y | Y | Y | N |
| granular scope enforcement (repo:/rpc:/blob:/account:/identity:) | N | Y | Y | ~ | N | N | Y | N | Y | ~ | Y | N |
| include:<nsid> permission-set resolution | N | Y | Y | Y | N | N | Y | N | Y | N | Y | N |
| com.atproto.temp.dereferenceScope routed locally | N | Y | Y | N | N | N | N | N | N | N | N | N |
| space: scope grammar parsed AND enforced (permissioned-data 0016) | Y | N | N | N | ~ | N | N | N | N | N | Y | N |
| RFC 9101 signed request objects (JAR) accepted at PAR | ~ | Y | N | N | N | N | N | N | N | N | N | N |
| authorization response delivered as a server-side redirect (incl. error=access_denied) | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | ~ |

### Notes

- **atproto-crates form encoding = N is the load-bearing cell in this table.** `par.rs:132-135` and `token.rs:100-103` use the JSON extractor, so a conforming client posting `application/x-www-form-urlencoded` gets HTTP 415. Nothing else in the column matters to a stock client library until this changes.
- **atproto-crates DPoP: Y on resource requests, N at the AS endpoints.** `http/auth.rs:178-181` verifies proofs on XRPC calls, but `token.rs:44-45` reads `dpop_jkt` as a JSON body field and never reads the `DPoP` header (`:100-124`). Nine implementations require the proof at PAR and token.
- **atproto-crates JWKS route = Y, third-party verifiability = N.** Access tokens are HS256 with a shared secret; `jwks.rs:5-7` concedes that the published keys verify nothing. cirrus made the same trade deliberately and ships an empty JWKS to say so (`provider.ts:947-953`).
- **arroba is N across this entire area by design.** No OAuth anywhere — a static bearer token (`server.py:22-29`). Read the arroba column here as out of product scope.
- **`space:` scope (permissioned-data 0016) is Y only in atproto-crates and zds.** rsky-pds parses the grammar but its own source says it is not wired to sessions (`src/space_scope.rs:1-10`). See [40-permissioned-overview.md](./permissioned/40-permissioned-overview.md).
- **JAR (RFC 9101) = N in ten columns.** Only the reference accepts signed request objects. atproto-crates verifies them (`par.rs:258-400`) but treats `aud` as advisory (`:383-397`) and never advertises support, hence `~`.
- **metalbear's OAuth column reads well below its tier** — no client-metadata validation, no nonces, and the resource-side verifier at `oauth.c:597-621` is dead code.

## H. Service auth and proxying — see [28-service-auth.md](./capability-areas/28-service-auth.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.server.getServiceAuth (routed) | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| service-auth JWT signed with the calling account's own key | Y | Y | Y | Y | N | Y | Y | ~ | Y | Y | Y | Y |
| getServiceAuth `exp` read as absolute Unix epoch | N | Y | Y | Y | ~ | Y | N | n/a | N | Y | Y | Y |
| BadExpiration error per lexicon | N | Y | ~ | ~ | ~ | Y | N | n/a | N | Y | Y | N |
| PROTECTED_METHODS refused at mint | N | Y | Y | ~ | Y | N | N | n/a | N | Y | Y | N |
| PRIVILEGED_METHODS gated at mint (privileged session required) | N | Y | N | N | ~ | Y | N | n/a | N | Y | N | n/a |
| takendown account blocked at mint (createAccount carve-out) | N | Y | Y | N | N | ? | n/a | n/a | N | ~ | N | n/a |
| OAuth `rpc:` scope asserted at mint | N | Y | Y | N | N | N | N | n/a | Y | Y | Y | N |
| service-JWT `typ` interoperable with reference verifier (JWT, not at+jwt) | N | Y | Y | Y | Y | ? | Y | ? | Y | Y | Y | ? |
| inbound service auth verified against issuer DID document | Y | Y | Y | ~ | Y | N | ~ | N | Y | Y | Y | Y |
| strict `lxm` on verify (token without lxm rejected) | N | Y | Y | Y | N | n/a | N | n/a | Y | N | Y | N |
| admin service-auth revocation actually enforced on the request path | N | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| `Atproto-Proxy: <did>#<service>` header honoured | ~ | Y | Y | Y | Y | Y | Y | n/a | Y | Y | Y | Y |
| arbitrary proxy DID resolved via DID document | N | Y | Y | Y | Y | ~ | Y | n/a | Y | Y | Y | Y |
| default AppView route when no Atproto-Proxy header is sent | N | Y | N | ~ | Y | Y | Y | n/a | N | Y | N | Y |
| proxy preserves the request query string | N | Y | Y | Y | Y | Y | Y | n/a | Y | ? | Y | Y |
| proxy forwards client headers (accept-language / atproto-accept-labelers) | N | Y | ? | Y | Y | N | Y | n/a | Y | Y | Y | Y |
| proxy returns upstream atproto-* response headers (repo-rev, content-labelers) | N | Y | ? | ? | Y | ? | ? | n/a | Y | ? | N | ? |
| never-proxy PROTECTED_METHODS guard on the proxy path | N | Y | Y | N | ~ | N | ? | n/a | N | Y | Y | ~ |
| `chat.bsky.*` reachable through the PDS | N | Y | Y | Y | Y | Y | Y | n/a | Y | Y | Y | Y |
| com.atproto.moderation.createReport forwarded with service auth | Y | Y | ~ | ~ | Y | N | Y | n/a | ~ | N | ~ | N |
| createAccount for an existing DID gated by inbound service auth | N | Y | Y | Y | ? | N | n/a | n/a | N | n/a | Y | n/a |
| DPoP-bound OAuth token usable on the proxy path | N | Y | ? | ? | ? | ? | Y | n/a | ? | ? | Y | n/a |

### Notes

- **atproto-crates `exp` = N.** `service_auth_handlers.rs:131-136` clamps the lexicon's absolute Unix `exp` into a 1-600 second TTL and adds it to `iat`. A client asking for an expiry timestamp gets a token that expires 600 seconds after issue. cirrus and pegasus ignore `exp` outright instead.
- **atproto-crates `typ` = N breaks interop in one line.** It mints `typ: at+jwt`; the reference verifier rejects that with `BadJwtType` (`xrpc-server/auth.ts:88-104`). Eight implementations emit plain `JWT`.
- **atproto-crates arbitrary proxy DID = N.** `proxy_handlers.rs:97-101` returns 502 `ProxyDidUnknown` for anything but the single pinned AppView DID, so labelers, chat and video services are unreachable. Nine columns resolve the DID document.
- **atproto-crates default AppView route = N for a mechanical reason.** The default pin exists but the NSID is truncated between `router.rs:109` and `proxy_handlers.rs:104`, so the match can never fire.
- **rsky-pds signs service auth with a global key.** `helpers/auth.rs:176` uses `PDS_REPO_SIGNING_KEYPAIR` rather than the calling account's key — the only N in that row, and a real interop hazard for a multi-account server.
- **Reconciliation — `createReport` forwarding.** Three `?` cells here conflicted with area J. metalbear registers `createReport` as a *local* procedure (`server.c:6943`) and persists reports itself, so it does not forward → **N**. alteran does not route it and it is not in the single-user unsupported set either (`unsupported-routes.ts:1-14` lists ten NSIDs plus the `com.atproto.admin.` prefix; `createReport` is in neither), so area J's "501 by policy" evidence is wrong although its N verdict stands → **N**. dnproto's catch-all proxies only `app.bsky.*` / `chat.bsky.*` and 501s everything else (`Pds.cs:254-271`) → **N**.
- **The admin service-auth revocation row is n/a in eleven columns** because it is not a canonical lexicon. Only atproto-crates has the endpoint, and its `contains()` check has no caller (`admin/handlers.rs:855`) — an N against a field of one.

## I. Blobs — see [29-blobs.md](./capability-areas/29-blobs.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.repo.uploadBlob (routed, real) | Y | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | Y |
| uploadBlob returns a valid lex-blob envelope ($type + ref.$link) | N | Y | Y | Y | Y | Y | Y | n/a | Y | Y | Y | Y |
| blob CID computed server-side as CIDv1/raw 0x55/sha2-256 | Y | Y | Y | Y | Y | Y | Y | n/a | Y | Y | Y | Y |
| upload size limit is enforced and operator-configurable | N | Y | Y | N | Y | Y | ~ | ~ | N | Y | Y | ~ |
| MIME sniffed from bytes rather than trusting Content-Type | N | Y | Y | N | Y | N | Y | n/a | ~ | Y | N | ~ |
| reference-time verification of record's declared mimeType/size vs stored blob | N | Y | N | N | Y | N | N | n/a | N | N | N | N |
| temp/untethered staging before a blob becomes permanent | N | Y | Y | N | Y | N | N | n/a | N | N | N | N |
| record->blob reference table populated on normal writes | N | Y | Y | Y | Y | N | N | N | Y | Y | Y | N |
| orphan blob GC when the last referencing record is deleted | N | Y | N | ~ | Y | N | N | n/a | Y | Y | N | N |
| com.atproto.repo.listMissingBlobs returns real data | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | N |
| com.atproto.sync.getBlob (routed, unauthenticated, real bytes) | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y | Y | ~ |
| getBlob applies a repo-availability gate (RepoNotFound/Takendown/Deactivated) | N | Y | Y | ~ | Y | N | n/a | ~ | ~ | ~ | Y | N |
| getBlob sets blob security headers (nosniff / content-disposition / CSP) | N | Y | ~ | N | ~ | Y | N | n/a | N | ~ | Y | N |
| getBlob restricted to blobs actually referenced by a public record | N | ~ | N | N | ~ | N | N | n/a | N | Y | Y | N |
| com.atproto.sync.listBlobs (routed, real) | Y | Y | Y | Y | Y | Y | Y | ~ | Y | Y | Y | ~ |
| listBlobs honours the `since` revision parameter (incremental blob sync) | N | Y | Y | N | Y | N | N | N | Y | Y | Y | N |
| listBlobs enumerates record-referenced blobs (not untethered uploads) | N | Y | ~ | N | Y | N | N | n/a | N | Y | Y | N |
| alternate blob byte backend (S3/R2/disk) selectable at runtime | N | Y | Y | Y | Y | N | n/a | n/a | Y | n/a | N | N |
| blob-level takedown / quarantine addressable by moderation | N | Y | Y | N | Y | N | n/a | N | ~ | n/a | ~ | N |
| OAuth blob: scope (MIME-bound) enforced on uploadBlob | N | Y | Y | N | N | N | Y | n/a | Y | N | Y | N |
| checkAccountStatus reports accurate expectedBlobs/importedBlobs | ~ | Y | Y | ~ | Y | Y | Y | N | Y | Y | Y | N |
| com.atproto.space.getBlob (0016 permissioned blob fetch) | Y | N | N | N | N | N | N | N | N | N | Y | N |

### Notes

- **Reconciliation — `listMissingBlobs returns real data`.** This area emitted `~`, area K emitted `N`. Opened the source: `blob::add_ref` (`blob.rs:115`) has no production caller anywhere in the tree — the only calls are inside `#[cfg(test)]` modules (`actor_store/sql/public_realm.rs:822-823`, `actor_store/fjall/public_realm.rs:1095-1096`) and one integration test. `repo_blob_ref` is therefore permanently empty and the endpoint always returns `[]`. Reconciled to **N** here. Area C keeps `~` because its row asks only whether the NSID is routed with the correct shape.
- **atproto-crates upload size limit = N.** `MAX_BLOB_BYTES` (`blob.rs:20`) is 16 MiB, but axum's default 2 MiB body limit sits in front of it, so the configured ceiling is unreachable and every upload over 2 MiB fails.
- **atproto-crates blob envelope = N.** `blob.rs:37-49` emits `{$link, mimeType, size}` — neither the legacy `{cid, mimeType}` form nor the current `{$type: "blob", ref: {$link}, mimeType, size}` form. Ten columns get this right; it breaks every client that uploads media.
- **Reference-time blob verification = N in nine columns.** Only the reference (`blob/transactor.ts:356-372`) and rsky-pds re-check a record's declared `mimeType`/`size` against the stored bytes.
- **`getBlob` restricted to referenced blobs = Y only in alteran and zds,** both of which join through a usage table. The reference is `~` (the blob row must exist and not be taken down, but there is no ref join). atproto-crates' N is worse in one specific way: `blob_handlers.rs:37-57` serves any `repo_blob` row, including space-only permissioned blobs, over the unauthenticated sync endpoint.
- **arroba's n/a cells are accurate, not generous.** It stores no local bytes at all — blobs are remote URLs and `getBlob` is a 301 redirect (`xrpc_sync.py:241-257`).

## J. Moderation and admin — see [30-moderation-admin.md](./capability-areas/30-moderation-admin.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.admin.updateSubjectStatus (routed) | ~ | Y | Y | N | Y | Y | n/a | N | N | n/a | Y | N |
| updateSubjectStatus canonical subject union (repoRef/strongRef/repoBlobRef) | N | Y | Y | N | Y | Y | n/a | N | N | n/a | ~ | N |
| com.atproto.admin.getSubjectStatus (routed, canonical shape) | ~ | Y | Y | N | Y | Y | n/a | N | N | n/a | N | N |
| Account takedown ENFORCED on public sync reads (getRepo/getBlocks/getBlob/listBlobs) | N | Y | Y | N | Y | N | n/a | N | N | n/a | Y | N |
| Account takedown ENFORCED on repo.getRecord / listRecords | Y | Y | Y | N | Y | N | n/a | N | N | n/a | Y | N |
| Account takedown ENFORCED on repo write paths | N | Y | Y | N | Y | N | n/a | N | ~ | n/a | Y | N |
| Takedown invalidates or restricts existing sessions / refresh tokens | N | Y | Y | N | Y | N | n/a | N | ~ | n/a | Y | N |
| Record-level takedown (public-realm repo records) | N | Y | Y | N | Y | ~ | n/a | N | N | n/a | N | N |
| Blob-level takedown | N | Y | Y | N | Y | ~ | n/a | N | N | n/a | ~ | N |
| com.atproto.moderation.createReport routed | Y | Y | Y | N | Y | Y | Y | N | N | N | N | N |
| createReport PROXIED to a moderation service (not stored locally) | Y | Y | Y | N | Y | N | Y | N | N | N | N | N |
| createReport validates lexicon-required reasonType/subject before forwarding | N | Y | ? | n/a | ~ | ? | N | n/a | n/a | n/a | n/a | n/a |
| com.atproto.admin.getAccountInfo / getAccountInfos | ~ | Y | Y | N | Y | Y | n/a | N | ~ | n/a | N | N |
| com.atproto.admin.searchAccounts | ~ | N | Y | N | N | N | n/a | N | N | n/a | N | N |
| com.atproto.admin.enableAccountInvites / disableAccountInvites at canonical NSID | N | Y | Y | N | Y | Y | n/a | N | N | n/a | N | N |
| com.atproto.admin.getInviteCodes / disableInviteCodes (canonical params + shape) | ~ | Y | Y | N | Y | Y | n/a | N | ~ | n/a | N | N |
| com.atproto.admin.sendEmail (with lexicon-required senderDid) | ~ | Y | Y | N | Y | Y | n/a | N | Y | n/a | N | N |
| com.atproto.admin.updateAccountEmail / Handle / Password | ~ | Y | Y | N | Y | Y | n/a | N | ~ | n/a | N | N |
| com.atproto.admin.deleteAccount purges repo/blob data (not just a state flip) | N | Y | ? | N | ? | Y | n/a | N | ? | n/a | N | N |
| com.atproto.admin.updateAccountSigningKey | N | N | N | N | N | N | n/a | N | N | n/a | N | N |
| Admin auth attributable to a person (beyond one shared secret) | N | Y | ~ | n/a | ~ | ~ | n/a | n/a | N | n/a | N | N |
| Handle/email banlist (denylist) with an operator interface | ~ | ~ | Y | N | ~ | N | n/a | N | N | n/a | N | N |
| Takedown state reflected on the firehose (#account event) | ~ | Y | Y | N | Y | N | n/a | N | N | n/a | Y | ~ |
| Record takedown for permissioned-data / spaces records | ~ | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| Operator admin CLI driving the admin XRPC surface | Y | Y | ~ | N | ? | Y | n/a | N | Y | n/a | ~ | N |

### Notes

- **cirrus and alteran are n/a down most of this table by declared policy.** Read every N count here against a field of ten, not twelve.
- **cocoon is N on every takedown row.** `TakeDownRepo` is an empty stub (`persist.go:159-161`) and the model has no takedown concept, on a serious-tier multi-account server.
- **metalbear records takedowns and never reads them.** The `subject_takedown` table is written but consulted on no read, write or auth path (`metalbear.md` §11). That is exactly the line between `~` and N through this area.
- **atproto-crates `updateSubjectStatus` = ~ for a shape reason with real consequences.** `admin/handlers.rs:156-162` takes `{did, state}` instead of the canonical `subject` union (`repoRef` / `strongRef` / `repoBlobRef`), so record-level and blob-level takedown cannot be expressed at all — which is why the record- and blob-takedown rows below it are N.
- **`updateAccountSigningKey` = N in ten columns including the reference.** The lexicon exists; nobody routes it.
- **atproto-crates admin auth = N.** A single Basic password compared with a non-constant-time `!=` (`handlers.rs:80`). metalbear also uses one shared secret but compares in constant time (`server.c:262-292`).
- **Reconciliation — pegasus `getAccountInfo`.** Area A scored it `Y`, this area `~`. Both are correct at their own scope: `getAccountInfo.ml:3-16` does emit the lexicon-required `indexedAt`, while this combined row is `~` because `getAccountInfos` parses the `dids` array parameter by splitting a single string on commas (`getAccountInfos.ml:6-8`), so a conforming `?dids=a&dids=b` request returns at most one account. No cell changed; the difference is row scope, not evidence.

## K. Account migration — see [31-migration.md](./capability-areas/31-migration.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| com.atproto.server.describeServer (migration step 0) | N | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | ~ |
| com.atproto.server.getServiceAuth with lxm binding | Y | Y | Y | Y | Y | Y | Y | N | ~ | Y | Y | Y |
| createAccount verifies service-auth proof of DID control (BYO-DID) | N | Y | Y | Y | ~ | N | n/a | n/a | ~ | n/a | Y | n/a |
| createAccount accepts a pre-existing did (inbound migration) | Y | Y | Y | Y | Y | Y | n/a | n/a | Y | n/a | Y | n/a |
| migrating account is created in deactivated state | N | Y | Y | N | Y | N | Y | Y | Y | n/a | Y | n/a |
| createAccount honours plcOp (+ reserved signing key) | N | ~ | N | N | N | N | n/a | n/a | N | n/a | Y | n/a |
| com.atproto.server.reserveSigningKey (routed and authenticated) | ~ | Y | Y | Y | Y | ~ | n/a | N | ~ | n/a | Y | N |
| com.atproto.repo.importRepo routed | Y | Y | Y | Y | Y | Y | Y | Y | Y | N | Y | N |
| importRepo indexes imported records into the read path | N | Y | Y | Y | ? | ? | Y | Y | Y | n/a | Y | n/a |
| importRepo extracts blob refs from imported records | N | Y | Y | Y | Y | Y | Y | N | Y | n/a | Y | n/a |
| importRepo verifies the incoming commit-chain signature | N | N | Y | N | ? | ? | ~ | Y | ? | n/a | ~ | n/a |
| com.atproto.sync.listBlobs supports the lexicon since (tid) param | N | Y | Y | N | Y | N | N | N | Y | Y | Y | N |
| com.atproto.repo.listMissingBlobs returns real data (not always empty) | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | N |
| app.bsky.actor.get/putPreferences served locally as PDS-private state | N | Y | Y | Y | Y | Y | Y | ~ | Y | Y | Y | Y |
| com.atproto.identity.getRecommendedDidCredentials | Y | Y | Y | Y | Y | ~ | ~ | N | Y | Y | Y | N |
| signPlcOperation uses the canonical lexicon input shape | N | Y | Y | Y | Y | Y | Y | N | Y | Y | Y | N |
| signPlcOperation gated on a confirmation token / second factor | N | Y | Y | Y | Y | Y | Y | N | Y | N | Y | N |
| submitPlcOperation validates the op targets this PDS before forwarding | N | Y | ? | ~ | ? | ? | ~ | N | Y | N | ~ | N |
| checkAccountStatus emits all 9 lexicon-required fields | ~ | Y | Y | ~ | Y | Y | ~ | N | Y | N | Y | ~ |
| checkAccountStatus.validDid is actually resolved (not hardcoded) | N | Y | Y | N | Y | Y | Y | N | Y | N | ? | N |
| activateAccount refuses when the DID document does not point at this PDS | N | Y | ? | N | Y | N | ~ | n/a | ? | n/a | ? | ? |
| activateAccount emits #account + #identity + #sync | ~ | Y | Y | ~ | Y | ~ | Y | n/a | ~ | n/a | Y | Y |
| deactivateAccount honours deleteAfter | Y | Y | Y | ~ | Y | Y | ~ | n/a | ~ | n/a | ? | ? |
| end-to-end migration tooling (CLI/wizard) or operator runbook | N | Y | Y | ~ | ? | ~ | Y | N | Y | ~ | ~ | ~ |

### Notes

- **Reconciliations landed in this area.** `describeServer` dnproto `Y` → `~` (see area A); `getRecommendedDidCredentials` metalbear and cirrus `Y` → `~` (see area D); the all-`?` `listBlobs since` row replaced with area I's resolved values; `getServiceAuth with lxm binding` cirrus `~` → **Y** (lxm is read and passed to `createServiceJwt`, `xrpc/server.ts:412,427`) and pegasus held at `~` for a different reason than originally cited — it binds lxm but substitutes the non-canonical wildcard `"*"` when the parameter is absent (`getServiceAuth.ml:8-12`). The ignored-`exp` defect that originally drove both downgrades is scored in area H, row 3, where it belongs.
- **atproto-crates creates migrating accounts Active = N.** `account/manager.rs:158` binds `AccountState::Active` unconditionally, so an inbound migration's repo is publicly readable and on the firehose before its DID document points at this PDS. Seven columns create it deactivated.
- **atproto-crates `reserveSigningKey` = ~ because it is unauthenticated.** Routed at `router.rs:169`, no guard at `auth_handlers.rs:891`. metalbear lists it public too (`server.c:208`).
- **atproto-crates `importRepo` indexes nothing.** `repo/import.rs` mentions `repo_record` only in a doc comment (`:10`), so imported records land in the MST but never in the read path — `getRecord` and `listRecords` see an empty repo after a successful import.
- **importRepo signature verification = N in the reference as well.** `importRepo.ts:54-63` runs `verifyDiff` and re-signs without checking the incoming signature. Only tranquil-pds (`repo/import.rs:130`) and arroba (`xrpc_repo.py:241-243`) verify against the source DID document.
- **alteran and dnproto are n/a across most of this area** because neither routes `createAccount` or `importRepo`; alteran's inbound path is an offline script (`scripts/import-car-to-d1.ts`).

## L. Operations — see [32-ops.md](./capability-areas/32-ops.md)

| Capability | atproto-crates | bluesky-reference | tranquil-pds | cocoon | rsky-pds | metalbear | cirrus | arroba | pegasus | alteran | zds | dnproto |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| per-IP rate limiting | N | Y | Y | N | N | ~ | N | N | Y | Y | N | N |
| rate limiting on repo writes / blob uploads | N | Y | N | N | N | Y | N | N | Y | Y | N | N |
| rate limiting on createSession (login) | ~ | Y | Y | N | N | Y | N | N | Y | Y | N | N |
| rate-limit middleware covering the whole route table | N | Y | N | N | N | Y | N | N | N | N | N | N |
| distributed / shared rate-limit backend (Redis or Valkey) | ~ | Y | Y | N | N | N | N | N | N | ~ | N | N |
| RateLimit-* response headers on 429 | N | Y | N | N | N | ? | N | N | Y | N | N | N |
| configurable blob/body upload size limit | N | Y | ? | ? | Y | Y | ~ | ? | ? | Y | Y | ? |
| GET /xrpc/_health | Y | Y | Y | Y | Y | Y | Y | ~ | Y | ~ | Y | Y |
| readiness probe that touches a dependency | Y | Y | Y | N | Y | N | Y | ~ | N | Y | N | N |
| Prometheus / OpenMetrics endpoint | ~ | N | Y | Y | N | N | N | N | N | ~ | ~ | ~ |
| OpenTelemetry / OTLP export | Y | N | N | N | N | N | N | N | N | N | N | N |
| per-request correlation ID in logs or response headers | N | Y | ? | ~ | ~ | N | N | N | N | Y | N | N |
| operator backup / restore path | N | N | ? | Y | N | ~ | N | N | Y | N | N | Y |
| outbound transactional email in the default/shipped build | N | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| startup validation of production secrets | Y | ~ | Y | N | N | ~ | ~ | N | N | ~ | ? | N |
| config file (TOML/YAML) support at runtime | N | N | Y | N | N | Y | ~ | N | N | ~ | N | ~ |
| multi-account hosting | Y | Y | Y | Y | Y | Y | n/a | Y | Y | n/a | Y | n/a |
| published container image | N | Y | Y | Y | Y | Y | n/a | N | Y | n/a | Y | N |
| packaged self-host deployment (installer / systemd / nix / compose) | ~ | Y | Y | Y | N | Y | Y | N | Y | ~ | Y | ~ |
| operator admin CLI | ~ | Y | ~ | Y | Y | Y | Y | N | Y | ~ | ~ | Y |
| graceful drain of background workers on shutdown | N | Y | Y | N | ? | ? | n/a | ~ | ? | n/a | ? | ? |
| CI that builds and tests the PDS | N | Y | ~ | Y | Y | Y | Y | ~ | ~ | Y | Y | N |
| operator runbook / ops documentation | N | Y | ~ | ~ | N | Y | Y | N | ~ | Y | Y | ~ |

### Notes

- **atproto-crates OTLP = Y is the only Y in that row.** `telemetry.rs:32-67` exports spans over OTLP HTTP with a W3C propagator. The reference has neither OpenTelemetry nor a Prometheus endpoint.
- **atproto-crates rate limiting = N, and the shape matters more than the symbol.** Four of 104 routes are limited; the `createSession` limiter keys on the caller-supplied identifier with no IP component (`auth_handlers.rs:300`); and the Valkey backend that would make limits shared across replicas (`valkey_backend.rs:131-211`) is not compiled into the shipped image. Seven of twelve columns are N here, so the field is weak — but the reference and metalbear both cover the whole route table.
- **atproto-crates `--config` = N in a way worth spelling out.** The flag is declared at `bin/pds.rs:44` and never read, and the precedence documentation at `:42` describes behaviour that does not exist.
- **atproto-crates ships no PDS container image and no CI.** `release-binaries.yml` builds four CLI binaries and not the server; `README.md:29-32` cites a `ci.yml` that is not in the repository.
- **atproto-crates email = N in the shipped build.** `smtp` is not a default feature and `Dockerfile:63,83` builds without it, so password-reset and account-delete tokens are logged at INFO instead of sent — which silently converts two of area A's `Y` cells into an unusable flow in production.
- **cocoon and pegasus both ship backup paths the reference lacks** — hourly `VACUUM INTO` to S3 (`server.go:673-691`) and a periodic copy of every `.db` file (`s3/backup.ml:25-60`). `pdsadmin` has no backup subcommand.
- **metalbear's `src/backup.c` exists but is unreachable from the binary or the CLI.** That pattern — real code with no caller — is what separates `~` from `Y` in several rows of this area, and it is the same pattern behind atproto-crates' `~` cells.

## How to read the atproto-crates column

`n/a` in the cirrus, alteran and dnproto columns marks a deliberate single-user scope decision, so
an atproto-crates `N` on those rows is being compared against a field of nine or ten, not twelve —
check the maturity table before reading a row's N count as a verdict. The bluesky-reference column
is a ceiling rather than a bar: it is the implementation the lexicons are generated from, and
several of its own cells are `N` or `n/a` (`did.json`, `refreshIdentity`, `listReposByCollection`,
metrics, backup) where independent projects chose to do more. The rows that should carry weight for
release readiness are the ones where atproto-crates is `N` and the *independent* field is uniformly
`Y` — those are enumerated and prioritised in
[50-synthesis-and-roadmap.md](./50-synthesis-and-roadmap.md).
