# Gap-analysis remediation progress

Report: .claude/context/gap-analysis/ (dated 2026-07-28, report HEAD `18b826f`)

**Report-baseline correction:** the commit `18b826f` cited by the report does not exist in this
repository — it was on the analysis branch `claude/atproto-crates-rc-gap-analysis-c6604d`, which was
never pushed to `origin`. All re-verification is therefore done against `main` (`abb5497`,
`release: 0.15.0-rc.1`), not against a diff from the report's HEAD.

| Finding | Milestone | Status | Branch | PR | Notes |
| --- | --- | --- | --- | --- | --- |
| F-OPS-01 + F-FIRE-13 | M1.1 | merged | F-OPS-01 | [#3](https://tangled.org/ngerakines.me/atproto-crates/pulls/3/round/0) | merged as `30463a7` (tangled replayed the SHA). CI + interop oracle — unblocks M1.2, M1.3, M1.9, M1.10, M1.11 |
| F-REPO-01 | M1.2 | merged | F-REPO-01 | [#4](https://tangled.org/ngerakines.me/atproto-crates/pulls/4) | merged as `382138f` |
| F-REPO-02 | M1.3 | merged | F-REPO-02 | [#5](https://tangled.org/ngerakines.me/atproto-crates/pulls/5) | merged as `043e02d` |
| F-OAUTH-01 + F-OAUTH-02 + F-OAUTH-03 | M1.4 + M2.1 + M2.2 | merged | F-OAUTH-01 | [#6](https://tangled.org/ngerakines.me/atproto-crates/pulls/6) | coupled group, shipped together; merged as `d7aed4a` |
| F-BLOB-01 | M1.5 | merged | F-BLOB-01 | [#7](https://tangled.org/ngerakines.me/atproto-crates/pulls/7) | merged as `0756999` |
| _(CI follow-up)_ | — | merged | ci-clippy-fix | [#8](https://tangled.org/ngerakines.me/atproto-crates/pulls/8/round/0) | toolchain pinned to 1.90; local now matches CI |
| F-SVC-03 + F-SVC-04/05/06/07 | M1.6 + M2.15 | merged | F-SVC-03 | [#9](https://tangled.org/ngerakines.me/atproto-crates/pulls/9) | coupled group; merged as `3b50308` |
| F-ACCT-01 + F-SYNC-01 + F-IDENT-04 + F-OPS-05 | M1.7 + M4.1 | merged | F-ACCT-01 | [#10](https://tangled.org/ngerakines.me/atproto-crates/pulls/10) | merged as `b01820b` |
| F-REC-01/02/03 + F-FIRE-04 (part) | M1.8 | merged | F-REC-03 | [#11](https://tangled.org/ngerakines.me/atproto-crates/pulls/11) | merged as `6c925a7` |
| F-REPO-03 | M1.9 | merged | F-REPO-03 | [#12](https://tangled.org/ngerakines.me/atproto-crates/pulls/12) | merged as `e077f1b` |
| F-REPO-04 | M1.10 | merged | F-REPO-04 | [#13](https://tangled.org/ngerakines.me/atproto-crates/pulls/13) | merged as `27bf577`; all six upstream MST vectors green |
| F-REPO-05 | M1.11 | merged | F-REPO-05 | [#14](https://tangled.org/ngerakines.me/atproto-crates/pulls/14) | merged as `480a493`; data-model vectors 3/3 |
| F-SVC-01 + F-SVC-02 | M1.12 | merged | F-SVC-01 | [#15](https://tangled.org/ngerakines.me/atproto-crates/pulls/15) | merged as `636f455` |
| F-FIRE-01 + F-FIRE-04 | M1.13 (B-1) | merged | F-FIRE-01 | [#16](https://tangled.org/ngerakines.me/atproto-crates/pulls/16) | merged as `05cb63e`; firehose `KNOWN_FAILURES` now empty |
| F-FIRE-05 | M1.13 (B-2) | merged | F-FIRE-05 | [#17](https://tangled.org/ngerakines.me/atproto-crates/pulls/17) | merged as `5c39cc2`; also closes F-FIRE-10. **M1.13 complete** |
| F-FIRE-02 + F-FIRE-03 | M1.14 | merged | F-FIRE-02 | [#18](https://tangled.org/ngerakines.me/atproto-crates/pulls/18) | merged as `93846fa`. **M1 COMPLETE** |
| F-OPS-03 | M2.3 | merged | F-OPS-03 | [#19](https://tangled.org/ngerakines.me/atproto-crates/pulls/19) | merged as `10f898d`; also unbroke the release build + added a CI release step |
| F-BLOB-05 | M2.4 | merged | F-BLOB-05 | [#20](https://tangled.org/ngerakines.me/atproto-crates/pulls/20) | merged as `ea3ae17` |
| F-OAUTH-04 | M2.5 | merged | F-OAUTH-04 | [#21](https://tangled.org/ngerakines.me/atproto-crates/pulls/21) | merged as `4f4eced`. **ALREADY FIXED** by PR #6; branch removed the re-armable trap |
| F-BLOB-06 + F-BLOB-07 (part) + F-OPS-11 (part) | M2.6 | merged | F-BLOB-06 | [#22](https://tangled.org/ngerakines.me/atproto-crates/pulls/22) | merged as `5867da1`; per-account quota still open |
| F-MOD-04 | M2.7 | merged | F-MOD-04 | [#23](https://tangled.org/ngerakines.me/atproto-crates/pulls/23) | merged as `86220bf`. **Breaking: unconfigured PDS no longer boots** |
| F-MOD-06 + F-MOD-05 | M2.8 | merged | F-MOD-06 | [#24](https://tangled.org/ngerakines.me/atproto-crates/pulls/24) | merged as `cd0525b`. **Breaking admin wire changes, no aliases** |
| F-REPO-06 | M2.9 | merged | F-REPO-06 | [#25](https://tangled.org/ngerakines.me/atproto-crates/pulls/25) | merged as `9cc5393`. **Verification is now stricter** |
| F-OAUTH-06 | M2.10 | merged | F-OAUTH-06 | [#26](https://tangled.org/ngerakines.me/atproto-crates/pulls/26) | merged as `c36f141`; wider than the finding — covers `/xrpc/*` too. **All starred M2 items done** |
| F-OAUTH-05 | M2.11 | merged | F-OAUTH-05 | [#27](https://tangled.org/ngerakines.me/atproto-crates/pulls/27) | merged as `1161641`; PAR half was already fixed by PR #6, spaces half + an unnamed third sink closed |
| F-MOD-01 + F-MOD-02 + F-ACCT-09 + F-ACCT-04 + F-BLOB-04 | M2.12 | merged | F-MOD-01 | [#28](https://tangled.org/ngerakines.me/atproto-crates/pulls/28) | merged as `3e51941`; five-finding group. **Deactivated accounts lose ordinary writes** |
| F-ACCT-02 + F-ACCT-03 + F-ACCT-15 + F-SVC-14 | M2.13 | merged | F-ACCT-02 | [#29](https://tangled.org/ngerakines.me/atproto-crates/pulls/29) | merged as `f751cc8`. **BYO-DID needs service auth — no escape hatch** |
| F-OAUTH-12 | M2.14 | merged | F-OAUTH-12 | [#30](https://tangled.org/ngerakines.me/atproto-crates/pulls/30) | merged as `271856f`. **Narrow-scoped tokens now refused where they used to succeed** |
| F-BLOB-02 | M2.16 | merged | F-BLOB-02 | [#31](https://tangled.org/ngerakines.me/atproto-crates/pulls/31) | merged as `38830ff`. Also unbroke the fjall test build |
| F-MIG-01 | M2.17 | merged | F-MIG-01 | [#32](https://tangled.org/ngerakines.me/atproto-crates/pulls/32) | merged as `1d724f2`. Reuses `walk_blob_refs` from M2.16 |
| F-MIG-02 | M2.18 | merged | F-MIG-02 | [#33](https://tangled.org/ngerakines.me/atproto-crates/pulls/33) | merged as `6b475fc`. Preferences stored opaquely per-actor |
| F-REC-04 | M2.19 | merged | F-REC-04 | [#34](https://tangled.org/ngerakines.me/atproto-crates/pulls/34) | merged as `a355059`. Real CAS inside the per-DID write mutex; the interim rejection option was not needed |
| F-IDENT-01 + F-IDENT-02 + F-IDENT-03 + F-IDENT-05 (+ F-IDENT-11) | M2.20 | merged | F-IDENT-01 | [#35](https://tangled.org/ngerakines.me/atproto-crates/pulls/35) | merged as `d3d67d5`. Four-finding group; F-IDENT-11 pulled in because the email-token gate is not implementable without it. **Three breaking wire changes** |
| F-MOD-03 + F-BLOB-15 | M2.21 | merged | F-MOD-03 | [#36](https://tangled.org/ngerakines.me/atproto-crates/pulls/36) | merged as `9708d32`. Canonical subject union + record/blob takedown. **Breaking: `{did, state}` gone, no alias** |
| F-OPS-02 + F-OPS-07 | M2.22 | merged | F-OPS-02 | [#37](https://tangled.org/ngerakines.me/atproto-crates/pulls/37) | merged as `2a41aa4`. Per-IP limiter over every route. **Breaking: all routes limited; `memory` durability refused in production** |
| F-REC-05 (structural) | M2.23 | merged | F-REC-05 | [#38](https://tangled.org/ngerakines.me/atproto-crates/pulls/38) | merged as `2eed30f`. **Deviates from the roadmap item: `$type` is supplied, not rejected** — the reference fills it in |
| F-OPS-06 + F-BLOB-09 | M2.24 | merged | F-OPS-06 | [#39](https://tangled.org/ngerakines.me/atproto-crates/pulls/39) | merged as `bf4c383`. **User chose: document both unsupported.** Postgres measured L/XL, S3 S/M. **Breaking: setting either variable refuses at boot**. **PDS `-rc` gate closed** |
| F-SPACE-19 + F-SPACE-04 + F-SPACE-18 | M3.1 | merged | F-SPACE-19 | [#40](https://tangled.org/ngerakines.me/atproto-crates/pulls/40) | merged as `3be0be7`. Coupled group. **Breaking: spaces created before this must be recreated; no migration is possible** |
| F-SPACE-30 | M3.2 | merged | F-SPACE-30 | [#41](https://tangled.org/ngerakines.me/atproto-crates/pulls/41) | merged as `59c93ac`. Cause was a type, not a line: `OwnPds` borrowed a DID nothing could lend. Compile-time regression guard |
| F-SPACE-07 | M3.3 | merged | F-SPACE-07 | [#42](https://tangled.org/ngerakines.me/atproto-crates/pulls/42) | merged as `e709c59`. **Inherited from the reference draft — upstream issue still owed.** Membership gated per read, deliberately not behind the scope gate |
| F-BLOB-03 + F-SPACE-12 | M3.4 | merged | F-BLOB-03 | [#43](https://tangled.org/ngerakines.me/atproto-crates/pulls/43) | merged as `5b371f8`. Public blobs = publicly-referenced blobs; `space_blob_ref` keys the rest. **Breaking: unreferenced blobs no longer publicly fetchable** |
| F-SPACE-11 | M3.5 | merged | F-SPACE-11 | [#44](https://tangled.org/ngerakines.me/atproto-crates/pulls/44) | merged as `571f863`. Viewer parameter removed, not corrected — it only ever selected the wrong store |
| F-SPACE-03 | M3.6 | merged | F-SPACE-03 | [#45](https://tangled.org/ngerakines.me/atproto-crates/pulls/45) | merged as `ae85ebf`. Values inlined by default; superseded-op omission via CID-matched join. **Breaking: responses much larger by default** |
| F-SPACE-01 + F-SPACE-02 + F-SPACE-20 | M3.7 | merged | F-SPACE-01 | [#46](https://tangled.org/ngerakines.me/atproto-crates/pulls/46) | merged as `473f617`. CAR export + canonical `getLatestCommit`; `getRepoState` kept as alias |
| F-SPACE-05 | M3.8 | merged | F-SPACE-05 | [#47](https://tangled.org/ngerakines.me/atproto-crates/pulls/47) | merged as `22fdcab`. Hash propagation loop closed. Sent always, optional on receipt |

**Report correction (F-REPO-01):** the report says "three attributes" and cites `node.rs:30`,
`entry.rs:54`, `commit.rs:52`. There are **four** — it missed `commit.rs:83`, the same attribute on
`UnsignedCommit.prev`, which is the struct `Commit::signing_bytes` serializes. Fixing only the three
cited would leave commit signatures over the wrong bytes while appearing to close the finding.

**Measured:** the fix does *not* flip any of the six upstream commit-proof vectors; F-REPO-04 is also
required. The `KNOWN_FAILURES` entries in `interop_mst.rs` are unchanged and still accurate.

## Decisions taken

- **CI platform: tangled spindle only** (`.tangled/workflows/ci.yml`). `origin` is tangled.org; the
  existing `.github/workflows/release-binaries.yml` is left untouched. `crates/atproto-pds/README.md`
  was repointed from the non-existent `.github/workflows/ci.yml` to the real workflow.
- **Red interop vectors use a `KNOWN_FAILURES` table, not `#[ignore]`.** A listed vector is required
  to fail; if it starts passing the harness fails and names the finding that must now be closed.
  Both guard directions were verified by perturbing the table. This is the handover mechanism for
  every later encoding finding — when M1.2/M1.9/M1.10/M1.11 land, the suite reports which entries to
  delete.

## Notes and corrections to the report

- **F-OPS-01 — CONFIRMED, and worse than reported.** All four cited facts hold on `main`. Three
  additional pre-existing breakages were found that the absence of CI allowed into the
  `0.15.0-rc.1` release commit:
  1. `Cargo.lock` is corrupt — 35 duplicate `[[package]]` stanzas plus an inconsistent
     `data-encoding` resolution, from a bad merge. `cargo` refuses to parse it, so **nothing in the
     workspace builds from a clean checkout of `main`**.
  2. `crates/atproto-space/benches/set_hash.rs` is stale (missing `criterion` dev-dep, references
     `XorSha256SetHash` which no longer exists and `set_hash_ecmh` which is not a declared module),
     so `cargo clippy --workspace --all-targets` fails to compile.
  3. `cargo test --workspace` fails 13/13 in `atproto-dasl`'s `dasl_compliance_test` because the
     `dasl-testing` submodule is not checked out. The gitlink *is* recorded
     (`533e6d5fa49d061f6443b7f7a84eecb5c58f36c0`); `git submodule update --init` makes all 13 pass.

  Baseline after repairing the lockfile: `cargo fmt --check` clean; `cargo clippy --workspace
  --all-targets` clean once the stale bench is removed; `cargo test --workspace --no-fail-fast`
  1976 passed / 13 failed / 63 ignored, the 13 being the submodule fixtures.

- **External oracle located.** `bluesky-social/atproto-interop-tests` (CC-0, HEAD `056e574`,
  2026-07-01) carries `mst/`, `firehose/commit-proof-fixtures.json` and `data-model/` known-answer
  vectors. Measured against `main`:
  - `mst/key_heights.json` — 9/9 pass.
  - `firehose/commit-proof-fixtures.json` — **0/6 MST root CIDs match**, before *and* after commit.
    Empirically confirms F-REPO-01's stated consequence.
  - `data-model/data-model-fixtures.json` — 1/3 CBOR+CID match; the two `$link`/`$bytes` fixtures
    fail, empirically confirming F-REPO-05.

- **F-FIRE-13 — CONFIRMED.** `crates/atproto-pds/src/sequencer/frame.rs:162-255` holds exactly six
  unit tests; `:206` and `:237` assert `v["payload"]["rev"]` / `body["payload"]["rev"]`, i.e. they
  pin the nested-envelope divergence F-FIRE-01 describes. No test in
  `crates/atproto-pds/tests/` (23 files) opens a WebSocket; the sole `subscribeRepos` mention is a
  doc comment at `http_phase8_polish.rs:6`.

## F-REPO-02 notes

- The report's "move `prevData` onto the firehose event" was **half done already** — the outbox
  `#commit` payload emits it at `crates/atproto-pds/src/repo/writer.rs`. The change was a removal
  from the commit, not a move.
- Two consumers read `prevData` off the commit and now derive it from the chain: `import.rs`'s
  verification loop (the cross-check it performed had no input left) and its `commit_obj` insert
  (`prev_data_cid` now comes from the previous commit's `data`).
- **Known consequence:** commits written before this decode fine but no longer verify, because
  signature checking reconstructs signed bytes from the decoded struct. CARs previously exported by
  this server fail signature-verified re-import. Already true via F-REPO-01.

## Resolved: spindle CI

**Confirmed working.** The pipeline parses and runs; it caught a `clippy::const_is_empty` failure on
`main` that local runs did not. F-OPS-01's CI half is closed.

It also exposed a defect in the workflow I wrote: the toolchain was unpinned, so CI and local
development ran different compilers and disagreed about lints. Fixed on `ci-clippy-fix` by adding
`rust-toolchain.toml` (1.90, matching `rust-version` and the Dockerfile) and switching the spindle
to `rustup`. **Verified that clippy 1.90 finds exactly one issue workspace-wide — the reported one.**

Consequence for this process: every branch merged before that pin was verified on 1.95 only. None
are known bad, but none were checked against the compiler CI actually used.

## F-OAUTH-01 group notes

- **Report correction:** F-OAUTH-02 says the token endpoint never checks `redirect_uri`. It does —
  `token.rs:154` already compared it to the stored value. The defect was the DPoP binding only.
- **Report correction:** the "workspace SSRF guard" is not `atproto-identity/src/host.rs` (that is
  `did:web`/`did:webvh` host extraction). The URL-level guard is
  `validation::validate_service_endpoint` at `crates/atproto-identity/src/validation.rs:741`.
- Adding a client-metadata fetch to PAR **widened** the F-OAUTH-05 SSRF sink (previously only the
  JAR path fetched). The fetches added here are guarded; the JAR-path and spaces fetches are not,
  and remain M2.11.
- Two intended behaviour changes: `token_type` is now `DPoP` on every token, and a `client_id`
  must be resolvable (HTTPS metadata document, or a loopback `http://localhost[?…]` identifier).

## Process note

The shell working directory silently reset from the worktree to the main repo mid-session, and two
`python3` edits using relative paths landed in the main checkout. Caught and reverted before
committing; main was clean. **Use absolute paths, or `cd <worktree> &&` in every command.**

## F-BLOB-01 notes

- No new type was needed: `atproto_record::lexicon::TypedBlob` already modelled the canonical
  envelope and `atproto-pds` already depended on the crate. The fix deleted a divergent second
  definition rather than adding one — another "built but not wired" case.
- The vendored interop corpus (`tests/interop/data-model/data-model-fixtures.json`, fixture #1's
  `c` value) already carried the canonical blob shape, so M1.1's oracle covered this finding too.

## Coupled group NOT in the original brief

**F-SVC-03 must ship with F-SVC-04/05/06/07.** §2 item 9 states it outright: the wrong `typ` is the
only thing making the unrestricted-credential defects unexploitable at real peers, so fixing `typ`
alone makes them live. §5 lists M1.6 as effort `S` with an empty `Depends on`, which contradicts §2.
§2 is right, and the code agreed on inspection. Shipped as one branch on Nick's instruction.

Treat the brief's coupled-group list (SPACE trio, OAUTH trio) as non-exhaustive — check §2 before
starting any finding whose fix removes an obstacle rather than adding a control.

## Report corrections (F-SVC group)

- F-SVC-04 reads as "require `lxm` at mint". The reference does **not**: it permits a method-less
  token and caps it at 60 seconds, putting the hard requirement on the verify side
  (`auth.ts:119-127`, which is what the report actually cites). Implemented the reference's split.

## F-ACCT-01 group notes

- The report says `sync.listRepos` only needs the existing `list_account_dids`. It needs more:
  `listRepos#repo` requires `{did, head, rev}`, so it joins accounts against their latest commit.
- **F-OPS-05 closed by deletion, not by mounting.** `deploy/well-known/*/did.json` were never mounted
  and every container already sets `PDS_SERVICE_DID` to the DID those files described, so the
  synthesised document is identical. Removed the files rather than adding a second source of truth.
- Transient SSH failures to tangled.org (`kex_exchange_identification: Connection reset`) hit twice
  while fetching; retrying worked. Not a repo problem.

## M1.8 notes

- **F-REC-03 needed a logic fix, not just `skip_serializing_if`.** Both `list_records` paths set the
  cursor from `rows.last()` unconditionally, so a partial final page advertised a cursor leading to
  an empty page that then carried `"cursor": null`.
- **`#repoOp.prev` keeps its `skip_serializing_if`.** The report groups it with `cid` as "the same
  root cause as F-REPO-01"; the lexicon declares `cid` required-and-nullable but `prev` *optional*
  ("for creations, field should not be defined"). Removing both would break every create.
- **F-REC-02 was wrong three ways**, not one: missing `$type`, per-result `commit` that the schema
  puts at the top level, and a `uri` on delete results that `#deleteResult` does not define.
- **`describeRepo.didDoc` is synthesised, not resolved** — a deliberate divergence from the
  reference, because the field is required and resolving would make a PLC outage fail the call.
  Flagged for review in the PR.

## M1.9 notes — and a dependency for M1.10

- **Reproduced the corruption**: 3 of 20 single-key deletes corrupt a 20-key/four-collection tree,
  and the damage *cascades* to the end of the node (one delete mangled nine records). The report's
  "rewrites a neighbouring record's key" understates the blast radius.
- Fixed structurally — derive all full keys, remove one, rebuild compression — rather than by
  correcting the index arithmetic, matching how the reference avoids the class.
- **No repair path exists for already-corrupted repositories.** The wrong keys are committed and
  signed with no record of the originals. Detecting it after the fact means diffing the MST key set
  against `repo_record`; that is separate work nobody has scoped.
- **M1.10 must carry a recursive delete.** `delete_recursive` never recurses — it ignores
  `node.left` and `entry.tree`, so a delete inside a subtree does nothing. Harmless only because
  `insert` never builds subtrees today (F-REPO-04). The moment height-aware insert lands, deletes
  start silently failing in subtrees.

## M1.10 — the interop oracle paid off

**All six upstream commit-proof vectors pass**, before and after commit. First time this workspace
produces MST roots a peer can recompute. The `KNOWN_FAILURES` table failed the suite to announce its
own entries were stale — the mechanism chosen in M1.1 working exactly as intended — and is now empty.

- **F-REPO-01 and F-REPO-04 were both load-bearing; neither alone moved a single vector.** That was
  the open question when the vectors landed and it is now answered.
- **Planned as B-1/B-2, delivered as one.** Merge and trim turned out to be required for delete to
  *function*, not just to canonicalise: removing a leaf between two subtrees leaves them adjacent,
  which no valid node can represent. `to_node` rejecting that shape is what surfaced it. With merge
  in place `rootAfterCommit` went green alongside `rootBeforeCommit`, so there is no B-2.
- **`get` and `delete` were rewritten too**, disclosed before starting: both were silently broken by
  subtrees existing. `diff.rs` and CAR export untouched as promised.
- **No migration for existing repositories** — they re-root on next write, but nothing rebuilds them
  into canonical shape ahead of time.

## Remaining in M1

M1.11 (F-REPO-05, record encode path — `$link` → tag 42, `$bytes`, reject non-integer numbers) is
the last M-sized item; the `data-model` interop vectors already sit red at 1/3 waiting for it.
M1.12 (proxy), M1.13 (firehose envelope, L) and M1.14 (CARv1 slices, L) remain.

## M1.11 notes

- **The read path had to change too**, which the finding does not mention: once records hold tag 42,
  `serde_json::Value` cannot decode them and `getRecord`/`listRecords` fail outright. Found by
  probing the round trip before wiring, not by a test afterwards.
- **`123.0` must be accepted as an integer; `123.456` must be refused.** The `data-model-valid`
  fixture's "float, but integer-like" case caught a mistake I was about to make ("reject floats").
- **Revised my own M1.1 design decision**: the interop harness asserted `to_vec(&Value)`, assuming
  the translation belonged in the generic encoder. It doesn't — `to_vec` is generic over
  `T: Serialize`, so sentinel-sniffing would change encoding for any type with a `$link` field. The
  harness now calls `atproto_json::to_vec`; expected bytes and CIDs unchanged.
- The vendored-but-unused `data-model-valid.json` and `data-model-invalid.json` are now wired.

## New finding candidate — spaces record encoding

`crates/atproto-pds/src/space/writer.rs:285` calls `atproto_dasl::to_vec(&value)` on a record body,
the **identical** defect F-REPO-05 fixes for the public repo. Spaces records containing blob refs get
non-interoperable CIDs. One line now that `atproto_json::to_vec` exists, but it is M3 territory and
was left out of the F-REPO-05 branch on scope grounds. **Not in the report as far as I can tell** —
worth filing.

## M1.12 notes

- **Reproduced the routing defect before touching it**: `/xrpc/app.bsky.{*nsid}` yields
  `nsid=feed.getTimeline`, so the `starts_with("app.bsky.")` pin can never match. Query was
  available on the `Uri` all along and simply never read.
- **The existing unit tests concealed it** by calling `resolve_target` with a hand-written full
  NSID. Every new test routes a real request against a stand-in upstream.
- Caching resolver follows the existing `CachingSpaceDeclarationResolver` shape. Negative results
  cached too, so a bad `Atproto-Proxy` header cannot amplify one inbound request into many outbound.
- `resolve_target` is now `async`; private, four unit tests updated.

## M1 remaining

Only **M1.13** (F-FIRE-01/04/05 — firehose flat bodies, native CBOR payloads, global sequence; L)
and **M1.14** (F-FIRE-02/03 — real CARv1 slices; L, depends on M1.13). Both large. M1.14 also
depends on M1.10, which is merged.

## F-FIRE-01 + F-FIRE-04 — merged (PR #16, `05cb63e`)

Branch `F-FIRE-01`, merged as `05cb63e` (content-identical to the pushed `99e4e1e`). Draft at `.claude/context/pr-drafts/F-FIRE-01.md`.
This is **B-1** of the M1.13 split the user approved: B-1 = shape + encoding, B-2 = F-FIRE-05
(global sequence) on its own branch, then M1.14.

**Both findings CONFIRMED as written.** Frames carried `{seq, repo, time, payload: {…}}` — a
`payload` field the lexicon does not declare, with none of the eight required `#commit` fields
readable — and bodies round-tripped through JSON, so `commit` and `ops[].cid` arrived as text
instead of tag-42 links and `blocks` was absent entirely.

New `sequencer/payload.rs` holds the four body types in lexicon shape, stored as DAG-CBOR;
`splice_envelope` adds `seq`/`time` by decoding to `Ipld` and re-encoding, so the splice stays
inside the data model. Both `KNOWN_FAILURES` entries removed; the guard demanded their removal.
Verified red against the unfixed encoder. 2096 tests pass, clippy clean.

### Report corrections

- **F-FIRE-01's scope is wider than the report states.** The report describes the envelope on
  `#commit`. Three further union members were also non-conformant and had to be fixed in the same
  change or the union stays undecodable:
  - `#sync` emitted `head` (not a field of the event) and a block **count** where the lexicon
    specifies a CARv1.
  - `#account` always emitted `status`, including `status: "active"`. The field is *optional*, not
    nullable, and must be omitted when the account is active.
  - `#commit` emitted `data`, which is not a field, and omitted `since`, which is
    required-and-nullable and is what tells a resuming subscriber where its gap starts.
- **The `did` / `repo` asymmetry is the specification's, not a defect.** `#commit` names the
  repository `repo`; `#sync`, `#identity` and `#account` name it `did`. Worth stating because it
  looks like a bug on first read.

### Process note — fourth instance of the same pattern

The existing unit tests passed against the broken encoder because they asserted the envelope they
were handed rather than the lexicon: `body["payload"]["rev"]` in `frame.rs`, `payload["head"]` and
`payload["blocks"] == 42` in `sync_event.rs`, `payload["rev"]` in `writer.rs`. Same class as the
proxy tests (M1.12) and the MST tests (M1.3). **A test that asserts the implementation instead of
the specification is worse than no test — it converts an open gap into a closed one.**

### Deliberate visible gap

`blocks` is present, well-typed and empty pending M1.14. `blocks_is_present_but_empty_pending_car_slices`
pins `Ipld::Bytes(vec![])` and instructs its own replacement, so the gap cannot be mistaken for done.

### Two near-misses worth recording

- The `cargo fmt`/`clippy`/`test` command ran with the shell's cwd already in the worktree, but the
  **CHANGELOG edit used the main-repo absolute path** and landed on `main`. Caught by `git status`,
  copied across, `git checkout --` on main. This is the third stray-edit incident. Absolute paths
  are not sufficient protection — the path itself has to be the worktree's.
- `commit_body` was appended after the `#[cfg(test)] mod tests` block in `writer.rs`, which clippy
  rejects (`items after a test module`). Only surfaces under `--all-targets`.


## F-FIRE-05 — merged (PR #17, `5c39cc2`)

Branch `F-FIRE-05`, merged as `5c39cc2` (pushed as `108ca0b`). Draft at `.claude/context/pr-drafts/F-FIRE-05.md`.
Completes M1.13. **CONFIRMED as written**, all four citations still accurate.

One global `stream_event` log in the accounts DB (opened under every storage profile, so one schema
covers SQLite *and* fjall). `seq` allocated by the INSERT — allocation order is commit order.
2105 workspace tests pass; 406 under `--features fjall`; clippy clean on default, `fjall` and
`postgres`.

### Report corrections

- **The report understates it.** It describes duplicate and non-monotonic numbers. The subscriber
  loop also drained one account's outbox *fully* before touching the next
  (`subscribe_handlers.rs:116-140`), so frames left out of order even where the numbers differed.
  Fixing the numbering without rewriting the loop would have left the wire order broken.
- **F-FIRE-10 is closed by this change**, not deferred. The per-DID loop was the *cause* of the
  1000-account cap, the connect-time-fixed DID set, and the per-tick outbox reopen; none of them
  survive a single-cursor tail. Recorded as a side effect rather than scope creep.
- **F-FIRE-09 becomes checkable** for the first time — `Sequencer::latest_seq` is the global
  high-water mark a `FutureCursor` check needs. Still not emitted.

### Design decision — atomicity traded for monotonicity (approved before implementing)

A `#commit` no longer rides in the per-actor transaction, because the log is server-global.
Considered and rejected: a global counter over per-actor storage. It preserves atomicity but cannot
be monotonic — poll A (empty) → B commits 11 → emit 11 → A's 10 commits → emit 10. Only allocation
inside a single table makes allocation order *be* commit order. Event published after the commit is
durable, so the failure is a lost event, not a wrong one. The reference splits its sequencer from
its actor stores the same way.

### Honest test note

`resume_from_a_cursor_returns_the_exact_tail` **passed before the change** — with two accounts and
per-DID cursors it happened to give the right answer. Kept as a post-change guard, and the PR says
so rather than implying four red tests went green. The other three were genuinely red; the clearest
was `[1, 1, 1, 2, 2, 2, 3, 3, 3]` — three repositories each counting independently.

### Process note — fresh worktrees need `git submodule update --init`

`cargo test --workspace` failed 13 `atproto-dasl` compliance tests in the new worktree because
`crates/atproto-dasl/tests/dasl-testing` is a submodule and `git worktree add` does not populate it.
Nothing to do with the change. This is also why `git worktree remove` needs `--force` ("working
trees containing submodules cannot be moved or removed"). **Add the submodule init to Step 1.**


## F-FIRE-02 + F-FIRE-03 — merged (PR #18, `93846fa`)

Branch `F-FIRE-02`, merged as `93846fa` (pushed as `0dafe6b`). Draft at `.claude/context/pr-drafts/F-FIRE-02.md`.
**F-FIRE-02 CONFIRMED, F-FIRE-03 DRIFTED.** This is the last item in M1.

`RecordingBlockStorage` wraps the storage the MST writes through, so the diff is captured by
construction rather than re-derived by comparing trees; the recorded set is then filtered to what
the new commit can reach, which drops intermediate nodes a multi-op batch leaves behind. 2115
workspace tests pass; clippy clean on default, `fjall` and `postgres`.

### Report corrections

- **F-FIRE-03 had already partly closed.** The report describes `#sync.blocks` as a block-count
  integer serialised to the wire (`sync_event.rs:38`, `:72`). That stopped being true at `05cb63e`
  — B-1 made it a well-typed empty byte string, and `SyncEvent.blocks: usize` survived only as a
  vestigial field. The remaining gap was identical to F-FIRE-02's: an empty slice.
- **`car_export` citations renumbered**: `handlers.rs:191`/`:250` are now `:264`/`:323`. Same
  meaning — still only `getRepo` and `getBlocks`.
- The report's `frame.rs:110-114` "we wrap the JSON-decoded payload as-is" quote no longer exists;
  B-1 replaced that encoder.

### Scope boundary held deliberately

This ships the naive diff, **not** the Sync 1.1 covering proof (F-FIRE-06). The report is explicit
that inductive consumers still reject these frames until that lands, and the PR and CHANGELOG both
say so rather than implying the firehose is now conformant. F-FIRE-06 is the one with an oracle
already vendored (`blocksInProof`), currently unasserted by `interop_mst.rs:110-125`.

### Fourth instance of the concealing-test pattern

`blocks_is_present_but_empty_pending_car_slices` was written to fail once the gap closed. It didn't
— it called `encode_event` with a hand-built body instead of going through the write path, so it
would have kept passing indefinitely. Even a test written *specifically* to detect a fix failed to,
for the same reason as the others: it asserted the encoder rather than the behaviour.

### **Pre-existing failure found — and a correction to my own reporting**

`http_phase2_fjall_blob::fjall_blob_upload_get_list_round_trip` fails — `uploadBlob` returns no
`blob.$link` on the fjall profile. Bisected: fails identically at `5c39cc2`, `05cb63e` and
`636f455`, so it predates this milestone entirely. **Not in the report — file it.**

**I reported the F-FIRE-05 fjall run as "406 passed, 0 failed". That was wrong.** The command was
piped through `head -10`, which truncated the output before this failure. Corrected in the
F-FIRE-02 PR description. **Process fix: never `head` a test summary — aggregate the counts.**

## M1 status

**M1 is complete** as of PR #18. Remaining firehose work moves to M2: F-FIRE-06 (covering
proof, M2.26) is the blocker for inductive consumers; F-FIRE-09 (`FutureCursor`), F-FIRE-11
(retention, now more pressing since frames carry record bytes) and F-FIRE-12 (`requestCrawl`)
follow.


## F-OPS-03 — merged (PR #19, `10f898d`)

Branch `F-OPS-03`, merged as `10f898d` (pushed as `8422937`). Draft at `.claude/context/pr-drafts/F-OPS-03.md`.
**CONFIRMED.** First M2 item (M2.1/M2.2 shipped with M1.4, M2.15 with M1.6).

Body no longer logged; `PDS_EMAIL_LOG_BODIES` restores it at DEBUG for dev with a loud startup
warning; Dockerfile gains `smtp`; unconfigured mailer now warns instead of INFO.

### Report correction

- **Four send sites, not two.** The report names `requestPasswordReset` and `requestAccountDelete`.
  `auth_handlers.rs` also sends tokens at `:1008` (email update) and `:1296` (email confirmation).
- Citations renumbered: `email.rs:75-83` → `:74-83`; `Cargo.toml:125-128` → `:130-133`;
  `Dockerfile:63,83` → `:31`, and the feature list is longer than the report states
  (`clap,hickory-dns,zeroize,tokio`, still no `smtp`).

### **The release build was broken — the container could not be built at all**

Found while verifying the image change. `cargo build --release` failed on `main`:
`atproto_record::lexicon::Blob doesn't implement std::fmt::Debug`
(`write_handlers.rs:539`, `UploadBlobResponse`).

Cause: 60 sites across seven crates derived `Debug` under
`#[cfg_attr(any(debug_assertions, test), derive(Debug))]`. A public type that implements a trait in
debug builds and not release ones is a latent break for every downstream consumer. Fixed at source —
`Debug` unconditional at all 60 — rather than by dropping the derive in `atproto-pds`.

**This survived 16 merged PRs because nothing in the repo had ever built in release mode.** Tests,
clippy and CI are all dev-profile. CI now runs `cargo check --release` with the Dockerfile's own
feature set. Scope expansion agreed with the user before making it.

### Process notes

- **Verify the thing the finding is about.** F-OPS-03 is about the *shipped container*; checking that
  premise is what surfaced the release breakage. Three prior branches touched the Dockerfile's
  premises without ever building in release.
- Tests assert on captured `tracing` events, not on the emitting code — the failure output
  (`fields: ["message", "to", "subject", "body"]` at INFO) *is* the finding.


## F-BLOB-05 — merged (PR #20, `ea3ae17`)

Branch `F-BLOB-05`, merged as `ea3ae17` (pushed as `e018517`). Draft at `.claude/context/pr-drafts/F-BLOB-05.md`.
**CONFIRMED exactly as written**, including the report's own remedy: `space.getBlob` already set all
three headers, so this was copying them across. Citations all still accurate.

`getBlob` now sends `nosniff`, `content-disposition: attachment` and `default-src 'none'; sandbox`.
Both handler branches (dispatch and legacy SQLite) share the response construction, so fjall is
covered. 2118 tests pass; clippy and the new release check clean.

### Judgement call worth recording

The `content-disposition` filename interpolates `q.cid`. That is safe today because an unmatched CID
404s before reaching the header, so the value is always server-generated base32 — but I did not want
header safety resting on that ordering, so it is built through `HeaderValue::from_str`, which
degrades to a bare `attachment` rather than interpolating anything malformed. The spaces version has
the same interpolation without that reasoning written down.

### Deliberately out of scope

`getRepo`/`getBlocks` (`handlers.rs:302`, `:365`) also set only `Content-Type`, but serve a fixed
`application/vnd.ipld.car` that no browser renders. Adding `nosniff` there is hygiene, not a fix, and
does not belong in a security change.

## M2 progress

M2.1, M2.2 (with M1.4), M2.15 (with M1.6), M2.3, M2.4 done. Next in table order: **M2.5**
(F-OAUTH-04 — non-DPoP sessions break on refresh, `unwrap_or_default()` where an `Option` belongs).


## F-OAUTH-04 — merged (PR #21, `4f4eced`; verdict: ALREADY FIXED)

Branch `F-OAUTH-04`, merged as `4f4eced` (pushed as `0f1d621`). Draft at `.claude/context/pr-drafts/F-OAUTH-04.md`.

### The finding was closed by PR #6, not by this branch

Both cited lines survive (`token.rs:352` `unwrap_or_default()`, `:292` passes the stored value back)
but the chain is unreachable: `token_handler:127-128` verifies a DPoP proof **before** dispatching
either grant, and `issue_pair`'s only two callers pass the resulting thumbprint. `dpop_jkt` is never
`None`, so `cnf` is never `Some(jkt: "")`.

Requiring the proof was the **F-OAUTH-02** fix. It closed F-OAUTH-04 as a side effect. The report
could not have known — both were written against the same pre-fix tree, and its §23 groups them.
The class of client the finding describes (one that omits DPoP) can no longer obtain a token at all.

**The report's stated remedy is now the opposite of the right change.** "Store `Option<String>`
rather than `unwrap_or_default()`" was correct when the absent case was real; today the `Option`
*is* the hazard. Shipped `&str`, unconditional `cnf`, constant `token_type` — the failure is
unrepresentable rather than merely not occurring.

### Honest test note

`a_session_survives_repeated_refreshes_bound_to_one_key` **passes before the change too.** There is
nothing to reproduce, so it is a regression guard on the property the new type rests on, and the PR
says so rather than implying a red-to-green. Three refresh rounds, not one, because the original
failure surfaced on the *second* exchange.

Also wrote a no-proof test before noticing PR #6 already added
`token_rejects_request_without_a_dpop_proof`; deleted mine rather than ship a duplicate.

### Watch for this pattern

This is the first finding invalidated by earlier remediation in this same series. **Findings in a
coupled group need re-verification against current `main`, not just their own cited lines** — the
lines can survive while the reachability that made them a bug does not. F-OAUTH-08, F-OAUTH-09 and
F-SVC-09 are the rest of §23 and should be re-read the same way when reached.

## M2 progress

Done: M2.1, M2.2 (with M1.4), M2.15 (with M1.6), M2.3, M2.4, M2.5. Next in table order: **M2.6**
(F-BLOB-06, F-BLOB-07, F-OPS-11 part — the 16 MiB upload ceiling is dead code, the real limit is
axum's 2 MiB default; needs a `DefaultBodyLimit` layer, both operator-tunable).


## F-BLOB-06 + F-BLOB-07 + F-OPS-11 (part) — merged (PR #22, `5867da1`)

Branch `F-BLOB-06`, merged as `5867da1` (pushed as `5596db1`). Draft at `.claude/context/pr-drafts/F-BLOB-06.md`.
**CONFIRMED**, all citations accurate. Reproduced before fixing: a 3 MiB upload returned
`413 Failed to buffer the request body: length limit exceeded`.

Both handlers take `Body` and buffer under their own ceiling; `PDS_BLOB_UPLOAD_LIMIT` (16 MiB) and
`PDS_IMPORT_LIMIT` (1 GiB), neither feature-gated. 2121 tests pass.

### Design note — why not `DefaultBodyLimit`

The roadmap says "add a `DefaultBodyLimit` layer sized to the blob ceiling". A layer bounds memory
but its rejection is still axum's plain-text 413, so the limit would be right and the error still
unusable by a client. Buffering in the handler gets both. Recorded because it is a deliberate
departure from the report's stated remedy.

Two knobs rather than one because they bound different things: a single number would force an
operator to accept 1 GiB blobs in order to allow a 1 GiB migration.

### Scope honestly short of the finding

**F-BLOB-07 asks for a limit *and* a per-DID quota. Only the limit shipped.** A quota needs
per-account storage accounting plus a refusal policy — a feature, not a knob. Stated in the PR
rather than letting "F-BLOB-07" read as closed. **The ledger row says "(part)" for this reason.**

### Breaking change worth noting at release

`put_blob` is public and gains a `limit` parameter. Also a real change in memory profile: the server
now buffers up to 16 MiB per concurrent upload and 1 GiB per concurrent import, where axum's default
had been holding it to 2 MiB. Intended, matches the reference, and `PDS_BLOB_UPLOAD_LIMIT=2097152`
restores the old bound.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3, M2.4, M2.5, M2.6. Next in table order: **M2.7**
(F-MOD-04 — constant-time admin password compare; refuse to start with the default password outside
dev).


## F-MOD-04 — merged (PR #23, `86220bf`)

Branch `F-MOD-04`, merged as `86220bf` (pushed as `732409f`). Draft at `.claude/context/pr-drafts/F-MOD-04.md`.
**CONFIRMED**, all citations accurate. All three parts of the finding shipped.

Shared `secret_eq` (HMAC-verifier compare, constant-time and length-independent) on both admin
surfaces; sliding-window limiter before the comparison; sentinel password refused everywhere unless
`PDS_ALLOW_DEV_DEFAULTS=true`. 2125 tests pass.

### Scope decision — included the rate limiting

The roadmap line names two items; the finding text names three ("...and is unrate-limited"). Shipped
all three. An unlimited online guessing oracle is worse than a timing oracle, and the limiter already
existed on `HttpState`. Cost was making `require_admin` async — 20 mechanical `.await`s in one file.

### The design point worth remembering

The old gate refused the sentinel only inside `if config.production`. **Forgetting the flag selected
the insecure branch.** The fix inverts the default: refuse everywhere, opt in explicitly. Any
security default reachable by *omission* is the wrong way round — worth checking for elsewhere.

### ⚠️ Breaking change

**An unconfigured PDS no longer boots.** Set `PDS_ADMIN_PASSWORD`, or `PDS_ALLOW_DEV_DEFAULTS=true`
for a local instance. Called out at the top of the CHANGELOG entry and in the PR.

### On not testing the timing property

No timing assertion — a measurement in CI is noise, not evidence. The test pins what a constant-time
rewrite can silently break: that the comparison still distinguishes right from wrong, including a
prefix, an extension and the empty string. **An always-true compare would pass a timing test.**

### New finding candidate — admin action attribution

The reference accepts a moderation-service JWT (`auth-verifier.ts:137-149`) so an admin action can be
attributed to a person rather than to "whoever had the password". This workspace has only the shared
secret, so the audit trail cannot name anyone. Mentioned in the F-MOD-04 evidence as a reference
behaviour but **not filed as a finding** — worth filing.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.7. Next in table order: **M2.8** (F-MOD-06, F-MOD-05 —
move `disable`/`enableAccountInvites` to `com.atproto.admin.*`; emit `accountView.indexedAt`; fix
`updateAccountEmail`'s `account` field).


## F-MOD-06 + F-MOD-05 — merged (PR #24, `cd0525b`)

Branch `F-MOD-06`, merged as `cd0525b` (pushed as `8bfc2eb`). Draft at `.claude/context/pr-drafts/F-MOD-06.md`.
**CONFIRMED, and wider than filed.**

### Checked against the lexicons, not the report — and it mattered

Used the Lexicon Garden MCP to read `com.atproto.admin.defs#accountView`, `sendEmail`,
`updateAccountEmail`, `searchAccounts` and `disableAccountInvites` directly. Two findings the report
does not have:

1. **`searchAccounts` returns `accountView` refs and had its own separate struct** with the identical
   `indexedAt`/`createdAt` defect. The report lists `searchAccounts` only for its `q`/`email`
   parameters, so fixing `getAccountInfo`/`getAccountInfos` and stopping — which is what the report
   describes — would have left the same bug in a third place. One `AccountView` now backs all three.
2. **`searchAccounts.limit` is declared `default 50, min 1, max 100`**; ours defaulted to 25. Minor,
   unmentioned, aligned.

**Process lesson: for wire-shape findings, read the schema, not the summary of the schema.** The
report was accurate about what it covered and silent about an adjacent instance.

### Clean break, no aliases (user decision)

Old spellings were unreachable by any conformant client, so nothing standards-compliant regresses.
`state` disappears from `accountView` — not a declared field; `getSubjectStatus` is the canonical way
to ask. In-repo callers fixed: `atproto-pds-admin` CLI and seven pre-existing tests that had encoded
the divergence.

### Near-miss worth recording

A blanket `input.did` → `input.account` rename hit **14 unrelated lines** across
`UpdateSubjectStatusInput`, `DeleteAccountInput`, `forceRepoSync` and others. Caught by the compiler
and reverted line-by-line. **Field renames need surgical edits, not global replaces** — the compiler
caught it here only because the other structs still had `did`; had any of them also had an `account`
field, it would have compiled and silently changed behaviour.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.8. Next in table order: **M2.9** (F-REPO-06 — low-S
normalization for P-256/P-384 using the existing helper at
`crates/atproto-attestation/src/signature.rs:30-80`; reject high-S on verify). Depends on M1.1, which
is merged.


## F-REPO-06 — merged (PR #25, `9cc5393`)

Branch `F-REPO-06`, merged as `9cc5393` (pushed as `112c868`). Draft at `.claude/context/pr-drafts/F-REPO-06.md`.
**CONFIRMED, and measured.**

### The measurement is the finding

Signing 64 times with a fresh P-256 key produced **27 high-S signatures** — a coin flip, exactly as
the theory predicts. Recorded because it converts "latent, conditional" into a number: a P-256 key
was failing ~half its signatures at random, permanently.

### Report correction — the suggested remedy does not fit

The finding says the correct helper "exists in this very workspace at
`crates/atproto-attestation/src/signature.rs:30-80` and the PDS does not use it." That helper works
but is the wrong shape:

1. **It covers P-256 and K-256 only.** `normalize_signature` returns `UnsupportedKeyType` for
   **P-384** — one of the two curves this very finding is about. Following the report literally would
   have fixed half the finding.
2. It lives in `atproto-attestation`, which `atproto-identity` does not and should not depend on —
   the dependency runs the other way.

Normalization went into `key.rs`, where signatures are produced. **Second time in three findings that
the report's stated remedy was wrong for a reason only visible in the code.**

### Design note

`sign` normalizes for K-256 too, where it is a no-op. The guarantee is now stated at the call site
rather than inherited from a dependency's implementation choice — which is exactly the thing that
differs between `k256` and `p256` and was never noticed.

### ⚠️ Upgrade hazard

**Verification is stricter.** A high-S signature from an older version of this crate, or from another
implementation that does not normalize, is now rejected. No such store found in this repo (accounts
default to K-256; attestation already normalized), but `atproto-identity` is published, so a
downstream user may have one.

### Test design worth keeping

`every_signature_is_low_s` signs **64 times per curve**. One round would have passed against unfixed
code on a coin flip. **When a defect is probabilistic, a single-shot test is worse than none** — it
reads as a guard and behaves as a coin toss.

### Adjacent finding worth doing soon

**F-REPO-07** — `RepoConfig::verify_signatures` is declared, defaults to `true`, and is read nowhere.
A knob that reads as a safety guarantee and is inert. Not in M2; sits right next to this work.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.9. Next in table order: **M2.10** (F-OAUTH-06 — CORS on
the discovery documents and the OAuth routes).


## F-OAUTH-06 — merged (PR #26, `c36f141`)

Branch `F-OAUTH-06`, merged as `c36f141` (pushed as `95f974d`). Draft at `.claude/context/pr-drafts/F-OAUTH-06.md`.
**CONFIRMED** — grep for CORS returned nothing; only the two metrics layers, now at `:480-481`
(report said `:442-447`).

### Scope widened deliberately (user decision)

The finding scopes to discovery + OAuth. Shipped across the whole surface including the 96
`/xrpc/*` routes, because a client that finishes the token exchange and then cannot call a single
method is still blocked — fixing the named routes only would close the finding as *written* while
leaving its stated consequence intact. **Worth watching for: a finding's letter and its consequence
can diverge.**

### The security reasoning, recorded because it is the whole design

`Allow-Origin: *` **with no `Allow-Credentials`**. Safe because AT Protocol authenticates with
`Authorization`/`DPoP` headers, never cookies: a browser attaches neither cross-origin unless the
script sets them, and a script that can set them already holds the token. `Allow-Credentials: true`
is the switch that would make this dangerous — ambient credentials, response handed to the page —
and is forbidden alongside a wildcard anyway.

**The test asserts `Allow-Credentials` is absent**, so a later "improvement" fails the build rather
than the security model. That assertion is the durable part of this change.

### Dependency note

`tower-http` was already in `Cargo.lock` (via `reqwest`), so this adds the `cors` feature and a
direct edge, not a new supply-chain root. Gated behind the existing `http` feature.

Also: `tower` is a **dev**-dependency here; I initially added `tower-http` beside it and had to move
it to `[dependencies]`. Worth remembering — the obvious neighbour was the wrong section.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.10. **All ten starred M2 items are now complete.**
Next in table order: **M2.11** (F-OAUTH-05 — apply the workspace SSRF guard to PAR metadata,
`jwks_uri`, and the spaces attestation fetches). Note the report cites
`crates/atproto-identity/src/host.rs` for the guard, but the ledger's earlier correction records the
real one as `validation::validate_service_endpoint` — re-verify before trusting either.


## F-OAUTH-05 — merged (PR #27, `1161641`)

Branch `F-OAUTH-05`, merged as `1161641` (pushed as `8a57084`). Draft at `.claude/context/pr-drafts/F-OAUTH-05.md`.
**PARTIALLY ALREADY FIXED, and the remainder was wider than filed.**

### Report corrections

1. **The PAR half was closed by PR #6.** `client_metadata.rs:198` and `:266` already apply
   `validate_service_endpoint` to `client_id` and `jwks_uri`. The report's "grep returns zero" claim
   is stale — it returns four hits.
2. **The guard is `validation::validate_service_endpoint`, not `host.rs`.** There is no `host.rs` in
   `atproto-identity`. Recorded in this ledger once before, from PR #6; M2.11's own roadmap text
   repeats the wrong path, so it is worth stating twice.
3. **A third sink the finding does not name.** The attested `client_id` also reaches
   `space/recipient.rs`, which derives a host and fetches `/.well-known/atproto-did` and then the DID
   document behind it. Fixing only the two named sinks would have left the attestation path
   exploitable — which is the entire point of the finding.

**Second time a finding named some sinks and not all of them** (cf. F-MOD-06, where `searchAccounts`
had its own copy of the `accountView` defect). **For "apply guard X at sites Y" findings, trace the
input, not the site list.**

### Honest scope limit, stated in the PR

`validate_service_endpoint` is syntactic — no DNS resolution, so no defence against rebinding or a
public name pointing inside. The PR says so rather than claiming "SSRF fixed". Also **not audited:
the other nineteen `reqwest::Client` constructions** in the crate. Said plainly rather than implying
a sweep; a systematic outbound-request audit deserves its own item.

### Test technique worth reusing

`resolve_recipient` returns the same stub whether a host was *refused* or merely *unreachable*, so
the return value proves nothing. The test asserts on the **emitted tracing event**, and neutralising
the guard produces `"event crates/atproto-identity/src/resolve.rs:157"` — the outbound request
actually happening. **When a failure path is lossy, assert on the log, not the result.**

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.11. Next in table order: **M2.12** (F-MOD-01,
F-MOD-02, F-ACCT-09, F-ACCT-04, F-BLOB-04 — enforce account state on writes, on refresh, and on every
public read path including all five sync endpoints and both blob endpoints; gate `activateAccount` on
not-takendown). Effort M, and §7 of the report calls this group "moderation actions do not take
effect" — a five-finding group, so expect the coupling to matter.


## F-MOD-01 group (five findings) — merged (PR #28, `3e51941`)

Branch `F-MOD-01`, merged as `3e51941` (pushed as `2b5b4f4`). Draft at `.claude/context/pr-drafts/F-MOD-01.md`.
**ALL FIVE CONFIRMED**, every citation accurate. 2143 tests pass.

### Two design errors the tests caught, not the plan

Both would have shipped as regressions had the suite been thinner.

1. **`listRepos` shares `get_latest_commit`** and must *list* taken-down repos with `active: false`,
   not refuse them. Gating the reader method broke it the moment any account was taken down. The
   gate belongs on the endpoint. **A shared read method serving both an "enforce" and a "report"
   caller cannot carry the gate itself.**
2. **Inbound migration runs entirely while deactivated** — create → deactivate → `importRepo` →
   upload → `activateAccount`. A blanket write gate made the prescribed migration path impossible.
   Split into `require_session` (refuses deactivated) and `require_migration_session` (permits it,
   still refuses moderated states).

### Process failure worth recording

**A `str.replace` for the `activateAccount` guard matched nothing and reported success.** `cargo
check` passed because the edit was a silent no-op; only the behavioural test caught it. This is the
same class as the CHANGELOG-written-to-main incident. **Every scripted edit needs an assert on the
match count** — I now use `assert s.count(old) == 1` and it caught a second over-broad match in the
same session (`http_phase6_admin.rs` had two identical assertions).

### Deliberate scope decisions

- `valid_transition(Takendown, Active)` left alone: an admin lifting a takedown is legitimate. The
  defect was who could ask.
- `getRecord`/`listRecords` moved from `403 Forbidden` to the lexicon's named errors. The report says
  this half "works and must not be reported as absent" — it did work, but answered differently from
  every other path. Unified.

### ⚠️ Behaviour changes

- **Deactivated accounts can no longer perform ordinary writes.**
- `getRecord`/`listRecords` now return 400 + named error, not 403.

### Still open on this surface

**F-MOD-07**: this hides a taken-down account's data behind gates; `deleteAccount` still erases
nothing, so it remains on disk. **F-OAUTH-10**: an existing access token is not revoked, so it stays
valid for its remaining 15 minutes — the write gate closes the damage, not the token.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.12. Next in table order: **M2.13** (F-ACCT-02,
F-ACCT-03, F-ACCT-15, F-SVC-14 — gate `createAccount`-with-existing-DID on inbound service auth;
create migrating accounts `Deactivated`; authenticate `reserveSigningKey`). §3 of the report calls
F-ACCT-02 "unauthenticated DID squatting, exploitable today, anonymously".


## F-ACCT-02 group (four findings) — merged (PR #29, `f751cc8`)

Branch `F-ACCT-02`, merged as `f751cc8` (pushed as `565b5b2`). Draft at `.claude/context/pr-drafts/F-ACCT-02.md`.
**ALL FOUR CONFIRMED.** 2147 tests pass.

### **Correction to my own earlier claim (PR #27)**

In the F-OAUTH-05 PR and in this ledger I wrote *"there is no `host.rs` in `atproto-identity`"*.
**That was wrong.** `crates/atproto-identity/src/host.rs` exists — 15 KB, providing `did_host()`,
which parses and validates the HTTPS target encoded in a `did:web`/`did:webvh` DID. The substance of
the correction held (the guard for arbitrary caller-supplied endpoints is
`validation::validate_service_endpoint`, and that is what was applied), but the parenthetical was
false and is in a merged PR description. **Do not assert a file's absence from a grep for a symbol.**

### Design decision — strict, no escape hatch (user's call, after analysis)

I first proposed a `PDS_ALLOW_UNVERIFIED_DID_CREATION` flag. The user asked for the impact of strict.
The analysis that changed the recommendation:

- Verification resolves the DID document **live** (`https://plc.directory/{did}`, or HTTPS for
  `did:web`), and `plc_query` hardcodes `https://`, so **no local stub is possible**.
- My "bootstrap deadlock on PLC-less deployments" claim was **overstated** — I corrected it. A user
  controlling a `did:web` domain can publish a document with a self-held `#atproto` key and sign
  their own token. Manual, but not impossible, and `atpdid` + `atproto-oauth-service-token` exist.
- The genuine cost is **local development**: `did_host` rejects IP literals and the reserved
  `.localhost`/`.internal`/`.arpa`/`.local` suffixes, so a laptop `did:web` cannot be verified by
  construction. That argues *for* strict — what breaks is exactly what a dev affordance would serve.

### The test-migration question, and why it is not a backdoor

No test can mint a verifiable token. Fixture accounts now go through `AccountManager::create_account`
instead of the XRPC endpoint. **No production path skips the check**, and the manager is the same API
the handler calls after verifying — tests are doing authorisation out of band, which is what fixture
setup is. Where `createAccount` is the subject, tests call the endpoint and assert the refusal.

Cost: 20 files, ~164 `build_app()` sites, ~95 `create_account` sites. Flagged to the user before
starting (report rated M2.13 "M"; this is L) and they chose one branch.

### Findings beyond what was filed

- **`reserveSigningKey`'s idempotency bug was worse than described.** The report says a fresh key is
  generated per call under a fresh row id. In fact `reserve_signing_key` uses `INSERT OR IGNORE`, so
  with a stable id the *first* reservation is kept — meaning the endpoint returned a **different key
  than the one reserved** on every call after the first. Fixed by looking up the existing reservation
  and returning its key.
- One coverage change stated plainly: `invite_redemption_records_real_did_not_placeholder` now tests
  `invite::redeem` directly, because invite-gated signup takes the PLC-genesis path the harness
  cannot exercise.

### Refactor that fell out

`createSession` verifies against an app-password row, never `account.password_hash`, so an account
without one exists and cannot log in. That two-step create-then-seed dance was inline in the handler;
it is now `AccountManager::set_primary_password`.

### Environment note

`git commit` failed once with `1Password: failed to fill whole buffer` — the signing agent, not the
repo. Retrying succeeded. Same class as the intermittent tangled.org SSH resets.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.13. Next in table order: **M2.14** (F-OAUTH-12 —
enforce OAuth scopes on repo writes, blob upload and `rpc:`; add the missing `assert_*` helpers).
The report calls it blocker (security): `scope=atproto` alone can write every collection, upload any
MIME type, rotate the handle and proxy arbitrary calls.


## F-OAUTH-12 — merged (PR #30, `271856f`)

Branch `F-OAUTH-12`, merged as `271856f` (pushed as `e2975b5`). Draft at `.claude/context/pr-drafts/F-OAUTH-12.md`.
**CONFIRMED** — `grep -c scope crates/atproto-pds/src/http/write_handlers.rs` returned **0**, and the
only `allows_*`/`assert_*` pairs in the crate were the three `space:` ones. The model was complete;
the enforcement was entirely absent.

### Two design decisions, both user-approved before implementing

1. **`transition:generic` satisfies repo/blob/rpc/identity.** It is the legacy full-access scope most
   real clients request. Enforcement that refuses every client is an outage, not a fix. Deliberately
   **not** a wildcard for `space:` — spaces post-date it, so nothing was granted it expecting space
   access. A unit test pins that asymmetry.
2. **`updateHandle` included**, though M2.14's remediation names only writes/blobs/rpc. It is the
   fourth of the four consequences the finding lists; omitting it would make "scopes are enforced"
   false for handle rotation.

### Followed an existing precedent rather than inventing a rule

App-password sessions are not scope-checked — they carry no scopes by construction, so checking them
refuses everything. `assert_space_scope` already used an `is_oauth()` gate for exactly this; reusing
it means the two cannot drift. **When a question already has an answer elsewhere in the codebase, the
second answer is the bug.**

### `applyWrites` is checked per operation

One batch can touch several collections with different verbs. A single batch-level check would let a
token scoped to create in one collection delete in another by riding along.

### ⚠️ Behaviour change

**A token granted narrow scopes is refused where it previously succeeded.** Given nothing was
enforced, no client has had reason to notice requesting less than it used. `transition:generic`
clients are unaffected.

### Still open on this surface

`getServiceAuth` mints tokens without consulting `rpc:` scopes — the proxy path is gated, the mint
path is a separate surface. Worth filing. F-OAUTH-13 (`include:` unresolved) and F-OAUTH-11 (metadata
omits nine fields, so clients cannot discover which scopes this server understands) remain.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.14. Next in table order: **M2.16** (F-BLOB-02 — blob
ref walker on the record write path, calling the existing `add_ref`). Note M2.17 depends on it.


## F-BLOB-02 — merged (PR #31, `38830ff`)

Branch `F-BLOB-02`, merged as `38830ff` (pushed as `e93d2bd`). Draft at `.claude/context/pr-drafts/F-BLOB-02.md`.
**CONFIRMED** — trait method, three backends, free functions, unit tests, and `grep` finds **no
production caller**. The doc comment on `add_ref` claimed the writer called it; it did not.

### **Correction to my own claim in PR #18**

I reported `fjall_blob_upload_get_list_round_trip` as *"a real bug on the fjall profile — uploadBlob
returns a body with no `blob.$link`"* and said it should be filed. **Wrong diagnosis.** It is a stale
test assertion: it read the pre-envelope shape, which stopped existing when blob refs became the
lexicon's typed envelope (`blob.ref.$link`). A second assertion in the same file compared two of
those absent values and asserted nothing.

**The fjall test build also did not compile**, so `cargo test --features fjall` had been reporting
zero failures by never running — which is how I got "0 failing" twice in this session. Fixed; fjall
is green at 643 passing, the first time in this series.

**Two process lessons.** (1) *A test-count of zero failures is meaningless without a successful
build* — check the exit code and that tests actually ran. (2) *Before calling something a production
defect, read the assertion.* I attributed a stale test to the storage layer and carried that claim
into a merged PR.

### Design notes

- The walker **recurses** rather than checking known paths (`embed.images`). One that had to be
  taught each lexicon would silently miss every lexicon it had not been taught — identical outcome
  to not walking.
- It **validates the whole envelope**. A bare `{"$type":"blob"}` must not produce a row with an empty
  CID, which `listMissingBlobs` would then report as missing forever.
- **Drops before adds** on update/delete. Add-only would make counts monotonically grow; blob GC
  reads those counts.

### Test detail worth remembering

The end-to-end tests need **real CIDs for bytes never uploaded** (`compute_raw_cid(b"...")`). A
made-up CID string fails the write with a 500 — the record encoder reads `$link` into the data model,
so an unparseable CID never reaches the ref index. My first attempt did exactly that and the 500
masked the real assertion.

### ⚠️ Behaviour change

`listMissingBlobs` now returns entries on repositories that previously reported none.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.14, M2.16. Next in table order: **M2.17** (F-MIG-01 —
`importRepo` populates `repo_record` and blob refs). It depends on M2.16, which this branch closes,
and `walk_blob_refs` is directly reusable there.


## F-MIG-01 — merged (PR #32, `1d724f2`)

Branch `F-MIG-01`, merged as `1d724f2` (pushed as `f6050c7`). Draft at `.claude/context/pr-drafts/F-MIG-01.md`.
**CONFIRMED** — `grep -c repo_record crates/atproto-pds/src/repo/import.rs` returned **1**, and that
one hit is the module doc claiming the import indexes records. It does not.

### The dependency paid off

M2.16's `walk_blob_refs` was reused directly for the blob half. Indexing records without also
indexing their blob refs would have left `listMissingBlobs` still answering "nothing owed" for an
imported repo — the very next question a migrating client asks.

### Two limits written into the code rather than left to be discovered

1. **Rev attribution**: records are indexed at the *head* commit's rev, not the rev each was written
   at. True per-record revs need every historical commit's tree walked and diffed; the reference does
   not do it on import either. A comment says the value is a lower bound.
2. **Missing blocks**: a CAR may omit blocks its MST names — that is what a diff slice is. The record
   is still indexed and only its blob walk is skipped. Refusing an entire import over one absent
   block would be a worse failure than the one being fixed.

### The fixture had to be rebuilt

`minimal_car_for` builds an **empty** MST, so any assertion against it would have been about the
fixture rather than the import. Added `car_with_record`, which builds a real tree — record block, MST
nodes, commit. **A fixture that cannot exhibit the defect cannot demonstrate the fix.**

### Verification habit changed

Now checking **exit code and counts together** after the fjall suite turned out to be reporting zero
failures by not compiling (see F-BLOB-02). Both suites here: exit 0, 2171 and 646 passing.

## M2 progress

Done: M2.1, M2.2 (M1.4), M2.15 (M1.6), M2.3–M2.14, M2.16, M2.17. Next in table order: **M2.18**
(F-MIG-02 — implement `app.bsky.actor.getPreferences`/`putPreferences` locally; today they are
proxied to an AppView that has no such endpoint, so preferences are lost on migration).


## F-MIG-02 — merged (PR #33, `6b475fc`)

Branch `F-MIG-02`, merged as `6b475fc` (pushed as `74a8fe9`). Draft at `.claude/context/pr-drafts/F-MIG-02.md`.
**CONFIRMED** — `grep` for either NSID in `crates/atproto-pds/src` returned nothing; both fell
through the `app.bsky.*` catch-all to an AppView that implements neither.

### Read the lexicons, not the summary (again)

Both fetched directly. Each carries exactly one required field, `preferences`, typed
`app.bsky.actor.defs#preferences`. That "required" is why a fresh account returns `[]` rather than a
404 or an omitted field — a client reading `.preferences.length` must not special-case a first run.

### Design decisions worth keeping

- **Opaque storage.** `#preferences` is an array of open-union objects. A PDS that parsed them would
  silently drop every type it had not been taught — for *private* state, data loss discovered much
  later with no error at the time. A test pins that an unknown `$type` with nested structure
  round-trips intact.
- **Full replacement, not merge.** The reference may merge by namespace; that could not be verified
  from here, and a subtly wrong merge discards settings silently. Did the predictable thing and said
  so in the handler doc. **When two behaviours are plausible and one fails loudly, choose that one.**
- **No scope gate.** There is no lexicon-defined OAuth scope for preferences (`AccountScope` covers
  email/repo/status only). Inventing one would refuse clients over a permission the ecosystem does
  not define. Noted as a gap rather than papered over.

### Near-miss

Wrote `preference_handlers.rs` to the **main checkout** instead of the worktree — the absolute path
omitted `.claude/worktrees/F-MIG-02/`. Caught by `git status` on main immediately after and moved.
**Fourth stray-write incident.** The pattern is always the same: an absolute path that is correct
except for the worktree prefix.

### Storage note

Preferences live in the per-actor SQLite store, not dispatched through `PublicRealmBackend`, so the
fjall profile also keeps them in SQLite. Consistent with how the actor store is opened elsewhere for
SQL-shaped state, but worth knowing.

## F-REC-04 — merged (PR #34, `a355059`)

Draft at `.claude/context/pr-drafts/F-REC-04.md`. Branch and worktree removed.

Verdict at Step 2 was **CONFIRMED, and worse than stated**. The report says `swapCommit` is
"accepted and ignored". Only `createRecord` accepted it at all (`write_handlers.rs:179-180`,
building `swap_record: None`); `putRecord`, `deleteRecord` and `applyWrites` had no such field in
their input structs, so a client sending it got it dropped by serde before any handler saw it.
`swapRecord` *was* honoured on standalone put/delete, as the report says — that half worked.

### The interim was unnecessary

The roadmap offered arroba-style rejection of any request carrying `swapCommit` as a cheap stand-in
for the real guard. Both write paths already load the prior commit inside `apply_writes`, which
holds the per-DID mutex from `lock_for(did)` — so the genuine compare-and-swap is one comparison at
a line that already had the value in hand. Doing the real thing was smaller than the workaround.

Placement is the whole point: after the prior commit is read, before anything is written, with the
lock held. Anywhere else it is check-then-hope.

### API shape

`RepoWriter::apply_writes` keeps its signature and delegates to a new `apply_writes_with_swap`.
Threading the parameter through the original would have touched 42 call sites, including the spaces
writer, which has no notion of a repo commit.

### Test note

`a_current_swap_commit_is_accepted_on_every_write_path` looks redundant next to the refusal test and
is not: a guard that refused *everything* would pass the refusal test. It re-reads the head before
each write, since every write moves it.

## F-IDENT-01 group — merged (PR #35, `d3d67d5`)

Draft at `.claude/context/pr-drafts/F-IDENT-01.md`. Branch and worktree removed.

All four CONFIRMED. Line numbers had drifted; the report's `admin/handlers.rs:628` is also the wrong
path — it is `crates/atproto-pds/src/admin/handlers.rs:691`.

### Report corrections

**F-IDENT-05** — the report says the reference `submitPlcOperation` performs "five checks". It
performs **six** (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/identity/submitPlcOperation.ts:20-52`):
shape, rotation key, `atproto_pds` type, `atproto_pds` endpoint, `verificationMethods.atproto`, and
`alsoKnownAs[0]`. Implemented here as five behavioural constraints plus the type discriminant.

**F-IDENT-03 could not be closed without F-IDENT-11 (M4.14).** M2.20's stated scope includes "plus
the email-token gate", and there is nothing for the gate to check until
`requestPlcOperationSignature` issues a consumable code rather than a service-auth JWT. Pulled in,
approved by the user before implementation.

### Scope note — `.example` is a disallowed TLD

Upstream's `DISALLOWED_TLDS` includes `.example`, which every existing fixture handle in this repo
uses. It bites only `updateHandle`, since `createAccount` fixtures go through the manager directly,
so no existing test needed changing. New tests use `.test`, which upstream explicitly permits.

### New finding candidate — the PLC round-trip is untestable

`atproto_identity::plc::{fetch_audit_log, submit}` hardcode `https://` (`plc/mod.rs:87,113`), and
`do_update_handle` builds its own `reqwest::Client` (`identity_handlers.rs:223`) rather than using
the injectable one on `PlcService`. Together these make every handler behind a PLC round-trip
unreachable from the test harness — the `#identity` emissions on `do_update_handle` and on a
successful `submitPlcOperation` are covered by inspection only. Not a defect in behaviour; a
testability gap that will keep costing coverage on the identity surface.

### One deleted test

`request_plc_operation_signature_returns_token` asserted the service-auth-JWT-in-the-body shape —
it pinned the vulnerability rather than the lexicon. Fifth instance in this series of a test
asserting the implementation instead of the specification.

## M2 progress

## F-MOD-03 group — merged (PR #36, `9708d32`)

Draft at `.claude/context/pr-drafts/F-MOD-03.md`. Branch and worktree removed.

Both CONFIRMED. Report line numbers drifted: `admin/handlers.rs:156-162,212-218` is now `:204-220`.

### New finding candidate — no actor-store pool cache

`SqlActorStore::open` (`actor_store/sql/store.rs:56-95`) builds a fresh 8-connection pool **and runs
migrations** on every call, and there is no cache. Every public read path pays it at least once per
request; `get_record` was about to pay it twice before this branch hoisted the open. Not introduced
here, but this is the first change that made the cost visible.

### Scope note — the 422/400 conformance hole

axum's `Json` rejects a malformed body with a plain-text HTTP 422, which is not an XRPC error shape.
It matters most on an **open union**, where a client naming a `$type` this build has not been taught
deserves a readable refusal. A narrow `XrpcJson` extractor (`http/extract.rs`) is used on
`updateSubjectStatus` only. **Converting the rest of the surface is a separate mechanical change**
and is not filed against any existing finding.

### Three existing tests updated rather than deleted

Unlike `request_plc_operation_signature_returns_token` in the identity branch, these pinned real
behaviour with the wrong spelling, so they were rewritten.

## F-OPS-02 group — merged (PR #37, `2a41aa4`)

Draft at `.claude/context/pr-drafts/F-OPS-02.md`. Branch and worktree removed.

Both CONFIRMED. **Report count drifted in the project's favour:** the limiter reaches **6** call
sites, not 4 — `admin-auth` was added at `admin/handlers.rs:89` and `admin/dashboard.rs:71` by M2.7.
Everything else held exactly, including `grep` for `ConnectInfo|X-Forwarded-For` returning nothing.

### New finding candidate — `admin-auth` is a global lockout lever

The only fixed-key bucket in the codebase. Anyone can exhaust `admin-auth` and deny admin login to
the operator. Introduced by M2.7's brute-force guard; not named by F-OPS-02 (which is about
caller-supplied keys) nor F-MOD-04. Needs to be keyed per-IP or given a much larger budget.

### Design note — `X-Forwarded-For` is off by default

Trusting the header unconditionally would hand every caller a private bucket, which is worse than no
limit because it reads as a defence. `PDS_TRUSTED_PROXY_HOPS` counts from the *right*, because each
trusted proxy appends what it saw. An operator behind a proxy who does not set it gets one shared
bucket for their whole user base — loud and safe rather than quiet and wrong, and the startup log
says which mode is active.

### Second clean-break production gate

`PDS_DURABILITY_PROFILE=memory` is refused under `PDS_PRODUCTION=true`, following the M2.7 admin
password precedent. Approved by the user before implementation.

## F-REC-05 (structural) — merged (PR #38, `2eed30f`)

Draft at `.claude/context/pr-drafts/F-REC-05.md`. Branch and worktree removed.

CONFIRMED. The validators already existed in `atproto-lexicon` with no PDS caller — the third
"built but not wired" finding in this series, after F-BLOB-02 and the M2.20 handle validation.

### Roadmap deviation — `$type` is supplied, not rejected

**M2.23 says "reject records with no `$type`". This branch fills it in from the collection**, which
is what `repo/prepare.ts:167-178` does. Rejecting would refuse writes the reference accepts, and the
finding's stated consequence — the record being undecodable — is addressed by supplying the field,
not by refusing. A `$type` that *disagrees* with the collection is refused. Approved by the user
before implementation.

### Report correction — `validate` is on three methods, not four

`deleteRecord` declares neither `validate` nor `validationStatus` (lexicon CID `bafyreibwdxb…`): a
delete has no record to validate. My own Step 2 summary said "all four" and was wrong.

### `validate: true` is refused rather than ignored

Schema validation is M2.25. Accepting `true` and validating nothing would be a control that reads as
working — the shape this report keeps finding — so it returns `ValidationUnavailable` by name.
`validationStatus` reports `unknown`, the only honest value while no schema engine runs.

### Three existing fixtures were wrong

`put_then_delete_round_trip`, `duplicate_create_rejected_over_http` and `apply_writes_atomic_batch`
used the collection `"c.col"` — two segments, not an NSID, and never valid. Written against a server
that did not check rather than against the protocol. **Sixth instance** of a test asserting the
implementation instead of the specification.

## M2 progress

## F-OPS-06 group — merged (PR #39, `bf4c383`)

Draft at `.claude/context/pr-drafts/F-OPS-06.md`. Branch and worktree removed.

Both CONFIRMED. **User decision: document both as unsupported**, chosen from three options after I
measured each half.

### Report correction — the writer line cite

The report puts the SQLite-dialect accounts query at `repo/writer.rs:360-364`. That line is the
*per-actor* store, which is SQLite by design and unaffected by the accounts-DB choice. The real
sites are `:548-552` and `:867-871` — `SELECT signing_key_ref FROM account WHERE did = ?` against
`self.accounts.pool()`, twice. The claim holds; the citation does not.

### Report addition — the panic was never reachable in a shipped artifact

Neither `postgres` nor `s3` is in `default`, and the release build compiles
`clap,hickory-dns,zeroize,tokio,smtp`. The report frames F-OPS-06 as "a documented supported
deployment mode that would crash the process"; the crash needs the feature compiled in, which no
shipped binary does. The reachable defect is the quiet one — the flags parse and are ignored.

### The measurement behind the decision

- **S3 — S/M.** `HybridS3BlobStorage::open` already returns a `BlobStorage`; `PublicRealmBackend`
  already has a `blob` slot at `bin/pds.rs:453-472`.
- **Postgres — L/XL, not the roadmap's M.** 57 of 59 `as_sqlite()` sites already dispatch, but 13
  production sites take the SQLite-only `pool()` accessor: `bin/pds.rs` (×5), `repo/writer.rs` (×2),
  `http/handlers.rs`, `http/space_handlers.rs`, `http/space_auth.rs`, `space/writer.rs`,
  `space/reader.rs`, `actor_store/sql/public_realm.rs` — reaching the OAuth state store, the JTI
  guard, GC, the notifier, the sequencer and four spaces files.

### New finding candidate — wire S3

Small and well-scoped: the storage impl is complete, the backend has a slot, and the remaining work
is reading one flag. Deliberately not done here because the decision was to document both.

### Lead-claim correction for §4 of the report

"SQLite/Postgres/Fjall/S3/Valkey" should be read as **SQLite/fjall/Valkey**.

## M2 progress

## F-SPACE-19 group — merged (PR #40, `3be0be7`)

Draft at `.claude/context/pr-drafts/F-SPACE-19.md`. Branch and worktree removed. **First item on
the M3 spaces track**, chosen by the user over finishing M2's two non-gate items.

All three CONFIRMED at the cited lines; the spec and both worked references (HappyView, the
reference `space-uri.ts`) are still in `/tmp/gap-scratch`.

### User decision — no migration for existing spaces

Chosen from three options. The space URI is the primary key of the `space` table with nine
FK-referencing tables, so the strings *could* be rewritten — but `sig`/`mac` on every stored commit
were computed over the old `ctx`, so a migration produces rows that look conformant and fail
verification. Commits can only be re-signed, which needs each author's key. Since the data was never
interoperable, spaces must be recreated.

### Report correction — field order is not a wire property

The `Commit` doc claimed "wire field order matches the lexicon required set", and the finding is
framed partly in those terms. **Order is not a requirement**: JSON objects are unordered and
canonical DAG-CBOR sorts keys by length then bytes. Surfaced when my first test asserted the order
and failed against `serde_json`'s own sorted map. The test now asserts the field set.

### Two hand-rolled URI copies

`space/writer.rs:226,276` built record URIs with `format!` rather than through `RecordUri`, so the
scheme lived in three places and the change had to be found by grep — and the writer's own test
asserted the old prefix, so nothing would have caught it. Both now build through the type.

### Conformance is dated

Claimed against the draft lexicons at **`3f6c96d` (2026-07-02)**. 0016 is an open WIP and that date
will expire; the report's thresholds list what would reclassify.

## F-SPACE-30 — merged (PR #41, `59c93ac`)

Draft at `.claude/context/pr-drafts/F-SPACE-30.md`. Branch and worktree removed.

CONFIRMED at `space_handlers.rs:1113`, the only `Box::leak` in the workspace.

### The finding understates the cause

The report reads as a stray `Box::leak`. It was forced by the type: `SpaceReadAuth::OwnPds` declared
`account_did: &'a str`, and the DID comes from `subject.sub()` — derived during authentication, not
a slice of the request — so no caller could ever supply a borrow that lived long enough. Deleting
the leak alone does not compile. The field had to become owned.

The lifetime parameter was kept: `SpaceCredential` genuinely borrows the `Authorization` header, and
dropping it would have meant cloning a JWT on every credential read to fix a leak on a different
variant.

### The regression guard is compile-time, and both escapes were checked

The leak was invisible through the HTTP surface, which is why it survived; an RSS assertion would be
flaky. The test builds the DID in a scope that ends before use, so it only compiles when the field
is owned. Reverting the field fails with `E0308`; taking the compiler's suggested `&subject_did`
fails with `E0597` (dropped while still borrowed). Both were run, not assumed.

### CHANGELOG hygiene

The first commit created a second `### Security` heading under `[Unreleased]`. Caught before review,
merged into the existing section, and amended. Fourth CHANGELOG-structure slip in this series — the
insert-at-anchor pattern keeps producing it.

## F-SPACE-07 — merged (PR #42, `e709c59`)

Draft at `.claude/context/pr-drafts/F-SPACE-07.md`. Branch and worktree removed.

**OUTSTANDING: an upstream issue against 0016 is still owed.** Not filed — that is the user's to
raise, and it is the one action item this branch leaves open.

CONFIRMED, all four links, at lines shifted slightly by M3.2. Tier 1, exploitable today with one
request and an ordinary app password.

### Inherited — an upstream issue is still owed

The reference on the `permissioned-data` branch shares all three links (`space/getRecord.ts`,
`space/util.ts:32-37`). Per the fairness rule this is not an atproto-crates authoring error. **I did
not file upstream on the user's behalf.** The report's threshold: if the reference closes it first,
the "inherited" framing evaporates — watch `packages/pds/src/api/com/atproto/space/util.ts`.

### Design decision — membership is not a scope

`assert_space_scope`'s `if !subject.is_oauth() { return Ok(()); }` was **left in place**, though it
is how the exploit reaches the code. App-password sessions carry no scopes by construction and are
full-authority (settled by PR #30), so scope-checking them would refuse them over a grant that cannot
exist. The fix is that the membership check must not live *behind* the scope gate. Approved by the
user before implementation.

### Most of it already existed

`SpaceService::is_member` was the exact predicate, owner-as-member included, and already on
`HttpState`; the `read_self`/`read` scope tier the report credits HappyView with was already there
too. Only the membership question was missing. Fourth "built but not wired" finding in this series.

### Refusals are `SpaceNotFound`, not a new error

A dedicated `NotAMember` would make the gate an oracle for space membership, which is the
confidential fact itself.

## F-BLOB-03 group — merged (PR #43, `5b371f8`)

Draft at `.claude/context/pr-drafts/F-BLOB-03.md`. Branch and worktree removed.

Both CONFIRMED. Tier 1 — F-BLOB-03 is exploitable with **no credential at all**, which is a longer
reach than F-SPACE-07.

### The report does not state the enabling fact, and it simplifies the fix

**There is no `com.atproto.space.uploadBlob`.** Permissioned blobs go through the ordinary
`com.atproto.repo.uploadBlob` into the same `repo_blob` table. And `grep -n "blob" space/writer.rs`
returned nothing — the space writer maintained no refs — so `repo_blob_ref` already held *only
public-record references*. The discriminator existed; nothing consulted it. Fifth "built but not
wired" variant in this series.

### Both gates are predicates, not joined fetches

On the fjall profile the bytes come from a fjall keyspace through `PublicRealmBackend`, so a joined
`SELECT … data` would cover one storage profile only. Asking the per-actor SQLite the *question*
works on both. Same reasoning as the M2.21 takedown gate — and unlike M2.21, this branch has
**cross-profile evidence**: `fjall_blob_upload_get_list_round_trip` went red because the gate fired
on the fjall path, with the reference in SQLite and the bytes in fjall.

### Four existing fixtures were wrong

`a_takedown_closes_every_public_read_path`, `a_blob_can_be_taken_down_without_touching_the_account`,
`get_blob_refuses_to_render_as_a_document` and `fjall_blob_upload_get_list_round_trip` all uploaded a
blob and fetched it publicly with no record referencing it. **Seventh instance** of a test asserting
the implementation rather than the specification — and the most consequential so far, since
`get_blob_refuses_to_render_as_a_document` would have silently stopped exercising its header
assertions.

### Behaviour change worth remembering

An uploaded-but-unreferenced blob is no longer publicly fetchable. Asserted explicitly by
`an_unreferenced_blob_is_not_publicly_fetchable`.

### `listBlobs` cursor semantics

Now advances over CIDs *scanned*, not *kept* — otherwise a fully-permissioned page returns empty with
no cursor, which reads as end-of-list. The SQLite path joins in SQL and keeps full pages; the fjall
path filters afterwards and may return short pages.

## F-SPACE-11 — merged (PR #44, `571f863`)

Draft at `.claude/context/pr-drafts/F-SPACE-11.md`. Branch and worktree removed.

CONFIRMED at every cited line. The handler's own comment already said to read the authority's store;
the code disagreed with it.

### Why it survived

**All four pre-existing unit tests pass the authority as the viewer**, so caller-store and
authority-store were the same store and none could distinguish the behaviour they named. Eighth
instance in this series. Two of them went red under neutralisation, which confirms they *do* exercise
the read — they simply could not tell the stores apart.

### The parameter was removed, not corrected

`GetSpaceOutput` is `{uri, config}` with no viewer-dependent field, so the parameter only ever
selected the wrong store. Deleting it makes the bug unrepresentable.

### Deliberately unchanged

`ensure_space_row`'s defaulted row stays — it carries `is_owner`/`is_member` and per-actor
`space_repo` state member writes need. And `listSpaces` also reads the caller's store, **correctly**,
because it lists the viewer's spaces; the two look alike and must not be "fixed" together.

### New finding candidate — `createSpace` 500s on a malformed config

`SpaceConfig::from_create_input` (`space/config.rs:140-144`) raises `PdsError::Storage` for a
caller-supplied shape error, which maps to HTTP 500 `InternalError`. Found by writing `dids` where the
field is `allowed`. A client cannot tell its own mistake from a server fault. Same class as the
422-vs-400 issue noted in M2.21; not filed against any existing finding.

## F-SPACE-03 — merged (PR #45, `ae85ebf`)

Draft at `.claude/context/pr-drafts/F-SPACE-03.md`. Branch and worktree removed.

CONFIRMED. Reading the lexicons directly changed two things the report does not mention:

1. **`limit` bounds differ per endpoint** — `listRecords` 1..100, `listRepoOps` 1..1000. The handler
   applied neither to `listRecords`.
2. **`opEntry.value` has a third omission condition**: superseded ops, plus deletes. Neither is in the
   finding text.

### The superseded-value omission, and why the CID match is the whole trick

HappyView's `LEFT JOIN … AND r.cid = o.cid` makes a superseded op find no current record and a delete
find nothing at all — both omissions with no bookkeeping. **Verified the failure mode**: with the join
made naive on `(collection, rkey)`, the superseded create came back carrying `{"v":"second"}` — the
newer value on the older op, which is worse than omitting it.

### Half of it was already present

`RecordRow` already carried `value: Vec<u8>`, so `listRecords` fetched values from storage and the
handler discarded them. `OplogEntry` genuinely had none.

### One converted test, one deleted test

`list_records_keys_only_paginated` asserted keys-only *without* `excludeValues`, pinning the
divergence — **ninth instance** in this series. Converted rather than deleted, since its pagination
coverage is real.

A limit-clamp test was written and then **removed**: the storage layer already clamps, so it could not
fail and would have read as a guard while guarding nothing.

### API shape

`SpaceReader::list_records` hit clippy's 8-argument limit; `collection`/`cursor`/`limit`/`reverse` are
grouped into `RecordListing` rather than suppressing the lint.

### Deliberately unchanged

`listRecords.repo` is lexicon-required and stays optional here — a wire-shape item for M3.11. Making
it required now would break the OAuth self-read that M3.3's tests rely on.

## F-SPACE-01 group — merged (PR #46, `473f617`)

Draft at `.claude/context/pr-drafts/F-SPACE-01.md`. Branch and worktree removed.

All three CONFIRMED: neither `getRepo` nor `getLatestCommit` was in the route table.

### Record blocks are copied, not re-encoded

HappyView re-encodes to JSON with RAW CIDs — a HappyView storage artefact, not a lexicon requirement.
Copying `space_record.value` with `space_record.cid` is the only choice under which the index, the
commit and `getRecord` all agree.

### Two tests route-removal could not verify

- **Paging**: broke the loop, watched the 105-record export truncate to one page.
- **The non-member refusal**: my first version asserted `!= OK`, which an *unrouted* endpoint also
  satisfies. Tightened to the specific 400 `SpaceNotFound`.

## ⚠️ NEW FINDING — pre-existing DRISL codec bug, reproducible on `main`

Hit while verifying; **not from this branch**, which does not touch `atproto-dasl`.

A byte string beginning `0x00 0x01` decodes as a `Link` instead of `Bytes`:

```rust
let mut data = vec![0u8, 1u8];
data.extend(std::iter::repeat_n(0u8, 23));
let encoded = to_vec(&Ipld::Bytes(data.clone())).unwrap();
assert_eq!(Ipld::Bytes(data), from_slice(&encoded).unwrap()); // FAILS on main
```

Reported by `atproto-dasl`'s `bytes_roundtrip` proptest and reproduced deterministically. This is
**data-model corruption in the DRISL codec** — the class of defect the whole M1 encoding track existed
to close — and the proptest only samples it occasionally, so **the workspace suite on `main` is
intermittently red**. Earlier green runs in this series passed partly because the input was not
sampled.

I removed the `proptest-regressions` file proptest wrote so this branch does not turn an unrelated
crate red in CI. **That file should be recreated deliberately** by whoever takes the fix — it is what
makes the case reproducible for everyone. Deserves its own branch and its own Step 2.

## F-SPACE-05 — merged (PR #47, `22fdcab`)

Draft at `.claude/context/pr-drafts/F-SPACE-05.md`. Branch and worktree removed.

CONFIRMED — and the plumbing already existed. `space_received_op.set_hash` was being filled with an
empty blob, and the writer built the signed commit and bound it to `_`. **Fifth built-but-not-wired
variant** in this series.

### The aggregate-correctness trap

`MAX(rev)` with a bare `set_hash` column would work on SQLite (documented behaviour) and silently
pair a rev with another row's hash anywhere else. Written as a correlated subquery. A wrong hash is
worse than a missing one because a syncer acts on it.

### Tolerance decision

`hash` is lexicon-required and always sent; a payload without one is accepted and logged. HappyView
omits it entirely — **no worked reference exists** — so rejecting would drop notifications from every
peer running today's code. Approved by the user before implementation.

### Testability gap — stated, not worked around

The end-to-end loop is **not** covered. `fire_notify_write` resolves the owner's `#atproto_pds`
endpoint from their DID document, which the harness cannot provide, so the hop never fires. My first
attempt drove a real space write and found zero receipts. Rather than assert around it I extracted
`build_notify_payload` as a seam and tested the three halves independently. Same root cause as the
M2.20 PLC gap.

### New finding candidate — `space_received_op` PK omits the issuer

PK is `(space, rev, nsid)`. Two members writing at the same rev collide under `INSERT OR IGNORE`, and
the second receipt is dropped — losing that repo from `listRepos` until its next write. TIDs are
per-writer, so unlikely rather than impossible.

## F-SPACE-23 group — merged (PR #48, `a922e82`)

**M3.11 · F-SPACE-16, 17, 22, 23, 24, 26** — the wire-shape conformance group. All six confirmed
against current code before implementation.

### Report corrections

- **F-SPACE-16 names `listRecords` only; three endpoints were unclamped.** `listRecords` was already
  fixed by M3.6. `listSpaces` (`space_handlers.rs:467`) and `listMembers` (`:577`) are not named in
  the report and were also unbounded. All four now share one `page_limit(requested, default, max)`
  helper — the ceilings genuinely differ (100 records/spaces, 1000 ops/members).
- **F-SPACE-26 names three 404s; the third is `getSpaceCredential` (`:1840`), which the report lists
  as a 400.** It was a 404. Same class, fixed the same way.
- **My own Step 2 summary was wrong about the four-way split.** I said fixing `applyWrites`' output
  meant splitting `SpaceCommitResult` into four types. `createRecord`/`putRecord` already projected
  through `single_write_response` into a conformant `{uri, cid}` and `deleteRecord` already returned
  `{}`. Only `applyWrites` returned the raw commit — one new type, not four.

### Departure from the approved plan — `policy` absent is not a 400

The approved plan said a `createSpace` config carrying neither `policy` nor `mintPolicy` becomes a
400, since `#spaceConfig` marks `policy` required. I did not do that.

`#spaceConfig`'s own description reads *"'member-list' (default) consults the member list"* — the
lexicon names a default for the field it marks required, and `#spaceConfig` is the shape on **both**
the create input and the `getSpace` output. The required-ness describes what a space always *has*,
not what a client must always *send*. A 400 would contradict the lexicon's own prose. Absent policy
still defaults; only the field name changed.

### Bug found by my own new test

`list_spaces`' `LIKE` prefix was built from `ATS_SCHEME` (`ats://`) rather than `AT_SCHEME`
(`at://`), so every `type=`/`did=` filter matched nothing and returned an empty page. Caught by
`list_spaces_filters_by_type_and_did_and_pages` on its first filtered assertion. Filter values are
`LIKE`-escaped with `ESCAPE '\'` so a `_` or `%` in a DID narrows rather than widens.

### Tests pinning the divergences — fourteen, across three files

Three asserted `config["mintPolicy"]` (one *sent* it on `updateSpace`); seventeen `applyWrites`
bodies had no `repo`, hidden behind a shared `space_write` helper; `apply_writes_then_read_back`
asserted on `rev`/`setHash`; two `getRecord` cases exercised the implicit-`repo` form, one named
"alice → alice implicit" — precisely the behaviour the lexicon does not have.

`delegation_token_expired_rejected` minted a zero-TTL token and slept 1.1s, which now lands *inside*
the new 60s skew window. Rewritten to build the payload directly with `exp` past the tolerance; the
sleep is gone.

### Breaking wire changes

`applyWrites` requires `repo` and drops `rev`/`setHash`; `getRecord` requires `repo` (no implicit
form); `listSpaces` drops `filter` — the `owned`/`member` distinction has no lexicon equivalent;
three endpoints changed status for `SpaceNotFound`.

### New finding candidates

- **`SpaceDeleted` is still 404** while `SpaceNotFound` is now 400 everywhere. Arguably the same
  inconsistency class, but out of F-SPACE-26's scope and a distinguishable condition.
- **`validate` accepted and ignored on `applyWrites`**, matching `createRecord`/`putRecord`, which
  have carried `#[allow(dead_code)]` on it since they were written. Wiring space writes through
  `repo/prepare.rs`'s `ValidateMode` is a behaviour change, not a wire-shape one.
- **422-vs-400 on space handlers** — already recorded; this branch surfaces it, since `repo`
  becoming required makes axum's `Json` rejection the common failure for older clients.

### Still owed upstream

HappyView shares the `mintPolicy` divergence, so **no worked reference exists** and the report asks
for an upstream 0016 issue. Not filed — alongside the F-SPACE-07 one still outstanding.

## F-SPACE-21 — merged (PR #49, `b7274a4`)

**M3.12** — `listRepoOps.since` accepts a bare rev. CONFIRMED; report cites had drifted (M3.6 and
M3.11 moved them): `:1273` → `:1642-1645`, `:1331-1340` → `:1714-1723`, `:1354` → `:1734-1738`;
`batch_larger_than_limit_pages_fully` is `space_repo.rs:648-694`.

### The argument the report does not make, and which settles it

**`listRepoOps` declares no `cursor` *input*.** Its output schema declares `cursor`; its parameters
are `space`, `repo`, `since`, `limit`, `excludeValues`. So the draft's own next-page token has
nowhere to go except back into `since` — `since` is the resume cursor by construction, and the
"operations after this revision" wording is imprecision rather than evidence of a second parameter.
Accepting both forms is the only coherent reading, not a concession.

### Report correction — no worked reference exists here either

HappyView reads a parameter named **`cursor`** on `listRepoOps` (`routes.rs:1085-1130`), which the
lexicon does not declare on that method, passes it as bare `rev > ?` (`oplog.rs:40-44,109-113`), and
returns neither `cursor` nor `commit`. It stores `idx` and never pages by it — it has the tail-drop
bug the report predicted. The two implementations diverge from the lexicon in *different*
directions: this server had the right semantics under the wrong name, HappyView the right name under
lossy semantics.

### Design: `(rev, 0)`, not `(rev, u32::MAX)`

A bare rev cannot express a mid-batch position, so the reading must be safe for the case it cannot
represent. `(rev, 0)` re-delivers a batch's remaining ops — duplicates, which a syncer absorbs since
it applies by `(collection, rkey, cid)`. `(rev, MAX)` is exact for a client that consumed the whole
batch and **drops the tail** for one that stopped inside it. Only one of the two can lose data.

`(rev, MAX)` is not hypothetical: it is the most literal reading of the lexicon's prose and it is
what HappyView does. The acceptance test `a_bare_rev_recovers_a_batch_tail_rather_than_skipping_it`
was verified red against **both** neutralisations — the branch removed, and the branch present as
`(rev, MAX)` — so it genuinely discriminates the two readings.

### Test pinning the divergence

`oplog_cursor_rejects_malformed`'s first case asserted a bare rev is an error, labelled *"Missing
separator"* — the exact behaviour fixed. Replaced with the empty-token case.

### Process note — worktrees and the DASL submodule

`git worktree add` does not populate `crates/atproto-dasl/tests/dasl-testing`, so the first workspace
run in a fresh worktree fails 13 DASL compliance tests on missing fixtures.
`git submodule update --init --recursive` inside the worktree fixes it. Unrelated to any branch;
worth knowing for the next one.

### Still owed upstream — now three

The batch-tail-drop issue joins F-SPACE-07 (read-time membership) and F-SPACE-22 (`policy` vs
`mintPolicy`). None filed.

## Milestone — the PDS `-rc` gate is closed

**Done: M1.1–M1.14 and M2.1–M2.24.**

Every item the report names as gating the PDS `-rc` suffix has merged, across 39 PRs. M2.25 (full
lexicon validation) and M2.26 (covering proofs) are M2 items the report explicitly excludes from the
gate; all of M4 is ops hardening that gates nothing.

**The spaces `-rc` gate is closed as well.** M3.1–M3.8, M3.11 and M3.12 merged across PRs #40–#49.
The report notes M3 does not depend on M1 or M2 — `space_record` is disjoint from the MST and block
store — which is why the two tracks ran back to back without interleaving.

### What the gate closing does and does not mean

The report is explicit that closing these items is **not** the same as verified conformance. Its own
thresholds name three observable events that have not happened:

1. **No live relay has ingested this firehose.** F-FIRE-01…05 are closed by inspection and by the
   vendored interop vectors, not by observation.
2. **No end-to-end OAuth run.** A scripted `@atproto/oauth-client-node` completing PAR → authorize →
   token would move F-OAUTH-01…05 from source-read to verified — which matters most because M1.4 +
   M2.1 + M2.2 shipped as the account-takeover chain.
3. The upstream MST/commit vectors **are** now a CI gate and pass, so F-REPO-01…04 are provably
   closed rather than believed closed. That threshold has been crossed.

Recommend running (1) and (2) before dropping the suffix, and treating them as release criteria
rather than as follow-up work.

M2.25 and M2.26 are M2 items the report explicitly excludes from the gate.

### Remaining work snapshot (stale — kept for the M1-complete milestone note)

Written when 31 findings were closed and the PDS gate had 5 items left. Superseded by the M2
progress section above; the M1-complete and spaces-track observations below still hold.

**Spaces `-rc` gate — untouched.** All 16 M3 items are open; 9 of them are in the gate
(M3.1–M3.8, M3.11, M3.12). The report notes M3 does not depend on M1 or M2 — `space_record` is
disjoint from the MST and block store — so the spaces track could run in parallel.

**M4** — M4.1 landed with M1.7 (PR #10); F-FIRE-10 landed with M1.13 (PR #17). The rest is open
and none of it gates either `-rc`.
