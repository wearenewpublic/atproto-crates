# atproto-crates `0.15.0-rc.1` — release-candidate gap analysis

_Analysed 2026-07-28 at git HEAD `18b826f`, branch `claude/atproto-crates-rc-gap-analysis-c6604d`._

## The answer

**Neither `-rc` suffix can come off today**, and the two tracks are blocked for structurally
different reasons. This is the most useful single result in the report, because it means they are
**not blocked on each other** and can be worked in parallel or in either order.

**(a) The PDS** is blocked on correctness, not on missing features. It does not currently produce AT
Protocol repositories that any other implementation can verify: three
`#[serde(skip_serializing_if = "Option::is_none")]` attributes drop map keys the data model requires
to be present-and-null, so every MST root CID and every commit CID this server has ever produced
hashes differently from what a peer computes (F-REPO-01, verified by execution down to the byte
count and the CID pair). A separate defect in `Mst::delete` silently rewrites a neighbouring
record's key, which is data loss rather than non-conformance (F-REPO-03). The firehose emits a body
matching no member of the `subscribeRepos` union and never carries repo blocks, so no relay can
consume it (F-FIRE-01, F-FIRE-02). The OAuth authorization server is extensively built and
unreachable, because PAR and token accept JSON where every standard client sends form encoding
(F-OAUTH-01) — and behind that wall sits an authorization-code exfiltration chain that ends in full
account takeover (F-OAUTH-02 + F-OAUTH-03). Account migration fails at three independent points in
sequence. None of it was caught because there is no CI running the test suite at all, and the
conformance-vector submodule the project declares is empty (F-OPS-01).

**(b) The permissioned-data / spaces track** is blocked on two confidentiality holes and three
byte-level divergences, against a target that is still moving. Permissioned records are readable by
any other account on the same PDS (F-SPACE-07, inherited from the reference draft), and permissioned
blobs are readable by anyone at all through the public `com.atproto.sync.getBlob` (F-BLOB-03, which
is *not* inherited and is scored fully against atproto-crates). The signed-commit context string
omits the author DID, the commit has no `ver` field, and the space URI uses `ats://` where the draft
lexicons type every space reference as `at-uri`; those three are one coordinated change of roughly a
hundred lines and must land together, because `space` is length-prefixed into the signed context.

The honest counterweight, which the comparison work established rather than assumed: on the spaces
track atproto-crates is **ahead of every comparison target on integration and behind on byte-level
conformance**. Its LtHash is byte-identical to the reference and runs on the production write path,
where HappyView's is correct and dead code; its commit signing, real CIDs, `jti` replay guard and
end-to-end client attestation all execute, where the equivalent code in HappyView does not. Fixing a
byte layout is small and surgical. Fixing "the crypto was never wired" would not be.

## Top 5 blockers — PDS

1. Every repository and commit CID is non-conformant, because three optional map keys are omitted
   where the spec requires present-and-null — F-REPO-01 (with F-REPO-02, `prevData` carried inside
   the signed commit body) · [B. repo](./capability-areas/22-repo.md)
2. `Mst::delete` reconstructs the following entry against the wrong base key and silently corrupts a
   neighbouring record in place — the only finding in the report that destroys user data —
   F-REPO-03 · [B. repo](./capability-areas/22-repo.md)
3. Authorization-code exfiltration via an unvalidated `redirect_uri`, chained to a `/oauth/token`
   endpoint that requires no client authentication and lets the caller pick its own `cnf.jkt` —
   F-OAUTH-03 + F-OAUTH-02, gated today only by F-OAUTH-01, which must therefore ship with them ·
   [G. OAuth](./capability-areas/27-oauth.md)
4. The firehose is not consumable by any relay: a non-union envelope, no CARv1 blocks anywhere, and
   per-actor rather than global sequence numbers — F-FIRE-01 + F-FIRE-02 + F-FIRE-05 ·
   [E. firehose](./capability-areas/25-firehose.md)
5. Password-reset and account-delete tokens are written to the application log at INFO in the
   shipped container image — F-OPS-03 · [L. ops](./capability-areas/32-ops.md)

Ranked from §2 (exploitability × blast radius) and §5 (remediation order) of the
[synthesis](./50-synthesis-and-roadmap.md). Two more sit just outside: unauthenticated DID squatting
through `createAccount` (F-ACCT-02) and moderation actions that do not take effect in any of the
three senses an operator would mean (F-MOD-01 + F-MOD-02 + F-ACCT-04).

## Top 5 blockers — spaces

1. Permissioned blobs are world-readable through the public `com.atproto.sync.getBlob`, needing no
   credential at all, only a CID — F-BLOB-03 · [I. blobs](./capability-areas/29-blobs.md)
2. Any app-password session on the same instance can read any other account's permissioned records —
   F-SPACE-07, scored as inherited from the reference draft, fix locally and raise upstream ·
   [permissioned overview](./permissioned/40-permissioned-overview.md)
3. The commit format diverges in three coupled ways that cannot be split: the `ctx` omits the author
   DID, the signed commit has no `ver`, and the URI scheme is `ats://` — F-SPACE-19 + F-SPACE-04 +
   F-SPACE-18 · [permissioned overview](./permissioned/40-permissioned-overview.md)
4. `Box::leak` on the hottest authenticated space read path leaks a string per request — a
   one-line availability defect — F-SPACE-30 ·
   [permissioned overview](./permissioned/40-permissioned-overview.md)
5. The sync path has no recovery route: no `getRepo`, no `getLatestCommit`, and `listRecords` and
   `listRepoOps` return no record values, so backfill is quadratic and a syncer past its oplog
   retention cannot catch up — F-SPACE-01 + F-SPACE-02 + F-SPACE-03 (with F-SPACE-11, F-SPACE-05) ·
   [permissioned overview](./permissioned/40-permissioned-overview.md)

## Scope and method

The subject is atproto-crates at workspace version `0.15.0-rc.1`, covering both the public federated
PDS surface and the permissioned-data implementation. It was compared against **eleven other PDS
implementations** — the Bluesky reference plus ten independent projects in nine languages — and
against **three permissioned-data systems** (contrail, HappyView, stratos). Every claim is
source-derived: each is anchored to a `file:line` an agent opened, in this worktree for
atproto-crates and in a cloned comparison corpus under `/tmp/gap-scratch/` for everything else.
Nothing is recalled, and where a pass could not establish something it is carried forward as an
explicit unknown rather than smoothed over.

XRPC method behaviour was verified against the canonical lexicon JSON in `bluesky-social/atproto`,
not against prose documentation or against the reference implementation's habits, so a divergence is
a divergence from the schema the ecosystem's clients validate with. For the spaces track the oracle
is the 0016 draft lexicons obtained from that repository's `permissioned-data` branch at HEAD
`3f6c96d` (2026-07-02) — 19 files under `space/` and 8 under `simplespace/` — together with the
reference TypeScript implementation on the same branch (`packages/space/*`,
`packages/pds/src/api/com/atproto/space/*`). Having both is why spaces conformance could be
*measured* rather than guessed: the lexicons settle the `ctx` field order, the required `ver`, the
`at-uri` format on every space reference, the `policy` field name and the required `hash` on
`notifyWrite`, all of which the proposal prose leaves open.

A dedicated citation audit then re-opened roughly **576 load-bearing citations at their cited
lines**. Drifted line numbers were corrected in place, and claims the cited source did not support
were rewritten or downgraded in place rather than deleted — the `importRepo` historical-key credit,
the takedown-enforcement framing, the rate-limiting framing and the spaces read-authorization
scoping all changed as a result, and the corrected readings are the ones this report carries.

## How to read this report

Findings carry a stable ID of the form `F-<AREA>-<nn>` and are classified into four gap classes.
**MISSING** means the capability does not exist. **PARTIAL** means it is present but incomplete
enough to break a real workflow. **DIVERGENT** means it is present and working, on a different wire
contract than the oracle — which is the most common and most dangerous class here, because a
divergent implementation looks healthy in its own tests. **OUT-OF-SCOPE** marks deliberate
deferrals, each justified in the synthesis as a defensible RC-to-stable call. Severity is tracked
separately from class: *blocker*, *stable-gap*, *cosmetic*.

The fairness calibration matters more here than it usually would, and reading a row without it
produces wrong conclusions. The reference PDS is a completeness **ceiling, not a bar** — it is the
implementation the lexicons are generated from, and several of its own cells are `N` where
independent projects chose to do more. A gap that atproto-crates **shares with the reference is not
scored as an atproto-crates defect**; it is noted and, where appropriate, given an upstream action.
And the independent field is considerably stronger than the "a bunch of hobby PDSes" framing
suggests: cocoon ships a complete OAuth 2.1 authorization server, zds routes 46 canonical
`com.atproto.*` methods against a real multi-account store, and metalbear and pegasus are both
multi-account with working OAuth. Only alteran (hobby-experiment) and cirrus and dnproto
(single-user by construction, not by omission) sit below the "serious" line. So when this report
says atproto-crates is behind the field on something, the field it is behind is a high one — and
conversely, the places where it leads are worth more than they would be against a weak corpus.

## Full index

### Baseline and matrix

- [00-atproto-crates-inventory.md](./00-atproto-crates-inventory.md) — the factual baseline: the
  19-crate workspace map, which crates implement the PDS and which implement permissioned data,
  every route the server registers, the storage backends, and the confidence-and-unknowns ledger the
  rest of the report inherits.
- [20-coverage-matrix.md](./20-coverage-matrix.md) — 280 granular capability rows scored across all
  twelve implementations, one table per capability area, opening with the maturity-tier table and
  closing with "How to read the atproto-crates column", which explains why an `N` next to a
  single-user project's `n/a` is not the finding it looks like.

### Capability areas (rubric A–L)

- [A · 21-accounts.md](./capability-areas/21-accounts.md) — account lifecycle: server discovery,
  creation, sessions, the active/deactivated/suspended/takendown/deleted state machine, and the
  `#account` events that broadcast it.
- [B · 22-repo.md](./capability-areas/22-repo.md) — repository and data model: MST structure and
  encoding, commit objects, DAG-CBOR, CIDs and CAR. The byte-level chapter, and the one whose
  findings were reproduced by execution.
- [C · 23-records.md](./capability-areas/23-records.md) — `com.atproto.repo.*` write and read
  operations, optimistic concurrency via `swapCommit`/`swapRecord`, and record validation.
- [D · 24-identity.md](./capability-areas/24-identity.md) — handles, DID documents, PLC operation
  signing and submission, and the well-known endpoints. The area with the strongest library asset
  and the weakest wiring of it.
- [E · 25-firehose.md](./capability-areas/25-firehose.md) — `com.atproto.sync.subscribeRepos`: frame
  encoding, the four event types, the CAR block slice, sequencing and backfill.
- [F · 26-sync.md](./capability-areas/26-sync.md) — Sync 1.1: inductive verification with `prevData`
  and covering proofs, host status, and the `com.atproto.sync.*` read surface.
- [G · 27-oauth.md](./capability-areas/27-oauth.md) — the PDS as OAuth 2.1 authorization server and
  resource server: PAR, PKCE, DPoP, client metadata, token issuance, and scope enforcement.
- [H · 28-service-auth.md](./capability-areas/28-service-auth.md) — inter-service JWTs
  (`getServiceAuth`, `lxm` scoping, verification, revocation) and AppView proxying.
- [I · 29-blobs.md](./capability-areas/29-blobs.md) — upload, reference-time enforcement, quotas,
  serving headers, blob lifecycle and the permissioned-blob exposure.
- [J · 30-moderation-admin.md](./capability-areas/30-moderation-admin.md) — the `com.atproto.admin.*`
  control plane and, more importantly, whether takedowns actually take effect on reads and writes.
- [K · 31-migration.md](./capability-areas/31-migration.md) — account migration in and out, judged on
  whether the whole canonical sequence completes rather than on individual endpoints; CAR
  import/export.
- [L · 32-ops.md](./capability-areas/32-ops.md) — cross-cutting operations: CI, rate limiting,
  secrets and logging, configuration and production gates, metrics, backup, deployment and operator
  documentation.

### Permissioned data (proposal 0016)

- [40-permissioned-overview.md](./permissioned/40-permissioned-overview.md) — the spaces track: what
  0016 specifies, the full `F-SPACE-*` finding set scored against the draft lexicons, and the
  four-way cross-implementation comparison.
- [41-contrail.md](./permissioned/41-contrail.md) — contrail, a pre-alpha TypeScript appview library
  that stores permissioned records in its own SQL and never touches a PDS. Read for ideas
  (enrollment as host consent, signed membership manifests, invite tokens), not for wire conformance.
- [42-happyview.md](./permissioned/42-happyview.md) — HappyView, a Rust AppView and the **only
  same-direction interop yardstick** in the field: same namespace, same credential exchange, same
  LtHash parameters. Where both diverge from the draft, that is a signal about the draft.
- [43-stratos.md](./permissioned/43-stratos.md) — Stratos, Northsky's TypeScript boundary-aware data
  layer; another point in the design space, contributing the read-leakage rule and service-qualified
  boundary tokens.

### Per-implementation notes

| Implementation | Language | Verified tier | Notes |
| --- | --- | --- | --- |
| [bluesky-reference](./impl-notes/bluesky-reference.md) | TypeScript / Node | reference | `@atproto/pds` plus the self-host wrapper; the spec oracle for the whole report |
| [tranquil-pds](./impl-notes/tranquil-pds.md) | Rust | serious | 22-crate workspace, axum + Postgres, repo primitives from external crates |
| [rsky-pds](./impl-notes/rsky-pds.md) | Rust | serious | now SQLite-backed, not Postgres; full OAuth AS and blob ref-counting |
| [cocoon](./impl-notes/cocoon.md) | Go | serious | complete OAuth 2.1 AS, resumable firehose with Sync 1.1, CI and published images |
| [zds](./impl-notes/zds.md) | Zig | serious | 46 canonical methods on a real multi-account store; strongest independent identity handling |
| [metalbear](./impl-notes/metalbear.md) | C11 | serious | application layer only; protocol primitives live in the un-vendored Wolfram SDK |
| [pegasus](./impl-notes/pegasus.md) | OCaml | serious | Dream + Caqti, multi-account, S3 backup path |
| [arroba](./impl-notes/arroba.md) | Python | serious | a library plus a demo app; runs the upstream interop-test fixtures as a CI gate |
| [cirrus](./impl-notes/cirrus.md) | TypeScript / Cloudflare Workers | single-user | full `com.atproto.repo`/`sync` coverage and a real OAuth AS at single-account scope |
| [dnproto](./impl-notes/dnproto.md) | C# / .NET 10 | single-user | gets the MST and DAG-CBOR byte format right, including tag-42 `$link` |
| [alteran](./impl-notes/alteran.md) | TypeScript / Cloudflare Workers | hobby-experiment | an Astro integration rather than a server; still ships flat firehose bodies, real CARv1 and per-IP limits |

### Capstone

- [50-synthesis-and-roadmap.md](./50-synthesis-and-roadmap.md) — the authoritative document. All 182
  classified findings consolidated (§1), the security and spec-compliance blockers ranked (§2), the
  "even a smaller project does this" list (§3), where atproto-crates leads the field (§4), the
  four-milestone remediation roadmap including the separate minimum sets for each `-rc` (§5), the
  observable thresholds that would change the recommendation (§6), and confidence and provenance
  (§7). Where this index and the synthesis appear to differ, the synthesis is correct.

## Caveats

**0016 is an explicitly work-in-progress draft.** Its README says so in those words. Spaces
"divergences" are therefore statements about interop with an in-flight design, not about
correctness, and any conformance claim has to be dated: the defensible one here is "conformant to
the draft lexicons at `3f6c96d` (2026-07-02)", and it will expire. In at least one place
(the `(rev, idx)` oplog cursor) atproto-crates is right on the merits and wrong on the wire.

**No finding in this report was reproduced against a running instance.** The DID-squatting path, the
OAuth takeover chain, the firehose's rejection by a live relay and the cross-tenant space read are
all verified line by line in source, with no live request issued. The five repo-layer findings marked
"executed" are the exception: they were reproduced by compiling against this worktree's own crates
and printing actual bytes and CIDs.

**Two comparison columns are thinner than the other nine.** tranquil-pds and metalbear read as
unaudited across most of the repo area for structural reasons — their MST, commit and CBOR code
lives in un-vendored dependencies (`jacquard-repo`/`jacquard-common` and an external Wolfram library
respectively) — so "atproto-crates is behind the field on MST encoding" rests on nine columns, not
eleven.
