# fix(pds): correct four response shapes that no validating client accepts

## What and why

Four independent divergences, each small, each fatal to a client that checks its responses against
the lexicons. Batched because they are all the same size, not because they interact.

| Finding | Site | Defect |
| --- | --- | --- |
| `F-REC-03` | `repo/reader.rs:250,328` | `listRecords` emits a cursor on every non-empty page, and `null` when there is none |
| `F-FIRE-04` (part) | `mst/diff.rs:170` | `#repoOp.cid` omitted where the lexicon requires present-and-null |
| `F-REC-02` | `http/write_handlers.rs:326-332` | `applyWrites` results carry no `$type` union discriminator |
| `F-REC-01` | `repo/reader.rs:463-484` | `describeRepo` omits the required `didDoc` |

## Three things the findings understate

**1. `listRecords` needed a logic fix, not just `skip_serializing_if`.** Both code paths set the
cursor from `rows.last()` unconditionally, so a partial final page advertised a cursor that led to
an empty page carrying `"cursor": null`. The client therefore made one wasted round trip *and* then
threw. A cursor is now emitted only when the page was full — a partial page cannot have more behind
it.

**2. `prev` must keep its `skip_serializing_if`.** The finding groups `#repoOp.cid` with the MST
`l`/`t` fix as "the same root cause", which is right for `cid` and wrong for `prev`. The lexicon
declares `cid` **required and nullable** but `prev` **optional** — "for creations, field should not
be defined". Removing both would have broken every create. The asymmetry is the specification's.

**3. `applyWrites` was wrong in three ways, not one.** Beyond the missing discriminator, reading
`applyWrites.json` shows that neither `#createResult` nor `#updateResult` carries `commit` — it
appears once at the top level — and `#deleteResult` is an empty object (`"required": []`,
`"properties": {}`), where results previously carried a `uri` it does not define.

Standalone `createRecord`/`putRecord` keep their existing `{uri, cid, commit}` shape: that is a
different schema, and it was already correct.

## The one judgement call: `describeRepo.didDoc`

The reference resolves the DID through a caching `idResolver`. This synthesises the document from
local state instead, using `atproto_identity::model::DocumentBuilder` — the same builder
`crates/atproto-pds/src/plc.rs:198` already uses to construct this exact document at PLC genesis.

The reasoning: `didDoc` is a **required** field. Resolving would turn a PLC outage into a hard
failure of `describeRepo`, for a document whose useful contents — the handle, the signing key, the
PDS service endpoint — this server is itself the authority for, for the accounts it hosts.

The tradeoff, stated in the code and worth review: an account whose PLC document already points at
another PDS mid-migration is described here as still local. `describeRepo` is only meaningful for
accounts this server holds, so that window is the migration itself.

Happy to switch to resolve-with-synthesised-fallback if you would rather match the reference.

## Worked reference

`packages/lexicon/src/validators/primitives.ts:172-177` (cursor is a non-nullable string);
`applyWrites.json`'s closed output union plus `packages/lexicon/src/validators/complex.ts:165-174`;
`describeRepo.json` `"required": [handle, did, didDoc, collections, handleIsCorrect]`;
`subscribeRepos.json` `#repoOp` with `"required": [action, path, cid]` and `"nullable": [cid]`.

All eleven comparisons emit `didDoc`; eight discriminate the `applyWrites` union correctly; dnproto
re-types CIDs before emitting (`src/pds/UserRepo.cs:353-357`).

## Testing

Four tests in a new `wire_shapes.rs`, asserting **serialized JSON** rather than round-tripping Rust
values — in every case the defect is the presence or absence of a key, which a round trip cannot
see. **All four fail against the previous code.**

The `repoOp` test asserts both halves of the asymmetry in one place: a create must omit `prev`, a
delete must carry `"cid": null`.

One existing test, `apply_writes_atomic_batch`, asserted `result["commit"]["rev"]` on each entry —
the shape being corrected. Updated to assert the discriminator and the absence of per-result
`commit`.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2047 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**`applyWrites` is a breaking response change.** Anything reading `results[].commit` or
`results[].uri` on a delete will need updating. That is the point — those fields are not in the
schema — but it is a visible break rather than an additive fix.

`#repoOp.cid` changes firehose payload bytes for deletions. The firehose is not yet consumable by a
relay for other reasons (F-FIRE-01, F-FIRE-02), so nothing downstream is relying on the old shape.

`listRecords` clients that followed the cursor to an empty page will now stop one request earlier.

## Deliberately out of scope

- The rest of **F-FIRE-04** — payloads still round-trip through JSON, so CIDs still serialize as
  `{"": [bytes…]}` rather than tag 42. That is M1.13 and needs the writer to store DAG-CBOR
  natively.
- The non-lexicon `head_cid`/`head_rev`/`head_data` extras on `describeRepo`. Nothing in the
  workspace reads them, lexicon objects are not closed so they do not fail validation, and removing
  them could break a consumer outside this repository.
- `validationStatus` on create/update results — nothing validates records yet (F-REC-05).
- `F-REC-04` (`swapCommit` accepted and never enforced), `F-REC-06` through `F-REC-11`.

## Resolves

`F-REC-01`, `F-REC-02`, `F-REC-03`, and the `#repoOp.cid` half of `F-FIRE-04` (roadmap M1.8).
