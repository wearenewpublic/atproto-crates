# feat(atproto-pds): structural checks on every record write

Closes **F-REC-05 (structural half)**. Milestone M2.23. The schema half is M2.25 and out of the `-rc` gate.

## What was wrong

`repo/writer.rs:361` — `format!("{}/{}", op.collection, op.rkey)`, and again at `:689` on the dispatch path. Nothing between the handler and the MST inspected either half. `:370-375` encoded `op.value` without looking at `$type`. `grep -n "validate" http/write_handlers.rs` returned **nothing**, though the lexicon declares the field.

Neither failure is recoverable. A key containing `/` produces a record whose MST path and its own AT-URI disagree; a record without `$type` cannot be decoded by any consumer — and by the time either is noticed, the commit is signed and sequenced.

**The validators already existed.** `atproto_lexicon::validation::syntax::{validate_record_key, validate_nsid}` implement the grammars exactly — the record-key one matches `syntax/src/recordkey.ts:3-6` character for character. The PDS has always depended on the crate and used it only in `space/declaration.rs:31-32`. Same "built but not wired" shape as F-BLOB-02 and the identity validation in M2.20.

## A deliberate deviation from the roadmap item

**The item says "reject records with no `$type`". This supplies one instead**, from the collection.

That is what `repo/prepare.ts:167-178` does:

- absent → set to `collection`
- present and equal → accept
- present and different → reject

Rejecting would turn away writes the reference accepts. And the finding's own stated consequence — *"a record stored without `$type` is undecodable by every consumer"* — is addressed by filling the field in. Rejecting does not make anything decodable; it just refuses.

## What changed

Three checks, applied to every op on both write paths:

1. `collection` is a valid NSID.
2. `rkey` matches the record-key grammar — 1–512 chars from `[A-Za-z0-9.:_~-]`, never `.` or `..`. That character set is precisely what keeps a key simultaneously a legal MST path segment and a legal URI path component, which is why `/` is not merely untidy.
3. `$type` reconciled with `collection`.

They run **before the write lock and before anything is encoded**, in `apply_writes_with_swap` rather than in either path — so both get them, and a refused `applyWrites` batch lands none of its ops, as its lexicon requires.

## `validate` — three methods, not four

`createRecord`, `putRecord` and `applyWrites` take it. **`deleteRecord` does not** — I checked the lexicon (CID `bafyreibwdxb…`) and it declares neither `validate` nor `validationStatus`, because a delete has no record to validate. My Step 2 summary said "all four"; that was wrong.

The flag has three states, not two: *"'false' to skip … 'true' to require it, or leave unset to validate only for known Lexicons."* Hence `ValidateMode`, not a `bool`.

**`validate: true` is refused by name** with `ValidationUnavailable`. Schema validation is not implemented here — that is M2.25 — and accepting `true` while validating nothing would be a control that reads as working and is not, which is the failure shape this whole report keeps finding. `validate: false` and unset both write.

`validationStatus` reports `unknown`. The lexicon's `knownValues` are `valid` and `unknown`; `unknown` is the only honest one until a schema engine runs, since `valid` would claim a check that did not happen.

## Tests

19 new (8 unit, 8 acceptance, plus the control). **7 verified red** across two neutralisations.

Removing the prepare step and the `validate` gate:

```
a_record_key_outside_the_grammar_is_refused_before_any_commit ... FAILED
an_absent_type_is_filled_in_from_the_collection ................. FAILED
a_type_that_disagrees_with_the_collection_is_refused ............ FAILED
a_collection_that_is_not_an_nsid_is_refused ..................... FAILED
the_checks_apply_to_every_write_path ............................ FAILED
validate_true_is_refused_by_name_rather_than_ignored ............ FAILED
```

Separately, stubbing `ValidateMode::status()` to `None`:

```
validate_false_and_unset_both_write_and_report_honestly ......... FAILED
```

`the_keys_the_protocol_allows_still_write` stays green by design — it is the control. Every other acceptance test asserts a refusal, and a prepare step that refused everything would pass all of them.

Two assertions carry more than the status code: the refused-key test re-reads `getLatestCommit` and asserts the head did not move, and the `applyWrites` test asserts the *valid* op in a refused batch was not written. A refusal that still advanced the repo would be a different bug wearing the same status code.

The unit tests are known-answer against the grammar constants, including both boundaries (512 accepted, 513 refused).

## Three existing fixtures were wrong

`put_then_delete_round_trip`, `duplicate_create_rejected_over_http` and `apply_writes_atomic_batch` used the collection `"c.col"` — two segments, which is not an NSID and never was. They were written against a server that did not check, not against the protocol. Changed to `com.example.record`.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2266 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **741 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

**Record keys and collections this server previously accepted are now refused.** That is the fix. Existing repositories may already contain such records; nothing here rewrites them, and reads are unaffected.

`validationStatus` is a new field on three responses. It is additive, and omitted entirely when the caller passed `validate: false`.

One new module, two error variants, three input structs, three output shapes, one call site in the writer.

## Not fixed here

- **M2.25** — the schema half. `validate: true` stays refused until it lands, and `validationStatus` stays `unknown`.
- The reference also rejects slurs in `rkey` (`prepare.ts:185-187`). There is no slur list in this workspace and inventing one is not this item — the same call made for the handle reserved-list in M2.20, which is deliberately smaller than upstream's.
- **F-REC-06/07/08** (M4.13) — `swapRecord` returning 403 rather than 400 `InvalidSwap`, no `applyWrites` batch cap, and `deleteRecord` on a missing record returning 400 where the reference no-ops.
- Records already stored with an invalid key or a missing `$type` are not migrated or reported. There is no sweep; `listRecords` will keep returning them.
