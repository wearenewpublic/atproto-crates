# feat(atproto-pds): inline record values on the permissioned sync path

Closes **F-SPACE-03**. Milestone M3.6.

## What was wrong

| Claim | Now |
|---|---|
| `SpaceRecordItem` is `{collection, rkey, cid}` | `space_handlers.rs:985-992` — exactly that |
| `RecordOpEntry` has no value field | `:1352-1363` |
| No `excludeValues` anywhere | Absent from both `RepoOplogQuery` (`:1333-1344`) and `ListSpaceRecordsQuery` (`:964-979`) |
| The in-code comment contradicts the lexicon | `:980-982` said *"keys-only per `com.atproto.space.listRecords#record`… Fetch the value separately via `getRecord`"*. The lexicon: **"By default each record's value is inlined"** |

So a syncer issued one `getRecord` per record with no bulk path. Initial backfill was unusable and the pull design was quadratic.

## Reading the lexicons changed two things the report does not mention

**The `limit` bounds differ per endpoint.** `listRecords` is 1–100 default 50; `listRepoOps` is 1–1000 default 100. The handler clamped `listRepoOps` correctly and applied nothing to `listRecords`.

**`opEntry.value` has a third omission condition.** *"Omitted when excludeValues is set, **for deletes, or when the value has been superseded by a later operation**."* The report mentions neither the deletes case nor the superseded case.

That third one is the load-bearing subtlety, and HappyView's construction handles it elegantly: its `LEFT JOIN` includes `AND r.cid = o.cid` (`spaces/oplog.rs:110`). Matching on the op's own CID means a superseded op finds no current record, and a delete has no CID to match at all — both omissions fall out with no extra bookkeeping.

**I verified the failure mode rather than trusting the reasoning.** With the join made naive — `(collection, rkey)` only — the superseded create came back carrying `{"v":"second"}`: the *newer* value attached to the *older* op. That is worse than omitting it, and the test catches it.

## What changed

Values inlined by default on both endpoints, decoded through the same atproto-JSON path the public reader uses, so a stored CBOR tag 42 comes back as `{"$link": …}` rather than a raw map. `excludeValues` on both; `reverse` on `listRecords`; `listRecords` clamps to 1–100.

**Half of it was already there.** `RecordRow` (`atproto-space/src/storage.rs:91-103`) already carried `value: Vec<u8>`, so `listRecords` was fetching values from storage and discarding them in the handler. `OplogEntry` genuinely had no value field — that half is new, in both storage impls.

`reverse` flips both the ordering and the cursor comparison. Getting one without the other returns the first page forever; the fjall impl also had to collect and reverse rather than break early, since its keyspace scan is ascending.

## An API shape decision

Once `reverse` arrived, `SpaceReader::list_records` took eight arguments and clippy objected. Rather than suppress it, `collection`/`cursor`/`limit`/`reverse` are grouped into `RecordListing`. At a call site `(None, None, 50, false)` says nothing about which is which.

## Tests

Five new. **Four verified red** by reverting the inlining, the `reverse` plumbing and the clamp:

```
list_records_inlines_values_by_default ..................... FAILED
list_records_honours_reverse ............................... FAILED
list_repo_ops_inlines_values_and_omits_superseded_ones ..... FAILED
list_repo_ops_exclude_values_omits_every_value ............. FAILED
```

`list_repo_ops_inlines_values_and_omits_superseded_ones` is the one worth reading. It writes create → update on one key and create → delete on another, then reads the oplog from the beginning and checks all four ops: the superseded create carries no value, the update carries `"second"`, the deleted record's create carries none, and the delete itself carries neither `cid` nor value. **Verified red a second time** against the naive join specifically.

`list_records_inlines_values_by_default` stores a `$link` so the decode path is exercised, not just the plumbing.

`list_records_honours_reverse` asserts the order *and* that reverse pagination continues rather than restarting — the cursor-comparison half of the change.

## Two tests I did not keep

**One existing test was converted, not deleted.** `list_records_keys_only_paginated` asserted the keys-only shape *without* passing `excludeValues`, which pinned the divergence. It now passes `excludeValues=true`, preserving its pagination coverage and making it conformant. Ninth instance in this series of a test asserting the implementation rather than the specification.

**A limit-clamp test was written and then removed.** The storage layer already clamps to 1–100, so the handler clamp is defence-in-depth and the test could not fail. Shipping it would have read as a guard while guarding nothing.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2302 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **770 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

Both storage impls changed, and both suites cover them.

## Blast radius

**Responses are substantially larger by default.** That is the fix; `excludeValues` restores the old shape for callers that only want keys. Both new fields are additive, so a strict parser is unaffected.

One trait method gained a parameter, one reader signature was regrouped, two storage impls and two handlers changed.

## Not fixed here

- **`listRecords.repo` is marked required by the lexicon** and stays `Option<String>` here, defaulting to the authenticated subject. That is a wire-shape item and belongs with the rest of them in M3.11 rather than being changed in passing — making it required now would break the OAuth self-read convenience that M3.3's tests rely on.
- **F-SPACE-01/02** (M3.7) — `space.getRepo` and `space.getLatestCommit` are still absent, so a syncer past its oplog retention still has no recovery path. This item makes `listRecords` a *usable* bulk read, which is what the report says `getRepo` cannot substitute for and vice versa.
- `listRepoOps` has no `reverse`, correctly — its lexicon declares none.
