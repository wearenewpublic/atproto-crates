# fix(repo): drop `prevData` from the signed commit body

## What and why

`prevData` is a `com.atproto.sync.subscribeRepos#commit` **event** field, not a commit field. It
carries the prior MST root CID so a Sync 1.1 verifier can check a new commit against state it
already holds — per-delivery information about how an update is being shipped, not repository
state, and not something the repository owner signs.

Carrying it inside the commit made the signed body a six-key object where the schema has five, so
the commit CID and the signature still differed from what a conformant peer computes even after the
nullable-key fix in the previous change.

Half of this was already in place: the outbox `#commit` payload has always emitted `prevData`, so
this is a removal, not a move.

## Evidence

### Before

| Site | |
| --- | --- |
| `crates/atproto-repo/src/repo/commit.rs:59-60` | `prev_data` on `Commit` |
| `crates/atproto-repo/src/repo/commit.rs:93-94` | `prev_data` on `UnsignedCommit` — the struct `signing_bytes()` serializes |
| `crates/atproto-pds/src/repo/writer.rs:349,664` | both commit paths call `UnsignedCommit::new_with_prev_data(…)` with a real value |
| `crates/atproto-pds/src/repo/writer.rs:454` | **already** emits `"prevData"` into the outbox `#commit` payload |

### What changes on the wire

```
before  a6 { did, rev, data, prev, version, prevData }    208 bytes
after   a5 { did, rev, data, prev, version }              158 bytes
```

The firehose payload is untouched. Subscribers see no change.

## Worked reference

`prevData` appears nowhere in `packages/repo/src/types.ts` or `packages/repo/src/repo.ts`. Grepping
the reference for the string returns `lexicons/com/atproto/sync/subscribeRepos.json` plus
`packages/pds/src/sequencer/events.ts`, `packages/pds/src/repo/types.ts` and
`actor-store/repo/transactor.ts` — the event and sequencer layer. It is a firehose field there and
only there.

## Testing

New byte-level known-answer vector, `unsigned_non_initial_commit_has_no_prev_data_key`, asserting
the exact 158-byte five-key encoding. **Confirmed failing against the previous code** at 208 bytes,
`a6`, with a trailing `687072657644617461` (`"prevData"`) key.

The vector has to be a *non-initial* commit. The initial-commit vectors added with the previous fix
cannot catch this: `prev_data` was `None` there and the old `skip_serializing_if` dropped it, so the
encoding was already five keys. Only a commit that would have carried a value shows the difference.

A second test, `test_commit_with_legacy_prev_data_key_still_decodes`, pins that a commit encoded
with the extra key still decodes — `DecodeConfig::disallow_unknown_fields` defaults to `false`, and
this makes that a guarantee rather than an accident.

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` are green — **2003 passed, 0 failed, 63 ignored.**

## Two consumers that read `prevData` off the commit

Both now derive it, which is a strictly better source — a value computed from blocks that are
actually present, rather than one the commit declares about itself.

- **`import.rs` verification loop.** It carried the prior root down the chain already and
  additionally cross-checked it against `commit.prev_data`. That check has no input now, and nothing
  to catch: with the field gone there is no self-declaration to disagree with. `verify_inductive`
  is unchanged and still runs on every commit.
- **`import.rs` `commit_obj` insert.** `prev_data_cid` is now set from the previous commit's `data`
  as the loop walks oldest-to-newest. The column's meaning and contents are unchanged.

## Risk and blast radius

**Commits written before this change still decode, but their signatures no longer verify.**
`import.rs:391` reconstructs signing bytes from the decoded struct, and those bytes no longer
include `prevData`. Concretely: a CAR previously exported by this server will fail
signature-verified re-import.

Those repositories were already unverifiable by any peer — for exactly this reason plus F-REPO-01 —
so nothing that previously worked stops working. It is in the CHANGELOG.

`Commit::new_unsigned_with_prev_data` and `UnsignedCommit::new_with_prev_data` are removed. Both
were internal to this workspace; `UnsignedCommit::new` / `Commit::new_unsigned` replace them.

## Deliberately out of scope

- The firehose `#commit` envelope shape itself — the payload carries `prevData` correctly, but it
  is nested under `payload` rather than flat (F-FIRE-01, roadmap M1.13). Unchanged here.
- The `commit_obj.prev_data_cid` column stays. It is correct storage of a real quantity; only its
  source changed.

## Resolves

`F-REPO-02` (roadmap M1.3).
