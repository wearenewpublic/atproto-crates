# fix(atproto-space): accept a bare rev on `listRepoOps.since`

Closes **F-SPACE-21**. Milestone M3.12 — **the last item in the spaces `-rc` gate.**

## What was wrong

`OplogCursor::from_token` (`atproto-space/src/storage.rs`) required a composite `"<rev>__<idx>"` token and returned `InvalidCursor` for anything else; the handler turned that into a 400 (`space_handlers.rs:1714-1723`). A client written against the lexicon alone sends a bare rev, so it could not page the oplog at all — the first `since` it tried was rejected.

Report cites had drifted (M3.6 and M3.11 moved them): `:1273` → `:1642-1645`, `:1331-1340` → `:1714-1723`, `:1354` → `:1734-1738`, and `batch_larger_than_limit_pages_fully` is `space_repo.rs:648-694`.

## The argument the report makes, plus one it doesn't

The report's framing is right: *"atproto-crates is right on the merits and wrong on the wire."* The `(rev, idx)` cursor exists because of a real regression test — a bare-rev cursor drops the tail of an atomic batch larger than `limit`.

What the report does not mention, and what settles it: **`listRepoOps` has no `cursor` input parameter.** Its output schema declares `cursor`; its params declare `since`, `limit`, `excludeValues`, `space`, `repo`. So the draft's own next-page token has nowhere to go *except* `since`. `since` is already the resume cursor by construction — the "revision" wording is the draft's imprecision, not evidence of a second, opaque parameter.

That makes accepting both forms the only coherent reading, rather than a concession.

## No worked reference — HappyView diverges too, differently

`list_repo_ops` (`routes.rs:1085-1130`) reads a parameter named **`cursor`**, which the lexicon does not declare on this method at all, passes it as a bare `rev > ?` (`oplog.rs:40-44`, `:109-113`), and returns neither `cursor` nor `commit`. It stores `idx` in the oplog table and never pages by it.

So HappyView has the tail-drop bug the report predicted, and the two implementations disagree with the lexicon in *different directions*: this server had the right semantics under a name the lexicon doesn't imply; HappyView has the right name under semantics that lose data.

## Why `(rev, 0)` and not "strictly after `rev`"

This is the whole design decision, so it is worth stating plainly.

| Client state | `(rev, 0)` | `(rev, u32::MAX)` |
|---|---|---|
| Received all of batch `R` | re-delivers `R.idx ≥ 1` — **duplicates** | exact |
| Stopped mid-batch at `R.idx = k` | re-delivers `R.idx ≥ 1`, including the tail — **correct** | **drops `R.idx > k`** |

A bare rev cannot express `k`, so the reading has to be safe for the case it cannot represent. Duplicates are harmless — a syncer applies ops by `(collection, rkey, cid)`. A dropped tail is silent data loss. `(rev, 0)` can only duplicate; the strict reading can only lose.

`u32::MAX` is not a straw man: it is the reading the lexicon's prose most literally supports, and it is what HappyView does.

## Unambiguous by construction

A rev is a TID — thirteen base32-sortable characters — so it can never contain `__`. `from_token` splits on the **last** separator; absence of one means bare rev. No heuristic, no ambiguity.

## Tests

Five new — three unit, two acceptance (plus one guard). **Four verified red**, in two neutralisation passes:

```
# Pass 1 — the bare-rev branch removed entirely
a_bare_rev_is_accepted_as_the_start_of_its_batch ............ FAILED
a_bare_rev_resolves_to_index_zero_not_past_the_batch ........ FAILED
list_repo_ops_accepts_a_bare_rev_as_since ................... FAILED
a_bare_rev_recovers_a_batch_tail_rather_than_skipping_it .... FAILED

# Pass 2 — bare rev accepted, but as (rev, u32::MAX)
a_bare_rev_recovers_a_batch_tail_rather_than_skipping_it .... FAILED
```

The second pass is the one that matters. `(rev, MAX)` passes every "a bare rev is accepted" assertion and fails only the tail test — so that test is a genuine discriminator between the two readings, not a restatement of the first. It writes one atomic batch of five ops, pages two, resumes from the bare rev, and asserts `k1..k4` come back. Under the strict reading it returns empty and three writes vanish with nothing to indicate it.

`a_malformed_since_is_still_refused` stays **green** under both neutralisations, which is correct — it is a guard against the widening going too far (`"3kabc__x"` and `"__3"` are still 400), not a regression test for the fix.

## One test was pinning the divergence

`oplog_cursor_rejects_malformed`'s first case asserted that `"3kabc"` — a bare rev — is an error, labelled *"Missing separator"*. That is the exact behaviour being fixed. Replaced with the empty-token case, which is still genuinely malformed.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2345 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **806 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns` — 0 errors

One process note: the first workspace run in this worktree failed 13 DASL compliance tests because `crates/atproto-dasl/tests/dasl-testing` is a submodule and `git worktree add` does not populate it. `git submodule update --init --recursive` fixed it; nothing to do with this branch, but worth knowing for anyone else working from a fresh worktree.

## Blast radius

One parsing function, widening only — every token that parsed before parses identically. No emitted shape changes. Both storage backends and the in-memory one share the same `(rev > ? OR (rev = ? AND idx > ?))` predicate, so nothing downstream changed.

## Not fixed here

- **The upstream issue is owed and I have not filed it.** The batch-tail-drop bug will bite the reference implementation, and HappyView already has it. This is now the **third** outstanding upstream item, with F-SPACE-07 (read-time membership) and F-SPACE-22 (`policy` vs `mintPolicy`).
- **`SpaceSync::list_repo_ops` still does not call `ensure_space_live`**, so a tombstoned space's oplog stays readable. That is F-SPACE-15 / M3.13, outside the gate.
