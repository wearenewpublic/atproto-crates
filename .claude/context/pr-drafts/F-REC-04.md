# fix(atproto-pds): enforce `swapCommit` on all four write paths

Closes **F-REC-04**. Milestone M2.19.

## What was wrong

| Method | State |
|---|---|
| `createRecord` | declared `swapCommit` (`:179-180`) and never read it — built `swap_record: None` |
| `putRecord` | no `swapCommit` in the input struct |
| `deleteRecord` | no `swapCommit` in the input struct |
| `applyWrites` | input was `{repo, writes}` only |

All four lexicons declare it and name `InvalidSwap` as the error. `applyWrites`'s says plainly: *"If provided, the entire operation will fail if the current repo commit CID does not match this value. Used to prevent conflicting repo mutations."*

So two clients that each read the repo, decided something, and wrote both received HTTP 200 — and the second silently discarded the first's work. **The loser is never told**, which is what makes this data loss rather than a conflict.

(`swapRecord` *was* already honoured on standalone `putRecord`/`deleteRecord`, as the report says. That half worked and is unchanged.)

## What changed

A real compare-and-swap on all four.

**The interim was not needed.** The roadmap offered arroba-style rejection of any request carrying `swapCommit` as a cheap stand-in. It turned out unnecessary: both write paths already load the prior commit inside `apply_writes`, which holds the per-DID write mutex. The guard is a comparison at a line that already had the value in hand.

That placement is what makes it a genuine CAS rather than a check-then-hope — after the prior commit is read, before anything is written, with the lock held.

`applyWrites` guards the whole batch, per its lexicon.

## Error shape

`InvalidSwap` carries both the expected and the actual commit:

```
swapCommit bafy…abc does not match the current commit bafy…xyz
```

A client can see what to rebase onto, not merely that something went wrong. An empty repository reports `none` rather than pretending a caller's named commit almost matched.

## Opt-in, deliberately

Omitting `swapCommit` writes exactly as before. The guard is a claim the caller chooses to make; requiring it would break every existing client for a property they never asked for.

## API note

`RepoWriter::apply_writes` keeps its signature and delegates to a new `apply_writes_with_swap`. Threading the parameter through the original would have touched call sites in the spaces writer, which has no notion of a repo commit — 42 call sites for a parameter 4 of them care about.

## Tests

Four, two of them **verified red** by neutralising the check:

```
a_stale_swap_commit_is_refused_on_every_write_path ... FAILED
two_writers_on_one_read_do_not_both_succeed ......... FAILED
```

The other two stay green by design and are not redundant:

- **`a_current_swap_commit_is_accepted_on_every_write_path`** — a guard that refused *everything* would pass the refusal test. This one re-reads the head before each write, since every write moves it.
- **`omitting_swap_commit_writes_as_before`** — pins that the guard is opt-in.

`two_writers_on_one_read_do_not_both_succeed` is the finding stated as a test: both clients read the same head, both write against it, and it asserts the first wins, the second is refused, **and the first writer's value is what survived** — the last part being the actual consequence, not just the status code.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2180 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **655 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

One new error variant, four input structs, four call sites, one new writer method. No storage or wire-shape changes beyond a field that was already declared in every lexicon.

Clients that were sending `swapCommit` and having it ignored will now get `InvalidSwap` when they are genuinely stale — correct, but it is a refusal they have never seen from this server.

## Not fixed here

- The guard is per-server. It compares against this PDS's current commit under this PDS's write lock; it says nothing about a repository being written through two PDSes at once, which nothing in AT Protocol permits anyway.
- **F-REC-05** (M2.23/M2.25) — structural and schema record validation. `validate` is declared on `applyWrites` and is still not honoured.
