# fix(atproto-pds): make the firehose `seq` number the stream

Closes **F-FIRE-05**. Completes milestone M1.13 (B-2 of the two-branch split; B-1 was F-FIRE-01/04).

## What was wrong

`seq` in `com.atproto.sync.subscribeRepos` orders the *stream*: one number space for the server, strictly increasing in the order frames go out, never reissued. A subscriber hands it back as a resume cursor.

It was an `AUTOINCREMENT` column inside each **per-actor** database (`migrations/actor/…_init.sql:56-57`, `sequencer/outbox.rs:228-240`, `sql/public_realm.rs:326-340`, fjall `outbox_meta` at `fjall/public_realm.rs:390-410`). Consequences, in order of severity:

- **Two repositories were handed the same number.** Every account's first event was `seq = 1`. A resuming relay cannot tell those events apart.
- **A repository created mid-stream restarted at 1**, so a relay holding a cursor discarded its entire history as already-seen.
- **Frames left out of order.** Worse than the finding states: the subscriber loop (`subscribe_handlers.rs:116-140`) drained one account's outbox *fully* before touching the next, so ordering was broken even where the numbers happened to differ.

The client's cursor was also seeded into every repository's counter (`:102-103`) — one number compared against N unrelated sequences.

## What changed

One ordered event log for the whole server, in the accounts database. That database is opened under every storage profile, so a single schema serves both the SQLite and fjall deployments — no backend-specific work, no fjall keyspace changes.

`seq` is allocated by the `INSERT` into that log, and that is the load-bearing detail: **allocation order is commit order**. Handing out globally-unique numbers over per-actor storage would not have been enough — a subscriber merging those rows can still observe a later number before an earlier one commits:

```
poll A (empty) → B commits seq 11 → emit 11 → A's seq 10 commits → emit 10
```

New `sequencer/stream.rs` holds `Sequencer` (`append` / `read_after` / `latest_seq`) over the `AccountPool`, following the existing dual-dialect pattern so both SQLite and Postgres accounts backends work.

### The subscriber collapses to one cursor

`run_subscriber` now tails one log. Three limits disappear along with the per-account bookkeeping — not scope creep, but things the per-DID loop was the *cause* of:

| Was | Now |
|---|---|
| `list_accounts(None, 1000)` — a connection covered at most 1000 accounts | no ceiling |
| DID set fixed at connect; new accounts invisible until reconnect | appears on the next poll |
| `OutboxReader` reopened per DID per 5s tick | one handle |

That is **F-FIRE-10**, closed as a side effect.

`?did=` remains, now as a filter over the stream rather than a separate stream. It does not renumber, so a filtered subscriber's cursor stays valid against the unfiltered stream.

### The deliberate trade

A `#commit` is no longer written in the same transaction as the commit it describes — the repository lives in a per-actor store and the log is server-global, so `apply_atomic_commit` cannot reach it. `CommitBatch` loses its two outbox fields and returns `()` instead of a seq.

The event is published **only after the commit is durable**. A crash between the two therefore loses an event rather than announcing a commit that does not exist — the case `#sync` and `getRepo` re-anchoring exist to repair. The reference implementation splits its sequencer from its actor stores the same way.

### Migration

`stream_event` is added to both the SQLite and Postgres accounts schemas. The per-actor `outbox` table is left in place but is **no longer written or read**; dropping it is a separate change, so this one is not destructive. Existing outbox rows are not migrated — their `seq` values are meaningless by definition, and this is pre-release.

## Tests

`crates/atproto-pds/tests/firehose_sequence.rs` asserts the contract from the outside, over a real WebSocket, because the defect was invisible from inside a single actor's outbox. Three of the four were **red before the change**:

```
two_repositories_never_share_a_seq ................ FAILED
  both handed 1; a resuming subscriber cannot tell those events apart
seq_increases_strictly_in_wire_order .............. FAILED
  got 1 after 1 in [1, 1, 1, 2, 2, 2, 3, 3, 3]
a_new_repository_continues_the_stream ............. FAILED
resume_from_a_cursor_returns_the_exact_tail ....... ok
```

The `[1, 1, 1, 2, 2, 2, 3, 3, 3]` is three repositories each counting independently — the defect in one line.

**`resume_from_a_cursor_returns_the_exact_tail` passed before the change and I have not pretended otherwise.** With two accounts and per-DID cursors it happened to give the right answer. It is kept as a guard on the post-change behaviour, where resume is a real single-cursor operation rather than an accident.

Five unit tests in `stream.rs` cover the number space, paging, the `did` filter preserving stream numbering, the high-water mark, and payload round-tripping.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo clippy -p atproto-pds --all-targets --features fjall -- -D warnings` — clean
- `cargo check -p atproto-pds --all-targets --features postgres` — clean
- `cargo test --workspace` — **2105 passed, 0 failed, 63 ignored**
- `cargo test -p atproto-pds --features fjall` — **406 passed, 0 failed**

## Blast radius

`atproto-pds` only, but wider than B-1: one migration per accounts dialect, five emit sites converted (`repo/writer.rs` both paths, `sequencer/sync_event.rs`, `http/identity_handlers.rs`, `account/manager.rs`), `CommitBatch` loses two fields and its return type, `SubscribeEvent.seq` changes meaning, and `publish_sync` takes a `&Sequencer` instead of a data dir or backend. `RepoImporter` gains `.with_sequencer()`.

Four unit tests that asserted the per-actor outbox now assert the stream.

## Not fixed here

- **F-FIRE-09** — `FutureCursor` / `OutdatedCursor` are now *checkable* for the first time, since a global high-water mark exists (`Sequencer::latest_seq`). Emitting them is still not done.
- **F-FIRE-11** — outbox retention. Now tractable against one table rather than N.
- **F-FIRE-02/03** — `blocks` still carries an empty CARv1 (M1.14, next).
- **F-FIRE-06/07**, **F-BLOB-02** — unchanged.
- Dropping the now-unused per-actor `outbox` table and its `OutboxStorage` trait.
