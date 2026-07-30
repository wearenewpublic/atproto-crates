# feat(atproto-pds): propagate the repo commit hash to the space host

Closes **F-SPACE-05**. Milestone M3.8. Depended on M3.7, merged in #46 — the hash now describes state a syncer can actually fetch.

## What was wrong

| Cite | Now |
|---|---|
| `NotifyWritePayload {space, repo, rev}` | `space/notify.rs:49-56`. The lexicon's `required` set is `["space","repo","rev","hash"]` |
| `RepoRef {did, rev}` | `space_handlers.rs:2592-2598`. `#repo` declares `did`, `rev`, `hash` |

The lexicon states the purpose outright: *"Lets the space host maintain each repo's hash for listRepos."* Without it a syncer cannot tell which repos have actually changed without fetching every one — the propagation loop from repo host to space host never closed.

## Everything needed already existed and was unused

The report describes two missing fields. What was actually there:

- **`space_received_op` has always had a `set_hash BLOB NOT NULL` column** (`20260506000001_space_received_op.sql`), and `receive_write` (`space/inbound.rs:37-46`) passed **`&[]`** for it.
- **The writer already built the commit**: `let _signed_commit = create_commit(...)` at `space/writer.rs:352`, bound to `_`. `Commit.hash` *is* "sha256 of the LtHash state" — precisely the value the lexicon asks for.
- `listRepos` selected `issuer_did, MAX(rev)` and never touched `set_hash`.

Fifth "built but not wired" variant in this series. The fix is mostly connecting three things.

## The one non-trivial part

`listRepos` reports the hash belonging to the **latest** rev, via a correlated subquery rather than a bare column beside `MAX(rev)`.

SQLite *does* define a bare column in a `MAX()` aggregate as coming from the winning row, so the shortcut would have worked here. But it is a SQLite-specific guarantee, and anywhere else it would silently pair a rev with some other row's hash. **A wrong hash is worse than a missing one**, because a syncer acts on it — it would skip a repo that had in fact changed.

## Sent always, optional on receipt

The lexicon marks `hash` required, and this server always emits it. Inbound, a payload **without** `hash` is accepted and logged rather than rejected.

`notifyWrite` is declared *"Best-effort"*, this is the only implementation that emits a hash at all — HappyView omits it, so **no worked reference exists** — and refusing would drop write notifications from every peer running older code, including this server's own previous releases. A repo whose host reported no hash is listed **without** one, never with an empty one, which would claim a hash that is not one.

## A type moved

`BytesValue` moves from the HTTP DTOs into `space/lex_bytes.rs` and gains a `Deserialize`. `notifyWrite` is *sent* by domain code and *received* by a handler, so both directions need it. Leaving it in the HTTP layer would have meant the writer reaching upwards, or a second copy — and two types doing the same encoding is exactly how encodings diverge. `SignedCommitDto` keeps working through a re-export.

## Tests

Six new — four acceptance, plus unit coverage of the `$bytes` codec. **Three verified red**, one per half, neutralised independently:

```
the_payload_a_writer_sends_carries_the_commit_hash ......... FAILED   (send)
an_inbound_hash_is_stored_on_the_receipt ................... FAILED   (receive)
list_repos_reports_the_hash_belonging_to_the_latest_rev .... FAILED   (report)
```

**The three halves are tested separately, and that is a real limitation worth naming.** My first attempt drove the whole loop through a space write and found zero receipts: `fire_notify_write` resolves the owner's `#atproto_pds` endpoint from their DID document, which the harness cannot provide, so the hop never fires. Rather than assert around that, I extracted `build_notify_payload` as a genuine seam — the send half is now testable without a network hop, and the receive half is driven by calling `receive_write` directly.

So **no test proves the writer's hash reaches `listRepos` end to end.** Each link is covered; the joins between them are covered by construction. Same shape as the PLC round-trip gap recorded in M2.20, and it has the same root cause: a hop that needs a resolvable DID document.

`list_repos_reports_the_hash_belonging_to_the_latest_rev` delivers two revs with different hashes and asserts the later one is reported — the aggregate-correctness case that a bare-column query would fail on a non-SQLite backend.

`a_notify_write_without_a_hash_is_accepted_and_reports_none` pins both halves of the tolerance decision: accepted, and reported as absent rather than empty.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2321 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **789 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

Two wire shapes gain a field, both additive and both optional on the way in. One query, one persist call, one send site, one type relocated. Peers running older code keep working in both directions.

## Not fixed here — one new finding

**`space_received_op`'s primary key is `(space, rev, nsid)` — no issuer.** Two members whose writes land at the same rev would collide under `INSERT OR IGNORE`, and the second receipt would be silently dropped, losing that repo from `listRepos` until its next write. TIDs are per-writer so a collision is unlikely rather than impossible.

Not part of F-SPACE-05 and not fixed. Recorded in `PROGRESS.md`.

Also unchanged: the end-to-end notify hop remains untestable in this harness, per above.
