# fix(atproto-pds): make a takedown take something down

Closes **F-MOD-01**, **F-MOD-02**, **F-ACCT-09**, **F-ACCT-04** and **F-BLOB-04**. Milestone M2.12 — the report's §7 group.

All five confirmed exactly as filed. They compose into one sentence: **a takedown did almost nothing.**

## What was wrong

| Area | State before |
|---|---|
| **Reads** | `getRepo`, `getBlocks`, `getBlob`, `listBlobs`, `getLatestCommit`, `describeRepo` had no state check. The sync and blob files contained **no `AccountState` reference of any kind**. |
| **Writes** | `AccountState::allows_writes` had **no caller anywhere**; the write guard never read state |
| **Refresh** | Neither `refreshSession` nor the OAuth refresh grant checked state |
| **Activation** | `activateAccount` called `set_state(Active)` unconditionally |
| **Storage** | Both blob handlers opened the per-actor store *before* any check |

`refreshSession` was the sharpest: it already loaded the account row and read only `.did` off it. The state was one field away.

So a takedown for illegal content did not remove the content — the CAR, the blocks and the blobs stayed anonymously downloadable — and the account kept writing and publishing firehose commits until its refresh token expired, up to 90 days later.

## What changed

**Reads.** All nine public read paths share one gate and answer with the errors their lexicons declare — `RepoTakendown`, `RepoSuspended`, `RepoDeactivated` — previously unreachable on the five endpoints that declare them.

`getRecord` and `listRecords` move from a generic `403 Forbidden` to those same names. The report is explicit that this half worked and must not be reported as absent; it did work, but it answered differently from every other path, so a caller branching on state needed one branch per endpoint.

**Writes, refresh, activation.** The dead predicate gets a caller; both refresh paths reject a non-writable account before rotating; `activateAccount` refuses `Takendown`/`Suspended`.

`valid_transition(Takendown, Active)` is deliberately untouched — an administrator lifting a takedown is legitimate. The defect was *who could ask*, not that the transition exists.

**Storage.** The gate runs before `SqlActorStore::open`, which closes F-BLOB-04's second half: that call runs `create_dir_all` plus migrations, so an unauthenticated caller could materialise a SQLite file for every DID it cared to invent.

## Two things the tests caught that the design did not

Both were real and both would have shipped as regressions.

**`listRepos` must list taken-down repositories, not refuse them.** It shares `get_latest_commit`, so gating that method broke `listRepos` outright the moment any account was taken down. The gate belongs on the *endpoint*, which answers about one repository and declares the takedown errors — not on the shared reader method.

**Inbound migration runs entirely while deactivated.** The prescribed flow is create → deactivate → `importRepo` → upload the blobs `listMissingBlobs` reports → `activateAccount`. A blanket write gate made that impossible. Those three endpoints take a gate that refuses moderated states but permits deactivation; a taken-down account still cannot import a repository.

## ⚠️ Behaviour changes

- **Deactivated accounts can no longer perform ordinary writes.** This matches `allows_writes` and the reference, but it is a real change for anyone using deactivation as a soft pause.
- **`getRecord`/`listRecords` return `400` with a named error** where they returned `403 Forbidden`.

## Tests

`tests/account_state_enforcement.rs`, seven tests. The main one walks **all nine** public read paths and asserts each **succeeds** before the takedown — with a real record rkey, a real uploaded blob CID and the real head commit CID — then asserts each refuses after. Without the success precondition a later refusal proves nothing; three iterations of this test were wrong for exactly that reason (unrouted path, absent blob, blob CID passed to `getBlocks`).

Plus: the refusal names the state; a taken-down account cannot write, cannot refresh, cannot self-activate; a deactivated one can still self-activate; and an invented DID creates nothing on disk — asserted by counting directory entries, since that is the actual claim.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2143 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

Six read handlers, one write guard split in two, two refresh paths, one lifecycle handler, one new error variant. No storage or wire-shape changes beyond the error names above.

Three pre-existing tests asserted the old behaviour and are updated: `get_record_takendown_account_denied` (error type), `admin_takedown_blocks_public_reads` (status), and the migration sequence needed no change once the gate split correctly — which is what told me the split was right.

## Not fixed here

- **F-MOD-07** — `deleteAccount` performs no data erasure. This change *hides* a taken-down account's data behind gates; it does not remove it. A "deleted" account's repository and blobs remain on disk.
- **F-MOD-03** (M2.21) — the subject union, so record- and blob-level takedown remain unaddressable. Only whole accounts can be taken down.
- **F-OAUTH-10** — access-token revocation is still a no-op, so a taken-down account's *existing* access token remains valid for its remaining TTL (15 minutes) even though it can no longer write. The write gate closes the damage; the token itself is not revoked.
