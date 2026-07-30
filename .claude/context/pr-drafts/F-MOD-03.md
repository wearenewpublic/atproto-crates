# feat(atproto-pds): canonical admin subject union, record and blob takedown

Closes **F-MOD-03**, **F-BLOB-15**. Milestone M2.21.

## What was wrong

`updateSubjectStatus` and `getSubjectStatus` spoke a shape that appears **nowhere in any lexicon**.

| | This PDS | The lexicon |
|---|---|---|
| input | `{did, state}` (`admin/handlers.rs:206-211`) | `{subject: union, takedown?: statusAttr, deactivated?: statusAttr}` |
| output | `{did, state}` (`:215-220`) | `{subject, takedown}` |
| `getSubjectStatus` | params `{did}`, required (`:255-258`) | `{did?, uri?, blob?}` |

Not one field name overlaps. This is a **total deserialization failure**, not a partial one: every call from Ozone or `pdsadmin` failed before reaching a handler. This PDS could not be moderated by any tool that speaks the protocol.

(Report line numbers had drifted — `:156-162,212-218` is now `:204-220`.)

**F-BLOB-15 is confirmed by absence.** `migrations/actor/20260504000001_blobs.sql:12-20` — `repo_blob` is `(cid, mime_type, size, data, created_at)`. `repo_record` likewise. `grep -rn "takedown_ref" crates/atproto-pds/src/` returned **nothing**. The two non-account subject kinds had no storage behind them, which is why they read as "ignored" rather than "unimplemented". An operator asked to remove one illegal post or one illegal image had no option short of taking down the whole account.

## What changed

Both endpoints speak the union, and the two subject kinds it makes addressable now work.

**Account takedown** maps onto the existing `takendown` state, which the read and write gates from #28 already enforce everywhere. **`deactivated`** maps onto `deactivated`, and is **refused** on a record or blob rather than silently ignored — a moderator who believes they deactivated something otherwise has no way to discover they didn't.

**Record takedown** hides the record from `getRecord` and `listRecords`. **Blob takedown** withholds the bytes from `com.atproto.sync.getBlob`. Both report **not-found rather than forbidden**: a probe should not confirm the content is still stored here. Both lift cleanly, and applying or lifting twice is a no-op — moderation actions arrive from queues that retry.

The reference's guard against `takedown.applied` with `deactivated.applied == false` comes along. Whichever half ran last would win silently, so neither runs.

## Two decisions worth stating

**Separate tables, not columns.** Records and blobs dispatch through `PublicRealmBackend`, so on the fjall profile their bytes are not in the per-actor SQLite at all. A `takedown_ref` column on `repo_record` would have covered the SQLite profile and silently missed fjall — the worst kind of half-fix for a moderation control. The per-actor SQLite is always present, which is the same reasoning behind `space_record_takedown` (`20260506000002`) and the `preference` table from #33.

**`getSubjectStatus` checks blob → record → account.** A blob query carries a `did` too, so reading them in the other order would answer about the account every time. The echoed `strongRef` carries the record's *current* CID rather than one the caller supplied.

## A 422 that should have been a 400

`subject` is an **open union**, and axum's `Json` rejects an unrecognized `$type` with a plain-text HTTP 422 — which is not part of XRPC. A moderation service naming a subject kind this build has not been taught got a status code it could not interpret, which is a smaller version of the same failure being fixed.

New `XrpcJson<T>` extractor, used on this handler only: 400 `InvalidRequest` with serde's reason. The rest of the surface still returns axum's default; converting it is a mechanical change worth doing on its own rather than inside a behavioural fix.

## An unrelated cost this nearly introduced

`SqlActorStore::open` builds a fresh 8-connection pool **and runs migrations** on every call (`actor_store/sql/store.rs:56-95`). `get_record` already called it in its legacy branch, so adding the takedown lookup naively doubled that on every public record read. It now opens once and reuses.

Filed as a new finding candidate: there is no actor-store pool cache, so this cost is paid per request across the whole read surface.

## Tests

21 new (7 union, 5 storage, 9 acceptance). **Verified red** in two passes.

Neutralising the enforcement gates:

```
a_record_can_be_taken_down_without_touching_the_account ... FAILED
a_blob_can_be_taken_down_without_touching_the_account ..... FAILED
```

Breaking one `$type` string (`com.atproto.admin.defs#repoRef` → `repoRef`):

```
update_subject_status_speaks_the_canonical_union .................... FAILED
deactivated_round_trips_on_an_account_and_is_refused_elsewhere ...... FAILED
admin_takedown_then_lift ........................................... FAILED
a_repo_ref_uses_the_lexicon_type_string (unit) ..................... FAILED
```

The union tests are **known-answer against the lexicon's own spellings**, not round-trips — a round-trip passes just as happily against a `$type` this server invented, which is precisely the bug. `com.atproto.repo.strongRef` gets its own test because it is the one union member whose namespace is not `com.atproto.admin.defs`.

`a_record_can_be_taken_down_without_touching_the_account` is the finding stated as a test: two records, one taken down, and it asserts the other still reads, `listRecords` returns only the survivor, and the account itself is untouched — then that lifting restores both.

**Three existing tests were updated, not deleted.** `admin_takedown_then_lift`, `admin_takedown_blocks_public_reads` and `admin_delete_account_terminal` asserted the `{did, state}` shape. Unlike the identity-branch case, the behaviour they pin is still real — only the spelling was wrong — so they were rewritten rather than dropped.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2230 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **705 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

**Breaking, no alias:** the `{did, state}` shape is gone. There is no `state` field in the lexicon, so it was not an alternative spelling of anything — nothing that speaks the protocol was relying on it. Same call as the M2.8 admin wire changes in #24.

One migration, two rewritten handlers, three read gates, one new extractor. `listRecords` pagination is unchanged: the cursor still advances over the underlying rows, so a page containing a taken-down record returns fewer items rather than stalling.

## Not fixed here

- **The fjall profile is covered by construction, not by test.** Every gate runs before backend dispatch and reads a table that exists on both profiles, but the acceptance tests build a router without a `PublicRealmBackend`, so the fjall path is not exercised for takedown specifically.
- **`listBlobs` still lists a taken-down blob's CID.** A syncing peer will then 404 on the fetch, which is the correct outcome — the bytes are withheld — but the listing is not filtered. The reference does not filter it either.
- **F-MOD-07** — `admin.deleteAccount` still sets state and erases nothing.
- **F-MOD-09** — the denylist is consulted only at signup. Now more visible than the report describes: M2.20 built the handle-validation path where that check belongs and deliberately left it out of scope, so a banned handle can still be adopted through `updateHandle`.
- Spaces oplog takedown is **F-SPACE-14** (M3.14).
