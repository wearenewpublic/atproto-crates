# fix(atproto-pds): index records and blob refs on import

Closes **F-MIG-01**. Milestone M2.17. Depends on M2.16, which landed in #31.

## What was wrong

`importRepo` persisted blocks (`import.rs:255-281`) and commit rows (`:290-333`) and stopped.

Every record read resolves through `repo_record` — `reader.rs:160` (`getRecord`), `:268` (`listRecords`), `:353` (`describeRepo`) — and nothing populated it. `grep -c repo_record import.rs` returned **1**: the module doc claiming the import would index records.

So the import reported success, the commit chain verified inductively — that part genuinely works — and the account then presented as **empty**. Not-found for every record, an empty page, no collections.

Silent data loss at the last step of a migration, with every step reporting success. The user has no signal that anything went wrong.

## What changed

The import walks the head commit's MST — `Mst::entries()` already enumerates `collection/rkey → CID` — and writes the record index. It then reads each record and records the blob references it carries, reusing `walk_blob_refs` from #31.

That second half matters as much as the first: `listMissingBlobs` is the question a migrating client asks *next*, and the answer was always "nothing owed" regardless of what the records referenced.

## Two limits, stated in the code

**Rev attribution.** Records are indexed at the head commit's rev, not the rev each was actually written at. Deriving true per-record revs means walking every historical commit's tree and diffing; the reference implementation does not do that on import either. The value is a lower bound on recency, and a comment says so — better than a number that looks precise and is not.

**Missing blocks.** A CAR may legitimately omit blocks its MST names — that is exactly what a diff slice is. When a record's block is absent, the row is still indexed and only its blob walk is skipped. The record genuinely exists in the tree, and refusing an entire import over one absent block would be a worse failure than the one being fixed.

## Tests

Three, **verified red** by neutralising the indexing call:

```
an_imported_repo_is_visible_to_the_record_apis ....... FAILED
an_imported_record_reports_the_blobs_it_still_needs .. FAILED
importing_twice_is_idempotent ....................... FAILED
```

They assert through the HTTP surface: `getRecord` returns the imported record with its value intact, `listRecords` pages it, `describeRepo` lists the collection, and `listMissingBlobs` names a blob the record references that the CAR did not carry.

**The fixture needed rebuilding.** The existing `minimal_car_for` produces an *empty* MST, which cannot show whether the import indexes anything — assertions against it would have been about the fixture. `car_with_record` builds a real tree: record block, MST nodes, commit, all written into the CAR.

Reads are done as the account owner, since a migrating account is deactivated and the public read gate from #28 applies.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2171 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **646 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

I am checking the exit code and the counts together now, after the fjall suite turned out to be reporting zero failures by not compiling.

## Blast radius

`import.rs` only, both storage paths. Import is now slower proportional to record count — it reads every record block to walk for blobs — and an imported repository stops presenting as empty, which the existing migration test now sees.

## Not fixed here

- **F-MIG-02** (M2.18) — `app.bsky.actor.getPreferences`/`putPreferences` are unimplemented and proxied to an AppView that has no such endpoint, so preferences are lost on migration.
- `verify_inductive` still accepts missing blocks on faith (`inductive.rs:114-135`). That is what makes the missing-block case above reachable at all, and it belongs with the covering-proof work (F-FIRE-06).
- Per-record rev attribution, per above.
