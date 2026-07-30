# fix(atproto-pds): walk records for blob refs on write

Closes **F-BLOB-02**. Milestone M2.16.

## What was wrong

Everything existed except the call.

| Piece | State |
|---|---|
| trait method | `traits.rs:251-259` — `add_ref`, `drop_refs_for_record`, `delete_blob` |
| backends | SQL, fjall and S3 all implement it |
| free functions | `blob.rs:133` `add_ref`, `:150` `drop_record_refs`, with unit tests |
| production callers | **`grep` returns nothing** outside the definitions and their own tests |
| the doc that lied | `blob.rs:130-132`: *"Called from the writer after a record write that contains a blob ref"* |

So `listMissingBlobs` answered `{"blobs": []}` forever and `checkAccountStatus.expectedBlobs` stayed `0`. A migrating client asked what still needed transferring, was told nothing, and activated an account with **none of its media** — while every step reported success.

That silence is what makes it a blocker rather than a gap. The client has no way to detect it.

## What changed

`blob::walk_blob_refs` recurses a record's value collecting the lexicon's typed envelope — `{"$type": "blob", "ref": {"$link": …}, "mimeType": …, "size": …}` — and the write path maintains the index from it.

**It recurses rather than checking known paths.** Blobs sit at arbitrary depth and inside arrays: `embed.images[0].image`, `embed.media.video`, inside a record union. A walker that had to be taught each lexicon would silently miss every lexicon it had not been taught, which is the same outcome as not walking at all.

**It validates the whole envelope.** A record may legitimately carry a map with `$type: "blob"` and nothing else, or a `ref` that is not a `$link`. Treating those as references would write rows with an empty CID that `listMissingBlobs` would then report as missing forever — swapping one wrong answer for another.

**Updates and deletes drop the record's existing refs first.** Adding without dropping would make the counts only ever grow, and blob GC reads those counts to decide what is orphaned.

Best-effort, like the firehose publish: the commit is already durable, so failing here would report a record that exists as not written. Failures log at ERROR, because the consequence — media silently absent after a migration — is invisible to the client.

## Tests

Four unit tests on the walker (top-level, nested-and-repeated across arrays, malformed lookalikes, no-blobs) and four end-to-end.

The three end-to-end ones that matter were **verified red** by neutralising the call:

```
a_referenced_but_absent_blob_is_reported_missing ... FAILED
dropping_a_blob_from_a_record_drops_the_reference ... FAILED
deleting_a_record_drops_its_references ........... FAILED
```

One detail worth recording: the tests use **real CIDs for bytes that were never uploaded** (`compute_raw_cid(b"never uploaded")`). A made-up CID string does not work — the record encoder reads `$link` into the data model, so an unparseable CID fails the write with a 500 before it ever reaches the ref index. My first attempt did exactly that.

## The fjall suite was not running

Worth its own heading, because it changes something I told you earlier.

The `fjall` test build **did not compile**, so `cargo test --features fjall` was reporting zero failures by never running. Once fixed, one test failed on a stale assertion: it read `blob.$link` from an `uploadBlob` response, a shape that stopped existing when blob refs became the lexicon's typed envelope (`blob.ref.$link`). A second assertion in the same file compared two of those absent values, so it asserted nothing at all.

**This corrects my diagnosis in PR #18.** I reported that failure as "a real bug on the fjall profile" and said it should be filed. It was a stale test, not a storage defect. The fjall profile is now green — 643 passing, which is the first time it has been in this series.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2168 passed, 0 failed, 63 ignored**
- `cargo test -p atproto-pds --features fjall` — **643 passed, 0 failed**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

`blob.rs` gains a walker; both write paths gain ref maintenance. Ref rows begin accumulating for the first time, so **`listMissingBlobs` now returns entries on repositories that previously reported none** — correct, but it will look like a regression to anything asserting the empty list.

## Not fixed here

- **F-MIG-01** (M2.17) depends on this: `importRepo` populates neither `repo_record` nor blob refs, so an imported repository still reports no missing blobs. `walk_blob_refs` is reusable there and that is the next item.
- **F-BLOB-03** — permissioned-space blobs are served with no authentication at all. Separate blocker on the same file, not in M2.16.
- Blob GC now has ref-counts to consult, but nothing consults them yet; orphaned bytes are dropped by `drop_record_refs` only when a record referencing them changes.
