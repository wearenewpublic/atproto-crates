# feat(atproto-pds): `space.getRepo` CAR export and canonical `getLatestCommit`

Closes **F-SPACE-01**, **F-SPACE-02**, **F-SPACE-20**. Milestone M3.7. Depended on M3.1, merged in #40.

## What was wrong

`router.rs:332-401` listed eighteen `com.atproto.space.*` routes. **`getRepo` and `getLatestCommit` were not among them.** `getRepoState` was, under a name the draft does not define.

So there was **no conformant path to permissioned repo state at all**. `listRepoOps` replays *changes* and cannot rebuild a repo whose earliest ops have been pruned; `listRecords` — even after M3.6 made it inline values — carries no commit and no CID-addressed blocks. A syncer past its oplog retention had nowhere to go, and a client asking for the commit by its canonical name got a 404.

## The lexicon did most of the design

> *"The CAR declares two roots in order: the signed commit, then a DRISL (DAG-CBOR) index mapping `'{collection}/{rkey}'` to record CID. Record blocks follow in lexicographic order. Blobs are not included and are fetched separately via getBlob."*

So the builder is a transcription. HappyView's `serialize_repo` (`spaces/car.rs:60-151`) is the worked reference and does the same shape.

## The one thing I did not copy from the reference

HappyView re-encodes each record as JSON and takes a **RAW** CID (`make_cid(RAW, &serde_json::to_vec(...))`). That reflects how HappyView stores records, not anything the lexicon asks for.

Here records are already DAG-CBOR and `space_record.cid` *is* the CID `getRecord` returns, so **blocks are copied verbatim with their stored CIDs**. Re-encoding would produce blocks whose CIDs disagreed with the index, with `getRecord`, and with the commit. A CAR that cannot be verified is worse than no CAR.

## Three decisions worth stating

**The commit construction is shared.** `sign_current_commit` was extracted so the JSON path and the CAR produce the *same* commit. A first root that disagreed with `getLatestCommit` would send a syncer chasing a mismatch it cannot resolve.

**The export pages.** `list_records` clamps to the lexicon's 100, so `getRepo` drains each collection a page at a time rather than issuing one unbounded query — keeping the contract every other reader honours. It stops on a **short page**, not on a null cursor: a page entirely removed by takedowns would otherwise spin.

**`RepoNotFound` is used where it is declared.** It appears on `getRepo` and on no sibling method. A repo with no commits has no state to export, and that is a different answer from an empty CAR.

## F-SPACE-20 — alias, not replacement

`getLatestCommit` is the canonical name; `getRepoState` routes to the same handler. Removing the old name would break clients written against this server for no gain, and HappyView keeps both (`routes.rs:229,233`).

## Tests

Eleven new — five unit on the CAR builder, six acceptance. **Five verified red** by removing the two routes:

```
get_repo_exports_a_two_root_car_a_syncer_can_verify ........... FAILED
the_car_root_is_the_commit_get_latest_commit_reports .......... FAILED
get_latest_commit_and_get_repo_state_are_the_same_endpoint .... FAILED
get_repo_exports_every_record_across_the_page_boundary ........ FAILED
get_repo_reports_repo_not_found_for_an_empty_repo ............. FAILED
```

**Two verified separately, because route removal could not distinguish them:**

- **Paging** — breaking the loop truncated the 105-record export to one page. A truncated recovery CAR is worse than none, because it looks complete.
- **The non-member refusal** — my first version asserted `!= OK`, which an *unrouted* endpoint also satisfies, so it would have passed against a server that never served `getRepo`. It now asserts the specific 400 `SpaceNotFound` from the membership gate.

The CAR tests parse the response back with `CarReader` and assert the roots are in order, that every block hashes to the CID the CAR claims, that the index maps `{collection}/{rkey}` to CIDs *present in the CAR*, and that record blocks are lexicographically ordered when handed in unsorted.

One fixture bug worth recording: my first index test used `"bafyreiabc"` as a link, and the encoder correctly rejected it — the same "fake CIDs fail" lesson as the blob-ref work. It now computes a real CID.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2313 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **781 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## ⚠️ A pre-existing bug I hit while verifying — not from this branch

One workspace run failed in `atproto-dasl`'s `bytes_roundtrip` proptest, a crate this branch does not touch. I chased it rather than re-running:

```
left:  Bytes([0, 1, 0, 0, 0, ... ])   // 25 bytes
right: Link(Cid(baeaaaaa))
```

**It reproduces deterministically on `main`.** A byte string beginning `0x00 0x01` decodes as a `Link` instead of `Bytes`:

```rust
let mut data = vec![0u8, 1u8];
data.extend(std::iter::repeat_n(0u8, 23));
let encoded = to_vec(&Ipld::Bytes(data.clone())).unwrap();
assert_eq!(Ipld::Bytes(data), from_slice(&encoded).unwrap()); // fails on main
```

That is a **data-model corruption bug in the DRISL codec**: any record carrying a byte string with that prefix would round-trip as a link. It is latent rather than exploitable — `$bytes` values that short and that shaped are unusual — but it is exactly the class the M1 encoding work existed to close, and the proptest only samples it occasionally.

I removed the `proptest-regressions` file proptest wrote, so this branch does not turn an unrelated crate red in CI. **That file is worth recreating deliberately** once someone owns the fix — it is what makes the case reproducible for everyone. Recorded in `PROGRESS.md` with the repro above.

Two honest consequences: the workspace suite on `main` is **occasionally red** for this reason, and earlier green runs in this series passed partly because proptest did not sample the failing input.

## Blast radius

Three routes (two names plus one alias), one new module, one extracted helper, one new reader method. No existing shape changes; `getRepoState` keeps working byte-for-byte.

`getRepo` reads a whole repo into memory before writing the CAR. Acceptable at permissioned-space sizes and consistent with `com.atproto.sync.getRepo`, which the report notes is also non-streaming (F-REPO-09, M4.13).

## Not fixed here

- **M3.8** (F-SPACE-05) — `hash` on `notifyWrite` and `listRepos#repo`. It depends on this item for its value to mean anything and is next. The report notes **no worked reference exists**: HappyView omits it too.
- **Streaming export** — F-REPO-09 covers the public equivalent and is M4.13.
- Blobs are excluded from the CAR by the lexicon, so a syncer still fetches each through `space.getBlob`. That is the design, not a gap.
