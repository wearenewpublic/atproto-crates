# feat(atproto-pds): ship a real CARv1 in the firehose `blocks` field

Closes **F-FIRE-02** and **F-FIRE-03**. Milestone M1.14 — the last item in M1.

## What was wrong

`#commit.blocks` is a required `bytes` field that the lexicon describes as a CAR rooted at the commit block, carrying what the commit touched. It was **zero bytes**. No CAR was ever built for the firehose: `car_export` is reachable only from `getRepo` (`handlers.rs:264`) and `getBlocks` (`:323`), and the commit-write path never called it.

The stream therefore said *that* a record changed but never *what* it said. A consumer had to come back over XRPC for every event, which makes the firehose a notification feed rather than the thing federation runs on.

**F-FIRE-03 had drifted and is smaller than filed.** The report describes `#sync.blocks` as a block-count integer serialised straight to the wire. That stopped being true in `05cb63e` — the previous change made it a well-typed empty byte string. `SyncEvent.blocks: usize` survived as a vestigial field but no longer reached the frame. What remained was the same gap as F-FIRE-02: the byte string was empty.

## What changed

`RecordingBlockStorage` wraps the storage the MST writes through and keeps a copy of every block written during the commit. `Mst<S: BlockStorage>` is already generic, so both write paths wrap without touching backend dispatch.

That captures the diff **by construction** — the writer puts exactly the record blocks and MST nodes the commit creates — rather than re-deriving it afterwards by comparing two trees.

Recording alone over-collects. A multi-operation batch rewrites intermediate MST nodes the final root never references, and a re-put record whose bytes are unchanged is recorded again. So the recorded set is filtered to what the new commit can reach.

Blocks the commit did **not** write stay out even when reachable. They are by definition blocks the consumer already has from an earlier event, and leaving them out is what makes this a diff rather than a snapshot.

`#sync` carries the commit block alone — what a consumer that lost the `#commit` chain needs to re-anchor, with the tree available through `getRepo`.

## Scope boundary, stated plainly

**This is not the Sync 1.1 covering proof (F-FIRE-06).** A proof also carries the blocks needed to verify the *prior* state of every touched key, so a consumer can check the operation inductively without holding the repository. The vendored `firehose/commit-proof-fixtures.json` describes that larger set, and `interop_mst.rs:110-125` deliberately leaves `blocksInProof` unasserted pending that work.

Until F-FIRE-06 lands, consumers that verify inductively will still reject these frames. Consumers that trust the PDS can now read records off the stream. `blobs` also remains empty (F-BLOB-02).

## Tests

`crates/atproto-pds/tests/firehose_car.rs` — five tests, **all five red before the change** with `blocks carries no CAR at all — the event names records it does not ship`:

| Test | Asserts |
|---|---|
| `a_commit_ships_the_record_it_announces` | CAR root is the commit; the block the op's `cid` names is present and decodes to the record written |
| `a_commit_ships_the_tree_its_root_points_at` | the MST root is in the CAR, so the commit's `data` link does not dangle |
| `a_later_commit_ships_only_what_it_changed` | the second commit re-ships neither the first commit block nor its record |
| `a_delete_ships_a_tree_but_no_record` | post-delete MST root present, removed record absent, op `cid` null |
| `a_sync_event_ships_its_commit` | `#sync` is a CAR rooted at the head, carrying that block |

Five unit tests in `commit_car.rs` cover the wrapper not disturbing reads, only-written-blocks being recorded, CAR rooting, unreachable recorded blocks being dropped, and the `#sync` shape.

`blocks_is_present_but_empty_pending_car_slices` said in its own message that it should be replaced when this landed, and has been — by `the_encoder_passes_a_car_slice_through_unchanged`, which pins the encoder's half of the contract. **Worth noting it did not fail on its own**: it called `encode_event` with a hand-built body rather than going through the write path, so it would have kept passing indefinitely. Same pattern as the tests flagged in the previous three branches.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo clippy -p atproto-pds --all-targets --features fjall -- -D warnings` — clean
- `cargo check -p atproto-pds --all-targets --features postgres` — clean
- `cargo test --workspace` — **2115 passed, 0 failed, 63 ignored**
- `cargo test -p atproto-pds --features fjall` — 443 passed, **1 failed**, see below

## Pre-existing failure, not from this branch

`http_phase2_fjall_blob::fjall_blob_upload_get_list_round_trip` fails: `uploadBlob` returns a body with no `blob.$link`. I bisected it — it fails identically at `5c39cc2`, `05cb63e` and `636f455`, so it predates all of this milestone's work. It is a real bug on the fjall profile and is not in the gap-analysis report; it should be filed.

**Correction to the previous PR:** the F-FIRE-05 description reported `cargo test -p atproto-pds --features fjall` as "406 passed, 0 failed". That was wrong — the command was piped through `head -10`, which truncated the output before this failure. The fjall integration suite had this one failure then too.

## Blast radius

`atproto-pds`. Both write paths build a CAR per commit, so frames grow from ~200 bytes to record-sized — that is the point, but it changes the stream's bandwidth profile and makes F-FIRE-11 (no outbox retention) matter more, since the stream table now grows with record bytes rather than metadata.

`SyncEvent` drops `head` and `blocks: usize` — neither was a field of the event — and takes `commit_cid` + `commit_block`. Both call sites updated: `repo/import.rs` re-encodes the head commit it already holds, `admin/handlers.rs` reads the block from `repo_block`.

## Not fixed here

- **F-FIRE-06** — the covering proof. This is the remaining blocker for inductive consumers, and the one with an interop oracle already vendored.
- **F-BLOB-02** — `blobs` still empty.
- **F-FIRE-11** — retention, now more pressing.
- The fjall `uploadBlob` failure above.
