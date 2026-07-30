# fix(atproto-pds): stop serving permissioned blobs publicly, key them to the space

Closes **F-BLOB-03**, **F-SPACE-12**. Milestone M3.4. Depended on M2.12, which merged in #28.

## One fact, two defects

**There is no `com.atproto.space.uploadBlob`.** Permissioned blobs are uploaded through the ordinary `com.atproto.repo.uploadBlob` and land in the same `repo_blob` table as public ones — `space.getBlob`'s own doc said so (`space_handlers.rs:2275`, *"as originally uploaded from `repo`'s regular blobstore"*). Nothing recorded which space a blob belonged to. Everything else follows.

**F-BLOB-03.** `blob_handlers.rs:42-46` — `get_blob` takes `State` and `Query` only. Correct for public repos, and it served permissioned bytes by CID with **no credential at all**. `blob.rs:181-191` selected `repo_blob` by CID with no join; `listBlobs` enumerated every stored CID.

This reaches further than F-SPACE-07, which at least needs an account here. CIDs are high-entropy but not secret — they appear in space oplog entries, in `listRepoOps` output, in any AppView indexing the space, in logs, and to every member including one since removed. **A removed member retained permanent access to every blob whose CID they ever saw, and deleting the record did not revoke it.**

**F-SPACE-12.** `space_handlers.rs:2295` gated on `space` and then discarded it, fetching `crate::blob::get_blob(&store, &q.cid)`. So a member of one space could read a blob referenced only from another space in the same account's store.

## One fact the report does not state, and it made the fix cleaner

`grep -n "blob" space/writer.rs` returned **nothing** — the space writer maintained no blob refs at all. So `repo_blob_ref`, which M2.16 populates from `walk_blob_refs` on the public write path, already contained *only public-record references*. The discriminator existed; nothing consulted it.

## What changed

**Public paths** serve only blobs a **public** record references — `repo_blob_ref` joined to `repo_record`. That is zds's `getPublicBlob` construction (`store.zig:2538-2563`) in this schema; zds is the only other 0016 implementation and the one that got this right. It joins the same way in its public `listBlobs` (`:2566-2592`).

**Space path** gets a `space_blob_ref` table keyed `(space, record_uri, blob_cid)`, maintained on the space write path with the same blob-envelope walker the public path uses, and `space.getBlob` requires a reference in the space it was asked about. contrail keys `spaces_blobs` on the space URI the same way (`contrail-record-host/src/routes.ts:224-239`).

Every op **drops its existing references before re-adding, including deletes**. Adding without dropping would leave a blob readable in a space after the last record naming it stopped naming it, and nothing would visibly break — the revocation half is the easy half to omit.

## Two implementation decisions

**Predicates, not joined fetches.** On the fjall profile the bytes come from a fjall keyspace through `PublicRealmBackend`, so a joined `SELECT … data` would only cover SQLite. Asking the per-actor SQLite the *question* works on both profiles; asking it for the *bytes* would not. Same reasoning as the M2.21 takedown gate.

**`listBlobs`' cursor now advances over CIDs scanned, not CIDs kept.** A page where every blob turned out to be permissioned would otherwise come back empty with no cursor, which a client reads as end-of-list while there is more behind it — or, if it restarts, as a loop. The SQLite path joins in SQL and keeps full pages; the fjall path filters after the fact and may return a short page, which is documented at the call site.

## Tests

Six new acceptance tests plus four unit tests. **Four verified red** by neutralising each gate:

```
a_permissioned_blob_is_not_served_by_the_public_endpoint ... FAILED
an_unreferenced_blob_is_not_publicly_fetchable ............ FAILED
the_space_parameter_reaches_the_blob_lookup ............... FAILED
deleting_the_last_referencing_record_revokes_the_blob ..... FAILED
```

Two controls stay green by design, and both matter — a gate that refused everything would pass all four above:

- `the_same_blob_is_served_to_a_member_through_the_space_endpoint`
- `a_public_blob_is_still_served_publicly`

`the_space_parameter_reaches_the_blob_lookup` is the F-SPACE-12 assertion stated directly: one account owns two spaces, a blob is referenced only from the first, and it is 200 through that space and 404 through the other.

`an_unreferenced_blob_is_not_publicly_fetchable` asserts the behaviour change explicitly rather than leaving it implied.

## Four existing fixtures were wrong, and one of them proved the fjall coverage

`a_takedown_closes_every_public_read_path`, `a_blob_can_be_taken_down_without_touching_the_account`, `get_blob_refuses_to_render_as_a_document` and `fjall_blob_upload_get_list_round_trip` all uploaded a blob and fetched it publicly **without any record referencing it**. Each now writes the reference, which is also what a real deployment looks like.

The fjall one is worth calling out: the reference lives in per-actor SQLite while the bytes live in a fjall keyspace, so **its failure was the gate working on the fjall profile**, and its passing is the evidence these gates hold on both. That is the cross-profile coverage M2.21 explicitly lacked.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2295 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **763 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

**An uploaded-but-unreferenced blob is no longer publicly fetchable.** Anything that uploads and then fetches back before writing the record will get a 404. `importRepo` is unaffected — M2.17 indexes records and refs together.

**Blobs referenced only from permissioned records stop being publicly fetchable.** That is the fix.

Refusals are `BlobNotFound`, matching the takedown gate: a caller with no business knowing whether these bytes exist should not learn it from the error.

One migration, one predicate on two public paths, ref maintenance on the space write path, one gated lookup.

## Not fixed here

- **F-BLOB-12** is listed as cosmetic in isolation and is described in the report as *"the mechanism behind F-BLOB-03"*. The `listBlobs` join closes it incidentally. I am noting that rather than claiming it, since the finding's own framing is about `repo_blob` versus `record_blob` selection generally.
- **Blob GC still does not consult ref counts.** `space_blob_ref` gives it a second thing to consult and nothing does.
- **F-SPACE-06** (M3.9) — no credential revocation, so a removed member's existing SpaceCredential still works for up to two hours, including for blobs.
- Space blob refs are maintained best-effort, like `notifyWrite` and the public blob refs: the commit is already durable, so failing there would report a written record as unwritten. Failures log at ERROR because the consequence is invisible to the caller.
