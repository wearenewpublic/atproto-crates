# fix(pds): return the typed blob envelope from uploadBlob

## What and why

`uploadBlob` emitted `{"$link", "mimeType", "size"}`. The AT Protocol data model accepts exactly two
blob-ref shapes, both declared strict:

```
typed   {"$type": "blob", "ref": {"$link": …}, "mimeType", "size"}
legacy  {"cid", "mimeType"}
```

`$link` is a key in neither. It belongs nested under `ref` as a cid-link, not spliced into the
envelope, and the typed form additionally carries `$type`. The legacy form is rejected at write time
upstream regardless, so the typed form is the only one worth emitting.

Because both schemas are **strict**, the extra key is not leniently ignored — this is why the defect
is a blocker rather than cosmetic. `@atproto/api` throws on the upload call itself, and a client that
embeds the returned object produces a record the reference validator rejects. Media was broken
against every real client.

## Evidence

### Before

| Site | |
| --- | --- |
| `crates/atproto-pds/src/blob.rs:39-49` | `struct BlobRef { #[serde(rename = "$link")] link, mime_type, size }` |
| `crates/atproto-pds/src/blob.rs:89` | constructed by `put_blob` |
| `crates/atproto-pds/src/http/write_handlers.rs:550-554` | constructed on the trait-dispatched path |
| `crates/atproto-pds/src/http/write_handlers.rs:507` | returned as `UploadBlobResponse.blob` |

### After

```
before  {"$link": "bafkrei…", "mimeType": "image/jpeg", "size": 10000}
after   {"$type": "blob", "ref": {"$link": "bafkrei…"}, "mimeType": "image/jpeg", "size": 10000}
```

`blob::BlobRef` is now an alias for `atproto_record::lexicon::TypedBlob`. **The workspace already had
this exact type** — `Blob { ref_: Link, mime_type, size }` with `$type` supplied by the
`TypedLexicon` wrapper (`atproto-record/src/lexicon/primatives.rs:38-67`), and `atproto-pds` already
depended on the crate. This removes a second, divergent local definition rather than adding a type.

## Worked reference

`packages/lexicon/src/blob-refs.ts:5-13,15-21,23` defines both schemas with `.strict()`;
`packages/pds/src/repo/prepare.ts:208-211` rejects the legacy form at write time. All ten comparison
implementations that serve `uploadBlob` emit the typed form — dnproto
`ComAtprotoRepo_UploadBlob.cs:85-99`, cocoon `handle_repo_upload_blob.go:143-146`, zds
`repo.zig:550-551`, tranquil `repo/blob.rs:207-212`.

The canonical shape is also already in this repository: `tests/interop/data-model/data-model-fixtures.json`
carries it verbatim as fixture #1's `c` value, vendored when the conformance vectors landed. The new
test asserts against that shape rather than an invented one.

## Testing

- `blob_ref_serializes_as_the_typed_lexicon_envelope` — byte-level known-answer on the serialized
  envelope: exactly four keys, `ref.$link` nested, and an explicit assertion that `$link` does **not**
  appear at the top level.
- `upload_blob_round_trip` — the existing integration test now asserts the shape of the live HTTP
  response body rather than reading `body["blob"]["$link"]`.

Both confirmed failing against the previous code (the integration test panics at the `$type`
assertion; the unit test could not even compile against the old struct).

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` are green — **2021 passed, 0 failed, 63 ignored.**

## Risk and blast radius

Small and one-directional. `UploadBlobResponse` is the only wire surface that changes. Blob storage,
the `repo_blob_ref` rows and the `listMissingBlobs` output are untouched.

There is no read path to migrate: nothing in the workspace parses this envelope back out of a record
value. The blob-ref walker exists, is tested, and has no production caller (F-BLOB-02), so the only
consumer of `BlobRef` besides the response is `add_ref`, which is reachable from tests only.

Records already written by clients that embedded the old shape keep whatever they stored — this
changes what the server returns, not stored record values. Those records were already invalid to the
reference validator, which is the defect being fixed.

## Deliberately out of scope

- **F-BLOB-02** (M2.16) — the record→blob ref walker is implemented across all three backends and
  never invoked. Fixing the envelope does not wire it up.
- `listMissingBlobs` and `sync.listBlobs` output shapes.
- F-BLOB-05 (`getBlob` response headers), F-BLOB-06/07 (body limits).

## Resolves

`F-BLOB-01` (roadmap M1.5).
