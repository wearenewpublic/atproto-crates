# fix(atproto-pds): make the blob and import ceilings real and tunable

Closes **F-BLOB-06** and **F-BLOB-07** (partly), plus the M2.6 slice of **F-OPS-11**. Milestone M2.6.

## What was wrong

`MAX_BLOB_BYTES` said 16 MiB (`blob.rs:20`) and `uploadBlob` checked it. But the handler extracted `axum::body::Bytes`, which applies axum's `DEFAULT_LIMIT` of 2 MiB unless a body-limit layer overrides it — and the router applied no such layer.

So the documented ceiling described nothing the server did. **The real limit was eight times smaller.** A typical phone photo failed to upload, and the same cap bit `importRepo`, so inbound migration failed for any repository worth migrating. `README.md` meanwhile told operators to size their reverse proxy for bodies over 1 GiB.

The refusal was wrong too:

```
Failed to buffer the request body: length limit exceeded
```

`text/plain`, not the XRPC error shape every other failure on this surface uses — so a client's error handling never saw it.

Confirmed by reproduction before touching anything: a 3 MiB upload returned `413` with exactly that body.

## What changed

Both handlers take `axum::body::Body` rather than `Bytes` and buffer it under a ceiling of their own. That makes the configured limit the operative one, and lets the refusal be XRPC-shaped: `BlobTooLarge` or `RepoTooLarge` with a JSON body.

Buffering ourselves rather than adding a `DefaultBodyLimit` layer is deliberate. The layer bounds memory but its rejection is still axum's plain-text 413 — the limit would have been right and the error still unusable.

Two knobs, **neither feature-gated**, so both work in the shipped image (the F-OPS-11 concern):

| Variable | Default | Bounds |
| --- | --- | --- |
| `PDS_BLOB_UPLOAD_LIMIT` | 16 MiB | one blob through `uploadBlob` |
| `PDS_IMPORT_LIMIT` | 1 GiB | one repository CAR through `importRepo` |

Separate because they bound different things — one media file against a whole repository. A single number would force an operator to accept 1 GiB blobs to allow a 1 GiB migration.

`MAX_BLOB_BYTES` becomes `DEFAULT_BLOB_UPLOAD_LIMIT_BYTES` — a default rather than a constant — and `put_blob` takes the limit as an argument instead of reading a global, so there is one source of truth and it is the configured one.

The README's proxy note is corrected, and the two variables are documented with a warning that the proxy's own limit needs sizing to match or it rejects first.

## Tests

Two tests, both **red before the change**:

```
a_blob_under_the_ceiling_uploads ................. FAILED
  a 3 MiB upload is well under the 16 MiB ceiling this server advertises;
  body: Failed to buffer the request body: length limit exceeded
  left: 413   right: 200

a_blob_over_the_ceiling_is_refused_as_xrpc ....... FAILED
  the refusal should be an XRPC error body, got
  "Failed to buffer the request body: length limit exceeded"
```

The first pins the ceiling being real; the second pins the refusal being usable. They go through the router, so they cover the wiring rather than the handler in isolation.

`oversize_blob_rejected` in `blob.rs` previously allocated a 16 MiB `Vec` to test the limit; it now passes a 64-byte limit and a 65-byte body, which tests the same branch without the allocation.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo clippy -p atproto-pds --all-targets --features clap -- -D warnings` — clean
- `cargo test --workspace` — **2121 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

`put_blob` gains a parameter — a public function, so this is a breaking change for anything calling it outside this workspace. `HttpState` gains two fields with defaults, so existing constructions are unaffected.

Raising the effective blob limit from 2 MiB to 16 MiB means the server now buffers up to 16 MiB per concurrent upload, and up to 1 GiB per concurrent import. That is the intended behaviour and matches the reference, but it is a real change in memory profile — an operator who wants the old bound can set `PDS_BLOB_UPLOAD_LIMIT=2097152`.

## Not fixed here

- **F-BLOB-07's second half — per-account quotas.** The finding asks for a limit *and* a per-DID quota; this delivers the limit. A quota needs storage accounting per account and an eviction or refusal policy, which is a feature rather than a knob. Operators can now bound a single upload but still cannot bound an account's total.
- **F-OPS-11 proper** — the shipped image still omits `valkey`, `metrics`, `s3`, `postgres` and `otel`, so those env knobs remain inert. That is M4.2; only the blob-limit slice belonged here.
- **F-BLOB-08** — MIME still trusted from the client header, never sniffed.
