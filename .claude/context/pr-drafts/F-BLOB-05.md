# fix(atproto-pds): stop `getBlob` serving blobs as renderable documents

Closes **F-BLOB-05**. Milestone M2.4.

## What was wrong

`com.atproto.sync.getBlob` set only `Content-Type` (`blob_handlers.rs:65-70`), echoing the MIME the uploader declared in its request header — a value that is neither validated nor sniffed (`write_handlers.rs:522-527`, F-BLOB-08).

Upload `text/html`, get someone to open the blob URL, and the script runs on the origin that also serves the OAuth consent screen and its session cookies. That is stored XSS against the authorization server, and it chains directly into account takeover.

`getBlob` is public per the lexicon, so no authentication stands between an attacker and the delivery of their own bytes.

## What changed

The three headers `space.getBlob` has sent since it shipped (`space_handlers.rs:2262-2274`):

| Header | Why |
|---|---|
| `x-content-type-options: nosniff` | a browser does not second-guess a benign declared type |
| `content-disposition: attachment; filename="<cid>"` | the response downloads rather than renders |
| `content-security-policy: default-src 'none'; sandbox` | anything rendered regardless can do nothing |

The finding describes this as "copying five lines across", and that is what it is.

On the filename: it is the CID, which reaches that line only by having matched a stored blob, so it is server-generated base32 rather than caller text — an unmatched CID 404s first. It is built through `HeaderValue::from_str` anyway, so a value that could not form a well-formed header degrades to a bare `attachment` rather than being interpolated. I did not want the safety of the header to rest on that lookup ordering staying true.

Both branches of the handler — backend dispatch and the legacy SQLite path — converge on the same response construction, so fjall deployments are covered by the same change.

## Tests

`get_blob_refuses_to_render_as_a_document` uploads `<script>alert(document.domain)</script>` declared as `text/html`, fetches it back through the router, and asserts all three headers. It goes through the real routes rather than calling the handler, so it covers the wiring and not just the function.

Red before the change:

```
assertion `left == right` failed: without nosniff a browser may execute a blob
whose declared type is benign
  left: None
 right: Some("nosniff")
```

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2118 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean (the CI step added in #19)

## Blast radius

One handler. Clients that previously rendered blobs inline from this endpoint will now download them — which is the intended behaviour and matches the reference, alteran, metalbear, zds, tranquil and rsky-pds.

## Not fixed here

- **F-BLOB-08** — the MIME is still whatever the client declared, never sniffed. These headers make it non-dangerous on this origin, but an AppView acting on the declared type is still acting on attacker-chosen data. That is the next blob item.
- `getRepo` and `getBlocks` (`handlers.rs:302`, `:365`) set only `Content-Type` too, but serve a fixed `application/vnd.ipld.car` that no browser renders, so there is no equivalent exposure. Adding `nosniff` there is hygiene rather than a fix, and I left it out of a security change.
