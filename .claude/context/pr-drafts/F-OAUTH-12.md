# fix(atproto-oauth): enforce granular scopes on writes, blobs and rpc

Closes **F-OAUTH-12**. Milestone M2.14.

## What was wrong

The authorization server parsed and stored exactly what the user granted. The resource server never looked at it.

| Claim | Verified |
|---|---|
| no `scope` reference in `write_handlers.rs` | `grep -c scope` returns **0** |
| the model is complete | `Scope::{Repo,Blob,Rpc,Identity}`, `RepoCollection::{All,Nsid}`, `RepoAction::{Create,Update,Delete}`, `MimePattern`, `RpcLexicon`/`RpcAudience` |
| the assertions are missing | the only `allows_*`/`assert_*` pairs were `allows_space`, `allows_space_with`, `allows_space_manage` |

So `scope=atproto` alone could write every collection, upload any MIME type, rotate the handle and proxy arbitrary calls on the holder's behalf. **The authorization server's decisions were not enforced by the resource server** — a consent screen that asked for one collection granted all of them.

## What changed

`atproto-oauth::scopes` gains the missing `allows_*`/`assert_*` pairs for repo, blob, rpc and identity, mirroring the `space:` ones. A refusal carries the minimal scope that would have satisfied the request, so a client sees `InsufficientScope: this token does not grant repo:app.bsky.feed.post?action=create` rather than a bare 403 it can only guess at.

Enforced on `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `uploadBlob`, the `rpc:` proxy path, and `updateHandle`.

**`applyWrites` is checked per operation, not once for the batch.** One call can touch several collections with different verbs; a token scoped to create in one collection must not delete in another by riding along in the same request.

## Two decisions worth stating

**`transition:generic` satisfies all four axes.** It is the legacy full-access migration scope, and it is what most AT Protocol OAuth clients request today. Enforcing the granular axes without honouring it would refuse every one of them — enforcement that nothing can connect to isn't enforcement, it's an outage.

It is deliberately **not** a wildcard for `space:`. Spaces post-date it, so nothing was granted it expecting space access, and widening it there would be inventing authority nobody consented to.

**App-password sessions are not scope-checked.** They carry no scopes by construction (`auth.rs:98` returns an empty set), so checking them would refuse everything. This is the same `is_oauth()` gate `assert_space_scope` already applies (`space_handlers.rs:1866-1868`) — inventing a second rule for the same question is the thing that eventually diverges.

## Scope: `updateHandle` is included

M2.14's remediation names writes, blobs and `rpc:`. Handle rotation is the fourth of the four consequences the finding itself lists, and it is the same shape — `Scope::Identity` already existed. Leaving it out would make "scopes are enforced" untrue for one of the four things the finding says is broken.

## Tests

Nine unit tests in `atproto-oauth` and five end-to-end through the router. All red before the change — nothing was checked, so every one of them passed a write it should have refused.

The end-to-end ones run the real PAR → authorize → token exchange with a chosen scope string, then attempt a DPoP-bound write:

- `atproto` alone cannot write a record
- a `repo:app.bsky.feed.post?action=create` grant writes that collection and is **refused** for `app.bsky.graph.follow`
- `transition:generic` still writes
- the refusal names the scope that would have worked
- an app-password session is unaffected

Plus, in the unit tests: a create grant does not confer delete, an `image/*` grant does not confer `text/html`, an `rpc:` grant for one audience does not confer another, and `transition:generic` does **not** confer space access.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2160 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## ⚠️ Blast radius

`atproto-oauth::scopes` gains eight methods and `RepoAction::as_str`. Seven handlers gain an assertion.

**A token granted narrow scopes is now refused where it previously succeeded.** That is the fix, but it will surface as breakage in any client that requested less than it actually used — which, given nothing was enforced, is a class of bug no client has had reason to notice. Clients on `transition:generic` are unaffected.

## Not fixed here

- **F-OAUTH-13** — `include:<nsid>` is still unresolved and `dereferenceScope` unrouted, so a client asking for a named permission set gets nothing. `Scope::Include` parses; nothing expands it.
- **F-OAUTH-11** — AS metadata still omits nine fields, so clients cannot discover which scopes this server understands.
- `getServiceAuth` mints tokens without consulting `rpc:` scopes; the proxy path is gated but the mint path is a separate surface.
