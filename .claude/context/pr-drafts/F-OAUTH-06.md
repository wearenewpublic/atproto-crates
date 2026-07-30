# feat(atproto-pds): send CORS headers so browser clients can connect

Closes **F-OAUTH-06**. Milestone M2.10.

## What was wrong

`grep -rn "cors\|Access-Control\|CorsLayer"` over `crates/atproto-pds/src` returned nothing. The only layers on the router were the two metrics ones (`router.rs:480-481`, renumbered from the report's `:442-447`).

A browser OAuth client runs on some other origin. Without `Access-Control-Allow-Origin` the browser refuses to hand it the response body, so discovery failed before the authorization request was attempted — and had a client got past that, every XRPC call would have failed the same way.

## Wider than the finding, deliberately

The finding and the roadmap scope this to "the discovery documents and the OAuth routes". This covers **the whole surface**, including the 96 `/xrpc/*` routes.

A client that completes the token exchange and then cannot call a single method is still blocked, so fixing only the named routes would resolve the finding as written while leaving its stated consequence — "browser OAuth clients fail" — substantially in place. Same policy, same reasoning, applied where the consequence actually lands.

## The security decision, stated plainly

**`Allow-Origin: *` with no `Allow-Credentials`.** The second half is the load-bearing one.

AT Protocol authenticates with `Authorization` and `DPoP` request headers, never with cookies. A browser attaches neither to a cross-origin request unless the calling script sets them explicitly — and a script that can set them already holds the token. So the wildcard grants a hostile page nothing it could not get by calling this server from its own backend.

`Allow-Credentials: true` is the switch that would change that: it is what makes a browser send *ambient* credentials — cookies, cached Basic-auth — and hand the response to the page. Alongside a wildcard origin it is also forbidden outright by the Fetch standard. It is deliberately absent, and `preflight_is_answered_without_credentials` fails if it ever appears, so a later "improvement" breaks the build rather than the security model.

This covers the admin routes too. They are Basic-auth gated, and an operator's browser will not attach cached Basic credentials to a cross-origin request whose response it may not read.

## Headers

Allowed on request: `content-type`, `authorization`, `dpop`, `atproto-proxy`, `atproto-accept-labelers`.

Exposed on response: `dpop-nonce`, `WWW-Authenticate`, `atproto-repo-rev`. A client cannot read a response header it was not told about, and each of those exists to be acted on — `dpop-nonce` in particular is what F-OAUTH-08 will need once nonces are issued.

Preflights cache for 24 hours.

## Dependency

`tower-http` was **already in `Cargo.lock` at 0.6.11**, pulled in by `reqwest`. This adds the `cors` feature and a direct edge, not a new supply-chain root. It is gated behind the existing `http` feature, so a build without the HTTP layer does not pull it.

## Tests

Both **red before the change**:

```
preflight_is_answered_without_credentials ... FAILED
  /.well-known/oauth-authorization-server answered a preflight with no
  Access-Control-Allow-Origin; a browser client cannot call it
a_simple_request_carries_the_origin_header ... FAILED
  the protected-resource document is unreadable by a browser client
```

The preflight test walks eleven routes spanning all three groups — discovery, OAuth, XRPC — and asserts three things each: the origin header is present, `Allow-Credentials` is **absent**, and `authorization`/`dpop`/`content-type` are permitted.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2134 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

One layer in `router.rs` and one dependency feature. No handler changes.

Every response now carries CORS headers, including error responses and the admin surface. The documents this exposes cross-origin were already unauthenticated; the authenticated ones remain unreachable without a token the caller must already hold.

`/oauth/authorize` is included. It is a top-level navigation rather than a fetch, so CORS is inert for its actual use; being able to `fetch` the consent page cross-origin requires a valid, unguessable, single-use `request_uri`, and the page contains only what the holder of that URI already requested.

## Not fixed here

- **F-OAUTH-07** — metadata advertises `private_key_jwt` with no verification path.
- **F-OAUTH-08** — no server-issued DPoP nonces. The `dpop-nonce` header is now exposed, so the client half is ready.
- **F-OAUTH-10** — access-token revocation is a no-op.
- **F-OAUTH-11** — AS metadata omits nine fields clients read.
