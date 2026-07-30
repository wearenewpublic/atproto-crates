# fix(pds): forward the whole NSID and query, and resolve Atproto-Proxy DIDs

## What and why

Proxying did not work as routed. `/xrpc/app.bsky.{*nsid}` places the literal prefix in the parent
node, so the catch-all captures only the remainder. Reproduced against a minimal router before
changing anything:

```
GET /xrpc/app.bsky.feed.getTimeline?limit=5
  →  nsid=feed.getTimeline   query=Some("limit=5")
```

Two consequences:

1. `resolve_target`'s default pin tests `nsid.starts_with("app.bsky.")` (`proxy_handlers.rs:104`),
   which **can never match**, so every unheadered call fell through to 503.
2. A headered call forwarded to `{appview}/xrpc/feed.getTimeline` — wrong path — **with the query
   string discarded**, since the handler never asked for it. The query was right there on the `Uri`.

No Bluesky client works against that.

Separately, `Atproto-Proxy: <did>#<service-id>` was parsed and thrown away: the `service-id` half
was never read (`:77`), and any DID other than the operator-pinned AppView returned 502
(`:88-101`). A PDS that can only reach one operator-chosen service is not a network participant —
no labeler, no feed generator, no chat, no Ozone, no third-party AppView.

## How this survived

The unit tests at `proxy_handlers.rs:359-430` called `resolve_target` with a **hand-written full
NSID** instead of routing a request, so they passed against code that could not serve a single call.

Every test added here goes through the real router and asserts what a stand-in upstream actually
receives. Nothing hand-writes an NSID.

## What changed

- **NSID and query** now come from `OriginalUri` rather than the route capture, so the handler does
  not depend on the exact route literals it is mounted at.
- **`Atproto-Proxy` resolution**: the DID's document is fetched and the service carrying the named
  fragment is forwarded to. The pinned AppView remains a fast path, so the common case costs no
  network.
- **New routes**: `chat.bsky.*`, `tools.ozone.*`, `com.atproto.label.*`.

## Two consequences of the endpoint being attacker-supplied

**SSRF.** The endpoint comes from a DID a caller names, so it is read through
`Document::service_endpoint_validated` — the same URL policy the OAuth work wired for client
metadata. HTTPS only, no address literals in any resolver-accepted form, no embedded userinfo, no
non-443 ports, no reserved suffixes. Syntactic only: it does not resolve DNS, so it does not stop
rebinding. Five hostile endpoint forms are tested.

**Amplification.** Resolutions are cached with a five-minute TTL, **negative results included** —
otherwise an unresolvable DID in a header buys one outbound request per inbound one. Tested: five
proxied requests cost one resolution, and five failures also cost one.

The caching resolver follows the shape already used by `CachingSpaceDeclarationResolver` in this
codebase rather than introducing a different pattern.

## Why `com.atproto.label.` and not `com.atproto.`

Almost every other method in that namespace is served locally. A broader prefix would shadow them,
so the route is the narrow one — and there is a test asserting that `com.atproto.repo.describeRepo`
still answers locally and never reaches the upstream.

## Worked reference

Ten of eleven comparisons resolve the header properly: cirrus (`xrpc-proxy.ts:112-142`), alteran
(`src/lib/appview/did-resolver.ts:83-102`), dnproto (`AppBsky_Proxy.cs:60-118`, with an allow-list
*and* an SSRF filter).

## Testing

Five router-level tests, **three of which fail against the previous code**, all with the 503 the
finding describes:

| Test | Fails on `main`? |
| --- | --- |
| full NSID and query reach the upstream | yes — 503 |
| a call with no query sends a bare path | yes — 503 |
| all four proxied namespaces are routed | yes — 503 |
| locally-served `com.atproto.*` is not shadowed | no — guards the new routes |
| an unconfigured proxy is refused | no — guards the fallback |

Six unit tests on resolution: fragment lookup, missing fragment, five hostile endpoints refused,
positive caching, negative caching, and TTL expiry.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2088 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**The proxy goes from returning 503 to actually forwarding**, which is the point, but it means a
deployment with `PDS_BSKY_APP_VIEW_*` set starts making outbound requests it did not make before.

`Atproto-Proxy` with an arbitrary DID now performs DID resolution. That is a new outbound path from
an authenticated request, guarded and cached as described. An operator who wants only the pinned
AppView can leave the resolver unset — `HttpState::proxy_resolver` is `Option`, and the binary is
what wires it.

`resolve_target` became `async`. It is private; the four existing unit tests were updated to await.

## Deliberately out of scope

- **F-SVC-09** — DPoP-bound tokens still cannot use the proxy, because `build_parts_for_authn`
  constructs a synthetic `/` URI so `htu` never matches. Real, adjacent, and untouched here.
- **F-SVC-10** — only `Content-Type` is forwarded in each direction; `accept-encoding`,
  `accept-language`, `atproto-accept-labelers` and the response's `atproto-repo-rev` are still
  dropped.
- **F-SVC-11** — no never-proxy `PROTECTED_METHODS` guard on the proxy path. This change makes that
  more relevant, not less, since more namespaces are now proxyable.

All three are M4 in the roadmap.

## Resolves

`F-SVC-01`, `F-SVC-02` (roadmap M1.12).
