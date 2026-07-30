# H. Service auth & proxying

*Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), the [coverage matrix](../20-coverage-matrix.md),
the [synthesis and roadmap](../50-synthesis-and-roadmap.md), and the
[permissioned-data overview](../permissioned/40-permissioned-overview.md).*

## Assessment

Service auth is the AT Protocol's inter-service bearer: a short-lived compact JWS signed by an
*account's own* `#atproto` signing key, carrying `iss` (the account), `aud` (the receiving service),
an optional `lxm` (the single XRPC method the token may be spent on), `iat`, `exp`, and `jti`. It is
minted through `com.atproto.server.getServiceAuth`, whose canonical lexicon requires only `aud` and
documents `exp` as "The time in Unix Epoch seconds that the JWT expires"
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/getServiceAuth.json:12-25`). The companion
capability is proxying: a client sets `Atproto-Proxy: <did>#<service-id>` on any XRPC call, the PDS
resolves that DID document, finds the named service entry, mints a fresh service-auth token addressed
to it, and forwards. Together these two are how a PDS participates in the network at all — how a
user's timeline comes back from an AppView, how a report reaches a labeler, how chat works, and how
one PDS hands an account to another.

atproto-crates mints service-auth tokens for real. `getServiceAuth` is routed
(`crates/atproto-pds/src/http/router.rs:152-155`), authenticated
(`crates/atproto-pds/src/http/service_auth_handlers.rs:102`), and signs with the calling account's
own key fetched from the keystore (`:129` → `crates/atproto-pds/src/http/space_auth.rs:74`). That is
the hard part and it is done. Everything layered on top of it is thinner than the field. The `exp`
parameter is read as a *time-to-live in seconds* rather than an absolute epoch and clamped to
`[1, 600]` (`service_auth_handlers.rs:131-136`), so a spec-conforming client asking for
"expires 30 seconds from now" receives a ten-minute token and `BadExpiration` is never returned.
`lxm` is optional at mint (`:45`, omitted from the payload when absent at `:68-69`) *and* only
enforced when present on the verifying side
(`crates/atproto-pds/src/space/service_auth.rs:151-157`), so a wildcard token that satisfies every
method is one query string away. There is no `PROTECTED_METHODS` refusal, no `PRIVILEGED_METHODS`
gate — `AuthSubject::privileged()` has exactly one call site in the whole HTTP layer and it is
`importRepo` (`crates/atproto-pds/src/http/write_handlers.rs:601`) — no takendown-account carve-out,
and no `rpc:` scope assertion, because `atproto_oauth::scopes::ScopesSet` parses `Scope::Rpc`
(`crates/atproto-oauth/src/scopes.rs:578`) but exposes no `assert_rpc` at all; the only assertions
it ships are the three `assert_space*` helpers (`:1116-1141`). And the JWS header carries
`typ: "at+jwt"` (`service_auth_handlers.rs:35`), which the reference's service-token verifier
rejects outright as `BadJwtType`
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:88-104`).

That last point sets the tone for how atproto-crates compares. This is not an area where only the
reference does the work. On `exp` semantics alone — absolute epoch, past rejected, hour cap,
one-minute cap for method-less tokens — the reference
(`.../pds/src/api/com/atproto/server/getServiceAuth.ts:68-86`), zds
(`/tmp/gap-scratch/zds/src/atproto/server.zig:1109-1131`), tranquil-pds
(`.../crates/tranquil-api/src/server/service_auth.rs:149-169`), rsky-pds
(`.../src/apis/com/atproto/server/get_service_auth.rs:21-33`), metalbear
(`/tmp/gap-scratch/metalbear/src/server.c:1970-1992`), cocoon
(`/tmp/gap-scratch/cocoon/server/handle_server_get_service_auth.go:40-58`), dnproto
(`.../ComAtprotoServer_GetServiceAuth.cs:44-68`) and even alteran, the hobby-experiment
(`.../src/pages/xrpc/com.atproto.server.getServiceAuth.ts:64-80`) all agree with each other and
disagree with atproto-crates; only cirrus and pegasus deviate, and they deviate by *ignoring* `exp`
rather than by reinterpreting its units. Every one of the eight implementations whose service-JWT
header I read emits `typ: "JWT"`; atproto-crates is alone on `at+jwt`. Protected-method refusal at
mint is present in the reference, zds, tranquil, rsky and alteran; a privileged-scope gate in the
reference, metalbear and alteran (rsky has one at `get_service_auth.rs:38-40` with inverted polarity
— it blocks privileged callers rather than non-privileged ones).

Proxying is worse, and it is worse in a way that does not survive first contact with a client. The
`Atproto-Proxy` header is parsed (`crates/atproto-pds/src/http/proxy_handlers.rs:68-85`) but any DID
other than the single operator-pinned `PDS_BSKY_APP_VIEW_DID` is refused with `502 ProxyDidUnknown`
(`:97-101`); there is no DID-document resolution anywhere on the proxy path. Ten of the eleven
comparisons resolve arbitrary proxy DIDs against the DID document — including cirrus
(`/tmp/gap-scratch/cirrus/packages/pds/src/xrpc-proxy.ts:112-142`), a single-user PDS, and alteran
(`/tmp/gap-scratch/alteran/src/lib/appview/did-resolver.ts:83-102`), a hobby experiment; the
exception is arroba, which has no proxy at all because it is a library rather than a server. dnproto,
a single-account C# PDS, resolves the DID document *and* runs the resolved endpoint through an SSRF
filter (`/tmp/gap-scratch/dnproto/src/pds/xrpc/AppBsky_Proxy.cs:70-118`). Worse, the atproto-crates
proxy as routed does not work at all: the route is `/xrpc/app.bsky.{*nsid}`
(`crates/atproto-pds/src/http/router.rs:109`), whose catch-all captures only the text *after* the
literal `app.bsky.` prefix, so the handler's `nsid` is `feed.getTimeline` rather than
`app.bsky.feed.getTimeline`. `resolve_target`'s default-pin branch tests
`nsid.starts_with("app.bsky.")` (`proxy_handlers.rs:104`) and therefore never fires, and when the
explicit header path does fire the forwarded URL is `{appview}/xrpc/feed.getTimeline` with
`lxm=feed.getTimeline`. Separately, the handler never extracts the request URI, so every query
parameter is dropped on the floor. This is the single most consequential finding in this chapter and
it is verified empirically, not inferred — see Finding 1.

Where atproto-crates is genuinely ahead of part of the field: it *verifies* inbound service auth,
resolving the issuer's DID document for both `did:plc:` and `did:web:` and checking the signature
against the `#atproto` Multikey (`crates/atproto-pds/src/space/service_auth.rs:162-213`). metalbear
and arroba never verify an inbound service-auth token at all
([metalbear.md](../impl-notes/metalbear.md) §5; [arroba.md](../impl-notes/arroba.md) §"Service auth"),
and cirrus verifies only tokens it issued itself, hardcoding `expectedIssuer` to its own DID
([cirrus.md](../impl-notes/cirrus.md)). And the use it puts that verifier to — inter-PDS
`com.atproto.space.notifyWrite` / `notifySpaceDeleted` for permissioned data — has no analogue
anywhere in the comparison set. The problem is not that the verifier is absent; it is that the
verifier is lax in exactly the places that matter (see Findings 4 and 5) and is reachable only from
the two Spaces handlers.

---

## Capability analysis

### Minting: `com.atproto.server.getServiceAuth`

The route is registered as a `GET` at `crates/atproto-pds/src/http/router.rs:152-155` and handled at
`crates/atproto-pds/src/http/service_auth_handlers.rs:93-176`. It requires authentication via the
unified guard (`:101-102`), which accepts both app-password sessions and OAuth access tokens with a
DPoP proof when `cnf.jkt` is present. `aud` is required and validated with
`aud.starts_with("did:")` (`:104-110`); the reference requires `isAtprotoDid(aud) ||
isAtprotoDidRefAbsolute(aud)` (`.../getServiceAuth.ts:38-42`), so `did:` alone or `did:nonsense`
passes here. `lxm`, when supplied, is checked against a permissive NSID shape (`:111-119`, `is_nsid`
at `:179-190`). The token is signed with the caller's own key
(`:129` → `crates/atproto-pds/src/http/space_auth.rs:74`) and the claim set is `iss`, `aud`, `lxm?`,
`iat`, `exp`, `jti` (`:143-150`) — structurally correct. **Classification: PARTIAL.**

Four gates the reference applies are absent. `PROTECTED_METHODS` (16 account-management NSIDs that
may never be service-authed, `/tmp/gap-scratch/atproto/packages/pds/src/pipethrough.ts:613-630`) is
not checked. `PRIVILEGED_METHODS` — the chat lexicons plus `com.atproto.server.createAccount`
(`pipethrough.ts:605-608`) — is not checked, and since `privileged()` is never consulted here, an
app-password session with `privileged=false` or an OAuth token whose scope is the bare `atproto` can
mint `lxm=com.atproto.server.createAccount`, the account-migration token. Takendown accounts are not
blocked (`require_authn` performs no account-state lookup). And no `rpc:` scope is asserted, because
no such assertion exists in the workspace. **Classification: MISSING** for each of the four.

### `exp` semantics

`crates/atproto-pds/src/http/service_auth_handlers.rs:131-136`:

```rust
let ttl = q.exp.unwrap_or(DEFAULT_SERVICE_AUTH_TTL_SECS).clamp(1, MAX_SERVICE_AUTH_TTL_SECS);
let iat = now_secs();
let exp = iat + ttl;
```

`MAX_SERVICE_AUTH_TTL_SECS` is 600 (`:32`). A client following the lexicon sends an absolute epoch —
a ten-digit number — which clamps to 600 and yields a ten-minute token regardless of what was asked
for. Method-less tokens get the same ten minutes, where the reference caps them at sixty seconds
(`.../getServiceAuth.ts:80-86`). The `BadExpiration` error named in the lexicon
(`getServiceAuth.json:40-45`) is never emitted. **Classification: DIVERGENT.**

### JWS `typ` header — the interop wall

All five service-auth minters in the crate emit `typ: "at+jwt"`: `service_auth_handlers.rs:35`,
`crates/atproto-pds/src/http/identity_handlers.rs:327`,
`crates/atproto-pds/src/http/proxy_handlers.rs:306`,
`crates/atproto-pds/src/http/moderation_handlers.rs:175`, and
`crates/atproto-pds/src/space/mint_authz.rs:490`. The reference's `verifyJwt`, which every
`@atproto/xrpc-server`-based service uses to accept a service token, rejects three `typ` values up
front and `at+jwt` is the first of them:

> ``header['typ'] === 'at+jwt' || …`` then ``throw new AuthRequiredError(…, 'BadJwtType')``
> — `/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:88-104`

The rationale in the comment is that service tokens are not RFC 9068 OAuth access tokens. tranquil-pds
— the other Rust PDS in this set — encodes the same conclusion in its type enum, mapping `Access` to
`at+jwt` and `Service` to `JWT` with the comment "for atproto inter-service auth its a requirement"
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-auth/src/types.rs:14-24`). Every other comparison
whose header I read agrees: reference `typ: 'JWT'`
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:36-39`), rsky-pds
(`/tmp/gap-scratch/rsky/rsky-pds/src/account_manager/helpers/auth.rs:158-161`), zds
(`/tmp/gap-scratch/zds/src/auth/tokens.zig:179-183`), cocoon
(`/tmp/gap-scratch/cocoon/server/handle_server_get_service_auth.go:62-66`), cirrus
(`/tmp/gap-scratch/cirrus/packages/pds/src/service-auth.ts:76-79`), alteran
(`/tmp/gap-scratch/alteran/src/lib/appview/service-jwt.ts:63`), pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/jwt.ml:33`). **Classification: DIVERGENT.** A minor cousin:
`JwtHeader.kid` is `Option<String>` set to `None` with no `skip_serializing_if`
(`service_auth_handlers.rs:56-61`, `:141`), so the header serializes as
`{"alg":…,"typ":"at+jwt","kid":null}`.

### Verification: `lxm` is advisory

`crates/atproto-pds/src/space/service_auth.rs:125-172` is the only inbound service-auth verifier in
the tree. It checks `aud` (`:145-150`), `exp` (`:158-160`), resolves the issuer's `#atproto` key from
its DID document (`:162-164`, helper at `:181-213`) and verifies the signature (`:165-170`). The
`lxm` check is:

```rust
if let Some(lxm) = claims.lxm.as_deref()
    && lxm != expected_lxm
```

A token minted without `lxm` skips the branch entirely and is accepted by every `lxm`-scoped
endpoint. The reference makes the same check unconditional and names the missing-claim case
explicitly — `if (lxm !== null && payload.lxm !== lxm) … "missing jwt lexicon method (\"lxm\"). must
match: …"` (`/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:119-127`). cocoon checks `lxm`
against the request's last path segment (`/tmp/gap-scratch/cocoon/server/middleware.go:71-98`),
pegasus against the request NSID with a cache-skipping re-resolve retry on signature failure
(`/tmp/gap-scratch/pegasus/pegasus/lib/jwt.ml:131-207`), zds and tranquil likewise
([zds.md](../impl-notes/zds.md) §5, [tranquil-pds.md](../impl-notes/tranquil-pds.md) §"Service auth").
**Classification: DIVERGENT**, and it is a real security finding rather than a cosmetic one because
the minting side makes the wildcard trivially obtainable.

### Verification: header ignored, no replay window

The verifier decodes only the payload; `header_b64` is spliced into the signing input at
`space/service_auth.rs:168` without ever being parsed (`:132-142`). `typ` and `alg` are therefore
unvalidated — the algorithm actually used is whatever the DID-document key implies, so this is not
directly forgeable, but a token whose header claims anything at all is accepted. `iat` and `nbf` are
unchecked. The minted `jti` (`service_auth_handlers.rs:149`) is never recorded or consulted, so a
captured token is replayable for its full lifetime. **Classification: PARTIAL.**

### `com.atproto.admin.revokeServiceAuth` is inert

`crates/atproto-pds/src/admin/handlers.rs:842-860` writes the revoked `jti` into the blacklist table
via `service_auth_blacklist::add` (`:855`). The read side, `service_auth_blacklist::contains`
(`crates/atproto-pds/src/service_auth_blacklist.rs:63`), has no caller anywhere in
`crates/atproto-pds/src/` — a full-tree grep finds the definition, the module declaration in
`lib.rs:58`, and the GC helper in `gc.rs:137-139`, and nothing else. `verify_service_auth` does not
consult it. The handler's own doc comment asserts the opposite: "Inbound service-auth verifiers check
`service_auth_blacklist::contains` before honoring a token" (`admin/handlers.rs:838-840`). Note also
that this NSID is not canonical — `/tmp/gap-scratch/atproto/lexicons/com/atproto/admin/` contains no
`revokeServiceAuth.json` — so this is a project-defined control that does not work.
**Classification: DIVERGENT.**

### Inbound service auth on canonical endpoints

No canonical endpoint accepts an inbound service-auth token. `create_account` takes only
`State` and `Json` (`crates/atproto-pds/src/http/auth_handlers.rs:81-83`) — it has no `Parts`
extractor and so cannot read an `Authorization` header at all, even though `CreateAccountInput`
accepts a caller-supplied `did` (`:35`). The reference gates this
([bluesky-reference.md](../impl-notes/bluesky-reference.md) §5), and so do cocoon
(`/tmp/gap-scratch/cocoon/server/handle_server_create_account.go:81-95`), zds
([zds.md](../impl-notes/zds.md) §5, `verifyCreateAccountServiceAuth`) and tranquil-pds
([tranquil-pds.md](../impl-notes/tranquil-pds.md) §"Migration"). **Classification: MISSING.** The
account-migration consequence belongs to the migration chapter; recorded here because the inbound
service-auth verifier that would be needed already exists and is simply not wired to it.

### `Atproto-Proxy` resolution

`resolve_target` (`crates/atproto-pds/src/http/proxy_handlers.rs:63-116`) parses the header into
`<did>#<service-id>`, 400s on a malformed value (`:79-85`), then accepts the DID only if it equals
`state.bsky_app_view_did` (`:88-96`) and 502s `ProxyDidUnknown` otherwise (`:97-101`). The
`service-id` half is parsed and discarded. The module's own doc comment describes the intended
behaviour — "Resolve the DID document, look up the named service entry, and forward" (`:9`) — and
then concedes at `:26-29` that it is not implemented. There is no `chat.bsky.*`, `tools.ozone.*`, or
`com.atproto.label.*` route in the router (grep of `crates/atproto-pds/src/http/router.rs` returns
nothing for any of them), so those namespaces are unreachable regardless of header.
**Classification: MISSING.**

Comparison detail worth stating plainly, since this is where atproto-crates is furthest behind the
independent field:

| Impl | Arbitrary `Atproto-Proxy` DID → DID doc | Evidence |
|---|---|---|
| bluesky-reference | yes | `pipethrough.ts:331-340` |
| tranquil-pds | yes | `crates/tranquil-pds/src/api/proxy.rs:257` |
| cocoon | yes | `server/handle_proxy.go:20-46` |
| rsky-pds | yes | `src/pipethrough.rs:388-404` |
| metalbear | `did:web` only | `src/server.c:2084-2095`, `:2470-2487` |
| cirrus | yes | `packages/pds/src/xrpc-proxy.ts:112-142` |
| arroba | n/a — no proxy, no server surface | `arroba/util.py:355` is minting only |
| pegasus | yes | `pegasus/lib/xrpc.ml:269-283` |
| alteran | yes | `src/lib/appview/did-resolver.ts:83-102` |
| zds | yes | `src/atproto/proxy.zig:151-170` |
| dnproto | yes, plus operator allow-list and SSRF filter | `AppBsky_Proxy.cs:60-118` |
| **atproto-crates** | **no** | `http/proxy_handlers.rs:88-101` |

### Proxy request fidelity

Assuming a request reaches `proxy_call` at all, the forwarded request is lossy. The upstream URL is
built as `format!("{base}/xrpc/{nsid}")` (`proxy_handlers.rs:170-173`) with no query string; the
handler signature (`:120-126`) extracts `Path`, `Method`, `HeaderMap` and `Bytes` and never touches
the `Uri`. Only `Content-Type` is forwarded (`:195-199`) — not `Accept-Encoding`, `Accept-Language`,
`atproto-accept-labelers`, or `x-bsky-topics`, all four of which the reference forwards, alongside
`content-encoding` and `content-length`
(`/tmp/gap-scratch/atproto/packages/pds/src/pipethrough.ts:124-135`). On the way back only
`Content-Type` is copied (`:227-238`); the reference forwards `atproto-repo-rev`,
`atproto-content-labelers` and `retry-after` in addition to the content headers
(`pipethrough.ts:527-558`). The reference's never-proxy `PROTECTED_METHODS` guard
(`pipethrough.ts:92-95`) has no counterpart. **Classification: PARTIAL** on fidelity, **MISSING** on
the protected-method guard.

Query preservation is not a subtle point of parity — every implementation with a proxy keeps it
(rsky `pipethrough.rs:265-268`, tranquil `api/proxy.rs:262-265`, zds `proxy.zig:75`, metalbear
`server.c:2498-2501`, dnproto `AppBsky_Proxy.cs:121-124`, cirrus `xrpc-proxy.ts:157-158`, pegasus
`xrpc.ml:295-296`, cocoon `handle_proxy.go:64-67`). Without it `getTimeline` has no cursor and
`getPosts` has no URIs.

### DPoP on the proxy path

`proxy_call` synthesizes a `Parts` for the auth guard with `.uri("/")`
(`proxy_handlers.rs:244-261`, `:250`). `request_htm_htu` derives `htu` from `parts.uri.path()`
(`crates/atproto-pds/src/http/auth.rs:207-233`), so the value compared against a DPoP proof is
`https://<host>/` rather than `https://<host>/xrpc/app.bsky.…`. Any DPoP-bound OAuth token — which is
what `@atproto/oauth-client-*` produces — will fail `htu` validation on every proxied call.
**Classification: DIVERGENT.**

### `com.atproto.moderation.createReport` forwarding

This one is real and correct in shape. `crates/atproto-pds/src/http/moderation_handlers.rs:44-136`
authenticates the caller, mints a service-auth token with `aud = PDS_REPORT_SERVICE_DID` and
`lxm = com.atproto.moderation.createReport` (`:156-190`), POSTs the body verbatim to the configured
report service, and echoes the upstream status and body. It returns
`503 ModerationServiceUnavailable` when unconfigured (`:61-74`). It uses the real request `Parts`, so
the DPoP problem above does not apply. What is missing is header-driven retargeting: a client cannot
send `Atproto-Proxy` to pick a different labeler, which cirrus supports
(`/tmp/gap-scratch/cirrus/packages/pds/src/xrpc-proxy.ts:409-422`) and the reference supports through
the generic proxy. The `typ: "at+jwt"` problem applies to this token too. **Classification: PARTIAL.**

---

## Findings

**1. `Atproto-Proxy`/AppView proxying is non-functional as routed — the NSID is truncated and the
query string is discarded.**
CLASS: DIVERGENT · severity: **rc-blocker** ·
Evidence: the route is `/xrpc/app.bsky.{*nsid}` (`crates/atproto-pds/src/http/router.rs:109`) and the
handler consumes the captured value directly (`crates/atproto-pds/src/http/proxy_handlers.rs:120-128`).
matchit 0.8.4 places the literal prefix in the parent node and the catch-all captures only the
remainder (`matchit-0.8.4/src/tree.rs:369-393`), and axum passes route paths through verbatim
(`axum-0.8.8/src/routing/path_router.rs:83-88`). I confirmed this empirically against axum 0.8:
`GET /xrpc/app.bsky.feed.getTimeline?limit=5&cursor=abc` yields `nsid=feed.getTimeline` with the
query available on `Uri` but unused. Consequence: `resolve_target`'s default-pin test
`nsid.starts_with("app.bsky.")` (`proxy_handlers.rs:104`) never matches, so every unheadered
`app.bsky.*` call returns `503 ProxyUnavailable`; and when a client does send
`Atproto-Proxy: <configured-appview-did>#bsky_appview` the request is forwarded to
`{appview}/xrpc/feed.getTimeline` with `lxm=feed.getTimeline` and no query parameters. No Bluesky
client works against this PDS. Comparison: every implementation with a proxy forwards the full NSID
and query — see the fidelity table above. The unit tests at `proxy_handlers.rs:359-430` pass because
they call `resolve_target` with a hand-written full NSID rather than through the router.

**2. `Atproto-Proxy` DIDs are not resolved against the DID document; only one operator-pinned AppView
is reachable.**
CLASS: MISSING · severity: **rc-blocker** ·
Evidence: `crates/atproto-pds/src/http/proxy_handlers.rs:88-101` — any DID other than
`state.bsky_app_view_did` returns `502 ProxyDidUnknown`; the `service-id` half of the header is parsed
and thrown away. No `chat.bsky.*`, `tools.ozone.*` or `com.atproto.label.*` routes exist
(`crates/atproto-pds/src/http/router.rs`). Comparison: ten of eleven do this, including cirrus
(single-user, `xrpc-proxy.ts:112-142`), alteran (hobby-experiment,
`src/lib/appview/did-resolver.ts:83-102`) and dnproto (single-user, with an allow-list and an SSRF
filter, `AppBsky_Proxy.cs:60-118`). Consequence: no labeler, no feed generator, no chat, no Ozone, no
third-party AppView. This is the capability that makes a PDS a network participant.

**3. Service-auth JWTs carry `typ: "at+jwt"`, which the reference verifier rejects outright.**
CLASS: DIVERGENT · severity: **rc-blocker** ·
Evidence: `crates/atproto-pds/src/http/service_auth_handlers.rs:35` and `:140`, plus the four other
minters at `identity_handlers.rs:327`, `proxy_handlers.rs:306`, `moderation_handlers.rs:175`,
`space/mint_authz.rs:490`. Reference:
`/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:88-104` throws `BadJwtType` for exactly
this value. Comparison: seven other implementations emit `typ: "JWT"` (citations in the analysis
above); none emits `at+jwt`, and tranquil-pds distinguishes the two token classes explicitly
(`crates/tranquil-auth/src/types.rs:14-24`). Consequence: every token this PDS mints is rejected by the Bluesky
AppView, Ozone, and any other `@atproto/xrpc-server`-based service. One-line fix, network-wide blast
radius.

**4. `lxm` is optional on both the minting and the verifying side, yielding a wildcard cross-service
bearer.**
CLASS: DIVERGENT · severity: **rc-blocker** (security) ·
Evidence: mint — `crates/atproto-pds/src/http/service_auth_handlers.rs:45` and `:68-69`
(`skip_serializing_if = "Option::is_none"`); verify —
`crates/atproto-pds/src/space/service_auth.rs:151-157` only compares when the claim is present.
Reference: `/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:119-127` treats a missing `lxm`
as a failure with a dedicated message. Consequence: any authenticated account calls
`getServiceAuth?aud=<target>` with no `lxm`, receives a 600-second token (Finding 6), and that token
satisfies both `notifyWrite` and `notifySpaceDeleted` — and, at any peer implementing the same lax
check, every other `lxm`-scoped method. Combined with Finding 5 (no protected/privileged gate) this
is an unrestricted cross-service credential minted on demand.

**5. No `PROTECTED_METHODS`, `PRIVILEGED_METHODS`, takendown, or `rpc:` scope gate at mint.**
CLASS: MISSING · severity: **rc-blocker** (security) ·
Evidence: `crates/atproto-pds/src/http/service_auth_handlers.rs:93-176` contains no such check;
`AuthSubject::privileged()` has exactly one call site in the HTTP layer
(`crates/atproto-pds/src/http/write_handlers.rs:601`); `ScopesSet` has no `assert_rpc`
(`crates/atproto-oauth/src/scopes.rs:1092-1141` exposes only the space assertions, while
`Scope::Rpc` is parsed at `:578`). Reference:
`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/server/getServiceAuth.ts:29`,
`:45-66`, `:88-93`. Comparison: protected-method refusal in zds
(`server.zig:1083-1085`), tranquil (`service_auth.rs:139-147`), rsky (`get_service_auth.rs:34-41`)
and alteran (`com.atproto.server.getServiceAuth.ts:13-23`); privileged gating in metalbear
(`server.c:1964-1969`) and alteran (`com.atproto.server.getServiceAuth.ts:21-23`), and in rsky with
inverted polarity (`get_service_auth.rs:38-40`); `rpc:` scope assertion in zds
(`server.zig:1086-1088`), tranquil (`service_auth.rs:112-133`), pegasus
(`api/server/getServiceAuth.ml:15`) and cirrus (`xrpc-proxy.ts:207-215`). Consequence: a
non-privileged app-password session, or an OAuth token whose scope is the bare `atproto`, can mint
`lxm=com.atproto.server.createAccount` — the migration credential — and can mint tokens for the
account-management NSIDs the reference protects.

**6. `exp` is interpreted as a TTL rather than an absolute Unix epoch, and `BadExpiration` is never
returned.**
CLASS: DIVERGENT · severity: **stable-gap** ·
Evidence: `crates/atproto-pds/src/http/service_auth_handlers.rs:131-136` — `q.exp.unwrap_or(60)
.clamp(1, 600)` then `exp = iat + ttl`. Lexicon:
`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/getServiceAuth.json:17-20` and the
`BadExpiration` error at `:40-45`. Comparison: eight implementations read it as an epoch (citations
in the Assessment); cirrus and pegasus ignore it. Consequence: a client asking for a 30-second token
gets 600 seconds, and a method-less token gets 600 seconds where the reference caps at 60. Not
independently exploitable — 600 s is inside the reference's own one-hour ceiling — but it multiplies
the exposure of Finding 4 and it means the PDS silently overrides a client's stated security
preference.

**7. `com.atproto.admin.revokeServiceAuth` has no effect.**
CLASS: DIVERGENT · severity: **stable-gap** (security control that reads as working) ·
Evidence: `crates/atproto-pds/src/admin/handlers.rs:855` writes; `service_auth_blacklist::contains`
(`crates/atproto-pds/src/service_auth_blacklist.rs:63`) has no production caller — grep across
`crates/atproto-pds/src/` finds only the definition, `lib.rs:58`, and `gc.rs:137-139`. The doc comment
at `admin/handlers.rs:838-840` states that inbound verifiers consult it; they do not
(`space/service_auth.rs:125-172`). The NSID is also not canonical (no
`/tmp/gap-scratch/atproto/lexicons/com/atproto/admin/revokeServiceAuth.json`). Consequence: an
operator who revokes a leaked token, sees `200 OK` and an `admin: service-auth jti revoked` log line,
and believes the token is dead, is wrong. A no-op endpoint is worse than an absent one.

**8. Inbound service-auth verification ignores the JWS header and never checks `jti` replay,
`iat`, or `nbf`.**
CLASS: PARTIAL · severity: **stable-gap** ·
Evidence: `crates/atproto-pds/src/space/service_auth.rs:132-142` decodes the payload only;
`header_b64` reaches the signing input at `:168` unparsed. No `jti` bookkeeping anywhere on the
service-auth path (`jti` is minted at `service_auth_handlers.rs:149` and never read).
Comparison: the reference parses the header and requires `alg` to be a string
(`/tmp/gap-scratch/atproto/packages/xrpc-server/src/auth.ts:194-200`) and rejects three `typ` values;
cocoon runs a `jti` replay guard on its OAuth path ([cocoon.md](../impl-notes/cocoon.md) §5).
Consequence: a captured token is replayable for its whole lifetime, which Finding 6 has stretched to
600 seconds.

**9. DPoP-bound OAuth tokens cannot use the proxy path — `htu` is derived from a synthetic `/` URI.**
CLASS: DIVERGENT · severity: **stable-gap** (moot until Findings 1 and 2 are fixed) ·
Evidence: `crates/atproto-pds/src/http/proxy_handlers.rs:244-261` builds the auth `Parts` with
`.uri("/")` at `:250`; `crates/atproto-pds/src/http/auth.rs:207-233` derives `htu` from
`parts.uri.path()`. Comparison: cirrus verifies the DPoP-bound token against the real request
(`xrpc-proxy.ts:196-202`, `provider.verifyAccessToken(c.req.raw)`). Consequence: every browser OAuth
client 401s on proxied calls even after the routing bug is fixed.

**10. Proxied requests and responses drop the headers the AppView protocol depends on.**
CLASS: PARTIAL · severity: **stable-gap** ·
Evidence: request — only `Content-Type` is forwarded
(`crates/atproto-pds/src/http/proxy_handlers.rs:195-199`); response — only `Content-Type` is copied
back (`:227-238`). Reference forwards `accept-encoding`, `accept-language`, `atproto-accept-labelers` and
`x-bsky-topics` outbound (`pds/src/pipethrough.ts:124-135`) and `atproto-repo-rev`,
`atproto-content-labelers`, `retry-after` inbound (`:527-558`). Comparison: alteran carries a
fourteen-header allow-list (`src/lib/appview/proxy.ts:19-34`), zds five (`proxy.zig:79-87`), pegasus
forwards `atproto-accept-labelers` and returns all upstream headers (`xrpc.ml:298-305`, `:320-328`).
Consequence: label preferences are silently ignored and read-after-write freshness signals are lost.

**11. No never-proxy `PROTECTED_METHODS` guard on the proxy path.**
CLASS: MISSING · severity: **cosmetic** in current shape ·
Evidence: `crates/atproto-pds/src/http/proxy_handlers.rs:63-116` has no such list. Reference:
`pipethrough.ts:92-95`. Comparison: zds (`proxy.zig:28-31`), tranquil (`api/proxy.rs:113-115`,
`:234`), alteran (`src/lib/appview/proxy.ts:96`) all carry one. Consequence today is limited
because the proxy only ever routes `app.bsky.*` and the protected set is `com.atproto.*`; it becomes
load-bearing the moment Finding 2 is fixed and arbitrary namespaces become proxyable.

**12. `aud` validation accepts any string beginning `did:`.**
CLASS: PARTIAL · severity: **cosmetic** ·
Evidence: `crates/atproto-pds/src/http/service_auth_handlers.rs:104-110`. Reference:
`.../getServiceAuth.ts:38-42` requires `isAtprotoDid || isAtprotoDidRefAbsolute`. zds validates the
`did#serviceId` shape including a single-`#` rule (`server.zig:1101-1108`); alteran does the same
(`com.atproto.server.getServiceAuth.ts:46-50`). Consequence: garbage audiences mint successfully and
fail late at the receiving service.

**13. `kid` serializes as literal `null` in the service-auth header.**
CLASS: DIVERGENT · severity: **cosmetic** ·
Evidence: `crates/atproto-pds/src/http/service_auth_handlers.rs:56-61` and `:141` — `kid:
Option<String>` with no `skip_serializing_if`. No comparison implementation emits a `kid` at all.
Consequence: a strict JOSE header parser could object. UNVERIFIED whether any live consumer does; it
is moot until Finding 3 is fixed, since the same header is rejected on `typ` first.

**14. No canonical endpoint accepts an inbound service-auth token.**
CLASS: MISSING · severity: **stable-gap** (primary consequence is scored in the migration chapter) ·
Evidence: `verify_service_auth` has exactly two callers, both Spaces
(`crates/atproto-pds/src/http/space_handlers.rs:2096`, `:2570`); `create_account` cannot read headers
(`crates/atproto-pds/src/http/auth_handlers.rs:81-83`). Comparison: reference, cocoon
(`handle_server_create_account.go:81-95`), zds and tranquil all gate `createAccount`-with-existing-DID
on service auth. Consequence: an account cannot be migrated *into* this PDS under the standard flow,
and `createAccount` accepts a caller-supplied `did` (`auth_handlers.rs:35`) with no proof of control.

---

## Confidence & unknowns

Findings 1, 3, 4, 5, 6, 7 and 14 are source-verified on both sides and I re-opened each atproto-crates
file:line rather than relying on the inventory. Finding 1 additionally rests on an empirical check: I
built a standalone axum 0.8 server with the exact route pattern `/xrpc/app.bsky.{*nsid}` and observed
`nsid=feed.getTimeline` for `GET /xrpc/app.bsky.feed.getTimeline?limit=5&cursor=abc`, and separately
confirmed the same result directly against matchit 0.8.4, the router axum delegates to. I did not run
the atproto-crates binary, so the end-to-end 503 is inferred from the routing behaviour plus
`resolve_target`'s `starts_with` test rather than observed against a live PDS — that inference is
mechanical, but it is an inference.

Two things I could not establish. metalbear's service-JWT header value is **UNVERIFIED**: the signing
function `wf_server_create_service_auth` is declared in
`/tmp/gap-scratch/metalbear/include/metalbear/repo_store.h:395` and called from
`src/repo_store.c:2716`, but its definition lives in a `wf_` support library that is not vendored into
the clone. Its `getServiceAuth` parameter handling I did read
(`src/server.c:1950-2008`). And whether any live AppView rejects the literal-`null` `kid`
(Finding 13) would need a request against a real service, which this pass did not make.

Where the comparison tier assignments mattered I leaned on them rather than on reputation: cirrus and
alteran are scored `Y` on arbitrary proxy-DID resolution and on getServiceAuth `exp` semantics because
I read their source, not because of their tier, and those two data points are the reason Findings 2
and 6 are graded as harshly as they are. arroba is `n/a` on every proxy row because it is a repository
library with a demo Flask app, not a serving PDS — it mints service JWTs
(`/tmp/gap-scratch/arroba/arroba/util.py:355-384`) and never routes `getServiceAuth`, which
[arroba.md](../impl-notes/arroba.md) states and I confirmed by grep. cirrus and alteran are `n/a` on
"inbound service auth gates createAccount" because neither supports multi-account signup at all.
