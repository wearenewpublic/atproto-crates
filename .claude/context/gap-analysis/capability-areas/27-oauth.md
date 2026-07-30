# G. OAuth — Authorization Server and Resource Server

Part of the [atproto-crates 0.15.0-rc.1 gap analysis](../README.md). See also the
[inventory](../00-atproto-crates-inventory.md), [coverage matrix](../20-coverage-matrix.md), and
[roadmap](../50-synthesis-and-roadmap.md).

## Assessment

An AT Protocol PDS is simultaneously an OAuth 2.1 authorization server and the resource server it
protects, and the obligations are unusually concrete because the ecosystem's only client library,
`@atproto/oauth-client-*`, doubles as a conformance oracle: mandatory pushed authorization requests
(RFC 9126), PKCE `S256` only, DPoP (RFC 9449) on both the AS endpoints and every resource request
with server-issued nonces, `client_id`-as-URL metadata documents instead of registration,
`private_key_jwt` for confidential clients (RFC 7523), rotating single-use refresh tokens, revocation
(RFC 7009), and the two discovery documents `/.well-known/oauth-authorization-server` (RFC 8414) and
`/.well-known/oauth-protected-resource` (RFC 9728). Above that sits atproto's scope layer: `atproto`,
the `transition:*` bridges, and the granular `repo:` / `rpc:` / `blob:` / `account:` / `identity:`
grammar with `include:<nsid>` permission-set references.

atproto-crates routes all eight expected surfaces and has real machinery behind them. PAR validates
`response_type`, `code_challenge_method`, and the presence of the `atproto` scope
(`crates/atproto-pds/src/oauth/par.rs:147-174`), and additionally verifies RFC 9101 signed request
objects — which **no independent PDS in this comparison implements**. PKCE is `S256`-only and truly
verified at exchange (`crates/atproto-pds/src/oauth/token.rs:316-320`). Resource-side DPoP is
thorough: `typ`, `alg`, `htm`, `htu`, `ath`, `iat` window, thumbprint equality against `cnf.jkt`, and
a single-use `jti` guard (`crates/atproto-pds/src/oauth/dpop.rs:44-109`). Refresh rotation is
single-use and persisted in SQL. On paper this is a serious authorization server.

In practice it does not work, and not subtly. PAR and token are wired with axum's `Json` extractor
(`crates/atproto-pds/src/oauth/par.rs:132-135`, `crates/atproto-pds/src/oauth/token.rs:100-103`), so
a client sending the RFC-mandated `application/x-www-form-urlencoded` body — exactly what
`/tmp/gap-scratch/atproto/packages/oauth/oauth-client/src/oauth-server-agent.ts:236-239` sends — gets
HTTP 415 and cannot complete one flow. Behind that interop wall sit two chained security defects:
PAR never validates `redirect_uri` against the client metadata document, and `/oauth/token` requires
no client authentication and no DPoP proof while letting the caller name its own `cnf.jkt`. Together
those are authorization-code exfiltration plus free redemption against any user who can be phished
onto a consent URL. A fourth defect makes every non-DPoP OAuth session permanently unusable after its
first refresh. These are O1–O4 in the orchestrator's verification notes
(`/tmp/gap-scratch/verified-commit-divergences.md`); each was re-opened at the cited line for this
chapter.

The comparison is where this gets uncomfortable, because OAuth is emphatically **not** an area where
"only the reference does it." Ten of eleven comparisons ship an authorization server; only
[arroba](../impl-notes/arroba.md) has none, and arroba has no session management at all
(`/tmp/gap-scratch/arroba/arroba/server.py:22-29` is a static bearer token). Seven issue rotating
DPoP nonces. Six implement `private_key_jwt`. **All ten constrain `redirect_uri`; atproto-crates is
the only implementation in the set that does not.** And every AS that pins a DPoP key at PAR —
including [metalbear](../impl-notes/metalbear.md) in C
(`/tmp/gap-scratch/metalbear/src/oauth.c:509-513`) and hobby-tier
[alteran](../impl-notes/alteran.md) (`/tmp/gap-scratch/alteran/src/pages/oauth/token.ts:77`) —
refuses to let the token request override that pin, where atproto-crates prefers the request-time
value (`crates/atproto-pds/src/oauth/token.rs:176`). On the items that produce this chapter's
blockers, atproto-crates is behind the hobby tier, not merely behind the reference.

## 1. Are the standalone OAuth crates wired in? — definitively no, and they could not have been

`crates/atproto-pds/Cargo.toml:36` lists `atproto-oauth` and nothing else; `atproto-oauth-aip` and
`atproto-oauth-axum` appear nowhere in that manifest, in no feature, in no dev-dependency. A full
grep of `crates/atproto-pds/src/` for `atproto_oauth` resolves to three modules only: `scopes`
(`crates/atproto-pds/src/http/auth.rs:96-99` plus ~25 sites in `http/space_handlers.rs`),
`dpop::{DpopValidationConfig, validate_dpop_jwt}` (`crates/atproto-pds/src/oauth/dpop.rs:24`), and
`jwk::WrappedJsonWebKeySet` (`crates/atproto-pds/src/space/mint_authz.rs:27`). Zero references to
`atproto_oauth_aip::*` or `atproto_oauth_axum::*`.

This is not a missed reuse opportunity: those crates are *client*-side.
`crates/atproto-oauth-aip/src/lib.rs:1-16` documents a relying-party flow taking `redirect_uri`,
`client_id`, `client_secret`; `crates/atproto-oauth/src/workflow.rs:1-13` is `oauth_init` /
`oauth_complete` with client-side PKCE and client-assertion *minting*. No server-side AS exists in
the workspace, so the PDS wrote one. The cost is visible — PKCE is hand-rolled at
`crates/atproto-pds/src/oauth/token.rs:316-320` rather than calling `atproto_oauth::pkce`, and the
tree now carries seven independent hand-rolled JWS mint/verify implementations
(`oauth/token.rs:335-388`, `account/session.rs:82-158`, `http/service_auth_handlers.rs:152-175`,
`space/service_auth.rs:101-172`, `http/proxy_handlers.rs:318-345`,
`http/identity_handlers.rs:315-341`, `space/mint_authz.rs:496-511`). Architectural debt, not a spec
violation. **CLASSIFICATION: n/a (context).**

## 2. Endpoint surface and wire format

All eight surfaces are routed at `crates/atproto-pds/src/http/router.rs:246-259`: `POST /oauth/par`,
`GET`+`POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke`, `GET /oauth/jwks`, and both
well-knowns. The surface is complete; the wire format is not. `par_handler` takes `Json<ParInput>`
(`par.rs:132-135`) and `token_handler` takes `Json<TokenInput>` (`token.rs:100-103`); axum's `Json`
rejects any non-`application/json` request with 415. RFC 9126 §2 and RFC 6749 §4.1.3 both require
form encoding. That the sibling `revoke_handler` correctly uses `Form`
(`crates/atproto-pds/src/oauth/revoke.rs:41`) shows the inconsistency is accidental.

Nobody else has this problem. The reference accepts both —
`parseHttpRequest(req, ['json','urlencoded'])` at
`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/router/create-oauth-middleware.ts:95,135,167`.
[tranquil-pds](../impl-notes/tranquil-pds.md) content-type-sniffs and handles both
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-oauth-server/src/endpoints/par.rs:57-73`,
`.../token/mod.rs:27-42`); metalbear does the same in C (`parse_form_body`,
`/tmp/gap-scratch/metalbear/src/oauth_routes.c:344-371`); [rsky-pds](../impl-notes/rsky-pds.md) uses
Rocket `FromForm` (`/tmp/gap-scratch/rsky/rsky-pds/src/oauth/routes.rs:130,170,211`);
[cocoon](../impl-notes/cocoon.md) tags every field `form:`/`json:`
(`/tmp/gap-scratch/cocoon/oauth/provider/models.go:39`); alteran reads
`new URLSearchParams(bodyText)` (`/tmp/gap-scratch/alteran/src/pages/oauth/par.ts:50-51`).
**DIVERGENT — rc-blocker.**

## 3. PAR, the client-metadata document, and `redirect_uri`

The inline PAR path never fetches client metadata. `merge_inline_into_resolved`
(`crates/atproto-pds/src/oauth/par.rs:202-223`) copies the caller's `redirect_uri` verbatim;
`POST /oauth/authorize` echoes it unchecked (`crates/atproto-pds/src/oauth/authorize.rs:127-139`);
the consent page's inline JavaScript navigates the browser to it
(`crates/atproto-pds/src/oauth/consent.rs:325-331`). An attacker PARs with a recognisable `client_id`
and their own `redirect_uri`, phishes a victim onto the consent URL, and collects a valid code.

The reference rejects this at
`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/client/client.ts:332-343` — the
caller's `redirect_uri` must match one of `this.metadata.redirect_uris` under `compareRedirectUri`
or the request throws `Invalid redirect_uri` — and so does
every independent AS: tranquil (`.../endpoints/par.rs:85`), cocoon
(`/tmp/gap-scratch/cocoon/server/handle_oauth_par.go:65`, with a regression test at
`handle_oauth_par_test.go:34-51`), rsky (`/tmp/gap-scratch/rsky/rsky-oauth/src/client.rs:155-167`),
zds (`/tmp/gap-scratch/zds/src/atproto/oauth.zig:121-123`), pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/api/oauth_/par.ml:16-19`), alteran
(`/tmp/gap-scratch/alteran/src/lib/oauth/clients.ts:418`), cirrus, and dnproto through an operator
allowlist (`/tmp/gap-scratch/dnproto/src/pds/oauth/Oauth_Par.cs:69-77` — restrictive rather than
spec-shaped, but safe). metalbear declines to fetch metadata yet still constrains the value by
byte-comparing the token-request `redirect_uri` against the PAR-stored one
(`/tmp/gap-scratch/metalbear/src/oauth.c:509-513`). **MISSING — rc-blocker (security).**

The JAR path *does* fetch, unguarded. `resolve_client_signing_key`
(`crates/atproto-pds/src/oauth/par.rs:405-457`) builds a bare `reqwest::Client` (`:409-413`), GETs
the caller-supplied `client_id` verbatim (`:414-415`), then the response's `jwks_uri` verbatim
(`:426-433`). No scheme check (`http://` accepted), no host validation, no private/loopback
rejection, no redirect cap. The SSRF hardening from commit `18b826f` landed in
`crates/atproto-identity/src/host.rs` and `crates/atproto-pds` does not call it — grep for
`is_private|loopback|link_local|ssrf` in that tree is empty. Alteran, the lowest-maturity comparison,
gates the identical fetch with `isSafeFetchUrl(client_id)`
(`/tmp/gap-scratch/alteran/src/pages/oauth/par.ts:63-67`). **MISSING — rc-blocker (security).**

Smaller but functionally real: `PAR_TTL_SECS = 60` and `AUTH_CODE_TTL_SECS = 60`
(`crates/atproto-pds/src/oauth/state.rs:34-37`). Sixty seconds is the whole window in which a human
loads the consent page, reads it, and types an identifier and password. The reference allows five
minutes (`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/constants.ts:54`); tranquil ten
(`.../endpoints/par.rs:14`). **DIVERGENT — stable-gap.**

## 4. PKCE

Correct and complete: `S256` mandatory at PAR (`crates/atproto-pds/src/oauth/par.rs:154-160`),
`code_verifier` mandatory at exchange (`crates/atproto-pds/src/oauth/token.rs:160-166`), verified as
`b64url_nopad(SHA256(verifier)) == challenge` (`:316-320`). `plain` never accepted. Matches the
reference and every AS in the field. No finding.

## 5. DPoP

**Resource side: strong.** When the token carries `cnf.jkt`, `require_authn` calls `verify_dpop_proof`
(`crates/atproto-pds/src/http/auth.rs:178-181` → `crates/atproto-pds/src/oauth/dpop.rs:44-109`),
which delegates to `atproto_oauth::dpop::validate_dpop_jwt` with
`DpopValidationConfig::for_resource_request(htm, htu, access_token)` — `typ == "dpop+jwt"`, alg
allow-list, header `jwk`, `jti`, `htm`, `htu`, `iat` window, and `ath` binding all enforced
(`crates/atproto-oauth/src/dpop.rs:485-492`, `:558-653`). Thumbprint compared to `cnf.jkt`
(`oauth/dpop.rs:81-87`), proof `jti` single-use via the replay guard (`:90-106`). `htm`/`htu` derived
from the live request with query and fragment stripped, honouring `X-Forwarded-*`
(`http/auth.rs:207-235`). As good as the field.

**AS side: absent.** No proof is required at `/oauth/par`, `/oauth/token`, or `/oauth/revoke`.
`TokenInput` declares `dpop_jkt: Option<String>` as a plain body field
(`crates/atproto-pds/src/oauth/token.rs:44-45`) and `token_handler` (`:100-124`) never reads a `DPoP`
header — so the thumbprint bound into `cnf` is a value the caller typed, not one it proved possession
of. Worse, `handle_code` computes
`let dpop_jkt = input.dpop_jkt.clone().or(auth.request.dpop_jkt.clone());` (`:176`), so the
request-time value **wins over** the PAR-pinned one. With no client authentication, a stolen code is
redeemable by anyone and bindable to the attacker's key. The reference cross-checks the proof against
the PAR-stored jkt — a missing proof or a thumbprint mismatch is an `InvalidGrantError`
(`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/oauth-provider.ts:840-848`) — reached
from the code grant only after `compareClientAuth` (`:933`), and adopts the proof's jkt at exchange
solely when PAR left it unset (`:937-942`).

Every comparison AS that stores a PAR jkt treats it as a pin: tranquil errors on mismatch
(`.../endpoints/token/grants.rs:114-118`), cocoon
(`/tmp/gap-scratch/cocoon/server/handle_oauth_token.go:200-201`), rsky
(`/tmp/gap-scratch/rsky/rsky-oauth/src/provider.rs:454-474,561`), cirrus
(`/tmp/gap-scratch/cirrus/packages/oauth-provider/src/provider.ts:844-849`), zds — which refuses a
code exchange whose authorization request was not DPoP-bound at all
(`/tmp/gap-scratch/zds/src/atproto/oauth.zig:476-480`), alteran
(`/tmp/gap-scratch/alteran/src/pages/oauth/token.ts:77,171`), pegasus, which requires a proof at PAR
itself (`/tmp/gap-scratch/pegasus/pegasus/lib/api/oauth_/par.ml:5-6`), and even metalbear
(`strcmp` at `/tmp/gap-scratch/metalbear/src/oauth.c:509-513`). dnproto validates a genuine header
proof at its token endpoint (`/tmp/gap-scratch/dnproto/src/pds/oauth/Oauth_Token.cs:61-67`) and pins
the thumbprint across refresh (`:232`). **MISSING + DIVERGENT — rc-blocker (security).**

**Server nonces: absent.** `DpopValidationConfig.expected_nonce_values` exists
(`crates/atproto-oauth/src/dpop.rs:451-452`) but the PDS sets only `max_age_seconds`
(`crates/atproto-pds/src/oauth/dpop.rs:71-72`); grep of `crates/atproto-pds/` for `DPoP-Nonce` or
`use_dpop_nonce` returns nothing. Issued by the reference (`dpop/dpop-nonce.ts:34-107`), tranquil
(a middleware stamping every `/oauth/*` and `/xrpc/*` response,
`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/oauth/verify.rs:404-416`), cocoon
(`/tmp/gap-scratch/cocoon/oauth/dpop/nonce.go:33-107`), rsky
(`/tmp/gap-scratch/rsky/rsky-pds/src/oauth/routes.rs:76-106`), cirrus (`provider.ts:718-731`),
alteran (`/tmp/gap-scratch/alteran/src/lib/oauth/dpop.ts:100-149`), zds
(`/tmp/gap-scratch/zds/src/internal/dpop.zig:33,41,199-211`), and pegasus, which makes it
**mandatory** (`/tmp/gap-scratch/pegasus/pegasus/lib/oauth/dpop.ml:45-87`). Only metalbear and
dnproto join the omission; clients tolerate a missing nonce, so this is conformance, not outage.
**MISSING — stable-gap.**

## 6. The non-DPoP refresh break

`issue_pair` stores `dpop_jkt.clone().unwrap_or_default()` into the persisted handle
(`crates/atproto-pds/src/oauth/token.rs:290`) — an empty `String` when absent. `handle_refresh` feeds
it back as `Some(handle.dpop_jkt)` (`:230`), so the reissued token carries `cnf: Some(jkt: "")`
(`:246-248`) and `token_type` flips to `"DPoP"` (`:298`). On the next resource request
`claims.cnf.is_some()` is true (`crates/atproto-pds/src/http/auth.rs:179`) and the proof thumbprint is
compared against `""` (`crates/atproto-pds/src/oauth/dpop.rs:81-87`), which no key satisfies. Every
non-DPoP OAuth session is dead after its first refresh. Internal contradiction; no comparison needed.
**DIVERGENT — rc-blocker (functional).**

## 7. Client authentication and `private_key_jwt`

Not implemented. `TokenInput` (`crates/atproto-pds/src/oauth/token.rs:30-46`) has no
`client_assertion` field, and grepping `crates/` for it finds only client-side minting inside
`atproto-oauth`. `handle_code` compares the body `client_id` to the PAR-stored value (`:146-152`) and
`handle_refresh` to the refresh JWT claim (`:201-207`) — identifier matching, not authentication. The
metadata nevertheless advertises `token_endpoint_auth_methods_supported: ["none","private_key_jwt"]`
(`crates/atproto-pds/src/oauth/metadata.rs:77-80`), and the RFC 8414 §2 companion field
`token_endpoint_auth_signing_alg_values_supported` is absent.

Six comparisons implement it for real: cocoon
(`/tmp/gap-scratch/cocoon/oauth/provider/client_auth.go:58-146`, with `jti` replay and an `iat` age
bound), tranquil (`/tmp/gap-scratch/tranquil-pds/crates/tranquil-oauth/src/client.rs:392-559`), rsky
(`/tmp/gap-scratch/rsky/rsky-oauth/src/client.rs:36-104`), zds
(`/tmp/gap-scratch/zds/src/atproto/oauth.zig:579-694`), alteran
(`/tmp/gap-scratch/alteran/src/lib/oauth/clients.ts:354-393,440-481`), cirrus
(`/tmp/gap-scratch/cirrus/packages/oauth-provider/src/client-auth.ts`). Three advertise without
implementing, exactly as atproto-crates does — pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/api/well_known.ml:61-62`), dnproto
(`/tmp/gap-scratch/dnproto/src/pds/oauth/Oauth_AuthorizationServer.cs:39`), metalbear
(`/tmp/gap-scratch/metalbear/src/oauth_routes.c:129-133`). Public clients dominate atproto and do
work, so this is a gap rather than an outage. **MISSING (impl) / DIVERGENT (metadata) — stable-gap.**

## 8. Token issuance, format, and revocation

`issue_pair` (`crates/atproto-pds/src/oauth/token.rs:236-307`) mints HS256 compact JWS over
`state.jwt_secret` with `typ` headers `at-oauth-access` / `at-oauth-refresh` (`:24,27`) rather than
RFC 9068's `at+jwt`. TTLs default to 900 s / 30 d and unlike the app-password TTLs *are*
operator-configurable (`crates/atproto-pds/src/oauth/state.rs:28,31`). Refresh rotation is single-use
and SQL-backed: `rotate_refresh` returns `None` on a second presentation and the handler answers
`invalid_grant` (`token.rs:209-223`). That part matches the field.

Two consequences follow from the symmetric signature. `state.jwt_secret`
(`crates/atproto-pds/src/http/state.rs:31`) signs *four* token classes — app-password access and
refresh (`crates/atproto-pds/src/account/session.rs:82`) plus OAuth access and refresh
(`token.rs:278-281`) — separated only by the `typ` string, so no key-rotation path exists that does
not invalidate every live token, and one disclosure forges all four. And `/oauth/jwks` publishes real
keys with correct `use`, `alg`, and RFC 7638 thumbprint `kid`s
(`crates/atproto-pds/src/oauth/jwks.rs:42-99`) while its own module doc concedes at `:5-7` that the
access tokens are HS256 and verifiable with none of them. This is not unusual — cirrus does the same
and its JWKS is deliberately empty (`.../oauth-provider/src/provider.ts:947-953`) and tranquil uses
HS256 reference tokens (`.../tranquil-pds/src/oauth/verify.rs:103-183`), though metalbear
(`/tmp/gap-scratch/metalbear/src/oauth.c:377-428`, ES256) and pegasus
(`/tmp/gap-scratch/pegasus/pegasus/lib/jwt.ml:89-116`) do sign asymmetrically. Defensible while the
PDS is its own AS and RS. **DIVERGENT — stable-gap.**

`verify_oauth_jwt` (`crates/atproto-pds/src/oauth/token.rs:358-388`) checks `alg`, `typ`, HMAC, and
`exp` — and nothing else. `aud` and `iss` are minted (`:257-259`) and never verified, so any
deployment sharing `PDS_JWT_SECRET` across services or environments cross-accepts tokens. metalbear's
resource verifier checks both plus a mandatory `dpop_bound` flag
(`/tmp/gap-scratch/metalbear/src/oauth.c:612-615`). **MISSING — stable-gap.**

Revocation is half-effective. `POST /oauth/revoke` is form-encoded, honours `token_type_hint`, and
always returns 200 per RFC 7009 §2.2 (`crates/atproto-pds/src/oauth/revoke.rs:39-56`). Refresh
revocation drops the rotation handle (`:63-74`) and works. Access revocation inserts the `jti` into
the replay guard (`:75-82`), but `require_authn` never queries that guard for an access token's `jti`
— the only request-path `check_and_insert` is for the *DPoP proof's* `jti`
(`crates/atproto-pds/src/oauth/dpop.rs:97-106`), so a revoked access token keeps working for its full
900 s. metalbear has the identical shape (`metalbear_oauth_revoke` deletes refresh rows only,
`/tmp/gap-scratch/metalbear/src/oauth.c:578-595`); pegasus has no revocation endpoint at all and
dnproto advertises one it never routes (`Oauth_AuthorizationServer.cs:41`). tranquil, cocoon, rsky,
cirrus, alteran, zds all implement it, and tranquil and zds additionally serve RFC 7662 introspection
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-oauth-server/src/lib.rs:57`;
`/tmp/gap-scratch/zds/src/http/router.zig:145`). **PARTIAL — stable-gap (security-relevant).**

## 9. The two discovery documents

`crates/atproto-pds/src/oauth/metadata.rs:56-81` emits fourteen fields with correct values. What it
omits, relative to
`/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/metadata/build-metadata.ts`, matters
because clients read these:

| Missing field | Ref line | Impact |
|---|---|---|
| `authorization_response_iss_parameter_supported` | `:98` | RFC 9207; client uses it to decide whether to require `iss` on the callback |
| `client_id_metadata_document_supported` | `:139` | the atproto client-id-as-URL signal |
| `request_object_signing_alg_values_supported` | `:101` | JAR is implemented (`par.rs:285`) but never advertised |
| `request_parameter_supported`, `request_uri_parameter_supported`, `require_request_uri_registration` | `:105-107` | |
| `token_endpoint_auth_signing_alg_values_supported` | `:115` | required by RFC 8414 §2 once `private_key_jwt` is claimed |
| `subject_types_supported` / `response_modes_supported` | `:39` / `:57` | |
| `scopes_supported` omits `transition:email` | `:33` | |

The comparison is bleak because the *smallest* implementations publish more. metalbear's C builder
emits every field in that table except `request_object_signing_alg_values_supported`
(`/tmp/gap-scratch/metalbear/src/oauth_routes.c:64-146`); zds emits all of those plus the full
granular scope list and `token_endpoint_auth_signing_alg_values_supported` in a single format string
(`/tmp/gap-scratch/zds/src/atproto/oauth.zig:70`); cocoon
(`/tmp/gap-scratch/cocoon/server/handle_well_known.go:114-145`), rsky
(`/tmp/gap-scratch/rsky/rsky-oauth/src/provider.rs:741-777`), cirrus
(`/tmp/gap-scratch/cirrus/packages/oauth-provider/src/provider.ts:898-941`) and tranquil
(`.../endpoints/metadata.rs:60-129`) are comparably complete. **PARTIAL — stable-gap.**

Three advertised values are also wrong rather than absent: `private_key_jwt` (§7);
`dpop_signing_alg_values_supported: ["ES256","ES256K"]` (`metadata.rs:75`) is narrower than the
validator's actual accept set, which includes `ES384` (`crates/atproto-oauth/src/dpop.rs:574`); and
`require_dpop_bound_access_tokens: true` (`metadata.rs:76`) is a promise the server breaks — an
exchange with no `dpop_jkt` yields `cnf: None` and `token_type: "Bearer"` (`token.rs:246-248,298`),
after which `require_authn` skips DPoP entirely (`http/auth.rs:179`). zds enforces the equivalent
claim (`oauth.zig:476-479`) and metalbear requires `dpop_jkt` at PAR (`oauth_routes.c:213-222`).
**DIVERGENT — stable-gap.**

`/.well-known/oauth-protected-resource` emits only `resource` and `authorization_servers`
(`crates/atproto-pds/src/oauth/metadata.rs:44-49,86-93`); the reference adds
`bearer_methods_supported`, `scopes_supported`, `resource_documentation`
(`/tmp/gap-scratch/atproto/packages/pds/src/auth-routes.ts:19-21`). More important, the reference
sets `Access-Control-Allow-Origin/Method/Headers: *` on that response (`auth-routes.ts:32-34`) and
atproto-crates has **no CORS anywhere** — the handler returns a bare `Json<…>`, the router applies
only the optional metrics layer (`crates/atproto-pds/src/http/router.rs:442-447`), and grep for
`cors|Access-Control` across `crates/atproto-pds/src/` is empty. `@atproto/oauth-client-browser`
fetches this document from page JavaScript, so without the header discovery fails before the flow
starts. tranquil installs a `CorsLayer`
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-pds/src/lib.rs:38,106`), cocoon uses echo's
(`server/server.go:295`), cirrus hono's (`packages/pds/src/index.ts:81-84`), and rsky, pegasus
(`bin/main.ml:25,29` plus `xrpc.ml`), alteran (`src/middleware.ts`) and zds
(`src/http/api.zig:282`) all set it. **PARTIAL — rc-blocker for browser clients.**

## 10. Scopes and permission sets

`atproto_oauth::scopes::Scope` parses the whole grammar (`crates/atproto-oauth/src/scopes.rs:34-59`),
but the PDS accepts and then ignores almost all of it. PAR performs one scope check — the string must
contain the bare token `atproto` (`crates/atproto-pds/src/oauth/par.rs:161-167`) — and anything else
is stored verbatim and copied into the token's `scope` claim
(`crates/atproto-pds/src/oauth/token.rs:260`). No allow-list, no rejection of unknown scopes, no
check against the client metadata's declared `scope`.

Enforcement is narrower still. `ScopesSet` exposes assertions for `space:` only —
`assert_space`, `assert_space_with`, `assert_space_manage`
(`crates/atproto-oauth/src/scopes.rs:1092-1141`); there is no `assert_repo`, `assert_rpc`,
`assert_blob`, `assert_account`, or `assert_identity`. In the PDS the only scope-driven decisions are
the `assert_space*` sites in `crates/atproto-pds/src/http/space_handlers.rs` — 24 calls to the local
`assert_space_scope` wrapper (defined at `:1859`) plus 12 `assert_space_manage` and one
`assert_space_with` — and a single `privileged()` check on `com.atproto.repo.importRepo`
(`crates/atproto-pds/src/http/write_handlers.rs:601-608`), where `privileged()` for an OAuth subject
means the literal presence of `transition:generic` in the scope string
(`crates/atproto-pds/src/http/auth.rs:110-118`). Concretely: a token bearing only `scope=atproto` can
create, update, and delete records in any collection of its own repo, because
`crates/atproto-pds/src/http/write_handlers.rs:113-127` gates on subject-equals-repo and nothing else.
The reference gates each write with `permissions.assertRepo({action, collection})`
(`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/repo/applyWrites.ts:119`), the proxy with
`assertRpc` (`/tmp/gap-scratch/atproto/packages/pds/src/pipethrough.ts:68`), identity mutation with
`assertIdentity`.

Four independents enforce the granular grammar: pegasus (666-line engine; call sites
`/tmp/gap-scratch/pegasus/pegasus/lib/api/repo/putRecord.ml:21-24`, `.../uploadBlob.ml:14`), cirrus
(`assertRepo` at `/tmp/gap-scratch/cirrus/packages/pds/src/xrpc/repo.ts:285,367,414,529`, `assertBlob`
at `:622,638`, `assertRpc` at `xrpc-proxy.ts:210`), tranquil (`crates/tranquil-scopes/`, with PAR
refusing mixed transition+granular at `.../endpoints/par.rs:210-227`), and cocoon (`hasRepoScope`,
`/tmp/gap-scratch/cocoon/server/scope_enforcement.go:29-56`, called from all four repo-write
handlers). zds enforces `rpc:` on service-auth minting
(`/tmp/gap-scratch/zds/src/atproto/server.zig:1086`). rsky maps OAuth scopes onto the legacy ladder
and errors on anything granular (`/tmp/gap-scratch/rsky/rsky-pds/src/auth_verifier.rs:842-854`);
dnproto stores scopes and never reads them. atproto-crates is not alone, but it is in the minority.
**MISSING — stable-gap (security-relevant).**

`include:<nsid>` resolution is absent entirely and `com.atproto.temp.dereferenceScope`
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/temp/dereferenceScope.json`) is unrouted — grep of
`crates/atproto-pds/src/` finds no mention of either. cocoon resolves permission sets through indigo
with a negative cache (`/tmp/gap-scratch/cocoon/oauth/scopes/resolver.go:58-99`), pegasus over DNS
`_lexicon.` TXT plus fetched records
(`/tmp/gap-scratch/pegasus/pegasus/lib/lexicon_resolver.ml:36-58`), cirrus with 24 h
stale-while-revalidate caching (`/tmp/gap-scratch/cirrus/packages/pds/src/oauth.ts:145-184`), zds in a
dedicated `/tmp/gap-scratch/zds/src/atproto/oauth/permission_sets.zig`, and tranquil routes
`dereferenceScope` locally (`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/lib.rs:388`).
**MISSING — stable-gap.**

The consent page is the one place granular scopes surface: `describe_scope`
(`crates/atproto-pds/src/oauth/consent.rs:377-401`) renders friendly prose for `atproto`,
`transition:*`, and `space:*`, and everything else — `repo:app.bsky.feed.post`, `rpc:*`, `blob:*/*`,
`account:email`, `include:…` — falls through to ``"request access to scope `<s>`"`` at `:400`.

## 11. Authorization response delivery

`GET /oauth/authorize` renders a hand-rolled consent page that only `peek`s the PAR row
(`crates/atproto-pds/src/oauth/consent.rs:43-78`). Submission is inline JavaScript POSTing JSON, and
the *browser* performs the redirect via
`window.location = body.redirect_uri + "?code=…&state=…&iss=…"` (`:305-333`). RFC 9207's `iss` is
present, which is right, but the server never issues a 302 and there is no `response_mode` support.
Two consequences: a denial returns HTTP 403 with an `"access_denied"` JSON body
(`crates/atproto-pds/src/oauth/authorize.rs:62-68`) instead of redirecting back to the client with
`error=access_denied` as RFC 6749 §4.1.2.1 requires, so a waiting client hangs; and the whole flow
requires JavaScript. Every comparison AS redirects server-side — zds builds and 302s both success and
error (`/tmp/gap-scratch/zds/src/atproto/oauth.zig:347-368`, `:767-778`), pegasus returns `iss` on
allow and deny (`/tmp/gap-scratch/pegasus/pegasus/lib/api/oauth_/authorize.ml:225-229,244-248`).
**DIVERGENT — stable-gap.** (The denial branch is `crates/atproto-pds/src/oauth/authorize.rs:59-65`.)

`POST /oauth/authorize` is also where the user's identifier and password are submitted
(`crates/atproto-pds/src/oauth/authorize.rs:107-125`) and it carries **no rate limit** and no CSRF
token (`crates/atproto-pds/src/oauth/consent.rs:280-303`). Scope this precisely: atproto-crates does
have a real sliding-window limiter and *does* apply it to `/oauth/token`, keyed
`oauth-token:{client_id}` (`crates/atproto-pds/src/oauth/token.rs:104-114`), so the gap here is
coverage rather than capability — PAR (`par.rs:132-144`) and `POST /oauth/authorize`
(`authorize.rs:47-57`) take no limiter, and the token bucket is keyed on caller-supplied input
rather than on the client IP. tranquil rate-limits both PAR and token with typed extractors
(`.../endpoints/par.rs:52`, `.../token/mod.rs:23`). **MISSING (on PAR and authorize) —
stable-gap.**

## 12. Where atproto-crates is ahead of the independent field

**RFC 9101 signed request objects (JAR).** `crates/atproto-pds/src/oauth/par.rs:258-400` accepts a
`request` JWS at PAR, resolves the client's `jwks`/`jwks_uri` (`:405-457`), accepts
`ES256|ES256K|ES384` (`:285-294`), enforces `iss == client_id` (`:311-319`) and `exp`/`nbf`
(`:332-350`), and verifies the signature (`:372-378`). The reference implements JAR (`decodeJAR`,
defined at `/tmp/gap-scratch/atproto/packages/oauth/oauth-provider/src/oauth-provider.ts:454`,
invoked at `:503` and `:579`); **not one of
the ten independents does** — a `request_object` grep across all of them returns only metadata
declarations in cocoon, pegasus, and dnproto. The irony is that atproto-crates does not advertise it
(§9), so no client will use it. The embedded `aud` is also advisory only: on mismatch the code logs at
debug and continues (`par.rs:383-397`), where RFC 9101 §4 makes it a MUST-verify, so a request object
minted for PDS-A is replayable at PDS-B. **Ahead, with a DIVERGENT sub-finding (stable-gap).**

**`space:` scopes with human-readable consent.** The 0016 permissioned-data grammar is parsed and
enforced at ~37 call sites (`crates/atproto-pds/src/http/space_handlers.rs`) — with the caveat that
the `assert_space_scope` wrapper returns `Ok(())` outright for any non-OAuth subject, so
app-password sessions bypass space-scope enforcement entirely (`space_handlers.rs:1866-1868`) —
and the consent page goes
further than anyone: it resolves space-owner DIDs to bidirectionally-verified handles and space-type
NSIDs to their declaration `name`, so a user sees people and spaces rather than DIDs
(`crates/atproto-pds/src/oauth/consent.rs:80-110,412-464`). Only two other projects have a `space:`
grammar at all — zds, which enforces it (`/tmp/gap-scratch/zds/src/internal/scopes.zig:64`, called
from `/tmp/gap-scratch/zds/src/atproto/space.zig:173,1251`) and even expands `include:` into space
scopes (`.../oauth/permission_sets.zig:636-640`), and rsky, whose module is explicitly "pure: parsing
and matching only… wiring scopes to sessions is the A7 OAuth track's concern"
(`/tmp/gap-scratch/rsky/rsky-pds/src/space_scope.rs:1-10`). See the
[permissioned-data overview](../permissioned/40-permissioned-overview.md).

Two smaller points of parity-or-better: `/oauth/jwks` publishes real keys with RFC 7638 `kid`s where
cirrus deliberately publishes an empty set and pegasus has no JWKS route; and refresh rotation is
SQL-persisted rather than in-memory (`crates/atproto-pds/src/oauth/state.rs:188-197`, wired at
`crates/atproto-pds/src/bin/pds.rs:598`).

## Findings

| # | Finding | Class | Severity |
|---|---|---|---|
| G-1 | PAR/token accept JSON only | DIVERGENT | rc-blocker |
| G-2 | No client auth at `/oauth/token`; caller picks its own `cnf.jkt` | MISSING + DIVERGENT | rc-blocker (security) |
| G-3 | `redirect_uri` never validated against client metadata | MISSING | rc-blocker (security) |
| G-4 | Non-DPoP sessions break permanently after first refresh | DIVERGENT | rc-blocker (functional) |
| G-5 | Unguarded SSRF on the PAR metadata / `jwks_uri` fetch | MISSING | rc-blocker (security) |
| G-6 | No CORS on any route, incl. protected-resource metadata | MISSING | rc-blocker (browser clients) |
| G-7 | `private_key_jwt` advertised, not implemented | DIVERGENT | stable-gap |
| G-8 | No server-issued DPoP nonces | MISSING | stable-gap |
| G-9 | `require_dpop_bound_access_tokens: true` not enforced | DIVERGENT | stable-gap |
| G-10 | Access-token revocation is a no-op | PARTIAL | stable-gap (security-relevant) |
| G-11 | AS metadata omits nine fields clients read | PARTIAL | stable-gap |
| G-12 | Granular scopes accepted and ignored outside `space:` | MISSING | stable-gap (security-relevant) |
| G-13 | `include:<nsid>` unresolved; `dereferenceScope` unrouted | MISSING | stable-gap |
| G-14 | Inbound access tokens: `aud`/`iss` unchecked | MISSING | stable-gap |
| G-15 | One symmetric secret signs four token classes; JWKS verifies none | DIVERGENT | stable-gap |
| G-16 | Authorization response is JSON + JS; denials never reach `redirect_uri` | DIVERGENT | stable-gap |
| G-17 | JAR request-object `aud` advisory; JAR unadvertised | DIVERGENT | stable-gap |
| G-18 | 60 s PAR and authorization-code lifetimes | DIVERGENT | stable-gap |
| G-19 | `POST /oauth/authorize` unrate-limited, no CSRF token | MISSING | stable-gap |
| G-20 | Protected-resource metadata missing three fields | PARTIAL | cosmetic |

Evidence and comparison for each live in the section named. Consequences of the six blockers:

- **G-1** (§2, `oauth/par.rs:132-135`, `oauth/token.rs:100-103`) — every `@atproto/oauth-client-*`
  request returns 415; the whole stack is unreachable. Highest-value, lowest-effort fix in the report.
- **G-2** (§5, `oauth/token.rs:100-124,176,188-234`) — a stolen authorization code is redeemable by
  anyone and bindable to the attacker's key; a leaked refresh token is bearer-usable despite carrying
  `cnf`. Chained with G-3 this is full account takeover.
- **G-3** (§3, `oauth/par.rs:202-223`, `oauth/authorize.rs:127-139`, `oauth/consent.rs:325-331`) —
  authorization-code exfiltration via a trusted `client_id` with an attacker-chosen redirect. All ten
  independents constrain this.
- **G-4** (§6, `oauth/token.rs:290,230,246-248,298`; `http/auth.rs:179`; `oauth/dpop.rs:81-87`) —
  silent, unfixable `InvalidDpopProof` for any client that does not send `dpop_jkt`.
- **G-5** (§3, `oauth/par.rs:409-413,414-415,426-433`) — an unauthenticated caller drives the PDS to GET
  arbitrary internal URLs. Alteran guards the identical fetch.
- **G-6** (§9, `oauth/metadata.rs:85-93`, `http/router.rs:442-447`) — browser OAuth clients fail
  discovery before PAR is attempted. Independent of G-1.

Among the stable-gaps, three carry security weight even though none blocks a correct client: G-10
(a revoked access token keeps working for its remaining 900 s while the endpoint reports success),
G-12 (`scope=atproto` alone can write every collection, rotate the handle, and proxy arbitrary
AppView calls, so least privilege is unavailable to clients that ask for it), and G-14 (cross-realm
token acceptance wherever `PDS_JWT_SECRET` is shared). G-7, G-9 and G-11 are all cases of the
metadata document promising more than the server delivers, which is the cheapest cluster to fix
because two of the three are one-line honesty edits. G-20 is the only cosmetic entry.

Six rc-blockers, thirteen stable-gaps, one cosmetic. G-1, G-6, G-18 and G-19 are interop or usability
problems; G-2, G-3 and G-5 are exploitable security defects; G-4 is a functional break.

## Confidence & unknowns

Everything asserted about atproto-crates was read at the cited line in this pass; G-1 through G-4 were
additionally re-opened against the orchestrator's independent verification
(`/tmp/gap-scratch/verified-commit-divergences.md`, O1–O4). Comparison claims were read in source for
tranquil-pds, cocoon, rsky-pds, metalbear, zds, and alteran; for cirrus, pegasus, and dnproto I relied
on the impl-notes' file:line citations for narrative points and verified the specific matrix cells by
direct grep. The brief's "rsky-pds's OAuth is reportedly partial" framing is **wrong** and corrected
here: `rsky-oauth` is a 6,866-line provider with `private_key_jwt`, `redirect_uri` validation, DPoP
nonces, and complete metadata (`/tmp/gap-scratch/rsky/rsky-oauth/src/{client,provider,dpop}.rs`),
mounted at `/tmp/gap-scratch/rsky/rsky-pds/src/lib.rs:427-437`.

Open items:

- **No end-to-end reproduction.** G-1 through G-5 are source-read conclusions. Confirming them would
  need a live PDS plus a scripted PAR → authorize → token exchange with a real
  `@atproto/oauth-client-node`. G-1 should reproduce trivially (415) and G-3 with a crafted PAR body;
  G-2 needs a captured code to demonstrate cleanly.
- **metalbear's PAR content-type.** Its token endpoint definitively handles form encoding
  (`/tmp/gap-scratch/metalbear/src/oauth_routes.c:344-371`), but PAR reads the pre-parsed
  `req->params` cJSON object (`:198`) and the `wf_xrpc` server that populates it is an external
  dependency not vendored into the repo. Recorded `~` rather than `Y`.
- **Third-party verifiability of access tokens** across cocoon, rsky, zds, dnproto, and alteran was
  not established key-by-key; those cells are `?`.
- **dnproto's default-off OAuth.** `FeatureEnabled_Oauth` is `false`
  (`/tmp/gap-scratch/dnproto/src/pds/Installer.cs:140`), so its rows are recorded `~` for
  availability even where the implementation itself is complete.

## Cross-links

[README](../README.md) ·
[inventory](../00-atproto-crates-inventory.md) ·
[coverage matrix](../20-coverage-matrix.md) ·
[synthesis and roadmap](../50-synthesis-and-roadmap.md) ·
[permissioned-data overview](../permissioned/40-permissioned-overview.md)

Implementation notes: [bluesky-reference](../impl-notes/bluesky-reference.md) ·
[tranquil-pds](../impl-notes/tranquil-pds.md) · [cocoon](../impl-notes/cocoon.md) ·
[rsky-pds](../impl-notes/rsky-pds.md) · [metalbear](../impl-notes/metalbear.md) ·
[cirrus](../impl-notes/cirrus.md) · [arroba](../impl-notes/arroba.md) ·
[pegasus](../impl-notes/pegasus.md) · [alteran](../impl-notes/alteran.md) ·
[zds](../impl-notes/zds.md) · [dnproto](../impl-notes/dnproto.md)
