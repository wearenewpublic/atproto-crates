# fix(oauth): accept form encoding, validate redirect_uri, and bind tokens to a proven DPoP key

## What and why

Three defects that had to be fixed together, because fixing the first alone makes the other two
reachable.

**The wall.** `/oauth/par` and `/oauth/token` took `Json<T>` extractors, while RFC 9126 §2 and
RFC 6749 §4.1.3 specify `application/x-www-form-urlencoded` — which is what every standard AT
Protocol OAuth client sends. `@atproto/oauth-client-node` and `-browser` received HTTP 415 before
any handler ran, so an extensively implemented authorization server could not complete a single
flow.

**What the wall was hiding.** An authorization-code exfiltration chain ending in full account
takeover, against any user who could be phished onto a consent URL — and invisible to the victim,
because the `client_id` shown on the consent screen was genuine.

## Evidence

### Before

| Site | |
| --- | --- |
| `oauth/par.rs:132-135` | `Json(input): Json<ParInput>` |
| `oauth/token.rs:100-103` | `Json(input): Json<TokenInput>` |
| `oauth/revoke.rs:39-41` | `Form(input): Form<RevokeForm>` — correct, and shows the inconsistency was unintentional |
| `oauth/par.rs:215`, `:181` | `redirect_uri` taken from input and stored verbatim; **no client metadata fetched on the inline path at all** |
| `oauth/authorize.rs:131` | echoes it back unchecked |
| `oauth/consent.rs:328-331` | consent page JS navigates to it |
| `oauth/token.rs:100-124` | no client authentication, no DPoP proof |
| `oauth/token.rs:176` | `input.dpop_jkt.clone().or(auth.request.dpop_jkt.clone())` — request body wins over the PAR-pinned thumbprint |

### After

- `oauth/extract.rs` — `JsonOrForm<T>`, dispatching on `Content-Type`; applied to both endpoints.
  JSON still accepted.
- `oauth/client_metadata.rs` — client resolution and exact-match `redirect_uri` validation.
- PAR resolves metadata and rejects an unregistered redirect with `invalid_request`.
- `oauth/dpop.rs` — `verify_token_endpoint_dpop`, a token-endpoint proof check.
- Both grants require a proof; the binding comes from the proof and nothing else. The `dpop_jkt`
  request field is **removed**, not merely deprioritised.

## Worked reference

The reference accepts both encodings at PAR, token and revoke
(`create-oauth-middleware.ts:95,135,167`) and its own client sends form encoding
(`oauth-server-agent.ts:236-239`). It throws `Invalid redirect_uri`
(`oauth-provider/src/client/client.ts:339-342`), and all ten independent implementations constrain
the redirect. It cross-checks the proof against the stored `dpop_jkt`
(`oauth-provider.ts:840-848`, session checks at `:933,937-942`).

The loopback client shape follows `oauth-types/src/oauth-client-id-loopback.ts` and
`atproto-loopback-client-metadata.ts`: `http://localhost[/][?scope=…&redirect_uri=…]`, no path or
fragment, defaulting to `http://127.0.0.1/` and `http://[::1]/` — `localhost` deliberately excluded
from the defaults because it may not resolve to the loopback interface.

## Testing

Five integration regressions in `http_phase4_oauth.rs`, **each confirmed failing against the
previous code** by stashing the source changes and re-running:

| Test | Closes |
| --- | --- |
| `par_rejects_redirect_uri_not_registered_by_the_client` | F-OAUTH-03 |
| `token_rejects_request_without_a_dpop_proof` | F-OAUTH-02 |
| `token_rejects_a_dpop_key_other_than_the_one_pinned_at_authorization` | F-OAUTH-02 |
| `refresh_rejects_a_dpop_key_other_than_the_bound_one` | F-OAUTH-02 |
| `par_and_token_accept_form_encoding` | F-OAUTH-01 |

Plus 12 unit tests: 4 on the extractor (form, JSON, `charset` parameter, malformed body) and 8 on
client resolution — including that a registered `https://app.example/cb` matches neither
`https://app.example.attacker.test/cb` nor `https://app.example/cbx`, and that five hostile
`client_id` forms are rejected before any request is issued.

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` are green — **2020 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**Two behaviour changes callers will notice, both intended:**

1. `token_type` is now `DPoP` rather than `Bearer` on every issued token, because every grant now
   presents a proof. This is what the server's own `require_dpop_bound_access_tokens: true`
   metadata has always advertised; it was previously advertised and not enforced (F-OAUTH-09).
2. A `client_id` must now be resolvable — an HTTPS URL serving a metadata document, or a loopback
   identifier. A client using an unreachable `client_id` will now fail at PAR. That is the fix
   working.

**This widens an existing SSRF sink and is guarded accordingly.** Previously only the JAR path
fetched a caller-supplied URL; PAR now always does. Both the `client_id` and any `jwks_uri` reached
through it pass `atproto_identity::validation::validate_service_endpoint` first — the guard the
workspace already had and the PDS never called. It is syntactic: no DNS resolution, so it does not
stop rebinding or a public name pointing into a private range.

Existing OAuth tests needed updating: they now use a loopback `client_id` (no network) and attach
real DPoP proofs. That is test churn from correct enforcement, not from a change of intent.

## Deliberately out of scope

- **F-OAUTH-05 in full** (M2.11). Only the fetches this change adds are guarded. The JAR-path
  `jwks_uri` fetch in `par.rs` and the spaces attestation fetches in `space/mint_authz.rs` and
  `http/space_handlers.rs` are untouched.
- **F-OAUTH-04** — `issue_pair` still stores `dpop_jkt.unwrap_or_default()`. Unreachable now that
  every token is bound, but the `unwrap_or_default` remains and is M2.5.
- **F-OAUTH-06** (CORS), **F-OAUTH-07/09** (metadata honesty), **F-OAUTH-12** (scope enforcement),
  **F-OAUTH-19** (CSRF on the consent POST).
- `private_key_jwt` is still advertised and unimplemented (F-OAUTH-07). Client authentication here
  is the DPoP proof, which is what a public AT Protocol client has.

## A correction to the gap analysis

F-OAUTH-02 states the token endpoint never checks `redirect_uri`. It does — `token.rs:154`
(now `:176`) already compared it against the stored value. The defect was the DPoP binding, not the
redirect check at that endpoint.

The report also names `crates/atproto-identity/src/host.rs` as "the workspace SSRF guard"; that
module extracts hosts from `did:web`/`did:webvh` identifiers. The URL-level guard is
`validation::validate_service_endpoint` (`validation.rs:741`), which is what this change uses.

## Resolves

`F-OAUTH-01`, `F-OAUTH-02`, `F-OAUTH-03` (roadmap M1.4 + M2.1 + M2.2, shipped together as §5
requires).
