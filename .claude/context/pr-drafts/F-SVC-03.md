# fix(pds): type service-auth JWTs as JWT and gate what they may authorise

## What and why

Four changes that had to land together. The `typ` fix alone would have made the other three
exploitable — the same sequencing shape as the OAuth group, and the report says so explicitly in §2:
"Blunted in practice only by F-SVC-03 … **fixing F-SVC-03 without these makes it live**."

**The header.** Service-auth JWTs carried `typ: "at+jwt"`. `@atproto/xrpc-server` throws
`BadJwtType` for exactly that value, so every token this PDS minted was refused by the Bluesky
AppView, by Ozone, and by any service built on that library — before the signature was checked.

**What the header was hiding.** A service-auth token authorises another service to act for the
account. `getServiceAuth` applied no gate to what it authorised.

## Evidence

### Before

| Site | |
| --- | --- |
| `http/service_auth_handlers.rs:35` | `const TYP_SERVICE_AUTH: &str = "at+jwt"` |
| `http/proxy_handlers.rs:306`, `identity_handlers.rs:327`, `moderation_handlers.rs:175`, `space/mint_authz.rs:490` | four more literals |
| `space/service_auth.rs:28` | the verifier's constant, same value |
| `http/service_auth_handlers.rs:93-176` | no protected-method, privileged-method or takedown gate anywhere in the handler |
| `space/service_auth.rs:151-157` | `if let Some(lxm) = claims.lxm` — compares only when present |
| `http/service_auth_handlers.rs:131-136` | `q.exp.unwrap_or(60).clamp(1,600)` then `iat + ttl` |
| `admin/handlers.rs:855` | writes a blacklist row; `service_auth_blacklist::contains` had no production caller |

Verified against the code, not taken on trust: today any authenticated app-password session can mint
a 600-second, unscoped, unrevocable token for `lxm=com.atproto.server.createAccount`.

### After

- `typ` is `"JWT"` at all five minters and both verifier constants, routed through one constant so
  they cannot drift apart again.
- `PROTECTED_METHODS` — the 16 account-management NSIDs the reference protects — can never be
  reached through service auth.
- `PRIVILEGED_METHODS` — `createAccount` plus the `chat.bsky.*` namespace — require a privileged
  session.
- A taken-down account may mint only `com.atproto.server.createAccount`, deliberately, so a takedown
  cannot strand someone mid-migration but cannot be worked around either.
- Inbound verification requires `lxm` present **and** matching.
- `revokeServiceAuth` takes effect: the verifier consults the blacklist.
- `exp` is an absolute epoch-seconds instant with `BadExpiration` for the past, for beyond an hour,
  and for beyond a minute when no `lxm` scopes the token.

`AccountManager::account_state` is new, mirroring the query already inside `set_state`, so the
takedown gate reads state through the same dual-backend dispatch rather than a SQLite-only shortcut.

## Worked reference

`packages/pds/src/api/com/atproto/server/getServiceAuth.ts:29,45-93` applies all four gates in this
order, with the 16-NSID `PROTECTED_METHODS` and the `PRIVILEGED_METHODS` sets at
`pipethrough.ts:605-630`. `packages/xrpc-server/src/auth.ts:36-39` mints `typ: 'JWT'` and `:88-104`
rejects anything else; `:119-127` treats a missing `lxm` as `BadJwtLexiconMethod`.

Note the reference does **not** require `lxm` at mint — it permits a method-less token but caps it at
a minute, and puts the hard requirement on the verify side. This change follows that split rather
than the stricter reading, so a legitimate method-less token still works.

Protected-method refusal also exists in zds (`server.zig:1083-1085`), tranquil
(`service_auth.rs:139-147`), rsky (`get_service_auth.rs:34-41`) and alteran.

## Testing

Twelve integration tests in `http_phase5_service_auth.rs` and two verifier unit tests. **Eight of
the twelve fail against the previous code**, confirmed by stashing the source changes:

| Test | Closes |
| --- | --- |
| `service_auth_header_is_typed_jwt` | F-SVC-03 |
| `service_auth_refuses_protected_methods` | F-SVC-05 |
| `service_auth_refuses_privileged_methods_to_unprivileged_sessions` | F-SVC-05 |
| `service_auth_restricts_takendown_accounts_to_migration` | F-SVC-05 |
| `service_auth_rejects_expiry_in_the_past` | F-SVC-06 |
| `service_auth_rejects_expiry_beyond_one_hour` | F-SVC-06 |
| `service_auth_caps_method_less_tokens_at_one_minute` | F-SVC-04 / F-SVC-06 |
| `verify_rejects_a_token_with_no_lxm`, `verify_rejects_a_token_scoped_to_another_method` | F-SVC-04 |

The verifier unit tests exercise the claim checks that run before key resolution, so they need no
network and no valid signature.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2029 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**`exp` semantics change is breaking for any caller that passed a lifetime.** A client sending
`exp=120` previously got a two-minute token; it now gets `BadExpiration`, because 120 is an instant
in 1970. This is the correct reading and what eight comparison implementations do, but it is a
visible break. Two existing tests encoded the old behaviour and were rewritten.

`verify_service_auth` gains a parameter for the revocation pool. Both call sites are in
`space_handlers.rs`; passing `None` disables the check, which is what a caller without an account
manager gets.

Tokens minted before this change remain valid until they expire — nothing re-validates old `typ`
values, and the verifier does not yet parse the header at all (F-SVC-08).

## Deliberately out of scope

- **F-SVC-08** — the verifier still ignores the JWS header entirely and performs no `jti` replay,
  `iat` or `nbf` check. The `typ` constant is now correct but nothing verifies it inbound.
- **F-SVC-12** — `aud` is still accepted as any string starting `did:`, not validated as
  `did` or `did#serviceId`.
- **F-SVC-09/10/11** — the proxy path.
- The `chat.bsky.*` list is transcribed from the reference's `CHAT_BSKY_METHODS`; this workspace has
  no chat namespace of its own, so the entries are forward-looking.

## Resolves

`F-SVC-03` (roadmap M1.6) plus `F-SVC-04`, `F-SVC-05`, `F-SVC-06`, `F-SVC-07` (roadmap M2.15), as
one branch per the §2 sequencing constraint.
