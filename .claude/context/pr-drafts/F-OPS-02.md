# feat(atproto-pds): per-IP rate limiting across every route

Closes **F-OPS-02**, **F-OPS-07**. Milestone M2.22.

## What was wrong

The limiter was never broken. `SlidingWindowLimiter` works, has three backends, and is GC'd. What was missing was a caller it could bound.

| | Now on `main` |
|---|---|
| call sites | **6**, not the report's 4 — `admin-auth` was added by M2.7 (#23) |
| bucket keys | `createSession:{identifier}`, `createAccount:{handle}`, `requestPasswordReset:{email}`, `oauth-token:{client_id}` — every one caller-supplied |
| middleware | none. `router.rs:479,543-544` is CORS and the optional metrics pair |
| client address | `grep -rn "ConnectInfo\|[Xx]-[Ff]orwarded"` over `src/` returned **nothing**; `bin/pds.rs:807` was plain `axum::serve(listener, app)` |

So a password sprayer varied `identifier` for a fresh bucket per attempt, and a signup flood varied `handle`. **The limiter did not bound the attack it most resembles a defence against.** Everything else — all repo writes, all of sync, `subscribeRepos`, the whole spaces namespace, `/oauth/par`, `/oauth/authorize`, every admin route — had no limit at all.

## What changed

A middleware applying a per-IP budget over every route, in **two tiers**. Auth and account-creation endpoints get the tighter one: a hundred `getRecord` calls a minute is a busy client, a hundred `createSession` calls a minute is someone guessing. Separate limiter instances, so a flood on one cannot consume the other's budget.

**The existing per-identifier limits stay.** They bound a single account attacked from many addresses, which a per-IP limit cannot see. The finding was that they were the *only* limit, not that they were wrong.

## Where the address comes from — the decision that matters

**`X-Forwarded-For` is ignored by default.** A header any client can set is not an identity. Trusting it would hand every caller a private bucket, which is *worse* than no limit because it reads as a defence.

`PDS_TRUSTED_PROXY_HOPS=N` takes the address *N* entries from the right. Counting from the right is what makes the value trustworthy: each trusted proxy appends the address it saw, so the rightmost *N* entries were written by infrastructure the operator controls and everything left of them is caller-supplied text. A chain shorter than configured, or an unparseable entry, falls back to the peer address rather than believing a header that does not match what the operator described.

`into_make_service_with_connect_info` is what puts the peer address in request extensions. Without it the limiter would have had no address to key on and would have silently limited nothing — the same failure shape as the one being fixed.

## Two more decisions

**Layered outside the router**, so a scan of a hundred nonexistent paths costs the scanner its budget rather than costing nothing because none of them matched.

**No peer address means no limit**, not a refusal. In-process callers and test harnesses have no socket; refusing those breaks the caller rather than an attacker.

## `requestPasswordReset` was fail-open

`let _ = try_acquire(...)` — the result was discarded, so the limit was decorative. Reset mail goes to an address the requester does not have to control, which made this a mail cannon pointed at a third party. Now fail-closed, returning the same 429 the middleware does.

## F-OPS-07 — the untunable knobs and the volatile default

`PDS_RATE_LIMIT`, `PDS_RATE_LIMIT_AUTH`, `PDS_RATE_LIMIT_WINDOW_SECS`, `PDS_RATE_LIMIT_BYPASS_IPS`, `PDS_TRUSTED_PROXY_HOPS`. The bypass list is the one the report names specifically: without it an operator must choose between limiting attackers and letting their own relay work.

**`PDS_DURABILITY_PROFILE=memory` is now refused under `PDS_PRODUCTION=true`.** The memory backend keeps the OAuth replay guard and every bucket in process, so a restart makes single-use refresh tokens replayable and hands an attacker mid-flood a fresh budget. `security.rs:10-12` has said so since it was written; `config.rs` never checked. Valkey satisfies the gate too, and is reported as the effective profile when a URL is configured rather than whatever was typed in the flag.

The per-IP tiers use the same backend as everything else. On a multi-node deployment a rate limit that is not shared across nodes is a rate limit multiplied by the node count.

## Tests

20 new: 7 unit on address resolution, 3 on the production gate, 10 acceptance. **9 of 10 acceptance tests verified red** by neutralising the middleware layer and restoring the fail-open:

```
an_ordinary_read_path_is_limited_per_address ................... FAILED
two_addresses_get_independent_budgets .......................... FAILED
a_spoofed_forwarded_header_cannot_buy_a_fresh_bucket ........... FAILED
with_a_trusted_proxy_the_header_is_the_key ..................... FAILED
a_bypassed_address_is_never_limited ............................ FAILED
the_auth_tier_trips_before_the_global_one ...................... FAILED
a_password_sprayer_cannot_escape_by_varying_the_identifier ..... FAILED
request_password_reset_is_now_fail_closed ...................... FAILED
an_unrouted_path_still_costs_budget ............................ FAILED
```

The tenth, `a_request_with_no_peer_address_is_not_refused`, stays green by design — it asserts the *absence* of limiting, and would pass against a middleware that refused everything only if that middleware also had no address, which is the case it pins.

`a_password_sprayer_cannot_escape_by_varying_the_identifier` is the finding stated as a test: three login attempts against three different victims from one address, and the fourth is refused. Under the old keying every one of them got a fresh bucket.

`a_spoofed_forwarded_header_cannot_buy_a_fresh_bucket` is its counterpart for the header. The unit tests cover hop selection as **known-answer** against a multi-entry chain, including a forged prefix — off-by-one there is the whole vulnerability.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2250 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **725 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius — two breaking changes, both intended

1. **Every route is limited.** Anything doing bulk work from one address — a migration script, a test harness, a backfill, a relay — will start seeing 429s at the default 300/60s. `PDS_RATE_LIMIT_BYPASS_IPS` is the answer and ships with it.
2. **A production deployment on the default durability profile will not boot.** Same call as refusing the default admin password in #23.

An operator behind a reverse proxy who does not set `PDS_TRUSTED_PROXY_HOPS` gets one shared bucket for their whole user base. That is loud and safe rather than quiet and wrong, and the startup log says which mode is active.

`with_rate_limit` is a separate function from `build_router`, so every existing test builds an unlimited router and a test that *is* about limiting opts in explicitly.

## Not fixed here

- **F-OPS-17** (M4.3) — the error name is still `RateLimited`; the lexicon's is `RateLimitExceeded`, and no `RateLimit-*` headers are emitted. Both belong to that item.
- **The `admin-auth` bucket is a fixed key**, so it is a global lockout lever: anyone can exhaust it and deny admin login to the operator. Not in either finding; worth its own.
- Per-route budgets (the reference has them per endpoint) are two tiers here, not per-NSID.
- `subscribeRepos` is limited at connection time only — a long-lived WebSocket costs one request.
