# fix(atproto-pds): harden the admin password check

Closes **F-MOD-04**. Milestone M2.7.

## What was wrong

One shared secret guards every admin verb. It was comparable by timing, guessable without limit, and — in any deployment that had not set `PDS_PRODUCTION=true` — published in this repository.

All three parts confirmed exactly as filed.

### Non-constant-time compare

`admin/handlers.rs:80` and `admin/dashboard.rs:71` both used `!=` on `&str`. That short-circuits at the first differing byte, so how long a rejection takes reveals how much of the prefix was right — enough to recover the secret a byte at a time against an endpoint an attacker can call repeatedly.

Both now call one shared `secret_eq` in `security.rs`. It MACs each side under a key generated for that call and compares through HMAC's own verifier, which is constant-time in the contents **and** independent of length — a 4-byte guess and a 400-byte guess take the same path, so neither the password nor its size leaks. One helper rather than two, so the two surfaces cannot drift apart.

The workspace already used this idiom (`account/session.rs:131`, `atproto-space/src/commit.rs:180`) and `hmac` was already a dependency, so this needed no new crate.

### No rate limit

An attacker who can guess without limit does not need a side-channel at all — this is the larger of the two problems, and the one the roadmap line omits.

Both surfaces now pass through the same sliding-window limiter that already guards `/oauth/token`, before any comparison happens. That makes `require_admin` async, hence the mechanical `.await` at its 20 call sites.

### A live default password

`admin-default-CHANGE-ME` is a `const` in this crate. It was refused only inside `if config.production` (`config.rs:52-58`), so **forgetting `PDS_PRODUCTION=true` selected the insecure branch** — the wrong way round for a default, and the flag's own help says "Set this in production", so the safe path was opt-in.

Startup now refuses the sentinel everywhere unless `PDS_ALLOW_DEV_DEFAULTS=true` asserts the deployment is unreachable by anyone else. That opt-in is itself refused alongside `PDS_PRODUCTION`, so it cannot become a production escape hatch.

## ⚠️ Operators and developers

**A PDS with no `PDS_ADMIN_PASSWORD` set now fails to start.** Set a real password, or set `PDS_ALLOW_DEV_DEFAULTS=true` for a local instance. This is deliberate: absence of configuration used to fail open.

## Tests

`dev_admin_password_refused_without_an_explicit_opt_in` — **verified red** by neutralising the new check:

```
called `Result::unwrap_err()` on an `Ok` value: ()
```

Plus `dev_admin_password_allowed_with_an_explicit_opt_in` and `the_dev_opt_in_cannot_be_combined_with_production`.

`admin_auth_still_distinguishes_right_from_wrong` goes through the real router with five passwords: exact, wrong, a prefix of the real one, the real one extended by a byte, and empty.

**The timing property itself is not asserted.** A timing measurement in CI is noise, not evidence; the guarantee comes from using HMAC's verifier rather than from a benchmark. What the test pins is the property a constant-time rewrite can silently destroy — that the comparison still tells right from wrong. An always-false comparison leaks nothing and locks everyone out; an always-true one leaks nothing either. Neither would show up in a timing test.

`dev_secret_accepted_outside_production` asserted the behaviour this change reverses. It is about the *JWT* sentinel and passed only because both sentinels were permitted together; it now uses a real admin password and is renamed `dev_jwt_secret_accepted_outside_production` for what it actually tests.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo clippy -p atproto-pds --all-targets --features clap -- -D warnings` — clean
- `cargo test --workspace` — **2125 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

Two auth helpers, one config validator, one new env var, and 20 mechanical `.await` additions in `admin/handlers.rs`.

The startup refusal is a breaking change for any deployment relying on the default password — which is the point, but it will stop an existing unconfigured instance from booting on upgrade.

Both admin surfaces now share one rate-limit bucket (`admin-auth`), so a flood against the dashboard also throttles the XRPC surface. That is intended — they guard the same verbs behind the same secret — but it does mean one attacker can degrade an operator's own access.

## Not fixed here

- **Admin action attribution.** The reference also accepts a moderation-service JWT (`auth-verifier.ts:137-149`) so an admin action can be traced to a person rather than to "whoever had the password". That is a real gap, is not part of this finding, and should be filed.
- **F-MOD-05 through F-MOD-09** — separate M2 items.
- **F-OPS-02 / F-OPS-07** (M2.22) — per-IP rate limiting generally. This bucket is global, not per-IP, so a distributed guessing attempt is bounded in aggregate rather than per source.
