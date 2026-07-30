# refactor(atproto-pds): make an unbound OAuth token unrepresentable

Addresses **F-OAUTH-04** (M2.5). **The finding was already fixed** — this removes what it left behind.

## Verdict: already fixed by PR #6

The report describes non-DPoP sessions breaking permanently after the first refresh: `issue_pair` stores `dpop_jkt.clone().unwrap_or_default()`, so an absent thumbprint becomes `""`; `handle_refresh` passes it back as `Some("")`; `cnf` becomes `Some(jkt: "")` and `token_type` flips to `"DPoP"`; thereafter `claims.cnf.is_some()` is true and every proof is compared against `""`, which can never match.

Both cited lines still exist. The chain they form does not.

`token_handler:127-128` calls `verify_token_endpoint_dpop` **before dispatching either grant**, and it returns a thumbprint or an error. Both call sites pass it on — `handle_code:222-227`, `handle_refresh:287-292` — and `issue_pair` has exactly those two callers. So `dpop_jkt` was never `None`, `unwrap_or_default()` never produced `""`, and `token_type` was always `"DPoP"`.

That mandatory-proof line is the F-OAUTH-02 fix from PR #6. **It closed F-OAUTH-04 as a side effect.** The report could not have known — both findings were written against the same pre-fix tree, and its own §23 groups them on one mechanism.

More plainly: the class of client the finding is about no longer exists. A client that omits DPoP cannot get a token at all now, so it has no session to break.

## What this changes, and why it is worth a branch

What survived is a trap. `issue_pair` still took `Option<String>`, still had `unwrap_or_default()`, still had `if dpop_jkt.is_some()`. A future caller passing `None` would re-create exactly this bug — an empty-string thumbprint that fails every comparison, with no error at the point of the mistake and a symptom that surfaces one exchange later in a different subsystem.

So: the parameter is `&str`, `cnf` is unconditional, `token_type` is the constant `"DPoP"`. The failure cannot be expressed rather than merely not happening, and the type now says what PR #6 made true.

The report's stated remedy — "store `Option<String>` rather than `unwrap_or_default()`" — is the opposite of this, because it was written when the absent case was real.

## Tests

`a_session_survives_repeated_refreshes_bound_to_one_key` runs the authorization-code exchange and then refreshes **three** times, asserting `token_type == "DPoP"` throughout and that each rotated refresh token still works.

Three rounds rather than one because of how the original failure was shaped: the first refresh minted the poisoned binding and the *next* use of it failed, so a single round trip would have gone green against the bug.

**It passes before this change as well, and I am not going to present it as a reproduction.** The defect is unreachable, so there is nothing to reproduce. What it pins is the property the new type depends on — that a thumbprint is always present and always the real one.

I also wrote a "token endpoint refuses a request with no proof" test before noticing `token_rejects_request_without_a_dpop_proof` already covers it from PR #6, and deleted mine rather than ship a duplicate.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2119 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

One private function and its two callers. No wire change: `token_type` was already always `"DPoP"` in practice, and `cnf` was always populated.

## Not fixed here

- **F-OAUTH-09**, from the same §23 group: the metadata advertises `require_dpop_bound_access_tokens: true`, which the token endpoint now honours — but `require_authn` (`http/auth.rs:179`) still demands a proof only when `cnf.is_some()`. For tokens this server issues that is always true, so the gap is theoretical today; the check still expresses the wrong rule, and would silently accept an unbound token if one ever appeared.
- **F-OAUTH-08** and **F-SVC-09**, also §23, untouched.
