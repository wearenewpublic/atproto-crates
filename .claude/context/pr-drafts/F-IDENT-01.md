# fix(atproto-pds): validate handles and gate PLC signing

Closes **F-IDENT-01**, **F-IDENT-02**, **F-IDENT-03**, **F-IDENT-05**. Milestone M2.19 → **M2.20**.

Also closes **F-IDENT-11** (M4.14), pulled in because M2.20's email-token gate is not implementable without it — see below.

## The four findings, as the code actually stood

| | What the report said | What `main` @ `a355059` showed |
|---|---|---|
| **F-IDENT-01** | no `#identity` on handle change | `emit_identity_event` (`identity_handlers.rs:705`) is private with **one** caller, `refreshIdentity` at `:681` |
| **F-IDENT-02** | `updateHandle` does no validation | `do_update_handle` `:172-297` — raw string → `format!("at://{new_handle}")` at `:250` → signed PLC op |
| **F-IDENT-03** | non-lexicon input, no token gate | input was `{op}` (`auth_handlers.rs:1786`); lexicon declares `{token, services, alsoKnownAs, rotationKeys, verificationMethods}` |
| **F-IDENT-05** | `submitPlcOperation` validates nothing | `:1877-1902` — deserialize, POST |

Line numbers had drifted from the report; the substance had not. The report's `admin/handlers.rs:628` is also the wrong path — it is `crates/atproto-pds/src/admin/handlers.rs:691`.

## F-IDENT-03 — the second factor was handed to whoever held the first

`requestPlcOperationSignature` returned a **service-auth JWT in its response body**. Its lexicon declares no output at all, and describes itself as *"Request an email with a code to in order to request a signed PLC operation."*

So the flow that exists to require something the attacker does not have returned that something to the attacker. A stolen two-hour access token was enough to have this server sign an operation replacing the account's rotation keys — and PLC is append-only, so the server cannot undo it afterwards.

It now mails a 15-minute one-time code and returns no body. `signPlcOperation` requires and consumes it: bound to the account, bound to the flow, single-use. All four failure modes report the same message — a caller probing codes should not learn which of the four it hit.

**This is why F-IDENT-11 came along.** The gate has nothing to check until the endpoint that issues the code actually issues one. M2.20 as written ("plus the email-token gate") is not implementable otherwise.

The infrastructure was already there — `account/email_token.rs` with four purposes and `insert`/`lookup` driving the email-update and password-reset flows. This is a fifth purpose and a `consume` helper, not new machinery.

## F-IDENT-03 — the input shape

The canonical input describes a *change*, not a whole operation. The server fetches the DID's current operation and merges — which it has to, because the caller cannot know `prev`.

`apply_plc_deltas` is a pure function so the merge semantics are testable without a directory. **Replacement per field, not union**: supplying `rotationKeys` replaces the list. A union would make it impossible to *remove* a rotation key, which is the main reason to rotate.

## F-IDENT-02 — any account could claim any handle

No syntax check, no TLD check, no service-domain constraint, no reserved name check, no ownership proof, no uniqueness check. `admin.<the-operator's-domain>` was available to anyone, and so was a domain belonging to someone else — after which this server answers `resolveHandle` for it.

Worse, a collision surfaced as a 500 **after** the PLC operation was submitted, leaving the DID document permanently claiming a handle the local database refused to record.

New `handle.rs`:

- **Syntax** via `atproto_identity::validation::is_valid_handle` — which the workspace has always shipped and the PDS had **never called from anywhere**. The report's framing was right: this is an area where the project arrives with a real asset and fails to spend it.
- **Disallowed TLDs**, mirroring `@atproto/syntax`. Four (`.localhost`, `.internal`, `.arpa`, `.local`) were already rejected by `is_valid_hostname` as SSRF-relevant; the other four are handle policy. `.example` is the one that matters — it reads as a perfectly ordinary handle. `.test` stays allowed, as upstream explicitly allows it for development.
- **Service-domain shape** — single label, 3–18 characters, not reserved.
- **Ownership proof** for anything else: the handle must already resolve back to the claiming DID. Dual DNS-plus-HTTPS when a resolver is wired, HTTPS `.well-known/atproto-did` alone when one is not — weaker, but still a real proof, since it requires controlling the web server the domain points at.
- **Uniqueness**, before the operation rather than after.

The reserved list is 66 names, not the reference's several thousand. It covers what would let a holder impersonate the operator, a protocol role, or mail/DNS infrastructure; the doc comment says it is deliberately smaller and why.

**Ordering is cheapest-first**: syntax → uniqueness → service-shape-or-proof. A malformed handle costs no DNS lookup, and none of it costs a PLC operation. (The reference checks uniqueness last; there is nothing to leak by checking it first, since `resolveHandle` already tells anyone which handles exist here.)

The admin path permits reserved names and nothing else. An operator assigning `support.<their-domain>` to their own support account is doing exactly what the reserved list exists to stop a stranger doing.

## F-IDENT-05 — it forwarded whatever it was given

The lexicon: *"Validates a PLC operation to ensure that it doesn't violate a service's constraints or get the identity into a bad state, then submits it to the PLC registry."* Validation was the one thing it did not do — which makes routing the operation through the PDS at all pointless.

Five constraints now run before the POST, matching `submitPlcOperation.ts:20-52`: the operation lists this server's rotation key, its `atproto_pds` service has the right type and endpoint, its `atproto` verification method is this account's signing key, and its first `alsoKnownAs` is this account's handle.

**The report says the reference performs five checks. It performs six** — the shape check on the operation itself is separate. Counted here as five behavioural constraints plus the type discriminant.

`check_plc_submit` is a pure function taking a `PlcSubmitConstraints`, so all of it is testable without a directory or an account store.

## Tests

25 new. **12 verified red** by neutralising the three fixes in turn:

```
update_handle_refuses_a_syntactically_invalid_handle ............ FAILED
update_handle_refuses_a_disallowed_tld ......................... FAILED
update_handle_refuses_a_handle_another_account_holds ........... FAILED
update_handle_refuses_a_reserved_name_and_a_bad_shape .......... FAILED
update_handle_refuses_an_unproven_external_domain .............. FAILED
sign_plc_operation_refuses_a_code_belonging_to_another_account .. FAILED
sign_plc_operation_refuses_a_code_from_a_different_flow ........ FAILED
sign_plc_operation_refuses_an_expired_code ..................... FAILED
submit_plc_operation_refuses_an_operation_dropping_the_servers_rotation_key ... FAILED
submit_plc_operation_refuses_an_operation_pointing_at_another_host ............ FAILED
submit_plc_operation_refuses_a_mismatched_signing_key_or_handle .............. FAILED
submit_plc_operation_refuses_a_tombstone ..................................... FAILED
```

`sign_plc_operation_refuses_without_a_code` was verified red separately, by neutralising the presence check rather than the consume call.

Two positive controls, because a check that refused everything would pass every refusal test above:

- `a_conformant_operation_is_accepted` (unit)
- `submit_plc_operation_lets_a_conformant_operation_through_to_plc` — satisfies every constraint and asserts the request got *past* validation, then failed at the deliberately unroutable directory. That failure is the proof it was forwarded rather than refused.

The submit tests reach their assertions **without a single network call**, which is the same property the fix has.

**One existing test was deleted rather than adapted.** `request_plc_operation_signature_returns_token` asserted the JWT-in-the-body shape — it pinned the vulnerability. Fifth instance in this series of a test asserting the implementation rather than the specification.

## Not covered by a test, stated rather than glossed

The `#identity` emission on `do_update_handle` and on a **successful** `submitPlcOperation` are covered by inspection only. Both sit behind a PLC round-trip, and `atproto_identity::plc::{fetch_audit_log, submit}` hardcode `https://` (`plc/mod.rs:87,113`), so the harness cannot stand up a directory to drive them. `do_update_handle` also builds its own `reqwest::Client` (`identity_handlers.rs:223`) rather than using the injectable one on `PlcService`, so even a TLS mock would not reach it.

Filed as a new finding candidate in `PROGRESS.md`. The emission itself is one line at each site calling a function `refreshIdentity` already exercises.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2210 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **685 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius — three breaking changes, all deliberate

1. **`requestPlcOperationSignature` no longer returns `{token}`.** The lexicon declares no output. Anything reading that field breaks; that field was the vulnerability.
2. **`signPlcOperation` no longer accepts `{op}`** and requires `token`. The old shape was never conformant — canonical migration clients 400 against it today.
3. **`updateHandle` refuses handles it used to accept.** Malformed, disallowed-TLD, reserved, mis-shaped, taken, and any external domain that does not resolve back to the caller.

Operators without SMTP still see the code: the shipped `EmailService` stub logs it, as it already does for password resets. An account with no email on file gets a token row and a WARN.

## Not fixed here

- **F-IDENT-06** — `activateAccount` does not validate the DID document. Worth noting the report's own correction: *no* implementation blocks activation on missing blobs; the canonical gate is the document check.
- **F-IDENT-07** — `getRecommendedDidCredentials` omits the operator's external rotation key, so a migration following its advice deletes the deployment's fallback recovery key.
- **F-IDENT-08/09/10** — `refreshIdentity` shape, `resolveHandle` normalization, and did:web accounts breaking on the unconditional PLC fetch at `identity_handlers.rs:233`. All M4.14.
- `EMAIL_TOKEN_PURPOSE_RESET` in `auth_handlers.rs` still duplicates `PURPOSE_RESET_PASSWORD` in `account/email_token.rs:30`. I used the module's constant for the new flow rather than adding a third.
- The `consume` helper is used by the new flow only. The email-update and password-reset flows predate it and still check inline; consolidating them is not this branch's job.
