# fix(atproto-pds): require proof of control to claim a DID

Closes **F-ACCT-02**, **F-ACCT-03**, **F-ACCT-15** and **F-SVC-14**. Milestone M2.13.

All four confirmed. They are one mechanism seen from four sides: this server could not *accept* an inbound service-auth token on any canonical endpoint, so it could not tell a migration from a squat — and permitted both.

## What was wrong

`create_account` took `(State, Json)`. **No `Parts` — it could not read a header if it wanted to** (`auth_handlers.rs:81-84`), and used a caller-supplied `did` verbatim (`:184-185`).

So anyone could claim any DID: obtain a session bound to the victim's identity, have this server answer `describeRepo`, `getRepo` and firehose events for it, and permanently deny the victim an inbound migration here. Forged commits fail relay signature verification, so the damage was bounded; the lockout was not.

`reserveSigningKey` was the precursor primitive — unauthenticated, generating a fresh keypair per call and writing a reservation row for whatever `did` the caller named.

## What changed

A caller-supplied DID requires a service-auth token issued by that DID's **current host**: `iss` is the DID being claimed, `aud` is this server, `lxm` is `com.atproto.server.createAccount`, and the signature is checked against the `#atproto` key in the DID's own document, fetched live. Only whoever controls that identity *today* can move it here.

This is also the first canonical endpoint here to accept an inbound service-auth token at all — `verify_service_auth` had two callers, both in Spaces. F-SVC-14 and F-ACCT-02 are the same gap from either side.

**There is deliberately no way to switch it off.** An escape hatch would be set on exactly the deployments that most need the check.

**F-ACCT-03:** a verified migration lands `Deactivated`. Landing `Active` left the repository publicly readable and emitting firehose events before the DID document pointed here, and left `activateAccount` with nothing to gate.

**F-ACCT-15:** `reserveSigningKey` is session-gated, restricted to the caller's own DID, and genuinely idempotent. The row id was a millisecond timestamp, so the *first* reservation was kept while every later call returned a **different** key — what was handed out and what was reserved diverged after the first request. A repeat call now returns the reserved key.

## What this costs `did:web` and PLC-less deployments

Worth stating, because it is the part with no workaround.

Verification resolves the DID document live: `https://plc.directory/{did}` or `https://{host}/.well-known/did.json`. A DID that cannot be resolved is a DID whose control cannot be demonstrated.

- **Migrating in** an existing identity: unaffected. The current host mints the token, as the canonical flow intends.
- **A new `did:web` on a fresh server**: workable. The operator controls the document — publish `did.json` with an `#atproto` key they hold, self-sign the token, then create → import → `reserveSigningKey` → repoint the document → activate.
- **Local development**: `did_host` rejects IP literals and the reserved `.localhost`/`.internal`/`.arpa`/`.local` suffixes (`host.rs:194-215`), and resolution is always HTTPS. So `did:web:localhost%3A3000` cannot be verified by construction. A developer needs a publicly-resolvable DID or must create accounts through the internal API.

## Tests

`createAccount` with an unproven DID is refused (`create_account_with_an_unproven_did_is_refused`, `migration_create_account_requires_service_auth`); `reserveSigningKey` refuses an anonymous caller and returns a stable key across repeat calls.

**The test migration is the bulk of this diff.** 20 files, ~164 `build_app()` sites, ~95 `create_account` sites. Fixture accounts are created through `AccountManager` instead of the XRPC endpoint, because no test can produce a verifiable token — there is no live identity to resolve.

**That is not a bypass.** No production path skips the check; `AccountManager::create_account` is the same API the handler calls *once it has verified*. Tests using it are doing authorisation out of band, which is what fixture setup is. Where `createAccount` itself is the subject, the tests call the endpoint and assert the refusal.

One genuine coverage change: `invite_redemption_records_real_did_not_placeholder` now exercises `invite::redeem` directly. Invite-gated signup normally takes the PLC-genesis path, which the harness has no directory for; the test's subject — what `redeem` writes to `used_by` — is unchanged.

## A refactor that fell out

`createSession` verifies against an app-password row, never against `account.password_hash`, so an account without one exists and cannot log in. That two-step dance was inline in the handler, meaning every other caller had to know it. It is now `AccountManager::set_primary_password`.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2147 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

Production: `create_account` gains `Parts` and a verification branch; `CreateAccountParams` gains `state`; `AccountState` gains `Default`; `reserve_signing_key` gains a guard, a subject check and an idempotent lookup; `AccountManager` gains two methods.

**Operationally this is a real gate.** Any tooling that created accounts by POSTing a DID will now get `401 AuthRequired` unless it presents a service-auth token from that DID's current host.

## Not fixed here

- **F-ACCT-06** — `deleteAccount` is single-factor on an emailed token, with no `did`/`password` binding.
- **F-ACCT-08** — `createInviteCode` is gated by an ordinary user session, and issuance defaults enabled.
- **F-ACCT-07** — `checkAccountStatus.validDid` is still hardcoded `true`, so a migration tool cannot tell when the DID document actually points here.
