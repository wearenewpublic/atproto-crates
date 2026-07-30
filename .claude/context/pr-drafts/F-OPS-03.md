# fix(atproto-pds): stop logging email bodies, and ship a buildable image

Closes **F-OPS-03**. Milestone M2.3. Also fixes a release-build breakage found while verifying it.

## The finding

`EmailService::Disabled::send` logged the full rendered body at INFO (`email.rs:74-83`). That body carries the confirmation URL — and therefore the token — for password reset, account deletion and email change.

The stub is meant for development and says so. But **the published image always selected it**: `smtp` is not a default feature (`Cargo.toml:130-133`, `default = ["sqlite", "hickory-dns", "http"]`) and the Dockerfile built `-F clap,hickory-dns,zeroize,tokio` (`Dockerfile:31`). So in the only build that ships, every reset token went to the log.

Logs are routinely lower-trust than the credential store they were protecting: shipped to aggregators, mounted into sidecars, swept up by crash reporters, readable by operators. Anyone who could read one could complete a reset for **any** account on the instance.

**The report says two endpoints; it is four.** `auth_handlers.rs:1008` (email update), `:1153` (account deletion), `:1296` (email confirmation), `:1452` (password reset).

## What changed

The body is no longer logged. The recipient and subject still are, so an operator can see that a send was attempted and to whom.

`PDS_EMAIL_LOG_BODIES=true` restores the body for local development — at DEBUG, never INFO — and warns at startup, in as many words, that anyone who can read the log can take over any account.

> I considered gating this on `debug_assertions` instead, which cannot be switched on in a release image at all. I chose the env var because it is discoverable, documented, and matches how everything else here is configured — but it is a strictly weaker guarantee. Say the word and I will make it compile-time.

The image now builds with `smtp`. `lettre` was already pinned to `tokio1-rustls-tls` with `default-features = false` (workspace `Cargo.toml:121`), so no OpenSSL enters the distroless runtime.

An unconfigured mailer now warns at startup rather than noting itself at INFO. That is not pedantry: with no mailer, `requestPasswordReset` and `requestAccountDelete` return success and send nothing, so the flows are broken in a way the caller cannot see.

## The release build did not compile

While verifying the image change I found that **`cargo build --release` failed, so the container could not be built at all** — on `main`, before any of my edits:

```
error[E0277]: `atproto_record::lexicon::Blob` doesn't implement `std::fmt::Debug`
   --> crates/atproto-pds/src/http/write_handlers.rs:539:5
```

Seven crates derived `Debug` under `#[cfg_attr(any(debug_assertions, test), derive(Debug))]` — 60 sites. That makes a public type implement the trait in a debug build and not in a release one. `atproto-pds` derives `Debug` on `UploadBlobResponse`, which holds a `BlobRef`, so the Dockerfile's exact command failed.

Tests, clippy and CI all run the dev profile. Nothing in this repository had ever built in release mode, which is why it survived 16 merged PRs.

`Debug` is now unconditional at all 60 sites. A published type that implements a trait only in debug builds is a latent break for **every downstream consumer**, not just this workspace — and these are published library crates.

CI gains a release-profile step using the Dockerfile's own feature set, so an image that cannot be built fails CI rather than the release.

This was a scope expansion, agreed before I made it: adding `smtp` to an image that does not build is not a fix anyone could verify.

## Tests

Four tests in `email.rs` install a capturing `tracing` subscriber and assert on the events actually emitted, rather than on the code that emits them. Three were **red before the change**:

```
a_disabled_send_never_logs_the_body ............... FAILED
  an email body reached the log:
  Captured { level: Level(Info), fields: ["message", "to", "subject", "body"] }
the_body_is_logged_at_debug_when_explicitly_opted_in  FAILED
  a message body is never INFO-worthy: left: Level(Info)
an_unconfigured_mailer_warns ...................... FAILED
```

The first one's failure output is the finding itself: `body` sitting in an INFO event's field list.

The release-build fix is verified by stashing only the `Debug` changes and re-running the release check — it fails with the original error, and passes with them.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo clippy -p atproto-pds --all-targets --features smtp -- -D warnings` — clean
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — **clean (was failing on `main`)**
- `cargo test --workspace` — **2117 passed, 0 failed, 63 ignored**
- `cargo test -p atproto-pds --features smtp` — **566 passed, 0 failed**

Docker is not installed here, so the image itself was not built; the verification is the Dockerfile's exact `cargo` invocation, which is the part that was failing.

## Blast radius

Wider than the finding, because of the release fix. `Debug` becomes unconditional on 60 public types across `atproto-record`, `atproto-oauth`, `atproto-client`, `atproto-identity`, `atproto-attestation`, `atproto-jetstream` and `atproto-pds` — additive for consumers, slightly larger release binaries.

Behaviour change for anyone reading reset tokens out of the dev log; `PDS_EMAIL_LOG_BODIES` is the migration path. `walking-club-cluster-plan.md:1338` documented the old feature list and is corrected.

## Not fixed here

- The four endpoints still return success when email is disabled. Making them fail loudly on an unconfigured mailer is a deliberate behaviour change and belongs in its own branch — the startup warning is the interim.
- **F-OPS-04** — still no backup or restore path of any kind.
- The `debug_assertions`-gated `Debug` pattern is gone, but nothing prevents it being reintroduced; the CI release step would catch the consequence, not the cause.
