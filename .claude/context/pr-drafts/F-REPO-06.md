# fix(atproto-identity): low-S normalize P-256/P-384 and reject high-S

Closes **F-REPO-06**. Milestone M2.9.

## What was wrong

ECDSA signatures are malleable: for every valid `(r, s)` the pair `(r, -s)` verifies just as well, so a signature has two forms and only one of them is canonical. AT Protocol requires low-S.

`k256` normalizes inside its own `SignPrimitive`, which is why K-256 account keys were never affected. `p256` and `p384` ship an **empty** `SignPrimitive` impl (`p256-0.13.2/src/ecdsa.rs:73`), so nothing normalized theirs and `sign` returned whichever form the nonce happened to produce.

**Measured, not assumed.** Signing 64 times with a fresh P-256 key:

```
P256Private produced 27/64 high-S signatures; a peer enforcing low-S
rejects each of them
```

A coin flip, as predicted. So a P-256 key failed roughly half its signatures at random, for the life of the key.

## One thing the report gets slightly wrong

The finding says "the correct helper exists in this very workspace at `crates/atproto-attestation/src/signature.rs:30-80` and the PDS does not use it", implying the fix is to call it.

That helper works, but it is not the right shape for this:

- It covers **P-256 and K-256 only** — `normalize_signature` returns `UnsupportedKeyType` for P-384, which is one of the two curves this finding is about.
- It lives in `atproto-attestation`, which `atproto-identity` does not depend on and should not: the dependency runs the other way.

So the normalization goes where the signature is produced, in `key.rs`. `atproto-attestation`'s helper is left alone — it is a separate public API for callers normalizing signatures they did not produce.

## What changed

`sign` normalizes for all three curves, K-256 included. That last one is a no-op today, but it states the guarantee at the call site rather than inheriting it silently from a dependency's implementation choice — which is precisely the kind of thing that changed for `p256` and was never noticed.

`validate` refuses high-S outright with a new `KeyError::SignatureMalleable` (`error-atproto-identity-key-14`), checked before verification proper. Producing low-S is only half the contract: accepting both forms means anyone holding a valid signature can derive a second, different byte string that also verifies, so "the signature over this commit" is not a unique value — the property anything content-addressing or deduplicating a signature depends on.

## ⚠️ Verification is stricter

`atproto-identity` is a published library other projects sign with, so this was never limited to this PDS.

A high-S signature produced by an **older version of this crate**, or by another implementation that does not normalize, is now **rejected** where it previously passed. Any P-256 or P-384 signature this workspace has already written down and retained — roughly half of them — will fail to verify against the new code.

I did not find such a store in this repository: account keys default to K-256, and the attestation path already normalized. But a downstream user of the library may have one, and that is the upgrade hazard worth naming.

## Tests

Both **verified red** before the change:

```
every_signature_is_low_s ......... FAILED
  P256Private produced 27/64 high-S signatures
a_high_s_signature_is_refused .... FAILED
  P256Private accepted a high-S signature, so a signature is not a unique value
```

`every_signature_is_low_s` signs **64 times** per curve rather than once. A single signature is low-S half the time by luck, so a one-round test would have passed against the unfixed code on a coin flip — the odds of 64 consecutive coincidences are about 1 in 2^64.

`a_high_s_signature_is_refused` derives the high-S counterpart of a real signature and asserts it is refused. It flips conditionally, because before the fix `sign` returned either form at random and an unconditional flip landed on low-S half the time.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2132 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

`atproto-identity::key` — `sign` and `validate` — plus one new error variant. Every crate in the workspace that signs or verifies goes through these, and all 2132 tests pass, which includes the MST commit-proof vectors and the attestation suite.

One `#[allow(deprecated)]` on the new helper: the bound `Signature::s` requires reaches `ArrayLength` only through `elliptic_curve`'s re-export, which is deprecated pending that crate's own generic-array 1.x migration. Dropping the bound does not compile, and duplicating the check per curve would be three copies of one line. Suppressed with the reason written down rather than worked around.

## Not fixed here

- **F-REPO-07** — `RepoConfig::verify_signatures` is still dead: declared, defaulted to `true`, read nowhere. A knob that reads as a safety guarantee and is inert. Separate finding, adjacent enough to be worth doing soon.
- `atproto-attestation::normalize_signature` still rejects P-384. Now that signing normalizes, nothing in this workspace depends on it for correctness, but it is a public API with a gap.
