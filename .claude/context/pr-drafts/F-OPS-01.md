# ci: add a CI gate and known-answer interop vectors, and repair the broken lockfile

## What and why

Nothing in this repository ran the test suite. `.github/workflows/` held one file,
`release-binaries.yml`, while `crates/atproto-pds/README.md:29-32` claimed that fmt, clippy and test
were enforced on every push and every pull request, and linked to a `ci.yml` that does not exist.
This adds that gate — on tangled spindle, where the canonical repo and its pull requests live.

Standing the gate up immediately turned up three things that had already shipped in `0.15.0-rc.1`,
including a `Cargo.lock` so damaged that no crate in the workspace builds from a clean checkout.

The larger problem it addresses is that every encoding test here was a **round trip**: encode,
decode, compare. A round trip proves the code agrees with itself and passes just as happily against
a wrong encoding — which is how byte-level divergences reached a release candidate. This vendors the
upstream AT Protocol interop vectors as an external oracle and wires three harnesses to them. They
are red where the workspace is wrong, and they say exactly how.

## Evidence

### Before

| | |
| --- | --- |
| `.github/workflows/` | `release-binaries.yml` only; no `.tangled/workflows/` either |
| `crates/atproto-pds/README.md:29-32` | claims fmt/clippy/test are enforced, links to `.github/workflows/ci.yml` — absent |
| `crates/atproto-repo/tests/` | does not exist; MST coverage is round-trip only (`mst/serialize.rs`, `mst/tree.rs`) |
| `crates/atproto-dasl/tests/dasl-testing/` | empty; `dasl_compliance_test.rs:140` panics `Failed to read …/fixtures/cbor/*.json` |
| `Cargo.lock` | 35 duplicate `[[package]]` stanzas + inconsistent `data-encoding`; `cargo` refuses to parse it |
| `crates/atproto-space/benches/set_hash.rs` | no `[[bench]]` target, no `criterion` dev-dep, imports `XorSha256SetHash` (renamed `LtHash`) from `set_hash_ecmh` (not a declared module) — `clippy --all-targets` fails to compile |
| `crates/atproto-pds/src/sequencer/frame.rs:162-255` | six unit tests; `:206`/`:237` assert `["payload"]["rev"]`, pinning the current envelope rather than the specified one |
| `crates/atproto-pds/tests/` | 23 files, none opens a WebSocket; the only `subscribeRepos` mention is a doc comment at `http_phase8_polish.rs:6` |

Baseline once the lockfile is repaired by hand: `cargo test --workspace --no-fail-fast` →
**1976 passed / 13 failed / 63 ignored**, the 13 being the missing submodule fixtures.

### After

| | |
| --- | --- |
| `.tangled/workflows/ci.yml` | recursive submodule checkout → `fmt --check` → `clippy --workspace --all-targets -- -D warnings` → `test --workspace`, on push to `main` and on pull requests |
| `Cargo.lock` | regenerated; 716 package entries → 577, zero duplicates |
| `crates/atproto-space/benches/set_hash.rs` | deleted |
| `tests/interop/` | `atproto-interop-tests` @ `056e574` (CC-0) + provenance README |
| `crates/atproto-repo/tests/interop_mst.rs` | key heights, common prefixes, commit-proof root CIDs |
| `crates/atproto-dasl/tests/interop_data_model.rs` | canonical DAG-CBOR bytes and CIDs |
| `crates/atproto-pds/tests/interop_firehose.rs` | frame headers vs hand-decoded CBOR, `#commit` body vs lexicon, end-to-end WebSocket |
| `crates/atproto-repo/src/mst/mod.rs:57` | re-exports `common_prefix_len` (needed to drive `mst/common_prefix.json`) |

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` are all green: **1997 passed, 0 failed, 63 ignored.**

## What the oracle says about this workspace

The point of the vectors is that they are not all green, and that is the finding:

| Vector set | Result |
| --- | --- |
| `mst/key_heights.json` | 9/9 pass — `key_height` is correct |
| `mst/common_prefix.json` | all pass |
| `firehose/commit-proof-fixtures.json` | **0 of 6 MST root CIDs match**, before *and* after commit |
| `data-model/data-model-fixtures.json` | 1 of 3 — the two `$link`/`$bytes` fixtures produce wrong bytes and a wrong CID |
| `subscribeRepos#commit` body | carries `["payload", "repo", "seq", "time"]`; the lexicon requires eight further fields flat |

Every MST root CID this server produces differs from what a peer computes. No round-trip test in
this repository could have observed that.

## Known failures, and why they are not `#[ignore]`

Each red vector is listed in a `KNOWN_FAILURES` table naming the defect that explains it, and is
**required to fail**. Three outcomes:

- unlisted vector fails → `REGRESSION`, test fails;
- listed vector fails → `XFAIL`, printed with detail, test passes;
- listed vector **passes** → test fails: *"vector #1 now PASSES — F-REPO-05 appears to be fixed.
  Remove it from KNOWN_FAILURES in this file."*

Both guard directions were verified by temporarily perturbing the table. `#[ignore]` was rejected
because it is silent: a fix landing would make nothing go red, so the entries would rot and nobody
would learn which defect had been closed. This way the suite tells you.

The tables are the handover to the rest of the remediation work — each entry cites the finding and
the roadmap item that will clear it.

## Worked reference

arroba runs the same upstream fixtures as a CI gate
(`arroba/tests/test_testdata.py:26-96`), loading `common_prefix.json`, `key_heights.json` and
`commit-proof-fixtures.json` from a vendored `testdata/` copied from the same repository. indigo
ships `mst_interop_test.go`; the reference implementation carries `interop-test-files/` at its root.
cocoon, rsky, metalbear, cirrus, alteran and zds all run CI. The approach here follows arroba's:
vendor rather than submodule, so a plain `cargo test` works from a fresh clone.

Where this goes further is the `KNOWN_FAILURES` mechanism — arroba's fixtures pass, so it never
needed one; this workspace's do not yet, and a permanently-red or silently-skipped gate would be
worth little.

## Testing

The harnesses *are* the test, and they were confirmed red before any of this landed: the 0/6 and 1/3
figures above were measured against unmodified `main` with throwaway probes before a line was
written. The `#commit` body check reports its failure in the run output today.

The end-to-end firehose test is new coverage rather than a regression test: it binds a real port,
serves the real router, completes a real WebSocket upgrade, writes a record, and reads the binary
frame back off the socket.

## Risk and blast radius

**The lockfile regeneration is the only change with real reach.** Direct dependency requirements in
`Cargo.toml` are untouched; transitive selections move, notably `fjall` 3.1.4 → 3.1.8 (3.1.4 is
yanked upstream, which is why an offline regeneration fails). `cargo check --workspace --all-features
--all-targets` compiles clean and the full suite passes.

Everything else is additive: new test files, vendored data, one `pub use`, three dev-dependencies
(`base64` on `atproto-dasl`; `futures`, `hex`, `http`, `tokio-websockets` on `atproto-pds`), and the
deletion of a bench that had not compiled in some time.

**One thing I could not verify locally:** spindle YAML cannot be validated offline. The pipeline is
written against the documented schema, but the first run on this pull request is what proves it
parses, and the nixpkgs toolchain may need adjusting if it lags the workspace's `rust-version =
"1.90"` / edition 2024.

## Deliberately out of scope

- The red vectors themselves — F-REPO-01, F-REPO-04, F-REPO-05, F-FIRE-01 and F-FIRE-04 are
  separate items. This branch makes them *provable*, which is its whole purpose.
- `blocksInProof` in the commit-proof fixtures: covering proofs are not constructed yet (F-FIRE-06).
- `--all-features` in CI: it compiles, but the Postgres, S3 and Valkey suites want live services.
  The README now states exactly what the gate runs instead of overstating it.
- `crates/atproto-space/src/set_hash_ecmh.rs` is an undeclared dead module — noticed while removing
  the bench that referenced it, left alone.
- No GitHub Actions CI. `release-binaries.yml` is untouched.

## Resolves

`F-OPS-01`, `F-FIRE-13` (roadmap M1.1). Unblocks M1.2, M1.3, M1.9, M1.10 and M1.11, each of which
lists M1.1 as its dependency.
