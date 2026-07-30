# ci: pin the toolchain and stop asserting on a const's emptiness

## What and why

`main` is red. `assert!(!BUILD_REV.is_empty())` trips `clippy::const_is_empty` under
`-D warnings`, and the lint is correct: `BUILD_REV` is a `const` filled by `env!`, so
`BUILD_REV.is_empty()` is decided by the compiler and the assertion can never do any work at run
time.

The more useful finding is why it reached `main` at all. The spindle installed nixpkgs
`cargo`/`rustc`/`clippy` **unpinned**, so CI ran whatever that channel carried while developers ran
their own. Three declarations of the toolchain existed and none agreed:

| Where | Version |
| --- | --- |
| `Cargo.toml` `rust-version` | 1.90 |
| `Dockerfile` builder stage | `rust:1.90-slim-bookworm` |
| `.tangled/workflows/ci.yml` | whatever nixpkgs supplies |

The same code passed `cargo clippy --workspace --all-targets -- -D warnings` on 1.95 and failed on
the version CI installed. "Green locally" did not imply "green in CI" for any branch merged so far.

## Changes

1. **`rust-toolchain.toml`** pins 1.90 with the `rustfmt` and `clippy` components, matching the two
   existing declarations.
2. **`.tangled/workflows/ci.yml`** installs `rustup` rather than nixpkgs `cargo`/`rustc`/`clippy`, so
   it honours that file. A first step prints `rustup show active-toolchain` and
   `cargo clippy --version`, so the version under test is visible in the log rather than inferred.
3. **The assertion** is replaced by one that reads the build rev back out of the string
   `user_agent()` formats — the value that actually ships on outbound requests, and a run-time
   `String` no compiler can fold away. The separate `user_agent_format` test folds into it rather
   than asserting the prefix twice.

```rust
#[test]
fn user_agent_is_well_formed_and_carries_a_build_rev() {
    let ua = user_agent();
    assert!(ua.starts_with("atproto-pds/"), "...");
    let (version, rev) = ua.rsplit_once('+').unwrap_or_else(|| panic!("..."));
    assert_eq!(version, format!("atproto-pds/{CRATE_VERSION}"));
    assert!(!rev.is_empty(), "build.rs should stamp a non-empty BUILD_REV: {ua}");
}
```

## Testing

I could not reproduce the failure on 1.95 even with `-W clippy::const_is_empty` forced and a clean
rebuild, so I installed 1.90 and confirmed it directly:

- clippy 1.90 on unmodified `main` reproduces the reported failure **exactly, and finds nothing else
  across all twenty crates** — so the pin is safe and does not drag in a pile of new lints.
- After the change, under the pinned toolchain: `cargo fmt --all -- --check` clean,
  `cargo clippy --workspace --all-targets -- -D warnings` exit 0, `cargo test --workspace`
  **2020 passed, 0 failed, 63 ignored**. (2020 rather than 2021 because two tests merged into one.)

## Risk

`rustup` fetches the toolchain at CI time, so the job now depends on network access to
`static.rust-lang.org` and will be slower on a cold cache. That is the cost of the two environments
agreeing.

Anyone with a local toolchain other than 1.90 will find `cargo` switching automatically via rustup;
without rustup installed, `rust-toolchain.toml` is ignored and behaviour is unchanged from today.

Bumping Rust now means editing three files. A follow-up could collapse that, but not here.

## Follow-up to

`F-OPS-01` — the CI gate that finding added is what caught this, one merge after it landed. That is
the gate working, not a regression in it.
