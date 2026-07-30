# fix(atproto-pds): stop leaking the caller's DID on every space read

Closes **F-SPACE-30**. Milestone M3.2.

## What was wrong

`http/space_handlers.rs:1113`:

```rust
let did_static: &'a str = Box::leak(sub.clone().into_boxed_str());
```

`resolve_record_auth` is the entry point for every authenticated permissioned-record read — `getRecord` (`:926`), `listRecords` (`:1017`), `getBlob` (`:2229`). So any account with a valid session could drive unbounded process memory growth with ordinary reads. The permissioned chapter filed this under "operational hazards" as outside 0016 conformance; the synthesis reclassifies it as a real availability defect, and lists it in Tier 1 as exploitable today.

## The cause was a type, not a line

`SpaceReadAuth::OwnPds` declared `account_did: &'a str`. But the DID is produced by `subject.sub()` during request authentication — it is **derived, not a slice of the request** — so no caller could ever supply a borrow that lived long enough. `Box::leak` was not a shortcut; it was the only way to satisfy that signature.

Deleting the `Box::leak` alone would not compile. The field is now owned, which removes the leak *and* the reason it was written.

## The lifetime stays, deliberately

`SpaceCredential { token: &'a str }` genuinely borrows the `Authorization` header, which outlives the call. Dropping the lifetime entirely would have meant cloning a JWT on every credential read to fix a leak on a *different* variant — paying a real cost on one path to fix another.

An enum whose variants differ in ownership is the honest shape: one borrows something that exists, the other owns something that was computed.

## The regression guard is a compile-time one

There is no runtime assertion available. The leak was **invisible through the HTTP surface** — same status codes, same bodies, same latency — which is exactly why it survived. Asserting on RSS would be flaky and platform-specific.

So the test builds the DID in a scope that ends before the value is used:

```rust
let auth = {
    let subject_did = format!("did:plc:{}", "derived-at-request-time");
    SpaceReadAuth::OwnPds { account_did: subject_did }
};
```

That only compiles when the field is owned. **Both failure modes were checked rather than assumed:**

- Reverting the field to `&'a str` → `error[E0308]: mismatched types` at the test *and* at the handler.
- Taking the compiler's suggested fix (`&subject_did`) → `error[E0597]: subject_did does not live long enough … dropped here while still borrowed`.

A second test pins that `SpaceCredential` still borrows, via `std::ptr::eq` against the source string — so a future tidy-up that makes both variants owned has to argue with a test rather than slip through.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2279 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **747 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors
- `grep -rn "Box::leak" crates/` — one hit, in the doc comment explaining why it is gone

## Blast radius

Three files. One `String` allocation per authenticated space read replaces one permanent leak per authenticated space read — the allocation was already happening (`sub.clone()`), it just was not being freed.

No wire change, no behavioural change, no new error.

## Not fixed here

**F-SPACE-07 (M3.3) is the same function.** `resolve_record_auth` adopts the caller-supplied `repo` verbatim at `:1114` and performs no membership check, so any authenticated local account can read any other local account's permissioned records. The report is explicit that both fixes touch this code, and equally explicit that F-SPACE-07 is *inherited from the reference draft* — `packages/pds/src/api/com/atproto/space/util.ts` shares it — so the recommendation is to raise it upstream as well as fix it here.

I have deliberately not folded it in: it is a confidentiality hole with a real design question behind it (where the membership predicate belongs), and it deserves its own branch and its own Step 2 rather than riding along on a memory fix.
