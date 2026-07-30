# docs(atproto-pds): mark Postgres and S3 unsupported, refuse them at boot

Closes **F-OPS-06**, **F-BLOB-09**. Milestone M2.24 — **the last item in the PDS `-rc` gate.**

## What was wrong

Two backends have complete, feature-gated, tested implementations in this crate and **no construction site in the binary**.

| | Declared | Read |
|---|---|---|
| `PDS_POSTGRES_URL` | `bin/pds.rs:389`, with a paragraph describing how it routes every accounts-DB call site | never — `AccountDirectory::open(&accounts_path)` at `:488` is the only construction, and `open_postgres` (`directory.rs:126`) has no caller |
| `PDS_BLOB_STORE_URL` | `bin/pds.rs:381`, with a paragraph describing AWS credential resolution | never — `HybridS3BlobStorage` is referenced only from `tests/feature_s3.rs` |

Both were advertised in `README.md:125,133`. So an operator who configured S3 got per-actor SQLite, and one who configured Postgres got the same, **with nothing to indicate it**.

## Report corrections

**The writer line cite is wrong, but the claim holds.** The report puts the SQLite-dialect accounts query at `repo/writer.rs:360-364`; that line is the *per-actor* store, which is SQLite by design and unaffected by the accounts-DB choice. The real sites are **`:548-552` and `:867-871`** — `SELECT signing_key_ref FROM account WHERE did = ?` against `self.accounts.pool()`, twice.

**Neither feature is in any shipped artifact.** Neither is in `default`, and the release build compiles `clap,hickory-dns,zeroize,tokio,smtp`. The report calls this *"a documented supported deployment mode that would crash the process"* — the crash was never reachable in a shipped binary, because the code is not there. The defect that *was* reachable is the quiet one: the flags are declared without `#[cfg]`, so they parse and are ignored.

## I measured before deciding

The roadmap sizes M2.24 as "M / S" — construct them, or document them away. The two halves are not the same size:

- **S3 — small.** `HybridS3BlobStorage::open(url, refs)` already returns a `BlobStorage`, and `PublicRealmBackend` already carries a `blob` slot built at `bin/pds.rs:453-472`.
- **Postgres — weeks.** 59 `as_sqlite()` call sites, of which **57 already dispatch per dialect** — genuinely good work. But **13 production call sites** take the SQLite-only `pool()` accessor and would panic: `bin/pds.rs` (×5), `repo/writer.rs` (×2), `http/handlers.rs`, `http/space_handlers.rs`, `http/space_auth.rs`, `space/writer.rs`, `space/reader.rs`, `actor_store/sql/public_realm.rs`. Behind them sit the OAuth state store, the JTI replay guard and rate-limit SQL backend, the GC loop, the notifier, the sequencer and four spaces files.

**The decision was yours: document both as unsupported.** That is what this branch does.

## What changed

Both README rows are gone, replaced by an explicit **"Unsupported deployment modes"** section naming what exists, what is missing, and how many call sites stand in the way. The module docs on `blob_s3` and `account::pool` now *open* by saying the mode is not selectable, rather than describing one that is not.

**Setting either variable refuses at boot**, naming which backend, why it does not work, and what you get instead.

Refusing rather than deleting the flags: an unrecognised environment variable is *also* silent, and silence is the failure being fixed.

The check lives in `config.rs` beside `validate_production_safety` rather than in the binary — so it is testable, and so it reports both problems in one boot for the same reason that one does.

**The code stays.** It compiles under its feature, its tests still run, and deleting it would make wiring it later harder than leaving it. `cargo check -p atproto-pds --features postgres,clap,http` and `--features s3,clap,http` both remain clean.

## Tests

Four new, **three verified red** by stubbing the "is it set" predicate to `false`:

```
a_configured_postgres_url_refuses_and_says_why ... FAILED
a_configured_blob_store_url_refuses_and_says_why . FAILED
both_are_reported_together ....................... FAILED
```

`an_unset_backend_url_is_fine` stays green — it is the control, and it also pins that an exported-but-empty variable counts as unset. An operator who writes `PDS_POSTGRES_URL=` in a compose file has not configured anything, and refusing them would be a worse bug than the one being fixed.

The two refusal tests assert on the *reason*, not just the failure: a refusal that does not say why leaves the operator exactly where the silent version did.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2270 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **745 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors
- `cargo check -p atproto-pds --features postgres,clap,http` — 0 errors
- `cargo check -p atproto-pds --features s3,clap,http` — 0 errors

## Blast radius

**A deployment that sets either variable will not boot.** That is the point: it previously believed it had a backend it did not have. Anyone who set `PDS_BLOB_STORE_URL` was already storing blobs in SQLite — this tells them so rather than changing where their data goes.

No behavioural change to any request path. Documentation, two module doc headers, one startup check.

## What this does not close

This is the honest-documentation half of the decision, not the implementation half. The advertised horizontal-scale story remains unavailable, and the report's §4 lead claim — "SQLite/Postgres/Fjall/S3/Valkey" — should be read as **SQLite/fjall/Valkey**.

**Wiring S3 is a small, well-scoped follow-up** and worth filing: the storage impl is complete, the backend has a slot, and the remaining work is reading one flag. I have recorded it in `PROGRESS.md` as a finding candidate rather than doing it here, because the decision was to document both.
