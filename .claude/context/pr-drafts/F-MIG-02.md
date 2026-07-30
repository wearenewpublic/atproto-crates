# feat(atproto-pds): serve `getPreferences` and `putPreferences` locally

Closes **F-MIG-02**. Milestone M2.18.

## What was wrong

`grep -rn "getPreferences\|putPreferences" crates/atproto-pds/src` returned **nothing**. The `app.bsky.*` catch-all (`router.rs:119-120`) forwarded both to an AppView that implements neither, so every call failed.

Muted words, feed preferences and content-label settings were broken for every logged-in user — and private state could not migrate in either direction, which is the one thing the lexicon says these are for. `getPreferences`'s own description: *"synchronization between multiple devices, and import/export during account migration."*

That is exactly the flow M2.17 just finished repairing, so this was the remaining hole in it.

## What changed

Two handlers, backed by a per-actor `preference` table, routed **ahead of** the catch-all — which would otherwise keep proxying them.

I read both lexicons directly rather than working from the report's summary. Each takes or returns exactly one required field, `preferences`, typed `app.bsky.actor.defs#preferences`.

## The payload is stored opaquely, deliberately

`#preferences` is an array of open-union objects. A PDS that parsed them would silently drop every preference type it had not been taught — and for private state, that is data loss the user discovers much later, with no error at the time.

So the array is stored as the JSON that arrived and returned verbatim. `preferences_round_trip_including_unknown_types` puts a `com.example.someFuturePref` with nested structure alongside two real ones and asserts all three come back intact.

## Two decisions stated rather than guessed

**Full replacement, not merge.** `putPreferences` replaces the stored array wholesale. The reference may instead merge by namespace, leaving entries outside `app.bsky.*` untouched. I could not verify that from here, and a merge rule that is subtly wrong discards user settings without saying so — so this does the predictable thing and documents it in the handler. A client that reads, edits and writes back the whole array — the shape the lexicon invites — is unaffected either way.

**No scope gate.** After #30, OAuth tokens are scope-checked on writes. There is **no lexicon-defined scope for preferences** — `AccountScope` covers email, repo and status only. Inventing one would refuse clients over a permission the ecosystem does not define, so an authenticated session is required and the gap is noted rather than papered over.

## Tests

Five, **verified red** by removing the routes — they fell back to the proxy and failed:

```
get_preferences_starts_empty ......................... FAILED
preferences_round_trip_including_unknown_types ....... FAILED
put_preferences_replaces_the_stored_set .............. FAILED
preferences_require_auth ............................. FAILED
preferences_are_per_account .......................... FAILED
```

`get_preferences_starts_empty` matters more than it looks: `preferences` is required by the lexicon, so a fresh account gets `[]` rather than an omitted field or a 404. A client reading `.preferences.length` should not have to special-case a first run.

`preferences_are_per_account` checks the obvious thing that would be embarrassing to get wrong — one account cannot read another's private state.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2176 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **651 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

One migration, one new module, two routes. The routes shadow the `app.bsky` catch-all for exactly these two NSIDs; everything else still proxies.

Storage is the per-actor SQLite store, so preferences travel with the account and are reachable while an account is deactivated mid-migration.

## Not fixed here

- Preferences are **not** carried by any export path — `getRepo` ships records, not private state. Migrating them means the client calling `getPreferences` on the old PDS and `putPreferences` on the new one, which is what the lexicon intends and what these endpoints now make possible.
- No OAuth scope covers preferences, per above.
- The fjall profile stores preferences in the per-actor SQLite store rather than a fjall keyspace. That is consistent with how the actor store is opened elsewhere for SQL-shaped state, but it is worth knowing that this table is not dispatched through `PublicRealmBackend`.
