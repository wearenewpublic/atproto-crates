# fix(atproto-pds): `getSpace` describes the authority's space, not the caller's

Closes **F-SPACE-11**. Milestone M3.5.

## What was wrong

Three links, all confirmed at the cited lines:

| | Where | What |
|---|---|---|
| 1 | `space_handlers.rs:423-428` | `viewer` is the caller's DID (`s.sub()`), the authority only when unauthenticated |
| 2 | `space/service.rs:132-133` | `get_space(&self, viewer_did, uri)` opens `SqlActorStore::open(&self.data_dir, viewer_did)` |
| 3 | `actor_store/sql/space_repo_storage.rs:38-41` | `ensure_space_row` does `INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at) VALUES (?, 0, 0, ?)` — a member's store gets a space row whose `mint_policy` and `app_access` are the column defaults |

So a client asking about an `allowList` space was told `open`, and could not make a correct minting decision. A member who had never written had no row at all and got `SpaceNotFound` for a space they belong to.

**The handler's own comment, two lines above the bug, already said what to do:** *"describe from the authority's store regardless of which member's credential authorized the read."* The comment was right; the code disagreed with it.

Two independent confirmations: the sibling `load_mint_authz_inputs` (`service.rs:170`) opens `uri.space_did` and its doc says so, and the draft lexicon (`lex-0016/space/getSpace.json`) describes the endpoint as *"Describe a space. **Served by the space host.**"* HappyView reads the authority row (`spaces/routes.rs:455-465`).

## What changed

`SpaceService::get_space` no longer takes a viewer, and opens `uri.space_did`.

**Removed rather than corrected.** `GetSpaceOutput` is `{uri, config}` (`service.rs:553-558`) — no viewer-dependent field — so the parameter only ever selected the wrong store. Deleting it makes the bug unrepresentable instead of merely fixed, and the handler's `viewer` binding disappears with it.

Authorization is untouched: `require_any_authn` and `assert_space_read_opt` still decide *who may ask*. The answer no longer depends on who asked.

## Why this survived

**All four pre-existing unit tests call `svc.get_space("did:plc:owner", &uri)`** — the authority *is* the viewer, so caller-store and authority-store are the same store. The bug was invisible to every existing assertion. Eighth instance in this series of a test that cannot distinguish the behaviour it names.

## Tests

Three new. **Two verified red** by standing a member DID in for the authority's:

```
a_member_who_never_wrote_can_describe_the_space ............... FAILED
the_authoritys_config_is_reported_not_the_callers_defaults .... FAILED
```

Two *pre-existing* tests also went red under that neutralisation — `create_space_round_trip` and `update_space_reflects_in_get_space` — which is worth noting: they do exercise the read, they just could not tell the two stores apart while the viewer was the owner.

`the_authoritys_config_is_reported_not_the_callers_defaults` is the test the existing four could not have been. The member **writes first**, which is what plants the defaulted row in their store — so it passing means the defaulted row is being *ignored*, not merely absent. It then asserts the member and the authority receive identical config.

`a_deleted_space_is_still_not_found` stays green by design: reading the authority's store must not resurrect a tombstoned space.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2298 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **766 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

One parameter removed, one call site, four unit-test call sites updated. `getSpace` starts answering for members who previously got `SpaceNotFound`, and starts returning the true config where it previously returned defaults. Both are the fix. No wire-shape change.

## Not fixed here

- **`ensure_space_row`'s defaulted row is left in place.** It is the mechanism, not the bug: those rows carry the `is_owner`/`is_member` flags and per-actor `space_repo` state that member-side writes legitimately need. The fix is to stop reading config from them.
- **`listSpaces` also reads the caller's store — correctly.** It lists *the viewer's* spaces, so it must not be changed alongside this. Stated because the two look alike at a glance.

## One new finding, discovered while writing the test

**`createSpace` returns HTTP 500 `InternalError` for a malformed `config`.** My first test payload used `dids` where the field is `allowed`; `SpaceConfig::from_create_input` (`space/config.rs:140-144`) raises `PdsError::Storage` for a caller-supplied shape error, which maps to 500. A client sending a bad config cannot tell its own mistake from a server fault.

Not in F-SPACE-11 and not fixed here — recorded in `PROGRESS.md` as a finding candidate. It is the same class as the 422-versus-400 issue noted in M2.21.
