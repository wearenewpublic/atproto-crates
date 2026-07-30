# fix(atproto-pds): conform six space wire shapes to their lexicons

Closes **F-SPACE-16**, **F-SPACE-17**, **F-SPACE-22**, **F-SPACE-23**, **F-SPACE-24**, **F-SPACE-26**. Milestone M3.11 — the wire-shape conformance group. Last spaces-gate item after this is M3.12.

## What was wrong

| # | Cite | Divergence |
|---|---|---|
| 22 | `space/config.rs:206,232,260` | Reads and writes `mintPolicy`; the lexicon's field is `policy` |
| 23 | `space_handlers.rs:612-619,632` | `applyWrites` input lacks `repo`/`validate`; output is the internal commit result |
| 23 | `space_handlers.rs:437-480` | `listSpaces` takes a `filter` the lexicon does not declare; returns no cursor |
| 24 | `space_handlers.rs:956` | `getRecord`'s response URI drops the author segment; `repo` optional |
| 16 | `:1581`, `:467`, `:577` | `limit` unclamped on `listRepoOps`, `listSpaces`, `listMembers` |
| 26 | `errors.rs` vs `:2648`, `:2775`, `:1840` | `SpaceNotFound` is 400 in the mapping and 404 in three handlers |
| 17 | `atproto-space/src/credential.rs:255-261` | No clock skew, no `iat` check; TTL unvalidated on the builder |

## The two that actually matter

**`policy` vs `mintPolicy`** is the worst of the six because it fails *quietly*. A client sending the lexicon's `policy` had it dropped and `member-list` applied instead — the space was created, the call returned 200, and the authorization policy was not the one asked for. Nothing surfaced.

**`iat` was never checked.** `check_exp` looked only at `exp`. An issuer that can date a token forward can extend its life without bound, which is the same as having no expiry. That is why this ships under *Security* rather than beside the shape fixes.

## Two places the report was narrower than the code, and one where it was wider

**Wider — the four-way split does not exist.** My Step 2 summary said fixing `applyWrites`' output meant splitting `SpaceCommitResult` into four types, because `ApplyWritesResponse` was a re-export of the same type the three single-record handlers returned. That was only half right: `createRecord`/`putRecord` already project through `single_write_response` into a conformant `{uri, cid}`, and `deleteRecord` already returns `{}`. Only `applyWrites` returned the raw commit. One new type, not four.

**Narrower — F-SPACE-16 names one endpoint, three were unclamped.** `listRecords` was already fixed by M3.6. `listSpaces` and `listMembers` are not named in the report and were also unbounded. All four now resolve `limit` through one `page_limit(requested, default, max)` helper, because the ceilings genuinely differ (100 for records/spaces, 1000 for ops/members) and three hand-written `.clamp()` calls is how they drift apart.

**Narrower — F-SPACE-26 names three handlers; the third is `getSpaceCredential`.** The report cites `:1840` as a 400. It is `getSpaceCredential`'s `SpaceNotFound` and it was a 404. Same class, same fix.

## One deliberate departure from the approved plan

The plan said a `createSpace` config carrying neither `policy` nor `mintPolicy` becomes a **400**, since `#spaceConfig` marks `policy` required. I did not do that.

`#spaceConfig`'s own description reads *"'member-list' (default) consults the member list"* — the lexicon names a default for the field it marks required, and `#spaceConfig` is the shape on **both** the create input and the `getSpace` output. The required-ness is about what a space always *has*, not what a client must always *send*. Rejecting would contradict the prose. Absent policy still defaults; the divergence being fixed is the field name.

## Breaking wire changes

For clients written against this server rather than against the lexicons:

- `applyWrites` requires `repo` and no longer returns `rev`/`setHash` (read `getLatestCommit`).
- `getRecord` requires `repo`. There is no implicit form — a record URI names its author even when that author is the caller.
- `listSpaces` no longer accepts `filter`. The `owned`/`member` distinction is gone; the lexicon has no equivalent.
- Three endpoints changed status for `SpaceNotFound`.

## Tests

Sixteen new — eleven unit, five acceptance. **Every one verified red**, in two neutralisation passes:

```
create_space_honours_the_lexicon_policy_field .................. FAILED  (22)
update_space_honours_the_lexicon_policy_field .................. FAILED  (22)
get_record_reports_a_uri_that_parses_back ...................... FAILED  (24)
space_not_found_uses_one_status_everywhere ..................... FAILED  (26)
a_limit_above_the_lexicon_maximum_is_clamped_not_honoured ...... FAILED  (16)
a_zero_or_absent_limit_falls_back_rather_than_returning_nothing  FAILED  (16)
a_token_expired_inside_the_skew_window_is_still_accepted ....... FAILED  (17)
an_iat_far_in_the_future_is_rejected ........................... FAILED  (17)

apply_writes_returns_one_typed_result_per_write ................ FAILED  (23)
apply_writes_requires_a_repo_naming_the_caller ................. FAILED  (23)
list_spaces_filters_by_type_and_did_and_pages .................. FAILED  (23)
```

Two passes because the `applyWrites`/`listSpaces` fixes are structural — reverting them mechanically alongside the others was not possible, so they were neutralised separately.

`results_follow_the_actions_not_the_presence_of_a_cid` is the one worth reading: it feeds a create/delete/update batch whose middle `cid` is `None` and asserts the variants come out in that order. Deciding the variant from "did a CID come back" would produce the same output here and the wrong one for a create whose CID was missing for another reason.

**My own test caught a real bug in this branch.** `list_spaces`' `LIKE` prefix was built from `ATS_SCHEME` (`ats://`) rather than `AT_SCHEME` (`at://`), so every `type=` and `did=` filter matched nothing and returned an empty page — a filter that silently returns nothing is worse than one that errors. `list_spaces_filters_by_type_and_did_and_pages` failed on the first filtered assertion.

Filter values are `LIKE`-escaped with `ESCAPE '\'`. A `_` or `%` in a DID would otherwise widen the filter rather than narrow it.

## Tests that were pinning the divergences

Fourteen, across three files:

- Three asserted `config["mintPolicy"]`, including one integration test that *sent* `mintPolicy` on `updateSpace`.
- `delegation_token_expired_rejected` minted a zero-TTL token and slept 1.1s. That now lands inside the skew window. Rewritten to build the payload directly with `exp` well past the tolerance — and it no longer sleeps.
- Seventeen `applyWrites` bodies had no `repo`; the shared `space_write` helper hid the field the endpoint now requires, so it takes an explicit one.
- `apply_writes_then_read_back` asserted on `body["rev"]` and `body["setHash"]`.
- Two `getRecord` cases exercised the implicit-`repo` form. One was named "alice → alice implicit" — the exact behaviour the lexicon does not have. Both now assert the request is refused.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2338 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **802 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns` — 0 errors

The TTL range invariant is a `const _: () = assert!(...)` beside the constants rather than a test — clippy correctly points out that a test comparing two constants is optimised away, and a compile-time assertion is what that check actually is.

## Not fixed here

- **`validate` is accepted and ignored** on `applyWrites`, matching `createRecord` and `putRecord`, which have carried `#[allow(dead_code)]` on the same field since they were written. Wiring space writes through `repo/prepare.rs`'s `ValidateMode` is a behaviour change, not a wire-shape one, and belongs to its own finding.
- **`#spaceView` declares only `uri` and `isOwner`.** `listSpaces` still returns `isMember` and `createdAt` alongside them. The union is not closed and the extra fields are useful; removing them would break clients for no conformance gain.
- **`SpaceDeleted` is still 404** while `SpaceNotFound` is 400. Arguably the same inconsistency class, but F-SPACE-26 scopes to `SpaceNotFound` and `SpaceDeleted` is a distinguishable condition. Recorded, not changed.
- **`applyWrites` and the other space handlers still return 422** for a malformed body, where XRPC wants 400 `InvalidRequest`. The `XrpcJson` extractor built in M2 is not applied to these routes. Already recorded as a separate finding candidate; this branch surfaces it on `repo` becoming required.
- **HappyView shares the `mintPolicy` divergence**, so there is no worked reference and an upstream 0016 issue is owed — alongside the F-SPACE-07 one still outstanding. I have not filed either.
