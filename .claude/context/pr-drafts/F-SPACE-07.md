# fix(atproto-pds): enforce membership on every permissioned read

Closes **F-SPACE-07**. Milestone M3.3.

## What was wrong

Four links, all open:

| | Where | What |
|---|---|---|
| 1 | `space_handlers.rs:1113` | `target_repo` taken from the caller's `repo` parameter verbatim — no comparison to the subject, no membership lookup — and auth recorded as `OwnPds { account_did: <the caller> }` |
| 2 | `:1872-1874` | `assert_space_scope` opens `if !subject.is_oauth() { return Ok(()); }` |
| 3 | `space/reader.rs:221-222` | `verify_auth` is a documented no-op for `OwnPds` |
| 4 | `reader.rs:~98` | `get_record` opens the target store and returns the record |

The exploit is one request:

```
GET /xrpc/com.atproto.space.getRecord?space=<uri>&collection=<c>&rkey=<k>&repo=<victim DID>
Authorization: Bearer <any local account's app-password session>
```

Same override reaches `listRecords` — which returns the whole repo — and `getBlob`.

**The confidentiality property the entire permissioned-data feature exists to provide did not hold against anyone on the same PDS.**

## What changed

Reads are gated on membership, checked per request in `resolve_record_auth`. Two questions, both necessary:

- **Is the caller a member?** Otherwise a stranger reads a space they were never added to. Skipped for a `SpaceCredential`, which is authority-signed and pre-authorises whole-space read — `verify_auth` checks that.
- **Is the named repo a member?** A space is not a lens onto arbitrary accounts. This applies to `SpaceCredential` too: an authority authorises reads *within* its space, not reads of repos outside it.

**Most of the machinery already existed.** `SpaceService::is_member` (`space/service.rs:361-376`) is exactly this predicate, with owner-as-member built in, and `SpaceService` was already on `HttpState`. So was the `read_self`-versus-`read` scope tier the report credits HappyView with (`assert_space_record_read`, `:1966-1999`). What was missing was only the membership question, which is orthogonal to the scope question.

## The decision that matters: membership is not a scope

**I left `assert_space_scope`'s `if !subject.is_oauth() { return Ok(()); }` alone**, even though it is how the exploit reaches the code.

App-password sessions carry no scopes by construction and are full-authority — PR #30 (M2.14) settled that, and the existing `space:` assertions already followed it. Scope-checking them now would refuse them over a grant that cannot exist.

The correct fix is that **membership must not live behind the scope gate.** Scope asks what a token was granted; membership asks who the account is. Putting the check in `resolve_record_auth`, before and independent of any scope logic, closes the app-password path without inventing a scope model for credentials that have none.

## Refusals report `SpaceNotFound`

Not a distinct `NotAMember`. Whether a given space holds a given account's records is itself the confidential fact — a caller who is not a member should not be able to probe it. A dedicated error would turn the gate into an oracle for space membership.

## Tests

Six new. **Five verified red** by neutralising the gate:

```
a_non_member_cannot_read_another_accounts_records ... FAILED
a_non_member_cannot_list_another_accounts_records .. FAILED
a_non_member_cannot_read_another_accounts_blobs .... FAILED
a_member_naming_a_non_member_target_is_refused ..... FAILED
a_removed_member_loses_read_access ................. FAILED
```

The report notes that *"the absence of a regression test for a non-member reading another account's records is itself part of the gap."* `a_non_member_cannot_read_another_accounts_records` is the exploit written out: Mallory, never added to the space, with an ordinary app-password session, naming Alice as `repo`.

`members_can_still_read_each_other` is the control and stays green by design — every other test asserts a refusal, so a gate that refused everything would pass all of them. It covers owner→member (owner is implicitly a member), member→own repo with an explicit `repo`, and member→own repo without one.

`a_removed_member_loses_read_access` pins that membership is evaluated per request rather than captured at session creation. It is also the one place this branch touches F-SPACE-06's territory: a removed member loses *read* access immediately here, while a previously-issued **SpaceCredential** still works for up to its two-hour TTL. That is F-SPACE-06 and is not fixed.

**The pre-existing `get_record_oauth_with_repo_override` still passes unchanged.** The report is right that it does not lock in arbitrary cross-account reads — its reader is the space authority and its target is a member the authority added — so the new gate does not contradict it.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2285 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **753 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

One new function, one signature change, three call sites. Two `is_member` queries per cross-repo read, one for a self-read.

**Anything relying on cross-account space reads by non-members was relying on the vulnerability.** Reads by members are unaffected.

## This is inherited — please raise it upstream

The report's Phase 4 audit opened the reference on the `permissioned-data` branch and found all three links shared: `packages/pds/src/api/com/atproto/space/getRecord.ts` destructures `repo` straight into `ctx.actorStore.read(repo, …)`, and `.../space/util.ts:32-37` skips the scope check for every non-OAuth credential. Per the fairness rule, **this is not an atproto-crates authoring error** — it is a real hole in 0016 as currently implemented by everyone following it.

Worked references exist and both do it per read: HappyView's `require_membership` (`src/spaces/service.rs:75-118`) and contrail's `authorizeRead` + `checkAccess` (`packages/contrait-record-host/src/routes.ts:125-195`).

I have not filed an upstream issue on your behalf. The report's threshold is worth noting: *"if the reference closes the hole in its own branch first, the 'inherited' framing evaporates"* — watch `space/util.ts`.

## Not fixed here

- **F-SPACE-06** (M3.9) — no credential revocation, so a removed member keeps credential-based read for up to two hours. Portable design in HappyView's `revoked_at`.
- **F-SPACE-04's sibling on writes** — this branch gates reads. Space writes go through `assert_space_scope` and the writer's own owner/member checks; I did not re-audit that path and am not claiming it.
- **F-SPACE-08** (M3.10) — cross-PDS credential verification is still unwired, so this membership check only knows about local members.
