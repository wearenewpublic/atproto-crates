# feat(pds): route describeServer, sync.listRepos and the two identity well-knowns

## What and why

Four endpoints that were never wired. Each 404 breaks something concrete, and between them they are
why the shipped `deploy/` cluster could not federate.

| Endpoint | What its absence broke |
| --- | --- |
| `com.atproto.server.describeServer` | Migration failed at step two: the client calls it on the **new** PDS to learn the `aud` for the service-auth token the **old** PDS must mint |
| `com.atproto.sync.listRepos` | A relay could subscribe to the firehose but never learn which accounts to backfill |
| `/.well-known/atproto-did` | The PDS could not host a handle on its own domain without an external web server synthesising the file |
| `/.well-known/did.json` | Spaces and service-auth peers could not resolve this PDS's own `did:web` |

## Evidence

### Before

- `describeServer` — **no implementation at all**: `grep -rn "describeServer\|describe_server"`
  across `crates/` returned zero hits.
- `com.atproto.sync.listRepos` — absent; only `com.atproto.**space**.listRepos` existed.
- `.well-known` in `http/router.rs` — exactly two routes, `:253` and `:257`, both OAuth.

### After

Four routes in `http/router.rs`, handlers in a new `http/discovery_handlers.rs`.

## Notes on the implementation

**`listRepos` needed more than the report's "the enumeration already exists".** `list_account_dids`
returns DIDs only, but `listRepos#repo` requires `{did, head, rev}`. It now joins the account list
against each account's latest commit, reports `active`/`status` from account state, and paginates on
`limit`/`cursor`.

Accounts with **no commits are omitted** rather than announced. `head` is a required field, and
inventing one would have a relay chase a commit that does not exist.

**`atproto-did` returns 404 for an unknown handle**, not a 200 with an empty body, so a resolver can
distinguish "not here" from "here, but blank". The `Host` port is stripped before lookup.

**`did.json` is synthesised, not read from disk**, from `PDS_SERVICE_DID`. It 404s when the service
DID is not a `did:web`, since no other method resolves through that path.

## F-OPS-05, closed by deletion rather than by wiring

The report's M4.1 says to mount `deploy/well-known/` so the reference cluster can resolve its own
`did:web`, and flags it as the one M4 item that should ride along with M1.7. Having looked at the
deployment, mounting is the wrong fix:

- The three `deploy/well-known/*/did.json` files were **never mounted** by `docker-compose.yml`.
- Every container **already** sets `PDS_SERVICE_DID` to exactly the DID those files describe
  (`deploy/env/pds1.env:5` → `did:web:pds1.ngerakines.dev`, and likewise for `pds2` and
  `space-host`).
- The synthesised document is identical: same `id`, same `#atproto_pds` and `#atproto_space_host`
  entries, same endpoints.

So the files were pure duplication — a second source of truth that can drift from the DID the server
actually runs as. Deleted.

## Worked reference

All eleven comparisons route `describeServer` (cirrus `index.ts:278`, dnproto `Pds.cs:190`, alteran
`index.js:42`) and all eleven route `sync.listRepos` (alteran `index.js:58`, dnproto `Pds.cs:209`,
cirrus `index.ts:204`). Ten of eleven serve `atproto-did`; eight serve `did.json` (tranquil
`lib.rs:471`, cocoon `handle_well_known.go:53-67`, metalbear `server.c:6390`, cirrus `index.ts:113`,
zds `router.zig:136`, dnproto `Pds.cs:215`, pegasus, alteran).

The reference and rsky-pds omit `did.json`, which the report calibrates down — I serve it anyway
because this repository's own deployment needs it.

## Testing

Nine integration tests in `discovery_endpoints.rs` and five unit tests. **Eight of the nine fail
against the previous code.**

The ninth — `well_known_atproto_did_404s_for_an_unknown_handle` — passed before, for the wrong
reason: the route did not exist, so every path 404'd. It is kept because it is the right assertion
now, but it is not evidence of anything on its own.

Unit tests cover the `did:web` → origin derivation including a percent-encoded port
(`did:web:localhost%3A8080` → `https://localhost:8080`), and the state → `active`/`status` mapping.

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2043 passed, 0 failed, 63 ignored.**

## Risk and blast radius

Additive: four new routes, one new module, no existing behaviour changed.

Two judgement calls worth reviewing:

1. **`did.json` advertises `#atproto_space_host` as well as `#atproto_pds`**, matching what the
   deleted static files declared and what this build actually serves. If a deployment ships without
   spaces, it will advertise a service it does not offer.
2. **`listRepos` is unauthenticated**, matching the lexicon and every comparison. It enumerates
   account DIDs and handles-by-implication for anyone who asks; that is the intended design of a
   federated network, but it is worth stating rather than discovering.

## Deliberately out of scope

- `F-ACCT-02` — `createAccount` still adopts a caller-supplied DID with no proof of control
  (M2.13). `describeServer` being routed makes the migration flow reachable up to that point.
- `F-SYNC-02/03/05/06`, `F-IDENT-01/02/03/05`.
- `describeServer`'s optional `links` and `contact` blocks — nothing in the config carries them yet.

## Resolves

`F-ACCT-01`, `F-SYNC-01`, `F-IDENT-04` (roadmap M1.7) and `F-OPS-05` (roadmap M4.1, which §5 asks to
ride along with M1.7).
