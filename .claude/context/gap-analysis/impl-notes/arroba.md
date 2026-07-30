# arroba (snarfed) — implementation notes

Source examined: `/tmp/gap-scratch/arroba/` at git HEAD `9fd551d` (2026-07-27, "firehose: add tooBig to
emitted events"). Canonical lexicons cross-checked from `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.

All citations below are absolute paths under the scratch checkout.

---

## 1. Language, stack, build, license

Python, `requires-python = '>=3.9'` (`/tmp/gap-scratch/arroba/pyproject.toml:29`), built with setuptools
(`pyproject.toml:3-5`), published to PyPI as `arroba` version `3.0` with trove classifier
`Development Status :: 3 - Alpha` (`pyproject.toml:22`, `pyproject.toml:36`).

Runtime dependencies (`pyproject.toml:39-53`): `carbox` (CAR v1 read/write), `dag-cbor`, `dag-json`,
`libipld` (fast DAG-CBOR decode in the MST hot path), `multiformats`, `lexrpc` (XRPC server/validation
layer), `cryptography`, `pyjwt`, `pymediainfo`, `dnspython`, `requests` + `requests-hardened` (SSRF
guard, added in 3.0 per `README.md:136`). Optional extras: `datastore` = `google-cloud-ndb` +
`pymemcache`; `flask` = `Flask` + `werkzeug` (`pyproject.toml:55-62`). Flask is imported defensively
everywhere (`/tmp/gap-scratch/arroba/arroba/server.py:7-10`,
`/tmp/gap-scratch/arroba/arroba/xrpc_sync.py:16-19`) so the core library works without it.

License: CC0 1.0 Universal (`/tmp/gap-scratch/arroba/LICENSE:1-3`, `pyproject.toml:31`). The README states
it plainly: "This project is placed in the public domain." (`/tmp/gap-scratch/arroba/README.md:12`).

CI is CircleCI on `cimg/python:3.12` (`/tmp/gap-scratch/arroba/.circleci/config.yml:9-10`), running
`unittest discover` under coverage plus a single `flake8 --select=F811` check
(`.circleci/config.yml:41-51`). GitHub Actions carries only CodeQL and dependabot auto-merge
(`/tmp/gap-scratch/arroba/.github/workflows/`).

## 2. Library vs server; single-user vs multi-account; deployment

**arroba is primarily a library.** `README.md:6` frames it as "You can build your own PDS on top of
arroba with just a few lines of Python and run it in any WSGI server... Or you can build a different
ATProto service, eg an AppView, relay". The published surface (`README.md:58-74`) is: data structures
(`Repo`, `MST`), storage ABC + two backends, three XRPC handler modules, and utility modules (`did`,
`diff`, `util`). Nothing in `arroba/` binds a port; the only server is the demo `app.py`.

The core is **multi-account by construction**: `Storage.load_repos(after, limit, minimal)`
(`/tmp/gap-scratch/arroba/arroba/storage.py:237-254`) and `com.atproto.sync.listRepos`
(`/tmp/gap-scratch/arroba/arroba/xrpc_sync.py:90-111`) page over arbitrarily many repos, and
`DatastoreStorage.load_repo` keys on DID or handle (`/tmp/gap-scratch/arroba/arroba/datastore_storage.py:665`).
The bundled demo `app.py` is single-repo: it reads exactly one `did:plc:*.json` file, asserting there is
exactly one (`/tmp/gap-scratch/arroba/app.py:43-48`), and installs a single module-global
`server.repo` (`app.py:127-133`).

Deployment model: Google App Engine Flexible, `env: flex`, `manual_scaling: instances: 1`,
`entrypoint: gunicorn --workers 1 --threads 20` (`/tmp/gap-scratch/arroba/app.yaml:7-24`). The
single-instance pinning is deliberate and documented in-file: "need only one instance so that new
events can be delivered to subscribeRepos subscribers in memory" (`app.yaml:16-18`). There is no
Dockerfile, no systemd unit, no installer in the repo.

## 3. Storage backends

`Storage` is an ABC (`/tmp/gap-scratch/arroba/arroba/storage.py:180-644`) covering repo metadata,
blocks, sequence allocation, and commit construction. `_commit` is the single shared write path
(`storage.py:526-644`); subclasses override it only to add a transaction
(`/tmp/gap-scratch/arroba/arroba/datastore_storage.py:886-890`).

Two concrete backends:

| Backend | Class | Engine | Schema location |
|---|---|---|---|
| In-memory | `MemoryStorage` (`storage.py:669-743`) | Python dicts (`self.blocks`, `self.repos`) | n/a |
| Google Cloud Datastore | `DatastoreStorage` (`datastore_storage.py:612`) | Firestore-in-Datastore-mode via `google-cloud-ndb` | ndb model classes, `datastore_storage.py:61-433` |

Datastore entity kinds (there is no SQL DDL; the models *are* the schema):

- `AtpRepo` (`datastore_storage.py:75-121`) — key = DID; `handles` (repeated), `head` (CID str),
  `status` ∈ {deactivated, deleted, tombstoned}, plus `encrypted_signing_key` /
  `encrypted_rotation_key` (`datastore_storage.py:90-95`). Key encryption via `ENCRYPTED_PROPERTY_KEY`
  (AES-256-GCM) was a 3.0 breaking change (`README.md:130`).
- `AtpBlock` (`datastore_storage.py:124-212`) — key = base32 CID; `repo` KeyProperty, `seq`
  (`datastore_storage.py:139-141`), and an embedded `CommitOp` structured property carrying
  `action`/`path`/`cid`/`prev_cid` (`datastore_storage.py:61-72`). All block classes — records, MST
  nodes, commits, and firehose events — share this one kind.
- `AtpSequence` (`datastore_storage.py:214-227`) — per-NSID monotonic counter.
- `AtpRemoteBlob` (`datastore_storage.py:398-433`) — blob *metadata* keyed by source URL.

Filesystem storage is an open TODO (`README.md:66`). Sequence allocation has three implementations:
`MemorySequences` (`storage.py:647-666`), `DatastoreSequences` (`datastore_storage.py:267`), and
`MemcacheSequences` (`datastore_storage.py:311`), the last batching allocations through memcache to cut
Datastore contention at 5-10 qps (`README.md:159`).

## 4. Endpoint coverage snapshot

Route registry: `lexrpc.server.Server` instantiated with `validate=True` at
`/tmp/gap-scratch/arroba/arroba/server.py:16`; handlers attach via the `@server.server.method('<nsid>')`
decorator. The complete registered set is 28 NSIDs across three families — grep for
`@server.server.method` returns nothing outside `xrpc_repo.py`, `xrpc_server.py`, `xrpc_sync.py`.

### com.atproto.server.*

| NSID | Registered at | Status |
|---|---|---|
| `createSession` | `xrpc_server.py:10` | **Degenerate.** Looks up the repo by identifier, never checks a password, returns `os.environ['REPO_TOKEN']` as both `accessJwt` and `refreshJwt`; `# TODO: generate JWT` at `xrpc_server.py:18` |
| `getSession` | `xrpc_server.py:28` | **Degenerate.** Returns the module-global `server.repo`, ignoring the caller's token subject; `# TODO: parse JWT, extract repo DID` at `xrpc_server.py:33` |
| `refreshSession` | `xrpc_server.py:41` | **Degenerate.** Re-returns the same static token (`xrpc_server.py:46`) |
| `describeServer` | `xrpc_server.py:55` | Real but thin: `availableUserDomains: []`, `did: did:web:$PDS_HOST` (`xrpc_server.py:59-63`) |
| `getAccountInviteCodes` | `xrpc_server.py:66` | **Stub** — hardcoded `{'codes': []}` (`xrpc_server.py:69`) |
| `listAppPasswords` | `xrpc_server.py:72` | **Stub** — hardcoded `{'passwords': []}` (`xrpc_server.py:75`) |

Not served (all present in canonical lexicons): `createAccount`, `deleteAccount`, `deleteSession`,
`activateAccount`, `deactivateAccount`, `checkAccountStatus`, `getServiceAuth`, `reserveSigningKey`,
`createAppPassword`, `revokeAppPassword`, `createInviteCode(s)`, `updateEmail`, `confirmEmail`,
`request*` (`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/`).

### com.atproto.repo.*

| NSID | Registered at | Status |
|---|---|---|
| `createRecord` | `xrpc_repo.py:42` | Real; allocates a TID rkey then delegates to `putRecord` (`xrpc_repo.py:49-51`). `# TODO: check the lexicon's key field first` (`xrpc_repo.py:49`) |
| `putRecord` | `xrpc_repo.py:163` | Real; CREATE-or-UPDATE decided by an MST lookup (`xrpc_repo.py:170-177`) |
| `deleteRecord` | `xrpc_repo.py:97` | Real; silent no-op when absent (`xrpc_repo.py:104-106`) |
| `getRecord` | `xrpc_repo.py:54` | Real, with AppView fallback on miss (`xrpc_repo.py:76-94`). `cid` param rejected (`xrpc_repo.py:60-61`) |
| `listRecords` | `xrpc_repo.py:115` | Real; `reverse`, `rkeyStart`, `rkeyEnd` all rejected (`xrpc_repo.py:128-131`) |
| `describeRepo` | `xrpc_repo.py:185` | Real; resolves the DID doc and enumerates collections (`xrpc_repo.py:192-207`) |
| `importRepo` | `xrpc_repo.py:210` | Real — see §8 |
| `applyWrites` | `xrpc_repo.py:265` | **Stub** — `return 'Not implemented', 501` (`xrpc_repo.py:270`) |
| `uploadBlob` | `xrpc_repo.py:273` | **Stub** — `return 'Not implemented', 501` (`xrpc_repo.py:279`) |

`listMissingBlobs` is not served. `swapCommit`/`swapRecord` are rejected on every repo write
(`xrpc_repo.py:34-36`), so there is no compare-and-swap concurrency control.

### com.atproto.sync.*

| NSID | Registered at | Status |
|---|---|---|
| `getRepo` | `xrpc_sync.py:45` | Real, streaming CAR; `since` implemented as a seq-filtered MST walk (`xrpc_sync.py:61-67` → `mst.py:800-847`). Gated by `DISABLE_GETREPO` / `GETREPO_TOKEN` (`xrpc_sync.py:52-59`) |
| `getCheckout` | `xrpc_sync.py:34` | Deprecated alias → `get_repo` (`xrpc_sync.py:42`) |
| `getRepoStatus` | `xrpc_sync.py:70` | Real; returns `did`/`active`/`status`. Does **not** return the optional `rev` the lexicon allows (`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getRepoStatus.json`) |
| `listRepos` | `xrpc_sync.py:90` | Real, cursor-paged (`xrpc_sync.py:95-111`) |
| `subscribeRepos` | `xrpc_sync.py:114` | Real generator — see §6/§7 |
| `getBlocks` | `xrpc_sync.py:166` | Real; `BlockNotFound` on unknown CID (`xrpc_sync.py:181-183`) |
| `getLatestCommit` | `xrpc_sync.py:201` | Real |
| `getHead` | `xrpc_sync.py:189` | Deprecated, real |
| `getRecord` | `xrpc_sync.py:211` | Real **with covering proofs** — see §6 |
| `getBlob` | `xrpc_sync.py:234` | Redirect-only (301 to the remote URL), no local bytes (`xrpc_sync.py:241-257`) |
| `listBlobs` | `xrpc_sync.py:260` | Real for remote blobs; `since` raises (`xrpc_sync.py:263-264`) |

Not served: `requestCrawl`, `notifyOfUpdate`, `listHosts`, `getHostStatus`, `listReposByCollection`.
`getHostStatus`/`listHosts` are relay-side per their own lexicons ("Implemented by relays",
`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getHostStatus.json`) so they are **n/a** for a PDS;
`listReposByCollection` carries no such qualifier and is a genuine gap.

### com.atproto.identity.* / admin.* / moderation.* / label.* / temp.*

**Zero handlers.** No `@server.server.method` registration for any NSID in these families. The demo app
routes `com.atproto.identity.resolveHandle` straight through to the AppView as a proxy
(`/tmp/gap-scratch/arroba/app.py:102-121`) — that is demo-app plumbing, not an arroba handler.

**n/a vs missing.** arroba ships the *primitives* for identity work and leaves the endpoints to the
embedding app: `did.create_plc` / `update_plc` / `write_plc_operation` / `rollback_plc`
(`/tmp/gap-scratch/arroba/arroba/did.py:105`, `:115`, `:249`, `:285`), `did.resolve_handle`
(`did.py:487`), `util.service_jwt` (`/tmp/gap-scratch/arroba/arroba/util.py:355`), and
`Storage.activate_repo` / `deactivate_repo` / `tombstone_repo` (`storage.py:256`, `:275`, `:292`).
Treat `identity.updateHandle`, `identity.signPlcOperation`, `identity.submitPlcOperation`,
`server.createAccount`, `server.activateAccount`, `server.deactivateAccount` as **n/a (library
primitive present, endpoint deliberately unbound)**; treat `repo.uploadBlob`, `repo.applyWrites`,
`repo.listMissingBlobs`, `server.checkAccountStatus`, `server.getServiceAuth`, and all of `admin.*` /
`moderation.*` as **missing** — no primitive exists for them either.

**README vs code.** `README.md:58-74` claims only the three XRPC modules, which matches the code
exactly; the README does not overstate coverage. The one intra-file contradiction is in
`xrpc_sync.py`: the `subscribe_repos` docstring says "it's not automatically registered with the XRPC
server. Instead, clients should choose how to register and serve it themselves"
(`xrpc_sync.py:121-124`) — but the `@server.server.method('com.atproto.sync.subscribeRepos')` decorator
one line above (`xrpc_sync.py:114`) does register it. The docstring is stale.

## 5. Auth posture

There is no authorization server and no session management. `server.auth()`
(`/tmp/gap-scratch/arroba/arroba/server.py:22-29`) is the entire check: a single process-wide static
bearer token from `$REPO_TOKEN`, string-compared against the `Authorization` header. If `$REPO_TOKEN`
is unset it raises `NotImplementedError`, which the README documents as the intended behavior: "If not
set, XRPC methods that require auth will return HTTP 501 Not Implemented." (`README.md:96`). The token
is explicitly "Not required to be an actual JWT" (`README.md:96`).

- App passwords: none (`listAppPasswords` is a hardcoded empty list, `xrpc_server.py:75`).
- Session JWTs: none. `createSession` hands back the static token (`xrpc_server.py:19-25`) with no
  password verification at all.
- OAuth (PAR / PKCE / DPoP / nonce / `private_key_jwt` / `.well-known/oauth-*`): **entirely absent.**
  Grep for `dpop`, `PAR`, `oauth`, `.well-known` across `arroba/*.py` and `app.py` returns nothing.
- Service auth: **minting only, never verifying.** `util.service_jwt` (`util.py:355-384`) builds an
  ES256K JWT with `iss`/`aud`/`exp` and arbitrary extra claims (e.g. `lxm`), defaulting `aud` to
  `did:web:{host}`. The demo app mints 999-day tokens for the AppView and relay
  (`app.py:75-83`, `app.py:184-191`). `com.atproto.server.getServiceAuth` is not served, and no code
  path calls `jwt.decode` — the only occurrence is commented out at `xrpc_server.py:34`. Inbound
  inter-service JWTs are therefore never validated.
- Commit signing is real: ECDSA/SHA-256 with explicit low-S normalization (`util.py:271-321`,
  crediting picopds at `util.py:308-309`), verification at `util.py:324-352`. K-256 only
  (`util.py:253-268`).

## 6. Sync 1.1 (inductive firehose) — forensic detail

This is arroba's strongest area. Sync 1.1 landed in 1.0 (`README.md:185-192`).

**`#sync` event emission.** Exactly one call site: `Repo.create`
(`/tmp/gap-scratch/arroba/arroba/repo.py:165-170`). It CAR-encodes just the initial commit block with
that commit as the sole CAR root (`repo.py:166-168`) and writes it via
`storage.write_event(repo=repo, type='sync', blocks=blocks_bytes, rev=...)`. `write_event`
(`storage.py:456-483`) allocates its own seq and stamps
`$type: com.atproto.sync.subscribeRepos#sync`. **`#sync` is emitted only at repo creation** — there is
no periodic re-sync, no desync-repair emission, and no operator trigger.

The emission *order* is wrong and the source says so: `repo.py:162-164` carries the TODO "`#sync` event
should be after `#account`/`#identity` but before first `#commit`". Because `storage.commit` at
`repo.py:155` allocates seq 1 before the three `write_event` calls take seqs 2/3/4, the firehose (which
orders strictly by seq) emits `#commit, #identity, #account, #sync`. The test asserts exactly that
order while flagging it as wrong (`/tmp/gap-scratch/arroba/arroba/tests/test_repo.py:130-131`).

**`prevData` on the commit.** Computed in `firehose.process_event`
(`/tmp/gap-scratch/arroba/arroba/firehose.py:376-382`): read the `prev` CID off the new commit, load
that prev commit block (pre-fetched in bulk during rollback preload, `firehose.py:233-245`), and take
its `data` field. Attached at `firehose.py:421-422` only when non-None, so the repo's first commit
omits the key rather than sending `null` — a deliberate 2.0 fix, since `prevData` is not nullable in the
lexicon (`README.md:168`; test `test_initial_commit_no_prevData`,
`/tmp/gap-scratch/arroba/arroba/tests/test_xrpc_sync.py:1382-1398`). Matches
`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json` `#commit.prevData`
("effectively required for the 'inductive' version of firehose").

**Per-op `prev`.** Captured at commit-build time, not at emit time. In `Storage._commit`, for every
UPDATE or DELETE the pre-image CID is read out of the MST *before* mutation and stored on the
`CommitOp` namedtuple (`storage.py:563-568`, `:574-575`, `:587-588`); a missing path raises `ValueError`
rather than silently proceeding (`storage.py:567-568`). It is persisted to Datastore as
`CommitOp.prev_cid` (`datastore_storage.py:72`) so it survives a rollback-window replay. At emit time
`firehose.py:386-395` writes `prev` into the op dict `if op.action != Action.CREATE` — exactly the
lexicon's rule ("For updates and deletes, the previous record CID... For creations, field should not be
defined", `subscribeRepos.json` `#repoOp.prev`).

**Covering-proof blocks in the CAR slice.** `firehose.process_event` reconstructs an `MST` rooted at the
new commit's `data` CID and calls `add_covering_proofs(event, blocks=event.blocks)`, mutating
`event.blocks` in place (`firehose.py:369-372`); the CAR is then written from that same dict with the
commit CID as sole root (`firehose.py:373-374`, `:397`).

`MST.add_covering_proofs` (`/tmp/gap-scratch/arroba/arroba/mst.py:871-949`) implements the
proposal-0006 operation-inversion proof set. Per op: descend from the root
(`mst.py:897-899`); at each layer decode the node and scan entries reconstructing prefix-compressed keys
(`mst.py:902-922`), tracking the left-neighbour subtree CID and the right-neighbour subtree CID; batch
all three loads through one `read_many` (`mst.py:888-894, 924`); stop when the key is found exactly
(`mst.py:915-917`) or the scan passes it (`mst.py:919-920`). Then walk the right-most spine of the left
neighbour down to the bottom (`mst.py:936-943`) and the left-most spine of the right neighbour
(`mst.py:945-947`) — the adjacency needed to prove a merge/split inversion.

This is verified against **upstream interop fixtures**: `arroba/tests/testdata/commit-proof-fixtures.json`
is "Copied from https://github.com/bluesky-social/atproto-interop-tests"
(`/tmp/gap-scratch/arroba/arroba/tests/testdata/README.md:1`), 6 cases including "two deep split",
"two deep leafless split", "add on edge with neighbor two layers down", "merge and split in multi-op
commit", "complex multi-op commit", "split with earlier leaves on same layer". The driver at
`/tmp/gap-scratch/arroba/arroba/tests/test_testdata.py:44-96` builds the tree, asserts
`rootBeforeCommit` and `rootAfterCommit` CIDs, then asserts
`assertCountEqual(blocksInProof, proofs.keys())` (`test_testdata.py:87-88`). This is the strongest
covering-proof evidence in the study.

Covering proofs are also served on the **read** path: `com.atproto.sync.getRecord`
(`xrpc_sync.py:211-230`) synthesizes a `CommitOp(Action.CREATE, ...)` for the requested path, runs
`add_covering_proofs`, and returns a CAR containing the record block, the head commit block, and the
proof blocks, rooted at the head commit (`xrpc_sync.py:219-230`). That satisfies the lexicon's "Get
data blocks needed to prove the existence or non-existence of record"
(`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getRecord.json`). The head-commit-as-root behavior
is a 3.0 change (`README.md:145`).

**No-op update handling — skip, not reject.** `Storage._commit` snapshots the MST root pointer before
`mst.update`, and if it is unchanged afterwards the `CommitOp` is *omitted* from the ops list, with the
in-source rationale "no-op updates are invalid in ATProto, so only include this update operation if it
changes the the record and MST" (`storage.py:596-605`). But the write is **not rejected**: the record
block was already added to `commit_blocks` at `storage.py:585`, and a new signed commit with a fresh
`rev` is still built (`storage.py:616-627`) and emitted. `test_commit_noop_update_doesnt_commit`
asserts only `repo.head.ops == []` (`/tmp/gap-scratch/arroba/arroba/tests/test_storage.py:450-455`), i.e.
an empty `#commit` frame goes out. The lexicon permits this ("Note that empty commits are allowed",
`subscribeRepos.json` `#commit`), so it is conformant but not the same as rejection.

**Commit size limits.** Constants defined at `storage.py:26-30`. `MAX_OPERATIONS_PER_COMMIT` (200) is
enforced (`storage.py:555-556`) and `MAX_RECORD_SIZE_BYTES` (1 MB) is enforced
(`storage.py:583-584`). `MAX_COMMIT_BLOCKS_BYTES` (2 MB) and `MAX_EVENT_SIZE_BYTES` (5 MB) are **not
enforced** — both checks are commented out at `firehose.py:398-402` and `firehose.py:424-431` with the
note that they should be checked at commit-write time instead.

**Gap: `since` is always null.** `firehose.py:416` hardcodes `'since': None,  # TODO: load
event.commit['prev']'s CID`. The lexicon marks `since` required-and-nullable and defines `prevData` as
"the MST tree for the previous commit from this repo (indicated by the 'since' revision field in this
message)" — so consumers get `prevData` with no matching `since` rev to bind it to.

## 7. Firehose

`subscribeRepos` is implemented as a generator yielding `(header, payload)` dicts
(`xrpc_sync.py:114-163`); DAG-CBOR frame serialization is delegated to `lexrpc.flask_server`
(`app.py:123`). Event types the code can emit: `#commit` (`firehose.py:404-407`), plus `#sync`,
`#identity`, `#account`, `#tombstone` via `write_event`'s allowlist (`storage.py:470`) and the generic
fragment path (`firehose.py:356-361`), plus `#info`/`OutdatedCursor` (`xrpc_sync.py:160`).
Note `#tombstone` is **no longer in the canonical union** — `subscribeRepos.json` `main.message.schema.refs`
is `['#commit', '#sync', '#identity', '#account', '#info']` and there is no `tombstone` def — yet
`Storage.tombstone_repo` still writes one (`storage.py:292-308`).

Sequencing: a single `Sequences.allocate(SUBSCRIBE_REPOS_NSID)` per commit or event
(`storage.py:513`, `:472`), and the commit `rev` is derived from that same seq —
`'rev': util.int_to_tid(seq, clock_id=0)` with the comment "reuse subscribeRepos sequence number as
rev" (`storage.py:619-621`). So rev order and seq order are identical by construction.

Fan-out architecture (redesigned in 1.0 for near-constant per-subscriber cost, `README.md:200`): one
singleton daemon `Collector` thread (`firehose.py:205-343`) polls `read_events_by_seq` and pushes each
processed event to every subscriber's queue plus the shared `rollback` deque (`firehose.py:333-339`).
`process_event` runs **once per event**, not once per subscriber.

- Backfill window: `rollback` is a `deque(maxlen=ROLLBACK_WINDOW)`, default 50 000
  (`firehose.py:30`, `:241-245`); `PRELOAD_WINDOW` default 4 000 events are read from storage at
  startup (`firehose.py:32`, `:226-249`).
- Cursor resume: `cursor > current seq` → `FutureCursor` error frame (`xrpc_sync.py:150-153`);
  `cursor` older than the rollback start → `#info`/`OutdatedCursor` then clamp
  (`xrpc_sync.py:156-161`). A cursor behind the in-memory window is served straight from storage and
  then handed off to the live deque (`firehose.py:126-194`).
- Gap handling: seqs allocated but never used are marked lost (`firehose.py:94-102`) and skipped;
  otherwise the collector waits for a missing seq up to `SUBSCRIBE_REPOS_SKIPPED_SEQ_DELAY` (120 s) if
  within `SUBSCRIBE_REPOS_SKIPPED_SEQ_WINDOW` (300 seqs) of head, then gives up
  (`firehose.py:292-314`). Non-monotonic emission is refused and logged
  (`firehose.py:436-443`); the in-source comment at `firehose.py:326-330` notes that going backward
  "breaks Bluesky's own relays for our PDS".
- Slow consumers: **not handled.** Each subscriber gets an unbounded `SimpleQueue`
  (`firehose.py:177`, `:335-339`); `ConsumerTooSlow` (a declared lexicon error) is never raised and no
  connection is ever dropped for lag.
- The collector must be started by the embedding app — `firehose.start()` is called **only from
  tests** (grep: all hits are in `arroba/tests/test_xrpc_sync.py`). `app.py` wires the repo callback
  (`app.py:135-141`) but never calls `firehose.start()`, so `subscribe()`'s `started.wait()`
  (`firehose.py:114`) would block in the shipped demo.

## 8. Account migration / import-export

- `com.atproto.repo.importRepo` — implemented (`xrpc_repo.py:210-262`). Reads the CAR, locates the
  head commit, **verifies its signature against the signing key in the source DID doc**
  (`xrpc_repo.py:241-244`), refuses if a repo already exists for that DID (`xrpc_repo.py:238-239`),
  writes all blocks with `seq=0` so they are never replayed on the firehose (`xrpc_repo.py:229`), and
  creates the repo in `status='deactivated'` with freshly generated signing/rotation keys
  (`xrpc_repo.py:260-261`).
- `com.atproto.sync.getRepo` — export, with `since` diff support (`xrpc_sync.py:45-67`).
- `com.atproto.repo.listMissingBlobs` — **missing**, no handler, no primitive.
- `com.atproto.server.checkAccountStatus` — **missing.**
- `activateAccount` / `deactivateAccount` — **n/a as endpoints**; library primitives
  `Storage.activate_repo` / `deactivate_repo` exist and emit `#account` events
  (`storage.py:256-291`).
- `identity.signPlcOperation` / `submitPlcOperation` / `getRecommendedDidCredentials` —
  **n/a as endpoints**; `did.write_plc` / `write_plc_operation` / `update_plc` / `rollback_plc`
  (`did.py:142`, `:249`, `:115`, `:285`) cover the PLC mechanics for an embedding app.

The result: arroba can *receive* a migrating repo but the migration handshake (status polling, blob
reconciliation, PLC rotation endpoints) has to be built by the embedder.

## 9. did:plc vs did:web

`did.resolve` dispatches on prefix and supports exactly two methods, raising otherwise
(`did.py:50-70`): `resolve_plc` fetches `https://$PLC_HOST/{did}` (`did.py:75-102`), `resolve_web`
handles `did:web` (`did.py:455`). No `did:webvh`.

- **Account DIDs**: either. Repo DIDs are opaque strings threaded through `Storage.commit`
  (`storage.py:526-548`); tests routinely use `did:web:user.com`
  (`/tmp/gap-scratch/arroba/arroba/tests/test_storage.py:451`). `did:plc` creation is scripted in
  `/tmp/gap-scratch/arroba/create_identity.py` via `did.create_plc`.
- **Service DID**: `did:web` only, synthesized from the host — `describeServer` returns
  `f'did:web:{os.environ["PDS_HOST"]}'` (`xrpc_server.py:62`), and `service_jwt` defaults its audience
  to `did:web:{host}` (`util.py:378`), with a docstring caveat that mod services use `did:plc` instead
  (`util.py:366-367`).
- did:plc write support is comparatively rich: create/update/rollback with optional
  `new_rotation_key` (`did.py:142-247`, `:285-326`), genesis-op signing and `did:key` encode/decode
  (`did.py:327-374`). There is no did:web document *publisher* — only a resolver.

## 10. Blobs

There is no blob store. `com.atproto.repo.uploadBlob` returns 501 (`xrpc_repo.py:273-279`), so arroba
never ingests bytes. Instead, `AtpRemoteBlob` (`datastore_storage.py:398-433`) records metadata for a
blob that lives at a public HTTP URL — the entity key *is* the URL (truncated to the Datastore keypart
limit, `datastore_storage.py:464-470`) — and `com.atproto.sync.getBlob` answers with a **301 redirect**
to that URL plus a 1-day `Cache-Control` (`xrpc_sync.py:31`, `:241-257`).

- Validation: `AtpRemoteBlob.validate` (`datastore_storage.py:588-610`) enforces the lexicon's
  `maxSize` and `accept` (MIME) constraints and a 3-minute video-duration cap (`README.md:226`);
  `BLOB_MAX_BYTES` defaults to 100 MB (`README.md:102`). Dimensions/duration are extracted with
  pymediainfo for `aspectRatio` (`datastore_storage.py:417-426`).
- Liveness: `maybe_fetch` (`datastore_storage.py:491-...`) re-GETs image blobs every
  `BLOB_REFETCH_DAYS` (default 7) and marks them `status='inactive'` on a 4xx
  (`datastore_storage.py:514-516`); `getBlob` skips inactive blobs (`xrpc_sync.py:243-244`).
- Ref-counting / GC: `AtpRemoteBlob.repos` is a repeated KeyProperty that is only ever **appended to**
  (`datastore_storage.py:478-480`). Nothing removes a repo from that list on record delete, and no
  sweeper exists. So there is no blob GC — which is largely moot given nothing is stored locally.

## 11. Moderation / admin / takedown

None. No `com.atproto.admin.*`, `com.atproto.moderation.*`, or `com.atproto.label.*` handler is
registered anywhere. There is no label store, no report intake, no per-record takedown.

The only enforcement surface is repo-level status. `Repo.status` is `None` or one of
`deactivated` / `deleted` / `tombstoned` (`repo.py:44-47`, `datastore_storage.py:95`). Reads are gated
in `server.load_repo`, which raises `RepoDeactivated` for any non-null status
(`/tmp/gap-scratch/arroba/arroba/server.py:41-43`), and writes are gated in `Storage._commit`, which
raises `InactiveRepo` (`storage.py:529-530`). `getRepoStatus` reports it as
`active: false, status: 'deactivated'` (`xrpc_sync.py:73-83`) — note it collapses *every* status to the
literal `'deactivated'` there, and `listRepos` separately maps `tombstoned → deactivated`
(`xrpc_sync.py:93`). The canonical lexicon's `knownValues` include `takendown` and `suspended`, which
arroba can neither set nor report.

## 12. Rate limiting, metrics, health, ops

- Rate limiting: **none.** No middleware, no counters, no `RateLimitExceeded` anywhere in
  `arroba/*.py` or `app.py`.
- Metrics: **none.** No Prometheus/OpenTelemetry/statsd. Observability is Python `logging` plus
  `google.cloud.logging` in the demo app (`app.py:52-55`).
- Health: `/liveness_check` and `/readiness_check` returning `'OK'` in the demo app
  (`app.py:161-168`), matching App Engine Flex's updated health checks.
- Resilience details that do exist: an explicit 30 s Datastore query timeout after observed indefinite
  hangs (`datastore_storage.py:830-843`), ndb `ContextError` recovery that re-issues the block query
  from the last seq (`datastore_storage.py:854-862`), a collector loop that swallows and logs uncaught
  exceptions rather than dying (`firehose.py:256-262`), and SSRF-hardened outbound HTTP via
  `requests-hardened` (`README.md:136`).
- Relay notification is a 5-minute-delayed one-shot `requestCrawl` timer in the demo app
  (`app.py:193-203`), not a library feature.

## 13. Notable spec deviations and explicitly-unsupported features

The README has no "Status" or "Known issues" section; candid statements are scattered through the
config docs, changelog, and docstrings. Quoting the ones that exist, with code corroboration:

| Statement | Where | Code agrees? |
|---|---|---|
| "If not set, XRPC methods that require auth will return HTTP 501 Not Implemented." | `README.md:96` | Yes — `server.py:24-26` raises `NotImplementedError` |
| "KNOWN ISSUE: cursor is interpreted as inclusive, so whenever a cursor is used, the response includes the last record returned in the previous response." | `xrpc_repo.py:122-124` | Yes — `xrpc_repo.py:139-143` starts the walk *at* the cursor key |
| "TODO: filesystem storage" | `README.md:66` | Yes — only `MemoryStorage` and `DatastoreStorage` exist |
| "TODO: `#sync` event should be after `#account`/`#identity` but before first `#commit`" | `repo.py:162-164` | Yes — seq order forces `#commit` first; `test_repo.py:130-131` |
| "`'since': None,  # TODO: load event.commit['prev']'s CID`" | `firehose.py:416` | Yes — `since` is always null on the firehose |
| "TODO: this is a sync v1.1 limit. ideally we should check it at commit write time" | `firehose.py:398-402`, `:424-431` | Yes — both size checks are commented out |
| "it's not automatically registered with the XRPC server" (subscribeRepos) | `xrpc_sync.py:121-124` | **No** — the decorator at `xrpc_sync.py:114` registers it |

Additional deviations found only in code:

1. `createSession` performs **no credential check** (`xrpc_server.py:13-25`) — any caller who knows a
   handle or DID gets the shared token back.
2. `getSession` ignores the caller entirely and returns the process-global repo
   (`xrpc_server.py:35-38`) — wrong answer on any multi-repo deployment.
3. `swapCommit` / `swapRecord` rejected on every write (`xrpc_repo.py:34-36`); no CAS.
4. `#tombstone` is still emitted (`storage.py:292-308`, `:470`) though it has been dropped from the
   `subscribeRepos` union in the canonical lexicon.
5. `getRepoStatus` never returns `rev`, and maps all statuses to `'deactivated'`
   (`xrpc_sync.py:70-87`).
6. `listBlobs` rejects `since` (`xrpc_sync.py:263-264`); `listRecords` rejects `reverse`
   (`xrpc_repo.py:130-131`); `repo.getRecord` rejects `cid` (`xrpc_repo.py:60-61`).
7. `DISABLE_GETREPO` can disable full-repo export for repos older than 12 h, bypassable only with a
   shared `GETREPO_TOKEN` (`xrpc_sync.py:52-59`, `README.md:108-109`) — a documented, deliberate
   deviation from "does not require auth" in `sync/getRepo.json`.

### MST implementation quality

The MST is a close port of `bluesky-social/atproto/packages/repo/src/mst/mst.ts`, credited as such
(`mst.py:7-11`), with the full node algebra: `add`/`update`/`delete` with recursive split/merge
(`mst.py:287-457`), `split_around` / `append_merge` / `trim_top` (`mst.py:582`, `:614`, `:563`),
prefix-compressed serialization (`mst.py:1022-1063`), `leading_zeros_on_hash` fanout
(`mst.py:952-978`), key validation (`mst.py:1088`), and a `Walker` for ordered traversal
(`mst.py:1115-1220`). `diff.py` implements deterministic minimal MST diffs (282 lines).

Test coverage of the MST is layered:

1. **Upstream interop fixtures**, vendored: `common_prefix.json`, `key_heights.json`, and
   `commit-proof-fixtures.json`, all "Copied from
   https://github.com/bluesky-social/atproto-interop-tests" (`arroba/tests/testdata/README.md:1`),
   driven by generated test methods in `test_testdata.py:26-96`. These pass in CI.
2. **`mst-test-suite/`** — a git submodule pointing at `DavidBuchanan314/mst-test-suite`
   (`/tmp/gap-scratch/arroba/.gitmodules:1-3`). The directory is **empty in this checkout**, and the
   CircleCI job never runs `git submodule update` (`.circleci/config.yml:13-30`) — it clones
   `bluesky-social/atproto` but not the suite. The harness at
   `/tmp/gap-scratch/arroba/arroba/tests/mst_test_suite.py:28-37` discovers cases by `os.walk` over
   `./mst-test-suite/tests/`, which yields nothing for a missing directory, so both tests pass
   vacuously in CI.
3. What that harness *would* cover, when populated: only `$type == "mst-diff"` cases
   (`mst_test_suite.py:35`), run against both `MemoryStorage` and `DatastoreStorage`
   (`mst_test_suite.py:143-157`), checking `record_ops`, `created_nodes`, `deleted_nodes`
   (`mst_test_suite.py:105-110`) and an inverse-application round trip
   (`mst_test_suite.py:113-140`). The author's own inline comments mark several of these as failing:
   `# currently fails!` on `created_nodes` (`mst_test_suite.py:108`), `# fails occasionally` on the
   inverse new root (`:138`), and `# basically always fails, I think I'm doing something wrong` on the
   inverse CID set (`:140`). `proof_nodes` and `firehose_cids` checks are an explicit TODO
   (`mst_test_suite.py:111`).

So: strong, CI-verified conformance on commit proofs and key-height/prefix primitives; the broader
diff-suite conformance is claimed but not actually exercised, and is self-reported as partly failing.

## 14. Maturity tier

**serious.**

It is the repo/MST/firehose engine running under Bridgy Fed in production — the changelog is a running
log of production incidents (`README.md:138` on hanging Datastore queries, `:180` on uncaught firehose
exceptions, `:194`, `:225`) and the code links a live Google Cloud error console for
`service=atproto-hub ... project=bridgy-federated` (`datastore_storage.py:836`) — and it implements
Sync 1.1 more completely and more verifiably than any non-reference implementation here, passing the
upstream `atproto-interop-tests` commit-proof fixtures outright. It is not "reference" because it is
deliberately a library plus a demo: no account creation, no real session or OAuth auth, no blob upload,
no moderation surface, and 501 stubs for `applyWrites`/`uploadBlob` — an operator cannot stand it up as
a general-purpose PDS without writing the missing half themselves.

---

## Confidence & unknowns

- **UNVERIFIED: firehose wire framing.** arroba yields `(header, payload)` Python dicts
  (`xrpc_sync.py:143-144`); the DAG-CBOR frame encoding, WebSocket upgrade, and error-frame shape are
  all inside `lexrpc.flask_server` (`app.py:123`), which is not vendored here and is not installed in
  this environment (`import lexrpc` → `ModuleNotFoundError`). To verify I would need the `lexrpc`
  source (github.com/snarfed/lexrpc).
- **UNVERIFIED: which lexicons `Server(validate=True)` validates against.** `server.py:16` enables
  validation and `storage.py:580` calls `server.validate(record['$type'], 'record', record)`, but the
  lexicon catalog ships with `lexrpc`, not arroba. Whether it tracks current `com.atproto`/`app.bsky`
  lexicons — and therefore whether e.g. the `#tombstone` emission would be rejected at validation
  time — could not be checked.
- **UNVERIFIED: production scale claims.** I cite the bridgy-federated error-console link
  (`datastore_storage.py:836`) and bridgy-fed issue references in the changelog as evidence of
  production use; I did not verify repo counts, qps, or uptime.
- **UNVERIFIED: `getRepo` `since` diff correctness.** `mst.py:800-847` filters by block `seq >= start`
  while descending and skips whole subtrees below the threshold, but leaf blocks are re-read without a
  seq filter (`mst.py:845-847`). Whether the emitted diff is exactly minimal, or a superset, would need
  a differential test against the reference implementation.
- **UNVERIFIED: `mst-test-suite` pass rate.** The submodule is unpopulated in this checkout, so I could
  only read the harness and its inline failure comments (`mst_test_suite.py:108`, `:138`, `:140`), not
  run it. I did not fetch `DavidBuchanan314/mst-test-suite` to count cases.
- **Partly inferred: `firehose.start()` never being called in `app.py`.** Established by grep (all hits
  are in tests) and by reading `app.py` end to end; I did not run the demo app to confirm the resulting
  block on `started.wait()` (`firehose.py:114`).
- Endpoint enumeration is exhaustive for the decorator-based registry
  (`@server.server.method` / `server.server.register`). If `lexrpc` exposes another registration path
  that arroba uses indirectly, it would not appear in my grep — but no such call exists in
  `arroba/*.py` or `app.py`.
