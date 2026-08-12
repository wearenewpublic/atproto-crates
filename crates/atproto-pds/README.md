# atproto-pds

EXPERIMENTAL - FOR THE LOVE OF GOD DON'T USE THIS YET.

AT Protocol Personal Data Server — server library and binaries.

This crate provides the production PDS server (`pds` binary) and the admin
CLI (`atproto-pds-admin` binary). It builds on the rest of the
`atproto-crates` workspace plus the `atproto-space` crate (permissioned-data
primitives) and is the second PDS implementation overall to ship Spaces, the
first in Rust.

## Production status

The PDS is **single-node deployable for federated public traffic**. All
foundational subsystems (storage profile dispatch, federation gaps, admin
endpoints, OAuth provider, Sync 1.1 protocol, identity gaps, user-facing
endpoints, env-var consumers, account migration, and operational
hardening) are shipped end-to-end. Both heavy storage-layer batches are
also closed:

- **fjall public-realm sweep** — every public-realm read + write path
  (writer, reader, importer, CAR exporter, outbox, subscribeRepos)
  routes through the `PublicRealmBackend` trait surface.
- **Postgres accounts cutover** — every accounts-DB call site routes
  through the runtime-dispatch `AccountPool` enum so SQLite and
  Postgres deployments share a single code path.

CI gates: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, and `cargo test --workspace` are enforced on
every push to main and every pull request (see
[`.tangled/workflows/ci.yml`](../../.tangled/workflows/ci.yml)).

The test suite includes known-answer conformance vectors from
[`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests),
vendored at [`tests/interop/`](../../tests/interop/). Those are the only tests
in the workspace that compare against an external oracle rather than against
this codebase's own output; vectors that do not pass yet are listed in each
harness's `KNOWN_FAILURES` table alongside the finding that explains them.

## Surface

XRPC endpoints (default features):

- **`com.atproto.repo.*`** — `getRecord`, `listRecords`, `describeRepo`,
  `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `importRepo`,
  `listMissingBlobs`.
- **`com.atproto.sync.*`** — `getLatestCommit`, `getRepoStatus`, `getRepo`
  (CAR streaming, `?since=<rev>` diff slice), `getBlocks`, `listRepos`,
  `subscribeRepos` (broadcast-channel WS with poll-fallback for catch-up).
- **`com.atproto.server.*`** — `describeServer`, `createAccount` (with optional PLC genesis),
  `createSession`, `getSession`, `refreshSession`, `deleteSession`,
  `createAppPassword`, `listAppPasswords`, `revokeAppPassword`,
  `createInviteCode`, `getServiceAuth`, `activateAccount`,
  `deactivateAccount`, `checkAccountStatus`, `reserveSigningKey`,
  `requestEmailUpdate`, `confirmEmailUpdate`, `requestEmailConfirmation`,
  `confirmEmail`, `requestPasswordReset`, `resetPassword`,
  `requestAccountDelete`, `deleteAccount`.
- **`com.atproto.identity.*`** — `resolveHandle`, `updateHandle`,
  `requestPlcOperationSignature`, `signPlcOperation`, `submitPlcOperation`,
  `getRecommendedDidCredentials`, `refreshIdentity`.
- **OAuth 2.1** — `/oauth/par`, `/oauth/authorize` (HTML consent + JSON POST),
  `/oauth/token` (rate-limited, PKCE+DPoP+refresh-rotation), `/oauth/revoke`
  (RFC 7009), `/oauth/jwks`, `/.well-known/oauth-authorization-server`,
  `/.well-known/oauth-protected-resource`. Multi-key JWK rotation is
  supported via `PDS_OAUTH_KEYS_JWK_SET`.
- **Identity discovery** — `/.well-known/atproto-did` resolves a handle hosted
  on this server's own domain to its DID; `/.well-known/did.json` serves this
  server's own `did:web` document, synthesised from `PDS_SERVICE_DID` rather
  than read from a file.
- **Spaces** — owner-side management under `com.atproto.simplespace.*`
  (`createSpace`, `updateSpace`, `deleteSpace`, `addMember`, `removeMember`,
  `listMembers`) and the permissioned realm under `com.atproto.space.*`
  (`getSpace`, `listSpaces`, `applyWrites`, `createRecord`, `putRecord`,
  `deleteRecord`, `getRecord`, `listRecords` (values inlined by default,
  `excludeValues` for keys only), `getBlob`,
  `listRepos`, `getRepoState`, `listRepoOps`, `getDelegationToken` →
  `getSpaceCredential` (the two-step delegation-token/credential exchange,
  replay-protected via the in-memory JTI guard with optional Valkey/Redis
  backing), `registerNotify`/`unregisterNotify`, and the contentless
  `notifyWrite`/`notifySpaceDeleted` inbound hooks). Aligned to the published
  0016 Permissioned Data spec.
- **Admin** (`com.atproto.admin.*`) — `getAccountInfo`, `getAccountInfos`,
  `getSubjectStatus`, `updateSubjectStatus`, `deleteAccount`,
  `searchAccounts`, `getInviteCodes`, `disableInviteCodes`,
  `disableAccountInvites`, `enableAccountInvites`, `updateAccountEmail`,
  `updateAccountHandle`, `updateAccountPassword`, `sendEmail`,
  `takedownSpaceRecord`, `revokeServiceAuth`, `forceRepoSync`. HTML
  operator dashboard at `GET /admin`.
- **Federation** — Inbound `notifyWrite` / `notifySpaceDeleted` receipts,
  outbound `requestCrawl` announcements, default-pin `Atproto-Proxy`
  routing for `app.bsky.*` plus per-request override via header.

Health: `GET /_alive`, `GET /_ready`, `GET /xrpc/_health`. Prometheus
metrics at `GET /metrics` when the `metrics` feature is on.

## Storage profiles

Two backends for the per-actor store, selected at compile time:

- **SQLite (default)** — per-actor SQLite files. Matches the upstream
  0016 Permissioned Data draft exactly. `cargo build` (or `cargo install`)
  produces this profile.
- **fjall** — single fjall `Database` per data-dir with one `Keyspace`
  per logical table. Lower-overhead single-host alternative; build with
  `--features fjall` **on top of the defaults**. The trait dispatch
  (`PublicRealmBackend` + `AtomicCommitWriter`) lifts every public-realm read
  + write path through the same surface.

The profiles are alternatives for the per-actor store and nothing else, so
`fjall` is additive rather than a replacement: the `sqlite` feature stays on
because the accounts database below is SQLite either way. Turning defaults off
does not produce a fjall build, it produces one that does not compile — the
crate refuses at build time with a message saying so.

For the cross-account accounts DB:

- **SQLite** — one shared SQLite at `PDS_DATA_DIRECTORY/accounts.sqlite`.
  This is the only supported accounts backend.

Per-actor SQLite vs fjall is independent of the accounts DB.

## Unsupported deployment modes

Two backends exist in the source tree, compile behind Cargo features, and
have tests — and are **not wired into the `pds` binary**. They are listed
here so nobody discovers that the hard way.

- **PostgreSQL accounts DB** (`postgres` feature, `PDS_POSTGRES_URL`).
  `AccountDirectory::open_postgres` exists and 57 of 59 accounts-DB query
  sites already dispatch per dialect, but thirteen production call sites —
  the OAuth state store, the JTI replay guard and rate-limit SQL backend,
  the GC loop, the notifier, the sequencer, four files of the spaces
  subsystem, and the repository writer's signing-key lookup — take a
  SQLite-only pool accessor that panics on a Postgres pool.
- **S3 blob storage** (`s3` feature, `PDS_BLOB_STORE_URL`).
  `HybridS3BlobStorage` is complete and implements `BlobStorage`; nothing
  constructs it.

**Setting `PDS_POSTGRES_URL` or `PDS_BLOB_STORE_URL` refuses at boot.**
Previously both were parsed and silently ignored, so an operator who
configured either believed they had it and got neither. A documented mode
that does not work is worse than an absent one; a mode that fails loudly at
startup is neither.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `sqlite` | yes | Per-actor SQLite via sqlx. |
| `fjall` | | LSM backend for the per-actor store. |
| `http` | yes | axum router + WebSocket subscribeRepos. |
| `clap` | | Build the `pds` and `atproto-pds-admin` binaries. |
| `hickory-dns` | yes | Hickory resolver via `atproto-identity/hickory-dns`. |
| `smtp` | | SMTP integration via `lettre`. When off, email-issuing endpoints fall back to dev-only INFO logging. |
| `metrics` | | `prometheus-client` exporter at `GET /metrics` + axum request-counter middleware. |
| `valkey` | | Valkey/Redis-backed JTI replay guard + sliding-window rate limiter. Wins over `--durability-profile` when `PDS_VALKEY_URL` is set. |
| `otel` | | OpenTelemetry OTLP HTTP/protobuf tracing exporter. Activated when `PDS_OTEL_ENDPOINT` is set. |
| `postgres-live-tests` | | Exercises the Postgres accounts adapter against a live instance (`tests/feature_postgres_live.rs`, DSN from `PDS_POSTGRES_TEST_URL`). Keeps the unsupported adapter compiling and correct; see **Unsupported deployment modes**. Emits an INFO skip and reports OK when the env var is unset. |

## Binaries

- **`pds`** — the production server. Reads config from environment + flags
  (see `--help`); writes to `PDS_DATA_DIRECTORY`. Drains on SIGTERM/SIGINT
  via a coordinated shutdown controller (cancels long-lived workers, lets
  in-flight requests complete, closes WebSocket subscribers cleanly). The
  whole drain is bounded by `PDS_SHUTDOWN_DEADLINE_SECS` (default 25); set
  it below whatever grace period your supervisor allows between SIGTERM and
  SIGKILL, so the process gets to log an unfinished drain and flush its
  telemetry rather than being killed mid-drain.
- **`atproto-pds-admin`** — operational CLI. Subcommands for invite-code
  issuance, account inspection, takedown, etc.

## Building

```bash
# Default (SQLite) profile binary build:
cargo build --features clap,smtp,metrics,hickory-dns --bin pds --bin atproto-pds-admin

# Run the server (dev defaults):
PDS_DATA_DIRECTORY=./.pds-data \
PDS_SERVICE_DID=did:web:pds.example.com \
PDS_JWT_SECRET=$(openssl rand -hex 32) \
PDS_ADMIN_PASSWORD=$(openssl rand -hex 16) \
  cargo run --features clap,smtp,metrics,hickory-dns --bin pds

# fjall-profile build (additive — the defaults stay on):
cargo build --features clap,fjall,smtp,metrics \
  --bin pds --bin atproto-pds-admin
```

## Container image

A multi-stage `Dockerfile` lives next to this README. Build with:

```bash
docker build -t atproto-pds:dev -f crates/atproto-pds/Dockerfile .
```

The image runs as non-root (`pds` UID 1000), exposes 3000, and includes a
`HEALTHCHECK` against `/xrpc/_health`. Front it with a reverse proxy for
TLS, large request bodies, and WS upgrades.

## Request-body limits

Two ceilings, both operator-tunable. The application enforces them itself and
refuses over-sized requests as XRPC errors, so a client sees the same error
shape it sees everywhere else rather than a bare `413 text/plain`.

| Variable | Default | Bounds |
| --- | --- | --- |
| `PDS_BLOB_UPLOAD_LIMIT` | 16 MiB | one blob through `com.atproto.repo.uploadBlob` |
| `PDS_IMPORT_LIMIT` | 1 GiB | one repository CAR through `com.atproto.repo.importRepo` |

Size the reverse proxy's own body limit to whatever you set here, or it will
reject first and the operator-facing error will be the proxy's, not the PDS's.

## Tests

```bash
# Default (SQLite + http + clap):
cargo test -p atproto-pds --features http,clap

# With fjall feature (adds the fjall storage parity suite):
cargo test -p atproto-pds --features http,clap,fjall

# With Postgres accounts adapter:
cargo test -p atproto-pds --features http,clap,postgres

# All features:
cargo test --workspace --all-features

# Live Postgres CRUD round-trip (requires a running Postgres):
PDS_POSTGRES_TEST_URL=postgres://pds:pds@127.0.0.1:5432/pds_live \
  cargo test -p atproto-pds --features postgres-live-tests \
    --test feature_postgres_live
```

## License

MIT — see [LICENSE](../../LICENSE).
