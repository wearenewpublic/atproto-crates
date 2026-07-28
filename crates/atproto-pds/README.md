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
  (CAR streaming, `?since=<rev>` diff slice), `getBlocks`, `subscribeRepos`
  (broadcast-channel WS with poll-fallback for catch-up).
- **`com.atproto.server.*`** — `createAccount` (with optional PLC genesis),
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
- **Spaces** — owner-side management under `com.atproto.simplespace.*`
  (`createSpace`, `updateSpace`, `deleteSpace`, `addMember`, `removeMember`,
  `listMembers`) and the permissioned realm under `com.atproto.space.*`
  (`getSpace`, `listSpaces`, `applyWrites`, `createRecord`, `putRecord`,
  `deleteRecord`, `getRecord`, `listRecords` (keys-only), `getBlob`,
  `listRepos`, `getRepoState`, `listRepoOps`, `getDelegationToken` →
  `getSpaceCredential` (the two-step delegation-token/credential exchange,
  replay-protected via the in-memory JTI guard with optional Valkey/Redis
  backing), `registerNotify`, and the contentless
  `notifyWrite`/`notifySpaceDeleted` inbound hooks). Aligned to the published
  0016 Permissioned Data spec.
- **Admin** (`com.atproto.admin.*`) — `getAccountInfo`, `getAccountInfos`,
  `getSubjectStatus`, `updateSubjectStatus`, `deleteAccount`,
  `searchAccounts`, `getInviteCodes`, `disableInviteCodes`,
  `disableAccountInvites`, `enableAccountInvites`, `updateAccountEmail`,
  `updateAccountHandle`, `updateAccountPassword`, `sendEmail`,
  `takedownSpaceRecord`, `revokeServiceAuth`, `forceRepoSync`. HTML
  operator dashboard at `GET /admin`.
- **Federation** — Inbound `notifyWrite` / `notifyMembership` receipts,
  outbound `requestCrawl` announcements, default-pin `Atproto-Proxy`
  routing for `app.bsky.*` plus per-request override via header.

Health: `GET /_alive`, `GET /_ready`, `GET /xrpc/_health`. Prometheus
metrics at `GET /metrics` when the `metrics` feature is on.

## Storage profiles

Two compile-time-mutually-exclusive backends for the per-actor store:

- **SQLite (default)** — per-actor SQLite files. Matches the upstream
  0016 Permissioned Data draft exactly. `cargo build` (or `cargo install`)
  produces this profile.
- **fjall** — single fjall `Database` per data-dir with one `Keyspace`
  per logical table. Lower-overhead single-host alternative; build with
  `--no-default-features --features fjall,smtp,metrics,hickory-dns`. The
  trait dispatch (`PublicRealmBackend` + `AtomicCommitWriter`) lifts
  every public-realm read + write path through the same surface.

For the cross-account accounts DB:

- **SQLite (default)** — one shared SQLite at
  `PDS_DATA_DIRECTORY/accounts.sqlite`.
- **PostgreSQL** — opt in via `--features postgres` plus the
  `PDS_POSTGRES_URL` env var. Every accounts-DB call site routes
  through the `AccountPool` runtime-dispatch enum, so SQLite and
  Postgres share a single code path.

Per-actor SQLite vs fjall is independent of the accounts-DB choice.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `sqlite` | yes | Per-actor SQLite via sqlx. |
| `fjall` | | LSM backend for the per-actor store. |
| `postgres` | | PostgreSQL accounts adapter. Selected via `PDS_POSTGRES_URL` at boot. |
| `http` | yes | axum router + WebSocket subscribeRepos. |
| `clap` | | Build the `pds` and `atproto-pds-admin` binaries. |
| `hickory-dns` | yes | Hickory resolver via `atproto-identity/hickory-dns`. |
| `smtp` | | SMTP integration via `lettre`. When off, email-issuing endpoints fall back to dev-only INFO logging. |
| `metrics` | | `prometheus-client` exporter at `GET /metrics` + axum request-counter middleware. |
| `valkey` | | Valkey/Redis-backed JTI replay guard + sliding-window rate limiter. Wins over `--durability-profile` when `PDS_VALKEY_URL` is set. |
| `s3` | | `HybridS3BlobStorage` — blob bytes go to S3, ref tracking stays relational. Selected via `PDS_BLOB_STORE_URL=s3://...`. |
| `otel` | | OpenTelemetry OTLP HTTP/protobuf tracing exporter. Activated when `PDS_OTEL_ENDPOINT` is set. |
| `postgres-live-tests` | | Opt in to the live-CRUD acceptance suite in `tests/feature_postgres_live.rs`. Reads the target DSN from `PDS_POSTGRES_TEST_URL`; emits an INFO skip + reports OK when the env var is unset, so CI without a Postgres instance still passes. |

## Binaries

- **`pds`** — the production server. Reads config from environment + flags
  (see `--help`); writes to `PDS_DATA_DIRECTORY`. Drains on SIGTERM/SIGINT
  via a coordinated shutdown controller (cancels long-lived workers, lets
  in-flight requests complete, closes WebSocket subscribers cleanly).
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

# fjall-profile build:
cargo build --no-default-features --features clap,fjall,smtp,metrics,hickory-dns \
  --bin pds --bin atproto-pds-admin
```

## Container image

A multi-stage `Dockerfile` lives next to this README. Build with:

```bash
docker build -t atproto-pds:dev -f crates/atproto-pds/Dockerfile .
```

The image runs as non-root (`pds` UID 1000), exposes 3000, and includes a
`HEALTHCHECK` against `/xrpc/_health`. Front it with a reverse proxy for
TLS, large request bodies (>1 GiB for `importRepo`), and WS upgrades.

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
