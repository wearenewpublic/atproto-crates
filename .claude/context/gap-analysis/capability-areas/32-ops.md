# L. Cross-cutting ops

Capability-area chapter of the release-candidate gap analysis for **atproto-crates** `0.15.0-rc.1`.
See also: [inventory](../00-atproto-crates-inventory.md) · [coverage matrix](../20-coverage-matrix.md) ·
[synthesis & roadmap](../50-synthesis-and-roadmap.md) · [index](../README.md) ·
[permissioned-data overview](../permissioned/40-permissioned-overview.md).

Citations are repo-relative for atproto-crates and absolute under `/tmp/gap-scratch/` for comparisons.

---

## Assessment

A public multi-account PDS is an internet-facing service that mints credentials, stores other people's
data, and hands strangers an unauthenticated `createAccount` and `createSession`. Abuse limiting,
observability, backup, mail, secret handling and a repeatable deployment are not decoration on top of
protocol work — they are the difference between a server you can run for other people and one you can
only demo. atproto-crates says both things about itself: `crates/atproto-pds/README.md:15-16` claims the
PDS is "single-node deployable for federated public traffic," while `:3` says "EXPERIMENTAL - FOR THE
LOVE OF GOD DON'T USE THIS YET." This chapter is largely about which claim the ops surface supports.

The honest summary is that atproto-crates built good machinery and wired almost none of it to the
request path. The sliding-window limiter (`crates/atproto-pds/src/security.rs:299-520`) is a real
three-backend implementation with an atomic Valkey `ZSET` (`crates/atproto-pds/src/valkey_backend.rs:131-211`)
that only tranquil-pds matches; it is called at four sites in the whole crate. The OTLP exporter
(`crates/atproto-pds/src/telemetry.rs:32-67`) is ahead of everyone including the reference. The
Prometheus registry carries two counters. `ShutdownController::wait_drain()` has a 30-second deadline
(`crates/atproto-pds/src/shutdown.rs:82-85`) the binary never calls. `--config` is documented with a
precedence chain (`crates/atproto-pds/src/bin/pds.rs:42`) and never read. The pattern repeats often
enough to be this chapter's through-line: components pass their unit tests and connect to nothing.

Rate limiting is the headline and calibration matters. It would be wrong to say atproto-crates has none;
the orchestrator's verified note says so explicitly
(`/tmp/gap-scratch/verified-commit-divergences.md:145-147`). What it has is limiting on four endpoints,
each keyed on a string the attacker supplies, and no per-IP limiting — the server runs
`axum::serve(listener, app)` (`crates/atproto-pds/src/bin/pds.rs:745`) rather than
`into_make_service_with_connect_info`, so the peer address never reaches a handler. This is where the
independent field is unambiguously ahead. **Alteran — hobby-experiment tier, single-user on Cloudflare
Workers — keys write and blob buckets on `cf-connecting-ip`
(`/tmp/gap-scratch/alteran/src/lib/ratelimit.ts:16-19`) and runs a five-strike, fifteen-minute per-IP
login lockout (`.../createSession.ts:16-17,80-116`).** Metalbear installs its token bucket into the XRPC
server globally (`/tmp/gap-scratch/metalbear/src/server.c:6958-6959`); pegasus keys login on identifier
plus IP (`.../createSession.ml:35`); the reference runs a 3000-per-IP-per-5-minutes global bucket
(`/tmp/gap-scratch/atproto/packages/pds/src/rate-limits.ts:31-44`) behind a `trust proxy` allowlist
(`index.ts:116-124`). Four serious peers (cocoon, rsky-pds, arroba, effectively zds) also lack
meaningful limiting, so atproto-crates is not alone — but none claim public-traffic readiness, and
rsky-pds carries a literal `// @TODO: Add rate limiting`
(`/tmp/gap-scratch/rsky/rsky-pds/src/apis/com/atproto/server/create_session.rs:112`) rather than a doc
comment asserting the limiter is universal, which is what `crates/atproto-pds/src/security.rs:6` does.

Outside rate limiting the picture is mixed rather than bad. Health probes are the strongest cell here and
beat the reference; configuration is a broad 40-variable surface with a real production gate;
multi-account hosting is genuine. But there is no backup or restore of any kind, the shipped container
cannot send email, the shipped `deploy/` cluster cannot resolve its own `did:web`, request bodies are
capped three orders of magnitude below what the README tells operators to configure, and no CI runs
`fmt`/`clippy`/`test` despite `crates/atproto-pds/README.md:29-32` citing a workflow file that does not
exist. For an artifact tagged `rc.1`, the missing CI is what most undermines confidence in everything
else here.

---

## 1. Rate limiting

**Per-IP limiting — MISSING.** A grep for `ConnectInfo`, `X-Forwarded-For`, `SocketAddr`, `peer_addr`
and `remote_addr` over `crates/atproto-pds/src/` returns two hits, both the *listen*-address parse
(`bin/pds.rs:25`, `:681`). Because `bin/pds.rs:745` uses plain `axum::serve`, no handler can obtain the
peer address, and no forwarded-header parsing exists to recover it from behind the cloudflared proxy that
`deploy/cloudflared/config.yml.tmpl` puts in front. The consequence, per
`/tmp/gap-scratch/verified-commit-divergences.md:161-166`: a password sprayer varies `identifier` and a
signup flood varies `handle` to get a fresh 300-request bucket per attempt, so the limiters that exist do
not bound the attack they most resemble a defence against.

**Coverage — PARTIAL.** `build_router` (`crates/atproto-pds/src/http/router.rs:27-433`) registers 104
routes, 91 under `/xrpc/`; the only `.layer(...)` calls are the two inside `with_metrics` (`:446-447`),
and every guard in this crate is inline in a handler (corroborated at `/tmp/gap-scratch/inv/auth.md:11`).
Unlimited: all `com.atproto.repo.*` writes including `applyWrites`, `uploadBlob` and `importRepo`; all
`com.atproto.sync.*`; `subscribeRepos`; the entire `com.atproto.space.*` / `simplespace.*` namespace
including credential minting; `/oauth/par`, `/oauth/authorize` (the password-entry endpoint) and
`/oauth/revoke`; every `com.atproto.admin.*` route plus `/admin`. The module doc at `security.rs:6`
states "every authenticated XRPC call passes through a rate limiter" — four of 104 routes are limited and
three of those four are *unauthenticated*, so both halves of the sentence are false.

| Implementation | Coverage | Keying | Evidence |
|---|---|---|---|
| bluesky-reference | global + per-route + shared write buckets | source IP, `trust proxy` | `packages/pds/src/rate-limits.ts:31-57`; `index.ts:116-124` |
| tranquil-pds | 20 named auth/identity policies | client IP | `crates/tranquil-pds/src/rate_limit/extractor.rs:176-188` |
| metalbear | global, installed on the XRPC server | per-client (impl in unvendored lib) | `src/server.c:6958-6959`, `:6572-6577` |
| pegasus | 9 write/identity routes + login | DID; `identifier+IP` for login | `pegasus/lib/rate_limiter.ml:11-52`; `.../createSession.ml:35` |
| alteran | write + blob buckets, plus login lockout | `cf-connecting-ip` | `src/lib/ratelimit.ts:16-19`; `.../createSession.ts:16-17` |
| **atproto-crates** | **4 endpoints of 104** | **caller-supplied string only** | `src/http/auth_handlers.rs:87,300,1404`; `src/oauth/token.rs:106` |
| zds | 1 endpoint + 2 concurrency caps | subject | `src/atproto/identity.zig:199,203`; `sync.zig:12,214-220` |
| cocoon / rsky-pds / arroba / dnproto / cirrus | none | — | see the respective impl notes, §12 |

**Backends and tuning — PARTIAL.** Three backends sit behind one enum
(`crates/atproto-pds/src/security.rs:299-346`); the Valkey path pipelines
`ZREMRANGEBYSCORE`/`ZCARD`/`ZADD`/`EXPIRE` atomically and is genuinely good work, putting atproto-crates
in a two-member club with tranquil-pds's Lua INCR+EXPIRE
(`/tmp/gap-scratch/tranquil-pds/crates/tranquil-cache/src/lib.rs:92-128`); both fail open on a Redis
error (`valkey_backend.rs:169-172`; `lib.rs:110-113`), an identically-chosen, defensible tradeoff. Two
problems sit on top. `PDS_DURABILITY_PROFILE` defaults to `memory` (`bin/pds.rs:140`), which the crate's
own doc calls a gap for refresh rotation and service-auth (`security.rs:11-14`), and the production gate
does not flag it. And the window is hardcoded at 300/60s in five places (`bin/pds.rs:551-554`,
`:1102-1105`, `:1113-1116`; `http/state.rs:139`, `:182`) with no tuning knob and no bypass, where
metalbear exposes `limits.rate_limit` / `rate_limit_window_seconds`
(`/tmp/gap-scratch/metalbear/config.example.toml:64-65`, with a README warning that the default is too
small for a backfilling relay) and the reference exposes `PDS_RATE_LIMITS_ENABLED` plus bypass key and
bypass-IP list (`rate-limits.ts:21-30`). A legitimate relay or AppView cannot be exempted here.

**Fail-open and wire contract.** `crates/atproto-pds/src/http/auth_handlers.rs:1401-1405` writes
`let _ = state.rate_limiter.try_acquire(...)`, documented as tolerating "a storage hiccup" but in fact
discarding every outcome including a legitimate rejection — so the enforcing count is three, not four.
On rejection, `enforce_rate_limit` (`:69-77`) returns error name `"RateLimited"` and
`IntoResponse for XrpcError` (`http/errors.rs:34-45`) emits `{error, message}` with no headers. The
canonical XRPC 429 name is `RateLimitExceeded`, derived from `ResponseType[429]`
(`/tmp/gap-scratch/atproto/packages/xrpc/src/types.ts:43`) via `XRPCError.typeName`
(`xrpc-server/src/errors.ts:59-75`) and matched by zds (`/tmp/gap-scratch/zds/src/atproto/sync.zig:214-220`);
the reference and pegasus both set `RateLimit-Limit/Reset/Remaining/Policy`
(`xrpc-server/src/rate-limiter-http.ts:78-81`; `/tmp/gap-scratch/pegasus/pegasus/lib/xrpc.ml:89-95`).
Clients branching on the error string or backing off from headers get neither. **DIVERGENT, cosmetic
relative to the above.**

---

## 2. Request body limits — DIVERGENT

`upload_blob` and `import_repo` both take `body: axum::body::Bytes`
(`crates/atproto-pds/src/http/write_handlers.rs:519`, `:598`), buffering the whole body into memory
before any check. No `DefaultBodyLimit` layer exists anywhere in the crate, so axum's default applies:
`axum-core-0.5.6/src/ext_traits/request.rs:319` defines `const DEFAULT_LIMIT: usize = 2_097_152` and
`:326` wraps the body in `Limited::new(b, DEFAULT_LIMIT)` when no override extension is present
(`Cargo.lock:1074-1075` pins axum 0.8.8). The crate's own `MAX_BLOB_BYTES = 16 MiB` (`blob.rs:20`,
checked at `write_handlers.rs:531`) is therefore unreachable — and `crates/atproto-pds/README.md:162-163`
plus `Dockerfile:14-16` instruct operators to size their reverse proxy for ">1 GiB for `importRepo`",
advice that cannot help when the application rejects at 2 MiB. Inbound account migration fails for any
non-trivial repo and no test catches it. The reference makes the cap a knob (`PDS_BLOB_UPLOAD_LIMIT`,
`/tmp/gap-scratch/atproto/packages/pds/src/config/env.ts:19`, 100 MiB in `bsky-pds/sample.env:7`), as do
rsky-pds (`config/mod.rs:155`), metalbear (`include/metalbear/server.h:58-60`), zds
(`docs/operations.md:110`) and alteran (`PDS_MAX_JSON_BYTES`, `src/lib/util.ts:22-75`).

---

## 3. Observability

**Health and readiness — complete, and ahead of the reference.** Three routes at
`crates/atproto-pds/src/http/router.rs:29-31`: `/_alive` is an unconditional 200
(`http/handlers.rs:23-25`); `/_ready` acquires an accounts-pool connection and `ping()`s it, 503 on
failure (`:28-41`); `/xrpc/_health` returns `{version, status, setHash}` (`:47-53`), where `setHash` is a
documented non-standard extension letting peers confirm commit-digest interop without trial-and-error.
`/xrpc/_health` is a convention, not a lexicon — no JSON for it exists under
`/tmp/gap-scratch/atproto/lexicons/com/atproto/` — and everyone serves it, but only rsky-pds
(`lib.rs:125-159`), alteran (`src/pages/health.ts:14-67`) and arroba (`app.py:161-168`) split liveness
from readiness at all, and the reference folds the DB check into a single `_health`
(`/tmp/gap-scratch/atproto/packages/pds/src/basic-routes.ts:39-49`). No finding.

**Prometheus — PARTIAL.** `crates/atproto-pds/src/metrics.rs:80-89` registers exactly two counter
families, `atproto_pds_http_requests {method,route}` and `atproto_pds_http_responses {method,route,status}`.
No latency histogram, no in-flight gauge, no counters for GC, notifier deliveries, space commits, DB-pool
saturation or firehose subscribers; the low-cardinality label design (route template, never raw path) is
thoughtful. **The reference PDS has no metrics at all** — a grep for `prom-client|prometheus|/metrics`
over `/tmp/gap-scratch/atproto/packages/pds/src` returns nothing — so any exposure is above the reference
bar and below the serious-peer bar set by tranquil-pds (`crates/tranquil-pds/src/metrics.rs:27-190`:
HTTP, auth-cache, firehose, block ops, queue depth, rate-limit rejections, plus dashboards) and cocoon
(`/tmp/gap-scratch/cocoon/metrics/metrics.go:12-30`, dedicated listener). Two caveats: `/metrics` is
unauthenticated by design, delegating the ACL to the operator's proxy (`metrics.rs:11-13`), while the
only shipped proxy forwards every path with no rule (`deploy/cloudflared/config.yml.tmpl:10-23`); and the
module doc at `:6-9` promises `text/plain; version=0.0.4` and "status code histograms" while `export()`
at `:133` emits `application/openmetrics-text; version=1.0.0` and registers no histogram.

**OpenTelemetry — AHEAD OF THE FIELD.** `crates/atproto-pds/src/telemetry.rs:32-67` builds an OTLP
HTTP/protobuf span exporter with `Sampler::AlwaysOn`, a batch exporter on the Tokio runtime, a
`service.name` resource attribute and a globally-installed W3C `TraceContextPropagator` (`:37`); init
failure degrades to `None` with a warning (`:45-52`) and spans flush on exit (`bin/pds.rs:767`). Traces
only. **No other implementation surveyed emits OpenTelemetry** — verified absent in the reference, and
stated absent in the notes for [arroba](../impl-notes/arroba.md), [cirrus](../impl-notes/cirrus.md),
[dnproto](../impl-notes/dnproto.md), [pegasus](../impl-notes/pegasus.md) and
[rsky-pds](../impl-notes/rsky-pds.md). This is the clearest capability where atproto-crates leads,
reference included. The absent metrics/logs pipelines are **OUT-OF-SCOPE**: traces are the useful half
for a request-path service and no peer offers a baseline to measure against.

**Logging — PARTIAL.** `tracing` + `EnvFilter` from `RUST_LOG`, default `"info,atproto_pds=debug"`
(`bin/pds.rs:59`, init at `:1122-1136`), with `#[instrument]` on the background loops. Missing is
per-request correlation: no `tower_http::trace` layer in `build_router`, no access log, no request-ID or
trace-ID echoed into responses. Alteran emits structured JSON with a per-request UUID returned as
`X-Request-ID` (`/tmp/gap-scratch/alteran/src/middleware.ts:74-108`); the reference uses per-subsystem
pino loggers behind a `loggerMiddleware` (`/tmp/gap-scratch/atproto/packages/pds/src/index.ts:126`).
Since a `TraceContextPropagator` is already installed, surfacing the trace ID is a small delta.

---

## 4. Backup and restore — MISSING

A grep for `backup|restore|snapshot` across `crates/atproto-pds/src/`, `crates/atproto-pds/README.md` and
`deploy/` returns three hits, all "snapshot" in the firehose sense
(`crates/atproto-pds/src/blob.rs:136`, `src/http/handlers.rs:180`, `src/repo/car_export.rs:116`).
`atproto-pds-admin` has `version`, `invite list`, `account info|search|delete` and
`takedown apply|lift|status` and nothing else (`crates/atproto-pds/src/bin/atproto-pds-admin.rs:41-111`);
`deploy/Makefile` has no snapshot step; neither README documents a restore. The only data-egress path is
per-account `sync.getRepo` CAR export plus `importRepo` — the migration path, which covers none of the
accounts DB, signing keys, OAuth state, spaces tables or blobs.

The field is split but the serious tier is ahead. Cocoon takes hourly SQLite `VACUUM INTO` to S3
(`/tmp/gap-scratch/cocoon/server/server.go:673-691`); pegasus copies every `.db` file to S3 on an interval
(`/tmp/gap-scratch/pegasus/pegasus/lib/s3/backup.ml:25-60`); dnproto — *single-user tier* — ships
`BackupAccount` and `RestoreAccount` CLI commands (`/tmp/gap-scratch/dnproto/src/cli/commands/`).
Metalbear's backup library is unreachable from any binary ([metalbear](../impl-notes/metalbear.md) §12)
and `pdsadmin` has no backup subcommand either (`/tmp/gap-scratch/bsky-pds/pdsadmin/`) — so this is not a
reference-only capability, but three independents including a single-user project are ahead.

---

## 5. Email and notifications

**Email — PARTIAL, with a log-disclosure edge.** `crates/atproto-pds/src/email.rs:27-36` has two
backends. `Disabled` is the `#[default]` (`:31-32`) and logs recipient, subject and **full body** at
`INFO` (`:75-83`). `Smtp` uses `lettre` (`:110-114`), plain text only. The problem is packaging: `smtp`
is not a default feature (`Cargo.toml:96,128`) and the shipped container is built
`--features clap,hickory-dns` (`Dockerfile:63,83`), so the reference deployment cannot send mail and
every password-reset token, email-confirmation token and account-delete URL lands in `INFO` logs instead;
setting `PDS_EMAIL_SMTP_URL` against that image is inert. Secrets in logs on the only shipped deployment
is what pushes this past a packaging nit. For contrast: the reference bundles nodemailer + handlebars
(`/tmp/gap-scratch/atproto/packages/pds/package.json:65,71-72`); cocoon takes six SMTP flags
(`cmd/cocoon/main.go:92-113`); metalbear initialises email whenever `smtp_host` and `from_address` are
set (`src/server.c:6961-6971`); zds ships two pluggable providers, comail and resend
(`/tmp/gap-scratch/zds/src/core/mail.zig:14-17`, documented at `docs/comail.md`).

**Notifier — OUT-OF-SCOPE for pluggability, PARTIAL otherwise.** The spaces `notifyWrite` fan-out is a
DLQ-backed POST worker over `notify_attempt` (`notifier.rs:62-80`), drained in batches of 50 on a ticker
(`bin/pds.rs:700-706`, `:854-859`) with exponential retry (`notifier.rs:222`) — a real durable queue,
more than the permissioned-data spec requires (see
[permissioned overview](../permissioned/40-permissioned-overview.md)). Not being pluggable is defensible
while that spec settles: `Notifier` is a concrete struct holding a `reqwest::Client` (`:246-263`) with no
trait boundary. Two smaller defects are not. The client is `reqwest::Client::new()` with no user-agent
(`:263`), unlike every other outbound client in the binary (`bin/pds.rs:625`), so receiving hosts cannot
identify or allowlist it; and the documented backoff totals contradict the code in two directions
(`bin/pds.rs:218` "≈ 4 min", `notifier.rs:17,28` "~1.5h", `:222` formula ≈510 s).

---

## 6. Configuration, secrets and the reverse-proxy contract

The real config surface is the clap `Args` struct at `crates/atproto-pds/src/bin/pds.rs:41-330`: 39
flags, 38 of them env-backed, plus one direct `std::env::var` (`actor_store/mod.rs:81-83`). Breadth is fine —
comparable to the reference's 101 variables, of which its self-host README documents 20 — and
range-validated integers are a real strength. `validate_production_safety` (`config.rs:42-75`) is a
genuine gate: it always requires a ≥32-byte `PDS_JWT_SECRET`, and under `PDS_PRODUCTION=true` rejects the
dev-sentinel JWT secret, the dev-sentinel admin password, and `did:web:localhost` or non-`did:` service
DIDs, collecting all issues together. Only tranquil-pds has a comparable validator, and its
`config validate` goes further by checking the PLC rotation key, TLS material and reserved-TLD handle
domains (`/tmp/gap-scratch/tranquil-pds/crates/tranquil-server/src/main.rs:53-90`). The gaps: no check on
`PDS_BIND` (a production deploy can silently stay on loopback), no requirement for
`PDS_SERVICE_HANDLE_DOMAINS` (empty means any handle is accepted, `bin/pds.rs:239-242`), and no warning
when `PDS_DURABILITY_PROFILE=memory` in production. **PARTIAL.**

Config-file support is documented and absent: `bin/pds.rs:42` states the precedence
"env > --config > /etc/atproto-pds/config.toml > defaults", `args.config` is declared at `:44` and never
referenced, and no TOML loader exists. Metalbear parses a TOML file with env override and makes an
unknown key a hard error with a line number (`/tmp/gap-scratch/metalbear/src/config_file.c`,
`README.md:240-268`); tranquil-pds ships a 671-line `example.toml`. Both are better operator ergonomics
than a 40-flag env surface. **MISSING.** Secret handling in the shipped deployment is sound in shape —
read-only mounts at `/run/secrets` `cat`-ed into env by an entrypoint wrapper
(`deploy/docker-compose.yml:23-29`), generated idempotently by `deploy/init/00-gen-secrets.sh:8-22` —
with one dead branch: that script writes `plc_rotation.didkey` / `.priv` per service and nothing ever
exports `PDS_PLC_ROTATION_KEY_DID_KEY` / `_PRIVATE`.

The reverse-proxy contract is stated consistently (`crates/atproto-pds/Dockerfile:14-16`,
`README.md:162-163`): external TLS, large bodies, WS upgrades. The realisation is cloudflared with
`keepAliveTimeout: 600s` per PDS hostname so `subscribeRepos` survives
(`deploy/cloudflared/config.yml.tmpl:13-21`) — a correct and non-obvious detail. Three things are unmet:
the large-body half is contradicted by §2; there is no path-level ACL, so `/metrics` and `/admin` are
internet-routable when enabled; and because no forwarded-header parsing exists, running behind a proxy
forecloses any future per-client identification. The reference confronts the last directly with a
`trust proxy` allowlist of loopback, linklocal, uniquelocal and configured entryway IPs
(`/tmp/gap-scratch/atproto/packages/pds/src/index.ts:116-124`). **PARTIAL.**

---

## 7. Multi-account hosting — complete

`AccountDirectory` is a shared accounts DB (`crates/atproto-pds/src/bin/pds.rs:415-419`); each account
gets its own actor store keyed by DID — the per-actor SQLite filename is `sha256(did)`
(`crates/atproto-pds/src/actor_store/sql/store.rs:21-26`, path at `:30`, opened + migrated per DID at
`:55-95`);
`createAccount` is public (`crates/atproto-pds/src/http/router.rs:116-119`) with optional invite gating
(`PDS_INVITE_REQUIRED`, `bin/pds.rs:88-89`); admin `searchAccounts` / `getAccountInfos` are batch
operations (`router.rs:362-365`, `:378-381`); `deploy/init/40-create-accounts.sh:32-34` creates three
accounts across three instances. Matches the reference, tranquil-pds, cocoon, rsky-pds, metalbear,
pegasus and zds; cirrus, alteran and dnproto are single-user by design and score `n/a`. No finding.

---

## 8. Deployment, tooling and CI

**Container.** `crates/atproto-pds/Dockerfile` is a competent four-stage `cargo-chef` build:
`debian:bookworm-slim` runtime (`:89`), non-root `pds` uid/gid 1000 (`:98-101`), baked data dir and
`PDS_BIND=0.0.0.0` (`:110-113`), `EXPOSE 3000`, `HEALTHCHECK` on `/xrpc/_health` (`:118-119`). It builds
`--features clap,hickory-dns` (`:63`, `:83`), so the image contains no `metrics`, `otel`, `smtp`,
`valkey`, `s3`, `postgres` or `fjall`; those env variables are inert against it, silently so for
`PDS_VALKEY_URL` because the precedence branch at `bin/pds.rs:537-559` is `#[cfg]`-ed out. It also pins
`ARG RUST_VERSION=1.85` (`:30`) against a workspace `rust-version = "1.90"` and `resolver = "3"`
(`Cargo.toml:26,30`). The root `Dockerfile` does not build `pds` at all, and
`.github/workflows/release-binaries.yml` cross-compiles four CLI binaries and never touches the PDS — so
no image is published.

**`deploy/`.** Sixteen files describing the Walking Club test cluster: a compose project with `pds1`,
`pds2`, `space-host` (all the same image, confirming the PDS binary *is* the space host), an appview and
cloudflared; a `Makefile` with `secrets`/`images`/`tunnel`/`config`/`accounts`/`up`/`down`/`nuke`/`logs`/`ps`;
four init scripts. No Kubernetes manifests, no Helm chart, no systemd unit, no Nix expression. The
load-bearing defect is that this deployment cannot federate: `deploy/well-known/*/.well-known/did.json`
exist but no compose service mounts `deploy/well-known` (volumes are only `*_data:/var/lib/pds` and
`./secrets/*:/run/secrets` — `deploy/docker-compose.yml:20-22`, `:45-47`, `:70-72`), cloudflared routes
hostnames straight to the container, and `crates/atproto-pds/src/http/router.rs` serves no
`/.well-known/did.json` route (its only well-knowns are the two OAuth metadata documents at `:253`,
`:257`). So `did:web:pds1.ngerakines.dev` does not resolve.

The benchmark is `/tmp/gap-scratch/bsky-pds`: `installer.sh` installs docker-ce, generates secrets with
`openssl rand` (`:324-342`), writes a Caddyfile for the host and its wildcard (`:304-312`), fetches
`compose.yaml`, installs a `Type=oneshot RemainAfterExit=yes` systemd unit (`:362-382`), opens ufw 80/443
(`:384-394`) and drops `pdsadmin` into `/usr/local/bin` (`:399-406`); the stack adds watchtower on an
`@midnight` auto-update (`compose.yaml:28-39`). In the independent field, tranquil-pds packages
containers, a NixOS module, podman quadlets and OpenRC; metalbear publishes three images plus a
`scripts/setup.sh --hostname` provisioner; cocoon, pegasus and zds publish images. atproto-crates is
behind all of them. **PARTIAL.**

**Admin tooling.** `atproto-pds-admin` covers invite listing, account info/search/delete and takedown
apply/lift/status (`crates/atproto-pds/src/bin/atproto-pds-admin.rs:41-111`). Against `pdsadmin` it lacks
account creation, password reset, invite creation, request-crawl and any update path — though it avoids
`pdsadmin.sh`'s habit of downloading and root-executing a remote shell script on every invocation
(`/tmp/gap-scratch/bsky-pds/pdsadmin.sh:6,19-28`). An `/admin` HTML dashboard
(`crates/atproto-pds/src/admin/dashboard.rs`) puts atproto-crates alongside pegasus, dnproto and cirrus,
ahead of most of the field.

**CI — MISSING.** `crates/atproto-pds/README.md:29-32` claims `cargo fmt --all -- --check`,
`cargo clippy … -D warnings` and `cargo test --workspace --all-features` "are enforced on every push to
main and every PR (see `.github/workflows/ci.yml`)". That file does not exist; `ls .github/workflows/`
returns only `release-binaries.yml`, which runs no fmt, clippy or test step and does not build the PDS.
Every serious peer runs tests in CI: cocoon (`go-test.yml`, `-race`), rsky-pds (`rust.yml:141-142,167`,
a per-package `cargo test` matrix including `rsky-pds`), metalbear (`ci.yml`), cirrus (`test.yml` +
`e2e.yml`), alteran (`ci.yml`), zds (`.tangled/workflows/ci.yml`: `zig build test` + `tools/smoke.sh`),
and the reference (`.github/workflows/repo.yaml` on every PR). Pegasus, tranquil-pds and arroba publish
or scan without a test job — three projects sit near atproto-crates, but none advertise a pipeline they
lack.

**Runbook — MISSING.** Docs are dense where they exist (`#![warn(missing_docs)]` at
`crates/atproto-pds/src/lib.rs:31`, `//!` headers throughout), but three source sites defer to an
operator runbook that does not exist: `crates/atproto-pds/src/valkey_backend.rs:215-218`,
`tests/feature_s3.rs:6-7`, `src/metrics.rs:11-13`. No backup, upgrade, migration-rollback, incident or
key-rotation procedure is written anywhere. ZDS ships `docs/operations.md`,
`docs/account-takedown-runbook.md` and more; alteran ships `docs/SECRET_ROTATION.md` and
`docs/MIGRATION_GUIDE.md`. Both are below atproto-crates in maturity tier and above it here.

---

## 9. Lifecycle and GC

`ShutdownController::wait_drain()` (`crates/atproto-pds/src/shutdown.rs:82-85`) applies the
30-second `DEFAULT_SHUTDOWN_DEADLINE` (`:19`), and `grep -rn "wait_drain" crates/atproto-pds/`
finds callers only inside `shutdown.rs` and its own unit
tests (`:113`, `:132`). `bin/pds.rs:762-764` logs "draining tasks" then drops the token and tracker, so
the notifier, GC and account-deletion loops are abandoned mid-tick while the process proceeds to
`telemetry::shutdown()` at `:767`. Axum's own `with_graceful_shutdown` (`:745-747`) still drains in-flight
HTTP requests, so this is unfinished background work on every restart rather than request-path data loss
— but it contradicts `README.md:129-131`. Signals are SIGTERM and SIGINT only, Unix-only
(`shutdown.rs:14`, `:66-73`). The reference uses `http-terminator` with a 90 s keep-alive
(`/tmp/gap-scratch/atproto/packages/pds/src/index.ts:141-149`); tranquil-pds cancels the shutdown token
from a panic hook (`crates/tranquil-server/src/main.rs:170-175`); cocoon does not drain at all
(`/tmp/gap-scratch/cocoon/server/server.go:637-641`), so atproto-crates is mid-field. **PARTIAL.**

Three GC loops exist (unified `gc.rs:103-160`, account deletion `bin/pds.rs:796-838`, inline blob deref
`blob.rs:132-173`). Two portability defects follow the storage abstraction: the unified GC is hardcoded
`SqlitePool` (`gc.rs:92-96`, `:136`), so a `PDS_POSTGRES_URL` deployment gets no GC at all; and
`prune_space_oplogs` opens `SqlActorStore::open` per DID (`:236`) and `debug!`-skips on failure
(`:238-241`), so a fjall deployment's space oplogs are never pruned. There is no sweep for blobs orphaned
by a crash. The storage chapter owns the backend detail; recorded here because unbounded table growth on
a supported backend is an operational failure mode. **PARTIAL.**

---

## Findings

1. **No per-IP rate limiting; peer IP is not plumbed to handlers.** MISSING · **rc-blocker.**
   `crates/atproto-pds/src/bin/pds.rs:745` uses plain `axum::serve`; grep for
   `ConnectInfo|X-Forwarded-For|peer_addr` yields only the listen-addr parse. Compare alteran
   (`src/lib/ratelimit.ts:16-19`, `.../createSession.ts:16-17`), metalbear (`src/server.c:6958-6959`),
   pegasus (`.../createSession.ml:35`), reference (`rate-limits.ts:31-44`). *Consequence:* nothing bounds
   volume from a single source against an open `createAccount`. Even the hobby tier does this.

2. **Rate limiting reaches 4 of 104 routes; no middleware layer exists.** PARTIAL · **rc-blocker.**
   `crates/atproto-pds/src/http/auth_handlers.rs:87,300,1404`, `src/oauth/token.rs:106`; only `.layer` in
   `router.rs:27-433` is metrics at `:446-447`. Compare `/tmp/gap-scratch/verified-commit-divergences.md:155-172`.
   *Consequence:* all repo writes, all sync reads, `subscribeRepos`, the whole spaces namespace,
   `/oauth/par`, `/oauth/authorize` and all admin routes are unbounded.

3. **Every rate-limit bucket key is attacker-controlled.** DIVERGENT · **rc-blocker.**
   Keys are `createAccount:{handle}`, `createSession:{identifier}`, `requestPasswordReset:{email}`,
   `oauth-token:{client_id}`. Compare pegasus keying on `identifier ^ "-" ^ request_ip`. *Consequence:*
   the limiter does not bound password spraying or signup flooding, the attacks it most resembles a
   defence against.

4. **Request bodies cap at axum's 2 MiB default, silently breaking `importRepo` and `uploadBlob`.**
   DIVERGENT · **rc-blocker.** `write_handlers.rs:519,598` take `Bytes`; no `DefaultBodyLimit` in the
   crate; `axum-core-0.5.6/src/ext_traits/request.rs:319,326`; `blob.rs:20`'s 16 MiB is unreachable.
   Compare `PDS_BLOB_UPLOAD_LIMIT` (reference, rsky-pds), `METALBEAR_BLOB_UPLOAD_LIMIT`,
   `ZDS_BLOB_UPLOAD_LIMIT`. *Consequence:* `README.md:162-163` tells operators to size their proxy for
   >1 GiB while the app rejects at 2 MiB, so inbound migration fails for any non-trivial repo. Untested.

5. **No backup or restore path of any kind.** MISSING · **rc-blocker.**
   Grep over `crates/atproto-pds/src/`, README and `deploy/` returns three unrelated hits; no admin
   subcommand, no snapshot step in `deploy/Makefile`. Compare cocoon (`server.go:673-691`), pegasus
   (`s3/backup.ml:25-60`), dnproto (`BackupAccount.cs` — single-user tier). *Consequence:* a host holding
   other people's repos has no tooled or documented way to take or restore a consistent copy.

6. **The shipped container cannot send email; tokens go to INFO logs.** PARTIAL · **rc-blocker.**
   `smtp` is not a default feature (`Cargo.toml:96,128`); the image builds `--features clap,hickory-dns`
   (`Dockerfile:63,83`); the `Disabled` default logs the full body at INFO (`email.rs:31-32,75-83`).
   Compare reference, cocoon, metalbear, zds — all ship working delivery. *Consequence:* password-reset
   and confirmation tokens are written to logs on the only shipped deployment.

7. **The shipped `deploy/` cluster cannot resolve its own `did:web`.** PARTIAL · **rc-blocker.**
   `deploy/well-known/*` is never mounted (`docker-compose.yml:20-22,45-47,70-72`), cloudflared routes
   hostnames straight to the container, and no `/.well-known/did.json` route exists in `router.rs`.
   *Consequence:* the reference deployment cannot federate and no test would catch it.

8. **No CI runs fmt, clippy or tests; the README cites a workflow that does not exist.** MISSING ·
   **rc-blocker.** `ls .github/workflows/` → `release-binaries.yml` only, against the claim at
   `crates/atproto-pds/README.md:29-32`. Compare reference `repo.yaml`, cocoon `go-test.yml`, rsky
   `rust.yml:141-142,167`, metalbear, cirrus, alteran, zds. *Consequence:* for an `rc.1` artifact nothing
   mechanically prevents regressing the 157 integration tests, and the claim that something does is false.

9. **`requestPasswordReset` records rate-limit hits and never rejects.** PARTIAL · stable-gap.
   `let _ = state.rate_limiter.try_acquire(...)` (`auth_handlers.rs:1401-1405`); pegasus limits it for
   real. *Consequence:* the mail-send path is unbounded while appearing bounded, so the enforcing count
   is three, not four.

10. **The limiter is untunable and its default backend is volatile.** PARTIAL · stable-gap.
    Window hardcoded 300/60s at `bin/pds.rs:551-554,1102-1105,1113-1116` and `http/state.rs:139,182`, no
    bypass; `PDS_DURABILITY_PROFILE` defaults to `memory` (`bin/pds.rs:140`) against the crate's own
    caveat (`security.rs:11-14`) with no check in `config.rs:42-75`. Compare metalbear
    `config.example.toml:64-65` and the reference's bypass key/IPs (`rate-limits.ts:21-30`).
    *Consequence:* a relay cannot be exempted, the limit cannot be moved, and buckets clear on restart.

11. **429s carry no `RateLimit-*` headers and use a non-canonical error name.** DIVERGENT · cosmetic.
    `auth_handlers.rs:69-77` emits `"RateLimited"`; `http/errors.rs:34-45` sets no headers; canonical is
    `RateLimitExceeded` (`xrpc/src/types.ts:43` via `xrpc-server/src/errors.ts:59-75`), headers at
    `rate-limiter-http.ts:78-81` and `pegasus/lib/xrpc.ml:89-95`.

12. **Metrics are two counters, undocumented-as-shipped, and unauthenticated.** PARTIAL · stable-gap.
    `metrics.rs:80-89` vs the `:6-9` doc (histograms, `text/plain; version=0.0.4`) and the `:133` output;
    no auth on `/metrics` while `deploy/cloudflared/config.yml.tmpl:10-23` forwards every path, mitigated
    today only by the feature being absent from the image and the `PDS_METRICS_BIND` gate
    (`bin/pds.rs:671-678`). Compare tranquil-pds `metrics.rs:27-190` and cocoon `metrics/metrics.go:12-30`;
    note the reference has **no** metrics at all. *Consequence:* no latency or saturation visibility.

13. **`--config` is documented with a precedence chain and never read.** MISSING · stable-gap.
    `bin/pds.rs:42` documents it, `:44` declares the field, nothing reads it, no TOML loader exists.
    Compare metalbear `src/config_file.c`, tranquil-pds `example.toml`.

14. **The production gate misses bind address, handle domains and durability profile.** PARTIAL ·
    stable-gap. `config.rs:42-75` checks only JWT secret, admin password and service DID;
    `bin/pds.rs:239-242` notes an empty `PDS_SERVICE_HANDLE_DOMAINS` accepts any handle. Compare
    tranquil-pds `main.rs:53-90`.

15. **The shipped image omits seven optional features, making their env knobs inert.** DIVERGENT ·
    stable-gap. `Dockerfile:63,83`; the `valkey` branch at `bin/pds.rs:537-559` is `#[cfg]`-ed out, so
    `PDS_VALKEY_URL` fails silently. `RUST_VERSION=1.85` (`Dockerfile:30`) also contradicts
    `rust-version = "1.90"` (`Cargo.toml:30`).

16. **`wait_drain()` is never called; background workers are abandoned on shutdown.** PARTIAL ·
    stable-gap. `shutdown.rs:82-85` defines it; `bin/pds.rs:762-764` drops the token and tracker instead,
    contradicting `README.md:129-131`.

17. **Unified GC is SQLite-only.** PARTIAL · stable-gap. `gc.rs:92-96,136` hardcode `SqlitePool`;
    `prune_space_oplogs` `debug!`-skips non-SQLite actors (`:236-241`). *Consequence:* Postgres gets no
    GC and fjall never prunes space oplogs, so `notify_attempt`, `email_token`, `oauth_par`, `jti_replay`
    and `rate_limit_window` grow without bound.

18. **No published container image and no self-host installer.** PARTIAL · stable-gap.
    `release-binaries.yml` builds four CLI binaries, not `pds`; `deploy/` is a five-service test cluster.
    Compare `/tmp/gap-scratch/bsky-pds/installer.sh` and the six independents publishing images.

19. **No operator runbook, though three source sites defer to one.** MISSING · stable-gap.
    `valkey_backend.rs:215-218`, `tests/feature_s3.rs:6-7`, `metrics.rs:11-13`; `find docs -type f` is
    empty. Compare zds and alteran, both below atproto-crates in tier and above it here.

20. **The notifier sends no user-agent and its backoff is documented three ways.** PARTIAL · cosmetic.
    `reqwest::Client::new()` (`notifier.rs:263`) vs the user-agent-carrying client at `bin/pds.rs:625`;
    the `:222` formula yields ≈510 s against "≈ 4 min" (`bin/pds.rs:218`) and "~1.5h"
    (`notifier.rs:17,28`).

**Tally:** 8 rc-blockers, 10 stable-gaps, 2 cosmetic. By class: 5 MISSING, 11 PARTIAL, 4 DIVERGENT.
Two areas are explicitly **OUT-OF-SCOPE** and defensible for RC→stable: OTel metrics/logs pipelines (no
peer offers a baseline) and notifier transport pluggability (the 0016 draft is still settling).

---

## Confidence & unknowns

Everything cited under `crates/atproto-pds/` was re-opened in this pass rather than taken from the
inventory: the four limiter call sites, the absence of any router layer beyond metrics, the `axum::serve`
call, the `Bytes` extractors, the axum-core default-limit constant in the vendored registry copy, the
metrics registration and export, the health handlers, `validate_production_safety`, the shutdown block,
the admin CLI subcommands, the Dockerfile feature flags, the compose volume list and the cloudflared
ingress. Reference claims (`rate-limits.ts`, `index.ts`, `rate-limiter-http.ts`, `errors.ts`,
`xrpc/types.ts`, `config/env.ts`) and metalbear, alteran, pegasus, zds, cocoon and tranquil citations
were verified by opening those files; the remainder rest on the cited impl notes.

- **Metalbear's rate-limit keying.** `wf_rate_limiter_new` (`/tmp/gap-scratch/metalbear/src/server.c:6575`)
  lives in the unvendored Wolfram library; `README.md:147` claims per-IP and `config.example.toml:62`
  calls it a per-client budget, but byte-level keying is UNVERIFIED. What *is* verified is that the
  limiter is installed globally (`:6958-6959`), which is the axis on which atproto-crates is behind.
- **Whether `crates/atproto-pds/Dockerfile` builds.** `RUST_VERSION=1.85` against `rust-version = "1.90"`
  and `resolver = "3"` is a mismatch on its face. UNVERIFIED: needs an actual `docker build`.
- **Whether the 2 MiB cap has been observed at runtime.** The chain (no `DefaultBodyLimit` + `Bytes`
  extractor + axum-core default) is verified in source, but no >2 MiB upload was executed. UNVERIFIED:
  needs a live `uploadBlob` with a 3 MiB payload.
- **Whether the `deploy/` cluster has ever run end to end.** The `did:web` 404 suggests the `.well-known`
  step is manual or unfinished; no note in the repo says either way.
- **tranquil-pds and arroba CI.** `.tangled/workflows/` holds only cachix and image-publish jobs; a Nix
  build may run checks inside the derivation, untraced. Arroba's workflows are CodeQL and dependabot only.
  Both scored `~`.
- **Graceful-drain behaviour of rsky-pds, metalbear, pegasus, zds and dnproto** was not examined; those
  cells are `?`.
- **Live behaviour of the Valkey and S3 backends.** No live test exists in-repo
  (`tests/feature_valkey.rs`, `feature_s3.rs` are symbol-existence smoke tests by their own module docs)
  and no server was stood up.
