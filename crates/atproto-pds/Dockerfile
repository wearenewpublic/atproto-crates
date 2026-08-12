# syntax=docker/dockerfile:1.6
#
# Multi-stage build for `atproto-pds`.
#
# Stage 1 (chef-planner): cook a recipe of all workspace dependencies so the
#   actual build can cache them.
# Stage 2 (chef-cacher): build only the dependency tree.
# Stage 3 (builder): copy source over the cached deps and build the `pds` and
#   `atproto-pds-admin` binaries.
# Stage 4 (runtime): minimal `debian:bookworm-slim` with just CA certs +
#   non-root user; copies the two binaries from stage 3.
#
# Per the PDS plan §13 (deployment): the binary is statically-linked against
# rustls (no openssl), uses tokio multi-thread runtime, and is fronted by an
# external reverse proxy (Caddy/nginx/Traefik) for TLS termination + large
# bodies (importRepo) + WS upgrade (subscribeRepos).
#
# Build:
#   docker build -t atproto-pds:dev -f crates/atproto-pds/Dockerfile .
#
# Run (dev):
#   docker run --rm -p 3000:3000 \
#     -e PDS_DATA_DIRECTORY=/var/lib/pds \
#     -e PDS_SERVICE_DID=did:web:pds.example.com \
#     -e PDS_JWT_SECRET=$(openssl rand -hex 32) \
#     -e PDS_ADMIN_PASSWORD=$(openssl rand -hex 16) \
#     -v $PWD/.pds-data:/var/lib/pds \
#     atproto-pds:dev

# Keep in step with `channel` in rust-toolchain.toml, `rust-version` in the
# workspace Cargo.toml, and the builder stages in `Dockerfile` and
# `Dockerfile.pds`. The CI "toolchain pins" step fails on drift.
ARG RUST_VERSION=1.97
ARG DEBIAN_VERSION=bookworm

# ---------------------------------------------------------------------------
# Stage 1: cargo-chef recipe
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef-planner

# cargo-chef caches workspace dependencies as a JSON recipe.
RUN cargo install cargo-chef --locked --version 0.1.71

WORKDIR /work
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# Stage 2: cook deps
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef-cacher

RUN cargo install cargo-chef --locked --version 0.1.71

# Build deps system packages the build needs (sqlx feature gates for SQLite,
# etc.). rustls-vendored means no openssl-sys.
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=chef-planner /work/recipe.json recipe.json

# Bake all workspace dependencies. `--release --bin pds` keeps it tight.
RUN cargo chef cook --release --recipe-path recipe.json \
        -p atproto-pds --features clap,hickory-dns

# ---------------------------------------------------------------------------
# Stage 3: build the actual binaries
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=chef-cacher /work/target target
COPY --from=chef-cacher /usr/local/cargo /usr/local/cargo
COPY . .

ARG BUILD_REV=unknown
ENV BUILD_REV=$BUILD_REV

RUN cargo build --release \
    -p atproto-pds --features clap,hickory-dns \
    --bin pds --bin atproto-pds-admin

# ---------------------------------------------------------------------------
# Stage 4: runtime
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# CA certificates so reqwest+rustls can verify outbound TLS targets (PLC
# directory, jetstream, AppView).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root user. Data goes under /var/lib/pds (mount as a volume).
RUN groupadd --system --gid 1000 pds \
 && useradd --system --uid 1000 --gid pds --home-dir /var/lib/pds --shell /bin/false pds \
 && mkdir -p /var/lib/pds \
 && chown -R pds:pds /var/lib/pds

# Binaries.
COPY --from=builder /work/target/release/pds /usr/local/bin/pds
COPY --from=builder /work/target/release/atproto-pds-admin /usr/local/bin/atproto-pds-admin

USER pds
WORKDIR /var/lib/pds

ENV PDS_DATA_DIRECTORY=/var/lib/pds \
    PDS_BIND=0.0.0.0 \
    PDS_PORT=3000 \
    RUST_LOG=info

EXPOSE 3000

# The /xrpc/_health endpoint is the canonical liveness probe per the plan.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/xrpc/_health || exit 1

ENTRYPOINT ["/usr/local/bin/pds"]
