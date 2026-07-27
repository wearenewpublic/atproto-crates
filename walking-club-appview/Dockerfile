# Walking Club AppView — 2-stage build.
# Build context is the REPO ROOT (so ../crates and the parent Cargo.toml are
# available for path-dep + workspace inheritance). NO JS/npm stage — templates
# are embedded via minijinja-embed.

# 1) rust build
FROM rust:1.95-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && rm -rf /var/lib/apt/lists/*

# Bring in the parent workspace manifest + the in-tree crates the path deps need,
# then the appview itself. Context is the repo root.
COPY Cargo.toml ./Cargo.toml
COPY crates ./crates
COPY walking-club-appview ./walking-club-appview

ARG BUILD_REV=dev
ENV BUILD_REV=${BUILD_REV}

# Build only the appview crate (its own standalone workspace) with embedded
# templates and no default (reload) feature.
WORKDIR /app/walking-club-appview
RUN cargo build --release --no-default-features --features embed --bin walking_club_appview

# 2) runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd -u 1000 -m wca && mkdir -p /data && chown wca /data

COPY --from=builder /app/walking-club-appview/target/release/walking_club_appview /usr/local/bin/
COPY --from=builder /app/walking-club-appview/static /app/static
COPY --from=builder /app/walking-club-appview/migrations /app/migrations

USER wca
ENV HTTP_PORT=8080 \
    HTTP_STATIC_PATH=/app/static \
    DATABASE_URL=sqlite:/data/walking_club.sqlite?mode=rwc \
    RUST_LOG=info,walking_club_appview=info
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK CMD curl -fsS http://127.0.0.1:8080/_ready || exit 1
ENTRYPOINT ["/usr/local/bin/walking_club_appview"]
