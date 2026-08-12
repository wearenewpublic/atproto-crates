# Multi-stage build for atproto-identity-rs workspace
# Builds and installs all 15 binaries from the workspace

# Build stage. Keep in step with `rust-version` in Cargo.toml and
# `channel` in rust-toolchain.toml.
FROM rust:1.97-slim-bookworm AS builder

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/app

# Copy the entire workspace
COPY . .

# Build all binaries in release mode
# This will build all binaries defined in the workspace:
# - atproto-identity: 4 binaries (resolve, key, sign, validate)
# - atproto-attestation: 2 binaries (attestation-sign, attestation-verify)
# - atproto-record: 1 binary (record-cid)
# - atproto-client: 3 binaries (auth, app-password, dpop)
# - atproto-oauth: 1 binary (service-token)
# - atproto-oauth-axum: 1 binary (oauth-tool)
# - atproto-jetstream: 1 binary (jetstream-consumer)
# - atproto-lexicon: 1 binary (lexicon-resolve)
# Note: atproto-identity-resolve and atproto-lexicon-resolve require hickory-dns feature
# `smtp` is required for the image to deliver mail at all: without it the
# binary always selects EmailService::Disabled, so password reset, account
# deletion and email confirmation report success and send nothing. lettre is
# pinned to rustls, so this adds no OpenSSL to the runtime image.
RUN cargo build --release --bins -F clap,hickory-dns,zeroize,tokio,smtp

# Runtime stage - use distroless for minimal attack surface
FROM gcr.io/distroless/cc-debian12

# Create directory for binaries
WORKDIR /usr/local/bin

# Copy all built binaries from builder stage
COPY --from=builder /usr/src/app/target/release/atproto-identity-resolve .
COPY --from=builder /usr/src/app/target/release/atproto-identity-key .
COPY --from=builder /usr/src/app/target/release/atproto-identity-sign .
COPY --from=builder /usr/src/app/target/release/atproto-identity-validate .
COPY --from=builder /usr/src/app/target/release/atproto-attestation-sign .
COPY --from=builder /usr/src/app/target/release/atproto-attestation-verify .
COPY --from=builder /usr/src/app/target/release/atproto-record-cid .
COPY --from=builder /usr/src/app/target/release/atproto-client-auth .
COPY --from=builder /usr/src/app/target/release/atproto-client-app-password .
COPY --from=builder /usr/src/app/target/release/atproto-client-dpop .
COPY --from=builder /usr/src/app/target/release/atproto-oauth-service-token .
COPY --from=builder /usr/src/app/target/release/atproto-oauth-tool .
COPY --from=builder /usr/src/app/target/release/atproto-jetstream-consumer .
COPY --from=builder /usr/src/app/target/release/atproto-lexicon-resolve .

# Default to the main resolution tool
# Users can override with specific binary: docker run <image> atproto-identity-resolve --help
# Or run other tools:
#   docker run <image> atproto-identity-key --help
#   docker run <image> atproto-attestation-sign --help
#   docker run <image> atproto-attestation-verify --help
#   docker run <image> atproto-record-cid --help
#   docker run <image> atproto-client-auth --help
#   docker run <image> atproto-oauth-service-token --help
#   docker run <image> atproto-oauth-tool --help
#   docker run <image> atproto-jetstream-consumer --help
#   docker run <image> atproto-lexicon-resolve --help
CMD ["atproto-identity-resolve", "--help"]

# Add labels for documentation
LABEL org.opencontainers.image.title="atproto-identity-rs"
LABEL org.opencontainers.image.description="AT Protocol identity management tools"
LABEL org.opencontainers.image.authors="Nick Gerakines <nick.gerakines@gmail.com>"
LABEL org.opencontainers.image.source="https://tangled.org/ngerakines.me/atproto-crates"
LABEL org.opencontainers.image.version="0.15.0-rc.4"
LABEL org.opencontainers.image.licenses="MIT"

# Document available binaries
LABEL binaries="atproto-identity-resolve,atproto-identity-key,atproto-identity-sign,atproto-identity-validate,atproto-attestation-sign,atproto-attestation-verify,atproto-record-cid,atproto-client-auth,atproto-client-app-password,atproto-client-dpop,atproto-oauth-service-token,atproto-oauth-tool,atproto-jetstream-consumer,atproto-lexicon-resolve"