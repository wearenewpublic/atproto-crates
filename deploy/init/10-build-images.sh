#!/usr/bin/env bash
# deploy/init/10-build-images.sh — build the PDS + AppView images.
# Build context for both is the repo root (so path-deps + workspace
# inheritance resolve). Uses podman if present, else docker.
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE="$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)"

# shellcheck disable=SC1091
set -a; . ./.env; set +a

REPO_ROOT="$PWD/.."

echo ">>> building ${PDS_IMAGE}"
"$ENGINE" build -t "${PDS_IMAGE}" \
  --build-arg BUILD_REV=dev \
  -f "$REPO_ROOT/crates/atproto-pds/Dockerfile" "$REPO_ROOT"

echo ">>> building ${APPVIEW_IMAGE}"
"$ENGINE" build -t "${APPVIEW_IMAGE}" \
  --build-arg BUILD_REV=dev \
  -f "$REPO_ROOT/walking-club-appview/Dockerfile" "$REPO_ROOT"

echo "images built"
