#!/usr/bin/env bash
# deploy/init/20-create-tunnel.sh — one-time cloudflared credential bootstrap +
# DNS routing for the four tunneled hostnames (identity1/2/3 get DNS-TXT only).
set -euo pipefail
cd "$(dirname "$0")/.."
TUNNEL_NAME="${TUNNEL_NAME:-wccluster}"; ZONE="ngerakines.dev"
CF_DIR="$PWD/secrets/cloudflared"; mkdir -p "$CF_DIR"
export TUNNEL_ORIGIN_CERT="$CF_DIR/cert.pem"

cloudflared tunnel --origincert "$CF_DIR/cert.pem" login
cloudflared tunnel --origincert "$CF_DIR/cert.pem" \
  --credentials-file "$CF_DIR/CREDS.json" create "$TUNNEL_NAME"
UUID="$(cloudflared tunnel --origincert "$CF_DIR/cert.pem" list | awk -v n="$TUNNEL_NAME" '$2==n{print $1}')"
echo "Tunnel UUID: $UUID"
[ -f "$CF_DIR/CREDS.json" ] && mv "$CF_DIR/CREDS.json" "$CF_DIR/$UUID.json"

for h in walking-club-appview pds1 pds2 space-host ; do
  cloudflared tunnel --origincert "$CF_DIR/cert.pem" route dns "$TUNNEL_NAME" "$h.$ZONE"
done
echo ">>> Put this in deploy/.env :   TUNNEL_UUID=$UUID"
