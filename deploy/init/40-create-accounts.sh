#!/usr/bin/env bash
# deploy/init/40-create-accounts.sh — create the three test accounts.
# identity1 -> pds1, identity2 -> pds2, identity3 (authority) -> space-host.
# Requires the cluster to be up (PDSes healthy). Captures the minted did:plc for
# each so you can set the _atproto.identityN TXT records (Option A) and fill
# SPACE_OWNER_DID / SPACE_URI for the appview.
set -euo pipefail
cd "$(dirname "$0")/.."

ZONE="ngerakines.dev"
declare -A HOSTS=( [identity1]=pds1 [identity2]=pds2 [identity3]=space-host )

createacct() {
  local handle="$1" host="$2"
  local base="https://${host}.${ZONE}"
  local email="${handle}@${ZONE}"
  local password; password="$(openssl rand -hex 16)"
  echo ">>> creating ${handle}.${ZONE} on ${host}"
  local resp
  resp="$(curl -fsS -X POST "${base}/xrpc/com.atproto.server.createAccount" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"handle":"%s.%s","email":"%s","password":"%s"}' "$handle" "$ZONE" "$email" "$password")")"
  local did; did="$(printf '%s' "$resp" | sed -n 's/.*"did":"\([^"]*\)".*/\1/p')"
  mkdir -p secrets/accounts
  printf 'handle=%s.%s\nemail=%s\npassword=%s\ndid=%s\n' "$handle" "$ZONE" "$email" "$password" "$did" \
    > "secrets/accounts/${handle}.env"
  chmod 600 "secrets/accounts/${handle}.env"
  echo "    did=${did}"
  echo "    TXT  _atproto.${handle}.${ZONE}  \"did=${did}\""
}

for handle in "${!HOSTS[@]}"; do
  createacct "$handle" "${HOSTS[$handle]}"
done

echo ""
echo "Next: set the _atproto.identityN TXT records to the dids above,"
echo "create the space on space-host (identity3 = authority), then fill"
echo "SPACE_OWNER_DID + SPACE_URI in env/appview.env."
