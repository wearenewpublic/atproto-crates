#!/usr/bin/env bash
# deploy/init/00-gen-secrets.sh — generate all cluster secrets (idempotent).
set -euo pipefail
cd "$(dirname "$0")/.."; S="$PWD/secrets"
gen() { local f="$1"; shift; [ -s "$f" ] || { mkdir -p "$(dirname "$f")"; "$@" >"$f"; chmod 600 "$f"; echo "wrote $f"; }; }
ATPDID="cargo run -q -p atproto-identity --features clap,hickory-dns --bin atpdid --"

for svc in pds1 pds2 space-host; do
  gen "$S/$svc/jwt_secret"     openssl rand -hex 32
  gen "$S/$svc/admin_password" openssl rand -hex 24
  if [ ! -s "$S/$svc/oauth_jwks.json" ]; then
    mkdir -p "$S/$svc"
    JWK="$($ATPDID key generate p256 --jwk | sed -n '/{/,/}/p')"
    printf '{"keys":[%s]}\n' "$JWK" > "$S/$svc/oauth_jwks.json"; chmod 600 "$S/$svc/oauth_jwks.json"
  fi
  if [ ! -s "$S/$svc/plc_rotation.didkey" ]; then
    OUT="$($ATPDID key generate p256)"
    echo "$OUT" | awk '/public:/{print $NF}'  > "$S/$svc/plc_rotation.didkey"
    echo "$OUT" | awk '/private:/{print $NF}' > "$S/$svc/plc_rotation.priv"
    chmod 600 "$S/$svc/plc_rotation".*
  fi
done

gen "$S/appview/cookie_secret"  openssl rand -base64 32
gen "$S/appview/admin_password" openssl rand -hex 24
if [ ! -s "$S/appview/oauth_private_keys" ]; then
  $ATPDID key generate p256 | awk '/private:/{print $NF}' > "$S/appview/oauth_private_keys"
  chmod 600 "$S/appview/oauth_private_keys"
fi
echo "All secrets present under $S"
