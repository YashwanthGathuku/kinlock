#!/usr/bin/env bash
# Run Kinlock locally with the simulated Alexa+ page.
# First run creates var/.env with a random owner passphrase and simulator secret (kept out of git).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p var
if [ ! -f var/.env ]; then
  umask 077
  PASS=$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')
  SIM=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
  python3 - "$SIM" <<'PY'
import hashlib, json, sys
json.dump([{"client_id": "simulator", "secret_sha256": hashlib.sha256(sys.argv[1].encode()).hexdigest(), "redirect_uris": [], "grants": ["client_credentials"]}], open("var/clients.json", "w"))
PY
  {
    echo "KINLOCK_OWNER_PASSPHRASE=$PASS"
    echo "KINLOCK_OWNER_PASSPHRASE_HASH='$(python3 -c "import hashlib,secrets,sys;s=secrets.token_bytes(16);n=600000;print(f'pbkdf2_sha256\${n}\${s.hex()}\${hashlib.pbkdf2_hmac(\"sha256\",sys.argv[1].encode(),s,n).hex()}')" "$PASS")'"
    echo "KINLOCK_SIM_CLIENT_ID=simulator"
    echo "KINLOCK_SIM_CLIENT_SECRET=$SIM"
  } > var/.env
  echo "Created var/.env. Your owner passphrase is in that file (KINLOCK_OWNER_PASSPHRASE)."
fi
set -a; . var/.env; set +a
# The simulator is off by default; the local demo (bound to 127.0.0.1) switches it on.
export KINLOCK_SIMULATOR="${KINLOCK_SIMULATOR:-1}"
export PYTHONPATH=src
exec python3 -m kinlock.server
