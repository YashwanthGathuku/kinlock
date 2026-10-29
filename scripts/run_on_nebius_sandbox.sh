#!/usr/bin/env bash
# Run the Kinlock test suite and the Nemotron replay demos inside a Nebius
# Token Factory Sandbox (ConTree). Needs NEBIUS_API_KEY and NEBIUS_PROJECT_ID
# in the environment; neither value is printed.
#
#   uv tool install "contree-cli==0.9.4"
#   NEBIUS_AI_PROJECT="$NEBIUS_PROJECT_ID" contree auth -y   # profile status must be "ok"
#   scripts/run_on_nebius_sandbox.sh
set -euo pipefail
: "${NEBIUS_API_KEY:?set NEBIUS_API_KEY}" "${NEBIUS_PROJECT_ID:?set NEBIUS_PROJECT_ID}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SESSION="${CONTREE_SESSION_KEY:-kinlock_sandbox_$$}"
SRC="$(mktemp -d)"
trap 'rm -rf "$SRC"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$SRC"

contree -S "$SESSION" use tag:python:3.12
contree -S "$SESSION" run -t 600 -F "$SRC:/work/kinlock" -C /work/kinlock -s -- \
  'pip install -q -e ".[dev]" && echo installed'
# Replay mode only: no API key enters the sandbox.
contree -S "$SESSION" run -t 700 -C /work/kinlock -s -- '
  set -e
  echo "sandbox host=$(hostname) kernel=$(uname -r) at $(date -u)"
  python -m pytest -q 2>&1 | tail -3
  for s in errand injection injection_hijacked recovery_email_hijacked tech_support tech_support_hijacked; do
    echo "=== nemotron_demo --scenario $s (replay)"
    python scripts/nemotron_demo.py --scenario "$s" | tail -6
  done
  python eval/audit_attacks.py | tail -1'
contree -o json ps -a | head -2
