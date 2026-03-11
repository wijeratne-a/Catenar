#!/usr/bin/env bash
# Ensure policy.json exists for proxy. Creates from policy.json.example if missing.
# Usage: ./scripts/ensure-policy.sh
# Run before first docker compose up.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f policy.json ]; then
  cp policy.json.example policy.json
  echo "Created policy.json from policy.json.example"
fi
