#!/usr/bin/env bash
# Run Bring Your Own Agent from any directory.
# Prerequisites: docker compose up -d verifier proxy
# Usage: ./scripts/run-byoa.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export CATENAR_DEMO=1
export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"
export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"
export NO_PROXY="${NO_PROXY:-127.0.0.1,localhost}"

CA_PATH="$REPO_ROOT/deploy/certs/ca.crt"
if [ -f "$CA_PATH" ]; then
  export REQUESTS_CA_BUNDLE="$CA_PATH"
  export SSL_CERT_FILE="$CA_PATH"
fi

python examples/bring_your_own_agent.py
