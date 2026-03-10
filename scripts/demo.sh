#!/usr/bin/env bash
# Catenar demo script: sets env vars and starts infrastructure.
# Usage: ./scripts/demo.sh [--run-agent]
#   --run-agent: after infra is up, run python sdks/python/agent.py --demo

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Policy.json for new clones
if [ ! -f policy.json ]; then
  cp policy.json.example policy.json
  echo "Created policy.json from policy.json.example"
fi

# Env for proxy and CA
export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"
export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"
export NO_PROXY="${NO_PROXY:-127.0.0.1,localhost}"
export CATENAR_DEMO=1

CA_PATH="$REPO_ROOT/deploy/certs/ca.crt"
if [ -f "$CA_PATH" ]; then
  export REQUESTS_CA_BUNDLE="$CA_PATH"
  export SSL_CERT_FILE="$CA_PATH"
fi

# Start infra
docker compose up -d --wait verifier proxy web prometheus grafana

echo ""
echo "Dashboard: http://localhost:3001 | Grafana: http://localhost:3002"
echo "Demo: cd sdks/python && python agent.py --demo"
echo "Set CATENAR_DEMO=1 for auto proxy/CA config"

if [ "$1" = "--run-agent" ]; then
  echo ""
  echo "Running agent demo..."
  cd sdks/python && python agent.py --demo
fi
