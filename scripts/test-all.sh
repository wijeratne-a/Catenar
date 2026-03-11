#!/usr/bin/env bash
# Run all unit/integration tests. Exit 1 on first failure.
# Usage: ./scripts/test-all.sh [--swarm]
#   --swarm: after unit tests, run swarm demo (requires verifier+proxy up)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

RUN_SWARM=false
for arg in "$@"; do
  if [ "$arg" = "--swarm" ]; then
    RUN_SWARM=true
    break
  fi
done

echo "=== Verifier ==="
cd core/verifier && cargo test
echo "Verifier: OK"
echo ""

echo "=== Proxy ==="
cd "$REPO_ROOT/core/proxy" && cargo test
echo "Proxy: OK"
echo ""

echo "=== catenar-verify ==="
cd "$REPO_ROOT/tools/catenar-verify" && cargo test
echo "catenar-verify: OK"
echo ""

echo "=== Python SDK ==="
cd "$REPO_ROOT/sdks/python" && pytest
echo "Python SDK: OK"
echo ""

echo "=== Dashboard ==="
cd "$REPO_ROOT/dashboard" && npm test && npm run lint
echo "Dashboard: OK"
echo ""

if [ "$RUN_SWARM" = true ]; then
  echo "=== Swarm demo (E2E) ==="
  if [ ! -f policy.json ]; then cp policy.json.example policy.json; fi
  docker compose up -d --wait verifier proxy
  python examples/swarm_demo.py 2>&1 || { echo "Swarm demo failed"; exit 1; }
  echo "Swarm: OK"
fi

echo ""
echo "All tests passed."
