# Catenar Demo Script

## Prerequisites

**First-time setup:** Run `make setup` or `cp policy.json.example policy.json` before `docker compose up`. The proxy requires policy.json (or uses empty policy if missing). For a ready-made blocklist (e.g. database.internal, admin.company.com): `cp examples/policies/policy_quickstart.json policy.json`. Or run `./scripts/ensure-policy.sh` (Unix) / `.\scripts\ensure-policy.ps1` (Windows) before first `docker compose up`.

1. **Start infrastructure** (Docker Compose):
   ```bash
   make demo
   ```
   Alternatively, `./scripts/demo.sh` sets proxy/CA env vars and starts infra. Use `./scripts/demo.sh --run-agent` to run the Python demo after. On Windows: `.\scripts\demo.ps1`.
   Or manually:
   ```bash
   docker compose up -d --wait verifier proxy web prometheus grafana
   ```
   `make demo` waits for verifier and proxy health checks, then prints:
   - Dashboard: http://localhost:3001
   - Demo: `cd sdks/python && python agent.py --demo`

2. **Control Plane**: The `web` service in Docker is the dashboard (http://localhost:3001) and receives receipt webhooks. To run the dashboard locally with hot reload instead of the container:
   ```bash
   cd dashboard && npm run dev
   ```

3. **Python environment**:
   ```bash
   cd sdks/python && pip install -e .
   ```

4. **CA Trust:** After the proxy starts, it writes the Root CA to `deploy/certs/ca.crt`. Set `REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt` (Python) or `NODE_EXTRA_CA_CERTS=./deploy/certs/ca.crt` (Node) for HTTPS through the proxy. The CA path is relative to your current working directory—run agents from repo root or use an absolute path for `REQUESTS_CA_BUNDLE`. Or set `CATENAR_DEMO=1` before running agents to auto-configure.

See [policy-quickstart.md](policy-quickstart.md) for where policy is defined and how dashboard, proxy, and agent relate.

## Quick Demo (Python)

```bash
cd sdks/python
python agent.py --demo
```

Runs a scripted three-phase enterprise demo with colored output.

## Bring Your Own Agent

Minimal 2-line integration for existing agents (LangChain, CrewAI, raw Python):

- **[examples/bring_your_own_agent.py](../../examples/bring_your_own_agent.py)** — Import `catenar_intercept` first, then `get_catenar().init(...)`. Your requests/httpx calls are auto-traced.
- Set `CATENAR_DEMO=1` for minimal env setup (auto proxy + CA config).
- Run from repo root: `python examples/bring_your_own_agent.py` (with verifier and proxy up).

### A2A (agent calling agent)

When your agent calls another agent, set the parent receipt ID so the chain is recorded: `get_catenar().set_parent_task_id(other_agent_receipt_id)` before making the request. The interceptor will add `X-Catenar-Caller` and `X-Catenar-Trace` and log the call.

### CISO Quick Demo

Fastest path to show Receipts and Alerts:

```bash
docker compose up -d verifier proxy
python examples/bring_your_own_agent.py
```

Then open Dashboard → Receipts and Alerts (http://localhost:3001). Run from repo root so the CA path resolves.

## Manual Python Demo

```bash
# Configure proxy (required for TLS MITM)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY=127.0.0.1,localhost
# With Docker: CA is at deploy/certs/ca.crt after proxy starts
# Without Docker: curl http://127.0.0.1:8080/ca -o ca.crt
export REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt  # or path to fetched ca.crt

cd sdks/python
python -c "
from catenar_sdk import Catenar

catenar = Catenar(base_url='http://127.0.0.1:3000')
policy = {'public_values': {'max_spend': 1000, 'restricted_endpoints': ['/admin']}}
catenar.init(policy=policy, domain='defi', public_values=policy['public_values'])

@catenar.trace
def execute_swap(amount: float):
    return {'ok': True, 'amount': amount}

execute_swap(500)
print(catenar.wait_for_results(1))
catenar.close()
"
```

## Node.js Demo

```bash
cd sdks/nodejs
npm install
npm run build

# Set proxy for agent traffic
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY=127.0.0.1,localhost
# With Docker: CA is at deploy/certs/ca.crt after proxy starts
# Without Docker: curl http://127.0.0.1:8080/ca -o ca.crt
export NODE_EXTRA_CA_CERTS=./deploy/certs/ca.crt

node -e "
const { Catenar } = require('./dist/index.js');
(async () => {
  const catenar = new Catenar({ baseUrl: 'http://127.0.0.1:3000' });
  const policy = { public_values: { max_spend: 1000, restricted_endpoints: ['/admin'] } };
  await catenar.init(policy, 'defi', policy.public_values);
  catenar.trace('execute_swap', '/api/swap', { amount: 500 });
  const res = await catenar.verify();
  console.log('Verify result:', res);
})();
"
```

## Stress Test (Zero-Config Intercept)

Uses `catenar_intercept` to auto-trace all HTTP calls without decorators:

```bash
# Install httpx for intercept
pip install httpx

# Set proxy (NO_PROXY for verifier so register/verify go direct)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY=127.0.0.1,localhost
# Ensure proxy is running first (CA written to deploy/certs/)
export REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt

python examples/stress_test_agent.py
```

**Mock mode** (avoids DNS errors for fake domains): Set `STRESS_TEST_USE_MOCK=1` to run a local mock server. The proxy must have `CATENAR_STRESS_MOCK_PORT=9999` (set in Docker by default). For full policy testing with real blocked/allowed hosts, use real endpoints.

## Developer Tools

- **Debug Watch**: Tail proxy trace WAL in real time: `cargo run --manifest-path dev/cli/Cargo.toml -- debug watch`
- **Chain Verify**: Verify BLAKE3 hash chain integrity of the **proxy's** trace log: `cargo run --manifest-path tools/catenar-verify/Cargo.toml -- ./data/proxy-trace.jsonl`. Note: This tool verifies the proxy's WAL (`./data/proxy-trace.jsonl`), not the Python SDK's local crash-recovery WAL (`catenar-trace-wal.jsonl`).

When using Docker, the proxy writes the trace to `./data/proxy-trace.jsonl` on the host (via volume mount). Run `make debug` or `make verify` from the repo root.

## Swarm / Multi-Agent Tracing

When Agent A calls Agent B, pass `parent_task_id` in trace entries so you can query the swarm lineage. Set `parent_task_id` to the parent agent's receipt ID when appending trace entries. Then query `GET /api/receipts?parent_task_id=X` to see receipts from child agents that were called by that parent.

**Swarm demo:** `python examples/swarm_demo.py` — Agent A calls Agent B over HTTP with `X-Catenar-Parent-Task-Id`; script asserts lineage. Dashboard Receipts page has a lineage filter and displays `parent_task_ids`.

**Trust:** Lineage is best-effort; see [trust-model.md](../security/trust-model.md) for limits and high-assurance options.

## Webhook + Alerts

To receive policy violation alerts in the Control Plane:

1. Set in verifier environment:
   - `WEBHOOK_URL=https://your-control-plane/api/alerts/ingest`
   - `WEBHOOK_SECRET=<min-32-chars>`

2. Set in Control Plane (dashboard):
   - `WEBHOOK_SECRET=<same-secret>`

3. Violations will appear in Dashboard → Alerts.

## Observability

- **Prometheus**: Scrape proxy `/metrics` (port 8080)
- **Grafana**: Pre-provisioned with Prometheus datasource (port 3002)
- **Splunk** (optional): `docker compose --profile observability up -d splunk`

## Production Security

- **Verifier API key**: Set `VERIFIER_API_KEY` for all production deployments. Pass it as Bearer token or `x-api-key` when calling the verifier. When unset, the verifier API is unauthenticated. Use `VERIFIER_REQUIRE_API_KEY=1` to fail startup if the key is not configured. See [trust-model.md](../security/trust-model.md).
- **Grafana**: For production, set `GRAFANA_ADMIN_PASSWORD` to a strong value. Never use the default in production.
