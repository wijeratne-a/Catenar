# Aegis Demo Script

## Prerequisites

1. **Start infrastructure** (Docker Compose):
   ```bash
   docker compose up -d verifier proxy web prometheus grafana
   ```

2. **Control Plane**: The `web` service in Docker is the dashboard (http://localhost:3001) and receives receipt webhooks. To run the dashboard locally with hot reload instead of the container:
   ```bash
   cd dashboard && npm run dev
   ```

3. **Python environment**:
   ```bash
   cd sdks/python && pip install -e .
   ```

## Quick Demo (Python)

```bash
cd sdks/python
python agent.py --demo
```

Runs a scripted three-phase enterprise demo with colored output.

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
from aegis_sdk import Aegis

aegis = Aegis(base_url='http://127.0.0.1:3000')
policy = {'public_values': {'max_spend': 1000, 'restricted_endpoints': ['/admin']}}
aegis.init(policy=policy, domain='defi', public_values=policy['public_values'])

@aegis.trace
def execute_swap(amount: float):
    return {'ok': True, 'amount': amount}

execute_swap(500)
print(aegis.wait_for_results(1))
aegis.close()
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
const { Aegis } = require('./dist/index.js');
(async () => {
  const aegis = new Aegis({ baseUrl: 'http://127.0.0.1:3000' });
  const policy = { public_values: { max_spend: 1000, restricted_endpoints: ['/admin'] } };
  await aegis.init(policy, 'defi', policy.public_values);
  aegis.trace('execute_swap', '/api/swap', { amount: 500 });
  const res = await aegis.verify();
  console.log('Verify result:', res);
})();
"
```

## Stress Test (Zero-Config Intercept)

Uses `aegis_intercept` to auto-trace all HTTP calls without decorators:

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

## Developer Tools

- **Debug Watch**: Tail proxy trace WAL in real time: `cargo run --manifest-path dev/cli/Cargo.toml -- debug watch`
- **Chain Verify**: Verify BLAKE3 hash chain integrity of the **proxy's** trace log: `cargo run --manifest-path tools/aegis-verify/Cargo.toml -- ./data/proxy-trace.jsonl`. Note: This tool verifies the proxy's WAL (`./data/proxy-trace.jsonl`), not the Python SDK's local crash-recovery WAL (`aegis-trace-wal.jsonl`).

When using Docker, the proxy writes the trace to `./data/proxy-trace.jsonl` on the host (via volume mount). Run `make debug` or `make verify` from the repo root.

## Swarm / Multi-Agent Tracing

When Agent A calls Agent B, pass `parent_task_id` in trace entries so you can query the swarm lineage. Set `parent_task_id` to the parent agent's task ID when appending trace entries. Then query `GET /api/receipts?parent_task_id=<task_id>` to see receipts from child agents that were called by that parent.

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

- **Verifier API key**: For production, set `VERIFIER_API_KEY` and pass it as Bearer token or `x-api-key` when calling the verifier.
- **Grafana**: For production, set `GRAFANA_ADMIN_PASSWORD` to a strong value. Never use the default in production.
