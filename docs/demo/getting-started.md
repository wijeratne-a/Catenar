# Aegis Demo Script

## Prerequisites

1. **Start infrastructure** (Docker Compose):
   ```bash
   docker compose up -d verifier proxy web prometheus grafana
   ```

2. **Start Control Plane** (optional, for receipt ingest):
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
export REQUESTS_CA_BUNDLE=/etc/aegis/ca.crt  # or path to proxy CA

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
export REQUESTS_CA_BUNDLE=/etc/aegis/ca.crt  # or path to proxy CA

python examples/stress_test_agent.py
```

## Developer Tools

- **Debug Watch**: Tail proxy trace WAL in real time: `cargo run --manifest-path dev/cli/Cargo.toml -- debug watch`
- **Chain Verify**: Verify BLAKE3 hash chain: `cargo run --manifest-path tools/aegis-verify/Cargo.toml -- ./data/proxy-trace.jsonl`

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
