# Aegis Demo Script

## Prerequisites

1. **Start infrastructure** (Docker Compose):
   ```bash
   docker compose up -d aegis-verifier aegis-proxy redis otel-collector prometheus
   ```

2. **Start Control Plane** (optional, for receipt ingest):
   ```bash
   cd web && npm run dev
   ```

3. **Python environment**:
   ```bash
   cd agent && pip install -e .
   ```

## Quick Demo (Python)

```bash
cd agent
python agent.py --demo
```

Runs a scripted three-phase enterprise demo with colored output.

## Manual Python Demo

```bash
# Configure proxy (required for TLS MITM)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export REQUESTS_CA_BUNDLE=/etc/aegis/ca.crt  # or path to proxy CA

cd agent
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
cd sdk-node
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

## Webhook + Alerts

To receive policy violation alerts in the Control Plane:

1. Set in verifier environment:
   - `WEBHOOK_URL=https://your-control-plane/api/alerts/ingest`
   - `WEBHOOK_SECRET=<min-32-chars>`

2. Set in Control Plane (web):
   - `WEBHOOK_SECRET=<same-secret>`

3. Violations will appear in Dashboard → Alerts.

## Observability

- **Prometheus**: Scrape proxy `/metrics` (port 8080)
- **Grafana**: Pre-provisioned with Prometheus datasource (port 3001)
- **Splunk** (optional): `docker compose --profile observability up -d splunk`
