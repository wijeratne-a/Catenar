# Policy Examples

This directory contains sample policy configurations for Catenar.

## default.json

A minimal policy template that mirrors [policy.json.example](../../policy.json.example) at the repo root. The proxy reads policy via `POLICY_PATH` (default: `policy.json` at repo root).

### Fields

- **restricted_endpoints**: List of hostnames the proxy will block (e.g., `admin.company.com`, `db.internal`)

### Setup

Use [policy.json.example](../../policy.json.example) as the primary template:

```bash
cp policy.json.example policy.json
```

Or run `make setup` to create `policy.json` automatically. For Rego-based policies, see [../../policies/](../../policies/) (e.g., `payload.rego`, `response.rego`).

See [docs/demo/policy-quickstart.md](../../docs/demo/policy-quickstart.md) for the full policy layout and how policy sources interact.
