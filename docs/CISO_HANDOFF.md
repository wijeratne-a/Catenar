# Catenar: CISO Handoff

One-page summary for engineers handing off Catenar to CISOs.

## Problem

AI agents make outbound calls to tools, APIs, and databases. Without inspection, agents can exfiltrate PII, access restricted endpoints, or execute unauthorized actions. Standard network controls do not decrypt or evaluate agent traffic.

## Solution

Catenar is a Zero Trust layer for AI agents. It sits between agents and external systems, inspects every outbound call, enforces policy, and produces cryptographically verifiable Proof-of-Task (PoT) receipts.

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **Policy enforcement** | Block restricted endpoints, PII patterns, and custom Rego rules |
| **Proof-of-Task receipts** | Each action cryptographically bound to policy; BLAKE3 chain + Ed25519 signature |
| **Real-time alerts** | Violations fire webhooks to control plane; incidents grouped for forensics |
| **Swarm lineage** | Trace agent-to-agent calls via `parent_task_id` |
| **Compliance export** | JSON/CSV export for SIEM; date range filters |

## What Engineers Get Today (Open Core)

- HTTP/1.1 interception and policy evaluation
- Rego policy engine (payload and response)
- Dashboard with receipts, alerts, and compliance export
- Swarm lineage and `parent_task_id` indexing
- BLAKE3 hash chain for trace integrity
- Local Ed25519 signing (env key)

## What Enterprise Adds

- **HA Idempotency Ledger** — Survives crash; rejects duplicate traces across zones
- **HSM Signing** — AWS KMS, Yubico; SOC2-compliant key custody
- **Multi-Signature Policy** — 2-of-2 (Operator + Compliance) for policy commitments
- **Binary WebSocket Inspection** — Packet-by-packet Rego evaluation

See [ENTERPRISE_BOUNDARY.md](ENTERPRISE_BOUNDARY.md) for full comparison.

## Demo

- **Dashboard:** http://localhost:3001 (after `make demo`)
- **Scripted walkthrough:** [docs/demo/ciso-demo-script.md](demo/ciso-demo-script.md) (15 min)

## Security and Audit

- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) — AppSec remediation and key management
- [RED_TEAM_SECURITY_AUDIT.md](RED_TEAM_SECURITY_AUDIT.md) — Red team findings
- [docs/runbooks/](runbooks/) — Operational runbooks (policy violation spike, proxy unhealthy, etc.)

## Enterprise Contact

For production deployments, HSM signing, and HA: contact Catenar Enterprise.
