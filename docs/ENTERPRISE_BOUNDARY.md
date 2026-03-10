# Catenar Enterprise Boundary

This document clarifies which capabilities are in the Open Core (free, community) versus Catenar Enterprise (commercial license).

## Production Resilience (Enterprise)

The Open Core is designed for testing, proof-of-concept, and development. Production deployments requiring crash recovery, deep protocol inspection, or hardware-backed trust require Catenar Enterprise.

| Feature | Open Core | Enterprise |
|---------|-----------|------------|
| **Persistence** | In-memory store; restart loses receipts | HA Idempotency Ledger; survives crash across zones |
| **WebSocket inspection** | Log and tunnel only | Binary frame Rego evaluation; packet-by-packet policy |
| **Signing** | Local Ed25519 (env key) | AWS KMS, HSM, Yubico; SOC2 compliance |

## Open Core Capabilities

- HTTP/1.1 interception and policy evaluation
- WebSocket handshake detection and logging
- Correction suggestions in policy block responses
- `parent_task_id` indexing for swarm lineage
- BLAKE3 hash chain for trace integrity
- Rego policy engine (payload and response)
- Dashboard with receipts, alerts, and agents

## Enterprise Extensions

- **Global Idempotency State**: Distributed deduplication ledger; rejects duplicate trace submissions across agents and zones
- **Hardware-Backed HSM Signing**: Receipt signatures via AWS CloudHSM, Yubico, or equivalent
- **Multi-Signature Policy Validation**: 2-of-2 multisig (Operator + Compliance) for policy commitments
- **Distributed Lease Consensus**: Prevents multi-zone deadlocks when agents contend for resources
