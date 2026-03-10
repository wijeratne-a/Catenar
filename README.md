# Catenar

Zero Trust Network Access (ZTNA) proxy and cryptographic verifier for AI agents. Catenar inspects and enforces policy on outbound agent traffic, producing cryptographically verifiable Proof-of-Task receipts.

## Architecture

```mermaid
flowchart TB
    subgraph DataPlane [Data Plane]
        Proxy[core/proxy]
        Verifier[core/verifier]
        Proxy -->|verify traces| Verifier
    end

    subgraph ControlPlane [Control Plane]
        Dashboard[dashboard]
        Dashboard -->|policy registration| Verifier
        Verifier -->|webhook alerts| Dashboard
    end

    subgraph Agents [AI Agents]
        PythonSDK[sdks/python]
        NodeSDK[sdks/nodejs]
    end

    PythonSDK -->|HTTP via proxy| Proxy
    NodeSDK -->|HTTP via proxy| Proxy
```

- **Data plane** (`core/proxy`, `core/verifier`): TLS MITM proxy with Rego policy evaluation; verifier signs receipts and validates traces
- **Control plane** (`dashboard`): Next.js UI for policy management and receipt viewing
- **SDKs** (`sdks/python`, `sdks/nodejs`): Lightweight client libraries for agents to register policies and emit traced calls

## Quick Start

```bash
# Start infrastructure
docker compose up -d verifier proxy web prometheus grafana

# Verifier: http://localhost:3000
# Proxy:   http://localhost:8080
# Dashboard: http://localhost:3001
# Grafana:  http://localhost:3002 (admin/admin)
```

See [docs/demo/getting-started.md](docs/demo/getting-started.md) for full demo instructions.

## Component Index

| Component | Path | Description |
|-----------|------|-------------|
| Proxy | [core/proxy](core/proxy) | Forward proxy with TLS MITM, payload parsing, Rego policy |
| Verifier | [core/verifier](core/verifier) | Cryptographic verification and receipt signing |
| Crypto | [core/crypto](core/crypto) | Key generation and manifest signing (dev utility) |
| Python SDK | [sdks/python](sdks/python) | Catenar Proof-of-Task SDK for Python agents |
| Node.js SDK | [sdks/nodejs](sdks/nodejs) | Catenar Proof-of-Task SDK for Node.js |
| Dashboard | [dashboard](dashboard) | Next.js control plane UI |

## Developer Tools

| Tool | Command | Description |
|------|---------|-------------|
| Debug Watch | `make debug` or `cargo run --manifest-path dev/cli/Cargo.toml -- debug watch` | Tail proxy trace WAL and show policy decisions, BLAKE3 hashes in real time |
| Chain Verify | `make verify` or `cargo run --manifest-path tools/catenar-verify/Cargo.toml -- ./data/proxy-trace.jsonl` | Verify BLAKE3 hash chain. Run against proxy WAL (`./data/proxy-trace.jsonl`), not SDK WAL (`catenar-trace-wal.jsonl`). |

## Examples

- **[examples/stress_test_agent.py](examples/stress_test_agent.py)**: Stress test with 100+ concurrent HTTP calls. Uses `catenar_intercept` for zero-config tracing. Run with proxy and verifier: `HTTP_PROXY=http://127.0.0.1:8080 python examples/stress_test_agent.py`

## Open Core

**Catenar Community Edition** is open source under the [Apache 2.0 License](LICENSE). See [docs/OPEN_CORE.md](docs/OPEN_CORE.md) for supported key providers (local, env) and what is available in Catenar Enterprise (KMS, Vault, Redis, SIEM).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Proxy CA Trust](docs/proxy_mitm_ca_trust.md)
- [Security Audit](docs/SECURITY_AUDIT.md)
- [Design Standards](docs/web/design_standards.md)
- [Runbooks](docs/runbooks/)
- [Demo Getting Started](docs/demo/getting-started.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to report bugs, submit PRs, and contribute.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
