# Catenar Proxy

Forward proxy with TLS MITM, payload parsing, and Rego-based policy evaluation. See [../docs/proxy_mitm_ca_trust.md](../docs/proxy_mitm_ca_trust.md) for CA trust (REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS) and proxy setup.

## Quick Start

```bash
# Write CA to file for agent trust
export CATENAR_CA_PATH=/etc/catenar/ca.crt
cargo run
```

## Environment

| Variable        | Default          | Description                          |
|-----------------|------------------|--------------------------------------|
| PROXY_BIND      | 0.0.0.0:8080    | Listen address                       |
| CATENAR_CA_PATH   | (unset)         | Write Root CA PEM here for agents    |
| POLICY_PATH     | policy.json     | JSON policy config                   |
| POLICY_REGO_PATH| policies/payload.rego | Rego payload policy (optional) |
| SCHEMA_REGISTRY_PATH | (unset)         | Path to schema registry JSON (optional) |
| SCHEMA_DIR      | (unset)               | Dir containing registry.json (optional; see [schemas/registry.json.example](../../schemas/registry.json.example) for structure) |
| SEMANTIC_DENY   | true                  | Return 200+semantic body instead of 403 on block |
| VERIFIER_URL    | http://127.0.0.1:3000 | Verifier for healthcheck      |
| ENFORCE_MODE    | strict          | strict \| audit_only                 |
| UPSTREAM_TIMEOUT_SECS | 10 | Timeout in seconds for upstream requests (1–300) |
| CATENAR_CA_CERT_PATH | (unset) | PEM cert for BYO Root CA (enterprise PKI) |
| CATENAR_CA_KEY_PATH | (unset) | PEM private key for BYO Root CA |

## Trace Log

The proxy can write a trace WAL (write-ahead log) for audit. Each entry includes a `chain_hash` field. The chain is computed with BLAKE3 using derive key `catenar.trace.chain.v1` (previous hash + payload). Third-party verification must use the same key to reproduce hashes. See `proxy/src/trace_log.rs` → `compute_chain_hash`.
