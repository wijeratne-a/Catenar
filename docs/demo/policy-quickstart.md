# Policy Quickstart

This guide explains where policy is defined in Catenar and how the pieces relate.

## Policy Sources

| Source | Purpose |
|-------|---------|
| **policy.json** | Proxy baseline: `restricted_endpoints` loaded at startup. Also used by core/crypto for BLAKE3 manifest signing. File-based, gitignored by default. Use `make setup` to create from policy.json.example. |
| **policies/payload.rego** | Advanced request-level rules (A2T/A2D/A2A). Loaded by proxy at startup. |
| **policies/response.rego** | Response inspection rules (e.g. prompt injection). Loaded by proxy at startup. |
| **Agent `catenar.init()`** | Policy registered with verifier: `public_values` (max_spend, restricted_endpoints) and optional Rego. Used for verification. |
| **Dashboard Policy Builder** | Registers policy to verifier and optionally syncs `restricted_endpoints` to proxy via `POST /policy`. |

## How They Relate

1. **Verifier** holds the canonical policy commitment for each agent session. The verifier validates execution traces against the registered policy.
2. **Proxy** enforces `restricted_endpoints` (and Rego rules) on traffic. Policy can come from:
   - `policy.json` at startup
   - `POST /policy` API (merge/override `restricted_endpoints` in memory)
   - Dashboard sync after registration (when `CATENAR_PROXY_URL` is set)
3. **Agent** must call `catenar.init()` with the same policy it intends to follow. The verifier rejects traces that violate the registered policy.

## Single Source of Truth (After Unification)

- **Verifier** = source of truth for *what the agent committed to*.
- **Proxy** = runtime enforcement. Sync from dashboard or API keeps proxy aligned with registered policy.
- **Recommendation:** Define policy once (dashboard or agent), register to verifier, and let dashboard sync to proxy when `CATENAR_PROXY_URL` is configured.

## Proxy Policy API

- `GET /policy` — Returns current in-memory policy (JSON with `restricted_endpoints`).
- `POST /policy` — Accepts `{"restricted_endpoints": ["host1", "host2"]}` and merges into live policy.
- Policy management endpoints require loopback or `POLICY_MANAGEMENT_FROM_DASHBOARD=1` / `POLICY_MANAGEMENT_ALLOW_NETWORKS`.

See [getting-started.md](getting-started.md) for setup and [ARCHITECTURE](../ARCHITECTURE.md) for system design.
