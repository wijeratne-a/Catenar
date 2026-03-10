# Policy Examples

This directory contains sample policy configurations for Catenar.

## default.json

A minimal policy template used by the proxy and crypto utilities. The proxy reads policy via `POLICY_PATH` (default: `policy.json` at repo root).

### Fields

- **version**: Policy schema version
- **allowed_paths**: Paths explicitly allowed (if your policy engine uses this)
- **denied_paths**: Paths explicitly denied (e.g., sensitive files)

### Customizing

Copy `default.json` to `policy.json` at the repo root (or set `POLICY_PATH` to point to your custom file). For Rego-based policies, see [../../policies/](../../policies/) (e.g., `payload.rego`, `response.rego`).
