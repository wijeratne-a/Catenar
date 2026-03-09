# Aegis Deployment

## Open Core Chart

The base Helm chart at `helm/aegis/` deploys the Aegis proxy and verifier with Open Core capabilities:

- **Verifier**: Uses `KEY_PROVIDER=env` with `AEGIS_SIGNING_KEY_HEX` (or `local` with `AEGIS_DEV_ALLOW_EPHEMERAL_KEY=1` for development only)
- **Proxy**: TLS MITM, Rego policy evaluation, BLAKE3 trace chaining
- **Observability**: Prometheus metrics, OTLP export (when configured)

## Enterprise Chart

The `helm/enterprise/` chart adds Enterprise-only resources:

- **Redis**: Distributed rate limiting and state (when `redis.enabled=true`)
- **SIEM Integrations**: Datadog, Splunk HEC configmaps (when `integrations.*.enabled=true`)

For AWS KMS, HashiCorp Vault signing, and full SIEM pipelines, use **Aegis Enterprise**.
