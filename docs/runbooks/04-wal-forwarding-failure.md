# Runbook: WAL Forwarding Failure

## Symptom
- Fluent Bit sidecar errors
- Logs not appearing in Splunk/Datadog
- OTel collector pipeline errors

## Checks

1. **Fluent Bit logs**:
   ```bash
   kubectl logs <proxy-pod> -c fluent-bit
   ```

2. **OTel collector**:
   ```bash
   kubectl logs deployment/otel-collector
   ```

3. **Endpoints**:
   - `SIEM_OTLP_HTTP_ENDPOINT` / `SPLUNK_HEC_ENDPOINT` reachable from cluster
   - Tokens set and valid

4. **WAL path**: Ensure `TRACE_WAL_PATH` volume is writable and shared with Fluent Bit sidecar.

## Resolution

- **Fluent Bit config**: Verify `configmap-fluent-bit` output host/port match otel-collector.
- **Network**: Allow egress from proxy/otel-collector to SIEM endpoints.
- **TLS**: If SIEM requires HTTPS, ensure CA bundle is configured in OTel collector.
- **Fallback**: WAL is still written locally; forwarding is best-effort. Receipts remain in verifier/control plane.
