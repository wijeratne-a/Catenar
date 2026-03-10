# Runbook: Policy Violation Spike

## Symptom
Policy violation rate exceeds baseline (e.g., 3σ above rolling 1h average).

## Detection
- Datadog: `avg(last_15m):anomalies(sum:catenar.policy_violation{domain:*}.as_rate(), 'agile', 3) >= 1`
- Splunk: `index=catenar_audit | timechart span=5m count by domain | streamstats window=12 avg(count) as baseline stdev(count) as std | where count > baseline + 3*std`

## Response

1. **Identify domain**: Check which agent domain(s) are spiking.
2. **Check recent policy changes**: Review policy history in Control Plane.
3. **Inspect violation reasons**: Filter alerts by `violation_type` (restricted_endpoint, pii_pattern, spend_limit, etc.).
4. **Escalate**: If pattern suggests prompt injection or model drift, escalate to SOC P1.
5. **Mitigate**: Consider switching proxy to `ENFORCE_MODE=audit_only` temporarily if blocking critical business flow.

## Recovery
- Revert policy changes if accidental.
- Update restricted_endpoints or Rego rules if legitimate new endpoints needed.
- Restore `ENFORCE_MODE=strict` after root cause resolved.
