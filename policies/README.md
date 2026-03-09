# Aegis Rego Policies

## ReDoS Prevention

Rego's `regex.match` uses the Go regex engine. To avoid ReDoS:

- Avoid nested quantifiers (e.g. `(a+)+`, `(a|a)*`)
- Prefer simple alternation and character classes
- Current patterns in response.rego and payload.rego are low-risk
- Do not add user-configurable regex without validation

## Policy Files

- `payload.rego` – Request body evaluation
- `response.rego` – Response body evaluation (instruction-hijack, credential patterns)
- `default.rego` – Default policy behavior

## Correction Suggestions

Policies can emit `suggestion` for developer-friendly block messages. When a payload or response rule sets `allow = false`, the policy can also define `suggestion` (e.g. "Try using the read-only endpoint or check restricted_endpoints in policy"). The proxy includes this in the semantic block response when `SEMANTIC_DENY=true`, enabling agents to programmatically correct their behavior.
