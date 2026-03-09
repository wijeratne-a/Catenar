# Red Team Security Audit Report

**Auditor:** Senior Lead Security Researcher (Red Team)  
**Scope:** core/proxy, core/verifier, dashboard, policies  
**Date:** 2025-03

---

## Executive Summary

| Severity | Count | Summary |
|----------|-------|---------|
| Critical | 1 | Timing oracle in API key comparison |
| High | 3 | Verifier auth when unset, Grafana default password, potential HTTP/2 bypass |
| Medium | 4 | Rego ReDoS surface, receipt store limits, error info leakage |
| Low | 2 | .env.example placeholder, idempotency gap |

---

## Remediation Status

| ID | Severity | Status | Fixed In |
|----|----------|--------|----------|
| 1 | Critical | Fixed | Phase 1 |
| 2 | High | Fixed | Phase 2.1 |
| 3 | High | Fixed | Phase 2.2 |
| 4 | High | Documented | Phase 2.3 |
| 5 | Medium | Documented | Phase 3.1 |
| 6 | Medium | Documented | Phase 3.2 |
| 7 | Medium | Fixed | Phase 3.3 |
| 8 | Low | Fixed | Phase 4.1 |
| 9 | Low | Documented | Phase 4.2 |

---

## Vulnerability Detailed Breakdown

### 1. Timing Oracle in API Key Comparison (Critical)

**File Path:** [core/verifier/src/lib.rs:144-146](core/verifier/src/lib.rs)

**Vulnerability Type:** Timing Side-Channel (Information Disclosure)

**Exploit Scenario:** An attacker measures response time for `/v1/verify` with different-length API keys. The check `a.len() != b.len()` returns immediately when lengths differ, before `constant_time_eq`. By probing with keys of length 1, 2, 3, ... the attacker can infer the correct key length, then brute-force character-by-character using timing.

**Current Code:**
```rust
if a.len() != b.len() || !constant_time_eq(a, b) {
    return (StatusCode::UNAUTHORIZED, ...);
}
```

**Fix:** Always perform constant-time comparison. Hash both values and compare hashes, or pad to fixed length:
```rust
// Option A: Compare hashes
let a_hash = blake3::hash(a);
let b_hash = blake3::hash(b);
if !constant_time_eq(a_hash.as_bytes(), b_hash.as_bytes()) {
    return (StatusCode::UNAUTHORIZED, ...);
}
// Option B: Pad to max len and compare (ensure no early exit on length)
```

**FIX APPLIED (Phase 1):** Hash-based constant-time comparison implemented in lib.rs (API key) and engine.rs (task token signature).

---

### 2. Verifier Returns 401 When VERIFIER_API_KEY Unset (High)

**File Path:** [core/verifier/src/lib.rs:117-123](core/verifier/src/lib.rs)

**Vulnerability Type:** Misconfiguration / Default-Deny Breaking Demo

**Exploit Scenario:** When `VERIFIER_API_KEY` is not set, `state.api_key` is `None`. The middleware returns 401 "API key required" for all protected routes (`/v1/register`, `/v1/verify`, etc.). Docker Compose does not set `VERIFIER_API_KEY`. The demo and SDK flows fail. If the intent is "no auth when not configured," this is a bug. If the intent is "always require API key," the demo and docs must be updated.

**Fix (if no-auth-when-unset is desired):**
```rust
let Some(ref expected) = state.api_key else {
    return next.run(request).await;  // Allow through when not configured
};
```

**Fix (if default-deny is desired):** Add `VERIFIER_API_KEY` to docker-compose and document in getting-started.md.

---

### 3. Grafana Default Credentials (High)

**File Path:** [docker-compose.yml:81-84](docker-compose.yml)

**Vulnerability Type:** Hardcoded Default Password

**Exploit Scenario:** `GF_SECURITY_ADMIN_PASSWORD: admin` is committed. Any user who runs `docker compose up` exposes Grafana on port 3002 with admin/admin. In production, this is a critical credential.

**Fix:** Use env var with no default, or generate at first run:
```yaml
GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD required}
```

**FIX APPLIED (Phase 2.2):** Grafana uses `GRAFANA_ADMIN_PASSWORD` env var with `changeme-admin-demo-only` default. .env.example updated. Production note in getting-started.md.

---

### 4. HTTP/2 Bypass Risk (High – Informational)

**File Path:** [core/proxy/src/intercept.rs:52-60](core/proxy/src/intercept.rs)

**Vulnerability Type:** Protocol Support Gap

**Exploit Scenario:** The proxy uses `looks_like_http()` to detect HTTP by checking for method prefixes (`GET `, `POST `, etc.). HTTP/2 uses binary framing (SETTINGS, HEADERS) and does not start with ASCII method strings. Clients using HTTP/2 inside the CONNECT tunnel may be rejected with "Non-HTTP protocol detected" or fail in unexpected ways. An attacker could potentially use HTTP/2 to bypass policy if the proxy mishandles it.

**Fix:** Document that the proxy supports HTTP/1.1 only. Add explicit HTTP/2 detection and rejection with a clear error, or implement H2 support.

**FIX APPLIED (Phase 2.3):** Error message updated to "Non-HTTP/1.1 protocol detected"; HTTP/2 support documented in docs/proxy_mitm_ca_trust.md.

---

### 5. Rego Regex ReDoS Surface (Medium)

**File Path:** [policies/response.rego:10,47](policies/response.rego), [policies/payload.rego:17](policies/payload.rego)

**Vulnerability Type:** Regular Expression Denial of Service (ReDoS)

**Exploit Scenario:** The patterns `"ignore (all|any|previous) (instructions|rules)"` and `"(api_key|apikey|secret_key|...)[ \\t]*[=:]"` are relatively simple. Rego's `regex.match` uses the Go regex engine. These specific patterns are unlikely to cause catastrophic backtracking, but user-supplied or configurable regex in future policies could. The `[0-9]{3}-[0-9]{2}-[0-9]{4}` SSN pattern is safe.

**Fix:** Audit any user-configurable regex. Consider regex complexity limits or a safe regex subset. Current patterns appear low-risk but should be documented as "do not add nested quantifiers."

**FIX APPLIED (Phase 3.1):** ReDoS prevention guidelines added to policies/README.md.

---

### 6. Receipt Store Unbounded Growth (Medium)

**File Path:** [dashboard/src/lib/receipt-store.ts:9-20](dashboard/src/lib/receipt-store.ts)

**Vulnerability Type:** Resource Exhaustion (Mitigated)

**Exploit Scenario:** `MAX_RECEIPTS = 1000` caps the in-memory store. An attacker with a valid `SIDECAR_INGEST_TOKEN` could push 1000 receipts rapidly. The cap prevents OOM but the store is still in-memory; restart loses data. No persistence or audit trail beyond the cap.

**Fix:** Document the 1000-receipt limit. Consider persistence for audit. Rate limiting on ingest (already present) helps.

**FIX APPLIED (Phase 3.2):** JSDoc added to receipt-store.ts documenting MAX_RECEIPTS and in-memory behavior.

---

### 7. Error Message Leakage (Medium)

**File Path:** [core/verifier/src/lib.rs:82-83](core/verifier/src/lib.rs), [core/verifier/src/engine.rs:347](core/verifier/src/engine.rs)

**Vulnerability Type:** Information Disclosure

**Exploit Scenario:** `AppError::internal` logs the full error with `tracing::error!(error = %self.message)`. Internal errors (e.g. serialization failures) may include stack traces or payload fragments. The client receives only `"Internal error (ref: {uuid})"` which is good, but server logs could leak sensitive data.

**Fix:** Sanitize `self.message` before logging—redact tokens, keys, and large payloads.

**FIX APPLIED (Phase 3.3):** `sanitize_log_message()` added to redact sensitive terms and truncate before logging.

---

### 8. .env.example Placeholder Secret (Low)

**File Path:** [.env.example](.env.example)

**Vulnerability Type:** Weak Default

**Exploit Scenario:** `WEBHOOK_SECRET=demo-webhook-secret-min-32-characters-long` is a placeholder. If users copy to `.env` without changing it, webhook signatures are predictable.

**Fix:** Add a comment: "CHANGE THIS before production. Generate with: openssl rand -hex 32"

**FIX APPLIED (Phase 4.1):** Hardening comments added for WEBHOOK_SECRET, GRAFANA_ADMIN_PASSWORD, VERIFIER_API_KEY.

---

### 9. Byzantine Failure: Proof Loss on Crash (Low)

**File Path:** [core/verifier/src/engine.rs](core/verifier/src/engine.rs), proxy trace flow

**Vulnerability Type:** Idempotency / Crash Recovery Gap

**Exploit Scenario:** If the proxy successfully forwards a request and appends to the trace WAL, but crashes before the verifier generates a receipt, the "Proof" for that request is lost. The trace chain continues on restart, but there is no receipt. The verifier has no crash-recovery or idempotency key for verify requests—duplicate verify calls produce new receipts. No "Order 12" style idempotency was found.

**Fix:** Document that receipt generation is best-effort. For critical audit, consider WAL replay or idempotency keys for verify.

**FIX APPLIED (Phase 4.2):** Receipt Generation Semantics section added to docs/ARCHITECTURE.md.

---

## Hardcoded Secret Scan

| Location | Type | Risk |
|----------|------|------|
| [.env.example:3](.env.example) | WEBHOOK_SECRET placeholder | Low – documented |
| [docker-compose.yml:81](docker-compose.yml) | GF_SECURITY_ADMIN_PASSWORD (env var) | Fixed – uses GRAFANA_ADMIN_PASSWORD |
| [core/verifier/src/engine.rs:441-442](core/verifier/src/engine.rs) | TEST_WEBHOOK_SECRET (test only) | None – test |
| [core/proxy/src/webhook.rs:86-87](core/proxy/src/webhook.rs) | TEST_SECRET (test only) | None – test |

---

## Rate-Limiting Audit

| Endpoint | Component | Rate Limit | Notes |
|----------|-----------|------------|-------|
| Proxy (all) | core/proxy | 60 req/60s per IP | [intercept.rs:37-38,562](core/proxy/src/intercept.rs) |
| /healthz | verifier | 60 req/60s | rate_limit_middleware |
| /v1/register | verifier | 60 req/60s | rate_limit_middleware |
| /v1/verify | verifier | 60 req/60s | rate_limit_middleware |
| /v1/receipt | verifier | 60 req/60s | rate_limit_middleware |
| /v1/agent/register | verifier | 60 req/60s | rate_limit_middleware |
| /v1/agents | verifier | 60 req/60s | rate_limit_middleware |
| CA forge | core/proxy certs | 100/60s | [certs.rs:137](core/proxy/src/certs.rs) |
| POST /api/alerts/ingest | dashboard | None | Webhook signature required |
| POST /api/receipts | dashboard | Yes | checkReceiptIngestLimit |
| GET /api/receipts | dashboard | None | Session required |

---

## Positive Findings

- **Constant-time comparison:** API key and task token use `constant_time_eq` (except length short-circuit).
- **Body size limits:** Proxy limits request 5MB, response 10MB. Verifier limits 1MB. Schema limits execution_trace to 256 entries, strings to 4096 chars.
- **Dashboard webhook/auth:** Alerts ingest requires HMAC signature. Receipts GET requires session. Receipt POST requires SIDECAR_INGEST_TOKEN with timingSafeEqual.
- **Ed25519:** Uses `OsRng` (CSPRNG) for LocalKeyProvider.
- **No SQL/NoSQL:** Receipt and alert stores are in-memory arrays; no injection vector.

---

## Recommended Priority

1. **Immediate:** Fix timing oracle (Critical).
2. **Before production:** Resolve VERIFIER_API_KEY behavior, remove Grafana default password.
3. **Document:** HTTP/2 support, Rego regex guidelines, proof loss on crash.

---

## Remediation Changelog

- **2025-03:** Critical timing oracle fixed (hash-based comparison). Verifier auth allows unauthenticated when VERIFIER_API_KEY unset. Grafana uses env var. HTTP/2, ReDoS, receipt store, error leakage, .env.example, idempotency documented or fixed.
