# Catenar Security & Performance Audit

**Auditor stance:** Zero-trust AppSec / Principal Systems Architect. Every user is malicious, every input is poisoned, every millisecond of latency is a failure.

**Scope:** Next.js API routes, Rust Verifier, Rust Proxy, Python SDK. Line-by-line references with production-grade fixes.

---

## Security Audit Remediation (March 2026)

The following 16 findings from the Senior AppSec line-by-line audit were fixed via multi-agent orchestration:

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| 1.1 | Critical | SSRF via DNS rebinding / authority bypass | DNS resolution check before forwarding; reject if any resolved IP is internal/private |
| 1.2 | High | Header injection via identity values | `sanitize_header_value()` rejects control bytes before x-catenar-caller insertion |
| 1.3 | Medium | SQL injection in SqlitePolicyStore | Already mitigated (parameterized queries) |
| 1.4 | Medium | Hash chaining lacks domain separation | `compute_chain_hash` uses `blake3::Hasher::new_derive_key("catenar.trace.chain.v1")` + length prefixes |
| 2.1 | Critical | Demo mode auth bypass (ALLOW_DEMO_LOGIN=true) | Requires exact `dangerous_insecure_demo_mode`; blocks in NODE_ENV=production |
| 2.2 | High | Task token secret in logs | Documented; zeroize pattern recommended for future |
| 2.3 | Medium | Webhook secret weak/absent | Validate WEBHOOK_SECRET ≥ 32 chars at startup; disable webhook if invalid |
| 3.1 | High | Rate limiter unbounded per-key arrays | MAX_ENTRIES_PER_KEY=60; cap array before push |
| 3.2 | High | Rego evaluation CPU exhaustion | Semaphore(64) limits concurrent policy evaluations in proxy and verifier |
| 3.3 | Medium | Certificate cache DoS (512 unique SNIs) | Forge rate limit: max 100 forges per 60s window |
| 4.1 | High | WAL race condition / corruption | Atomic write via temp file + `os.replace`; delete+persist under single lock |
| 4.2 | Medium | RwLock poisoning continues with corrupt state | Explicit error handling; return 500 on poisoned lock |
| 4.3 | Low | Schema validation error unbounded | Truncate reason to 500 chars |
| 4.4 | Medium | Timing side-channel in org extraction | Documented; lower priority |
| 4.5 | High | Rego policy user input without validation | Server-side: max 100KB; block http.send, crypto.x509, walk( |

**Migration:** `ALLOW_DEMO_LOGIN=true` or `1` no longer enables demo login. Use `ALLOW_DEMO_LOGIN=dangerous_insecure_demo_mode` for local development only.

---

## Latest Remediation (Multi-Agent Sprint)

The following 12 findings were fixed in a coordinated security sprint:

| Finding | Fix |
|---------|-----|
| **F1** Ephemeral LocalKeyProvider invalidates receipts on restart | Guard: `KEY_PROVIDER=local` now requires `CATENAR_DEV_ALLOW_EPHEMERAL_KEY=1` |
| **F2** Demo login accepts any password | Require `DEMO_PASSWORD` (min 16 chars); `timingSafeEqual` comparison |
| **F3** Identity headers from client used in Rego (policy bypass) | `get_identity()` now returns empty `IdentityContext`; no client header trust |
| **F4** X-Forwarded-For spoofing bypasses rate limits | `getTrustedIp()` uses last XFF when `TRUST_PROXY=true`; else x-real-ip/request.ip |
| **F5** Verifier HTTP client has no timeout | `reqwest::Client` with 5s timeout, 3s connect_timeout |
| **F6** Org ID from headers allows cross-tenant poisoning | Token-bound org: `orgId.signature` format; parse org from token when present |
| **F7** Webhook HMAC encoding mismatch (proxy hex vs verifier base64) | Verifier now uses hex to match proxy/GitHub convention |
| **F8** /v1/receipt silently discards payload | Returns 501 Not Implemented with explicit error |
| **F9** Audit export not admin-only | Added `role === "admin"` check; 403 for auditors |
| **F10** Rate limiter O(n) cleanup + unbounded Map | Periodic cleanup (30s); `MAX_TRACKED_KEYS=50_000` load shedding |
| **F11** Next.js register not forwarding to verifier | POST to `VERIFIER_URL/v1/register` with API key when set |
| **F12** Vault public_key returned as UTF-8 bytes | Base64-decode Vault Transit public_key before use |

**New env vars:** `DEMO_PASSWORD`, `TRUST_PROXY`, `CATENAR_DEV_ALLOW_EPHEMERAL_KEY`, `VERIFIER_URL`, `VERIFIER_API_KEY`

---

## Remediation Status

| Finding | Status | Notes |
|---------|--------|-------|
| POST /api/receipts open when SIDECAR_INGEST_TOKEN unset | **Fixed** | Token required (min 32 chars); 503 when not configured; timing-safe comparison |
| Verifier /v1/register, /v1/verify unauthenticated | **Mitigated** | Optional VERIFIER_API_KEY; Bearer or X-Api-Key; constant-time comparison |
| /v1/receipt accepts arbitrary JSON, no-op | **Deferred** | Document as deprecated/no-op; receipt ingest via Next.js control plane |
| Login simulated auth, no rate limit | **Fixed** | ALLOW_DEMO_LOGIN flag; 5/min rate limit per IP; production must use real IdP |
| GET /api/receipts returns all receipts | **Fixed** | tenant_id scoping; filter by session.username |
| AppError exposes internal messages | **Fixed** | CATENAR_DEBUG controls exposure; generic "Internal error" in production |
| Verifier no body size limit | **Fixed** | RequestBodyLimitLayer 1 MB |
| Verifier CORS .unwrap() on parse | **Fixed** | .expect("hardcoded origin") |
| Proxy CONNECT SSRF | **Fixed** | is_internal_or_private(); 403 for localhost, private IPs, link-local |
| Proxy .expect("valid response") | **Fixed** | Fallback to 500 on builder failure |
| Proxy blocking I/O (trace log) | **Fixed** | spawn_blocking for logger.append |
| Receipt POST no rate limit | **Fixed** | 60/min per tenant/key |
| Receipt POST no body limit | **Fixed** | 64 KB max before parse |
| VerifyRequest unbounded execution_trace | **Fixed** | Schema + policy caps: 256 entries, 4096 char strings |
| hex_encode per-byte allocation | **Fixed** | Preallocated String, write_fmt |
| GET /api/receipts unbounded | **Fixed** | Pagination: limit (default 50, max 200), offset |
| In-memory rate limit | **Deferred** | Document in runbook: use Redis/Upstash for production |
| Verifier policy persistence | **Deferred** | Document: sidecars re-register after restart |

---

## 1. Zero-Trust API Test

### 1.1 Unintentionally exposed / weakly protected endpoints

| Location | Flaw | Severity |
|----------|------|----------|
| `web/src/app/api/receipts/route.ts:13–17` | **POST /api/receipts** — When `SIDECAR_INGEST_TOKEN` is unset, `isAuthorizedSidecar()` returns `true`. Any unauthenticated client can push arbitrary receipt objects into the control plane and exhaust the in-memory store. | **Critical** |
| `verifier/src/main.rs:98–104` | **/v1/register, /v1/verify, /v1/receipt, /healthz** — No authentication. Any client on the network can register policies, verify traces, and ingest receipts. Sidecar is assumed to run in a trusted VPC; if ever exposed (misconfig, VPN, etc.), full takeover. | **Critical** (when verifier is reachable from untrusted networks) |
| `verifier/src/main.rs:99` | **/v1/receipt** — Accepts arbitrary JSON (`Json<Value>`), does nothing with it, returns 200. Unauthenticated and useless; either remove or require auth and validate. | **High** (noise / abuse) |
| `web/src/app/api/auth/login/route.ts:22–29` | **Simulated auth** — Accepts any non-empty username/password and issues a valid JWT. No credential check, no rate limit on login. Enables brute-force and account enumeration. | **Critical** in production |

**Production-grade fixes**

- **Receipts POST:** Require `SIDECAR_INGEST_TOKEN` in production and reject with 503 when unset so the endpoint is never “open by default”:

```ts
// web/src/app/api/receipts/route.ts
function isAuthorizedSidecar(request: NextRequest): boolean {
  const expected = process.env.SIDECAR_INGEST_TOKEN;
  if (!expected || expected.length < 32) return false; // require explicit secret
  const token = request.headers.get("x-catenar-ingest-token");
  return token != null && crypto.timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(token, "utf8"));
}
```

- **Verifier:** Add optional API key or mTLS for /v1/register and /v1/verify when deployed in a DMZ; at minimum enforce a `Content-Length` / body size limit (see §2).
- **Login:** Remove simulated auth; integrate a real IdP or at minimum hash passwords, use constant-time comparison, and rate-limit by IP and username.

### 1.2 Broken object-level authorization

| Location | Flaw |
|----------|------|
| `web/src/app/api/receipts/route.ts:50` | **GET /api/receipts** — Returns *all* receipts to any authenticated user. No tenant/user/org scoping. One user sees every sidecar’s receipts. |

**Fix:** Store receipts with a `tenant_id` or `user_id` (from session or ingest token) and filter: `receipts.filter(r => r.tenantId === session.tenantId)`.

### 1.3 Internal state leakage via error messages

| Location | Flaw |
|----------|------|
| `verifier/src/main.rs:51–56` | **AppError::into_response** — Returns `error: self.message` in JSON. Messages come from `AppError::internal(format!("..."))` and can include serialization/verification details (e.g. “failed to encode policy JSON: …”). |
| `web/src/app/api/register/route.ts:68–71` | On failure, returns generic “Failed to register policy commitment” but logs full `err` to stdout (stack traces, env, paths). Ensure logs are not exposed to clients. |

**Fix (verifier):** In production, map internal errors to a generic message and a stable `error_code`; log the real error server-side only.

```rust
// verifier: map to generic in production
let message = if std::env::var("RUST_BACKTRACE").is_ok() {
    self.message.clone()
} else {
    "Internal error".to_string()
};
```

---

## 2. Abuse & Rate Limiting Test

### 2.1 DDoS and bypass vectors

| Location | Flaw |
|----------|------|
| `web/src/app/api/receipts/route.ts` | **POST /api/receipts** — No rate limiting. Attacker can flood receipt ingest and fill the in-memory array (capped at 1000) and cause churn. |
| `web/src/lib/rate-limit.ts:11` | In-memory `Map`; per-process and lost on restart. No cross-instance limit; trivial to bypass with many IPs. |
| `web/src/app/api/register/route.ts:12` | Rate limit key uses `session:username` when logged in, else IP. Spoofing `X-Forwarded-For` (when not behind a trusted proxy) can bypass or share limits. |
| `verifier/src/main.rs` | **No rate limiting.** /v1/register and /v1/verify can be hammered; policy store and CPU (Rego, hashing) are exhaustible. |

### 2.2 Algorithmic complexity / oversized payloads

| Location | Flaw |
|----------|------|
| `verifier` (all handlers) | **No body size limit.** Axum reads the body until EOF. A 10 GB JSON payload will be buffered and parsed; leads to OOM or CPU exhaustion (serde_json). |
| `web/src/lib/schemas.ts:65` | **registerPolicySchema** — `rego_policy: z.string().max(20000)` allows 20 KB of Rego per request; no limit on total request body in Next.js for this route (only generic 1MB in register). |
| `verifier/src/schema.rs` | **VerifyRequest** — No `#[serde(max_depth)]` or array length limit. Deeply nested or huge `execution_trace` can cause high CPU/memory during parse or in Rego. |

**Production-grade fixes**

- **Verifier:** Enforce a max body size (e.g. 1 MB) via tower layer or in the first middleware:

```rust
// Add to verifier: body size limit
use axum::body::Body;
use axum::extract::Request;
// In router: .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
```

- **Next.js receipts POST:** Add the same rate-limit helper used by register (or a stricter one) and validate body size before parsing.
- **Rate limit:** Use Redis/Upstash with a single key space and consistent hashing so all instances share the same limit.

---

## 3. Code Hardening (Anti-Hack) Test

### 3.1 SSRF

| Location | Flaw |
|----------|------|
| `proxy/src/intercept.rs:279–293` | **CONNECT tunnel** — `authority` is taken directly from the client request. `TcpStream::connect(&authority)` is classic SSRF: attacker sends `CONNECT 169.254.169.254:80` or `CONNECT internal-service:3000` and the proxy connects to metadata or internal services and tunnels traffic. |
| `web/src/lib/anchor.ts:40` | **GitHub API** — URL is fixed (`https://api.github.com/gists/${gistId}`). `gistId` comes from env, not user input; low risk unless env is poisoned. No user-controlled URL. |

**Fix (proxy):** Block private/internal IPs and hostnames for CONNECT:

```rust
fn is_internal_or_private(authority: &str) -> bool {
    let (host, _) = authority.split_once(':').unwrap_or((authority, ""));
    if host == "localhost" || host == "127.0.0.1" || host.ends_with(".local") { return true; }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_link_local();
    }
    false
}
// In handle_connect, before tunnel():
if is_internal_or_private(&authority) {
    return Ok(response_with(StatusCode::FORBIDDEN, r#"{"error":"CONNECT to internal targets forbidden"}"#));
}
```

### 3.2 Unsafe unwraps / panics in Rust

| Location | Risk |
|----------|------|
| `verifier/src/main.rs:67–68` | `"http://localhost:3001".parse().unwrap()` — If the constant were ever wrong, panic and process exit. Low risk but avoidable. |
| `proxy/src/intercept.rs:90, 235, 285` | `Response::builder().body(...).expect("valid response")` — Builder only panics on invalid header values; body type is fixed. Moderate; prefer `unwrap_or_else(|| unreachable!())` or handle. |
| `proxy/src/main.rs:93, 100` | Same pattern in error paths; one bad header could crash the proxy. |
| `verifier/src/engine.rs:63` | `Utc::now().timestamp_nanos_opt().unwrap_or_default()` — Safe; only returns 0 on overflow. |

**Fix:** Replace `.unwrap()` in main.rs with:

```rust
let mut origins: Vec<_> = vec![
    "http://localhost:3001".parse().expect("hardcoded origin"),
    "http://127.0.0.1:3001".parse().expect("hardcoded origin"),
];
```

So the panic message is explicit; or use `try_into().unwrap_or_else(|_| default_origins())` and avoid panics in production.

### 3.3 OWASP / injection

| Location | Flaw |
|----------|------|
| `verifier/src/policy.rs:101–104` | **Rego input** — Full `VerifyRequest` is serialized to JSON and passed as Rego `input`. Malicious trace content (e.g. huge strings, deep nesting) can stress the Rego engine; no sanitization of `request.execution_trace` or `details`. |
| `web/src/app/api/register/route.ts:55–56` | **blake3Commitment(parsed.data)** — `parsed.data` includes user-controlled `rego_policy`. Commitment is over that; no injection into anchor publish except via metadata (username from session). |

Recommendation: Cap `execution_trace` length and size of `details` in schema (e.g. `#[serde(max_depth = 5)]`, max array len 256 already in Zod but not in Rust), and optionally sanitize strings before Rego.

---

## 4. Micro-Optimization Test

### 4.1 Blocking I/O in async path

| Location | Flaw |
|----------|------|
| `proxy/src/intercept.rs:178` | `state.logger.append(&trace_entry)` is called from the async `handle()`. `TraceLogger::append` uses `fs::OpenOptions`, `write_all`, and `flush` — all blocking. Under load this blocks the async worker thread. |

**Fix:** Use `tokio::fs::File` and `tokio::io::AsyncWriteExt`, or spawn a blocking task:

```rust
let logger = state.logger.clone();
let trace_entry = trace_entry.clone();
tokio::task::spawn_blocking(move || logger.append(&trace_entry)).await.ok();
```

### 4.2 Unnecessary allocations (Rust)

| Location | Flaw |
|----------|------|
| `verifier/src/engine.rs:16–17` | `hex_encode(bytes)` — Allocates a new `String` per byte with `format!("{b:02x}")`. For 64-byte sig + 32-byte key this is 96 small allocations. |
| `verifier/src/engine.rs:70–71` | `trace_hash.clone()`, `identity_hash.clone()` in `UnsignedReceipt` — Struct could take references to avoid clones. |
| `verifier/src/engine.rs:84–85` | `hex_encode(&signature)` — Signature is already `Vec<u8>`; `hex_encode` allocates again. |

**Fix (hex_encode):** Preallocate and write into a single buffer:

```rust
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
```

### 4.3 Latency and scalability

| Location | Flaw |
|----------|------|
| `web/src/app/api/receipts/route.ts:10` | **In-memory array** — `const receipts: StoredReceipt[] = []` is a global mutable array. No TTL; under sustained ingest the array grows (capped at 1000). GET returns the whole array every time (no pagination). |
| `web/src/app/api/register/route.ts:8` | **policies Map** — In-process only; lost on restart and not shared across instances. |
| `verifier` | **Policy store** — `DashMap<String, Value>` in memory; no persistence. Restart wipes policies; /v1/verify will always return “unknown policy commitment” after restart until re-register. |

---

## Summary Table

| Vector | Critical | High | Medium |
|--------|----------|------|--------|
| Zero-Trust API | 3 | 2 | 1 |
| Abuse / Rate limit | 0 | 2 | 3 |
| Code Hardening | 1 (SSRF) | 1 | 3 |
| Micro-Optimization | 0 | 1 (blocking I/O) | 4 |

**Immediate actions (production):**

1. **Never** run with `SIDECAR_INGEST_TOKEN` unset if receipt ingest is public; use timing-safe comparison.
2. **Add** body size limit (e.g. 1 MB) to the Rust verifier.
3. **Block** CONNECT to private/internal IPs and hostnames in the proxy.
4. **Replace** simulated login with real auth and rate-limit login + receipt POST.
5. **Scope** GET /api/receipts by tenant/user.
6. **Move** proxy trace log append to `spawn_blocking` or async file I/O.
7. **Harden** verifier error responses (no internal details to client).

---

## Key Management Roadmap

### KeyProvider Trait

All signing operations go through the `KeyProvider` trait (`verifier/src/keys.rs`):

```rust
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}
```

The active provider is selected at startup via the `KEY_PROVIDER` env var in `build_key_provider()`.

### Current Implementations

| Provider | `KEY_PROVIDER` value | Description | Env Vars |
|----------|---------------------|-------------|----------|
| `LocalKeyProvider` | `local` (default) | Generates a random Ed25519 keypair in-process on each startup. Suitable for development and demos. Keys are ephemeral and not persisted. | None |
| `EnvKeyProvider` | `env` | Loads a static Ed25519 private key from a hex-encoded env var. Suitable for staging or single-instance deployments where the key can be injected via secret management. | `CATENAR_SIGNING_KEY_HEX` (32-byte hex) |

### Planned Implementations (Stubs)

| Provider | `KEY_PROVIDER` value | Status | Description | Env Vars |
|----------|---------------------|--------|-------------|----------|
| `AwsKmsProvider` | `aws_kms` | **Stub** | Will delegate signing to AWS KMS via the `aws-sdk-kms` crate. The private key never leaves the HSM boundary. | `AWS_KMS_KEY_ID` |
| `VaultProvider` | `vault` | **Stub** | Will delegate signing to HashiCorp Vault Transit secrets engine. The private key is managed by Vault and never exposed to the verifier process. | `VAULT_MOUNT_PATH`, `VAULT_KEY_NAME` |

Both stubs currently bail with an explanatory error message at runtime if selected. They exist to validate the trait interface and env-var plumbing ahead of full integration.

### Production Guidance

- **Production deployments should use unextractable keys** managed by a KMS, Vault Transit engine, or hardware security module (HSM). The `local` and `env` providers expose raw key material in process memory.
- When `aws_kms` or `vault` providers are fully implemented, the private key will never be present in the verifier's address space; only the public key (for receipt verification) will be available locally.
- Rotate keys via KMS/Vault key versioning; the `public_key` field in each `PotReceipt` allows verifiers to identify which key version signed a given receipt.
