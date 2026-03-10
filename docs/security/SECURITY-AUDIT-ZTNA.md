# Catenar Open Core — Security Audit (ZTNA / Red Team)

**Auditor role:** Principal Application Security Engineer / Red Team  
**Scope:** Rust Proxy, Verifier, SDKs, Next.js Dashboard  
**Methodology:** Data flow & taint, auth/authz, crypto & trust, concurrency & memory, AI business logic  
**Date:** 2025-03-04

---

## Executive summary

This audit identifies vulnerabilities and logic flaws in the Catenar open-core codebase from a zero-trust perspective. Findings are ordered by severity; each includes file/line, exploit scenario, impact, and a concrete fix.

---

## 1. CRITICAL: Unbounded upstream response body in non-CONNECT path (proxy OOM DoS)

- **Severity:** Critical  
- **Type:** Unbounded buffer DoS / memory exhaustion  
- **File & line:** `core/proxy/src/intercept.rs` (response body handling in `handle()`, ~1006–1037)

**Description:**  
In the non-CONNECT HTTP proxy path (`handle()`), the upstream response body is read with `upstream.bytes().await` with no size limit. There is a `content_length()` check earlier only when building the request; for chunked encoding or when Content-Length is absent/wrong, the entire response is read into memory. The CONNECT/MITM path correctly streams and enforces `MAX_RESPONSE_BYTES`; the direct proxy path does not.

**Exploit scenario:**

1. Attacker (or compromised agent) sends a normal request through the proxy (non-CONNECT) to a server they control.
2. Upstream responds with chunked encoding and no Content-Length, streaming a multi-GB body.
3. Proxy calls `upstream.bytes().await` and buffers the full response.
4. Repeated requests or a single very large response exhausts proxy memory and crashes the process.

**Impact:** Denial of service of the proxy (and thus the AI data plane); possible OOM kill in containers.

**Fix:** Stream the response body through a size-limited reader (e.g. `BodyExt` with a limit) and reject once `MAX_RESPONSE_BYTES` is exceeded, consistent with the MITM path. Example pattern (conceptually):

```rust
// In handle(), replace:
//   let response_body = match upstream.bytes().await { ... };
// With a stream that enforces MAX_RESPONSE_BYTES (e.g. wrap upstream body in
// http_body_util::Limited and collect, or use a capped stream), then return
// 502 "upstream response too large" if the limit is exceeded.
use http_body_util::{BodyExt, Limited};

let body_stream = upstream.into_body();
let limited = Limited::new(body_stream, MAX_RESPONSE_BYTES);
let collected = limited.collect().await.map_err(|e| {
    if e.downcast_ref::<LengthLimitError>().is_some() {
        return Ok(block_response(
            &state.config,
            StatusCode::BAD_GATEWAY,
            "upstream response too large",
            Some("Catenar: Upstream response exceeds size limit. Do not retry."),
            None,
        ));
    }
    Err(anyhow::anyhow!("body collection failed: {}", e))
})??;
let response_body = collected.to_bytes();
```

Ensure the rest of `handle()` uses `response_body` as it does today (e.g. for response policy and building the final response).

---

## 2. HIGH: Host header injection / CRLF in absolute URI (request smuggling / SSRF)

- **Severity:** High  
- **Type:** Header injection / request smuggling  
- **File & line:** `core/proxy/src/intercept.rs` — `absolute_uri()` (lines 788–801)

**Description:**  
When building the absolute URI for non-CONNECT requests, the code uses the `Host` header value directly: `format!("http://{host}{path_q}")` and then parses it as a `Uri`. The `Host` value is not sanitized for control characters (CR, LF, NUL, etc.). A malicious client can send a `Host` header containing `\r\n` (or other control chars) and inject additional headers or alter the request line when the URI is serialized or when the request is forwarded.

**Exploit scenario:**

1. Attacker sends a request with  
   `Host: evil.com\r\nX-Malicious-Header: value`  
   or  
   `Host: good.com%0d%0aX-Injection: foo`.
2. `absolute_uri()` builds  
   `http://evil.com\r\nX-Malicious-Header: value/path`  
   (or the percent-decoded equivalent).
3. Parsing may produce a host that includes the injection, or the downstream/upstream parser may interpret the CRLF as a new line and treat it as a second request or header line.
4. Result: request smuggling, cache poisoning, or SSRF if the injected content changes the effective target.

**Impact:** Request smuggling, possible bypass of policy (e.g. targeting a different host), or header injection into upstream.

**Fix:** Sanitize the `Host` value before building the URI: reject or strip any byte &lt; 0x20 or 0x7f (reuse the same rule as `sanitize_header_value`), and optionally restrict to a single host (no spaces/CRLF). Example:

```rust
fn absolute_uri(uri: &Uri, headers: &http::HeaderMap<HeaderValue>) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }

    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .context("missing host header")?;

    // Prevent CRLF / control character injection
    let host_trimmed = host.trim();
    if !host_trimmed.bytes().all(|b| b >= 0x20 && b != 0x7f) {
        anyhow::bail!("invalid host header: control characters not allowed");
    }
    if host_trimmed.contains(['\r', '\n']) {
        anyhow::bail!("invalid host header: CR/LF not allowed");
    }

    let path_q = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let joined = format!("http://{host_trimmed}{path_q}");
    joined
        .parse::<Uri>()
        .with_context(|| format!("invalid absolute URI: {joined}"))
}
```

---

## 3. HIGH: Unbounded policy POST body (DoS for policy management)

- **Severity:** High  
- **Type:** Unbounded buffer DoS  
- **File & line:** `core/proxy/src/intercept.rs` — `handle_policy_post()` (lines 728–762)

**Description:**  
`handle_policy_post()` reads the request body with `req.body_mut().collect().await` and no length limit. Only callers with policy-management access (loopback, private IP, or `POLICY_MANAGEMENT_ALLOW_NETWORKS`) can reach this endpoint, but an attacker on the allowed network (or a compromised dashboard) can send a very large body and exhaust memory.

**Exploit scenario:**

1. Attacker has network access to the proxy’s policy management interface (e.g. same private network or compromised dashboard).
2. Sends `POST /policy` with a body of hundreds of MB or more.
3. Proxy buffers the full body before parsing JSON, causing high memory use or OOM.

**Impact:** DoS of the proxy for anyone allowed to use policy management; possible OOM.

**Fix:** Enforce a maximum body size (e.g. 256 KB or 1 MB) before collecting. Use the same pattern as elsewhere: wrap the body in `Limited` and collect, then return 413 if the limit is exceeded.

```rust
// In handle_policy_post, replace:
//   let body = req.body_mut();
//   let bytes = body.collect().await...
// With:
const MAX_POLICY_BODY_BYTES: usize = 256 * 1024; // 256 KB
let body = req.body_mut();
let limited = Limited::new(body, MAX_POLICY_BODY_BYTES);
let collected = limited
    .collect()
    .await
    .map_err(|e| anyhow::anyhow!("failed to read body: {}", e))?
    .to_bytes();
if collected.len() > MAX_POLICY_BODY_BYTES {
    return Ok(response_with(
        StatusCode::PAYLOAD_TOO_LARGE,
        r#"{"error":"policy body too large"}"#,
    ));
}
let update: PolicyUpdateBody = match serde_json::from_slice(&collected) {
    // ...
};
```

---

## 4. HIGH: Trace WAL full read on startup/reload (OOM / DoS)

- **Severity:** High  
- **Type:** Unbounded read / resource exhaustion  
- **File & line:** `core/proxy/src/trace_log.rs` — `load_last_hash()` (lines 87–106)

**Description:**  
`load_last_hash()` loads the entire trace file with `fs::read_to_string(path)`. For a long-running or heavily used proxy, the WAL can grow very large. Each time a new trace entry is appended, the code path may not call `load_last_hash` on every append (it only uses the in-memory `last_hash` after the first line), but `load_last_hash` is called from `TraceLogger::new()`. So on every proxy restart or any code path that constructs a new `TraceLogger` against an existing file, the full file is read into memory with no cap.

**Exploit scenario:**

1. Proxy runs for a long time (or under heavy load) and the trace WAL grows to several GB.
2. Proxy restarts (or a new `TraceLogger` is created against the same path).
3. `TraceLogger::new()` calls `load_last_hash(&path)`, which does `fs::read_to_string(path)`.
4. Process allocates multiple GB and may OOM or become unresponsive.

**Impact:** DoS on restart or re-init; OOM in containers; possible data loss if the process is killed.

**Fix:** Avoid reading the whole file. Read from the end in bounded chunks (e.g. last 64 KB or last N lines) and scan backwards for the last valid JSON line with `chain_hash`. Alternatively, maintain a small sidecar file that stores only the last hash (e.g. `<path>.last_hash`) and update it on each append; on init, read only that file. Example of reading last chunk:

```rust
fn load_last_hash(path: &Path) -> String {
    const TAIL_BYTES: usize = 64 * 1024; // 64 KB from end
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut file = std::io::BufReader::new(file);
    let len = file.seek(std::io::SeekFrom::End(0)).ok().unwrap_or(0) as usize;
    if len == 0 {
        return String::new();
    }
    let start = len.saturating_sub(TAIL_BYTES);
    file.seek(std::io::SeekFrom::Start(start as u64)).ok()?;
    let mut tail = vec![0u8; len - start];
    file.read_exact(&mut tail).ok()?;
    let content = String::from_utf8_lossy(&tail);
    for line in content.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(hash) = value.get("chain_hash").and_then(|v| v.as_str()) {
                return hash.to_string();
            }
        }
        break;
    }
    String::new()
}
```

(Adjust to use only standard library or existing deps; ensure `read_to_string` is never used on the full file.)

---

## 5. MEDIUM: Verifier API unauthenticated when API key not set

- **Severity:** Medium  
- **Type:** Missing authentication  
- **File & line:** `core/verifier/src/lib.rs` — route registration and `api_key_middleware` (lines 284–298, 123–161)

**Description:**  
The verifier’s sensitive routes (`/v1/register`, `/v1/verify`, `/v1/receipt`, `/v1/agent/register`, `/v1/agents`) are protected by `api_key_middleware` only when `state.api_key` is `Some`, i.e. when `VERIFIER_API_KEY` is set. If the operator does not set `VERIFIER_API_KEY`, any client can register policies, verify traces, and (where implemented) submit or list data.

**Exploit scenario:**

1. Verifier is deployed without `VERIFIER_API_KEY` (e.g. dev or misconfiguration).
2. Attacker calls `POST /v1/register` with arbitrary policy JSON and gets a policy commitment and optional task token.
3. Attacker can verify traces against that policy, register agents, and (if implemented) list agents or submit receipts.
4. Result: policy injection, trace verification abuse, or data exfiltration depending on what the API does with the data.

**Impact:** Unauthorized policy registration and verification; possible abuse of receipt/agent data if those endpoints are fully implemented.

**Fix:** Document that `VERIFIER_API_KEY` is required in production and fail fast at startup if the verifier is bound to a non-loopback address and `VERIFIER_API_KEY` is unset. Optionally, add a strict mode that refuses to start without an API key when not in dev.

```rust
// In run(), after building state:
if state.api_key.is_none() {
    let bind_public = true; // or detect from addr
    if bind_public {
        tracing::warn!("VERIFIER_API_KEY not set; verifier API is unauthenticated");
        // Optional: return Err(anyhow::anyhow!("VERIFIER_API_KEY required for production"))?
    }
}
```

---

## 6. MEDIUM: BLAKE3 trace chain — no genesis marker (truncation / log forgery)

- **Severity:** Medium  
- **Type:** Log integrity / chain truncation  
- **File & line:** `core/proxy/src/trace_log.rs` — `load_last_hash()`, `append()` (lines 36–53, 87–106)

**Description:**  
The trace chain uses `last_hash` derived from the previous line; the first entry uses an empty string as the previous hash. There is no dedicated “STRAND_GENESIS” or signed genesis event. An attacker with write access to the WAL file can truncate the file and then append new entries; the new chain will be valid from that point because `load_last_hash` will return the hash of the last line before truncation (or empty if the file is emptied), and new appends will chain from that. So the chain does not detect truncation or replacement of the beginning of the log.

**Exploit scenario:**

1. Attacker has filesystem access to the proxy’s trace WAL (e.g. container escape, compromised host, or exposed volume).
2. Truncates the WAL (or replaces it with a short, attacker-controlled prefix).
3. Proxy continues appending; new entries form a valid BLAKE3 chain from the new “head.”
4. Third-party auditors or tools that verify the chain from the beginning will see a broken or missing history; verification from the new head onward will pass.

**Impact:** Inability to prove full history; possible suppression of evidence (e.g. policy violations) by truncating the log.

**Fix:** (1) Optionally add a genesis entry at first use (e.g. a well-known “STRAND_GENESIS” event with a fixed structure and hash derivation) and reject verification if the first line is not genesis. (2) For high-assurance deployments, sign the genesis (or periodic checkpoints) with a key that the proxy does not have, or append to an append-only store that enforces ordering and prevents truncation.

---

## 7. MEDIUM: Certificate cache and forge rate limit — per-resolver clone

- **Severity:** Medium (low if clone is rare)  
- **Type:** Rate-limit bypass / resource exhaustion  
- **File & line:** `core/proxy/src/certs.rs` — `DynamicCertResolver::clone()` (lines 125–135)

**Description:**  
`DynamicCertResolver` uses a shared `LruCache` and a shared `ca`, but `forge_count` and `last_reset` are not shared: `clone()` creates `AtomicU64::new(0)` and `Mutex::new(None)`. If multiple clones of the resolver are used (e.g. per-connection or per-request), each has its own forge rate limit, so the intended 100 forges per 60 seconds can be multiplied by the number of clones. The cache (512 entries) is still shared, so memory is bounded, but CPU and key generation could be stressed.

**Exploit scenario:**

1. Code path creates many clones of `DynamicCertResolver` (e.g. one per CONNECT tunnel).
2. Each clone has its own `forge_count`; an attacker triggers many CONNECTs to distinct hostnames.
3. Effective forge rate becomes 100 × number_of_clones per 60 seconds, increasing load and potentially bypassing the intended rate limit.

**Impact:** Higher than intended certificate generation rate; possible CPU exhaustion; rate limit effectively bypassed if clones are numerous.

**Fix:** Share `forge_count` and `last_reset` across clones (e.g. `Arc<AtomicU64>` and `Arc<Mutex<Option<Instant>>>`) so all clones share the same rate limit. Keep the cache and CA as they are.

---

## 8. LOW: Rego policy evaluation — no explicit recursion / evaluation cap

- **Severity:** Low  
- **Type:** ReDoS / policy engine DoS  
- **File & line:** `core/proxy/src/payload_policy.rs` and `core/proxy/src/response_policy.rs` (Rego evaluation, e.g. lines 52–94, 114–152)

**Description:**  
Payload and response policy evaluation passes attacker-controlled (or upstream-controlled) JSON (method, path, host, body, headers) into the Rego engine. The regorus engine may have internal limits, but there is no explicit recursion depth limit or evaluation timeout in the Catenar code. A malicious body with deeply nested structures or a policy that uses regexes on that input could cause long evaluation (ReDoS) or high CPU.

**Exploit scenario:**

1. Attacker sends a request with a very deep or regex-unfriendly JSON body (or triggers a response that is then fed to response policy).
2. Rego policy (or default rules) perform recursion or regex over the input.
3. Evaluation takes seconds or more, tying up the semaphore (64 concurrent evaluations) and causing latency or DoS.

**Impact:** Policy evaluation DoS; increased latency for other requests.

**Fix:** Add an evaluation timeout (e.g. 100–500 ms) around `engine.evaluate()` (e.g. with `tokio::time::timeout`) and return “policy evaluation failed” or deny on timeout. Optionally enforce a maximum JSON depth when building Rego input.

---

## 9. LOW: Panic in trace logger on poisoned mutex

- **Severity:** Low  
- **Type:** Panic / reliability  
- **File & line:** `core/proxy/src/trace_log.rs` — `append()` (line 36)

**Description:**  
The code uses `self.inner.lock().unwrap_or_else(|e| e.into_inner())`, so a poisoned mutex is recovered by consuming the poison. That is correct and does not panic. No change required for this item; included only for completeness. If any other `.unwrap()` were used on the same lock, it could panic under poison.

**Recommendation:** Audit all uses of `TraceLoggerInner`’s mutex and ensure no `.unwrap()` can panic on poison; prefer `unwrap_or_else(|e| e.into_inner())` or explicit handling.

---

## 10. AI / business logic: Swarm lineage and parent_task_id

- **Severity:** Informational / design  
- **Type:** Trust model / spoofing  
- **File & line:** Dashboard and SDKs that accept or display `parent_task_id` / trace context (e.g. dashboard receipt listing, SDK `set_parent_task_id`).

**Description:**  
If `parent_task_id` or trace context are taken from client-supplied headers or agent-supplied data without cryptographic binding to a prior receipt, a malicious agent can forge lineage by sending arbitrary `parent_task_id` values. The dashboard and verifier should treat lineage as advisory unless it is bound to signed receipts or a verifiable chain.

**Recommendation:** Document that lineage is best-effort unless backed by receipt signatures or verifier-issued tokens. For high-assurance deployments, bind parent-child relationships in signed receipts (e.g. parent receipt id signed by verifier and included in child’s proof).

---

## Summary table

| # | Severity  | Type                     | Location                          |
|---|-----------|--------------------------|-----------------------------------|
| 1 | Critical  | Unbounded response body  | intercept.rs (non-CONNECT handle) |
| 2 | High      | Host header injection     | intercept.rs `absolute_uri`        |
| 3 | High      | Unbounded policy POST     | intercept.rs `handle_policy_post` |
| 4 | High      | WAL full read             | trace_log.rs `load_last_hash`      |
| 5 | Medium    | Verifier API no auth      | verifier lib.rs                   |
| 6 | Medium    | Chain truncation          | trace_log.rs                      |
| 7 | Medium    | Cert resolver clone rate  | certs.rs                          |
| 8 | Low       | Rego evaluation DoS       | payload_policy.rs                 |
| 9 | Low       | Mutex poison (no panic)   | trace_log.rs                      |
| 10| Info      | Lineage spoofing          | Design / docs                     |

---

## Remediation status (2025-03)

All 10 findings remediated per multi-agent sprint:

- **1–3:** Capped response body (stream + MAX_RESPONSE_BYTES), Host sanitization in `absolute_uri`, 256 KB limit on policy POST.
- **4, 6, 9:** Tail-read in `load_last_hash` (64 KB), truncation doc comment, mutex poison handling confirmed.
- **5:** Startup warn when API key unset; `VERIFIER_REQUIRE_API_KEY=1` for strict mode.
- **7:** Shared `Arc` for `forge_count` and `last_reset` in DynamicCertResolver clones.
- **8:** 500 ms timeout around payload/response policy evaluation via `spawn_blocking`.
- **10:** [docs/security/trust-model.md](trust-model.md) documents lineage trust and VERIFIER_API_KEY.

---

## Positive findings

- **Webhook signature (dashboard):** `alerts/ingest` uses `timingSafeEqual` and validates HMAC; body size limited to 16 KB.
- **Verifier API key comparison:** Uses `constant_time_eq` on BLAKE3 hashes of API keys.
- **Identity:** Proxy does not trust client-supplied identity headers for policy; `get_identity()` returns empty in open core.
- **Request body limits:** MITM path uses `MAX_BODY_BYTES` (5 MB) and `MAX_RESPONSE_BYTES` (10 MB) with streaming.
- **CA/certs:** LRU cache size (512) and forge rate (100/min) bound certificate generation; BYO-CA supported.
- **Dashboard receipts GET:** Requires session; policy GET/POST require session and (for reload) admin role.

---

*End of audit.*
