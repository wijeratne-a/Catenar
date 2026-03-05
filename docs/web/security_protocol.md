# Aegis Security & Authentication Protocol

## 1. Authentication & Token Management
- **Mechanism**: Use JWT (JSON Web Tokens) for session management.
- **Secure Storage**: 
  - **Access Tokens**: Store in-memory (JS state).
  - **Refresh Tokens**: Store in `HttpOnly`, `Secure`, `SameSite=Strict` cookies. This prevents XSS attacks from accessing the session.
- **CSRF Protection**: Implement Anti-CSRF tokens for any state-changing `POST` requests.

## 2. API Protection (Gateway Layer)
- **Rate Limiting**: Implement a "sliding window" rate limiter (e.g., Upstash or Redis) to limit users to X verifications per minute.
- **Payload Validation**: 
  - Strictly enforce the `VerifyRequestModel` schema from `aegis_sdk.py`.
  - Max Payload Size: Reject any JSON body larger than 1MB to prevent DoS attacks.
- **CORS Policy**: Restrict `Access-Control-Allow-Origin` to only the specific production domain of the Aegis Playground.

## 3. Code & Trace Protection
- **Sanitization**: Before sending traces to the Rust API, the SDK/Frontend must scrub common PII patterns (emails, passwords) unless explicitly part of the test case.
- **Input Filtering**: Use Zod to sanitize all strings in the "Policy Builder" to prevent injection attacks into the Rust `engine.rs` logic.
- **Environment Secrets**: API keys for the demo environment must be managed via `process.env` and never exposed in client-side bundles.

## 4. Rust Backend Integration
- **Auth Middleware**: Update `verifier/src/main.rs` to include an `AuthLayer` that validates the JWT from the cookie/header before calling `verify_trace`.
- **Request ID**: Attach a unique UUID to every verification request to allow for end-to-end audit logging between the frontend and the Rust backend.


## 5. Architectural Boundaries (Crucial for Context)
- **The Data Plane (`proxy/`, `verifier/`)**: Completely stateless network-layer firewall. Inspects outbound agent traffic (Agent-to-Tool, Agent-to-Database). Written in Rust.
- **The Control Plane (`web/`)**: Next.js dashboard used by CISOs to manage policies and view cryptographic receipts. 
- **The Agent SDK (`agent/`)**: Lightweight Python wrapper used *only* to inject the Proxy Root CA and Context Headers (`X-Aegis-Session`).

---

## 6. Proxy & Network Security (The Data Plane)

### 6.1 TLS Termination & MITM (`certs.rs` / `intercept.rs`)
- **Mechanism**: The proxy intercepts HTTP `CONNECT` methods and uses `rcgen` to dynamically forge leaf certificates signed by a local, ephemeral Root CA.
- **Protocol Constraint**: Aegis V1 **only supports Layer-7 HTTP/HTTPS traffic** (REST/GraphQL). 
- **Rule**: If an AI agent attempts to use L4 TCP wire protocols (e.g., native `psycopg2` for Postgres), the proxy must fail-closed or explicitly reject the connection. Do not attempt to parse raw DB wire protocols yet.

### 6.2 The Dual-Gate Validation Pipeline
When buffering and parsing decrypted JSON payloads in the proxy, code must execute in this exact order:
1. **Positive Validation (Shape)**: `schema_validator.rs` uses JSON Schema to ensure the payload matches the expected OpenAPI spec. (Prevents LLM Hallucination poisoning).
2. **Negative Validation (Semantic)**: `payload_policy.rs` uses Open Policy Agent (Rego) to check for business logic violations (e.g., PII leaks, unauthorized roles).

### 6.3 Cryptographic Provenance (Proof of Task)
- **Hashing**: Use `BLAKE3` for all trace logs. The hash payload MUST include: `[Human_Session_ID + Agent_Role + Tool_Target + Request_Payload + Timestamp]`.
- **Signing**: Traces must be signed using Ed25519 (`keys.rs`). 
- **Rule**: The private key must NEVER be hardcoded. It must be loaded via secure environment variables (`AEGIS_SIGNING_KEY`) or Kubernetes Secrets.

---

## 7. Edge Case Handling & Agent Deadlocks (Cursor Directives)

### 7.1 The "Retry Loop" Deadlock (CRITICAL)
- **Context**: ReAct/LangChain agents interpret standard HTTP `4xx/5xx` errors as temporary network failures and will retry the same malicious payload infinitely, draining tokens.
- **Cursor Rule**: When implementing blocked requests in `intercept.rs`, **DO NOT** return a standard HTTP `403 Forbidden` with a text body. 
- **Implementation**: Intercept the block and return an HTTP `200 OK` (or the tool's expected error schema) containing a semantic conversational error: 
  ```json
  { "status": "error", "message": "Aegis Security Block: Payload violates Enterprise PII policy. Do not retry this action." }