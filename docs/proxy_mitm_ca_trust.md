# Aegis Proxy MITM and CA Trust

The Aegis proxy terminates TLS on CONNECT requests to inspect decrypted HTTP payloads for policy evaluation. Agents must trust the proxy's Root CA or they will see `CERTIFICATE_VERIFY_FAILED` when making HTTPS requests through the proxy.

## Environment Setup

### Proxy Configuration

```bash
export HTTP_PROXY=http://aegis-proxy:8080
export HTTPS_PROXY=http://aegis-proxy:8080
```

### Root CA Trust

The proxy generates a self-signed Root CA at startup. Configure your runtime to trust it:

**Python** (requests, aiohttp, httpx):
```bash
export REQUESTS_CA_BUNDLE=/etc/aegis/ca.crt
# or for aiohttp/httpx:
export SSL_CERT_FILE=/etc/aegis/ca.crt
```

**Node.js**:
```bash
export NODE_EXTRA_CA_CERTS=/etc/aegis/ca.crt
```

**Docker / Kubernetes**: Set `AEGIS_CA_PATH=/etc/aegis/ca.crt` when starting the proxy so it writes the CA to that path. Mount a volume or ConfigMap so the agent container can read it.

### Local development (Docker)

With `docker compose up`, the proxy writes the CA to `deploy/certs/ca.crt` on the host. From the repo root, set:

- **Python**: `export REQUESTS_CA_BUNDLE=./deploy/certs/ca.crt`
- **Node.js**: `export NODE_EXTRA_CA_CERTS=./deploy/certs/ca.crt`

### Local development (non-Docker)

When running the proxy locally (e.g. `cargo run`), fetch the CA from the loopback-only endpoint: `curl http://127.0.0.1:8080/ca -o ca.crt`, then set the appropriate env var to the path of the fetched file.

## CA Export Path

- **`AEGIS_CA_PATH`**: If set at proxy startup, the proxy writes the Root CA PEM to this path (e.g. `/etc/aegis/ca.crt`). The orchestrator can mount this into the agent container.
- **`GET /ca`** and **`GET /.well-known/ca.crt`**: Serve the CA PEM when the request comes from loopback (127.0.0.1). Use for local development or operators who can `curl http://127.0.0.1:8080/ca` from the proxy host.

## Without CA Trust

If agents do not set the CA bundle, HTTPS requests through the proxy will fail with certificate verification errors. Plain HTTP requests (sent via the proxy without CONNECT) are unaffected.

## Protocol Scope (V1)

Aegis V1 supports **HTTP/1.1 only**. The proxy performs TLS MITM and inspects HTTP/1.1 traffic only. Clients using HTTP/2 inside the CONNECT tunnel will receive "Non-HTTP/1.1 protocol detected" and the connection will fail. HTTP/2 support is planned for a future release.

**WebSocket:** The WebSocket handshake (HTTP GET with `Upgrade: websocket`) is detected and allowed. The proxy logs "WebSocket upgrade detected" when present. Handshake and 101 responses are forwarded. Post-handshake frame tunneling (bidirectional copy) is in progress; binary frame inspection (packet-by-packet Rego evaluation) is an Enterprise feature.

CONNECT tunnels carrying non-HTTP protocols (e.g. PostgreSQL wire, Redis, raw TCP) are rejected with a clear error. Database clients that use native wire protocols must not be routed through the Aegis proxy.

Upstream requests (both plain HTTP forward and MITM CONNECT) are bounded by `UPSTREAM_TIMEOUT_SECS` to prevent hung APIs from blocking the proxy.
