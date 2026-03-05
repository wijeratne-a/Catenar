use std::{net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc};

use rustls::ServerConfig;

use anyhow::{Context, Result};
use chrono::Utc;
use http::{
    header::{HOST, HeaderValue},
    Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, info_span, warn};

use crate::trace_log::TraceLogger;

/// HTTP/1.x method prefixes. If the decrypted stream doesn't start with one of these, it's not HTTP.
const HTTP_METHOD_PREFIXES: &[&[u8]] = &[
    b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS ", b"TRACE ", b"PATCH ",
];

fn looks_like_http(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    HTTP_METHOD_PREFIXES
        .iter()
        .any(|prefix| buf.len() >= prefix.len() && buf.starts_with(prefix))
}

/// Wraps a stream to prepend bytes for read while forwarding writes. Used after HTTP protocol peek.
struct PrependReader<R> {
    prepended: Option<Cursor<Vec<u8>>>,
    inner: R,
}

impl<R> PrependReader<R> {
    fn new(prepended: Vec<u8>, inner: R) -> Self {
        Self {
            prepended: Some(Cursor::new(prepended)),
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrependReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(ref mut cursor) = self.prepended {
            let unfilled = buf.initialize_unfilled();
            match std::io::Read::read(cursor, unfilled) {
                Ok(0) => {
                    self.prepended = None;
                    return AsyncRead::poll_read(std::pin::Pin::new(&mut self.inner), cx, buf);
                }
                Ok(n) => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
        AsyncRead::poll_read(std::pin::Pin::new(&mut self.inner), cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrependReader<R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.inner), cx)
    }
}

fn is_internal_or_private(authority: &str) -> bool {
    let host = authority.split(':').next().unwrap_or(authority).trim();
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
        return match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_unicast_link_local(),
        };
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceMode {
    Strict,
    AuditOnly,
}

impl EnforceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::AuditOnly => "audit_only",
        }
    }
}

impl FromStr for EnforceMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "audit_only" => Ok(Self::AuditOnly),
            _ => anyhow::bail!("unknown ENFORCE_MODE value: {value}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub enforce_mode: EnforceMode,
    pub verifier_url: String,
    pub policy: PolicyConfig,
    /// When true, return 200 with semantic error body instead of 403/4xx. Prevents LLM retry loops.
    pub semantic_deny: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub restricted_endpoints: Vec<String>,
}

/// Max HTTP request body size (5 MB) for MITM payload parsing.
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Max HTTP response body size (10 MB) when relaying from upstream.
const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct IdentityContext {
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub iam_role: Option<String>,
}

/// Input shape for Rego payload policy evaluation (A2T/A2D/A2A).
#[derive(Debug, Clone, Serialize)]
pub struct PayloadRegoInput {
    pub method: String,
    pub path: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<JsonValue>,
    pub headers: std::collections::HashMap<String, String>,
    pub identity: IdentityContext,
}

#[derive(Debug, Clone, Serialize)]
struct ProxyTraceLogEntry {
    timestamp_ns: i64,
    method: String,
    target: String,
    blocked: bool,
    enforce_mode: String,
    enforcement: String,
    identity: IdentityContext,
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ProxyConfig>,
    pub logger: TraceLogger,
    pub client: reqwest::Client,
    pub mitm_server_config: Arc<ServerConfig>,
    pub payload_engine: Option<Arc<crate::payload_policy::PayloadPolicyEngine>>,
    pub schema_registry: Option<Arc<crate::schema_validator::SchemaRegistry>>,
    /// Root CA PEM for GET /ca (loopback only). Used for agent trust setup.
    pub ca_pem: Option<String>,
}

pub type ProxyBody = Full<bytes::Bytes>;

fn response_with(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(body.to_owned())))
        .unwrap_or_else(|_| response_500())
}

fn response_500() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(r#"{"error":"internal error"}"#)))
        .expect("fallback 500 response must succeed")
}

/// Returns a block response: either 200 with semantic body (for LLM agents) or 403/4xx (for programmatic clients).
/// When semantic_deny is true, LLMs can "read" the block and stop retrying.
fn block_response(
    config: &ProxyConfig,
    status_when_strict: StatusCode,
    reason: &str,
    message_override: Option<&str>,
) -> Response<ProxyBody> {
    let message: String = message_override
        .map(String::from)
        .unwrap_or_else(|| format!("Aegis Security Block: {}. Do not retry.", reason));
    if config.semantic_deny {
        let body = serde_json::json!({
            "status": "error",
            "aegis_block": true,
            "message": message,
            "reason": reason
        });
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("X-Aegis-Blocked", "true")
            .body(Full::new(bytes::Bytes::from(
                serde_json::to_string(&body).unwrap_or_else(|_| r#"{"status":"error","aegis_block":true}"#.to_string()),
            )))
            .unwrap_or_else(|_| response_500())
    } else {
        Response::builder()
            .status(status_when_strict)
            .header("content-type", "application/json")
            .header("X-Aegis-Blocked", "true")
            .body(Full::new(bytes::Bytes::from(
                serde_json::to_string(&serde_json::json!({
                    "error": "policy violation",
                    "reason": reason
                }))
                .unwrap_or_else(|_| r#"{"error":"policy violation"}"#.to_string()),
            )))
            .unwrap_or_else(|_| response_500())
    }
}

fn is_json_content_type(headers: &http::HeaderMap<HeaderValue>) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim().to_lowercase().starts_with("application/json"))
        .unwrap_or(false)
}

fn headers_to_map(headers: &http::HeaderMap<HeaderValue>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    map
}

fn get_identity(headers: &http::HeaderMap<HeaderValue>) -> IdentityContext {
    let header_to_string = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    IdentityContext {
        session_id: header_to_string("x-aegis-session-id"),
        user_id: header_to_string("x-aegis-user-id"),
        iam_role: header_to_string("x-aegis-iam-role"),
    }
}

fn should_block(target: &str, policy: &PolicyConfig) -> bool {
    policy
        .restricted_endpoints
        .iter()
        .any(|blocked| !blocked.is_empty() && target.contains(blocked))
}

pub async fn handle(
    state: ProxyState,
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
) -> Result<Response<ProxyBody>> {
    let method = req.method().clone();

    if method == Method::GET {
        let path = req.uri().path();
        if path == "/healthz" {
            let verifier_health = format!(
                "{}/healthz",
                state.config.verifier_url.trim_end_matches('/')
            );
            let healthy = state.client.get(verifier_health).send().await;
            if healthy.as_ref().map(|r| r.status().is_success()).unwrap_or(false) {
                return Ok(response_with(StatusCode::OK, r#"{"status":"ok"}"#));
            }
            return Ok(response_with(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"status":"degraded"}"#,
            ));
        }
        if (path == "/ca" || path == "/.well-known/ca.crt")
            && state.ca_pem.is_some()
            && remote_addr.ip().is_loopback()
        {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-pem-file")
                .body(Full::new(bytes::Bytes::from(
                    state.ca_pem.as_ref().unwrap().clone(),
                )))
                .unwrap_or_else(|_| response_500()));
        }
    }

    if method == Method::CONNECT {
        return handle_connect(state, req, remote_addr).await;
    }

    let identity = get_identity(req.headers());
    req.headers_mut().remove("x-aegis-session-id");
    req.headers_mut().remove("x-aegis-user-id");
    req.headers_mut().remove("x-aegis-iam-role");

    let target_uri = absolute_uri(req.uri(), req.headers())
        .context("failed to resolve absolute URI for proxy request")?;
    let target = target_uri.to_string();
    let target_host = target_uri.host().unwrap_or_default().to_string();
    let blocked = should_block(&target, &state.config.policy);
    let enforce_mode = state.config.enforce_mode;
    let request_span = info_span!(
        "aegis.proxy.request",
        method = %method,
        target_host = %target_host,
        blocked = blocked,
        enforce_mode = enforce_mode.as_str()
    );
    let _request_guard = request_span.enter();

    let enforcement = if blocked && enforce_mode == EnforceMode::AuditOnly {
        "audit_only_bypass"
    } else if blocked {
        "blocked"
    } else {
        "allowed"
    };

    let trace_entry = ProxyTraceLogEntry {
        timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        method: method.as_str().to_string(),
        target: target.clone(),
        blocked,
        enforce_mode: enforce_mode.as_str().to_string(),
        enforcement: enforcement.to_string(),
        identity: identity.clone(),
    };
    let logger = state.logger.clone();
    let entry = trace_entry.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(err) = logger.append(&entry) {
            warn!("failed writing proxy trace log: {err}");
        }
    });

    if blocked && enforce_mode == EnforceMode::Strict {
        warn!("strict mode blocked request target={target}");
        return Ok(block_response(
            &state.config,
            StatusCode::BAD_GATEWAY,
            "blocked by policy in strict mode",
            None,
        ));
    }
    if blocked {
        warn!("audit_only policy violation target={target}");
    }

    let forward_headers = req.headers().clone();
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("failed reading request body")?
        .to_bytes();

    let mut forward = state.client.request(method.clone(), target_uri.to_string());
    for (name, value) in &forward_headers {
        if name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        forward = forward.header(name, value);
    }
    forward = forward.body(body_bytes.clone());

    let upstream = match forward.send().await {
        Ok(res) => res,
        Err(err) => {
            if err.is_timeout() {
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Aegis: Upstream request timed out. Do not retry."),
                ));
            }
            error!("proxy forward failed: {err}");
            if enforce_mode == EnforceMode::AuditOnly {
                return Ok(response_with(
                    StatusCode::BAD_GATEWAY,
                    r#"{"warning":"upstream error in audit_only mode"}"#,
                ));
            }
            return Ok(response_with(
                StatusCode::BAD_GATEWAY,
                r#"{"error":"failed to forward request"}"#,
            ));
        }
    };

    let status = upstream.status();
    let mut resp_builder = Response::builder().status(status);
    for (name, value) in upstream.headers() {
        resp_builder = resp_builder.header(name, value);
    }
    let response_body = match upstream.bytes().await {
        Ok(b) => b,
        Err(err) => {
            if err.is_timeout() {
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Aegis: Upstream request timed out. Do not retry."),
                ));
            }
            return Err(err.into());
        }
    };
    let resp = resp_builder
        .body(Full::new(response_body))
        .unwrap_or_else(|_| response_500());
    info!(
        method = method.as_str(),
        target = target,
        blocked,
        enforce_mode = enforce_mode.as_str(),
        remote = %remote_addr,
        "proxied request"
    );
    Ok(resp)
}

fn absolute_uri(uri: &Uri, headers: &http::HeaderMap<HeaderValue>) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }

    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .context("missing host header")?;

    let path_q = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let joined = format!("http://{host}{path_q}");
    joined
        .parse::<Uri>()
        .with_context(|| format!("invalid absolute URI: {joined}"))
}

async fn handle_connect(
    state: ProxyState,
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
) -> Result<Response<ProxyBody>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .context("CONNECT missing authority host:port")?;
    if is_internal_or_private(&authority) {
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "CONNECT to internal targets forbidden",
            None,
        ));
    }
    info!(target = authority, remote = %remote_addr, "connect tunnel requested");
    let on_upgrade = hyper::upgrade::on(&mut req);

    tokio::spawn(async move {
        if let Err(err) = run_mitm_tunnel(state, on_upgrade, authority).await {
            error!("CONNECT MITM tunnel error: {err}");
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(bytes::Bytes::new()))
        .unwrap_or_else(|_| response_500()))
}

async fn run_mitm_tunnel(
    state: ProxyState,
    on_upgrade: hyper::upgrade::OnUpgrade,
    authority: String,
) -> Result<()> {
    let upgraded = on_upgrade.await.context("upgrade failed")?;
    let io = TokioIo::new(upgraded);
    let acceptor = TlsAcceptor::from(Arc::clone(&state.mitm_server_config));
    let mut tls_stream = acceptor
        .accept(io)
        .await
        .context("TLS handshake failed")?;

    let mut peek_buf = [0u8; 8];
    let n = tls_stream
        .read(&mut peek_buf)
        .await
        .context("failed to peek CONNECT tunnel")?;
    if n == 0 {
        return Err(anyhow::anyhow!("CONNECT tunnel closed by client before data"));
    }
    let peeked = peek_buf[..n].to_vec();
    if !looks_like_http(&peeked) {
        return Err(anyhow::anyhow!(
            "Non-HTTP protocol detected on CONNECT tunnel to {}; Aegis V1 supports HTTP/HTTPS only",
            authority
        ));
    }
    let io = TokioIo::new(PrependReader::new(peeked, tls_stream));

    let authority_clone = authority.clone();
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let authority = authority_clone.clone();
        async move {
            Ok::<_, hyper::Error>(
                handle_mitm_request(state, authority, req)
                    .await
                    .unwrap_or_else(|_| response_500()),
            )
        }
    });

    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades();

    conn.await.context("MITM connection error")?;
    Ok(())
}

async fn handle_mitm_request(
    state: ProxyState,
    authority: String,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Box<dyn std::error::Error + Send + Sync>> {
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let path_q = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let host = authority.split(':').next().unwrap_or(&authority).to_string();

    let limited_body = Limited::new(body, MAX_BODY_BYTES);
    let collected = match limited_body.collect().await {
        Ok(c) => c,
        Err(e) => {
            if e.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(block_response(
                    &state.config,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds 5MB limit",
                    Some("Aegis Security Block: Payload too large. Reduce request body size. Do not retry."),
                ));
            }
            return Err(e.into());
        }
    };
    let body_bytes = collected.to_bytes();

    let body_json: Option<JsonValue> = if is_json_content_type(&parts.headers) && !body_bytes.is_empty() {
        serde_json::from_slice(&body_bytes).ok()
    } else {
        None
    };

    let identity = get_identity(&parts.headers);
    let headers_map = headers_to_map(&parts.headers);

    if let Some(ref registry) = state.schema_registry {
        if let Some(ref body_val) = body_json {
            if let Err(validation_errors) = registry.validate(&host, method.as_str(), path_q, body_val) {
                let reason = validation_errors.join("; ");
                let msg = format!(
                    "Aegis Schema Validation Failed: {}. Do not retry with same payload.",
                    reason
                );
                return Ok(block_response(&state.config, StatusCode::BAD_REQUEST, &reason, Some(&msg)));
            }
        }
    }

    let rego_input = PayloadRegoInput {
        method: method.as_str().to_string(),
        path: path_q.to_string(),
        host: host.clone(),
        body: body_json,
        headers: headers_map,
        identity: identity.clone(),
    };

    if let Some(ref engine) = state.payload_engine {
        match engine.evaluate(&rego_input) {
            Ok(decision) if !decision.allow => {
                let reason = decision.reason.unwrap_or_else(|| "policy violation".to_string());
                return Ok(block_response(
                    &state.config,
                    StatusCode::FORBIDDEN,
                    &reason,
                    None,
                ));
            }
            Err(e) => {
                tracing::warn!("payload policy evaluation error: {e}");
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(Full::new(bytes::Bytes::from(
                        r#"{"error":"policy evaluation failed"}"#,
                    )))
                    .unwrap_or_else(|_| response_500()));
            }
            _ => {}
        }
    }

    let target_url = format!("https://{authority}{path_q}");
    let mut headers = parts.headers.clone();
    headers.remove("proxy-connection");
    headers.remove("Proxy-Connection");

    let trace_hash = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(method.as_str().as_bytes());
        hasher.update(path_q.as_bytes());
        hasher.update(host.as_bytes());
        hasher.update(&body_bytes);
        hasher.update(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes().as_slice());
        format!("0x{}", hasher.finalize().to_hex())
    };
    headers.insert(
        "x-aegis-trace",
        http::HeaderValue::from_str(&trace_hash).unwrap_or_else(|_| http::HeaderValue::from_static("invalid")),
    );
    if let Some(ref c) = identity.user_id {
        if let Ok(v) = http::HeaderValue::from_str(c) {
            let _ = headers.insert("x-aegis-caller", v);
        }
    } else if let Some(ref s) = identity.session_id {
        if let Ok(v) = http::HeaderValue::from_str(s) {
            let _ = headers.insert("x-aegis-caller", v);
        }
    }

    let upstream_res = match state
        .client
        .request(method, &target_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            if err.is_timeout() {
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Aegis: Upstream request timed out. Do not retry."),
                ));
            }
            return Err(err.into());
        }
    };

    let status = upstream_res.status();
    let headers = upstream_res.headers().clone();
    if upstream_res.content_length().unwrap_or(0) > MAX_RESPONSE_BYTES {
        return Ok(block_response(
            &state.config,
            StatusCode::BAD_GATEWAY,
            "upstream response too large",
            Some("Aegis: Upstream response exceeds size limit. Do not retry."),
        ));
    }
    let mut body_stream = upstream_res.bytes_stream();
    let mut total: u64 = 0;
    let mut body_buf = bytes::BytesMut::new();
    while let Some(chunk_res) = body_stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(err) => {
                if err.is_timeout() {
                    return Ok(block_response(
                        &state.config,
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream timeout",
                        Some("Aegis: Upstream request timed out. Do not retry."),
                    ));
                }
                return Err(err.into());
            }
        };
        total += chunk.len() as u64;
        if total > MAX_RESPONSE_BYTES {
            return Ok(block_response(
                &state.config,
                StatusCode::BAD_GATEWAY,
                "upstream response too large",
                Some("Aegis: Upstream response exceeds size limit. Do not retry."),
            ));
        }
        body_buf.extend_from_slice(&chunk);
    }
    let body_bytes = body_buf.freeze();

    let mut resp_builder = Response::builder().status(status);
    for (name, value) in &headers {
        resp_builder = resp_builder.header(name.as_str(), value.clone());
    }
    let resp = resp_builder
        .body(Full::new(body_bytes))
        .unwrap_or_else(|_| response_500());
    Ok(resp)
}
