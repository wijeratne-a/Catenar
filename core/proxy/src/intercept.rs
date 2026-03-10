use std::cell::Cell;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, RwLock},
};

use dashmap::DashMap;

use rustls::ServerConfig;

use anyhow::{Context, Result};
use chrono::Utc;
use futures_util::StreamExt;
use http::{
    header::{HeaderValue, HOST},
    Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, info_span, warn};
use uuid::Uuid;

use crate::telemetry;
use crate::trace_log::TraceLogger;
use crate::webhook::{self, WebhookEvent};

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: u32 = 60;

/// HTTP/1.x method prefixes. If the decrypted stream doesn't start with one of these, it's not HTTP.
const HTTP_METHOD_PREFIXES: &[&[u8]] = &[
    b"GET ",
    b"HEAD ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"CONNECT ",
    b"OPTIONS ",
    b"TRACE ",
    b"PATCH ",
];

fn looks_like_http(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    HTTP_METHOD_PREFIXES
        .iter()
        .any(|prefix| buf.len() >= prefix.len() && buf.starts_with(prefix))
}

/// Detects WebSocket upgrade request (HTTP GET with Upgrade: websocket in headers).
fn looks_like_websocket_upgrade(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let s = match std::str::from_utf8(buf) {
        Ok(x) => x.to_lowercase(),
        Err(_) => return false,
    };
    s.contains("upgrade:") && s.contains("websocket")
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

/// Rejects values containing bytes < 0x20 or 0x7f (control chars). Returns true if safe to use in headers.
fn sanitize_header_value(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Returns true if remote_addr is allowed to access policy management endpoints (GET/POST /policy).
fn is_policy_management_allowed(remote_addr: &SocketAddr) -> bool {
    if remote_addr.ip().is_loopback() {
        return true;
    }
    if std::env::var("POLICY_MANAGEMENT_FROM_DASHBOARD")
        .map(|v| v.trim().eq_ignore_ascii_case("1") || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        if let IpAddr::V4(v4) = remote_addr.ip() {
            return v4.is_private();
        }
    }
    if let Ok(networks) = std::env::var("POLICY_MANAGEMENT_ALLOW_NETWORKS") {
        let ip = remote_addr.ip();
        for cidr in networks.split(',') {
            let cidr = cidr.trim();
            if cidr.is_empty() {
                continue;
            }
            if cidr_contains(cidr, ip) {
                return true;
            }
        }
    }
    false
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((addr_str, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let prefix: u8 = match prefix.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let cidr_ip: IpAddr = match addr_str.trim().parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    match (cidr_ip, ip) {
        (IpAddr::V4(c), IpAddr::V4(i)) => {
            let mask = !0u32 << (32 - prefix.min(32));
            (u32::from_be_bytes(c.octets()) & mask) == (u32::from_be_bytes(i.octets()) & mask)
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => false,
        _ => false,
    }
}

/// When CATENAR_DEMO_EVIL_PORT or CATENAR_STRESS_MOCK_PORT is set, allow 127.0.0.1:{port} for local demo/mock.
fn is_demo_evil_host_allowed(authority: &str) -> bool {
    for env_key in ["CATENAR_DEMO_EVIL_PORT", "CATENAR_STRESS_MOCK_PORT"] {
        if let Ok(port) = std::env::var(env_key) {
            let port = port.trim();
            if !port.is_empty() && authority == format!("127.0.0.1:{}", port) {
                return true;
            }
        }
    }
    false
}

fn is_internal_or_private(authority: &str) -> bool {
    if is_demo_evil_host_allowed(authority) {
        return false;
    }
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

/// Returns true if any resolved IP for the host is loopback, private, or link-local (SSRF unsafe).
/// Uses tokio::net::lookup_host for async DNS resolution. Fails closed on resolution errors.
async fn host_resolves_to_unsafe_ip(host_or_authority: &str) -> Result<bool> {
    let host = host_or_authority
        .split(':')
        .next()
        .unwrap_or(host_or_authority)
        .trim();
    // Demo bypass: when CATENAR_DEMO_EVIL_PORT or CATENAR_STRESS_MOCK_PORT is set, allow 127.0.0.1 for local demo/mock
    if host == "127.0.0.1"
        && (std::env::var("CATENAR_DEMO_EVIL_PORT")
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false)
            || std::env::var("CATENAR_STRESS_MOCK_PORT")
                .map(|p| !p.trim().is_empty())
                .unwrap_or(false))
    {
        return Ok(false);
    }
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".local") {
        return Ok(true);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let unsafe_ip = ip.is_loopback()
            || match ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_unicast_link_local(),
            };
        return Ok(unsafe_ip);
    }
    let addrs = match tokio::net::lookup_host(format!("{host}:443")).await {
        Ok(iter) => iter.collect::<Vec<_>>(),
        Err(_) => return Ok(true), // fail closed: block on resolution failure
    };
    if addrs.is_empty() {
        return Ok(true); // no addresses = treat as unsafe
    }
    let any_unsafe = addrs.iter().any(|addr| {
        let ip = addr.ip();
        ip.is_loopback()
            || match ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_unicast_link_local(),
            }
    });
    Ok(any_unsafe)
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
    pub metrics_enabled: bool,
    pub policy_debug: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Input shape for Rego response policy evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseRegoInput {
    pub method: String,
    pub path: String,
    pub host: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

/// Heartbeat entry written to trace WAL during degraded mode to maintain BLAKE3 chain continuity.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatLogEntry {
    pub timestamp_ns: i64,
    pub action: String,
    pub target: String,
    pub status: String,
}

/// Sanitized trace log entry for writing to disk; omits PII (session_id, user_id, iam_role).
#[derive(Debug, Clone, Serialize)]
struct ProxyTraceLogEntrySanitized {
    timestamp_ns: i64,
    request_id: String,
    method: String,
    target: String,
    blocked: bool,
    enforce_mode: String,
    enforcement: String,
    has_identity: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_debug_reason: Option<String>,
}

struct RequestLatencyGuard {
    started_at: Instant,
}

impl RequestLatencyGuard {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Drop for RequestLatencyGuard {
    fn drop(&mut self) {
        telemetry::observe_latency_ms(self.started_at.elapsed().as_secs_f64() * 1000.0);
    }
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ProxyConfig>,
    pub webhook: Option<crate::webhook::WebhookConfig>,
    pub logger: TraceLogger,
    pub client: reqwest::Client,
    pub mitm_server_config: Arc<ServerConfig>,
    pub payload_engine: Option<Arc<crate::payload_policy::PayloadPolicyEngine>>,
    pub response_policy_engine: Option<Arc<crate::payload_policy::ResponsePolicyEngine>>,
    pub schema_registry: Option<Arc<crate::schema_validator::SchemaRegistry>>,
    /// Root CA PEM for GET /ca (loopback only). Used for agent trust setup.
    pub ca_pem: Option<String>,
    /// Mutable policy state for hot-reload. Holds (PolicyConfig, Option<PayloadPolicyEngine>).
    pub live_policy: Arc<RwLock<LivePolicy>>,
    /// Per-IP rate limit: (window_start, count).
    pub rate_limit: Arc<DashMap<String, (Instant, u32)>>,
    /// When true, verifier is unreachable; proxy operates in Audit-Only mode and writes heartbeats.
    pub degraded_mode: Arc<AtomicBool>,
}

pub struct LivePolicy {
    pub config: PolicyConfig,
    pub payload_engine: Option<Arc<crate::payload_policy::PayloadPolicyEngine>>,
}

pub type ProxyBody = Full<bytes::Bytes>;

fn generate_request_id() -> String {
    Uuid::new_v4().to_string()
}

fn redact_query_from_target(target: &str) -> String {
    target
        .parse::<Uri>()
        .ok()
        .and_then(|uri| {
            let scheme = uri.scheme_str()?;
            let authority = uri.authority()?.as_str();
            let path = uri.path();
            Some(format!("{scheme}://{authority}{path}"))
        })
        .unwrap_or_else(|| {
            target
                .split_once('?')
                .map(|(prefix, _)| prefix.to_string())
                .unwrap_or_else(|| target.to_string())
        })
}

fn insert_request_id_header(headers: &mut http::HeaderMap<HeaderValue>, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("X-Catenar-Request-Id", value);
    }
}

fn append_trace_entry(
    state: &ProxyState,
    request_id: String,
    method: &Method,
    target: &str,
    blocked: bool,
    enforcement: &str,
    has_identity: bool,
    policy_debug_reason: Option<&str>,
) {
    let trace_entry = ProxyTraceLogEntrySanitized {
        timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        request_id,
        method: method.as_str().to_string(),
        target: redact_query_from_target(target),
        blocked,
        enforce_mode: state.config.enforce_mode.as_str().to_string(),
        enforcement: enforcement.to_string(),
        has_identity,
        policy_debug_reason: if state.config.policy_debug {
            policy_debug_reason.map(|r| r.to_string())
        } else {
            None
        },
    };
    let logger = state.logger.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(err) = logger.append(&trace_entry) {
            warn!("failed writing proxy trace log: {err}");
        }
    });
}

fn emit_webhook_event(state: &ProxyState, event: WebhookEvent) {
    if let Some(config) = state.webhook.clone() {
        let client = state.client.clone();
        tokio::spawn(async move {
            webhook::emit(&client, &config, &event).await;
        });
    }
}

fn response_with(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(body.to_owned())))
        .unwrap_or_else(|e| {
            tracing::error!("response builder failed, returning 500: {:?}", e);
            response_500()
        })
}

fn response_500() -> Response<ProxyBody> {
    tracing::error!("returning generic 500 internal error");
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(
            r#"{"error":"internal error"}"#,
        )))
        .expect("fallback 500 response must succeed")
}

/// Returns a block response: either 200 with semantic body (for LLM agents) or 403/4xx (for programmatic clients).
/// When semantic_deny is true, LLMs can "read" the block and stop retrying.
fn block_response(
    config: &ProxyConfig,
    status_when_strict: StatusCode,
    reason: &str,
    message_override: Option<&str>,
    suggestion: Option<&str>,
) -> Response<ProxyBody> {
    let message: String = message_override
        .map(String::from)
        .unwrap_or_else(|| format!("CATENAR SECURITY BLOCK: {}. Do not retry.", reason));
    if config.semantic_deny {
        let mut body = serde_json::json!({
            "status": "error",
            "catenar_block": true,
            "message": message,
            "reason": reason
        });
        if let Some(s) = suggestion {
            body["suggestion"] = serde_json::json!(s);
        }
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("X-Catenar-Blocked", "true")
            .body(Full::new(bytes::Bytes::from(
                serde_json::to_string(&body)
                    .unwrap_or_else(|_| r#"{"status":"error","catenar_block":true}"#.to_string()),
            )))
            .unwrap_or_else(|e| {
                tracing::error!("block_response semantic body build failed: {:?}", e);
                response_500()
            })
    } else {
        Response::builder()
            .status(status_when_strict)
            .header("content-type", "application/json")
            .header("X-Catenar-Blocked", "true")
            .body(Full::new(bytes::Bytes::from(
                serde_json::to_string(&serde_json::json!({
                    "error": "policy violation",
                    "reason": reason
                }))
                .unwrap_or_else(|_| r#"{"error":"policy violation"}"#.to_string()),
            )))
            .unwrap_or_else(|e| {
                tracing::error!("block_response strict body build failed: {:?}", e);
                response_500()
            })
    }
}

fn is_json_content_type(headers: &http::HeaderMap<HeaderValue>) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim().to_lowercase().starts_with("application/json"))
        .unwrap_or(false)
}

fn headers_to_map(
    headers: &http::HeaderMap<HeaderValue>,
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            map.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    map
}

/// Returns empty identity. Identity must come from a verified token in future implementation.
/// Client-supplied headers are untrusted and would allow policy bypass - do not read them.
fn get_identity(_headers: &http::HeaderMap<HeaderValue>) -> IdentityContext {
    IdentityContext {
        session_id: None,
        user_id: None,
        iam_role: None,
    }
}

fn should_block(target_host: &str, policy: &PolicyConfig) -> bool {
    let host_lower = target_host.to_ascii_lowercase();
    policy.restricted_endpoints.iter().any(|blocked| {
        if blocked.is_empty() {
            return false;
        }
        let blocked_lower = blocked.to_ascii_lowercase();
        host_lower == blocked_lower || host_lower.ends_with(&format!(".{}", blocked_lower))
    })
}

fn classify_violation(reason: &str) -> telemetry::ViolationType {
    let reason_lc = reason.to_ascii_lowercase();
    if reason_lc.contains("schema") {
        telemetry::ViolationType::SchemaValidation
    } else if reason_lc.contains("response injection")
        || reason_lc.contains("response_injection")
        || reason_lc.contains("responseinjection")
    {
        telemetry::ViolationType::ResponseInjection
    } else if reason_lc.contains("ssn") || reason_lc.contains("sensitive") {
        telemetry::ViolationType::SensitiveDataExposure
    } else if reason_lc.contains("readonly")
        || reason_lc.contains("read-only")
        || reason_lc.contains("delete mutation")
    {
        telemetry::ViolationType::UnauthorizedDataMutation
    } else if reason_lc.contains("x-catenar-trace") || reason_lc.contains("audit") {
        telemetry::ViolationType::MissingAuditTrace
    } else {
        telemetry::ViolationType::PolicyViolation
    }
}

fn check_rate_limit(state: &ProxyState, remote_addr: &SocketAddr) -> bool {
    let key = remote_addr.to_string();
    let now = Instant::now();
    let exceeded = Cell::new(false);
    state
        .rate_limit
        .entry(key.clone())
        .and_modify(|(window_start, count)| {
            if now.duration_since(*window_start) > RATE_LIMIT_WINDOW {
                *window_start = now;
                *count = 1;
            } else {
                *count = count.saturating_add(1);
                if *count > RATE_LIMIT_MAX {
                    exceeded.set(true);
                }
            }
        })
        .or_insert((now, 1));
    !exceeded.get()
}

pub async fn handle(
    state: ProxyState,
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
) -> Result<Response<ProxyBody>> {
    if !check_rate_limit(&state, &remote_addr) {
        return Ok(block_response(
            &state.config,
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
            Some("Catenar Security Block: Rate limit exceeded. Do not retry."),
            None,
        ));
    }

    let method = req.method().clone();

    if method == Method::GET {
        let path = req.uri().path();
        if path == "/metrics" {
            if !state.config.metrics_enabled {
                return Ok(response_with(
                    StatusCode::NOT_FOUND,
                    r#"{"error":"not found"}"#,
                ));
            }
            if state.config.enforce_mode == EnforceMode::Strict && !remote_addr.ip().is_loopback() {
                return Ok(response_with(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"metrics endpoint requires loopback in strict mode"}"#,
                ));
            }
            let body = telemetry::render_prometheus_text().unwrap_or_default();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(bytes::Bytes::from(body)))
                .unwrap_or_else(|e| {
                    tracing::error!("ca response body build failed: {:?}", e);
                    response_500()
                }));
        }
        if path == "/healthz" {
            let verifier_health = format!(
                "{}/healthz",
                state.config.verifier_url.trim_end_matches('/')
            );
            let healthy = state.client.get(verifier_health).send().await;
            if healthy
                .as_ref()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                return Ok(response_with(StatusCode::OK, r#"{"status":"ok"}"#));
            }
            return Ok(response_with(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"status":"degraded"}"#,
            ));
        }
        if (path == "/ca" || path == "/.well-known/ca.crt") && remote_addr.ip().is_loopback() {
            if let Some(ca) = state.ca_pem.as_ref() {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/x-pem-file")
                    .body(Full::new(bytes::Bytes::from(ca.clone())))
                    .unwrap_or_else(|e| {
                        tracing::error!("ca cert response build failed: {:?}", e);
                        response_500()
                    }));
            }
        }
        if path == "/policy/current" && is_policy_management_allowed(&remote_addr) {
            let live = match state.live_policy.read() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("RwLock poisoned for live_policy: {}", e);
                    return Ok(response_with(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"policy state unavailable"}"#,
                    ));
                }
            };
            let raw = serde_json::to_vec(&live.config).unwrap_or_default();
            let policy_hash = format!("0x{}", blake3::hash(&raw).to_hex());
            let body = serde_json::json!({
                "policy_hash": policy_hash,
                "has_rego_engine": live.payload_engine.is_some(),
            });
            return Ok(response_with(StatusCode::OK, &body.to_string()));
        }
        if path == "/policy" && is_policy_management_allowed(&remote_addr) {
            return handle_policy_get(state).await;
        }
    }

    if method == Method::POST && req.uri().path() == "/policy" && is_policy_management_allowed(&remote_addr) {
        return handle_policy_post(state, req).await;
    }

    if method == Method::POST
        && req.uri().path() == "/policy/reload"
        && is_policy_management_allowed(&remote_addr)
    {
        return handle_policy_reload(state).await;
    }

    if method == Method::CONNECT {
        return handle_connect(state, req, remote_addr).await;
    }

    let identity = get_identity(req.headers());
    req.headers_mut().remove("x-catenar-session-id");
    req.headers_mut().remove("x-catenar-user-id");
    req.headers_mut().remove("x-catenar-iam-role");

    let target_uri = absolute_uri(req.uri(), req.headers())
        .context("failed to resolve absolute URI for proxy request")?;
    let authority = target_uri
        .authority()
        .map(|a| a.as_str())
        .unwrap_or_default();
    if is_internal_or_private(authority) {
        let request_id = generate_request_id();
        let target = target_uri.to_string();
        append_trace_entry(
            &state,
            request_id.clone(),
            &method,
            &target,
            true,
            "blocked",
            false,
            Some("forwarding to internal or private targets is forbidden"),
        );
        telemetry::increment_blocked(authority, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id,
                method.as_str(),
                target,
                "forwarding to internal or private targets is forbidden",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "forwarding to internal or private targets is forbidden",
            None,
            None,
        ));
    }
    if host_resolves_to_unsafe_ip(authority).await.unwrap_or(true) {
        let request_id = generate_request_id();
        let target = target_uri.to_string();
        append_trace_entry(
            &state,
            request_id.clone(),
            &method,
            &target,
            true,
            "blocked",
            false,
            Some("forwarding to internal or private targets is forbidden (DNS SSRF)"),
        );
        telemetry::increment_blocked(authority, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id,
                method.as_str(),
                target,
                "forwarding to internal or private targets is forbidden (DNS SSRF)",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "forwarding to internal or private targets is forbidden",
            None,
            None,
        ));
    }
    let target = target_uri.to_string();
    let target_host = target_uri.host().unwrap_or_default().to_string();
    let _latency_guard = RequestLatencyGuard::new();
    telemetry::increment_request(&target_host);
    let blocked = {
        let policy = match state.live_policy.read() {
            Ok(guard) => guard.config.clone(),
            Err(e) => {
                error!("RwLock poisoned for live_policy: {}", e);
                state.config.policy.clone()
            }
        };
        should_block(&target_host, &policy)
    };
    let enforce_mode = if state
        .degraded_mode
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        EnforceMode::AuditOnly
    } else {
        state.config.enforce_mode
    };
    let request_id = generate_request_id();
    let request_span = info_span!(
        "catenar.proxy.request",
        method = %method,
        target_host = %target_host,
        catenar.request_id = %request_id,
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

    let has_identity = identity
        .session_id
        .as_ref()
        .or(identity.user_id.as_ref())
        .or(identity.iam_role.as_ref())
        .is_some();
    append_trace_entry(
        &state,
        request_id.clone(),
        &method,
        &target,
        blocked,
        enforcement,
        has_identity,
        if blocked {
            Some("blocked by policy target rule")
        } else {
            None
        },
    );

    if blocked && enforce_mode == EnforceMode::Strict {
        warn!("strict mode blocked request target={target}");
        telemetry::increment_blocked(&target_host, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id,
                method.as_str(),
                target.clone(),
                "blocked by policy in strict mode",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::BAD_GATEWAY,
            "blocked by policy in strict mode",
            None,
            None,
        ));
    }
    if blocked {
        warn!("audit_only policy violation target={target}");
        telemetry::increment_blocked(&target_host, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id.clone(),
                method.as_str(),
                target.clone(),
                "audit_only policy violation",
            ),
        );
    }

    let forward_headers = req.headers().clone();
    let (_, body) = req.into_parts();
    let limited_body = Limited::new(body, MAX_BODY_BYTES);
    let collected = match limited_body.collect().await {
        Ok(c) => c,
        Err(e) => {
            if e.downcast_ref::<LengthLimitError>().is_some() {
                return Ok(block_response(
                    &state.config,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds 5MB limit",
                    Some("Catenar Security Block: Payload too large. Reduce request body size. Do not retry."),
                    None,
                ));
            }
            return Err(anyhow::anyhow!("body collection failed: {}", e));
        }
    };
    let body_bytes = collected.to_bytes();

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
                telemetry::increment_timeout(&target_host);
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "upstream_timeout",
                        request_id.clone(),
                        method.as_str(),
                        target.clone(),
                        "upstream timeout",
                    ),
                );
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Catenar: Upstream request timed out. Do not retry."),
                    None,
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
    let headers = upstream.headers().clone();
    let mut resp_builder = Response::builder().status(status);
    for (name, value) in &headers {
        resp_builder = resp_builder.header(name.as_str(), value.clone());
    }
    let response_body = match upstream.bytes().await {
        Ok(b) => b,
        Err(err) => {
            if err.is_timeout() {
                telemetry::increment_timeout(&target_host);
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "upstream_timeout",
                        request_id.clone(),
                        method.as_str(),
                        target.clone(),
                        "upstream timeout",
                    ),
                );
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Catenar: Upstream request timed out. Do not retry."),
                    None,
                ));
            }
            return Err(err.into());
        }
    };

    if let Some(ref engine) = state.response_policy_engine {
        let path_q = target_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let response_input = ResponseRegoInput {
            method: method.as_str().to_string(),
            path: path_q.to_string(),
            host: target_host.clone(),
            status: status.as_u16(),
            body: std::str::from_utf8(&response_body)
                .ok()
                .map(|v| v.to_string()),
            headers: headers_to_map(&headers),
        };
        if let Ok(decision) = engine.evaluate(&response_input) {
            if !decision.allow {
                let reason = decision
                    .reason
                    .unwrap_or_else(|| "response policy violation".to_string());
                telemetry::increment_blocked(&target_host, classify_violation(&reason));
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target,
                    true,
                    "blocked",
                    has_identity,
                    Some(&reason),
                );
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "response_policy_block",
                        request_id.clone(),
                        method.as_str(),
                        target.clone(),
                        reason.clone(),
                    ),
                );
                let injection_override = if decision.response_injection.is_some() {
                    Some("CATENAR INTERCEPT: Malicious Prompt Injection detected in tool response.")
                } else {
                    None
                };
                return Ok(block_response(
                    &state.config,
                    StatusCode::BAD_GATEWAY,
                    &reason,
                    injection_override,
                    None,
                ));
            }
        }
    }

    let resp = resp_builder
        .body(Full::new(response_body))
        .unwrap_or_else(|e| {
            tracing::error!("forward response build failed: {:?}", e);
            response_500()
        });
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

async fn handle_policy_get(state: ProxyState) -> Result<Response<ProxyBody>> {
    let live = match state.live_policy.read() {
        Ok(guard) => guard,
        Err(e) => {
            error!("RwLock poisoned for live_policy: {}", e);
            return Ok(response_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"policy state unavailable"}"#,
            ));
        }
    };
    let body = serde_json::to_string(&live.config).unwrap_or_else(|_| r#"{"restricted_endpoints":[]}"#.to_string());
    Ok(response_with(StatusCode::OK, &body))
}

#[derive(Debug, Deserialize)]
struct PolicyUpdateBody {
    #[serde(default)]
    restricted_endpoints: Option<Vec<String>>,
}

async fn handle_policy_post(state: ProxyState, mut req: Request<Incoming>) -> Result<Response<ProxyBody>> {
    let body = req.body_mut();
    let bytes = body
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read body: {}", e))?
        .to_bytes();
    let update: PolicyUpdateBody = match serde_json::from_slice(&bytes) {
        Ok(u) => u,
        Err(e) => {
            return Ok(response_with(
                StatusCode::BAD_REQUEST,
                &format!(r#"{{"error":"invalid JSON: {}"}}"#, e),
            ));
        }
    };
    if let Some(restricted) = update.restricted_endpoints {
        let mut live = match state.live_policy.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("RwLock poisoned for live_policy: {}", e);
                return Ok(response_with(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"policy update failed"}"#,
                ));
            }
        };
        live.config.restricted_endpoints = restricted;
        info!("policy updated via API (restricted_endpoints)");
    }
    Ok(response_with(StatusCode::OK, r#"{"status":"ok"}"#))
}

async fn handle_policy_reload(state: ProxyState) -> Result<Response<ProxyBody>> {
    let policy_path = std::env::var("POLICY_PATH").unwrap_or_else(|_| "policy.json".to_string());
    let rego_path =
        std::env::var("POLICY_REGO_PATH").unwrap_or_else(|_| "policies/payload.rego".to_string());

    let raw = match std::fs::read_to_string(&policy_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to read policy file {}: {}", policy_path, e);
            return Ok(response_with(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"failed to read policy"}"#,
            ));
        }
    };

    let new_config: PolicyConfig = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("invalid policy JSON: {}", e);
            return Ok(response_with(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid policy JSON"}"#,
            ));
        }
    };

    let new_engine = crate::payload_policy::PayloadPolicyEngine::load_from_path(&rego_path)
        .map(Arc::new)
        .ok();

    {
        let mut live = match state.live_policy.write() {
            Ok(guard) => guard,
            Err(e) => {
                error!("RwLock poisoned for live_policy during reload: {}", e);
                return Ok(response_with(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":"policy reload failed"}"#,
                ));
            }
        };
        live.config = new_config;
        live.payload_engine = new_engine;
    }

    info!("policy reloaded from disk");
    Ok(response_with(StatusCode::OK, r#"{"status":"reloaded"}"#))
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
        let request_id = generate_request_id();
        let target = format!("https://{authority}");
        append_trace_entry(
            &state,
            request_id.clone(),
            &Method::CONNECT,
            &target,
            true,
            "blocked",
            false,
            Some("CONNECT to internal targets forbidden"),
        );
        telemetry::increment_blocked(&authority, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id,
                "CONNECT",
                target,
                "CONNECT to internal targets forbidden",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "CONNECT to internal targets forbidden",
            None,
            None,
        ));
    }
    let host = authority.split(':').next().unwrap_or(&authority);
    if host_resolves_to_unsafe_ip(host).await.unwrap_or(true) {
        let request_id = generate_request_id();
        let target = format!("https://{authority}");
        append_trace_entry(
            &state,
            request_id.clone(),
            &Method::CONNECT,
            &target,
            true,
            "blocked",
            false,
            Some("CONNECT to internal targets forbidden (DNS SSRF)"),
        );
        telemetry::increment_blocked(host, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id,
                "CONNECT",
                target,
                "CONNECT to internal targets forbidden (DNS SSRF)",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "CONNECT to internal targets forbidden",
            None,
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
        .unwrap_or_else(|e| {
            tracing::error!("empty error response build failed: {:?}", e);
            response_500()
        }))
}

async fn run_mitm_tunnel(
    state: ProxyState,
    on_upgrade: hyper::upgrade::OnUpgrade,
    authority: String,
) -> Result<()> {
    let upgraded = on_upgrade.await.context("upgrade failed")?;
    let io = TokioIo::new(upgraded);
    let acceptor = TlsAcceptor::from(Arc::clone(&state.mitm_server_config));
    let mut tls_stream = acceptor.accept(io).await.context("TLS handshake failed")?;

    let mut peek_buf = [0u8; 1024];
    let n = tls_stream
        .read(&mut peek_buf)
        .await
        .context("failed to peek CONNECT tunnel")?;
    if n == 0 {
        return Err(anyhow::anyhow!(
            "CONNECT tunnel closed by client before data"
        ));
    }
    let peeked = peek_buf[..n].to_vec();
    let is_websocket = looks_like_websocket_upgrade(&peeked);
    if is_websocket {
        info!(authority = %authority, "WebSocket upgrade detected; tunneling post-handshake");
    }
    if !looks_like_http(&peeked) && !is_websocket {
        return Err(anyhow::anyhow!(
            "Non-HTTP/1.1 protocol detected on CONNECT tunnel to {}; Catenar V1 supports HTTP/1.1 only (HTTP/2 not supported)",
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
                    .unwrap_or_else(|e| {
                        tracing::error!("handle_mitm_request failed, returning 500: {:?}", e);
                        response_500()
                    }),
            )
        }
    });

    let builder = auto::Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection_with_upgrades(io, svc);

    conn.await.map_err(|e| anyhow::anyhow!("MITM connection error: {e}"))?;
    Ok(())
}

async fn handle_mitm_request(
    state: ProxyState,
    authority: String,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Box<dyn std::error::Error + Send + Sync>> {
    let method = req.method().clone();
    let request_id = generate_request_id();
    let request_span = info_span!(
        "catenar.proxy.mitm_request",
        catenar.request_id = %request_id,
        method = %method,
        authority = %authority
    );
    let _request_guard = request_span.enter();
    let (parts, body) = req.into_parts();
    let path_q = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let host = authority
        .split(':')
        .next()
        .unwrap_or(&authority)
        .to_string();
    let _latency_guard = RequestLatencyGuard::new();

    telemetry::increment_request(&host);

    let limited_body = Limited::new(body, MAX_BODY_BYTES);
    let collected = match limited_body.collect().await {
        Ok(c) => c,
        Err(e) => {
            if e.downcast_ref::<LengthLimitError>().is_some() {
                let target_url = format!("https://{authority}{path_q}");
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target_url,
                    true,
                    "blocked",
                    false,
                    Some("request body exceeds 5MB limit"),
                );
                telemetry::increment_blocked(&host, telemetry::ViolationType::PolicyViolation);
                return Ok(block_response(
                    &state.config,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds 5MB limit",
                    Some("Catenar Security Block: Payload too large. Reduce request body size. Do not retry."),
                    None,
                ));
            }
            return Err(e);
        }
    };
    let body_bytes = collected.to_bytes();

    let body_json: Option<JsonValue> =
        if is_json_content_type(&parts.headers) && !body_bytes.is_empty() {
            serde_json::from_slice(&body_bytes).ok()
        } else {
            None
        };

    let identity = get_identity(&parts.headers);
    let has_identity = identity
        .session_id
        .as_ref()
        .or(identity.user_id.as_ref())
        .or(identity.iam_role.as_ref())
        .is_some();
    let headers_map = headers_to_map(&parts.headers);

    if let Some(ref registry) = state.schema_registry {
        if let Some(ref body_val) = body_json {
            if let Err(validation_errors) =
                registry.validate(&host, method.as_str(), path_q, body_val)
            {
                let reason = validation_errors.join("; ");
                let truncated = if reason.len() > 500 {
                    format!("{}...", &reason[..497])
                } else {
                    reason.to_string()
                };
                let msg = format!(
                    "Catenar Schema Validation Failed: {}. Do not retry with same payload.",
                    truncated
                );
                telemetry::increment_blocked(&host, telemetry::ViolationType::SchemaValidation);
                let target_url = format!("https://{authority}{path_q}");
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target_url,
                    true,
                    "blocked",
                    has_identity,
                    Some(&truncated),
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "schema_validation",
                        outcome = "blocked",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q,
                        reason = %truncated
                    );
                }
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "policy_block",
                        request_id.clone(),
                        method.as_str(),
                        target_url,
                        truncated.clone(),
                    ),
                );
                return Ok(block_response(
                    &state.config,
                    StatusCode::BAD_REQUEST,
                    &truncated,
                    Some(&msg),
                    None,
                ));
            }
            if state.config.policy_debug {
                debug!(
                    event = "policy_checkpoint",
                    checkpoint = "schema_validation",
                    outcome = "allowed",
                    request_id = %request_id,
                    method = %method,
                    host = %host,
                    path = %path_q
                );
            }
        } else if state.config.policy_debug {
            debug!(
                event = "policy_checkpoint",
                checkpoint = "schema_validation",
                outcome = "skipped",
                request_id = %request_id,
                method = %method,
                host = %host,
                path = %path_q,
                reason = "non_json_or_empty_body"
            );
        }
    } else if state.config.policy_debug {
        debug!(
            event = "policy_checkpoint",
            checkpoint = "schema_validation",
            outcome = "skipped",
            request_id = %request_id,
            method = %method,
            host = %host,
            path = %path_q,
            reason = "schema_registry_unavailable"
        );
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
        let policy_eval_started = Instant::now();
        match engine.evaluate(&rego_input) {
            Ok(decision) if !decision.allow => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                let reason = decision
                    .reason
                    .unwrap_or_else(|| "policy violation".to_string());
                let violation_source = decision.violation_type.as_deref().unwrap_or(&reason);
                telemetry::increment_blocked(&host, classify_violation(violation_source));
                let target_url = format!("https://{authority}{path_q}");
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target_url,
                    true,
                    "blocked",
                    has_identity,
                    Some(&reason),
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "payload_policy_decision",
                        outcome = "blocked",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q,
                        reason = %reason
                    );
                }
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "policy_block",
                        request_id.clone(),
                        method.as_str(),
                        target_url,
                        reason.clone(),
                    ),
                );
                return Ok(block_response(
                    &state.config,
                    StatusCode::FORBIDDEN,
                    &reason,
                    None,
                    decision.suggestion.as_deref(),
                ));
            }
            Err(e) => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "payload_policy_decision",
                        outcome = "error",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q,
                        reason = %e
                    );
                }
                tracing::warn!("payload policy evaluation error: {e}");
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(Full::new(bytes::Bytes::from(
                        r#"{"error":"policy evaluation failed"}"#,
                    )))
                    .unwrap_or_else(|e| {
                        tracing::error!("payload verification response build failed: {:?}", e);
                        response_500()
                    }));
            }
            _ => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "payload_policy_decision",
                        outcome = "allowed",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q
                    );
                }
            }
        }
    } else if state.config.policy_debug {
        debug!(
            event = "policy_checkpoint",
            checkpoint = "payload_policy_decision",
            outcome = "skipped",
            request_id = %request_id,
            method = %method,
            host = %host,
            path = %path_q,
            reason = "payload_engine_unavailable"
        );
    }

    let target_url = format!("https://{authority}{path_q}");
    let mut headers = parts.headers.clone();
    headers.remove("proxy-connection");
    headers.remove("Proxy-Connection");
    insert_request_id_header(&mut headers, &request_id);

    let trace_hash = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(method.as_str().as_bytes());
        hasher.update(path_q.as_bytes());
        hasher.update(host.as_bytes());
        hasher.update(&body_bytes);
        hasher.update(
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_le_bytes()
                .as_slice(),
        );
        format!("0x{}", hasher.finalize().to_hex())
    };
    headers.insert(
        "x-catenar-trace",
        http::HeaderValue::from_str(&trace_hash)
            .unwrap_or_else(|_| http::HeaderValue::from_static("invalid")),
    );
    if let Some(ref c) = identity.user_id {
        if sanitize_header_value(c) {
            if let Ok(v) = http::HeaderValue::from_str(c) {
                let _ = headers.insert("x-catenar-caller", v);
            }
        }
    } else if let Some(ref s) = identity.session_id {
        if sanitize_header_value(s) {
            if let Ok(v) = http::HeaderValue::from_str(s) {
                let _ = headers.insert("x-catenar-caller", v);
            }
        }
    }

    if host_resolves_to_unsafe_ip(&host).await.unwrap_or(true) {
        let target_url = format!("https://{authority}{path_q}");
        append_trace_entry(
            &state,
            request_id.clone(),
            &method,
            &target_url,
            true,
            "blocked",
            has_identity,
            Some("forwarding to internal or private targets is forbidden (DNS SSRF)"),
        );
        telemetry::increment_blocked(&host, telemetry::ViolationType::PolicyViolation);
        emit_webhook_event(
            &state,
            WebhookEvent::new(
                "policy_block",
                request_id.clone(),
                method.as_str(),
                target_url.clone(),
                "forwarding to internal or private targets is forbidden (DNS SSRF)",
            ),
        );
        return Ok(block_response(
            &state.config,
            StatusCode::FORBIDDEN,
            "forwarding to internal or private targets is forbidden",
            None,
            None,
        ));
    }

    let upstream_res = match state
        .client
        .request(method.clone(), &target_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            if err.is_timeout() {
                telemetry::increment_timeout(&host);
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target_url,
                    false,
                    "upstream_timeout",
                    has_identity,
                    Some("upstream timeout"),
                );
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "upstream_timeout",
                        request_id.clone(),
                        method.as_str(),
                        target_url.clone(),
                        "upstream timeout",
                    ),
                );
                return Ok(block_response(
                    &state.config,
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream timeout",
                    Some("Catenar: Upstream request timed out. Do not retry."),
                    None,
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
            Some("Catenar: Upstream response exceeds size limit. Do not retry."),
            None,
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
                    telemetry::increment_timeout(&host);
                    append_trace_entry(
                        &state,
                        request_id.clone(),
                        &method,
                        &target_url,
                        false,
                        "upstream_timeout",
                        has_identity,
                        Some("upstream timeout"),
                    );
                    emit_webhook_event(
                        &state,
                        WebhookEvent::new(
                            "upstream_timeout",
                            request_id.clone(),
                            method.as_str(),
                            target_url.clone(),
                            "upstream timeout",
                        ),
                    );
                    return Ok(block_response(
                        &state.config,
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream timeout",
                        Some("Catenar: Upstream request timed out. Do not retry."),
                        None,
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
                Some("Catenar: Upstream response exceeds size limit. Do not retry."),
                None,
            ));
        }
        body_buf.extend_from_slice(&chunk);
    }
    let body_bytes = body_buf.freeze();

    if let Some(ref engine) = state.response_policy_engine {
        let response_input = ResponseRegoInput {
            method: method.as_str().to_string(),
            path: path_q.to_string(),
            host: host.clone(),
            status: status.as_u16(),
            body: std::str::from_utf8(&body_bytes).ok().map(|v| v.to_string()),
            headers: headers_to_map(&headers),
        };
        let policy_eval_started = Instant::now();
        match engine.evaluate(&response_input) {
            Ok(decision) if !decision.allow => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                let reason = decision
                    .reason
                    .unwrap_or_else(|| "response policy violation".to_string());
                let metric_reason = decision
                    .response_injection
                    .clone()
                    .unwrap_or_else(|| reason.clone());
                telemetry::increment_blocked(&host, classify_violation(&metric_reason));
                append_trace_entry(
                    &state,
                    request_id.clone(),
                    &method,
                    &target_url,
                    true,
                    "blocked",
                    has_identity,
                    Some(&reason),
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "response_policy_decision",
                        outcome = "blocked",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q,
                        reason = %reason
                    );
                }
                emit_webhook_event(
                    &state,
                    WebhookEvent::new(
                        "response_policy_block",
                        request_id.clone(),
                        method.as_str(),
                        target_url.clone(),
                        reason.clone(),
                    ),
                );
                let deny_status = if decision.response_injection.is_some() {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::FORBIDDEN
                };
                let injection_override = if decision.response_injection.is_some() {
                    Some("CATENAR INTERCEPT: Malicious Prompt Injection detected in tool response.")
                } else {
                    None
                };
                return Ok(block_response(
                    &state.config,
                    deny_status,
                    &reason,
                    injection_override,
                    None,
                ));
            }
            Err(e) => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "response_policy_decision",
                        outcome = "error",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q,
                        reason = %e
                    );
                }
                tracing::warn!("response policy evaluation error: {e}");
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(Full::new(bytes::Bytes::from(
                        r#"{"error":"policy evaluation failed"}"#,
                    )))
                    .unwrap_or_else(|e| {
                        tracing::error!("response policy block build failed: {:?}", e);
                        response_500()
                    }));
            }
            _ => {
                telemetry::observe_policy_eval_ms(
                    policy_eval_started.elapsed().as_secs_f64() * 1000.0,
                );
                if state.config.policy_debug {
                    debug!(
                        event = "policy_checkpoint",
                        checkpoint = "response_policy_decision",
                        outcome = "allowed",
                        request_id = %request_id,
                        method = %method,
                        host = %host,
                        path = %path_q
                    );
                }
            }
        }
    } else if state.config.policy_debug {
        debug!(
            event = "policy_checkpoint",
            checkpoint = "response_policy_decision",
            outcome = "skipped",
            request_id = %request_id,
            method = %method,
            host = %host,
            path = %path_q,
            reason = "response_engine_unavailable"
        );
    }

    let mut resp_builder = Response::builder().status(status);
    for (name, value) in &headers {
        resp_builder = resp_builder.header(name.as_str(), value.clone());
    }
    let resp = resp_builder
        .body(Full::new(body_bytes))
        .unwrap_or_else(|e| {
            tracing::error!("final response body build failed: {:?}", e);
            response_500()
        });
    append_trace_entry(
        &state,
        request_id,
        &method,
        &target_url,
        false,
        "allowed",
        has_identity,
        None,
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::{generate_request_id, insert_request_id_header, redact_query_from_target};

    #[test]
    fn generated_request_id_is_uuid() {
        let id = generate_request_id();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn redacts_query_from_target_url() {
        let redacted =
            redact_query_from_target("https://api.example.com/v1/chat?token=secret&debug=true");
        assert_eq!(redacted, "https://api.example.com/v1/chat");
    }

    #[test]
    fn adds_request_id_header() {
        let mut headers = http::HeaderMap::new();
        insert_request_id_header(&mut headers, "abc-123");
        assert_eq!(
            headers
                .get("X-Catenar-Request-Id")
                .and_then(|v| v.to_str().ok()),
            Some("abc-123")
        );
    }
}
