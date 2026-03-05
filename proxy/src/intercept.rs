use std::{net::{IpAddr, SocketAddr}, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use chrono::Utc;
use http::{
    header::{HOST, HeaderValue},
    Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::{io::copy_bidirectional, net::TcpStream};
use tracing::{error, info, info_span, warn};

use crate::trace_log::TraceLogger;

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
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub restricted_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityContext {
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub iam_role: Option<String>,
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

    if method == Method::GET && req.uri().path() == "/healthz" {
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

    if method == Method::CONNECT {
        return handle_connect(req, remote_addr).await;
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
        return Ok(response_with(
            StatusCode::BAD_GATEWAY,
            r#"{"error":"blocked by policy in strict mode"}"#,
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
    let response_body = upstream.bytes().await.context("failed reading upstream body")?;
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
    mut req: Request<Incoming>,
    remote_addr: SocketAddr,
) -> Result<Response<ProxyBody>> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .context("CONNECT missing authority host:port")?;
    if is_internal_or_private(&authority) {
        return Ok(response_with(
            StatusCode::FORBIDDEN,
            r#"{"error":"CONNECT to internal targets forbidden"}"#,
        ));
    }
    info!(target = authority, remote = %remote_addr, "connect tunnel requested");
    let on_upgrade = hyper::upgrade::on(&mut req);

    tokio::spawn(async move {
        if let Err(err) = tunnel(on_upgrade, authority).await {
            error!("CONNECT tunnel error: {err}");
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(bytes::Bytes::new()))
        .unwrap_or_else(|_| response_500()))
}

async fn tunnel(on_upgrade: OnUpgrade, authority: String) -> Result<()> {
    let mut upgraded = TokioIo::new(on_upgrade.await.context("upgrade failed")?);
    let mut server = TcpStream::connect(&authority)
        .await
        .with_context(|| format!("failed to connect tunnel target {authority}"))?;
    let _ = copy_bidirectional(&mut upgraded, &mut server)
        .await
        .context("tunnel copy failed")?;
    Ok(())
}
