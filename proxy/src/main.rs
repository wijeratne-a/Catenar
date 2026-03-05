use std::{fs, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use hyper::{
    body::Incoming,
    server::conn::http1,
    service::service_fn,
    Request,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

mod intercept;
mod trace_log;

use intercept::{EnforceMode, PolicyConfig, ProxyConfig, ProxyState};
use trace_log::TraceLogger;

fn init_logging() {
    let json_logs = std::env::var("AEGIS_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = fmt().with_env_filter(filter);
    if json_logs {
        builder.json().init();
    } else {
        builder.init();
    }
}

fn read_policy(path: &str) -> Result<PolicyConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid policy JSON in {path}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let policy_path = std::env::var("POLICY_PATH").unwrap_or_else(|_| "policy.json".to_string());
    let enforce_mode = std::env::var("ENFORCE_MODE")
        .unwrap_or_else(|_| "strict".to_string())
        .parse::<EnforceMode>()?;
    let verifier_url =
        std::env::var("VERIFIER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let bind = std::env::var("PROXY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let trace_wal =
        std::env::var("TRACE_WAL_PATH").unwrap_or_else(|_| "./data/proxy-trace.jsonl".to_string());

    let policy = read_policy(&policy_path).unwrap_or_else(|err| {
        error!("failed to load policy from {}: {}; defaulting empty", policy_path, err);
        PolicyConfig::default()
    });

    let state = ProxyState {
        config: Arc::new(ProxyConfig {
            enforce_mode,
            verifier_url,
            policy,
        }),
        logger: TraceLogger::new(&trace_wal)?,
        client: reqwest::Client::new(),
    };

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid PROXY_BIND address {bind}"))?;
    let listener = TcpListener::bind(addr).await?;
    info!("aegis-proxy listening on http://{addr}");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    let resp = match intercept::handle(state.clone(), req, remote_addr).await {
                        Ok(resp) => resp,
                        Err(err) => {
                            error!("proxy request handling error: {err}");
                            let body = if state.config.enforce_mode == EnforceMode::AuditOnly {
                                r#"{"warning":"proxy error in audit_only mode"}"#
                            } else {
                                r#"{"error":"proxy failure in strict mode"}"#
                            };
                            hyper::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                                .unwrap_or_else(|_| {
                                    hyper::Response::builder()
                                        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(http_body_util::Full::new(bytes::Bytes::from(
                                            r#"{"error":"internal error"}"#,
                                        )))
                                        .expect("fallback 500 must succeed")
                                })
                        }
                    };
                    Ok::<_, hyper::Error>(resp)
                }
            });

            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!("connection error: {err}");
            }
        });
    }
}
