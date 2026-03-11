use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, net::SocketAddr, sync::Arc};

use dashmap::DashMap;

use anyhow::{Context, Result};
use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tracing::{error, info};

mod certs;
mod intercept;
mod payload_policy;
mod schema_validator;
pub mod telemetry;
mod trace_log;
mod webhook;

use certs::{build_mitm_server_config, RootCa};
use intercept::{
    EnforceMode, HeartbeatLogEntry, LivePolicy, PolicyConfig, ProxyConfig, ProxyState,
};
use trace_log::TraceLogger;

fn env_var_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_var_true(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

fn build_http_client(upstream_timeout_secs: u64) -> Result<reqwest::Client> {
    let connect_timeout = std::time::Duration::from_secs(3);
    let read_timeout = std::time::Duration::from_secs(
        std::env::var("UPSTREAM_READ_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s >= 1 && s <= 60)
            .unwrap_or(5),
    );
    let mut builder = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(read_timeout)
        .timeout(std::time::Duration::from_secs(upstream_timeout_secs));

    if let Some(ca_path) = env_var_non_empty("VERIFIER_TLS_CA_PATH") {
        let ca_pem = fs::read(&ca_path)
            .with_context(|| format!("failed to read verifier CA cert from {ca_path}"))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .with_context(|| format!("invalid PEM CA cert in {ca_path}"))?;
        builder = builder.add_root_certificate(ca_cert);
    }

    let cert_path = env_var_non_empty("VERIFIER_TLS_CERT_PATH");
    let key_path = env_var_non_empty("VERIFIER_TLS_KEY_PATH");
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = fs::read(&cert_path)
                .with_context(|| format!("failed to read verifier client cert from {cert_path}"))?;
            let key_pem = fs::read(&key_path)
                .with_context(|| format!("failed to read verifier client key from {key_path}"))?;
            let mut identity_pem = cert_pem;
            if !identity_pem.ends_with(b"\n") {
                identity_pem.push(b'\n');
            }
            identity_pem.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&identity_pem).with_context(|| {
                format!("failed to parse verifier client identity from {cert_path} and {key_path}")
            })?;
            builder = builder.identity(identity);
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "VERIFIER_TLS_CERT_PATH and VERIFIER_TLS_KEY_PATH must both be set for mTLS"
            );
        }
        (None, None) => {}
    }

    builder.build().context("failed to build reqwest client")
}

fn read_policy(path: &str) -> Result<PolicyConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid policy JSON in {path}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");
    telemetry::init_telemetry()?;

    let policy_path = std::env::var("POLICY_PATH").unwrap_or_else(|_| "policy.json".to_string());
    let enforce_mode = std::env::var("ENFORCE_MODE")
        .unwrap_or_else(|_| "strict".to_string())
        .parse::<EnforceMode>()?;
    let verifier_url =
        std::env::var("VERIFIER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let bind = std::env::var("PROXY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let trace_wal =
        std::env::var("TRACE_WAL_PATH").unwrap_or_else(|_| "./data/proxy-trace.jsonl".to_string());
    let semantic_deny = std::env::var("SEMANTIC_DENY")
        .map(|v| v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("1"))
        .unwrap_or(true);
    let webhook_url = std::env::var("WEBHOOK_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let webhook_secret = std::env::var("WEBHOOK_SECRET")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let metrics_enabled = env_var_true("METRICS_ENABLED");
    let policy_debug = env_var_true("POLICY_DEBUG");
    telemetry::set_metrics_enabled(metrics_enabled);

    let upstream_timeout_secs = std::env::var("UPSTREAM_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s >= 1 && s <= 300)
        .unwrap_or_else(|| {
            if std::env::var("UPSTREAM_TIMEOUT_SECS").is_ok() {
                error!("UPSTREAM_TIMEOUT_SECS invalid (must be 1-300); using 10");
            }
            10
        });

    let policy = read_policy(&policy_path).unwrap_or_else(|err| {
        error!(
            "failed to load policy from {}: {}; defaulting empty",
            policy_path, err
        );
        PolicyConfig::default()
    });

    let root_ca = match (
        std::env::var("CATENAR_CA_CERT_PATH"),
        std::env::var("CATENAR_CA_KEY_PATH"),
    ) {
        (Ok(cert_path), Ok(key_path)) => {
            let cert_pem = fs::read_to_string(&cert_path)
                .with_context(|| format!("failed to read CA cert from {cert_path}"))?;
            let key_pem = fs::read_to_string(&key_path)
                .with_context(|| format!("failed to read CA key from {key_path}"))?;
            RootCa::from_pem(&cert_pem, &key_pem)?
        }
        _ => RootCa::generate()?,
    };
    let ca_pem = root_ca.export_pem();
    if let Ok(ca_path) = std::env::var("CATENAR_CA_PATH") {
        if let Some(parent) = std::path::Path::new(&ca_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&ca_path, &ca_pem)?;
        info!("Root CA written to {}", ca_path);
    }

    let mitm_server_config = build_mitm_server_config(root_ca)?;

    let payload_engine =
        std::env::var("POLICY_REGO_PATH").unwrap_or_else(|_| "policies/payload.rego".to_string());
    let payload_engine = payload_policy::PayloadPolicyEngine::load_from_path(&payload_engine)
        .map(Arc::new)
        .ok();
    let response_policy_engine = std::env::var("POLICY_RESPONSE_REGO_PATH")
        .unwrap_or_else(|_| "policies/response.rego".to_string());
    let response_policy_engine =
        payload_policy::ResponsePolicyEngine::load_from_path(&response_policy_engine)
            .map(Arc::new)
            .ok();

    let schema_registry = std::env::var("SCHEMA_REGISTRY_PATH").ok().or_else(|| {
        std::env::var("SCHEMA_DIR")
            .ok()
            .map(|d| format!("{}/registry.json", d))
    });
    let schema_registry = schema_registry
        .as_ref()
        .and_then(|p| {
            schema_validator::SchemaRegistry::load_from_path(p)
                .ok()
                .flatten()
        })
        .map(Arc::new);

    if schema_registry.is_some() {
        info!("Schema registry loaded for request body validation");
    }

    let live_policy = Arc::new(std::sync::RwLock::new(LivePolicy {
        config: policy.clone(),
        payload_engine: payload_engine.clone(),
    }));

    let policy_api_key = std::env::var("PROXY_POLICY_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let state = ProxyState {
        config: Arc::new(ProxyConfig {
            enforce_mode,
            verifier_url,
            policy,
            semantic_deny,
            metrics_enabled,
            policy_debug,
            policy_api_key,
        }),
        webhook: webhook_url.zip(webhook_secret).and_then(|(url, secret)| {
            if secret.len() < 32 {
                error!("WEBHOOK_SECRET must be at least 32 characters; webhook disabled");
                None
            } else {
                Some(webhook::WebhookConfig { url, secret })
            }
        }),
        logger: TraceLogger::new(&trace_wal)?,
        client: build_http_client(upstream_timeout_secs)?,
        mitm_server_config,
        payload_engine,
        response_policy_engine,
        schema_registry,
        ca_pem: Some(ca_pem),
        live_policy,
        rate_limit: Arc::new(DashMap::new()),
        degraded_mode: Arc::new(AtomicBool::new(false)),
    };

    let degraded_mode = state.degraded_mode.clone();
    let verifier_url = state.config.verifier_url.clone();
    let client = state.client.clone();
    let logger = state.logger.clone();
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        const FAILURE_THRESHOLD: u32 = 3;
        const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            let health_url = format!("{}/healthz", verifier_url.trim_end_matches('/'));
            let healthy = client.get(&health_url).send().await;
            let ok = healthy
                .as_ref()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                if degraded_mode.load(Ordering::Relaxed) {
                    degraded_mode.store(false, Ordering::Relaxed);
                    tracing::info!("Verifier recovered. Exiting degraded mode.");
                }
                consecutive_failures = 0;
            } else {
                consecutive_failures += 1;
                if consecutive_failures >= FAILURE_THRESHOLD
                    && !degraded_mode.load(Ordering::Relaxed)
                {
                    degraded_mode.store(true, Ordering::Relaxed);
                    tracing::warn!("Verifier unreachable. Entering degraded mode (Audit-Only).");
                }
                if degraded_mode.load(Ordering::Relaxed) {
                    let entry = HeartbeatLogEntry {
                        timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                        action: "heartbeat".to_string(),
                        target: "catenar-proxy-degraded".to_string(),
                        status: "degraded".to_string(),
                    };
                    if let Err(e) = logger.append(&entry) {
                        tracing::warn!("failed to write degraded heartbeat: {}", e);
                    }
                }
            }
        }
    });

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid PROXY_BIND address {bind}"))?;
    let listener = TcpListener::bind(addr).await?;
    info!("catenar-proxy listening on http://{addr}");

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
                            let body = if state.config.enforce_mode == EnforceMode::AuditOnly
                                || state.degraded_mode.load(Ordering::Relaxed)
                            {
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

            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection_with_upgrades(io, svc)
                .await
            {
                error!("connection error: {err}");
            }
        });
    }
}
