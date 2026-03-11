//! Catenar Verifier API library. Run the server with `run(key_provider)`.

use std::{
    cell::Cell,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::{
    extract::connect_info::ConnectInfo,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use constant_time_eq::constant_time_eq;
use dashmap::DashMap;
use serde_json::Value;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

pub mod engine;
pub mod keys;
mod policy;
mod schema;
mod store;
mod telemetry;

use crate::engine::{
    issue_task_token, notify_policy_violation_if_configured, report_receipt_if_configured,
    verify_trace,
};
use crate::keys::KeyProvider;
use crate::policy::{build_policy_engine, PolicyEngine};
use crate::schema::{
    AgentRegistration, AgentRegistrationResponse, AgentTaskToken, RegisterResponse,
    VerifyRequest, VerifyResponse,
};
use crate::store::{build_agent_store, build_policy_store, AgentStore, PolicyStore};

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX: u32 = 60;
const DEFAULT_TASK_TOKEN_TTL_SECS: i64 = 300;
const DEFAULT_AGENT_ID: &str = "unknown-agent";
const DEFAULT_TASK_ID: &str = "unknown-task";

fn sanitize_log_message(msg: &str) -> String {
    let max_len = 200;
    let blacklist = ["token", "secret", "key", "password", "authorization"];
    let lower = msg.to_lowercase();
    let should_redact = blacklist.iter().any(|w| lower.contains(w));
    let trimmed = if msg.len() > max_len { &msg[..max_len] } else { msg };
    if should_redact {
        format!("[redacted: contains sensitive term] (len={})", msg.len())
    } else {
        format!("{}", trimmed)
    }
}

#[derive(Clone)]
struct AppState {
    policy_store: Arc<dyn PolicyStore>,
    agent_store: Arc<dyn AgentStore>,
    key_provider: Arc<dyn KeyProvider>,
    policy_engine: Arc<dyn PolicyEngine>,
    http_client: reqwest::Client,
    api_key: Option<String>,
    rate_limit: Arc<DashMap<String, (Instant, u32)>>,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let ref_id = uuid::Uuid::new_v4();
        tracing::error!(ref_id = %ref_id, error = %sanitize_log_message(&self.message), "internal error");
        let msg = format!("Internal error (ref: {})", ref_id);
        (
            self.status,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response()
    }
}

type AppResult<T> = Result<T, AppError>;

fn get_header_or_default(headers: &HeaderMap, name: &'static str, default: &'static str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default.to_string())
}

fn task_token_ttl_secs() -> i64 {
    std::env::var("TASK_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|s| *s > 0 && *s <= 86_400)
        .unwrap_or(DEFAULT_TASK_TOKEN_TTL_SECS)
}

async fn api_key_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ref expected) = state.api_key else {
        return next.run(request).await;
    };
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
    let Some(provided) = provided else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "API key required" })),
        )
            .into_response();
    };
    let a_hash = blake3::hash(expected.as_bytes());
    let b_hash = blake3::hash(provided.as_bytes());
    if !constant_time_eq(a_hash.as_bytes(), b_hash.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid API key" })),
        )
            .into_response();
    }
    next.run(request).await
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let identifier = if state.api_key.is_some() {
        let provided = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.as_bytes())
            .or_else(|| {
                request
                    .headers()
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.as_bytes())
            });
        match provided {
            Some(b) => blake3::hash(b).to_hex().to_string(),
            None => addr,
        }
    } else {
        addr
    };

    let now = Instant::now();
    let allow = Cell::new(true);
    state.rate_limit.entry(identifier.clone()).and_modify(|(window_start, count)| {
        if now.duration_since(*window_start) > RATE_LIMIT_WINDOW {
            *window_start = now;
            *count = 1;
        } else {
            *count = count.saturating_add(1);
            if *count > RATE_LIMIT_MAX {
                allow.set(false);
            }
        }
    }).or_insert_with(|| (now, 1));

    if !allow.get() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }
    next.run(request).await
}

fn build_cors_layer() -> CorsLayer {
    if let Ok(frontend_url) = std::env::var("FRONTEND_URL") {
        let mut origins: Vec<_> = vec![
            "http://localhost:3001"
                .parse()
                .expect("hardcoded origin"),
            "http://127.0.0.1:3001"
                .parse()
                .expect("hardcoded origin"),
        ];
        for url in frontend_url.split(',') {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                if let Ok(hv) = trimmed.parse() {
                    origins.push(hv);
                }
            }
        }
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    } else {
        let origins: Vec<_> = vec![
            "http://localhost:3001"
                .parse()
                .expect("hardcoded origin"),
            "http://127.0.0.1:3001"
                .parse()
                .expect("hardcoded origin"),
        ];
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    }
}

/// Run the Catenar Verifier API server with the given key provider.
pub async fn run(key_provider: Arc<dyn KeyProvider>) -> anyhow::Result<()> {
    telemetry::init_telemetry()?;

    let state = AppState {
        policy_store: build_policy_store(),
        agent_store: build_agent_store(),
        key_provider,
        policy_engine: Arc::from(build_policy_engine()),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(3))
            .build()
            .context("failed to build http client")?,
        api_key: std::env::var("VERIFIER_API_KEY").ok(),
        rate_limit: Arc::new(DashMap::new()),
    };

    if state.api_key.is_none() {
        tracing::warn!(
            "VERIFIER_API_KEY not set; verifier API is unauthenticated. Set VERIFIER_API_KEY in production."
        );
        if std::env::var("VERIFIER_REQUIRE_API_KEY")
            .map(|v| v.trim().eq_ignore_ascii_case("1") || v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            anyhow::bail!(
                "VERIFIER_REQUIRE_API_KEY is set but VERIFIER_API_KEY is not set. \
                 Configure VERIFIER_API_KEY for production."
            );
        }
    }

    let cors = build_cors_layer();

    let healthz = Router::new()
        .route("/healthz", get(healthz_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    let protected = Router::new()
        .route("/v1/register", post(register_handler))
        .route("/v1/verify", post(verify_handler))
        .route("/v1/receipt", post(receipt_ingest_handler))
        .route("/v1/agent/register", post(agent_register_handler))
        .route("/v1/agents", get(list_agents_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api_key_middleware,
        ));

    let app = Router::new()
        .merge(healthz)
        .merge(protected)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1 MB
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("[catenar-api] listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("[catenar-api] failed to listen for shutdown signal: {error}");
    }
    info!("[catenar-api] shutdown signal received");
}

async fn register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(policy): Json<Value>,
) -> AppResult<Json<RegisterResponse>> {
    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|e| AppError::internal(format!("failed to encode policy JSON: {e}")))?;
    let commitment = format!("0x{}", blake3::hash(&policy_bytes).to_hex());

    state
        .policy_store
        .upsert_policy(&commitment, &policy)
        .await
        .map_err(|e| AppError::internal(format!("failed to persist policy: {e}")))?;

    let task_token = std::env::var("TASK_TOKEN_SECRET")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(|secret| {
            let payload = AgentTaskToken {
                agent_id: get_header_or_default(&headers, "x-catenar-agent-id", DEFAULT_AGENT_ID),
                task_id: get_header_or_default(&headers, "x-catenar-task-id", DEFAULT_TASK_ID),
                policy_commitment: commitment.clone(),
                exp: chrono::Utc::now().timestamp() + task_token_ttl_secs(),
            };
            issue_task_token(&secret, &payload)
                .map_err(|e| AppError::internal(format!("failed to issue task token: {e}")))
        })
        .transpose()?;
    let task_token_required = std::env::var("TASK_TOKEN_SECRET")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    Ok(Json(RegisterResponse {
        policy_commitment: commitment,
        task_token,
        task_token_required,
    }))
}

async fn verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VerifyRequest>,
) -> AppResult<Json<VerifyResponse>> {
    let parent_task_ids_received: Vec<&str> = request
        .execution_trace
        .iter()
        .filter_map(|e| e.parent_task_id.as_deref())
        .collect();
    tracing::info!(
        trace_len = request.execution_trace.len(),
        parent_task_ids_in_request = ?parent_task_ids_received,
        "verify request received"
    );
    request
        .validate_bounds()
        .map_err(|e| AppError {
            status: StatusCode::BAD_REQUEST,
            message: e,
        })?;
    let agent_id = headers
        .get("x-catenar-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let response = verify_trace(
        &request,
        agent_id,
        state.policy_store.as_ref(),
        state.agent_store.as_ref(),
        state.key_provider.as_ref(),
        state.policy_engine.as_ref(),
    )
        .await
        .map_err(|e| AppError::internal(format!("verification failed: {e}")))?;
    if let Err(err) = report_receipt_if_configured(&state.http_client, &response).await {
        eprintln!("[catenar-api] failed to report receipt: {err}");
    }
    if let Err(err) = notify_policy_violation_if_configured(&state.http_client, &request, &response).await {
        eprintln!("[catenar-api] failed to send policy violation webhook: {err}");
    }
    Ok(Json(response))
}

async fn agent_register_handler(
    State(state): State<AppState>,
    Json(registration): Json<AgentRegistration>,
) -> AppResult<Json<AgentRegistrationResponse>> {
    let registered_at = state
        .agent_store
        .upsert_agent(&registration)
        .await
        .map_err(|e| AppError::internal(format!("failed to register agent: {e}")))?;
    Ok(Json(AgentRegistrationResponse {
        agent_id: registration.agent_id,
        registered_at,
    }))
}

async fn list_agents_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AgentRegistration>>> {
    let role = headers
        .get("x-catenar-role")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if role != "admin" {
        return Err(AppError {
            status: StatusCode::FORBIDDEN,
            message: "admin role required".to_string(),
        });
    }
    let agents = state
        .agent_store
        .list_agents()
        .await
        .map_err(|e| AppError::internal(format!("failed to list agents: {e}")))?;
    Ok(Json(agents))
}

async fn receipt_ingest_handler(Json(_receipt): Json<Value>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({ "error": "receipt ingest not implemented" })),
    )
}

async fn healthz_handler() -> AppResult<Json<Value>> {
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use axum::http::Request;
    use crate::keys::LocalKeyProvider;
    use crate::store::{InMemoryAgentStore, InMemoryPolicyStore};
    use tower::ServiceExt;

    fn build_test_app() -> Router {
        let state = AppState {
            policy_store: Arc::new(InMemoryPolicyStore::new()),
            agent_store: Arc::new(InMemoryAgentStore::new()),
            key_provider: Arc::new(LocalKeyProvider::new_random()),
            policy_engine: Arc::from(crate::policy::build_policy_engine()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
            api_key: None,
            rate_limit: Arc::new(DashMap::new()),
        };
        let cors = build_cors_layer();
        let healthz = Router::new()
            .route("/healthz", get(healthz_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware));
        let protected = Router::new()
            .route("/v1/register", post(register_handler))
            .route("/v1/verify", post(verify_handler))
            .route("/v1/receipt", post(receipt_ingest_handler))
            .route("/v1/agent/register", post(agent_register_handler))
            .route("/v1/agents", get(list_agents_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
            .route_layer(middleware::from_fn_with_state(state.clone(), api_key_middleware));
        Router::new()
            .merge(healthz)
            .merge(protected)
            .with_state(state)
            .layer(RequestBodyLimitLayer::new(1024 * 1024))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
    }

    #[tokio::test]
    async fn verify_http_includes_parent_task_ids() {
        let _ = tracing_subscriber::fmt::try_init();
        let app = build_test_app();

        // Register policy
        let register_body = serde_json::json!({"public_values": {"restricted_endpoints": ["/admin"]}});
        let register_req = Request::post("/v1/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
            .unwrap();
        let register_res = app.clone().oneshot(register_req).await.unwrap();
        assert_eq!(register_res.status(), StatusCode::OK);
        let reg_bytes = register_res.into_body().collect().await.unwrap().to_bytes();
        let reg_json: serde_json::Value = serde_json::from_slice(&reg_bytes).unwrap();
        let pc = reg_json["policy_commitment"].as_str().unwrap();

        // Verify with parent_task_id in trace
        let verify_body = serde_json::json!({
            "agent_metadata": {"domain": "defi", "version": "1.0"},
            "policy_commitment": pc,
            "execution_trace": [{"action": "function_call", "target": "sub_task", "parent_task_id": "test-parent-123", "details": {}}],
            "public_values": {"restricted_endpoints": ["/admin"]}
        });
        let verify_req = Request::post("/v1/verify")
            .header("content-type", "application/json")
            .header("x-catenar-agent-id", "agent-b")
            .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let res_bytes = verify_res.into_body().collect().await.unwrap().to_bytes();
        let res_json: serde_json::Value = serde_json::from_slice(&res_bytes).unwrap();
        let proof = res_json.get("proof").expect("expected proof");
        let parent_task_ids = proof.get("parent_task_ids");
        assert!(parent_task_ids.is_some(), "proof must include parent_task_ids");
        let ids = parent_task_ids.unwrap().as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str().unwrap(), "test-parent-123");
    }

    /// Real HTTP request over TCP - verifies the full stack works.
    #[tokio::test]
    async fn verify_over_tcp_includes_parent_task_ids() {
        let _ = tracing_subscriber::fmt::try_init();
        let app = build_test_app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let reg: serde_json::Value = client
            .post(format!("http://{addr}/v1/register"))
            .json(&serde_json::json!({"public_values": {"restricted_endpoints": ["/admin"]}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let pc = reg["policy_commitment"].as_str().unwrap();

        let verify_body = serde_json::json!({
            "agent_metadata": {"domain": "defi", "version": "1.0"},
            "policy_commitment": pc,
            "execution_trace": [{"action": "function_call", "target": "sub_task", "parent_task_id": "test-parent-123", "details": {}}],
            "public_values": {"restricted_endpoints": ["/admin"]}
        });
        let res: serde_json::Value = client
            .post(format!("http://{addr}/v1/verify"))
            .header("x-catenar-agent-id", "agent-b")
            .json(&verify_body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let proof = res.get("proof").expect("expected proof");
        let parent_task_ids = proof.get("parent_task_ids");
        assert!(parent_task_ids.is_some(), "proof must include parent_task_ids when request goes over TCP");
        let ids = parent_task_ids.unwrap().as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str().unwrap(), "test-parent-123");
    }

    /// Same as TCP test but send body as raw bytes (like curl) instead of .json()
    #[tokio::test]
    async fn verify_with_raw_body_includes_parent_task_ids() {
        let _ = tracing_subscriber::fmt::try_init();
        let app = build_test_app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let reg: serde_json::Value = client
            .post(format!("http://{addr}/v1/register"))
            .json(&serde_json::json!({"public_values": {"restricted_endpoints": ["/admin"]}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let pc = reg["policy_commitment"].as_str().unwrap();

        let body = format!(
            r#"{{"agent_metadata":{{"domain":"defi","version":"1.0"}},"policy_commitment":"{}","execution_trace":[{{"action":"function_call","target":"sub_task","parent_task_id":"test-parent-123","details":{{}}}}],"public_values":{{"restricted_endpoints":["/admin"]}}}}"#,
            pc
        );
        let res: serde_json::Value = client
            .post(format!("http://{addr}/v1/verify"))
            .header("content-type", "application/json")
            .header("x-catenar-agent-id", "agent-b")
            .body(body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let proof = res.get("proof").expect("expected proof");
        let parent_task_ids = proof.get("parent_task_ids");
        assert!(parent_task_ids.is_some(), "proof must include parent_task_ids with raw body");
        let ids = parent_task_ids.unwrap().as_array().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].as_str().unwrap(), "test-parent-123");
    }

}
