use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use constant_time_eq::constant_time_eq;
use dashmap::DashMap;
use serde_json::Value;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod engine;
mod keys;
mod policy;
mod schema;
mod telemetry;

use crate::engine::{report_receipt_if_configured, verify_trace};
use crate::keys::{build_key_provider, KeyProvider};
use crate::policy::{build_policy_engine, PolicyEngine};
use crate::schema::{ReceiptIngestResponse, RegisterResponse, VerifyRequest, VerifyResponse};

#[derive(Clone)]
struct AppState {
    policies: Arc<DashMap<String, Value>>,
    key_provider: Arc<dyn KeyProvider>,
    policy_engine: Arc<dyn PolicyEngine>,
    http_client: reqwest::Client,
    api_key: Option<String>,
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
        let expose = std::env::var("AEGIS_DEBUG")
            .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let msg = if expose {
            self.message
        } else {
            "Internal error".to_string()
        };
        (
            self.status,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response()
    }
}

type AppResult<T> = Result<T, AppError>;

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
    let a = expected.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() || !constant_time_eq(a, b) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid API key" })),
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
        CorsLayer::permissive()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init_telemetry()?;

    let state = AppState {
        policies: Arc::new(DashMap::new()),
        key_provider: build_key_provider()?,
        policy_engine: Arc::from(build_policy_engine()),
        http_client: reqwest::Client::new(),
        api_key: std::env::var("VERIFIER_API_KEY").ok(),
    };

    let cors = build_cors_layer();

    let protected = Router::new()
        .route("/v1/register", post(register_handler))
        .route("/v1/verify", post(verify_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api_key_middleware,
        ));

    let app = Router::new()
        .route("/v1/receipt", post(receipt_ingest_handler))
        .route("/healthz", get(healthz_handler))
        .merge(protected)
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1 MB
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("[aegis-api] listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("[aegis-api] failed to listen for shutdown signal: {error}");
    }
    info!("[aegis-api] shutdown signal received");
}

async fn register_handler(
    State(state): State<AppState>,
    Json(policy): Json<Value>,
) -> AppResult<Json<RegisterResponse>> {
    let policy_bytes = serde_json::to_vec(&policy)
        .map_err(|e| AppError::internal(format!("failed to encode policy JSON: {e}")))?;
    let commitment = format!("0x{}", blake3::hash(&policy_bytes).to_hex());

    state.policies.insert(commitment.clone(), policy);
    Ok(Json(RegisterResponse {
        policy_commitment: commitment,
    }))
}

async fn verify_handler(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> AppResult<Json<VerifyResponse>> {
    request
        .validate_bounds()
        .map_err(|e| AppError {
            status: StatusCode::BAD_REQUEST,
            message: e,
        })?;
    let response = verify_trace(
        &request,
        &state.policies,
        state.key_provider.as_ref(),
        state.policy_engine.as_ref(),
    )
        .await
        .map_err(|e| AppError::internal(format!("verification failed: {e}")))?;
    if let Err(err) = report_receipt_if_configured(&state.http_client, &response).await {
        eprintln!("[aegis-api] failed to report receipt: {err}");
    }
    Ok(Json(response))
}

async fn receipt_ingest_handler(
    Json(_receipt): Json<Value>,
) -> AppResult<Json<ReceiptIngestResponse>> {
    Ok(Json(ReceiptIngestResponse {
        status: "ok".to_string(),
    }))
}

async fn healthz_handler() -> AppResult<Json<Value>> {
    Ok(Json(serde_json::json!({ "status": "ok" })))
}
