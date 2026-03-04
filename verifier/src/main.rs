use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::Value;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use axum::http::{header, Method};

mod engine;
mod schema;

use crate::engine::verify_trace;
use crate::schema::{RegisterResponse, VerifyRequest, VerifyResponse};

#[derive(Clone)]
struct AppState {
    policies: Arc<DashMap<String, Value>>,
    signing_key: Arc<SigningKey>,
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
        (
            self.status,
            Json(serde_json::json!({
                "error": self.message
            })),
        )
            .into_response()
    }
}

type AppResult<T> = Result<T, AppError>;

fn build_cors_layer() -> CorsLayer {
    if let Ok(frontend_url) = std::env::var("FRONTEND_URL") {
        let mut origins: Vec<_> = vec![
            "http://localhost:3001".parse().unwrap(),
            "http://127.0.0.1:3001".parse().unwrap(),
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
    let state = AppState {
        policies: Arc::new(DashMap::new()),
        signing_key: Arc::new(SigningKey::generate(&mut OsRng)),
    };

    let cors = build_cors_layer();

    let app = Router::new()
        .route("/v1/register", post(register_handler))
        .route("/v1/verify", post(verify_handler))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("[aegis-api] listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("[aegis-api] failed to listen for shutdown signal: {error}");
    }
    println!("[aegis-api] shutdown signal received");
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
    let response = verify_trace(&request, &state.policies, &state.signing_key)
        .map_err(|e| AppError::internal(format!("verification failed: {e}")))?;
    Ok(Json(response))
}
