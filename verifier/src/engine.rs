use std::fmt::Write;

use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use serde::Serialize;
use serde_json::Value;
use tracing::{info, info_span, warn};
use uuid::Uuid;

use crate::{
    keys::KeyProvider,
    policy::{identity_hash, PolicyEngine},
    schema::{PotReceipt, VerifyRequest, VerifyResponse},
    telemetry,
};

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[derive(Serialize)]
struct UnsignedReceipt<'a> {
    receipt_id: &'a str,
    policy_commitment: &'a str,
    trace_hash: String,
    identity_hash: Option<String>,
    timestamp_ns: i64,
}

pub async fn verify_trace(
    request: &VerifyRequest,
    policy_store: &DashMap<String, Value>,
    key_provider: &dyn KeyProvider,
    policy_engine: &dyn PolicyEngine,
) -> Result<VerifyResponse> {
    let verify_span = info_span!(
        "aegis.verify",
        policy_commitment = %request.policy_commitment,
        domain = %request.agent_metadata.domain
    );
    let _span_guard = verify_span.enter();

    if !policy_store.contains_key(&request.policy_commitment) {
        warn!(policy_commitment=%request.policy_commitment, "unknown policy commitment");
        telemetry::increment_policy_violation(&request.agent_metadata.domain);
        return Ok(invalid("unknown policy commitment"));
    }

    let decision = policy_engine.evaluate(request)?;
    if !decision.allow {
        warn!(
            policy_commitment=%request.policy_commitment,
            reason=?decision.reason,
            "policy denied request"
        );
        telemetry::increment_policy_violation(&request.agent_metadata.domain);
        return Ok(invalid(
            decision.reason.unwrap_or_else(|| "policy denied request".to_string()),
        ));
    }

    let trace_bytes = serde_json::to_vec(&request.execution_trace)
        .context("failed to serialize execution_trace for hashing")?;
    let trace_hash = format!("0x{}", blake3::hash(&trace_bytes).to_hex());
    let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let receipt_id = Uuid::new_v4().to_string();
    let identity_hash = identity_hash(&request.identity_context)?;

    let unsigned = UnsignedReceipt {
        receipt_id: &receipt_id,
        policy_commitment: &request.policy_commitment,
        trace_hash: trace_hash.clone(),
        identity_hash: identity_hash.clone(),
        timestamp_ns,
    };
    let unsigned_bytes =
        serde_json::to_vec(&unsigned).context("failed to serialize PoT receipt for signing")?;
    let signature = key_provider.sign(&unsigned_bytes).await?;

    let proof = PotReceipt {
        receipt_id,
        policy_commitment: request.policy_commitment.clone(),
        trace_hash,
        identity_hash,
        timestamp_ns,
        signature: hex_encode(&signature),
        public_key: hex_encode(&key_provider.public_key_bytes()),
    };

    info!(
        policy_commitment=%request.policy_commitment,
        domain=%request.agent_metadata.domain,
        "verification succeeded"
    );
    telemetry::increment_verification_success(&request.agent_metadata.domain);

    Ok(VerifyResponse {
        valid: true,
        reason: None,
        proof: Some(proof),
    })
}

fn invalid(reason: impl Into<String>) -> VerifyResponse {
    VerifyResponse {
        valid: false,
        reason: Some(reason.into()),
        proof: None,
    }
}

pub async fn report_receipt_if_configured(
    client: &reqwest::Client,
    response: &VerifyResponse,
) -> Result<()> {
    let Some(proof) = &response.proof else {
        return Ok(());
    };
    let cloud_url = match std::env::var("AEGIS_CLOUD_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };

    let res = client
        .post(cloud_url)
        .json(proof)
        .send()
        .await
        .context("failed to submit receipt to cloud control plane")?;
    if !res.status().is_success() {
        warn!("cloud receipt ingest responded with {}", res.status());
    }
    Ok(())
}
