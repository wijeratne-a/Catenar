// ENTERPRISE_EXTENSION_POINT: The following stubs are placeholders for closed-source features.

//! Verification engine for Catenar PoT receipts.
//!
//! ## Enterprise Control Plane Boundary
//!
//! The open-core engine provides local verification, policy evaluation, and receipt signing.
//! Enterprise capabilities (global idempotency, HSM signing, multisig policy validation,
//! distributed lease consensus) are extension points that require a commercial license.
//! Stubs below document the boundary and return errors when invoked without the enterprise module.

use std::fmt::Write;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::{
    keys::KeyProvider,
    policy::{identity_hash, PolicyEngine},
    schema::{AgentTaskToken, PotReceipt, VerifyRequest, VerifyResponse},
    store::{AgentStore, PolicyStore},
    telemetry,
};

// ---------------------------------------------------------------------------
// Enterprise Control Plane stubs (closed-source extension points)
// ---------------------------------------------------------------------------

/// Enterprise: Global idempotency state. Rejects duplicate trace submissions.
/// Requires distributed deduplication ledger.
pub fn check_idempotency(
    _agent_id: &str,
    _request_id: &str,
    _timestamp_ns: i64,
) -> Result<bool> {
    bail!("Enterprise feature: requires commercial license");
}

/// Enterprise: Hardware-backed HSM (AWS CloudHSM/Yubico). Receipt signatures must be HSM-signed.
pub fn require_hsm_signing(_data: &[u8]) -> Result<Vec<u8>> {
    bail!("Enterprise feature: requires commercial license");
}

/// Enterprise: 2-of-2 multisig for policy commitments. Operator + Compliance officer.
pub fn validate_policy_multisig(
    _commitment: &[u8],
    _sig1: &[u8],
    _sig2: &[u8],
) -> Result<bool> {
    bail!("Enterprise feature: requires commercial license");
}

/// Enterprise: Distributed lease consensus. Prevents multi-zone deadlocks.
pub fn acquire_lease(
    _agent_id: &str,
    _window_start_ns: i64,
    _window_end_ns: i64,
) -> Result<bool> {
    bail!("Enterprise feature: requires commercial license");
}

// ---------------------------------------------------------------------------

fn classify_violation(reason: &str) -> telemetry::ViolationType {
    let reason_lc = reason.to_ascii_lowercase();
    if reason_lc.contains("unknown policy commitment") {
        telemetry::ViolationType::UnknownPolicyCommitment
    } else if reason_lc.contains("denied") {
        telemetry::ViolationType::PolicyDenied
    } else {
        telemetry::ViolationType::PolicyViolation
    }
}

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
    combined_hash: String,
    timestamp_ns: i64,
    agent_id: Option<&'a str>,
}

fn sign_task_token_hex(secret: &str, payload_segment: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .context("TASK_TOKEN_SECRET is invalid for HMAC")?;
    mac.update(payload_segment.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn issue_task_token(secret: &str, payload: &AgentTaskToken) -> Result<String> {
    let payload_json =
        serde_json::to_vec(payload).context("failed to serialize task token payload")?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signature = sign_task_token_hex(secret, &payload_b64)?;
    Ok(format!("{payload_b64}.{signature}"))
}

fn parse_and_validate_task_token(secret: &str, token: &str) -> Result<AgentTaskToken> {
    let mut parts = token.split('.');
    let payload_b64 = parts
        .next()
        .filter(|p| !p.is_empty())
        .context("invalid task token format")?;
    let signature = parts
        .next()
        .filter(|p| !p.is_empty())
        .context("invalid task token format")?;
    if parts.next().is_some() {
        bail!("invalid task token format");
    }
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid task token signature format");
    }

    let expected_sig = sign_task_token_hex(secret, payload_b64)?;
    let a_hash = blake3::hash(expected_sig.as_bytes());
    let b_hash = blake3::hash(signature.as_bytes());
    if !constant_time_eq(a_hash.as_bytes(), b_hash.as_bytes()) {
        bail!("invalid task token signature");
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("invalid task token payload encoding")?;
    let payload: AgentTaskToken =
        serde_json::from_slice(&payload_bytes).context("invalid task token payload")?;
    if payload.exp <= Utc::now().timestamp() {
        bail!("task token expired");
    }
    Ok(payload)
}

pub async fn verify_trace(
    request: &VerifyRequest,
    agent_id: Option<&str>,
    policy_store: &dyn PolicyStore,
    agent_store: &dyn AgentStore,
    key_provider: &dyn KeyProvider,
    policy_engine: &dyn PolicyEngine,
) -> Result<VerifyResponse> {
    let verify_span = info_span!(
        "catenar.verify",
        policy_commitment = %request.policy_commitment,
        domain = %request.agent_metadata.domain,
        catenar.session_id = tracing::field::Empty,
        catenar.user_id = tracing::field::Empty,
        catenar.iam_role = tracing::field::Empty,
    );
    let _span_guard = verify_span.enter();

    if !policy_store.has_policy(&request.policy_commitment).await? {
        warn!(policy_commitment=%request.policy_commitment, "unknown policy commitment");
        telemetry::increment_policy_violation(
            &request.agent_metadata.domain,
            telemetry::ViolationType::UnknownPolicyCommitment,
        );
        return Ok(invalid("unknown policy commitment"));
    }

    if let Ok(secret_raw) = std::env::var("TASK_TOKEN_SECRET") {
        let secret = secret_raw.trim();
        if !secret.is_empty() {
            let Some(task_token) = request.task_token.as_deref() else {
                telemetry::increment_policy_violation(
                    &request.agent_metadata.domain,
                    telemetry::ViolationType::PolicyViolation,
                );
                return Ok(invalid("missing task token"));
            };
            let payload = match parse_and_validate_task_token(secret, task_token) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(error=%err, "task token rejected");
                    telemetry::increment_policy_violation(
                        &request.agent_metadata.domain,
                        telemetry::ViolationType::PolicyViolation,
                    );
                    return Ok(invalid("invalid or expired task token"));
                }
            };
            if payload.policy_commitment != request.policy_commitment {
                warn!(
                    token_policy_commitment=%payload.policy_commitment,
                    request_policy_commitment=%request.policy_commitment,
                    "task token policy commitment mismatch"
                );
                telemetry::increment_policy_violation(
                    &request.agent_metadata.domain,
                    telemetry::ViolationType::PolicyViolation,
                );
                return Ok(invalid("task token policy commitment mismatch"));
            }
        }
    }

    let decision = policy_engine.evaluate(request)?;
    if !decision.allow {
        warn!(
            policy_commitment=%request.policy_commitment,
            reason=?decision.reason,
            "policy denied request"
        );
        let denial_reason = decision
            .reason
            .as_deref()
            .unwrap_or("policy denied request");
        telemetry::increment_policy_violation(
            &request.agent_metadata.domain,
            classify_violation(denial_reason),
        );
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
    if let Some(agent_id) = agent_id {
        if let Err(err) = agent_store.touch_agent_last_seen(agent_id).await {
            warn!(agent_id = %agent_id, error = %err, "failed to update agent last_seen");
        }
    }

    if let Some(ref id_ctx) = request.identity_context {
        verify_span.record(
            "catenar.session_id",
            id_ctx.session_id.as_deref().unwrap_or(""),
        );
        verify_span.record("catenar.user_id", id_ctx.user_id.as_deref().unwrap_or(""));
        verify_span.record("catenar.iam_role", id_ctx.iam_role.as_deref().unwrap_or(""));
        telemetry::increment_identity_bound(&request.agent_metadata.domain);
    }

    let combined_binding = format!(
        "{}\n{}\n{}",
        trace_hash,
        identity_hash.as_deref().unwrap_or(""),
        timestamp_ns
    );
    let combined_hash = format!("0x{}", blake3::hash(combined_binding.as_bytes()).to_hex());

    let unsigned = UnsignedReceipt {
        receipt_id: &receipt_id,
        policy_commitment: &request.policy_commitment,
        trace_hash: trace_hash.clone(),
        identity_hash: identity_hash.clone(),
        combined_hash: combined_hash.clone(),
        timestamp_ns,
        agent_id,
    };
    let unsigned_bytes =
        serde_json::to_vec(&unsigned).context("failed to serialize PoT receipt for signing")?;
    let signature = key_provider.sign(&unsigned_bytes).await?;

    let reasoning_summary = request
        .execution_trace
        .iter()
        .find_map(|e| e.reasoning_summary.as_deref())
        .map(|s| s.to_string());

    let parent_task_ids: Vec<String> = request
        .execution_trace
        .iter()
        .filter_map(|e| e.parent_task_id.as_ref())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .take(64)
        .collect::<Vec<_>>();
    let parent_task_ids = if parent_task_ids.is_empty() {
        None
    } else {
        Some(parent_task_ids)
    };

    let proof = PotReceipt {
        receipt_id,
        policy_commitment: request.policy_commitment.clone(),
        trace_hash,
        identity_hash,
        combined_hash,
        timestamp_ns,
        agent_id: agent_id.map(|v| v.to_string()),
        signature: hex_encode(&signature),
        public_key: hex_encode(&key_provider.public_key_bytes()),
        reasoning_summary,
        parent_task_ids,
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

#[derive(Serialize)]
struct PolicyViolationWebhook<'a> {
    event: &'a str,
    policy_commitment: &'a str,
    domain: &'a str,
    reason: &'a str,
    timestamp_ns: i64,
}

pub async fn notify_policy_violation_if_configured(
    client: &reqwest::Client,
    request: &VerifyRequest,
    response: &VerifyResponse,
) -> Result<()> {
    if response.valid {
        return Ok(());
    }
    let webhook_url = match std::env::var("WEBHOOK_URL") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };
    let secret = std::env::var("WEBHOOK_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if secret.as_ref().map_or(false, |s| s.len() < 32) {
        error!("WEBHOOK_SECRET must be at least 32 characters when WEBHOOK_URL is set; webhook disabled");
        return Ok(());
    }
    let reason = response.reason.as_deref().unwrap_or("policy denied request");
    send_policy_violation_webhook(
        client,
        &webhook_url,
        secret.as_deref(),
        &PolicyViolationWebhook {
            event: "policy_violation_denied",
            policy_commitment: &request.policy_commitment,
            domain: &request.agent_metadata.domain,
            reason,
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        },
    )
    .await
}

async fn send_policy_violation_webhook(
    client: &reqwest::Client,
    webhook_url: &str,
    webhook_secret: Option<&str>,
    payload: &PolicyViolationWebhook<'_>,
) -> Result<()> {
    let body = serde_json::to_vec(payload).context("failed to encode webhook payload")?;
    let signature: Option<String> = webhook_secret
        .map(|secret| {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .context("WEBHOOK_SECRET is invalid for HMAC")?;
            mac.update(&body);
            Ok::<_, anyhow::Error>(hex::encode(mac.finalize().into_bytes()))
        })
        .transpose()?;

    const MAX_RETRIES: u32 = 3;
    let mut last_err = None;
    for attempt in 0..=MAX_RETRIES {
        let mut req = client
            .post(webhook_url)
            .header("content-type", "application/json")
            .body(body.clone());
        if let Some(ref sig) = signature {
            req = req.header("x-catenar-signature", format!("sha256={sig}"));
        }
        match req.send().await {
            Ok(res) => {
                if res.status().is_success() {
                    return Ok(());
                }
                last_err = Some(anyhow::anyhow!("webhook responded with {}", res.status()));
                warn!("policy violation webhook responded with {} (attempt {})", res.status(), attempt + 1);
            }
            Err(e) => {
                last_err = Some(e.into());
                warn!("policy violation webhook send failed (attempt {}): {}", attempt + 1, last_err.as_ref().unwrap());
            }
        }
        if attempt < MAX_RETRIES {
            let delay_ms = 500u64 * (1 << attempt);
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("webhook failed after {} retries", MAX_RETRIES)))
}

pub async fn report_receipt_if_configured(
    client: &reqwest::Client,
    response: &VerifyResponse,
) -> Result<()> {
    let Some(proof) = &response.proof else {
        return Ok(());
    };
    let cloud_url = match std::env::var("CATENAR_CLOUD_URL") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AgentMetadata, PublicValues};
    use httpmock::Method::POST;
    use httpmock::MockServer;

    /// Test placeholder secret (not a real credential) - satisfies length requirements for scanners.
    const TEST_WEBHOOK_SECRET: &str = "test-secret-value-must-be-at-least-32-bytes!";

    #[tokio::test]
    async fn sends_webhook_with_signature() {
        let server = MockServer::start_async().await;
        let webhook = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/hook")
                    .header_exists("x-catenar-signature")
                    .body_contains("\"event\":\"policy_violation_denied\"")
                    .body_contains("\"policy_commitment\":\"0xabc\"");
                then.status(202);
            })
            .await;

        let client = reqwest::Client::new();
        let request = VerifyRequest {
            agent_metadata: AgentMetadata {
                domain: "defi".to_string(),
                version: "1.0".to_string(),
            },
            policy_commitment: "0xabc".to_string(),
            execution_trace: vec![],
            public_values: PublicValues {
                max_spend: None,
                restricted_endpoints: None,
            },
            identity_context: None,
            task_token: None,
        };
        let response = VerifyResponse {
            valid: false,
            reason: Some("denied".to_string()),
            proof: None,
        };

        send_policy_violation_webhook(
            &client,
            &format!("{}/hook", server.base_url()),
            Some(TEST_WEBHOOK_SECRET),
            &PolicyViolationWebhook {
                event: "policy_violation_denied",
                policy_commitment: &request.policy_commitment,
                domain: &request.agent_metadata.domain,
                reason: response.reason.as_deref().unwrap_or("policy denied request"),
                timestamp_ns: 1,
            },
        )
        .await
        .expect("webhook send");

        webhook.assert_async().await;
    }
}
