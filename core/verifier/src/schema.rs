use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum number of entries in execution_trace to prevent Rego/serde abuse.
pub const MAX_EXECUTION_TRACE_LEN: usize = 256;
/// Maximum length for string fields to prevent unbounded memory consumption.
pub const MAX_STRING_LEN: usize = 4096;

fn check_string_len(s: &str, field: &str) -> Result<(), String> {
    if s.len() > MAX_STRING_LEN {
        Err(format!("{field} exceeds max length {MAX_STRING_LEN}"))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResponse {
    pub policy_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_token: Option<String>,
    pub task_token_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub team: String,
    pub model: String,
    pub env: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistrationResponse {
    pub agent_id: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMetadata {
    pub domain: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEntry {
    pub action: String,
    pub target: String,
    pub amount: Option<f64>,
    pub table: Option<String>,
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityContext {
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub iam_role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicValues {
    pub max_spend: Option<f64>,
    pub restricted_endpoints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub agent_metadata: AgentMetadata,
    pub policy_commitment: String,
    pub execution_trace: Vec<TraceEntry>,
    pub public_values: PublicValues,
    pub identity_context: Option<IdentityContext>,
    pub task_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTaskToken {
    pub agent_id: String,
    pub task_id: String,
    pub policy_commitment: String,
    pub exp: i64,
}

impl VerifyRequest {
    /// Validates size bounds to prevent abuse. Returns Err with message for 400.
    pub fn validate_bounds(&self) -> Result<(), String> {
        if self.execution_trace.len() > MAX_EXECUTION_TRACE_LEN {
            return Err(format!(
                "execution_trace exceeds max length {MAX_EXECUTION_TRACE_LEN}"
            ));
        }
        check_string_len(&self.agent_metadata.domain, "agent_metadata.domain")?;
        check_string_len(&self.agent_metadata.version, "agent_metadata.version")?;
        check_string_len(&self.policy_commitment, "policy_commitment")?;
        if let Some(ref token) = self.task_token {
            check_string_len(token, "task_token")?;
        }
        for (i, entry) in self.execution_trace.iter().enumerate() {
            check_string_len(&entry.action, &format!("execution_trace[{i}].action"))?;
            check_string_len(&entry.target, &format!("execution_trace[{i}].target"))?;
            if let Some(ref t) = entry.table {
                check_string_len(t, &format!("execution_trace[{i}].table"))?;
            }
            if let Some(ref s) = entry.reasoning_summary {
                check_string_len(s, &format!("execution_trace[{i}].reasoning_summary"))?;
            }
            if let Some(ref s) = entry.model_id {
                check_string_len(s, &format!("execution_trace[{i}].model_id"))?;
            }
            if let Some(ref s) = entry.instruction_hash {
                check_string_len(s, &format!("execution_trace[{i}].instruction_hash"))?;
            }
            if let Some(ref s) = entry.parent_task_id {
                check_string_len(s, &format!("execution_trace[{i}].parent_task_id"))?;
            }
            if let Some(ref d) = entry.details {
                let s = serde_json::to_string(d).map_err(|e| e.to_string())?;
                if s.len() > MAX_STRING_LEN {
                    return Err(format!(
                        "execution_trace[{i}].details exceeds max size {MAX_STRING_LEN}"
                    ));
                }
            }
        }
        if let Some(ref pv) = self.public_values.restricted_endpoints {
            for (i, s) in pv.iter().enumerate() {
                check_string_len(s, &format!("public_values.restricted_endpoints[{i}]"))?;
            }
        }
        if let Some(ref id) = self.identity_context {
            if let Some(ref s) = id.session_id {
                check_string_len(s, "identity_context.session_id")?;
            }
            if let Some(ref s) = id.user_id {
                check_string_len(s, "identity_context.user_id")?;
            }
            if let Some(ref s) = id.iam_role {
                check_string_len(s, "identity_context.iam_role")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotReceipt {
    pub receipt_id: String,
    pub policy_commitment: String,
    pub trace_hash: String,
    pub identity_hash: Option<String>,
    /// BLAKE3(trace_hash || identity_hash || timestamp_ns) - single binding hash for audit verification.
    pub combined_hash: String,
    pub timestamp_ns: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub signature: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_summary: Option<String>,
    /// Parent task IDs from execution_trace for swarm lineage indexing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_task_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResponse {
    pub valid: bool,
    pub reason: Option<String>,
    pub proof: Option<PotReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIngestResponse {
    pub status: String,
}
