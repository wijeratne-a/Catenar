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
        for (i, entry) in self.execution_trace.iter().enumerate() {
            check_string_len(&entry.action, &format!("execution_trace[{i}].action"))?;
            check_string_len(&entry.target, &format!("execution_trace[{i}].target"))?;
            if let Some(ref t) = entry.table {
                check_string_len(t, &format!("execution_trace[{i}].table"))?;
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
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
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
