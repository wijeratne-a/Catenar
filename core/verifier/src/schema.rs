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
    #[serde(skip_serializing_if = "Option::is_none", alias = "parentTaskId")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_entry_deserializes_parent_task_id() {
        let json = r#"{"action":"function_call","target":"sub_task","parent_task_id":"my-parent-12345"}"#;
        let entry: TraceEntry = serde_json::from_str(json).expect("deserialize");
        assert_eq!(entry.parent_task_id.as_deref(), Some("my-parent-12345"));
    }

    #[test]
    fn verify_request_deserializes_parent_task_id_in_trace() {
        let json = r#"{
            "agent_metadata": {"domain": "defi", "version": "1.0"},
            "policy_commitment": "0xabc",
            "execution_trace": [{"action": "function_call", "target": "sub_task", "parent_task_id": "my-parent-12345"}],
            "public_values": {"restricted_endpoints": ["/admin"]}
        }"#;
        let req: VerifyRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.execution_trace.len(), 1);
        assert_eq!(
            req.execution_trace[0].parent_task_id.as_deref(),
            Some("my-parent-12345")
        );
    }

    /// SDK sends trace with "details" object - ensure parent_task_id still deserializes.
    #[test]
    fn verify_request_with_full_sdk_trace_structure() {
        let json = r#"{
            "agent_metadata": {"domain": "defi", "version": "1.0"},
            "policy_commitment": "0xabc",
            "execution_trace": [{
                "action": "function_call",
                "target": "sub_task",
                "amount": null,
                "table": null,
                "details": {"function": "sub_task", "args": [42], "kwargs": {}, "result": {"result": 84}, "execution_ms": 0.5},
                "reasoning_summary": null,
                "model_id": null,
                "instruction_hash": null,
                "parent_task_id": "agent-a-receipt-uuid"
            }],
            "public_values": {"restricted_endpoints": ["/admin"]}
        }"#;
        let req: VerifyRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.execution_trace.len(), 1);
        assert_eq!(
            req.execution_trace[0].parent_task_id.as_deref(),
            Some("agent-a-receipt-uuid")
        );
    }

    #[test]
    fn parent_task_ids_extraction_from_trace() {
        let trace = vec![
            TraceEntry {
                action: "function_call".to_string(),
                target: "sub".to_string(),
                amount: None,
                table: None,
                details: None,
                reasoning_summary: None,
                model_id: None,
                instruction_hash: None,
                parent_task_id: Some("parent-uuid-1".to_string()),
            },
        ];
        let ids: Vec<String> = trace
            .iter()
            .filter_map(|e| e.parent_task_id.as_ref())
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .take(64)
            .collect();
        assert!(!ids.is_empty());
        assert!(ids.contains(&"parent-uuid-1".to_string()));
    }
}
