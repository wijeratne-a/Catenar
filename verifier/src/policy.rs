use anyhow::Result;
use regorus::{Engine as RegoEngineImpl, Value as RegoValue};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::schema::{VerifyRequest, MAX_EXECUTION_TRACE_LEN, MAX_STRING_LEN};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allow: bool,
    pub reason: Option<String>,
}

pub trait PolicyEngine: Send + Sync {
    fn evaluate(&self, request: &VerifyRequest) -> Result<PolicyDecision>;
}

pub struct LegacyJsonEngine;

impl PolicyEngine for LegacyJsonEngine {
    fn evaluate(&self, request: &VerifyRequest) -> Result<PolicyDecision> {
        let domain = request.agent_metadata.domain.to_ascii_lowercase();
        if domain != "defi" && domain != "enterprise" {
            return Ok(PolicyDecision {
                allow: false,
                reason: Some("unsupported domain".to_string()),
            });
        }

        let restricted = request
            .public_values
            .restricted_endpoints
            .clone()
            .unwrap_or_default();

        if domain == "defi" {
            let max_spend = request.public_values.max_spend.unwrap_or(f64::INFINITY);
            let mut total_spend = 0.0_f64;
            for entry in &request.execution_trace {
                if let Some(amount) = entry.amount {
                    total_spend += amount;
                }
                if restricted.iter().any(|blocked| entry.target.contains(blocked)) {
                    return Ok(PolicyDecision {
                        allow: false,
                        reason: Some(format!("restricted endpoint accessed: {}", entry.target)),
                    });
                }
            }
            if total_spend > max_spend {
                return Ok(PolicyDecision {
                    allow: false,
                    reason: Some(format!(
                        "max spend exceeded: total_spend={total_spend}, max_spend={max_spend}"
                    )),
                });
            }
            return Ok(PolicyDecision {
                allow: true,
                reason: None,
            });
        }

        for entry in &request.execution_trace {
            if let Some(table) = &entry.table {
                if restricted.iter().any(|blocked| blocked == table) {
                    return Ok(PolicyDecision {
                        allow: false,
                        reason: Some(format!("restricted table accessed: {table}")),
                    });
                }
            }
        }
        Ok(PolicyDecision {
            allow: true,
            reason: None,
        })
    }
}

pub struct RegoEngine {
    source: String,
}

impl RegoEngine {
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let mut source = String::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rego") {
                source.push_str(&fs::read_to_string(path)?);
                source.push('\n');
            }
        }
        Ok(Self { source })
    }
}

impl PolicyEngine for RegoEngine {
    fn evaluate(&self, request: &VerifyRequest) -> Result<PolicyDecision> {
        if request.execution_trace.len() > MAX_EXECUTION_TRACE_LEN {
            return Ok(PolicyDecision {
                allow: false,
                reason: Some(format!(
                    "execution_trace exceeds max length {MAX_EXECUTION_TRACE_LEN}"
                )),
            });
        }
        for (i, entry) in request.execution_trace.iter().enumerate() {
            if entry.action.len() > MAX_STRING_LEN || entry.target.len() > MAX_STRING_LEN {
                return Ok(PolicyDecision {
                    allow: false,
                    reason: Some(format!(
                        "execution_trace[{i}] string field exceeds max length {MAX_STRING_LEN}"
                    )),
                });
            }
            if let Some(ref t) = entry.table {
                if t.len() > MAX_STRING_LEN {
                    return Ok(PolicyDecision {
                        allow: false,
                        reason: Some(format!(
                            "execution_trace[{i}].table exceeds max length {MAX_STRING_LEN}"
                        )),
                    });
                }
            }
        }
        let mut engine = RegoEngineImpl::new();
        engine.add_policy("aegis.rego".to_string(), self.source.clone())?;
        let input = serde_json::to_string(request)?;
        engine.set_input(RegoValue::from_json_str(&input)?);

        let allow = engine.eval_allow_query("data.aegis.allow".to_string(), false);
        if allow {
            return Ok(PolicyDecision {
                allow: true,
                reason: None,
            });
        }

        let reason = engine
            .eval_query("data.aegis.reason".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));

        Ok(PolicyDecision {
            allow: false,
            reason: reason.or(Some("rego policy denied request".to_string())),
        })
    }
}

pub fn build_policy_engine() -> Box<dyn PolicyEngine> {
    let mode = std::env::var("POLICY_ENGINE").unwrap_or_else(|_| "legacy".to_string());
    if mode == "rego" {
        let policy_dir = std::env::var("POLICY_DIR").unwrap_or_else(|_| "./policies".to_string());
        if let Ok(rego) = RegoEngine::load_from_dir(policy_dir) {
            return Box::new(rego);
        }
    }
    Box::new(LegacyJsonEngine)
}

pub fn identity_hash(identity: &Option<crate::schema::IdentityContext>) -> Result<Option<String>> {
    if let Some(identity) = identity {
        let bytes = serde_json::to_vec(identity)?;
        return Ok(Some(format!("0x{}", blake3::hash(&bytes).to_hex())));
    }
    Ok(None)
}

