//! Request-level Rego policy evaluation for MITM payload parsing.
//! Evaluates allow/reason against decrypted HTTP request (method, path, host, body, headers, identity).
//! The Rego policy is compiled once at startup; each evaluation clones the pre-built engine.

use anyhow::{Context, Result};
use regorus::Value as RegoValue;
use serde::Serialize;
use std::{fs, path::Path, sync::Arc};
use tokio::sync::Semaphore;

pub struct PayloadPolicyEngine {
    engine: regorus::Engine,
    semaphore: Arc<Semaphore>,
}

pub struct ResponsePolicyEngine {
    engine: regorus::Engine,
    semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub struct PayloadDecision {
    pub allow: bool,
    pub reason: Option<String>,
    pub violation_type: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResponseDecision {
    pub allow: bool,
    pub reason: Option<String>,
    pub response_injection: Option<String>,
}

impl PayloadPolicyEngine {
    /// Load and pre-compile payload policy from a file path (e.g. policies/payload.rego).
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read payload policy from {}", path.display()))?;
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("payload.rego".to_string(), source)
            .context("failed to compile payload Rego policy")?;
        Ok(Self {
            engine,
            semaphore: Arc::new(Semaphore::new(64)),
        })
    }

    /// Evaluate the pre-compiled policy against the given request input.
    pub fn evaluate(&self, input: &impl Serialize) -> Result<PayloadDecision> {
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("policy evaluation limit reached"))?;
        let mut engine = self.engine.clone();
        let input_json = serde_json::to_string(input)?;
        engine.set_input(RegoValue::from_json_str(&input_json)?);

        let allow = engine.eval_allow_query("data.aegis.payload.allow".to_string(), false);
        if allow {
            return Ok(PayloadDecision {
                allow: true,
                reason: None,
                violation_type: None,
                suggestion: None,
            });
        }

        let reason = engine
            .eval_query("data.aegis.payload.reason".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));
        let violation_type = engine
            .eval_query("data.aegis.payload.violation_type".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));
        let suggestion = engine
            .eval_query("data.aegis.payload.suggestion".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));

        Ok(PayloadDecision {
            allow: false,
            reason: reason.or(Some("payload policy denied request".to_string())),
            violation_type,
            suggestion,
        })
    }
}

impl ResponsePolicyEngine {
    /// Load and pre-compile response policy from a file path (e.g. policies/response.rego).
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read response policy from {}", path.display()))?;
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("response.rego".to_string(), source)
            .context("failed to compile response Rego policy")?;
        Ok(Self {
            engine,
            semaphore: Arc::new(Semaphore::new(64)),
        })
    }

    /// Evaluate the pre-compiled policy against the given response input.
    pub fn evaluate(&self, input: &impl Serialize) -> Result<ResponseDecision> {
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("policy evaluation limit reached"))?;
        let mut engine = self.engine.clone();
        let input_json = serde_json::to_string(input)?;
        engine.set_input(RegoValue::from_json_str(&input_json)?);

        let allow = engine.eval_allow_query("data.aegis.response.allow".to_string(), false);
        if allow {
            return Ok(ResponseDecision {
                allow: true,
                reason: None,
                response_injection: None,
            });
        }

        let reason = engine
            .eval_query("data.aegis.response.reason".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));

        let response_injection = engine
            .eval_query("data.aegis.response.response_injection".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));

        Ok(ResponseDecision {
            allow: false,
            reason: reason.or(Some("response policy denied response".to_string())),
            response_injection,
        })
    }
}
