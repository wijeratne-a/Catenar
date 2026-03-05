use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tracing::warn;

use crate::schema::AgentRegistration;

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()>;
    async fn has_policy(&self, commitment: &str) -> Result<bool>;
}

#[async_trait]
pub trait AgentStore: Send + Sync {
    async fn upsert_agent(&self, registration: &AgentRegistration) -> Result<i64>;
    async fn list_agents(&self) -> Result<Vec<AgentRegistration>>;
    async fn touch_agent_last_seen(&self, agent_id: &str) -> Result<()>;
}

pub struct InMemoryPolicyStore {
    policies: DashMap<String, Value>,
}

pub struct InMemoryAgentStore {
    agents: DashMap<String, AgentRegistration>,
}

impl InMemoryAgentStore {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
        }
    }
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
        }
    }
}

#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()> {
        self.policies
            .insert(commitment.to_string(), policy.clone());
        Ok(())
    }

    async fn has_policy(&self, commitment: &str) -> Result<bool> {
        Ok(self.policies.contains_key(commitment))
    }
}

#[async_trait]
impl AgentStore for InMemoryAgentStore {
    async fn upsert_agent(&self, registration: &AgentRegistration) -> Result<i64> {
        self.agents
            .insert(registration.agent_id.clone(), registration.clone());
        Ok(chrono::Utc::now().timestamp())
    }

    async fn list_agents(&self) -> Result<Vec<AgentRegistration>> {
        let mut values: Vec<AgentRegistration> =
            self.agents.iter().map(|v| v.value().clone()).collect();
        values.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        Ok(values)
    }

    async fn touch_agent_last_seen(&self, _agent_id: &str) -> Result<()> {
        Ok(())
    }
}

pub struct SqlitePolicyStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqlitePolicyStore {
    pub fn new(path: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open sqlite policy db at {path}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS policies (
                policy_commitment TEXT PRIMARY KEY,
                policy_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            )",
            [],
        )
        .context("failed to initialize sqlite policy table")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

pub struct SqliteAgentStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteAgentStore {
    pub fn new(path: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open sqlite agent db at {path}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                team TEXT NOT NULL,
                model TEXT NOT NULL,
                env TEXT NOT NULL,
                version TEXT NOT NULL,
                registered_at_unix INTEGER NOT NULL,
                last_seen_unix INTEGER NOT NULL
            )",
            [],
        )
        .context("failed to initialize sqlite agents table")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl PolicyStore for SqlitePolicyStore {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()> {
        let policy_json =
            serde_json::to_string(policy).context("failed to encode policy json for sqlite")?;
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        conn.execute(
            "INSERT INTO policies(policy_commitment, policy_json, created_at_unix)
             VALUES (?1, ?2, strftime('%s','now'))
             ON CONFLICT(policy_commitment)
             DO UPDATE SET policy_json=excluded.policy_json",
            rusqlite::params![commitment, policy_json],
        )
        .context("failed to upsert policy in sqlite store")?;
        Ok(())
    }

    async fn has_policy(&self, commitment: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        let mut stmt = conn
            .prepare("SELECT 1 FROM policies WHERE policy_commitment = ?1 LIMIT 1")
            .context("failed to prepare sqlite exists query")?;
        let mut rows = stmt
            .query(rusqlite::params![commitment])
            .context("failed to execute sqlite exists query")?;
        Ok(rows.next()?.is_some())
    }
}

#[async_trait]
impl AgentStore for SqliteAgentStore {
    async fn upsert_agent(&self, registration: &AgentRegistration) -> Result<i64> {
        let now = chrono::Utc::now().timestamp();
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        conn.execute(
            "INSERT INTO agents(agent_id, team, model, env, version, registered_at_unix, last_seen_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(agent_id)
             DO UPDATE SET
                 team=excluded.team,
                 model=excluded.model,
                 env=excluded.env,
                 version=excluded.version,
                 last_seen_unix=excluded.last_seen_unix",
            rusqlite::params![
                &registration.agent_id,
                &registration.team,
                &registration.model,
                &registration.env,
                &registration.version,
                now
            ],
        )
        .context("failed to upsert agent in sqlite store")?;

        let mut stmt = conn
            .prepare("SELECT registered_at_unix FROM agents WHERE agent_id = ?1")
            .context("failed to prepare agent registered_at query")?;
        let registered_at = stmt
            .query_row(rusqlite::params![&registration.agent_id], |row| row.get::<_, i64>(0))
            .context("failed to fetch agent registered_at")?;
        Ok(registered_at)
    }

    async fn list_agents(&self) -> Result<Vec<AgentRegistration>> {
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, team, model, env, version
                 FROM agents
                 ORDER BY agent_id ASC",
            )
            .context("failed to prepare list agents query")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AgentRegistration {
                    agent_id: row.get(0)?,
                    team: row.get(1)?,
                    model: row.get(2)?,
                    env: row.get(3)?,
                    version: row.get(4)?,
                })
            })
            .context("failed to query agents")?;

        let mut agents = Vec::new();
        for row in rows {
            agents.push(row.context("failed to decode agent row")?);
        }
        Ok(agents)
    }

    async fn touch_agent_last_seen(&self, agent_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        conn.execute(
            "UPDATE agents SET last_seen_unix = strftime('%s','now') WHERE agent_id = ?1",
            rusqlite::params![agent_id],
        )
        .context("failed to touch agent last_seen")?;
        Ok(())
    }
}

pub fn build_policy_store() -> Arc<dyn PolicyStore> {
    let mode = std::env::var("POLICY_STORE").unwrap_or_else(|_| "sqlite".to_string());
    if mode == "memory" || mode == "in_memory" {
        return Arc::new(InMemoryPolicyStore::new());
    }

    let path = std::env::var("POLICY_DB_PATH").unwrap_or_else(|_| "policies.db".to_string());
    match SqlitePolicyStore::new(&path) {
        Ok(store) => Arc::new(store),
        Err(err) => {
            warn!(
                error = %err,
                "sqlite policy store unavailable, falling back to in-memory store"
            );
            Arc::new(InMemoryPolicyStore::new())
        }
    }
}

pub fn build_agent_store() -> Arc<dyn AgentStore> {
    let mode = std::env::var("POLICY_STORE").unwrap_or_else(|_| "sqlite".to_string());
    if mode == "memory" || mode == "in_memory" {
        return Arc::new(InMemoryAgentStore::new());
    }

    let path = std::env::var("POLICY_DB_PATH").unwrap_or_else(|_| "policies.db".to_string());
    match SqliteAgentStore::new(&path) {
        Ok(store) => Arc::new(store),
        Err(err) => {
            warn!(
                error = %err,
                "sqlite agent store unavailable, falling back to in-memory store"
            );
            Arc::new(InMemoryAgentStore::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_policy_store_persists_policy() {
        let store = SqlitePolicyStore::new(":memory:").expect("store create");
        let policy = serde_json::json!({ "domain": "defi" });
        store
            .upsert_policy("0xabc", &policy)
            .await
            .expect("insert policy");

        let exists = store.has_policy("0xabc").await.expect("exists query");
        assert!(exists);
        let missing = store.has_policy("0xdef").await.expect("missing query");
        assert!(!missing);
    }
}
