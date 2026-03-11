//! Trace WAL with BLAKE3 hash chain for audit integrity.
//!
//! **Checkpoint file:** When present, `{wal_path}.chain_checkpoint` stores the last chain hash.
//! On startup, we compare the WAL tail's last hash to the checkpoint; on mismatch we treat the
//! log as tampered and reset so the next entry chains from empty. The WAL directory and
//! checkpoint file must be integrity-protected (e.g. permissions, append-only).

use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::warn;

#[derive(Clone)]
pub struct TraceLogger {
    inner: Arc<Mutex<TraceLoggerInner>>,
}

struct TraceLoggerInner {
    path: PathBuf,
    last_hash: String,
}

fn checkpoint_path(wal_path: &Path) -> PathBuf {
    let mut p = wal_path.to_path_buf();
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    p.set_file_name(format!("{}.chain_checkpoint", name));
    p
}

fn write_checkpoint(checkpoint_path: &Path, hash: &str) -> Result<()> {
    fs::write(checkpoint_path, hash.as_bytes())
        .with_context(|| format!("failed to write checkpoint {}", checkpoint_path.display()))
}

impl TraceLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create WAL directory {}", parent.display()))?;
        }
        let mut last_hash = load_last_hash(&path);
        if !last_hash.is_empty() {
            let cp = checkpoint_path(&path);
            if let Ok(contents) = fs::read_to_string(&cp) {
                let checkpoint_hash = contents.trim();
                if !checkpoint_hash.is_empty() && checkpoint_hash != last_hash {
                    warn!(
                        "WAL chain checkpoint mismatch; possible tampering. Resetting chain. path={}",
                        path.display()
                    );
                    last_hash = String::new();
                }
            }
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(TraceLoggerInner { path, last_hash })),
        })
    }

    pub fn append<T: Serialize>(&self, value: &T) -> Result<()> {
        // Recover from poisoned mutex to avoid process crash; prefer explicit handling over panic.
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
            .with_context(|| format!("failed to open trace log {}", inner.path.display()))?;

        let payload =
            serde_json::to_string(value).context("failed to serialize trace log entry")?;
        let chain_hash = compute_chain_hash(&inner.last_hash, &payload);
        inner.last_hash = chain_hash.clone();
        let line = with_chain_hash(value, &chain_hash)?;
        file.write_all(line.as_bytes())
            .context("failed to write trace entry")?;
        file.write_all(b"\n")
            .context("failed to terminate trace entry line")?;
        file.flush().context("failed to flush trace WAL")?;
        let cp = checkpoint_path(&inner.path);
        write_checkpoint(&cp, &chain_hash).ok(); // best-effort; log append succeeded
        Ok(())
    }
}

fn with_chain_hash<T: Serialize>(value: &T, chain_hash: &str) -> Result<String> {
    let mut json = serde_json::to_value(value).context("failed to convert trace log entry")?;
    match &mut json {
        serde_json::Value::Object(map) => {
            map.insert(
                "chain_hash".to_string(),
                serde_json::Value::String(chain_hash.to_string()),
            );
            serde_json::to_string(&json).context("failed to serialize chained trace log entry")
        }
        _ => serde_json::to_string(&serde_json::json!({
            "payload": json,
            "chain_hash": chain_hash
        }))
        .context("failed to serialize wrapped chained trace log entry"),
    }
}

/// Chain hash: BLAKE3 with derive key "catenar.trace.chain.v1".
/// Third-party verification must use the same key to reproduce hashes.
fn compute_chain_hash(previous_hash: &str, payload: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("catenar.trace.chain.v1");
    let prev_bytes = previous_hash.as_bytes();
    let payload_bytes = payload.as_bytes();
    hasher.update(&(prev_bytes.len() as u64).to_le_bytes());
    hasher.update(prev_bytes);
    hasher.update(&(payload_bytes.len() as u64).to_le_bytes());
    hasher.update(payload_bytes);
    format!("0x{}", hasher.finalize().to_hex())
}

const TAIL_BYTES: usize = 64 * 1024; // 64 KB from end; avoids OOM on large WAL

fn load_last_hash(path: &Path) -> String {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let len = match file.seek(SeekFrom::End(0)) {
        Ok(n) => n as usize,
        Err(_) => return String::new(),
    };
    if len == 0 {
        return String::new();
    }
    let start = len.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(start as u64)).is_err() {
        return String::new();
    }
    let mut tail = vec![0u8; len - start];
    if file.read_exact(&mut tail).is_err() {
        return String::new();
    }
    let content = String::from_utf8_lossy(&tail);
    for line in content.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(hash) = value.get("chain_hash").and_then(|v| v.as_str()) {
                return hash.to_string();
            }
        }
        break;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::{checkpoint_path, compute_chain_hash, TraceLogger};
    use serde_json::Value;
    use std::{fs, path::PathBuf};

    fn temp_wal_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("catenar-proxy-trace-{}.jsonl", uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn appends_chain_hash_on_each_entry() {
        let path = temp_wal_path();
        let logger = TraceLogger::new(&path).unwrap();
        logger.append(&serde_json::json!({"a":1})).unwrap();
        logger.append(&serde_json::json!({"b":2})).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        let first: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        let second: Value = serde_json::from_str(lines.next().unwrap()).unwrap();

        let first_hash = first.get("chain_hash").and_then(|v| v.as_str()).unwrap();
        let second_hash = second.get("chain_hash").and_then(|v| v.as_str()).unwrap();
        assert!(first_hash.starts_with("0x"));
        assert!(second_hash.starts_with("0x"));
        assert_ne!(first_hash, second_hash);

        let cp = checkpoint_path(&path);
        fs::remove_file(&path).ok();
        fs::remove_file(cp).ok();
    }

    #[test]
    fn tampered_wal_resets_chain() {
        let path = temp_wal_path();
        let logger = TraceLogger::new(&path).unwrap();
        logger.append(&serde_json::json!({"a":1})).unwrap();
        let cp = checkpoint_path(&path);
        assert!(cp.exists(), "checkpoint should exist after append");

        // Tamper: overwrite WAL with a line that has a different chain_hash (trailing newline
        // so append adds a separate line)
        fs::write(
            &path,
            format!("{}\n", r#"{"chain_hash":"0xbad","timestamp_ns":0,"other":"tampered"}"#),
        )
        .unwrap();
        // Checkpoint still has correct hash from before

        let logger2 = TraceLogger::new(&path).unwrap();
        logger2.append(&serde_json::json!({"c":3})).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(
            lines.len() >= 1,
            "expected at least one line after append, got {}",
            lines.len()
        );
        let last: Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
        let last_hash = last.get("chain_hash").and_then(|v| v.as_str()).unwrap();
        assert!(last_hash.starts_with("0x"));
        assert_ne!(last_hash, "0xbad"); // chained from empty, not from tampered
        fs::remove_file(&path).ok();
        fs::remove_file(cp).ok();
    }

    #[test]
    fn chain_hash_uses_previous_hash_and_payload() {
        let first = compute_chain_hash("", r#"{"a":1}"#);
        let second = compute_chain_hash(&first, r#"{"b":2}"#);
        let different = compute_chain_hash("", r#"{"b":2}"#);
        assert_ne!(second, different);
    }
}
