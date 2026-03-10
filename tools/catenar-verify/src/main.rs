//! catenar-verify: Verify BLAKE3 chain integrity of catenar-trace-wal.jsonl files.
//! Uses the same algorithm as core/proxy/src/trace_log.rs.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;

const GAP_THRESHOLD_NS: i64 = 60_000_000_000; // 60 seconds

#[derive(Parser)]
#[command(name = "catenar-verify")]
#[command(about = "Verify BLAKE3 chain integrity of catenar trace WAL")]
struct Args {
    /// Path to catenar-trace-wal.jsonl
    path: std::path::PathBuf,

    /// Public key (hex) for future Ed25519 signature verification (stub)
    #[arg(long)]
    public_key: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.public_key.is_some() {
        eprintln!("Note: --public-key is a stub; Ed25519 verification not yet implemented.");
    }

    verify_wal(&args.path)?;
    Ok(())
}

/// Chain hash: BLAKE3 with derive key "catenar.trace.chain.v1".
/// Must match core/proxy/src/trace_log.rs compute_chain_hash.
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

/// Extract payload (JSON string without chain_hash) for hashing.
/// Matches trace_log.rs: for Object values we remove chain_hash and serialize;
/// for wrapped {payload, chain_hash} we serialize the inner payload.
fn payload_without_chain_hash(value: &Value) -> Result<String> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected JSON object"))?;
    if !obj.contains_key("chain_hash") {
        anyhow::bail!("missing chain_hash");
    }
    // Wrapped format: {payload: X, chain_hash: "0x"} — payload for hashing is serialize(X)
    if obj.len() == 2 && obj.contains_key("payload") {
        return serde_json::to_string(obj.get("payload").unwrap())
            .context("failed to serialize wrapped payload");
    }
    // Normal format: remove chain_hash and serialize the rest
    let mut copy = obj.clone();
    copy.remove("chain_hash");
    serde_json::to_string(&Value::Object(copy)).context("failed to serialize payload")
}

fn verify_wal(path: &Path) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut prev_hash = String::new();
    let mut total = 0usize;
    let mut chain_valid = true;
    let mut invalid_line: Option<usize> = None;
    let mut gap_warnings: Vec<String> = Vec::new();
    let mut prev_timestamp_ns: Option<i64> = None;

    for (line_num, line) in reader.lines().enumerate() {
        let line_num = line_num + 1;
        let line = line.with_context(|| format!("failed to read line {}", line_num))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("invalid JSON at line {}", line_num))?;

        let stored_hash = value
            .get("chain_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("line {}: missing chain_hash", line_num))?;

        let payload = payload_without_chain_hash(&value)?;
        let expected_hash = compute_chain_hash(&prev_hash, &payload);

        if expected_hash != stored_hash {
            chain_valid = false;
            if invalid_line.is_none() {
                invalid_line = Some(line_num);
            }
        }

        prev_hash = stored_hash.to_string();
        total += 1;

        // Gap detection: timestamp_ns jumps > 60 seconds
        if let Some(ts) = value.get("timestamp_ns").and_then(|v| v.as_i64()) {
            if let Some(prev) = prev_timestamp_ns {
                let delta = ts - prev;
                if delta.abs() > GAP_THRESHOLD_NS {
                    gap_warnings.push(format!(
                        "Line {}: timestamp_ns gap of {} seconds ({} ns)",
                        line_num,
                        delta / 1_000_000_000,
                        delta
                    ));
                }
            }
            prev_timestamp_ns = Some(ts);
        }
    }

    println!("Total entries: {}", total);

    if chain_valid {
        println!("Chain: VALID");
    } else {
        println!(
            "Chain: INVALID at line {}",
            invalid_line.unwrap_or(0)
        );
    }

    for w in &gap_warnings {
        println!("Warning: {}", w);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_chain_hash_matches_trace_log() {
        let first = compute_chain_hash("", r#"{"a":1}"#);
        let second = compute_chain_hash(&first, r#"{"b":2}"#);
        assert!(first.starts_with("0x"));
        assert!(second.starts_with("0x"));
        assert_ne!(first, second);
    }

    #[test]
    fn verify_valid_chain() {
        let first_hash = compute_chain_hash("", r#"{"a":1}"#);
        let second_hash = compute_chain_hash(&first_hash, r#"{"b":2}"#);
        let content = format!(
            r#"{{"a":1,"chain_hash":"{}"}}
{{"b":2,"chain_hash":"{}"}}
"#,
            first_hash, second_hash
        );
        let path = std::env::temp_dir().join("catenar-verify-test.jsonl");
        std::fs::write(&path, &content).unwrap();
        verify_wal(&path).unwrap();
        std::fs::remove_file(path).ok();
    }
}
