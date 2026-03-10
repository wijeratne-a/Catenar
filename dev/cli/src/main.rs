use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::AsyncSeekExt;
use tokio::signal;

#[derive(Parser)]
#[command(name = "catenar")]
#[command(about = "Catenar debug CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
}

#[derive(Subcommand)]
enum DebugCommands {
    /// Watch the trace WAL file and print new entries
    Watch {
        /// Proxy URL (e.g. http://localhost:8080)
        #[arg(long, default_value = "http://localhost:8080")]
        proxy: String,

        /// Path to the trace WAL file
        #[arg(long, default_value = "./data/proxy-trace.jsonl")]
        trace_wal: PathBuf,

        /// Print full chain_hash instead of truncated
        #[arg(long)]
        full_hash: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Debug {
            command: DebugCommands::Watch {
                proxy: _,
                trace_wal,
                full_hash,
            },
        } => run_watch(trace_wal, full_hash).await?,
    }

    Ok(())
}

async fn run_watch(trace_wal: PathBuf, full_hash: bool) -> Result<()> {
    loop {
        match File::open(&trace_wal).await {
            Ok(file) => {
                let mut file = file;
                let _ = file.seek(SeekFrom::End(0)).await;
                let mut reader = BufReader::new(file);

                loop {
                    tokio::select! {
                        _ = signal::ctrl_c() => {
                            return Ok(());
                        }
                        result = read_and_process_line(&mut reader, full_hash) => {
                            match result {
                                Ok(Some(())) => {}
                                Ok(None) => {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("Waiting for trace file...");
                tokio::select! {
                    _ = signal::ctrl_c() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    }
}

async fn read_and_process_line(
    reader: &mut BufReader<File>,
    full_hash: bool,
) -> Result<Option<()>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }

    let line = line.trim_end_matches('\n').trim_end_matches('\r');
    if line.is_empty() {
        return Ok(Some(()));
    }

    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Ok(Some(())),
    };

    let timestamp = v
        .get("timestamp_ns")
        .and_then(|t| t.as_i64())
        .map(|ns| format!("{}", ns / 1_000_000_000))
        .unwrap_or_else(|| "-".to_string());
    let request_id = v
        .get("request_id")
        .and_then(|r| r.as_str())
        .unwrap_or("-");
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("-");
    let target = v
        .get("target")
        .and_then(|t| t.as_str())
        .unwrap_or("-");
    let blocked = v
        .get("blocked")
        .and_then(|b| b.as_bool())
        .map(|b| if b { "yes" } else { "no" })
        .unwrap_or("-");
    let enforcement = v
        .get("enforcement")
        .and_then(|e| e.as_str())
        .unwrap_or("-");
    let chain_hash = v
        .get("chain_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("-");
    let chain_hash_display = if full_hash || chain_hash == "-" {
        chain_hash.to_string()
    } else if chain_hash.len() > 12 {
        format!("{}...", &chain_hash[..12])
    } else {
        chain_hash.to_string()
    };

    println!(
        "{} | {} | {} | {} | blocked={} | enforcement={} | chain_hash={}",
        timestamp, request_id, method, target, blocked, enforcement, chain_hash_display
    );

    Ok(Some(()))
}
