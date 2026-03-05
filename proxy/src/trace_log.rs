use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Clone)]
pub struct TraceLogger {
    path: PathBuf,
}

impl TraceLogger {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create WAL directory {}", parent.display()))?;
        }
        Ok(Self { path })
    }

    pub fn append<T: Serialize>(&self, value: &T) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open trace log {}", self.path.display()))?;

        let line = serde_json::to_string(value).context("failed to serialize trace log entry")?;
        file.write_all(line.as_bytes())
            .context("failed to write trace entry")?;
        file.write_all(b"\n")
            .context("failed to terminate trace entry line")?;
        file.flush().context("failed to flush trace WAL")?;
        Ok(())
    }
}
