//! Aegis Enterprise Verifier - uses KMS/Vault when configured, falls back to Open Core providers.

use std::sync::Arc;

use aegis_api::{keys, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = match aegis_enterprise_keys::build_key_provider_enterprise().await? {
        Some(p) => p,
        None => keys::build_key_provider().await?,
    };
    run(provider).await
}
