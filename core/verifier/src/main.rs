use aegis_api::{keys, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(keys::build_key_provider().await?).await
}
