use anyhow::{Context, Result};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Arc;

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

pub struct LocalKeyProvider {
    key: SigningKey,
}

impl LocalKeyProvider {
    pub fn new_random() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }
}

pub struct EnvKeyProvider {
    key: SigningKey,
}

impl EnvKeyProvider {
    pub fn from_env() -> Result<Self> {
        let hex_key = std::env::var("AEGIS_SIGNING_KEY_HEX")
            .context("AEGIS_SIGNING_KEY_HEX missing for EnvKeyProvider")?;
        let raw = hex::decode(hex_key).context("AEGIS_SIGNING_KEY_HEX is invalid hex")?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .context("AEGIS_SIGNING_KEY_HEX must be 32 bytes")?;
        Ok(Self {
            key: SigningKey::from_bytes(&arr),
        })
    }
}

#[async_trait]
impl KeyProvider for EnvKeyProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }
}

pub fn build_key_provider() -> Result<Arc<dyn KeyProvider>> {
    let provider = std::env::var("KEY_PROVIDER").unwrap_or_else(|_| "local".to_string());
    match provider.as_str() {
        "local" => Ok(Arc::new(LocalKeyProvider::new_random())),
        "env" => Ok(Arc::new(EnvKeyProvider::from_env()?)),
        _ => anyhow::bail!("unknown KEY_PROVIDER={provider}, expected local|env"),
    }
}
