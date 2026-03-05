use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use reqwest::header::HeaderValue;
use serde_json::Value;
use std::sync::Arc;

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

#[async_trait]
trait KmsApi: Send + Sync {
    async fn sign_raw(
        &self,
        key_id: &str,
        message: Vec<u8>,
        signing_algorithm: SigningAlgorithmSpec,
    ) -> Result<Vec<u8>>;
    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>>;
}

struct AwsSdkKmsApi {
    client: aws_sdk_kms::Client,
}

#[async_trait]
impl KmsApi for AwsSdkKmsApi {
    async fn sign_raw(
        &self,
        key_id: &str,
        message: Vec<u8>,
        signing_algorithm: SigningAlgorithmSpec,
    ) -> Result<Vec<u8>> {
        let output = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(signing_algorithm)
            .send()
            .await
            .context("AWS KMS sign call failed")?;
        let signature = output
            .signature()
            .map(|s| s.as_ref().to_vec())
            .context("AWS KMS sign response missing signature")?;
        Ok(signature)
    }

    async fn get_public_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let output = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .context("AWS KMS get_public_key call failed")?;
        let public_key = output
            .public_key()
            .map(|k| k.as_ref().to_vec())
            .context("AWS KMS get_public_key response missing public_key")?;
        Ok(public_key)
    }
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

pub struct AwsKmsProvider {
    key_id: String,
    signing_algorithm: SigningAlgorithmSpec,
    public_key: Vec<u8>,
    api: Arc<dyn KmsApi>,
}

impl AwsKmsProvider {
    pub async fn new(key_id: String) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let api: Arc<dyn KmsApi> = Arc::new(AwsSdkKmsApi {
            client: aws_sdk_kms::Client::new(&config),
        });
        let signing_algorithm = kms_signing_algorithm_from_env()?;
        Self::new_with_api(key_id, signing_algorithm, api).await
    }

    async fn new_with_api(
        key_id: String,
        signing_algorithm: SigningAlgorithmSpec,
        api: Arc<dyn KmsApi>,
    ) -> Result<Self> {
        let public_key = api.get_public_key(&key_id).await?;
        Ok(Self {
            key_id,
            signing_algorithm,
            public_key,
            api,
        })
    }
}

#[async_trait]
impl KeyProvider for AwsKmsProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.api
            .sign_raw(
                &self.key_id,
                data.to_vec(),
                self.signing_algorithm.clone(),
            )
            .await
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

pub struct VaultProvider {
    mount_path: String,
    key_name: String,
    public_key: Vec<u8>,
    api: Arc<dyn VaultApi>,
}

#[async_trait]
trait VaultApi: Send + Sync {
    async fn sign(&self, mount_path: &str, key_name: &str, input_b64: String) -> Result<String>;
    async fn public_key(&self, mount_path: &str, key_name: &str) -> Result<Vec<u8>>;
}

struct ReqwestVaultApi {
    base_url: String,
    client: reqwest::Client,
}

impl ReqwestVaultApi {
    fn new(base_url: String, token: String) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-vault-token",
            HeaderValue::from_str(&token).context("VAULT_TOKEN contains invalid header chars")?,
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to build Vault HTTP client")?;
        Ok(Self {
            base_url,
            client,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[async_trait]
impl VaultApi for ReqwestVaultApi {
    async fn sign(&self, mount_path: &str, key_name: &str, input_b64: String) -> Result<String> {
        let url = self.endpoint(&format!("v1/{mount_path}/sign/{key_name}"));
        let res = self
            .client
            .post(url)
            .json(&serde_json::json!({ "input": input_b64 }))
            .send()
            .await
            .context("Vault Transit sign request failed")?;
        if !res.status().is_success() {
            anyhow::bail!("Vault Transit sign failed with status {}", res.status());
        }
        let body: Value = res
            .json()
            .await
            .context("failed to parse Vault Transit sign response JSON")?;
        let signature = body["data"]["signature"]
            .as_str()
            .map(|s| s.to_string())
            .context("Vault Transit sign response missing data.signature")?;
        Ok(signature)
    }

    async fn public_key(&self, mount_path: &str, key_name: &str) -> Result<Vec<u8>> {
        let url = self.endpoint(&format!("v1/{mount_path}/keys/{key_name}"));
        let res = self
            .client
            .get(url)
            .send()
            .await
            .context("Vault Transit key read request failed")?;
        if !res.status().is_success() {
            anyhow::bail!("Vault Transit key read failed with status {}", res.status());
        }
        let body: Value = res
            .json()
            .await
            .context("failed to parse Vault Transit key read response JSON")?;
        let latest = body["data"]["latest_version"]
            .as_i64()
            .context("Vault key response missing data.latest_version")?;
        let latest_key = latest.to_string();
        let public_key = body["data"]["keys"][&latest_key]["public_key"]
            .as_str()
            .context("Vault key response missing latest public_key")?;
        base64::engine::general_purpose::STANDARD
            .decode(public_key.as_bytes())
            .context("Vault public_key base64 decode failed")
    }
}

impl VaultProvider {
    pub async fn new(mount_path: String, key_name: String) -> Result<Self> {
        let addr = std::env::var("VAULT_ADDR").context("VAULT_ADDR required for VaultProvider")?;
        let token =
            std::env::var("VAULT_TOKEN").context("VAULT_TOKEN required for VaultProvider")?;
        let api: Arc<dyn VaultApi> = Arc::new(ReqwestVaultApi::new(addr, token)?);
        Self::new_with_api(mount_path, key_name, api).await
    }

    async fn new_with_api(
        mount_path: String,
        key_name: String,
        api: Arc<dyn VaultApi>,
    ) -> Result<Self> {
        let public_key = api.public_key(&mount_path, &key_name).await?;
        Ok(Self {
            mount_path,
            key_name,
            public_key,
            api,
        })
    }
}

#[async_trait]
impl KeyProvider for VaultProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let input_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let signature = self
            .api
            .sign(&self.mount_path, &self.key_name, input_b64)
            .await?;
        decode_vault_signature(&signature)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

fn kms_signing_algorithm_from_env() -> Result<SigningAlgorithmSpec> {
    let raw =
        std::env::var("AWS_KMS_SIGNING_ALGORITHM").unwrap_or_else(|_| "ECDSA_SHA_256".to_string());
    let alg = match raw.as_str() {
        "ECDSA_SHA_256" => SigningAlgorithmSpec::EcdsaSha256,
        "ECDSA_SHA_384" => SigningAlgorithmSpec::EcdsaSha384,
        "ECDSA_SHA_512" => SigningAlgorithmSpec::EcdsaSha512,
        "RSASSA_PKCS1_V1_5_SHA_256" => SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
        "RSASSA_PKCS1_V1_5_SHA_384" => SigningAlgorithmSpec::RsassaPkcs1V15Sha384,
        "RSASSA_PKCS1_V1_5_SHA_512" => SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
        "RSASSA_PSS_SHA_256" => SigningAlgorithmSpec::RsassaPssSha256,
        "RSASSA_PSS_SHA_384" => SigningAlgorithmSpec::RsassaPssSha384,
        "RSASSA_PSS_SHA_512" => SigningAlgorithmSpec::RsassaPssSha512,
        _ => anyhow::bail!("unsupported AWS_KMS_SIGNING_ALGORITHM={raw}"),
    };
    Ok(alg)
}

fn decode_vault_signature(signature: &str) -> Result<Vec<u8>> {
    let encoded = signature
        .rsplit(':')
        .next()
        .context("Vault signature missing base64 segment")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("Vault signature base64 decode failed")?;
    Ok(decoded)
}

pub async fn build_key_provider() -> Result<Arc<dyn KeyProvider>> {
    let provider = std::env::var("KEY_PROVIDER").unwrap_or_else(|_| "env".to_string());
    match provider.as_str() {
        "local" => {
            let allow = std::env::var("AEGIS_DEV_ALLOW_EPHEMERAL_KEY")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false);
            if !allow {
                anyhow::bail!("KEY_PROVIDER=local generates a new key on every start and invalidates all receipts. Set KEY_PROVIDER=env and AEGIS_SIGNING_KEY_HEX, or AEGIS_DEV_ALLOW_EPHEMERAL_KEY=1 for dev only.");
            }
            Ok(Arc::new(LocalKeyProvider::new_random()))
        }
        "env" => Ok(Arc::new(EnvKeyProvider::from_env()?)),
        "aws_kms" => {
            let key_id = std::env::var("AWS_KMS_KEY_ID")
                .context("AWS_KMS_KEY_ID required when KEY_PROVIDER=aws_kms")?;
            Ok(Arc::new(AwsKmsProvider::new(key_id).await?))
        }
        "vault" => {
            let mount_path = std::env::var("VAULT_MOUNT_PATH")
                .context("VAULT_MOUNT_PATH required when KEY_PROVIDER=vault")?;
            let key_name = std::env::var("VAULT_KEY_NAME")
                .context("VAULT_KEY_NAME required when KEY_PROVIDER=vault")?;
            Ok(Arc::new(VaultProvider::new(mount_path, key_name).await?))
        }
        _ => anyhow::bail!("unknown KEY_PROVIDER={provider}, expected local|env|aws_kms|vault"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use std::sync::Mutex;

    struct MockKmsApi {
        pub_key: Vec<u8>,
        sig: Vec<u8>,
        sign_calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait]
    impl KmsApi for MockKmsApi {
        async fn sign_raw(
            &self,
            key_id: &str,
            message: Vec<u8>,
            _signing_algorithm: SigningAlgorithmSpec,
        ) -> Result<Vec<u8>> {
            self.sign_calls
                .lock()
                .expect("sign_calls lock")
                .push((key_id.to_string(), message));
            Ok(self.sig.clone())
        }

        async fn get_public_key(&self, _key_id: &str) -> Result<Vec<u8>> {
            Ok(self.pub_key.clone())
        }
    }

    #[tokio::test]
    async fn aws_kms_provider_signs_using_api() {
        let api: Arc<dyn KmsApi> = Arc::new(MockKmsApi {
            pub_key: vec![1, 2, 3],
            sig: vec![9, 8, 7],
            sign_calls: Mutex::new(Vec::new()),
        });
        let provider = AwsKmsProvider::new_with_api(
            "kms-key".to_string(),
            SigningAlgorithmSpec::EcdsaSha256,
            api.clone(),
        )
        .await
        .expect("provider must construct");

        let sig = provider.sign(b"hello").await.expect("sign must succeed");
        assert_eq!(sig, vec![9, 8, 7]);
        assert_eq!(provider.public_key_bytes(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn vault_provider_uses_transit_http_api() {
        let server = MockServer::start_async().await;
        let key_read = server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/transit/keys/aegis-signing");
                then.status(200).json_body(serde_json::json!({
                    "data": {
                        "latest_version": 1,
                        "keys": {
                            "1": { "public_key": "cHVibGljLWtleQ==" }
                        }
                    }
                }));
            })
            .await;
        let sign = server
            .mock_async(|when, then| {
                when.method(POST).path("/v1/transit/sign/aegis-signing");
                then.status(200).json_body(serde_json::json!({
                    "data": { "signature": "vault:v1:c2lnLWJ5dGVz" }
                }));
            })
            .await;

        let api: Arc<dyn VaultApi> = Arc::new(
            ReqwestVaultApi::new(server.base_url(), "token-123".to_string())
                .expect("api create"),
        );
        let provider = VaultProvider::new_with_api(
            "transit".to_string(),
            "aegis-signing".to_string(),
            api,
        )
        .await
        .expect("provider create");

        let sig = provider.sign(b"payload").await.expect("sign");
        assert_eq!(sig, b"sig-bytes");
        assert_eq!(provider.public_key_bytes(), b"public-key");
        key_read.assert_async().await;
        sign.assert_async().await;
    }
}
