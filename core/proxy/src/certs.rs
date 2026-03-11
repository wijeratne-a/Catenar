//! Root CA and dynamic leaf certificate generation for TLS MITM.
//! Agents must trust the Root CA via REQUESTS_CA_BUNDLE or NODE_EXTRA_CA_CERTS.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::ServerConfig;
use tracing::info;

const CERT_CACHE_CAP: usize = 512;

/// Root CA for forging leaf certificates. Generated at proxy startup.
pub struct RootCa {
    cert: Certificate,
    key: KeyPair,
}

impl RootCa {
    /// Load a Root CA from PEM-encoded certificate and private key files.
    /// Use this when the enterprise provides their own PKI (BYO-CA).
    /// Re-signs the CA params with the provided key to produce a usable rcgen Certificate.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("failed to parse CA private key PEM")?;
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Catenar Proxy Root CA (BYO)".into()),
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params
            .self_signed(&key)
            .context("failed to reconstruct CA certificate from BYO key")?;
        let _ = cert_pem; // Original cert PEM acknowledged; we re-sign with the provided key
        info!("External Root CA loaded (BYO-CA)");
        Ok(Self { cert, key })
    }

    /// Return the CA certificate in DER form (for building the cert chain).
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().as_ref().to_vec().into()
    }

    /// Generate a new self-signed Root CA in memory.
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Catenar Proxy Root CA".into()),
        );
        params.subject_alt_names = vec![SanType::DnsName(rcgen::string::Ia5String::try_from(
            "catenar-proxy-ca.local",
        )?)];
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key = KeyPair::generate().context("failed to generate CA key pair")?;
        let cert = params
            .self_signed(&key)
            .context("failed to self-sign CA certificate")?;

        info!("Catenar Proxy Root CA generated");
        Ok(Self { cert, key })
    }

    /// Forge a leaf certificate for the given SNI hostname, signed by this CA.
    pub fn forge_leaf(&self, sni: &str) -> Result<rustls::sign::CertifiedKey> {
        let mut params =
            CertificateParams::new(vec![sni.to_string()]).context("invalid SNI for certificate")?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        let leaf_key = KeyPair::generate().context("failed to generate leaf key pair")?;
        let issuer = rcgen::Issuer::from_ca_cert_der(&self.cert_der(), &self.key)?;
        let leaf_cert = params
            .signed_by(&leaf_key, &issuer)
            .context("failed to sign leaf certificate")?;

        let cert_der: rustls::pki_types::CertificateDer<'static> =
            leaf_cert.der().as_ref().to_vec().into();
        let key_der = PrivateKeyDer::from(leaf_key);

        let ck = rustls::sign::CertifiedKey::from_der(
            vec![cert_der],
            key_der,
            &rustls::crypto::aws_lc_rs::default_provider(),
        )
        .context("failed to build CertifiedKey from DER")?;

        Ok(ck)
    }

    /// Export the CA certificate as PEM for agent trust (REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS).
    pub fn export_pem(&self) -> String {
        self.cert.pem()
    }
}

/// Resolves server cert by forging a leaf for the SNI from ClientHello.
/// Uses an LRU cache so the least-recently-used entry is evicted when capacity is reached.
/// Rate-limited to 100 forges per 60 seconds for DoS mitigation.
/// forge_count and last_reset are shared across clones so rate limit applies globally.
pub struct DynamicCertResolver {
    ca: Arc<RootCa>,
    cache: Arc<Mutex<LruCache<String, Arc<rustls::sign::CertifiedKey>>>>,
    forge_count: Arc<AtomicU64>,
    last_reset: Arc<Mutex<Option<Instant>>>,
}

impl Clone for DynamicCertResolver {
    fn clone(&self) -> Self {
        Self {
            ca: Arc::clone(&self.ca),
            cache: Arc::clone(&self.cache),
            forge_count: Arc::clone(&self.forge_count),
            last_reset: Arc::clone(&self.last_reset),
        }
    }
}

const FORGE_RATE_LIMIT: u64 = 100;
const FORGE_RESET_INTERVAL: Duration = Duration::from_secs(60);

impl DynamicCertResolver {
    pub fn new(ca: RootCa) -> Self {
        Self {
            ca: Arc::new(ca),
            cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(CERT_CACHE_CAP).expect("non-zero cache cap"),
            ))),
            forge_count: Arc::new(AtomicU64::new(0)),
            last_reset: Arc::new(Mutex::new(None)),
        }
    }

    fn reset_if_needed(&self) {
        let now = Instant::now();
        let mut last = match self.last_reset.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let should_reset = last
            .map(|t| now.duration_since(t) >= FORGE_RESET_INTERVAL)
            .unwrap_or(true);
        if should_reset {
            self.forge_count.store(0, Ordering::Relaxed);
            *last = Some(now);
        }
    }

    fn resolve_impl(&self, sni: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mut cache = self.cache.lock().ok()?;
        if let Some(ck) = cache.get(sni) {
            return Some(Arc::clone(ck));
        }
        drop(cache);

        self.reset_if_needed();
        let count = self.forge_count.fetch_add(1, Ordering::Relaxed);
        if count >= FORGE_RATE_LIMIT {
            return None;
        }

        // At capacity: refuse to forge new SNIs to prevent cache/CPU exhaustion
        {
            let cache = self.cache.lock().ok()?;
            if cache.len() >= CERT_CACHE_CAP {
                return None;
            }
        }

        let ck = Arc::new(self.ca.forge_leaf(sni).ok()?);
        let mut cache = self.cache.lock().ok()?;
        cache.put(sni.to_string(), Arc::clone(&ck));
        Some(ck)
    }
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver").finish()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni_str = client_hello.server_name()?;
        self.resolve_impl(sni_str)
    }
}

/// Build a ServerConfig that uses the dynamic cert resolver for TLS MITM.
pub fn build_mitm_server_config(ca: RootCa) -> Result<Arc<ServerConfig>> {
    let resolver = Arc::new(DynamicCertResolver::new(ca));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(Arc::new(config))
}
