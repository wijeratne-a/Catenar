use std::{
    collections::HashMap,
    fmt as stdfmt,
    sync::{Mutex, OnceLock},
};

use anyhow::Result;
use opentelemetry::{
    global, metrics::{Counter, Histogram}, trace::TracerProvider as _, InstrumentationScope,
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{PeriodicReader, SdkMeterProvider},
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

struct Metrics {
    policy_violation: Counter<u64>,
    verification_success: Counter<u64>,
    identity_bound_verification: Counter<u64>,
    violation_rate: Counter<u64>,
    consecutive_violations: Histogram<u64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();
static CONSECUTIVE_VIOLATIONS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationType {
    UnknownPolicyCommitment,
    PolicyDenied,
    PolicyViolation,
}

impl ViolationType {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::UnknownPolicyCommitment => "unknown_policy_commitment",
            Self::PolicyDenied => "policy_denied",
            Self::PolicyViolation => "policy_violation",
        }
    }
}

impl stdfmt::Display for ViolationType {
    fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
        f.write_str(self.as_label())
    }
}

pub fn increment_policy_violation(domain: &str, violation_type: ViolationType) {
    if let Some(m) = METRICS.get() {
        let labels = [
            KeyValue::new("domain", domain.to_string()),
            KeyValue::new("violation_type", violation_type.to_string()),
        ];
        m.policy_violation.add(1, &labels);
        m.violation_rate.add(1, &labels);
        let streak = {
            let map = CONSECUTIVE_VIOLATIONS.get_or_init(|| Mutex::new(HashMap::new()));
            let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
            let key = format!("{domain}|{}", violation_type.as_label());
            let next = guard.get(&key).copied().unwrap_or(0).saturating_add(1);
            guard.insert(key, next);
            next
        };
        m.consecutive_violations.record(streak, &labels);
    }
}

pub fn increment_verification_success(domain: &str) {
    if let Some(m) = METRICS.get() {
        m.verification_success
            .add(1, &[KeyValue::new("domain", domain.to_string())]);
    }
}

pub fn increment_identity_bound(domain: &str) {
    if let Some(m) = METRICS.get() {
        m.identity_bound_verification
            .add(1, &[KeyValue::new("domain", domain.to_string())]);
    }
}

pub fn init_telemetry() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json_logs = std::env::var("CATENAR_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(true);
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "catenar-verifier".to_string());

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    if let Some(endpoint) = endpoint {
        let resource = Resource::new([KeyValue::new("service.name", service_name.clone())]);

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .build()?;

        let tracer_provider = TracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter, runtime::Tokio)
            .build();

        let tracer = tracer_provider.tracer_with_scope(InstrumentationScope::builder(service_name).build());
        global::set_tracer_provider(tracer_provider);

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let reader = PeriodicReader::builder(metric_exporter, runtime::Tokio).build();
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        global::set_meter_provider(meter_provider);
        let meter = global::meter("catenar-verifier");
        let _ = METRICS.set(Metrics {
            policy_violation: meter.u64_counter("catenar.policy_violation").build(),
            verification_success: meter.u64_counter("catenar.verification_success").build(),
            identity_bound_verification: meter
                .u64_counter("catenar.identity_bound_verification")
                .build(),
            violation_rate: meter.u64_counter("catenar.verifier.violation_rate").build(),
            consecutive_violations: meter
                .u64_histogram("catenar.verifier.consecutive_violations")
                .build(),
        });

        let init_result = if json_logs {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
        };
        if let Err(err) = init_result {
            return Err(anyhow::anyhow!("{err}"));
        }
    } else {
        let init_result = if json_logs {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .try_init()
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .try_init()
        };
        if let Err(err) = init_result {
            return Err(anyhow::anyhow!("{err}"));
        }
    }

    Ok(())
}
