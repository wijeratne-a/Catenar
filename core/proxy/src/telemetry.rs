use std::{
    collections::HashMap,
    fmt as stdfmt,
    sync::{Mutex, OnceLock},
};

use anyhow::Result;
use opentelemetry::{
    global,
    metrics::{Counter, Histogram},
    trace::TracerProvider as _,
    InstrumentationScope, KeyValue,
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
    request: Counter<u64>,
    blocked: Counter<u64>,
    timeout: Counter<u64>,
    violation_rate: Counter<u64>,
    consecutive_violations: Histogram<u64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();
static CONSECUTIVE_VIOLATIONS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
static PROM_SNAPSHOT: OnceLock<Mutex<PrometheusSnapshot>> = OnceLock::new();

const HISTOGRAM_BUCKETS_MS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

#[derive(Default)]
struct HistogramState {
    bucket_counts: Vec<u64>,
    inf_count: u64,
    sum: f64,
    count: u64,
}

impl HistogramState {
    fn new() -> Self {
        Self {
            bucket_counts: vec![0; HISTOGRAM_BUCKETS_MS.len()],
            inf_count: 0,
            sum: 0.0,
            count: 0,
        }
    }

    fn record(&mut self, value_ms: f64) {
        let value = if value_ms.is_finite() {
            value_ms.max(0.0)
        } else {
            0.0
        };
        self.sum += value;
        self.count = self.count.saturating_add(1);
        let mut placed = false;
        for (idx, upper_bound) in HISTOGRAM_BUCKETS_MS.iter().enumerate() {
            if value <= *upper_bound {
                self.bucket_counts[idx] = self.bucket_counts[idx].saturating_add(1);
                placed = true;
                break;
            }
        }
        if !placed {
            self.inf_count = self.inf_count.saturating_add(1);
        }
    }
}

struct PrometheusSnapshot {
    enabled: bool,
    requests_total: u64,
    blocked_total: u64,
    timeout_total: u64,
    latency_ms: HistogramState,
    policy_eval_ms: HistogramState,
}

impl Default for PrometheusSnapshot {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_total: 0,
            blocked_total: 0,
            timeout_total: 0,
            latency_ms: HistogramState::new(),
            policy_eval_ms: HistogramState::new(),
        }
    }
}

fn with_snapshot_mut<F>(f: F)
where
    F: FnOnce(&mut PrometheusSnapshot),
{
    let snapshot = PROM_SNAPSHOT.get_or_init(|| Mutex::new(PrometheusSnapshot::default()));
    let mut guard = snapshot.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationType {
    SchemaValidation,
    ResponseInjection,
    SensitiveDataExposure,
    UnauthorizedDataMutation,
    MissingAuditTrace,
    PolicyViolation,
}

impl ViolationType {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SchemaValidation => "schema_validation",
            Self::ResponseInjection => "response_injection",
            Self::SensitiveDataExposure => "sensitive_data_exposure",
            Self::UnauthorizedDataMutation => "unauthorized_data_mutation",
            Self::MissingAuditTrace => "missing_audit_trace",
            Self::PolicyViolation => "policy_violation",
        }
    }
}

impl stdfmt::Display for ViolationType {
    fn fmt(&self, f: &mut stdfmt::Formatter<'_>) -> stdfmt::Result {
        f.write_str(self.as_label())
    }
}

pub fn increment_request(host: &str) {
    with_snapshot_mut(|s| {
        s.requests_total = s.requests_total.saturating_add(1);
    });
    if let Some(m) = METRICS.get() {
        m.request.add(1, &[KeyValue::new("host", host.to_string())]);
    }
}

pub fn increment_blocked(host: &str, violation_type: ViolationType) {
    with_snapshot_mut(|s| {
        s.blocked_total = s.blocked_total.saturating_add(1);
    });
    if let Some(m) = METRICS.get() {
        let labels = [
            KeyValue::new("host", host.to_string()),
            KeyValue::new("violation_type", violation_type.to_string()),
        ];
        m.blocked.add(1, &labels);
        m.violation_rate.add(1, &labels);

        let streak = {
            let map = CONSECUTIVE_VIOLATIONS.get_or_init(|| Mutex::new(HashMap::new()));
            let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
            let key = format!("{host}|{}", violation_type.as_label());
            let next = guard.get(&key).copied().unwrap_or(0).saturating_add(1);
            guard.insert(key, next);
            next
        };
        m.consecutive_violations.record(streak, &labels);
    }
}

pub fn increment_timeout(host: &str) {
    with_snapshot_mut(|s| {
        s.timeout_total = s.timeout_total.saturating_add(1);
    });
    if let Some(m) = METRICS.get() {
        m.timeout.add(1, &[KeyValue::new("host", host.to_string())]);
    }
}

pub fn set_metrics_enabled(enabled: bool) {
    with_snapshot_mut(|s| {
        s.enabled = enabled;
    });
}

pub fn observe_latency_ms(value_ms: f64) {
    with_snapshot_mut(|s| {
        s.latency_ms.record(value_ms);
    });
}

pub fn observe_policy_eval_ms(value_ms: f64) {
    with_snapshot_mut(|s| {
        s.policy_eval_ms.record(value_ms);
    });
}

fn render_histogram(out: &mut String, metric: &str, state: &HistogramState) {
    let mut cumulative = 0u64;
    for (idx, le) in HISTOGRAM_BUCKETS_MS.iter().enumerate() {
        cumulative = cumulative.saturating_add(state.bucket_counts[idx]);
        out.push_str(&format!("{metric}_bucket{{le=\"{le}\"}} {cumulative}\n"));
    }
    let inf_cumulative = cumulative.saturating_add(state.inf_count);
    out.push_str(&format!(
        "{metric}_bucket{{le=\"+Inf\"}} {inf_cumulative}\n"
    ));
    out.push_str(&format!("{metric}_sum {}\n", state.sum));
    out.push_str(&format!("{metric}_count {}\n", state.count));
}

fn histogram_p95_ms(state: &HistogramState) -> f64 {
    if state.count == 0 {
        return 0.0;
    }
    let target_rank = (state.count as f64 * 0.95).ceil() as u64;
    let mut cumulative = 0u64;
    for (idx, le) in HISTOGRAM_BUCKETS_MS.iter().enumerate() {
        cumulative = cumulative.saturating_add(state.bucket_counts[idx]);
        if cumulative >= target_rank {
            return *le;
        }
    }
    HISTOGRAM_BUCKETS_MS.last().copied().unwrap_or(0.0)
}

pub fn render_prometheus_text() -> Option<String> {
    let snapshot = PROM_SNAPSHOT.get_or_init(|| Mutex::new(PrometheusSnapshot::default()));
    let guard = snapshot.lock().unwrap_or_else(|e| e.into_inner());
    if !guard.enabled {
        return None;
    }
    let mut out = String::new();
    out.push_str("# TYPE catenar_proxy_requests_total counter\n");
    out.push_str(&format!(
        "catenar_proxy_requests_total {}\n",
        guard.requests_total
    ));
    out.push_str("# TYPE catenar_proxy_blocked_total counter\n");
    out.push_str(&format!(
        "catenar_proxy_blocked_total {}\n",
        guard.blocked_total
    ));
    out.push_str("# TYPE catenar_proxy_timeout_total counter\n");
    out.push_str(&format!(
        "catenar_proxy_timeout_total {}\n",
        guard.timeout_total
    ));
    out.push_str("# TYPE catenar_proxy_latency_ms_bucket histogram\n");
    render_histogram(&mut out, "catenar_proxy_latency_ms", &guard.latency_ms);
    out.push_str("# TYPE catenar_proxy_policy_eval_ms_bucket histogram\n");
    render_histogram(
        &mut out,
        "catenar_proxy_policy_eval_ms",
        &guard.policy_eval_ms,
    );
    out.push_str("# TYPE catenar_proxy_policy_eval_p95_ms gauge\n");
    out.push_str(&format!(
        "catenar_proxy_policy_eval_p95_ms {}\n",
        histogram_p95_ms(&guard.policy_eval_ms)
    ));
    Some(out)
}

pub fn init_telemetry() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json_logs = std::env::var("CATENAR_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "catenar-proxy".to_string());

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    if let Some(endpoint) = endpoint {
        let resource = Resource::new([KeyValue::new("service.name", service_name.clone())]);

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone())
            .build()?;

        let tracer_provider = TracerProvider::builder()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                1.0,
            ))))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter, runtime::Tokio)
            .build();

        let tracer =
            tracer_provider.tracer_with_scope(InstrumentationScope::builder(service_name).build());
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
        let meter = global::meter("catenar-proxy");
        let _ = METRICS.set(Metrics {
            request: meter.u64_counter("catenar.proxy.request").build(),
            blocked: meter.u64_counter("catenar.proxy.blocked").build(),
            timeout: meter.u64_counter("catenar.proxy.timeout").build(),
            violation_rate: meter.u64_counter("catenar.proxy.violation_rate").build(),
            consecutive_violations: meter
                .u64_histogram("catenar.proxy.consecutive_violations")
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
