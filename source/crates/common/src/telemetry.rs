//! Observability: OpenTelemetry logs + metrics + traces over OTLP.
//!
//! Every service calls [`init`] once at startup instead of building a
//! `tracing_subscriber` registry by hand. Instrumentation is **opt-in by
//! endpoint**: with `OTEL_EXPORTER_OTLP_ENDPOINT` unset the services keep the
//! exact stdout-JSON logging they had before (no exporter, no behaviour change
//! for dev/e2e). With it set, the existing `tracing` events/spans are bridged
//! onto OTLP pipelines and shipped to an OTLP backend (Grafana Cloud's free
//! OTLP gateway in production; a local `grafana/otel-lgtm` for verification).
//!
//! Vendor-neutral on purpose: the backend is a single env var, so switching
//! from Grafana Cloud to a self-hosted collector never touches code.
//!
//! ## Secrets (invariant #9)
//!
//! The Grafana Cloud OTLP gateway authenticates with HTTP Basic
//! (`base64(instanceID:token)`). The credential is read from the tmpfs file at
//! `OTEL_AUTH_TOKEN_PATH` (inforge-projected) via [`config::read_secret_file`]
//! and assembled into an `Authorization` header here — never passed through an
//! env var.
//!
//! ## Signals
//!
//! - **logs** — `tracing` events are mirrored to OTLP via
//!   [`OpenTelemetryTracingBridge`] (and still printed as JSON to stdout).
//! - **traces** — `tracing` spans become OTLP spans via [`tracing_opentelemetry`];
//!   the HTTP layer + `#[tracing::instrument]` give them shape, and the W3C
//!   propagator carries context across the mesh HTTP hops.
//! - **metrics** — RED metrics from [`http_metrics`] plus per-service domain
//!   instruments built off [`opentelemetry::global::meter`].

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use base64::Engine as _;
use opentelemetry::metrics::Histogram;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config;

/// The instrumentation scope name shared by every meter/tracer in the cloud
/// services (the OTLP `scope.name`).
pub const SCOPE: &str = "wardnet";

/// Upper bound on each provider's final flush at process exit. Caps how long a
/// slow or unreachable collector can stall shutdown — without it, the blocking
/// exporter could hang the exit path waiting on the network.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Held for the lifetime of `main`; flushes and shuts down the OTLP pipelines on
/// drop so the final batch is never lost when the process exits. When the OTLP
/// endpoint is unset this is the `Disabled` variant and `Drop` is a no-op.
#[must_use = "hold the guard for the lifetime of `main`; dropping it flushes telemetry"]
pub enum TelemetryGuard {
    /// No OTLP endpoint configured — stdout JSON logging only.
    Disabled,
    /// OTLP exporters live; shut down in `Drop`.
    Enabled {
        tracer: SdkTracerProvider,
        meter: SdkMeterProvider,
        logger: SdkLoggerProvider,
    },
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let TelemetryGuard::Enabled {
            tracer,
            meter,
            logger,
        } = self
        {
            // Best-effort flush on shutdown, time-bounded so an unreachable
            // collector can't hang the exit path; a failure must not panic, so we
            // only log it.
            if let Err(e) = tracer.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
                tracing::warn!(error = %e, "tracer provider shutdown failed");
            }
            if let Err(e) = meter.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
                tracing::warn!(error = %e, "meter provider shutdown failed");
            }
            if let Err(e) = logger.shutdown_with_timeout(SHUTDOWN_TIMEOUT) {
                tracing::warn!(error = %e, "logger provider shutdown failed");
            }
        }
    }
}

/// Initialise telemetry for a service. Call exactly once, early in `main`, and
/// keep the returned guard bound for the whole process lifetime.
///
/// `service_name` is the OTLP `service.name` (e.g. `"wardnet-tenants"`);
/// `service_version` is typically `env!("CARGO_PKG_VERSION")`.
///
/// Reads:
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` — OTLP/HTTP base URL. **Unset ⇒ disabled.**
/// - `OTEL_AUTH_TOKEN_PATH` — optional tmpfs path to `instanceID:token` for
///   Grafana Cloud Basic auth (omit for an unauthenticated local collector).
/// - `RUST_LOG` — filters the **log** signals only (stdout JSON + OTLP logs).
/// - `OTEL_TRACES_FILTER` — filters the **trace** signal independently of log
///   verbosity (default `info`). Traces are a separate axis from log level: this
///   is per-layer so dropping `RUST_LOG` to `warn` never silently kills traces,
///   and raising it to `debug` never floods the trace backend. Trace *volume* is
///   a sampler concern (a later knob), not a severity concern.
/// - Resource attributes (best-effort, INFORGE-injected — see the env contract in
///   `resource`): `INFORGE_SERVICE_NAMESPACE` → `service.namespace`,
///   `INFORGE_INSTANCE_ID` → `service.instance.id`, `INFORGE_HOST_ID` → `host.id`,
///   `INFORGE_DEPLOYMENT_ENV` → `deployment.environment.name`,
///   `INFORGE_DEPLOYMENT_REGION_SLUG` → `region`.
pub fn init(service_name: &'static str, service_version: &'static str) -> TelemetryGuard {
    // The W3C propagator is harmless when disabled and required when enabled, so
    // set it unconditionally — the inbound/outbound mesh middlewares use it.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|e| !e.trim().is_empty());

    let Some(endpoint) = endpoint else {
        // Disabled: today's exact behaviour — JSON logs to stdout, nothing else.
        tracing_subscriber::registry()
            .with(fmt::layer().json())
            .with(env_filter())
            .init();
        tracing::info!("telemetry: OTLP disabled (OTEL_EXPORTER_OTLP_ENDPOINT unset)");
        return TelemetryGuard::Disabled;
    };

    match build_enabled(&endpoint, service_name, service_version) {
        Ok(guard) => {
            tracing::info!(endpoint = %endpoint, service = service_name, "telemetry: OTLP enabled");
            guard
        }
        Err(e) => {
            // Never let an observability misconfiguration take the service down:
            // fall back to stdout logging and carry on.
            tracing_subscriber::registry()
                .with(fmt::layer().json())
                .with(env_filter())
                .init();
            tracing::error!(error = %e, "telemetry: OTLP setup failed; falling back to stdout logs");
            TelemetryGuard::Disabled
        }
    }
}

/// The log filter (`RUST_LOG`, default `info`) — governs the stdout JSON and OTLP
/// log layers. `EnvFilter` is not `Clone`, so build a fresh one per layer.
fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// The trace filter (`OTEL_TRACES_FILTER`, default `info`) — governs the
/// spans-as-traces layer, independent of `RUST_LOG`.
fn trace_filter() -> EnvFilter {
    std::env::var("OTEL_TRACES_FILTER")
        .ok()
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new("info"))
}

/// Build the three OTLP pipelines and install the layered subscriber.
fn build_enabled(
    endpoint: &str,
    service_name: &'static str,
    service_version: &'static str,
) -> anyhow::Result<TelemetryGuard> {
    let base = endpoint.trim_end_matches('/');
    let headers = auth_headers()?;
    let resource = resource(service_name, service_version);

    // Traces ----------------------------------------------------------------
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/traces"))
        .with_headers(headers.clone())
        .build()?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    // Metrics ---------------------------------------------------------------
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/metrics"))
        .with_headers(headers.clone())
        .build()?;
    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource.clone())
        .build();
    global::set_meter_provider(meter_provider.clone());

    // Logs ------------------------------------------------------------------
    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{base}/v1/logs"))
        .with_headers(headers)
        .build()?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
        .with_resource(resource)
        .build();

    // Subscriber with **per-layer** filters so logs and traces are independent axes
    // (not one global EnvFilter gating everything): the log layers — stdout JSON
    // (kept for the container runtime) + the OTLP events-as-logs bridge — follow
    // `RUST_LOG`, while the spans-as-traces layer follows `OTEL_TRACES_FILTER`. So a
    // quiet `RUST_LOG=warn` no longer silently drops HTTP traces.
    let tracer = tracer_provider.tracer(SCOPE);
    let otel_logs = OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry()
        .with(fmt::layer().json().with_filter(env_filter()))
        .with(otel_logs.with_filter(env_filter()))
        .with(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(trace_filter()),
        )
        .init();

    Ok(TelemetryGuard::Enabled {
        tracer: tracer_provider,
        meter: meter_provider,
        logger: logger_provider,
    })
}

/// The OTLP `Resource` — identity attributes attached to every signal.
fn resource(service_name: &'static str, service_version: &'static str) -> Resource {
    // Resource attributes are constant per process and attach to every signal. The
    // deployment-identity ones are injected by INFORGE in production (the env-var
    // contract below); each is best-effort — a missing/empty var is simply omitted
    // so a deploy without it still starts (the signal just lacks that label).
    // Per-request attributes (route, tenant id, …) belong on spans/logs, never here.
    let mut builder = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new("service.version", service_version));
    for (attribute, env_var) in [
        ("service.namespace", "INFORGE_SERVICE_NAMESPACE"),
        ("service.instance.id", "INFORGE_INSTANCE_ID"),
        ("host.id", "INFORGE_HOST_ID"),
        ("deployment.environment.name", "INFORGE_DEPLOYMENT_ENV"),
        ("region", "INFORGE_DEPLOYMENT_REGION_SLUG"),
    ] {
        match std::env::var(env_var) {
            Ok(value) if !value.is_empty() => {
                builder = builder.with_attribute(KeyValue::new(attribute, value));
            }
            _ => {}
        }
    }
    builder.build()
}

/// Build the Basic-auth header from the tmpfs credential file, if configured.
/// Absent `OTEL_AUTH_TOKEN_PATH` ⇒ no auth header (local collector).
fn auth_headers() -> anyhow::Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    if std::env::var_os("OTEL_AUTH_TOKEN_PATH").is_some() {
        let credential = config::read_secret_file("OTEL_AUTH_TOKEN_PATH")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(credential.trim());
        headers.insert("Authorization".to_owned(), format!("Basic {encoded}"));
    }
    Ok(headers)
}

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

/// Install the standard observability layer stack on a service router, before
/// `.with_state(...)`: RED metrics, inbound trace-context extraction, and an
/// **INFO-level** request span (so traces survive the default `info` filters —
/// `tower_http`'s default span level is DEBUG, which the info filter drops). The
/// layer order/levels live here once rather than copy-pasted per service, so a
/// future change is made in a single place.
pub fn install_http_layers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // `.layer()` applies outside-in, so the last layer is outermost on the request
    // path: TraceLayer opens the span, `extract_trace_context` adopts any
    // propagated parent, then `http_metrics` records RED metrics. All three pass
    // the `Request` through untouched, preserving the `OnUpgrade` extension the
    // tunnel WebSocket handshake depends on (invariant #10).
    router
        .layer(from_fn(http_metrics))
        .layer(from_fn(extract_trace_context))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(tracing::Level::INFO)),
        )
}

/// The RED request-duration histogram, built once on first use. Boundaries are
/// the `http.server` semantic-convention **seconds** buckets — the SDK's default
/// boundaries are millisecond-scale, which would collapse essentially all traffic
/// into the first bucket and leave the latency histogram with no resolution.
fn request_duration() -> &'static Histogram<f64> {
    static HISTOGRAM: OnceLock<Histogram<f64>> = OnceLock::new();
    HISTOGRAM.get_or_init(|| {
        global::meter(SCOPE)
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .with_description("Duration of inbound HTTP requests.")
            .with_boundaries(vec![
                0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
            ])
            .build()
    })
}

/// Axum middleware recording RED metrics for every request: the
/// `http.server.request.duration` histogram (seconds) labelled with the matched
/// route template, method, and status code.
///
/// **Cardinality discipline (plan §5a):** labels are bounded only — the matched
/// route *template* (never the raw path, which embeds tenant/network IDs),
/// method, and status code. Never add an unbounded identifier here.
pub async fn http_metrics(matched: Option<MatchedPath>, req: Request, next: Next) -> Response {
    // The route template (`/v1/networks/{id}`), not the concrete path. Requests
    // that match no route collapse to a single bounded bucket.
    let route = matched
        .as_ref()
        .map_or("<unmatched>", MatchedPath::as_str)
        .to_owned();
    let method = req.method().as_str().to_owned();

    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    let status = i64::from(response.status().as_u16());

    request_duration().record(
        elapsed,
        &[
            KeyValue::new("http.request.method", method),
            KeyValue::new("http.route", route),
            KeyValue::new("http.response.status_code", status),
        ],
    );

    response
}

/// Axum middleware that extracts a propagated W3C trace context from the inbound
/// request headers and sets it as the parent of the current request span, so a
/// trace started in one service continues across the mesh HTTP hop. Mount it
/// *inside* the `TraceLayer` (so a span already exists).
pub async fn extract_trace_context(req: Request, next: Next) -> Response {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&opentelemetry_http::HeaderExtractor(req.headers()))
    });
    let _ = tracing::Span::current().set_parent(parent);
    next.run(req).await
}

/// Inject the current span's W3C trace context into an outbound `reqwest`
/// request's headers, so the receiving service can continue the trace. Use on
/// the mesh HTTP clients (DDNS work-queue, Tunneller routing-policy reads).
#[must_use]
pub fn inject_trace_context(mut request: reqwest::Request) -> reqwest::Request {
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(
            &context,
            &mut opentelemetry_http::HeaderInjector(request.headers_mut()),
        );
    });
    request
}

#[cfg(test)]
mod tests;
