//! Integration test for the OTLP pipeline end-to-end: stand up an in-process
//! OTLP/HTTP receiver, point `telemetry::init` at it, emit one of each signal,
//! flush by dropping the guard, and assert the receiver saw all three exports.
//!
//! This exercises the OTLP machinery a unit test can't reach — `init` /
//! `build_enabled` (the three exporter builds + the layered subscriber), the
//! resource/auth assembly, and the `TelemetryGuard` `Drop` flush — without a real
//! collector or Docker. It is its own test binary because `init` installs the
//! process-global subscriber + tracer/meter/logger providers exactly once.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::net::TcpListener;

/// Per-signal receipt counters for the fake OTLP/HTTP collector.
#[derive(Clone, Default)]
struct Hits {
    traces: Arc<AtomicUsize>,
    metrics: Arc<AtomicUsize>,
    logs: Arc<AtomicUsize>,
}

async fn on_traces(State(h): State<Hits>) -> StatusCode {
    h.traces.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}
async fn on_metrics(State(h): State<Hits>) -> StatusCode {
    h.metrics.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}
async fn on_logs(State(h): State<Hits>) -> StatusCode {
    h.logs.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

// Multi-threaded: `drop(guard)` blocks one worker flushing the exporters, so the
// receiver must be able to serve their POSTs on another worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_pipeline_exports_traces_metrics_and_logs() {
    let hits = Hits::default();
    let app = Router::new()
        .route("/v1/traces", post(on_traces))
        .route("/v1/metrics", post(on_metrics))
        .route("/v1/logs", post(on_logs))
        .with_state(hits.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Point the (opt-in) exporter at the in-process receiver; no auth token so the
    // unauthenticated-collector path is exercised. `init` reads these on this thread
    // before any exporter thread is spawned, so the set_var is safe here.
    unsafe {
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", format!("http://{addr}"));
        std::env::remove_var("OTEL_AUTH_TOKEN_PATH");
        std::env::set_var("RUST_LOG", "info");
        std::env::set_var("OTEL_TRACES_FILTER", "info");
    }

    let guard = wardnet_common::telemetry::init("wardnet-test", "0.0.0");

    // One of each signal: a span (→ trace), an event inside it (→ log via the
    // appender bridge), and a counter (→ metric).
    {
        let span = tracing::info_span!("integration-span");
        let _enter = span.enter();
        tracing::info!(test = true, "integration log line");
    }
    opentelemetry::global::meter(wardnet_common::telemetry::SCOPE)
        .u64_counter("test.integration.counter")
        .build()
        .add(1, &[]);

    // Dropping the guard force-flushes + shuts down all three providers (blocking).
    drop(guard);

    // Shutdown flush is synchronous, but allow brief slack for the receiver to
    // record the POSTs before asserting.
    for _ in 0..50 {
        if hits.traces.load(Ordering::SeqCst) >= 1
            && hits.metrics.load(Ordering::SeqCst) >= 1
            && hits.logs.load(Ordering::SeqCst) >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        hits.traces.load(Ordering::SeqCst) >= 1,
        "no trace export received"
    );
    assert!(
        hits.metrics.load(Ordering::SeqCst) >= 1,
        "no metric export received"
    );
    assert!(
        hits.logs.load(Ordering::SeqCst) >= 1,
        "no log export received"
    );
}
