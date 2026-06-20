//! End-to-end observability over the **real** OTLP pipeline.
//!
//! `#[ignore]`d by default — it needs the docker-compose topology up, including
//! the bundled `otel-lgtm` collector (Prometheus + Tempo + Loki). Real `tenants`
//! and `ddns` binaries export logs/metrics/traces over OTLP/HTTP to the collector;
//! this test queries the collector's HTTP query APIs (exposed to the host) and
//! asserts all three signals from the running services actually landed:
//!
//! - **metrics** (Prometheus): the `tenants` tombstone-sweep domain counter — it
//!   ticks every `TENANT_SWEEP_INTERVAL_SECS` unconditionally, so it appears
//!   without any seeded data.
//! - **logs** (Loki): startup/loop log lines tagged `service_name="wardnet-tenants"`.
//! - **traces** (Tempo): the `ddns` provisioner's work-queue reads are
//!   `#[tracing::instrument]`ed, so each reconcile tick emits a span for
//!   `service.name="wardnet-ddns"`.
//!
//! Run via the `source/Makefile` targets:
//!
//! ```sh
//! make e2e-all          # gen certs → build+up (incl. otel-lgtm) → run e2e tests → tear down
//! ```

use std::time::{Duration, Instant};

const POLL_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Poll `check` until it yields `true` or the timeout elapses; returns whether it
/// succeeded. `check` returns `Ok(true)` on a hit, `Ok(false)` to keep polling,
/// and `Err` (transient query failure, e.g. backend not ready) is treated as
/// keep-polling.
async fn poll_until<F, Fut>(label: &str, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<bool>>,
{
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        match check().await {
            Ok(true) => return true,
            Ok(false) => {}
            Err(e) => eprintln!("{label}: transient query error (retrying): {e}"),
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
#[ignore = "requires the docker-compose mesh harness incl. otel-lgtm (make e2e-all)"]
async fn services_export_metrics_logs_and_traces_over_otlp() {
    let prometheus = env_or("E2E_PROMETHEUS", "http://127.0.0.1:19090");
    let tempo = env_or("E2E_TEMPO", "http://127.0.0.1:13200");
    let loki = env_or("E2E_LOKI", "http://127.0.0.1:13100");
    let client = reqwest::Client::new();

    // ── metrics (Prometheus) ────────────────────────────────────────────────
    // The tombstone-sweep counter increments every sweep tick (2s), independent
    // of any seeded data. The series must also carry the INFORGE resource identity
    // promoted to a Prometheus label — `service_namespace` (Prometheus promotes the
    // identifying resource attrs; `region` lives on `target_info`, joined in Grafana).
    let c = client.clone();
    let url = format!("{prometheus}/api/v1/query");
    let metrics_ok = poll_until("metrics", || {
        let c = c.clone();
        let url = url.clone();
        async move {
            let body: serde_json::Value = c
                .get(&url)
                .query(&[("query", "tenants_tombstone_sweep_runs_total")])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            // A series whose resource identity landed as labels (service_namespace
            // from INFORGE_SERVICE_NAMESPACE, service_name from the service itself).
            Ok(body["data"]["result"].as_array().is_some_and(|series| {
                series.iter().any(|s| {
                    s["metric"]["service_name"] == "wardnet-tenants"
                        && s["metric"]["service_namespace"] == "wardnet"
                })
            }))
        }
    })
    .await;
    assert!(
        metrics_ok,
        "no `tenants_tombstone_sweep_runs_total{{service_namespace=\"wardnet\"}}` series in Prometheus \
         — metrics and/or the INFORGE resource labels did not reach the collector"
    );

    // ── logs (Loki) ─────────────────────────────────────────────────────────
    let c = client.clone();
    let url = format!("{loki}/loki/api/v1/query_range");
    let logs_ok = poll_until("logs", || {
        let c = c.clone();
        let url = url.clone();
        async move {
            let body: serde_json::Value = c
                .get(&url)
                .query(&[
                    ("query", "{service_name=\"wardnet-tenants\"}"),
                    ("limit", "5"),
                ])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Ok(body["data"]["result"]
                .as_array()
                .is_some_and(|r| !r.is_empty()))
        }
    })
    .await;
    assert!(
        logs_ok,
        "no `service_name=wardnet-tenants` log stream in Loki — logs did not reach the collector"
    );

    // ── traces (Tempo) ──────────────────────────────────────────────────────
    // The ddns provisioner's work-queue reads are instrumented spans.
    let c = client.clone();
    let url = format!("{tempo}/api/search");
    let traces_ok = poll_until("traces", || {
        let c = c.clone();
        let url = url.clone();
        async move {
            let body: serde_json::Value = c
                .get(&url)
                .query(&[
                    ("q", "{ resource.service.name = \"wardnet-ddns\" }"),
                    ("limit", "5"),
                ])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            Ok(body["traces"].as_array().is_some_and(|t| !t.is_empty()))
        }
    })
    .await;
    assert!(
        traces_ok,
        "no traces for service.name=wardnet-ddns in Tempo — traces did not reach the collector"
    );
}
