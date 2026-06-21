//! Unit tests for the observability HTTP layer stack. Telemetry is *disabled*
//! here (no `init` call, so the global meter/tracer are the no-op defaults), so
//! these exercise the middleware control flow — routing, the `<unmatched>` route
//! label, trace-context extraction — without standing up an OTLP backend.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt as _; // oneshot

use super::{install_http_layers, request_duration};

async fn ok() -> &'static str {
    "ok"
}

/// A router with one matched route, wrapped in the standard observability stack.
fn app() -> Router {
    install_http_layers(Router::new().route("/v1/health", get(ok)))
}

async fn send(req: Request<Body>) -> StatusCode {
    app().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn matched_request_passes_through_the_layer_stack() {
    // Exercises http_metrics with a real `MatchedPath` (route template) +
    // extract_trace_context with no inbound context.
    let status = send(
        Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unmatched_request_hits_the_bounded_fallback_label() {
    // No route matches → http_metrics records under the bounded `<unmatched>`
    // bucket rather than the raw path (the cardinality guard).
    let status = send(
        Request::builder()
            .uri("/no/such/route")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn inbound_traceparent_is_accepted() {
    // A propagated W3C context on the request must not break the handler;
    // extract_trace_context parses it and sets it as the span parent.
    let status = send(
        Request::builder()
            .uri("/v1/health")
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn request_duration_histogram_is_cached() {
    // Both calls resolve the same cached instrument (the OnceLock path); recording
    // against the no-op global meter must not panic.
    let h1 = request_duration();
    let h2 = request_duration();
    h1.record(0.012, &[]);
    assert!(std::ptr::eq(h1, h2));
}

#[test]
fn inject_trace_context_returns_the_request() {
    // With no active OTel span/propagator (telemetry disabled), injection is a
    // no-op that must still hand the request back unchanged — and never panic.
    let request = reqwest::Client::new()
        .get("http://example.invalid/v1/networks")
        .build()
        .unwrap();
    let out = super::inject_trace_context(request);
    assert_eq!(out.url().path(), "/v1/networks");
}

#[test]
fn resource_carries_the_inforge_identity_attributes() {
    use opentelemetry::Key;

    // SAFETY: these `INFORGE_*` vars are read by nothing else in the test binary.
    unsafe {
        std::env::set_var("INFORGE_SERVICE_NAMESPACE", "wardnet");
        std::env::set_var("INFORGE_INSTANCE_ID", "tenants-test-7");
        std::env::set_var("INFORGE_HOST_ID", "node-3");
        std::env::set_var("INFORGE_DEPLOYMENT_ENV", "test");
        std::env::set_var("INFORGE_DEPLOYMENT_REGION_SLUG", "use1");
    }

    let resource = super::resource("wardnet-tenants", "9.9.9");
    let attr = |k: &str| {
        resource
            .get(&Key::new(k.to_string()))
            .map(|v| v.as_str().into_owned())
    };

    assert_eq!(attr("service.name").as_deref(), Some("wardnet-tenants"));
    assert_eq!(attr("service.version").as_deref(), Some("9.9.9"));
    assert_eq!(attr("service.namespace").as_deref(), Some("wardnet"));
    assert_eq!(
        attr("service.instance.id").as_deref(),
        Some("tenants-test-7")
    );
    assert_eq!(attr("host.id").as_deref(), Some("node-3"));
    assert_eq!(attr("deployment.environment.name").as_deref(), Some("test"));
    assert_eq!(attr("region").as_deref(), Some("use1"));

    unsafe {
        std::env::remove_var("INFORGE_SERVICE_NAMESPACE");
        std::env::remove_var("INFORGE_INSTANCE_ID");
        std::env::remove_var("INFORGE_HOST_ID");
        std::env::remove_var("INFORGE_DEPLOYMENT_ENV");
        std::env::remove_var("INFORGE_DEPLOYMENT_REGION_SLUG");
    }
}
