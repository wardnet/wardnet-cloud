//! Regression guard for the shared HTTP layer stack (`telemetry::install_http_layers`).
//!
//! A panic in a handler must be caught and turned into a `500` response — it must
//! NOT propagate out of the service (which, on the live listener, took the whole
//! API down). The service must keep serving subsequent requests afterwards.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use tower::ServiceExt; // oneshot
use wardnet_common::telemetry::install_http_layers;

async fn boom() -> &'static str {
    panic!("boom in handler");
}

async fn ok() -> &'static str {
    "ok"
}

#[tokio::test]
async fn handler_panic_is_caught_as_500_and_service_keeps_serving() {
    let app: Router = install_http_layers(
        Router::new()
            .route("/boom", get(boom))
            .route("/ok", get(ok)),
    );

    // A panicking handler must yield a 500 response, not propagate the panic out
    // of the service (the `.await` returning Ok proves it did not unwind).
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
        .await
        .expect("a panicking handler must produce a response, not propagate the panic");
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // The stack must still serve a subsequent request — the panic must not have
    // poisoned or torn down anything shared.
    let resp = app
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .expect("service must keep serving after a handler panic");
    assert_eq!(resp.status(), StatusCode::OK);
}
