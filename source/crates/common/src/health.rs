use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

/// Register health routes onto the given [`OpenApiRouter`].
///
/// Generic over the router state `S`: the `health` handler takes no `State`, so
/// this composes onto any service's router regardless of its `AppState` type.
pub fn register<S>(router: OpenApiRouter<S>) -> OpenApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.routes(routes!(health))
}

#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    description = "Liveness probe. Returns 200 OK when the bridge process is running. \
                   No authentication required. Used by load balancers and uptime monitors.",
    responses(
        (status = 200, description = "Bridge is alive"),
    ),
    security(()),
)]
pub async fn health() -> StatusCode {
    StatusCode::OK
}
