pub mod acme;
pub mod ip;
pub mod tunnel;

use axum::Router;
use axum::middleware;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use wardnet_common::error::ErrorBody;

use crate::state::AppState;

/// `OpenAPI` document metadata for the cloud (DDNS + Tunneller) API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Wardnet Cloud API (DDNS + Tunneller)",
        description = "Regional DDNS (IP + ACME challenge) and reverse-tunnel endpoints.",
        version = "0.2.0",
    ),
    tags(
        (name = "health",   description = "Liveness probes"),
        (name = "installs", description = "IP updates and ACME challenge lifecycle"),
        (name = "tunnel",   description = "Reverse-tunnel WebSocket endpoint"),
    ),
    components(schemas(ErrorBody)),
)]
struct ApiDoc;

/// Build the OpenAPI-aware router with all routes registered.
fn build_openapi_router() -> OpenApiRouter<AppState> {
    let mut r = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi());
    r = wardnet_common::health::register(r);
    r = ip::register(r);
    r = acme::register(r);
    r = tunnel::register(r);
    r
}

/// Build the complete Axum [`Router`] with the shared signed-request auth
/// middleware applied. These endpoints authenticate the **external daemon** by
/// identity JWT only — the opaque-bearer DB path lives in the Tenants service.
pub fn router(state: AppState) -> Router {
    let (api_router, _openapi) = build_openapi_router().split_for_parts();

    api_router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            wardnet_common::auth::auth_layer::<AppState>,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
