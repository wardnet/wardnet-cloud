pub mod challenge;
pub mod deregister;
pub mod introspect;
pub mod names;
pub mod register;
pub mod token;

use axum::Router;
use axum::middleware;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use wardnet_common::error::ErrorBody;

use crate::state::AppState;

/// `OpenAPI` document metadata for the Tenants public API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Wardnet Tenants API",
        description = "Global identity & naming authority: registration, name availability, \
                       token refresh, and deregistration.",
        version = "0.1.0",
    ),
    tags(
        (name = "health",   description = "Liveness probes"),
        (name = "installs", description = "Registration and identity lifecycle"),
    ),
    components(schemas(ErrorBody)),
)]
struct ApiDoc;

/// Build the public, nginx-fronted Tenants router.
///
/// The mesh-only `introspect` endpoint is **not** registered here — it is served
/// on the internal mTLS listener (see [`crate::mesh`]).
fn build_openapi_router() -> OpenApiRouter<AppState> {
    let mut r = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi());
    r = wardnet_common::health::register(r);
    r = challenge::register(r);
    r = register::register(r);
    r = names::register(r);
    r = token::register(r);
    r = deregister::register(r);
    r
}

/// Build the complete public Axum [`Router`] with the shared signed-request auth
/// middleware applied.
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
