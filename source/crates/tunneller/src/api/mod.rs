//! Public, nginx-fronted Tunneller API.
//!
//! The daemon-facing surface is a single endpoint — the reverse-tunnel WebSocket
//! upgrade — grouped under the [`authenticate`](wardnet_common::auth::authenticate)
//! middleware for [`CallerType::DAEMON`] (JWT + Ed25519 `PoP`). This is a
//! **route-layer** guard, not the legacy `/v1/installs/` path-gate: the target
//! network is the JWT `net` claim, so a daemon can only ever open its own tunnel.
//! Health carries no middleware.

pub mod tunnel;

use axum::Router;
use axum::extract::State;
use axum::middleware::from_fn_with_state;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use wardnet_common::auth::{CallerType, authenticate};
use wardnet_common::error::ErrorBody;
use wardnet_common::health;

use crate::state::AppState;

/// `OpenAPI` metadata for the Tunneller public API.
#[derive(OpenApi)]
#[openapi(
    info(title = "Wardnet Tunneller API", version = "0.1.0"),
    tags(
        (name = "health", description = "Liveness"),
        (name = "tunnel", description = "Reverse-tunnel WebSocket endpoint"),
    ),
    components(schemas(ErrorBody)),
)]
struct ApiDoc;

/// Build the public API router.
pub fn router(state: AppState) -> Router {
    // Bootstrap: health only. No auth middleware.
    let bootstrap = health::register(OpenApiRouter::new());

    // Daemon plane: the tunnel upgrade. JWT + PoP, scoped to the token's `net`.
    let daemon = tunnel::register(OpenApiRouter::new()).route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::DAEMON, st, r, n),
    ));

    let (router, _openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap)
        .merge(daemon)
        .split_for_parts();

    router.layer(TraceLayer::new_for_http()).with_state(state)
}
