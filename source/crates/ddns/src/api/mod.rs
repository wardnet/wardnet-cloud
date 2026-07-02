//! Public, nginx-fronted DDNS API.
//!
//! The daemon-facing surface: report-IP and ACME DNS-01 challenge management. All
//! daemon routes are grouped under the [`authenticate`](wardnet_common::auth::authenticate)
//! middleware for [`CallerType::DAEMON`] (JWT + `Ed25519` `PoP`). Unlike the legacy
//! cloud auth, this is a **route-layer** guard, not a `/v1/installs/` path-gate —
//! the target network is the JWT `net` claim, so a daemon can only ever touch its
//! own network. The **bootstrap** group (health) carries no middleware.

pub mod acme;
pub mod ip;

use axum::Router;
use axum::extract::State;
use axum::middleware::from_fn_with_state;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use wardnet_common::auth::{CallerType, authenticate};
use wardnet_common::error::ErrorBody;
use wardnet_common::health;

use crate::state::AppState;

/// Spec version tracks the crate version (== the release tag `ddns-v<version>`).
const API_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `OpenAPI` metadata for the DDNS public API.
#[derive(OpenApi)]
#[openapi(
    info(title = "Wardnet DDNS API", version = API_VERSION),
    tags(
        (name = "health", description = "Liveness"),
        (name = "ip", description = "Daemon IP reporting"),
        (name = "acme", description = "ACME DNS-01 challenge management"),
    ),
    components(schemas(ErrorBody)),
)]
struct ApiDoc;

// The route registrations, grouped by caller kind. Single-sourced here so [`router`]
// (which adds the auth `route_layer`s + state) and [`api_doc`] (which needs only the
// paths) can never drift on which endpoints exist.
fn bootstrap_routes() -> OpenApiRouter<AppState> {
    // Bootstrap: health only. No auth middleware.
    health::register(OpenApiRouter::new())
}

fn daemon_routes() -> OpenApiRouter<AppState> {
    // Daemon plane: report-IP + ACME.
    acme::register(ip::register(OpenApiRouter::new()))
}

/// The DDNS public `OpenAPI` document (paths + schemas), with no middleware or state.
///
/// Emitted as the committed build artifact by the `dump_openapi` bin. Mirrors the
/// merge chain in [`router`] minus the auth layers, which do not affect the spec.
#[must_use]
pub fn api_doc() -> utoipa::openapi::OpenApi {
    let (_router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap_routes())
        .merge(daemon_routes())
        .split_for_parts();
    api
}

/// Build the public API router.
pub fn router(state: AppState) -> Router {
    let bootstrap = bootstrap_routes();

    // Daemon plane: JWT + PoP, scoped to the token's `net`.
    let daemon = daemon_routes().route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::DAEMON, st, r, n),
    ));

    let (router, _openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap)
        .merge(daemon)
        .split_for_parts();

    wardnet_common::telemetry::install_http_layers(router).with_state(state)
}

#[cfg(test)]
mod tests;
