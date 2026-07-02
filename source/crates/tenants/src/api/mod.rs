//! Public, nginx-fronted Tenants API.
//!
//! Routes are grouped by the caller kind they accept and each group gets the
//! [`authenticate`](wardnet_common::auth::authenticate) middleware for its
//! [`CallerType`] set. The **bootstrap** group (health + the credential-minting
//! enroll/token/signup endpoints) carries no middleware — those endpoints verify
//! their own one-time-code / key-`PoP` credentials.

mod auth;
mod availability;
mod billing;
mod cookies;
pub mod daemons;
mod enroll;
mod me;
pub mod network;
pub mod networks;
mod plans;
pub mod reconcile;
pub mod tenant;
pub mod tenants;
mod token;
mod verification_codes;

use axum::Router;
use axum::extract::State;
use axum::middleware::from_fn_with_state;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use wardnet_common::auth::{CallerType, authenticate};
use wardnet_common::error::ErrorBody;
use wardnet_common::health;

use crate::state::AppState;

/// Spec version tracks the crate version (== the release tag `tenants-v<version>`).
const API_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `OpenAPI` metadata for the Tenants public API.
#[derive(OpenApi)]
#[openapi(
    info(title = "Wardnet Tenants API", version = API_VERSION),
    tags(
        (name = "health", description = "Liveness"),
        (name = "enrollment", description = "Daemon enrollment + JWT issuance"),
        (name = "networks", description = "Network registration + availability"),
        (name = "tenants", description = "Account-plane tenant management"),
        (name = "auth", description = "Human/web authentication (password + federated login)"),
        (name = "billing", description = "Stripe billing webhook + checkout/portal"),
    ),
    components(schemas(ErrorBody)),
)]
struct ApiDoc;

// The route registrations, grouped by the caller kind each group accepts. Single-sourced
// here so [`router`] (which adds the auth `route_layer`s + state) and [`api_doc`] (which
// needs only the paths) can never drift on which endpoints exist. Only the **public**
// nginx-fronted surface is registered — the internal mesh/reconcile listener
// (`src/mesh.rs` + `src/api/reconcile.rs`) is SPIFFE-only and intentionally excluded.
fn bootstrap_routes() -> OpenApiRouter<AppState> {
    // Bootstrap: health + credential-minting endpoints + the Stripe webhook + the
    // web-auth surface. No auth middleware — each verifies its own one-time code / key
    // PoP / Stripe signature / session cookie / OAuth state.
    plans::register(auth::register(billing::register(
        verification_codes::register(token::register(enroll::register(health::register(
            OpenApiRouter::new(),
        )))),
    )))
}

fn daemon_or_user_routes() -> OpenApiRouter<AppState> {
    // Availability accepts a daemon (wizard) or a user (account plane).
    availability::register(OpenApiRouter::new())
}

fn daemon_routes() -> OpenApiRouter<AppState> {
    // Register-network and daemon self-removal are daemon-only.
    daemons::register(networks::register(OpenApiRouter::new()))
}

fn user_routes() -> OpenApiRouter<AppState> {
    // The account plane is user-only (incl. the `/v1/me/*` security endpoints).
    me::register(tenants::register(OpenApiRouter::new()))
}

/// The Tenants public `OpenAPI` document (paths + schemas), with no middleware or state.
///
/// Emitted as the committed build artifact by the `dump_openapi` bin. Mirrors the
/// merge chain in [`router`] minus the auth layers, which do not affect the spec. The
/// internal mesh/reconcile routes are not part of this public document.
#[must_use]
pub fn api_doc() -> utoipa::openapi::OpenApi {
    let (_router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap_routes())
        .merge(daemon_or_user_routes())
        .merge(daemon_routes())
        .merge(user_routes())
        .split_for_parts();
    api
}

/// Build the public API router.
pub fn router(state: AppState) -> Router {
    let bootstrap = bootstrap_routes();

    let daemon_or_user = daemon_or_user_routes().route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::DAEMON | CallerType::USER, st, r, n),
    ));

    let daemon = daemon_routes().route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::DAEMON, st, r, n),
    ));

    let user = user_routes().route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::USER, st, r, n),
    ));

    let (router, _openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap)
        .merge(daemon_or_user)
        .merge(daemon)
        .merge(user)
        .split_for_parts();

    wardnet_common::telemetry::install_http_layers(router).with_state(state)
}

#[cfg(test)]
mod tests;
