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
mod codes;
mod enroll;
pub mod network;
pub mod networks;
pub mod reconcile;
pub mod tenant;
pub mod tenants;
mod token;

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

/// `OpenAPI` metadata for the Tenants public API.
#[derive(OpenApi)]
#[openapi(
    info(title = "Wardnet Tenants API", version = "0.1.0"),
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

/// Build the public API router.
pub fn router(state: AppState) -> Router {
    // Bootstrap: health + credential-minting endpoints + the Stripe webhook + the
    // web-auth surface. No auth middleware — each verifies its own one-time code / key
    // PoP / Stripe signature / session cookie / OAuth state.
    let bootstrap = auth::register(billing::register(codes::register(token::register(
        enroll::register(health::register(OpenApiRouter::new())),
    ))));

    // Availability accepts a daemon (wizard) or a user (account plane).
    let daemon_or_user = availability::register(OpenApiRouter::new()).route_layer(
        from_fn_with_state(state.clone(), |st: State<AppState>, r, n| {
            authenticate(CallerType::DAEMON | CallerType::USER, st, r, n)
        }),
    );

    // Register-network is daemon-only.
    let daemon = networks::register(OpenApiRouter::new()).route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::DAEMON, st, r, n),
    ));

    // The account plane is user-only.
    let user = tenants::register(OpenApiRouter::new()).route_layer(from_fn_with_state(
        state.clone(),
        |st: State<AppState>, r, n| authenticate(CallerType::USER, st, r, n),
    ));

    let (router, _openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(bootstrap)
        .merge(daemon_or_user)
        .merge(daemon)
        .merge(user)
        .split_for_parts();

    router.layer(TraceLayer::new_for_http()).with_state(state)
}
