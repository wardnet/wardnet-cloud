//! `GET /v1/availability?slug=` — is a vanity slug free? Accepts a daemon (wizard)
//! or a user (account plane) JWT.

use axum::Json;
use axum::extract::{Query, State};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::AuthCaller;
use wardnet_common::contract::{AvailabilityQuery, AvailabilityResponse};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the availability route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(availability))
}

#[utoipa::path(
    get,
    path = "/v1/availability",
    tag = "networks",
    params(AvailabilityQuery),
    description = "Check whether a vanity slug is available. An invalid or reserved \
                   slug reads as unavailable rather than an error.",
    responses(
        (status = 200, description = "Availability", body = AvailabilityResponse),
        (status = 401, description = "Unauthenticated"),
    ),
)]
async fn availability(
    State(state): State<AppState>,
    _caller: AuthCaller,
    Query(query): Query<AvailabilityQuery>,
) -> Result<Json<AvailabilityResponse>, ApiError> {
    let available = state.tenants().check_availability(&query.slug).await?;
    Ok(Json(AvailabilityResponse { available }))
}
