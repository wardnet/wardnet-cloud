//! `GET /v1/plans` — the public plan catalog (bootstrap group, no auth).
//!
//! The catalog is non-secret pricing info anyone (incl. an unauthenticated visitor
//! picking a plan) may read. It is served from the Billing-owned projection via the
//! [`PlanCatalog`](wardnet_common::ports::PlanCatalog) port — never a live Stripe call on
//! the request path (ADR-0011). A projection older than the staleness bound yields `503`.

use axum::Json;
use axum::extract::State;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::contract::PlanView;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the public plan-catalog route (bootstrap group, no auth layer).
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(list_plans))
}

#[utoipa::path(
    get,
    path = "/v1/plans",
    tag = "billing",
    description = "The purchasable plan catalog (ascending by level), each with its live \
                   promotion's discounted price. Public; sourced from Stripe via the projection.",
    responses(
        (status = 200, description = "The plan catalog", body = [PlanView]),
        (status = 503, description = "Catalog temporarily unavailable (too stale)"),
    ),
    security(()),
)]
async fn list_plans(State(state): State<AppState>) -> Result<Json<Vec<PlanView>>, ApiError> {
    Ok(Json(state.plans().plans().await?))
}
