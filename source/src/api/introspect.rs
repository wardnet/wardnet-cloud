use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the introspection route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(introspect))
}

/// Request body for `POST /v1/introspect`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct IntrospectRequest {
    /// Install IDs to check (typically the ones a regional service holds
    /// operational rows for).
    pub install_ids: Vec<String>,
}

/// Response for `POST /v1/introspect`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct IntrospectResponse {
    /// The subset of the requested IDs with **no active identity** — tombstoned
    /// (deregistered) or never-registered. The caller (the DDNS reconcile reaper)
    /// tears down the regional DNS state for these.
    pub inactive: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/v1/introspect",
    tag = "internal",
    description = "Batch identity introspection for the DDNS reconcile reaper: given a \
                   set of install IDs, return those that no longer have an active \
                   identity (tombstoned or absent). \
                   \n\n\
                   Internal Tenants endpoint. It carries no install authentication — at \
                   the service split it is reached only over the mesh-mTLS internal \
                   listener (Tenants ↔ DDNS).",
    request_body = IntrospectRequest,
    responses(
        (status = 200, description = "The inactive subset", body = IntrospectResponse),
        (status = 500, description = "Internal server error"),
    ),
    security(()),
)]
pub async fn introspect(
    State(state): State<AppState>,
    Json(body): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    let inactive = state
        .tenants()
        .introspect_inactive(&body.install_ids)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(IntrospectResponse { inactive }))
}

// Full-stack introspection tests live in tests/api.rs.
