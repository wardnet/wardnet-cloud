//! Mesh-plane resource read: `GET /v1/tenants/{id}` → the full [`TenantView`] or
//! `404`.
//!
//! SERVICE-plane (mounted on the mesh-mTLS listener, `authenticate(SERVICE)`). No
//! caller policy — the full resource is returned; the consumer reads what it needs
//! (the Tunneller checks the embedded subscription).

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::middleware::from_fn_with_state;
use axum::routing::get;

use wardnet_common::auth::{CallerType, authenticate};
use wardnet_common::contract::TenantView;

use crate::error::ApiError;
use crate::state::AppState;

/// Build the tenant resource-read router, guarded by `authenticate(SERVICE)`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/tenants/{id}", get(get_tenant))
        .route_layer(from_fn_with_state(
            state.clone(),
            |st: State<AppState>, r, n| authenticate(CallerType::SERVICE, st, r, n),
        ))
        .with_state(state)
}

async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TenantView>, ApiError> {
    let tenant = state
        .tenants()
        .find_tenant(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such tenant".to_string()))?;
    let subscription = state
        .subscriptions()
        .current(&id)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(crate::api::tenants::tenant_view(tenant, subscription)))
}
