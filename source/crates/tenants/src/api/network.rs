//! Mesh-plane resource read: `GET /v1/networks/{id}` → the full [`NetworkView`] or
//! `404`.
//!
//! SERVICE-plane (mounted on the mesh-mTLS listener, `authenticate(SERVICE)`). There
//! is **no caller policy here** — the full resource is returned and the caller (e.g.
//! the Tunneller routing policy) reads only the fields it needs. The Tunneller is the
//! current consumer; the shared DTO means a producer change is caught at compile time.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::middleware::from_fn_with_state;
use axum::routing::get;

use wardnet_common::auth::{CallerType, authenticate};
use wardnet_common::contract::NetworkView;

use crate::error::ApiError;
use crate::state::AppState;

/// Build the network resource-read router, guarded by `authenticate(SERVICE)`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/networks/{id}", get(get_network))
        .route_layer(from_fn_with_state(
            state.clone(),
            |st: State<AppState>, r, n| authenticate(CallerType::SERVICE, st, r, n),
        ))
        .with_state(state)
}

async fn get_network(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<NetworkView>, ApiError> {
    let network = state
        .tenants()
        .find_network(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such network".to_string()))?;
    Ok(Json(network.into()))
}
