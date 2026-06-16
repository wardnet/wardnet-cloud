//! Mesh-plane **work-queue** API (Tenants ↔ DDNS provisioner/reaper).
//!
//! This is the SERVICE-plane reconcile surface: the desired-state contract the
//! regional DDNS service drives. It is *not* mounted on the public, nginx-fronted
//! router — its [`router`] is served only by the mesh-mTLS listener
//! ([`crate::mesh::serve_mesh`]), and is guarded by `authenticate(SERVICE)`.
//!
//! Endpoints:
//! - `GET /v1/networks?provisioningState=&region=&afterId=&limit=` — a cursor page
//!   of desired-state networks to act on.
//! - `PATCH /v1/networks/{id}` — record the result: `active` (provisioner published
//!   DNS) or `deprovisioned` (reaper tore DNS down → delete the row).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::Deserialize;

use wardnet_common::auth::{CallerType, authenticate};

use crate::api::networks::NetworkView;
use crate::error::ApiError;
use crate::repository::ProvisioningState;
use crate::state::AppState;

/// Default / max page size for a reconcile scan.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Build the mesh work-queue router, guarded by `authenticate(SERVICE)`.
///
/// Mounted by [`crate::mesh::serve_mesh`] onto the mesh-mTLS listener only.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/networks", get(list_for_reconcile))
        .route("/v1/networks/{id}", patch(transition_network))
        .route_layer(from_fn_with_state(
            state.clone(),
            |st: State<AppState>, r, n| authenticate(CallerType::SERVICE, st, r, n),
        ))
        .with_state(state)
}

/// Query for the reconcile scan.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconcileQuery {
    provisioning_state: String,
    region: String,
    after_id: Option<String>,
    limit: Option<i64>,
}

async fn list_for_reconcile(
    State(state): State<AppState>,
    Query(query): Query<ReconcileQuery>,
) -> Result<Json<Vec<NetworkView>>, ApiError> {
    let state_filter = ProvisioningState::from_db(&query.provisioning_state)
        .map_err(|_| ApiError::BadRequest("invalid provisioningState".to_string()))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let networks = state
        .tenants()
        .reconcile_page(
            state_filter,
            &query.region,
            query.after_id.as_deref(),
            limit,
        )
        .await?;
    Ok(Json(networks.into_iter().map(Into::into).collect()))
}

/// Body for a network state transition.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransitionRequest {
    provisioning_state: String,
}

async fn transition_network(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<TransitionRequest>,
) -> Result<StatusCode, ApiError> {
    use wardnet_common::error::ApiError as E;

    match body.provisioning_state.as_str() {
        // Provisioner published the DNS record. Idempotent: already-active is success.
        "active" => {
            if state.tenants().mark_network_active(&id).await? {
                return Ok(StatusCode::NO_CONTENT);
            }
            match state.tenants().network_state(&id).await? {
                Some(ProvisioningState::Active) => Ok(StatusCode::NO_CONTENT),
                None => Err(E::NotFound("no such network".to_string())),
                Some(_) => Err(E::Conflict("network is not in 'provisioning'".to_string())),
            }
        }
        // Reaper tore the DNS record down — delete the row, freeing the slug.
        // Idempotent: an already-deleted row (a retried reaper tick) is success.
        "deprovisioned" => {
            if state.tenants().finish_deprovision(&id).await? {
                return Ok(StatusCode::NO_CONTENT);
            }
            match state.tenants().network_state(&id).await? {
                None => Ok(StatusCode::NO_CONTENT),
                Some(_) => Err(E::Conflict(
                    "network is not in 'deprovisioning'".to_string(),
                )),
            }
        }
        other => Err(E::BadRequest(format!(
            "unsupported transition target {other:?}"
        ))),
    }
}
