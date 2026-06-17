//! `POST /v1/enroll` — bootstrap endpoint (auth = the one-time code).
//!
//! Validates + burns the code, creates/resolves the tenant, and writes a TTL'd
//! pending pubkey↔tenant binding. Returns no JWT — the daemon next calls
//! `POST /v1/token` (key-`PoP`) to mint one.

use axum::Json;
use axum::extract::State;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::contract::{EnrollRequest, EnrollResponse};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the enroll route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(enroll))
}

#[utoipa::path(
    post,
    path = "/v1/enroll",
    tag = "enrollment",
    description = "Bootstrap a daemon: consume a one-time code and bind its public key \
                   to a tenant via a short-lived pending record. No JWT is returned — \
                   call POST /v1/token next.",
    request_body = EnrollRequest,
    responses(
        (status = 200, description = "Daemon enrolled (pending)", body = EnrollResponse),
        (status = 401, description = "Invalid/expired/used code"),
        (status = 409, description = "Tenant daemon limit reached"),
        (status = 400, description = "Invalid public key"),
    ),
    security(()),
)]
async fn enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let result = state.tenants().enroll(&body.code, &body.public_key).await?;
    Ok(Json(EnrollResponse {
        tenant_id: result.tenant_id,
    }))
}
