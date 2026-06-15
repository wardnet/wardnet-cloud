use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::AuthenticatedInstall;
use crate::error::ApiError;
use crate::state::AppState;

/// Register the token-refresh route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(refresh_token))
}

/// Response for `POST /v1/installs/{id}/token`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RefreshResponse {
    /// A freshly-minted Tenants-signed identity JWT. Replace the stored one.
    pub identity_jwt: String,
}

#[utoipa::path(
    post,
    path = "/v1/installs/{id}/token",
    tag = "installs",
    description = "Refresh this installation's identity JWT. The daemon re-authenticates \
                   with its usual signed request (bearer token *or* the current identity \
                   JWT + proof-of-possession) and receives a fresh, short-lived JWT. \
                   \n\n\
                   Liveness is re-checked: a deregistered (tombstoned) install cannot \
                   refresh, so its access ends when the current token expires.",
    params(
        ("id" = String, Path, description = "Installation UUID"),
    ),
    responses(
        (status = 200, description = "A fresh identity JWT", body = RefreshResponse),
        (status = 401, description = "Authentication required or invalid"),
        (status = 403, description = "Credential does not own this install ID, or the install is deregistered"),
        (status = 500, description = "Internal server error"),
    ),
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AuthenticatedInstall(principal): AuthenticatedInstall,
) -> Result<Json<RefreshResponse>, ApiError> {
    // The credential must own this install ID.
    if principal.id != id {
        return Err(ApiError::Forbidden(
            "credential does not match the requested install ID".to_string(),
        ));
    }

    // `refresh_token` re-loads the active identity by id, so a tombstoned install
    // (which may still hold a valid JWT) is rejected here.
    let identity_jwt = state.tenants().refresh_token(&id).await?;
    tracing::info!(install_id = %id, "identity JWT refreshed");
    Ok(Json(RefreshResponse { identity_jwt }))
}

// Full-stack refresh tests live in tests/api.rs.
