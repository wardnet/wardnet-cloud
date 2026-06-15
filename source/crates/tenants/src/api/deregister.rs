use axum::extract::{Path, State};
use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::AuthenticatedInstall;
use crate::error::ApiError;
use crate::state::AppState;

/// Register the deregister route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(deregister))
}

#[utoipa::path(
    delete,
    path = "/v1/installs/{id}",
    tag = "installs",
    description = "Deregister an installation by tombstoning its global identity. The \
                   install can no longer authenticate or refresh its token, so its \
                   identity JWT becomes inert within one TTL. \
                   \n\n\
                   Regional DNS cleanup (the Cloudflare A record + any ACME TXT records) \
                   is performed asynchronously by the DDNS reconcile reaper, which polls \
                   the mesh introspect endpoint for tombstoned installs — it is not done \
                   inline here (DDNS lives in a separate service).",
    params(
        ("id" = String, Path, description = "Installation UUID"),
    ),
    responses(
        (status = 204, description = "Installation deregistered (identity tombstoned)"),
        (status = 401, description = "Authentication required or invalid"),
        (status = 403, description = "Credential does not own this install ID"),
        (status = 500, description = "Internal server error"),
    ),
)]
pub async fn deregister(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AuthenticatedInstall(install): AuthenticatedInstall,
) -> Result<StatusCode, ApiError> {
    if install.id != id {
        return Err(ApiError::Forbidden(
            "credential does not match the requested install ID".to_string(),
        ));
    }

    // Tombstone the global identity. DNS teardown is the DDNS reaper's job (it
    // reconciles against this service's mesh introspect endpoint) — Tenants holds
    // no regional DNS state.
    state
        .tenants()
        .deregister_identity(&id)
        .await
        .map_err(ApiError::Internal)?;

    tracing::info!(install_id = %id, name = %install.name, "installation deregistered (tombstoned)");
    Ok(StatusCode::NO_CONTENT)
}

// Full-stack deregister tests live in tests/api.rs.
