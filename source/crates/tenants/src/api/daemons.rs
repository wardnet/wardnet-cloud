//! `DELETE /v1/networks/{id}/daemons/self` — daemon self-removal (auth = `DAEMON`).
//!
//! On teardown (uninstall / factory-reset / re-enrollment) a daemon removes **only its
//! own** row from its network. This is not [`delete_network`](super::tenants) — the
//! network and its DNS survive one daemon leaving; only the calling daemon's row goes.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the daemon self-removal route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(remove_self))
}

#[utoipa::path(
    delete,
    path = "/v1/networks/{id}/daemons/self",
    tag = "networks",
    description = "Remove the calling daemon from its network (self-removal on teardown). \
                   The row-level effect is idempotent — removing an already-absent daemon \
                   still returns 204, though a retry must be freshly re-signed (a \
                   byte-identical replay is rejected). Does not deprovision the network \
                   or delete its DNS.",
    params(("id" = String, Path, description = "The daemon's own network id")),
    responses(
        (status = 204, description = "Daemon removed (or already absent)"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Token is not scoped to this network"),
    ),
)]
async fn remove_self(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(network_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let Caller::Daemon(daemon) = caller else {
        return Err(ApiError::Forbidden(
            "daemon credential required".to_string(),
        ));
    };
    // A daemon may only remove itself from its own network: the path id must match the
    // token's `net` scope. A tenant-scoped token (`network == None`) never matches.
    if daemon.network.as_deref() != Some(network_id.as_str()) {
        return Err(ApiError::Forbidden(
            "daemon may only remove itself from its own network".to_string(),
        ));
    }
    state
        .tenants()
        .remove_daemon(&daemon.public_key, &network_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
