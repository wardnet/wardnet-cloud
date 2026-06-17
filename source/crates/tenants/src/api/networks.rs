//! `POST /v1/networks` — register-network (auth = `DAEMON`).
//!
//! The daemon (already enrolled, holding a tenant-scoped JWT) claims a vanity and
//! creates its network + daemon row. The daemon's public key is its JWT subject.

use axum::Json;
use axum::extract::State;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};
use wardnet_common::contract::{NetworkView, RegisterNetworkRequest};

use crate::error::ApiError;
use crate::repository::Network;
use crate::state::AppState;

/// Register the register-network route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(register_network))
}

impl From<Network> for NetworkView {
    fn from(n: Network) -> Self {
        Self {
            id: n.id,
            tenant_id: n.tenant_id,
            slug: n.slug,
            display_name: n.display_name,
            region: n.region,
            provisioning_state: n.provisioning_state,
            created_at: n.created_at,
            updated_at: n.updated_at,
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/networks",
    tag = "networks",
    description = "Register a network for the calling daemon's tenant and bind the \
                   daemon to it. The new network starts in `provisioning`.",
    request_body = RegisterNetworkRequest,
    responses(
        (status = 200, description = "Network registered", body = NetworkView),
        (status = 400, description = "Invalid slug/region"),
        (status = 409, description = "Slug taken / limit reached / daemon already registered"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not a daemon caller"),
    ),
)]
async fn register_network(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Json(body): Json<RegisterNetworkRequest>,
) -> Result<Json<NetworkView>, ApiError> {
    let Caller::Daemon(daemon) = caller else {
        return Err(ApiError::Forbidden(
            "daemon credential required".to_string(),
        ));
    };
    // `public_key` is the daemon's identity (token `sub` == its `cnf`); it becomes
    // the `daemons.public_key` row.
    let network = state
        .tenants()
        .register_network(
            &daemon.tenant_id,
            &daemon.public_key,
            &body.slug,
            body.display_name.as_deref(),
            &body.region,
        )
        .await?;
    Ok(Json(network.into()))
}
