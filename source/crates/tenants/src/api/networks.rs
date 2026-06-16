//! `POST /v1/networks` — register-network (auth = `DAEMON`).
//!
//! The daemon (already enrolled, holding a tenant-scoped JWT) claims a vanity and
//! creates its network + daemon row. The daemon's public key is its JWT subject.

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};

use crate::error::ApiError;
use crate::repository::Network;
use crate::state::AppState;

/// Register the register-network route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(register_network))
}

/// Request body for `POST /v1/networks`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterNetworkRequest {
    /// Desired vanity slug (`[a-z0-9-]`, 3–32, not reserved).
    pub slug: String,
    /// Human-facing name; defaults to the slug when omitted/empty.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Region that will own this network's DNS/tunnel.
    pub region: String,
}

/// Public view of a network.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NetworkView {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub region: String,
    pub provisioning_state: String,
    pub created_at: DateTime<Utc>,
}

impl From<Network> for NetworkView {
    fn from(n: Network) -> Self {
        Self {
            id: n.id,
            slug: n.slug,
            display_name: n.display_name,
            region: n.region,
            provisioning_state: n.provisioning_state.as_str().to_string(),
            created_at: n.created_at,
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
