//! `GET /v1/tunnel` — the daemon's reverse-tunnel WebSocket upgrade (auth = `DAEMON`).
//!
//! Network-scoped: the target network is the token's `net` claim, so a daemon can
//! only ever open a tunnel for its own network (a tenant-scoped token is rejected
//! `403`). The path carries no id — it is dropped from the old per-install shape, and
//! the old nonce challenge is retired (the per-request Ed25519 `PoP` that
//! `authenticate(DAEMON)` enforces on this upgrade GET already proves key
//! possession).
//!
//! The **routing policy lives here** (not in the Tenants resource reads it calls):
//! resolve `net` → vanity slug and reject a decommissioned network or an inactive
//! subscription, then claim the `tunnel_routes` row, register the tunnel, and
//! upgrade.

use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};
use wardnet_common::contract::{ProvisioningState, SubscriptionStatus};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the tunnel WebSocket route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(tunnel_connect))
}

#[utoipa::path(
    get,
    path = "/v1/tunnel",
    tag = "tunnel",
    description = "Upgrade to a reverse-tunnel WebSocket. The daemon dials this with a \
                   network-scoped identity JWT and keeps the connection open; the \
                   Tunneller forwards inbound TLS connections arriving at its SNI \
                   demuxer down the tunnel, and the daemon decrypts them locally so \
                   the private key never leaves the device. \
                   \n\n\
                   **Frame protocol** (binary WebSocket messages): \
                   \n\
                   - `CONNECT (0x01)`: node→pi, 7 bytes `[type, conn_id:u32be, dest_port:u16be]` \
                   - `READY   (0x02)`: pi→node, 5 bytes `[type, conn_id:u32be]` \
                   - `DATA    (0x03)`: both, 5+N bytes `[type, conn_id:u32be, payload…]` \
                   - `CLOSE   (0x04)`: both, 5 bytes `[type, conn_id:u32be]` \
                   - `PING    (0x05)`: pi→node, 5 bytes (conn_id=0) \
                   - `PONG    (0x06)`: node→pi, 5 bytes (conn_id=0)",
    responses(
        (status = 101, description = "Switching protocols — tunnel established"),
        (status = 401, description = "Authentication required or invalid"),
        (status = 403, description = "Not a network-scoped daemon, or network/subscription not eligible"),
    ),
)]
// Auth note: the route group carries `authenticate(CallerType::DAEMON)`, which
// enforces the full Ed25519 signed-request flow (JWT + timestamp window + signature
// over "GET\n/v1/tunnel\n{ts}\nhex-sha256("") + replay check) before this handler
// runs; `into_parts`/`from_parts` in the middleware preserve the `OnUpgrade`
// extension, so the WebSocket upgrade survives the layer.
async fn tunnel_connect(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    let Caller::Daemon(daemon) = caller else {
        return Err(ApiError::Forbidden(
            "daemon credential required".to_string(),
        ));
    };
    let network_id = daemon
        .network
        .ok_or_else(|| ApiError::Forbidden("a network-scoped token is required".to_string()))?;

    // Resolve net → slug and apply policy via the Tenants resource reads.
    let network = state
        .tenants()
        .get_network(&network_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::Forbidden("network not found".to_string()))?;
    if network.provisioning_state == ProvisioningState::Deprovisioning {
        return Err(ApiError::Forbidden("network is deprovisioning".to_string()));
    }
    let tenant = state
        .tenants()
        .get_tenant(&network.tenant_id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::Forbidden("tenant not found".to_string()))?;
    if tenant.subscription_status != SubscriptionStatus::Active {
        return Err(ApiError::Forbidden(
            "tenant subscription is not active".to_string(),
        ));
    }

    let slug = network.slug;
    let node_addr = state.node_addr().to_string();

    // Claim the route (this node now owns the slug), then register + upgrade.
    state
        .routes()
        .upsert(&slug, &node_addr, &network_id, &network.tenant_id)
        .await
        .map_err(ApiError::Internal)?;

    let registry = state.registry();
    let routes = state.routes();
    let reg = registry.register(&slug);

    tracing::info!(slug = %slug, network_id = %network_id, "tunnel established");

    Ok(ws.on_upgrade(move |socket| {
        crate::tunnel::handler::run(socket, slug, registry, routes, node_addr, reg)
    }))
}
