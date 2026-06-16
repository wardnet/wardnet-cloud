//! Internal mesh-mTLS **work-queue** listener (Tenants ↔ DDNS provisioner/reaper).
//!
//! Served over mutual TLS on a private address — a peer must present a client
//! certificate chained to the mesh CA to complete the handshake. That handshake is
//! the `SERVICE` authentication: each accepted connection is stamped with a
//! [`ServiceIdentity`], and the routes are guarded by `authenticate(SERVICE)`.
//!
//! Endpoints (the reconciler contract the regional DDNS service drives):
//! - `GET /v1/networks?provisioningState=&region=&afterId=&limit=` — a cursor page
//!   of desired-state networks to act on.
//! - `PATCH /v1/networks/{id}` — record the result: `active` (provisioner published
//!   DNS) or `deprovisioned` (reaper tore DNS down → delete the row).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, patch};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use wardnet_common::auth::{CallerType, ServiceIdentity, authenticate};
use wardnet_common::{mtls, serve};

use crate::api::networks::NetworkView;
use crate::config::Config;
use crate::error::ApiError;
use crate::repository::ProvisioningState;
use crate::state::AppState;

/// Max concurrent in-flight mesh connections (accept-storm guard).
const MAX_CONCURRENT_MESH: usize = 1024;
/// Default / max page size for a reconcile scan.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Serve the mesh work-queue over mutual TLS on `config.mesh_listen_addr`.
///
/// # Errors
/// Returns an error if the mesh PEM material cannot be read/parsed or the listener
/// cannot be bound.
pub async fn serve_mesh(config: &Config, state: AppState) -> anyhow::Result<()> {
    let ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;

    let server_config = mtls::server_config_from_pem(&cert, &key, &ca)?;
    let acceptor = TlsAcceptor::from(server_config);
    let router = mesh_router(state);

    let listener = TcpListener::bind(&config.mesh_listen_addr).await?;
    tracing::info!(addr = %config.mesh_listen_addr, "mesh work-queue listener (mTLS) listening");

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_MESH));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "mesh listener accept error");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    // The handshake validated a mesh-CA client cert; stamp the
                    // service identity so `authenticate(SERVICE)` accepts the route.
                    let conn_router = router.layer(Extension(ServiceIdentity {
                        subject: String::new(),
                    }));
                    if let Err(e) = serve::connection(tls, conn_router, peer).await {
                        tracing::debug!(error = %e, %peer, "mesh connection error");
                    }
                }
                Err(e) => tracing::debug!(error = %e, %peer, "mesh mTLS handshake rejected"),
            }
        });
    }
}

/// Build the mesh work-queue router, guarded by `authenticate(SERVICE)`.
pub fn mesh_router(state: AppState) -> Router {
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
