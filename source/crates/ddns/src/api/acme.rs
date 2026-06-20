//! `PUT` / `DELETE /v1/acme-challenge` — the daemon manages its DNS-01 ACME
//! challenge TXT records (auth = `DAEMON`).
//!
//! ACME is orthogonal to provisioning (the Pi terminates its own TLS under SNI
//! passthrough). The target network is the JWT `net` claim. The challenge FQDN is
//! derived from the **stored** A-record FQDN (set by the provisioner), so a daemon
//! whose network is not yet active gets `409`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the ACME-challenge routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(set_acme_challenge))
        .routes(routes!(delete_acme_challenge))
}

/// Request body for `PUT /v1/acme-challenge`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetAcmeChallengeRequest {
    /// The ACME DNS-01 challenge token values (raw, no quoting needed). A
    /// **per-user wildcard certificate** authorizes its apex and wildcard SANs
    /// through the same `_acme-challenge` name, so this carries one value per SAN
    /// (typically two), published as that many TXT records at once.
    pub values: Vec<String>,
}

/// Resolve the calling daemon's network id from the `net` claim, or `403`.
fn network_of(caller: Caller) -> Result<String, ApiError> {
    let Caller::Daemon(daemon) = caller else {
        return Err(ApiError::Forbidden(
            "daemon credential required".to_string(),
        ));
    };
    daemon
        .network
        .ok_or_else(|| ApiError::Forbidden("a network-scoped token is required".to_string()))
}

#[utoipa::path(
    put,
    path = "/v1/acme-challenge",
    tag = "acme",
    description = "Set the DNS-01 ACME challenge TXT records for the calling daemon's \
                   network. Creates one `_acme-challenge.<slug>.<parent>` TXT record \
                   per supplied value. Returns 409 if the network is not yet active.",
    request_body = SetAcmeChallengeRequest,
    responses(
        (status = 204, description = "TXT records created"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not a network-scoped daemon caller"),
        (status = 409, description = "Network not yet active, or a concurrent ACME update was in flight; retry"),
        (status = 500, description = "Internal server error"),
    ),
)]
async fn set_acme_challenge(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Json(body): Json<SetAcmeChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    let network_id = network_of(caller)?;

    // Bound the list before any Cloudflare write: each value fans out to a TXT
    // create against the region's shared zone, so an unchecked count from a
    // (merely authenticated) daemon is a cross-tenant DoS vector.
    wardnet_common::validation::validate_acme_values(&body.values)?;

    // Derive the challenge FQDN from the stored A-record FQDN (set by the
    // provisioner). No stored FQDN ⇒ the network is not yet active.
    let fqdn = state
        .ddns()
        .network_fqdn(&network_id)
        .await?
        .ok_or_else(|| ApiError::Conflict("network is not yet active".to_string()))?;
    let acme_fqdn = format!("_acme-challenge.{fqdn}");

    state
        .ddns()
        .set_acme_challenge(&network_id, &acme_fqdn, &body.values)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/acme-challenge",
    tag = "acme",
    description = "Remove the DNS-01 ACME challenge TXT records for the calling \
                   daemon's network. Idempotent — safe to call even if none is set.",
    responses(
        (status = 204, description = "TXT records deleted (or were already absent)"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not a network-scoped daemon caller"),
        (status = 409, description = "A concurrent ACME challenge update was in flight; retry"),
        (status = 500, description = "Internal server error"),
    ),
)]
async fn delete_acme_challenge(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
) -> Result<StatusCode, ApiError> {
    let network_id = network_of(caller)?;
    state.ddns().clear_acme_challenge(&network_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
