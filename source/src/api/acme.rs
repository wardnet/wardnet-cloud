use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::AuthenticatedInstall;
use crate::error::ApiError;
use crate::state::AppState;

/// Register ACME challenge routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(set_acme_challenge))
        .routes(routes!(delete_acme_challenge))
}

/// Request body for `PUT /v1/installs/{id}/acme-challenge`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetAcmeChallengeRequest {
    /// The ACME DNS-01 challenge token values (raw, no quoting needed). A
    /// **per-user wildcard certificate** authorizes its apex and wildcard SANs
    /// through the same `_acme-challenge` name, so this carries one value per SAN
    /// (typically two) and they are published as that many TXT records at once.
    pub values: Vec<String>,
}

#[utoipa::path(
    put,
    path = "/v1/installs/{id}/acme-challenge",
    tag = "installs",
    description = "Set the DNS-01 ACME challenge TXT records for this installation. \
                   Creates one `_acme-challenge.<name>.my.wardnet.services` TXT record \
                   per supplied value (a per-user wildcard cert authorizes two SANs \
                   through the same name). \
                   \n\n\
                   Called by the daemon's `AcmeManager` before presenting the DNS-01 \
                   challenge to Let's Encrypt. The daemon must wait for DNS propagation \
                   before completing the ACME order.",
    params(
        ("id" = String, Path, description = "Installation UUID"),
    ),
    request_body = SetAcmeChallengeRequest,
    responses(
        (status = 204, description = "TXT records created"),
        (status = 401, description = "Authentication required or invalid"),
        (status = 403, description = "Bearer token does not own this install ID"),
        (status = 409, description = "A concurrent ACME challenge update was in flight; retry"),
        (status = 500, description = "Internal server error"),
    ),
)]
pub async fn set_acme_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AuthenticatedInstall(install): AuthenticatedInstall,
    Json(body): Json<SetAcmeChallengeRequest>,
) -> Result<StatusCode, ApiError> {
    if install.id != id {
        return Err(ApiError::Forbidden(
            "bearer token does not match the requested install ID".to_string(),
        ));
    }

    // Bound the list before any Cloudflare write: each value fans out to a TXT
    // create against the region's shared zone, so an unchecked count from a
    // (merely authenticated) install is a cross-tenant DoS vector.
    crate::api::validation::validate_acme_values(&body.values)?;

    let fqdn = state.config().acme_fqdn(&install.name);

    // DDNS owns the whole replace-set: it reads the install's current TXT records
    // fresh, deletes the stale set, creates the new one, and persists with a
    // compare-and-set (a concurrent challenge write surfaces as 409 Conflict).
    state
        .ddns()
        .set_acme_challenge(&id, &fqdn, &body.values)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/v1/installs/{id}/acme-challenge",
    tag = "installs",
    description = "Remove the DNS-01 ACME challenge TXT records for this installation. \
                   Deletes every TXT record from the active challenge (a per-user \
                   wildcard cert publishes more than one). Called by the daemon's \
                   `AcmeManager` after Let's Encrypt has completed DNS-01 validation. \
                   Idempotent — safe to call even if no TXT record is currently set.",
    params(
        ("id" = String, Path, description = "Installation UUID"),
    ),
    responses(
        (status = 204, description = "TXT records deleted (or were already absent)"),
        (status = 401, description = "Authentication required or invalid"),
        (status = 403, description = "Bearer token does not own this install ID"),
        (status = 409, description = "A concurrent ACME challenge update was in flight; retry"),
        (status = 500, description = "Internal server error"),
    ),
)]
pub async fn delete_acme_challenge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    AuthenticatedInstall(install): AuthenticatedInstall,
) -> Result<StatusCode, ApiError> {
    if install.id != id {
        return Err(ApiError::Forbidden(
            "bearer token does not match the requested install ID".to_string(),
        ));
    }

    // DDNS reads the live TXT records fresh, deletes them, and clears the stored
    // IDs; a no-op when none is live (idempotent).
    state.ddns().clear_acme_challenge(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Full-stack ACME-challenge tests live in tests/api.rs.
