use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::challenge::client_ip;
use crate::api::validation::{validate_name, validate_public_key};
use crate::error::ApiError;
use crate::service::RegisterParams;
use crate::state::AppState;

/// Register the `POST /v1/register` route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(register_install))
}

/// Request body for `POST /v1/register`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterRequest {
    /// Desired subdomain slug, e.g. `"happy-einstein"`.
    /// Must match `[a-z0-9-]`, 3–32 characters, no leading/trailing hyphen.
    pub name: String,
    /// Base64-encoded raw Ed25519 verifying-key bytes (exactly 32 bytes).
    pub public_key: String,
    /// Challenge UUID obtained from `GET /v1/register/challenge`.
    pub challenge_id: String,
    /// `PoW` proof: a `u64` such that
    /// `SHA256(nonce\nname\npublic_key\nproof_decimal)` has at least
    /// `difficulty` leading zero bits.
    pub proof: u64,
}

/// Response body for `POST /v1/register`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegisterResponse {
    /// Server-assigned installation UUID. Used in all subsequent API paths.
    pub id: String,
    /// Opaque bearer token. Store in the Pi's `SecretStore`.
    /// The bridge stores only `SHA256(token)` — this is the only time the
    /// raw value is returned.
    pub bearer_token: String,
    /// Tenants-signed identity JWT (`EdDSA`). Store it; the daemon will carry it to
    /// the regional services once the JWT/PoP cutover lands. Refreshed via
    /// `POST /v1/token`.
    pub identity_jwt: String,
    /// Fully-qualified subdomain assigned to this installation,
    /// e.g. `"happy-einstein.my.wardnet.services"`.
    pub subdomain: String,
    /// Region this bridge instance serves, e.g. `"us"` or `"eu"`.
    pub region: String,
}

#[utoipa::path(
    post,
    path = "/v1/register",
    tag = "installs",
    description = "Register a new wardnet installation. \
                   \n\n\
                   Requires a valid, unexpired PoW challenge obtained from \
                   `GET /v1/register/challenge`. The challenge is single-use and \
                   burned atomically on success. \
                   \n\n\
                   Rate-limited to **3 registrations per remote IP per 24 hours** \
                   (a legitimate Pi registers once at setup).",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Installation registered", body = RegisterResponse),
        (status = 400, description = "Invalid name, public key, or PoW proof"),
        (status = 409, description = "Name already taken"),
        (status = 429, description = "Registration rate limit exceeded (3/IP/24 h)"),
        (status = 500, description = "Internal server error"),
    ),
    security(()),
)]
pub async fn register_install(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let remote_ip = client_ip(&headers, addr);

    validate_name(&body.name)?;
    let pub_key_bytes = validate_public_key(&body.public_key)?;

    let region = state.config().region.clone();
    let outcome = state
        .tenants()
        .register(RegisterParams {
            name: &body.name,
            public_key: &body.public_key,
            pub_key_bytes,
            challenge_id: &body.challenge_id,
            proof: body.proof,
            remote_ip: &remote_ip,
            region: &region,
        })
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: outcome.id,
            bearer_token: outcome.bearer_token,
            identity_jwt: outcome.identity_jwt,
            subdomain: state.config().install_fqdn(&body.name),
            region,
        }),
    ))
}

#[cfg(test)]
mod tests;
