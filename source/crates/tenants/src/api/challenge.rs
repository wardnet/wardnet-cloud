use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use serde::Serialize;
use std::net::SocketAddr;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::proxy_protocol::client_ip;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the challenge route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(get_challenge))
}

/// Response body for `GET /v1/register/challenge`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ChallengeResponse {
    /// Opaque challenge UUID. Pass this as `challenge_id` in
    /// `POST /v1/register`.
    pub challenge_id: String,
    /// 32 random bytes as lowercase hex. Include verbatim in the `PoW` input.
    pub nonce: String,
    /// Number of leading zero bits the `SHA256` output must have.
    pub difficulty: u32,
    /// ISO 8601 UTC timestamp after which the challenge is invalid.
    pub expires_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/register/challenge",
    tag = "installs",
    description = "Issue a single-use proof-of-work challenge that must be solved before \
                   calling `POST /v1/register`. \
                   \n\n\
                   The client must find a `proof` (u64) such that \
                   `SHA256(nonce\\nname\\npublic_key\\nproof_decimal)` has at least \
                   `difficulty` leading zero bits. \
                   \n\n\
                   Challenges expire after 5 minutes and are burned on first use. \
                   Rate-limited to 20 requests per remote IP per hour.",
    responses(
        (status = 200, description = "PoW challenge issued", body = ChallengeResponse),
        (status = 429, description = "Challenge rate limit exceeded (20/IP/hour)"),
        (status = 500, description = "Internal server error"),
    ),
    security(()),
)]
pub async fn get_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let remote_ip = client_ip(&headers, addr);

    // Rate limit (20/IP/hour), generation, and persistence all live behind the
    // Tenants service — this handler only shapes the HTTP response.
    let challenge = state.tenants().issue_challenge(remote_ip).await?;

    Ok(Json(ChallengeResponse {
        difficulty: challenge.difficulty,
        expires_at: challenge.expires_at.to_rfc3339(),
        challenge_id: challenge.id,
        nonce: challenge.nonce,
    }))
}
