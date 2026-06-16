//! `POST /v1/enrollment-codes` — bootstrap endpoint (public, per-IP rate-limited).
//!
//! The new-signup entry point: a one-time code is issued for a claimed email
//! (controlling the inbox is the proof). In production the code is emailed (Resend,
//! deferred); for now it is returned in the response so the flow is exercisable.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::proxy_protocol::client_ip;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the signup-code route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(request_signup_code))
}

/// Request body for `POST /v1/enrollment-codes`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SignupCodeRequest {
    /// The account email a code should be issued for.
    pub email: String,
}

/// Response body for `POST /v1/enrollment-codes`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SignupCodeResponse {
    /// The one-time code. **Transitional:** returned here until email delivery
    /// (Resend) lands; thereafter it is emailed, not returned.
    pub code: String,
}

#[utoipa::path(
    post,
    path = "/v1/enrollment-codes",
    tag = "enrollment",
    description = "Issue a new-signup one-time code for an email (public, per-IP \
                   rate-limited). The code is emailed in production; returned here for now.",
    request_body = SignupCodeRequest,
    responses(
        (status = 200, description = "Code issued", body = SignupCodeResponse),
        (status = 400, description = "Invalid email"),
        (status = 429, description = "Per-IP rate limit exceeded"),
    ),
    security(()),
)]
async fn request_signup_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SignupCodeRequest>,
) -> Result<Json<SignupCodeResponse>, ApiError> {
    let remote_ip = client_ip(&headers, addr);
    let code = state
        .tenants()
        .issue_signup_code(&body.email, &remote_ip)
        .await?;
    Ok(Json(SignupCodeResponse { code }))
}
