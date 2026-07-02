//! `POST /v1/verification-codes` — the unified one-time-code resource (PR3, #18/#20).
//!
//! Bootstrap endpoint (public, per-IP rate-limited). Supersedes the old
//! `/v1/enrollment-codes` and `/v1/auth/password/reset-code`: one resource issues a
//! one-time, email-proof code for any of three `purpose`s (`signup` / `password_reset`
//! / `enrollment`). The `purpose` is **bound to the issued code** so it can only be
//! consumed by the matching flow. In production the code is emailed (Resend); in dev
//! (no-op sender) it is returned so the flow stays exercisable without a mailbox.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::contract::{CodePurpose, VerificationCodeRequest, VerificationCodeResponse};
use wardnet_common::proxy_protocol::client_ip;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the verification-code route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(create_verification_code))
}

#[utoipa::path(
    post,
    path = "/v1/verification-codes",
    tag = "auth",
    description = "Issue a one-time, email-proof code bound to a purpose (signup / \
                   password_reset / enrollment). Public, per-IP rate-limited. Emailed in \
                   production; returned here in dev.",
    request_body = VerificationCodeRequest,
    responses(
        (status = 200, description = "Code issued", body = VerificationCodeResponse),
        (status = 400, description = "Invalid email"),
        (status = 429, description = "Per-IP rate limit exceeded"),
    ),
    security(()),
)]
async fn create_verification_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<VerificationCodeRequest>,
) -> Result<Json<VerificationCodeResponse>, ApiError> {
    let remote_ip = client_ip(&headers, addr);
    // Password-reset issuance stays an Identities concern (the one-way Identities →
    // TenantsService edge); signup + enrollment go straight to the tenant aggregate.
    // All three land on the purpose-aware `issue_signup_code`.
    let code = match body.purpose {
        CodePurpose::PasswordReset => {
            state
                .identities()
                .request_password_reset(&body.email, &remote_ip)
                .await?
        }
        purpose @ (CodePurpose::Signup | CodePurpose::Enrollment | CodePurpose::PasswordChange) => {
            state
                .tenants()
                .issue_signup_code(&body.email, &remote_ip, purpose)
                .await?
        }
    };
    // Emailed in production → don't echo it; dev/no-op sender → return it.
    let code = (!state.tenants().email_delivers()).then_some(code);
    Ok(Json(VerificationCodeResponse { code }))
}
