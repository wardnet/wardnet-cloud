//! `POST /v1/billing/stripe/webhook` — bootstrap endpoint (auth = the Stripe
//! signature).
//!
//! Stripe delivers subscription-lifecycle events here. The endpoint is
//! unauthenticated in the JWT sense — the **`Stripe-Signature` header is the
//! credential**, verified in the handler (mirroring the enroll/token bootstrap
//! pattern). Delivery is idempotent (Stripe redelivers; the service dedupes by event
//! id). The account-plane billing endpoints (checkout-session / portal) live with the
//! other USER routes in [`crate::api::tenants`].

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::ApiError;
use crate::state::AppState;

/// Register the Stripe webhook route (bootstrap group, no auth layer).
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(stripe_webhook))
}

#[utoipa::path(
    post,
    path = "/v1/billing/stripe/webhook",
    tag = "billing",
    description = "Stripe subscription-lifecycle webhook. Unauthenticated: the \
                   Stripe-Signature header is verified as the credential. Idempotent.",
    request_body = String,
    responses(
        (status = 200, description = "Event accepted (or a harmless redelivery)"),
        (status = 400, description = "Missing/invalid signature or payload"),
    ),
    security(()),
)]
async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::BadRequest("missing Stripe-Signature header".to_string()))?;
    state.billing().handle_webhook(&body, signature).await?;
    Ok(StatusCode::OK)
}
