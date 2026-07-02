//! Account-plane endpoints (auth = `USER`).
//!
//! Tenant creation + management reads + the lifecycle writes (add-daemon code,
//! subscription cancel cascade, network delete). User login is out of scope this
//! session, so these are exercised via test-minted user JWTs; every `{id}`-scoped
//! route checks the path tenant against the caller's own tenant.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};
use wardnet_common::contract::{
    BillingSubscriptionView, ChangePlanRequest, ChangePlanResponse, CheckoutSessionResponse,
    CodeResponse, CreateCheckoutSessionRequest, DaemonView, InvoiceView, MeView, NetworkView,
    PaymentMethodView, PromoUnavailableBody, SubscriptionView, TenantView, UpdateTenantRequest,
};
use wardnet_common::ports::BillingError;

use crate::error::ApiError;
use crate::repository::{Daemon, Tenant};
use crate::state::AppState;

/// Register all account-plane routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(me))
        .routes(routes!(issue_tenant_code))
        .routes(routes!(list_networks))
        .routes(routes!(list_tenant_daemons))
        .routes(routes!(list_network_daemons))
        .routes(routes!(update_tenant, delete_tenant))
        .routes(routes!(delete_network))
        .routes(routes!(create_checkout_session))
        .routes(routes!(change_plan))
        .routes(routes!(start_card_update))
        .routes(routes!(get_billing_subscription))
        .routes(routes!(get_payment_method))
        .routes(routes!(list_invoices))
}

/// Map a `BillingError` to a response, rendering a `PromoUnavailable` as a structured
/// `409` (with the real price for the SPA to re-confirm) and everything else through the
/// standard `ApiError` mapping.
fn billing_err_response(e: BillingError) -> Response {
    match e {
        BillingError::PromoUnavailable {
            actual_amount_cents,
            currency,
        } => (
            StatusCode::CONFLICT,
            Json(PromoUnavailableBody {
                error: "promo_unavailable".to_string(),
                actual_amount_cents,
                currency,
            }),
        )
            .into_response(),
        other => ApiError::from(other).into_response(),
    }
}

// ── Domain → contract conversions (orphan rule OK: the domain type is local) ───
//
// `From<Subscription> for SubscriptionView` now lives in the `subscriptions` crate
// (it owns `Subscription`); handlers receive the `SubscriptionView` straight from the
// `SubscriptionReader` port.

/// Build the full [`TenantView`] from a tenant and its current subscription view.
pub(crate) fn tenant_view(tenant: Tenant, subscription: Option<SubscriptionView>) -> TenantView {
    TenantView {
        id: tenant.id,
        email: tenant.email,
        subscription,
        created_at: tenant.created_at,
    }
}

impl From<Daemon> for DaemonView {
    fn from(d: Daemon) -> Self {
        Self {
            id: d.id,
            network_id: d.network_id,
            public_key: d.public_key,
            created_at: d.created_at,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the user caller and ensure it owns `tenant_id`.
fn require_owner<'a>(caller: &'a Caller, tenant_id: &str) -> Result<&'a str, ApiError> {
    match caller {
        Caller::User(u) if u.tenant_id == tenant_id => Ok(&u.user_id),
        Caller::User(_) => Err(ApiError::Forbidden("not your tenant".to_string())),
        _ => Err(ApiError::Forbidden("user credential required".to_string())),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/v1/me", tag = "tenants",
    description = "The current user's account profile (the SPA's identity bootstrap).",
    responses(
        (status = 200, description = "Account profile", body = MeView),
        (status = 401, description = "Unauthenticated"),
        (status = 404, description = "Account no longer exists"),
    ),
)]
async fn me(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
) -> Result<Json<MeView>, ApiError> {
    let Caller::User(user) = &caller else {
        return Err(ApiError::Forbidden("user credential required".to_string()));
    };
    let tenant = state
        .tenants()
        .find_tenant(&user.tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such tenant".to_string()))?;
    let subscription = state
        .subscriptions()
        .current(&user.tenant_id)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(MeView {
        tenant_id: tenant.id,
        email: tenant.email,
        subscription,
    }))
}

#[utoipa::path(
    post, path = "/v1/tenants/{id}/codes", tag = "tenants",
    description = "Issue an add-daemon one-time code for an existing tenant.",
    responses(
        (status = 200, description = "Code issued", body = CodeResponse),
        (status = 403, description = "Not your tenant"),
        (status = 404, description = "No such tenant"),
    ),
)]
async fn issue_tenant_code(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<CodeResponse>, ApiError> {
    require_owner(&caller, &id)?;
    let code = state.tenants().issue_tenant_code(&id).await?;
    let code = (!state.tenants().email_delivers()).then_some(code);
    Ok(Json(CodeResponse { code }))
}

#[utoipa::path(
    get, path = "/v1/tenants/{id}/networks", tag = "tenants",
    description = "List a tenant's networks.",
    responses((status = 200, body = [NetworkView]), (status = 403, description = "Not your tenant")),
)]
async fn list_networks(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<Vec<NetworkView>>, ApiError> {
    require_owner(&caller, &id)?;
    let networks = state.tenants().list_networks(&id).await?;
    Ok(Json(networks.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get, path = "/v1/tenants/{id}/daemons", tag = "tenants",
    description = "List a tenant's daemons.",
    responses((status = 200, body = [DaemonView]), (status = 403, description = "Not your tenant")),
)]
async fn list_tenant_daemons(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<Vec<DaemonView>>, ApiError> {
    require_owner(&caller, &id)?;
    let daemons = state.tenants().list_tenant_daemons(&id).await?;
    Ok(Json(daemons.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get, path = "/v1/networks/{id}/daemons", tag = "networks",
    description = "List a network's daemons (scoped to the caller's tenant).",
    responses((status = 200, body = [DaemonView]), (status = 404, description = "No such network")),
)]
async fn list_network_daemons(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<DaemonView>>, ApiError> {
    let Caller::User(user) = &caller else {
        return Err(ApiError::Forbidden("user credential required".to_string()));
    };
    let daemons = state
        .tenants()
        .list_network_daemons(&user.tenant_id, &network_id)
        .await?;
    Ok(Json(daemons.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    patch, path = "/v1/tenants/{id}", tag = "tenants",
    description = "Update a tenant. Currently only subscription_status=canceled, which \
                   cascades the tenant's networks to deprovisioning.",
    request_body = UpdateTenantRequest,
    responses(
        (status = 204, description = "Updated"),
        (status = 400, description = "Unsupported update"),
        (status = 403, description = "Not your tenant"),
        (status = 404, description = "No such tenant"),
    ),
)]
async fn update_tenant(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<StatusCode, ApiError> {
    require_owner(&caller, &id)?;
    if body.subscription_status != "canceled" {
        return Err(ApiError::BadRequest(
            "only subscription_status=canceled is supported".to_string(),
        ));
    }
    // Cancelling deactivates the subscription; the network-deprovision cascade follows
    // from the published `SubscriptionDeactivated` event (network reactor).
    state
        .subscription_commands()
        .cancel(&id)
        .await
        .map_err(ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/tenants/{id}/networks/{slug}", tag = "tenants",
    description = "Mark a network for deprovisioning (the reaper tears down DNS, then \
                   deletes the row).",
    responses(
        (status = 202, description = "Accepted; network is deprovisioning"),
        (status = 403, description = "Not your tenant"),
        (status = 404, description = "No such network"),
    ),
)]
async fn delete_network(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path((id, slug)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_owner(&caller, &id)?;
    state.tenants().delete_network(&id, &slug).await?;
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    delete, path = "/v1/tenants/{id}", tag = "tenants",
    description = "Deregister (tombstone) the account: all its networks are marked for \
                   deprovisioning, its subscription is canceled, and once the networks are \
                   fully reaped the account row is swept. Idempotent.",
    responses(
        (status = 202, description = "Accepted; account is deregistering"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
        (status = 404, description = "No such tenant"),
    ),
)]
async fn delete_tenant(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_owner(&caller, &id)?;
    // Idempotent: a repeat call on an already-tombstoned tenant still returns 202.
    state.tenants().deregister_tenant(&id).await?;
    Ok(StatusCode::ACCEPTED)
}

#[utoipa::path(
    post, path = "/v1/tenants/{id}/billing/checkout-session", tag = "tenants",
    description = "Start a Stripe Checkout for a plan; returns the URL to redirect to. \
                   Auto-applies the live promo unless accept_full_price re-confirms.",
    request_body = CreateCheckoutSessionRequest,
    responses(
        (status = 200, description = "Checkout session created", body = CheckoutSessionResponse),
        (status = 409, description = "A displayed promo lapsed; re-confirm at full price",
            body = PromoUnavailableBody),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
        (status = 404, description = "No such tenant"),
    ),
)]
async fn create_checkout_session(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
    Json(body): Json<CreateCheckoutSessionRequest>,
) -> Result<Response, ApiError> {
    require_owner(&caller, &id)?;
    // Cross-aggregate orchestration: read the tenant email here, then drive Billing
    // through its port (Billing never depends on the tenant aggregate).
    let tenant = state
        .tenants()
        .find_tenant(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such tenant".to_string()))?;
    match state
        .billing()
        .start_checkout(&id, &tenant.email, &body.price_id, body.accept_full_price)
        .await
    {
        Ok(url) => Ok(Json(CheckoutSessionResponse { url }).into_response()),
        Err(e) => Ok(billing_err_response(e)),
    }
}

#[utoipa::path(
    post, path = "/v1/tenants/{id}/billing/change-plan", tag = "tenants",
    description = "Change an already-paid subscription's plan. Upgrade is immediate; \
                   downgrade is scheduled for the period end. Entitlement lands via webhook.",
    request_body = ChangePlanRequest,
    responses(
        (status = 202, description = "Change applied/scheduled", body = ChangePlanResponse),
        (status = 400, description = "No paid subscription, unknown plan, or no-op change"),
        (status = 409, description = "A displayed promo lapsed; re-confirm at full price",
            body = PromoUnavailableBody),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
    ),
)]
async fn change_plan(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
    Json(body): Json<ChangePlanRequest>,
) -> Result<Response, ApiError> {
    require_owner(&caller, &id)?;
    match state
        .billing()
        .change_plan(&id, &body.price_id, body.accept_full_price)
        .await
    {
        Ok(resp) => Ok((StatusCode::ACCEPTED, Json(resp)).into_response()),
        Err(e) => Ok(billing_err_response(e)),
    }
}

#[utoipa::path(
    post, path = "/v1/tenants/{id}/billing/card-update", tag = "tenants",
    description = "Start a Stripe setup-mode Checkout to add/replace the card (no purchase); \
                   returns the URL to redirect to.",
    responses(
        (status = 200, description = "Setup session created", body = CheckoutSessionResponse),
        (status = 400, description = "Tenant has no billing account yet"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
    ),
)]
async fn start_card_update(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<CheckoutSessionResponse>, ApiError> {
    require_owner(&caller, &id)?;
    let url = state.billing().start_card_update(&id).await?;
    Ok(Json(CheckoutSessionResponse { url }))
}

#[utoipa::path(
    get, path = "/v1/tenants/{id}/billing/subscription", tag = "tenants",
    description = "Provider (Billing) view of the subscription: current Stripe price + any \
                   pending scheduled downgrade. Composed by the SPA with /v1/me.",
    responses(
        (status = 200, description = "Billing subscription view", body = BillingSubscriptionView),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
    ),
)]
async fn get_billing_subscription(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<BillingSubscriptionView>, ApiError> {
    require_owner(&caller, &id)?;
    Ok(Json(state.billing().billing_subscription(&id).await?))
}

#[utoipa::path(
    get, path = "/v1/tenants/{id}/billing/payment-method", tag = "tenants",
    description = "The tenant's default payment-method summary, or null. Read-only and \
                   provider-proxied; never PAN/CVC (SAQ-A).",
    responses(
        (status = 200, description = "Payment method summary, or null", body = Option<PaymentMethodView>),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
    ),
)]
async fn get_payment_method(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<Option<PaymentMethodView>>, ApiError> {
    require_owner(&caller, &id)?;
    Ok(Json(state.billing().payment_method(&id).await?))
}

#[utoipa::path(
    get, path = "/v1/tenants/{id}/billing/invoices", tag = "tenants",
    description = "Recent invoices, newest first; empty when the tenant has no provider \
                   customer. Read-only and provider-proxied.",
    responses(
        (status = 200, description = "Invoice history", body = [InvoiceView]),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not your tenant"),
    ),
)]
async fn list_invoices(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(id): Path<String>,
) -> Result<Json<Vec<InvoiceView>>, ApiError> {
    require_owner(&caller, &id)?;
    Ok(Json(state.billing().invoices(&id).await?))
}
