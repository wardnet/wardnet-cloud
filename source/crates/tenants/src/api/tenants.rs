//! Account-plane endpoints (auth = `USER`).
//!
//! Tenant creation + management reads + the lifecycle writes (add-daemon code,
//! subscription cancel cascade, network delete). User login is out of scope this
//! session, so these are exercised via test-minted user JWTs; every `{id}`-scoped
//! route checks the path tenant against the caller's own tenant.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};
use wardnet_common::contract::{
    CodeResponse, DaemonView, NetworkView, RegisterTenantRequest, SubscriptionView, TenantView,
    UpdateTenantRequest,
};

use crate::error::ApiError;
use crate::repository::{Daemon, Subscription, Tenant};
use crate::state::AppState;

/// Register all account-plane routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(register_tenant))
        .routes(routes!(issue_tenant_code))
        .routes(routes!(list_networks))
        .routes(routes!(list_tenant_daemons))
        .routes(routes!(list_network_daemons))
        .routes(routes!(update_tenant, delete_tenant))
        .routes(routes!(delete_network))
}

// ── Domain → contract conversions (orphan rule OK: the domain type is local) ───

impl From<Subscription> for SubscriptionView {
    fn from(s: Subscription) -> Self {
        Self {
            id: s.id,
            status: s.status,
            entitlement: s.entitlement,
            stripe_customer_id: s.stripe_customer_id,
            stripe_subscription_id: s.stripe_subscription_id,
            price_id: s.price_id,
            trial_expires_at: s.trial_expires_at,
            current_period_end: s.current_period_end,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

/// Build the full [`TenantView`] from a tenant and its current subscription.
pub(crate) fn tenant_view(tenant: Tenant, subscription: Option<Subscription>) -> TenantView {
    TenantView {
        id: tenant.id,
        email: tenant.email,
        subscription: subscription.map(Into::into),
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
    post, path = "/v1/tenants", tag = "tenants",
    description = "Create a tenant (management plane). Entitlement defaults to 1/1.",
    request_body = RegisterTenantRequest,
    responses(
        (status = 200, description = "Tenant created", body = TenantView),
        (status = 400, description = "Invalid email"),
        (status = 409, description = "Email already taken"),
        (status = 401, description = "Unauthenticated"),
    ),
)]
async fn register_tenant(
    State(state): State<AppState>,
    AuthCaller(_caller): AuthCaller,
    Json(body): Json<RegisterTenantRequest>,
) -> Result<Json<TenantView>, ApiError> {
    let tenant = state.tenants().register_tenant(&body.email).await?;
    // The trial subscription is opened by the subscription reactor reacting to the
    // published `TenantCreated`, so it may not be visible yet — read whatever is
    // current (typically none for a brand-new tenant) and let the SPA refresh.
    let subscription = state.subscriptions().current(&tenant.id).await?;
    Ok(Json(tenant_view(tenant, subscription)))
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
    state.subscriptions().cancel(&id).await?;
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
