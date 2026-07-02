//! Account-plane **security** endpoints (auth = `USER`), the My-Account Security tab's
//! backing surface (PR3, #18). Caller-scoped (`/v1/me/*`, no path id), in the Identities
//! aggregate: the connected sign-in methods (list + unlink) and sign-out-of-all-sessions.
//! Provider **linking** is the `mode=link` branch of the OIDC flow in [`super::auth`].

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum_extra::extract::PrivateCookieJar;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller, UserCaller};
use wardnet_common::contract::{ConnectedIdentityView, SetPasswordRequest};

use super::cookies::{SESSION_COOKIE, cleared, session_cookie};
use crate::error::ApiError;
use crate::repository::identity::TenantIdentity;
use crate::state::AppState;

/// Register the account-security routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(list_identities))
        .routes(routes!(unlink_identity))
        .routes(routes!(signout_all))
        .routes(routes!(set_password))
}

/// Require a `USER` caller (the `/v1/me/*` plane is human-only). The route layer already
/// gates on `CallerType::USER`, so this only narrows the verified caller to its claims.
fn require_user(caller: &Caller) -> Result<&UserCaller, ApiError> {
    match caller {
        Caller::User(user) => Ok(user),
        _ => Err(ApiError::Forbidden("user credential required".to_string())),
    }
}

// ── Domain → contract conversion (orphan rule OK: the domain type is local) ─────

impl From<TenantIdentity> for ConnectedIdentityView {
    fn from(i: TenantIdentity) -> Self {
        // The verified email is the human-facing label; the secret hash + opaque
        // subject are deliberately dropped (invariant #1 — never leak the credential).
        Self {
            provider: i.provider,
            label: i.email,
            connected_at: i.created_at,
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/v1/me/identities", tag = "tenants",
    description = "List the caller's connected login methods. Never leaks secret hashes.",
    responses(
        (status = 200, description = "Connected login methods", body = [ConnectedIdentityView]),
        (status = 401, description = "Unauthenticated"),
    ),
)]
async fn list_identities(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
) -> Result<Json<Vec<ConnectedIdentityView>>, ApiError> {
    let user = require_user(&caller)?;
    let identities = state.identities().list_identities(&user.tenant_id).await?;
    Ok(Json(identities.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    delete, path = "/v1/me/identities/{provider}", tag = "tenants",
    description = "Unlink a login method. At least one login method must always remain.",
    params(("provider" = String, Path, description = "password | google | github")),
    responses(
        (status = 204, description = "Unlinked (idempotent)"),
        (status = 401, description = "Unauthenticated"),
        (status = 409, description = "Would remove the last login method"),
    ),
)]
async fn unlink_identity(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Path(provider): Path<String>,
) -> Result<StatusCode, ApiError> {
    let user = require_user(&caller)?;
    state
        .identities()
        .unlink_identity(&user.tenant_id, &provider)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete, path = "/v1/me/sessions", tag = "tenants",
    description = "Sign out of all sessions (including the current one) and clear the cookie.",
    responses(
        (status = 204, description = "All sessions revoked"),
        (status = 401, description = "Unauthenticated"),
    ),
)]
async fn signout_all(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    let user = require_user(&caller)?;
    state.identities().logout_all(&user.tenant_id).await?;
    Ok((jar.remove(cleared(SESSION_COOKIE)), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    post, path = "/v1/me/password", tag = "tenants",
    description = "Set or change the caller's password, proven by a fresh one-time email \
        code for the caller's own account email. Revokes every existing session (evicting \
        other devices) and issues a new session cookie for this browser, so the caller \
        stays signed in.",
    request_body = SetPasswordRequest,
    responses(
        (status = 204, description = "Password set; a fresh session cookie is issued"),
        (status = 400, description = "Weak password"),
        (status = 401, description = "Unauthenticated, or a bad/expired/mismatched code"),
    ),
)]
async fn set_password(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    jar: PrivateCookieJar,
    Json(body): Json<SetPasswordRequest>,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    let user = require_user(&caller)?;
    let token = state
        .identities()
        .set_password_authenticated(&user.tenant_id, &body.code, &body.password)
        .await?;
    Ok((jar.add(session_cookie(token)), StatusCode::NO_CONTENT))
}
