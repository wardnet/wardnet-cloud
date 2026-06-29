//! Human/web authentication endpoints (WS-F, ADR-0009) — the **bootstrap** group
//! (own-credential, no JWT layer): each verifies its own one-time code / password /
//! session cookie / OAuth `state`.
//!
//! The browser-durable credential is an httpOnly **session cookie** (encrypted via the
//! `axum-extra` private jar); the SPA never reads it. API calls go through
//! `POST /v1/auth/token`, which reads the cookie and mints a short-TTL `USER` JWT — so
//! the auth layer itself stays pure-JWT (invariant #18). Federated login is
//! backend-orchestrated with `state`/PKCE stashed in a separate short-lived signed
//! cookie.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Redirect;
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::contract::{
    PasswordLoginRequest, PasswordResetRequest, PasswordSignupRequest, TokenResponse,
};
use wardnet_common::proxy_protocol::client_ip;

use super::cookies::{OAUTH_COOKIE, SESSION_COOKIE, cleared, oauth_cookie, session_cookie};
use crate::error::ApiError;
use crate::state::AppState;

/// Register all web-auth bootstrap routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(password_signup))
        .routes(routes!(password_login))
        .routes(routes!(password_reset))
        .routes(routes!(oidc_start))
        .routes(routes!(oidc_callback))
        .routes(routes!(token))
        .routes(routes!(logout))
}

// ── Password ────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/v1/auth/password/signup", tag = "auth",
    description = "Sign up with email + password (the one-time code proves the email). \
                   Sets the session cookie on success.",
    request_body = PasswordSignupRequest,
    responses(
        (status = 204, description = "Signed up; session cookie set"),
        (status = 400, description = "Weak password"),
        (status = 401, description = "Bad or expired code"),
        (status = 409, description = "Email already has a password"),
    ),
    security(()),
)]
async fn password_signup(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(body): Json<PasswordSignupRequest>,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    let token = state
        .identities()
        .password_signup(&body.email, &body.code, &body.password)
        .await?;
    Ok((jar.add(session_cookie(token)), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    post, path = "/v1/auth/password/login", tag = "auth",
    description = "Log in with email + password. Sets the session cookie on success.",
    request_body = PasswordLoginRequest,
    responses(
        (status = 204, description = "Logged in; session cookie set"),
        (status = 401, description = "Invalid email or password"),
    ),
    security(()),
)]
async fn password_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
    Json(body): Json<PasswordLoginRequest>,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    let remote_ip = client_ip(&headers, addr);
    let token = state
        .identities()
        .password_login(&body.email, &body.password, &remote_ip)
        .await?;
    Ok((jar.add(session_cookie(token)), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    post, path = "/v1/auth/password/reset", tag = "auth",
    description = "Reset (or set) the account password from a one-time code; force-logs-out \
                   every existing session.",
    request_body = PasswordResetRequest,
    responses(
        (status = 204, description = "Password reset"),
        (status = 400, description = "Weak password"),
        (status = 401, description = "Bad or expired code"),
    ),
    security(()),
)]
async fn password_reset(
    State(state): State<AppState>,
    Json(body): Json<PasswordResetRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .identities()
        .password_reset(&body.code, &body.password)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Federated (OIDC / OAuth2) ─────────────────────────────────────────────────────

/// The CSRF/PKCE bundle stashed in the OAuth cookie across the redirect. When
/// `link_tenant` is set, the callback **links** the verified identity to that
/// already-authenticated tenant instead of logging in (the `mode=link` flow, PR3).
#[derive(Serialize, Deserialize)]
struct OauthStash {
    csrf_state: String,
    verifier: String,
    /// The tenant to link the verified identity to (`mode=link`), or `None` for login.
    #[serde(default)]
    link_tenant: Option<String>,
}

/// Start query params (`?mode=link` to link to the signed-in account, else login).
#[derive(Deserialize)]
struct StartQuery {
    #[serde(default)]
    mode: Option<String>,
}

/// Callback query params (`?code=...&state=...`).
#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[utoipa::path(
    get, path = "/v1/auth/oidc/{provider}/start", tag = "auth",
    description = "Begin federated login: stash CSRF/PKCE in a signed cookie and 302 to \
                   the provider. With ?mode=link (called while signed in via the session \
                   cookie) the callback links the verified identity to the current account.",
    params(
        ("provider" = String, Path, description = "google | github"),
        ("mode" = Option<String>, Query, description = "\"link\" to link to the signed-in account"),
    ),
    responses(
        (status = 302, description = "Redirect to the provider"),
        (status = 400, description = "Unknown/unconfigured provider"),
        (status = 401, description = "mode=link without an active session"),
    ),
    security(()),
)]
async fn oidc_start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<StartQuery>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), ApiError> {
    // mode=link carries the current tenant through the (encrypted) stash. A top-level
    // browser navigation can't send a bearer JWT, so the signed-in tenant is resolved
    // from the session cookie (ADR-0009).
    let link_tenant = if query.mode.as_deref() == Some("link") {
        let session = jar
            .get(SESSION_COOKIE)
            .ok_or_else(|| ApiError::Unauthorized("must be signed in to link".to_string()))?;
        Some(
            state
                .identities()
                .tenant_for_session(session.value())
                .await?
                .ok_or_else(|| ApiError::Unauthorized("no active session".to_string()))?,
        )
    } else {
        None
    };
    let authorize = state.identities().oidc_start(&provider)?;
    let stash = serde_json::to_string(&OauthStash {
        csrf_state: authorize.csrf_state,
        verifier: authorize.verifier,
        link_tenant,
    })
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize oauth stash: {e}")))?;
    Ok((jar.add(oauth_cookie(stash)), Redirect::to(&authorize.url)))
}

#[utoipa::path(
    get, path = "/v1/auth/oidc/{provider}/callback", tag = "auth",
    description = "Federated callback: validate state, exchange the code, then either log \
                   in (set the session cookie) or — for a mode=link flow — link the \
                   verified identity to the current account. 302s back to the account SPA.",
    params(("provider" = String, Path, description = "google | github")),
    responses(
        (status = 302, description = "Logged in / linked; redirect to the SPA"),
        (status = 401, description = "State mismatch / unverified email / exchange failure"),
        (status = 409, description = "Provider identity already linked to another account"),
    ),
    security(()),
)]
async fn oidc_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(params): Query<CallbackQuery>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), ApiError> {
    let stash = jar
        .get(OAUTH_COOKIE)
        .ok_or_else(|| ApiError::Unauthorized("missing or expired oauth state".to_string()))?;
    let stash: OauthStash = serde_json::from_str(stash.value())
        .map_err(|_| ApiError::Unauthorized("malformed oauth state".to_string()))?;
    // CSRF guard: the provider must echo back the exact state we stashed.
    if params.state != stash.csrf_state {
        return Err(ApiError::Unauthorized("oauth state mismatch".to_string()));
    }
    let account_spa = state.config().account_base_url.as_str();
    if let Some(tenant_id) = stash.link_tenant {
        // Re-check the session is still live and still this tenant's at callback time —
        // it may have been revoked (sign-out-all / deregister) during the provider
        // round-trip, in which case the link must not complete.
        let still_signed_in = match jar.get(SESSION_COOKIE) {
            Some(session) => {
                state
                    .identities()
                    .tenant_for_session(session.value())
                    .await?
                    == Some(tenant_id.clone())
            }
            None => false,
        };
        let jar = jar.remove(cleared(OAUTH_COOKIE));
        if !still_signed_in {
            return Err(ApiError::Unauthorized(
                "session is no longer valid; sign in again to link".to_string(),
            ));
        }
        // Already signed in: attach the verified identity, no new session.
        state
            .identities()
            .link_identity(&provider, &params.code, &stash.verifier, &tenant_id)
            .await?;
        Ok((jar, Redirect::to(account_spa)))
    } else {
        let jar = jar.remove(cleared(OAUTH_COOKIE));
        let token = state
            .identities()
            .oidc_callback(&provider, &params.code, &stash.verifier)
            .await?;
        Ok((jar.add(session_cookie(token)), Redirect::to(account_spa)))
    }
}

// ── Session lifecycle ──────────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/v1/auth/token", tag = "auth",
    description = "Silent exchange: read the session cookie and mint a short-TTL USER JWT \
                   (aud:[tenants]). The SPA holds the JWT only in memory.",
    responses(
        (status = 200, description = "USER JWT minted", body = TokenResponse),
        (status = 401, description = "No active session"),
    ),
    security(()),
)]
async fn token(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<Json<TokenResponse>, ApiError> {
    let session = jar
        .get(SESSION_COOKIE)
        .ok_or_else(|| ApiError::Unauthorized("not logged in".to_string()))?;
    let token = state.identities().exchange_session(session.value()).await?;
    Ok(Json(TokenResponse { token }))
}

#[utoipa::path(
    post, path = "/v1/auth/logout", tag = "auth",
    description = "Delete the current session (server-side) and clear the cookie. Idempotent.",
    responses((status = 204, description = "Logged out")),
    security(()),
)]
async fn logout(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    if let Some(session) = jar.get(SESSION_COOKIE) {
        state.identities().logout(session.value()).await?;
    }
    Ok((jar.remove(cleared(SESSION_COOKIE)), StatusCode::NO_CONTENT))
}
