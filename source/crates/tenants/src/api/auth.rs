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
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::contract::{
    PasswordLoginRequest, PasswordResetRequest, PasswordSignupRequest, SignupCodeRequest,
    SignupCodeResponse, TokenResponse,
};
use wardnet_common::proxy_protocol::client_ip;

use crate::error::ApiError;
use crate::state::AppState;

/// The encrypted session cookie (the browser-durable web credential).
const SESSION_COOKIE: &str = "wardnet_session";
/// The short-lived OAuth `state`/PKCE cookie (one in-flight federated login).
const OAUTH_COOKIE: &str = "wardnet_oauth";
/// Session cookie lifetime — 30 days (the server-side row slides on each exchange).
const SESSION_COOKIE_DAYS: i64 = 30;
/// OAuth `state` cookie lifetime — long enough to complete the provider round-trip.
const OAUTH_COOKIE_MINUTES: i64 = 10;

/// Register all web-auth bootstrap routes.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router
        .routes(routes!(password_signup))
        .routes(routes!(password_login))
        .routes(routes!(request_password_reset))
        .routes(routes!(password_reset))
        .routes(routes!(oidc_start))
        .routes(routes!(oidc_callback))
        .routes(routes!(token))
        .routes(routes!(logout))
}

// ── Cookie helpers ──────────────────────────────────────────────────────────────

/// Build the session cookie carrying `token` (httpOnly + Secure + SameSite=Lax).
fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::days(SESSION_COOKIE_DAYS))
        .build()
}

/// Build the short-lived OAuth `state`/PKCE cookie carrying `value`.
fn oauth_cookie(value: String) -> Cookie<'static> {
    Cookie::build((OAUTH_COOKIE, value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::minutes(OAUTH_COOKIE_MINUTES))
        .build()
}

/// A removal cookie for `name` (Path=/ so it matches the one we set).
fn cleared(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, "")).path("/").build()
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
    jar: PrivateCookieJar,
    Json(body): Json<PasswordLoginRequest>,
) -> Result<(PrivateCookieJar, StatusCode), ApiError> {
    let token = state
        .identities()
        .password_login(&body.email, &body.password)
        .await?;
    Ok((jar.add(session_cookie(token)), StatusCode::NO_CONTENT))
}

#[utoipa::path(
    post, path = "/v1/auth/password/reset-code", tag = "auth",
    description = "Request a one-time password-reset code for an email (public, per-IP \
                   rate-limited). Emailed in production; returned here in dev.",
    request_body = SignupCodeRequest,
    responses(
        (status = 200, description = "Code issued", body = SignupCodeResponse),
        (status = 400, description = "Invalid email"),
        (status = 429, description = "Per-IP rate limit exceeded"),
    ),
    security(()),
)]
async fn request_password_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SignupCodeRequest>,
) -> Result<Json<SignupCodeResponse>, ApiError> {
    let remote_ip = client_ip(&headers, addr);
    let code = state
        .identities()
        .request_password_reset(&body.email, &remote_ip)
        .await?;
    // Emailed in production → don't echo it; dev/no-op sender → return it.
    let code = (!state.tenants().email_delivers()).then_some(code);
    Ok(Json(SignupCodeResponse { code }))
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

/// The CSRF/PKCE bundle stashed in the OAuth cookie across the redirect.
#[derive(Serialize, Deserialize)]
struct OauthStash {
    csrf_state: String,
    verifier: String,
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
                   the provider.",
    params(("provider" = String, Path, description = "google | github")),
    responses(
        (status = 302, description = "Redirect to the provider"),
        (status = 400, description = "Unknown/unconfigured provider"),
    ),
    security(()),
)]
async fn oidc_start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), ApiError> {
    let authorize = state.identities().oidc_start(&provider)?;
    let stash = serde_json::to_string(&OauthStash {
        csrf_state: authorize.csrf_state,
        verifier: authorize.verifier,
    })
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize oauth stash: {e}")))?;
    Ok((
        jar.add(oauth_cookie(stash)),
        Redirect::to(&authorize.url),
    ))
}

#[utoipa::path(
    get, path = "/v1/auth/oidc/{provider}/callback", tag = "auth",
    description = "Federated-login callback: validate state, exchange the code, set the \
                   session cookie, and 302 back to the account SPA.",
    params(("provider" = String, Path, description = "google | github")),
    responses(
        (status = 302, description = "Logged in; redirect to the SPA"),
        (status = 401, description = "State mismatch / unverified email / exchange failure"),
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
    let token = state
        .identities()
        .oidc_callback(&provider, &params.code, &stash.verifier)
        .await?;
    let jar = jar.remove(cleared(OAUTH_COOKIE)).add(session_cookie(token));
    Ok((jar, Redirect::to(state.config().account_base_url.as_str())))
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
    let token = state
        .identities()
        .exchange_session(session.value())
        .await?;
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
