//! Shared web-auth cookie helpers.
//!
//! The encrypted session cookie (the browser-durable credential) and the short-lived
//! OAuth `state`/PKCE cookie are built here so both the login surface (`api::auth`) and
//! the account-plane sign-out handler (`api::me`) agree on the cookie names + attributes
//! (httpOnly + Secure + SameSite=Lax). The SPA never reads these — they are exchanged
//! for a short-TTL `USER` JWT via `POST /v1/auth/token` (ADR-0009, invariant #18).

use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

/// The encrypted session cookie (the browser-durable web credential).
pub(crate) const SESSION_COOKIE: &str = "wardnet_session";
/// The short-lived OAuth `state`/PKCE cookie (one in-flight federated login).
pub(crate) const OAUTH_COOKIE: &str = "wardnet_oauth";
/// Session cookie lifetime — 30 days (the server-side row slides on each exchange).
const SESSION_COOKIE_DAYS: i64 = 30;
/// OAuth `state` cookie lifetime — long enough to complete the provider round-trip.
const OAUTH_COOKIE_MINUTES: i64 = 10;

/// Build the session cookie carrying `token` (httpOnly + Secure + SameSite=Lax).
pub(crate) fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::days(SESSION_COOKIE_DAYS))
        .build()
}

/// Build the short-lived OAuth `state`/PKCE cookie carrying `value`.
pub(crate) fn oauth_cookie(value: String) -> Cookie<'static> {
    Cookie::build((OAUTH_COOKIE, value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::minutes(OAUTH_COOKIE_MINUTES))
        .build()
}

/// A removal cookie for `name` (Path=/ so it matches the one we set).
pub(crate) fn cleared(name: &'static str) -> Cookie<'static> {
    Cookie::build((name, "")).path("/").build()
}
