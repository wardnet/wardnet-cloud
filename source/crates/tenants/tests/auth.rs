//! HTTP-level integration tests over the mock-backed router for the web-auth surface
//! (WS-F): password signup/login/reset, the OIDC callback against a mock provider,
//! the session→JWT exchange, `GET /v1/me`, logout, and the OIDC auto-link path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use serde_json::{Value, json};
use tower::ServiceExt;

use wardnet_tenants::api;
use wardnet_tenants::identities::provider::{ExternalIdentityProvider, VerifiedIdentity};
use wardnet_tenants::repository::tenant::Tenant;
use wardnet_tenants::test_helpers::{Harness, MockIdentityProvider, build_harness_with_providers};

const SEED: u8 = 5;

/// Build a router + harness with the given mock OIDC provider registered as `google`.
fn app_with_google(identity: VerifiedIdentity) -> (Router, Harness) {
    let mut providers: HashMap<String, Arc<dyn ExternalIdentityProvider>> = HashMap::new();
    providers.insert(
        "google".to_string(),
        Arc::new(MockIdentityProvider::new(identity)),
    );
    let h = build_harness_with_providers(SEED, providers);
    (api::router(h.state.clone()), h)
}

fn plain_app() -> (Router, Harness) {
    let h = build_harness_with_providers(SEED, HashMap::new());
    (api::router(h.state.clone()), h)
}

fn connect_info() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999)))
}

fn post_json(uri: &str, body: &Value) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    // Handlers that read the client IP (login, reset-code) extract ConnectInfo; attach
    // it to every POST so oneshot requests resolve it (ignored by handlers that don't).
    req.extensions_mut().insert(connect_info());
    req
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Extract a `name=value` cookie pair from the response's `Set-Cookie` headers, ready
/// to replay verbatim as a `Cookie:` request header (the value stays encrypted — the
/// server decrypts it with its key).
fn cookie_pair(resp: &axum::response::Response, name: &str) -> String {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|c| c.split(';').next().unwrap_or("").to_string())
        .find(|pair| pair.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no Set-Cookie for {name} in {:?}", resp.headers()))
}

/// Issue a signup code through the public enrollment-code endpoint (dev echoes it).
async fn signup_code(app: &Router, email: &str) -> String {
    let mut req = post_json("/v1/enrollment-codes", &json!({ "email": email }));
    req.extensions_mut().insert(connect_info());
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    json_body(resp).await["code"].as_str().unwrap().to_string()
}

// ── Password ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_signup_sets_session_then_token_exchange_mints_jwt() {
    let (app, _h) = plain_app();
    let code = signup_code(&app, "alice@example.com").await;

    // Signup → 204 + session cookie.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": "alice@example.com", "code": code, "password": "hunter2hunter2" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let session = cookie_pair(&resp, "wardnet_session");

    // The cookie exchanges to a USER JWT.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let jwt = json_body(resp).await["token"].as_str().unwrap().to_string();

    // And that JWT authenticates GET /v1/me.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["email"], "alice@example.com");
}

#[tokio::test]
async fn token_exchange_without_cookie_is_unauthorized() {
    let (app, _h) = plain_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_cookie_is_httponly_secure_samesite() {
    // The browser-durable credential must be unreadable to JS (HttpOnly), TLS-only
    // (Secure), and SameSite-scoped — dropping any of these widens hijack/CSRF exposure.
    let (app, _h) = plain_app();
    let code = signup_code(&app, "carol@example.com").await;
    let resp = app
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": "carol@example.com", "code": code, "password": "hunter2hunter2" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("wardnet_session="))
        .expect("a wardnet_session Set-Cookie header")
        .to_string();
    assert!(
        raw.contains("HttpOnly"),
        "session cookie must be HttpOnly: {raw}"
    );
    assert!(
        raw.contains("Secure"),
        "session cookie must be Secure: {raw}"
    );
    assert!(
        raw.contains("SameSite=Lax"),
        "session cookie must be SameSite=Lax: {raw}"
    );
}

#[tokio::test]
async fn login_after_signup_succeeds_and_logout_revokes() {
    let (app, _h) = plain_app();
    let code = signup_code(&app, "bob@example.com").await;
    app.clone()
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": "bob@example.com", "code": code, "password": "longenough1" }),
        ))
        .await
        .unwrap();

    // Login → session cookie.
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "bob@example.com", "password": "longenough1" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let session = cookie_pair(&resp, "wardnet_session");

    // Logout deletes the server-side session.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The old cookie no longer exchanges.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_with_wrong_password_is_unauthorized() {
    let (app, _h) = plain_app();
    let code = signup_code(&app, "carol@example.com").await;
    app.clone()
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": "carol@example.com", "code": code, "password": "rightpassword" }),
        ))
        .await
        .unwrap();

    let resp = app
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "carol@example.com", "password": "wrongpassword" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_reset_changes_the_password() {
    let (app, _h) = plain_app();
    let code = signup_code(&app, "dave@example.com").await;
    app.clone()
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": "dave@example.com", "code": code, "password": "originalpass" }),
        ))
        .await
        .unwrap();

    // Request a reset code (dev echoes it), then reset.
    let mut req = post_json(
        "/v1/auth/password/reset-code",
        &json!({ "email": "dave@example.com" }),
    );
    req.extensions_mut().insert(connect_info());
    let resp = app.clone().oneshot(req).await.unwrap();
    let reset_code = json_body(resp).await["code"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/reset",
            &json!({ "code": reset_code, "password": "brandnewpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // New password works, old one does not.
    let ok = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "dave@example.com", "password": "brandnewpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    let bad = app
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "dave@example.com", "password": "originalpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
}

// ── Federated (mock provider) ─────────────────────────────────────────────────────

/// Drive `start` then `callback`, returning the callback response (302 + session).
async fn oidc_login(app: &Router, code: &str) -> axum::response::Response {
    // start → 302 + the signed oauth cookie.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let oauth = cookie_pair(&resp, "wardnet_oauth");

    // callback (the MockIdentityProvider's authorize_url uses csrf_state "test-state").
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/auth/oidc/google/callback?code={code}&state=test-state"
                ))
                .header(header::COOKIE, &oauth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn oidc_callback_creates_account_and_session() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "google-sub-1".to_string(),
        email: "newuser@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);

    let resp = oidc_login(&app, "auth-code-xyz").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session = cookie_pair(&resp, "wardnet_session");

    // The session exchanges, and /v1/me shows the web-first-signup account.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwt = json_body(resp).await["token"].as_str().unwrap().to_string();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/me")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(resp).await["email"], "newuser@example.com");
}

#[tokio::test]
async fn oidc_callback_auto_links_daemon_born_tenant() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "google-sub-2".to_string(),
        email: "owner@example.com".to_string(),
        email_verified: true,
    };
    let (app, h) = app_with_google(identity);
    // A tenant for this email already exists (born via daemon enroll, no login method).
    h.store.seed_tenant(Tenant {
        id: "tenant-daemon-born".to_string(),
        email: "owner@example.com".to_string(),
        created_at: Utc::now(),
        deregistered_at: None,
    });

    let resp = oidc_login(&app, "auth-code-link").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session = cookie_pair(&resp, "wardnet_session");

    // The minted JWT's subject is the pre-existing tenant — the OIDC identity linked,
    // it did not create a second tenant.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwt = json_body(resp).await["token"].as_str().unwrap().to_string();
    // sub == the daemon-born tenant id (the auto-link target).
    let payload = jwt.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&base64_url_decode(payload)).unwrap();
    assert_eq!(claims["sub"], "tenant-daemon-born");
}

#[tokio::test]
async fn oidc_callback_with_bad_state_is_rejected() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "google-sub-3".to_string(),
        email: "x@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);

    // start to obtain the oauth cookie, then present a mismatched `state`.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let oauth = cookie_pair(&resp, "wardnet_oauth");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/callback?code=c&state=WRONG")
                .header(header::COOKIE, &oauth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Minimal base64url-decode for a JWT payload segment (no padding).
fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}
