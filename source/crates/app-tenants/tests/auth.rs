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
mod common;
use common::{Harness, MockIdentityProvider, build_harness_with_providers};

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

/// Issue a verification code of `purpose` through the public endpoint (dev echoes it).
async fn verification_code(app: &Router, email: &str, purpose: &str) -> String {
    let mut req = post_json(
        "/v1/verification-codes",
        &json!({ "email": email, "purpose": purpose }),
    );
    req.extensions_mut().insert(connect_info());
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    json_body(resp).await["code"].as_str().unwrap().to_string()
}

/// Issue a web-signup code (dev echoes it).
async fn signup_code(app: &Router, email: &str) -> String {
    verification_code(app, email, "signup").await
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
    let reset_code = verification_code(&app, "dave@example.com", "password_reset").await;

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

// ── Account security: verification-codes, connected methods, sessions (PR3) ────────

/// Sign up `email` and return the resulting `wardnet_session` cookie pair.
async fn signup_session(app: &Router, email: &str, password: &str) -> String {
    let code = signup_code(app, email).await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/signup",
            &json!({ "email": email, "code": code, "password": password }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    cookie_pair(&resp, "wardnet_session")
}

/// Exchange a session cookie for a USER bearer JWT.
async fn bearer_from_session(app: &Router, session: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    json_body(resp).await["token"].as_str().unwrap().to_string()
}

/// Status of a session→JWT exchange (200 live, 401 revoked).
async fn exchange_status(app: &Router, session: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/token")
                .header(header::COOKIE, session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Drive the OIDC `mode=link` flow with the signed-in `session` cookie; return the
/// callback response (303 on success, 409 on a cross-tenant collision).
async fn oidc_link(app: &Router, session: &str) -> axum::response::Response {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/start?mode=link")
                .header(header::COOKIE, session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let oauth = cookie_pair(&resp, "wardnet_oauth");
    // The browser sends both the oauth-state cookie and the (httpOnly) session cookie on
    // the callback navigation; the callback re-validates the session before linking.
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/callback?code=link-code&state=test-state")
                .header(header::COOKIE, format!("{oauth}; {session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn verification_codes_issue_for_every_purpose() {
    let (app, h) = plain_app();
    for purpose in ["signup", "password_reset", "enrollment"] {
        let code = verification_code(&app, "person@example.com", purpose).await;
        assert!(!code.is_empty());
    }
    // Each issuance emailed the code (the dev sender records it).
    assert_eq!(h.email.sent().len(), 3);
}

#[tokio::test]
async fn verification_codes_are_rate_limited_per_ip() {
    let (app, _h) = plain_app();
    // The per-IP budget is shared across purposes (all log to the same IP).
    for _ in 0..10 {
        let resp = app
            .clone()
            .oneshot(post_json(
                "/v1/verification-codes",
                &json!({ "email": "flood@example.com", "purpose": "signup" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/verification-codes",
            &json!({ "email": "flood@example.com", "purpose": "password_reset" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn me_identities_lists_methods_and_never_leaks_secrets() {
    let (app, _h) = plain_app();
    let session = signup_session(&app, "list@example.com", "longenough1").await;
    let jwt = bearer_from_session(&app, &session).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/me/identities")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw = String::from_utf8(bytes.to_vec()).unwrap();
    // No hashed secret ever crosses the wire.
    assert!(!raw.contains("secret"));
    assert!(!raw.contains("argon2"));
    let body: Value = serde_json::from_str(&raw).unwrap();
    let methods = body.as_array().unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0]["provider"], "password");
    assert_eq!(methods[0]["label"], "list@example.com");
}

#[tokio::test]
async fn oidc_link_attaches_provider_to_current_account() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "g-link-sub".to_string(),
        email: "linker@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);
    let session = signup_session(&app, "linker@example.com", "longenough1").await;

    let resp = oidc_link(&app, &session).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // The link sets no new session cookie (the user was already signed in).
    assert!(
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|v| !v.to_str().unwrap().starts_with("wardnet_session="))
    );

    // The account now lists both methods; the session/tenant is unchanged.
    let jwt = bearer_from_session(&app, &session).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/me/identities")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let methods = json_body(resp).await;
    let providers: Vec<String> = methods
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["provider"].as_str().unwrap().to_string())
        .collect();
    assert!(providers.contains(&"password".to_string()));
    assert!(providers.contains(&"google".to_string()));
}

#[tokio::test]
async fn oidc_link_rejects_a_cross_tenant_collision() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "g-shared-sub".to_string(),
        email: "owner-b@example.com".to_string(),
        email_verified: true,
    };
    let (app, h) = app_with_google(identity);
    // Tenant B already owns this google subject.
    h.store.seed_tenant(Tenant {
        id: "tenant-b".to_string(),
        email: "owner-b@example.com".to_string(),
        created_at: Utc::now(),
        deregistered_at: None,
    });
    h.store
        .seed_identity("tenant-b", "google", "g-shared-sub", "owner-b@example.com");

    // User A signs in and tries to link the same subject → 409.
    let session = signup_session(&app, "user-a@example.com", "longenough1").await;
    let resp = oidc_link(&app, &session).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn oidc_link_is_idempotent_for_the_same_account() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "g-idem-sub".to_string(),
        email: "idem@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);
    let session = signup_session(&app, "idem@example.com", "longenough1").await;

    assert_eq!(
        oidc_link(&app, &session).await.status(),
        StatusCode::SEE_OTHER
    );
    // Linking the same provider subject again to the same account is a no-op success.
    assert_eq!(
        oidc_link(&app, &session).await.status(),
        StatusCode::SEE_OTHER
    );

    let jwt = bearer_from_session(&app, &session).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/me/identities")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let google = json_body(resp)
        .await
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["provider"] == "google")
        .count();
    assert_eq!(google, 1);
}

#[tokio::test]
async fn oidc_link_without_a_session_is_unauthorized() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "g-nosess".to_string(),
        email: "nosess@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/start?mode=link")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unlink_endpoint_enforces_the_last_method_guard() {
    let (app, _h) = plain_app();
    let session = signup_session(&app, "onlypw@example.com", "longenough1").await;
    let jwt = bearer_from_session(&app, &session).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/identities/password")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn signout_all_revokes_every_session() {
    let (app, _h) = plain_app();
    // Two independent sessions for the same account (signup opens one; login a second).
    let session1 = signup_session(&app, "multi-sess@example.com", "longenough1").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "multi-sess@example.com", "password": "longenough1" }),
        ))
        .await
        .unwrap();
    let session2 = cookie_pair(&resp, "wardnet_session");
    assert_eq!(exchange_status(&app, &session1).await, StatusCode::OK);
    assert_eq!(exchange_status(&app, &session2).await, StatusCode::OK);

    // Sign out of all (the browser sends the bearer + the httpOnly session cookie) →
    // revokes every session and clears the cookie.
    let jwt = bearer_from_session(&app, &session2).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/sessions")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header(header::COOKIE, &session2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let cleared = cookie_pair(&resp, "wardnet_session");
    assert_eq!(cleared, "wardnet_session=");

    // Both prior sessions can no longer exchange.
    assert_eq!(
        exchange_status(&app, &session1).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        exchange_status(&app, &session2).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn in_app_change_password_revokes_all_sessions_then_new_password_works() {
    let (app, _h) = plain_app();
    let session1 = signup_session(&app, "changer@example.com", "originalpass").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "changer@example.com", "password": "originalpass" }),
        ))
        .await
        .unwrap();
    let session2 = cookie_pair(&resp, "wardnet_session");

    // Drive the in-app change-password = email-code-exchange flow.
    let reset_code = verification_code(&app, "changer@example.com", "password_reset").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/reset",
            &json!({ "code": reset_code, "password": "brandnewpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The reset revoked every session.
    assert_eq!(
        exchange_status(&app, &session1).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        exchange_status(&app, &session2).await,
        StatusCode::UNAUTHORIZED
    );

    // The new password logs in; the old one does not.
    let ok = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "changer@example.com", "password": "brandnewpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    let bad = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "changer@example.com", "password": "originalpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
}

/// `POST /v1/me/password` with a Bearer JWT + a `password_change` code body.
async fn post_me_password(
    app: &Router,
    jwt: &str,
    code: &str,
    password: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/me/password")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "code": code, "password": password })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn authenticated_set_password_rotates_sessions_and_keeps_caller_signed_in() {
    let (app, _h) = plain_app();
    // Two devices for the same account; session2 is the "current browser".
    let session1 = signup_session(&app, "setter@example.com", "originalpass").await;
    let resp = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "setter@example.com", "password": "originalpass" }),
        ))
        .await
        .unwrap();
    let session2 = cookie_pair(&resp, "wardnet_session");
    let jwt = bearer_from_session(&app, &session2).await;

    // A fresh password_change code for the caller's own email.
    let code = verification_code(&app, "setter@example.com", "password_change").await;
    let resp = post_me_password(&app, &jwt, &code, "brandnewpass").await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // A fresh session cookie is issued and works — the caller stays signed in.
    let new_session = cookie_pair(&resp, "wardnet_session");
    assert!(!new_session.is_empty());
    assert_eq!(exchange_status(&app, &new_session).await, StatusCode::OK);

    // Every prior session is revoked — even the current token is rotated out.
    assert_eq!(
        exchange_status(&app, &session1).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        exchange_status(&app, &session2).await,
        StatusCode::UNAUTHORIZED
    );

    // The new password logs in.
    let ok = app
        .clone()
        .oneshot(post_json(
            "/v1/auth/password/login",
            &json!({ "email": "setter@example.com", "password": "brandnewpass" }),
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn authenticated_set_password_rejects_wrong_purpose_and_foreign_email_codes() {
    let (app, _h) = plain_app();
    let session = signup_session(&app, "owner@example.com", "originalpass").await;
    let jwt = bearer_from_session(&app, &session).await;

    // A password_reset code (wrong purpose) must NOT be accepted by /v1/me/password —
    // purpose-binding keeps recovery codes out of the authenticated change flow.
    let reset_code = verification_code(&app, "owner@example.com", "password_reset").await;
    let resp = post_me_password(&app, &jwt, &reset_code, "brandnewpass").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A password_change code for a DIFFERENT inbox must be rejected (email mismatch),
    // so a hijacked session can't set a password with someone else's proof.
    let foreign = verification_code(&app, "intruder@example.com", "password_change").await;
    let resp = post_me_password(&app, &jwt, &foreign, "brandnewpass").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Both attempts failed → nothing rotated, the caller's session still works.
    assert_eq!(exchange_status(&app, &session).await, StatusCode::OK);
}

#[tokio::test]
async fn oidc_link_aborts_if_session_revoked_mid_flight() {
    let identity = VerifiedIdentity {
        provider: "google".to_string(),
        subject: "g-revoke-sub".to_string(),
        email: "revoke@example.com".to_string(),
        email_verified: true,
    };
    let (app, _h) = app_with_google(identity);
    let session = signup_session(&app, "revoke@example.com", "longenough1").await;

    // Begin the link → obtain the oauth-state cookie.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/start?mode=link")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let oauth = cookie_pair(&resp, "wardnet_oauth");

    // The session is revoked (e.g. sign-out-all) during the provider round-trip.
    let jwt = bearer_from_session(&app, &session).await;
    let revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/me/sessions")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    // The callback must refuse to link against the now-dead session.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/oidc/google/callback?code=c&state=test-state")
                .header(header::COOKIE, format!("{oauth}; {session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
