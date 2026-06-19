//! Accept/reject matrix for [`authenticate`] across the three caller kinds.
//!
//! A tiny axum app guards one route with the middleware at a chosen
//! [`CallerType`] set, then drives requests through it with `tower::oneshot`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::{AuthCaller, AuthContext, Caller, CallerType, ServiceIdentity, authenticate};
use crate::replay_cache::ReplayCache;
use crate::test_helpers::jwt_keypair_pem;
use crate::token::{ClaimsSpec, PrincipalType, Signer, Verifier, canonical_request_payload};

const TTL: i64 = 300;

#[derive(Clone)]
struct TestState {
    verifier: Arc<Verifier>,
    replay: Arc<ReplayCache>,
}

impl AuthContext for TestState {
    fn verifier(&self) -> &Verifier {
        &self.verifier
    }
    fn replay_cache(&self) -> &ReplayCache {
        &self.replay
    }
}

fn state() -> (TestState, Signer) {
    let (priv_pem, pub_pem) = jwt_keypair_pem(1);
    let signer = Signer::from_pem(priv_pem.as_bytes(), None).unwrap();
    // Scope the verifier to `tenants`; every token minted below carries it in `aud`.
    let verifier = Verifier::from_pem(pub_pem.as_bytes(), "tenants").unwrap();
    (
        TestState {
            verifier: Arc::new(verifier),
            replay: Arc::new(ReplayCache::new()),
        },
        signer,
    )
}

async fn handler(AuthCaller(caller): AuthCaller) -> Json<&'static str> {
    Json(match caller {
        Caller::Service(_) => "service",
        Caller::Daemon(_) => "daemon",
        Caller::User(_) => "user",
    })
}

fn app(st: TestState, allowed: CallerType) -> Router {
    Router::new()
        .route("/echo", post(handler))
        .route_layer(from_fn_with_state(
            st.clone(),
            move |s: State<TestState>, r, n| authenticate(allowed, s, r, n),
        ))
        .with_state(st)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A daemon token + a request signed by its key (`PoP`). `body` is the raw bytes the
/// request carries; the canonical payload hashes exactly these.
fn signed_daemon_request(signer: &Signer, seed: u8, timestamp: i64, body: &[u8]) -> Request<Body> {
    let daemon = SigningKey::from_bytes(&[seed; 32]);
    let cnf = base64::engine::general_purpose::STANDARD.encode(daemon.verifying_key().to_bytes());
    let token = signer
        .sign(
            &ClaimsSpec {
                tenant_id: "t1",
                principal_type: PrincipalType::Daemon,
                subject: "daemon-1",
                network: Some("n1"),
                cnf_ed25519_b64: Some(&cnf),
                audience: vec!["tenants", "ddns", "tunneller"],
            },
            now(),
            TTL,
        )
        .unwrap();

    let body_hash = hex::encode(Sha256::digest(body));
    let payload = canonical_request_payload("POST", "/echo", timestamp, &body_hash);
    let sig = base64::engine::general_purpose::STANDARD
        .encode(daemon.sign(payload.as_bytes()).to_bytes());

    Request::builder()
        .method("POST")
        .uri("/echo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("X-Wardnet-Timestamp", timestamp.to_string())
        .header("X-Wardnet-Signature", sig)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn status_of(app: Router, req: Request<Body>) -> StatusCode {
    app.oneshot(req).await.unwrap().status()
}

// ── No credential ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_credential_is_unauthorized() {
    let (st, _signer) = state();
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        status_of(app(st, CallerType::all()), req).await,
        StatusCode::UNAUTHORIZED
    );
}

// ── USER ────────────────────────────────────────────────────────────────────────

fn user_request(signer: &Signer) -> Request<Body> {
    let token = signer
        .sign(
            &ClaimsSpec {
                tenant_id: "t1",
                principal_type: PrincipalType::User,
                subject: "user-1",
                network: None,
                cnf_ed25519_b64: None,
                audience: vec!["tenants"],
            },
            now(),
            TTL,
        )
        .unwrap();
    Request::builder()
        .method("POST")
        .uri("/echo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn user_token_accepted_when_user_allowed() {
    let (st, signer) = state();
    assert_eq!(
        status_of(app(st, CallerType::USER), user_request(&signer)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn user_token_forbidden_when_only_daemon_allowed() {
    let (st, signer) = state();
    assert_eq!(
        status_of(app(st, CallerType::DAEMON), user_request(&signer)).await,
        StatusCode::FORBIDDEN
    );
}

// ── DAEMON ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn daemon_signed_request_accepted_when_daemon_allowed() {
    let (st, signer) = state();
    let req = signed_daemon_request(&signer, 7, now(), b"{}");
    assert_eq!(
        status_of(app(st, CallerType::DAEMON | CallerType::USER), req).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn daemon_token_forbidden_when_only_user_allowed() {
    let (st, signer) = state();
    let req = signed_daemon_request(&signer, 7, now(), b"{}");
    assert_eq!(
        status_of(app(st, CallerType::USER), req).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn daemon_request_with_bad_signature_is_unauthorized() {
    let (st, signer) = state();
    // Sign the payload with one key but present a token whose cnf is a different key:
    // build a normal signed request, then swap the signature header for a forgery.
    let mut req = signed_daemon_request(&signer, 7, now(), b"{}");
    let forged = SigningKey::from_bytes(&[99; 32]);
    let payload =
        canonical_request_payload("POST", "/echo", now(), &hex::encode(Sha256::digest(b"{}")));
    let bad_sig = base64::engine::general_purpose::STANDARD
        .encode(forged.sign(payload.as_bytes()).to_bytes());
    req.headers_mut()
        .insert("X-Wardnet-Signature", bad_sig.parse().unwrap());
    assert_eq!(
        status_of(app(st, CallerType::DAEMON), req).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn replayed_daemon_request_is_rejected() {
    let (st, signer) = state();
    let ts = now();
    // Two byte-identical signed requests → identical replay key.
    let first = signed_daemon_request(&signer, 7, ts, b"{}");
    let second = signed_daemon_request(&signer, 7, ts, b"{}");

    let allowed = CallerType::DAEMON;
    assert_eq!(
        status_of(app(st.clone(), allowed), first).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(app(st, allowed), second).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn daemon_request_with_stale_timestamp_is_rejected() {
    let (st, signer) = state();
    let stale = now() - 3600;
    let req = signed_daemon_request(&signer, 7, stale, b"{}");
    assert_eq!(
        status_of(app(st, CallerType::DAEMON), req).await,
        StatusCode::UNAUTHORIZED
    );
}

// ── SERVICE ─────────────────────────────────────────────────────────────────────

fn service_request() -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::empty())
        .unwrap();
    // The mTLS listener stamps this after a successful handshake.
    req.extensions_mut().insert(ServiceIdentity {
        trust_domain: "wardnet.test".to_string(),
        env: "dev".to_string(),
        scope: "global".to_string(),
        service: "ddns".to_string(),
    });
    req
}

#[tokio::test]
async fn service_identity_accepted_when_service_allowed() {
    let (st, _signer) = state();
    assert_eq!(
        status_of(app(st, CallerType::SERVICE), service_request()).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn service_identity_forbidden_when_only_jwt_allowed() {
    let (st, _signer) = state();
    assert_eq!(
        status_of(
            app(st, CallerType::DAEMON | CallerType::USER),
            service_request()
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let (st, signer) = state();
    let big = vec![b'a'; 2 * 1024 * 1024];
    let req = signed_daemon_request(&signer, 7, now(), &big);
    assert_eq!(
        status_of(app(st, CallerType::DAEMON), req).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
