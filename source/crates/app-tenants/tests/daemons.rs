//! HTTP-level integration tests for `DELETE /v1/networks/{id}/daemons/self`
//! (daemon self-removal), driven with `oneshot` over the mock-backed router. Covers
//! the happy path, idempotency, the network-scope `403`s, and that removal touches
//! only the calling daemon — never the network, its DNS, or another daemon.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use tower::ServiceExt;

use wardnet_common::contract::{CodePurpose, ProvisioningState};
use wardnet_tenants::api;
use wardnet_tenants::repository::daemon::Daemon;

mod common;
use common::{Harness, build_harness, daemon_keypair, daemon_request_at, now_ts};

const SEED: u8 = 5;
const REGION: &str = "use1";

/// A daemon-signed `DELETE .../daemons/self` (empty body) at an explicit timestamp.
/// The explicit `ts` lets the idempotency test issue two distinct signed requests
/// (the replay cache keys on `pubkey:ts:body_hash`, so identical bytes collide).
fn delete_self(path: &str, key: &SigningKey, bearer: Option<&str>, ts: i64) -> Request<Body> {
    daemon_request_at("DELETE", path, b"", key, bearer, ts)
}

/// Enroll daemon `seed` under a fresh tenant and register a network for it. Returns the
/// harness, the network id, the daemon's signing key, and a network-scoped daemon JWT.
async fn registered(seed: u8, slug: &str) -> (Harness, String, SigningKey, String) {
    let h = build_harness(SEED);
    let (key, cnf) = daemon_keypair(seed);
    let code = h
        .state
        .tenants()
        .issue_signup_code("user@example.com", "1.2.3.4", CodePurpose::Enrollment)
        .await
        .unwrap();
    let tenant_id = h
        .state
        .tenants()
        .enroll(&code, &cnf)
        .await
        .unwrap()
        .tenant_id;
    // The subscription reactor opens the trial so the daemon can mint a token.
    h.pump().await;
    let network = h
        .state
        .tenants()
        .register_network(&tenant_id, &cnf, slug, None, REGION)
        .await
        .unwrap();
    // After register-network the same key mints a network-scoped token.
    let token = h.state.tenants().mint_jwt(&cnf).await.unwrap();
    (h, network.id, key, token)
}

#[tokio::test]
async fn remove_self_deletes_only_the_caller_and_leaves_the_network() {
    let (h, network_id, key, token) = registered(11, "happy-einstein").await;
    assert_eq!(h.store.daemon_count(), 1);

    let path = format!("/v1/networks/{network_id}/daemons/self");
    let resp = api::router(h.state.clone())
        .oneshot(delete_self(&path, &key, Some(&token), now_ts()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // The daemon row is gone; the network (and thus its DNS) is untouched.
    assert_eq!(h.store.daemon_count(), 0);
    assert_eq!(h.store.network_count(), 1);
    assert_eq!(
        h.store.network_state("happy-einstein"),
        Some(ProvisioningState::Provisioning),
    );
}

#[tokio::test]
async fn remove_self_is_idempotent() {
    let (h, network_id, key, token) = registered(11, "happy-einstein").await;
    let app = api::router(h.state.clone());
    let path = format!("/v1/networks/{network_id}/daemons/self");

    let first = app
        .clone()
        .oneshot(delete_self(&path, &key, Some(&token), now_ts()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    assert_eq!(h.store.daemon_count(), 0);

    // A retried teardown (distinct timestamp, row already gone) still succeeds.
    let second = app
        .oneshot(delete_self(&path, &key, Some(&token), now_ts() + 5))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
    assert_eq!(h.store.daemon_count(), 0);
}

#[tokio::test]
async fn remove_self_rejects_a_foreign_network_id() {
    let (h, _network_id, key, token) = registered(11, "happy-einstein").await;
    // A valid network-scoped token, but a path id that is not the token's `net`.
    let path = "/v1/networks/some-other-network/daemons/self";
    let resp = api::router(h.state.clone())
        .oneshot(delete_self(path, &key, Some(&token), now_ts()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The daemon row survives a rejected call.
    assert_eq!(h.store.daemon_count(), 1);
}

#[tokio::test]
async fn remove_self_rejects_a_tenant_scoped_token() {
    // A daemon that enrolled but never registered a network gets a tenant-scoped token
    // (no `net` claim); it may not remove itself from any network.
    let h = build_harness(SEED);
    let (key, cnf) = daemon_keypair(11);
    let code = h
        .state
        .tenants()
        .issue_signup_code("user@example.com", "1.2.3.4", CodePurpose::Enrollment)
        .await
        .unwrap();
    h.state.tenants().enroll(&code, &cnf).await.unwrap();
    h.pump().await;
    let token = h.state.tenants().mint_jwt(&cnf).await.unwrap();

    let resp = api::router(h.state.clone())
        .oneshot(delete_self(
            "/v1/networks/any-network/daemons/self",
            &key,
            Some(&token),
            now_ts(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn remove_self_without_auth_is_unauthorized() {
    let (h, network_id, _key, _token) = registered(11, "happy-einstein").await;
    let resp = api::router(h.state.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/networks/{network_id}/daemons/self"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(h.store.daemon_count(), 1);
}

#[tokio::test]
async fn remove_self_leaves_other_daemons_on_the_same_network() {
    let (h, network_id, key, token) = registered(11, "happy-einstein").await;
    // A second daemon sharing the network must survive the first's self-removal.
    let (_other_key, other_cnf) = daemon_keypair(12);
    h.store.seed_daemon(Daemon {
        id: "daemon-2".to_string(),
        // The tenant binding is immaterial here — `remove` keys on public_key + network.
        tenant_id: "tenant-x".to_string(),
        network_id: network_id.clone(),
        public_key: other_cnf.clone(),
        created_at: Utc::now(),
    });
    assert_eq!(h.store.daemon_count(), 2);

    let path = format!("/v1/networks/{network_id}/daemons/self");
    let resp = api::router(h.state.clone())
        .oneshot(delete_self(&path, &key, Some(&token), now_ts()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // Only the caller's row went; the second daemon remains.
    assert_eq!(h.store.daemon_count(), 1);
}
