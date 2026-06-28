//! Integration tests for the Identities aggregate: the two-gate verified-email
//! resolver and the password / session flows over the fully-wired [`Harness`]. The
//! argon2 primitive round-trip (which needs the private `hash_password`/
//! `verify_password`) stays a unit test in the `tenants` crate.

use chrono::Utc;

use wardnet_common::token::Verifier;

use wardnet_tenants::error::IdentitiesError;
use wardnet_tenants::identities::provider::VerifiedIdentity;
use wardnet_tenants::repository::tenant::Tenant;
mod common;
use common::{Harness, build_harness, jwt_keypair_pem};

const SEED: u8 = 5;

/// A verifier over the harness's keypair, scoped to `tenants` (the USER JWT audience).
fn verifier() -> Verifier {
    Verifier::from_pem(jwt_keypair_pem(SEED).1.as_bytes(), "tenants").unwrap()
}

fn verified(provider: &str, subject: &str, email: &str, email_verified: bool) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: provider.to_string(),
        subject: subject.to_string(),
        email: email.to_string(),
        email_verified,
    }
}

// ── resolve_identity: the two gates ────────────────────────────────────────────────

#[tokio::test]
async fn resolve_verified_no_match_creates_tenant() {
    let h = build_harness(SEED);
    let (tenant_id, existed) = h
        .identities
        .resolve_identity(&verified("google", "g-1", "New@Example.com", true), None)
        .await
        .unwrap();
    assert!(!existed);
    // Web-first signup created the tenant (normalized email) + published TenantCreated.
    let tenant = h.store.find_tenant(&tenant_id).unwrap();
    assert_eq!(tenant.email, "new@example.com");
}

#[tokio::test]
async fn resolve_verified_match_auto_links_existing_tenant() {
    let h = build_harness(SEED);
    // A daemon-born tenant already exists for this email.
    h.store.seed_tenant(Tenant {
        id: "tenant-daemon-born".to_string(),
        email: "owner@example.com".to_string(),
        created_at: Utc::now(),
        deregistered_at: None,
    });
    let (tenant_id, existed) = h
        .identities
        .resolve_identity(&verified("google", "g-9", "owner@example.com", true), None)
        .await
        .unwrap();
    assert!(!existed);
    assert_eq!(tenant_id, "tenant-daemon-born");
}

#[tokio::test]
async fn resolve_returning_identity_is_existing() {
    let h = build_harness(SEED);
    let v = verified("google", "g-7", "repeat@example.com", true);
    let (first, existed1) = h.identities.resolve_identity(&v, None).await.unwrap();
    assert!(!existed1);
    let (second, existed2) = h.identities.resolve_identity(&v, None).await.unwrap();
    assert!(existed2);
    assert_eq!(first, second);
}

#[tokio::test]
async fn resolve_unverified_email_is_rejected() {
    let h = build_harness(SEED);
    let err = h
        .identities
        .resolve_identity(&verified("google", "g-2", "spoof@example.com", false), None)
        .await
        .unwrap_err();
    assert!(matches!(err, IdentitiesError::Unauthorized(_)));
    // No tenant was created behind the rejected gate.
    assert!(
        h.tenants
            .find_tenant_by_email("spoof@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

// ── Password flows ─────────────────────────────────────────────────────────────────

/// Issue a real signup code through the tenant aggregate (the gate-1 primitive).
async fn signup_code(h: &Harness, email: &str) -> String {
    h.tenants
        .issue_signup_code(email, "203.0.113.7")
        .await
        .unwrap()
}

#[tokio::test]
async fn password_signup_then_login() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "alice@example.com").await;
    let session = h
        .identities
        .password_signup("alice@example.com", &code, "hunter2hunter2")
        .await
        .unwrap();
    assert!(!session.is_empty());

    // The session exchanges to a USER JWT the verifier accepts (aud = [tenants]).
    let jwt = h.identities.exchange_session(&session).await.unwrap();
    let claims = verifier().verify(&jwt).unwrap();
    assert_eq!(claims.aud, vec!["tenants".to_string()]);
    assert_eq!(claims.tid, claims.sub); // User == Tenant 1:1

    // And the password logs in.
    let login = h
        .identities
        .password_login("alice@example.com", "hunter2hunter2", "203.0.113.1")
        .await
        .unwrap();
    assert!(!login.is_empty());
}

#[tokio::test]
async fn password_signup_rejects_bad_code() {
    let h = build_harness(SEED);
    let err = h
        .identities
        .password_signup("bob@example.com", "deadbeef", "longenough1")
        .await
        .unwrap_err();
    assert!(matches!(err, IdentitiesError::BadCode(_)));
}

#[tokio::test]
async fn password_signup_rejects_weak_password() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "weak@example.com").await;
    let err = h
        .identities
        .password_signup("weak@example.com", &code, "short")
        .await
        .unwrap_err();
    assert!(matches!(err, IdentitiesError::BadRequest(_)));
}

#[tokio::test]
async fn second_password_signup_for_same_email_conflicts() {
    let h = build_harness(SEED);
    let code1 = signup_code(&h, "dup@example.com").await;
    h.identities
        .password_signup("dup@example.com", &code1, "longenough1")
        .await
        .unwrap();
    let code2 = signup_code(&h, "dup@example.com").await;
    let err = h
        .identities
        .password_signup("dup@example.com", &code2, "longenough2")
        .await
        .unwrap_err();
    assert!(matches!(err, IdentitiesError::Conflict(_)));
}

#[tokio::test]
async fn login_rejects_unknown_and_wrong_password() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "carol@example.com").await;
    h.identities
        .password_signup("carol@example.com", &code, "rightpassword")
        .await
        .unwrap();

    assert!(matches!(
        h.identities
            .password_login("carol@example.com", "wrongpassword", "203.0.113.2")
            .await
            .unwrap_err(),
        IdentitiesError::Unauthorized(_)
    ));
    assert!(matches!(
        h.identities
            .password_login("nobody@example.com", "whatever12", "203.0.113.3")
            .await
            .unwrap_err(),
        IdentitiesError::Unauthorized(_)
    ));
}

// ── Session lifecycle ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_invalidates_the_exchange() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "dave@example.com").await;
    let session = h
        .identities
        .password_signup("dave@example.com", &code, "longenough1")
        .await
        .unwrap();

    assert!(h.identities.exchange_session(&session).await.is_ok());
    h.identities.logout(&session).await.unwrap();
    assert!(matches!(
        h.identities.exchange_session(&session).await.unwrap_err(),
        IdentitiesError::Unauthorized(_)
    ));
}

#[tokio::test]
async fn purge_for_deletes_sessions_and_identities() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "erin@example.com").await;
    let session = h
        .identities
        .password_signup("erin@example.com", &code, "longenough1")
        .await
        .unwrap();
    let tenant = h
        .tenants
        .find_tenant_by_email("erin@example.com")
        .await
        .unwrap()
        .unwrap();

    h.identities.purge_for(&tenant.id).await.unwrap();
    // Session gone (exchange fails) and the password identity gone (login fails).
    assert!(h.identities.exchange_session(&session).await.is_err());
    assert!(
        h.identities
            .password_login("erin@example.com", "longenough1", "203.0.113.4")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn deregistered_tenant_cannot_exchange_or_log_in() {
    // Even if the identities reactor has NOT yet purged the session/identity (best-effort
    // bus), a tombstoned tenant must not mint a USER JWT or open a new session.
    let h = build_harness(SEED);
    let code = signup_code(&h, "frank@example.com").await;
    let session = h
        .identities
        .password_signup("frank@example.com", &code, "longenough1")
        .await
        .unwrap();
    let tenant = h
        .tenants
        .find_tenant_by_email("frank@example.com")
        .await
        .unwrap()
        .unwrap();

    // Tombstone the tenant WITHOUT running the identities reactor (rows still present).
    assert!(h.tenants.deregister_tenant(&tenant.id).await.unwrap());

    // The silent exchange refuses to mint for a tombstoned tenant (session-query guard).
    assert!(matches!(
        h.identities.exchange_session(&session).await.unwrap_err(),
        IdentitiesError::Unauthorized(_)
    ));
    // And a fresh login is refused at session creation (create_session liveness check).
    assert!(matches!(
        h.identities
            .password_login("frank@example.com", "longenough1", "203.0.113.9")
            .await
            .unwrap_err(),
        IdentitiesError::Unauthorized(_)
    ));
}

#[tokio::test]
async fn password_login_is_rate_limited_per_ip() {
    let h = build_harness(SEED);
    let code = signup_code(&h, "grace@example.com").await;
    h.identities
        .password_signup("grace@example.com", &code, "longenough1")
        .await
        .unwrap();

    // 10 wrong attempts from one IP are each Unauthorized; the 11th is RateLimited.
    let ip = "198.51.100.7";
    for _ in 0..10 {
        assert!(matches!(
            h.identities
                .password_login("grace@example.com", "wrongpassword", ip)
                .await
                .unwrap_err(),
            IdentitiesError::Unauthorized(_)
        ));
    }
    assert!(matches!(
        h.identities
            .password_login("grace@example.com", "longenough1", ip)
            .await
            .unwrap_err(),
        IdentitiesError::RateLimited(_)
    ));
    // A different IP is unaffected (correct credentials still succeed).
    assert!(
        h.identities
            .password_login("grace@example.com", "longenough1", "198.51.100.8")
            .await
            .is_ok()
    );
}
