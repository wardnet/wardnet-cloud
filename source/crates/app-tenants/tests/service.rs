//! Service-level tests for [`TenantsService`] over the fully-wired [`Harness`] (the
//! tenant + subscription + billing aggregates over one shared mock store + recording
//! event bus). Flows that depend on the event-driven trial run [`Harness::pump`] to
//! apply the split reactors deterministically. Lives in the composition crate because
//! it needs all three aggregates wired together.

use chrono::Utc;

use wardnet_common::contract::{Entitlement, SubscriptionStatus};
use wardnet_common::token::{PrincipalType, Verifier};

use wardnet_subscriptions::Subscription;
use wardnet_tenants::error::TenantsError;
use wardnet_tenants::repository::{ProvisioningState, Tenant};
mod common;
use common::{Harness, build_harness, build_state, daemon_keypair, jwt_keypair_pem};

const SEED: u8 = 5;
const REGION: &str = "use1";

fn verifier() -> Verifier {
    Verifier::from_pem(jwt_keypair_pem(SEED).1.as_bytes(), "tenants").unwrap()
}

/// Seed a tenant + an active (paid) subscription granting `max_networks`/`max_daemons`.
fn seed_tenant_with_entitlement(h: &Harness, id: &str, max_networks: u32, max_daemons: u32) {
    let now = Utc::now();
    h.store.seed_tenant(Tenant {
        id: id.to_string(),
        email: format!("{id}@b.com"),
        created_at: now,
        deregistered_at: None,
    });
    h.store.seed_subscription(Subscription {
        id: format!("sub-{id}"),
        tenant_id: id.to_string(),
        status: SubscriptionStatus::Active,
        entitlement: Entitlement {
            max_networks,
            max_daemons,
        },
        trial_expires_at: None,
        current_period_end: None,
        created_at: now,
        updated_at: now,
    });
}

/// Run the full wizard flow up to a registered network, pumping the trial into being.
/// Returns `(harness, tenant_id, daemon_cnf, slug)`.
async fn enrolled_and_registered() -> (Harness, String, String, String) {
    let h = build_harness(SEED);
    let (_key, cnf) = daemon_keypair(11);

    let code = h
        .state
        .tenants()
        .issue_signup_code("user@example.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = h
        .state
        .tenants()
        .enroll(&code, &cnf)
        .await
        .unwrap()
        .tenant_id;
    // The subscription reactor opens the trial.
    h.pump().await;

    let network = h
        .state
        .tenants()
        .register_network(&tenant_id, &cnf, "happy-einstein", None, REGION)
        .await
        .unwrap();
    assert_eq!(network.provisioning_state, ProvisioningState::Provisioning);
    (h, tenant_id, cnf, "happy-einstein".to_string())
}

#[tokio::test]
async fn enroll_then_token_is_tenant_scoped_then_network_scoped() {
    let h = build_harness(SEED);
    let (_key, cnf) = daemon_keypair(11);
    let code = h
        .state
        .tenants()
        .issue_signup_code("a@b.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = h
        .state
        .tenants()
        .enroll(&code, &cnf)
        .await
        .unwrap()
        .tenant_id;
    h.pump().await; // open the trial

    // Before a network exists: a tenant-scoped token (no `net`).
    let token = h.state.tenants().mint_jwt(&cnf).await.unwrap();
    let claims = verifier().verify(&token).unwrap();
    assert_eq!(claims.pt, PrincipalType::Daemon);
    assert_eq!(claims.tid, tenant_id);
    assert_eq!(claims.sub, cnf);
    assert!(claims.net.is_none());
    assert_eq!(claims.cnf.unwrap().ed25519, cnf);

    // After register-network: a network-scoped token (`net` set).
    let network = h
        .state
        .tenants()
        .register_network(&tenant_id, &cnf, "my-net", None, REGION)
        .await
        .unwrap();
    let token = h.state.tenants().mint_jwt(&cnf).await.unwrap();
    let claims = verifier().verify(&token).unwrap();
    assert_eq!(claims.net.as_deref(), Some(network.id.as_str()));
}

#[tokio::test]
async fn mint_jwt_unknown_key_is_rejected() {
    let (state, _store) = build_state(SEED);
    let (_key, cnf) = daemon_keypair(99);
    assert!(matches!(
        state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::BadCode(_))
    ));
}

#[tokio::test]
async fn mint_jwt_denied_without_a_subscription() {
    // A daemon enrolled but whose trial was never opened (event dropped, not yet
    // reconciled) has no active subscription, so cannot mint a token.
    let h = build_harness(SEED);
    let (_key, cnf) = daemon_keypair(11);
    let code = h
        .state
        .tenants()
        .issue_signup_code("a@b.com", "1.2.3.4")
        .await
        .unwrap();
    h.state.tenants().enroll(&code, &cnf).await.unwrap();
    // No pump → no trial subscription yet.
    assert!(matches!(
        h.state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::Forbidden(_))
    ));
}

#[tokio::test]
async fn issue_signup_code_emails_the_code() {
    let h = build_harness(SEED);
    let code = h
        .state
        .tenants()
        .issue_signup_code("mail@b.com", "1.2.3.4")
        .await
        .unwrap();
    let sent = h.email.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "mail@b.com");
    assert_eq!(sent[0].1, code);
}

#[tokio::test]
async fn enroll_with_bad_code_is_rejected() {
    let (state, _store) = build_state(SEED);
    let (_key, cnf) = daemon_keypair(11);
    assert!(matches!(
        state.tenants().enroll("deadbeef", &cnf).await,
        Err(TenantsError::BadCode(_))
    ));
}

#[tokio::test]
async fn enroll_is_single_use() {
    let (state, _store) = build_state(SEED);
    let (_key, cnf) = daemon_keypair(11);
    let code = state
        .tenants()
        .issue_signup_code("a@b.com", "1.2.3.4")
        .await
        .unwrap();
    assert!(state.tenants().enroll(&code, &cnf).await.is_ok());
    // The same code cannot be reused.
    assert!(matches!(
        state.tenants().enroll(&code, &cnf).await,
        Err(TenantsError::BadCode(_))
    ));
}

#[tokio::test]
async fn enroll_publishes_tenant_created_only_for_a_new_tenant() {
    use wardnet_common::event::DomainEvent;
    let h = build_harness(SEED);
    let (_k1, c1) = daemon_keypair(11);
    let code = h
        .state
        .tenants()
        .issue_signup_code("new@b.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = h
        .state
        .tenants()
        .enroll(&code, &c1)
        .await
        .unwrap()
        .tenant_id;
    assert!(h.events.published().contains(&DomainEvent::TenantCreated {
        tenant_id: tenant_id.clone()
    }));
    h.pump().await;

    // An add-daemon enroll into the same tenant does NOT re-publish TenantCreated.
    let before = h.events.published().len();
    let (_k2, c2) = daemon_keypair(12);
    let code2 = h
        .state
        .tenants()
        .issue_tenant_code(&tenant_id)
        .await
        .unwrap();
    h.state.tenants().enroll(&code2, &c2).await.unwrap();
    let new_events = &h.events.published()[before..];
    assert!(
        !new_events
            .iter()
            .any(|e| matches!(e, DomainEvent::TenantCreated { .. }))
    );
}

#[tokio::test]
async fn register_network_default_entitlement_blocks_second_daemon() {
    // Trial entitlement is 1 network / 1 daemon: the wizard registers one network +
    // daemon, and a second daemon is rejected at register-network (the daemon limit's
    // new home — enroll no longer caps it).
    let (h, tenant_id, _cnf, _slug) = enrolled_and_registered().await;
    let (_key2, cnf2) = daemon_keypair(22);
    let code = h
        .state
        .tenants()
        .issue_tenant_code(&tenant_id)
        .await
        .unwrap();
    // Enroll succeeds now (no cap at enroll)…
    h.state.tenants().enroll(&code, &cnf2).await.unwrap();
    // …but register-network is rejected on the entitlement.
    assert!(matches!(
        h.state
            .tenants()
            .register_network(&tenant_id, &cnf2, "second-net", None, REGION)
            .await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn register_network_enforces_daemon_limit() {
    // Generous networks, capped at one daemon: a second daemon (in a second network)
    // is rejected.
    let h = build_harness(SEED);
    seed_tenant_with_entitlement(&h, "t-dae", 5, 1);
    let (_k1, c1) = daemon_keypair(31);
    let (_k2, c2) = daemon_keypair(32);
    assert!(
        h.state
            .tenants()
            .register_network("t-dae", &c1, "net-a", None, REGION)
            .await
            .is_ok()
    );
    assert!(matches!(
        h.state
            .tenants()
            .register_network("t-dae", &c2, "net-b", None, REGION)
            .await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn register_network_enforces_network_limit() {
    let h = build_harness(SEED);
    // A tenant generous on daemons but capped at one network.
    seed_tenant_with_entitlement(&h, "t-net", 1, 5);
    let (_k1, c1) = daemon_keypair(33);
    let (_k2, c2) = daemon_keypair(34);

    assert!(
        h.state
            .tenants()
            .register_network("t-net", &c1, "net-a", None, REGION)
            .await
            .is_ok()
    );
    assert!(matches!(
        h.state
            .tenants()
            .register_network("t-net", &c2, "net-b", None, REGION)
            .await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn register_network_rejects_taken_slug() {
    let h = build_harness(SEED);
    seed_tenant_with_entitlement(&h, "t1", 5, 5);
    let (_k1, c1) = daemon_keypair(41);
    let (_k2, c2) = daemon_keypair(42);
    h.state
        .tenants()
        .register_network("t1", &c1, "taken", None, REGION)
        .await
        .unwrap();
    assert!(matches!(
        h.state
            .tenants()
            .register_network("t1", &c2, "taken", None, REGION)
            .await,
        Err(TenantsError::Conflict(_))
    ));
}

#[tokio::test]
async fn register_network_denied_without_a_subscription() {
    // A tenant with no subscription (only identity seeded) cannot register a network.
    let h = build_harness(SEED);
    h.store.seed_tenant(Tenant {
        id: "lonely".to_string(),
        email: "lonely@b.com".to_string(),
        created_at: Utc::now(),
        deregistered_at: None,
    });
    let (_k, c) = daemon_keypair(43);
    assert!(matches!(
        h.state
            .tenants()
            .register_network("lonely", &c, "net", None, REGION)
            .await,
        Err(TenantsError::Forbidden(_))
    ));
}

#[tokio::test]
async fn mint_jwt_denied_after_subscription_canceled() {
    let (h, tenant_id, cnf, _slug) = enrolled_and_registered().await;
    // Active (trialing) tenant mints fine.
    assert!(h.state.tenants().mint_jwt(&cnf).await.is_ok());
    // After cancel, the daemon's key can no longer mint a token (revocation at refresh).
    h.state
        .subscription_commands()
        .cancel(&tenant_id)
        .await
        .unwrap();
    assert!(matches!(
        h.state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::Forbidden(_))
    ));
}

#[tokio::test]
async fn register_network_rejects_unknown_region() {
    let h = build_harness(SEED);
    seed_tenant_with_entitlement(&h, "t1", 5, 5);
    let (_k, c) = daemon_keypair(51);
    assert!(matches!(
        h.state
            .tenants()
            .register_network("t1", &c, "net-x", None, "mars")
            .await,
        Err(TenantsError::BadRequest(_))
    ));
}

#[tokio::test]
async fn availability_reflects_validity_and_use() {
    let (h, _tid, _cnf, slug) = enrolled_and_registered().await;
    assert!(!h.state.tenants().check_availability(&slug).await.unwrap()); // taken
    assert!(
        h.state
            .tenants()
            .check_availability("free-name")
            .await
            .unwrap()
    ); // free
    assert!(!h.state.tenants().check_availability("api").await.unwrap()); // reserved
    assert!(!h.state.tenants().check_availability("A_B").await.unwrap()); // invalid
}

#[tokio::test]
async fn reconcile_provisioner_then_reaper_lifecycle() {
    let (h, tenant_id, _cnf, slug) = enrolled_and_registered().await;

    // Provisioner sees it in `provisioning`, marks it active.
    let page = h
        .state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    let id = page[0].id.clone();
    assert!(h.state.tenants().mark_network_active(&id).await.unwrap());
    assert_eq!(
        h.store.network_state(&slug),
        Some(ProvisioningState::Active)
    );

    // Cancel deactivates the subscription; the network reactor cascades the network
    // to deprovisioning.
    h.state
        .subscription_commands()
        .cancel(&tenant_id)
        .await
        .unwrap();
    h.pump().await;
    assert_eq!(
        h.store.network_state(&slug),
        Some(ProvisioningState::Deprovisioning)
    );

    // Reaper sees it, finishes deprovision → row deleted.
    let page = h
        .state
        .tenants()
        .reconcile_page(ProvisioningState::Deprovisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(h.state.tenants().finish_deprovision(&id).await.unwrap());
    assert_eq!(h.store.network_count(), 0);
    // Idempotent: a second finish is a no-op (false).
    assert!(!h.state.tenants().finish_deprovision(&id).await.unwrap());
}

#[tokio::test]
async fn deregister_tombstones_cancels_cascades_and_is_idempotent() {
    let (h, tenant_id, cnf, slug) = enrolled_and_registered().await;

    // Deregister tombstones + publishes TenantDeregistered; pumping cancels the
    // subscription and cascades the network to deprovisioning.
    assert!(
        h.state
            .tenants()
            .deregister_tenant(&tenant_id)
            .await
            .unwrap()
    );
    h.pump().await;
    let tenant = h.store.find_tenant(&tenant_id).unwrap();
    assert!(tenant.deregistered_at.is_some());
    assert!(h.store.current_subscription(&tenant_id).is_none());
    assert_eq!(
        h.store.network_state(&slug),
        Some(ProvisioningState::Deprovisioning)
    );

    // A tombstoned tenant's daemon key can no longer mint a token.
    assert!(matches!(
        h.state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::Forbidden(_))
    ));

    // Idempotent: a second deregister is a no-op (false), not an error.
    assert!(
        !h.state
            .tenants()
            .deregister_tenant(&tenant_id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn issue_tenant_code_rejected_after_deregister() {
    let (h, tenant_id, _cnf, _slug) = enrolled_and_registered().await;
    // A live tenant can issue an add-daemon code.
    assert!(
        h.state
            .tenants()
            .issue_tenant_code(&tenant_id)
            .await
            .is_ok()
    );
    // After deregister, the tombstoned tenant cannot grow daemons.
    h.state
        .tenants()
        .deregister_tenant(&tenant_id)
        .await
        .unwrap();
    assert!(matches!(
        h.state.tenants().issue_tenant_code(&tenant_id).await,
        Err(TenantsError::Forbidden(_))
    ));
}

#[tokio::test]
async fn deregister_unknown_tenant_is_not_found() {
    let (state, _store) = build_state(SEED);
    assert!(matches!(
        state.tenants().deregister_tenant("nope").await,
        Err(TenantsError::NotFound(_))
    ));
}

#[tokio::test]
async fn sweep_deletes_tombstoned_only_after_networks_gone() {
    let (h, tenant_id, _cnf, slug) = enrolled_and_registered().await;
    let network_id = h.store.network_id(&slug).unwrap();

    h.state
        .tenants()
        .deregister_tenant(&tenant_id)
        .await
        .unwrap();
    h.pump().await;

    // While the (deprovisioning) network row still exists, the sweep must not delete it.
    assert_eq!(h.state.tenants().sweep_deregistered().await.unwrap(), 0);
    assert!(h.store.find_tenant(&tenant_id).is_some());

    // Reaper finishes deprovision → the network row is gone.
    assert!(
        h.state
            .tenants()
            .finish_deprovision(&network_id)
            .await
            .unwrap()
    );
    assert_eq!(h.store.network_count(), 0);

    // Now the sweep deletes the tombstoned, network-less tenant.
    assert_eq!(h.state.tenants().sweep_deregistered().await.unwrap(), 1);
    assert!(h.store.find_tenant(&tenant_id).is_none());
}

#[tokio::test]
async fn deregister_frees_email_for_fresh_signup() {
    let h = build_harness(SEED);
    let (_k1, c1) = daemon_keypair(11);
    let code = h
        .state
        .tenants()
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let first_id = h
        .state
        .tenants()
        .enroll(&code, &c1)
        .await
        .unwrap()
        .tenant_id;
    h.pump().await;

    // Tombstoning frees the email: a fresh signup resolves to a new tenant id.
    h.state
        .tenants()
        .deregister_tenant(&first_id)
        .await
        .unwrap();
    h.pump().await;
    let (_k2, c2) = daemon_keypair(12);
    let code2 = h
        .state
        .tenants()
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let second_id = h
        .state
        .tenants()
        .enroll(&code2, &c2)
        .await
        .unwrap()
        .tenant_id;
    assert_ne!(first_id, second_id);
}

#[tokio::test]
async fn reconcile_backfills_a_missing_trial() {
    // A tenant created without its trial event landing (dropped) is backfilled by the
    // reconcile pass; a tenant whose trial was reaped is NOT resurrected.
    let h = build_harness(SEED);
    h.store.seed_tenant(Tenant {
        id: "drift".to_string(),
        email: "drift@b.com".to_string(),
        created_at: Utc::now(),
        deregistered_at: None,
    });
    assert!(h.store.current_subscription("drift").is_none());
    wardnet_tenants_app::reconcile(h.tenants.as_ref(), h.subscriptions.as_ref())
        .await
        .unwrap();
    assert!(h.store.current_subscription("drift").is_some());

    // Reap it, then reconcile again — no fresh trial (history exists).
    h.state
        .subscription_commands()
        .cancel("drift")
        .await
        .unwrap();
    wardnet_tenants_app::reconcile(h.tenants.as_ref(), h.subscriptions.as_ref())
        .await
        .unwrap();
    assert!(h.store.current_subscription("drift").is_none());
}

#[tokio::test]
async fn reconcile_pagination_is_region_scoped_and_cursored() {
    let h = build_harness(SEED);
    seed_tenant_with_entitlement(&h, "t", 10, 10);
    for i in 0..5u8 {
        let (_k, c) = daemon_keypair(60 + i);
        h.state
            .tenants()
            .register_network("t", &c, &format!("net-{i}"), None, REGION)
            .await
            .unwrap();
    }
    // Other-region network must not appear.
    let (_ko, co) = daemon_keypair(80);
    h.state
        .tenants()
        .register_network("t", &co, "elsewhere", None, "eu1")
        .await
        .unwrap();

    let first = h
        .state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, None, 2)
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    let cursor = first.last().unwrap().id.clone();
    let second = h
        .state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, Some(&cursor), 100)
        .await
        .unwrap();
    assert_eq!(second.len(), 3); // 5 in-region minus the first 2
    assert!(second.iter().all(|n| n.id > cursor));
    assert!(second.iter().all(|n| n.region == REGION));
}
