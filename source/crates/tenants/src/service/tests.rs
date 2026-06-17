//! Unit tests for [`TenantsService`] over the shared mock store.

use wardnet_common::token::{PrincipalType, Verifier};

use crate::error::TenantsError;
use crate::repository::ProvisioningState;
use crate::repository::tenant::{Entitlement, SubscriptionStatus, Tenant};
use crate::test_helpers::{build_state, daemon_keypair, jwt_keypair_pem};

const SEED: u8 = 5;
const REGION: &str = "use1";

fn verifier() -> Verifier {
    Verifier::from_pem(jwt_keypair_pem(SEED).1.as_bytes()).unwrap()
}

/// Run the full wizard flow up to a registered network, returning
/// `(state, store, tenant_id, daemon_cnf, slug)`.
async fn enrolled_and_registered() -> (
    crate::state::AppState,
    crate::test_helpers::MockStore,
    String,
    String,
    String,
) {
    let (state, store) = build_state(SEED);
    let (_key, cnf) = daemon_keypair(11);

    let code = state
        .tenants()
        .issue_signup_code("user@example.com", "1.2.3.4")
        .await
        .unwrap();
    let enroll = state.tenants().enroll(&code, &cnf).await.unwrap();
    let tenant_id = enroll.tenant_id;

    let network = state
        .tenants()
        .register_network(&tenant_id, &cnf, "happy-einstein", None, REGION)
        .await
        .unwrap();
    assert_eq!(network.provisioning_state, ProvisioningState::Provisioning);
    (state, store, tenant_id, cnf, "happy-einstein".to_string())
}

#[tokio::test]
async fn enroll_then_token_is_tenant_scoped_then_network_scoped() {
    let (state, _store) = build_state(SEED);
    let (_key, cnf) = daemon_keypair(11);
    let code = state
        .tenants()
        .issue_signup_code("a@b.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = state.tenants().enroll(&code, &cnf).await.unwrap().tenant_id;

    // Before a network exists: a tenant-scoped token (no `net`).
    let token = state.tenants().mint_jwt(&cnf).await.unwrap();
    let claims = verifier().verify(&token).unwrap();
    assert_eq!(claims.pt, PrincipalType::Daemon);
    assert_eq!(claims.tid, tenant_id);
    assert_eq!(claims.sub, cnf);
    assert!(claims.net.is_none());
    assert_eq!(claims.cnf.unwrap().ed25519, cnf);

    // After register-network: a network-scoped token (`net` set).
    let network = state
        .tenants()
        .register_network(&tenant_id, &cnf, "my-net", None, REGION)
        .await
        .unwrap();
    let token = state.tenants().mint_jwt(&cnf).await.unwrap();
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
async fn register_network_default_entitlement_blocks_second_daemon() {
    // Default entitlement is 1 network / 1 daemon: a second daemon for the same
    // tenant is rejected at enroll (daemon limit).
    let (state, _store, tenant_id, _cnf, _slug) = enrolled_and_registered().await;
    let (_key2, cnf2) = daemon_keypair(22);
    let code = state.tenants().issue_tenant_code(&tenant_id).await.unwrap();
    assert!(matches!(
        state.tenants().enroll(&code, &cnf2).await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn register_network_enforces_network_limit() {
    let (state, store) = build_state(SEED);
    // A tenant generous on daemons but capped at one network.
    let tenant = Tenant {
        id: "t-net".to_string(),
        email: "n@b.com".to_string(),
        entitlement: Entitlement {
            max_networks: 1,
            max_daemons: 5,
        },
        subscription_status: SubscriptionStatus::Active,
        subscription_id: None,
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    };
    store.seed_tenant(tenant);
    let (_k1, c1) = daemon_keypair(31);
    let (_k2, c2) = daemon_keypair(32);

    assert!(
        state
            .tenants()
            .register_network("t-net", &c1, "net-a", None, REGION)
            .await
            .is_ok()
    );
    assert!(matches!(
        state
            .tenants()
            .register_network("t-net", &c2, "net-b", None, REGION)
            .await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn register_network_rejects_taken_slug() {
    let (state, store) = build_state(SEED);
    store.seed_tenant(Tenant {
        id: "t1".to_string(),
        email: "t1@b.com".to_string(),
        entitlement: Entitlement {
            max_networks: 5,
            max_daemons: 5,
        },
        subscription_status: SubscriptionStatus::Active,
        subscription_id: None,
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    let (_k1, c1) = daemon_keypair(41);
    let (_k2, c2) = daemon_keypair(42);
    state
        .tenants()
        .register_network("t1", &c1, "taken", None, REGION)
        .await
        .unwrap();
    assert!(matches!(
        state
            .tenants()
            .register_network("t1", &c2, "taken", None, REGION)
            .await,
        Err(TenantsError::Conflict(_))
    ));
}

#[tokio::test]
async fn mint_jwt_denied_after_subscription_canceled() {
    let (state, _store, tenant_id, cnf, _slug) = enrolled_and_registered().await;
    // Active tenant mints fine.
    assert!(state.tenants().mint_jwt(&cnf).await.is_ok());
    // After cancel, the daemon's key can no longer mint a token (revocation at refresh).
    state
        .tenants()
        .cancel_subscription(&tenant_id)
        .await
        .unwrap();
    assert!(matches!(
        state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::Forbidden(_))
    ));
}

#[tokio::test]
async fn register_network_rejects_unknown_region() {
    let (state, store) = build_state(SEED);
    store.seed_tenant(Tenant {
        id: "t1".to_string(),
        email: "t1@b.com".to_string(),
        entitlement: Entitlement {
            max_networks: 5,
            max_daemons: 5,
        },
        subscription_status: SubscriptionStatus::Active,
        subscription_id: None,
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    let (_k, c) = daemon_keypair(51);
    assert!(matches!(
        state
            .tenants()
            .register_network("t1", &c, "net-x", None, "mars")
            .await,
        Err(TenantsError::BadRequest(_))
    ));
}

#[tokio::test]
async fn enroll_pending_bindings_count_against_daemon_limit() {
    // Default entitlement 1 daemon: a first key may enroll (pending), but a second
    // key for the same tenant is rejected even before either registers a network.
    let (state, _store) = build_state(SEED);
    let (_k1, c1) = daemon_keypair(11);
    let code = state
        .tenants()
        .issue_signup_code("p@b.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = state.tenants().enroll(&code, &c1).await.unwrap().tenant_id;

    let (_k2, c2) = daemon_keypair(12);
    let code2 = state.tenants().issue_tenant_code(&tenant_id).await.unwrap();
    assert!(matches!(
        state.tenants().enroll(&code2, &c2).await,
        Err(TenantsError::EntitlementExceeded(_))
    ));
}

#[tokio::test]
async fn availability_reflects_validity_and_use() {
    let (state, _store, _tid, _cnf, slug) = enrolled_and_registered().await;
    assert!(!state.tenants().check_availability(&slug).await.unwrap()); // taken
    assert!(
        state
            .tenants()
            .check_availability("free-name")
            .await
            .unwrap()
    ); // free
    assert!(!state.tenants().check_availability("api").await.unwrap()); // reserved
    assert!(!state.tenants().check_availability("A_B").await.unwrap()); // invalid
}

#[tokio::test]
async fn reconcile_provisioner_then_reaper_lifecycle() {
    let (state, store, tenant_id, _cnf, slug) = enrolled_and_registered().await;

    // Provisioner sees it in `provisioning`, marks it active.
    let page = state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    let id = page[0].id.clone();
    assert!(state.tenants().mark_network_active(&id).await.unwrap());
    assert_eq!(store.network_state(&slug), Some(ProvisioningState::Active));

    // Cancel cascades the network to deprovisioning.
    state
        .tenants()
        .cancel_subscription(&tenant_id)
        .await
        .unwrap();
    assert_eq!(
        store.network_state(&slug),
        Some(ProvisioningState::Deprovisioning)
    );

    // Reaper sees it, finishes deprovision → row deleted.
    let page = state
        .tenants()
        .reconcile_page(ProvisioningState::Deprovisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(state.tenants().finish_deprovision(&id).await.unwrap());
    assert_eq!(store.network_count(), 0);
    // Idempotent: a second finish is a no-op (false).
    assert!(!state.tenants().finish_deprovision(&id).await.unwrap());
}

#[tokio::test]
async fn deregister_tombstones_cascades_cancels_and_is_idempotent() {
    let (state, store, tenant_id, cnf, slug) = enrolled_and_registered().await;

    // First deregister tombstones, cascades the network to deprovisioning, and cancels.
    assert!(state.tenants().deregister_tenant(&tenant_id).await.unwrap());
    let tenant = store.find_tenant(&tenant_id).unwrap();
    assert!(tenant.deregistered_at.is_some());
    assert_eq!(tenant.subscription_status, SubscriptionStatus::Canceled);
    assert_eq!(
        store.network_state(&slug),
        Some(ProvisioningState::Deprovisioning)
    );

    // A tombstoned tenant's daemon key can no longer mint a token.
    assert!(matches!(
        state.tenants().mint_jwt(&cnf).await,
        Err(TenantsError::Forbidden(_))
    ));

    // Idempotent: a second deregister is a no-op (false), not an error.
    assert!(!state.tenants().deregister_tenant(&tenant_id).await.unwrap());
}

#[tokio::test]
async fn issue_tenant_code_rejected_after_deregister() {
    let (state, _store, tenant_id, _cnf, _slug) = enrolled_and_registered().await;
    // A live tenant can issue an add-daemon code.
    assert!(state.tenants().issue_tenant_code(&tenant_id).await.is_ok());
    // After deregister, the tombstoned tenant cannot grow daemons.
    state.tenants().deregister_tenant(&tenant_id).await.unwrap();
    assert!(matches!(
        state.tenants().issue_tenant_code(&tenant_id).await,
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
    let (state, store, tenant_id, _cnf, slug) = enrolled_and_registered().await;
    let network_id = store.network_id(&slug).unwrap();

    state.tenants().deregister_tenant(&tenant_id).await.unwrap();

    // While the (deprovisioning) network row still exists, the sweep must not delete it.
    assert_eq!(state.tenants().sweep_deregistered().await.unwrap(), 0);
    assert!(store.find_tenant(&tenant_id).is_some());

    // Reaper finishes deprovision → the network row is gone.
    assert!(
        state
            .tenants()
            .finish_deprovision(&network_id)
            .await
            .unwrap()
    );
    assert_eq!(store.network_count(), 0);

    // Now the sweep deletes the tombstoned, network-less tenant.
    assert_eq!(state.tenants().sweep_deregistered().await.unwrap(), 1);
    assert!(store.find_tenant(&tenant_id).is_none());
}

#[tokio::test]
async fn deregister_frees_email_for_fresh_signup() {
    let (state, _store) = build_state(SEED);
    let (_k1, c1) = daemon_keypair(11);
    let code = state
        .tenants()
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let first_id = state.tenants().enroll(&code, &c1).await.unwrap().tenant_id;

    // Tombstoning frees the email: a fresh signup resolves to a new tenant id.
    state.tenants().deregister_tenant(&first_id).await.unwrap();
    let (_k2, c2) = daemon_keypair(12);
    let code2 = state
        .tenants()
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let second_id = state.tenants().enroll(&code2, &c2).await.unwrap().tenant_id;
    assert_ne!(first_id, second_id);
}

#[tokio::test]
async fn reconcile_pagination_is_region_scoped_and_cursored() {
    let (state, store) = build_state(SEED);
    store.seed_tenant(Tenant {
        id: "t".to_string(),
        email: "t@b.com".to_string(),
        entitlement: Entitlement {
            max_networks: 10,
            max_daemons: 10,
        },
        subscription_status: SubscriptionStatus::Active,
        subscription_id: None,
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    for i in 0..5u8 {
        let (_k, c) = daemon_keypair(60 + i);
        state
            .tenants()
            .register_network("t", &c, &format!("net-{i}"), None, REGION)
            .await
            .unwrap();
    }
    // Other-region network must not appear.
    let (_ko, co) = daemon_keypair(80);
    state
        .tenants()
        .register_network("t", &co, "elsewhere", None, "eu1")
        .await
        .unwrap();

    let first = state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, None, 2)
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    let cursor = first.last().unwrap().id.clone();
    let second = state
        .tenants()
        .reconcile_page(ProvisioningState::Provisioning, REGION, Some(&cursor), 100)
        .await
        .unwrap();
    assert_eq!(second.len(), 3); // 5 in-region minus the first 2
    assert!(second.iter().all(|n| n.id > cursor));
    assert!(second.iter().all(|n| n.region == REGION));
}
