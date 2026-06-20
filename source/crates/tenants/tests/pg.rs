//! Postgres-gated tests for the real SQL repositories (the enroll + register-network
//! transactions and the reconcile cursor the in-memory mocks can't validate).
//!
//! `#[ignore]`d by default — they need a `PostgreSQL` server. Run with:
//!   `TENANTS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432 \
//!    cargo test -p wardnet-tenants -- --ignored`
//! The URL is a bare server URL **without** a `/database` suffix; each test creates
//! a fresh UUID-named database and runs the init migration into it.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use wardnet_tenants::db::{self, DbPools};
use wardnet_tenants::repository::{
    DaemonRepository, EnrollmentRepository, NetworkRepository, PgDaemonRepository,
    PgEnrollmentRepository, PgNetworkRepository, PgSubscriptionRepository, PgTenantRepository,
    ProvisioningState, SubscriptionRepository, TenantRepository,
};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants::subscription::{SubscriptionService, TrialPolicy};
use wardnet_tenants::test_helpers::{
    MockStripeGateway, RecordingEventPublisher, daemon_keypair, pump_events, test_signer,
};

const SEED: u8 = 5;
const REGION: &str = "use1";

/// Create a fresh per-test database and return its initialised pool.
async fn test_pool() -> DbPools {
    let base = std::env::var("TENANTS_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432".to_string());
    let db_name = format!("tenants_test_{}", Uuid::new_v4().simple());

    let maintenance = PgPool::connect(&format!("{base}/postgres"))
        .await
        .expect("connect to maintenance database");
    // DDL: the database identifier cannot be bind-parameterised. The name is a
    // fresh UUID (not user input); this inline format is the deliberate, test-only
    // exception to the const-SQL convention.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{db_name}\""
    )))
    .execute(&maintenance)
    .await
    .expect("CREATE DATABASE");
    drop(maintenance);

    db::init(&format!("{base}/{db_name}"))
        .await
        .expect("init test database")
}

/// A Postgres-backed harness mirroring the mock one: the tenant + subscription
/// services over real repos, plus the recording publisher so flows can be pumped
/// deterministically (the spawned reactors are not running in tests).
struct PgHarness {
    events: Arc<RecordingEventPublisher>,
    subscriptions: Arc<SubscriptionService>,
    tenants: Arc<TenantsService>,
}

impl PgHarness {
    fn tenants(&self) -> &TenantsService {
        &self.tenants
    }

    async fn pump(&self) {
        pump_events(&self.events, &self.subscriptions, &self.tenants).await;
    }
}

fn harness(pools: DbPools) -> PgHarness {
    // Built concretely so the harness keeps the recording handle; the `Arc` coerces
    // to `Arc<dyn EventPublisher>` at each service call site.
    let events: Arc<RecordingEventPublisher> = Arc::new(RecordingEventPublisher::new());
    let subscriptions = Arc::new(SubscriptionService::new(
        Arc::new(PgSubscriptionRepository::new_pools(pools.clone()))
            as Arc<dyn SubscriptionRepository>,
        events.clone(),
        Arc::new(MockStripeGateway::new()),
        TrialPolicy {
            trial_days: 60,
            trial_grace_days: 15,
            payment_grace_days: 15,
        },
    ));
    let tenants = Arc::new(TenantsService::new(
        Arc::new(PgTenantRepository::new_pools(pools.clone())) as Arc<dyn TenantRepository>,
        Arc::new(PgNetworkRepository::new_pools(pools.clone())) as Arc<dyn NetworkRepository>,
        Arc::new(PgDaemonRepository::new_pools(pools.clone())) as Arc<dyn DaemonRepository>,
        Arc::new(PgEnrollmentRepository::new_pools(pools)) as Arc<dyn EnrollmentRepository>,
        subscriptions.clone(),
        events.clone(),
        Arc::new(wardnet_tenants::email::NoopEmailSender),
        Arc::new(test_signer(SEED)),
        ["use1".to_string(), "eu1".to_string()],
    ));
    PgHarness {
        events,
        subscriptions,
        tenants,
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn enroll_register_reconcile_lifecycle_on_postgres() {
    let h = harness(test_pool().await);
    let svc = h.tenants();
    let (_key, cnf) = daemon_keypair(11);

    // Signup → enroll → token (tenant-scoped) → register-network.
    let code = svc
        .issue_signup_code("user@example.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = svc.enroll(&code, &cnf).await.unwrap().tenant_id;
    h.pump().await; // the subscription reactor opens the trial
    assert!(svc.mint_jwt(&cnf).await.is_ok());
    let network = svc
        .register_network(&tenant_id, &cnf, "happy-einstein", None, REGION)
        .await
        .unwrap();
    assert_eq!(network.provisioning_state, ProvisioningState::Provisioning);

    // Provisioner: provisioning → active.
    let page = svc
        .reconcile_page(ProvisioningState::Provisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(svc.mark_network_active(&network.id).await.unwrap());

    // Cancel deactivates the subscription; the network reactor cascades → deprovisioning;
    // reaper finishes → row deleted.
    h.subscriptions.cancel(&tenant_id).await.unwrap();
    h.pump().await;
    let page = svc
        .reconcile_page(ProvisioningState::Deprovisioning, REGION, None, 100)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(svc.finish_deprovision(&network.id).await.unwrap());
    assert!(svc.list_networks(&tenant_id).await.unwrap().is_empty());
    // The slug is free again.
    assert!(svc.check_availability("happy-einstein").await.unwrap());
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn slug_uniqueness_and_single_use_code_on_postgres() {
    let h = harness(test_pool().await);
    let svc = h.tenants();
    let (_k1, c1) = daemon_keypair(11);

    let code = svc.issue_signup_code("a@b.com", "1.2.3.4").await.unwrap();
    let tenant_id = svc.enroll(&code, &c1).await.unwrap().tenant_id;
    h.pump().await;
    // Single-use: the burned code is rejected on reuse.
    let (_k2, c2) = daemon_keypair(22);
    assert!(svc.enroll(&code, &c2).await.is_err());

    svc.register_network(&tenant_id, &c1, "taken-slug", None, REGION)
        .await
        .unwrap();
    // A second tenant cannot claim the same slug.
    let code2 = svc.issue_signup_code("c@d.com", "5.6.7.8").await.unwrap();
    let (_k3, c3) = daemon_keypair(33);
    let tenant2 = svc.enroll(&code2, &c3).await.unwrap().tenant_id;
    h.pump().await;
    let outcome = svc
        .register_network(&tenant2, &c3, "taken-slug", None, REGION)
        .await;
    assert!(outcome.is_err());
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn deregister_tombstone_sweep_and_email_reuse_on_postgres() {
    let h = harness(test_pool().await);
    let svc = h.tenants();
    let (_k1, c1) = daemon_keypair(11);

    // Signup → enroll → register-network.
    let code = svc
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let first_id = svc.enroll(&code, &c1).await.unwrap().tenant_id;
    h.pump().await;
    let network = svc
        .register_network(&first_id, &c1, "tombstone-net", None, REGION)
        .await
        .unwrap();

    // Deregister tombstones + publishes TenantDeregistered; pumping cancels the
    // subscription and cascades the network to deprovisioning.
    assert!(svc.deregister_tenant(&first_id).await.unwrap());
    h.pump().await;
    assert_eq!(
        svc.find_network(&network.id)
            .await
            .unwrap()
            .unwrap()
            .provisioning_state,
        ProvisioningState::Deprovisioning
    );
    // A tombstoned tenant can no longer mint a token.
    assert!(svc.mint_jwt(&c1).await.is_err());
    // Idempotent second deregister.
    assert!(!svc.deregister_tenant(&first_id).await.unwrap());

    // The partial unique index frees the email: a fresh signup gets a new tenant id.
    let code2 = svc
        .issue_signup_code("reuse@example.com", "1.2.3.4")
        .await
        .unwrap();
    let (_k2, c2) = daemon_keypair(22);
    let second_id = svc.enroll(&code2, &c2).await.unwrap().tenant_id;
    assert_ne!(first_id, second_id);

    // The sweep must not delete the tombstoned tenant while its network row survives.
    assert_eq!(svc.sweep_deregistered().await.unwrap(), 0);
    assert!(svc.find_tenant(&first_id).await.unwrap().is_some());

    // Reaper finishes deprovision → network row gone → sweep deletes the tenant.
    assert!(svc.finish_deprovision(&network.id).await.unwrap());
    assert_eq!(svc.sweep_deregistered().await.unwrap(), 1);
    assert!(svc.find_tenant(&first_id).await.unwrap().is_none());
    // The live re-signup tenant is untouched.
    assert!(svc.find_tenant(&second_id).await.unwrap().is_some());
}
