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
    PgEnrollmentRepository, PgNetworkRepository, PgTenantRepository, ProvisioningState,
    TenantRepository,
};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants::test_helpers::{daemon_keypair, test_signer};

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
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&maintenance)
        .await
        .expect("CREATE DATABASE");
    drop(maintenance);

    db::init(&format!("{base}/{db_name}"))
        .await
        .expect("init test database")
}

fn service(pools: DbPools) -> TenantsService {
    TenantsService::new(
        Arc::new(PgTenantRepository::new_pools(pools.clone())) as Arc<dyn TenantRepository>,
        Arc::new(PgNetworkRepository::new_pools(pools.clone())) as Arc<dyn NetworkRepository>,
        Arc::new(PgDaemonRepository::new_pools(pools.clone())) as Arc<dyn DaemonRepository>,
        Arc::new(PgEnrollmentRepository::new_pools(pools)) as Arc<dyn EnrollmentRepository>,
        test_signer(SEED),
        ["use1".to_string(), "eu1".to_string()],
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn enroll_register_reconcile_lifecycle_on_postgres() {
    let svc = service(test_pool().await);
    let (_key, cnf) = daemon_keypair(11);

    // Signup → enroll → token (tenant-scoped) → register-network.
    let code = svc
        .issue_signup_code("user@example.com", "1.2.3.4")
        .await
        .unwrap();
    let tenant_id = svc.enroll(&code, &cnf).await.unwrap().tenant_id;
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

    // Cancel cascades → deprovisioning; reaper finishes → row deleted.
    svc.cancel_subscription(&tenant_id).await.unwrap();
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
    let svc = service(test_pool().await);
    let (_k1, c1) = daemon_keypair(11);

    let code = svc.issue_signup_code("a@b.com", "1.2.3.4").await.unwrap();
    let tenant_id = svc.enroll(&code, &c1).await.unwrap().tenant_id;
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
    let outcome = svc
        .register_network(&tenant2, &c3, "taken-slug", None, REGION)
        .await;
    assert!(outcome.is_err());
}
