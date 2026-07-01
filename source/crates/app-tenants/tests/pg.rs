//! Postgres-gated tests for the real SQL repositories (the enroll + register-network
//! transactions and the reconcile cursor the in-memory mocks can't validate), wired
//! through the composition root's **merged** migrator (tenants + subscriptions +
//! billing) — the only place the live schema exists.
//!
//! `#[ignore]`d by default — they need a `PostgreSQL` server. Run with:
//!   `TENANTS_TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432 \
//!    cargo test -p wardnet-tenants-bin -- --ignored`
//! The URL is a bare server URL **without** a `/database` suffix; each test creates
//! a fresh UUID-named database and runs the merged migration into it.

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use chrono::{Duration, Utc};

use wardnet_common::contract::{CodePurpose, Entitlement, SubscriptionStatus};
use wardnet_common::db::DbPools;
use wardnet_common::event::EventBus;
use wardnet_common::ports::{SubscriptionCommands, SubscriptionReader};

use wardnet_billing::repository::{
    BillingRepository, CatalogPlan, CatalogPromo, PgBillingRepository,
};
use wardnet_subscriptions::{
    PgSubscriptionRepository, SubscriptionRepository, SubscriptionService, TrialPolicy,
};
use wardnet_tenants::email::EmailSender;
use wardnet_tenants::identities::IdentitiesService;
use wardnet_tenants::repository::{
    DaemonRepository, EnrollmentRepository, NetworkRepository, PgDaemonRepository,
    PgEnrollmentRepository, PgNetworkRepository, PgSessionRepository, PgTenantIdentityRepository,
    PgTenantRepository, ProvisioningState, SessionRepository, TenantIdentityRepository,
    TenantRepository,
};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants_app::db;
mod common;
use common::{RecordingEventBus, daemon_keypair, pump_events, test_signer};

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

/// A Postgres-backed harness mirroring the mock one: the tenant + subscription +
/// identities services over real repos, plus the recording bus so flows can be pumped
/// deterministically (the spawned reactors are not running in tests).
struct PgHarness {
    events: Arc<RecordingEventBus>,
    subscriptions: Arc<SubscriptionService>,
    tenants: Arc<TenantsService>,
    identities: Arc<IdentitiesService>,
}

impl PgHarness {
    fn tenants(&self) -> &TenantsService {
        &self.tenants
    }

    async fn pump(&self) {
        pump_events(
            &self.events,
            &self.subscriptions,
            &self.tenants,
            &self.identities,
        )
        .await;
    }
}

fn harness(pools: DbPools) -> PgHarness {
    // Built concretely so the harness keeps the recording handle; the `Arc` coerces
    // to `Arc<dyn EventBus>` at each service call site.
    let events: Arc<RecordingEventBus> = Arc::new(RecordingEventBus::new());
    let subscriptions = Arc::new(SubscriptionService::new(
        Arc::new(PgSubscriptionRepository::new_pools(pools.clone()))
            as Arc<dyn SubscriptionRepository>,
        Arc::clone(&events) as Arc<dyn EventBus>,
        TrialPolicy {
            trial_days: 60,
            trial_grace_days: 15,
            payment_grace_days: 15,
        },
    ));
    let subscription_reader: Arc<dyn SubscriptionReader> = subscriptions.clone();
    let signer = Arc::new(test_signer(SEED));
    let tenants = Arc::new(TenantsService::new(
        Arc::new(PgTenantRepository::new_pools(pools.clone())) as Arc<dyn TenantRepository>,
        Arc::new(PgNetworkRepository::new_pools(pools.clone())) as Arc<dyn NetworkRepository>,
        Arc::new(PgDaemonRepository::new_pools(pools.clone())) as Arc<dyn DaemonRepository>,
        Arc::new(PgEnrollmentRepository::new_pools(pools.clone())) as Arc<dyn EnrollmentRepository>,
        Arc::clone(&subscription_reader),
        Arc::clone(&events) as Arc<dyn EventBus>,
        Arc::new(wardnet_tenants::email::NoopEmailSender) as Arc<dyn EmailSender>,
        Arc::clone(&signer),
        ["use1".to_string(), "eu1".to_string()],
    ));
    let identities = Arc::new(IdentitiesService::new(
        Arc::new(PgTenantIdentityRepository::new_pools(pools.clone()))
            as Arc<dyn TenantIdentityRepository>,
        Arc::new(PgSessionRepository::new_pools(pools)) as Arc<dyn SessionRepository>,
        Arc::clone(&tenants),
        HashMap::new(),
        signer,
        300,
    ));
    PgHarness {
        events,
        subscriptions,
        tenants,
        identities,
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
        .issue_signup_code("user@example.com", "1.2.3.4", CodePurpose::Enrollment)
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

    let code = svc
        .issue_signup_code("a@b.com", "1.2.3.4", CodePurpose::Enrollment)
        .await
        .unwrap();
    let tenant_id = svc.enroll(&code, &c1).await.unwrap().tenant_id;
    h.pump().await;
    // Single-use: the burned code is rejected on reuse.
    let (_k2, c2) = daemon_keypair(22);
    assert!(svc.enroll(&code, &c2).await.is_err());

    svc.register_network(&tenant_id, &c1, "taken-slug", None, REGION)
        .await
        .unwrap();
    // A second tenant cannot claim the same slug.
    let code2 = svc
        .issue_signup_code("c@d.com", "5.6.7.8", CodePurpose::Enrollment)
        .await
        .unwrap();
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
        .issue_signup_code("reuse@example.com", "1.2.3.4", CodePurpose::Enrollment)
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
        .issue_signup_code("reuse@example.com", "1.2.3.4", CodePurpose::Enrollment)
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

/// Two Stripe events from the same checkout (e.g. `customer.subscription.created`
/// and `.updated`) can reach `billing::apply_upsert` together: both read the tenant
/// as still `trialing` and both drive the trial→paid conversion. The conversion must
/// be concurrency-safe — exactly one live row, no `uq_subscriptions_live` violation.
/// Regression guard for the webhook 500 observed in the real-Stripe e2e (the losing
/// event's second live-row INSERT collided on the partial unique index).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires PostgreSQL"]
async fn concurrent_trial_conversion_keeps_one_live_row() {
    let pools = test_pool().await;
    let h = harness(pools.clone());

    // Signup → enroll → the subscription reactor opens the trial.
    let (_key, cnf) = daemon_keypair(11);
    let code = h
        .tenants()
        .issue_signup_code("race@example.com", "1.2.3.4", CodePurpose::Enrollment)
        .await
        .unwrap();
    let tenant_id = h.tenants().enroll(&code, &cnf).await.unwrap().tenant_id;
    h.pump().await;

    // Deterministically stage the exact race two racing checkout webhooks produce:
    // event A has begun converting and holds the trial row lock, but has not yet
    // committed its paid row. Open A's transaction by hand and cancel the trial (taking
    // the row lock) without committing.
    let mut tx_a = pools.write.begin().await.unwrap();
    sqlx::query(
        "UPDATE subscriptions SET status = 'canceled', updated_at = now() \
         WHERE tenant_id = $1 AND status <> 'canceled'",
    )
    .bind(&tenant_id)
    .execute(&mut *tx_a)
    .await
    .unwrap();

    // Event B is the real method under test. Its cancel-UPDATE blocks on A's row lock,
    // pinning B's snapshot *before* A's paid row exists — the window that produced the
    // e2e 500. Spawn it, then wait until it is genuinely blocked on the lock.
    let b = Arc::clone(&h.subscriptions);
    let tb = tenant_id.clone();
    let handle = tokio::spawn(async move {
        b.convert_trial_to_paid(
            &tb,
            SubscriptionStatus::Active,
            Entitlement {
                max_networks: 1,
                max_daemons: 2,
            },
            Some(Utc::now() + Duration::days(30)),
        )
        .await
    });
    // Poll (on a separate connection) until B's UPDATE is waiting on the row lock.
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE wait_event_type = 'Lock' AND query ILIKE '%subscriptions%'",
        )
        .fetch_one(&pools.read)
        .await
        .unwrap();
        if waiting >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // A finishes: insert its paid row and commit, releasing the lock. B now unblocks
    // with a stale snapshot and, on the buggy blind INSERT, collides on
    // `uq_subscriptions_live`.
    sqlx::query(
        "INSERT INTO subscriptions \
         (id, tenant_id, status, entitlement, trial_expires_at, current_period_end, created_at, updated_at) \
         VALUES ($1, $2, 'active', '{\"max_networks\":1,\"max_daemons\":1}'::jsonb, NULL, now(), now(), now())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&tenant_id)
    .execute(&mut *tx_a)
    .await
    .unwrap();
    tx_a.commit().await.unwrap();

    let rb = handle.await.unwrap();
    assert!(
        rb.is_ok(),
        "the racing conversion must not violate uq_subscriptions_live: {rb:?}"
    );

    // Exactly one live row remains, and it is a paid (Active) subscription.
    let live = h
        .subscriptions
        .current(&tenant_id)
        .await
        .unwrap()
        .expect("a live subscription must remain");
    assert_eq!(live.status, SubscriptionStatus::Active);
}

/// Round-trip the `PgBillingRepository` — the idempotency ledger, the catalog projection
/// replace/read, and the customer/subscription reference reads — against real Postgres.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn billing_repository_round_trips_on_postgres() {
    let pools = test_pool().await;
    let h = harness(pools.clone());
    // A real tenant for the billing_customers foreign key.
    let (_key, cnf) = daemon_keypair(11);
    let code = h
        .tenants()
        .issue_signup_code("bill@example.com", "1.2.3.4", CodePurpose::Enrollment)
        .await
        .unwrap();
    let tenant_id = h.tenants().enroll(&code, &cnf).await.unwrap().tenant_id;

    let repo = PgBillingRepository::new_pools(pools);

    // Idempotency ledger.
    assert!(!repo.is_event_processed("evt_1").await.unwrap());
    repo.record_event("evt_1", Utc::now()).await.unwrap();
    assert!(repo.is_event_processed("evt_1").await.unwrap());

    // Catalog projection: replace then read back.
    let plan = CatalogPlan {
        price_id: "price_1".to_string(),
        product_id: "prod_1".to_string(),
        name: "Home".to_string(),
        level: 1,
        entitlement: Entitlement {
            max_networks: 1,
            max_daemons: 1,
        },
        amount_cents: 370,
        currency: "usd".to_string(),
        interval: "month".to_string(),
    };
    let promo = CatalogPromo {
        coupon_id: "co_1".to_string(),
        name: "Founders".to_string(),
        percent_off: Some(25.0),
        amount_off: None,
        currency: Some("usd".to_string()),
        applies_to_products: vec!["prod_1".to_string()],
        start: Some(Utc::now() - Duration::days(1)),
        redeem_by: Some(Utc::now() + Duration::days(1)),
    };
    repo.replace_catalog(&[plan], &[promo], Utc::now())
        .await
        .unwrap();
    let snap = repo.read_catalog().await.unwrap();
    assert_eq!(snap.plans.len(), 1);
    assert_eq!(snap.plans[0].price_id, "price_1");
    assert_eq!(snap.promos.len(), 1);

    // Customer + subscription references.
    repo.upsert_customer(&tenant_id, "cus_1").await.unwrap();
    assert_eq!(
        repo.customer_id(&tenant_id).await.unwrap().as_deref(),
        Some("cus_1")
    );
    repo.upsert_subscription(&tenant_id, "cus_1", "sub_1", Some("price_1"))
        .await
        .unwrap();
    let bref = repo.billing_ref(&tenant_id).await.unwrap().unwrap();
    assert_eq!(bref.stripe_subscription_id.as_deref(), Some("sub_1"));
    assert_eq!(bref.price_id.as_deref(), Some("price_1"));
    assert_eq!(
        repo.tenant_for_subscription("sub_1")
            .await
            .unwrap()
            .as_deref(),
        Some(tenant_id.as_str())
    );
    assert_eq!(
        repo.subscription_for_customer("cus_1")
            .await
            .unwrap()
            .as_deref(),
        Some("sub_1")
    );
}
