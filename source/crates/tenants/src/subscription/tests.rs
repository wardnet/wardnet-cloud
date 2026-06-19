//! Unit tests for [`SubscriptionService`] over the shared mock store + recording
//! event publisher.

use std::sync::Arc;

use chrono::{Duration, Utc};

use wardnet_common::event::DomainEvent;

use crate::repository::SubscriptionRepository;
use crate::repository::subscription::{Entitlement, Subscription, SubscriptionStatus};
use crate::subscription::{SubscriptionService, TrialPolicy};
use crate::test_helpers::{MockStore, MockStripeGateway, RecordingEventPublisher};

const POLICY: TrialPolicy = TrialPolicy {
    trial_days: 60,
    trial_grace_days: 15,
    payment_grace_days: 15,
};

fn service() -> (
    Arc<SubscriptionService>,
    MockStore,
    Arc<RecordingEventPublisher>,
) {
    let store = MockStore::new();
    let events = Arc::new(RecordingEventPublisher::new());
    let svc = Arc::new(SubscriptionService::new(
        Arc::new(store.clone()) as Arc<dyn SubscriptionRepository>,
        events.clone(),
        Arc::new(MockStripeGateway::new()),
        POLICY,
    ));
    (svc, store, events)
}

/// A subscription row with the given status + timestamps, all Stripe fields empty.
fn sub(tenant_id: &str, status: SubscriptionStatus) -> Subscription {
    let now = Utc::now();
    Subscription {
        id: format!("sub-{tenant_id}"),
        tenant_id: tenant_id.to_string(),
        status,
        entitlement: Entitlement::DEFAULT,
        stripe_customer_id: None,
        stripe_subscription_id: None,
        price_id: None,
        trial_expires_at: None,
        current_period_end: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn create_trial_opens_one_trial_and_is_idempotent() {
    let (svc, store, _events) = service();
    assert!(svc.create_trial("t1").await.unwrap());
    assert_eq!(store.subscription_count("t1"), 1);
    let current = svc.current("t1").await.unwrap().unwrap();
    assert_eq!(current.status, SubscriptionStatus::Trialing);
    assert!(current.trial_expires_at.is_some());

    // A second call (replayed TenantCreated) does not open a second trial.
    assert!(!svc.create_trial("t1").await.unwrap());
    assert_eq!(store.subscription_count("t1"), 1);
}

#[tokio::test]
async fn create_trial_does_not_resurrect_a_reaped_trial() {
    let (svc, store, _events) = service();
    svc.create_trial("t1").await.unwrap();
    svc.cancel("t1").await.unwrap();
    // The tenant now has a canceled row but no live one.
    assert!(svc.current("t1").await.unwrap().is_none());
    // create_trial must not open a fresh trial (history exists).
    assert!(!svc.create_trial("t1").await.unwrap());
    assert!(svc.current("t1").await.unwrap().is_none());
    assert_eq!(store.subscription_count("t1"), 1);
}

#[tokio::test]
async fn cancel_publishes_deactivation_and_is_idempotent() {
    let (svc, _store, events) = service();
    svc.create_trial("t1").await.unwrap();

    svc.cancel("t1").await.unwrap();
    assert!(svc.current("t1").await.unwrap().is_none());
    assert!(
        events
            .published()
            .contains(&DomainEvent::SubscriptionDeactivated {
                tenant_id: "t1".to_string()
            })
    );

    // A second cancel (no live row) publishes nothing further.
    let before = events.published().len();
    svc.cancel("t1").await.unwrap();
    assert_eq!(events.published().len(), before);
}

#[tokio::test]
async fn expire_overdue_cancels_expired_trials_and_past_due() {
    let (svc, store, events) = service();
    let now = Utc::now();

    // A trial that lapsed past its 15-day grace.
    let mut expired_trial = sub("t-trial", SubscriptionStatus::Trialing);
    expired_trial.trial_expires_at = Some(now - Duration::days(20));
    store.seed_subscription(expired_trial);

    // A trial still within grace — must survive.
    let mut fresh_trial = sub("t-fresh", SubscriptionStatus::Trialing);
    fresh_trial.trial_expires_at = Some(now - Duration::days(2));
    store.seed_subscription(fresh_trial);

    // A past-due subscription past its payment grace.
    let mut overdue_paid = sub("t-paid", SubscriptionStatus::PastDue);
    overdue_paid.current_period_end = Some(now - Duration::days(20));
    store.seed_subscription(overdue_paid);

    let n = svc.expire_overdue().await.unwrap();
    assert_eq!(n, 2);
    assert!(svc.current("t-trial").await.unwrap().is_none());
    assert!(svc.current("t-paid").await.unwrap().is_none());
    assert!(svc.current("t-fresh").await.unwrap().is_some());

    // Each cancellation cascaded via an event.
    let deactivations = events
        .published()
        .iter()
        .filter(|e| matches!(e, DomainEvent::SubscriptionDeactivated { .. }))
        .count();
    assert_eq!(deactivations, 2);
}

// ── Stripe-driven lifecycle ─────────────────────────────────────────────────────

use crate::stripe::{StripeEvent, StripeEventKind, SubscriptionData};

fn upsert_event(
    id: &str,
    tenant_id: Option<&str>,
    sid: &str,
    status: SubscriptionStatus,
) -> StripeEvent {
    StripeEvent {
        id: id.to_string(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: tenant_id.map(str::to_string),
            stripe_subscription_id: sid.to_string(),
            stripe_customer_id: "cus_1".to_string(),
            price_id: Some("price_pro".to_string()),
            entitlement: Some(Entitlement {
                max_networks: 3,
                max_daemons: 10,
            }),
            status,
            current_period_end: Some(Utc::now() + Duration::days(30)),
        }),
    }
}

#[tokio::test]
async fn webhook_created_converts_trial_to_paid() {
    let (svc, store, _events) = service();
    svc.create_trial("t1").await.unwrap();

    svc.apply_stripe_event(upsert_event(
        "evt_1",
        Some("t1"),
        "sub_x",
        SubscriptionStatus::Active,
    ))
    .await
    .unwrap();

    let current = svc.current("t1").await.unwrap().unwrap();
    assert_eq!(current.status, SubscriptionStatus::Active);
    assert_eq!(current.entitlement.max_networks, 3);
    assert_eq!(current.entitlement.max_daemons, 10);
    assert_eq!(current.stripe_subscription_id.as_deref(), Some("sub_x"));
    // The trial row was superseded → only one live row, history has two.
    assert_eq!(store.subscription_count("t1"), 2);
}

#[tokio::test]
async fn webhook_redelivery_is_idempotent() {
    let (svc, store, _events) = service();
    svc.create_trial("t1").await.unwrap();
    let event = upsert_event("evt_1", Some("t1"), "sub_x", SubscriptionStatus::Active);

    svc.apply_stripe_event(event.clone()).await.unwrap();
    // Same event id again — must not create a second paid row.
    svc.apply_stripe_event(event).await.unwrap();
    assert_eq!(store.subscription_count("t1"), 2);
}

#[tokio::test]
async fn webhook_missing_price_metadata_does_not_grant() {
    let (svc, store, _events) = service();
    svc.create_trial("t1").await.unwrap();
    let mut event = upsert_event("evt_1", Some("t1"), "sub_x", SubscriptionStatus::Active);
    if let StripeEventKind::SubscriptionUpsert(ref mut data) = event.kind {
        data.entitlement = None; // price had no max_networks/max_daemons metadata
    }
    svc.apply_stripe_event(event).await.unwrap();
    // No paid row created; the trial is still the current subscription.
    let current = svc.current("t1").await.unwrap().unwrap();
    assert_eq!(current.status, SubscriptionStatus::Trialing);
    assert_eq!(store.subscription_count("t1"), 1);
}

#[tokio::test]
async fn webhook_missing_tenant_id_does_not_grant() {
    // A brand-new paid subscription whose metadata carries no `tenant_id` cannot be
    // attributed to an account — safe-closed: decline to grant rather than guess (the
    // sibling of the missing-price-metadata path).
    let (svc, store, _events) = service();
    svc.create_trial("t1").await.unwrap();
    let event = upsert_event("evt_1", None, "sub_orphan", SubscriptionStatus::Active);
    svc.apply_stripe_event(event).await.unwrap();
    // The existing tenant's trial is untouched; nothing was granted.
    let current = svc.current("t1").await.unwrap().unwrap();
    assert_eq!(current.status, SubscriptionStatus::Trialing);
    assert_eq!(store.subscription_count("t1"), 1);
}

#[tokio::test]
async fn webhook_deleted_cancels_and_deactivates() {
    let (svc, _store, events) = service();
    svc.create_trial("t1").await.unwrap();
    svc.apply_stripe_event(upsert_event(
        "evt_1",
        Some("t1"),
        "sub_x",
        SubscriptionStatus::Active,
    ))
    .await
    .unwrap();

    svc.apply_stripe_event(StripeEvent {
        id: "evt_2".to_string(),
        kind: StripeEventKind::SubscriptionDeleted {
            stripe_subscription_id: "sub_x".to_string(),
        },
    })
    .await
    .unwrap();

    assert!(svc.current("t1").await.unwrap().is_none());
    assert!(
        events
            .published()
            .contains(&DomainEvent::SubscriptionDeactivated {
                tenant_id: "t1".to_string()
            })
    );
}

#[tokio::test]
async fn webhook_payment_failed_moves_to_past_due() {
    let (svc, _store, _events) = service();
    svc.create_trial("t1").await.unwrap();
    svc.apply_stripe_event(upsert_event(
        "evt_1",
        Some("t1"),
        "sub_x",
        SubscriptionStatus::Active,
    ))
    .await
    .unwrap();

    svc.apply_stripe_event(StripeEvent {
        id: "evt_2".to_string(),
        kind: StripeEventKind::PaymentFailed {
            stripe_subscription_id: "sub_x".to_string(),
        },
    })
    .await
    .unwrap();

    let current = svc.current("t1").await.unwrap().unwrap();
    assert_eq!(current.status, SubscriptionStatus::PastDue);
    // Entitlement is preserved across the payment-failed transition.
    assert_eq!(current.entitlement.max_networks, 3);
}

#[test]
fn is_active_respects_status_and_grace() {
    let store = MockStore::new();
    let events = Arc::new(RecordingEventPublisher::new());
    let svc = SubscriptionService::new(
        Arc::new(store) as Arc<dyn SubscriptionRepository>,
        events,
        Arc::new(MockStripeGateway::new()),
        POLICY,
    );
    let now = Utc::now();

    // Active is always entitling.
    assert!(svc.is_active(&sub("t", SubscriptionStatus::Active), now));

    // Trialing: within trial_expires_at + grace true, past it false.
    let mut trial = sub("t", SubscriptionStatus::Trialing);
    trial.trial_expires_at = Some(now - Duration::days(10)); // 10d < 15d grace
    assert!(svc.is_active(&trial, now));
    trial.trial_expires_at = Some(now - Duration::days(20)); // past grace
    assert!(!svc.is_active(&trial, now));

    // Past-due: within current_period_end + grace true, past it false.
    let mut paid = sub("t", SubscriptionStatus::PastDue);
    paid.current_period_end = Some(now - Duration::days(10));
    assert!(svc.is_active(&paid, now));
    paid.current_period_end = Some(now - Duration::days(20));
    assert!(!svc.is_active(&paid, now));

    // Canceled is never entitling.
    assert!(!svc.is_active(&sub("t", SubscriptionStatus::Canceled), now));
}
