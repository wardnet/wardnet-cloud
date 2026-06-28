//! Unit tests for [`SubscriptionService`] over a small in-memory mock repository +
//! a recording [`EventBus`]. License logic only (trial creation, grace, the reaper,
//! cancel); the Stripe-driven lifecycle is exercised in the `billing` aggregate and
//! the composition-root webhook integration tests, not here.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use wardnet_common::contract::{Entitlement, SubscriptionStatus};
use wardnet_common::event::{DomainEvent, EventBus, EventStream};

use crate::repository::{Subscription, SubscriptionRepository};
use crate::service::{SubscriptionService, TrialPolicy};

const POLICY: TrialPolicy = TrialPolicy {
    trial_days: 60,
    trial_grace_days: 15,
    payment_grace_days: 15,
};

// ── In-memory mock repository ─────────────────────────────────────────────────────

/// A minimal in-memory [`SubscriptionRepository`] mirroring the SQL guards the live
/// loops depend on (one live row per tenant; the trial insert is skipped when any
/// history exists).
#[derive(Default)]
struct MockRepo(Mutex<Vec<Subscription>>);

impl MockRepo {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    /// Seed a subscription row directly.
    fn seed(&self, sub: Subscription) {
        self.0.lock().unwrap().push(sub);
    }

    /// Number of rows stored for a tenant (history included).
    fn subscription_count(&self, tenant_id: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.tenant_id == tenant_id)
            .count()
    }
}

#[async_trait]
impl SubscriptionRepository for MockRepo {
    async fn create_trial(&self, sub: &Subscription) -> anyhow::Result<bool> {
        let mut rows = self.0.lock().unwrap();
        if rows.iter().any(|s| s.tenant_id == sub.tenant_id) {
            return Ok(false);
        }
        rows.push(sub.clone());
        Ok(true)
    }

    async fn find_current(&self, tenant_id: &str) -> anyhow::Result<Option<Subscription>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
            .cloned())
    }

    async fn convert_trial_to_paid(
        &self,
        tenant_id: &str,
        paid: &Subscription,
    ) -> anyhow::Result<()> {
        let mut rows = self.0.lock().unwrap();
        for s in rows.iter_mut() {
            if s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled {
                s.status = SubscriptionStatus::Canceled;
            }
        }
        rows.push(paid.clone());
        Ok(())
    }

    async fn update_current(
        &self,
        tenant_id: &str,
        status: SubscriptionStatus,
        entitlement: Entitlement,
        current_period_end: Option<DateTime<Utc>>,
    ) -> anyhow::Result<bool> {
        let mut rows = self.0.lock().unwrap();
        if let Some(s) = rows
            .iter_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = status;
            s.entitlement = entitlement;
            s.current_period_end = current_period_end;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn mark_past_due_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let mut rows = self.0.lock().unwrap();
        if let Some(s) = rows
            .iter_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = SubscriptionStatus::PastDue;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn cancel_current(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let mut rows = self.0.lock().unwrap();
        if let Some(s) = rows
            .iter_mut()
            .find(|s| s.tenant_id == tenant_id && s.status != SubscriptionStatus::Canceled)
        {
            s.status = SubscriptionStatus::Canceled;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list_overdue(
        &self,
        trial_cutoff: DateTime<Utc>,
        payment_cutoff: DateTime<Utc>,
    ) -> anyhow::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| match s.status {
                SubscriptionStatus::Trialing => {
                    s.trial_expires_at.is_some_and(|t| t < trial_cutoff)
                }
                SubscriptionStatus::PastDue => {
                    s.current_period_end.is_some_and(|c| c < payment_cutoff)
                }
                _ => false,
            })
            .map(|s| s.tenant_id.clone())
            .collect())
    }
}

// ── Recording event bus ───────────────────────────────────────────────────────────

/// An [`EventBus`] that records every published event for assertions. `subscribe` is
/// never exercised by these synchronous tests.
#[derive(Default)]
struct RecordingBus(Mutex<Vec<DomainEvent>>);

impl RecordingBus {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    fn published(&self) -> Vec<DomainEvent> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl EventBus for RecordingBus {
    async fn publish(&self, event: &DomainEvent) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn subscribe(&self, _group: &str) -> anyhow::Result<Box<dyn EventStream>> {
        unreachable!("these tests never subscribe")
    }
}

// ── Fixtures ──────────────────────────────────────────────────────────────────────

fn service() -> (Arc<SubscriptionService>, Arc<MockRepo>, Arc<RecordingBus>) {
    let repo = Arc::new(MockRepo::new());
    let events = Arc::new(RecordingBus::new());
    let svc = Arc::new(SubscriptionService::new(
        Arc::clone(&repo) as Arc<dyn SubscriptionRepository>,
        Arc::clone(&events) as Arc<dyn EventBus>,
        POLICY,
    ));
    (svc, repo, events)
}

/// A subscription row with the given status + default timestamps.
fn sub(tenant_id: &str, status: SubscriptionStatus) -> Subscription {
    let now = Utc::now();
    Subscription {
        id: format!("sub-{tenant_id}"),
        tenant_id: tenant_id.to_string(),
        status,
        entitlement: Entitlement::DEFAULT,
        trial_expires_at: None,
        current_period_end: None,
        created_at: now,
        updated_at: now,
    }
}

// ── Trial creation ─────────────────────────────────────────────────────────────────

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

// ── Cancel + reaper ────────────────────────────────────────────────────────────────

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
    store.seed(expired_trial);

    // A trial still within grace — must survive.
    let mut fresh_trial = sub("t-fresh", SubscriptionStatus::Trialing);
    fresh_trial.trial_expires_at = Some(now - Duration::days(2));
    store.seed(fresh_trial);

    // A past-due subscription past its payment grace.
    let mut overdue_paid = sub("t-paid", SubscriptionStatus::PastDue);
    overdue_paid.current_period_end = Some(now - Duration::days(20));
    store.seed(overdue_paid);

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

// ── Grace-aware entitlement ─────────────────────────────────────────────────────────

#[test]
fn is_active_respects_status_and_grace() {
    let (svc, _store, _events) = service();
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

#[test]
fn is_active_grace_boundary_is_exclusive() {
    // The grace check is `now < expiry + grace` (strict): at the exact cutoff the
    // subscription is already inactive. Pins the operator so a `<` → `<=` regression
    // (a free extra moment of service past grace) is caught.
    let (svc, _store, _events) = service();
    let now = Utc::now();

    let mut trial = sub("t", SubscriptionStatus::Trialing);
    // One second inside the 15-day grace window → still active.
    trial.trial_expires_at =
        Some(now - Duration::days(POLICY.trial_grace_days) + Duration::seconds(1));
    assert!(svc.is_active(&trial, now));
    // Exactly at the cutoff (now == expiry + grace) → no longer active.
    trial.trial_expires_at = Some(now - Duration::days(POLICY.trial_grace_days));
    assert!(!svc.is_active(&trial, now));
}
