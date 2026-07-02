//! Billing-plane integration: server-side promo derivation forwards the live coupon to
//! Stripe on checkout, and suppresses it on an explicit full-price re-confirm.

mod common;

use chrono::{Duration, Utc};

use wardnet_billing::gateway::{
    PlanData, PromotionData, ScheduledChange, StripeEvent, StripeEventKind, SubscriptionData,
    SubscriptionDetails,
};
use wardnet_billing::repository::{BillingRepository, CatalogPlan, CatalogPromo};
use wardnet_common::contract::{Entitlement, PlanChangeEffect, SubscriptionStatus};
use wardnet_common::ports::SubscriptionCommands;

use common::build_harness;

/// Seed a two-tier catalog: Home (the trial-equivalent, `1/1`) and Pro (`3/6`).
async fn seed_home_and_pro(h: &common::Harness) {
    let now = Utc::now();
    let plan = |price: &str, prod: &str, name: &str, level, nets, daemons, cents| CatalogPlan {
        price_id: price.to_string(),
        product_id: prod.to_string(),
        name: name.to_string(),
        level,
        entitlement: Entitlement {
            max_networks: nets,
            max_daemons: daemons,
        },
        amount_cents: cents,
        currency: "usd".to_string(),
        interval: "month".to_string(),
    };
    let plans = vec![
        plan("price_home", "prod_home", "Home", 1, 1, 1, 370),
        plan("price_pro", "prod_pro", "Pro", 3, 3, 6, 1490),
    ];
    h.store.replace_catalog(&plans, &[], now).await.unwrap();
}

/// Seed the catalog projection with one plan carrying a live auto-apply promotion.
async fn seed_catalog_with_live_promo(h: &common::Harness) {
    let now = Utc::now();
    let plans = vec![CatalogPlan {
        price_id: "price_pro".to_string(),
        product_id: "prod_pro".to_string(),
        name: "Pro".to_string(),
        level: 2,
        entitlement: Entitlement {
            max_networks: 3,
            max_daemons: 25,
        },
        amount_cents: 800,
        currency: "usd".to_string(),
        interval: "month".to_string(),
    }];
    let promos = vec![CatalogPromo {
        coupon_id: "co_holiday".to_string(),
        name: "Holiday".to_string(),
        percent_off: Some(25.0),
        amount_off: None,
        currency: Some("usd".to_string()),
        applies_to_products: vec!["prod_pro".to_string()],
        start: Some(now - Duration::days(1)),
        redeem_by: Some(now + Duration::days(1)),
    }];
    h.store.replace_catalog(&plans, &promos, now).await.unwrap();
}

#[tokio::test]
async fn checkout_forwards_the_live_coupon() {
    let h = build_harness(1);
    seed_catalog_with_live_promo(&h).await;

    h.state
        .billing()
        .start_checkout("tenant_1", "u@example.com", "price_pro", false)
        .await
        .unwrap();

    let coupons = h.stripe.checkout_coupons.lock().unwrap();
    assert_eq!(coupons.as_slice(), &[Some("co_holiday".to_string())]);
}

#[tokio::test]
async fn checkout_suppresses_the_coupon_on_accept_full_price() {
    let h = build_harness(2);
    seed_catalog_with_live_promo(&h).await;

    h.state
        .billing()
        .start_checkout("tenant_1", "u@example.com", "price_pro", true)
        .await
        .unwrap();

    let coupons = h.stripe.checkout_coupons.lock().unwrap();
    assert_eq!(coupons.as_slice(), &[None]);
}

// ── ADR-0012: honor the remaining trial when subscribing to the trial-equivalent plan ──

/// Subscribing to Home (the trial tier) from the managed trial defers the first charge to
/// the tenant's original trial end — the checkout carries `trial_end`.
#[tokio::test]
async fn checkout_preserves_the_trial_for_the_trial_tier() {
    let h = build_harness(10);
    seed_home_and_pro(&h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();

    h.state
        .billing()
        .start_checkout("tenant_1", "u@e.com", "price_home", false)
        .await
        .unwrap();

    let expiry = h
        .subscriptions
        .current("tenant_1")
        .await
        .unwrap()
        .unwrap()
        .trial_expires_at
        .unwrap();
    let trial_ends = h.stripe.checkout_trial_ends.lock().unwrap();
    assert_eq!(trial_ends.as_slice(), &[Some(expiry.timestamp())]);
}

/// Subscribing to a higher tier (Pro) from the trial forfeits it — no `trial_end`, so the
/// first charge is immediate.
#[tokio::test]
async fn checkout_does_not_preserve_the_trial_for_a_higher_tier() {
    let h = build_harness(11);
    seed_home_and_pro(&h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();

    h.state
        .billing()
        .start_checkout("tenant_1", "u@e.com", "price_pro", false)
        .await
        .unwrap();

    let trial_ends = h.stripe.checkout_trial_ends.lock().unwrap();
    assert_eq!(trial_ends.as_slice(), &[None]);
}

/// Upgrading a subscription still in its Stripe trial ends the trial so it charges now
/// (closes the subscribe-Home-then-upgrade loophole).
#[tokio::test]
async fn upgrade_during_the_stripe_trial_ends_it() {
    let h = build_harness(12);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_home"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".to_string(),
        price_id: "price_home".to_string(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: None,
        trialing: true,
    });

    let resp = h
        .state
        .billing()
        .change_plan("tenant_1", "price_pro", false)
        .await
        .unwrap();

    assert_eq!(
        h.stripe.upgrade_end_trials.lock().unwrap().as_slice(),
        &[true]
    );
    // The response reflects the new current plan immediately (no webhook wait).
    assert_eq!(resp.current_price_id.as_deref(), Some("price_pro"));
}

/// `billing_subscription` surfaces the Stripe trial flag so the SPA can confirm an
/// in-app upgrade that would end a honored trial (a honored trial reads locally `Active`).
#[tokio::test]
async fn billing_subscription_reports_the_stripe_trial() {
    let h = build_harness(14);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_home"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".to_string(),
        price_id: "price_home".to_string(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: None,
        trialing: true,
    });

    let view = h
        .state
        .billing()
        .billing_subscription("tenant_1")
        .await
        .unwrap();

    assert!(view.trialing);
    assert_eq!(view.current_price_id.as_deref(), Some("price_home"));
    assert!(view.pending_change.is_none());
}

/// The setup-mode card-update session's currency is derived from the tenant's plan (setup
/// mode has no line items to infer it), not hardcoded — proven with a non-USD plan.
#[tokio::test]
async fn card_update_uses_the_plan_currency() {
    let h = build_harness(15);
    let now = Utc::now();
    let plans = vec![CatalogPlan {
        price_id: "price_eur".to_string(),
        product_id: "prod_eur".to_string(),
        name: "Euro".to_string(),
        level: 1,
        entitlement: Entitlement {
            max_networks: 1,
            max_daemons: 1,
        },
        amount_cents: 500,
        currency: "eur".to_string(),
        interval: "month".to_string(),
    }];
    h.store.replace_catalog(&plans, &[], now).await.unwrap();
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_eur"))
        .await
        .unwrap();

    h.state
        .billing()
        .start_card_update("tenant_1")
        .await
        .unwrap();

    assert_eq!(
        h.stripe.setup_currencies.lock().unwrap().as_slice(),
        &["eur".to_string()]
    );
}

// ── Webhook apply-event branches ──────────────────────────────────────────────

/// A tenant with an active paid subscription and its recorded Stripe billing ref.
async fn seed_paid_tenant(h: &common::Harness) {
    seed_home_and_pro(h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();
    h.subscriptions
        .convert_trial_to_paid(
            "tenant_1",
            SubscriptionStatus::Active,
            Entitlement {
                max_networks: 3,
                max_daemons: 6,
            },
            Some(Utc::now() + Duration::days(30)),
        )
        .await
        .unwrap();
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_pro"))
        .await
        .unwrap();
}

#[tokio::test]
async fn webhook_payment_failed_marks_past_due() {
    let h = build_harness(20);
    seed_paid_tenant(&h).await;
    h.stripe.set_event(StripeEvent {
        id: "evt_pf".into(),
        kind: StripeEventKind::PaymentFailed {
            stripe_subscription_id: "sub_1".into(),
        },
    });
    h.state
        .billing()
        .handle_webhook(b"{}", "sig")
        .await
        .unwrap();
    let cur = h.subscriptions.current("tenant_1").await.unwrap().unwrap();
    assert_eq!(cur.status, SubscriptionStatus::PastDue);
}

#[tokio::test]
async fn webhook_subscription_deleted_cancels() {
    let h = build_harness(21);
    seed_paid_tenant(&h).await;
    h.stripe.set_event(StripeEvent {
        id: "evt_del".into(),
        kind: StripeEventKind::SubscriptionDeleted {
            stripe_subscription_id: "sub_1".into(),
        },
    });
    h.state
        .billing()
        .handle_webhook(b"{}", "sig")
        .await
        .unwrap();
    assert!(h.subscriptions.current("tenant_1").await.unwrap().is_none());
}

#[tokio::test]
async fn webhook_card_setup_promotes_the_new_default_payment_method() {
    let h = build_harness(22);
    seed_paid_tenant(&h).await;
    h.stripe.set_event(StripeEvent {
        id: "evt_setup".into(),
        kind: StripeEventKind::CardSetupCompleted {
            stripe_customer_id: "cus_1".into(),
            setup_intent_id: "seti_1".into(),
        },
    });
    h.state
        .billing()
        .handle_webhook(b"{}", "sig")
        .await
        .unwrap();
    assert_eq!(
        h.stripe.default_pm_setups.lock().unwrap().as_slice(),
        &[(
            "cus_1".to_string(),
            Some("sub_1".to_string()),
            "seti_1".to_string()
        )]
    );
}

#[tokio::test]
async fn webhook_upsert_without_price_metadata_declines_to_grant() {
    let h = build_harness(23);
    seed_home_and_pro(&h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();
    h.stripe.set_event(StripeEvent {
        id: "evt_up".into(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("tenant_1".into()),
            stripe_subscription_id: "sub_x".into(),
            stripe_customer_id: "cus_x".into(),
            price_id: Some("price_x".into()),
            entitlement: None,
            status: SubscriptionStatus::Active,
            current_period_end: None,
        }),
    });
    h.state
        .billing()
        .handle_webhook(b"{}", "sig")
        .await
        .unwrap();
    // Safe-closed: no entitlement metadata → the tenant stays on its trial, not granted.
    let cur = h.subscriptions.current("tenant_1").await.unwrap().unwrap();
    assert_eq!(cur.status, SubscriptionStatus::Trialing);
}

// ── change_plan downgrade paths ───────────────────────────────────────────────

#[tokio::test]
async fn change_plan_downgrade_schedules_at_period_end() {
    let h = build_harness(24);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_pro"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".into(),
        price_id: "price_pro".into(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: None,
        trialing: false,
    });

    let resp = h
        .state
        .billing()
        .change_plan("tenant_1", "price_home", false)
        .await
        .unwrap();

    assert!(matches!(resp.effect, PlanChangeEffect::DowngradeScheduled));
    assert!(resp.effective_at.is_some());
    assert!(
        h.stripe
            .changes
            .lock()
            .unwrap()
            .iter()
            .any(|(_, price, kind, _)| price == "price_home" && *kind == "downgrade")
    );
}

#[tokio::test]
async fn change_plan_reselect_current_cancels_the_pending_downgrade() {
    let h = build_harness(25);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_pro"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".into(),
        price_id: "price_pro".into(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: Some("sched_1".into()),
        trialing: false,
    });

    let resp = h
        .state
        .billing()
        .change_plan("tenant_1", "price_pro", false)
        .await
        .unwrap();

    assert!(matches!(resp.effect, PlanChangeEffect::DowngradeCanceled));
    assert_eq!(
        h.stripe.released.lock().unwrap().as_slice(),
        &["sched_1".to_string()]
    );
}

/// A failed act after releasing the schedule best-effort restores the pending downgrade,
/// so the user doesn't silently lose it (release-then-act rollback).
#[tokio::test]
async fn change_plan_restores_pending_downgrade_when_the_act_fails() {
    let h = build_harness(28);
    let now = Utc::now();
    let plan = |price: &str, prod: &str, name: &str, level: u32, daemons: u32| CatalogPlan {
        price_id: price.to_string(),
        product_id: prod.to_string(),
        name: name.to_string(),
        level,
        entitlement: Entitlement {
            max_networks: 1,
            max_daemons: daemons,
        },
        amount_cents: 100 * i64::from(level),
        currency: "usd".to_string(),
        interval: "month".to_string(),
    };
    h.store
        .replace_catalog(
            &[
                plan("price_home", "prod_home", "Home", 1, 1),
                plan("price_hha", "prod_hha", "Home HA", 2, 2),
                plan("price_pro", "prod_pro", "Pro", 3, 6),
            ],
            &[],
            now,
        )
        .await
        .unwrap();
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_hha"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".into(),
        price_id: "price_hha".into(),
        current_period_end: now + Duration::days(30),
        schedule_id: Some("sched_1".into()),
        trialing: false,
    });
    // The pending downgrade currently scheduled (HA → Home).
    h.stripe.set_pending_change(ScheduledChange {
        price_id: "price_home".into(),
        effective_at: now + Duration::days(30),
    });
    h.stripe.fail_next_upgrade();

    // Upgrade HA→Pro: releases the schedule, the upgrade fails, the pending is restored.
    let result = h
        .state
        .billing()
        .change_plan("tenant_1", "price_pro", false)
        .await;
    assert!(result.is_err());
    // The released schedule was re-created for the prior downgrade target (Home).
    assert!(
        h.stripe
            .changes
            .lock()
            .unwrap()
            .iter()
            .any(|(_, price, kind, _)| price == "price_home" && *kind == "downgrade")
    );
}

// ── start_checkout: no trial preservation for a non-trialing subscriber ────────

#[tokio::test]
async fn checkout_from_a_paid_subscription_sets_no_trial_end() {
    let h = build_harness(26);
    seed_paid_tenant(&h).await; // active (paid), not trialing
    h.state
        .billing()
        .start_checkout("tenant_1", "u@e.com", "price_pro", false)
        .await
        .unwrap();
    assert_eq!(
        h.stripe.checkout_trial_ends.lock().unwrap().as_slice(),
        &[None]
    );
}

/// A trial with less than the preserve window (`TRIAL_PRESERVE_MIN_HOURS`) left can't be
/// deferred (Stripe would reject the near `trial_end`), so it charges immediately even for
/// the trial-equivalent plan.
#[tokio::test]
async fn checkout_does_not_preserve_a_near_expiry_trial() {
    let h = build_harness(29);
    seed_home_and_pro(&h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();
    h.store
        .set_trial_expiry("tenant_1", Utc::now() + Duration::hours(12));

    h.state
        .billing()
        .start_checkout("tenant_1", "u@e.com", "price_home", false)
        .await
        .unwrap();

    assert_eq!(
        h.stripe.checkout_trial_ends.lock().unwrap().as_slice(),
        &[None]
    );
}

/// A trial already past its expiry (the tenant is in grace) has no free days to defer, so
/// subscribing charges immediately.
#[tokio::test]
async fn checkout_does_not_preserve_an_expired_trial() {
    let h = build_harness(30);
    seed_home_and_pro(&h).await;
    h.subscriptions.create_trial("tenant_1").await.unwrap();
    h.store
        .set_trial_expiry("tenant_1", Utc::now() - Duration::days(1));

    h.state
        .billing()
        .start_checkout("tenant_1", "u@e.com", "price_home", false)
        .await
        .unwrap();

    assert_eq!(
        h.stripe.checkout_trial_ends.lock().unwrap().as_slice(),
        &[None]
    );
}

// ── billing_subscription surfaces a pending downgrade (the schedule read path) ─

#[tokio::test]
async fn billing_subscription_surfaces_a_pending_downgrade() {
    let h = build_harness(27);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_pro"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".into(),
        price_id: "price_pro".into(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: Some("sched_1".into()),
        trialing: false,
    });
    h.stripe.set_pending_change(ScheduledChange {
        price_id: "price_home".into(),
        effective_at: Utc::now() + Duration::days(30),
    });

    let view = h
        .state
        .billing()
        .billing_subscription("tenant_1")
        .await
        .unwrap();

    let pending = view.pending_change.expect("a pending downgrade");
    assert_eq!(pending.price_id, "price_home");
    assert_eq!(pending.name, "Home");
}

/// An ordinary upgrade on an already-paid (non-trialing) subscription does not touch the
/// trial.
#[tokio::test]
async fn upgrade_on_a_paid_subscription_does_not_end_a_trial() {
    let h = build_harness(13);
    seed_home_and_pro(&h).await;
    h.store
        .upsert_subscription("tenant_1", "cus_1", "sub_1", Some("price_home"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_1".to_string(),
        price_id: "price_home".to_string(),
        current_period_end: Utc::now() + Duration::days(30),
        schedule_id: None,
        trialing: false,
    });

    h.state
        .billing()
        .change_plan("tenant_1", "price_pro", false)
        .await
        .unwrap();

    assert_eq!(
        h.stripe.upgrade_end_trials.lock().unwrap().as_slice(),
        &[false]
    );
}

// ── Catalog sync + read-model edge branches ───────────────────────────────────

/// `sync_catalog` projects Stripe's live catalog into the local tables, keeping only
/// plans with entitlement metadata and only auto-apply promotions.
#[tokio::test]
async fn sync_catalog_projects_valid_plans_and_drops_invalid() {
    let h = build_harness(31);
    h.stripe.set_catalog(
        vec![
            PlanData {
                price_id: "price_ok".to_string(),
                product_id: "prod_ok".to_string(),
                name: "Home".to_string(),
                level: Some(1),
                entitlement: Some(Entitlement {
                    max_networks: 1,
                    max_daemons: 1,
                }),
                amount_cents: 370,
                currency: "usd".to_string(),
                interval: "month".to_string(),
                active: true,
            },
            // No level/entitlement metadata → validate_plans drops it.
            PlanData {
                price_id: "price_bad".to_string(),
                product_id: "prod_bad".to_string(),
                name: "Mystery".to_string(),
                level: None,
                entitlement: None,
                amount_cents: 100,
                currency: "usd".to_string(),
                interval: "month".to_string(),
                active: true,
            },
        ],
        vec![
            PromotionData {
                coupon_id: "co_auto".to_string(),
                name: "Founders".to_string(),
                percent_off: Some(25.0),
                amount_off: None,
                currency: Some("usd".to_string()),
                applies_to_products: vec!["prod_ok".to_string()],
                start: None,
                redeem_by: None,
                auto_apply: true,
            },
            // Not auto-apply → validate_promos drops it.
            PromotionData {
                coupon_id: "co_manual".to_string(),
                name: "Manual".to_string(),
                percent_off: Some(10.0),
                amount_off: None,
                currency: None,
                applies_to_products: vec![],
                start: None,
                redeem_by: None,
                auto_apply: false,
            },
        ],
    );

    h.billing.sync_catalog().await.unwrap();

    let snap = h.store.read_catalog().await.unwrap();
    assert_eq!(snap.plans.len(), 1);
    assert_eq!(snap.plans[0].price_id, "price_ok");
    assert_eq!(snap.promos.len(), 1);
    assert_eq!(snap.promos[0].coupon_id, "co_auto");
}

/// A tenant that has never subscribed (no billing ref) reports an empty billing view —
/// no current price, no pending change, not a Stripe trial — without calling Stripe.
#[tokio::test]
async fn billing_subscription_without_a_billing_ref_is_empty() {
    let h = build_harness(32);
    seed_home_and_pro(&h).await;

    let view = h
        .state
        .billing()
        .billing_subscription("tenant_1")
        .await
        .unwrap();

    assert!(view.current_price_id.is_none());
    assert!(view.pending_change.is_none());
    assert!(!view.trialing);
}

/// A `customer.subscription.updated` for an already-active subscription takes the
/// update path (re-entitle in place), not a second convert.
#[tokio::test]
async fn webhook_upsert_updates_an_active_subscription() {
    let h = build_harness(33);
    seed_paid_tenant(&h).await; // active, entitlement 3/6
    h.stripe.set_event(StripeEvent {
        id: "evt_upd".into(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("tenant_1".into()),
            stripe_subscription_id: "sub_1".into(),
            stripe_customer_id: "cus_1".into(),
            price_id: Some("price_home".into()),
            entitlement: Some(Entitlement {
                max_networks: 1,
                max_daemons: 1,
            }),
            status: SubscriptionStatus::Active,
            current_period_end: Some(Utc::now() + Duration::days(30)),
        }),
    });
    h.state
        .billing()
        .handle_webhook(b"{}", "sig")
        .await
        .unwrap();

    let cur = h.subscriptions.current("tenant_1").await.unwrap().unwrap();
    assert_eq!(cur.status, SubscriptionStatus::Active);
    assert_eq!(cur.entitlement.max_networks, 1);
    assert_eq!(cur.entitlement.max_daemons, 1);
}
