//! Unit tests for the pure catalog/promo helpers (no Stripe/DB needed).

use chrono::{Duration, Utc};

use wardnet_common::contract::Entitlement;

use super::{best_live_promo, discounted_amount, plan_view, validate_plans, validate_promos};
use crate::gateway::{PlanData, PromotionData};
use crate::repository::{CatalogPlan, CatalogPromo};

fn plan(price: &str, level: Option<u32>, ent: Option<Entitlement>) -> PlanData {
    PlanData {
        price_id: price.to_string(),
        product_id: "prod".to_string(),
        name: "Plan".to_string(),
        level,
        entitlement: ent,
        amount_cents: 1000,
        currency: "usd".to_string(),
        interval: "month".to_string(),
        active: true,
    }
}

fn ent() -> Entitlement {
    Entitlement {
        max_networks: 3,
        max_daemons: 25,
    }
}

fn catalog_plan(price: &str, product: &str, amount: i64) -> CatalogPlan {
    CatalogPlan {
        price_id: price.to_string(),
        product_id: product.to_string(),
        name: "Pro".to_string(),
        level: 2,
        entitlement: ent(),
        amount_cents: amount,
        currency: "usd".to_string(),
        interval: "month".to_string(),
    }
}

fn promo(id: &str, percent: Option<f64>, amount_off: Option<i64>) -> CatalogPromo {
    let now = Utc::now();
    CatalogPromo {
        coupon_id: id.to_string(),
        name: "Holiday".to_string(),
        percent_off: percent,
        amount_off,
        currency: Some("usd".to_string()),
        applies_to_products: vec![],
        start: Some(now - Duration::days(1)),
        redeem_by: Some(now + Duration::days(1)),
    }
}

#[test]
fn validate_plans_keeps_well_formed_drops_incomplete_and_duplicate_levels() {
    let raw = vec![
        plan("good", Some(1), Some(ent())),
        plan("no_level", None, Some(ent())),
        // A malformed price sharing level 1 must NOT poison `good` (regression guard):
        // it is dropped for the missing entitlement and excluded from the level count.
        plan("no_ent", Some(1), None),
        // Two *well-formed* plans share level 2 → both dropped (genuinely ambiguous).
        plan("dup_a", Some(2), Some(ent())),
        plan("dup_b", Some(2), Some(ent())),
    ];
    let kept = validate_plans(raw);
    let ids: Vec<_> = kept.iter().map(|p| p.price_id.as_str()).collect();
    assert_eq!(ids, vec!["good"]);
}

#[test]
fn validate_promos_keeps_only_auto_apply() {
    let mk = |id: &str, auto: bool| PromotionData {
        coupon_id: id.to_string(),
        name: "x".to_string(),
        percent_off: Some(10.0),
        amount_off: None,
        currency: None,
        applies_to_products: vec![],
        start: None,
        redeem_by: Some(Utc::now()),
        auto_apply: auto,
    };
    let kept = validate_promos(vec![mk("a", true), mk("b", false)]);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].coupon_id, "a");
}

#[test]
fn discounted_amount_percent_and_amount_off() {
    let p = catalog_plan("price", "prod", 1000);
    // 20% off 1000 = 800.
    assert_eq!(
        discounted_amount(p.amount_cents, &p.currency, &promo("c", Some(20.0), None)),
        800
    );
    // $2 off (same currency) = 800.
    assert_eq!(
        discounted_amount(p.amount_cents, &p.currency, &promo("c", None, Some(200))),
        800
    );
}

#[test]
fn discounted_amount_ignores_amount_off_in_other_currency() {
    let p = catalog_plan("price", "prod", 1000);
    let mut c = promo("c", None, Some(200));
    c.currency = Some("eur".to_string());
    // Currency mismatch → no discount applied.
    assert_eq!(discounted_amount(p.amount_cents, &p.currency, &c), 1000);
}

#[test]
fn best_live_promo_picks_largest_discount_within_window() {
    let p = catalog_plan("price", "prod", 1000);
    let now = Utc::now();
    let small = promo("small", Some(10.0), None);
    let big = promo("big", Some(40.0), None);
    let expired = CatalogPromo {
        redeem_by: Some(now - Duration::days(1)),
        ..promo("expired", Some(90.0), None)
    };
    let promos = [small, big, expired];
    let chosen = best_live_promo(&p, &promos, now).unwrap();
    assert_eq!(chosen.coupon_id, "big");
}

#[test]
fn best_live_promo_respects_product_targeting() {
    let p = catalog_plan("price", "prod_pro", 1000);
    let other = CatalogPromo {
        applies_to_products: vec!["prod_other".to_string()],
        ..promo("other", Some(50.0), None)
    };
    let promos = [other];
    assert!(best_live_promo(&p, &promos, Utc::now()).is_none());
}

#[test]
fn plan_view_attaches_promo_discounted_price() {
    let p = catalog_plan("price", "prod", 1000);
    let view = plan_view(&p, &[promo("c", Some(25.0), None)], Utc::now());
    let promo = view.promo.expect("a live promo");
    assert_eq!(view.amount_cents, 1000);
    assert_eq!(promo.amount_cents_after, 750);
}
