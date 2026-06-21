//! Unit tests for the hand-rolled Stripe gateway: the security-critical webhook
//! signature verification (valid / tampered / stale) and event normalization.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::*;

const SECRET: &str = "whsec_test_secret";

/// Build a valid `Stripe-Signature` header for `payload` at time `t`.
fn sign(payload: &[u8], t: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={t},v1={sig}")
}

#[test]
fn valid_signature_within_tolerance_passes() {
    let payload = br#"{"id":"evt_1","type":"ping"}"#;
    let now = 1_700_000_000;
    let header = sign(payload, now);
    assert!(verify_signature(payload, &header, SECRET, now).is_ok());
}

#[test]
fn tampered_payload_is_rejected() {
    let payload = br#"{"id":"evt_1","type":"ping"}"#;
    let now = 1_700_000_000;
    let header = sign(payload, now);
    // Same header, different body — the HMAC no longer matches.
    let tampered = br#"{"id":"evt_1","type":"pong"}"#;
    let err = verify_signature(tampered, &header, SECRET, now).unwrap_err();
    assert!(
        err.to_string()
            .contains("no Stripe webhook signature matched")
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let now = 1_700_000_000;
    // A well-formed but wrong v1 (correct length, all zeros).
    let header = format!("t={now},v1={}", "0".repeat(64));
    assert!(verify_signature(payload, &header, SECRET, now).is_err());
}

#[test]
fn wrong_secret_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let now = 1_700_000_000;
    let header = sign(payload, now);
    assert!(verify_signature(payload, &header, "whsec_other", now).is_err());
}

#[test]
fn stale_timestamp_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let signed_at = 1_700_000_000;
    let header = sign(payload, signed_at);
    // The signature is cryptographically valid, but `now` is 6 min later.
    let now = signed_at + SIGNATURE_TOLERANCE_SECS + 60;
    let err = verify_signature(payload, &header, SECRET, now).unwrap_err();
    assert!(err.to_string().contains("outside tolerance"));
}

#[test]
fn future_timestamp_outside_tolerance_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let signed_at = 1_700_000_000;
    let header = sign(payload, signed_at);
    let now = signed_at - SIGNATURE_TOLERANCE_SECS - 60;
    assert!(verify_signature(payload, &header, SECRET, now).is_err());
}

#[test]
fn timestamp_at_tolerance_boundary_passes() {
    let payload = br#"{"id":"evt_1"}"#;
    let signed_at = 1_700_000_000;
    let header = sign(payload, signed_at);
    let now = signed_at + SIGNATURE_TOLERANCE_SECS;
    assert!(verify_signature(payload, &header, SECRET, now).is_ok());
}

#[test]
fn multiple_v1_signatures_one_matching_passes() {
    let payload = br#"{"id":"evt_1"}"#;
    let now = 1_700_000_000;
    let good = sign(payload, now);
    let real_sig = &good[good.find("v1=").unwrap() + 3..];
    // Prepend a bogus v1 before the real one; any match is enough.
    let header = format!("t={now},v1={},v1={real_sig}", "0".repeat(64));
    assert!(verify_signature(payload, &header, SECRET, now).is_ok());
}

#[test]
fn missing_timestamp_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let header = format!("v1={}", "0".repeat(64));
    assert!(verify_signature(payload, &header, SECRET, 1_700_000_000).is_err());
}

#[test]
fn missing_signature_is_rejected() {
    let payload = br#"{"id":"evt_1"}"#;
    let header = "t=1700000000".to_string();
    assert!(verify_signature(payload, &header, SECRET, 1_700_000_000).is_err());
}

// ── Event normalization ─────────────────────────────────────────────────────────

#[test]
fn subscription_updated_maps_full_data() {
    let raw = serde_json::json!({
        "id": "evt_1",
        "type": "customer.subscription.updated",
        "data": { "object": {
            "id": "sub_123",
            "customer": "cus_abc",
            "status": "active",
            "current_period_end": 1_700_000_000_i64,
            "metadata": { "tenant_id": "tnt_xyz" },
            "items": { "data": [ { "price": {
                "id": "price_1",
                "metadata": { "max_networks": "3", "max_daemons": "10" }
            } } ] }
        } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let StripeEventKind::SubscriptionUpsert(data) = normalize_event(event).unwrap().kind else {
        panic!("expected SubscriptionUpsert");
    };
    assert_eq!(data.tenant_id.as_deref(), Some("tnt_xyz"));
    assert_eq!(data.stripe_subscription_id, "sub_123");
    assert_eq!(data.stripe_customer_id, "cus_abc");
    assert_eq!(data.price_id.as_deref(), Some("price_1"));
    let ent = data.entitlement.expect("entitlement parsed");
    assert_eq!(ent.max_networks, 3);
    assert_eq!(ent.max_daemons, 10);
    assert_eq!(data.status, SubscriptionStatus::Active);
    assert!(data.current_period_end.is_some());
}

#[test]
fn subscription_with_missing_price_metadata_declines_entitlement() {
    let raw = serde_json::json!({
        "id": "evt_2",
        "type": "customer.subscription.created",
        "data": { "object": {
            "id": "sub_1",
            "customer": "cus_1",
            "status": "trialing",
            "current_period_end": 1_700_000_000_i64,
            "items": { "data": [ { "price": { "id": "price_x", "metadata": {} } } ] }
        } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let StripeEventKind::SubscriptionUpsert(data) = normalize_event(event).unwrap().kind else {
        panic!("expected SubscriptionUpsert");
    };
    assert!(data.entitlement.is_none());
    // Stripe `trialing` is an entitling (Active) state on our side.
    assert_eq!(data.status, SubscriptionStatus::Active);
}

#[test]
fn unknown_status_is_safe_closed_to_canceled() {
    assert_eq!(map_status("active"), SubscriptionStatus::Active);
    assert_eq!(map_status("trialing"), SubscriptionStatus::Active);
    assert_eq!(map_status("past_due"), SubscriptionStatus::PastDue);
    assert_eq!(map_status("unpaid"), SubscriptionStatus::PastDue);
    assert_eq!(map_status("canceled"), SubscriptionStatus::Canceled);
    assert_eq!(map_status("incomplete"), SubscriptionStatus::Canceled);
    assert_eq!(map_status("paused"), SubscriptionStatus::Canceled);
    assert_eq!(
        map_status("some_future_state"),
        SubscriptionStatus::Canceled
    );
}

#[test]
fn subscription_deleted_maps_id() {
    let raw = serde_json::json!({
        "id": "evt_3",
        "type": "customer.subscription.deleted",
        "data": { "object": { "id": "sub_gone", "customer": "cus_1", "status": "canceled",
            "current_period_end": 0, "items": { "data": [] } } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let kind = normalize_event(event).unwrap().kind;
    assert!(matches!(
        kind,
        StripeEventKind::SubscriptionDeleted { stripe_subscription_id } if stripe_subscription_id == "sub_gone"
    ));
}

#[test]
fn invoice_payment_failed_maps_subscription_id() {
    let raw = serde_json::json!({
        "id": "evt_4",
        "type": "invoice.payment_failed",
        "data": { "object": { "subscription": "sub_late" } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let kind = normalize_event(event).unwrap().kind;
    assert!(matches!(
        kind,
        StripeEventKind::PaymentFailed { stripe_subscription_id } if stripe_subscription_id == "sub_late"
    ));
}

#[test]
fn invoice_payment_failed_without_subscription_is_ignored() {
    let raw = serde_json::json!({
        "id": "evt_5",
        "type": "invoice.payment_failed",
        "data": { "object": {} }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        normalize_event(event).unwrap().kind,
        StripeEventKind::Ignored
    ));
}

#[test]
fn unhandled_event_type_is_ignored() {
    let raw = serde_json::json!({
        "id": "evt_6",
        "type": "charge.succeeded",
        "data": { "object": {} }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        normalize_event(event).unwrap().kind,
        StripeEventKind::Ignored
    ));
}

#[test]
fn expandable_customer_object_form_is_read() {
    // Defensive: if `customer` ever arrives expanded, we still read its id.
    let raw = serde_json::json!({
        "id": "evt_7",
        "type": "customer.subscription.updated",
        "data": { "object": {
            "id": "sub_1",
            "customer": { "id": "cus_obj", "object": "customer" },
            "status": "active",
            "current_period_end": 1_700_000_000_i64,
            "items": { "data": [] }
        } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let StripeEventKind::SubscriptionUpsert(data) = normalize_event(event).unwrap().kind else {
        panic!("expected SubscriptionUpsert");
    };
    assert_eq!(data.stripe_customer_id, "cus_obj");
}

#[test]
fn current_period_end_read_from_subscription_item() {
    // Stripe API 2025-03-31+ omits the top-level field and puts it on the item.
    let raw = serde_json::json!({
        "id": "evt_8",
        "type": "customer.subscription.updated",
        "data": { "object": {
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "items": { "data": [ {
                "current_period_end": 1_700_000_000_i64,
                "price": { "id": "price_1", "metadata": {} }
            } ] }
        } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    let StripeEventKind::SubscriptionUpsert(data) = normalize_event(event).unwrap().kind else {
        panic!("expected SubscriptionUpsert");
    };
    assert!(data.current_period_end.is_some());
}

#[test]
fn unparseable_subscription_object_is_an_error_not_ignored() {
    // A handled event type whose object can't be parsed (missing required `customer`)
    // must surface an error so the handler retries — never a silent Ignored that the
    // idempotency ledger would record as permanently processed.
    let raw = serde_json::json!({
        "id": "evt_9",
        "type": "customer.subscription.updated",
        "data": { "object": { "id": "sub_1", "status": "active", "items": { "data": [] } } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    assert!(normalize_event(event).is_err());
}

#[test]
fn invoice_payment_failed_reads_nested_subscription() {
    // Stripe API 2025-03-31+ relocated the ref under parent.subscription_details.
    let raw = serde_json::json!({
        "id": "evt_10",
        "type": "invoice.payment_failed",
        "data": { "object": {
            "parent": { "subscription_details": { "subscription": "sub_nested" } }
        } }
    });
    let event: WebhookEvent = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        normalize_event(event).unwrap().kind,
        StripeEventKind::PaymentFailed { stripe_subscription_id } if stripe_subscription_id == "sub_nested"
    ));
}

// ── construct_event wrapper + constructors ──────────────────────────────────────

/// A `StripeClient` whose webhook secret matches [`sign`]'s `SECRET`. The base URL is
/// never dialed — these tests exercise the offline `construct_event` path only.
fn offline_client() -> StripeClient {
    StripeClient::from_url(
        "http://stripe.invalid",
        "sk_test",
        SECRET,
        "https://account.test/",
    )
}

#[test]
fn construct_event_verifies_signature_and_normalizes() {
    let body = serde_json::to_vec(&serde_json::json!({
        "id": "evt_x",
        "type": "customer.subscription.deleted",
        "data": { "object": {
            "id": "sub_x", "customer": "cus_1", "status": "canceled", "items": { "data": [] }
        } }
    }))
    .unwrap();
    let header = sign(&body, chrono::Utc::now().timestamp());

    let event = offline_client().construct_event(&body, &header).unwrap();
    assert_eq!(event.id, "evt_x");
    assert!(matches!(
        event.kind,
        StripeEventKind::SubscriptionDeleted { stripe_subscription_id } if stripe_subscription_id == "sub_x"
    ));
}

#[test]
fn construct_event_rejects_a_bad_signature() {
    let body = br#"{"id":"e","type":"x","data":{"object":{}}}"#;
    let header = format!("t={},v1={}", chrono::Utc::now().timestamp(), "0".repeat(64));
    assert!(offline_client().construct_event(body, &header).is_err());
}

#[test]
fn construct_event_rejects_malformed_json_under_a_valid_signature() {
    let body = b"not json at all";
    let header = sign(body, chrono::Utc::now().timestamp());
    let err = offline_client().construct_event(body, &header).unwrap_err();
    assert!(err.to_string().contains("malformed Stripe webhook payload"));
}

#[test]
fn new_constructs_a_client() {
    // The production constructor (covers `new` -> `with_base`); never dialed here.
    let _client = StripeClient::new("sk_live_x", "whsec_x", "https://account.example/");
}
