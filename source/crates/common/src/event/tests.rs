//! Unit tests for the in-process event bus + the versioned wire format.

use super::{DomainEvent, EVENT_WIRE_VERSION, EventBus, InProcessEventBus, WireEnvelope};

#[tokio::test]
async fn subscriber_receives_published_events() {
    let bus = InProcessEventBus::new(16);
    let mut stream = bus.subscribe("test").await.expect("subscribe");

    bus.publish(&DomainEvent::TenantCreated {
        tenant_id: "t1".to_string(),
    })
    .await
    .expect("publish");

    let delivery = stream.next().await.expect("event delivered");
    assert_eq!(
        delivery.event(),
        &DomainEvent::TenantCreated {
            tenant_id: "t1".to_string()
        }
    );
    delivery.ack().await;
}

#[tokio::test]
async fn publish_with_no_subscribers_is_a_noop() {
    let bus = InProcessEventBus::new(16);
    // No panic / no error surfaced to the caller when nobody is listening.
    bus.publish(&DomainEvent::SubscriptionDeactivated {
        tenant_id: "t1".to_string(),
    })
    .await
    .expect("publish with no subscribers must not error");
}

#[tokio::test]
async fn each_subscriber_sees_every_event() {
    let bus = InProcessEventBus::new(16);
    let mut a = bus.subscribe("a").await.expect("subscribe a");
    let mut b = bus.subscribe("b").await.expect("subscribe b");

    bus.publish(&DomainEvent::TenantDeregistered {
        tenant_id: "t9".to_string(),
    })
    .await
    .expect("publish");

    let expected = DomainEvent::TenantDeregistered {
        tenant_id: "t9".to_string(),
    };
    assert_eq!(a.next().await.unwrap().event(), &expected);
    assert_eq!(b.next().await.unwrap().event(), &expected);
}

#[test]
fn wire_format_is_stable_and_versioned() {
    // Pin the on-the-wire shape a future broker adapter must produce/consume:
    // `{ "v": 1, "type": "tenant_created", "tenant_id": "t1" }`.
    let env = WireEnvelope::new(DomainEvent::TenantCreated {
        tenant_id: "t1".to_string(),
    });
    let json = serde_json::to_value(&env).expect("serialize");
    assert_eq!(json["v"], EVENT_WIRE_VERSION);
    assert_eq!(json["type"], "tenant_created");
    assert_eq!(json["tenant_id"], "t1");

    let round: WireEnvelope = serde_json::from_value(json).expect("deserialize");
    assert_eq!(round.v, EVENT_WIRE_VERSION);
    assert_eq!(
        round.event,
        DomainEvent::TenantCreated {
            tenant_id: "t1".to_string()
        }
    );
}
