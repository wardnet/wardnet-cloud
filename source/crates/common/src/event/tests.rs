//! Unit tests for the broadcast event bus.

use super::{BroadcastEventBus, DomainEvent, EventPublisher};

#[tokio::test]
async fn subscriber_receives_published_events() {
    let bus = BroadcastEventBus::new(16);
    let mut rx = bus.subscribe();

    bus.publish(DomainEvent::TenantCreated {
        tenant_id: "t1".to_string(),
    });

    let got = rx.recv().await.expect("event delivered");
    assert_eq!(
        got,
        DomainEvent::TenantCreated {
            tenant_id: "t1".to_string()
        }
    );
}

#[tokio::test]
async fn publish_with_no_subscribers_is_a_noop() {
    let bus = BroadcastEventBus::new(16);
    // No panic / no error surfaced to the caller when nobody is listening.
    bus.publish(DomainEvent::SubscriptionDeactivated {
        tenant_id: "t1".to_string(),
    });
}

#[tokio::test]
async fn each_subscriber_sees_every_event() {
    let bus = BroadcastEventBus::new(16);
    let mut a = bus.subscribe();
    let mut b = bus.subscribe();

    bus.publish(DomainEvent::TenantDeregistered {
        tenant_id: "t9".to_string(),
    });

    let expected = DomainEvent::TenantDeregistered {
        tenant_id: "t9".to_string(),
    };
    assert_eq!(a.recv().await.unwrap(), expected);
    assert_eq!(b.recv().await.unwrap(), expected);
}
