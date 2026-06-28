//! The **subscription** reactor — the long-running loop that turns published
//! [`DomainEvent`]s into [`SubscriptionService`] calls. It holds an
//! `Arc<SubscriptionService>` (never a repository), and every reaction is
//! **idempotent** so a redelivery is harmless and the periodic reconcile can
//! re-drive a dropped event. Spawn it from the binary
//! (`tokio::spawn(run_subscription_reactor(svc, bus.subscribe(group).await?))`).

use std::sync::Arc;

use wardnet_common::event::{DomainEvent, EventStream};

use crate::service::SubscriptionService;

/// Apply a single event to the subscription aggregate: `TenantCreated` → open the
/// trial, `TenantDeregistered` → cancel. Other events are ignored. Factored out so
/// both the live loop and the deterministic test pump share one body.
pub async fn apply_to_subscription(service: &SubscriptionService, event: &DomainEvent) {
    match event {
        DomainEvent::TenantCreated { tenant_id } => {
            if let Err(e) = service.create_trial(tenant_id).await {
                tracing::error!(error = %e, tenant_id, "subscription reactor: create_trial failed");
            }
        }
        DomainEvent::TenantDeregistered { tenant_id } => {
            if let Err(e) = service.cancel(tenant_id).await {
                tracing::error!(error = %e, tenant_id, "subscription reactor: cancel failed");
            }
        }
        DomainEvent::SubscriptionDeactivated { .. } => {}
    }
}

/// React to tenant-lifecycle events by driving the subscription aggregate.
pub async fn run_subscription_reactor(
    service: Arc<SubscriptionService>,
    mut events: Box<dyn EventStream>,
) {
    while let Some(delivery) = events.next().await {
        apply_to_subscription(&service, delivery.event()).await;
        delivery.ack().await;
    }
}
