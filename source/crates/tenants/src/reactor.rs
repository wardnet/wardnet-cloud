//! The **network** reactor — reacts to `SubscriptionDeactivated` by deprovisioning
//! the tenant's networks (`TenantsService` owns the network repository). Holds an
//! `Arc<TenantsService>` (never a repository); the reaction is **idempotent** so a
//! redelivery is harmless and the periodic reconcile re-drives a dropped event.
//! Spawn it from the binary
//! (`tokio::spawn(run_network_reactor(svc, bus.subscribe(group).await?))`).

use std::sync::Arc;

use wardnet_common::event::{DomainEvent, EventStream};

use crate::service::TenantsService;

/// Apply a single event to the network side of the tenants aggregate:
/// `SubscriptionDeactivated` → deprovision the tenant's networks. Factored out so
/// both the live loop and the deterministic test pump share one body.
pub async fn apply_to_network(service: &TenantsService, event: &DomainEvent) {
    if let DomainEvent::SubscriptionDeactivated { tenant_id } = event
        && let Err(e) = service.deprovision_networks_for(tenant_id).await
    {
        tracing::error!(error = %e, tenant_id, "network reactor: deprovision failed");
    }
}

/// React to `SubscriptionDeactivated` by deprovisioning the tenant's networks.
pub async fn run_network_reactor(service: Arc<TenantsService>, mut events: Box<dyn EventStream>) {
    while let Some(delivery) = events.next().await {
        apply_to_network(&service, delivery.event()).await;
        delivery.ack().await;
    }
}
