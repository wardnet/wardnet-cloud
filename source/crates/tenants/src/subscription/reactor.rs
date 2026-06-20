//! Domain-event reactors — the long-running loops that turn published
//! [`DomainEvent`]s into the owning service's method calls. Each holds an
//! `Arc<Service>` (never a repository), and every reaction is **idempotent** so a
//! redelivery is harmless and the periodic reconcile can re-drive a dropped event.
//!
//! Spawn these from `main` (`tokio::spawn(run_subscription_reactor(...))`).

use std::sync::Arc;

use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

use wardnet_common::event::DomainEvent;

use crate::service::TenantsService;
use crate::subscription::SubscriptionService;

/// Apply a single event to the **subscription** aggregate: `TenantCreated` → open
/// the trial, `TenantDeregistered` → cancel. Other events are ignored. Factored out
/// so both the live loop and the deterministic test pump share one body.
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

/// Apply a single event to the **network** side of the tenants aggregate:
/// `SubscriptionDeactivated` → deprovision the tenant's networks.
pub async fn apply_to_network(service: &TenantsService, event: &DomainEvent) {
    if let DomainEvent::SubscriptionDeactivated { tenant_id } = event
        && let Err(e) = service.deprovision_networks_for(tenant_id).await
    {
        tracing::error!(error = %e, tenant_id, "network reactor: deprovision failed");
    }
}

/// React to tenant-lifecycle events by driving the subscription aggregate.
pub async fn run_subscription_reactor(
    service: Arc<SubscriptionService>,
    mut events: Receiver<DomainEvent>,
) {
    loop {
        match events.recv().await {
            Ok(event) => apply_to_subscription(&service, &event).await,
            Err(RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "subscription reactor lagged; reconcile will backfill"
                );
            }
            Err(RecvError::Closed) => break,
        }
    }
}

/// React to `SubscriptionDeactivated` by deprovisioning the tenant's networks
/// (`TenantsService` owns the network repository).
pub async fn run_network_reactor(service: Arc<TenantsService>, mut events: Receiver<DomainEvent>) {
    loop {
        match events.recv().await {
            Ok(event) => apply_to_network(&service, &event).await,
            Err(RecvError::Lagged(skipped)) => {
                tracing::warn!(skipped, "network reactor lagged; reconcile will backfill");
            }
            Err(RecvError::Closed) => break,
        }
    }
}
