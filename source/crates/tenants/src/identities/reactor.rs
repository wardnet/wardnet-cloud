//! The **identities reactor** — turns `TenantDeregistered` into a force-logout +
//! identity purge on the Identities aggregate (ADR-0007 / invariant #23).
//!
//! This is the reverse-direction edge: the tenant aggregate publishes
//! `TenantDeregistered`; this reactor reacts by calling the *owning* service's method
//! ([`IdentitiesService::purge_for`]) — never a foreign repository. The reaction is
//! idempotent (a redelivery re-deletes nothing), and the FK `ON DELETE CASCADE` covers
//! the eventual hard sweep, so a dropped event is harmless.
//!
//! Spawn from `main` (`tokio::spawn(run_identities_reactor(...))`).

use std::sync::Arc;

use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

use wardnet_common::event::DomainEvent;

use crate::identities::IdentitiesService;

/// Apply a single event to the **Identities** aggregate: `TenantDeregistered` →
/// purge the tenant's sessions + login methods. Other events are ignored. Factored
/// out so both the live loop and the deterministic test pump share one body.
pub async fn apply_to_identities(service: &IdentitiesService, event: &DomainEvent) {
    if let DomainEvent::TenantDeregistered { tenant_id } = event
        && let Err(e) = service.purge_for(tenant_id).await
    {
        tracing::error!(error = %e, tenant_id, "identities reactor: purge_for failed");
    }
}

/// React to `TenantDeregistered` by purging the deregistered tenant's identities +
/// sessions (force-logout). The one-way edge stays one-way: reads/create flow
/// `IdentitiesService → TenantsService`; this reverse side-effect flows as an event.
pub async fn run_identities_reactor(
    service: Arc<IdentitiesService>,
    mut events: Receiver<DomainEvent>,
) {
    loop {
        match events.recv().await {
            Ok(event) => apply_to_identities(&service, &event).await,
            Err(RecvError::Lagged(skipped)) => {
                tracing::warn!(
                    skipped,
                    "identities reactor lagged; FK cascade is the safety net"
                );
            }
            Err(RecvError::Closed) => break,
        }
    }
}
