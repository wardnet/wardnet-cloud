//! Per-node reconcile loops over this node's own `tunnel_routes` rows.
//!
//! - [`abort_reaper`] (short interval) is the **pull-reconcile abort** (ADR-0004,
//!   consistent with ADR-0001: the Tunneller pulls desired state, Tenants stays
//!   ignorant of it). Each pass iterates the node's own routes, reads the network +
//!   tenant for each, and **aborts** the tunnel (close WS → delete route →
//!   unregister) when the network is gone/`deprovisioning` or the subscription is
//!   inactive. The same pass refreshes `last_seen` for the tunnels it keeps — so it
//!   doubles as the node's **heartbeat**.
//! - [`ttl_reaper`] (independent interval) purges rows orphaned by a node that
//!   crashed without deleting them (their `last_seen` went stale).
//!
//! Both follow a strict never-crash discipline: per-row failures are logged, never
//! propagated, and a transient Tenants read failure leaves the tunnel **up** (fail
//! safe — we only tear down on a *positive* decommission signal).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use wardnet_common::contract::{NetworkView, ProvisioningState, SubscriptionStatus, TenantView};

use crate::mesh::TenantsResolver;
use crate::repository::TunnelRouteRepository;
use crate::tunnel::TunnelRegistry;

/// Run the abort-reconcile + heartbeat loop forever, ticking every `interval` plus
/// up to `jitter_secs` of random jitter (so replicas don't all reconcile in lockstep).
pub async fn abort_reaper(
    registry: Arc<TunnelRegistry>,
    routes: Arc<dyn TunnelRouteRepository>,
    tenants: Arc<dyn TenantsResolver>,
    node_addr: String,
    interval: Duration,
    jitter_secs: u64,
) {
    loop {
        abort_reaper_tick(&registry, &routes, &tenants, &node_addr).await;
        let jitter = if jitter_secs == 0 {
            0
        } else {
            rand::random::<u64>() % (jitter_secs + 1)
        };
        tokio::time::sleep(interval + Duration::from_secs(jitter)).await;
    }
}

/// One abort-reconcile pass over this node's owned routes.
async fn abort_reaper_tick(
    registry: &Arc<TunnelRegistry>,
    routes: &Arc<dyn TunnelRouteRepository>,
    tenants: &Arc<dyn TenantsResolver>,
    node_addr: &str,
) {
    let rows = match routes.list_owned(node_addr).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "abort reaper: failed to list owned routes; retry next tick");
            return;
        }
    };

    for row in rows {
        // A transient read failure must not tear a live tunnel down — skip the row
        // this tick and retry; we abort only on a positive decommission signal.
        let network = match tenants.get_network(&row.network_id).await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(slug = %row.slug, error = %e, "abort reaper: network read failed; skipping");
                continue;
            }
        };
        let tenant = match tenants.get_tenant(&row.tenant_id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(slug = %row.slug, error = %e, "abort reaper: tenant read failed; skipping");
                continue;
            }
        };

        if should_abort(network.as_ref(), tenant.as_ref()) {
            registry.abort(&row.slug);
            if let Err(e) = routes.delete(&row.slug, node_addr).await {
                tracing::warn!(slug = %row.slug, error = %e, "abort reaper: failed to delete aborted route");
            }
            tracing::info!(slug = %row.slug, "abort reaper: tunnel decommissioned, aborted");
        } else if let Err(e) = routes.touch(&row.slug, node_addr).await {
            tracing::debug!(slug = %row.slug, error = %e, "abort reaper: heartbeat touch failed");
        }
    }
}

/// The abort decision: tear the tunnel down when its network is gone or
/// `deprovisioning`, or its tenant is gone or its subscription is inactive.
#[must_use]
pub fn should_abort(network: Option<&NetworkView>, tenant: Option<&TenantView>) -> bool {
    match network {
        // The network row is gone (reaper finished deprovisioning) — abort.
        None => true,
        Some(n) if n.provisioning_state == ProvisioningState::Deprovisioning => true,
        Some(_) => match tenant {
            None => true,
            Some(t) => t.subscription_status != SubscriptionStatus::Active,
        },
    }
}

/// Run the TTL reaper loop forever: purge route rows whose `last_seen` is older than
/// `ttl` (orphaned by a crashed node that never deleted them).
pub async fn ttl_reaper(routes: Arc<dyn TunnelRouteRepository>, ttl: Duration, interval: Duration) {
    loop {
        ttl_reaper_tick(&routes, ttl).await;
        tokio::time::sleep(interval).await;
    }
}

/// One TTL-reaper pass.
async fn ttl_reaper_tick(routes: &Arc<dyn TunnelRouteRepository>, ttl: Duration) {
    let deadline =
        Utc::now() - chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero());
    match routes.reap_expired(deadline).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(purged = n, "ttl reaper: purged orphaned tunnel routes"),
        Err(e) => tracing::warn!(error = %e, "ttl reaper: reap failed; retry next tick"),
    }
}

#[cfg(test)]
mod tests;
